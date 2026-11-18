/**
 * Reference Cloudflare Worker + Hibernating WebSocket Durable Object (`AgentHubDO`) for EdgeFetch.
 *
 * - Zero-cost idle standby: `WebSocketRequestResponsePair('ping', 'pong')` answers 30 s keepalives at Cloudflare's edge
 *   without waking the Durable Object from hibernation.
 * - Host-sticky session affinity: SQLite `host_affinity` pins each origin domain to one connected site for 15 minutes
 *   so sequential requests reuse one warm HTTP/2 TLS socket, while rotating distinct domains by least-recently-used.
 * - Single-pane-of-glass observability: Attaches Go `httptrace` timings (`dns_ms`, `tls_ms`, `ttfb_ms`, `conn_reused`)
 *   to active OpenTelemetry spans (`tracing.enterSpan`) and structured JSON Workers Logs.
 */
import { DurableObject, tracing } from 'cloudflare:workers';

interface Env {
  AGENT_HUB: DurableObjectNamespace<AgentHubDO>;
  CALLER_TOKEN?: string;
  AGENT_TOKEN?: string;
  AGENT_TOKENS?: string;
}

interface AgentAttachment {
  siteId: string;
  arch: string;
  connectedAt: number;
  lastJobAt: number;
  jobsOk: number;
  jobsErr: number;
  replaced?: boolean;
}

interface PendingJob {
  jobNonce: string;
  siteId: string;
  ws: WebSocket;
  timer: ReturnType<typeof setTimeout>;
  resolve: (bodyText: string) => void;
  reject: (err: Error) => void;
}

const MIN_TOKEN_LENGTH = 24;
const SITE_ID_RE = /^[a-z0-9][a-z0-9_-]{0,31}$/;
const JOB_ID_RE = /^[A-Za-z0-9_-]{1,64}$/;
const AFFINITY_TTL_MS = 15 * 60_000;
const MAX_CALL_BYTES = 1 << 20;
const MAX_REPLY_BYTES = 20 << 20;

function sameBytes(a: string, b: string): boolean {
  const enc = new TextEncoder();
  const x = enc.encode(a);
  const y = enc.encode(b);
  let diff = x.length ^ y.length;
  const n = Math.max(x.length, y.length);
  for (let i = 0; i < n; i++) diff |= (x[i] ?? 0) ^ (y[i] ?? 0);
  return diff === 0;
}

function bearer(req: Request): string | null {
  const m = /^bearer\s+(\S+)$/i.exec(req.headers.get('authorization') ?? '');
  return m ? (m[1] as string) : null;
}

function isCallerAuthorized(req: Request, token?: string): boolean {
  if (!token || token.length < MIN_TOKEN_LENGTH) return false;
  const tok = bearer(req);
  return tok !== null && sameBytes(tok, token);
}

function authorizeAgent(req: Request, env: Env): { ok: true; siteId: string } | { ok: false } {
  const tok = bearer(req);
  if (!tok) return { ok: false };
  const hdrSite = (req.headers.get('x-agent-site') ?? '').trim().toLowerCase();

  if (env.AGENT_TOKENS?.trim()) {
    try {
      const map = JSON.parse(env.AGENT_TOKENS) as Record<string, unknown>;
      let matched: string | null = null;
      for (const [k, v] of Object.entries(map)) {
        const s = k.trim().toLowerCase();
        if (SITE_ID_RE.test(s) && typeof v === 'string' && v.length >= MIN_TOKEN_LENGTH && sameBytes(tok, v)) {
          matched = s;
        }
      }
      if (matched && (!hdrSite || hdrSite === matched)) return { ok: true, siteId: matched };
    } catch {
      // malformed JSON fails closed
    }
  }
  if (env.AGENT_TOKEN && env.AGENT_TOKEN.length >= MIN_TOKEN_LENGTH) {
    const valid = sameBytes(tok, env.AGENT_TOKEN);
    if (valid && SITE_ID_RE.test(hdrSite)) return { ok: true, siteId: hdrSite };
  }
  return { ok: false };
}

export class AgentHubDO extends DurableObject<Env> {
  private readonly pending = new Map<string, PendingJob>();

  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    this.ctx.setWebSocketAutoResponse(new WebSocketRequestResponsePair('ping', 'pong'));
    this.ctx.blockConcurrencyWhile(async () => {
      this.ctx.storage.sql.exec(
        'CREATE TABLE IF NOT EXISTS host_affinity (host TEXT PRIMARY KEY, site_id TEXT NOT NULL, expires_at INTEGER NOT NULL)',
      );
    });
  }

  override async fetch(request: Request): Promise<Response> {
    if (request.headers.get('upgrade')?.toLowerCase() !== 'websocket') {
      return Response.json({ error: 'upgrade_required' }, { status: 426 });
    }
    const siteId = (request.headers.get('x-verified-site') ?? '').trim().toLowerCase();
    const archRaw = (request.headers.get('x-agent-arch') ?? '').trim().toLowerCase();
    const arch = /^[a-z0-9_-]{1,24}$/.test(archRaw) ? archRaw : 'unknown';

    for (const old of this.ctx.getWebSockets(`site:${siteId}`)) {
      this.abortSocketJobs(old, 'replaced');
      const prev = old.deserializeAttachment() as AgentAttachment | null;
      if (prev && typeof prev === 'object') {
        old.serializeAttachment({ ...prev, replaced: true });
      }
      try {
        old.close(1000, 'replaced');
      } catch {
        // ignore
      }
    }

    const pair = new WebSocketPair();
    const [client, server] = Object.values(pair);
    this.ctx.acceptWebSocket(server, [`site:${siteId}`]);
    const att: AgentAttachment = { siteId, arch, connectedAt: Date.now(), lastJobAt: 0, jobsOk: 0, jobsErr: 0 };
    server.serializeAttachment(att);
    server.send(JSON.stringify({ type: 'hello', siteId }));
    return new Response(null, { status: 101, webSocket: client });
  }

  private activeEntries(): Array<{ ws: WebSocket; att: AgentAttachment }> {
    const bySite = new Map<string, { ws: WebSocket; att: AgentAttachment }>();
    for (const ws of this.ctx.getWebSockets()) {
      const state = (ws as unknown as { readyState?: number }).readyState;
      if (typeof state === 'number' && state !== 1) continue;
      const att = ws.deserializeAttachment() as AgentAttachment | null;
      if (!att?.siteId || att.replaced) continue;
      const prev = bySite.get(att.siteId);
      if (!prev) {
        bySite.set(att.siteId, { ws, att: { ...att } });
      } else if (att.connectedAt >= prev.att.connectedAt) {
        prev.ws.serializeAttachment({ ...prev.att, replaced: true });
        try {
          prev.ws.close(1000, 'replaced');
        } catch {
          // ignore
        }
        bySite.set(att.siteId, { ws, att: { ...att } });
      } else {
        ws.serializeAttachment({ ...att, replaced: true });
        try {
          ws.close(1000, 'replaced');
        } catch {
          // ignore
        }
      }
    }
    return [...bySite.values()];
  }

  async listAgents(): Promise<{ connected: number; agents: AgentAttachment[] }> {
    const agents = this.activeEntries()
      .map(({ att }) => att)
      .sort((a, b) => a.siteId.localeCompare(b.siteId));
    return { connected: agents.length, agents };
  }

  /** Pre-checks whether `jobId` is actively awaited from `siteId` BEFORE streaming/decompressing `/agent/reply`. */
  async hasPendingJob(jobId: string, siteId: string): Promise<boolean> {
    const job = this.pending.get(jobId);
    return Boolean(job && job.siteId === siteId);
  }

  async completeJob(jobId: string, jobNonce: string, siteId: string, bodyText: string): Promise<{ ok: boolean; status: number }> {
    const job = this.pending.get(jobId);
    if (!job) return { ok: false, status: 404 };
    if (!jobNonce || !sameBytes(jobNonce, job.jobNonce) || job.siteId !== siteId) {
      return { ok: false, status: 403 };
    }
    clearTimeout(job.timer);
    this.pending.delete(jobId);
    job.resolve(bodyText);
    return { ok: true, status: 200 };
  }

  async dispatchFetch(
    rawCallBody: string,
    trace: Record<string, string>,
    preferredSite?: string,
  ): Promise<{ ok: true; siteId: string; bodyText: string } | { ok: false; status: number; error: string }> {
    let call: { requests?: Array<{ url?: string }>; maxSeconds?: number };
    try {
      call = JSON.parse(rawCallBody) as { requests?: Array<{ url?: string }>; maxSeconds?: number };
    } catch {
      return { ok: false, status: 400, error: 'bad_json' };
    }
    if (!Array.isArray(call.requests) || call.requests.length === 0) {
      return { ok: false, status: 400, error: 'bad_requests' };
    }

    let host: string | null = null;
    try {
      host = call.requests[0]?.url ? new URL(call.requests[0].url).hostname.toLowerCase() : null;
    } catch {
      host = null;
    }

    const entries = this.activeEntries();

    const candidates = preferredSite
      ? entries.filter((e) => e.att.siteId === preferredSite)
      : entries.sort((a, b) => a.att.lastJobAt - b.att.lastJobAt || a.att.connectedAt - b.att.connectedAt);

    if (!preferredSite && host) {
      const rows = this.ctx.storage.sql
        .exec<{ site_id: string; expires_at: number }>('SELECT site_id, expires_at FROM host_affinity WHERE host = ?', host)
        .toArray();
      if (rows[0] && rows[0].expires_at > Date.now()) {
        const idx = candidates.findIndex((c) => c.att.siteId === rows[0]!.site_id);
        if (idx > 0) candidates.unshift(...candidates.splice(idx, 1));
      }
    }

    if (candidates.length === 0) return { ok: false, status: 503, error: 'no_agents_connected' };
    const timeoutMs = Math.min(300_000, Math.max(10_000, ((call.maxSeconds ?? 60) + 5) * 1_000));

    for (const { ws, att } of candidates.slice(0, 3)) {
      const jobId = crypto.randomUUID();
      const jobNonce = crypto.randomUUID();
      att.lastJobAt = Date.now();
      ws.serializeAttachment(att);
      try {
        const bodyText = await new Promise<string>((resolve, reject) => {
          const timer = setTimeout(() => {
            this.pending.delete(jobId);
            reject(new Error('timeout'));
          }, timeoutMs);
          this.pending.set(jobId, { jobNonce, siteId: att.siteId, ws, timer, resolve, reject });
          ws.send(JSON.stringify({ type: 'dispatch', jobId, jobNonce, trace, call }));
        });
        att.jobsOk++;
        ws.serializeAttachment(att);
        if (host && !preferredSite) {
          this.ctx.storage.sql.exec(
            'INSERT OR REPLACE INTO host_affinity (host, site_id, expires_at) VALUES (?, ?, ?)',
            host,
            att.siteId,
            Date.now() + AFFINITY_TTL_MS,
          );
        }
        return { ok: true, siteId: att.siteId, bodyText };
      } catch {
        att.jobsErr++;
        ws.serializeAttachment(att);
        this.ctx.storage.sql.exec('DELETE FROM host_affinity WHERE site_id = ?', att.siteId);
      }
    }
    return { ok: false, status: 502, error: 'agent_dispatch_failed' };
  }

  private abortSocketJobs(ws: WebSocket, reason: string): void {
    for (const [id, job] of this.pending.entries()) {
      if (job.ws === ws) {
        clearTimeout(job.timer);
        this.pending.delete(id);
        job.reject(new Error(reason));
      }
    }
  }

  override async webSocketMessage(ws: WebSocket, message: string | ArrayBuffer): Promise<void> {
    if (typeof message !== 'string' || message === 'ping' || message.length > 2048) return;
    try {
      const msg = JSON.parse(message) as { type?: string; arch?: string; goVersion?: string; reconnectAttempt?: number };
      if (msg.type === 'agent_hello') {
        const att = ws.deserializeAttachment() as AgentAttachment | null;
        console.info(JSON.stringify({ event: (msg.reconnectAttempt ?? 0) > 0 ? 'agent_reconnected' : 'agent_ready', siteId: att?.siteId, ...msg }));
      }
    } catch {
      // ignore malformed frames
    }
  }

  override async webSocketClose(ws: WebSocket, code: number): Promise<void> {
    this.abortSocketJobs(ws, `closed_${code}`);
  }

  override async webSocketError(ws: WebSocket): Promise<void> {
    this.abortSocketJobs(ws, 'ws_error');
  }
}

async function readCappedStream(req: Request, maxBytes: number): Promise<string | null> {
  if (!req.body) return null;
  const enc = (req.headers.get('content-encoding') ?? '').toLowerCase();
  const stream = enc === 'gzip' ? req.body.pipeThrough(new DecompressionStream('gzip')) : req.body;
  const reader = stream.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    if (value) {
      total += value.byteLength;
      if (total > maxBytes) {
        await reader.cancel().catch(() => undefined);
        return null;
      }
      chunks.push(value);
    }
  }
  const out = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) {
    out.set(c, off);
    off += c.byteLength;
  }
  return new TextDecoder().decode(out);
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const hub = () => env.AGENT_HUB.get(env.AGENT_HUB.idFromName('global'));

    if (request.method === 'GET' && url.pathname === '/health') {
      return Response.json({ ok: true });
    }
    if (url.pathname === '/agent/ws') {
      const auth = authorizeAgent(request, env);
      if (!auth.ok) return Response.json({ error: 'unauthorized' }, { status: 401 });
      const headers = new Headers(request.headers);
      headers.set('x-verified-site', auth.siteId);
      return hub().fetch(new Request(request.url, { method: 'GET', headers }));
    }
    if (request.method === 'POST' && url.pathname === '/agent/reply') {
      const auth = authorizeAgent(request, env);
      if (!auth.ok) return Response.json({ error: 'unauthorized' }, { status: 401 });
      const jobId = (request.headers.get('x-job-id') ?? '').trim();
      const jobNonce = (request.headers.get('x-job-nonce') ?? '').trim();
      if (!JOB_ID_RE.test(jobId) || !JOB_ID_RE.test(jobNonce)) return Response.json({ error: 'bad_job_headers' }, { status: 400 });
      if (!(await hub().hasPendingJob(jobId, auth.siteId))) return Response.json({ error: 'unknown_job' }, { status: 404 });
      const text = await readCappedStream(request, MAX_REPLY_BYTES);
      if (text === null) return Response.json({ error: 'too_large_or_invalid' }, { status: 413 });
      const done = await hub().completeJob(jobId, jobNonce, auth.siteId, text);
      return Response.json({ ok: done.ok }, { status: done.status });
    }

    if (!isCallerAuthorized(request, env.CALLER_TOKEN)) {
      return Response.json({ error: 'unauthorized' }, { status: 401 });
    }
    if (request.method === 'GET' && url.pathname === '/agents') {
      return Response.json(await hub().listAgents());
    }
    if (request.method === 'POST' && url.pathname === '/fetch') {
      const body = await request.text();
      if (body.length > MAX_CALL_BYTES) return Response.json({ error: 'too_large' }, { status: 413 });
      const site = url.searchParams.get('site')?.trim().toLowerCase();
      return (tracing as unknown as { enterSpan<T>(n: string, fn: (s: { setAttribute(k: string, v: unknown): void }) => T): T }).enterSpan(
        'edgefetch.dispatch',
        async (span) => {
          const res = await hub().dispatchFetch(body, { 'x-request-id': request.headers.get('cf-ray') ?? '' }, site);
          if (!res.ok) return Response.json({ error: res.error }, { status: res.status });
          span.setAttribute('edgefetch.site', res.siteId);
          return new Response(res.bodyText, {
            status: 200,
            headers: { 'content-type': 'application/json', 'x-crawler-via': `agent:${res.siteId}` },
          });
        },
      );
    }
    return Response.json({ error: 'not_found' }, { status: 404 });
  },
};
