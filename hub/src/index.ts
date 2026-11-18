/**
 * Reference Cloudflare Hub Worker + Hibernating WebSocket Durable Object (`AgentHubDO`) for EdgeFetch.
 *
 * Architectural boundary:
 *  - ONLY this Cloudflare Hub hosts inbound HTTP routes (`/admin`, `/mcp`, `/oauth/*`, `/fetch`, `/agents`).
 *  - Edge nodes (Home Assistant OS / Docker Go binaries) host ZERO inbound endpoints; they strictly dial outbound
 *    `wss://` to `/agent/ws`, sleep via Cloudflare edge auto-pong (`0` idle DO wakeups), and upload gzipped replies
 *    to `/agent/reply`.
 */
import { DurableObject, tracing } from 'cloudflare:workers';
import { handleAdminRoute } from './admin';
import type { AffinityPin, AgentAttachment } from './agent-hub';
import { authorizeAgent, isCallerAuthorized, sameBytes } from './auth';
import { handleMcpRequest } from './mcp';
import {
  OAUTH_SQLITE_SCHEMA,
  createSqliteOAuthStore,
  handleOAuthRoute,
  type OAuthClientRecord,
  type OAuthCodeRecord,
  type OAuthGrantSummary,
  type OAuthStore,
  type OAuthTokenRecord,
  type SqlStorageLike,
} from './oauth';

interface Env {
  AGENT_HUB: DurableObjectNamespace<AgentHubDO>;
  CALLER_TOKEN?: string;
  AGENT_TOKEN?: string;
  AGENT_TOKENS?: string;
}

interface PendingJob {
  jobNonce: string;
  siteId: string;
  ws: WebSocket;
  timer: ReturnType<typeof setTimeout>;
  resolve: (bodyText: string) => void;
  reject: (err: Error) => void;
}

const JOB_ID_RE = /^[A-Za-z0-9_-]{1,64}$/;
const AFFINITY_TTL_MS = 15 * 60_000;
const MAX_CALL_BYTES = 1 << 20;
const MAX_REPLY_BYTES = 20 << 20;

export class AgentHubDO extends DurableObject<Env> {
  private readonly pending = new Map<string, PendingJob>();
  private readonly oauth: OAuthStore;

  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    this.ctx.setWebSocketAutoResponse(new WebSocketRequestResponsePair('ping', 'pong'));
    this.ctx.blockConcurrencyWhile(async () => {
      this.ctx.storage.sql.exec(`
        CREATE TABLE IF NOT EXISTS host_affinity (
          host TEXT PRIMARY KEY,
          site_id TEXT NOT NULL,
          expires_at INTEGER NOT NULL
        );
        ${OAUTH_SQLITE_SCHEMA}
      `);
    });
    this.oauth = createSqliteOAuthStore(this.ctx.storage.sql as unknown as SqlStorageLike);
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

  async listAffinities(now = Date.now()): Promise<AffinityPin[]> {
    this.ctx.storage.sql.exec('DELETE FROM host_affinity WHERE expires_at <= ?', now);
    return this.ctx.storage.sql
      .exec<{ host: string; site_id: string; expires_at: number }>('SELECT host, site_id, expires_at FROM host_affinity ORDER BY host ASC')
      .toArray()
      .map((r) => ({ host: r.host, siteId: r.site_id, expiresAt: r.expires_at }));
  }

  async clearAffinities(siteId?: string): Promise<void> {
    if (siteId?.trim()) {
      this.ctx.storage.sql.exec('DELETE FROM host_affinity WHERE site_id = ?', siteId.trim().toLowerCase());
    } else {
      this.ctx.storage.sql.exec('DELETE FROM host_affinity');
    }
  }

  async getPortalState(now: number): Promise<{
    connected: number;
    agents: AgentAttachment[];
    affinities: AffinityPin[];
    grants: OAuthGrantSummary[];
  }> {
    const fleet = await this.listAgents();
    return {
      ...fleet,
      affinities: await this.listAffinities(now),
      grants: await this.oauth.listGrants(now),
    };
  }

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

  // OAuth 2.1 SQLite RPC methods
  async oauthPutClient(c: OAuthClientRecord): Promise<void> {
    await this.oauth.putClient(c);
  }
  async oauthGetClient(id: string): Promise<OAuthClientRecord | null> {
    return await this.oauth.getClient(id);
  }
  async oauthPutCode(c: OAuthCodeRecord): Promise<void> {
    await this.oauth.putCode(c);
  }
  async oauthConsumeCode(h: string, now: number): Promise<OAuthCodeRecord | null> {
    return await this.oauth.consumeCode(h, now);
  }
  async oauthPutTokenPair(p: {
    grantId: string;
    accessHash: string;
    refreshHash: string;
    clientId: string;
    clientName: string;
    scopes: string[];
    resource: string;
    createdAt: number;
    accessExpiresAt: number;
    refreshExpiresAt: number;
  }): Promise<void> {
    await this.oauth.putTokenPair(p);
  }
  async oauthGetAccessToken(h: string, now: number): Promise<OAuthTokenRecord | null> {
    return await this.oauth.getAccessToken(h, now);
  }
  async oauthConsumeRefreshToken(h: string, now: number): Promise<OAuthTokenRecord | null> {
    return await this.oauth.consumeRefreshToken(h, now);
  }
  async oauthListGrants(now: number): Promise<OAuthGrantSummary[]> {
    return await this.oauth.listGrants(now);
  }
  async oauthRevokeGrant(id: string): Promise<boolean> {
    return await this.oauth.revokeGrant(id);
  }
  async oauthRevokeByTokenHash(h: string): Promise<void> {
    await this.oauth.revokeByTokenHash(h);
  }
  async oauthRecordAuthFailure(
    bucket: string,
    now: number,
    windowMs: number,
    maxFailures: number,
  ): Promise<{ allowed: boolean; retryAfterSec: number }> {
    return await this.oauth.recordAuthFailure(bucket, now, windowMs, maxFailures);
  }
  async oauthClearAuthFailures(bucket: string): Promise<void> {
    await this.oauth.clearAuthFailures(bucket);
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

function hubOAuthStore(hub: () => DurableObjectStub<AgentHubDO>): OAuthStore {
  return {
    putClient: (c) => hub().oauthPutClient(c),
    getClient: (id) => hub().oauthGetClient(id),
    putCode: (c) => hub().oauthPutCode(c),
    consumeCode: (h, now) => hub().oauthConsumeCode(h, now),
    putTokenPair: (p) => hub().oauthPutTokenPair(p),
    getAccessToken: (h, now) => hub().oauthGetAccessToken(h, now),
    consumeRefreshToken: (h, now) => hub().oauthConsumeRefreshToken(h, now),
    listGrants: (now) => hub().oauthListGrants(now),
    revokeGrant: (id) => hub().oauthRevokeGrant(id),
    revokeByTokenHash: (h) => hub().oauthRevokeByTokenHash(h),
    recordAuthFailure: (b, now, w, m) => hub().oauthRecordAuthFailure(b, now, w, m),
    clearAuthFailures: (b) => hub().oauthClearAuthFailures(b),
  };
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const hub = () => env.AGENT_HUB.get(env.AGENT_HUB.idFromName('global'));
    const executeHubFetch = async (body: string, site?: string) =>
      (tracing as unknown as { enterSpan<T>(n: string, fn: (s: { setAttribute(k: string, v: unknown): void }) => T): T }).enterSpan(
        'edgefetch.dispatch',
        async (span) => {
          const res = await hub().dispatchFetch(body, { 'x-request-id': request.headers.get('cf-ray') ?? '' }, site);
          if (!res.ok) {
            return { status: res.status, via: 'none', bodyText: JSON.stringify({ error: res.error }) };
          }
          span.setAttribute('edgefetch.site', res.siteId);
          return { status: 200, via: `agent:${res.siteId}`, bodyText: res.bodyText };
        },
      );

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

    const oauthStore = hubOAuthStore(hub);

    // Self-hosted OAuth 2.1 + RFC 9728 / RFC 8414 discovery
    const oauthRes = await handleOAuthRoute(request, url, {
      store: oauthStore,
      ownerSecret: env.CALLER_TOKEN,
      serviceName: 'EdgeFetch Hub',
    });
    if (oauthRes) return oauthRes;

    // Stateless Streamable HTTP MCP Server (`/mcp`)
    if (url.pathname === '/mcp') {
      return handleMcpRequest(request, url, {
        serverName: 'edgefetch-hub',
        serverVersion: '1.1.0',
        ownerSecret: env.CALLER_TOKEN,
        oauthStore,
        allowedTargets: ['agent'],
        defaultTarget: 'agent',
        listFleet: async () => {
          const state = await hub().getPortalState(Date.now());
          return { connected: state.connected, agents: state.agents, affinities: state.affinities };
        },
        executeFetch: ({ site, body }) => executeHubFetch(body, site),
      });
    }

    // Built-in Web Control Center (`/admin` & `/admin/*`)
    const adminRes = await handleAdminRoute(request, url, {
      serviceName: 'EdgeFetch Hub',
      mcpSlug: 'edgefetch',
      ownerSecret: env.CALLER_TOKEN,
      oauthStore,
      allowedTargets: ['agent'],
      defaultTarget: 'agent',
      getState: () => hub().getPortalState(Date.now()),
      clearAffinities: (siteId) => hub().clearAffinities(siteId),
      revokeGrant: (grantId) => hub().oauthRevokeGrant(grantId),
      executeFetch: ({ site, body }) => executeHubFetch(body, site),
    });
    if (adminRes) return adminRes;

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
      const out = await executeHubFetch(body, site);
      return new Response(out.bodyText, {
        status: out.status,
        headers: { 'content-type': 'application/json', 'x-crawler-via': out.via, 'cache-control': 'no-store' },
      });
    }
    return Response.json({ error: 'not_found' }, { status: 404 });
  },
};
