/**
 * Reference Cloudflare Hub Worker + Hibernating WebSocket Durable Object (`AgentHubDO`) for EdgeFetch.
 *
 * Routing & security boundary:
 *  - Tier 1 (Primary): Load-balances requests across all connected remote edge nodes (`amd64` / `aarch64` Go binaries)
 *    via Least-Recently-Used (`lastJobAt` ascending), sharding multi-URL batches across healthy nodes and cooling down
 *    any `(host, siteId)` that receives HTTP `429` while failing over to remaining healthy remote nodes.
 *  - Tier 2 (Cloudflare Overflow): Reaches out directly from Cloudflare (`cloudflareFallbackFetch` — or an optional
 *    Cloudflare Container) ONLY when remote nodes get HTTP `429` (or when zero remote nodes are connected).
 *  - ONLY this Cloudflare Hub hosts inbound HTTP routes (`/admin`, `/mcp`, `/oauth/*`, `/fetch`, `/agents`). Edge nodes
 *    host ZERO inbound endpoints.
 */
import { DurableObject, tracing } from 'cloudflare:workers';
import { handleAdminRoute } from './admin';
import {
  AgentHubEngine,
  parseFetchTarget,
  readAgentReplyBody,
  recomputeSummary,
  routeFetchWithFailover,
  type AffinityPin,
  type AgentAttachment,
  type AgentDispatchResult,
  type CompleteJobResult,
  type CooldownStore,
  type CrawlResultItem,
  type FetchTarget,
  type HubSocketLike,
} from './agent-hub';
import { authorizeAgent, isCallerAuthorized } from './auth';
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
  USER_AGENT?: string;
}

const JOB_ID_RE = /^[A-Za-z0-9_-]{1,64}$/;
const MAX_CALL_BYTES = 1 << 20;
const DEFAULT_UA = 'EdgeFetch/1.0 (+https://github.com/bartrumb/edgefetch)';
const ALLOWED_TARGETS: FetchTarget[] = ['auto', 'agent', 'container'];

export class AgentHubDO extends DurableObject<Env> {
  private readonly engine: AgentHubEngine;
  private readonly oauth: OAuthStore;

  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    this.ctx.setWebSocketAutoResponse(new WebSocketRequestResponsePair('ping', 'pong'));
    this.ctx.blockConcurrencyWhile(async () => {
      this.ctx.storage.sql.exec(`
        CREATE TABLE IF NOT EXISTS site_cooldowns (
          host TEXT NOT NULL,
          site_id TEXT NOT NULL,
          expires_at INTEGER NOT NULL,
          PRIMARY KEY (host, site_id)
        );
        ${OAUTH_SQLITE_SCHEMA}
      `);
    });

    const cooldowns: CooldownStore = {
      isCooledDown: (host, siteId, now) => {
        const rows = this.ctx.storage.sql
          .exec<{ expires_at: number }>(
            'SELECT expires_at FROM site_cooldowns WHERE host = ? AND site_id = ?',
            host.toLowerCase(),
            siteId.toLowerCase(),
          )
          .toArray();
        const row = rows[0];
        if (!row) return false;
        if (row.expires_at <= now) {
          this.ctx.storage.sql.exec('DELETE FROM site_cooldowns WHERE host = ? AND site_id = ?', host.toLowerCase(), siteId.toLowerCase());
          return false;
        }
        return true;
      },
      setCooldown: (host, siteId, expiresAt) => {
        this.ctx.storage.sql.exec(
          'INSERT OR REPLACE INTO site_cooldowns (host, site_id, expires_at) VALUES (?, ?, ?)',
          host.toLowerCase(),
          siteId.toLowerCase(),
          expiresAt,
        );
      },
      clearSite: (siteId) => {
        this.ctx.storage.sql.exec('DELETE FROM site_cooldowns WHERE site_id = ?', siteId.toLowerCase());
      },
      listPins: (now) => {
        this.ctx.storage.sql.exec('DELETE FROM site_cooldowns WHERE expires_at <= ?', now);
        return this.ctx.storage.sql
          .exec<{ host: string; site_id: string; expires_at: number }>(
            'SELECT host, site_id, expires_at FROM site_cooldowns ORDER BY host ASC, site_id ASC',
          )
          .toArray()
          .map((r) => ({ host: r.host, siteId: r.site_id, expiresAt: r.expires_at }));
      },
      clearAll: () => {
        this.ctx.storage.sql.exec('DELETE FROM site_cooldowns');
      },
    };

    this.engine = new AgentHubEngine({
      getSockets: (tag) => this.ctx.getWebSockets(tag) as unknown as HubSocketLike[],
      cooldowns,
    });
    this.oauth = createSqliteOAuthStore(this.ctx.storage.sql as unknown as SqlStorageLike);
  }

  override async fetch(request: Request): Promise<Response> {
    if (request.headers.get('upgrade')?.toLowerCase() !== 'websocket') {
      return Response.json({ error: 'upgrade_required' }, { status: 426 });
    }
    const siteId = (request.headers.get('x-verified-site') ?? '').trim().toLowerCase();
    const arch = request.headers.get('x-agent-arch');

    const pair = new WebSocketPair();
    const [client, server] = Object.values(pair);
    this.ctx.acceptWebSocket(server, [`site:${siteId}`]);
    const att = this.engine.registerAgent(server as unknown as HubSocketLike, siteId, arch);
    server.send(JSON.stringify({ type: 'hello', siteId: att.siteId }));
    return new Response(null, { status: 101, webSocket: client });
  }

  async listAgents(): Promise<{ connected: number; agents: AgentAttachment[] }> {
    return this.engine.listAgents();
  }

  async listAffinities(): Promise<AffinityPin[]> {
    return this.engine.listAffinities();
  }

  async clearAffinities(siteId?: string): Promise<void> {
    this.engine.clearAffinities(siteId);
  }

  async getPortalState(now: number): Promise<{
    connected: number;
    agents: AgentAttachment[];
    affinities: AffinityPin[];
    grants: OAuthGrantSummary[];
  }> {
    const fleet = this.engine.listAgents();
    return {
      ...fleet,
      affinities: this.engine.listAffinities(),
      grants: await this.oauth.listGrants(now),
    };
  }

  async dispatchFetch(rawCallBody: string, trace: Record<string, string>, preferredSite?: string): Promise<AgentDispatchResult> {
    return this.engine.dispatchFetch(rawCallBody, trace, { preferredSite });
  }

  async hasPendingJob(jobId: string, siteId: string): Promise<boolean> {
    return this.engine.hasPendingJob(jobId, siteId);
  }

  async completeJob(jobId: string, jobNonce: string, siteId: string, bodyText: string): Promise<CompleteJobResult> {
    return this.engine.completeJob(jobId, jobNonce, siteId, bodyText);
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

  override async webSocketMessage(ws: WebSocket, message: string | ArrayBuffer): Promise<void> {
    if (typeof message !== 'string' || message === 'ping' || message.length > 2048) return;
    try {
      const msg = JSON.parse(message) as { type?: string; reconnectAttempt?: number };
      if (msg.type === 'agent_hello') {
        const att = ws.deserializeAttachment() as AgentAttachment | null;
        console.info(JSON.stringify({ event: (msg.reconnectAttempt ?? 0) > 0 ? 'agent_reconnected' : 'agent_ready', siteId: att?.siteId, ...msg }));
      }
    } catch {
      // ignore malformed frames
    }
  }

  override async webSocketClose(ws: WebSocket, code: number, reason: string): Promise<void> {
    this.engine.handleDisconnect(ws as unknown as HubSocketLike, reason || `closed_${code}`);
  }

  override async webSocketError(ws: WebSocket): Promise<void> {
    this.engine.handleDisconnect(ws as unknown as HubSocketLike, 'ws_error');
  }
}

/**
 * Direct Cloudflare edge overflow fetcher invoked in `target=auto` ONLY when remote nodes hit HTTP `429`
 * (or when zero remote nodes are connected). Enforces public `https://:443` DNS-only URLs and streaming body caps.
 */
async function cloudflareOverflowFetch(rawBody: string, userAgent: string, selfHost: string): Promise<Response> {
  const started = Date.now();
  let call: {
    requests?: Array<{ id?: string; url?: string; kind?: string; ifNoneMatch?: string; ifModifiedSince?: string }>;
    options?: { includeBody?: boolean; maxBytes?: number };
  };
  try {
    call = JSON.parse(rawBody) as typeof call;
  } catch {
    return Response.json({ error: 'bad_json' }, { status: 400 });
  }
  const reqs = Array.isArray(call.requests) ? call.requests : [];
  const maxBytes = Math.min(16 << 20, Math.max(1024, call.options?.maxBytes ?? 8 << 20));
  const includeBody = Boolean(call.options?.includeBody);
  const results: CrawlResultItem[] = [];

  for (const r of reqs) {
    const reqStart = Date.now();
    let parsedUrl: URL;
    try {
      parsedUrl = new URL(r.url ?? '');
    } catch {
      results.push({ id: r.id, url: r.url, kind: r.kind, status: 0, outcome: 'error', problem: 'bad_url' });
      continue;
    }
    const host = parsedUrl.hostname.toLowerCase();
    if (
      parsedUrl.protocol !== 'https:' ||
      (parsedUrl.port && parsedUrl.port !== '443') ||
      !host.includes('.') ||
      host === 'localhost' ||
      host === selfHost.toLowerCase()
    ) {
      results.push({ id: r.id, url: r.url, kind: r.kind, status: 0, outcome: 'error', problem: 'disallowed_url' });
      continue;
    }

    const headers = new Headers({
      'user-agent': userAgent,
      accept: r.kind === 'feed' ? 'application/json' : 'text/html,application/xhtml+xml',
    });
    if (r.ifNoneMatch) headers.set('if-none-match', r.ifNoneMatch);
    if (r.ifModifiedSince) headers.set('if-modified-since', r.ifModifiedSince);

    try {
      const resp = await fetch(parsedUrl.toString(), { method: 'GET', headers, redirect: 'follow' });
      const reader = resp.body?.getReader();
      const chunks: Uint8Array[] = [];
      let total = 0;
      let truncated = false;
      if (reader) {
        for (;;) {
          const { done, value } = await reader.read();
          if (done) break;
          if (value) {
            if (total + value.byteLength > maxBytes) {
              truncated = true;
              await reader.cancel().catch(() => undefined);
              break;
            }
            total += value.byteLength;
            if (includeBody) chunks.push(value);
          }
        }
      }
      let bodyStr: string | undefined;
      if (includeBody && !truncated) {
        const buf = new Uint8Array(total);
        let off = 0;
        for (const c of chunks) {
          buf.set(c, off);
          off += c.byteLength;
        }
        bodyStr = new TextDecoder().decode(buf);
      }
      const cfMitigated = resp.headers.get('cf-mitigated') ?? undefined;
      const outcome = truncated
        ? 'error'
        : cfMitigated
          ? 'challenge'
          : resp.status >= 200 && resp.status < 400
            ? 'ok'
            : resp.status === 404 || resp.status === 410
              ? 'gone'
              : 'error';
      results.push({
        id: r.id,
        url: r.url,
        kind: r.kind,
        status: resp.status,
        outcome,
        bytes: total,
        truncated,
        durationMs: Date.now() - reqStart,
        contentType: resp.headers.get('content-type') ?? undefined,
        etag: resp.headers.get('etag') ?? undefined,
        retryAfter: resp.headers.get('retry-after') ?? undefined,
        ...(cfMitigated ? { cfMitigated } : {}),
        ...(bodyStr !== undefined ? { body: bodyStr } : {}),
      });
    } catch (e) {
      results.push({
        id: r.id,
        url: r.url,
        kind: r.kind,
        status: 0,
        outcome: 'error',
        problem: e instanceof Error ? e.message : String(e),
        durationMs: Date.now() - reqStart,
      });
    }
  }

  return Response.json({
    results,
    summary: recomputeSummary(results),
    durationMs: Date.now() - started,
  });
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
    const ua = env.USER_AGENT?.trim() || DEFAULT_UA;

    const executeHubFetch = async (target: FetchTarget, body: string, site?: string) =>
      (tracing as unknown as { enterSpan<T>(n: string, fn: (s: { setAttribute(k: string, v: unknown): void }) => T): T }).enterSpan(
        'edgefetch.dispatch',
        async (span) => {
          const trace = { 'x-request-id': request.headers.get('cf-ray') ?? '' };
          const res = await routeFetchWithFailover({
            target,
            site,
            body,
            trace,
            callAgent: (b, t, s) => hub().dispatchFetch(b, t, s),
            callContainer: (b) => cloudflareOverflowFetch(b, ua, url.hostname),
          });
          const via = res.headers.get('x-crawler-via') ?? target;
          span.setAttribute('edgefetch.via', via);
          return { status: res.status, via, bodyText: await res.text() };
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
      const payload = await readAgentReplyBody(request);
      if (!payload.ok) return Response.json({ error: payload.error }, { status: payload.status });
      const done = await hub().completeJob(jobId, jobNonce, auth.siteId, payload.text);
      return Response.json({ ok: done.ok }, { status: done.status });
    }

    const oauthStore = hubOAuthStore(hub);

    const oauthRes = await handleOAuthRoute(request, url, {
      store: oauthStore,
      ownerSecret: env.CALLER_TOKEN,
      serviceName: 'EdgeFetch Hub',
    });
    if (oauthRes) return oauthRes;

    if (url.pathname === '/mcp') {
      return handleMcpRequest(request, url, {
        serverName: 'edgefetch-hub',
        serverVersion: '1.2.0',
        ownerSecret: env.CALLER_TOKEN,
        oauthStore,
        allowedTargets: ALLOWED_TARGETS,
        defaultTarget: 'auto',
        listFleet: async () => {
          const state = await hub().getPortalState(Date.now());
          return { connected: state.connected, agents: state.agents, affinities: state.affinities };
        },
        executeFetch: ({ target, site, body }) => executeHubFetch(target, body, site),
      });
    }

    const adminRes = await handleAdminRoute(request, url, {
      serviceName: 'EdgeFetch Hub',
      mcpSlug: 'edgefetch',
      ownerSecret: env.CALLER_TOKEN,
      oauthStore,
      allowedTargets: ALLOWED_TARGETS,
      defaultTarget: 'auto',
      getState: () => hub().getPortalState(Date.now()),
      clearAffinities: (siteId) => hub().clearAffinities(siteId),
      revokeGrant: (grantId) => hub().oauthRevokeGrant(grantId),
      executeFetch: ({ target, site, body }) => executeHubFetch(target, body, site),
    });
    if (adminRes) return adminRes;

    if (!isCallerAuthorized(request, env.CALLER_TOKEN)) {
      return Response.json({ error: 'unauthorized' }, { status: 401 });
    }
    if (request.method === 'GET' && url.pathname === '/agents') {
      return Response.json(await hub().listAgents());
    }
    if (request.method === 'POST' && url.pathname === '/fetch') {
      const parsedTarget = parseFetchTarget(url);
      if (!parsedTarget.ok) return Response.json({ error: 'bad_target', message: parsedTarget.message }, { status: 400 });
      const body = await request.text();
      if (body.length > MAX_CALL_BYTES) return Response.json({ error: 'too_large' }, { status: 413 });
      const out = await executeHubFetch(parsedTarget.target, body, parsedTarget.site);
      return new Response(out.bodyText, {
        status: out.status,
        headers: { 'content-type': 'application/json', 'x-crawler-via': out.via, 'cache-control': 'no-store' },
      });
    }
    return Response.json({ error: 'not_found' }, { status: 404 });
  },
};
