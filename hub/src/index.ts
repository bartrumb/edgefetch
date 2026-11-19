/**
 * Reference Cloudflare Hub Worker + Hibernating WebSocket Durable Object (`AgentHubDO`) for EdgeFetch.
 *
 * Routing & security boundary:
 *  - Tier 1 (Primary): Load-balances requests across all connected remote edge nodes (`amd64` / `aarch64` Go binaries)
 *    via Least-Recently-Used (`lastJobAt` ascending), sharding multi-URL batches across healthy nodes and cooling down
 *    any `(host, siteId)` that receives HTTP `429` while failing over to remaining healthy remote nodes.
 *  - Tier 2 (Cloudflare Overflow): Reaches out directly from Cloudflare (`cloudflareOverflowFetch`) ONLY when remote
 *    nodes hit HTTP `429` (or when zero remote nodes are connected).
 *  - ONLY this Cloudflare Hub hosts inbound HTTP routes (`/admin`, `/mcp`, `/oauth/*`, `/fetch`, `/agents`). Edge nodes
 *    host ZERO inbound endpoints.
 */
import { DurableObject, tracing } from 'cloudflare:workers';
import {
  ACTIVITY_SQLITE_SCHEMA,
  buildCrawlActivityEvents,
  createSqliteActivityStore,
  sanitizeDetails,
  type ActivityStore,
  type HubEventInput,
  type HubEventRecord,
  type McpClientActivity,
} from './activity-log';
import { handleAdminRoute } from './admin';
import {
  AgentHubEngine,
  MAX_CALL_UTF8_BYTES,
  parseFetchTarget,
  readAgentReplyBody,
  routeFetchWithFailover,
  type AffinityPin,
  type AffinityStore,
  type AgentAttachment,
  type AgentDispatchResult,
  type ArtifactDispatchPolicy,
  type AuthorizeArtifactUploadParams,
  type AuthorizeArtifactUploadResult,
  type CompleteJobResult,
  type CooldownStore,
  type FetchTarget,
  type HostWindowStore,
  type HubSocketLike,
} from './agent-hub';
import { authorizeAgent, isCallerAuthorized } from './auth';
import { handleMcpRequest } from './mcp';
import { authorizeMcpRequest, createSqliteOAuthStore, handleOAuthRoute, OAUTH_SQLITE_SCHEMA } from './oauth';
import type {
  OAuthClientRecord,
  OAuthCodeRecord,
  OAuthGrantSummary,
  OAuthStore,
  OAuthTokenRecord,
  RotateRefreshParams,
  RotateRefreshResult,
  SqlStorageLike,
} from './oauth';
import { cloudflareOverflowFetch, parseHostAllowlist, validateCallRobotsPolicy } from './overflow';
import {
  executeIngestPipeline,
  IngestWorkflow,
  pruneExpiredFetchHistory,
  writeJobManifestToR2,
} from './ingest';
import { executeScrapeCall, type ScrapeRequestPayload } from './scrape';
import {
  buildCapabilities,
  handleAgentArtifactUpload,
  handleArtifactGetRequest,
  hydrateReplyBodiesFromR2,
  MAX_ARTIFACT_CONTENT_BYTES,
  readArtifactPage,
  type ArtifactRetention,
  type OptionalStorageBindings,
} from './storage';

interface Env extends OptionalStorageBindings {
  AGENT_HUB: DurableObjectNamespace<AgentHubDO>;
  CALLER_TOKEN?: string;
  AGENT_TOKEN?: string;
  AGENT_TOKENS?: string;
  USER_AGENT?: string;
  ROBOTS_BYPASS_HOSTS?: string;
  OAUTH_REDIRECT_ALLOWLIST?: string;
}

const JOB_ID_RE = /^[A-Za-z0-9_-]{1,64}$/;
const DEFAULT_UA = 'EdgeFetch/1.0 (+https://github.com/bartrumb/edgefetch)';
const ALLOWED_TARGETS: FetchTarget[] = ['auto', 'agent', 'container'];
const DAILY_CLEANUP_INTERVAL_MS = 24 * 60 * 60_000;
const MAX_SQLITE_TRACKED_HOSTS = 512;

export { IngestWorkflow };

export class AgentHubDO extends DurableObject<Env> {
  private readonly engine: AgentHubEngine;
  private readonly oauth: OAuthStore;
  private readonly activity: ActivityStore;
  private alarmScheduled = false;

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
        CREATE TABLE IF NOT EXISTS host_windows (
          host TEXT PRIMARY KEY,
          next_allowed_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS host_affinities (
          host TEXT PRIMARY KEY,
          site_id TEXT NOT NULL,
          expires_at INTEGER NOT NULL
        );
        ${OAUTH_SQLITE_SCHEMA}
        ${ACTIVITY_SQLITE_SCHEMA}
      `);
      const existingAlarm = await this.ctx.storage.getAlarm();
      if (existingAlarm === null) {
        await this.ctx.storage.setAlarm(Date.now() + DAILY_CLEANUP_INTERVAL_MS);
      }
      this.alarmScheduled = true;
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

    const hostWindows: HostWindowStore = {
      getNextAllowed: (host, now) => {
        const key = host.toLowerCase();
        const rows = this.ctx.storage.sql
          .exec<{ next_allowed_at: number }>('SELECT next_allowed_at FROM host_windows WHERE host = ?', key)
          .toArray();
        const row = rows[0];
        if (!row) return 0;
        if (row.next_allowed_at <= now) {
          this.ctx.storage.sql.exec('DELETE FROM host_windows WHERE host = ?', key);
          return 0;
        }
        return row.next_allowed_at;
      },
      setNextAllowed: (host, nextAllowedAt) => {
        const key = host.toLowerCase();
        const now = Date.now();
        this.ctx.storage.sql.exec('DELETE FROM host_windows WHERE next_allowed_at <= ?', now);
        const rows = this.ctx.storage.sql
          .exec<{ next_allowed_at: number }>('SELECT next_allowed_at FROM host_windows WHERE host = ?', key)
          .toArray();
        if ((rows[0]?.next_allowed_at ?? 0) >= nextAllowedAt) return;
        this.ctx.storage.sql.exec(
          'INSERT OR REPLACE INTO host_windows (host, next_allowed_at) VALUES (?, ?)',
          key,
          nextAllowedAt,
        );
        this.ctx.storage.sql.exec(
          `DELETE FROM host_windows
           WHERE host IN (SELECT host FROM host_windows ORDER BY next_allowed_at DESC LIMIT -1 OFFSET ?)`,
          MAX_SQLITE_TRACKED_HOSTS,
        );
      },
      clearAll: () => {
        this.ctx.storage.sql.exec('DELETE FROM host_windows');
      },
    };

    const affinities: AffinityStore = {
      getStickySite: (host, now) => {
        const key = host.toLowerCase();
        const row = this.ctx.storage.sql
          .exec<{ site_id: string; expires_at: number }>('SELECT site_id, expires_at FROM host_affinities WHERE host = ?', key)
          .toArray()[0];
        if (!row) return null;
        if (row.expires_at <= now) {
          this.ctx.storage.sql.exec('DELETE FROM host_affinities WHERE host = ?', key);
          return null;
        }
        return row.site_id;
      },
      setStickyHost: (host, siteId, expiresAt) => {
        const key = host.toLowerCase();
        this.ctx.storage.sql.exec('DELETE FROM host_affinities WHERE expires_at <= ?', Date.now());
        this.ctx.storage.sql.exec(
          'INSERT OR REPLACE INTO host_affinities (host, site_id, expires_at) VALUES (?, ?, ?)',
          key,
          siteId.toLowerCase(),
          expiresAt,
        );
        this.ctx.storage.sql.exec(
          `DELETE FROM host_affinities
           WHERE host IN (SELECT host FROM host_affinities ORDER BY expires_at DESC LIMIT -1 OFFSET ?)`,
          MAX_SQLITE_TRACKED_HOSTS,
        );
      },
      deleteStickyHost: (host) => {
        this.ctx.storage.sql.exec('DELETE FROM host_affinities WHERE host = ?', host.toLowerCase());
      },
      clearSite: (siteId) => {
        this.ctx.storage.sql.exec('DELETE FROM host_affinities WHERE site_id = ?', siteId.toLowerCase());
      },
      clearAll: () => {
        this.ctx.storage.sql.exec('DELETE FROM host_affinities');
      },
    };

    this.engine = new AgentHubEngine({
      getSockets: (tag) => this.ctx.getWebSockets(tag) as unknown as HubSocketLike[],
      cooldowns,
      hostWindows,
      affinities,
    });
    this.oauth = createSqliteOAuthStore(this.ctx.storage.sql as unknown as SqlStorageLike);
    this.activity = createSqliteActivityStore(this.ctx.storage.sql as unknown as SqlStorageLike);
  }

  override async alarm(): Promise<void> {
    const now = Date.now();
    this.ctx.storage.sql.exec('DELETE FROM site_cooldowns WHERE expires_at <= ?', now);
    this.ctx.storage.sql.exec('DELETE FROM host_windows WHERE next_allowed_at <= ?', now);
    this.ctx.storage.sql.exec('DELETE FROM host_affinities WHERE expires_at <= ?', now);
    this.ctx.storage.sql.exec('DELETE FROM oauth_codes WHERE expires_at <= ?', now);
    this.ctx.storage.sql.exec('DELETE FROM oauth_tokens WHERE expires_at <= ?', now);
    this.ctx.storage.sql.exec('DELETE FROM auth_failures WHERE reset_at <= ?', now);
    await this.ctx.storage.setAlarm(now + DAILY_CLEANUP_INTERVAL_MS);
    this.alarmScheduled = true;
  }

  override async fetch(request: Request): Promise<Response> {
    if (request.headers.get('upgrade')?.toLowerCase() !== 'websocket') {
      return Response.json({ error: 'upgrade_required' }, { status: 426 });
    }
    const siteId = (request.headers.get('x-verified-site') ?? '').trim().toLowerCase();
    const arch = request.headers.get('x-agent-arch');
    const version = request.headers.get('x-agent-version');
    const capabilities = request.headers.get('x-agent-capabilities');
    const publicIp = request.headers.get('x-verified-ip') ?? request.headers.get('cf-connecting-ip');

    const pair = new WebSocketPair();
    const [client, server] = Object.values(pair);
    this.ctx.acceptWebSocket(server, [`site:${siteId}`]);
    const att = this.engine.registerAgent(server as unknown as HubSocketLike, siteId, arch, { version, publicIp, capabilities });
    server.send(JSON.stringify({ type: 'hello', siteId: att.siteId }));
    await this.activity.recordEvent({
      level: 'info',
      category: 'agent',
      event: 'agent_ws_connected',
      summary: `Remote node "${att.siteId}" (${att.version ? `v${att.version}, ` : ''}${att.arch}) connected over WebSocket`,
      details: sanitizeDetails({ siteId: att.siteId, arch: att.arch, version: att.version ?? null }),
    });
    return new Response(null, { status: 101, webSocket: client });
  }

  async listAgents(): Promise<{ connected: number; distinctPublicIps: number; agents: AgentAttachment[] }> {
    return this.engine.listAgents();
  }

  async listAffinities(): Promise<AffinityPin[]> {
    return this.engine.listAffinities();
  }

  async clearAffinities(siteId?: string): Promise<void> {
    this.engine.clearAffinities(siteId);
  }

  async recordHubEvents(events: HubEventInput[]): Promise<void> {
    for (const ev of events) {
      await this.activity.recordEvent(ev);
    }
  }

  async clearHubEvents(): Promise<void> {
    await this.activity.clearEvents();
  }

  async recordMcpCall(params: {
    principal: string;
    authType: 'oauth' | 'bearer_token';
    userAgent: string;
    method: string;
    now?: number;
  }): Promise<void> {
    await this.activity.recordMcpCall(params);
  }

  async getPortalState(now: number): Promise<{
    connected: number;
    distinctPublicIps: number;
    agents: AgentAttachment[];
    affinities: AffinityPin[];
    grants: OAuthGrantSummary[];
    mcpClients: McpClientActivity[];
    events: HubEventRecord[];
  }> {
    const fleet = this.engine.listAgents();
    return {
      ...fleet,
      affinities: this.engine.listAffinities(),
      grants: await this.oauth.listGrants(now),
      mcpClients: await this.activity.listMcpClients(),
      events: await this.activity.listEvents(150),
    };
  }

  async waitForHostWindow(
    hosts: string[],
    pauseMs?: number,
    budgetDeadlineAt?: number,
  ): Promise<{ ok: true } | { ok: false; retryAfterWaitMs: number }> {
    return this.engine.waitForHostWindow(hosts, pauseMs, budgetDeadlineAt);
  }

  async dispatchFetch(
    rawCallBody: string,
    trace: Record<string, string>,
    preferredSite?: string,
    artifactPolicy?: ArtifactDispatchPolicy,
  ): Promise<AgentDispatchResult> {
    return this.engine.dispatchFetch(rawCallBody, trace, {
      preferredSite,
      ...(artifactPolicy ? { artifactPolicy } : {}),
    });
  }

  async hasPendingJob(jobId: string, siteId: string): Promise<boolean> {
    return this.engine.hasPendingJob(jobId, siteId);
  }

  async verifyPendingJob(jobId: string, jobNonce: string, siteId: string): Promise<boolean> {
    return this.engine.verifyPendingJob(jobId, jobNonce, siteId);
  }

  async authorizeArtifactUpload(params: AuthorizeArtifactUploadParams): Promise<AuthorizeArtifactUploadResult> {
    return this.engine.authorizeArtifactUpload(params);
  }

  async failJob(jobId: string, jobNonce: string, siteId: string, reason: string, permanent = true): Promise<CompleteJobResult> {
    return this.engine.failJob(jobId, jobNonce, siteId, reason, permanent);
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
  async oauthRotateRefreshToken(params: RotateRefreshParams): Promise<RotateRefreshResult> {
    return await this.oauth.rotateRefreshToken(params);
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
  async oauthCheckAuthLockout(
    bucket: string,
    now: number,
    maxFailures?: number,
  ): Promise<{ allowed: boolean; retryAfterSec: number }> {
    return await this.oauth.checkAuthLockout(bucket, now, maxFailures);
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
      const msg = JSON.parse(message) as {
        type?: string;
        version?: string;
        arch?: string;
        goVersion?: string;
        capabilities?: string[];
        reconnectAttempt?: number;
      };
      if (msg.type === 'agent_hello') {
        const updated = this.engine.updateAgentHello(ws as unknown as HubSocketLike, msg);
        const att = updated ?? (ws.deserializeAttachment() as AgentAttachment | null);
        const evName = (msg.reconnectAttempt ?? 0) > 0 ? 'agent_reconnected' : 'agent_ready';
        console.info(JSON.stringify({ event: evName, siteId: att?.siteId, ...msg }));
        await this.activity.recordEvent({
          level: (msg.reconnectAttempt ?? 0) > 0 ? 'warn' : 'info',
          category: 'agent',
          event: evName,
          summary: `Remote node "${att?.siteId ?? 'unknown'}" reported ${evName} (${att?.version ? `v${att.version}, ` : ''}${msg.goVersion ?? 'go'}, ${msg.arch ?? ''})`,
          details: sanitizeDetails({ siteId: att?.siteId, ...msg }),
        });
      }
    } catch {
      // ignore malformed frames
    }
  }

  override async webSocketClose(ws: WebSocket, code: number, reason: string): Promise<void> {
    const att = ws.deserializeAttachment() as AgentAttachment | null;
    this.engine.handleDisconnect(ws as unknown as HubSocketLike, reason || `closed_${code}`);
    if (att?.siteId && !att.replaced) {
      await this.activity.recordEvent({
        level: 'warn',
        category: 'agent',
        event: 'agent_ws_closed',
        summary: `Remote node "${att.siteId}" WebSocket closed (code ${code})`,
        details: { siteId: att.siteId, code, reason },
      });
    }
  }

  override async webSocketError(ws: WebSocket): Promise<void> {
    this.engine.handleDisconnect(ws as unknown as HubSocketLike, 'ws_error');
  }
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
    rotateRefreshToken: (p) => hub().oauthRotateRefreshToken(p),
    listGrants: (now) => hub().oauthListGrants(now),
    revokeGrant: (id) => hub().oauthRevokeGrant(id),
    revokeByTokenHash: (h) => hub().oauthRevokeByTokenHash(h),
    checkAuthLockout: (b, now, m) => hub().oauthCheckAuthLockout(b, now, m),
    recordAuthFailure: (b, now, w, m) => hub().oauthRecordAuthFailure(b, now, w, m),
    clearAuthFailures: (b) => hub().oauthClearAuthFailures(b),
  };
}

function hubActivityProxy(hub: () => DurableObjectStub<AgentHubDO>): ActivityStore {
  return {
    recordEvent: (ev) =>
      hub()
        .recordHubEvents([ev])
        .catch(() => undefined),
    listEvents: async () => (await hub().getPortalState(Date.now())).events ?? [],
    clearEvents: () =>
      hub()
        .clearHubEvents()
        .catch(() => undefined),
    recordMcpCall: (p) =>
      hub()
        .recordMcpCall(p)
        .catch(() => undefined),
    listMcpClients: async () => (await hub().getPortalState(Date.now())).mcpClients ?? [],
  };
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const hub = () => env.AGENT_HUB.get(env.AGENT_HUB.idFromName('global'));
    const ua = env.USER_AGENT?.trim() || DEFAULT_UA;

    const bypassAllowlist = parseHostAllowlist(env.ROBOTS_BYPASS_HOSTS);

    const executeHubFetch = async (
      target: FetchTarget,
      body: string,
      site?: string,
      source = 'rest',
      artifactRetention?: ArtifactRetention | 'off',
      hydrateInline = true,
    ) =>
      (tracing as unknown as { enterSpan<T>(n: string, fn: (s: { setAttribute(k: string, v: unknown): void }) => T): T }).enterSpan(
        'edgefetch.dispatch',
        async (span) => {
          const robotsCheck = validateCallRobotsPolicy(body, bypassAllowlist);
          if (!robotsCheck.ok) {
            return {
              status: 400,
              via: 'hub',
              bodyText: JSON.stringify({ error: robotsCheck.error, message: robotsCheck.message }),
            };
          }
          let wantsIncludeBody = false;
          let bodyRetentionOpt: ArtifactRetention | 'off' | undefined;
          try {
            const parsedCall = JSON.parse(body) as {
              options?: { includeBody?: boolean; artifactRetention?: string };
            };
            wantsIncludeBody = Boolean(parsedCall.options?.includeBody);
            const rawOptRet = parsedCall.options?.artifactRetention;
            if (rawOptRet === 'stored' || rawOptRet === 'transient' || rawOptRet === 'off') {
              bodyRetentionOpt = rawOptRet;
            }
          } catch {
            wantsIncludeBody = false;
          }
          const effectiveRetentionPref = artifactRetention ?? bodyRetentionOpt;
          const resolvedRetention: ArtifactRetention | undefined =
            effectiveRetentionPref === 'off'
              ? undefined
              : effectiveRetentionPref ?? (env.ARTIFACTS && wantsIncludeBody ? 'transient' : undefined);
          const artifactPolicy: ArtifactDispatchPolicy | undefined =
            env.ARTIFACTS && (wantsIncludeBody || effectiveRetentionPref === 'stored') && resolvedRetention
              ? { mode: 'r2', retention: resolvedRetention, maxContentBytes: MAX_ARTIFACT_CONTENT_BYTES }
              : undefined;

          const trace = { 'x-request-id': request.headers.get('cf-ray') ?? '' };
          const pendingEvents: HubEventInput[] = [];
          if (robotsCheck.bypassedHosts.length > 0) {
            pendingEvents.push({
              level: 'warn',
              category: 'crawl',
              event: 'robots_bypass_used',
              summary: `Owner-allowlisted robots.txt bypass used for ${robotsCheck.bypassedHosts.join(', ')}`,
              details: { hosts: robotsCheck.bypassedHosts.join(','), source },
            });
          }
          const res = await routeFetchWithFailover({
            target,
            site,
            body,
            trace,
            callAgent: (b, t, s) => hub().dispatchFetch(b, t, s, artifactPolicy),
            callContainer: (b) => cloudflareOverflowFetch(b, ua, url.hostname, { bypassAllowlist }),
            waitForHostWindow: (hosts, p, dl) =>
              hub()
                .waitForHostWindow(hosts, p, dl)
                .catch(() => ({ ok: true as const })),
            onFailover: ({ reason, siteId, count }) => {
              pendingEvents.push({
                level: 'warn',
                category: 'failover',
                event: 'cloudflare_overflow',
                summary: `Cloudflare overflow triggered (${reason}, site=${siteId}, urls=${count})`,
                details: { reason, siteId, count, source },
              });
            },
          });
          const via = res.headers.get('x-crawler-via') ?? target;
          const retryAfter = res.headers.get('retry-after');
          const rawCompletedBody = await res.text();
          let bodyText = rawCompletedBody;
          if (res.status === 200 && env.ARTIFACTS && wantsIncludeBody && hydrateInline) {
            bodyText = await hydrateReplyBodiesFromR2(rawCompletedBody, env.ARTIFACTS);
          }

          // S4: When ARTIFACTS + META are bound, write R2 manifest and trigger idempotent IngestWorkflow (never failing crawl response).
          if (res.status === 200 && env.ARTIFACTS && env.META) {
            const ingestJobId = `job_${crypto.randomUUID().replace(/-/g, '')}`;
            const siteMatch = /^agent:([a-z0-9_-]+)/i.exec(via);
            try {
              const written = await writeJobManifestToR2({
                bucket: env.ARTIFACTS,
                jobId: ingestJobId,
                via,
                ...(siteMatch?.[1] ? { siteId: siteMatch[1] } : {}),
                rawReplyText: rawCompletedBody,
              });
              if (written.ok) {
                const wfParams = {
                  manifestKey: written.manifestKey,
                  jobId: ingestJobId,
                  ...(siteMatch?.[1] ? { siteId: siteMatch[1] } : {}),
                  via,
                };
                if (env.INGEST) {
                  try {
                    await env.INGEST.create({ id: `ingest-${ingestJobId}`, params: wfParams });
                  } catch (wfErr) {
                    const wfMsg = wfErr instanceof Error ? wfErr.message : String(wfErr);
                    if (!/already exists|duplicate/i.test(wfMsg)) {
                      pendingEvents.push({
                        level: 'warn',
                        category: 'crawl',
                        event: 'ingest_workflow_error',
                        summary: `Failed to enqueue IngestWorkflow for ${ingestJobId}: ${wfMsg.slice(0, 140)}`,
                        details: { jobId: ingestJobId, manifestKey: written.manifestKey },
                      });
                    }
                  }
                } else {
                  await executeIngestPipeline(env, wfParams, undefined, {
                    onArtifactRejected: ({ blobSha256, reason, siteId }) => {
                      pendingEvents.push({
                        level: 'warn',
                        category: 'crawl',
                        event: 'artifact_verification_failed',
                        summary: `Rejected unverified artifact ${blobSha256.slice(0, 12)} (${reason})`,
                        details: { jobId: ingestJobId, blobSha256, reason, siteId: siteId ?? null },
                      });
                    },
                  });
                }
              }
            } catch (manifestErr) {
              const mMsg = manifestErr instanceof Error ? manifestErr.message : String(manifestErr);
              pendingEvents.push({
                level: 'warn',
                category: 'crawl',
                event: 'ingest_manifest_error',
                summary: `Failed to write R2 ingest manifest: ${mMsg.slice(0, 140)}`,
              });
            }
          }
          pendingEvents.push(...buildCrawlActivityEvents({ source, target, via, httpStatus: res.status, replyText: bodyText }));
          await hub()
            .recordHubEvents(pendingEvents)
            .catch(() => undefined);
          span.setAttribute('edgefetch.via', via);
          return { status: res.status, via, bodyText, ...(retryAfter ? { retryAfter } : {}) };
        },
      );

    try {
      if (request.method === 'GET' && url.pathname === '/health') {
        return Response.json({ ok: true });
      }
      if (url.pathname === '/agent/ws') {
        const auth = authorizeAgent(request, env);
        if (!auth.ok) return Response.json({ error: 'unauthorized' }, { status: 401 });
        const headers = new Headers(request.headers);
        headers.set('x-verified-site', auth.siteId);
        const clientIp = request.headers.get('cf-connecting-ip') ?? request.headers.get('x-forwarded-for');
        if (clientIp) headers.set('x-verified-ip', clientIp);
        return await hub().fetch(new Request(request.url, { method: 'GET', headers }));
      }
      if (request.method === 'PUT' && url.pathname.startsWith('/agent/artifacts/')) {
        const auth = authorizeAgent(request, env);
        if (!auth.ok) {
          await request.body?.cancel().catch(() => undefined);
          return Response.json({ error: 'unauthorized' }, { status: 401 });
        }
        const blobSha256 = url.pathname.slice('/agent/artifacts/'.length).trim();
        return await handleAgentArtifactUpload({
          request,
          blobSha256,
          siteId: auth.siteId,
          bucket: env.ARTIFACTS,
          authorizeJobUpload: (p) => hub().authorizeArtifactUpload(p),
        });
      }
      if (request.method === 'POST' && url.pathname === '/agent/reply') {
        const auth = authorizeAgent(request, env);
        if (!auth.ok) return Response.json({ error: 'unauthorized' }, { status: 401 });
        const jobId = (request.headers.get('x-job-id') ?? '').trim();
        const jobNonce = (request.headers.get('x-job-nonce') ?? '').trim();
        if (!JOB_ID_RE.test(jobId) || !JOB_ID_RE.test(jobNonce)) return Response.json({ error: 'bad_job_headers' }, { status: 400 });
        if (!(await hub().verifyPendingJob(jobId, jobNonce, auth.siteId))) {
          return Response.json({ error: 'unknown_job' }, { status: 404 });
        }
        const payload = await readAgentReplyBody(request);
        if (!payload.ok) {
          await hub().failJob(jobId, jobNonce, auth.siteId, payload.error, payload.error === 'too_large');
          return Response.json({ error: payload.error }, { status: payload.status });
        }
        const done = await hub().completeJob(jobId, jobNonce, auth.siteId, payload.text);
        return Response.json({ ok: done.ok }, { status: done.status });
      }

      const oauthStore = hubOAuthStore(hub);
      const activity = hubActivityProxy(hub);

      const oauthRes = await handleOAuthRoute(request, url, {
        store: oauthStore,
        ownerSecret: env.CALLER_TOKEN,
        serviceName: 'EdgeFetch Hub',
        redirectAllowlist: parseHostAllowlist(env.OAUTH_REDIRECT_ALLOWLIST),
        onEvent: (ev) => activity.recordEvent({ ...ev, details: sanitizeDetails(ev.details) }),
      });
      if (oauthRes) return oauthRes;

      if (url.pathname === '/mcp') {
        return await handleMcpRequest(request, url, {
          serverName: 'edgefetch-hub',
          serverVersion: '1.2.0',
          ownerSecret: env.CALLER_TOKEN,
          oauthStore,
          activity,
          allowedTargets: ALLOWED_TARGETS,
          defaultTarget: 'auto',
          listFleet: async () => {
            const state = await hub().getPortalState(Date.now());
            return { connected: state.connected, agents: state.agents, affinities: state.affinities };
          },
          executeFetch: ({ target, site, body, principal }) =>
            executeHubFetch(target, body, site, `mcp:${principal ?? 'client'}`),
          executeScrape: async ({ args, principal }) => {
            const out = await executeScrapeCall({
              payload: args as ScrapeRequestPayload,
              env,
              executeHubFetch,
              source: `mcp-scrape:${principal ?? 'client'}`,
            });
            return { status: out.status, body: out.body };
          },
          ...(env.ARTIFACTS
            ? {
                readArtifact: async ({ blobSha256, retention, offset, limit }) => {
                  const res = await readArtifactPage({
                    bucket: env.ARTIFACTS!,
                    ...(env.META ? { metaDb: env.META } : {}),
                    blobSha256,
                    ...(retention ? { retention } : {}),
                    offset,
                    limit,
                  });
                  return res.ok
                    ? { ok: true as const, page: res.page as unknown as Record<string, unknown> }
                    : { ok: false as const, status: res.status, error: res.error };
                },
              }
            : {}),
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
        clearEvents: () => hub().clearHubEvents(),
        revokeGrant: async (grantId) => {
          const revoked = await hub().oauthRevokeGrant(grantId);
          if (revoked) {
            await activity.recordEvent({
              level: 'warn',
              category: 'oauth',
              event: 'oauth_grant_revoked',
              summary: `Revoked OAuth 2.1 grant ${grantId} from /admin`,
              details: { grantId },
            });
          }
          return revoked;
        },
        executeFetch: ({ target, site, body }) => executeHubFetch(target, body, site, 'admin'),
      });
      if (adminRes) return adminRes;

      if (request.method === 'GET' && url.pathname === '/v1/capabilities') {
        const auth = await authorizeMcpRequest({
          request,
          origin: url.origin,
          ownerSecret: env.CALLER_TOKEN,
          store: oauthStore,
        });
        if (!auth.ok) {
          return Response.json(
            { error: 'unauthorized' },
            { status: 401, headers: { 'cache-control': 'no-store', 'www-authenticate': auth.wwwAuthenticate } },
          );
        }
        return Response.json(buildCapabilities(env, '1.2.0'), {
          status: 200,
          headers: { 'cache-control': 'no-store' },
        });
      }

      if (request.method === 'GET' && url.pathname.startsWith('/v1/artifacts/')) {
        const auth = await authorizeMcpRequest({
          request,
          origin: url.origin,
          ownerSecret: env.CALLER_TOKEN,
          store: oauthStore,
        });
        if (!auth.ok) {
          return Response.json(
            { error: 'unauthorized' },
            { status: 401, headers: { 'cache-control': 'no-store', 'www-authenticate': auth.wwwAuthenticate } },
          );
        }
        const blobSha256 = url.pathname.slice('/v1/artifacts/'.length).trim().toLowerCase();
        return await handleArtifactGetRequest({
          request,
          url,
          blobSha256,
          bucket: env.ARTIFACTS,
          metaDb: env.META,
        });
      }

      if (request.method === 'POST' && url.pathname === '/v1/scrape') {
        const auth = await authorizeMcpRequest({
          request,
          origin: url.origin,
          ownerSecret: env.CALLER_TOKEN,
          store: oauthStore,
        });
        if (!auth.ok) {
          return Response.json(
            { error: 'unauthorized' },
            { status: 401, headers: { 'cache-control': 'no-store', 'www-authenticate': auth.wwwAuthenticate } },
          );
        }
        if (!auth.scopes.includes('crawl:fetch')) {
          return Response.json({ error: 'insufficient_scope' }, { status: 403, headers: { 'cache-control': 'no-store' } });
        }
        const rawScrapeText = await request.text();
        if (new TextEncoder().encode(rawScrapeText).byteLength > MAX_CALL_UTF8_BYTES) {
          return Response.json({ error: 'too_large' }, { status: 413 });
        }
        let payload: ScrapeRequestPayload;
        try {
          payload = JSON.parse(rawScrapeText) as ScrapeRequestPayload;
        } catch {
          return Response.json({ error: 'bad_json' }, { status: 400 });
        }
        const out = await executeScrapeCall({
          payload,
          env,
          executeHubFetch,
          source: `scrape:${auth.principal}`,
        });
        return Response.json(out.body, {
          status: out.status,
          headers: {
            'cache-control': 'no-store',
            'x-crawler-via': out.via,
            ...(out.retryAfter ? { 'retry-after': out.retryAfter } : {}),
          },
        });
      }

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
        if (new TextEncoder().encode(body).byteLength > MAX_CALL_UTF8_BYTES) {
          return Response.json({ error: 'too_large' }, { status: 413 });
        }
        const rawRetention = url.searchParams.get('artifacts');
        const artifactRetention: ArtifactRetention | 'off' | undefined =
          rawRetention === 'stored'
            ? 'stored'
            : rawRetention === 'transient'
              ? 'transient'
              : rawRetention === 'off'
                ? 'off'
                : undefined;
        const hydrateInline = url.searchParams.get('hydrate') !== 'false' && url.searchParams.get('hydrate') !== '0';
        const out = await executeHubFetch(parsedTarget.target, body, parsedTarget.site, 'rest', artifactRetention, hydrateInline);
        return new Response(out.bodyText, {
          status: out.status,
          headers: {
            'content-type': 'application/json',
            'x-crawler-via': out.via,
            'cache-control': 'no-store',
            ...(out.retryAfter ? { 'retry-after': out.retryAfter } : {}),
          },
        });
      }
      return Response.json({ error: 'not_found' }, { status: 404 });
    } catch (e) {
      return Response.json(
        {
          error: 'hub_unavailable',
          message: e instanceof Error ? e.message : 'Coordinator temporarily unavailable; please retry',
        },
        { status: 503, headers: { 'cache-control': 'no-store' } },
      );
    }
  },

  async scheduled(_controller: ScheduledController, env: Env): Promise<void> {
    if (env.META) {
      await pruneExpiredFetchHistory(env.META).catch(() => undefined);
    }
  },
};
