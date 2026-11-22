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
  computeNextHostHealth,
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
  type HostHealthRecord,
  type HostHealthStore,
  type HostWindowStore,
  type HubSocketLike,
} from './agent-hub';
import {
  cancelAgentRun,
  findRelevantAdapters,
  formatPublicAgentResponse,
  loadAgentRun,
  startOrExecuteAgentCall,
} from './agent-runner';
import { authorizeAgent, isCallerAuthorized } from './auth';
import { handleBotTransparencyRoutes, type BotAuthEnv } from './bot-auth';
import { handleCompatRoutes } from './compat';
import {
  executeCatalogCall,
  getCatalogRecords,
  getCatalogStatus,
  type CatalogCallPayload,
  type CatalogHubFetchFn,
} from './catalog';
import { executeJobsCall, type JobsToolPayload } from './jobs';
import {
  cancelBatchScrape,
  cancelCrawlJob,
  CrawlWorkflow,
  createCrawlJob,
  executeCrawlJob,
  executeMapCall,
  getBatchScrapeStatus,
  getCrawlJobStatus,
  previewCrawlParams,
  startOrExecuteBatchScrape,
  type MapRequestPayload,
} from './map-crawl';
import { handleMcpRequest } from './mcp';
import { handleOpenApiRoute } from './openapi';
import { authorizeMcpRequest, createSqliteOAuthStore, handleOAuthRoute, OAUTH_SQLITE_SCHEMA } from './oauth';
import type {
  HubUserRecord,
  OAuthClientRecord,
  OAuthCodeRecord,
  OAuthGrantSummary,
  OAuthStore,
  OAuthTokenRecord,
  RotateRefreshParams,
  RotateRefreshResult,
  SqlStorageLike,
  UserRole,
} from './oauth';
import { isGitHubAuthConfigured, resolveSessionSecret, type GitHubAuthEnv } from './github-auth';
import {
  buildCrawlChildSpans,
  getActiveRequestTracer,
  injectTraceHeaders,
  RequestTracer,
  sanitizeUrlForSpan,
  setActiveSpanAttribute,
  type OtelEnvConfig,
} from './otel';
import { cloudflareOverflowFetch, parseHostAllowlist, validateCallRobotsPolicy } from './overflow';
import { readBodyTextCapped, safeDecodeURIComponent } from './safe-input';
import {
  executeIngestPipeline,
  IngestWorkflow,
  pruneExpiredFetchHistory,
  sha256HexString,
  writeJobManifestToR2,
} from './ingest';
import {
  executeInteractCall,
  executeScrapeCall,
  extractHtmlDocument,
  SCRAPE_PIPELINE_VERSION,
  type InteractRequestPayload,
  type ScrapeRequestPayload,
} from './scrape';
import {
  COLLECTION_ID_RE,
  D1FtsSearchIndex,
  executeExtractCall,
  resolveUserCollectionId,
  type ExtractRequestPayload,
} from './search-index';
import { executeSearchCall, type SearchRequestPayload } from './web-search';
import { listRegisteredAdapters } from './extractors/registry';
import {
  buildCapabilities,
  handleAgentArtifactUpload,
  handleArtifactGetRequest,
  hydrateReplyBodiesFromR2,
  MAX_ARTIFACT_CONTENT_BYTES,
  normalizeVisibility,
  r2DerivedKey,
  r2PrivateDerivedKey,
  readArtifactPage,
  sanitizeStorageUserId,
  type ArtifactRetention,
  type OptionalStorageBindings,
} from './storage';

interface Env extends OptionalStorageBindings, OtelEnvConfig, BotAuthEnv, GitHubAuthEnv {
  AGENT_HUB: DurableObjectNamespace<AgentHubDO>;
  HUB_SHARDS?: string;
  SAFE_FETCH?: typeof fetch;
  SAFE_PUBLIC_FETCH?: typeof fetch;
  CALLER_TOKEN?: string;
  MCP_TOKEN?: string;
  AGENT_TOKEN?: string;
  AGENT_TOKENS?: string;
  USER_AGENT?: string;
  ROBOTS_BYPASS_HOSTS?: string;
  OAUTH_REDIRECT_ALLOWLIST?: string;
  SERPER_API_KEY?: string;
  BRAVE_API_KEY?: string;
  TAVILY_API_KEY?: string;
  SEARXNG_URL?: string;
  WEBHOOK_SECRET?: string;
}

const JOB_ID_RE = /^[A-Za-z0-9_-]{1,64}$/;
const DEFAULT_UA = 'EdgeFetch/2.6 (bot@edgefetch.dev)';
const ALLOWED_TARGETS: FetchTarget[] = ['auto', 'agent', 'container'];
const DAILY_CLEANUP_INTERVAL_MS = 24 * 60 * 60_000;
const MAX_SQLITE_TRACKED_HOSTS = 512;

export { CrawlWorkflow, IngestWorkflow };

export class AgentHubDO extends DurableObject<Env> {
  private readonly engine: AgentHubEngine;
  private readonly oauth: OAuthStore;
  private readonly activity: ActivityStore;
  private readonly helloLogBySocket = new WeakMap<WebSocket, number>();
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
        CREATE TABLE IF NOT EXISTS host_health (
          host TEXT PRIMARY KEY,
          ok_count INTEGER NOT NULL,
          rate_limit_count INTEGER NOT NULL,
          challenge_count INTEGER NOT NULL,
          error_5xx_count INTEGER NOT NULL,
          rate_limit_streak INTEGER NOT NULL,
          ewma_ttfb_ms INTEGER NOT NULL,
          recommended_pause_ms INTEGER NOT NULL,
          last_waf_vendor TEXT,
          updated_at INTEGER NOT NULL
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

    const hostHealth: HostHealthStore = {
      recordOutcome: (params) => {
        const key = params.host.toLowerCase();
        if (!key) return;
        const row = this.ctx.storage.sql
          .exec<{
            host: string;
            ok_count: number;
            rate_limit_count: number;
            challenge_count: number;
            error_5xx_count: number;
            rate_limit_streak: number;
            ewma_ttfb_ms: number;
            recommended_pause_ms: number;
            last_waf_vendor: string | null;
            updated_at: number;
          }>('SELECT * FROM host_health WHERE host = ?', key)
          .toArray()[0];
        const prev: HostHealthRecord | undefined = row
          ? {
              host: row.host,
              okCount: row.ok_count,
              rateLimit429Count: row.rate_limit_count,
              challengeCount: row.challenge_count,
              error5xxCount: row.error_5xx_count,
              rateLimitStreak: row.rate_limit_streak,
              ewmaTtfbMs: row.ewma_ttfb_ms,
              recommendedPauseMs: row.recommended_pause_ms,
              ...(row.last_waf_vendor ? { lastWafVendor: row.last_waf_vendor } : {}),
              updatedAt: row.updated_at,
            }
          : undefined;
        const next = computeNextHostHealth(prev, params);
        this.ctx.storage.sql.exec(
          `INSERT OR REPLACE INTO host_health (
             host, ok_count, rate_limit_count, challenge_count, error_5xx_count,
             rate_limit_streak, ewma_ttfb_ms, recommended_pause_ms, last_waf_vendor, updated_at
           ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
          next.host,
          next.okCount,
          next.rateLimit429Count,
          next.challengeCount,
          next.error5xxCount,
          next.rateLimitStreak,
          next.ewmaTtfbMs,
          next.recommendedPauseMs,
          next.lastWafVendor ?? null,
          next.updatedAt,
        );
        this.ctx.storage.sql.exec(
          `DELETE FROM host_health
           WHERE host IN (SELECT host FROM host_health ORDER BY updated_at DESC LIMIT -1 OFFSET ?)`,
          MAX_SQLITE_TRACKED_HOSTS,
        );
      },
      getRecommendedPauseMs: (host) => {
        const row = this.ctx.storage.sql
          .exec<{ recommended_pause_ms: number }>('SELECT recommended_pause_ms FROM host_health WHERE host = ?', host.toLowerCase())
          .toArray()[0];
        return row?.recommended_pause_ms ?? 0;
      },
      listHosts: (limit = 100) => {
        const cap = Math.max(1, Math.min(500, Math.floor(limit)));
        return this.ctx.storage.sql
          .exec<{
            host: string;
            ok_count: number;
            rate_limit_count: number;
            challenge_count: number;
            error_5xx_count: number;
            rate_limit_streak: number;
            ewma_ttfb_ms: number;
            recommended_pause_ms: number;
            last_waf_vendor: string | null;
            updated_at: number;
          }>('SELECT * FROM host_health ORDER BY updated_at DESC LIMIT ?', cap)
          .toArray()
          .map((row) => ({
            host: row.host,
            okCount: row.ok_count,
            rateLimit429Count: row.rate_limit_count,
            challengeCount: row.challenge_count,
            error5xxCount: row.error_5xx_count,
            rateLimitStreak: row.rate_limit_streak,
            ewmaTtfbMs: row.ewma_ttfb_ms,
            recommendedPauseMs: row.recommended_pause_ms,
            ...(row.last_waf_vendor ? { lastWafVendor: row.last_waf_vendor } : {}),
            updatedAt: row.updated_at,
          }));
      },
      clearAll: () => {
        this.ctx.storage.sql.exec('DELETE FROM host_health');
      },
    };

    this.engine = new AgentHubEngine({
      getSockets: (tag) => this.ctx.getWebSockets(tag) as unknown as HubSocketLike[],
      cooldowns,
      hostWindows,
      affinities,
      hostHealth,
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
    this.ctx.storage.sql.exec('DELETE FROM admin_revocations WHERE expires_at <= ?', now);
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
    const browserVersion = request.headers.get('x-agent-browser-version');
    const browserSandbox = request.headers.get('x-agent-browser-sandbox');
    const capabilities = request.headers.get('x-agent-capabilities');
    const publicIp = request.headers.get('x-verified-ip') ?? request.headers.get('cf-connecting-ip');

    const pair = new WebSocketPair();
    const [client, server] = Object.values(pair);
    this.ctx.acceptWebSocket(server, [`site:${siteId}`]);
    const att = this.engine.registerAgent(server as unknown as HubSocketLike, siteId, arch, {
      version,
      browserVersion,
      browserSandbox,
      publicIp,
      capabilities,
    });
    server.send(JSON.stringify({ type: 'hello', siteId: att.siteId }));
    await this.activity.recordEvent({
      level: 'info',
      category: 'agent',
      event: 'agent_ws_connected',
      summary: `Remote node "${att.siteId}" (${att.version ? `v${att.version}, ` : ''}${att.arch}) connected over WebSocket`,
      details: sanitizeDetails({ siteId: att.siteId, arch: att.arch, version: att.version ?? null }),
    });
    const selectedProto = (request.headers.get('sec-websocket-protocol') ?? '')
      .split(',')
      .map((s) => s.trim())
      .find((s) => s === 'edgefetch-agent');
    return new Response(null, {
      status: 101,
      webSocket: client,
      ...(selectedProto ? { headers: { 'sec-websocket-protocol': selectedProto } } : {}),
    });
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

  async listHostHealth(limit = 100): Promise<HostHealthRecord[]> {
    return this.engine.listHostHealth(limit);
  }

  async recordHostOutcome(params: {
    host: string;
    status: number;
    outcome: string;
    ttfbMs?: number;
    retryAfterMs?: number;
    wafVendor?: string;
  }): Promise<void> {
    this.engine.recordHostOutcome(params);
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
    users: HubUserRecord[];
  }> {
    const fleet = this.engine.listAgents();
    return {
      ...fleet,
      affinities: this.engine.listAffinities(),
      grants: await this.oauth.listGrants(now),
      mcpClients: await this.activity.listMcpClients(),
      events: this.activity.listPortalEvents
        ? await this.activity.listPortalEvents(75, 75)
        : await this.activity.listEvents(150),
      users: this.oauth.listUsers ? await this.oauth.listUsers() : [],
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
    userId?: string;
    userRole?: UserRole;
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
  async oauthListGrants(now: number, userId?: string): Promise<OAuthGrantSummary[]> {
    return await this.oauth.listGrants(now, userId);
  }
  async oauthRevokeGrant(id: string, userId?: string): Promise<boolean> {
    return await this.oauth.revokeGrant(id, userId);
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
  async oauthUpsertUser(u: HubUserRecord): Promise<HubUserRecord> {
    if (!this.oauth.upsertUser) return u;
    return await this.oauth.upsertUser(u);
  }
  async oauthGetUser(id: string): Promise<HubUserRecord | null> {
    return this.oauth.getUser ? await this.oauth.getUser(id) : null;
  }
  async oauthListUsers(): Promise<HubUserRecord[]> {
    return this.oauth.listUsers ? await this.oauth.listUsers() : [];
  }
  async oauthCountUsers(): Promise<number> {
    return this.oauth.countUsers ? await this.oauth.countUsers() : 0;
  }
  async oauthUpdateUserRole(id: string, role: UserRole): Promise<boolean> {
    return this.oauth.updateUserRole ? await this.oauth.updateUserRole(id, role) : false;
  }

  override async webSocketMessage(ws: WebSocket, message: string | ArrayBuffer): Promise<void> {
    if (typeof message !== 'string' || message === 'ping' || message.length > 2048) return;
    try {
      const msg = JSON.parse(message) as {
        type?: string;
        version?: string;
        arch?: string;
        goVersion?: string;
        browserVersion?: string;
        browserSandbox?: string | boolean;
        capabilities?: string[];
        reconnectAttempt?: number;
      };
      if (msg.type === 'agent_hello' || msg.type === 'hello') {
        const updated = this.engine.updateAgentHello(ws as unknown as HubSocketLike, msg);
        const att = updated ?? (ws.deserializeAttachment() as AgentAttachment | null);
        const evName = (msg.reconnectAttempt ?? 0) > 0 ? 'agent_reconnected' : 'agent_ready';
        const nowMs = Date.now();
        const lastHelloAt = this.helloLogBySocket.get(ws) ?? 0;
        // M9: Rate-limit `agent_hello` ring-buffer writes per socket, log at `'info'` so agents cannot flush the
        // `'warn'`/`'error'` security ring, and spread `...msg` FIRST so `msg.siteId` never overwrites verified `att.siteId`!
        if (nowMs - lastHelloAt >= 60_000) {
          this.helloLogBySocket.set(ws, nowMs);
          console.info(JSON.stringify({ ...msg, event: evName, siteId: att?.siteId }));
          await this.activity.recordEvent({
            level: 'info',
            category: 'agent',
            event: evName,
            summary: `Remote node "${att?.siteId ?? 'unknown'}" reported ${evName} (${att?.version ? `v${att.version}, ` : ''}${msg.goVersion ?? 'go'}, ${msg.arch ?? ''})`,
            details: sanitizeDetails({ ...msg, siteId: att?.siteId }),
          });
        }
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
    listGrants: (now, userId) => hub().oauthListGrants(now, userId),
    revokeGrant: (id, userId) => hub().oauthRevokeGrant(id, userId),
    revokeByTokenHash: (h) => hub().oauthRevokeByTokenHash(h),
    checkAuthLockout: (b, now, m) => hub().oauthCheckAuthLockout(b, now, m),
    recordAuthFailure: (b, now, w, m) => hub().oauthRecordAuthFailure(b, now, w, m),
    clearAuthFailures: (b) => hub().oauthClearAuthFailures(b),
    upsertUser: (u) => hub().oauthUpsertUser(u),
    getUser: (id) => hub().oauthGetUser(id),
    listUsers: () => hub().oauthListUsers(),
    countUsers: () => hub().oauthCountUsers(),
    updateUserRole: (id, role) => hub().oauthUpdateUserRole(id, role),
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

function resolveCompatSpanMeta(pathname: string): { spanName: string; flavor: 'firecrawl_v2' | 'tavily' } | null {
  if (pathname.startsWith('/compat/tavily/')) {
    if (pathname === '/compat/tavily/search') return { spanName: 'edgefetch.search', flavor: 'tavily' };
    if (pathname === '/compat/tavily/extract') return { spanName: 'edgefetch.extract', flavor: 'tavily' };
    if (pathname === '/compat/tavily/map') return { spanName: 'edgefetch.map', flavor: 'tavily' };
    return { spanName: 'edgefetch.compat', flavor: 'tavily' };
  }
  let sub: string | null = null;
  if (pathname.startsWith('/v2/')) sub = pathname.slice('/v2'.length);
  else if (pathname.startsWith('/compat/firecrawl/v2/')) sub = pathname.slice('/compat/firecrawl/v2'.length);
  if (sub === null) return null;
  if (sub === '/scrape') return { spanName: 'edgefetch.scrape', flavor: 'firecrawl_v2' };
  if (sub === '/extract' || sub.startsWith('/extract/')) return { spanName: 'edgefetch.extract', flavor: 'firecrawl_v2' };
  if (sub === '/map') return { spanName: 'edgefetch.map', flavor: 'firecrawl_v2' };
  if (sub === '/crawl' || sub.startsWith('/crawl/')) return { spanName: 'edgefetch.crawl', flavor: 'firecrawl_v2' };
  if (sub === '/batch/scrape' || sub.startsWith('/batch/scrape/')) return { spanName: 'edgefetch.batch_scrape', flavor: 'firecrawl_v2' };
  if (sub === '/search') return { spanName: 'edgefetch.search', flavor: 'firecrawl_v2' };
  if (sub === '/agent' || sub.startsWith('/agent/')) return { spanName: 'edgefetch.agent', flavor: 'firecrawl_v2' };
  return { spanName: 'edgefetch.compat', flavor: 'firecrawl_v2' };
}

function wrapSseResponseWithFlush(res: Response, onClose: () => void | Promise<unknown>): Response {
  const body = res.body;
  if (!body) return res;
  const reader = body.getReader();
  let closed = false;
  const finish = async () => {
    if (closed) return;
    closed = true;
    await Promise.resolve(onClose()).catch(() => undefined);
  };
  const wrapped = new ReadableStream<Uint8Array>({
    async pull(controller) {
      let streamEnded = false;
      try {
        const { done, value } = await reader.read();
        if (done) {
          streamEnded = true;
          await finish();
          controller.close();
          return;
        }
        if (value) controller.enqueue(value);
      } catch (err) {
        streamEnded = true;
        throw err;
      } finally {
        if (streamEnded) await finish();
      }
    },
    async cancel(reason) {
      await reader.cancel(reason).catch(() => undefined);
      await finish();
    },
  });
  return new Response(wrapped, {
    status: res.status,
    statusText: res.statusText,
    headers: new Headers(res.headers),
  });
}

export default {
  async fetch(request: Request, env: Env, ctx?: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);
    const rootTracer = RequestTracer.fromRequest(request, { suppressWhenUnsampledHealth: true });
    const trackedCtx: ExecutionContext | undefined = ctx
      ? ({
          waitUntil(promise: Promise<unknown>) {
            const active = getActiveRequestTracer() ?? rootTracer;
            const wrapped = active
              .bindPromise(promise)
              .catch(() => undefined)
              .finally(() => rootTracer.flush({ env, fetchFn: env.SAFE_FETCH }).catch(() => false));
            ctx.waitUntil(wrapped);
          },
          passThroughOnException() {
            ctx.passThroughOnException?.();
          },
        } as unknown as ExecutionContext)
      : undefined;
    const shardNames = (env.HUB_SHARDS ?? 'global')
      .split(',')
      .map((s) => s.trim())
      .filter((s) => /^[a-z0-9_-]{1,32}$/i.test(s));
    if (shardNames.length === 0) shardNames.push('global');
    const hubShard = (name = shardNames[0]!) => env.AGENT_HUB.get(env.AGENT_HUB.idFromName(name));
    const hub = () => hubShard(shardNames[0]!);
    const dispatchAcrossShards = async (
      rawBody: string,
      traceMap: Record<string, string>,
      preferredSite?: string,
      policy?: ArtifactDispatchPolicy,
    ): Promise<AgentDispatchResult> => {
      let lastRes: AgentDispatchResult | undefined;
      let lastErr: unknown;
      for (const sName of shardNames) {
        try {
          const out = await hubShard(sName).dispatchFetch(rawBody, traceMap, preferredSite, policy);
          if (out.ok || shardNames.length === 1 || out.error === 'bad_request' || out.error === 'too_large') {
            return out;
          }
          lastRes = out;
        } catch (err) {
          lastErr = err;
        }
      }
      if (lastRes) return lastRes;
      throw lastErr instanceof Error ? lastErr : new Error('hub_shard_unavailable');
    };
    const ua = env.USER_AGENT?.trim() || DEFAULT_UA;

    const bypassAllowlist = parseHostAllowlist(env.ROBOTS_BYPASS_HOSTS);

    const executeHubFetch = async (
      target: FetchTarget,
      body: string,
      site?: string,
      source = 'rest',
      artifactRetention?: ArtifactRetention | 'off',
      hydrateInline = true,
      collectionId?: string,
      crawlId?: string,
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
              retryAfter: undefined as string | undefined,
              stageTimingsMs: undefined as { dispatchMs: number; hydrateR2Ms: number; totalHubMs: number } | undefined,
            };
          }
          let wantsIncludeBody = false;
          let bodyRetentionOpt: ArtifactRetention | 'off' | undefined;
          let bodyCollectionId: string | undefined;
          try {
            const parsedCall = JSON.parse(body) as {
              options?: { includeBody?: boolean; artifactRetention?: string; collectionId?: string };
            };
            wantsIncludeBody = Boolean(parsedCall.options?.includeBody);
            const rawOptRet = parsedCall.options?.artifactRetention;
            if (rawOptRet === 'stored' || rawOptRet === 'transient' || rawOptRet === 'off') {
              bodyRetentionOpt = rawOptRet;
            }
            const rawColl = parsedCall.options?.collectionId;
            if (typeof rawColl === 'string' && COLLECTION_ID_RE.test(rawColl.trim())) {
              bodyCollectionId = rawColl.trim();
            }
          } catch {
            wantsIncludeBody = false;
          }
          const resolvedCollectionId = collectionId ?? bodyCollectionId;
          const effectiveRetentionPref = artifactRetention ?? bodyRetentionOpt ?? (resolvedCollectionId && env.ARTIFACTS && env.META ? 'stored' : undefined);
          const resolvedRetention: ArtifactRetention | undefined =
            effectiveRetentionPref === 'off'
              ? undefined
              : effectiveRetentionPref ?? (env.ARTIFACTS && wantsIncludeBody ? 'transient' : undefined);
          const artifactPolicy: ArtifactDispatchPolicy | undefined =
            env.ARTIFACTS && (wantsIncludeBody || effectiveRetentionPref === 'stored') && resolvedRetention
              ? { mode: 'r2', retention: resolvedRetention, maxContentBytes: MAX_ARTIFACT_CONTENT_BYTES }
              : undefined;

          const startedAtMs = Date.now();
          const activeParent = getActiveRequestTracer();
          const localTracer = activeParent ?? RequestTracer.fromRequest(request);
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

          const dispatchResult = await localTracer.run(() =>
            localTracer.withSpan(
              'edgefetch.dispatch',
              {
                kind: 2,
                startTimeMs: startedAtMs,
                attributes: {
                  'crawler.target': target,
                  'crawler.source': source,
                },
              },
              async (dispatchSpan) => {
                const trace = getActiveRequestTracer()?.getTraceHeaders() ?? localTracer.getTraceHeaders();
                let botAuthSigned = false;
                const dispatchStartMs = Date.now();
                const res = await routeFetchWithFailover({
                  target,
                  site,
                  body,
                  trace,
                  callAgent: (b, t, s) => dispatchAcrossShards(b, t, s, artifactPolicy),
                  callContainer: (b, t) =>
                    cloudflareOverflowFetch(b, ua, url.hostname, {
                      bypassAllowlist,
                      trace: t,
                      onBotAuthSigned: () => {
                        botAuthSigned = true;
                      },
                      ...(env.SAFE_PUBLIC_FETCH ? { fetchFn: env.SAFE_PUBLIC_FETCH } : env.SAFE_FETCH ? { fetchFn: env.SAFE_FETCH } : {}),
                      ...(env.BOT_SIGNING_PRIVATE_KEY?.trim()
                        ? {
                            botAuth: {
                              privateKey: env.BOT_SIGNING_PRIVATE_KEY.trim(),
                              directoryUrl: `${url.origin}/.well-known/http-message-signatures-directory`,
                            },
                          }
                        : {}),
                    }),
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
                const dispatchMs = Date.now() - dispatchStartMs;
                const via = res.headers.get('x-crawler-via') ?? target;
                const retryAfter = res.headers.get('retry-after');
                const rawCompletedBody = await res.text();
                let bodyText = rawCompletedBody;
                let hydrateR2Ms = 0;
                if (res.status === 200 && env.ARTIFACTS && wantsIncludeBody && hydrateInline) {
                  const hydStart = Date.now();
                  bodyText = await hydrateReplyBodiesFromR2(rawCompletedBody, env.ARTIFACTS);
                  hydrateR2Ms = Date.now() - hydStart;
                }

                // P12 & S4: Move R2 manifest write + Cloudflare Workflows `INGEST.create(...)` + activity-log RPC off the
                // synchronous HTTP response path into `ctx.waitUntil(...)` whenever `env.INGEST` and `ctx.waitUntil` are bound!
                const runPostFetchPersistence = async () => {
                  if (res.status === 200 && effectiveRetentionPref !== 'off' && env.ARTIFACTS && env.META) {
                    const ingestJobId = `job_${crypto.randomUUID().replace(/-/g, '')}`;
                    const siteMatch = /^agent:([a-z0-9_-]+)/i.exec(via);
                    try {
                      const written = await writeJobManifestToR2({
                        bucket: env.ARTIFACTS,
                        jobId: ingestJobId,
                        via,
                        ...(siteMatch?.[1] ? { siteId: siteMatch[1] } : {}),
                        ...(resolvedCollectionId ? { collectionId: resolvedCollectionId } : {}),
                        ...(crawlId ? { crawlId } : {}),
                        rawReplyText: rawCompletedBody,
                      });
                      if (written.ok) {
                        const wfParams = {
                          manifestKey: written.manifestKey,
                          jobId: ingestJobId,
                          ...(siteMatch?.[1] ? { siteId: siteMatch[1] } : {}),
                          ...(resolvedCollectionId ? { collectionId: resolvedCollectionId } : {}),
                          via,
                        };
                        if (env.INGEST && !crawlId) {
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
                };

                if (env.INGEST && !crawlId && !resolvedCollectionId && trackedCtx?.waitUntil) {
                  trackedCtx.waitUntil(runPostFetchPersistence());
                } else {
                  await runPostFetchPersistence();
                }

                dispatchSpan.setAttribute('crawler.via', via);
                dispatchSpan.setAttribute('http.response.status_code', res.status);
                if (botAuthSigned) {
                  span.setAttribute('bot_auth.signed', true);
                  dispatchSpan.setAttribute('bot_auth.signed', true);
                }
                dispatchSpan.setStatus(res.status >= 200 && res.status < 400);
                if (!localTracer.suppressed && localTracer.sampled) {
                  localTracer.recordSpans(
                    buildCrawlChildSpans({
                      traceId: localTracer.traceId,
                      parentSpanId: dispatchSpan.spanId,
                      via,
                      endTimeMs: Date.now(),
                      replyText: bodyText,
                    }),
                  );
                }

                const totalHubMs = Date.now() - startedAtMs;
                const stageTimingsMs = { dispatchMs, hydrateR2Ms, totalHubMs };
                span.setAttribute('edgefetch.via', via);
                return { status: res.status, via, bodyText, stageTimingsMs, ...(retryAfter ? { retryAfter } : {}) };
              },
            ),
          );

          if (!activeParent && !localTracer.suppressed && localTracer.sampled) {
            const flushPromise = localTracer.flush({ env, fetchFn: env.SAFE_FETCH });
            if (ctx?.waitUntil) {
              ctx.waitUntil(flushPromise);
            } else {
              await flushPromise;
            }
          }
          return dispatchResult;
        },
      );

    const withRouteSpan = async (
      name: string,
      attrs: Record<string, string | number | boolean | undefined>,
      fn: () => Promise<Response>,
    ): Promise<Response> =>
      (getActiveRequestTracer() ?? rootTracer).withSpan(name, { kind: 1, attributes: attrs }, async (routeSpan) => {
        const res = await fn();
        routeSpan.setAttribute('http.response.status_code', res.status);
        routeSpan.setStatus(res.status < 500);
        return res;
      });

    const routeRequest = async (): Promise<Response> => {
      if (request.method === 'GET' && url.pathname === '/health') {
        return Response.json({ ok: true });
      }
      const openApiRes = handleOpenApiRoute(request, url, '2.6.3');
      if (openApiRes) return openApiRes;
      const botRes = await handleBotTransparencyRoutes(request, url, env, '2.6.3');
      if (botRes) return botRes;
      if (url.pathname === '/agent/ws') {
        const auth = authorizeAgent(request, env);
        if (!auth.ok) return Response.json({ error: 'unauthorized' }, { status: 401 });
        const headers = new Headers(request.headers);
        headers.set('x-verified-site', auth.siteId);
        const xffRaw = request.headers.get('x-forwarded-for');
        const rightmostXff = xffRaw
          ? xffRaw
              .split(',')
              .map((s) => s.trim())
              .filter(Boolean)
              .pop()
          : undefined;
        const clientIp = request.headers.get('cf-connecting-ip') ?? rightmostXff;
        if (clientIp) headers.set('x-verified-ip', clientIp);
        const reqShard = (url.searchParams.get('shard') ?? '').trim();
        const targetShard = reqShard && shardNames.includes(reqShard) ? reqShard : shardNames[0]!;
        return await hubShard(targetShard).fetch(new Request(request.url, { method: 'GET', headers }));
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
          authorizeJobUpload: async (p) => {
            let lastAuth: AuthorizeArtifactUploadResult | undefined;
            for (const sName of shardNames) {
              const res = await hubShard(sName).authorizeArtifactUpload(p);
              if (res.ok || shardNames.length === 1) return res;
              lastAuth = res;
            }
            return lastAuth!;
          },
        });
      }
      if (request.method === 'POST' && url.pathname === '/agent/reply') {
        const auth = authorizeAgent(request, env);
        if (!auth.ok) return Response.json({ error: 'unauthorized' }, { status: 401 });
        const jobId = (request.headers.get('x-job-id') ?? '').trim();
        const jobNonce = (request.headers.get('x-job-nonce') ?? '').trim();
        if (!JOB_ID_RE.test(jobId) || !JOB_ID_RE.test(jobNonce)) return Response.json({ error: 'bad_job_headers' }, { status: 400 });
        let matchedShard: DurableObjectStub<AgentHubDO> | null = null;
        for (const sName of shardNames) {
          const cand = hubShard(sName);
          if (await cand.verifyPendingJob(jobId, jobNonce, auth.siteId)) {
            matchedShard = cand;
            break;
          }
        }
        if (!matchedShard) {
          return Response.json({ error: 'unknown_job' }, { status: 404 });
        }
        const payload = await readAgentReplyBody(request);
        if (!payload.ok) {
          await matchedShard.failJob(jobId, jobNonce, auth.siteId, payload.error, payload.error === 'too_large');
          return Response.json({ error: payload.error }, { status: payload.status });
        }
        const done = await matchedShard.completeJob(jobId, jobNonce, auth.siteId, payload.text);
        return Response.json({ ok: done.ok }, { status: done.status });
      }

      const oauthStore = hubOAuthStore(hub);
      const activity = hubActivityProxy(hub);

      const makeCatalogHubFetch = (sourceLabel: string): CatalogHubFetchFn => {
        const boundTracer = getActiveRequestTracer();
        return async ({ url: pageUrl, kind = 'json', accept = 'application/json', maxBytes, target: rawTgt, site: rawSite, tracer }) => {
          const tgt: FetchTarget = rawTgt === 'agent' || rawTgt === 'container' ? rawTgt : 'auto';
          const siteStr = typeof rawSite === 'string' && rawSite.trim() ? rawSite.trim() : undefined;
          const boundedMaxBytes =
            typeof maxBytes === 'number' && Number.isFinite(maxBytes) && maxBytes > 0 ? Math.floor(maxBytes) : undefined;
          const callTracer = getActiveRequestTracer(tracer) ?? boundTracer;
          const doFetch = () =>
            executeHubFetch(
              tgt,
              JSON.stringify({
                maxSeconds: 30,
                options: {
                  includeBody: true,
                  respectRobots: true,
                  ...(boundedMaxBytes !== undefined ? { maxBytes: boundedMaxBytes } : {}),
                },
                requests: [{ id: 'cat-1', url: pageUrl, kind, accept }],
              }),
              siteStr,
              sourceLabel,
              'transient',
              true,
            );
          const hubOut = await (callTracer ? callTracer.run(doFetch) : doFetch());
          if (hubOut.status !== 200) {
            return {
              status: hubOut.status,
              outcome: hubOut.status === 429 ? 'rate_limited' : 'error',
              problem: hubOut.bodyText.slice(0, 240),
              headers: hubOut.retryAfter ? { 'retry-after': hubOut.retryAfter } : {},
              body: '',
            };
          }
          try {
            const parsedObj = JSON.parse(hubOut.bodyText) as { results?: Array<Record<string, unknown>> };
            const first = parsedObj.results?.[0];
            if (first && typeof first.retryAfter === 'string' && first.retryAfter) {
              const existingHdrs =
                first.headers && typeof first.headers === 'object' && !Array.isArray(first.headers)
                  ? (first.headers as Record<string, string>)
                  : {};
              first.headers = { 'retry-after': first.retryAfter, ...existingHdrs };
            }
            return parsedObj;
          } catch {
            return { status: 502, outcome: 'error', problem: 'malformed hub reply', headers: {}, body: '' };
          }
        };
      };

      const sessionSecret = resolveSessionSecret(env);
      const oauthRes = await handleOAuthRoute(request, url, {
        store: oauthStore,
        ownerSecret: env.CALLER_TOKEN,
        ...(env.MCP_TOKEN ? { mcpToken: env.MCP_TOKEN } : {}),
        ...(sessionSecret ? { sessionSecret } : {}),
        githubAuthEnabled: isGitHubAuthConfigured(env),
        serviceName: 'EdgeFetch Hub',
        redirectAllowlist: parseHostAllowlist(env.OAUTH_REDIRECT_ALLOWLIST),
        onEvent: (ev) => activity.recordEvent({ ...ev, details: sanitizeDetails(ev.details) }),
      });
      if (oauthRes) return oauthRes;

      if (url.pathname === '/mcp') {
        return await handleMcpRequest(request, url, {
          serverName: 'edgefetch-hub',
          serverVersion: '2.6.3',
          ownerSecret: env.CALLER_TOKEN,
          ...(env.MCP_TOKEN ? { mcpToken: env.MCP_TOKEN } : {}),
          oauthStore,
          activity,
          selfHost: url.hostname,
          ...(trackedCtx?.waitUntil ? { scheduleBackground: (p: Promise<unknown>) => trackedCtx.waitUntil(p) } : {}),
          allowedTargets: ALLOWED_TARGETS,
          defaultTarget: 'auto',
          listFleet: async () => {
            const state = await hub().getPortalState(Date.now());
            return { connected: state.connected, agents: state.agents, affinities: state.affinities };
          },
          executeFetch: ({ target, site, body, principal }) =>
            executeHubFetch(target, body, site, `mcp:${principal ?? 'client'}`),
          executeScrape: async ({ args, principal, userId }) => {
            const out = await executeScrapeCall({
              payload: args as ScrapeRequestPayload,
              env,
              executeHubFetch,
              selfHost: url.hostname,
              source: `mcp-scrape:${principal ?? 'client'}`,
              userId,
            });
            return { status: out.status, body: { via: out.via, ...out.body } };
          },
          executeExtract: async ({ args, principal, userId }) => {
            const out = await executeExtractCall({
              payload: args as ExtractRequestPayload,
              env,
              executeHubFetch,
              selfHost: url.hostname,
              source: `mcp-extract:${principal ?? 'client'}`,
              userId,
            });
            return { status: out.status, body: { via: out.via, ...out.body } };
          },
          executeInteract: async ({ args, principal, userId }) => {
            const out = await executeInteractCall({
              payload: args as InteractRequestPayload,
              env,
              executeHubFetch,
              selfHost: url.hostname,
              source: `mcp-interact:${principal ?? 'client'}`,
              principal: principal ?? 'client',
              userId,
              sessionSigningSecret: sessionSecret,
            });
            return { status: out.status, body: { via: out.via, ...out.body } };
          },
          executeMap: async ({ args, principal }) => {
            const out = await executeMapCall({
              payload: args as MapRequestPayload,
              executeHubFetch,
              selfHost: url.hostname,
              source: `mcp-map:${principal ?? 'client'}`,
            });
            return { status: out.status, body: { via: out.via, ...out.body } };
          },
          executeCrawl: async ({ args, principal, userId }) => {
            const existingId = typeof args.crawlId === 'string' ? args.crawlId.trim() : '';
            if (existingId) {
              if (args.cancel === true) {
                const cRes = await cancelCrawlJob(existingId, env.META);
                return { status: cRes.status, body: { ok: cRes.ok, crawlId: existingId, status: 'cancelled' } };
              }
              const st = await getCrawlJobStatus({
                crawlId: existingId,
                metaDb: env.META,
                bucket: env.ARTIFACTS,
                offset: typeof args.offset === 'number' ? args.offset : 0,
                ...(typeof args.limit === 'number' && Number.isFinite(args.limit) ? { limit: args.limit } : {}),
              });
              return st.ok ? { status: 200, body: st.crawl } : { status: st.status, body: { ok: false, error: st.error } };
            }
            const crawlArgs: Record<string, unknown> = { ...args };
            let displayCollectionId: string | undefined;
            if (typeof crawlArgs.collectionId === 'string' && crawlArgs.collectionId.trim()) {
              const resolvedColl = resolveUserCollectionId(crawlArgs.collectionId, userId);
              if (!resolvedColl.ok) {
                return { status: resolvedColl.status, body: { ok: false, error: resolvedColl.error, message: resolvedColl.message } };
              }
              crawlArgs.collectionId = resolvedColl.scopedId;
              displayCollectionId = resolvedColl.displayId;
            }
            const created = await createCrawlJob({ payload: crawlArgs, metaDb: env.META, selfHost: url.hostname });
            if (!created.ok) {
              return { status: created.status, body: { ok: false, error: created.error, message: created.message } };
            }
            const jobPromise = executeCrawlJob({
              crawlId: created.crawlId,
              rootUrl: created.rootUrl,
              options: created.options,
              env,
              executeHubFetch,
              selfHost: url.hostname,
              waitUntilBounded: Boolean(trackedCtx?.waitUntil),
            });
            if (trackedCtx?.waitUntil) {
              trackedCtx.waitUntil(jobPromise);
            } else {
              await jobPromise;
            }
            return {
              status: 202,
              body: {
                ok: true,
                crawlId: created.crawlId,
                status: 'queued',
                collectionId: displayCollectionId ?? created.options.collectionId,
                pollUrl: `${url.origin}/v1/crawl/${created.crawlId}`,
                principal: principal ?? 'client',
              },
            };
          },
          executeSearch: async ({ args, principal, userId }) => {
            const out = await executeSearchCall({
              payload: args as SearchRequestPayload,
              env,
              executeHubFetch,
              source: `mcp-search:${principal ?? 'client'}`,
              userId,
            });
            return { status: out.status, body: { via: out.via, ...out.body } };
          },
          executeJobs: async ({ args, principal, userId }) => {
            return await executeJobsCall({
              payload: args as JobsToolPayload,
              env: env as unknown as OptionalStorageBindings & Record<string, unknown>,
              executeSearch: async (sArgs) => {
                const sOut = await executeSearchCall({
                  payload: sArgs as SearchRequestPayload,
                  env,
                  executeHubFetch,
                  source: `mcp-jobs-search:${principal ?? 'client'}`,
                  userId,
                });
                return { status: sOut.status, body: sOut.body };
              },
              executeScrape: async (scArgs) => {
                const scOut = await executeScrapeCall({
                  payload: scArgs as ScrapeRequestPayload,
                  env,
                  executeHubFetch,
                  selfHost: url.hostname,
                  source: `mcp-jobs-scrape:${principal ?? 'client'}`,
                  userId,
                });
                return { status: scOut.status, body: scOut.body };
              },
            });
          },
          findExtractors: ({ query, category, limit }) => {
            return findRelevantAdapters({ query, category, limit }) as unknown as Array<Record<string, unknown>>;
          },
          executeCatalog: async ({ args, principal }) => {
            return await executeCatalogCall({
              payload: args as CatalogCallPayload,
              env: env as unknown as OptionalStorageBindings & Record<string, unknown>,
              executeHubFetch: makeCatalogHubFetch(`mcp-catalog:${principal ?? 'client'}`),
              selfHost: url.hostname,
              principal: principal ?? 'mcp',
              ...(trackedCtx?.waitUntil ? { ctx: { waitUntil: (p: Promise<unknown>) => trackedCtx.waitUntil(p) } } : {}),
            });
          },
          executeAgent: async ({ args, principal, userId }) => {
            if (typeof args.agentId === 'string' && args.agentId.trim()) {
              const aid = args.agentId.trim();
              if (args.cancel === true) {
                const cRes = await cancelAgentRun(aid, env.META, userId);
                return { status: cRes.status, body: { ok: cRes.ok, id: aid, status: 'cancelled' } };
              }
              const rec = await loadAgentRun(aid, env.META, userId);
              if (!rec) return { status: 404, body: { ok: false, error: 'agent_not_found' } };
              if (args.trace === true) {
                return { status: 200, body: { ok: true, id: rec.id, threadId: rec.threadId, status: rec.status, spans: rec.trace } };
              }
              return { status: 200, body: formatPublicAgentResponse(rec, false) };
            }
            const mcpAgentWaitUntil = trackedCtx?.waitUntil
              ? (p: Promise<unknown>) => trackedCtx.waitUntil(p)
              : (p: Promise<unknown>) => {
                  void p
                    .catch(() => undefined)
                    .finally(() => rootTracer.flush({ env, fetchFn: env.SAFE_FETCH }).catch(() => false));
                };
            const out = await startOrExecuteAgentCall({
              payload: args,
              env,
              executeHubFetch,
              selfHost: url.hostname,
              principal: principal ?? 'mcp',
              userId,
              sessionSigningSecret: sessionSecret,
              waitUntil: mcpAgentWaitUntil,
            });
            if (out.kind === 'sse') {
              return { status: 200, body: { ok: true, note: 'SSE stream completed' } };
            }
            return { status: out.status, body: out.body };
          },
          ...(env.SEARCH
            ? {
                searchCollection: async ({ collectionId, query, limit, userId }) => {
                  const resolved = resolveUserCollectionId(collectionId, userId);
                  if (!resolved.ok) {
                    return { ok: false as const, status: resolved.status, error: resolved.error };
                  }
                  const idx = new D1FtsSearchIndex(env.SEARCH!);
                  const hits = await idx.searchCollection({ collectionId: resolved.scopedId, query, limit });
                  return {
                    ok: true as const,
                    hits: hits.map((h) => ({ ...h, collectionId: resolved.displayId })) as unknown as Array<Record<string, unknown>>,
                  };
                },
              }
            : {}),
          ...(env.ARTIFACTS
            ? {
                readArtifact: async ({ blobSha256, retention, format, offset, limit, userId, visibility }) => {
                  const res = await readArtifactPage({
                    bucket: env.ARTIFACTS!,
                    ...(env.META ? { metaDb: env.META } : {}),
                    blobSha256,
                    ...(retention ? { retention } : {}),
                    ...(format ? { format } : {}),
                    ...(userId ? { userId } : {}),
                    ...(visibility ? { visibility } : {}),
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
        githubAuthEnv: env,
        metaDb: env.META,
        oauthStore,
        onEvent: (ev) => activity.recordEvent({ ...ev, details: sanitizeDetails(ev.details) }),
        allowedTargets: ALLOWED_TARGETS,
        defaultTarget: 'auto',
        getState: () => hub().getPortalState(Date.now()),
        clearAffinities: (siteId) => hub().clearAffinities(siteId),
        clearEvents: () => hub().clearHubEvents(),
        revokeGrant: async (grantId, userId) => {
          const revoked = await hub().oauthRevokeGrant(grantId, userId);
          if (revoked) {
            await activity.recordEvent({
              level: 'warn',
              category: 'oauth',
              event: 'oauth_grant_revoked',
              summary: `Revoked OAuth 2.1 grant ${grantId} from /admin`,
              details: { grantId, ...(userId ? { userId } : {}) },
            });
          }
          return revoked;
        },
        executeFetch: ({ target, site, body }) => executeHubFetch(target, body, site, 'admin'),
      });
      if (adminRes) return adminRes;

      if (request.method === 'GET' && url.pathname === '/v1/capabilities') {
        return withRouteSpan('edgefetch.capabilities', {}, async () => {
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
          return Response.json(buildCapabilities(env, '2.6.3'), {
            status: 200,
            headers: { 'cache-control': 'no-store' },
          });
        });
      }

      if (request.method === 'GET' && url.pathname === '/v1/extractors') {
        return withRouteSpan('edgefetch.extractors', {}, async () => {
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
          const category = url.searchParams.get('category') ?? undefined;
          const extractors = listRegisteredAdapters(category);
          const categories: Record<string, number> = {};
          for (const ex of extractors) {
            categories[ex.category] = (categories[ex.category] ?? 0) + 1;
          }
          return Response.json(
            { ok: true, total: extractors.length, categories, extractors },
            { status: 200, headers: { 'cache-control': 'no-store' } },
          );
        });
      }

      if (request.method === 'GET' && url.pathname === '/v1/hosts') {
        return withRouteSpan('edgefetch.hosts', {}, async () => {
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
          if (!auth.scopes.includes('crawl:read') && !auth.scopes.includes('crawl:fetch')) {
            return Response.json({ error: 'insufficient_scope' }, { status: 403, headers: { 'cache-control': 'no-store' } });
          }
          const rawLimit = Number(url.searchParams.get('limit') ?? 100);
          const safeLimit = Number.isFinite(rawLimit) ? Math.max(1, Math.min(500, Math.floor(rawLimit))) : 100;
          const hosts = await hub().listHostHealth(safeLimit);
          return Response.json({ ok: true, hosts }, { status: 200, headers: { 'cache-control': 'no-store' } });
        });
      }

      const compatMeta = resolveCompatSpanMeta(url.pathname);
      if (compatMeta) {
        const compatRes = await withRouteSpan(compatMeta.spanName, { 'edgefetch.compat': compatMeta.flavor }, async () => {
          const compatWaitUntil = trackedCtx?.waitUntil
            ? (p: Promise<unknown>) => trackedCtx.waitUntil(p)
            : (p: Promise<unknown>) => {
                void p
                  .catch(() => undefined)
                  .finally(() => rootTracer.flush({ env, fetchFn: env.SAFE_FETCH }).catch(() => false));
              };
          const res = await handleCompatRoutes({
            request,
            url,
            env,
            oauthStore,
            executeHubFetch,
            waitUntil: compatWaitUntil,
            tracer: getActiveRequestTracer() ?? rootTracer,
          });
          if (res && (res.headers.get('content-type') ?? '').toLowerCase().includes('text/event-stream')) {
            return wrapSseResponseWithFlush(res, () => {
              const p = rootTracer.flush({ env, fetchFn: env.SAFE_FETCH });
              if (ctx?.waitUntil) ctx.waitUntil(p);
              return p;
            });
          }
          return res ?? Response.json({ success: false, error: 'not_found' }, { status: 404 });
        });
        if (compatRes) return compatRes;
      }

      if (request.method === 'GET' && url.pathname.startsWith('/v1/artifacts/')) {
        return withRouteSpan('edgefetch.artifacts', {}, async () => {
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
            userId: auth.userId,
          });
        });
      }

      if (request.method === 'POST' && url.pathname === '/v1/scrape') {
        return withRouteSpan('edgefetch.scrape', {}, async () => {
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
          const cappedScrape = await readBodyTextCapped(request, MAX_CALL_UTF8_BYTES);
          if (!cappedScrape.ok) {
            return Response.json(
              { error: cappedScrape.error === 'too_large' ? 'payload_too_large' : 'bad_json' },
              { status: cappedScrape.error === 'too_large' ? 413 : 400 },
            );
          }
          let payload: ScrapeRequestPayload;
          try {
            payload = JSON.parse(cappedScrape.text) as ScrapeRequestPayload;
          } catch {
            return Response.json({ error: 'bad_json' }, { status: 400 });
          }
          const out = await executeScrapeCall({
            payload,
            env,
            executeHubFetch,
            selfHost: url.hostname,
            source: `scrape:${auth.principal}`,
            userId: auth.userId,
          });
          return Response.json(out.body, {
            status: out.status,
            headers: {
              'cache-control': 'no-store',
              'x-crawler-via': out.via,
              ...(out.retryAfter ? { 'retry-after': out.retryAfter } : {}),
            },
          });
        });
      }

      if (url.pathname === '/v1/ingest-tab' && (request.method === 'OPTIONS' || request.method === 'POST')) {
        const corsHeaders: Record<string, string> = {
          'access-control-allow-origin': '*',
          'access-control-allow-methods': 'POST, OPTIONS',
          'access-control-allow-headers': 'Authorization, Content-Type',
          'cache-control': 'no-store',
        };
        if (request.method === 'OPTIONS') {
          return new Response(null, { status: 204, headers: corsHeaders });
        }
        return withRouteSpan('edgefetch.ingest_tab', {}, async () => {
          const auth = await authorizeMcpRequest({
            request,
            origin: url.origin,
            ownerSecret: env.CALLER_TOKEN,
            store: oauthStore,
          });
          if (!auth.ok) {
            return Response.json(
              { error: 'unauthorized' },
              { status: 401, headers: { ...corsHeaders, 'www-authenticate': auth.wwwAuthenticate } },
            );
          }
          if (!auth.scopes.includes('crawl:fetch')) {
            return Response.json({ error: 'insufficient_scope' }, { status: 403, headers: corsHeaders });
          }
          const cappedClip = await readBodyTextCapped(request, 4 * 1024 * 1024);
          if (!cappedClip.ok) {
            return Response.json(
              {
                error: cappedClip.error === 'too_large' ? 'payload_too_large' : 'bad_json',
                ...(cappedClip.error === 'too_large' ? { message: 'Tab clip exceeds 4 MiB limit' } : {}),
              },
              { status: cappedClip.error === 'too_large' ? 413 : 400, headers: corsHeaders },
            );
          }
          let clipPayload: {
            url?: string;
            title?: string;
            html?: string;
            markdown?: string;
            collectionId?: string;
            onlyMainContent?: boolean;
            visibility?: unknown;
          };
          try {
            clipPayload = JSON.parse(cappedClip.text) as typeof clipPayload;
          } catch {
            return Response.json({ error: 'bad_json' }, { status: 400, headers: corsHeaders });
          }
          const tabUrl = typeof clipPayload.url === 'string' ? clipPayload.url.trim() : '';
          let parsedTabUrl: URL;
          try {
            parsedTabUrl = new URL(tabUrl);
            if (parsedTabUrl.protocol !== 'https:' && parsedTabUrl.protocol !== 'http:') {
              throw new Error('scheme');
            }
          } catch {
            return Response.json({ error: 'invalid_url', message: 'Valid http(s) tab url required' }, { status: 400, headers: corsHeaders });
          }
          parsedTabUrl.hash = '';
          const cleanUrl = parsedTabUrl.toString();
          const clipVisibility =
            clipPayload.visibility === 'private' || auth.userId !== 'owner'
              ? 'private'
              : normalizeVisibility(clipPayload.visibility);
          const rawCollectionId =
            typeof clipPayload.collectionId === 'string' && clipPayload.collectionId.trim()
              ? clipPayload.collectionId.trim()
              : 'browser-clips';
          const resolvedClipCollection = resolveUserCollectionId(rawCollectionId, auth.userId, clipVisibility);
          if (!resolvedClipCollection.ok) {
            return Response.json(
              { error: resolvedClipCollection.error, message: resolvedClipCollection.message },
              { status: resolvedClipCollection.status, headers: corsHeaders },
            );
          }
          const collectionId = resolvedClipCollection.displayId;
          setActiveSpanAttribute('url.full', sanitizeUrlForSpan(cleanUrl));
          setActiveSpanAttribute('edgefetch.collection_id', collectionId);

          let markdown = typeof clipPayload.markdown === 'string' ? clipPayload.markdown.trim() : '';
          let resolvedTitle = typeof clipPayload.title === 'string' ? clipPayload.title.trim() : '';
          let description: string | undefined;
          if (!markdown && typeof clipPayload.html === 'string' && clipPayload.html.trim()) {
            const extracted = extractHtmlDocument(clipPayload.html, {
              baseUrl: cleanUrl,
              onlyMainContent: clipPayload.onlyMainContent !== false,
            });
            markdown = extracted.markdown.trim();
            if (!resolvedTitle && extracted.title) resolvedTitle = extracted.title;
            description = extracted.description;
          }
          if (!markdown) {
            return Response.json({ error: 'empty_content', message: 'Clipped tab produced empty Markdown' }, { status: 400, headers: corsHeaders });
          }

          const contentSha256 = await sha256HexString(markdown);
          const pageIdSeed =
            clipVisibility === 'private' ? `${sanitizeStorageUserId(auth.userId)}:${cleanUrl}` : cleanUrl;
          const pageId = (await sha256HexString(pageIdSeed)).slice(0, 32);
          const documentId = `clip:${contentSha256.slice(0, 32)}`;
          const nowMs = Date.now();

          if (env.ARTIFACTS) {
            const mdKey =
              clipVisibility === 'private'
                ? r2PrivateDerivedKey(auth.userId, SCRAPE_PIPELINE_VERSION, 'markdown', contentSha256)
                : r2DerivedKey(SCRAPE_PIPELINE_VERSION, 'markdown', contentSha256);
            await env.ARTIFACTS.put(mdKey, markdown, {
              httpMetadata: { contentType: 'text/markdown; charset=utf-8' },
            }).catch(() => undefined);
          }

          let indexedChunks = 0;
          if (env.SEARCH) {
            const idx = new D1FtsSearchIndex(env.SEARCH);
            const rep = await idx.replacePageChunks({
              collectionId: resolvedClipCollection.scopedId,
              documentId,
              pageId,
              url: cleanUrl,
              title: resolvedTitle || cleanUrl,
              markdown,
              fetchedAt: nowMs,
            });
            if (rep.status === 'indexed') indexedChunks = rep.chunkCount;
          }
          setActiveSpanAttribute('edgefetch.ingest_tab.indexed_chunks', indexedChunks);

          return Response.json(
            {
              ok: true,
              url: cleanUrl,
              title: resolvedTitle || cleanUrl,
              ...(description ? { description } : {}),
              collectionId,
              visibility: clipVisibility,
              indexedChunks,
              contentSha256,
              pipelineVersion: SCRAPE_PIPELINE_VERSION,
              markdown,
            },
            { status: 200, headers: corsHeaders },
          );
        });
      }

      if (request.method === 'POST' && url.pathname === '/v1/extract') {
        return withRouteSpan('edgefetch.extract', {}, async () => {
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
          const cappedExtract = await readBodyTextCapped(request, MAX_CALL_UTF8_BYTES);
          if (!cappedExtract.ok) {
            return Response.json(
              { error: cappedExtract.error === 'too_large' ? 'payload_too_large' : 'bad_json' },
              { status: cappedExtract.error === 'too_large' ? 413 : 400 },
            );
          }
          let payload: ExtractRequestPayload;
          try {
            payload = JSON.parse(cappedExtract.text) as ExtractRequestPayload;
          } catch {
            return Response.json({ error: 'bad_json' }, { status: 400 });
          }
          const out = await executeExtractCall({
            payload,
            env,
            executeHubFetch,
            selfHost: url.hostname,
            source: `extract:${auth.principal}`,
            userId: auth.userId,
          });
          return Response.json(out.body, {
            status: out.status,
            headers: { 'cache-control': 'no-store', 'x-crawler-via': out.via },
          });
        });
      }

      if (request.method === 'POST' && url.pathname === '/v1/interact') {
        return withRouteSpan('edgefetch.interact', {}, async () => {
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
          const cappedInteract = await readBodyTextCapped(request, MAX_CALL_UTF8_BYTES);
          if (!cappedInteract.ok) {
            return Response.json(
              { error: cappedInteract.error === 'too_large' ? 'payload_too_large' : 'bad_json' },
              { status: cappedInteract.error === 'too_large' ? 413 : 400 },
            );
          }
          let payload: InteractRequestPayload;
          try {
            payload = JSON.parse(cappedInteract.text) as InteractRequestPayload;
          } catch {
            return Response.json({ error: 'bad_json' }, { status: 400 });
          }
          const out = await executeInteractCall({
            payload,
            env,
            executeHubFetch,
            selfHost: url.hostname,
            source: `interact:${auth.principal}`,
            principal: auth.principal,
            userId: auth.userId,
            sessionSigningSecret: sessionSecret,
          });
          return Response.json(out.body, {
            status: out.status,
            headers: { 'cache-control': 'no-store', 'x-crawler-via': out.via },
          });
        });
      }

      if (request.method === 'POST' && url.pathname === '/v1/map') {
        return withRouteSpan('edgefetch.map', {}, async () => {
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
          const cappedMap = await readBodyTextCapped(request, MAX_CALL_UTF8_BYTES);
          if (!cappedMap.ok) {
            return Response.json(
              { error: cappedMap.error === 'too_large' ? 'payload_too_large' : 'bad_json' },
              { status: cappedMap.error === 'too_large' ? 413 : 400 },
            );
          }
          let payload: MapRequestPayload;
          try {
            payload = JSON.parse(cappedMap.text) as MapRequestPayload;
          } catch {
            return Response.json({ error: 'bad_json' }, { status: 400 });
          }
          const out = await executeMapCall({
            payload,
            executeHubFetch,
            selfHost: url.hostname,
            source: `map:${auth.principal}`,
          });
          return Response.json(out.body, {
            status: out.status,
            headers: { 'cache-control': 'no-store', 'x-crawler-via': out.via },
          });
        });
      }

      if (request.method === 'POST' && url.pathname === '/v1/search') {
        return withRouteSpan('edgefetch.search', {}, async () => {
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
          if (!auth.scopes.includes('crawl:read') && !auth.scopes.includes('crawl:fetch')) {
            return Response.json({ error: 'insufficient_scope' }, { status: 403, headers: { 'cache-control': 'no-store' } });
          }
          const cappedSearch = await readBodyTextCapped(request, MAX_CALL_UTF8_BYTES);
          if (!cappedSearch.ok) {
            return Response.json(
              { error: cappedSearch.error === 'too_large' ? 'payload_too_large' : 'bad_json' },
              { status: cappedSearch.error === 'too_large' ? 413 : 400 },
            );
          }
          let payload: SearchRequestPayload;
          try {
            payload = JSON.parse(cappedSearch.text) as SearchRequestPayload;
          } catch {
            return Response.json({ error: 'bad_json' }, { status: 400 });
          }
          const out = await executeSearchCall({
            payload,
            env,
            executeHubFetch,
            source: `search:${auth.principal}`,
            userId: auth.userId,
          });
          return Response.json(out.body, {
            status: out.status,
            headers: { 'cache-control': 'no-store', 'x-crawler-via': out.via },
          });
        });
      }

      if (request.method === 'POST' && url.pathname === '/v1/crawl/params-preview') {
        return withRouteSpan('edgefetch.crawl', { 'edgefetch.op': 'params_preview' }, async () => {
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
          const cappedPreview = await readBodyTextCapped(request, MAX_CALL_UTF8_BYTES);
          if (!cappedPreview.ok) {
            return Response.json(
              { error: cappedPreview.error === 'too_large' ? 'payload_too_large' : 'bad_json' },
              { status: cappedPreview.error === 'too_large' ? 413 : 400 },
            );
          }
          let payload: Record<string, unknown>;
          try {
            payload = JSON.parse(cappedPreview.text) as Record<string, unknown>;
          } catch {
            return Response.json({ error: 'bad_json' }, { status: 400 });
          }
          const prev = previewCrawlParams(payload, url.hostname);
          return Response.json(prev.body, { status: prev.status, headers: { 'cache-control': 'no-store' } });
        });
      }

      if (request.method === 'POST' && url.pathname === '/v1/batch/scrape') {
        return withRouteSpan('edgefetch.batch_scrape', {}, async () => {
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
          const cappedBatch = await readBodyTextCapped(request, MAX_CALL_UTF8_BYTES);
          if (!cappedBatch.ok) {
            return Response.json(
              { error: cappedBatch.error === 'too_large' ? 'payload_too_large' : 'bad_json' },
              { status: cappedBatch.error === 'too_large' ? 413 : 400 },
            );
          }
          let payload: Record<string, unknown>;
          try {
            payload = JSON.parse(cappedBatch.text) as Record<string, unknown>;
          } catch {
            return Response.json({ error: 'bad_json' }, { status: 400 });
          }
          const batchOut = await startOrExecuteBatchScrape({
            payload,
            selfHost: url.hostname,
            executeScrape: async (scArgs) => {
              const res = await executeScrapeCall({
                payload: scArgs as ScrapeRequestPayload,
                env,
                executeHubFetch,
                selfHost: url.hostname,
                source: `batch-scrape:${auth.principal}`,
                userId: auth.userId,
              });
              return { status: res.status, body: res.body };
            },
            ...(trackedCtx?.waitUntil ? { waitUntil: (p: Promise<unknown>) => trackedCtx.waitUntil(p) } : {}),
          });
          if (!batchOut.ok) {
            return Response.json({ ok: false, error: batchOut.error, message: batchOut.message }, { status: batchOut.status });
          }
          return Response.json(
            {
              ok: true,
              id: batchOut.job.id,
              status: batchOut.job.status,
              total: batchOut.job.total,
              completed: batchOut.job.completed,
              url: `${url.origin}/v1/batch/scrape/${batchOut.job.id}`,
              ...(payload.sync === true ? { data: batchOut.job.data, errors: batchOut.job.errors } : {}),
            },
            { status: batchOut.status, headers: { 'cache-control': 'no-store' } },
          );
        });
      }

      const batchRouteMatch = /^\/v1\/batch\/scrape\/([^/]+)$/.exec(url.pathname);
      if (batchRouteMatch) {
        return withRouteSpan('edgefetch.batch_scrape', {}, async () => {
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
          const rawBatchId = safeDecodeURIComponent(batchRouteMatch[1] ?? '');
          if (rawBatchId === null) {
            return Response.json({ ok: false, error: 'bad_request', message: 'Malformed URL path parameter' }, { status: 400 });
          }
          const batchId = rawBatchId.trim();
          if (request.method === 'GET') {
            const job = getBatchScrapeStatus(batchId);
            if (!job) return Response.json({ ok: false, error: 'batch_not_found' }, { status: 404 });
            return Response.json({ ok: true, ...job }, { status: 200, headers: { 'cache-control': 'no-store' } });
          }
          if (request.method === 'DELETE') {
            if (!auth.scopes.includes('crawl:fetch')) {
              return Response.json({ ok: false, error: 'insufficient_scope' }, { status: 403 });
            }
            const ok = cancelBatchScrape(batchId);
            return Response.json({ ok, id: batchId, status: 'cancelled' }, { status: ok ? 200 : 404 });
          }
          return Response.json({ error: 'not_found' }, { status: 404 });
        });
      }

      if (request.method === 'POST' && url.pathname === '/v1/agent') {
        return withRouteSpan('edgefetch.agent', {}, async () => {
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
          const cappedAgent = await readBodyTextCapped(request, MAX_CALL_UTF8_BYTES);
          if (!cappedAgent.ok) {
            return Response.json(
              { error: cappedAgent.error === 'too_large' ? 'payload_too_large' : 'bad_json' },
              { status: cappedAgent.error === 'too_large' ? 413 : 400 },
            );
          }
          let payload: Record<string, unknown>;
          try {
            payload = JSON.parse(cappedAgent.text) as Record<string, unknown>;
          } catch {
            return Response.json({ error: 'bad_json' }, { status: 400 });
          }
          const wantSse = (request.headers.get('accept') ?? '').toLowerCase().includes('text/event-stream');
          const agentWaitUntil = trackedCtx?.waitUntil
            ? (p: Promise<unknown>) => trackedCtx.waitUntil(p)
            : (p: Promise<unknown>) => {
                void p
                  .catch(() => undefined)
                  .finally(() => rootTracer.flush({ env, fetchFn: env.SAFE_FETCH }).catch(() => false));
              };
          const out = await startOrExecuteAgentCall({
            payload,
            env,
            executeHubFetch,
            selfHost: url.hostname,
            principal: auth.principal,
            userId: auth.userId,
            sessionSigningSecret: sessionSecret,
            wantSseStream: wantSse,
            waitUntil: agentWaitUntil,
          });
          if (out.kind === 'sse') {
            return wrapSseResponseWithFlush(out.response, () => {
              const p = rootTracer.flush({ env, fetchFn: env.SAFE_FETCH });
              if (ctx?.waitUntil) ctx.waitUntil(p);
              return p;
            });
          }
          return Response.json(out.body, { status: out.status, headers: { 'cache-control': 'no-store' } });
        });
      }

      const agentTraceMatch = /^\/v1\/agent\/([^/]+)\/trace$/.exec(url.pathname);
      if (agentTraceMatch && request.method === 'GET') {
        return withRouteSpan('edgefetch.agent', { 'edgefetch.op': 'trace' }, async () => {
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
          const rawAgentId = safeDecodeURIComponent(agentTraceMatch[1] ?? '');
          if (rawAgentId === null) {
            return Response.json({ ok: false, error: 'bad_request', message: 'Malformed URL path parameter' }, { status: 400 });
          }
          const agentId = rawAgentId.trim();
          const rec = await loadAgentRun(agentId, env.META, auth.userId);
          if (!rec) return Response.json({ ok: false, error: 'agent_not_found' }, { status: 404 });
          return Response.json(
            {
              ok: true,
              success: true,
              id: rec.id,
              threadId: rec.threadId,
              status: rec.status,
              count: rec.trace.length,
              spans: rec.trace,
              trace: rec.trace,
              events: rec.trace,
            },
            { status: 200, headers: { 'cache-control': 'no-store' } },
          );
        });
      }

      const agentRouteMatch = /^\/v1\/agent\/([^/]+)$/.exec(url.pathname);
      if (agentRouteMatch) {
        return withRouteSpan('edgefetch.agent', {}, async () => {
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
          const rawAgentId = safeDecodeURIComponent(agentRouteMatch[1] ?? '');
          if (rawAgentId === null) {
            return Response.json({ ok: false, error: 'bad_request', message: 'Malformed URL path parameter' }, { status: 400 });
          }
          const agentId = rawAgentId.trim();
          if (request.method === 'GET') {
            const rec = await loadAgentRun(agentId, env.META, auth.userId);
            if (!rec) return Response.json({ ok: false, error: 'agent_not_found' }, { status: 404 });
            return Response.json(formatPublicAgentResponse(rec, false), { status: 200, headers: { 'cache-control': 'no-store' } });
          }
          if (request.method === 'DELETE') {
            if (!auth.scopes.includes('crawl:fetch')) {
              return Response.json({ error: 'insufficient_scope' }, { status: 403 });
            }
            const cRes = await cancelAgentRun(agentId, env.META, auth.userId);
            return Response.json({ ok: cRes.ok, id: agentId, status: 'cancelled' }, { status: cRes.status });
          }
          return Response.json({ error: 'not_found' }, { status: 404 });
        });
      }

      if (request.method === 'POST' && url.pathname === '/v1/crawl') {
        return withRouteSpan('edgefetch.crawl', {}, async () => {
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
          const cappedCrawl = await readBodyTextCapped(request, MAX_CALL_UTF8_BYTES);
          if (!cappedCrawl.ok) {
            return Response.json(
              { error: cappedCrawl.error === 'too_large' ? 'payload_too_large' : 'bad_json' },
              { status: cappedCrawl.error === 'too_large' ? 413 : 400 },
            );
          }
          let payload: Record<string, unknown>;
          try {
            payload = JSON.parse(cappedCrawl.text) as Record<string, unknown>;
          } catch {
            return Response.json({ error: 'bad_json' }, { status: 400 });
          }
          let displayCollectionId: string | undefined;
          if (typeof payload.collectionId === 'string' && payload.collectionId.trim()) {
            const resolvedColl = resolveUserCollectionId(payload.collectionId, auth.userId);
            if (!resolvedColl.ok) {
              return Response.json(
                { ok: false, error: resolvedColl.error, message: resolvedColl.message },
                { status: resolvedColl.status, headers: { 'cache-control': 'no-store' } },
              );
            }
            payload = { ...payload, collectionId: resolvedColl.scopedId };
            displayCollectionId = resolvedColl.displayId;
          }
          const created = await createCrawlJob({ payload, metaDb: env.META, selfHost: url.hostname });
          if (!created.ok) {
            return Response.json(
              { ok: false, error: created.error, message: created.message },
              { status: created.status, headers: { 'cache-control': 'no-store' } },
            );
          }
          const jobPromise = executeCrawlJob({
            crawlId: created.crawlId,
            rootUrl: created.rootUrl,
            options: created.options,
            env,
            executeHubFetch,
            selfHost: url.hostname,
          });
          if (payload.sync === true) {
            await jobPromise;
          } else if (trackedCtx?.waitUntil) {
            trackedCtx.waitUntil(jobPromise);
          } else {
            await jobPromise;
          }
          return Response.json(
            {
              ok: true,
              id: created.crawlId,
              status: payload.sync === true ? 'completed' : 'queued',
              collectionId: displayCollectionId ?? created.options.collectionId,
              url: `${url.origin}/v1/crawl/${created.crawlId}`,
            },
            { status: payload.sync === true ? 200 : 202, headers: { 'cache-control': 'no-store' } },
          );
        });
      }

      const crawlRouteMatch = /^\/v1\/crawl\/([^/]+)$/.exec(url.pathname);
      if (crawlRouteMatch) {
        return withRouteSpan('edgefetch.crawl', {}, async () => {
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
          const rawCrawlId = safeDecodeURIComponent(crawlRouteMatch[1] ?? '');
          if (rawCrawlId === null) {
            return Response.json({ ok: false, error: 'bad_request', message: 'Malformed URL path parameter' }, { status: 400 });
          }
          const crawlId = rawCrawlId.trim();
          if (request.method === 'GET') {
            if (!auth.scopes.includes('crawl:read') && !auth.scopes.includes('crawl:fetch')) {
              return Response.json({ error: 'insufficient_scope' }, { status: 403 });
            }
            const st = await getCrawlJobStatus({
              crawlId,
              metaDb: env.META,
              bucket: env.ARTIFACTS,
              offset: Number(url.searchParams.get('offset') ?? 0),
              limit: Number(url.searchParams.get('limit') ?? 25),
            });
            if (!st.ok) return Response.json({ ok: false, error: st.error }, { status: st.status });
            return Response.json({ ok: true, ...st.crawl }, { status: 200, headers: { 'cache-control': 'no-store' } });
          }
          if (request.method === 'DELETE') {
            if (!auth.scopes.includes('crawl:fetch')) {
              return Response.json({ error: 'insufficient_scope' }, { status: 403 });
            }
            const cRes = await cancelCrawlJob(crawlId, env.META);
            return Response.json({ ok: cRes.ok, id: crawlId, status: 'cancelled' }, { status: cRes.status });
          }
          return Response.json({ error: 'not_found' }, { status: 404 });
        });
      }

      const collectionSearchMatch = /^\/v1\/collections\/([^/]+)\/search$/.exec(url.pathname);
      if (collectionSearchMatch && (request.method === 'POST' || request.method === 'GET')) {
        return withRouteSpan('edgefetch.collection_search', {}, async () => {
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
          if (!auth.scopes.includes('crawl:read') && !auth.scopes.includes('crawl:fetch')) {
            return Response.json({ error: 'insufficient_scope' }, { status: 403, headers: { 'cache-control': 'no-store' } });
          }
          if (!env.SEARCH) {
            return Response.json({ error: 'search_not_configured' }, { status: 503, headers: { 'cache-control': 'no-store' } });
          }
          const rawCollectionId = safeDecodeURIComponent(collectionSearchMatch[1] ?? '');
          if (rawCollectionId === null) {
            return Response.json({ error: 'bad_request', message: 'Malformed URL path parameter' }, { status: 400, headers: { 'cache-control': 'no-store' } });
          }
          const resolvedCol = resolveUserCollectionId(rawCollectionId.trim(), auth.userId);
          if (!resolvedCol.ok) {
            return Response.json(
              { error: resolvedCol.error, message: resolvedCol.message },
              { status: resolvedCol.status, headers: { 'cache-control': 'no-store' } },
            );
          }
          let query = url.searchParams.get('q') ?? url.searchParams.get('query') ?? '';
          let limit = Number(url.searchParams.get('limit') ?? 10);
          if (request.method === 'POST') {
            const cappedColSearch = await readBodyTextCapped(request, MAX_CALL_UTF8_BYTES);
            if (!cappedColSearch.ok) {
              return Response.json(
                { error: cappedColSearch.error === 'too_large' ? 'payload_too_large' : 'bad_json' },
                { status: cappedColSearch.error === 'too_large' ? 413 : 400, headers: { 'cache-control': 'no-store' } },
              );
            }
            try {
              const bodyJson = JSON.parse(cappedColSearch.text) as { query?: unknown; q?: unknown; limit?: unknown };
              if (typeof bodyJson.query === 'string') query = bodyJson.query;
              else if (typeof bodyJson.q === 'string') query = bodyJson.q;
              if (typeof bodyJson.limit === 'number' && Number.isFinite(bodyJson.limit)) limit = bodyJson.limit;
            } catch {
              return Response.json({ error: 'bad_json' }, { status: 400, headers: { 'cache-control': 'no-store' } });
            }
          }
          const idx = new D1FtsSearchIndex(env.SEARCH);
          const hits = await idx.searchCollection({
            collectionId: resolvedCol.scopedId,
            query,
            limit: Number.isFinite(limit) ? limit : 10,
          });
          return Response.json(
            {
              ok: true,
              collectionId: resolvedCol.displayId,
              query,
              hits: hits.map((h) => ({ ...h, collectionId: resolvedCol.displayId })),
            },
            { status: 200, headers: { 'cache-control': 'no-store' } },
          );
        });
      }

      if (request.method === 'POST' && url.pathname === '/v1/jobs') {
        return withRouteSpan('edgefetch.jobs', {}, async () => {
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
          const cappedJobs = await readBodyTextCapped(request, MAX_CALL_UTF8_BYTES);
          if (!cappedJobs.ok) {
            return Response.json(
              { error: cappedJobs.error === 'too_large' ? 'payload_too_large' : 'bad_json' },
              { status: cappedJobs.error === 'too_large' ? 413 : 400 },
            );
          }
          let payload: JobsToolPayload;
          try {
            payload = JSON.parse(cappedJobs.text) as JobsToolPayload;
          } catch {
            return Response.json({ error: 'bad_json' }, { status: 400 });
          }
          const out = await executeJobsCall({
            payload,
            env: env as unknown as OptionalStorageBindings & Record<string, unknown>,
            executeSearch: async (sArgs) => {
              const sOut = await executeSearchCall({
                payload: sArgs as SearchRequestPayload,
                env,
                executeHubFetch,
                source: `jobs-search:${auth.principal}`,
                userId: auth.userId,
              });
              return { status: sOut.status, body: sOut.body };
            },
            executeScrape: async (scArgs) => {
              const scOut = await executeScrapeCall({
                payload: scArgs as ScrapeRequestPayload,
                env,
                executeHubFetch,
                selfHost: url.hostname,
                source: `jobs-scrape:${auth.principal}`,
                userId: auth.userId,
              });
              return { status: scOut.status, body: scOut.body };
            },
          });
          return Response.json(out.body, {
            status: out.status,
            headers: { 'cache-control': 'no-store' },
          });
        });
      }

      if (request.method === 'POST' && url.pathname === '/v1/catalog') {
        return withRouteSpan('edgefetch.catalog', {}, async () => {
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
          const cappedCat = await readBodyTextCapped(request, MAX_CALL_UTF8_BYTES);
          if (!cappedCat.ok) {
            return Response.json(
              { error: cappedCat.error === 'too_large' ? 'payload_too_large' : 'bad_json' },
              { status: cappedCat.error === 'too_large' ? 413 : 400 },
            );
          }
          let payload: CatalogCallPayload;
          try {
            payload = JSON.parse(cappedCat.text) as CatalogCallPayload;
          } catch {
            return Response.json({ error: 'bad_json' }, { status: 400 });
          }
          const out = await executeCatalogCall({
            payload,
            env: env as unknown as OptionalStorageBindings & Record<string, unknown>,
            executeHubFetch: makeCatalogHubFetch(`catalog:${auth.principal}`),
            selfHost: url.hostname,
            principal: auth.principal,
            ...(trackedCtx?.waitUntil ? { ctx: { waitUntil: (p: Promise<unknown>) => trackedCtx.waitUntil(p) } } : {}),
          });
          return Response.json(out.body, {
            status: out.status,
            headers: { 'cache-control': 'no-store' },
          });
        });
      }

      const catalogRecordsMatch = /^\/v1\/catalog\/([^/]+)\/records$/.exec(url.pathname);
      if (catalogRecordsMatch && request.method === 'GET') {
        return withRouteSpan('edgefetch.catalog', { 'edgefetch.op': 'records' }, async () => {
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
          if (!auth.scopes.includes('crawl:read') && !auth.scopes.includes('crawl:fetch')) {
            return Response.json({ error: 'insufficient_scope' }, { status: 403, headers: { 'cache-control': 'no-store' } });
          }
          const rawCatalogId = safeDecodeURIComponent(catalogRecordsMatch[1] ?? '');
          if (rawCatalogId === null) {
            return Response.json({ ok: false, error: 'bad_request', message: 'Malformed URL path parameter' }, { status: 400 });
          }
          const catalogId = rawCatalogId.trim();
          const vendors = url.searchParams.getAll('vendor').filter(Boolean);
          const productTypes = url.searchParams.getAll('productType').filter(Boolean);
          const rawOffset = url.searchParams.get('offset');
          const rawLimit = url.searchParams.get('limit');
          const rawAvail = url.searchParams.get('availableOnly');
          const query = url.searchParams.get('query') ?? url.searchParams.get('q') ?? undefined;
          const out = await getCatalogRecords({
            catalogId,
            ...(rawOffset !== null && Number.isFinite(Number(rawOffset)) ? { offset: Number(rawOffset) } : {}),
            ...(rawLimit !== null && Number.isFinite(Number(rawLimit)) ? { limit: Number(rawLimit) } : {}),
            ...(vendors.length > 1 ? { vendor: vendors } : vendors.length === 1 ? { vendor: vendors[0] } : {}),
            ...(productTypes.length > 1
              ? { productType: productTypes }
              : productTypes.length === 1
                ? { productType: productTypes[0] }
                : {}),
            ...(rawAvail === 'true' || rawAvail === '1' ? { availableOnly: true } : {}),
            ...(query ? { query } : {}),
            env: env as unknown as OptionalStorageBindings & Record<string, unknown>,
          });
          return Response.json(out.body, {
            status: out.status,
            headers: { 'cache-control': 'no-store' },
          });
        });
      }

      const catalogStatusMatch = /^\/v1\/catalog\/([^/]+)$/.exec(url.pathname);
      if (catalogStatusMatch && request.method === 'GET') {
        return withRouteSpan('edgefetch.catalog', { 'edgefetch.op': 'status' }, async () => {
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
          if (!auth.scopes.includes('crawl:read') && !auth.scopes.includes('crawl:fetch')) {
            return Response.json({ error: 'insufficient_scope' }, { status: 403, headers: { 'cache-control': 'no-store' } });
          }
          const rawCatalogId = safeDecodeURIComponent(catalogStatusMatch[1] ?? '');
          if (rawCatalogId === null) {
            return Response.json({ ok: false, error: 'bad_request', message: 'Malformed URL path parameter' }, { status: 400 });
          }
          const catalogId = rawCatalogId.trim();
          const out = await getCatalogStatus({
            catalogId,
            env: env as unknown as OptionalStorageBindings & Record<string, unknown>,
          });
          return Response.json(out.body, {
            status: out.status,
            headers: { 'cache-control': 'no-store' },
          });
        });
      }

      if (!isCallerAuthorized(request, env.CALLER_TOKEN)) {
        return Response.json({ error: 'unauthorized' }, { status: 401 });
      }
      if (request.method === 'GET' && url.pathname === '/agents') {
        return withRouteSpan('edgefetch.agents', {}, async () => Response.json(await hub().listAgents()));
      }
      if (request.method === 'POST' && url.pathname === '/fetch') {
        return withRouteSpan('edgefetch.fetch', {}, async () => {
          const parsedTarget = parseFetchTarget(url);
          if (!parsedTarget.ok) return Response.json({ error: 'bad_target', message: parsedTarget.message }, { status: 400 });
          const cappedFetch = await readBodyTextCapped(request, MAX_CALL_UTF8_BYTES);
          if (!cappedFetch.ok) {
            return Response.json(
              { error: cappedFetch.error === 'too_large' ? 'payload_too_large' : 'bad_json' },
              { status: cappedFetch.error === 'too_large' ? 413 : 400 },
            );
          }
          const body = cappedFetch.text;
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
        });
      }
      return Response.json({ error: 'not_found' }, { status: 404 });
    };

    let response!: Response;
    try {
      response = await rootTracer.run(() =>
        rootTracer.withSpan(
          'edgefetch.http',
          {
            kind: 2,
            attributes: {
              'http.request.method': request.method,
              'url.path': url.pathname,
            },
          },
          async (httpSpan) => {
            const res = await routeRequest();
            httpSpan.setAttribute('http.response.status_code', res.status);
            httpSpan.setStatus(res.status < 500);
            return res;
          },
        ),
      );
    } catch (e) {
      response = Response.json(
        {
          error: 'hub_unavailable',
          message: e instanceof Error ? e.message : 'Coordinator temporarily unavailable; please retry',
        },
        { status: 503, headers: { 'cache-control': 'no-store' } },
      );
    } finally {
      if (!rootTracer.suppressed && rootTracer.sampled) {
        const flushPromise = rootTracer.flush({ env, fetchFn: env.SAFE_FETCH });
        if (ctx?.waitUntil) {
          ctx.waitUntil(flushPromise);
        } else {
          await flushPromise;
        }
      }
    }
    return injectTraceHeaders(response, rootTracer);
  },

  async scheduled(_controller: ScheduledController, env: Env): Promise<void> {
    if (env.META) {
      await pruneExpiredFetchHistory(env.META).catch(() => undefined);
    }
  },
};
