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
  type McpTurnRecordInput,
} from './activity-log';
import { handleAdminRoute } from './admin';
import { queryHostGapRadar } from './gap-radar';
import {
  createSqliteHubSettingsStore,
  DEV_TELEMETRY_SETTING_KEY,
  HUB_SETTINGS_SQLITE_SCHEMA,
  isTruthyTelemetryFlag,
  resolveDevTelemetryState,
  type HubSettingsStore,
} from './dev-telemetry';
import { checkHubUpdateStatus, HUB_VERSION } from './update-check';
import {
  buildTrackerListWsFrames,
  getTrackerListAdminStatus,
  isTrackerListDisabled,
  loadStoredTrackerList,
  refreshHubTrackerList,
  resolveExtraNeverBlockHosts,
  type TrackerBucketLike,
} from './tracker-list';
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
  MAX_CONCURRENT_AGENTS_PER_USER,
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
import { executeCompanyCall, type CompanyToolPayload } from './company';
import { executeSalariesCall, type SalariesToolPayload } from './salaries';
/** Slug of Google's official hosted Maps MCP preset (Go `mcpfed.GoogleMapsMCPSlug`). */
const GOOGLE_MAPS_MCP_SLUG = 'google-maps';
import { executeJobsCall, type JobsToolPayload } from './jobs';
import {
  cancelBatchScrape,
  cancelCrawlJob,
  countExtractPayloadUrls,
  CrawlWorkflow,
  createCrawlJob,
  executeCrawlJob,
  executeMapCall,
  getBatchScrapeStatus,
  getCrawlJobStatus,
  MAX_CONCURRENT_EXTRACT_URLS_PER_USER,
  MAX_CONCURRENT_EXTRACTS_PER_USER,
  MAX_CONCURRENT_MAPS_PER_USER,
  previewCrawlParams,
  startOrExecuteBatchScrape,
  tryAcquireUserExtractSlots,
  tryAcquireUserMapSlot,
  type MapRequestPayload,
} from './map-crawl';
import { handleMcpRequest, isMcpRootRequest } from './mcp';
import {
  createSqliteHubSecretsStore,
  applyHubSecretOverlayFromBinding,
  HUB_SECRETS_SQLITE_SCHEMA,
  type HubSecretRow,
  type HubSecretsStore,
} from './hub-secrets';
import {
  ACCESS_POLICY_SQLITE_SCHEMA,
  createSqliteAccessPolicyStore,
  evaluateRouteAccess,
  listSharedServersFor,
  loadAccessPolicySnapshot,
  type AccessPolicyRuleRow,
  type AccessPolicyStore,
  type McpServerShareRow,
} from './access-policy';
import {
  executeFederatedMcpQuery,
  sanitizeConnectorStructuredValue,
  tryScrapeViaConnectedMcp,
  type QueryMcpCallInput,
} from './mcp-federation';
import { discoverMcps } from './mcp-registry';
import {
  createSqliteMcpVaultStore,
  MCP_VAULT_SQLITE_SCHEMA,
  parseAllowedMcpTools,
  resolveCallerUserId,
  type McpVaultStore,
  type PendingMcpOAuthStateRow,
  type StoredMcpServerRow,
} from './mcp-vault';
import { handleOpenApiRoute } from './openapi';
import {
  authorizeMcpRequest,
  createSqliteOAuthStore,
  getActiveCallerAuthContext,
  handleOAuthRoute,
  OAUTH_SQLITE_SCHEMA,
  annotateCallerAuthFailure,
  runWithCallerAuthContext,
} from './oauth';
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
import { MAX_WASM_INPUT_BYTES } from './wasm-bridge';
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
  sanitizeInlineHtmlInMarkdown,
  SCRAPE_PIPELINE_VERSION,
  type InteractRequestPayload,
  type ScrapeRequestPayload,
} from './scrape';
import {
  D1FtsSearchIndex,
  executeExtractCall,
  resolveUserCollectionId,
  sanitizeExtractedTitle,
  type ExtractRequestPayload,
} from './search-index';
import {
  executeSearchCall,
  type SearchRequestPayload,
} from './web-search';
import { listRegisteredAdapters } from './extractors/registry';
import { checkAndRecordWikipediaArticleQuota, parseWikipediaArticleUrl } from './wikipedia';
import {
  buildCapabilities,
  handleAgentArtifactUpload,
  handleArtifactGetRequest,
  hydrateReplyBodiesFromR2,
  isPrivateRequestPayload,
  MAX_ARTIFACT_CONTENT_BYTES,
  normalizeVisibility,
  r2DerivedKey,
  r2PrivateDerivedKey,
  readArtifactPage,
  sanitizeStorageUserId,
  writePrivateArtifactToR2,
  type ArtifactRetention,
  type OptionalStorageBindings,
} from './storage';

interface Env extends OptionalStorageBindings, OtelEnvConfig, BotAuthEnv, GitHubAuthEnv {
  AGENT_HUB: DurableObjectNamespace<AgentHubDO>;
  HUB_SHARDS?: string;
  SAFE_FETCH?: typeof fetch;
  SAFE_PUBLIC_FETCH?: typeof fetch;
  CALLER_TOKEN?: string;
  /** Optional old caller token still accepted during a rotation; uses are logged as `caller_token_previous_used`. */
  CALLER_TOKEN_PREVIOUS?: string;
  VAULT_MASTER_KEY?: string;
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
  CLOUDFLARE_ACCOUNT_ID?: string;
  CLOUDFLARE_WEBSEARCH_API_TOKEN?: string;
  CLOUDFLARE_AI_GATEWAY_ID?: string;
  CLOUDFLARE_WEBSEARCH_PROVIDER?: string;
  CLOUDFLARE_WEBSEARCH_BYOK_ALIAS?: string;
  WEBHOOK_SECRET?: string;
  EDGEFETCH_PUBLIC_ORIGIN?: string;
  EDGEFETCH_DISABLE_UPDATE_CHECK?: string;
  EDGEFETCH_TRACKER_LIST?: string;
  TRACKER_BUCKET?: TrackerBucketLike;
  EDGEFETCH_DEV_TELEMETRY?: string;
  EDGEFETCH_DEV_TELEMETRY_ENDPOINT?: string;
  EDGEFETCH_DEV_TELEMETRY_URL?: string;
  DO_NOT_TRACK?: string;
}

const JOB_ID_RE = /^[A-Za-z0-9_-]{1,64}$/;
const DEFAULT_UA = 'EdgeFetch/2.7 (bot@edgefetch.dev)';
const ALLOWED_TARGETS: FetchTarget[] = ['auto', 'agent', 'container'];
const DAILY_CLEANUP_INTERVAL_MS = 24 * 60 * 60_000;
const MAX_SQLITE_TRACKED_HOSTS = 512;

const MAX_CONCURRENT_SCRAPES_PER_USER = 16;
const MAX_CONCURRENT_INTERACTS_PER_USER = 4;

const inFlightScrapesByUser = new Map<string, number>();
const inFlightInteractsByUser = new Map<string, number>();

function tryAcquireUserConcurrencySlot(
  buckets: Map<string, number>,
  userId: string | undefined,
  maxConcurrent: number,
): (() => void) | null {
  const key = (userId ?? '').trim() || 'owner';
  const cur = buckets.get(key) ?? 0;
  if (cur >= maxConcurrent) return null;
  buckets.set(key, cur + 1);
  let released = false;
  return () => {
    if (released) return;
    released = true;
    const next = (buckets.get(key) ?? 1) - 1;
    if (next <= 0) buckets.delete(key);
    else buckets.set(key, next);
  };
}

function userQuotaExceededResponse(message: string, isPrivate = false): Response {
  return Response.json(
    { ok: false, success: false, error: 'user_quota_exceeded', message, ...(isPrivate ? { visibility: 'private' } : {}) },
    { status: 429, headers: { 'cache-control': isPrivate ? 'private, no-store' : 'no-store', 'retry-after': '2' } },
  );
}

export { CrawlWorkflow, IngestWorkflow };

export class AgentHubDO extends DurableObject<Env> {
  private readonly engine: AgentHubEngine;
  private readonly oauth: OAuthStore;
  private readonly mcpVault: McpVaultStore;
  private readonly activity: ActivityStore;
  private readonly settings: HubSettingsStore;
  private readonly hubSecrets: HubSecretsStore;
  private readonly accessPolicy: AccessPolicyStore;
  private readonly helloLogBySocket = new WeakMap<WebSocket, number>();
  private alarmScheduled = false;
  private trackerHydrated = false;
  private trackerHydrateRetryAt = 0;

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
        ${MCP_VAULT_SQLITE_SCHEMA}
        ${ACTIVITY_SQLITE_SCHEMA}
        ${HUB_SETTINGS_SQLITE_SCHEMA}
        ${HUB_SECRETS_SQLITE_SCHEMA}
        ${ACCESS_POLICY_SQLITE_SCHEMA}
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

    let selfHost: string | undefined;
    if (env.EDGEFETCH_PUBLIC_ORIGIN) {
      try {
        selfHost = new URL(env.EDGEFETCH_PUBLIC_ORIGIN).hostname;
      } catch {
        // ignore invalid EDGEFETCH_PUBLIC_ORIGIN
      }
    }
    this.engine = new AgentHubEngine({
      getSockets: (tag) => this.ctx.getWebSockets(tag) as unknown as HubSocketLike[],
      cooldowns,
      hostWindows,
      affinities,
      hostHealth,
      ...(selfHost ? { selfHost } : {}),
    });
    this.oauth = createSqliteOAuthStore(this.ctx.storage.sql as unknown as SqlStorageLike);
    this.mcpVault = createSqliteMcpVaultStore(this.ctx.storage.sql as unknown as SqlStorageLike);
    this.activity = createSqliteActivityStore(this.ctx.storage.sql as unknown as SqlStorageLike);
    this.settings = createSqliteHubSettingsStore(this.ctx.storage.sql as unknown as SqlStorageLike);
    this.hubSecrets = createSqliteHubSecretsStore(this.ctx.storage.sql as unknown as SqlStorageLike);
    this.accessPolicy = createSqliteAccessPolicyStore(this.ctx.storage.sql as unknown as SqlStorageLike);
  }

  override async alarm(): Promise<void> {
    const now = Date.now();
    this.ctx.storage.sql.exec('DELETE FROM site_cooldowns WHERE expires_at <= ?', now);
    this.ctx.storage.sql.exec('DELETE FROM host_windows WHERE next_allowed_at <= ?', now);
    this.ctx.storage.sql.exec('DELETE FROM host_affinities WHERE expires_at <= ?', now);
    this.ctx.storage.sql.exec('DELETE FROM oauth_codes WHERE expires_at <= ?', now);
    this.ctx.storage.sql.exec('DELETE FROM oauth_tokens WHERE expires_at <= ?', now);
    this.ctx.storage.sql.exec('DELETE FROM mcp_oauth_states WHERE expires_at <= ?', now);
    this.ctx.storage.sql.exec('DELETE FROM auth_failures WHERE reset_at <= ?', now);
    this.ctx.storage.sql.exec('DELETE FROM admin_revocations WHERE expires_at <= ?', now);

    // Cold-R2 EasyPrivacy bootstrap: if R2 has no stored tracker list yet when a background DO alarm fires,
    // hydrate EasyPrivacy once (still strictly obeying the 6-hour MIN_TRACKER_POLL_INTERVAL_MS floor) and
    // broadcast immediately to connected browser-v1 agents without waiting up to 24h for 04:00 UTC cron.
    const trackerBucket = this.env.ARTIFACTS ?? this.env.TRACKER_BUCKET;
    if (trackerBucket && !isTrackerListDisabled(this.env)) {
      const settingVal = await this.settings.getSetting('tracker_list').catch(() => null);
      if (!isTrackerListDisabled(this.env, settingVal)) {
        const stored = await loadStoredTrackerList(trackerBucket);
        if (!stored) {
          const refreshed = await refreshHubTrackerList({
            bucket: trackerBucket,
            fetchFn: this.env.SAFE_PUBLIC_FETCH ?? this.env.SAFE_FETCH ?? fetch,
            env: this.env,
            hubSettingValue: settingVal,
            publicOrigin: this.env.EDGEFETCH_PUBLIC_ORIGIN,
          }).catch(() => null);
          if (refreshed?.current) {
            const extraAllow = resolveExtraNeverBlockHosts({ publicOrigin: this.env.EDGEFETCH_PUBLIC_ORIGIN });
            await this.syncTrackerList(
              refreshed.current.meta.version,
              buildTrackerListWsFrames(refreshed.current, extraAllow),
            );
            await Promise.resolve(
              this.activity.recordEvent({
                level: 'info',
                category: 'agent',
                event: 'tracker_list_refreshed',
                summary: `Bootstrapped EasyPrivacy tracker list v${refreshed.current.meta.version} (${refreshed.current.meta.hostCount} hosts) via DO alarm`,
                details: {
                  version: refreshed.current.meta.version,
                  hostCount: refreshed.current.meta.hostCount,
                  source: 'do_alarm_bootstrap',
                },
              }),
            ).catch(() => undefined);
          }
        }
      }
    }

    await this.ctx.storage.setAlarm(now + DAILY_CLEANUP_INTERVAL_MS);
    this.alarmScheduled = true;
  }

  private async ensureTrackerListHydrated(): Promise<void> {
    const now = Date.now();
    if (this.trackerHydrated || now < this.trackerHydrateRetryAt) return;
    const settingVal = await this.settings.getSetting('tracker_list').catch(() => null);
    if (isTrackerListDisabled(this.env, settingVal)) {
      this.trackerHydrated = true;
      return;
    }
    const bucket = this.env.ARTIFACTS ?? this.env.TRACKER_BUCKET;
    if (!bucket) {
      this.trackerHydrated = true;
      return;
    }
    const stored = await loadStoredTrackerList(bucket);
    if (!stored) {
      this.trackerHydrateRetryAt = now + 60_000;
      const nextAlarm = await this.ctx.storage.getAlarm().catch(() => null);
      if (!nextAlarm || nextAlarm > now + 60_000) {
        await this.ctx.storage.setAlarm(now + 10_000).catch(() => undefined);
      }
      return;
    }
    this.trackerHydrated = true;
    const extraAllow = resolveExtraNeverBlockHosts({ publicOrigin: this.env.EDGEFETCH_PUBLIC_ORIGIN });
    this.engine.setTrackerListBroadcast(stored.meta.version, buildTrackerListWsFrames(stored, extraAllow));
  }

  async syncTrackerList(version: string | null, frames: string[]): Promise<void> {
    this.trackerHydrated = true;
    this.trackerHydrateRetryAt = 0;
    this.engine.setTrackerListBroadcast(version, frames);
  }

  override async fetch(request: Request): Promise<Response> {
    if (request.headers.get('upgrade')?.toLowerCase() !== 'websocket') {
      return Response.json({ error: 'upgrade_required' }, { status: 426 });
    }
    await this.ensureTrackerListHydrated();
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
    this.engine.sendCurrentTrackerListToSocket(server as unknown as HubSocketLike);
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

  async listAgents(): Promise<{
    connected: number;
    distinctPublicIps: number;
    trackerListVersion: string | null;
    agents: AgentAttachment[];
  }> {
    await this.ensureTrackerListHydrated();
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

  async recordMcpTurn(params: McpTurnRecordInput): Promise<void> {
    if (this.activity.recordMcpTurn) {
      await this.activity.recordMcpTurn(params);
      return;
    }
    await this.activity.recordMcpCall(params);
    if (params.event) {
      await this.activity.recordEvent(params.event);
    }
  }

  async getPortalState(now: number): Promise<{
    connected: number;
    distinctPublicIps: number;
    trackerListVersion: string | null;
    agents: AgentAttachment[];
    affinities: AffinityPin[];
    grants: OAuthGrantSummary[];
    mcpClients: McpClientActivity[];
    events: HubEventRecord[];
    users: HubUserRecord[];
  }> {
    await this.ensureTrackerListHydrated();
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
  async oauthGetRefreshTokenLineageHint(
    h: string,
    now: number,
  ): Promise<{ grantId: string; rotationCounter: number } | null> {
    return (await this.oauth.getRefreshTokenLineageHint?.(h, now)) ?? null;
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
  async oauthUpdateUserRole(id: string, role: UserRole, promotedByOwnerId?: string | null): Promise<boolean> {
    return this.oauth.updateUserRole ? await this.oauth.updateUserRole(id, role, promotedByOwnerId) : false;
  }
  async oauthEnforcePinnedFounderOwners(pinnedOwnerId: string): Promise<number> {
    return this.oauth.enforcePinnedFounderOwners ? await this.oauth.enforcePinnedFounderOwners(pinnedOwnerId) : 0;
  }

  async oauthResolveMcpAccessToken(params: {
    tokenHash: string;
    now: number;
    pinnedOwnerId?: string | null;
  }): Promise<{ token: OAuthTokenRecord | null; user: HubUserRecord | null }> {
    const token = await this.oauth.getAccessToken(params.tokenHash, params.now);
    if (!token) return { token: null, user: null };
    const uid = token.userId ?? 'owner';
    if (uid === 'owner') return { token, user: null };
    if (params.pinnedOwnerId && this.oauth.enforcePinnedFounderOwners) {
      await this.oauth.enforcePinnedFounderOwners(params.pinnedOwnerId);
    }
    const user = this.oauth.getUser ? await this.oauth.getUser(uid) : null;
    return { token, user };
  }

  // Per-user AES-256-GCM MCP Vault SQLite RPC methods
  async vaultListServers(userId: string): Promise<StoredMcpServerRow[]> {
    return await this.mcpVault.listServers(userId);
  }
  async vaultGetServer(userId: string, slugOrDomain: string): Promise<StoredMcpServerRow | null> {
    return await this.mcpVault.getServer(userId, slugOrDomain);
  }
  async vaultUpsertServer(row: StoredMcpServerRow): Promise<void> {
    await this.mcpVault.upsertServer(row);
  }
  async vaultResealServerSecret(
    params: Parameters<NonNullable<McpVaultStore['resealServerSecret']>>[0],
  ): Promise<boolean> {
    if (typeof this.mcpVault.resealServerSecret === 'function') {
      return await this.mcpVault.resealServerSecret(params);
    }
    return false;
  }
  async vaultDeleteServer(userId: string, slug: string): Promise<boolean> {
    return await this.mcpVault.deleteServer(userId, slug);
  }
  async vaultPutOAuthState(row: PendingMcpOAuthStateRow): Promise<void> {
    await this.mcpVault.putOAuthState(row);
  }
  async vaultConsumeOAuthState(stateHash: string, userId: string, now: number): Promise<PendingMcpOAuthStateRow | null> {
    return await this.mcpVault.consumeOAuthState(stateHash, userId, now);
  }

  // `hub_secrets` + `access_policies`/`mcp_server_shares` RPCs. Names match HubSecretsStore / AccessPolicyStore so the
  // stub itself satisfies those ports (hub/src/hub-secrets.ts, hub/src/access-policy.ts).
  async listHubSecretRows(): Promise<HubSecretRow[]> {
    return await this.hubSecrets.listHubSecretRows();
  }
  async putHubSecretRow(row: HubSecretRow): Promise<void> {
    await this.hubSecrets.putHubSecretRow(row);
  }
  async deleteHubSecretRow(name: string): Promise<boolean> {
    return await this.hubSecrets.deleteHubSecretRow(name);
  }
  async listAccessPolicyRules(): Promise<AccessPolicyRuleRow[]> {
    return await this.accessPolicy.listAccessPolicyRules();
  }
  async putAccessPolicyRule(row: AccessPolicyRuleRow): Promise<void> {
    await this.accessPolicy.putAccessPolicyRule(row);
  }
  async deleteAccessPolicyRule(subject: string, resource: string): Promise<boolean> {
    return await this.accessPolicy.deleteAccessPolicyRule(subject, resource);
  }
  async listMcpServerShares(): Promise<McpServerShareRow[]> {
    return await this.accessPolicy.listMcpServerShares();
  }
  async putMcpServerShare(row: McpServerShareRow): Promise<void> {
    await this.accessPolicy.putMcpServerShare(row);
  }
  async deleteMcpServerShare(ownerUserId: string, slug: string, subject: string): Promise<boolean> {
    return await this.accessPolicy.deleteMcpServerShare(ownerUserId, slug, subject);
  }

  async getHubSetting(key: string): Promise<string | null> {
    return await this.settings.getSetting(key);
  }
  async setHubSetting(key: string, value: string): Promise<void> {
    await this.settings.setSetting(key, value);
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
      } else if (msg.type === 'tracker_list_ack') {
        this.engine.noteTrackerListAck(ws as unknown as HubSocketLike, msg.version);
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
  const enforcePinnedFounderOwnersWithFallback = async (pinnedOwnerId: string): Promise<number> => {
    const stub = hub() as unknown as Partial<AgentHubDO>;
    if (typeof stub.oauthEnforcePinnedFounderOwners === 'function') {
      return await stub.oauthEnforcePinnedFounderOwners(pinnedOwnerId);
    }
    const users = await hub().oauthListUsers();
    let demoted = 0;
    for (const u of users) {
      if (
        u.userId !== 'owner' &&
        u.role === 'owner' &&
        String(u.githubId ?? '') !== pinnedOwnerId &&
        u.promotedByOwnerId !== pinnedOwnerId &&
        u.promotedByOwnerId !== 'owner'
      ) {
        await hub().oauthUpsertUser({
          ...u,
          role: 'member',
          promotedByOwnerId: undefined,
          sessionEpoch: (u.sessionEpoch ?? 1) + 1,
          mutationKind: 'demote_unapproved_owner',
          reconcilePinnedOwnerId: pinnedOwnerId,
        });
        demoted++;
      }
    }
    return demoted;
  };

  return {
    putClient: (c) => hub().oauthPutClient(c),
    getClient: (id) => hub().oauthGetClient(id),
    putCode: (c) => hub().oauthPutCode(c),
    consumeCode: (h, now) => hub().oauthConsumeCode(h, now),
    putTokenPair: (p) => hub().oauthPutTokenPair(p),
    getAccessToken: (h, now) => hub().oauthGetAccessToken(h, now),
    consumeRefreshToken: (h, now) => hub().oauthConsumeRefreshToken(h, now),
    getRefreshTokenLineageHint: async (h, now) => {
      const stub = hub() as unknown as Partial<AgentHubDO>;
      if (typeof stub.oauthGetRefreshTokenLineageHint === 'function') {
        return await stub.oauthGetRefreshTokenLineageHint(h, now);
      }
      return null;
    },
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
    updateUserRole: (id, role, promotedByOwnerId) => hub().oauthUpdateUserRole(id, role, promotedByOwnerId),
    resolveMcpAccessToken: async (params) => {
      const stub = hub() as unknown as Partial<AgentHubDO>;
      if (typeof stub.oauthResolveMcpAccessToken === 'function') {
        return await stub.oauthResolveMcpAccessToken(params);
      }
      const token = await hub().oauthGetAccessToken(params.tokenHash, params.now);
      if (!token) return { token: null, user: null };
      const uid = token.userId ?? 'owner';
      if (uid === 'owner') return { token, user: null };
      if (params.pinnedOwnerId) {
        await enforcePinnedFounderOwnersWithFallback(params.pinnedOwnerId);
      }
      const user = typeof stub.oauthGetUser === 'function' ? await stub.oauthGetUser(uid) : null;
      return { token, user };
    },
    enforcePinnedFounderOwners: enforcePinnedFounderOwnersWithFallback,
  };
}

function hubMcpVaultStore(hub: () => DurableObjectStub<AgentHubDO>): McpVaultStore {
  return {
    listServers: async (userId) => {
      const stub = hub() as unknown as Partial<AgentHubDO>;
      return typeof stub.vaultListServers === 'function' ? await stub.vaultListServers(userId) : [];
    },
    getServer: async (userId, slugOrDomain) => {
      const stub = hub() as unknown as Partial<AgentHubDO>;
      return typeof stub.vaultGetServer === 'function' ? await stub.vaultGetServer(userId, slugOrDomain) : null;
    },
    upsertServer: async (row) => {
      const stub = hub() as unknown as Partial<AgentHubDO>;
      if (typeof stub.vaultUpsertServer === 'function') await stub.vaultUpsertServer(row);
    },
    resealServerSecret: async (params) => {
      const stub = hub() as unknown as Partial<AgentHubDO>;
      return typeof stub.vaultResealServerSecret === 'function'
        ? await stub.vaultResealServerSecret(params)
        : false;
    },
    deleteServer: async (userId, slug) => {
      const stub = hub() as unknown as Partial<AgentHubDO>;
      return typeof stub.vaultDeleteServer === 'function' ? await stub.vaultDeleteServer(userId, slug) : false;
    },
    putOAuthState: async (row) => {
      const stub = hub() as unknown as Partial<AgentHubDO>;
      if (typeof stub.vaultPutOAuthState === 'function') await stub.vaultPutOAuthState(row);
    },
    consumeOAuthState: async (stateHash, userId, now) => {
      const stub = hub() as unknown as Partial<AgentHubDO>;
      return typeof stub.vaultConsumeOAuthState === 'function'
        ? await stub.vaultConsumeOAuthState(stateHash, userId, now)
        : null;
    },
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
    recordMcpTurn: (p) => {
      const stub = hub() as unknown as Partial<AgentHubDO>;
      if (typeof stub.recordMcpTurn === 'function') {
        return stub.recordMcpTurn(p).catch(() => undefined);
      }
      return hub()
        .recordMcpCall(p)
        .then(() => (p.event ? hub().recordHubEvents([p.event]) : undefined))
        .catch(() => undefined);
    },
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

const devTelemetrySettingCache = new WeakMap<object, { value: string | null; expiresAt: number }>();

/** Module-level handle on the real authorizer; `fetch()` shadows `authorizeMcpRequest` with a policy-gated wrapper. */
const authorizeMcpRequestUngated = authorizeMcpRequest;

/** Thrown by the gated authorizer when access policy denies a route; converted to a 403 by `withRouteSpan`/`fetch`. */
class AccessPolicyDeniedSignal extends Error {
  constructor(readonly response: Response) {
    super('forbidden_by_policy');
  }
}

/**
 * Route-policy resource path for a request path: `/v1/*` as-is, Firecrawl-compatible `/v2/*` and
 * `/compat/firecrawl/v2/*` and Tavily `/compat/tavily/*` mapped onto their `/v1/*` equivalents so compat aliases
 * can't bypass a `/v1` rule. `null` = not policy-governed (e.g. `/mcp`, `/admin`, `/oauth/*`).
 */
function policyRoutePathFor(pathname: string): string | null {
  if (pathname === '/v1' || pathname.startsWith('/v1/')) return pathname;
  if (pathname.startsWith('/v2/')) return `/v1${pathname.slice('/v2'.length)}`;
  if (pathname.startsWith('/compat/firecrawl/v2/')) return `/v1${pathname.slice('/compat/firecrawl/v2'.length)}`;
  if (pathname.startsWith('/compat/tavily/')) return `/v1/${pathname.slice('/compat/tavily/'.length)}`;
  return null;
}

export default {
  async fetch(request: Request, env: Env, ctx?: ExecutionContext): Promise<Response> {
    // Admin-managed provider-key overrides (hub_secrets) win over deployment env for this request. Bootstrap
    // secrets (CALLER_TOKEN, VAULT_MASTER_KEY, ...) can never be overridden, so auth is unaffected. No-op without
    // VAULT_MASTER_KEY; cached 30 s per isolate; never throws.
    const deploymentEnv: Env = env;
    env = await applyHubSecretOverlayFromBinding(env);
    const url = new URL(request.url);
    if (typeof env.EDGEFETCH_PUBLIC_ORIGIN === 'string' && env.EDGEFETCH_PUBLIC_ORIGIN.trim() !== '') {
      try {
        const pub = new URL(env.EDGEFETCH_PUBLIC_ORIGIN.trim());
        if ((pub.protocol === 'https:' || pub.protocol === 'http:') && !pub.username && !pub.password) {
          url.protocol = pub.protocol;
          url.host = pub.host;
        }
      } catch {
        // Ignore malformed EDGEFETCH_PUBLIC_ORIGIN and fall back to request URL
      }
    }
    const rootTracer = RequestTracer.fromRequest(request, { suppressWhenUnsampledHealth: true });
    const shardNames = (env.HUB_SHARDS ?? 'global')
      .split(',')
      .map((s) => s.trim())
      .filter((s) => /^[a-z0-9_-]{1,32}$/i.test(s));
    if (shardNames.length === 0) shardNames.push('global');
    const hubShard = (name = shardNames[0]!) => env.AGENT_HUB.get(env.AGENT_HUB.idFromName(name));
    const hub = () => hubShard(shardNames[0]!);

    const getCachedDevTelemetrySetting = async (): Promise<string | null> => {
      if (isTruthyTelemetryFlag(env.DO_NOT_TRACK)) return null;
      const cacheKey = (env.AGENT_HUB as unknown as object | undefined) ?? null;
      const now = Date.now();
      if (cacheKey) {
        const hit = devTelemetrySettingCache.get(cacheKey);
        if (hit && hit.expiresAt > now) return hit.value;
      }
      try {
        const stub = hub() as unknown as { getHubSetting?: (k: string) => Promise<string | null> };
        const val = typeof stub.getHubSetting === 'function' ? await stub.getHubSetting(DEV_TELEMETRY_SETTING_KEY) : null;
        if (cacheKey) {
          devTelemetrySettingCache.set(cacheKey, { value: val, expiresAt: now + 30_000 });
        }
        return val;
      } catch {
        return null;
      }
    };

    const flushTracerWithTelemetry = async (tracer: RequestTracer): Promise<boolean> => {
      const devTelemetrySetting = await getCachedDevTelemetrySetting();
      return tracer.flush({ env, fetchFn: env.SAFE_FETCH, devTelemetrySetting });
    };

    const trackedCtx: ExecutionContext | undefined = ctx
      ? ({
          waitUntil(promise: Promise<unknown>) {
            const active = getActiveRequestTracer() ?? rootTracer;
            const wrapped = active
              .bindPromise(promise)
              .catch(() => undefined)
              .finally(() => flushTracerWithTelemetry(rootTracer).catch(() => false));
            ctx.waitUntil(wrapped);
          },
          passThroughOnException() {
            ctx.passThroughOnException?.();
          },
        } as unknown as ExecutionContext)
      : undefined;
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
          const activeCaller = getActiveCallerAuthContext();
          const tenantUserId = activeCaller?.userId ? sanitizeStorageUserId(activeCaller.userId) : 'owner';
          const isPrivateTenant = tenantUserId !== 'owner' && tenantUserId !== 'anonymous';

          let wantsIncludeBody = false;
          let maxInlineBodyBytesOpt: number | undefined;
          let bodyRetentionOpt: ArtifactRetention | 'off' | undefined;
          let bodyCollectionId: string | undefined;
          const rawBase64RequestIds = new Set<string>();
          try {
            const parsedCall = JSON.parse(body) as {
              options?: {
                includeBody?: boolean;
                maxInlineBodyBytes?: number;
                artifactRetention?: string;
                collectionId?: string;
              };
              requests?: Array<{
                id?: unknown;
                kind?: unknown;
                formats?: unknown;
              }>;
            };
            wantsIncludeBody = Boolean(parsedCall.options?.includeBody);
            if (
              typeof parsedCall.options?.maxInlineBodyBytes === 'number' &&
              Number.isFinite(parsedCall.options.maxInlineBodyBytes) &&
              parsedCall.options.maxInlineBodyBytes > 0
            ) {
              maxInlineBodyBytesOpt = Math.floor(parsedCall.options.maxInlineBodyBytes);
            }
            const rawOptRet = parsedCall.options?.artifactRetention;
            if (rawOptRet === 'stored' || rawOptRet === 'transient' || rawOptRet === 'off') {
              bodyRetentionOpt = rawOptRet;
            }
            const rawColl = parsedCall.options?.collectionId;
            if (typeof rawColl === 'string' && rawColl.trim()) {
              const resolvedBodyColl = resolveUserCollectionId(
                rawColl.trim(),
                tenantUserId,
                isPrivateTenant ? 'private' : 'public',
              );
              if (resolvedBodyColl.ok) {
                bodyCollectionId = resolvedBodyColl.scopedId;
              }
            }
            if (Array.isArray(parsedCall.requests)) {
              for (const reqItem of parsedCall.requests) {
                if (!reqItem || typeof reqItem.id !== 'string' || !reqItem.id) continue;
                const isBinaryKind = reqItem.kind === 'binary';
                const hasRawBase64Format =
                  Array.isArray(reqItem.formats) &&
                  reqItem.formats.some((f) => f === 'rawBase64' || f === 'base64');
                if (isBinaryKind || hasRawBase64Format) {
                  rawBase64RequestIds.add(reqItem.id);
                }
              }
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
            !isPrivateTenant && env.ARTIFACTS && (wantsIncludeBody || effectiveRetentionPref === 'stored') && resolvedRetention
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
                if (res.status === 200 && isPrivateTenant && env.ARTIFACTS && resolvedRetention) {
                  try {
                    const parsedReply = JSON.parse(rawCompletedBody) as {
                      results?: Array<Record<string, unknown>>;
                      [k: string]: unknown;
                    };
                    if (Array.isArray(parsedReply.results)) {
                      let mutated = false;
                      for (const item of parsedReply.results) {
                        if (!item || typeof item !== 'object' || item.outcome !== 'ok' || typeof item.body !== 'string') {
                          continue;
                        }
                        let rawBytes: Uint8Array;
                        if (item.bodyEncoding === 'base64') {
                          const bin = atob(item.body);
                          rawBytes = new Uint8Array(bin.length);
                          for (let i = 0; i < bin.length; i++) rawBytes[i] = bin.charCodeAt(i);
                        } else {
                          rawBytes = new TextEncoder().encode(item.body);
                        }
                        if (rawBytes.byteLength > MAX_ARTIFACT_CONTENT_BYTES) continue;
                        const privArt = await writePrivateArtifactToR2({
                          bucket: env.ARTIFACTS,
                          userId: tenantUserId,
                          rawBytes,
                          retention: resolvedRetention,
                        });
                        item.artifact = {
                          blobSha256: privArt.blobSha256,
                          contentSha256: privArt.contentSha256,
                          contentBytes: rawBytes.byteLength,
                          storedBytes: 0,
                          encoding: 'gzip',
                          retention: resolvedRetention,
                          visibility: 'private',
                        };
                        if (!hydrateInline) {
                          delete item.body;
                          delete item.bodyEncoding;
                          item.bodyOmitted = true;
                        }
                        mutated = true;
                      }
                      if (mutated) {
                        bodyText = JSON.stringify(parsedReply);
                      }
                    }
                  } catch {
                    // Preserve raw bodyText if reply is non-JSON
                  }
                } else if (res.status === 200 && env.ARTIFACTS && wantsIncludeBody && hydrateInline) {
                  const hydStart = Date.now();
                  bodyText = await hydrateReplyBodiesFromR2(
                    rawCompletedBody,
                    env.ARTIFACTS,
                    undefined,
                    maxInlineBodyBytesOpt,
                    rawBase64RequestIds.size > 0 ? rawBase64RequestIds : undefined,
                  );
                  hydrateR2Ms = Date.now() - hydStart;
                }

                // P12 & S4: Move R2 manifest write + Cloudflare Workflows `INGEST.create(...)` + activity-log RPC off the
                // synchronous HTTP response path into `ctx.waitUntil(...)` whenever `env.INGEST` and `ctx.waitUntil` are bound!
                // Multi-tenant isolation: NEVER persist non-owner (`isPrivateTenant`) fetches into shared `META` (`pages`/`fetches`/`artifacts`/`documents`)!
                const runPostFetchPersistence = async () => {
                  if (!isPrivateTenant && res.status === 200 && effectiveRetentionPref !== 'off' && env.ARTIFACTS && env.META) {
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

                if (
                  trackedCtx?.waitUntil &&
                  ((env.INGEST && !crawlId && !resolvedCollectionId) || effectiveRetentionPref === 'off')
                ) {
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
                span.setAttribute('edgefetch.source', source.slice(0, 64));
                span.setAttribute('edgefetch.target', target);
                span.setAttribute('edgefetch.dispatch_ms', dispatchMs);
                span.setAttribute('http.response.status_code', res.status);
                return { status: res.status, via, bodyText, stageTimingsMs, ...(retryAfter ? { retryAfter } : {}) };
              },
            ),
          );

          if (!activeParent && !localTracer.suppressed && localTracer.sampled) {
            const flushPromise = flushTracerWithTelemetry(localTracer);
            if (ctx?.waitUntil) {
              ctx.waitUntil(flushPromise);
            } else {
              await flushPromise;
            }
          }
          return dispatchResult;
        },
      );

    const accessPolicyStore = (): AccessPolicyStore | null => {
      if (!env.AGENT_HUB) return null;
      const stub = hub() as unknown as Partial<AccessPolicyStore>;
      // Real DO stubs expose every RPC; minimal test doubles without the policy RPCs mean "no policy configured".
      return typeof stub.listAccessPolicyRules === 'function' && typeof stub.listMcpServerShares === 'function'
        ? (stub as AccessPolicyStore)
        : null;
    };
    const accessPolicyCacheKey = (env.AGENT_HUB as unknown as object | undefined) ?? 'default';
    /** Spread into executeFederatedMcpQuery / tryScrapeViaConnectedMcp so shared MCP servers resolve for members. */
    const federationPolicyOpts = (): { accessPolicy?: AccessPolicyStore; accessPolicyCacheKey?: string | object } => {
      const store = accessPolicyStore();
      return store ? { accessPolicy: store, accessPolicyCacheKey } : {};
    };

    /**
     * Policy-gated authorizer (shadows the module import for every route below). After a SUCCESSFUL auth on a
     * policy-governed path it evaluates `route:<path>`; a denial throws AccessPolicyDeniedSignal carrying the 403
     * `forbidden_by_policy` response (logged to the activity log), so every /v1 route is covered by this one hook.
     * Owners bypass route policy. Policy-store failures fail closed for non-owners.
     */
    const authorizeMcpRequest: typeof authorizeMcpRequestUngated = async (params) => {
      const res = await authorizeMcpRequestUngated(params);
      const policyPath = policyRoutePathFor(url.pathname);
      if (!res.ok || !policyPath || res.role === 'owner') return res;
      const store = accessPolicyStore();
      if (!store) return res;
      const caller = { userId: res.userId || resolveCallerUserId(res), role: res.role };
      let decision: { allowed: boolean; reason: string };
      try {
        decision = await evaluateRouteAccess(caller, policyPath, { store, cacheKey: accessPolicyCacheKey });
      } catch {
        decision = { allowed: false, reason: 'policy_unavailable' };
      }
      if (decision.allowed) return res;
      void request.body?.cancel().catch(() => undefined);
      await hubActivityProxy(hub).recordEvent({
        level: 'warn',
        category: 'admin',
        event: 'access_denied_route',
        summary: `Route ${policyPath} denied by access policy for ${caller.userId}`,
        details: { userId: caller.userId, path: policyPath, reason: decision.reason },
      });
      throw new AccessPolicyDeniedSignal(
        Response.json(
          { ok: false, error: 'forbidden_by_policy', path: policyPath, reason: decision.reason },
          { status: 403, headers: { 'cache-control': 'private, no-store' } },
        ),
      );
    };

    const withRouteSpan = async (
      name: string,
      attrs: Record<string, string | number | boolean | undefined>,
      fn: () => Promise<Response>,
    ): Promise<Response> =>
      (getActiveRequestTracer() ?? rootTracer).withSpan(name, { kind: 1, attributes: attrs }, async (routeSpan) => {
        let res: Response;
        try {
          res = await fn();
        } catch (err) {
          if (!(err instanceof AccessPolicyDeniedSignal)) throw err;
          res = err.response;
        }
        routeSpan.setAttribute('http.response.status_code', res.status);
        routeSpan.setStatus(res.status < 500);
        return res;
      });

    const routeRequest = async (): Promise<Response> => {
      if (request.method === 'GET' && url.pathname === '/health') {
        return Response.json({ ok: true });
      }
      const openApiRes = handleOpenApiRoute(request, url, HUB_VERSION);
      if (openApiRes) return openApiRes;
      const botRes = await handleBotTransparencyRoutes(request, url, env, HUB_VERSION);
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
          metaDb: env.META,
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
      const vaultStore: McpVaultStore = env.AGENT_HUB
        ? hubMcpVaultStore(hub)
        : {
            listServers: () => [],
            getServer: () => null,
            upsertServer: () => undefined,
            deleteServer: () => false,
            putOAuthState: () => undefined,
            consumeOAuthState: () => null,
          };
      const activity = hubActivityProxy(hub);
      const safePublicFetch = env.SAFE_PUBLIC_FETCH ?? env.SAFE_FETCH ?? fetch;

      /** `company` + `salaries` executors shared by the MCP tools and the REST routes. */
      const makeVerticalExecutors = (sourceLabel: string, callerUserId: string, callerTier: string) => {
        const runJobs = (jobsArgs: Record<string, unknown>) =>
          executeJobsCall({
            payload: jobsArgs as JobsToolPayload,
            env: env as unknown as OptionalStorageBindings & Record<string, unknown>,
            userId: callerUserId,
            authTier: callerTier,
            executeSearch: async (sArgs) => {
              const sOut = await executeSearchCall({
                payload: sArgs as SearchRequestPayload,
                env,
                executeHubFetch,
                source: `${sourceLabel}-jobs-search`,
                userId: callerUserId,
              });
              return { status: sOut.status, body: sOut.body };
            },
            executeScrape: async (scArgs) => {
              const scOut = await executeScrapeCall({
                payload: scArgs as ScrapeRequestPayload,
                env,
                executeHubFetch,
                selfHost: url.hostname,
                source: `${sourceLabel}-jobs-scrape`,
                userId: callerUserId,
              });
              return { status: scOut.status, body: scOut.body };
            },
          });
        const activeScopes = getActiveCallerAuthContext()?.scopes ?? [];
        // Google Maps enrichment calls the caller's own connected Maps MCP, so it needs the same `mcp:call` scope.
        const mayCallMcp = activeScopes.length === 0 || activeScopes.includes('mcp:call');
        const callMapsPlaces = mayCallMcp
          ? async (query: string): Promise<string | null> => {
              const listed = await executeFederatedMcpQuery({
                userId: callerUserId,
                input: { action: 'list_tools', server: GOOGLE_MAPS_MCP_SLUG },
                vaultStore,
                ...federationPolicyOpts(),
                vaultMasterKey: env.VAULT_MASTER_KEY,
                fetchFn: safePublicFetch,
                selfHost: url.hostname,
              });
              if (listed.status !== 200) return null;
              const tools = Array.isArray(listed.body.tools) ? (listed.body.tools as Array<Record<string, unknown>>) : [];
              const tool = tools.find((t) => t.name === 'search_places');
              if (!tool) return null;
              const props = ((tool.inputSchema as { properties?: Record<string, { type?: string }> } | undefined)?.properties ?? {});
              const required = ((tool.inputSchema as { required?: string[] } | undefined)?.required ?? []).filter(
                (k) => props[k]?.type === 'string',
              );
              const argName =
                required[0] ??
                Object.keys(props).find((k) => /query|text/i.test(k) && props[k]?.type === 'string') ??
                'textQuery';
              const out = await executeFederatedMcpQuery({
                userId: callerUserId,
                input: { action: 'call_tool', server: GOOGLE_MAPS_MCP_SLUG, tool: 'search_places', arguments: { [argName]: query } },
                vaultStore,
                ...federationPolicyOpts(),
                vaultMasterKey: env.VAULT_MASTER_KEY,
                fetchFn: safePublicFetch,
                selfHost: url.hostname,
              });
              if (out.status !== 200) return null;
              const res = (out.body.result ?? out.body) as unknown;
              return JSON.stringify(res);
            }
          : undefined;
        return {
          company: (args: Record<string, unknown>) =>
            executeCompanyCall({
              payload: args as CompanyToolPayload,
              deps: {
                scrapePage: async (pageUrl) => {
                  const scOut = await executeScrapeCall({
                    payload: { url: pageUrl, formats: ['markdown', 'rawHtml'], renderMode: 'auto' } as ScrapeRequestPayload,
                    env,
                    executeHubFetch,
                    selfHost: url.hostname,
                    source: `${sourceLabel}-company-page`,
                    userId: callerUserId,
                  });
                  return { status: scOut.status, body: scOut.body };
                },
                fetchFn: safePublicFetch,
                runJobs: async ({ company, domains, limit }) =>
                  runJobs({ company, ...(domains ? { domains } : {}), limit, includeBuiltIn: false }),
                ...(callMapsPlaces ? { callMapsPlaces } : {}),
              },
            }),
          salaries: (args: Record<string, unknown>) =>
            executeSalariesCall({
              payload: args as SalariesToolPayload,
              env: { ...(env.META ? { META: env.META } : {}) },
              runJobsSearch: async ({ query, locations, company }) =>
                runJobs({ query, ...(locations ? { locations } : {}), ...(company ? { company } : {}), limit: 50, includeBuiltIn: false }),
            }),
        };
      };

      const makeCatalogHubFetch = (sourceLabel: string): CatalogHubFetchFn => {
        const boundTracer = getActiveRequestTracer();
        return async ({ url: pageUrl, kind = 'json', accept = 'application/json', maxBytes, timeoutMs, target: rawTgt, site: rawSite, tracer }) => {
          const tgt: FetchTarget = rawTgt === 'agent' || rawTgt === 'container' ? rawTgt : 'auto';
          const siteStr = typeof rawSite === 'string' && rawSite.trim() ? rawSite.trim() : undefined;
          const boundedMaxBytes =
            typeof maxBytes === 'number' && Number.isFinite(maxBytes) && maxBytes > 0 ? Math.floor(maxBytes) : undefined;
          const boundedTimeoutMs =
            typeof timeoutMs === 'number' && Number.isFinite(timeoutMs) && timeoutMs > 0 ? Math.floor(timeoutMs) : undefined;
          const maxSeconds =
            boundedTimeoutMs !== undefined ? Math.max(2, Math.min(30, Math.ceil(boundedTimeoutMs / 1_000))) : 30;
          const callTracer = getActiveRequestTracer(tracer) ?? boundTracer;
          const doFetch = () =>
            executeHubFetch(
              tgt,
              JSON.stringify({
                maxSeconds,
                options: {
                  includeBody: true,
                  respectRobots: true,
                  // Go omits bodies over this cap (`bodyOmitted: true`) so a page that cannot fit the WASM evaluator never
                  // materialises as a multi-MiB JS string; the omission is surfaced below as an explicit error.
                  maxInlineBodyBytes: MAX_WASM_INPUT_BYTES,
                  ...(boundedMaxBytes !== undefined ? { maxBytes: boundedMaxBytes } : {}),
                  // `timeoutMs` lives on crawl.Options (Go `crawl.Request` has no such field): on the request it was
                  // silently dropped by lenient decoders (30 s default) and rejected by the strict server decoder.
                  ...(boundedTimeoutMs !== undefined ? { timeoutMs: boundedTimeoutMs } : {}),
                },
                requests: [
                  {
                    id: 'cat-1',
                    url: pageUrl,
                    kind,
                    accept,
                  },
                ],
              }),
              siteStr,
              sourceLabel,
              'off',
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
            if (
              first &&
              typeof first.body !== 'string' &&
              (first.bodyOmitted === true || first.bodyBase64Omitted === true)
            ) {
              // An omitted body is NOT an empty page: parsing '' would end pagination early as if the catalog were done.
              return {
                status: typeof first.status === 'number' ? first.status : 200,
                outcome: 'error',
                problem: `page body exceeded the ${MAX_WASM_INPUT_BYTES}-byte inline/WASM input budget and was omitted`,
                bodyOmitted: true,
                ...(typeof first.finalUrl === 'string' ? { finalUrl: first.finalUrl } : {}),
                headers: {},
                body: '',
              };
            }
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
        githubAuthEnv: env,
        serviceName: 'EdgeFetch Hub',
        redirectAllowlist: parseHostAllowlist(env.OAUTH_REDIRECT_ALLOWLIST),
        onEvent: (ev) => activity.recordEvent({ ...ev, details: sanitizeDetails(ev.details) }),
      });
      if (oauthRes) return oauthRes;

      if (url.pathname === '/mcp' || isMcpRootRequest(request, url)) {
        return await handleMcpRequest(request, url, {
          ...(() => {
            const store = accessPolicyStore();
            return store ? { accessPolicy: store, accessPolicyCacheKey } : {};
          })(),
          serverName: 'edgefetch-hub',
          serverVersion: HUB_VERSION,
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
            if (getActiveCallerAuthContext()?.role === 'member') {
              return { connected: state.connected, agents: [], affinities: [] };
            }
            return {
              connected: state.connected,
              trackerListVersion: state.trackerListVersion,
              agents: state.agents,
              affinities: state.affinities,
            };
          },
          executeFetch: async ({ target, site, body, principal, hydrateInline }) => {
            const effectiveUserId = getActiveCallerAuthContext()?.userId ?? resolveCallerUserId({ principal });
            const releaseScrapeSlot = tryAcquireUserConcurrencySlot(
              inFlightScrapesByUser,
              effectiveUserId,
              MAX_CONCURRENT_SCRAPES_PER_USER,
            );
            if (!releaseScrapeSlot) {
              return {
                status: 429,
                via: 'hub',
                bodyText: JSON.stringify({
                  ok: false,
                  error: 'user_quota_exceeded',
                  message: `Per-user concurrent scrape limit (${MAX_CONCURRENT_SCRAPES_PER_USER}) exceeded.`,
                }),
                retryAfter: '2',
              };
            }
            try {
              return await executeHubFetch(
                target,
                body,
                site,
                `mcp:${principal ?? 'client'}`,
                undefined,
                hydrateInline ?? true,
              );
            } finally {
              releaseScrapeSlot();
            }
          },
          executeScrape: async ({ args, principal, userId }) => {
            const activeAuth = getActiveCallerAuthContext();
            const effectivePrincipal = activeAuth?.principal ?? principal ?? '';
            const hasMcpCallScope = effectivePrincipal.startsWith('oauth:')
              ? Boolean(activeAuth?.scopes.includes('mcp:call'))
              : true;
            const effectiveUserId = userId ?? activeAuth?.userId ?? resolveCallerUserId({ principal });
            const { interact: _smuggledInteract, sessionId: _smuggledSessionId, ...cleanArgs } = args as Record<string, unknown>;
            const hasAllowedMcpToolsArg = cleanArgs.allowedMcpTools !== undefined;
            if (
              (cleanArgs.preferMcp === true || cleanArgs.useConnectedMcp === true || hasAllowedMcpToolsArg) &&
              !hasMcpCallScope
            ) {
              return {
                status: 403,
                body: {
                  ok: false,
                  error: 'insufficient_scope',
                  message: 'Scope mcp:call is required to route scrape through connected MCP servers.',
                },
              };
            }
            if (hasAllowedMcpToolsArg) {
              const parsedAllowed = parseAllowedMcpTools(cleanArgs.allowedMcpTools);
              if (!parsedAllowed.ok) {
                return {
                  status: 400,
                  body: {
                    ok: false,
                    error: parsedAllowed.error,
                    message: parsedAllowed.message,
                  },
                };
              }
            }
            const releaseScrapeSlot = tryAcquireUserConcurrencySlot(
              inFlightScrapesByUser,
              effectiveUserId,
              MAX_CONCURRENT_SCRAPES_PER_USER,
            );
            if (!releaseScrapeSlot) {
              return {
                status: 429,
                body: {
                  ok: false,
                  error: 'user_quota_exceeded',
                  message: `Per-user concurrent scrape limit (${MAX_CONCURRENT_SCRAPES_PER_USER}) exceeded.`,
                },
              };
            }
            try {
              const hasCallerCookies =
                (typeof cleanArgs.cookies === 'string' && cleanArgs.cookies.trim().length > 0) ||
                (Array.isArray(cleanArgs.cookies) && cleanArgs.cookies.length > 0) ||
                (cleanArgs.cookies !== null && typeof cleanArgs.cookies === 'object' && Object.keys(cleanArgs.cookies as object).length > 0);
              if (hasCallerCookies || cleanArgs.auth || cleanArgs.preferMcp === true || effectiveUserId !== 'owner') {
                cleanArgs.visibility = 'private';
              }
              if (
                hasMcpCallScope &&
                typeof cleanArgs.url === 'string' &&
                cleanArgs.url.trim() &&
                cleanArgs.useConnectedMcp !== false
              ) {
                const mcpOut = await tryScrapeViaConnectedMcp({
                  userId: effectiveUserId,
                  targetUrl: cleanArgs.url.trim(),
                  ...(typeof cleanArgs.query === 'string' ? { query: cleanArgs.query } : {}),
                  preferMcp: cleanArgs.preferMcp === true,
                  requireExplicitReadOnlyHint: true,
                  ...(hasAllowedMcpToolsArg
                    ? { allowedMcpTools: cleanArgs.allowedMcpTools as ReadonlyArray<string> }
                    : {}),
                  vaultStore,
                  ...federationPolicyOpts(),
                  vaultMasterKey: env.VAULT_MASTER_KEY,
                  fetchFn: safePublicFetch,
                  selfHost: url.hostname,
                });
                if (mcpOut) return { status: mcpOut.status, body: mcpOut.body };
              }
              const out = await executeScrapeCall({
                payload: cleanArgs as ScrapeRequestPayload,
                env,
                executeHubFetch,
                selfHost: url.hostname,
                source: `mcp-scrape:${principal ?? 'client'}`,
                userId: effectiveUserId,
              });
              return { status: out.status, body: { via: out.via, ...out.body } };
            } finally {
              releaseScrapeSlot();
            }
          },
          executeExtract: async ({ args, principal, userId }) => {
            const effectiveUserId = userId ?? getActiveCallerAuthContext()?.userId ?? resolveCallerUserId({ principal });
            const argsObj = args as Record<string, unknown>;
            const hasInvalidUrls =
              !Array.isArray(argsObj.urls) || argsObj.urls.length === 0 || argsObj.urls.length > 20;
            const releaseExtractSlots = hasInvalidUrls
              ? () => undefined
              : tryAcquireUserExtractSlots(effectiveUserId, countExtractPayloadUrls(argsObj));
            if (!releaseExtractSlots) {
              return {
                status: 429,
                body: {
                  ok: false,
                  error: 'user_quota_exceeded',
                  message: `Per-user concurrent extract limit (${MAX_CONCURRENT_EXTRACTS_PER_USER} requests / ${MAX_CONCURRENT_EXTRACT_URLS_PER_USER} URLs) exceeded.`,
                },
              };
            }
            try {
              const out = await executeExtractCall({
                payload: args as ExtractRequestPayload,
                env,
                executeHubFetch,
                selfHost: url.hostname,
                source: `mcp-extract:${principal ?? 'client'}`,
                userId: effectiveUserId,
              });
              return { status: out.status, body: { via: out.via, ...out.body } };
            } finally {
              releaseExtractSlots();
            }
          },
          executeInteract: async ({ args, principal, userId }) => {
            const effectiveUserId = userId ?? getActiveCallerAuthContext()?.userId ?? resolveCallerUserId({ principal });
            const releaseInteractSlot = tryAcquireUserConcurrencySlot(
              inFlightInteractsByUser,
              effectiveUserId,
              MAX_CONCURRENT_INTERACTS_PER_USER,
            );
            if (!releaseInteractSlot) {
              return {
                status: 429,
                body: {
                  ok: false,
                  error: 'user_quota_exceeded',
                  message: `Per-user concurrent interact limit (${MAX_CONCURRENT_INTERACTS_PER_USER}) exceeded.`,
                },
              };
            }
            try {
              const out = await executeInteractCall({
                payload: args as InteractRequestPayload,
                env,
                executeHubFetch,
                selfHost: url.hostname,
                source: `mcp-interact:${principal ?? 'client'}`,
                principal: principal ?? 'client',
                userId: effectiveUserId,
                sessionSigningSecret: sessionSecret,
              });
              return { status: out.status, body: { via: out.via, ...out.body } };
            } finally {
              releaseInteractSlot();
            }
          },
          executeMap: async ({ args, principal, userId }) => {
            const effectiveUserId = userId ?? getActiveCallerAuthContext()?.userId ?? resolveCallerUserId({ principal });
            const releaseMapSlot = tryAcquireUserMapSlot(effectiveUserId);
            if (!releaseMapSlot) {
              return {
                status: 429,
                body: {
                  ok: false,
                  error: 'user_quota_exceeded',
                  message: `Per-user concurrent map limit (${MAX_CONCURRENT_MAPS_PER_USER}) exceeded.`,
                },
              };
            }
            try {
              const out = await executeMapCall({
                payload: args as MapRequestPayload,
                executeHubFetch,
                selfHost: url.hostname,
                source: `mcp-map:${principal ?? 'client'}`,
              });
              return { status: out.status, body: { via: out.via, ...out.body } };
            } finally {
              releaseMapSlot();
            }
          },
          executeCrawl: async ({ args, principal, userId }) => {
            const effectiveUserId = userId ?? resolveCallerUserId({ principal });
            const existingId = typeof args.crawlId === 'string' ? args.crawlId.trim() : '';
            if (existingId) {
              if (args.cancel === true) {
                const cRes = await cancelCrawlJob(existingId, env.META, effectiveUserId);
                const isPrivCancel = sanitizeStorageUserId(effectiveUserId) !== 'owner' || cRes.visibility === 'private';
                return {
                  status: cRes.status,
                  body: {
                    ok: cRes.ok,
                    ...(isPrivCancel ? { visibility: 'private' as const } : {}),
                    crawlId: existingId,
                    status: 'cancelled',
                  },
                };
              }
              const st = await getCrawlJobStatus({
                crawlId: existingId,
                metaDb: env.META,
                bucket: env.ARTIFACTS,
                offset: typeof args.offset === 'number' ? args.offset : 0,
                ...(typeof args.limit === 'number' && Number.isFinite(args.limit) ? { limit: args.limit } : {}),
                userId: effectiveUserId,
              });
              return st.ok ? { status: 200, body: st.crawl } : { status: st.status, body: { ok: false, error: st.error } };
            }
            const crawlArgs: Record<string, unknown> = { ...args };
            const isPrivateCrawlReq = isPrivateRequestPayload(crawlArgs, effectiveUserId);
            let displayCollectionId: string | undefined;
            if (typeof crawlArgs.collectionId === 'string' && crawlArgs.collectionId.trim()) {
              const resolvedColl = resolveUserCollectionId(
                crawlArgs.collectionId,
                effectiveUserId,
                isPrivateCrawlReq ? 'private' : 'public',
              );
              if (!resolvedColl.ok) {
                return { status: resolvedColl.status, body: { ok: false, error: resolvedColl.error, message: resolvedColl.message } };
              }
              crawlArgs.collectionId = resolvedColl.scopedId;
              displayCollectionId = resolvedColl.displayId;
            }
            if (isPrivateCrawlReq && crawlArgs.visibility !== 'private') {
              crawlArgs.visibility = 'private';
            }
            const created = await createCrawlJob({
              payload: crawlArgs,
              metaDb: env.META,
              selfHost: url.hostname,
              userId: effectiveUserId,
            });
            if (!created.ok) {
              return { status: created.status, body: { ok: false, error: created.error, message: created.message } };
            }
            const resolvedCollectionId = displayCollectionId ?? created.options.collectionId;
            const pollHint = 'Call crawl with { crawlId } to poll progress';

            let dispatchedViaWorkflow = false;
            if (env.CRAWL) {
              try {
                await env.CRAWL.create({
                  id: created.crawlId,
                  params: {
                    crawlId: created.crawlId,
                    rootUrl: created.rootUrl,
                    userId: effectiveUserId,
                    options: created.options,
                    selfHost: url.hostname,
                  },
                });
                dispatchedViaWorkflow = true;
              } catch {
                dispatchedViaWorkflow = false;
              }
            }
            if (!dispatchedViaWorkflow) {
              const jobPromise = executeCrawlJob({
                crawlId: created.crawlId,
                rootUrl: created.rootUrl,
                userId: effectiveUserId,
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
            }
            return {
              status: 202,
              body: {
                ok: true,
                ...(isPrivateCrawlReq ? { visibility: 'private' as const } : {}),
                crawlId: created.crawlId,
                status: 'queued',
                collectionId: resolvedCollectionId,
                pollHint,
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
            const activeAuth = getActiveCallerAuthContext();
            const effectiveUserId = userId ?? activeAuth?.userId ?? resolveCallerUserId({ principal });
            const effectiveTier = activeAuth?.role ?? (effectiveUserId === 'owner' ? 'owner' : 'member');
            const releaseScrapeSlot = tryAcquireUserConcurrencySlot(
              inFlightScrapesByUser,
              effectiveUserId,
              MAX_CONCURRENT_SCRAPES_PER_USER,
            );
            if (!releaseScrapeSlot) {
              return {
                status: 429,
                body: {
                  ok: false,
                  error: 'user_quota_exceeded',
                  message: `Per-user concurrent scrape limit (${MAX_CONCURRENT_SCRAPES_PER_USER}) exceeded.`,
                },
              };
            }
            try {
              return await executeJobsCall({
                payload: args as JobsToolPayload,
                env: env as unknown as OptionalStorageBindings & Record<string, unknown>,
                userId: effectiveUserId,
                authTier: effectiveTier,
                executeSearch: async (sArgs) => {
                  const sOut = await executeSearchCall({
                    payload: sArgs as SearchRequestPayload,
                    env,
                    executeHubFetch,
                    source: `mcp-jobs-search:${principal ?? 'client'}`,
                    userId: effectiveUserId,
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
                    userId: effectiveUserId,
                  });
                  return { status: scOut.status, body: scOut.body };
                },
              });
            } finally {
              releaseScrapeSlot();
            }
          },
          findExtractors: ({ query, category, limit }) => {
            return findRelevantAdapters({ query, category, limit }) as unknown as Array<Record<string, unknown>>;
          },
          executeCompany: async ({ args, principal, userId }) => {
            const activeAuth = getActiveCallerAuthContext();
            const effectiveUserId = userId ?? activeAuth?.userId ?? resolveCallerUserId({ principal });
            const effectiveTier = activeAuth?.role ?? (effectiveUserId === 'owner' ? 'owner' : 'member');
            return makeVerticalExecutors(`mcp:${principal ?? 'client'}`, effectiveUserId, effectiveTier).company(args);
          },
          executeSalaries: async ({ args, principal, userId }) => {
            const activeAuth = getActiveCallerAuthContext();
            const effectiveUserId = userId ?? activeAuth?.userId ?? resolveCallerUserId({ principal });
            const effectiveTier = activeAuth?.role ?? (effectiveUserId === 'owner' ? 'owner' : 'member');
            return makeVerticalExecutors(`mcp:${principal ?? 'client'}`, effectiveUserId, effectiveTier).salaries(args);
          },
          executeCatalog: async ({ args, principal }) => {
            const effectiveUserId = getActiveCallerAuthContext()?.userId ?? resolveCallerUserId({ principal });
            return await executeCatalogCall({
              payload: args as CatalogCallPayload,
              env: env as unknown as OptionalStorageBindings & Record<string, unknown>,
              executeHubFetch: makeCatalogHubFetch(`mcp-catalog:${principal ?? 'client'}`),
              selfHost: url.hostname,
              principal: principal ?? 'mcp',
              userId: effectiveUserId,
              devTelemetrySetting: getCachedDevTelemetrySetting,
              ...(trackedCtx?.waitUntil ? { ctx: { waitUntil: (p: Promise<unknown>) => trackedCtx.waitUntil(p) } } : {}),
            });
          },
          executeAgent: async ({ args, principal, userId }) => {
            const effectiveUserId = userId ?? resolveCallerUserId({ principal });
            const isCallerPrivate = sanitizeStorageUserId(effectiveUserId) !== 'owner';
            if (typeof args.agentId === 'string' && args.agentId.trim()) {
              const aid = args.agentId.trim();
              if (args.cancel === true) {
                const cRes = await cancelAgentRun(aid, env.META, effectiveUserId);
                const isPrivCancel = isCallerPrivate || cRes.visibility === 'private';
                return {
                  status: cRes.status,
                  body: {
                    ok: cRes.ok,
                    ...(isPrivCancel ? { visibility: 'private' as const } : {}),
                    id: aid,
                    status: 'cancelled',
                  },
                };
              }
              const rec = await loadAgentRun(aid, env.META, effectiveUserId);
              if (!rec) {
                return {
                  status: 404,
                  body: { ok: false, ...(isCallerPrivate ? { visibility: 'private' as const } : {}), error: 'agent_not_found' },
                };
              }
              const isPrivRec = isCallerPrivate || rec.visibility === 'private';
              if (args.trace === true) {
                return {
                  status: 200,
                  body: {
                    ok: true,
                    ...(isPrivRec ? { visibility: 'private' as const } : {}),
                    id: rec.id,
                    threadId: rec.threadId,
                    status: rec.status,
                    spans: rec.trace,
                  },
                };
              }
              return {
                status: 200,
                body: {
                  ...formatPublicAgentResponse(rec, false),
                  ...(isPrivRec ? { visibility: 'private' as const } : {}),
                },
              };
            }
            const mcpAgentWaitUntil = trackedCtx?.waitUntil
              ? (p: Promise<unknown>) => trackedCtx.waitUntil(p)
              : (p: Promise<unknown>) => {
                  void p
                    .catch(() => undefined)
                    .finally(() => flushTracerWithTelemetry(rootTracer).catch(() => false));
                };
            const isPrivateReq = isPrivateRequestPayload(args, effectiveUserId);
            const effectiveArgs = isPrivateReq && args.visibility !== 'private' ? { ...args, visibility: 'private' } : args;
            const out = await startOrExecuteAgentCall({
              payload: effectiveArgs,
              env,
              executeHubFetch,
              selfHost: url.hostname,
              principal: principal ?? 'mcp',
              userId: effectiveUserId,
              sessionSigningSecret: sessionSecret,
              vaultStore,
              ...federationPolicyOpts(),
              waitUntil: mcpAgentWaitUntil,
            });
            if (out.kind === 'sse') {
              return {
                status: 200,
                body: { ok: true, ...(isPrivateReq ? { visibility: 'private' as const } : {}), note: 'SSE stream completed' },
              };
            }
            const isPrivOut = isPrivateReq || (out.body as { visibility?: string }).visibility === 'private';
            return {
              status: out.status,
              body: { ...out.body, ...(isPrivOut ? { visibility: 'private' as const } : {}) },
            };
          },
          discoverMcps: async ({ query, remoteOnly, limit }) => {
            const out = await discoverMcps({
              query,
              remoteOnly,
              limit,
              fetchFn: safePublicFetch,
              selfHost: url.hostname,
            });
            return { status: out.status, body: out as unknown as Record<string, unknown> };
          },
          executeQueryMcp: async ({ args, principal, userId }) => {
            const activeAuth = getActiveCallerAuthContext();
            const action = (args as QueryMcpCallInput).action ?? 'list_connected';
            if ((action === 'call_tool' || action === 'list_tools') && activeAuth && !activeAuth.scopes.includes('mcp:call')) {
              return {
                status: 403,
                body: {
                  ok: false,
                  error: 'insufficient_scope',
                  message: `OAuth scope mcp:call is required for action="${action}"`,
                },
              };
            }
            const effectiveUserId = userId ?? resolveCallerUserId({ principal });
            return await executeFederatedMcpQuery({
              userId: effectiveUserId,
              input: args as QueryMcpCallInput,
              vaultStore,
              ...federationPolicyOpts(),
              vaultMasterKey: env.VAULT_MASTER_KEY,
              fetchFn: safePublicFetch,
              selfHost: url.hostname,
            });
          },
          ...(env.SEARCH
            ? {
                searchCollection: async ({ collectionId, query, limit, userId, visibility }) => {
                  const effectiveUser = userId ?? 'owner';
                  const effectiveVis =
                    visibility === 'private' || sanitizeStorageUserId(effectiveUser) !== 'owner' ? 'private' : 'public';
                  const resolved = resolveUserCollectionId(collectionId, effectiveUser, effectiveVis);
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
                    : {
                        ok: false as const,
                        status: res.status,
                        via: 'hub' as const,
                        error: res.error,
                        ...(res.message ? { message: res.message } : {}),
                      };
                },
              }
            : {}),
        });
      }

      const adminRes = await handleAdminRoute(request, url, {
        ...(env.AGENT_HUB ? { hubSecretsStore: hub() as unknown as HubSecretsStore } : {}),
        secretsEnv: deploymentEnv as unknown as Record<string, unknown>,
        ...(() => {
          const store = accessPolicyStore();
          return store ? { accessPolicyStore: store } : {};
        })(),
        recordAdminEvent: (ev) => activity.recordEvent({ ...ev, details: sanitizeDetails(ev.details) }),
        serviceName: 'EdgeFetch Hub',
        mcpSlug: 'edgefetch',
        ownerSecret: env.CALLER_TOKEN,
        githubAuthEnv: env,
        metaDb: env.META,
        vaultMasterKey: env.VAULT_MASTER_KEY,
        vaultStore,
        safePublicFetch,
        selfHost: url.hostname,
        oauthStore,
        onEvent: (ev) => activity.recordEvent({ ...ev, details: sanitizeDetails(ev.details) }),
        allowedTargets: ALLOWED_TARGETS,
        defaultTarget: 'auto',
        getState: () => hub().getPortalState(Date.now()),
        getUpdateStatus: (agents) =>
          checkHubUpdateStatus({
            currentVersion: HUB_VERSION,
            agents,
            env,
          }),
        getTrackerListStatus: async () => {
          const stub = hub() as unknown as { getHubSetting?: (k: string) => Promise<string | null> };
          const settingVal =
            typeof stub.getHubSetting === 'function'
              ? await stub.getHubSetting('tracker_list').catch(() => null)
              : null;
          return getTrackerListAdminStatus({
            bucket: env.ARTIFACTS ?? env.TRACKER_BUCKET,
            env,
            hubSettingValue: settingVal,
          });
        },
        refreshTrackerList: async () => {
          const trackerBucket = env.ARTIFACTS ?? env.TRACKER_BUCKET;
          const stub = hub() as unknown as { getHubSetting?: (k: string) => Promise<string | null> };
          const settingVal =
            typeof stub.getHubSetting === 'function'
              ? await stub.getHubSetting('tracker_list').catch(() => null)
              : null;
          const refreshed = await refreshHubTrackerList({
            bucket: trackerBucket,
            fetchFn: safePublicFetch,
            env,
            hubSettingValue: settingVal,
            selfHost: url.hostname,
            publicOrigin: env.EDGEFETCH_PUBLIC_ORIGIN ?? url.origin,
          });
          if (refreshed.current && env.AGENT_HUB) {
            const extraAllow = resolveExtraNeverBlockHosts({
              selfHost: url.hostname,
              publicOrigin: env.EDGEFETCH_PUBLIC_ORIGIN ?? url.origin,
            });
            const frames = buildTrackerListWsFrames(refreshed.current, extraAllow);
            await Promise.allSettled(
              shardNames.map((sName) => {
                const shardStub = hubShard(sName) as unknown as {
                  syncTrackerList?: (v: string | null, f: string[]) => Promise<void>;
                };
                return typeof shardStub.syncTrackerList === 'function'
                  ? shardStub.syncTrackerList(refreshed.current!.meta.version, frames)
                  : Promise.resolve();
              }),
            );
          }
          if (refreshed.updated && refreshed.current) {
            await activity.recordEvent({
              level: 'info',
              category: 'agent',
              event: 'tracker_list_refreshed',
              summary: `Refreshed EasyPrivacy tracker list v${refreshed.current.meta.version} (${refreshed.current.meta.hostCount} hosts) via /admin`,
              details: {
                version: refreshed.current.meta.version,
                hostCount: refreshed.current.meta.hostCount,
                source: 'admin_refresh',
              },
            });
          }
          const trackerList = await getTrackerListAdminStatus({
            bucket: trackerBucket,
            env,
            hubSettingValue: settingVal,
          });
          return {
            ok: refreshed.ok,
            ...(refreshed.disabled ? { disabled: true } : {}),
            ...(refreshed.rateLimited ? { rateLimited: true } : {}),
            ...(refreshed.notModified ? { notModified: true } : {}),
            updated: refreshed.updated,
            ...(refreshed.reason ? { reason: refreshed.reason } : {}),
            trackerList,
          };
        },
        getTelemetrySettings: async () => {
          const stub = hub() as unknown as { getHubSetting?: (k: string) => Promise<string | null> };
          const dbSettingValue =
            typeof stub.getHubSetting === 'function' ? await stub.getHubSetting(DEV_TELEMETRY_SETTING_KEY) : null;
          return resolveDevTelemetryState({ env, dbSettingValue });
        },
        getHubSetting: async (k) => {
          const stub = hub() as unknown as { getHubSetting?: (key: string) => Promise<string | null> };
          return typeof stub.getHubSetting === 'function' ? await stub.getHubSetting(k) : null;
        },
        setHubSetting: async (k, v) => {
          const stub = hub() as unknown as { setHubSetting?: (key: string, val: string) => Promise<void> };
          if (typeof stub.setHubSetting === 'function') {
            await stub.setHubSetting(k, v);
          }
        },
        setTelemetryOptIn: async (enabled) => {
          const val = enabled ? '1' : '0';
          const stub = hub() as unknown as { setHubSetting?: (k: string, v: string) => Promise<void> };
          if (typeof stub.setHubSetting === 'function') {
            await stub.setHubSetting(DEV_TELEMETRY_SETTING_KEY, val);
          }
          const cacheKey = (env.AGENT_HUB as unknown as object | undefined) ?? null;
          if (cacheKey) {
            devTelemetrySettingCache.set(cacheKey, { value: val, expiresAt: Date.now() + 30_000 });
          }
          await activity.recordEvent({
            level: 'info',
            category: 'agent',
            event: 'dev_telemetry_updated',
            summary: `Opt-in dev error telemetry set to ${enabled ? 'ON' : 'OFF'} via /admin`,
            details: { enabled },
          });
          return resolveDevTelemetryState({ env, dbSettingValue: val });
        },
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
          if (!auth.scopes.includes('crawl:read') && !auth.scopes.includes('crawl:fetch')) {
            const isPriv403 = sanitizeStorageUserId(resolveCallerUserId(auth as { userId?: string; principal?: string })) !== 'owner';
            return Response.json(
              { error: 'insufficient_scope', ...(isPriv403 ? { visibility: 'private' as const } : {}) },
              { status: 403, headers: { 'cache-control': isPriv403 ? 'private, no-store' : 'no-store' } },
            );
          }
          return Response.json(buildCapabilities(env, HUB_VERSION), {
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
          if (!auth.scopes.includes('crawl:read') && !auth.scopes.includes('crawl:fetch')) {
            const isPriv403 = sanitizeStorageUserId(resolveCallerUserId(auth as { userId?: string; principal?: string })) !== 'owner';
            return Response.json(
              { error: 'insufficient_scope', ...(isPriv403 ? { visibility: 'private' as const } : {}) },
              { status: 403, headers: { 'cache-control': isPriv403 ? 'private, no-store' : 'no-store' } },
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
            const isPriv403 = sanitizeStorageUserId(resolveCallerUserId(auth as { userId?: string; principal?: string })) !== 'owner';
            return Response.json(
              { error: 'insufficient_scope', ...(isPriv403 ? { visibility: 'private' as const } : {}) },
              { status: 403, headers: { 'cache-control': isPriv403 ? 'private, no-store' : 'no-store' } },
            );
          }
          if (auth.role !== 'owner') {
            return Response.json(
              { ok: true, visibility: 'private' as const, hosts: [] },
              { status: 200, headers: { 'cache-control': 'private, no-store' } },
            );
          }
          const rawLimit = Number(url.searchParams.get('limit') ?? 100);
          const safeLimit = Number.isFinite(rawLimit) ? Math.max(1, Math.min(500, Math.floor(rawLimit))) : 100;
          const hosts = await hub().listHostHealth(safeLimit);
          return Response.json({ ok: true, hosts }, { status: 200, headers: { 'cache-control': 'no-store' } });
        });
      }

      if (request.method === 'GET' && url.pathname === '/v1/hosts/gaps') {
        return withRouteSpan('edgefetch.hosts_gaps', {}, async () => {
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
            const isPriv403 = sanitizeStorageUserId(resolveCallerUserId(auth as { userId?: string; principal?: string })) !== 'owner';
            return Response.json(
              { error: 'insufficient_scope', ...(isPriv403 ? { visibility: 'private' as const } : {}) },
              { status: 403, headers: { 'cache-control': isPriv403 ? 'private, no-store' : 'no-store' } },
            );
          }
          const rawDays = Number(url.searchParams.get('days') ?? 7);
          const safeDays = Number.isFinite(rawDays) ? Math.max(1, Math.min(90, Math.floor(rawDays))) : 7;
          const rawLimit = Number(url.searchParams.get('limit') ?? 25);
          const safeLimit = Number.isFinite(rawLimit) ? Math.max(1, Math.min(100, Math.floor(rawLimit))) : 25;
          const onlyUnadapted =
            url.searchParams.get('unadapted') === 'true' || url.searchParams.get('unadapted') === '1';
          if (auth.role !== 'owner') {
            return Response.json(
              {
                ok: true,
                visibility: 'private' as const,
                configured: Boolean(env.META),
                windowDays: safeDays,
                sinceMs: Date.now() - safeDays * 86_400_000,
                hosts: [],
              },
              { status: 200, headers: { 'cache-control': 'private, no-store' } },
            );
          }
          const radar = await queryHostGapRadar({
            metaDb: env.META,
            days: safeDays,
            limit: safeLimit,
            onlyUnadapted,
          });
          return Response.json(radar, { status: 200, headers: { 'cache-control': 'no-store' } });
        });
      }

      const compatMeta = resolveCompatSpanMeta(url.pathname);
      if (compatMeta) {
        const compatRes = await withRouteSpan(compatMeta.spanName, { 'edgefetch.compat': compatMeta.flavor }, async () => {
          // Compat aliases authenticate inside handleCompatRoutes; when any access rule exists, pre-authorize through
          // the policy-gated authorizer so /v2 and /compat/* can't bypass a /v1 route rule (throws -> 403).
          const compatPolicyStore = accessPolicyStore();
          if (compatPolicyStore) {
            const compatSnap = await loadAccessPolicySnapshot({ store: compatPolicyStore, cacheKey: accessPolicyCacheKey }).catch(
              () => null,
            );
            if (!compatSnap || compatSnap.rules.length > 0) {
              await authorizeMcpRequest({
                request,
                origin: url.origin,
                ownerSecret: env.CALLER_TOKEN,
                ...(env.MCP_TOKEN ? { mcpToken: env.MCP_TOKEN } : {}),
                store: oauthStore,
              });
            }
          }
          let releaseCompatScrapeSlot: (() => void) | null = null;
          let preReadBody:
            | { ok: true; text: string; byteLength: number }
            | { ok: false; error: 'too_large' | 'read_error' }
            | undefined;
          if (
            request.method === 'POST' &&
            (compatMeta.spanName === 'edgefetch.scrape' || compatMeta.spanName === 'edgefetch.batch_scrape')
          ) {
            const preAuth = await authorizeMcpRequest({
              request,
              origin: url.origin,
              ownerSecret: env.CALLER_TOKEN,
              ...(env.MCP_TOKEN ? { mcpToken: env.MCP_TOKEN } : {}),
              store: oauthStore,
            });
            if (preAuth.ok && preAuth.scopes.includes('crawl:fetch')) {
              const callerUid = resolveCallerUserId(preAuth as { userId?: string; principal?: string });
              let parsedPreBody: Record<string, unknown> | null = null;
              let preBodyParsedAttempted = false;
              const readPreBodyOnce = async (): Promise<Record<string, unknown> | null> => {
                if (!preReadBody) {
                  preReadBody = await readBodyTextCapped(request, MAX_CALL_UTF8_BYTES);
                }
                if (!preBodyParsedAttempted) {
                  preBodyParsedAttempted = true;
                  if (preReadBody.ok) {
                    try {
                      const rawParsed = JSON.parse(preReadBody.text);
                      if (rawParsed && typeof rawParsed === 'object' && !Array.isArray(rawParsed)) {
                        parsedPreBody = rawParsed as Record<string, unknown>;
                      }
                    } catch {
                      // let compat handler return 400
                    }
                  }
                }
                return parsedPreBody;
              };
              const resolveCompatPrePrivate = async (): Promise<boolean> => {
                if (sanitizeStorageUserId(callerUid) !== 'owner') return true;
                const parsed = await readPreBodyOnce();
                return isPrivateRequestPayload(parsed, callerUid);
              };
              const hasMcpCallScope = !preAuth.principal.startsWith('oauth:') || preAuth.scopes.includes('mcp:call');
              if (!hasMcpCallScope && compatMeta.spanName === 'edgefetch.scrape') {
                const parsed = await readPreBodyOnce();
                if (parsed && (parsed.preferMcp === true || parsed.useConnectedMcp === true)) {
                  const isPriv = isPrivateRequestPayload(parsed, callerUid);
                  return Response.json(
                    {
                      ok: false,
                      success: false,
                      ...(isPriv ? { visibility: 'private' as const } : {}),
                      error: 'insufficient_scope',
                      message: 'Scope mcp:call is required to route scrape through connected MCP servers.',
                    },
                    { status: 403, headers: { 'cache-control': isPriv ? 'private, no-store' : 'no-store' } },
                  );
                }
              }
              if (compatMeta.spanName === 'edgefetch.scrape') {
                releaseCompatScrapeSlot = tryAcquireUserConcurrencySlot(
                  inFlightScrapesByUser,
                  callerUid,
                  MAX_CONCURRENT_SCRAPES_PER_USER,
                );
                if (!releaseCompatScrapeSlot) {
                  const isPriv = await resolveCompatPrePrivate();
                  void request.body?.cancel().catch(() => undefined);
                  return userQuotaExceededResponse(
                    `Per-user concurrent scrape limit (${MAX_CONCURRENT_SCRAPES_PER_USER}) exceeded.`,
                    isPriv,
                  );
                }
              } else if ((inFlightScrapesByUser.get(callerUid) ?? 0) >= MAX_CONCURRENT_SCRAPES_PER_USER) {
                const isPriv = await resolveCompatPrePrivate();
                void request.body?.cancel().catch(() => undefined);
                return userQuotaExceededResponse(
                  `Per-user concurrent scrape limit (${MAX_CONCURRENT_SCRAPES_PER_USER}) exceeded.`,
                  isPriv,
                );
              }
            }
          }
          try {
            const compatWaitUntil = trackedCtx?.waitUntil
              ? (p: Promise<unknown>) => trackedCtx.waitUntil(p)
              : (p: Promise<unknown>) => {
                  void p
                    .catch(() => undefined)
                    .finally(() => flushTracerWithTelemetry(rootTracer).catch(() => false));
                };
            const res = await handleCompatRoutes({
              request,
              url,
              env,
              oauthStore,
              vaultStore,
              executeHubFetch,
              waitUntil: compatWaitUntil,
              tracer: getActiveRequestTracer() ?? rootTracer,
              ...(preReadBody ? { preReadBody } : {}),
            });
            if (res && (res.headers.get('content-type') ?? '').toLowerCase().includes('text/event-stream')) {
              return wrapSseResponseWithFlush(res, () => {
                const p = flushTracerWithTelemetry(rootTracer);
                if (ctx?.waitUntil) ctx.waitUntil(p);
                return p;
              });
            }
            if (res && res.status === 429 && !res.headers.get('retry-after')) {
              const hdrs = new Headers(res.headers);
              hdrs.set('retry-after', '2');
              return new Response(res.body, { status: 429, statusText: res.statusText, headers: hdrs });
            }
            return res ?? Response.json({ success: false, error: 'not_found' }, { status: 404 });
          } finally {
            releaseCompatScrapeSlot?.();
          }
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
          if (!auth.scopes.includes('crawl:read') && !auth.scopes.includes('crawl:fetch')) {
            const isPriv403 = sanitizeStorageUserId(resolveCallerUserId(auth as { userId?: string; principal?: string })) !== 'owner';
            return Response.json(
              { error: 'insufficient_scope', ...(isPriv403 ? { visibility: 'private' as const } : {}) },
              { status: 403, headers: { 'cache-control': isPriv403 ? 'private, no-store' : 'no-store' } },
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

      if (request.method === 'GET' && url.pathname === '/v1/mcp/registry') {
        return withRouteSpan('edgefetch.mcp_registry', {}, async () => {
          const auth = await authorizeMcpRequest({
            request,
            origin: url.origin,
            ownerSecret: env.CALLER_TOKEN,
            mcpToken: env.MCP_TOKEN,
            store: oauthStore,
          });
          if (!auth.ok) {
            return Response.json(
              { error: 'unauthorized' },
              { status: 401, headers: { 'cache-control': 'no-store', 'www-authenticate': auth.wwwAuthenticate } },
            );
          }
          if (!auth.scopes.includes('crawl:read') && !auth.scopes.includes('crawl:fetch')) {
            const isPriv403 = sanitizeStorageUserId(resolveCallerUserId(auth as { userId?: string; principal?: string })) !== 'owner';
            return Response.json(
              { error: 'insufficient_scope', ...(isPriv403 ? { visibility: 'private' as const } : {}) },
              { status: 403, headers: { 'cache-control': isPriv403 ? 'private, no-store' : 'no-store' } },
            );
          }
          const q = url.searchParams.get('q') ?? url.searchParams.get('query') ?? '';
          const remoteOnly = url.searchParams.get('remoteOnly') === 'true' || url.searchParams.get('remoteOnly') === '1';
          const rawLimit = Number(url.searchParams.get('limit') ?? 20);
          const out = await discoverMcps({
            query: q,
            remoteOnly,
            ...(Number.isFinite(rawLimit) ? { limit: rawLimit } : {}),
            fetchFn: safePublicFetch,
            selfHost: url.hostname,
          });
          return Response.json(out, { status: out.status, headers: { 'cache-control': 'no-store' } });
        });
      }

      if (request.method === 'GET' && url.pathname === '/v1/mcp/shared') {
        return withRouteSpan('edgefetch.mcp_shared', {}, async () => {
          const auth = await authorizeMcpRequest({
            request,
            origin: url.origin,
            ownerSecret: env.CALLER_TOKEN,
            mcpToken: env.MCP_TOKEN,
            store: oauthStore,
          });
          if (!auth.ok) {
            return Response.json(
              { error: 'unauthorized' },
              { status: 401, headers: { 'cache-control': 'no-store', 'www-authenticate': auth.wwwAuthenticate } },
            );
          }
          if (!auth.scopes.includes('crawl:read') && !auth.scopes.includes('crawl:fetch') && !auth.scopes.includes('mcp:call')) {
            return Response.json({ error: 'insufficient_scope', visibility: 'private' as const }, { status: 403, headers: { 'cache-control': 'private, no-store' } });
          }
          const userId = resolveCallerUserId(auth as { userId?: string; principal?: string });
          const store = accessPolicyStore();
          // Members see only name/slug/tools of servers shared with them: never URLs, auth summaries, or credentials.
          const shared = store
            ? await listSharedServersFor(userId, { store, vaultStore, cacheKey: accessPolicyCacheKey })
            : [];
          const san = sanitizeConnectorStructuredValue(shared);
          return Response.json(
            { ok: true, visibility: 'private', userId, count: shared.length, sanitized: san.sanitized, fullySanitized: san.fullySanitized, servers: san.value },
            { status: 200, headers: { 'cache-control': 'private, no-store' } },
          );
        });
      }

      if (request.method === 'POST' && url.pathname === '/v1/mcp/query') {
        return withRouteSpan('edgefetch.mcp_query', {}, async () => {
          const auth = await authorizeMcpRequest({
            request,
            origin: url.origin,
            ownerSecret: env.CALLER_TOKEN,
            mcpToken: env.MCP_TOKEN,
            store: oauthStore,
          });
          if (!auth.ok) {
            return Response.json(
              { error: 'unauthorized' },
              { status: 401, headers: { 'cache-control': 'no-store', 'www-authenticate': auth.wwwAuthenticate } },
            );
          }
          const userId = resolveCallerUserId(auth as { userId?: string; principal?: string });
          const isCallerPrivate = sanitizeStorageUserId(userId) !== 'owner';
          const privHdrs = { 'cache-control': isCallerPrivate ? 'private, no-store' : 'no-store' };
          const cappedMcpQuery = await readBodyTextCapped(request, MAX_CALL_UTF8_BYTES);
          if (!cappedMcpQuery.ok) {
            return Response.json(
              {
                error: cappedMcpQuery.error === 'too_large' ? 'payload_too_large' : 'bad_json',
                ...(isCallerPrivate ? { visibility: 'private' as const } : {}),
              },
              { status: cappedMcpQuery.error === 'too_large' ? 413 : 400, headers: privHdrs },
            );
          }
          let payload: QueryMcpCallInput;
          try {
            const parsed = JSON.parse(cappedMcpQuery.text);
            if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
              return Response.json(
                { error: 'bad_json', ...(isCallerPrivate ? { visibility: 'private' as const } : {}) },
                { status: 400, headers: privHdrs },
              );
            }
            payload = parsed as QueryMcpCallInput;
          } catch {
            return Response.json(
              { error: 'bad_json', ...(isCallerPrivate ? { visibility: 'private' as const } : {}) },
              { status: 400, headers: privHdrs },
            );
          }
          const action = payload.action ?? 'list_connected';
          if (action === 'call_tool' || action === 'list_tools') {
            if (!auth.scopes.includes('mcp:call')) {
              return Response.json(
                { error: 'insufficient_scope', ...(isCallerPrivate ? { visibility: 'private' as const } : {}) },
                { status: 403, headers: privHdrs },
              );
            }
          } else if (
            !auth.scopes.includes('crawl:read') &&
            !auth.scopes.includes('crawl:fetch') &&
            !auth.scopes.includes('mcp:call')
          ) {
            return Response.json(
              { error: 'insufficient_scope', ...(isCallerPrivate ? { visibility: 'private' as const } : {}) },
              { status: 403, headers: privHdrs },
            );
          }
          const out = await executeFederatedMcpQuery({
            userId,
            input: payload,
            vaultStore,
            ...federationPolicyOpts(),
            vaultMasterKey: env.VAULT_MASTER_KEY,
            fetchFn: safePublicFetch,
            selfHost: url.hostname,
          });
          return Response.json(
            { ...out.body, ...(isCallerPrivate ? { visibility: 'private' as const } : {}) },
            {
              status: out.status,
              headers: { 'cache-control': 'private, no-store' },
            },
          );
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
          const callerUserId = resolveCallerUserId(auth as { userId?: string; principal?: string });
          const isCallerPrivate = sanitizeStorageUserId(callerUserId) !== 'owner';
          if (!auth.scopes.includes('crawl:fetch')) {
            return Response.json(
              {
                error: 'insufficient_scope',
                ...(isCallerPrivate ? { visibility: 'private' as const } : {}),
              },
              { status: 403, headers: { 'cache-control': isCallerPrivate ? 'private, no-store' : 'no-store' } },
            );
          }
          const cappedScrape = await readBodyTextCapped(request, MAX_CALL_UTF8_BYTES);
          if (!cappedScrape.ok) {
            return Response.json(
              {
                error: cappedScrape.error === 'too_large' ? 'payload_too_large' : 'bad_json',
                ...(isCallerPrivate ? { visibility: 'private' as const } : {}),
              },
              {
                status: cappedScrape.error === 'too_large' ? 413 : 400,
                headers: { 'cache-control': isCallerPrivate ? 'private, no-store' : 'no-store' },
              },
            );
          }
          let payload: ScrapeRequestPayload;
          try {
            const parsed = JSON.parse(cappedScrape.text);
            if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
              return Response.json(
                { error: 'bad_json', ...(isCallerPrivate ? { visibility: 'private' as const } : {}) },
                { status: 400, headers: { 'cache-control': isCallerPrivate ? 'private, no-store' : 'no-store' } },
              );
            }
            payload = parsed as ScrapeRequestPayload;
          } catch {
            return Response.json(
              { error: 'bad_json', ...(isCallerPrivate ? { visibility: 'private' as const } : {}) },
              { status: 400, headers: { 'cache-control': isCallerPrivate ? 'private, no-store' : 'no-store' } },
            );
          }
          const hasMcpCallScope = !auth.principal.startsWith('oauth:') || auth.scopes.includes('mcp:call');
          const { interact: _smuggledInteract, sessionId: _smuggledSessionId, ...cleanScrapeObj } =
            payload as unknown as Record<string, unknown>;
          const isPrivateScrapeReq = isPrivateRequestPayload(cleanScrapeObj, callerUserId);
          const hasScrapeAllowedMcpTools = cleanScrapeObj.allowedMcpTools !== undefined;
          if (
            (cleanScrapeObj.preferMcp === true || cleanScrapeObj.useConnectedMcp === true || hasScrapeAllowedMcpTools) &&
            !hasMcpCallScope
          ) {
            return Response.json(
              {
                ok: false,
                ...(isPrivateScrapeReq ? { visibility: 'private' } : {}),
                error: 'insufficient_scope',
                message: 'Scope mcp:call is required to route scrape through connected MCP servers.',
              },
              { status: 403, headers: { 'cache-control': isPrivateScrapeReq ? 'private, no-store' : 'no-store' } },
            );
          }
          if (hasScrapeAllowedMcpTools) {
            const parsedAllowed = parseAllowedMcpTools(cleanScrapeObj.allowedMcpTools);
            if (!parsedAllowed.ok) {
              return Response.json(
                {
                  ok: false,
                  ...(isPrivateScrapeReq ? { visibility: 'private' } : {}),
                  error: parsedAllowed.error,
                  message: parsedAllowed.message,
                },
                { status: 400, headers: { 'cache-control': isPrivateScrapeReq ? 'private, no-store' : 'no-store' } },
              );
            }
          }
          const releaseScrapeSlot = tryAcquireUserConcurrencySlot(
            inFlightScrapesByUser,
            callerUserId,
            MAX_CONCURRENT_SCRAPES_PER_USER,
          );
          if (!releaseScrapeSlot) {
            return userQuotaExceededResponse(
              `Per-user concurrent scrape limit (${MAX_CONCURRENT_SCRAPES_PER_USER}) exceeded.`,
              isPrivateScrapeReq,
            );
          }
          try {
            const hasCallerCookies =
              (typeof cleanScrapeObj.cookies === 'string' && cleanScrapeObj.cookies.trim().length > 0) ||
              (Array.isArray(cleanScrapeObj.cookies) && cleanScrapeObj.cookies.length > 0) ||
              (cleanScrapeObj.cookies !== null &&
                typeof cleanScrapeObj.cookies === 'object' &&
                Object.keys(cleanScrapeObj.cookies as object).length > 0);
            if (hasCallerCookies || cleanScrapeObj.auth || cleanScrapeObj.preferMcp === true || callerUserId !== 'owner') {
              cleanScrapeObj.visibility = 'private';
            }
            const cleanPayload = cleanScrapeObj as ScrapeRequestPayload;
            if (
              hasMcpCallScope &&
              typeof cleanPayload.url === 'string' &&
              cleanPayload.url.trim() &&
              cleanScrapeObj.useConnectedMcp !== false
            ) {
              const mcpOut = await tryScrapeViaConnectedMcp({
                userId: callerUserId,
                targetUrl: cleanPayload.url.trim(),
                ...(typeof cleanPayload.query === 'string' ? { query: cleanPayload.query } : {}),
                preferMcp: cleanScrapeObj.preferMcp === true,
                requireExplicitReadOnlyHint: true,
                ...(hasScrapeAllowedMcpTools
                  ? { allowedMcpTools: cleanScrapeObj.allowedMcpTools as ReadonlyArray<string> }
                  : {}),
                vaultStore,
                ...federationPolicyOpts(),
                vaultMasterKey: env.VAULT_MASTER_KEY,
                fetchFn: safePublicFetch,
                selfHost: url.hostname,
              });
              if (mcpOut) {
                return Response.json(mcpOut.body, {
                  status: mcpOut.status,
                  headers: {
                    'cache-control': 'private, no-store',
                    'x-crawler-via': mcpOut.via,
                  },
                });
              }
            }
            const out = await executeScrapeCall({
              payload: cleanPayload,
              env,
              executeHubFetch,
              selfHost: url.hostname,
              source: `scrape:${auth.principal}`,
              userId: auth.userId,
            });
            const isPrivateScrape =
              (out.body as { visibility?: string }).visibility === 'private' ||
              isPrivateRequestPayload(cleanPayload, callerUserId);
            return Response.json(out.body, {
              status: out.status,
              headers: {
                'cache-control': isPrivateScrape ? 'private, no-store' : 'no-store',
                'x-crawler-via': out.via,
                ...(out.retryAfter ? { 'retry-after': out.retryAfter } : {}),
              },
            });
          } finally {
            releaseScrapeSlot();
          }
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
          const callerUserId = resolveCallerUserId(auth as { userId?: string; principal?: string });
          const isCallerPrivate = sanitizeStorageUserId(callerUserId) !== 'owner';
          const privCorsHeaders = {
            ...corsHeaders,
            'cache-control': isCallerPrivate ? 'private, no-store' : 'no-store',
          };
          if (!auth.scopes.includes('crawl:fetch')) {
            return Response.json(
              { error: 'insufficient_scope', ...(isCallerPrivate ? { visibility: 'private' as const } : {}) },
              { status: 403, headers: privCorsHeaders },
            );
          }
          const cappedClip = await readBodyTextCapped(request, 4 * 1024 * 1024);
          if (!cappedClip.ok) {
            return Response.json(
              {
                error: cappedClip.error === 'too_large' ? 'payload_too_large' : 'bad_json',
                ...(isCallerPrivate ? { visibility: 'private' as const } : {}),
                ...(cappedClip.error === 'too_large' ? { message: 'Tab clip exceeds 4 MiB limit' } : {}),
              },
              { status: cappedClip.error === 'too_large' ? 413 : 400, headers: privCorsHeaders },
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
            const parsed = JSON.parse(cappedClip.text);
            if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
              return Response.json(
                { error: 'bad_json', ...(isCallerPrivate ? { visibility: 'private' as const } : {}) },
                { status: 400, headers: privCorsHeaders },
              );
            }
            clipPayload = parsed as typeof clipPayload;
          } catch {
            return Response.json(
              { error: 'bad_json', ...(isCallerPrivate ? { visibility: 'private' as const } : {}) },
              { status: 400, headers: privCorsHeaders },
            );
          }
          const isPrivateClipReq = isPrivateRequestPayload(clipPayload, callerUserId);
          const clipRespHeaders = {
            ...corsHeaders,
            'cache-control': isPrivateClipReq ? 'private, no-store' : 'no-store',
          };
          const tabUrl = typeof clipPayload.url === 'string' ? clipPayload.url.trim() : '';
          let parsedTabUrl: URL;
          try {
            parsedTabUrl = new URL(tabUrl);
            if (parsedTabUrl.protocol !== 'https:' && parsedTabUrl.protocol !== 'http:') {
              throw new Error('scheme');
            }
          } catch {
            return Response.json(
              {
                error: 'invalid_url',
                message: 'Valid http(s) tab url required',
                ...(isPrivateClipReq ? { visibility: 'private' as const } : {}),
              },
              { status: 400, headers: clipRespHeaders },
            );
          }
          parsedTabUrl.hash = '';
          const cleanUrl = parsedTabUrl.toString();
          const clipVisibility =
            clipPayload.visibility === 'private' || isCallerPrivate
              ? 'private'
              : normalizeVisibility(clipPayload.visibility);
          const rawCollectionId =
            typeof clipPayload.collectionId === 'string' && clipPayload.collectionId.trim()
              ? clipPayload.collectionId.trim()
              : 'browser-clips';
          const resolvedClipCollection = resolveUserCollectionId(rawCollectionId, auth.userId, clipVisibility);
          if (!resolvedClipCollection.ok) {
            return Response.json(
              {
                error: resolvedClipCollection.error,
                message: resolvedClipCollection.message,
                ...(clipVisibility === 'private' ? { visibility: 'private' as const } : {}),
              },
              { status: resolvedClipCollection.status, headers: clipRespHeaders },
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
          if (markdown) {
            markdown = sanitizeInlineHtmlInMarkdown(markdown, cleanUrl).trim();
          }
          if (resolvedTitle) {
            resolvedTitle = sanitizeExtractedTitle(resolvedTitle, cleanUrl, false) ?? '';
          }
          if (!markdown) {
            return Response.json(
              {
                error: 'empty_content',
                message: 'Clipped tab produced empty Markdown',
                ...(clipVisibility === 'private' ? { visibility: 'private' as const } : {}),
              },
              { status: 400, headers: clipRespHeaders },
            );
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
            { status: 200, headers: clipRespHeaders },
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
          const callerUserId = resolveCallerUserId(auth as { userId?: string; principal?: string });
          const isCallerPrivate = sanitizeStorageUserId(callerUserId) !== 'owner';
          if (!auth.scopes.includes('crawl:fetch')) {
            return Response.json(
              {
                error: 'insufficient_scope',
                ...(isCallerPrivate ? { visibility: 'private' as const } : {}),
              },
              { status: 403, headers: { 'cache-control': isCallerPrivate ? 'private, no-store' : 'no-store' } },
            );
          }
          const cappedExtract = await readBodyTextCapped(request, MAX_CALL_UTF8_BYTES);
          if (!cappedExtract.ok) {
            return Response.json(
              {
                error: cappedExtract.error === 'too_large' ? 'payload_too_large' : 'bad_json',
                ...(isCallerPrivate ? { visibility: 'private' as const } : {}),
              },
              {
                status: cappedExtract.error === 'too_large' ? 413 : 400,
                headers: { 'cache-control': isCallerPrivate ? 'private, no-store' : 'no-store' },
              },
            );
          }
          let payload: ExtractRequestPayload;
          try {
            const parsed = JSON.parse(cappedExtract.text);
            if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
              return Response.json(
                { error: 'bad_json', ...(isCallerPrivate ? { visibility: 'private' as const } : {}) },
                { status: 400, headers: { 'cache-control': isCallerPrivate ? 'private, no-store' : 'no-store' } },
              );
            }
            payload = parsed as ExtractRequestPayload;
          } catch {
            return Response.json(
              { error: 'bad_json', ...(isCallerPrivate ? { visibility: 'private' as const } : {}) },
              { status: 400, headers: { 'cache-control': isCallerPrivate ? 'private, no-store' : 'no-store' } },
            );
          }
          const rawPayloadObj = payload as unknown as Record<string, unknown>;
          const isPrivateExtractReq = isPrivateRequestPayload(rawPayloadObj, callerUserId);
          const hasInvalidUrls =
            !Array.isArray(rawPayloadObj.urls) || rawPayloadObj.urls.length === 0 || rawPayloadObj.urls.length > 20;
          const releaseExtractSlots = hasInvalidUrls
            ? () => undefined
            : tryAcquireUserExtractSlots(callerUserId, countExtractPayloadUrls(rawPayloadObj));
          if (!releaseExtractSlots) {
            return userQuotaExceededResponse(
              `Per-user concurrent extract limit (${MAX_CONCURRENT_EXTRACTS_PER_USER} requests / ${MAX_CONCURRENT_EXTRACT_URLS_PER_USER} URLs) exceeded.`,
              isPrivateExtractReq,
            );
          }
          try {
            const out = await executeExtractCall({
              payload,
              env,
              executeHubFetch,
              selfHost: url.hostname,
              source: `extract:${auth.principal}`,
              userId: callerUserId,
            });
            const isPrivateExtract =
              (out.body as { visibility?: string }).visibility === 'private' || isPrivateExtractReq;
            return Response.json(out.body, {
              status: out.status,
              headers: {
                'cache-control': isPrivateExtract ? 'private, no-store' : 'no-store',
                'x-crawler-via': out.via,
                ...(out.retryAfter ? { 'retry-after': out.retryAfter } : {}),
              },
            });
          } finally {
            releaseExtractSlots();
          }
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
          const callerUserId = resolveCallerUserId(auth as { userId?: string; principal?: string });
          const isCallerPrivate = sanitizeStorageUserId(callerUserId) !== 'owner';
          const callerHdrs = { 'cache-control': isCallerPrivate ? 'private, no-store' : 'no-store' };
          if (!auth.scopes.includes('crawl:fetch')) {
            return Response.json(
              { error: 'insufficient_scope', ...(isCallerPrivate ? { visibility: 'private' as const } : {}) },
              { status: 403, headers: callerHdrs },
            );
          }
          const cappedInteract = await readBodyTextCapped(request, MAX_CALL_UTF8_BYTES);
          if (!cappedInteract.ok) {
            return Response.json(
              {
                error: cappedInteract.error === 'too_large' ? 'payload_too_large' : 'bad_json',
                ...(isCallerPrivate ? { visibility: 'private' as const } : {}),
              },
              { status: cappedInteract.error === 'too_large' ? 413 : 400, headers: callerHdrs },
            );
          }
          let payload: InteractRequestPayload;
          try {
            const parsed = JSON.parse(cappedInteract.text);
            if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
              return Response.json(
                { error: 'bad_json', ...(isCallerPrivate ? { visibility: 'private' as const } : {}) },
                { status: 400, headers: callerHdrs },
              );
            }
            payload = parsed as InteractRequestPayload;
          } catch {
            return Response.json(
              { error: 'bad_json', ...(isCallerPrivate ? { visibility: 'private' as const } : {}) },
              { status: 400, headers: callerHdrs },
            );
          }
          const isPrivateReq = isPrivateRequestPayload(payload, callerUserId);
          const releaseInteractSlot = tryAcquireUserConcurrencySlot(
            inFlightInteractsByUser,
            callerUserId,
            MAX_CONCURRENT_INTERACTS_PER_USER,
          );
          if (!releaseInteractSlot) {
            return userQuotaExceededResponse(
              `Per-user concurrent interact limit (${MAX_CONCURRENT_INTERACTS_PER_USER}) exceeded.`,
              isPrivateReq,
            );
          }
          try {
            const out = await executeInteractCall({
              payload,
              env,
              executeHubFetch,
              selfHost: url.hostname,
              source: `interact:${auth.principal}`,
              principal: auth.principal,
              userId: callerUserId,
              sessionSigningSecret: sessionSecret,
            });
            const isPrivOut = isPrivateReq || (out.body as { visibility?: string }).visibility === 'private';
            return Response.json(
              { ...out.body, ...(isPrivOut ? { visibility: 'private' as const } : {}) },
              {
                status: out.status,
                headers: { 'cache-control': isPrivOut ? 'private, no-store' : 'no-store', 'x-crawler-via': out.via },
              },
            );
          } finally {
            releaseInteractSlot();
          }
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
          const callerUserId = resolveCallerUserId(auth as { userId?: string; principal?: string });
          const isCallerPrivate = sanitizeStorageUserId(callerUserId) !== 'owner';
          const callerHdrs = { 'cache-control': isCallerPrivate ? 'private, no-store' : 'no-store' };
          if (!auth.scopes.includes('crawl:fetch')) {
            return Response.json(
              { error: 'insufficient_scope', ...(isCallerPrivate ? { visibility: 'private' as const } : {}) },
              { status: 403, headers: callerHdrs },
            );
          }
          const cappedMap = await readBodyTextCapped(request, MAX_CALL_UTF8_BYTES);
          if (!cappedMap.ok) {
            return Response.json(
              {
                error: cappedMap.error === 'too_large' ? 'payload_too_large' : 'bad_json',
                ...(isCallerPrivate ? { visibility: 'private' as const } : {}),
              },
              { status: cappedMap.error === 'too_large' ? 413 : 400, headers: callerHdrs },
            );
          }
          let payload: MapRequestPayload;
          try {
            const parsed = JSON.parse(cappedMap.text);
            if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
              return Response.json(
                { error: 'bad_json', ...(isCallerPrivate ? { visibility: 'private' as const } : {}) },
                { status: 400, headers: callerHdrs },
              );
            }
            payload = parsed as MapRequestPayload;
          } catch {
            return Response.json(
              { error: 'bad_json', ...(isCallerPrivate ? { visibility: 'private' as const } : {}) },
              { status: 400, headers: callerHdrs },
            );
          }
          const isPrivateReq = isPrivateRequestPayload(payload, callerUserId);
          const releaseMapSlot = tryAcquireUserMapSlot(callerUserId);
          if (!releaseMapSlot) {
            return userQuotaExceededResponse(
              `Per-user concurrent map limit (${MAX_CONCURRENT_MAPS_PER_USER}) exceeded.`,
              isPrivateReq,
            );
          }
          try {
            const out = await executeMapCall({
              payload,
              executeHubFetch,
              selfHost: url.hostname,
              source: `map:${auth.principal}`,
            });
            const isPrivOut = isPrivateReq || (out.body as { visibility?: string }).visibility === 'private';
            return Response.json(
              { ...out.body, ...(isPrivOut ? { visibility: 'private' as const } : {}) },
              {
                status: out.status,
                headers: { 'cache-control': isPrivOut ? 'private, no-store' : 'no-store', 'x-crawler-via': out.via },
              },
            );
          } finally {
            releaseMapSlot();
          }
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
            const isPriv403 = sanitizeStorageUserId(resolveCallerUserId(auth as { userId?: string; principal?: string })) !== 'owner';
            return Response.json(
              { error: 'insufficient_scope', ...(isPriv403 ? { visibility: 'private' as const } : {}) },
              { status: 403, headers: { 'cache-control': isPriv403 ? 'private, no-store' : 'no-store' } },
            );
          }
          const callerUserId = resolveCallerUserId(auth as { userId?: string; principal?: string });
          const isCallerPrivate = sanitizeStorageUserId(callerUserId) !== 'owner';
          const callerHdrs = { 'cache-control': isCallerPrivate ? 'private, no-store' : 'no-store' };
          const cappedSearch = await readBodyTextCapped(request, MAX_CALL_UTF8_BYTES);
          if (!cappedSearch.ok) {
            return Response.json(
              {
                error: cappedSearch.error === 'too_large' ? 'payload_too_large' : 'bad_json',
                ...(isCallerPrivate ? { visibility: 'private' as const } : {}),
              },
              { status: cappedSearch.error === 'too_large' ? 413 : 400, headers: callerHdrs },
            );
          }
          let payload: SearchRequestPayload;
          try {
            const parsed = JSON.parse(cappedSearch.text);
            if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
              return Response.json(
                { error: 'bad_json', ...(isCallerPrivate ? { visibility: 'private' as const } : {}) },
                { status: 400, headers: callerHdrs },
              );
            }
            payload = parsed as SearchRequestPayload;
          } catch {
            return Response.json(
              { error: 'bad_json', ...(isCallerPrivate ? { visibility: 'private' as const } : {}) },
              { status: 400, headers: callerHdrs },
            );
          }
          const isPrivateReq = isPrivateRequestPayload(payload, callerUserId);
          const out = await executeSearchCall({
            payload,
            env,
            executeHubFetch,
            source: `search:${auth.principal}`,
            userId: auth.userId,
          });
          const isPrivOut = isPrivateReq || (out.body as { visibility?: string }).visibility === 'private';
          return Response.json(
            { ...out.body, ...(isPrivOut ? { visibility: 'private' as const } : {}) },
            {
              status: out.status,
              headers: { 'cache-control': isPrivOut ? 'private, no-store' : 'no-store', 'x-crawler-via': out.via },
            },
          );
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
          if (!auth.scopes.includes('crawl:read') && !auth.scopes.includes('crawl:fetch')) {
            const isPriv403 = sanitizeStorageUserId(resolveCallerUserId(auth as { userId?: string; principal?: string })) !== 'owner';
            return Response.json(
              { error: 'insufficient_scope', ...(isPriv403 ? { visibility: 'private' as const } : {}) },
              { status: 403, headers: { 'cache-control': isPriv403 ? 'private, no-store' : 'no-store' } },
            );
          }
          const callerUserId = resolveCallerUserId(auth as { userId?: string; principal?: string });
          const isCallerPrivate = sanitizeStorageUserId(callerUserId) !== 'owner';
          const callerHdrs = { 'cache-control': isCallerPrivate ? 'private, no-store' : 'no-store' };
          const cappedPreview = await readBodyTextCapped(request, MAX_CALL_UTF8_BYTES);
          if (!cappedPreview.ok) {
            return Response.json(
              {
                error: cappedPreview.error === 'too_large' ? 'payload_too_large' : 'bad_json',
                ...(isCallerPrivate ? { visibility: 'private' as const } : {}),
              },
              { status: cappedPreview.error === 'too_large' ? 413 : 400, headers: callerHdrs },
            );
          }
          let payload: Record<string, unknown>;
          try {
            const parsed = JSON.parse(cappedPreview.text);
            if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
              return Response.json(
                { error: 'bad_json', ...(isCallerPrivate ? { visibility: 'private' as const } : {}) },
                { status: 400, headers: callerHdrs },
              );
            }
            payload = parsed as Record<string, unknown>;
          } catch {
            return Response.json(
              { error: 'bad_json', ...(isCallerPrivate ? { visibility: 'private' as const } : {}) },
              { status: 400, headers: callerHdrs },
            );
          }
          const isPrivateReq = isPrivateRequestPayload(payload, callerUserId);
          const prev = previewCrawlParams(payload, url.hostname);
          return Response.json(
            { ...prev.body, ...(isPrivateReq ? { visibility: 'private' as const } : {}) },
            { status: prev.status, headers: { 'cache-control': isPrivateReq ? 'private, no-store' : 'no-store' } },
          );
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
          const callerUserId = resolveCallerUserId(auth as { userId?: string; principal?: string });
          const isCallerPrivate = sanitizeStorageUserId(callerUserId) !== 'owner';
          const callerHdrs = { 'cache-control': isCallerPrivate ? 'private, no-store' : 'no-store' };
          if (!auth.scopes.includes('crawl:fetch')) {
            return Response.json(
              { error: 'insufficient_scope', ...(isCallerPrivate ? { visibility: 'private' as const } : {}) },
              { status: 403, headers: callerHdrs },
            );
          }
          const cappedBatch = await readBodyTextCapped(request, MAX_CALL_UTF8_BYTES);
          if (!cappedBatch.ok) {
            return Response.json(
              {
                error: cappedBatch.error === 'too_large' ? 'payload_too_large' : 'bad_json',
                ...(isCallerPrivate ? { visibility: 'private' as const } : {}),
              },
              { status: cappedBatch.error === 'too_large' ? 413 : 400, headers: callerHdrs },
            );
          }
          let payload: Record<string, unknown>;
          try {
            const parsed = JSON.parse(cappedBatch.text);
            if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
              return Response.json(
                { error: 'bad_json', ...(isCallerPrivate ? { visibility: 'private' as const } : {}) },
                { status: 400, headers: callerHdrs },
              );
            }
            payload = parsed as Record<string, unknown>;
          } catch {
            return Response.json(
              { error: 'bad_json', ...(isCallerPrivate ? { visibility: 'private' as const } : {}) },
              { status: 400, headers: callerHdrs },
            );
          }
          const isPrivateReq = isPrivateRequestPayload(payload, callerUserId);
          const batchHdrs = { 'cache-control': isPrivateReq ? 'private, no-store' : 'no-store' };
          if ((inFlightScrapesByUser.get(callerUserId) ?? 0) >= MAX_CONCURRENT_SCRAPES_PER_USER) {
            return userQuotaExceededResponse(
              `Per-user concurrent scrape limit (${MAX_CONCURRENT_SCRAPES_PER_USER}) exceeded.`,
              isPrivateReq,
            );
          }
          const batchOut = await startOrExecuteBatchScrape({
            payload,
            selfHost: url.hostname,
            userId: auth.userId,
            executeScrape: async (scArgs) => {
              const releaseBatchItemSlot = tryAcquireUserConcurrencySlot(
                inFlightScrapesByUser,
                callerUserId,
                MAX_CONCURRENT_SCRAPES_PER_USER,
              );
              if (!releaseBatchItemSlot) {
                return {
                  status: 429,
                  body: {
                    ok: false,
                    ...(isPrivateReq ? { visibility: 'private' as const } : {}),
                    error: 'user_quota_exceeded',
                    message: `Per-user concurrent scrape limit (${MAX_CONCURRENT_SCRAPES_PER_USER}) exceeded.`,
                  },
                };
              }
              try {
                const res = await executeScrapeCall({
                  payload: scArgs as ScrapeRequestPayload,
                  env,
                  executeHubFetch,
                  selfHost: url.hostname,
                  source: `batch-scrape:${auth.principal}`,
                  userId: auth.userId,
                });
                return { status: res.status, body: res.body, ...(res.retryAfter ? { retryAfter: res.retryAfter } : {}) };
              } finally {
                releaseBatchItemSlot();
              }
            },
            ...(trackedCtx?.waitUntil ? { waitUntil: (p: Promise<unknown>) => trackedCtx.waitUntil(p) } : {}),
          });
          if (!batchOut.ok) {
            return Response.json(
              {
                ok: false,
                ...(isPrivateReq ? { visibility: 'private' as const } : {}),
                error: batchOut.error,
                message: batchOut.message,
              },
              {
                status: batchOut.status,
                headers: batchOut.status === 429 ? { ...batchHdrs, 'retry-after': '2' } : batchHdrs,
              },
            );
          }
          return Response.json(
            {
              ok: true,
              ...(isPrivateReq ? { visibility: 'private' as const } : {}),
              id: batchOut.job.id,
              status: batchOut.job.status,
              total: batchOut.job.total,
              completed: batchOut.job.completed,
              failed: batchOut.job.failed,
              retryable: batchOut.job.retryable,
              url: `${url.origin}/v1/batch/scrape/${batchOut.job.id}`,
              ...(payload.sync === true ? { data: batchOut.job.data, errors: batchOut.job.errors } : {}),
            },
            { status: batchOut.status, headers: batchHdrs },
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
          const callerUserId = resolveCallerUserId(auth as { userId?: string; principal?: string });
          const isCallerPrivate = sanitizeStorageUserId(callerUserId) !== 'owner';
          const callerHdrs = { 'cache-control': isCallerPrivate ? 'private, no-store' : 'no-store' };
          const rawBatchId = safeDecodeURIComponent(batchRouteMatch[1] ?? '');
          if (rawBatchId === null) {
            return Response.json(
              {
                ok: false,
                ...(isCallerPrivate ? { visibility: 'private' as const } : {}),
                error: 'bad_request',
                message: 'Malformed URL path parameter',
              },
              { status: 400, headers: callerHdrs },
            );
          }
          const batchId = rawBatchId.trim();
          if (request.method === 'GET') {
            if (!auth.scopes.includes('crawl:read') && !auth.scopes.includes('crawl:fetch')) {
              return Response.json(
                { ok: false, ...(isCallerPrivate ? { visibility: 'private' as const } : {}), error: 'insufficient_scope' },
                { status: 403, headers: callerHdrs },
              );
            }
            const job = getBatchScrapeStatus(batchId, auth.userId);
            if (!job) {
              return Response.json(
                { ok: false, ...(isCallerPrivate ? { visibility: 'private' as const } : {}), error: 'batch_not_found' },
                { status: 404, headers: callerHdrs },
              );
            }
            const isPrivBatch = isCallerPrivate || job.visibility === 'private';
            const { visibility: _jobVis, ...restJob } = job;
            return Response.json(
              { ok: true, ...(isPrivBatch ? { visibility: 'private' as const } : {}), ...restJob },
              { status: 200, headers: { 'cache-control': isPrivBatch ? 'private, no-store' : 'no-store' } },
            );
          }
          if (request.method === 'DELETE') {
            if (!auth.scopes.includes('crawl:fetch')) {
              return Response.json(
                { ok: false, ...(isCallerPrivate ? { visibility: 'private' as const } : {}), error: 'insufficient_scope' },
                { status: 403, headers: callerHdrs },
              );
            }
            const existingJob = getBatchScrapeStatus(batchId, auth.userId);
            const ok = cancelBatchScrape(batchId, auth.userId);
            const isPrivBatch = isCallerPrivate || existingJob?.visibility === 'private';
            return Response.json(
              { ok, ...(isPrivBatch ? { visibility: 'private' as const } : {}), id: batchId, status: 'cancelled' },
              { status: ok ? 200 : 404, headers: { 'cache-control': isPrivBatch ? 'private, no-store' : 'no-store' } },
            );
          }
          return Response.json(
            { error: 'not_found', ...(isCallerPrivate ? { visibility: 'private' as const } : {}) },
            { status: 404, headers: callerHdrs },
          );
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
          const callerUserId = resolveCallerUserId(auth as { userId?: string; principal?: string });
          const isCallerPrivate = sanitizeStorageUserId(callerUserId) !== 'owner';
          const callerHdrs = { 'cache-control': isCallerPrivate ? 'private, no-store' : 'no-store' };
          if (!auth.scopes.includes('crawl:fetch')) {
            return Response.json(
              { error: 'insufficient_scope', ...(isCallerPrivate ? { visibility: 'private' as const } : {}) },
              { status: 403, headers: callerHdrs },
            );
          }
          const cappedAgent = await readBodyTextCapped(request, MAX_CALL_UTF8_BYTES);
          if (!cappedAgent.ok) {
            return Response.json(
              {
                error: cappedAgent.error === 'too_large' ? 'payload_too_large' : 'bad_json',
                ...(isCallerPrivate ? { visibility: 'private' as const } : {}),
              },
              { status: cappedAgent.error === 'too_large' ? 413 : 400, headers: callerHdrs },
            );
          }
          let payload: Record<string, unknown>;
          try {
            const parsed = JSON.parse(cappedAgent.text);
            if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
              return Response.json(
                { error: 'bad_json', ...(isCallerPrivate ? { visibility: 'private' as const } : {}) },
                { status: 400, headers: callerHdrs },
              );
            }
            payload = parsed as Record<string, unknown>;
          } catch {
            return Response.json(
              { error: 'bad_json', ...(isCallerPrivate ? { visibility: 'private' as const } : {}) },
              { status: 400, headers: callerHdrs },
            );
          }
          const isPrivateReq = isPrivateRequestPayload(payload, callerUserId);
          const wantSse = (request.headers.get('accept') ?? '').toLowerCase().includes('text/event-stream');
          const agentWaitUntil = trackedCtx?.waitUntil
            ? (p: Promise<unknown>) => trackedCtx.waitUntil(p)
            : (p: Promise<unknown>) => {
                void p
                  .catch(() => undefined)
                  .finally(() => flushTracerWithTelemetry(rootTracer).catch(() => false));
              };
          const out = await startOrExecuteAgentCall({
            payload,
            env,
            executeHubFetch,
            selfHost: url.hostname,
            principal: auth.principal,
            userId: callerUserId,
            sessionSigningSecret: sessionSecret,
            vaultStore,
            ...federationPolicyOpts(),
            wantSseStream: wantSse,
            waitUntil: agentWaitUntil,
          });
          if (out.kind === 'sse') {
            return wrapSseResponseWithFlush(out.response, () => {
              const p = flushTracerWithTelemetry(rootTracer);
              if (ctx?.waitUntil) ctx.waitUntil(p);
              return p;
            });
          }
          const isPrivOut = isPrivateReq || (out.body as { visibility?: string }).visibility === 'private';
          return Response.json(
            { ...out.body, ...(isPrivOut ? { visibility: 'private' as const } : {}) },
            {
              status: out.status,
              headers: {
                'cache-control': isPrivOut ? 'private, no-store' : 'no-store',
                ...(out.status === 429 ? { 'retry-after': '2' } : {}),
              },
            },
          );
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
          if (!auth.scopes.includes('crawl:read') && !auth.scopes.includes('crawl:fetch')) {
            const isPriv403 = sanitizeStorageUserId(resolveCallerUserId(auth as { userId?: string; principal?: string })) !== 'owner';
            return Response.json(
              { error: 'insufficient_scope', ...(isPriv403 ? { visibility: 'private' as const } : {}) },
              { status: 403, headers: { 'cache-control': isPriv403 ? 'private, no-store' : 'no-store' } },
            );
          }
          const callerUserId = resolveCallerUserId(auth as { userId?: string; principal?: string });
          const isCallerPrivate = sanitizeStorageUserId(callerUserId) !== 'owner';
          const callerHdrs = { 'cache-control': isCallerPrivate ? 'private, no-store' : 'no-store' };
          const rawAgentId = safeDecodeURIComponent(agentTraceMatch[1] ?? '');
          if (rawAgentId === null) {
            return Response.json(
              {
                ok: false,
                ...(isCallerPrivate ? { visibility: 'private' as const } : {}),
                error: 'bad_request',
                message: 'Malformed URL path parameter',
              },
              { status: 400, headers: callerHdrs },
            );
          }
          const agentId = rawAgentId.trim();
          const rec = await loadAgentRun(agentId, env.META, callerUserId);
          if (!rec) {
            return Response.json(
              { ok: false, ...(isCallerPrivate ? { visibility: 'private' as const } : {}), error: 'agent_not_found' },
              { status: 404, headers: callerHdrs },
            );
          }
          const isPrivTrace = isCallerPrivate || rec.visibility === 'private';
          return Response.json(
            {
              ok: true,
              success: true,
              ...(isPrivTrace ? { visibility: 'private' as const } : {}),
              id: rec.id,
              threadId: rec.threadId,
              status: rec.status,
              count: rec.trace.length,
              spans: rec.trace,
              trace: rec.trace,
              events: rec.trace,
            },
            { status: 200, headers: { 'cache-control': isPrivTrace ? 'private, no-store' : 'no-store' } },
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
          const callerUserId = resolveCallerUserId(auth as { userId?: string; principal?: string });
          const isCallerPrivate = sanitizeStorageUserId(callerUserId) !== 'owner';
          const callerHdrs = { 'cache-control': isCallerPrivate ? 'private, no-store' : 'no-store' };
          const rawAgentId = safeDecodeURIComponent(agentRouteMatch[1] ?? '');
          if (rawAgentId === null) {
            return Response.json(
              {
                ok: false,
                ...(isCallerPrivate ? { visibility: 'private' as const } : {}),
                error: 'bad_request',
                message: 'Malformed URL path parameter',
              },
              { status: 400, headers: callerHdrs },
            );
          }
          const agentId = rawAgentId.trim();
          if (request.method === 'GET') {
            if (!auth.scopes.includes('crawl:read') && !auth.scopes.includes('crawl:fetch')) {
              return Response.json(
                { error: 'insufficient_scope', ...(isCallerPrivate ? { visibility: 'private' as const } : {}) },
                { status: 403, headers: callerHdrs },
              );
            }
            const rec = await loadAgentRun(agentId, env.META, callerUserId);
            if (!rec) {
              return Response.json(
                { ok: false, ...(isCallerPrivate ? { visibility: 'private' as const } : {}), error: 'agent_not_found' },
                { status: 404, headers: callerHdrs },
              );
            }
            const isPrivGet = isCallerPrivate || rec.visibility === 'private';
            return Response.json(
              { ...formatPublicAgentResponse(rec, false), ...(isPrivGet ? { visibility: 'private' as const } : {}) },
              { status: 200, headers: { 'cache-control': isPrivGet ? 'private, no-store' : 'no-store' } },
            );
          }
          if (request.method === 'DELETE') {
            if (!auth.scopes.includes('crawl:fetch')) {
              return Response.json(
                { error: 'insufficient_scope', ...(isCallerPrivate ? { visibility: 'private' as const } : {}) },
                { status: 403, headers: callerHdrs },
              );
            }
            const cRes = await cancelAgentRun(agentId, env.META, callerUserId);
            const isPrivCancel = isCallerPrivate || cRes.visibility === 'private';
            return Response.json(
              { ok: cRes.ok, ...(isPrivCancel ? { visibility: 'private' as const } : {}), id: agentId, status: 'cancelled' },
              { status: cRes.status, headers: { 'cache-control': isPrivCancel ? 'private, no-store' : 'no-store' } },
            );
          }
          return Response.json(
            { error: 'not_found', ...(isCallerPrivate ? { visibility: 'private' as const } : {}) },
            { status: 404, headers: callerHdrs },
          );
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
          const callerUserId = resolveCallerUserId(auth as { userId?: string; principal?: string });
          const isCallerPrivate = sanitizeStorageUserId(callerUserId) !== 'owner';
          const callerHdrs = { 'cache-control': isCallerPrivate ? 'private, no-store' : 'no-store' };
          if (!auth.scopes.includes('crawl:fetch')) {
            return Response.json(
              { error: 'insufficient_scope', ...(isCallerPrivate ? { visibility: 'private' as const } : {}) },
              { status: 403, headers: callerHdrs },
            );
          }
          const cappedCrawl = await readBodyTextCapped(request, MAX_CALL_UTF8_BYTES);
          if (!cappedCrawl.ok) {
            return Response.json(
              {
                error: cappedCrawl.error === 'too_large' ? 'payload_too_large' : 'bad_json',
                ...(isCallerPrivate ? { visibility: 'private' as const } : {}),
              },
              { status: cappedCrawl.error === 'too_large' ? 413 : 400, headers: callerHdrs },
            );
          }
          let payload: Record<string, unknown>;
          try {
            const parsed = JSON.parse(cappedCrawl.text);
            if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
              return Response.json(
                { error: 'bad_json', ...(isCallerPrivate ? { visibility: 'private' as const } : {}) },
                { status: 400, headers: callerHdrs },
              );
            }
            payload = parsed as Record<string, unknown>;
          } catch {
            return Response.json(
              { error: 'bad_json', ...(isCallerPrivate ? { visibility: 'private' as const } : {}) },
              { status: 400, headers: callerHdrs },
            );
          }
          const isPrivateReq = isPrivateRequestPayload(payload, callerUserId);
          const crawlHdrs = { 'cache-control': isPrivateReq ? 'private, no-store' : 'no-store' };
          let displayCollectionId: string | undefined;
          if (typeof payload.collectionId === 'string' && payload.collectionId.trim()) {
            const resolvedColl = resolveUserCollectionId(payload.collectionId, auth.userId, isPrivateReq ? 'private' : 'public');
            if (!resolvedColl.ok) {
              return Response.json(
                {
                  ok: false,
                  ...(isPrivateReq ? { visibility: 'private' as const } : {}),
                  error: resolvedColl.error,
                  message: resolvedColl.message,
                },
                { status: resolvedColl.status, headers: crawlHdrs },
              );
            }
            payload = { ...payload, collectionId: resolvedColl.scopedId };
            displayCollectionId = resolvedColl.displayId;
          }
          const created = await createCrawlJob({
            payload,
            metaDb: env.META,
            selfHost: url.hostname,
            userId: auth.userId,
          });
          if (!created.ok) {
            return Response.json(
              {
                ok: false,
                ...(isPrivateReq ? { visibility: 'private' as const } : {}),
                error: created.error,
                message: created.message,
              },
              {
                status: created.status,
                headers: created.status === 429 ? { ...crawlHdrs, 'retry-after': '2' } : crawlHdrs,
              },
            );
          }
          let startedViaWorkflow = false;
          if (payload.sync !== true && env.CRAWL) {
            try {
              await env.CRAWL.create({
                id: created.crawlId,
                params: {
                  crawlId: created.crawlId,
                  rootUrl: created.rootUrl,
                  userId: auth.userId,
                  options: created.options,
                  selfHost: url.hostname,
                },
              });
              startedViaWorkflow = true;
            } catch {
              startedViaWorkflow = false;
            }
          }
          if (!startedViaWorkflow) {
            const jobPromise = executeCrawlJob({
              crawlId: created.crawlId,
              rootUrl: created.rootUrl,
              userId: auth.userId,
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
          }
          return Response.json(
            {
              ok: true,
              ...(isPrivateReq ? { visibility: 'private' as const } : {}),
              id: created.crawlId,
              status: payload.sync === true ? 'completed' : 'queued',
              collectionId: displayCollectionId ?? created.options.collectionId,
              url: `${url.origin}/v1/crawl/${created.crawlId}`,
            },
            { status: payload.sync === true ? 200 : 202, headers: crawlHdrs },
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
          const callerUserId = resolveCallerUserId(auth as { userId?: string; principal?: string });
          const isCallerPrivate = sanitizeStorageUserId(callerUserId) !== 'owner';
          const callerHdrs = { 'cache-control': isCallerPrivate ? 'private, no-store' : 'no-store' };
          const rawCrawlId = safeDecodeURIComponent(crawlRouteMatch[1] ?? '');
          if (rawCrawlId === null) {
            return Response.json(
              {
                ok: false,
                ...(isCallerPrivate ? { visibility: 'private' as const } : {}),
                error: 'bad_request',
                message: 'Malformed URL path parameter',
              },
              { status: 400, headers: callerHdrs },
            );
          }
          const crawlId = rawCrawlId.trim();
          if (request.method === 'GET') {
            if (!auth.scopes.includes('crawl:read') && !auth.scopes.includes('crawl:fetch')) {
              return Response.json(
                { error: 'insufficient_scope', ...(isCallerPrivate ? { visibility: 'private' as const } : {}) },
                { status: 403, headers: callerHdrs },
              );
            }
            const st = await getCrawlJobStatus({
              crawlId,
              metaDb: env.META,
              bucket: env.ARTIFACTS,
              offset: Number(url.searchParams.get('offset') ?? 0),
              limit: Number(url.searchParams.get('limit') ?? 25),
              userId: auth.userId,
            });
            if (!st.ok) {
              return Response.json(
                { ok: false, ...(isCallerPrivate ? { visibility: 'private' as const } : {}), error: st.error },
                { status: st.status, headers: callerHdrs },
              );
            }
            const isCrawlPrivate = isCallerPrivate || st.crawl.visibility === 'private';
            const crawlStatusHdrs = { 'cache-control': isCrawlPrivate ? 'private, no-store' : 'no-store' };
            return Response.json(
              { ok: true, ...(isCrawlPrivate ? { visibility: 'private' as const } : {}), ...st.crawl },
              { status: 200, headers: crawlStatusHdrs },
            );
          }
          if (request.method === 'DELETE') {
            if (!auth.scopes.includes('crawl:fetch')) {
              return Response.json(
                { error: 'insufficient_scope', ...(isCallerPrivate ? { visibility: 'private' as const } : {}) },
                { status: 403, headers: callerHdrs },
              );
            }
            const cRes = await cancelCrawlJob(crawlId, env.META, auth.userId);
            const isCrawlPrivate = isCallerPrivate || cRes.visibility === 'private';
            return Response.json(
              { ok: cRes.ok, ...(isCrawlPrivate ? { visibility: 'private' as const } : {}), id: crawlId, status: 'cancelled' },
              { status: cRes.status, headers: { 'cache-control': isCrawlPrivate ? 'private, no-store' : 'no-store' } },
            );
          }
          return Response.json(
            { error: 'not_found', ...(isCallerPrivate ? { visibility: 'private' as const } : {}) },
            { status: 404, headers: callerHdrs },
          );
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
            const isPriv403 = sanitizeStorageUserId(resolveCallerUserId(auth as { userId?: string; principal?: string })) !== 'owner';
            return Response.json(
              { error: 'insufficient_scope', ...(isPriv403 ? { visibility: 'private' as const } : {}) },
              { status: 403, headers: { 'cache-control': isPriv403 ? 'private, no-store' : 'no-store' } },
            );
          }
          const callerUserId = resolveCallerUserId(auth as { userId?: string; principal?: string });
          const isCallerPrivate = sanitizeStorageUserId(callerUserId) !== 'owner';
          const callerHdrs = { 'cache-control': isCallerPrivate ? 'private, no-store' : 'no-store' };
          if (!env.SEARCH) {
            return Response.json(
              { error: 'search_not_configured', ...(isCallerPrivate ? { visibility: 'private' as const } : {}) },
              { status: 503, headers: callerHdrs },
            );
          }
          const rawCollectionId = safeDecodeURIComponent(collectionSearchMatch[1] ?? '');
          if (rawCollectionId === null) {
            return Response.json(
              {
                error: 'bad_request',
                ...(isCallerPrivate ? { visibility: 'private' as const } : {}),
                message: 'Malformed URL path parameter',
              },
              { status: 400, headers: callerHdrs },
            );
          }
          let query = url.searchParams.get('q') ?? url.searchParams.get('query') ?? '';
          let limit = Number(url.searchParams.get('limit') ?? 10);
          let reqVisibility = url.searchParams.get('visibility') ?? '';
          if (request.method === 'POST') {
            const cappedColSearch = await readBodyTextCapped(request, MAX_CALL_UTF8_BYTES);
            if (!cappedColSearch.ok) {
              return Response.json(
                {
                  error: cappedColSearch.error === 'too_large' ? 'payload_too_large' : 'bad_json',
                  ...(isCallerPrivate ? { visibility: 'private' as const } : {}),
                },
                { status: cappedColSearch.error === 'too_large' ? 413 : 400, headers: callerHdrs },
              );
            }
            try {
              const parsed = JSON.parse(cappedColSearch.text);
              if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
                return Response.json(
                  { error: 'bad_json', ...(isCallerPrivate ? { visibility: 'private' as const } : {}) },
                  { status: 400, headers: callerHdrs },
                );
              }
              const bodyJson = parsed as { query?: unknown; q?: unknown; limit?: unknown; visibility?: unknown };
              if (typeof bodyJson.query === 'string') query = bodyJson.query;
              else if (typeof bodyJson.q === 'string') query = bodyJson.q;
              if (typeof bodyJson.limit === 'number' && Number.isFinite(bodyJson.limit)) limit = bodyJson.limit;
              if (typeof bodyJson.visibility === 'string') reqVisibility = bodyJson.visibility;
            } catch {
              return Response.json(
                { error: 'bad_json', ...(isCallerPrivate ? { visibility: 'private' as const } : {}) },
                { status: 400, headers: callerHdrs },
              );
            }
          }
          const isPrivateColSearch = isCallerPrivate || reqVisibility.trim().toLowerCase() === 'private';
          const colHdrs = { 'cache-control': isPrivateColSearch ? 'private, no-store' : 'no-store' };
          const resolvedCol = resolveUserCollectionId(
            rawCollectionId.trim(),
            auth.userId,
            isPrivateColSearch ? 'private' : 'public',
          );
          if (!resolvedCol.ok) {
            return Response.json(
              {
                error: resolvedCol.error,
                message: resolvedCol.message,
                ...(isPrivateColSearch ? { visibility: 'private' as const } : {}),
              },
              { status: resolvedCol.status, headers: colHdrs },
            );
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
              ...(isPrivateColSearch ? { visibility: 'private' as const } : {}),
              collectionId: resolvedCol.displayId,
              query,
              hits: hits.map((h) => ({ ...h, collectionId: resolvedCol.displayId })),
            },
            { status: 200, headers: colHdrs },
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
          const callerUserId = resolveCallerUserId(auth as { userId?: string; principal?: string });
          const isCallerPrivate = sanitizeStorageUserId(callerUserId) !== 'owner';
          const callerHdrs = { 'cache-control': isCallerPrivate ? 'private, no-store' : 'no-store' };
          if (!auth.scopes.includes('crawl:fetch')) {
            return Response.json(
              { error: 'insufficient_scope', ...(isCallerPrivate ? { visibility: 'private' as const } : {}) },
              { status: 403, headers: callerHdrs },
            );
          }
          const cappedJobs = await readBodyTextCapped(request, MAX_CALL_UTF8_BYTES);
          if (!cappedJobs.ok) {
            return Response.json(
              {
                error: cappedJobs.error === 'too_large' ? 'payload_too_large' : 'bad_json',
                ...(isCallerPrivate ? { visibility: 'private' as const } : {}),
              },
              { status: cappedJobs.error === 'too_large' ? 413 : 400, headers: callerHdrs },
            );
          }
          let payload: JobsToolPayload;
          try {
            const parsed = JSON.parse(cappedJobs.text);
            if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
              return Response.json(
                { error: 'bad_json', ...(isCallerPrivate ? { visibility: 'private' as const } : {}) },
                { status: 400, headers: callerHdrs },
              );
            }
            payload = parsed as JobsToolPayload;
          } catch {
            return Response.json(
              { error: 'bad_json', ...(isCallerPrivate ? { visibility: 'private' as const } : {}) },
              { status: 400, headers: callerHdrs },
            );
          }
          const isPrivateReq = isPrivateRequestPayload(payload, callerUserId);
          const callerAuthTier = auth.role ?? (callerUserId === 'owner' ? 'owner' : 'member');
          const releaseScrapeSlot = tryAcquireUserConcurrencySlot(
            inFlightScrapesByUser,
            callerUserId,
            MAX_CONCURRENT_SCRAPES_PER_USER,
          );
          if (!releaseScrapeSlot) {
            return userQuotaExceededResponse(
              `Per-user concurrent scrape limit (${MAX_CONCURRENT_SCRAPES_PER_USER}) exceeded.`,
              isPrivateReq,
            );
          }
          try {
            const out = await executeJobsCall({
              payload,
              env: env as unknown as OptionalStorageBindings & Record<string, unknown>,
              userId: callerUserId,
              authTier: callerAuthTier,
              executeSearch: async (sArgs) => {
                const sOut = await executeSearchCall({
                  payload: sArgs as SearchRequestPayload,
                  env,
                  executeHubFetch,
                  source: `jobs-search:${auth.principal}`,
                  userId: callerUserId,
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
                  userId: callerUserId,
                });
                return { status: scOut.status, body: scOut.body };
              },
            });
            const isPrivOut = isPrivateReq || (out.body as { visibility?: string }).visibility === 'private';
            return Response.json(
              { ...out.body, ...(isPrivOut ? { visibility: 'private' as const } : {}) },
              {
                status: out.status,
                headers: {
                  'cache-control': isPrivOut ? 'private, no-store' : 'no-store',
                  ...(out.status === 429 ? { 'retry-after': '2' } : {}),
                },
              },
            );
          } finally {
            releaseScrapeSlot();
          }
        });
      }

      if (request.method === 'POST' && url.pathname === '/v1/company') {
        return withRouteSpan('edgefetch.company', {}, async () => {
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
          const callerUserId = resolveCallerUserId(auth as { userId?: string; principal?: string });
          const isCallerPrivate = sanitizeStorageUserId(callerUserId) !== 'owner';
          const callerHdrs = { 'cache-control': isCallerPrivate ? 'private, no-store' : 'no-store' };
          if (!auth.scopes.includes('crawl:fetch')) {
            return Response.json(
              { error: 'insufficient_scope', ...(isCallerPrivate ? { visibility: 'private' as const } : {}) },
              { status: 403, headers: callerHdrs },
            );
          }
          const capped = await readBodyTextCapped(request, MAX_CALL_UTF8_BYTES);
          if (!capped.ok) {
            return Response.json({ error: 'payload_too_large' }, { status: 413, headers: callerHdrs });
          }
          let args: Record<string, unknown>;
          try {
            const parsed = JSON.parse(capped.text || '{}') as unknown;
            if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error('not an object');
            args = parsed as Record<string, unknown>;
          } catch {
            return Response.json({ error: 'invalid_json' }, { status: 400, headers: callerHdrs });
          }
          const tier = (auth as { role?: string }).role ?? (callerUserId === 'owner' ? 'owner' : 'member');
          const releaseSlot = tryAcquireUserConcurrencySlot(inFlightScrapesByUser, callerUserId, MAX_CONCURRENT_SCRAPES_PER_USER);
          if (!releaseSlot) {
            return Response.json({ ok: false, error: 'user_quota_exceeded' }, { status: 429, headers: callerHdrs });
          }
          try {
            const ex = makeVerticalExecutors('api:company', callerUserId, tier);
            const out = await ex.company(args);
            return Response.json(out.body, { status: out.status, headers: callerHdrs });
          } finally {
            releaseSlot();
          }
        });
      }

      if (request.method === 'POST' && url.pathname === '/v1/salaries') {
        return withRouteSpan('edgefetch.salaries', {}, async () => {
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
          const callerUserId = resolveCallerUserId(auth as { userId?: string; principal?: string });
          const isCallerPrivate = sanitizeStorageUserId(callerUserId) !== 'owner';
          const callerHdrs = { 'cache-control': isCallerPrivate ? 'private, no-store' : 'no-store' };
          if (!auth.scopes.includes('crawl:fetch')) {
            return Response.json(
              { error: 'insufficient_scope', ...(isCallerPrivate ? { visibility: 'private' as const } : {}) },
              { status: 403, headers: callerHdrs },
            );
          }
          const capped = await readBodyTextCapped(request, MAX_CALL_UTF8_BYTES);
          if (!capped.ok) {
            return Response.json({ error: 'payload_too_large' }, { status: 413, headers: callerHdrs });
          }
          let args: Record<string, unknown>;
          try {
            const parsed = JSON.parse(capped.text || '{}') as unknown;
            if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error('not an object');
            args = parsed as Record<string, unknown>;
          } catch {
            return Response.json({ error: 'invalid_json' }, { status: 400, headers: callerHdrs });
          }
          const tier = (auth as { role?: string }).role ?? (callerUserId === 'owner' ? 'owner' : 'member');
          const releaseSlot = tryAcquireUserConcurrencySlot(inFlightScrapesByUser, callerUserId, MAX_CONCURRENT_SCRAPES_PER_USER);
          if (!releaseSlot) {
            return Response.json({ ok: false, error: 'user_quota_exceeded' }, { status: 429, headers: callerHdrs });
          }
          try {
            const ex = makeVerticalExecutors('api:salaries', callerUserId, tier);
            const out = await ex.salaries(args);
            return Response.json(out.body, { status: out.status, headers: callerHdrs });
          } finally {
            releaseSlot();
          }
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
          const callerUserId = resolveCallerUserId(auth as { userId?: string; principal?: string });
          const isCallerPrivate = sanitizeStorageUserId(callerUserId) !== 'owner';
          const callerHdrs = { 'cache-control': isCallerPrivate ? 'private, no-store' : 'no-store' };
          if (!auth.scopes.includes('crawl:fetch')) {
            return Response.json(
              { error: 'insufficient_scope', ...(isCallerPrivate ? { visibility: 'private' as const } : {}) },
              { status: 403, headers: callerHdrs },
            );
          }
          const cappedCat = await readBodyTextCapped(request, MAX_CALL_UTF8_BYTES);
          if (!cappedCat.ok) {
            return Response.json(
              {
                error: cappedCat.error === 'too_large' ? 'payload_too_large' : 'bad_json',
                ...(isCallerPrivate ? { visibility: 'private' as const } : {}),
              },
              { status: cappedCat.error === 'too_large' ? 413 : 400, headers: callerHdrs },
            );
          }
          let payload: CatalogCallPayload;
          try {
            const parsed = JSON.parse(cappedCat.text);
            if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
              return Response.json(
                { error: 'bad_json', ...(isCallerPrivate ? { visibility: 'private' as const } : {}) },
                { status: 400, headers: callerHdrs },
              );
            }
            payload = parsed as CatalogCallPayload;
          } catch {
            return Response.json(
              { error: 'bad_json', ...(isCallerPrivate ? { visibility: 'private' as const } : {}) },
              { status: 400, headers: callerHdrs },
            );
          }
          const isPrivateReq = isPrivateRequestPayload(payload, callerUserId);
          const out = await executeCatalogCall({
            payload,
            env: env as unknown as OptionalStorageBindings & Record<string, unknown>,
            executeHubFetch: makeCatalogHubFetch(`catalog:${auth.principal}`),
            selfHost: url.hostname,
            principal: auth.principal,
            userId: auth.userId,
            devTelemetrySetting: getCachedDevTelemetrySetting,
            ...(trackedCtx?.waitUntil ? { ctx: { waitUntil: (p: Promise<unknown>) => trackedCtx.waitUntil(p) } } : {}),
          });
          const isPrivOut = isPrivateReq || (out.body as { visibility?: string }).visibility === 'private';
          return Response.json(
            { ...out.body, ...(isPrivOut ? { visibility: 'private' as const } : {}) },
            {
              status: out.status,
              headers: {
                'cache-control': isPrivOut ? 'private, no-store' : 'no-store',
                ...(out.status === 429 ? { 'retry-after': '2' } : {}),
              },
            },
          );
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
            const isPriv403 = sanitizeStorageUserId(resolveCallerUserId(auth as { userId?: string; principal?: string })) !== 'owner';
            return Response.json(
              { error: 'insufficient_scope', ...(isPriv403 ? { visibility: 'private' as const } : {}) },
              { status: 403, headers: { 'cache-control': isPriv403 ? 'private, no-store' : 'no-store' } },
            );
          }
          const callerUserId = resolveCallerUserId(auth as { userId?: string; principal?: string });
          const isCallerPrivate = sanitizeStorageUserId(callerUserId) !== 'owner';
          const callerHdrs = { 'cache-control': isCallerPrivate ? 'private, no-store' : 'no-store' };
          const rawCatalogId = safeDecodeURIComponent(catalogRecordsMatch[1] ?? '');
          if (rawCatalogId === null) {
            return Response.json(
              {
                ok: false,
                ...(isCallerPrivate ? { visibility: 'private' as const } : {}),
                error: 'bad_request',
                message: 'Malformed URL path parameter',
              },
              { status: 400, headers: callerHdrs },
            );
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
            userId: auth.userId,
            env: env as unknown as OptionalStorageBindings & Record<string, unknown>,
            ...(auth.scopes.includes('crawl:fetch') ? { executeHubFetch: makeCatalogHubFetch('catalog_records') } : {}),
          });
          const isPrivOut = isCallerPrivate || (out.body as { visibility?: string }).visibility === 'private';
          return Response.json(
            { ...out.body, ...(isPrivOut ? { visibility: 'private' as const } : {}) },
            {
              status: out.status,
              headers: { 'cache-control': isPrivOut ? 'private, no-store' : 'no-store' },
            },
          );
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
            const isPriv403 = sanitizeStorageUserId(resolveCallerUserId(auth as { userId?: string; principal?: string })) !== 'owner';
            return Response.json(
              { error: 'insufficient_scope', ...(isPriv403 ? { visibility: 'private' as const } : {}) },
              { status: 403, headers: { 'cache-control': isPriv403 ? 'private, no-store' : 'no-store' } },
            );
          }
          const callerUserId = resolveCallerUserId(auth as { userId?: string; principal?: string });
          const isCallerPrivate = sanitizeStorageUserId(callerUserId) !== 'owner';
          const callerHdrs = { 'cache-control': isCallerPrivate ? 'private, no-store' : 'no-store' };
          const rawCatalogId = safeDecodeURIComponent(catalogStatusMatch[1] ?? '');
          if (rawCatalogId === null) {
            return Response.json(
              {
                ok: false,
                ...(isCallerPrivate ? { visibility: 'private' as const } : {}),
                error: 'bad_request',
                message: 'Malformed URL path parameter',
              },
              { status: 400, headers: callerHdrs },
            );
          }
          const catalogId = rawCatalogId.trim();
          const out = await getCatalogStatus({
            catalogId,
            userId: auth.userId,
            env: env as unknown as OptionalStorageBindings & Record<string, unknown>,
          });
          const isPrivOut = isCallerPrivate || (out.body as { visibility?: string }).visibility === 'private';
          return Response.json(
            { ...out.body, ...(isPrivOut ? { visibility: 'private' as const } : {}) },
            {
              status: out.status,
              headers: { 'cache-control': isPrivOut ? 'private, no-store' : 'no-store' },
            },
          );
        });
      }

      if (request.method === 'POST' && (url.pathname === '/fetch' || url.pathname === '/fetch/batch')) {
        return withRouteSpan('edgefetch.fetch', {}, async () => {
          // U1 Security Invariant: Raw `/fetch` and `/fetch/batch` require `CALLER_TOKEN` strictly.
          // OAuth tokens (`efa_*` / `efu_*`) MUST use `/v1/*` or `/mcp` where per-user ownership, header stripping,
          // and robots policy guardrails are enforced.
          if (!isCallerAuthorized(request, env.CALLER_TOKEN, env.CALLER_TOKEN_PREVIOUS)) {
            return Response.json({ error: 'unauthorized' }, { status: 401, headers: { 'cache-control': 'no-store' } });
          }
          const parsedTarget = parseFetchTarget(url);
          if (!parsedTarget.ok) return Response.json({ error: 'bad_target', message: parsedTarget.message }, { status: 400, headers: { 'cache-control': 'no-store' } });
          const cappedFetch = await readBodyTextCapped(request, MAX_CALL_UTF8_BYTES);
          if (!cappedFetch.ok) {
            return Response.json(
              { error: cappedFetch.error === 'too_large' ? 'payload_too_large' : 'bad_json' },
              { status: cappedFetch.error === 'too_large' ? 413 : 400, headers: { 'cache-control': 'no-store' } },
            );
          }
          let body = cappedFetch.text;
          try {
            const parsedRaw = JSON.parse(body);
            if (!parsedRaw || typeof parsedRaw !== 'object' || Array.isArray(parsedRaw)) {
              return Response.json({ error: 'bad_json' }, { status: 400, headers: { 'cache-control': 'no-store' } });
            }
            const parsedReq = parsedRaw as Record<string, unknown>;
            if (url.pathname === '/fetch') {
              if (typeof parsedReq.url === 'string') {
                const wikiArt = parseWikipediaArticleUrl(parsedReq.url);
                if (wikiArt) {
                  const q = checkAndRecordWikipediaArticleQuota({ callerKey: 'owner', host: wikiArt.host });
                  if (!q.allowed) {
                    return Response.json(q.block, {
                      status: 429,
                      headers: { 'cache-control': 'no-store', 'retry-after': '60' },
                    });
                  }
                }
              }
            } else {
              const rawItems: unknown[] = Array.isArray(parsedReq.requests)
                ? (parsedReq.requests as unknown[])
                : Array.isArray(parsedReq.urls)
                  ? (parsedReq.urls as unknown[])
                  : [];
              for (const item of rawItems) {
                const rawItemUrl =
                  item && typeof item === 'object' && !Array.isArray(item)
                    ? (item as Record<string, unknown>).url
                    : item;
                if (typeof rawItemUrl === 'string') {
                  const wikiArt = parseWikipediaArticleUrl(rawItemUrl);
                  if (wikiArt) {
                    const q = checkAndRecordWikipediaArticleQuota({ callerKey: 'owner', host: wikiArt.host });
                    if (!q.allowed) {
                      return Response.json(q.block, {
                        status: 429,
                        headers: { 'cache-control': 'no-store', 'retry-after': '60' },
                      });
                    }
                  }
                }
              }
              if (Array.isArray(parsedReq.urls) && !Array.isArray(parsedReq.requests)) {
                body = JSON.stringify({
                  maxSeconds: typeof parsedReq.maxSeconds === 'number' ? parsedReq.maxSeconds : 60,
                  options: {
                    includeBody: true,
                    respectRobots: true,
                    concurrency: 4,
                    ...(parsedReq.options && typeof parsedReq.options === 'object' ? (parsedReq.options as object) : {}),
                  },
                  requests: (parsedReq.urls as unknown[]).map((u, idx) => ({
                    id: `b-${idx + 1}`,
                    url: String(u),
                  })),
                });
              }
            }
          } catch {
            return Response.json({ error: 'bad_json' }, { status: 400, headers: { 'cache-control': 'no-store' } });
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
        });
      }

      if (!isCallerAuthorized(request, env.CALLER_TOKEN, env.CALLER_TOKEN_PREVIOUS)) {
        return Response.json({ error: 'unauthorized' }, { status: 401 });
      }
      if (request.method === 'GET' && url.pathname === '/agents') {
        return withRouteSpan('edgefetch.agents', {}, async () => Response.json(await hub().listAgents()));
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
            const res = await runWithCallerAuthContext(
              async () => {
                try {
                  return annotateCallerAuthFailure(url, await routeRequest());
                } catch (err) {
                  if (err instanceof AccessPolicyDeniedSignal) return err.response;
                  throw err;
                }
              },
              undefined,
              env,
            );
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
        const flushPromise = flushTracerWithTelemetry(rootTracer);
        if (ctx?.waitUntil) {
          ctx.waitUntil(flushPromise);
        } else {
          await flushPromise;
        }
      }
    }
    return injectTraceHeaders(response, rootTracer);
  },

  async scheduled(_controller: ScheduledController, env: Env, _ctx?: ExecutionContext): Promise<void> {
    if (env.META) {
      await pruneExpiredFetchHistory(env.META).catch(() => undefined);
    }
    const trackerBucket = env.ARTIFACTS ?? env.TRACKER_BUCKET;
    if (trackerBucket && !isTrackerListDisabled(env)) {
      const shardNames = (env.HUB_SHARDS ?? 'global')
        .split(',')
        .map((s) => s.trim())
        .filter((s) => /^[a-z0-9_-]{1,32}$/i.test(s));
      if (shardNames.length === 0) shardNames.push('global');
      let settingVal: string | null = null;
      if (env.AGENT_HUB) {
        try {
          const primaryStub = env.AGENT_HUB.get(env.AGENT_HUB.idFromName(shardNames[0]!)) as unknown as {
            getHubSetting?: (k: string) => Promise<string | null>;
          };
          if (typeof primaryStub.getHubSetting === 'function') {
            settingVal = await primaryStub.getHubSetting('tracker_list');
          }
        } catch {
          settingVal = null;
        }
      }
      if (!isTrackerListDisabled(env, settingVal)) {
        const refreshed = await refreshHubTrackerList({
          bucket: trackerBucket,
          fetchFn: env.SAFE_PUBLIC_FETCH ?? env.SAFE_FETCH ?? fetch,
          env,
          hubSettingValue: settingVal,
          publicOrigin: env.EDGEFETCH_PUBLIC_ORIGIN,
        }).catch(() => null);
        if (refreshed?.updated && refreshed.current && env.AGENT_HUB) {
          const extraAllow = resolveExtraNeverBlockHosts({ publicOrigin: env.EDGEFETCH_PUBLIC_ORIGIN });
          const frames = buildTrackerListWsFrames(refreshed.current, extraAllow);
          await Promise.allSettled(
            shardNames.map((sName) => {
              const stub = env.AGENT_HUB.get(env.AGENT_HUB.idFromName(sName)) as unknown as {
                syncTrackerList?: (v: string | null, f: string[]) => Promise<void>;
              };
              return typeof stub.syncTrackerList === 'function'
                ? stub.syncTrackerList(refreshed.current!.meta.version, frames)
                : Promise.resolve();
            }),
          );
        }
      }
    }
  },
};
