/**
 * Autonomous Research Agent (`POST /v1/agent`, `GET /v1/agent/:id`, `GET /v1/agent/:id/trace`, `DELETE /v1/agent/:id`,
 * `/v2/agent` Firecrawl drop-in compat, and MCP `agent` + `find_extractors` tools).
 *
 * Delegates pure-CPU adapter intent routing (`findRelevantAdapters`), MCP selector matching (`doesMcpServerSelectorMatchRow`),
 * remote MCP parameter schema sanitization (`sanitizeRemoteToolSchemaForLlm`), URL scope checks, browser action allowlisting,
 * effort/location parsing, tool/prompt construction, untrusted MCP envelope wrapping, and public response formatting
 * to Go (`internal/agentloop` via `edgefetch-core.wasm`), while managing Cloudflare D1/in-memory state, SSE streaming,
 * async `waitUntil`, cancellation, per-user concurrency caps, and host tool I/O.
 */

import type { AdapterCategory } from './extractors/types';
import { executeJobsCall, type JobsToolPayload } from './jobs';
import {
  executeFederatedMcpQuery,
  extractMarkdownFromQueryMcpBody,
  formatFenceSafeUntrustedMcpEnvelope,
  matchConnectedMcpsForContext,
  sanitizeMcpMarkdownOutput,
  sanitizeRemoteMcpText,
  tryScrapeViaConnectedMcp,
  type QueryMcpCallInput,
} from './mcp-federation';
import {
  filterSafeCachedMcpTools,
  isCachedMcpToolPermitted,
  isSafeMcpIdentifier,
  isValidMcpConnectorSlug,
  parseAllowedMcpTools,
  resolveCallerUserId,
  toPublicMcpServerSummary,
  type CachedMcpToolSchema,
  type McpVaultStore,
  type StoredMcpServerRow,
} from './mcp-vault';
import { listCallableServersForCaller, type AccessPolicyStore } from './access-policy';
import { getActiveCallerAuthContext } from './oauth';
import {
  completeLlmTurn,
  extractJsonWithOptionalLlm,
  parseLooseJsonObject,
  redactLlmConfigForLog,
  resolveLlmConfig,
  summarizeMarkdownWithOptionalLlm,
  validateDataAgainstJsonSchema,
  type LlmEnvBindings,
  type LlmMessage,
  type LlmToolDefinition,
  type ResolvedLlmConfig,
} from './llm';
import { deliverSignedWebhook, executeMapCall, type HubFetchExecutor, type WebhookConfig } from './map-crawl';
import { validatePublicHttpsTargetUrl } from './overflow';
import {
  getActiveRequestTracer,
  sanitizeErrorMessageForSpan,
  sanitizeUrlForSpan,
  type ActiveSpanHandle,
  type RequestTracer,
  type TraceContext,
} from './otel';
import { executeInteractCall, executeScrapeCall, extractStructuredJsonFromPage, type ScrapeRequestPayload } from './scrape';
import { D1FtsSearchIndex, resolveUserCollectionId } from './search-index';
import { isPrivateRequestPayload, type OptionalStorageBindings } from './storage';
import { callCoreWasm } from './wasm-bridge';
import { executeSearchCall, type SearchBindings, type SearchRequestPayload } from './web-search';

export type AgentEffort = 'low' | 'medium' | 'high';
export type AgentStatus = 'queued' | 'processing' | 'completed' | 'failed' | 'cancelled';
export type AgentStopReason = 'completed' | 'budget_reached' | 'cancelled' | 'failed';

export interface AgentTraceSpan {
  sequence: number;
  spanId: string;
  kind: 'router' | 'tool_call' | 'llm_turn' | 'synthesis' | 'budget' | 'error';
  name: string;
  status: 'ok' | 'error' | 'skipped';
  startedAt: number;
  durationMs: number;
  input?: Record<string, unknown>;
  outputPreview?: unknown;
}

export interface AgentRunRecord {
  id: string;
  userId?: string;
  threadId: string;
  status: AgentStatus;
  stopReason?: AgentStopReason;
  prompt: string;
  urls: string[];
  strictConstrainToURLs: boolean;
  effort: AgentEffort;
  maxSteps: number;
  maxPages: number;
  stepsUsed: number;
  pagesRead: number;
  partial?: boolean;
  partialSchemaValid?: boolean;
  schemaValid?: boolean;
  zeroDataRetention: boolean;
  visibility?: 'public' | 'private';
  routedMcps?: string[];
  llmUsed: boolean;
  llmInfo?: Record<string, unknown>;
  routedAdapters: string[];
  sources: Array<{ url: string; title?: string; via?: string; extractorId?: string }>;
  data?: unknown;
  markdown?: string;
  error?: string;
  createdAt: number;
  updatedAt: number;
  finishedAt?: number;
  expiresAt: number;
  trace: AgentTraceSpan[];
  threadMemory?: string;
}

export interface RankedAdapterMatch {
  id: string;
  name: string;
  category: AdapterCategory;
  description: string;
  domains: readonly string[];
  exampleUrls: readonly string[];
  score: number;
}

export const MAX_CONCURRENT_AGENTS_PER_USER = 4;
export const UNTRUSTED_REMOTE_PARAM_PREFIX = '[UNTRUSTED_REMOTE_PARAM] ';

const MAX_IN_MEMORY_AGENT_RUNS = 256;
const AGENT_RUN_TTL_MS = 24 * 60 * 60_000;
const inMemoryAgentRuns = new Map<string, AgentRunRecord>();
const cancelledAgentIds = new Set<string>();
const activeAgentRunsByUser = new Map<string, number>();

export function findRelevantAdapters(params: {
  query: string;
  urls?: readonly string[];
  category?: string;
  limit?: number;
}): RankedAdapterMatch[] {
  return callCoreWasm<{ matches: RankedAdapterMatch[] }>('agent_find_adapters', {
    query: params.query,
    ...(params.urls && params.urls.length > 0 ? { urls: params.urls } : {}),
    ...(params.category ? { category: params.category } : {}),
    limit: params.limit ?? 8,
  }).matches;
}

function findRelevantAdaptersWithCount(params: {
  query: string;
  urls?: readonly string[];
  limit?: number;
}): { matches: RankedAdapterMatch[]; totalIndexedAdapters: number } {
  return callCoreWasm<{ matches: RankedAdapterMatch[]; totalIndexedAdapters: number }>('agent_find_adapters', {
    query: params.query,
    ...(params.urls && params.urls.length > 0 ? { urls: params.urls } : {}),
    limit: params.limit ?? 8,
  });
}

const migratedAgentDbs = new WeakSet<D1Database>();

async function ensureAgentRunsTable(metaDb?: D1Database): Promise<void> {
  if (!metaDb) return;
  await metaDb
    .prepare(
      `CREATE TABLE IF NOT EXISTS agent_runs (
         id TEXT PRIMARY KEY,
         user_id TEXT NOT NULL DEFAULT 'owner',
         thread_id TEXT NOT NULL,
         status TEXT NOT NULL,
         record_json TEXT NOT NULL,
         created_at INTEGER NOT NULL,
         updated_at INTEGER NOT NULL,
         expires_at INTEGER NOT NULL
       )`,
    )
    .run()
    .catch(() => undefined);
  if (!migratedAgentDbs.has(metaDb)) {
    migratedAgentDbs.add(metaDb);
    const colsRes = await metaDb
      .prepare('PRAGMA table_info(agent_runs)')
      .all<{ name?: string }>()
      .catch(() => null);
    const cols = colsRes?.results;
    if (!Array.isArray(cols) || !cols.some((c) => c?.name === 'user_id')) {
      await metaDb
        .prepare("ALTER TABLE agent_runs ADD COLUMN user_id TEXT NOT NULL DEFAULT 'owner'")
        .run()
        .catch(() => undefined);
    }
  }
}

async function persistAgentRun(record: AgentRunRecord, metaDb?: D1Database): Promise<void> {
  if (record.zeroDataRetention) return;
  if (inMemoryAgentRuns.size >= MAX_IN_MEMORY_AGENT_RUNS && !inMemoryAgentRuns.has(record.id)) {
    const oldestKey = inMemoryAgentRuns.keys().next().value;
    if (oldestKey) inMemoryAgentRuns.delete(oldestKey);
  }
  inMemoryAgentRuns.set(record.id, record);
  if (metaDb) {
    await ensureAgentRunsTable(metaDb);
    await metaDb
      .prepare(
        `INSERT OR REPLACE INTO agent_runs (id, thread_id, status, record_json, created_at, updated_at, expires_at, user_id)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .bind(
        record.id,
        record.threadId,
        record.status,
        JSON.stringify(record),
        record.createdAt,
        record.updatedAt,
        record.expiresAt,
        record.userId ?? 'owner',
      )
      .run()
      .catch(() => undefined);
  }
}

export async function loadAgentRun(
  agentId: string,
  metaDb?: D1Database,
  callerUserId?: string,
): Promise<AgentRunRecord | null> {
  const canCallerRead = (rec: AgentRunRecord): boolean => {
    if (callerUserId !== undefined) return (rec.userId ?? 'owner') === callerUserId;
    if (rec.visibility === 'private' && rec.userId) return false;
    return true;
  };
  const now = Date.now();
  const mem = inMemoryAgentRuns.get(agentId);
  if (mem) {
    if (mem.expiresAt <= now) {
      inMemoryAgentRuns.delete(agentId);
    } else {
      return canCallerRead(mem) ? mem : null;
    }
  }
  if (!metaDb) return null;
  await ensureAgentRunsTable(metaDb);
  const row = await metaDb
    .prepare('SELECT record_json, expires_at FROM agent_runs WHERE id = ? LIMIT 1')
    .bind(agentId)
    .first<{ record_json: string; expires_at: number }>()
    .catch(() => null);
  if (!row || row.expires_at <= now) return null;
  try {
    const parsed = JSON.parse(row.record_json) as AgentRunRecord;
    if (!canCallerRead(parsed)) return null;
    inMemoryAgentRuns.set(agentId, parsed);
    return parsed;
  } catch {
    return null;
  }
}

export async function cancelAgentRun(
  agentId: string,
  metaDb?: D1Database,
  callerUserId?: string,
): Promise<{ ok: boolean; status: number; visibility?: 'private' }> {
  const existing = await loadAgentRun(agentId, metaDb, callerUserId);
  if (!existing) return { ok: false, status: 404 };
  cancelledAgentIds.add(agentId);
  if (existing.status === 'queued' || existing.status === 'processing') {
    existing.status = 'cancelled';
    existing.stopReason = 'cancelled';
    existing.updatedAt = Date.now();
    existing.finishedAt = existing.updatedAt;
    await persistAgentRun(existing, metaDb);
  }
  return {
    ok: true,
    status: 200,
    ...(existing.visibility === 'private' ? { visibility: 'private' as const } : {}),
  };
}

export function doesMcpServerSelectorMatchRow(rawSelector: string, row: StoredMcpServerRow): boolean {
  return callCoreWasm<{ matched: boolean }>('agent_mcp_selector_match', {
    selector: rawSelector,
    rowId: row.id,
    rowSlug: row.slug,
  }).matched;
}

export function sanitizeRemoteToolSchemaForLlm(rawNode: unknown, depth = 0): Record<string, unknown> {
  if (!rawNode || typeof rawNode !== 'object' || Array.isArray(rawNode) || depth > 5) {
    return depth === 0 ? { type: 'object', properties: {} } : {};
  }
  return callCoreWasm<{ schema: Record<string, unknown> }>('agent_sanitize_tool_schema', {
    node: rawNode,
    depth,
  }).schema;
}

function wrapConnectorTextForAgentContext(
  rawText: string,
  maxChars: number,
  attributes?: Record<string, string | undefined>,
): string {
  const cleanAttrs: Record<string, string> = {};
  if (attributes) {
    for (const [k, v] of Object.entries(attributes)) {
      if (v !== undefined) cleanAttrs[k] = v;
    }
  }
  return callCoreWasm<{ out: string }>('agent_wrap_mcp_text', {
    text: rawText,
    maxChars,
    attributes: cleanAttrs,
  }).out;
}

function isUrlAllowedByConstraint(candidateUrl: string, allowedSeeds: readonly string[], strictConstrain: boolean): boolean {
  if (!strictConstrain || allowedSeeds.length === 0) return true;
  return callCoreWasm<{ allowed: boolean }>('agent_check_url_constraint', {
    candidateUrl,
    allowedSeeds,
    strictConstrain,
  }).allowed;
}

export function formatPublicAgentResponse(rec: AgentRunRecord, includeTrace = false): Record<string, unknown> {
  return callCoreWasm<{ out: Record<string, unknown> }>('agent_format_response', {
    record: rec,
    hasData: rec.data !== undefined,
    includeTrace,
  }).out;
}

export async function startOrExecuteAgentCall(params: {
  payload: Record<string, unknown>;
  env: OptionalStorageBindings &
    SearchBindings &
    LlmEnvBindings & {
      WEBHOOK_SECRET?: string;
      VAULT_MASTER_KEY?: string;
      SAFE_PUBLIC_FETCH?: typeof fetch;
      SAFE_FETCH?: typeof fetch;
    };
  executeHubFetch: HubFetchExecutor;
  selfHost?: string;
  principal?: string;
  userId?: string;
  sessionSigningSecret?: string;
  vaultStore?: McpVaultStore;
  /** Hub access policy: lets the run use MCP servers other users shared with the caller (owner keeps credentials). */
  accessPolicy?: AccessPolicyStore;
  accessPolicyCacheKey?: string | object;
  waitUntil?: (p: Promise<unknown>) => void;
  wantSseStream?: boolean;
  llmFetchFn?: typeof fetch;
  tracer?: RequestTracer | TraceContext;
}): Promise<
  | { kind: 'json'; status: number; body: Record<string, unknown> }
  | { kind: 'sse'; response: Response }
> {
  const {
    payload,
    env,
    executeHubFetch,
    selfHost,
    principal = 'api',
    sessionSigningSecret,
    vaultStore,
    waitUntil,
    wantSseStream = false,
    llmFetchFn,
  } = params;
  const effectiveUserId = params.userId ?? resolveCallerUserId({ principal });
  const userId = effectiveUserId;
  const federationPolicyOpts = params.accessPolicy
    ? {
        accessPolicy: params.accessPolicy,
        ...(params.accessPolicyCacheKey !== undefined ? { accessPolicyCacheKey: params.accessPolicyCacheKey } : {}),
      }
    : {};
  /** Own rows plus rows shared with the caller; shared rows carry an opaque remote URL so the run never sees it. */
  const listRunnableMcpServers = async (store: McpVaultStore): Promise<StoredMcpServerRow[]> => {
    if (!params.accessPolicy) return await store.listServers(effectiveUserId);
    const { rows } = await listCallableServersForCaller(effectiveUserId, { store: params.accessPolicy, vaultStore: store, ...(params.accessPolicyCacheKey !== undefined ? { cacheKey: params.accessPolicyCacheKey } : {}) });
    return rows.map((r) =>
      r.userId === effectiveUserId
        ? r
        : { ...r, remoteUrl: `shared-mcp:${r.userId}/${r.slug}`, remoteOrigin: `shared-mcp:${r.userId}/${r.slug}`, encryptedCredentials: null },
    );
  };
  const federatedServerRef = (row: { userId: string; slug: string }): string =>
    row.userId === effectiveUserId ? row.slug : `${row.userId}/${row.slug}`;
  const agentTracer = getActiveRequestTracer(params.tracer);

  const prompt = typeof payload.prompt === 'string' ? payload.prompt.trim() : '';
  if (!prompt) {
    return {
      kind: 'json',
      status: 400,
      body: { ok: false, success: false, error: 'missing_prompt', message: 'prompt must be a non-empty string (up to 10,000 chars)' },
    };
  }
  if (prompt.length > 10_000) {
    return {
      kind: 'json',
      status: 400,
      body: { ok: false, success: false, error: 'prompt_too_long', message: 'prompt exceeds 10,000 character maximum' },
    };
  }

  const seedUrls: string[] = [];
  if (Array.isArray(payload.urls)) {
    for (const rawU of payload.urls.slice(0, 25)) {
      const check = validatePublicHttpsTargetUrl(rawU, selfHost);
      if (!check.ok) {
        return { kind: 'json', status: 400, body: { ok: false, success: false, error: 'invalid_url', message: check.message } };
      }
      if (!seedUrls.includes(check.normalized)) seedUrls.push(check.normalized);
    }
  }

  const llmResolved = resolveLlmConfig({ env, requestLlm: payload.llm, selfHost });
  if (!llmResolved.ok) {
    return { kind: 'json', status: 400, body: { ok: false, success: false, error: llmResolved.error, message: llmResolved.message } };
  }
  const llmConfig: ResolvedLlmConfig | null = llmResolved.config;
  if (!llmConfig && payload.requireLlm === true) {
    return {
      kind: 'json',
      status: 503,
      body: {
        ok: false,
        success: false,
        error: 'llm_not_configured',
        message:
          'No LLM provider configured. Set EDGEFETCH_LLM_BASE_URL=http://127.0.0.1:11434/v1 (offline Ollama/LM Studio) or OPENAI_API_KEY / ANTHROPIC_API_KEY / GEMINI_API_KEY / Workers AI, or pass llm in the request.',
      },
    };
  }

  let webhook: WebhookConfig | undefined;
  if (payload.webhook) {
    const rawWh = typeof payload.webhook === 'string' ? { url: payload.webhook } : payload.webhook;
    if (rawWh && typeof rawWh === 'object' && !Array.isArray(rawWh)) {
      const w = rawWh as Record<string, unknown>;
      const whCheck = validatePublicHttpsTargetUrl(w.url, selfHost);
      if (!whCheck.ok) {
        return { kind: 'json', status: 400, body: { ok: false, success: false, error: 'invalid_webhook_url', message: whCheck.message } };
      }
      webhook = {
        url: whCheck.normalized,
        ...(typeof w.secret === 'string' && w.secret.trim() ? { secret: w.secret.trim() } : {}),
        ...(w.metadata && typeof w.metadata === 'object' ? { metadata: w.metadata as Record<string, unknown> } : {}),
      };
    }
  }

  const locObj =
    payload.location && typeof payload.location === 'object' && !Array.isArray(payload.location)
      ? (payload.location as Record<string, unknown>)
      : null;
  const planCfg = callCoreWasm<{
    effort: AgentEffort;
    maxSteps: number;
    maxPages: number;
    country: string;
    languages: string[];
    acceptLanguageHeader: string;
  }>('agent_plan_config', {
    effort: typeof payload.effort === 'string' ? payload.effort : 'medium',
    ...(typeof payload.maxSteps === 'number' && Number.isFinite(payload.maxSteps) ? { maxSteps: payload.maxSteps } : {}),
    ...(typeof payload.maxPages === 'number' && Number.isFinite(payload.maxPages) ? { maxPages: payload.maxPages } : {}),
    ...(typeof payload.maxCredits === 'number' && Number.isFinite(payload.maxCredits) ? { maxCredits: payload.maxCredits } : {}),
    country: typeof locObj?.country === 'string' ? locObj.country : '',
    languages: Array.isArray(locObj?.languages) ? locObj!.languages.filter((l): l is string => typeof l === 'string') : [],
  });
  const { effort, maxSteps, maxPages, languages } = planCfg;
  const country = planCfg.country || undefined;
  const acceptLanguageHeader = planCfg.acceptLanguageHeader || undefined;

  const strictConstrainToURLs = Boolean(payload.strictConstrainToURLs);
  const zeroDataRetention = Boolean(payload.zeroDataRetention);
  const safeSearch = Boolean(payload.safe);
  const schema =
    payload.schema && typeof payload.schema === 'object' && !Array.isArray(payload.schema)
      ? (payload.schema as Record<string, unknown>)
      : undefined;

  const requestedThreadId = typeof payload.threadId === 'string' && payload.threadId.trim() ? payload.threadId.trim() : undefined;
  const priorThread =
    requestedThreadId && !zeroDataRetention ? await loadAgentRun(requestedThreadId, env.META, effectiveUserId) : null;

  const now = Date.now();
  const agentId = `agt_${crypto.randomUUID().replace(/-/g, '').slice(0, 24)}`;
  const threadId = priorThread?.threadId ?? (requestedThreadId && priorThread ? requestedThreadId : agentId);

  const activeAuth = getActiveCallerAuthContext();
  const effectivePrincipal = activeAuth?.principal ?? principal;
  const canInvokeFederatedMcp = effectivePrincipal.startsWith('oauth:')
    ? Boolean(activeAuth?.scopes.includes('mcp:call'))
    : true;
  const preferMcpRequested = payload.preferMcp === true;
  const useConnectedMcpRequested = payload.useConnectedMcp === true;
  const allowWriteMcpToolsRequested = payload.allowWriteMcpTools === true;
  const rawAllowedMcpToolsValue = payload.allowedMcpTools;
  const hasAllowedMcpToolsProp =
    rawAllowedMcpToolsValue !== undefined &&
    rawAllowedMcpToolsValue !== null &&
    (!Array.isArray(rawAllowedMcpToolsValue) || rawAllowedMcpToolsValue.length > 0);
  const requestedMcpServerSelectors = Array.isArray(payload.mcpServers)
    ? payload.mcpServers
        .filter((s): s is string => typeof s === 'string' && s.trim().length > 0 && s.trim().length <= 253)
        .map((s) => s.trim())
    : [];
  const wantsConnectedMcps = requestedMcpServerSelectors.length > 0;
  const requestedAnyMcpFeature =
    wantsConnectedMcps ||
    preferMcpRequested ||
    useConnectedMcpRequested ||
    allowWriteMcpToolsRequested ||
    hasAllowedMcpToolsProp;

  if (requestedAnyMcpFeature && !canInvokeFederatedMcp) {
    return {
      kind: 'json',
      status: 403,
      body: {
        ok: false,
        success: false,
        error: 'insufficient_scope',
        message: 'Scope mcp:call is required to use connected MCP servers in /v1/agent.',
      },
    };
  }

  const parsedAllowedMcpTools = parseAllowedMcpTools(rawAllowedMcpToolsValue);
  if (!parsedAllowedMcpTools.ok) {
    return {
      kind: 'json',
      status: 400,
      body: { ok: false, success: false, error: parsedAllowedMcpTools.error, message: parsedAllowedMcpTools.message },
    };
  }

  const userQuotaKey = effectiveUserId.trim() || 'owner';
  const currentActiveRuns = activeAgentRunsByUser.get(userQuotaKey) ?? 0;
  if (currentActiveRuns >= MAX_CONCURRENT_AGENTS_PER_USER) {
    return {
      kind: 'json',
      status: 429,
      body: {
        ok: false,
        success: false,
        error: 'user_quota_exceeded',
        message: `Per-user concurrent agent limit (${MAX_CONCURRENT_AGENTS_PER_USER}) exceeded. Please wait for an active run to finish.`,
      },
    };
  }
  activeAgentRunsByUser.set(userQuotaKey, currentActiveRuns + 1);
  let agentQuotaReleased = false;
  const releaseAgentQuotaSlot = () => {
    if (agentQuotaReleased) return;
    agentQuotaReleased = true;
    const cur = activeAgentRunsByUser.get(userQuotaKey) ?? 0;
    if (cur <= 1) activeAgentRunsByUser.delete(userQuotaKey);
    else activeAgentRunsByUser.set(userQuotaKey, cur - 1);
  };

  try {
    const allowedMcpToolSet = parsedAllowedMcpTools.allowed;
    const isCachedToolPermittedForAgentRun = (srvSlug: string, tool: CachedMcpToolSchema): boolean =>
      canInvokeFederatedMcp && isCachedMcpToolPermitted(srvSlug, tool, allowedMcpToolSet);

    const routerStart = Date.now();
    const userConnectedMcps =
      vaultStore && wantsConnectedMcps && canInvokeFederatedMcp
        ? (await listRunnableMcpServers(vaultStore))
            .filter(
              (s) =>
                s.enabled &&
                isValidMcpConnectorSlug(s.slug) &&
                requestedMcpServerSelectors.some((sel) => doesMcpServerSelectorMatchRow(sel, s)),
            )
            .map((s) => {
              const safeTools = filterSafeCachedMcpTools(s.cachedTools).filter((t) =>
                isCachedToolPermittedForAgentRun(s.slug, t),
              );
              return { ...s, cachedTools: safeTools, toolCount: safeTools.length };
            })
        : [];
    const allowedConnectorIds = new Set(userConnectedMcps.map((s) => s.id));
    const allowedConnectorsById = new Map(userConnectedMcps.map((s) => [s.id, s]));
    const matchedMcps = matchConnectedMcpsForContext({ servers: userConnectedMcps, query: prompt, urls: seedUrls });
    const { matches: initialMatches, totalIndexedAdapters } = findRelevantAdaptersWithCount({
      query: prompt,
      urls: seedUrls,
      limit: 8,
    });
    const routedSet = new Set<string>([
      ...matchedMcps.map((m) => `mcp:${m.server.slug}`),
      ...initialMatches.map((m) => m.id),
    ]);
    const routedMcps = matchedMcps.map((m) => m.server.slug);
    if (agentTracer) {
      const initRouterSpan = agentTracer.startSpan('edgefetch.agent.router', {
        kind: 1,
        startTimeMs: routerStart,
        attributes: {
          'agent.id': agentId,
          'agent.router.name': 'dynamic_adapter_router',
          'agent.router.match_count': initialMatches.length + matchedMcps.length,
          'agent.router.matches': [...routedSet].join(','),
          'agent.seed_url_count': seedUrls.length,
        },
      });
      initRouterSpan.setStatus(true);
      initRouterSpan.end();
    }

    const isInitialPrivate =
      isPrivateRequestPayload(payload, effectiveUserId) ||
      Boolean(
        priorThread &&
          (priorThread.visibility === 'private' ||
            (priorThread.routedMcps && priorThread.routedMcps.length > 0) ||
            /untrusted_mcp/i.test(priorThread.threadMemory ?? '')),
      );
    const record: AgentRunRecord = {
      id: agentId,
      userId: effectiveUserId,
      threadId,
      status: 'processing',
      prompt,
      urls: seedUrls,
      strictConstrainToURLs,
      effort,
      maxSteps,
      maxPages,
      stepsUsed: 0,
      pagesRead: 0,
      zeroDataRetention,
      ...(isInitialPrivate ? { visibility: 'private' as const } : {}),
      ...(routedMcps.length > 0 ? { routedMcps } : {}),
      llmUsed: Boolean(llmConfig),
      ...(llmConfig ? { llmInfo: redactLlmConfigForLog(llmConfig) } : {}),
      routedAdapters: [...routedSet],
      sources: [...(priorThread?.sources ?? [])],
      createdAt: now,
      updatedAt: now,
      expiresAt: now + AGENT_RUN_TTL_MS,
      trace: [
        {
          sequence: 1,
          spanId: 'sp_router_init',
          kind: 'router',
          name: 'dynamic_adapter_router',
          status: 'ok',
          startedAt: routerStart,
          durationMs: Math.max(0, Date.now() - routerStart),
          input: { query: prompt.slice(0, 240), seedUrlCount: seedUrls.length, totalIndexedAdapters },
          outputPreview: initialMatches.map((m) => ({ id: m.id, category: m.category, score: m.score })),
        },
      ],
    };

    await persistAgentRun(record, env.META);

    const runLoop = async (emitEvent?: (event: string, data: Record<string, unknown>) => void): Promise<AgentRunRecord> => {
      const getLoopTracer = () => getActiveRequestTracer() ?? agentTracer;
      let seq = record.trace.length;
      const pushSpan = (span: Omit<AgentTraceSpan, 'sequence' | 'spanId'>): AgentTraceSpan => {
        seq++;
        const full: AgentTraceSpan = { sequence: seq, spanId: `sp_${seq}`, ...span };
        record.trace.push(full);
        record.updatedAt = Date.now();
        emitEvent?.('agent.trace', full as unknown as Record<string, unknown>);
        return full;
      };

      emitEvent?.('agent.started', {
        id: record.id,
        threadId: record.threadId,
        effort: record.effort,
        maxSteps: record.maxSteps,
        maxPages: record.maxPages,
        routedAdapters: record.routedAdapters,
        llmUsed: record.llmUsed,
      });

      if (webhook) {
        const whTracer = getLoopTracer();
        await deliverSignedWebhook({
          webhook,
          defaultSecret: env.WEBHOOK_SECRET,
          event: 'agent.started',
          crawlId: record.id,
          data: { agentId: record.id, status: 'processing', prompt: prompt.slice(0, 200) },
          selfHost,
          ...(env.SAFE_PUBLIC_FETCH ? { fetchFn: env.SAFE_PUBLIC_FETCH } : env.SAFE_FETCH ? { fetchFn: env.SAFE_FETCH } : {}),
          ...(whTracer ? { tracer: whTracer } : {}),
        }).catch(() => undefined);
      }

      const priorThreadTouchedMcp = Boolean(
        priorThread &&
          (priorThread.visibility === 'private' ||
            (priorThread.routedMcps && priorThread.routedMcps.length > 0) ||
            /untrusted_mcp/i.test(priorThread.threadMemory ?? '')),
      );
      let touchedConnectedMcp = priorThreadTouchedMcp;
      if (priorThreadTouchedMcp) {
        record.visibility = 'private';
        record.userId = effectiveUserId;
      }
      const replayedPriorThreadEnvelope = priorThread?.threadMemory
        ? wrapConnectorTextForAgentContext(priorThread.threadMemory, 4_500, { source: 'prior_thread', threadId: priorThread.id })
        : undefined;

      const gatheredEvidence: Array<{
        url: string;
        title?: string;
        markdown: string;
        json?: Record<string, unknown>;
        fromMcp?: boolean;
        mcpServer?: string;
        mcpTool?: string;
      }> = [];
      if (priorThread?.threadMemory) {
        gatheredEvidence.push({
          url: 'thread://prior-context',
          title: 'Prior Thread Findings',
          markdown: priorThread.threadMemory,
          fromMcp: true,
        });
      }

      const addSource = (url: string, title?: string, via?: string, extractorId?: string) => {
        if (!url || url.startsWith('thread://')) return;
        if (!record.sources.some((s) => s.url === url)) {
          record.sources.push({ url, ...(title ? { title } : {}), ...(via ? { via } : {}), ...(extractorId ? { extractorId } : {}) });
        }
        if (extractorId) {
          routedSet.add(extractorId);
          record.routedAdapters = [...routedSet];
        }
      };

      const isCancelled = () => cancelledAgentIds.has(record.id) || record.status === 'cancelled';

      const executeSingleTool = async (
        toolName: string,
        args: Record<string, unknown>,
      ): Promise<{ ok: boolean; summaryForLlm: string; budgetExhausted?: boolean }> => {
        const t0 = Date.now();
        const toolTracer = getLoopTracer();
        if (toolName === 'find_extractors') {
          const q = typeof args.query === 'string' ? args.query : prompt;
          const cat = typeof args.category === 'string' ? args.category : undefined;
          const runRouter = (span?: ActiveSpanHandle) => {
            const matches = findRelevantAdapters({ query: q, category: cat, limit: 10 });
            for (const m of matches) routedSet.add(m.id);
            record.routedAdapters = [...routedSet];
            span?.setAttribute('agent.router.match_count', matches.length);
            span?.setAttribute('agent.router.matches', matches.map((m) => m.id).join(','));
            pushSpan({
              kind: 'router',
              name: 'find_extractors',
              status: 'ok',
              startedAt: t0,
              durationMs: Date.now() - t0,
              input: { query: q, ...(cat ? { category: cat } : {}) },
              outputPreview: matches.map((m) => m.id),
            });
            return { ok: true, summaryForLlm: JSON.stringify({ matches }, null, 2) };
          };
          return toolTracer
            ? toolTracer.withSpan(
                'edgefetch.agent.router',
                { kind: 1, attributes: { 'agent.id': record.id, 'agent.router.name': 'find_extractors', ...(cat ? { 'agent.router.category': cat } : {}) } },
                (span) => runRouter(span),
              )
            : runRouter();
        }

        const withToolSpan = <T>(fn: (toolSpan?: ActiveSpanHandle) => Promise<T>): Promise<T> =>
          toolTracer
            ? toolTracer.withSpan('edgefetch.agent.tool_call', { kind: 1, attributes: { 'agent.id': record.id, 'agent.tool.name': toolName } }, (span) => fn(span))
            : fn();

        if (toolName === 'web_search') {
          if (strictConstrainToURLs) {
            return { ok: false, summaryForLlm: JSON.stringify({ error: 'strictConstrainToURLs is active; web_search is disabled.' }) };
          }
          return withToolSpan(async (toolSpan) => {
            const qBase = typeof args.query === 'string' && args.query.trim() ? args.query.trim() : prompt;
            const qEffective = safeSearch ? `${qBase} -nsfw -adult` : qBase;
            const isPrivateRun = zeroDataRetention || record.visibility === 'private';
            const sPayload: SearchRequestPayload = {
              query: qEffective,
              max_results: typeof args.maxResults === 'number' ? Math.min(10, Math.max(1, Math.floor(args.maxResults))) : 6,
              ...(isPrivateRun ? { visibility: 'private' } : {}),
              ...(country ? { country } : {}),
              ...(languages[0] ? { language: languages[0] } : {}),
            } as SearchRequestPayload;
            const sTracer = getLoopTracer();
            const sOut = await executeSearchCall({
              payload: sPayload,
              env,
              executeHubFetch,
              source: `agent:${principal}:search`,
              userId,
              ...(sTracer ? { tracer: sTracer } : {}),
            });
            const results = Array.isArray(sOut.body.results) ? (sOut.body.results as Array<Record<string, unknown>>) : [];
            const discoveredUrls = results.map((r) => (typeof r.url === 'string' ? r.url : '')).filter(Boolean);
            for (const dyn of findRelevantAdapters({ query: qBase, urls: discoveredUrls, limit: 5 })) routedSet.add(dyn.id);
            record.routedAdapters = [...routedSet];
            toolSpan?.setAttribute('search.result_count', results.length);
            toolSpan?.setAttribute('http.response.status_code', sOut.status);
            if (sOut.status !== 200) toolSpan?.setStatus(false, `search_http_${sOut.status}`);
            pushSpan({
              kind: 'tool_call',
              name: 'web_search',
              status: sOut.status === 200 ? 'ok' : 'error',
              startedAt: t0,
              durationMs: Date.now() - t0,
              input: { query: qEffective },
              outputPreview: { resultCount: results.length, topUrls: discoveredUrls.slice(0, 5) },
            });
            return {
              ok: sOut.status === 200,
              summaryForLlm: JSON.stringify(
                results.slice(0, 8).map((r) => ({
                  title: r.title,
                  url: r.url,
                  snippet: typeof r.content === 'string' ? r.content.slice(0, 360) : r.snippet,
                })),
                null,
                2,
              ),
            };
          });
        }

        if (toolName === 'search_jobs') {
          if (strictConstrainToURLs) {
            return { ok: false, summaryForLlm: JSON.stringify({ error: 'strictConstrainToURLs is active; search_jobs is disabled.' }) };
          }
          if (record.pagesRead >= record.maxPages) {
            return { ok: false, budgetExhausted: true, summaryForLlm: JSON.stringify({ error: 'maxPages budget reached' }) };
          }
          record.pagesRead++;
          return withToolSpan(async (toolSpan) => {
            const jTracer = getLoopTracer();
            const jOut = await executeJobsCall({
              payload: args as JobsToolPayload,
              env: env as unknown as OptionalStorageBindings & Record<string, unknown>,
              ...(jTracer ? { tracer: jTracer } : {}),
              executeSearch: async (sArgs) => {
                const sRes = await executeSearchCall({
                  payload: {
                    ...(sArgs as SearchRequestPayload),
                    ...(zeroDataRetention || record.visibility === 'private' ? { visibility: 'private' as const } : {}),
                  },
                  env,
                  executeHubFetch,
                  source: `agent:${principal}:jobs-search`,
                  userId,
                  ...(getLoopTracer() ? { tracer: getLoopTracer()! } : {}),
                });
                return { status: sRes.status, body: sRes.body };
              },
              executeScrape: async (scArgs) => {
                const scRes = await executeScrapeCall({
                  payload: {
                    ...(scArgs as ScrapeRequestPayload),
                    ...(zeroDataRetention ? { ephemeral: true } : {}),
                    ...(record.visibility === 'private' ? { visibility: 'private' as const } : {}),
                  },
                  env: zeroDataRetention ? {} : env,
                  executeHubFetch,
                  selfHost,
                  userId,
                  source: `agent:${principal}:jobs-scrape`,
                  ...(getLoopTracer() ? { tracer: getLoopTracer()! } : {}),
                });
                return { status: scRes.status, body: scRes.body };
              },
            });
            const jobsList = Array.isArray(jOut.body.jobs) ? (jOut.body.jobs as Array<Record<string, unknown>>) : [];
            const atsSources = new Set<string>();
            for (const j of jobsList.slice(0, 15)) {
              if (typeof j.source === 'string' && j.source) atsSources.add(j.source);
              if (typeof j.url === 'string') {
                addSource(j.url, typeof j.title === 'string' ? j.title : undefined, 'jobs', typeof j.source === 'string' ? j.source : undefined);
              }
            }
            toolSpan?.setAttribute('edgefetch.jobs.jobs_returned', jobsList.length);
            toolSpan?.setAttribute('http.response.status_code', jOut.status);
            if (atsSources.size > 0) {
              const joined = [...atsSources].join(',');
              toolSpan?.setAttribute('edgefetch.adapter_id', joined);
              agentTracer?.setAttribute('edgefetch.adapter_id', joined);
            }
            if (jOut.status !== 200) toolSpan?.setStatus(false, `jobs_http_${jOut.status}`);
            const mdSummary = JSON.stringify({ count: jobsList.length, jobs: jobsList.slice(0, 15) }, null, 2);
            gatheredEvidence.push({ url: 'edgefetch://jobs', title: 'Structured ATS Jobs', markdown: mdSummary });
            pushSpan({
              kind: 'tool_call',
              name: 'search_jobs',
              status: jOut.status === 200 ? 'ok' : 'error',
              startedAt: t0,
              durationMs: Date.now() - t0,
              input: args,
              outputPreview: { count: jobsList.length },
            });
            return { ok: jOut.status === 200, summaryForLlm: mdSummary.slice(0, 8_000) };
          });
        }

        if (toolName === 'map_site') {
          const targetUrl = typeof args.url === 'string' ? args.url.trim() : '';
          if (!isUrlAllowedByConstraint(targetUrl, seedUrls, strictConstrainToURLs)) {
            return { ok: false, summaryForLlm: JSON.stringify({ error: 'url_outside_strict_constraint', allowedUrls: seedUrls }) };
          }
          return withToolSpan(async (toolSpan) => {
            const mTracer = getLoopTracer();
            const mOut = await executeMapCall({
              payload: {
                url: targetUrl,
                search: args.search,
                limit: typeof args.limit === 'number' ? Math.min(60, Math.max(1, Math.floor(args.limit))) : 30,
              },
              executeHubFetch,
              selfHost,
              source: `agent:${principal}:map`,
              ...(mTracer ? { tracer: mTracer } : {}),
            });
            const rawLinks = Array.isArray(mOut.body.links) ? (mOut.body.links as string[]) : [];
            const links = rawLinks.filter((l) => isUrlAllowedByConstraint(l, seedUrls, strictConstrainToURLs));
            toolSpan?.setAttribute('url.full', sanitizeUrlForSpan(targetUrl));
            toolSpan?.setAttribute('map.link_count', links.length);
            toolSpan?.setAttribute('http.response.status_code', mOut.status);
            if (mOut.status !== 200) toolSpan?.setStatus(false, `map_http_${mOut.status}`);
            pushSpan({
              kind: 'tool_call',
              name: 'map_site',
              status: mOut.status === 200 ? 'ok' : 'error',
              startedAt: t0,
              durationMs: Date.now() - t0,
              input: { url: targetUrl, search: args.search },
              outputPreview: { total: links.length, sample: links.slice(0, 8) },
            });
            return { ok: mOut.status === 200, summaryForLlm: JSON.stringify({ url: targetUrl, links: links.slice(0, 40) }, null, 2) };
          });
        }

        if (toolName === 'interact_browser') {
          const targetUrl = typeof args.url === 'string' ? args.url.trim() : '';
          if (!isUrlAllowedByConstraint(targetUrl, seedUrls, strictConstrainToURLs)) {
            return { ok: false, summaryForLlm: JSON.stringify({ error: 'url_outside_strict_constraint', allowedUrls: seedUrls }) };
          }
          if (record.pagesRead >= record.maxPages) {
            return { ok: false, budgetExhausted: true, summaryForLlm: JSON.stringify({ error: 'maxPages budget reached' }) };
          }
          const filteredActions = Array.isArray(args.actions)
            ? callCoreWasm<{ actions: Array<Record<string, unknown>> }>('agent_filter_browser_actions', { actions: args.actions }).actions
            : [];
          record.pagesRead++;
          return withToolSpan(async (toolSpan) => {
            const iTracer = getLoopTracer();
            const iOut = await executeInteractCall({
              payload: {
                url: targetUrl,
                actions: filteredActions,
                formats: ['markdown'],
                ...(zeroDataRetention || record.visibility === 'private' ? { visibility: 'private' as const } : {}),
              },
              env: zeroDataRetention ? {} : env,
              executeHubFetch,
              selfHost,
              principal,
              userId,
              ...(sessionSigningSecret ? { sessionSigningSecret } : {}),
              source: `agent:${principal}:interact`,
              ...(iTracer ? { tracer: iTracer } : {}),
            });
            const md = typeof iOut.body.markdown === 'string' ? iOut.body.markdown : '';
            const title = (iOut.body.metadata as { title?: string } | undefined)?.title;
            toolSpan?.setAttribute('url.full', sanitizeUrlForSpan(targetUrl));
            toolSpan?.setAttribute('http.response.status_code', iOut.status);
            if (iOut.status !== 200) toolSpan?.setStatus(false, `interact_http_${iOut.status}`);
            if (iOut.status === 200 && md) {
              addSource(targetUrl, title, iOut.via);
              gatheredEvidence.push({ url: targetUrl, ...(title ? { title } : {}), markdown: md.slice(0, 12_000) });
            }
            pushSpan({
              kind: 'tool_call',
              name: 'interact_browser',
              status: iOut.status === 200 ? 'ok' : 'error',
              startedAt: t0,
              durationMs: Date.now() - t0,
              input: { url: targetUrl },
              outputPreview: { status: iOut.status, chars: md.length },
            });
            return { ok: iOut.status === 200, summaryForLlm: iOut.status === 200 ? md.slice(0, 6_000) : JSON.stringify(iOut.body) };
          });
        }

        if (toolName === 'search_collection' && env.SEARCH) {
          const rawCollId = typeof args.collectionId === 'string' && args.collectionId.trim() ? args.collectionId.trim() : 'default';
          const isPrivateSearchColl =
            zeroDataRetention ||
            record.visibility === 'private' ||
            args.visibility === 'private' ||
            isPrivateRequestPayload(payload, userId);
          const resolvedColl = resolveUserCollectionId(rawCollId, userId, isPrivateSearchColl ? 'private' : 'public');
          if (!resolvedColl.ok) return { ok: false, summaryForLlm: JSON.stringify({ error: resolvedColl.error }) };
          const collId = resolvedColl.scopedId;
          const q = typeof args.query === 'string' ? args.query : prompt;
          return withToolSpan(async (toolSpan) => {
            const idx = new D1FtsSearchIndex(env.SEARCH!);
            const scTracer = getLoopTracer();
            const hits = await idx.searchCollection({ collectionId: collId, query: q, limit: 8, ...(scTracer ? { tracer: scTracer } : {}) });
            toolSpan?.setAttribute('search.collection_id', collId);
            toolSpan?.setAttribute('search.hit_count', hits.length);
            pushSpan({
              kind: 'tool_call',
              name: 'search_collection',
              status: 'ok',
              startedAt: t0,
              durationMs: Date.now() - t0,
              input: { collectionId: resolvedColl.displayId, query: q },
              outputPreview: { hitCount: hits.length },
            });
            return { ok: true, summaryForLlm: JSON.stringify(hits, null, 2).slice(0, 6_000) };
          });
        }

        if (toolName.startsWith('mcp__') && vaultStore) {
          const parts = toolName.slice(5).split('__');
          if (parts.length === 2 && isValidMcpConnectorSlug(parts[0]!) && isSafeMcpIdentifier(parts[1]!)) {
            return await executeSingleTool('query_mcp', { action: 'call_tool', server: parts[0]!, tool: parts[1]!, arguments: args });
          }
          return {
            ok: false,
            summaryForLlm: JSON.stringify({ error: 'invalid_tool_identifier', message: 'Invalid or ambiguous composite MCP tool identifier.' }),
          };
        }

        if (toolName === 'query_mcp' && vaultStore) {
          if (!wantsConnectedMcps || userConnectedMcps.length === 0) {
            return {
              ok: false,
              summaryForLlm: JSON.stringify({
                error: 'mcp_not_enabled_for_run',
                message: 'Connected MCP servers were not explicitly enabled via mcpServers for this agent run.',
              }),
            };
          }
          return withToolSpan(async (toolSpan) => {
            const actionRaw = typeof args.action === 'string' ? args.action : 'call_tool';
            if ((actionRaw === 'call_tool' || actionRaw === 'list_tools') && !canInvokeFederatedMcp) {
              return {
                ok: false,
                summaryForLlm: JSON.stringify({
                  error: 'insufficient_scope',
                  message: 'OAuth scope mcp:call is required to query or invoke connected MCP tools.',
                }),
              };
            }
            if (actionRaw === 'list_connected') {
              touchedConnectedMcp = true;
              record.visibility = 'private';
              record.userId = effectiveUserId;
              const summaries = userConnectedMcps.map((s) => toPublicMcpServerSummary(s));
              return {
                ok: true,
                summaryForLlm: formatFenceSafeUntrustedMcpEnvelope({
                  tag: 'untrusted_mcp_tool_output',
                  attributes: { action: 'list_connected' },
                  content: JSON.stringify({ servers: summaries }, null, 2),
                  maxChars: 6_000,
                }),
              };
            }

            const requestedServerArg = typeof args.server === 'string' ? args.server.trim() : '';
            if (!requestedServerArg) {
              return { ok: false, summaryForLlm: JSON.stringify({ error: 'missing_server', message: 'server is required for query_mcp.' }) };
            }
            const matchedAllowedServer = userConnectedMcps.find((s) => doesMcpServerSelectorMatchRow(requestedServerArg, s));
            if (!matchedAllowedServer || !allowedConnectorIds.has(matchedAllowedServer.id)) {
              return {
                ok: false,
                summaryForLlm: JSON.stringify({
                  error: 'mcp_server_not_allowed',
                  message: 'Resolved MCP connector is not in the allowed mcpServers set for this agent run.',
                }),
              };
            }
            const resolvedVaultRow = await vaultStore.getServer(matchedAllowedServer.userId, matchedAllowedServer.slug);
            if (
              !resolvedVaultRow ||
              !resolvedVaultRow.enabled ||
              resolvedVaultRow.id !== matchedAllowedServer.id ||
              !doesMcpServerSelectorMatchRow(requestedServerArg, resolvedVaultRow) ||
              !allowedConnectorIds.has(resolvedVaultRow.id)
            ) {
              return {
                ok: false,
                summaryForLlm: JSON.stringify({
                  error: 'mcp_server_not_allowed',
                  message: 'Resolved MCP connector is not in the allowed mcpServers set for this agent run.',
                }),
              };
            }
            const canonicalAllowedServer = allowedConnectorsById.get(resolvedVaultRow.id)!;

            if (actionRaw === 'list_tools') {
              touchedConnectedMcp = true;
              record.visibility = 'private';
              record.userId = effectiveUserId;
              return {
                ok: true,
                summaryForLlm: formatFenceSafeUntrustedMcpEnvelope({
                  tag: 'untrusted_mcp_tool_output',
                  attributes: { server: canonicalAllowedServer.slug, action: 'list_tools' },
                  content: JSON.stringify({ server: canonicalAllowedServer.slug, tools: canonicalAllowedServer.cachedTools }, null, 2),
                  maxChars: 6_000,
                }),
              };
            }

            const candidateToolName = typeof args.tool === 'string' ? args.tool.trim() : '';
            if (!candidateToolName || !isSafeMcpIdentifier(candidateToolName)) {
              return {
                ok: false,
                summaryForLlm: JSON.stringify({ error: 'invalid_tool_identifier', message: 'Invalid or disallowed MCP tool identifier.' }),
              };
            }
            const permittedCachedTool = canonicalAllowedServer.cachedTools.find((t) => t.name === candidateToolName);
            if (!permittedCachedTool) {
              return {
                ok: false,
                summaryForLlm: JSON.stringify({
                  error: 'mcp_tool_not_permitted',
                  message: 'Requested MCP tool is either uncached or not readOnlyHint=true (and not explicitly allow-listed for this run).',
                }),
              };
            }

            const qInput: QueryMcpCallInput = {
              action: 'call_tool',
              server: federatedServerRef(canonicalAllowedServer),
              tool: permittedCachedTool.name,
              ...(args.arguments && typeof args.arguments === 'object' && !Array.isArray(args.arguments)
                ? { arguments: args.arguments as Record<string, unknown> }
                : {}),
            };
            const mOut = await executeFederatedMcpQuery({
              userId: effectiveUserId,
              input: qInput,
              allowedMcpTools: allowedMcpToolSet,
              vaultStore,
              ...federationPolicyOpts,
              vaultMasterKey: env.VAULT_MASTER_KEY,
              fetchFn: env.SAFE_PUBLIC_FETCH ?? env.SAFE_FETCH ?? fetch,
              selfHost,
            });
            touchedConnectedMcp = true;
            record.visibility = 'private';
            record.userId = effectiveUserId;

            const srvSlug = canonicalAllowedServer.slug.replace(/[^a-z0-9_-]/gi, '').slice(0, 48) || 'mcp';
            const toolCalled = permittedCachedTool.name;
            const extractedMd = extractMarkdownFromQueryMcpBody(mOut.body);
            const sanitizedMcpMd =
              mOut.body.sanitized === true && extractedMd
                ? extractedMd
                : sanitizeMcpMarkdownOutput(sanitizeRemoteMcpText(extractedMd || JSON.stringify(mOut.body, null, 2)).text);

            toolSpan?.setAttribute('mcp.server', srvSlug);
            if (toolCalled) toolSpan?.setAttribute('mcp.tool', toolCalled);
            toolSpan?.setAttribute('http.response.status_code', mOut.status);

            if (mOut.status === 200 && qInput.action === 'call_tool') {
              const originUrl =
                typeof mOut.body.remoteOrigin === 'string' && mOut.body.remoteOrigin ? mOut.body.remoteOrigin : `https://${srvSlug}.mcp.local`;
              addSource(originUrl, `${srvSlug}${toolCalled ? ` (${toolCalled})` : ''}`, `mcp:${srvSlug}`, `mcp:${srvSlug}`);
              gatheredEvidence.push({
                url: originUrl,
                title: `${srvSlug}${toolCalled ? ` — ${toolCalled}` : ''}`,
                markdown: sanitizedMcpMd.slice(0, 12_000),
                fromMcp: true,
                mcpServer: srvSlug,
                mcpTool: toolCalled,
                ...(mOut.body.structuredContent && typeof mOut.body.structuredContent === 'object' && !Array.isArray(mOut.body.structuredContent)
                  ? { json: mOut.body.structuredContent as Record<string, unknown> }
                  : {}),
              });
            }

            pushSpan({
              kind: 'tool_call',
              name: 'query_mcp',
              status: mOut.status === 200 ? 'ok' : 'error',
              startedAt: t0,
              durationMs: Date.now() - t0,
              input: { action: qInput.action, server: qInput.server, tool: qInput.tool },
              outputPreview: { status: mOut.status, server: srvSlug, tool: toolCalled, chars: sanitizedMcpMd.length },
            });

            return {
              ok: mOut.status === 200,
              summaryForLlm: formatFenceSafeUntrustedMcpEnvelope({
                tag: 'untrusted_mcp_tool_output',
                attributes: { server: srvSlug, ...(isSafeMcpIdentifier(toolCalled) ? { tool: toolCalled } : {}) },
                content: sanitizedMcpMd,
                maxChars: 7_600,
              }),
            };
          });
        }

        // Default: `scrape_url`
        const targetUrl = typeof args.url === 'string' ? args.url.trim() : '';
        if (!isUrlAllowedByConstraint(targetUrl, seedUrls, strictConstrainToURLs)) {
          return { ok: false, summaryForLlm: JSON.stringify({ error: 'url_outside_strict_constraint', allowedUrls: seedUrls }) };
        }
        if (record.pagesRead >= record.maxPages) {
          return { ok: false, budgetExhausted: true, summaryForLlm: JSON.stringify({ error: 'maxPages budget reached' }) };
        }
        record.pagesRead++;

        return withToolSpan(async (toolSpan) => {
          if (vaultStore && allowedConnectorIds.size > 0 && canInvokeFederatedMcp) {
            const mcpDirect = await tryScrapeViaConnectedMcp({
              userId: effectiveUserId,
              targetUrl,
              ...(typeof args.query === 'string' && args.query.trim() ? { query: args.query.trim() } : {}),
              preferMcp: preferMcpRequested,
              allowedServerIds: allowedConnectorIds,
              allowedMcpTools: allowedMcpToolSet,
              requireExplicitReadOnlyHint: true,
              vaultStore,
              ...federationPolicyOpts,
              vaultMasterKey: env.VAULT_MASTER_KEY,
              fetchFn: env.SAFE_PUBLIC_FETCH ?? env.SAFE_FETCH ?? fetch,
              selfHost,
            });
            if (mcpDirect) {
              touchedConnectedMcp = true;
              record.visibility = 'private';
              record.userId = effectiveUserId;
              const mcpMd = typeof mcpDirect.body.markdown === 'string' ? mcpDirect.body.markdown : '';
              const mcpTitle = (mcpDirect.body.metadata as { title?: string } | undefined)?.title;
              const mcpExt = typeof mcpDirect.body.extractorId === 'string' ? mcpDirect.body.extractorId : mcpDirect.via;
              const viaSlug = mcpDirect.via.startsWith('mcp:') ? mcpDirect.via.slice(4) : undefined;
              addSource(targetUrl, mcpTitle, mcpDirect.via, mcpExt);
              gatheredEvidence.push({
                url: targetUrl,
                ...(mcpTitle ? { title: mcpTitle } : {}),
                markdown: mcpMd,
                fromMcp: true,
                ...(viaSlug && isValidMcpConnectorSlug(viaSlug) ? { mcpServer: viaSlug } : {}),
              });
              pushSpan({
                kind: 'tool_call',
                name: 'scrape_url',
                status: 'ok',
                startedAt: t0,
                durationMs: Date.now() - t0,
                input: { url: targetUrl, via: mcpDirect.via },
                outputPreview: { status: 200, via: mcpDirect.via, chars: mcpMd.length },
              });
              return {
                ok: true,
                summaryForLlm: formatFenceSafeUntrustedMcpEnvelope({
                  tag: 'untrusted_mcp_tool_output',
                  attributes: { url: targetUrl, via: mcpDirect.via },
                  content: mcpMd,
                  maxChars: 6_500,
                }),
              };
            }
          }

          const scTracer = getLoopTracer();
          const isPrivateRun = zeroDataRetention || record.visibility === 'private';
          const scOut = await executeScrapeCall({
            payload: {
              url: targetUrl,
              formats: schema ? ['markdown', { type: 'json', schema }] : ['markdown'],
              ...(typeof args.query === 'string' && args.query.trim() ? { query: args.query.trim() } : {}),
              ...(typeof args.renderMode === 'string' ? { renderMode: args.renderMode } : {}),
              ...(acceptLanguageHeader ? { headers: { 'Accept-Language': acceptLanguageHeader } } : {}),
              ...(isPrivateRun ? { ephemeral: true } : {}),
              maxChars: 14_000,
            },
            env: isPrivateRun ? {} : env,
            executeHubFetch,
            selfHost,
            userId,
            source: `agent:${principal}:scrape`,
            ...(scTracer ? { tracer: scTracer } : {}),
          });
          const md = typeof scOut.body.markdown === 'string' ? scOut.body.markdown : '';
          const meta = (scOut.body.metadata as Record<string, unknown> | undefined) ?? {};
          const title = typeof meta.title === 'string' ? meta.title : undefined;
          const extractorId = typeof scOut.body.extractorId === 'string' ? scOut.body.extractorId : undefined;
          const pageJson =
            scOut.body.json && typeof scOut.body.json === 'object' && !Array.isArray(scOut.body.json)
              ? (scOut.body.json as Record<string, unknown>)
              : undefined;

          toolSpan?.setAttribute('url.full', sanitizeUrlForSpan(targetUrl));
          toolSpan?.setAttribute('http.response.status_code', scOut.status);
          if (extractorId) {
            toolSpan?.setAttribute('edgefetch.adapter_id', extractorId);
            agentTracer?.setAttribute('edgefetch.adapter_id', extractorId);
          }
          if (scOut.status !== 200) toolSpan?.setStatus(false, `scrape_http_${scOut.status}`);

          if (scOut.status === 200 && md) {
            addSource(targetUrl, title, scOut.via, extractorId);
            gatheredEvidence.push({
              url: targetUrl,
              ...(title ? { title } : {}),
              markdown: md,
              ...(pageJson ? { json: pageJson } : {}),
            });
          }
          pushSpan({
            kind: 'tool_call',
            name: 'scrape_url',
            status: scOut.status === 200 ? 'ok' : 'error',
            startedAt: t0,
            durationMs: Date.now() - t0,
            input: { url: targetUrl, ...(extractorId ? { extractorId } : {}) },
            outputPreview: { status: scOut.status, title, chars: md.length, ...(scOut.body.problem ? { problem: scOut.body.problem } : {}) },
          });
          return {
            ok: scOut.status === 200,
            summaryForLlm:
              scOut.status === 200
                ? `URL: ${targetUrl}${title ? `\nTitle: ${title}` : ''}${extractorId ? `\nAdapter: ${extractorId}` : ''}\n\n${md.slice(0, 6_500)}`
                : JSON.stringify({ ok: false, status: scOut.status, problem: scOut.body.problem, blocked: scOut.body.blocked }),
          };
        });
      };

      try {
        let hitBudget = false;
        if (llmConfig) {
          const { tools } = callCoreWasm<{ tools: LlmToolDefinition[] }>('agent_build_tools', {
            strictConstrainToURLs,
            hasSearchCollection: Boolean(env.SEARCH),
            connectedMcps: userConnectedMcps.map((s) => ({
              id: s.id,
              slug: s.slug,
              cachedTools: s.cachedTools.map((t) => ({ name: t.name, inputSchema: t.inputSchema })),
            })),
          });
          const { messages } = callCoreWasm<{ messages: LlmMessage[] }>('agent_build_messages', {
            prompt,
            seedUrls,
            strictConstrainToURLs,
            maxSteps: record.maxSteps,
            maxPages: record.maxPages,
            hasConnectedMcps: userConnectedMcps.length > 0,
            initialMatches,
            ...(schema ? { schema } : {}),
            ...(replayedPriorThreadEnvelope && priorThread
              ? { priorThreadId: priorThread.id, replayedPriorThreadEnvelope }
              : {}),
          });

          let finalAssistantText = '';
          for (let step = 0; step < record.maxSteps; step++) {
            if (isCancelled()) {
              record.status = 'cancelled';
              record.stopReason = 'cancelled';
              break;
            }
            record.stepsUsed = step + 1;
            const turnStart = Date.now();
            const turnTracer = getLoopTracer();
            const llmRes = await completeLlmTurn({
              config: llmConfig,
              messages,
              tools,
              temperature: 0.1,
              maxTokens: 2_048,
              ...(llmFetchFn ? { fetchFn: llmFetchFn } : {}),
              ...(turnTracer ? { tracer: turnTracer } : {}),
              traceAttributes: { 'agent.id': record.id, 'agent.step': step + 1, 'agent.tool_count': tools.length },
            });
            pushSpan({
              kind: 'llm_turn',
              name: `${llmConfig.provider}:${llmConfig.model}`,
              status: llmRes.ok ? 'ok' : 'error',
              startedAt: turnStart,
              durationMs: Date.now() - turnStart,
              input: { step: step + 1, toolCount: tools.length },
              outputPreview: {
                toolCalls: llmRes.toolCalls.map((tc) => tc.name),
                hasText: Boolean(llmRes.content),
                ...(llmRes.usage ? { usage: llmRes.usage } : {}),
                ...(llmRes.error ? { error: llmRes.error } : {}),
              },
            });

            if (!llmRes.ok) {
              record.error = llmRes.error ?? 'LLM provider call failed';
              record.status = 'failed';
              record.stopReason = 'failed';
              break;
            }
            if (llmRes.toolCalls.length === 0) {
              finalAssistantText = llmRes.content;
              break;
            }

            messages.push({ role: 'assistant', content: llmRes.content, toolCalls: llmRes.toolCalls });
            const callsSlice = llmRes.toolCalls.slice(0, 6);
            const stepTracer = getLoopTracer();
            const toolOutputs = await Promise.all(
              callsSlice.map((tc) => {
                const runTool = async () => {
                  emitEvent?.('agent.action', { step: step + 1, tool: tc.name, arguments: tc.arguments });
                  const out = await executeSingleTool(tc.name, tc.arguments);
                  return { tc, out };
                };
                return stepTracer ? stepTracer.run(runTool) : runTool();
              }),
            );
            for (const { tc, out } of toolOutputs) {
              messages.push({ role: 'tool', toolCallId: tc.id, name: tc.name, content: out.summaryForLlm });
              if (out.budgetExhausted) hitBudget = true;
            }
            await persistAgentRun(record, env.META);
            if (hitBudget || record.pagesRead >= record.maxPages) {
              hitBudget = true;
              break;
            }
            if (step + 1 >= record.maxSteps) hitBudget = true;
          }

          if (record.status !== 'cancelled' && record.status !== 'failed') {
            const synthStart = Date.now();
            const synthTracer = getLoopTracer();
            const formatEvidenceBlock = (maxChars: number, withSourceHeading: boolean) =>
              gatheredEvidence
                .map((e) => {
                  const safeTitle = e.fromMcp
                    ? sanitizeMcpMarkdownOutput(sanitizeRemoteMcpText(e.title ?? e.url, 200).text, undefined, 200)
                    : (e.title ?? e.url);
                  const safeBody = e.fromMcp
                    ? wrapConnectorTextForAgentContext(e.markdown, maxChars, {
                        source: e.url,
                        ...(e.mcpServer ? { server: e.mcpServer } : {}),
                        ...(e.mcpTool && isSafeMcpIdentifier(e.mcpTool) ? { tool: e.mcpTool } : {}),
                      })
                    : e.markdown.slice(0, maxChars);
                  return withSourceHeading ? `## Source: ${safeTitle} (${e.url})\n\n${safeBody}` : `## ${safeTitle}\nURL: ${e.url}\n\n${safeBody}`;
                })
                .join('\n\n---\n\n');

            const runSynthesis = async (synthSpan?: ActiveSpanHandle) => {
              if (schema) {
                const directParsed = finalAssistantText ? parseLooseJsonObject(finalAssistantText) : null;
                if (directParsed && Object.keys(directParsed).length > 0 && !hitBudget) {
                  record.data = directParsed;
                } else {
                  const combinedMd = formatEvidenceBlock(5_000, true);
                  const fallbackAssistantForSynth =
                    touchedConnectedMcp && finalAssistantText
                      ? wrapConnectorTextForAgentContext(finalAssistantText, 5_000, { source: 'assistant_draft' })
                      : finalAssistantText;
                  const extracted = await extractJsonWithOptionalLlm({
                    markdown: combinedMd || fallbackAssistantForSynth,
                    url: seedUrls[0] ?? 'https://edgefetch.local/agent',
                    prompt,
                    schema,
                    heuristicFallback: gatheredEvidence.find((e) => e.json)?.json ?? {},
                    llmConfig,
                    ...(llmFetchFn ? { fetchFn: llmFetchFn } : {}),
                    ...(getLoopTracer() ? { tracer: getLoopTracer()! } : {}),
                  });
                  record.data = extracted.data;
                }
                const val = validateDataAgainstJsonSchema(record.data, schema);
                record.schemaValid = val.valid;
                if (hitBudget) {
                  record.partial = true;
                  record.partialSchemaValid = val.partialValid;
                }
              } else {
                if (!finalAssistantText && gatheredEvidence.length > 0) {
                  const sum = await summarizeMarkdownWithOptionalLlm({
                    markdown: formatEvidenceBlock(4_000, false),
                    title: prompt.slice(0, 120),
                    llmConfig,
                    ...(llmFetchFn ? { fetchFn: llmFetchFn } : {}),
                    ...(getLoopTracer() ? { tracer: getLoopTracer()! } : {}),
                  });
                  finalAssistantText = sum.summary;
                }
                record.markdown = finalAssistantText;
                record.data = { answer: finalAssistantText, sources: record.sources };
                if (hitBudget) record.partial = true;
              }
              synthSpan?.setAttribute('agent.partial', Boolean(record.partial));
              if (record.schemaValid !== undefined) synthSpan?.setAttribute('agent.schema_valid', record.schemaValid);
            };
            if (synthTracer) {
              await synthTracer.withSpan(
                'edgefetch.agent.synthesis',
                { kind: 1, attributes: { 'agent.id': record.id, 'agent.has_schema': Boolean(schema), 'agent.llm_used': true } },
                (synthSpan) => runSynthesis(synthSpan),
              );
            } else {
              await runSynthesis();
            }
            pushSpan({
              kind: 'synthesis',
              name: 'final_synthesis',
              status: 'ok',
              startedAt: synthStart,
              durationMs: Date.now() - synthStart,
              outputPreview: { partial: Boolean(record.partial), schemaValid: record.schemaValid },
            });
            record.status = 'completed';
            record.stopReason = hitBudget ? 'budget_reached' : 'completed';
          }
        } else {
          // Zero-Key Deterministic Research Mode
          record.stepsUsed = 1;
          if (canInvokeFederatedMcp && wantsConnectedMcps && allowedConnectorIds.size > 0) {
            for (const matched of matchedMcps.slice(0, 2)) {
              if (isCancelled()) break;
              if (!allowedConnectorIds.has(matched.server.id)) continue;
              const mcpTool = filterSafeCachedMcpTools(matched.server.tools).find(
                (t) => isSafeMcpIdentifier(t.name) && t.readOnlyHint === true && t.destructiveHint !== true,
              );
              if (mcpTool) {
                const props =
                  mcpTool.inputSchema?.properties && typeof mcpTool.inputSchema.properties === 'object'
                    ? (mcpTool.inputSchema.properties as Record<string, unknown>)
                    : {};
                const autoArgs: Record<string, unknown> = {};
                if ('url' in props && seedUrls[0]) autoArgs.url = seedUrls[0];
                else if ('uri' in props && seedUrls[0]) autoArgs.uri = seedUrls[0];
                if ('query' in props) autoArgs.query = prompt;
                else if ('q' in props) autoArgs.q = prompt;
                else if ('search' in props) autoArgs.search = prompt;
                await executeSingleTool('query_mcp', { action: 'call_tool', server: matched.server.slug, tool: mcpTool.name, arguments: autoArgs });
              }
            }
          }

          let candidateUrls = [...seedUrls];
          if (candidateUrls.length === 0 && !strictConstrainToURLs && gatheredEvidence.length === 0) {
            const sRes = await executeSingleTool('web_search', { query: prompt, maxResults: Math.min(5, record.maxPages) });
            if (sRes.ok) {
              try {
                const parsedHits = JSON.parse(sRes.summaryForLlm) as Array<{ url?: string }>;
                candidateUrls = parsedHits
                  .map((h) => (typeof h.url === 'string' ? h.url : ''))
                  .filter(Boolean)
                  .slice(0, Math.min(4, record.maxPages));
              } catch {
                // ignore
              }
            }
          }
          for (const u of candidateUrls.slice(0, record.maxPages)) {
            if (isCancelled()) break;
            await executeSingleTool('scrape_url', { url: u, query: prompt });
          }

          const detSynthTracer = getLoopTracer();
          const runDeterministicSynthesis = async (synthSpan?: ActiveSpanHandle) => {
            const combinedMd = gatheredEvidence
              .map((e) => {
                const safeTitle = e.fromMcp
                  ? sanitizeMcpMarkdownOutput(sanitizeRemoteMcpText(e.title ?? e.url, 200).text, undefined, 200)
                  : (e.title ?? e.url);
                const safeBody = e.fromMcp
                  ? wrapConnectorTextForAgentContext(e.markdown, 3_500, {
                      source: e.url,
                      ...(e.mcpServer ? { server: e.mcpServer } : {}),
                      ...(e.mcpTool && isSafeMcpIdentifier(e.mcpTool) ? { tool: e.mcpTool } : {}),
                    })
                  : e.markdown.slice(0, 3_500);
                return `### [${safeTitle}](${e.url})\n\n${safeBody}`;
              })
              .join('\n\n---\n\n');
            record.markdown = combinedMd;
            if (schema) {
              const allLinks = record.sources.map((s) => s.url);
              const mergedHeuristic = extractStructuredJsonFromPage(
                '',
                {
                  markdown: combinedMd,
                  text: combinedMd,
                  title: gatheredEvidence.map((e) => e.title).filter(Boolean).join(' | ') || prompt.slice(0, 100),
                  links: allLinks,
                  images: [],
                  branding: { title: prompt.slice(0, 100) },
                },
                schema,
              );
              for (const ev of gatheredEvidence) {
                if (ev.json) {
                  for (const [k, v] of Object.entries(ev.json)) {
                    if (mergedHeuristic[k] === undefined || mergedHeuristic[k] === '') mergedHeuristic[k] = v;
                  }
                }
              }
              const schemaProps =
                schema.properties && typeof schema.properties === 'object' ? (schema.properties as Record<string, unknown>) : {};
              if ('sources' in schemaProps && (!Array.isArray(mergedHeuristic.sources) || mergedHeuristic.sources.length === 0)) {
                mergedHeuristic.sources = allLinks;
              }
              if ('summary' in schemaProps && combinedMd) {
                const sumRes = await summarizeMarkdownWithOptionalLlm({
                  markdown: combinedMd,
                  title: prompt.slice(0, 100),
                  llmConfig: null,
                });
                if (sumRes.summary) mergedHeuristic.summary = sumRes.summary;
              }
              record.data = mergedHeuristic;
              const val = validateDataAgainstJsonSchema(record.data, schema);
              record.schemaValid = val.valid;
              synthSpan?.setAttribute('agent.schema_valid', val.valid);
            } else {
              const detSummary = await summarizeMarkdownWithOptionalLlm({
                markdown: combinedMd,
                title: prompt.slice(0, 100),
                llmConfig: null,
              });
              record.data = { answer: detSummary.summary, markdown: combinedMd, sources: record.sources };
            }
          };
          if (detSynthTracer) {
            await detSynthTracer.withSpan(
              'edgefetch.agent.synthesis',
              { kind: 1, attributes: { 'agent.id': record.id, 'agent.has_schema': Boolean(schema), 'agent.llm_used': false } },
              (synthSpan) => runDeterministicSynthesis(synthSpan),
            );
          } else {
            await runDeterministicSynthesis();
          }
          record.status = isCancelled() ? 'cancelled' : 'completed';
          record.stopReason = isCancelled() ? 'cancelled' : 'completed';
        }
      } catch (err) {
        record.status = 'failed';
        record.stopReason = 'failed';
        record.error = err instanceof Error ? err.message : String(err);
        const errTracer = getLoopTracer();
        if (errTracer) {
          const errSpan = errTracer.startSpan('edgefetch.agent.error', { kind: 1, attributes: { 'agent.id': record.id } });
          errSpan.setStatus(false, sanitizeErrorMessageForSpan(err, 'unhandled_agent_exception'));
          errSpan.end();
        }
        pushSpan({
          kind: 'error',
          name: 'unhandled_agent_exception',
          status: 'error',
          startedAt: Date.now(),
          durationMs: 0,
          outputPreview: { error: record.error },
        });
      }

      record.finishedAt = Date.now();
      record.updatedAt = record.finishedAt;
      if (!zeroDataRetention) {
        const rawMemoryPayload =
          typeof record.markdown === 'string' && record.markdown
            ? `Findings:\n${record.markdown.slice(0, 4_000)}`
            : record.data
              ? `Structured data:\n${JSON.stringify(record.data).slice(0, 4_000)}`
              : '';
        const safeMemoryPayload = rawMemoryPayload
          ? touchedConnectedMcp || record.visibility === 'private'
            ? wrapConnectorTextForAgentContext(rawMemoryPayload, 4_000, { source: 'thread_memory', agentId: record.id })
            : sanitizeMcpMarkdownOutput(rawMemoryPayload, undefined, 4_100)
          : '';
        record.threadMemory = [`Previous prompt: ${prompt}`, ...(safeMemoryPayload ? [safeMemoryPayload] : [])].join('\n\n');
      }
      await persistAgentRun(record, env.META);
      cancelledAgentIds.delete(record.id);

      if (webhook) {
        const whEndTracer = getLoopTracer();
        await deliverSignedWebhook({
          webhook,
          defaultSecret: env.WEBHOOK_SECRET,
          event: record.status === 'completed' ? 'agent.completed' : record.status === 'cancelled' ? 'agent.cancelled' : 'agent.failed',
          crawlId: record.id,
          data: formatPublicAgentResponse(record, false),
          selfHost,
          ...(env.SAFE_PUBLIC_FETCH ? { fetchFn: env.SAFE_PUBLIC_FETCH } : env.SAFE_FETCH ? { fetchFn: env.SAFE_FETCH } : {}),
          ...(whEndTracer ? { tracer: whEndTracer } : {}),
        }).catch(() => undefined);
      }

      emitEvent?.('agent.completed', formatPublicAgentResponse(record, false));
      return record;
    };

    const runLoopWithQuotaRelease = async (
      emitEvent?: (event: string, data: Record<string, unknown>) => void,
    ): Promise<AgentRunRecord> => {
      try {
        return await runLoop(emitEvent);
      } finally {
        releaseAgentQuotaSlot();
      }
    };

    if (wantSseStream || payload.stream === true) {
      const encoder = new TextEncoder();
      const stream = new ReadableStream<Uint8Array>({
        async start(controller) {
          const send = (event: string, data: Record<string, unknown>) => {
            try {
              controller.enqueue(encoder.encode(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`));
            } catch {
              // client closed stream
            }
          };
          try {
            await (agentTracer ? agentTracer.run(() => runLoopWithQuotaRelease(send)) : runLoopWithQuotaRelease(send));
          } finally {
            releaseAgentQuotaSlot();
            try {
              controller.close();
            } catch {
              // ignore
            }
          }
        },
        cancel() {
          cancelledAgentIds.add(record.id);
          releaseAgentQuotaSlot();
        },
      });
      return {
        kind: 'sse',
        response: new Response(stream, {
          status: 200,
          headers: {
            'content-type': 'text/event-stream; charset=utf-8',
            'cache-control': record.visibility === 'private' ? 'private, no-store' : 'no-store',
            connection: 'keep-alive',
          },
        }),
      };
    }

    const runAsync = payload.async === true && !zeroDataRetention;
    if (runAsync) {
      const bgPromise = agentTracer ? agentTracer.run(() => runLoopWithQuotaRelease()) : runLoopWithQuotaRelease();
      if (waitUntil) waitUntil(bgPromise);
      else void bgPromise.catch(() => undefined);
      return {
        kind: 'json',
        status: 202,
        body: {
          ok: true,
          success: true,
          ...(record.visibility === 'private' ? { visibility: 'private' as const } : {}),
          id: record.id,
          threadId: record.threadId,
          status: 'processing',
          routedAdapters: record.routedAdapters,
          url: `/v1/agent/${record.id}`,
          traceUrl: `/v1/agent/${record.id}/trace`,
        },
      };
    }

    const completed = await (agentTracer ? agentTracer.run(() => runLoopWithQuotaRelease()) : runLoopWithQuotaRelease());
    return {
      kind: 'json',
      status: completed.status === 'failed' ? 502 : 200,
      body: formatPublicAgentResponse(completed, Boolean(payload.includeTrace)),
    };
  } catch (setupErr) {
    releaseAgentQuotaSlot();
    throw setupErr;
  }
}
