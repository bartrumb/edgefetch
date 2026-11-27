/**
 * Drop-in Firecrawl v2 (`/v2/*` AND `/compat/firecrawl/v2/*`) and Tavily (`/compat/tavily/*`) compatibility routes.
 *
 * Allows unmodified `new Firecrawl({ apiUrl: "https://<hub>" })` / `FirecrawlApp(api_url=...)` / Tavily SDK callers
 * to point directly at a self-hosted EdgeFetch Hub with zero path prefix or client code rewrites.
 */

import { MAX_CALL_UTF8_BYTES } from './agent-hub';
import {
  cancelAgentRun,
  formatPublicAgentResponse,
  loadAgentRun,
  startOrExecuteAgentCall,
} from './agent-runner';
import { isValidSecretMatch } from './auth';
import { resolveSessionSecret, type GitHubAuthEnv } from './github-auth';
import type { LlmEnvBindings } from './llm';
import type { McpVaultStore } from './mcp-vault';
import {
  cancelBatchScrape,
  cancelCrawlJob,
  countExtractPayloadUrls,
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
  type HubFetchExecutor,
} from './map-crawl';
import { authorizeMcpRequest, type OAuthStore } from './oauth';
import { getActiveRequestTracer, type RequestTracer, type TraceContext } from './otel';
import { readBodyTextCapped, safeDecodeURIComponent } from './safe-input';
import { executeScrapeCall } from './scrape';
import { executeExtractCall, resolveUserCollectionId } from './search-index';
import { isPrivateRequestPayload, sanitizeStorageUserId, type OptionalStorageBindings } from './storage';
import { executeSearchCall, type SearchBindings } from './web-search';

export async function handleCompatRoutes(params: {
  request: Request;
  url: URL;
  env: OptionalStorageBindings &
    SearchBindings &
    LlmEnvBindings &
    GitHubAuthEnv & {
      MCP_TOKEN?: string;
      WEBHOOK_SECRET?: string;
      VAULT_MASTER_KEY?: string;
      SAFE_PUBLIC_FETCH?: typeof fetch;
      SAFE_FETCH?: typeof fetch;
    };
  oauthStore: OAuthStore;
  vaultStore?: McpVaultStore;
  executeHubFetch: HubFetchExecutor;
  waitUntil?: (p: Promise<unknown>) => void;
  tracer?: RequestTracer | TraceContext;
  preReadBody?: { ok: true; text: string; byteLength: number } | { ok: false; error: 'too_large' | 'read_error' };
}): Promise<Response | null> {
  const { request, url, env, oauthStore, vaultStore, executeHubFetch, waitUntil } = params;
  const activeTracer = getActiveRequestTracer(params.tracer);
  const runCompat = async (): Promise<Response | null> => {
  const p = url.pathname;
  const isDirectFirecrawlV2 = p.startsWith('/v2/');
  const isPrefixedFirecrawlV2 = p.startsWith('/compat/firecrawl/v2/');
  const isTavily = p.startsWith('/compat/tavily/');
  if (!isDirectFirecrawlV2 && !isPrefixedFirecrawlV2 && !isTavily) {
    return null;
  }

  // M6 Security Invariant: Authenticate header-based callers BEFORE buffering POST request bodies!
  // Only Tavily SDKs pass `{ api_key: "tvly-..." }` inside the JSON body; for Tavily without header auth, cap pre-auth body at 64 KiB.
  let authorized = false;
  const auth = await authorizeMcpRequest({
    request,
    origin: url.origin,
    ownerSecret: env.CALLER_TOKEN,
    mcpToken: env.MCP_TOKEN,
    store: oauthStore,
  });
  const isAuthCallerPrivate = auth.ok && sanitizeStorageUserId(auth.userId) !== 'owner';
  const bodyErrHeaders = { 'cache-control': isAuthCallerPrivate ? 'private, no-store' : 'no-store' };
  if (auth.ok && auth.scopes.includes('crawl:fetch')) {
    authorized = true;
  } else if (auth.ok && !isTavily) {
    void request.body?.cancel().catch(() => undefined);
    return Response.json(
      {
        success: false,
        error: 'insufficient_scope',
        ...(isAuthCallerPrivate ? { visibility: 'private' as const } : {}),
      },
      { status: 403, headers: bodyErrHeaders },
    );
  } else if (!isTavily || request.method !== 'POST') {
    void request.body?.cancel().catch(() => undefined);
    return Response.json({ success: false, error: 'unauthorized' }, { status: 401, headers: { 'cache-control': 'no-store' } });
  }

  let bodyObj: Record<string, unknown> = {};
  if (request.method === 'POST') {
    const maxBytes = authorized ? MAX_CALL_UTF8_BYTES : 64 * 1024;
    const capped = params.preReadBody ?? (await readBodyTextCapped(request, maxBytes));
    if (!capped.ok) {
      const isTooLarge = capped.error === 'too_large';
      return Response.json(
        {
          success: false,
          error: isTooLarge ? 'too_large' : 'bad_json',
          ...(isAuthCallerPrivate ? { visibility: 'private' as const } : {}),
        },
        { status: isTooLarge ? 413 : 400, headers: bodyErrHeaders },
      );
    }
    try {
      const parsed = JSON.parse(capped.text);
      if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
        return Response.json(
          {
            success: false,
            error: 'bad_json',
            ...(isAuthCallerPrivate ? { visibility: 'private' as const } : {}),
          },
          { status: 400, headers: bodyErrHeaders },
        );
      }
      bodyObj = parsed as Record<string, unknown>;
    } catch {
      return Response.json(
        {
          success: false,
          error: 'bad_json',
          ...(isAuthCallerPrivate ? { visibility: 'private' as const } : {}),
        },
        { status: 400, headers: bodyErrHeaders },
      );
    }
  }

  if (
    !authorized &&
    isTavily &&
    typeof bodyObj.api_key === 'string' &&
    isValidSecretMatch(bodyObj.api_key.trim(), env.CALLER_TOKEN, env.MCP_TOKEN)
  ) {
    authorized = true;
  }

  if (!authorized) {
    if (auth.ok) {
      return Response.json(
        {
          success: false,
          error: 'insufficient_scope',
          ...(isAuthCallerPrivate ? { visibility: 'private' as const } : {}),
        },
        { status: 403, headers: bodyErrHeaders },
      );
    }
    return Response.json({ success: false, error: 'unauthorized' }, { status: 401, headers: { 'cache-control': 'no-store' } });
  }
  const callerUserId = auth.ok ? auth.userId : 'owner';
  const sessionSigningSecret = resolveSessionSecret(env);

  // Normalize `/v2/<subpath>` and `/compat/firecrawl/v2/<subpath>` into one canonical subpath
  const fcPrefix = isDirectFirecrawlV2 ? '/v2' : '/compat/firecrawl/v2';
  const fcSubpath = isDirectFirecrawlV2 ? p.slice('/v2'.length) : isPrefixedFirecrawlV2 ? p.slice('/compat/firecrawl/v2'.length) : '';

  // ── Firecrawl v2 Compatibility Surface (`/v2/*` & `/compat/firecrawl/v2/*`) ──
  if (fcSubpath === '/scrape' && request.method === 'POST') {
    const out = await executeScrapeCall({
      payload: {
        ...bodyObj,
        maxAgeMs: typeof bodyObj.maxAge === 'number' ? bodyObj.maxAge : bodyObj.maxAgeMs,
      },
      env,
      executeHubFetch,
      selfHost: url.hostname,
      userId: callerUserId,
      source: 'compat:firecrawl:scrape',
      ...(activeTracer ? { tracer: activeTracer } : {}),
    });
    const isPrivateScrape =
      (out.body as { visibility?: string }).visibility === 'private' ||
      isPrivateRequestPayload(bodyObj, callerUserId);
    const headers: Record<string, string> = {
      'cache-control': isPrivateScrape ? 'private, no-store' : 'no-store',
      ...(out.retryAfter ? { 'retry-after': out.retryAfter } : {}),
    };
    if (out.status !== 200) {
      return Response.json({ success: false, ...out.body }, { status: out.status, headers });
    }
    return Response.json({ success: true, data: out.body }, { status: 200, headers });
  }

  if (fcSubpath === '/map' && request.method === 'POST') {
    const isPrivateMapReq = isPrivateRequestPayload(bodyObj, callerUserId);
    const mapHeaders = { 'cache-control': isPrivateMapReq ? 'private, no-store' : 'no-store' };
    const releaseMapSlot = tryAcquireUserMapSlot(callerUserId);
    if (!releaseMapSlot) {
      return Response.json(
        {
          ok: false,
          success: false,
          ...(isPrivateMapReq ? { visibility: 'private' as const } : {}),
          error: 'user_quota_exceeded',
          message: `Per-user concurrent map limit (${MAX_CONCURRENT_MAPS_PER_USER}) exceeded.`,
        },
        { status: 429, headers: { ...mapHeaders, 'retry-after': '2' } },
      );
    }
    try {
      const out = await executeMapCall({
        payload: bodyObj,
        executeHubFetch,
        selfHost: url.hostname,
        source: 'compat:firecrawl:map',
        ...(activeTracer ? { tracer: activeTracer } : {}),
      });
      return Response.json(
        out.status === 200
          ? {
              success: true,
              ...(isPrivateMapReq ? { visibility: 'private' as const } : {}),
              links: out.body.links,
              entries: out.body.entries,
            }
          : {
              success: false,
              ...(isPrivateMapReq ? { visibility: 'private' as const } : {}),
              ...out.body,
            },
        { status: out.status, headers: mapHeaders },
      );
    } finally {
      releaseMapSlot();
    }
  }

  if (fcSubpath === '/crawl/params-preview' && request.method === 'POST') {
    const isPrivatePreview = isPrivateRequestPayload(bodyObj, callerUserId);
    const prev = previewCrawlParams(bodyObj, url.hostname);
    return Response.json(
      {
        ...prev.body,
        ...(isPrivatePreview ? { visibility: 'private' as const } : {}),
      },
      {
        status: prev.status,
        headers: { 'cache-control': isPrivatePreview ? 'private, no-store' : 'no-store' },
      },
    );
  }

  if (fcSubpath === '/crawl' && request.method === 'POST') {
    const isPrivateCrawlReq = isPrivateRequestPayload(bodyObj, callerUserId);
    const crawlHeaders = { 'cache-control': isPrivateCrawlReq ? 'private, no-store' : 'no-store' };
    const crawlPayload = { ...bodyObj };
    if (typeof crawlPayload.collectionId === 'string' && crawlPayload.collectionId.trim()) {
      const scoped = resolveUserCollectionId(
        crawlPayload.collectionId,
        callerUserId,
        isPrivateCrawlReq ? 'private' : 'public',
      );
      if (!scoped.ok) {
        return Response.json(
          { success: false, ...(isPrivateCrawlReq ? { visibility: 'private' as const } : {}), error: scoped.error },
          { status: scoped.status, headers: crawlHeaders },
        );
      }
      crawlPayload.collectionId = scoped.scopedId;
    }
    if (isPrivateCrawlReq && crawlPayload.visibility !== 'private') {
      crawlPayload.visibility = 'private';
    }
    const created = await createCrawlJob({ payload: crawlPayload, metaDb: env.META, selfHost: url.hostname, userId: callerUserId });
    if (!created.ok) {
      return Response.json(
        {
          success: false,
          ...(isPrivateCrawlReq ? { visibility: 'private' as const } : {}),
          error: created.error,
          message: created.message,
        },
        {
          status: created.status,
          headers: {
            ...crawlHeaders,
            ...(created.status === 429 ? { 'retry-after': '2' } : {}),
          },
        },
      );
    }
    const jobPromise = executeCrawlJob({
      crawlId: created.crawlId,
      rootUrl: created.rootUrl,
      options: created.options,
      env,
      executeHubFetch,
      selfHost: url.hostname,
      waitUntilBounded: Boolean(waitUntil) && bodyObj.sync !== true,
      ...(activeTracer ? { tracer: activeTracer } : {}),
    });
    if (bodyObj.sync === true) {
      await jobPromise;
    } else if (waitUntil) {
      waitUntil(jobPromise);
    } else {
      await jobPromise;
    }
    return Response.json(
      {
        success: true,
        ...(isPrivateCrawlReq ? { visibility: 'private' as const } : {}),
        id: created.crawlId,
        url: `${url.origin}${fcPrefix}/crawl/${created.crawlId}`,
      },
      { headers: crawlHeaders },
    );
  }

  const fcCrawlMatch = /^\/crawl\/([^/]+)$/.exec(fcSubpath);
  if (fcCrawlMatch && fcCrawlMatch[1] !== 'params-preview') {
    const crawlIdHeaders = { 'cache-control': isAuthCallerPrivate ? 'private, no-store' : 'no-store' };
    const crawlId = safeDecodeURIComponent(fcCrawlMatch[1] ?? '');
    if (crawlId === null) {
      return Response.json(
        {
          success: false,
          ...(isAuthCallerPrivate ? { visibility: 'private' as const } : {}),
          error: 'bad_request',
        },
        { status: 400, headers: crawlIdHeaders },
      );
    }
    if (request.method === 'GET') {
      const rawOffset = Number(url.searchParams.get('offset') ?? 0);
      const rawLimit = Number(url.searchParams.get('limit') ?? 25);
      const st = await getCrawlJobStatus({
        crawlId,
        metaDb: env.META,
        bucket: env.ARTIFACTS,
        offset: Number.isFinite(rawOffset) ? rawOffset : 0,
        limit: Number.isFinite(rawLimit) ? rawLimit : 25,
        userId: callerUserId,
      });
      if (!st.ok) {
        return Response.json(
          {
            success: false,
            ...(isAuthCallerPrivate ? { visibility: 'private' as const } : {}),
            error: st.error,
          },
          { status: st.status, headers: crawlIdHeaders },
        );
      }
      const isCrawlPrivate = isAuthCallerPrivate || st.crawl.visibility === 'private';
      const crawlGetHeaders = { 'cache-control': isCrawlPrivate ? 'private, no-store' : 'no-store' };
      return Response.json(
        {
          success: true,
          ...(isCrawlPrivate ? { visibility: 'private' as const } : {}),
          ...st.crawl,
        },
        { headers: crawlGetHeaders },
      );
    }
    if (request.method === 'DELETE') {
      const del = await cancelCrawlJob(crawlId, env.META, callerUserId);
      const isCrawlPrivate = isAuthCallerPrivate || del.visibility === 'private';
      return Response.json(
        {
          success: del.ok,
          ...(isCrawlPrivate ? { visibility: 'private' as const } : {}),
          status: 'cancelled',
        },
        { status: del.status, headers: { 'cache-control': isCrawlPrivate ? 'private, no-store' : 'no-store' } },
      );
    }
  }

  if (fcSubpath === '/batch/scrape' && request.method === 'POST') {
    const isPrivateBatchReq = isPrivateRequestPayload(bodyObj, callerUserId);
    const batchHeaders = { 'cache-control': isPrivateBatchReq ? 'private, no-store' : 'no-store' };
    const batchOut = await startOrExecuteBatchScrape({
      payload: bodyObj,
      selfHost: url.hostname,
      userId: callerUserId,
      executeScrape: async (scArgs) => {
        const res = await executeScrapeCall({
          payload: scArgs,
          env,
          executeHubFetch,
          selfHost: url.hostname,
          userId: callerUserId,
          source: 'compat:firecrawl:batch-scrape',
          ...(activeTracer ? { tracer: activeTracer } : {}),
        });
        return { status: res.status, body: res.body, ...(res.retryAfter ? { retryAfter: res.retryAfter } : {}) };
      },
      ...(waitUntil ? { waitUntil } : {}),
      ...(activeTracer ? { tracer: activeTracer } : {}),
    });
    if (!batchOut.ok) {
      return Response.json(
        {
          success: false,
          ...(isPrivateBatchReq ? { visibility: 'private' as const } : {}),
          error: batchOut.error,
          message: batchOut.message,
        },
        {
          status: batchOut.status,
          headers: {
            ...batchHeaders,
            ...(batchOut.status === 429 ? { 'retry-after': '2' } : {}),
          },
        },
      );
    }
    return Response.json(
      {
        success: true,
        ...(isPrivateBatchReq ? { visibility: 'private' as const } : {}),
        id: batchOut.job.id,
        url: `${url.origin}${fcPrefix}/batch/scrape/${batchOut.job.id}`,
        ...(bodyObj.sync === true ? { status: batchOut.job.status, total: batchOut.job.total, completed: batchOut.job.completed, data: batchOut.job.data } : {}),
      },
      { status: 200, headers: batchHeaders },
    );
  }

  const fcBatchMatch = /^\/batch\/scrape\/([^/]+)$/.exec(fcSubpath);
  if (fcBatchMatch) {
    const batchIdHeaders = { 'cache-control': isAuthCallerPrivate ? 'private, no-store' : 'no-store' };
    const batchId = safeDecodeURIComponent(fcBatchMatch[1] ?? '');
    if (batchId === null) {
      return Response.json(
        {
          success: false,
          ...(isAuthCallerPrivate ? { visibility: 'private' as const } : {}),
          error: 'bad_request',
        },
        { status: 400, headers: batchIdHeaders },
      );
    }
    if (request.method === 'GET') {
      const job = getBatchScrapeStatus(batchId, callerUserId);
      if (!job) {
        return Response.json(
          {
            success: false,
            ...(isAuthCallerPrivate ? { visibility: 'private' as const } : {}),
            error: 'batch_not_found',
          },
          { status: 404, headers: batchIdHeaders },
        );
      }
      const isPrivBatch = isAuthCallerPrivate || job.visibility === 'private';
      return Response.json(
        {
          success: true,
          ...(isPrivBatch ? { visibility: 'private' as const } : {}),
          status: job.status,
          total: job.total,
          completed: job.completed,
          creditsUsed: 0,
          expiresAt: new Date(job.expiresAt).toISOString(),
          data: job.data,
          ...(job.errors.length > 0 ? { errors: job.errors } : {}),
        },
        { headers: { 'cache-control': isPrivBatch ? 'private, no-store' : 'no-store' } },
      );
    }
    if (request.method === 'DELETE') {
      const existingJob = getBatchScrapeStatus(batchId, callerUserId);
      const ok = cancelBatchScrape(batchId, callerUserId);
      const isPrivBatch = isAuthCallerPrivate || existingJob?.visibility === 'private';
      return Response.json(
        {
          success: ok,
          ...(isPrivBatch ? { visibility: 'private' as const } : {}),
          message: ok ? 'Batch scrape job cancelled' : 'Batch not found',
        },
        { status: ok ? 200 : 404, headers: { 'cache-control': isPrivBatch ? 'private, no-store' : 'no-store' } },
      );
    }
  }

  if (fcSubpath === '/search' && request.method === 'POST') {
    const isPrivateSearchReq = isPrivateRequestPayload(bodyObj, callerUserId);
    const out = await executeSearchCall({
      payload: bodyObj,
      env,
      executeHubFetch,
      userId: callerUserId,
      source: 'compat:firecrawl:search',
      ...(activeTracer ? { tracer: activeTracer } : {}),
    });
    const isPrivateSearch = (out.body as { visibility?: string }).visibility === 'private' || isPrivateSearchReq;
    return Response.json(
      out.status === 200
        ? { success: true, ...(isPrivateSearch ? { visibility: 'private' as const } : {}), data: out.body.results, ...out.body }
        : { success: false, ...(isPrivateSearch ? { visibility: 'private' as const } : {}), ...out.body },
      {
        status: out.status,
        headers: { 'cache-control': isPrivateSearch ? 'private, no-store' : 'no-store' },
      },
    );
  }

  if (fcSubpath === '/extract' && request.method === 'POST') {
    const isPrivateExtractReq = isPrivateRequestPayload(bodyObj, callerUserId);
    const hasInvalidUrls =
      !Array.isArray(bodyObj.urls) || bodyObj.urls.length === 0 || bodyObj.urls.length > 20;
    const releaseExtractSlots = hasInvalidUrls
      ? () => undefined
      : tryAcquireUserExtractSlots(callerUserId, countExtractPayloadUrls(bodyObj));
    if (!releaseExtractSlots) {
      return Response.json(
        {
          ok: false,
          success: false,
          ...(isPrivateExtractReq ? { visibility: 'private' } : {}),
          error: 'user_quota_exceeded',
          message: `Per-user concurrent extract limit (${MAX_CONCURRENT_EXTRACTS_PER_USER} requests / ${MAX_CONCURRENT_EXTRACT_URLS_PER_USER} URLs) exceeded.`,
        },
        { status: 429, headers: { 'cache-control': isPrivateExtractReq ? 'private, no-store' : 'no-store', 'retry-after': '2' } },
      );
    }
    try {
      const out = await executeExtractCall({
        payload: {
          ...bodyObj,
          ...(typeof bodyObj.query !== 'string' && typeof bodyObj.prompt === 'string' ? { query: bodyObj.prompt } : {}),
        },
        env,
        executeHubFetch,
        selfHost: url.hostname,
        userId: callerUserId,
        source: 'compat:firecrawl:extract',
        ...(activeTracer ? { tracer: activeTracer } : {}),
      });
      const isPrivateExtract =
        (out.body as { visibility?: string }).visibility === 'private' || isPrivateExtractReq;
      return Response.json(
        out.status === 200
          ? { success: true, ...(isPrivateExtract ? { visibility: 'private' as const } : {}), data: out.body, ...out.body }
          : { success: false, ...(isPrivateExtract ? { visibility: 'private' as const } : {}), ...out.body },
        {
          status: out.status,
          headers: {
            'cache-control': isPrivateExtract ? 'private, no-store' : 'no-store',
            ...(out.retryAfter ? { 'retry-after': out.retryAfter } : {}),
          },
        },
      );
    } finally {
      releaseExtractSlots();
    }
  }

  // ── Firecrawl `/v2/agent` Drop-In Compatibility (with SSE + BYO-LLM + Dynamic Adapter Router) ──
  if (fcSubpath === '/agent' && request.method === 'POST') {
    const isPrivateAgentReq = isPrivateRequestPayload(bodyObj, callerUserId);
    const agentHeaders = { 'cache-control': isPrivateAgentReq ? 'private, no-store' : 'no-store' };
    const wantSse = (request.headers.get('accept') ?? '').toLowerCase().includes('text/event-stream');
    // Firecrawl POST /v2/agent defaults to async job creation unless zeroDataRetention=true or sync=true/stream=true
    const effectivePayload =
      bodyObj.async === undefined && bodyObj.sync !== true && bodyObj.stream !== true && !wantSse && bodyObj.zeroDataRetention !== true
        ? { ...bodyObj, async: true }
        : bodyObj;
    const out = await startOrExecuteAgentCall({
      payload: effectivePayload,
      env,
      executeHubFetch,
      selfHost: url.hostname,
      principal: auth.ok ? auth.principal : 'compat',
      userId: callerUserId,
      ...(sessionSigningSecret ? { sessionSigningSecret } : {}),
      ...(vaultStore ? { vaultStore } : {}),
      wantSseStream: wantSse,
      ...(waitUntil ? { waitUntil } : {}),
      ...(activeTracer ? { tracer: activeTracer } : {}),
    });
    if (out.kind === 'sse') return out.response;
    const isPrivAgentOut =
      isPrivateAgentReq || (out.body as { visibility?: string }).visibility === 'private';
    return Response.json(
      {
        ...out.body,
        ...(isPrivAgentOut ? { visibility: 'private' as const } : {}),
      },
      {
        status: out.status,
        headers: {
          'cache-control': isPrivAgentOut ? 'private, no-store' : 'no-store',
          ...(out.status === 429 ? { 'retry-after': '2' } : {}),
        },
      },
    );
  }

  const fcAgentTraceMatch = /^\/agent\/([^/]+)\/trace$/.exec(fcSubpath);
  if (fcAgentTraceMatch && request.method === 'GET') {
    const agentIdHeaders = { 'cache-control': isAuthCallerPrivate ? 'private, no-store' : 'no-store' };
    const agentId = safeDecodeURIComponent(fcAgentTraceMatch[1] ?? '');
    if (agentId === null) {
      return Response.json(
        {
          success: false,
          ...(isAuthCallerPrivate ? { visibility: 'private' as const } : {}),
          error: 'bad_request',
        },
        { status: 400, headers: agentIdHeaders },
      );
    }
    const rec = await loadAgentRun(agentId, env.META, callerUserId);
    if (!rec) {
      return Response.json(
        {
          success: false,
          ...(isAuthCallerPrivate ? { visibility: 'private' as const } : {}),
          error: 'agent_not_found',
        },
        { status: 404, headers: agentIdHeaders },
      );
    }
    const isPrivTrace = isAuthCallerPrivate || rec.visibility === 'private';
    return Response.json(
      {
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
      { headers: { 'cache-control': isPrivTrace ? 'private, no-store' : 'no-store' } },
    );
  }

  const fcAgentMatch = /^\/agent\/([^/]+)$/.exec(fcSubpath);
  if (fcAgentMatch) {
    const agentIdHeaders = { 'cache-control': isAuthCallerPrivate ? 'private, no-store' : 'no-store' };
    const agentId = safeDecodeURIComponent(fcAgentMatch[1] ?? '');
    if (agentId === null) {
      return Response.json(
        {
          success: false,
          ...(isAuthCallerPrivate ? { visibility: 'private' as const } : {}),
          error: 'bad_request',
        },
        { status: 400, headers: agentIdHeaders },
      );
    }
    if (request.method === 'GET') {
      const rec = await loadAgentRun(agentId, env.META, callerUserId);
      if (!rec) {
        return Response.json(
          {
            success: false,
            ...(isAuthCallerPrivate ? { visibility: 'private' as const } : {}),
            error: 'agent_not_found',
          },
          { status: 404, headers: agentIdHeaders },
        );
      }
      const pub = formatPublicAgentResponse(rec, false);
      const isPrivGet = isAuthCallerPrivate || rec.visibility === 'private';
      return Response.json(
        { ...pub, ...(isPrivGet ? { visibility: 'private' as const } : {}) },
        { headers: { 'cache-control': isPrivGet ? 'private, no-store' : 'no-store' } },
      );
    }
    if (request.method === 'DELETE') {
      const cRes = await cancelAgentRun(agentId, env.META, callerUserId);
      const isPrivCancel = isAuthCallerPrivate || cRes.visibility === 'private';
      return Response.json(
        {
          success: cRes.ok,
          ...(isPrivCancel ? { visibility: 'private' as const } : {}),
        },
        { status: cRes.status, headers: { 'cache-control': isPrivCancel ? 'private, no-store' : 'no-store' } },
      );
    }
  }

  // ── Tavily Compatibility Surface ──
  if (p === '/compat/tavily/search' && request.method === 'POST') {
    const isPrivateTavily = isPrivateRequestPayload(bodyObj, callerUserId);
    const out = await executeSearchCall({
      payload: bodyObj,
      env,
      executeHubFetch,
      userId: callerUserId,
      source: 'compat:tavily:search',
      ...(activeTracer ? { tracer: activeTracer } : {}),
    });
    const isPrivOut = isPrivateTavily || (out.body as { visibility?: string }).visibility === 'private';
    return Response.json(
      { ...out.body, ...(isPrivOut ? { visibility: 'private' as const } : {}) },
      { status: out.status, headers: { 'cache-control': isPrivOut ? 'private, no-store' : 'no-store' } },
    );
  }

  if (p === '/compat/tavily/extract' && request.method === 'POST') {
    const isPrivateTavily = isPrivateRequestPayload(bodyObj, callerUserId);
    const tavilyHeaders = { 'cache-control': isPrivateTavily ? 'private, no-store' : 'no-store' };
    const hasInvalidUrls =
      !Array.isArray(bodyObj.urls) || bodyObj.urls.length === 0 || bodyObj.urls.length > 20;
    const releaseExtractSlots = hasInvalidUrls
      ? () => undefined
      : tryAcquireUserExtractSlots(callerUserId, countExtractPayloadUrls(bodyObj));
    if (!releaseExtractSlots) {
      return Response.json(
        {
          ok: false,
          success: false,
          ...(isPrivateTavily ? { visibility: 'private' as const } : {}),
          error: 'user_quota_exceeded',
          message: `Per-user concurrent extract limit (${MAX_CONCURRENT_EXTRACTS_PER_USER} requests / ${MAX_CONCURRENT_EXTRACT_URLS_PER_USER} URLs) exceeded.`,
        },
        { status: 429, headers: { ...tavilyHeaders, 'retry-after': '2' } },
      );
    }
    try {
      const out = await executeExtractCall({
        payload: bodyObj,
        env,
        executeHubFetch,
        selfHost: url.hostname,
        userId: callerUserId,
        source: 'compat:tavily:extract',
        ...(activeTracer ? { tracer: activeTracer } : {}),
      });
      const isPrivOut = isPrivateTavily || (out.body as { visibility?: string }).visibility === 'private';
      return Response.json(
        out.status === 200
          ? {
              ...(isPrivOut ? { visibility: 'private' as const } : {}),
              results: out.body.results,
              failed_results: out.body.failedResults,
            }
          : {
              ...out.body,
              ...(isPrivOut ? { visibility: 'private' as const } : {}),
            },
        {
          status: out.status,
          headers: {
            'cache-control': isPrivOut ? 'private, no-store' : 'no-store',
            ...(out.retryAfter ? { 'retry-after': out.retryAfter } : {}),
          },
        },
      );
    } finally {
      releaseExtractSlots();
    }
  }

  if (p === '/compat/tavily/map' && request.method === 'POST') {
    const isPrivateTavily = isPrivateRequestPayload(bodyObj, callerUserId);
    const tavilyHeaders = { 'cache-control': isPrivateTavily ? 'private, no-store' : 'no-store' };
    const releaseMapSlot = tryAcquireUserMapSlot(callerUserId);
    if (!releaseMapSlot) {
      return Response.json(
        {
          ok: false,
          success: false,
          ...(isPrivateTavily ? { visibility: 'private' as const } : {}),
          error: 'user_quota_exceeded',
          message: `Per-user concurrent map limit (${MAX_CONCURRENT_MAPS_PER_USER}) exceeded.`,
        },
        { status: 429, headers: { ...tavilyHeaders, 'retry-after': '2' } },
      );
    }
    try {
      const out = await executeMapCall({
        payload: bodyObj,
        executeHubFetch,
        selfHost: url.hostname,
        source: 'compat:tavily:map',
        ...(activeTracer ? { tracer: activeTracer } : {}),
      });
      return Response.json(
        out.status === 200
          ? {
              ...(isPrivateTavily ? { visibility: 'private' as const } : {}),
              base_url: out.body.url,
              results: out.body.links,
            }
          : {
              ...out.body,
              ...(isPrivateTavily ? { visibility: 'private' as const } : {}),
            },
        { status: out.status, headers: tavilyHeaders },
      );
    } finally {
      releaseMapSlot();
    }
  }

  return Response.json(
    {
      success: false,
      ...(isAuthCallerPrivate ? { visibility: 'private' as const } : {}),
      error: 'not_found',
    },
    { status: 404, headers: bodyErrHeaders },
  );
  };
  return activeTracer ? activeTracer.run(runCompat) : runCompat();
}
