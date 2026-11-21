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
import type { LlmEnvBindings } from './llm';
import {
  cancelBatchScrape,
  cancelCrawlJob,
  createCrawlJob,
  executeCrawlJob,
  executeMapCall,
  getBatchScrapeStatus,
  getCrawlJobStatus,
  previewCrawlParams,
  startOrExecuteBatchScrape,
  type HubFetchExecutor,
} from './map-crawl';
import { authorizeMcpRequest, type OAuthStore } from './oauth';
import { readBodyTextCapped, safeDecodeURIComponent } from './safe-input';
import { executeScrapeCall } from './scrape';
import { executeExtractCall } from './search-index';
import type { OptionalStorageBindings } from './storage';
import { executeSearchCall, type SearchBindings } from './web-search';

export async function handleCompatRoutes(params: {
  request: Request;
  url: URL;
  env: OptionalStorageBindings & SearchBindings & LlmEnvBindings & { CALLER_TOKEN?: string; MCP_TOKEN?: string; WEBHOOK_SECRET?: string };
  oauthStore: OAuthStore;
  executeHubFetch: HubFetchExecutor;
  waitUntil?: (p: Promise<unknown>) => void;
}): Promise<Response | null> {
  const { request, url, env, oauthStore, executeHubFetch, waitUntil } = params;
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
  if (auth.ok && auth.scopes.includes('crawl:fetch')) {
    authorized = true;
  } else if (!isTavily || request.method !== 'POST') {
    await request.body?.cancel().catch(() => undefined);
    return Response.json({ success: false, error: 'unauthorized' }, { status: 401, headers: { 'cache-control': 'no-store' } });
  }

  let bodyObj: Record<string, unknown> = {};
  if (request.method === 'POST') {
    const maxBytes = authorized ? MAX_CALL_UTF8_BYTES : 64 * 1024;
    const capped = await readBodyTextCapped(request, maxBytes);
    if (!capped.ok) {
      return Response.json({ success: false, error: 'too_large' }, { status: 413 });
    }
    try {
      const parsed = JSON.parse(capped.text);
      if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
        return Response.json({ success: false, error: 'bad_json' }, { status: 400 });
      }
      bodyObj = parsed as Record<string, unknown>;
    } catch {
      return Response.json({ success: false, error: 'bad_json' }, { status: 400 });
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
    return Response.json({ success: false, error: 'unauthorized' }, { status: 401, headers: { 'cache-control': 'no-store' } });
  }

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
      source: 'compat:firecrawl:scrape',
    });
    if (out.status !== 200) {
      return Response.json({ success: false, ...out.body }, { status: out.status });
    }
    return Response.json({ success: true, data: out.body }, { status: 200 });
  }

  if (fcSubpath === '/map' && request.method === 'POST') {
    const out = await executeMapCall({
      payload: bodyObj,
      executeHubFetch,
      selfHost: url.hostname,
      source: 'compat:firecrawl:map',
    });
    return Response.json(
      out.status === 200 ? { success: true, links: out.body.links, entries: out.body.entries } : { success: false, ...out.body },
      { status: out.status },
    );
  }

  if (fcSubpath === '/crawl/params-preview' && request.method === 'POST') {
    const prev = previewCrawlParams(bodyObj, url.hostname);
    return Response.json(prev.body, { status: prev.status });
  }

  if (fcSubpath === '/crawl' && request.method === 'POST') {
    const created = await createCrawlJob({ payload: bodyObj, metaDb: env.META, selfHost: url.hostname });
    if (!created.ok) {
      return Response.json({ success: false, error: created.error, message: created.message }, { status: created.status });
    }
    const jobPromise = executeCrawlJob({
      crawlId: created.crawlId,
      rootUrl: created.rootUrl,
      options: created.options,
      env,
      executeHubFetch,
      selfHost: url.hostname,
      waitUntilBounded: Boolean(waitUntil) && bodyObj.sync !== true,
    });
    if (bodyObj.sync === true) {
      await jobPromise;
    } else if (waitUntil) {
      waitUntil(jobPromise);
    } else {
      await jobPromise;
    }
    return Response.json({ success: true, id: created.crawlId, url: `${url.origin}${fcPrefix}/crawl/${created.crawlId}` });
  }

  const fcCrawlMatch = /^\/crawl\/([^/]+)$/.exec(fcSubpath);
  if (fcCrawlMatch && fcCrawlMatch[1] !== 'params-preview') {
    const crawlId = safeDecodeURIComponent(fcCrawlMatch[1] ?? '');
    if (crawlId === null) return Response.json({ success: false, error: 'bad_request' }, { status: 400 });
    if (request.method === 'GET') {
      const rawOffset = Number(url.searchParams.get('offset') ?? 0);
      const rawLimit = Number(url.searchParams.get('limit') ?? 25);
      const st = await getCrawlJobStatus({
        crawlId,
        metaDb: env.META,
        bucket: env.ARTIFACTS,
        offset: Number.isFinite(rawOffset) ? rawOffset : 0,
        limit: Number.isFinite(rawLimit) ? rawLimit : 25,
      });
      if (!st.ok) return Response.json({ success: false, error: st.error }, { status: st.status });
      return Response.json({ success: true, ...st.crawl });
    }
    if (request.method === 'DELETE') {
      const del = await cancelCrawlJob(crawlId, env.META);
      return Response.json({ success: del.ok, status: 'cancelled' }, { status: del.status });
    }
  }

  if (fcSubpath === '/batch/scrape' && request.method === 'POST') {
    const batchOut = await startOrExecuteBatchScrape({
      payload: bodyObj,
      selfHost: url.hostname,
      executeScrape: async (scArgs) => {
        const res = await executeScrapeCall({
          payload: scArgs,
          env,
          executeHubFetch,
          selfHost: url.hostname,
          source: 'compat:firecrawl:batch-scrape',
        });
        return { status: res.status, body: res.body };
      },
      ...(waitUntil ? { waitUntil } : {}),
    });
    if (!batchOut.ok) {
      return Response.json({ success: false, error: batchOut.error, message: batchOut.message }, { status: batchOut.status });
    }
    return Response.json(
      {
        success: true,
        id: batchOut.job.id,
        url: `${url.origin}${fcPrefix}/batch/scrape/${batchOut.job.id}`,
        ...(bodyObj.sync === true ? { status: batchOut.job.status, total: batchOut.job.total, completed: batchOut.job.completed, data: batchOut.job.data } : {}),
      },
      { status: 200 },
    );
  }

  const fcBatchMatch = /^\/batch\/scrape\/([^/]+)$/.exec(fcSubpath);
  if (fcBatchMatch) {
    const batchId = safeDecodeURIComponent(fcBatchMatch[1] ?? '');
    if (batchId === null) return Response.json({ success: false, error: 'bad_request' }, { status: 400 });
    if (request.method === 'GET') {
      const job = getBatchScrapeStatus(batchId);
      if (!job) return Response.json({ success: false, error: 'batch_not_found' }, { status: 404 });
      return Response.json({
        success: true,
        status: job.status,
        total: job.total,
        completed: job.completed,
        creditsUsed: 0,
        expiresAt: new Date(job.expiresAt).toISOString(),
        data: job.data,
        ...(job.errors.length > 0 ? { errors: job.errors } : {}),
      });
    }
    if (request.method === 'DELETE') {
      const ok = cancelBatchScrape(batchId);
      return Response.json({ success: ok, message: ok ? 'Batch scrape job cancelled' : 'Batch not found' }, { status: ok ? 200 : 404 });
    }
  }

  if (fcSubpath === '/search' && request.method === 'POST') {
    const out = await executeSearchCall({
      payload: bodyObj,
      env,
      executeHubFetch,
      source: 'compat:firecrawl:search',
    });
    return Response.json(
      out.status === 200 ? { success: true, data: out.body.results, ...out.body } : { success: false, ...out.body },
      { status: out.status },
    );
  }

  // ── Firecrawl `/v2/agent` Drop-In Compatibility (with SSE + BYO-LLM + Dynamic Adapter Router) ──
  if (fcSubpath === '/agent' && request.method === 'POST') {
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
      wantSseStream: wantSse,
      ...(waitUntil ? { waitUntil } : {}),
    });
    if (out.kind === 'sse') return out.response;
    return Response.json(out.body, { status: out.status });
  }

  const fcAgentTraceMatch = /^\/agent\/([^/]+)\/trace$/.exec(fcSubpath);
  if (fcAgentTraceMatch && request.method === 'GET') {
    const agentId = safeDecodeURIComponent(fcAgentTraceMatch[1] ?? '');
    if (agentId === null) return Response.json({ success: false, error: 'bad_request' }, { status: 400 });
    const rec = await loadAgentRun(agentId, env.META);
    if (!rec) return Response.json({ success: false, error: 'agent_not_found' }, { status: 404 });
    return Response.json({
      success: true,
      id: rec.id,
      threadId: rec.threadId,
      status: rec.status,
      count: rec.trace.length,
      spans: rec.trace,
      trace: rec.trace,
      events: rec.trace,
    });
  }

  const fcAgentMatch = /^\/agent\/([^/]+)$/.exec(fcSubpath);
  if (fcAgentMatch) {
    const agentId = safeDecodeURIComponent(fcAgentMatch[1] ?? '');
    if (agentId === null) return Response.json({ success: false, error: 'bad_request' }, { status: 400 });
    if (request.method === 'GET') {
      const rec = await loadAgentRun(agentId, env.META);
      if (!rec) return Response.json({ success: false, error: 'agent_not_found' }, { status: 404 });
      return Response.json(formatPublicAgentResponse(rec, false));
    }
    if (request.method === 'DELETE') {
      const cRes = await cancelAgentRun(agentId, env.META);
      return Response.json({ success: cRes.ok }, { status: cRes.status });
    }
  }

  // ── Tavily Compatibility Surface ──
  if (p === '/compat/tavily/search' && request.method === 'POST') {
    const out = await executeSearchCall({
      payload: bodyObj,
      env,
      executeHubFetch,
      source: 'compat:tavily:search',
    });
    return Response.json(out.body, { status: out.status });
  }

  if (p === '/compat/tavily/extract' && request.method === 'POST') {
    const out = await executeExtractCall({
      payload: bodyObj,
      env,
      executeHubFetch,
      selfHost: url.hostname,
      source: 'compat:tavily:extract',
    });
    return Response.json(
      out.status === 200
        ? { results: out.body.results, failed_results: out.body.failedResults }
        : out.body,
      { status: out.status },
    );
  }

  if (p === '/compat/tavily/map' && request.method === 'POST') {
    const out = await executeMapCall({
      payload: bodyObj,
      executeHubFetch,
      selfHost: url.hostname,
      source: 'compat:tavily:map',
    });
    return Response.json(
      out.status === 200 ? { base_url: out.body.url, results: out.body.links } : out.body,
      { status: out.status },
    );
  }

  return Response.json({ success: false, error: 'not_found' }, { status: 404 });
}
