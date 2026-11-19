/**
 * Drop-in Firecrawl v2 (`/compat/firecrawl/v2/*`) and Tavily (`/compat/tavily/*`) compatibility routes (`Addition 11`).
 *
 * Allows existing `firecrawl-js` / `tavily-python` / `tavily-js` callers to point their `apiUrl` / `baseURL` directly at
 * a self-hosted EdgeFetch Hub without rewriting client code.
 */

import { MIN_TOKEN_LENGTH, sameBytes } from './auth';
import {
  cancelCrawlJob,
  createCrawlJob,
  executeCrawlJob,
  executeMapCall,
  getCrawlJobStatus,
  type HubFetchExecutor,
} from './map-crawl';
import { authorizeMcpRequest, type OAuthStore } from './oauth';
import { executeScrapeCall } from './scrape';
import { executeExtractCall } from './search-index';
import { executeSearchCall, type SearchBindings } from './web-search';

export async function handleCompatRoutes(params: {
  request: Request;
  url: URL;
  env: SearchBindings & { CALLER_TOKEN?: string; WEBHOOK_SECRET?: string };
  oauthStore: OAuthStore;
  executeHubFetch: HubFetchExecutor;
  waitUntil?: (p: Promise<unknown>) => void;
}): Promise<Response | null> {
  const { request, url, env, oauthStore, executeHubFetch, waitUntil } = params;
  const p = url.pathname;
  if (!p.startsWith('/compat/firecrawl/v2/') && !p.startsWith('/compat/tavily/')) {
    return null;
  }

  let bodyObj: Record<string, unknown> = {};
  if (request.method === 'POST') {
    try {
      bodyObj = (await request.json()) as Record<string, unknown>;
    } catch {
      return Response.json({ success: false, error: 'bad_json' }, { status: 400 });
    }
  }

  // Tavily SDKs pass `{ api_key: "tvly-..." }` in the POST JSON body; Firecrawl SDKs pass `Authorization: Bearer ...`.
  let authorized = false;
  const auth = await authorizeMcpRequest({
    request,
    origin: url.origin,
    ownerSecret: env.CALLER_TOKEN,
    store: oauthStore,
  });
  if (auth.ok && auth.scopes.includes('crawl:fetch')) {
    authorized = true;
  } else if (
    p.startsWith('/compat/tavily/') &&
    typeof bodyObj.api_key === 'string' &&
    env.CALLER_TOKEN &&
    env.CALLER_TOKEN.length >= MIN_TOKEN_LENGTH &&
    sameBytes(bodyObj.api_key.trim(), env.CALLER_TOKEN)
  ) {
    authorized = true;
  }

  if (!authorized) {
    return Response.json({ success: false, error: 'unauthorized' }, { status: 401, headers: { 'cache-control': 'no-store' } });
  }

  // ── Firecrawl v2 Compatibility Surface ──
  if (p === '/compat/firecrawl/v2/scrape' && request.method === 'POST') {
    const out = await executeScrapeCall({
      payload: {
        ...bodyObj,
        maxAgeMs: typeof bodyObj.maxAge === 'number' ? bodyObj.maxAge : bodyObj.maxAgeMs,
      },
      env,
      executeHubFetch,
      source: 'compat:firecrawl:scrape',
    });
    if (out.status !== 200) {
      return Response.json({ success: false, ...out.body }, { status: out.status });
    }
    return Response.json({ success: true, data: out.body }, { status: 200 });
  }

  if (p === '/compat/firecrawl/v2/map' && request.method === 'POST') {
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

  if (p === '/compat/firecrawl/v2/crawl' && request.method === 'POST') {
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
    });
    if (bodyObj.sync === true) {
      await jobPromise;
    } else if (waitUntil) {
      waitUntil(jobPromise);
    } else {
      await jobPromise;
    }
    return Response.json({ success: true, id: created.crawlId, url: `${url.origin}/compat/firecrawl/v2/crawl/${created.crawlId}` });
  }

  const fcCrawlMatch = /^\/compat\/firecrawl\/v2\/crawl\/([^/]+)$/.exec(p);
  if (fcCrawlMatch) {
    const crawlId = decodeURIComponent(fcCrawlMatch[1] ?? '');
    if (request.method === 'GET') {
      const st = await getCrawlJobStatus({ crawlId, metaDb: env.META, bucket: env.ARTIFACTS });
      if (!st.ok) return Response.json({ success: false, error: st.error }, { status: st.status });
      return Response.json({ success: true, ...st.crawl });
    }
    if (request.method === 'DELETE') {
      const del = await cancelCrawlJob(crawlId, env.META);
      return Response.json({ success: del.ok, status: 'cancelled' }, { status: del.status });
    }
  }

  if (p === '/compat/firecrawl/v2/search' && request.method === 'POST') {
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
