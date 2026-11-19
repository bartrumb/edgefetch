/**
 * Unified Web & Private Collection Search (`POST /v1/search` + MCP `search`, `PR V2-2`).
 *
 * Provider Policy (strictly enforced):
 *  1. Open-web search uses official/JSON APIs ONLY: Brave Search API (`BRAVE_API_KEY`) and/or bring-your-own SearXNG
 *     JSON endpoint (`SEARXNG_URL`). Search-engine result scraping is NEVER routed through HAOS residential agents.
 *  2. Private search queries `SEARCH` D1 FTS5 collections (`collections: ["default", ...]`).
 *  3. Results across active providers are merged with Reciprocal Rank Fusion (RRF, `k = 60`), filtered by
 *     `include_domains` / `exclude_domains`, and optionally enriched with live page content (`include_raw_content`)
 *     fetched politely through EdgeFetch agents (`executeExtractCall`).
 */

import type { HubFetchExecutor } from './map-crawl';
import { COLLECTION_ID_RE, D1FtsSearchIndex, executeExtractCall } from './search-index';
import type { OptionalStorageBindings } from './storage';

const RRF_K = 60;

export interface SearchBindings extends OptionalStorageBindings {
  BRAVE_API_KEY?: string;
  SEARXNG_URL?: string;
}

export interface SearchResultEntry {
  title: string;
  url: string;
  content: string;
  score: number;
  provider: string;
  providers: string[];
  rawContent?: string;
  chunks?: unknown[];
}

export interface SearchRequestPayload {
  query?: unknown;
  q?: unknown;
  max_results?: unknown;
  maxResults?: unknown;
  limit?: unknown;
  include_domains?: unknown;
  includeDomains?: unknown;
  exclude_domains?: unknown;
  excludeDomains?: unknown;
  time_range?: unknown;
  timeRange?: unknown;
  include_raw_content?: unknown;
  includeRawContent?: unknown;
  chunks_per_source?: unknown;
  chunksPerSource?: unknown;
  include_answer?: unknown;
  includeAnswer?: unknown;
  collections?: unknown;
  collectionId?: unknown;
  target?: unknown;
  site?: unknown;
}

function normalizeDomainList(raw: unknown): string[] {
  if (!Array.isArray(raw)) return [];
  return raw
    .map((d) => (typeof d === 'string' ? d.trim().toLowerCase().replace(/^\*\./, '').replace(/\.+$/, '') : ''))
    .filter((d) => d.includes('.'))
    .slice(0, 30);
}

function hostMatchesDomainRule(hostname: string, domains: string[]): boolean {
  const h = hostname.toLowerCase().replace(/\.+$/, '');
  return domains.some((d) => h === d || h.endsWith(`.${d}`));
}

function mapBraveFreshness(timeRange: string): string | undefined {
  switch (timeRange) {
    case 'day':
    case 'd':
      return 'pd';
    case 'week':
    case 'w':
      return 'pw';
    case 'month':
    case 'm':
      return 'pm';
    case 'year':
    case 'y':
      return 'py';
    default:
      return undefined;
  }
}

function mapSearxngTimeRange(timeRange: string): string | undefined {
  switch (timeRange) {
    case 'day':
    case 'd':
      return 'day';
    case 'week':
    case 'w':
      return 'week';
    case 'month':
    case 'm':
      return 'month';
    case 'year':
    case 'y':
      return 'year';
    default:
      return undefined;
  }
}

async function queryBraveWebSearch(params: {
  apiKey: string;
  query: string;
  count: number;
  timeRange: string;
  fetchFn: typeof fetch;
}): Promise<Array<{ url: string; title: string; snippet: string }>> {
  const { apiKey, query, count, timeRange, fetchFn } = params;
  const u = new URL('https://api.search.brave.com/res/v1/web/search');
  u.searchParams.set('q', query);
  u.searchParams.set('count', String(Math.min(20, Math.max(1, count))));
  const freshness = mapBraveFreshness(timeRange);
  if (freshness) u.searchParams.set('freshness', freshness);

  const resp = await fetchFn(u.toString(), {
    method: 'GET',
    headers: {
      accept: 'application/json',
      'x-subscription-token': apiKey,
    },
    signal: AbortSignal.timeout(12_000),
  });
  if (!resp.ok) {
    await resp.body?.cancel().catch(() => undefined);
    throw new Error(`brave_http_${resp.status}`);
  }
  const json = (await resp.json()) as {
    web?: { results?: Array<{ url?: string; title?: string; description?: string }> };
  };
  const out: Array<{ url: string; title: string; snippet: string }> = [];
  for (const r of json.web?.results ?? []) {
    if (typeof r.url !== 'string') continue;
    try {
      const parsed = new URL(r.url);
      if (parsed.protocol !== 'https:') continue;
      parsed.hash = '';
      out.push({
        url: parsed.toString(),
        title: (r.title ?? '').trim() || parsed.hostname,
        snippet: (r.description ?? '').replace(/<[^>]+>/g, '').trim(),
      });
    } catch {
      // ignore
    }
  }
  return out;
}

async function querySearxngSearch(params: {
  searxngBaseUrl: string;
  query: string;
  count: number;
  timeRange: string;
  fetchFn: typeof fetch;
}): Promise<Array<{ url: string; title: string; snippet: string }>> {
  const { searxngBaseUrl, query, count, timeRange, fetchFn } = params;
  const base = new URL(searxngBaseUrl);
  if (base.protocol !== 'https:' && base.protocol !== 'http:') {
    throw new Error('invalid_searxng_url');
  }
  const searchUrl = new URL('/search', base);
  searchUrl.searchParams.set('q', query);
  searchUrl.searchParams.set('format', 'json');
  const tr = mapSearxngTimeRange(timeRange);
  if (tr) searchUrl.searchParams.set('time_range', tr);

  const resp = await fetchFn(searchUrl.toString(), {
    method: 'GET',
    headers: { accept: 'application/json' },
    signal: AbortSignal.timeout(12_000),
  });
  if (!resp.ok) {
    await resp.body?.cancel().catch(() => undefined);
    throw new Error(`searxng_http_${resp.status}`);
  }
  const json = (await resp.json()) as {
    results?: Array<{ url?: string; title?: string; content?: string }>;
  };
  const out: Array<{ url: string; title: string; snippet: string }> = [];
  for (const r of (json.results ?? []).slice(0, count * 2)) {
    if (typeof r.url !== 'string') continue;
    try {
      const parsed = new URL(r.url);
      if (parsed.protocol !== 'https:') continue;
      parsed.hash = '';
      out.push({
        url: parsed.toString(),
        title: (r.title ?? '').trim() || parsed.hostname,
        snippet: (r.content ?? '').replace(/<[^>]+>/g, '').trim(),
      });
    } catch {
      // ignore
    }
  }
  return out;
}

export async function executeSearchCall(params: {
  payload: SearchRequestPayload;
  env: SearchBindings;
  executeHubFetch: HubFetchExecutor;
  providerFetchFn?: typeof fetch;
  source?: string;
}): Promise<{ status: number; via: string; body: Record<string, unknown> }> {
  const { payload, env, executeHubFetch, providerFetchFn = fetch, source = 'search' } = params;
  const rawQuery = typeof payload.query === 'string' ? payload.query : typeof payload.q === 'string' ? payload.q : '';
  const query = rawQuery.trim();
  if (!query || query.length > 500) {
    return { status: 400, via: 'hub', body: { ok: false, error: 'invalid_query', message: 'query must be 1..500 characters' } };
  }

  const rawMax = payload.max_results ?? payload.maxResults ?? payload.limit ?? 5;
  const maxResults = typeof rawMax === 'number' && Number.isFinite(rawMax) ? Math.min(20, Math.max(1, Math.floor(rawMax))) : 5;
  const includeDomains = normalizeDomainList(payload.include_domains ?? payload.includeDomains);
  const excludeDomains = normalizeDomainList(payload.exclude_domains ?? payload.excludeDomains);
  const rawTimeRange = payload.time_range ?? payload.timeRange;
  const timeRange = typeof rawTimeRange === 'string' ? rawTimeRange.trim().toLowerCase() : '';
  const includeRawContent = Boolean(payload.include_raw_content ?? payload.includeRawContent);
  const rawChunksPer = payload.chunks_per_source ?? payload.chunksPerSource ?? 3;
  const chunksPerSource =
    typeof rawChunksPer === 'number' && Number.isFinite(rawChunksPer) ? Math.min(10, Math.max(1, Math.floor(rawChunksPer))) : 3;
  const wantsAnswer = Boolean(payload.include_answer ?? payload.includeAnswer);

  const requestedCollections: string[] = [];
  if (typeof payload.collectionId === 'string' && COLLECTION_ID_RE.test(payload.collectionId.trim())) {
    requestedCollections.push(payload.collectionId.trim());
  }
  if (Array.isArray(payload.collections)) {
    for (const c of payload.collections) {
      if (typeof c === 'string' && COLLECTION_ID_RE.test(c.trim()) && !requestedCollections.includes(c.trim())) {
        requestedCollections.push(c.trim());
      }
    }
  }

  const unhonoredOptions: string[] = [];
  if (wantsAnswer) {
    unhonoredOptions.push('include_answer');
  }
  if (timeRange && requestedCollections.length > 0 && !env.BRAVE_API_KEY && !env.SEARXNG_URL) {
    unhonoredOptions.push('time_range');
  }

  const hasBrave = Boolean(env.BRAVE_API_KEY?.trim());
  const hasSearxng = Boolean(env.SEARXNG_URL?.trim());
  const hasD1Search = Boolean(env.SEARCH);

  if (!hasBrave && !hasSearxng && (!hasD1Search || requestedCollections.length === 0)) {
    // If SEARCH D1 is bound and no collections were specified, default to searching the 'default' collection!
    if (hasD1Search) {
      requestedCollections.push('default');
    } else {
      return {
        status: 503,
        via: 'hub',
        body: {
          ok: false,
          error: 'search_providers_not_configured',
          message: 'Configure BRAVE_API_KEY, SEARXNG_URL, or bind SEARCH D1 to enable /v1/search.',
        },
      };
    }
  }

  const providerLists: Array<{ provider: string; items: Array<{ url: string; title: string; snippet: string }> }> = [];
  const providerErrors: Array<{ provider: string; error: string }> = [];

  if (hasBrave) {
    try {
      const items = await queryBraveWebSearch({
        apiKey: env.BRAVE_API_KEY!.trim(),
        query,
        count: maxResults * 2,
        timeRange,
        fetchFn: providerFetchFn,
      });
      providerLists.push({ provider: 'brave', items });
    } catch (e) {
      providerErrors.push({ provider: 'brave', error: e instanceof Error ? e.message : String(e) });
    }
  }

  if (hasSearxng) {
    try {
      const items = await querySearxngSearch({
        searxngBaseUrl: env.SEARXNG_URL!.trim(),
        query,
        count: maxResults * 2,
        timeRange,
        fetchFn: providerFetchFn,
      });
      providerLists.push({ provider: 'searxng', items });
    } catch (e) {
      providerErrors.push({ provider: 'searxng', error: e instanceof Error ? e.message : String(e) });
    }
  }

  if (hasD1Search && requestedCollections.length > 0) {
    const idx = new D1FtsSearchIndex(env.SEARCH!);
    for (const coll of requestedCollections.slice(0, 5)) {
      const hits = await idx.searchCollection({ collectionId: coll, query, limit: maxResults * 2 });
      providerLists.push({
        provider: `collection:${coll}`,
        items: hits.map((h) => ({
          url: h.url,
          title: h.title || h.heading || h.url,
          snippet: h.snippet || h.text.slice(0, 320),
        })),
      });
    }
  }

  // Reciprocal Rank Fusion (RRF, k = 60) across all active providers + domain allow/block filtering.
  const fused = new Map<
    string,
    {
      url: string;
      title: string;
      content: string;
      rrfScore: number;
      providers: string[];
    }
  >();

  for (const { provider, items } of providerLists) {
    items.forEach((item, rankIdx) => {
      let host = '';
      try {
        host = new URL(item.url).hostname;
      } catch {
        return;
      }
      if (includeDomains.length > 0 && !hostMatchesDomainRule(host, includeDomains)) return;
      if (excludeDomains.length > 0 && hostMatchesDomainRule(host, excludeDomains)) return;

      const rrfAdd = 1 / (RRF_K + rankIdx + 1);
      const existing = fused.get(item.url);
      if (existing) {
        existing.rrfScore += rrfAdd;
        if (!existing.providers.includes(provider)) existing.providers.push(provider);
        if (!existing.content && item.snippet) existing.content = item.snippet;
      } else {
        fused.set(item.url, {
          url: item.url,
          title: item.title,
          content: item.snippet,
          rrfScore: rrfAdd,
          providers: [provider],
        });
      }
    });
  }

  const ranked = [...fused.values()]
    .sort((a, b) => b.rrfScore - a.rrfScore || a.url.localeCompare(b.url))
    .slice(0, maxResults);

  // Normalize top RRF score into clean (0, 1] range while preserving relative ordering.
  const maxRrf = ranked[0]?.rrfScore ?? 1;
  const results: SearchResultEntry[] = ranked.map((r) => ({
    title: r.title,
    url: r.url,
    content: r.content,
    score: Number(Math.min(1, (r.rrfScore / Math.max(maxRrf, 1e-6)) * 0.95).toFixed(4)),
    provider: r.providers[0]!,
    providers: r.providers,
  }));

  let via = providerLists.map((p) => p.provider).join('+') || 'search';

  // Optional live page fetch + BM25 chunk reranking through EdgeFetch agents (never storing Brave snippets!).
  if (includeRawContent && results.length > 0) {
    const extractOut = await executeExtractCall({
      payload: {
        urls: results.map((r) => r.url),
        query,
        chunksPerSource,
        maxAgeMs: 300_000,
        target: payload.target,
        site: payload.site,
      },
      env,
      executeHubFetch,
      source: `${source}:enrich`,
    });
    if (extractOut.status === 200 && Array.isArray(extractOut.body.results)) {
      via = `${via}+${extractOut.via}`;
      const extByUrl = new Map<string, Record<string, unknown>>();
      for (const er of extractOut.body.results as Array<Record<string, unknown>>) {
        if (typeof er.url === 'string') extByUrl.set(er.url, er);
      }
      for (const resItem of results) {
        const enriched = extByUrl.get(resItem.url);
        if (enriched) {
          if (typeof enriched.rawContent === 'string') resItem.rawContent = enriched.rawContent;
          if (Array.isArray(enriched.chunks)) resItem.chunks = enriched.chunks;
        }
      }
    }
  }

  return {
    status: 200,
    via,
    body: {
      ok: true,
      query,
      results,
      ...(unhonoredOptions.length > 0 ? { unhonoredOptions } : {}),
      ...(providerErrors.length > 0 ? { providerErrors } : {}),
    },
  };
}
