/**
 * Unified Edge-First & Multi-Provider Web Search (`POST /v1/search` + MCP `search`).
 *
 * Politeness & Edge-First Priority Policy (strictly enforced):
 *  1. Search-engine HTML SERP scraping is NEVER routed through HAOS residential agents (preserving residential IP
 *     reputation and respecting search-engine ToS). Open-web discovery uses official JSON APIs ONLY:
 *     - Serper.dev Google SERP API (`SERPER_API_KEY`, capped at `num: 10` = 1 credit)
 *     - Brave Search API (`BRAVE_API_KEY`, politely paced + Retry-After aware)
 *     - Tavily Search API (`TAVILY_API_KEY`, `search_depth: "basic"` = 1 credit automatic fallback)
 *     - Optional self-hosted SearXNG JSON endpoint (`SEARXNG_URL`)
 *  2. Edge & Local Zero-Cost Priority Tiers ALWAYS run first when applicable:
 *     - Private `SEARCH` D1 FTS5 corpus (`collection:default` + requested collections) indexed from pages/PDFs crawled
 *       by EdgeFetch HAOS nodes ($0).
 *     - Direct HAOS Edge-Node Domain Map (`edge-map` via `executeMapCall` over `/llms.txt` + `/sitemap.xml`, $0) when
 *       a query scopes to 1-2 specific domains (`site:example.com` or `include_domains`).
 *     - 24-hour `META` D1 external SERP cache (`search_cache`, $0) so repeated queries never burn duplicate API credits.
 *  3. Results across active sources are canonicalized (`utm_*`/`gclid`/`fbclid` stripped), merged with Reciprocal Rank
 *     Fusion (RRF, `k = 60`), filtered by `include_domains` / `exclude_domains`, and optionally enriched with live page
 *     & PDF content (`include_raw_content`) fetched politely through HAOS EdgeFetch nodes first (`target: "auto"`).
 */

import { sha256HexString } from './ingest';
import { executeMapCall, type HubFetchExecutor } from './map-crawl';
import { decodeHtmlEntities } from './scrape';
import { COLLECTION_ID_RE, D1FtsSearchIndex, executeExtractCall } from './search-index';
import type { OptionalStorageBindings } from './storage';

const RRF_K = 60;
const DEFAULT_SEARCH_CACHE_MAX_AGE_MS = 24 * 60 * 60 * 1_000; // 24h SERP cache
const BRAVE_MIN_GAP_MS = 1_050; // Polite 1 req/s pacing for Brave Search API
const DEFAULT_PROVIDER_GAP_MS = 50;
const DEFAULT_429_COOLDOWN_MS = 15_000;
const MAX_429_COOLDOWN_MS = 300_000;

const TRACKING_QUERY_PARAMS = new Set([
  'utm_source',
  'utm_medium',
  'utm_campaign',
  'utm_term',
  'utm_content',
  'utm_id',
  'gclid',
  'fbclid',
  'msclkid',
  'mc_cid',
  'mc_eid',
  '_hsenc',
  '_hsmi',
]);

const SAFE_DOMAIN_RE = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/i;

export interface SearchBindings extends OptionalStorageBindings {
  SERPER_API_KEY?: string;
  BRAVE_API_KEY?: string;
  TAVILY_API_KEY?: string;
  SEARXNG_URL?: string;
  SEARCH_DISABLE_BRAVE?: string;
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
  mode?: unknown;
  providers?: unknown;
  federate?: unknown;
  max_age_ms?: unknown;
  maxAgeMs?: unknown;
  noCache?: unknown;
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

interface RawSearchHit {
  url: string;
  title: string;
  snippet: string;
  isFiller?: boolean;
  rrfWeight?: number;
}

const EDGE_MAP_QUERY_STOPWORDS = new Set([
  'the',
  'and',
  'for',
  'with',
  'from',
  'into',
  'that',
  'this',
  'how',
  'what',
  'when',
  'where',
  'using',
]);

function cleanProviderText(raw: string | undefined): string {
  if (!raw) return '';
  return decodeHtmlEntities(raw.replace(/<[^>]+>/g, ' '))
    .replace(/[\u200b\u200e\u200f\ufeff]/g, '')
    .replace(/\s+/g, ' ')
    .trim();
}

function humanizeUrlTitle(urlStr: string): string {
  try {
    const u = new URL(urlStr);
    const segments = u.pathname
      .split('/')
      .map((s) => decodeURIComponent(s).trim())
      .filter((s) => s && !/^index\.[a-z0-9]+$/i.test(s))
      .slice(-4)
      .map((seg) =>
        seg
          .replace(/\.[a-z0-9]{1,5}$/i, '')
          .replace(/[-_]+/g, ' ')
          .replace(/\b[a-z]/g, (ch) => ch.toUpperCase()),
      );
    if (segments.length === 0) return u.hostname;
    return `${segments.join(' › ')} — ${u.hostname}`;
  } catch {
    return urlStr;
  }
}

class SearchProviderRateLimitError extends Error {
  readonly retryAfterMs: number;
  constructor(provider: string, retryAfterMs: number) {
    super(`${provider}_http_429`);
    this.name = 'SearchProviderRateLimitError';
    this.retryAfterMs = retryAfterMs;
  }
}

const providerLocks = new Map<string, Promise<void>>();
const providerNextAllowedAt = new Map<string, number>();

export function resetSearchProviderPacingForTests(): void {
  providerLocks.clear();
  providerNextAllowedAt.clear();
}

function parseRetryAfterHeaderMs(raw: string | null): number {
  if (!raw) return DEFAULT_429_COOLDOWN_MS;
  const trimmed = raw.trim();
  const secs = Number(trimmed);
  if (Number.isFinite(secs) && secs > 0) {
    return Math.min(MAX_429_COOLDOWN_MS, Math.max(2_000, Math.ceil(secs * 1_000)));
  }
  const parsedDate = Date.parse(trimmed);
  if (Number.isFinite(parsedDate)) {
    const delta = parsedDate - Date.now();
    if (delta > 0) return Math.min(MAX_429_COOLDOWN_MS, Math.max(2_000, delta));
  }
  return DEFAULT_429_COOLDOWN_MS;
}

async function runWithProviderPoliteness<T>(
  provider: string,
  minGapMs: number,
  enforcePacing: boolean,
  fn: () => Promise<T>,
): Promise<T> {
  if (!enforcePacing) {
    return fn();
  }
  const nowCheck = Date.now();
  const cooldownUntil = providerNextAllowedAt.get(`${provider}:cooldown`) ?? 0;
  if (cooldownUntil > nowCheck) {
    throw new Error(`${provider}_cooldown_${Math.ceil((cooldownUntil - nowCheck) / 1_000)}s`);
  }

  const prev = providerLocks.get(provider) ?? Promise.resolve();
  let release!: () => void;
  const gate = new Promise<void>((r) => {
    release = r;
  });
  const tail = prev.then(() => gate);
  providerLocks.set(provider, tail);

  await prev;
  try {
    const now = Date.now();
    const cd = providerNextAllowedAt.get(`${provider}:cooldown`) ?? 0;
    if (cd > now) {
      throw new Error(`${provider}_cooldown_${Math.ceil((cd - now) / 1_000)}s`);
    }
    const nextAt = providerNextAllowedAt.get(provider) ?? 0;
    if (nextAt > now) {
      await new Promise((r) => setTimeout(r, nextAt - now));
    }
    providerNextAllowedAt.set(provider, Date.now() + minGapMs);
    try {
      return await fn();
    } catch (e) {
      if (e instanceof SearchProviderRateLimitError) {
        providerNextAllowedAt.set(`${provider}:cooldown`, Date.now() + e.retryAfterMs);
      }
      throw e;
    }
  } finally {
    release();
    if (providerLocks.get(provider) === tail) {
      providerLocks.delete(provider);
    }
  }
}

export function canonicalizeSearchResultUrl(rawUrl: string): string | null {
  try {
    const parsed = new URL(rawUrl.trim());
    if (parsed.protocol !== 'https:') return null;
    if (parsed.username || parsed.password) return null;
    parsed.hash = '';
    parsed.hostname = parsed.hostname.toLowerCase().replace(/\.+$/, '');
    for (const key of [...parsed.searchParams.keys()]) {
      if (TRACKING_QUERY_PARAMS.has(key.toLowerCase()) || key.toLowerCase().startsWith('utm_')) {
        parsed.searchParams.delete(key);
      }
    }
    if (parsed.pathname.length > 1 && parsed.pathname.endsWith('/')) {
      parsed.pathname = parsed.pathname.replace(/\/+$/, '');
    }
    return parsed.toString();
  } catch {
    return null;
  }
}

function normalizeDomainList(raw: unknown): string[] {
  if (!Array.isArray(raw)) return [];
  return raw
    .map((d) => (typeof d === 'string' ? d.trim().toLowerCase().replace(/^\*\./, '').replace(/\.+$/, '') : ''))
    .filter((d) => SAFE_DOMAIN_RE.test(d))
    .slice(0, 30);
}

function hostMatchesDomainRule(hostname: string, domains: string[]): boolean {
  const h = hostname.toLowerCase().replace(/\.+$/, '');
  return domains.some((d) => h === d || h.endsWith(`.${d}`));
}

function urlMatchesSitePrefixes(urlStr: string, sitePrefixes: string[]): boolean {
  if (sitePrefixes.length === 0) return true;
  const lower = urlStr.toLowerCase();
  return sitePrefixes.some(
    (p) => lower === p || lower.startsWith(`${p}/`) || lower.startsWith(`${p}?`) || lower.startsWith(`${p}.`),
  );
}

export function extractEdgeMapDomains(
  query: string,
  includeDomains: string[],
): { domains: string[]; siteDomains: string[]; siteUrls: string[]; sitePrefixes: string[]; filterTerms: string } {
  const siteMatches: string[] = [];
  const siteUrls: string[] = [];
  const sitePrefixes: string[] = [];
  const stripped = query
    .replace(/\bsite:([A-Za-z0-9.-]+\.[A-Za-z]{2,})((?:\/[^\s"')]*)?)/gi, (_m, dom: string, rawPath = '') => {
      const clean = dom.toLowerCase().replace(/^\*\./, '').replace(/\.+$/, '');
      if (SAFE_DOMAIN_RE.test(clean)) {
        if (!siteMatches.includes(clean)) siteMatches.push(clean);
        const cleanPath = rawPath.replace(/[.,;:!?]+$/, '').replace(/\/+$/, '');
        const targetUrl = cleanPath ? `https://${clean}${cleanPath}/` : `https://${clean}/`;
        if (!siteUrls.includes(targetUrl)) siteUrls.push(targetUrl);
        if (cleanPath) {
          const prefix = `https://${clean}${cleanPath}`.toLowerCase();
          if (!sitePrefixes.includes(prefix)) sitePrefixes.push(prefix);
        }
      }
      return ' ';
    })
    .replace(/\s+/g, ' ')
    .trim();

  const combined = [...new Set([...siteMatches, ...includeDomains])];
  if (combined.length === 0 || combined.length > 2) {
    return { domains: [], siteDomains: siteMatches, siteUrls: [], sitePrefixes, filterTerms: stripped };
  }
  const mapUrls = [
    ...siteUrls,
    ...includeDomains.filter((d) => !siteMatches.includes(d)).map((d) => `https://${d}/`),
  ].slice(0, 2);
  return { domains: combined, siteDomains: siteMatches, siteUrls: mapUrls, sitePrefixes, filterTerms: stripped };
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

function mapSerperTbs(timeRange: string): string | undefined {
  switch (timeRange) {
    case 'day':
    case 'd':
      return 'qdr:d';
    case 'week':
    case 'w':
      return 'qdr:w';
    case 'month':
    case 'm':
      return 'qdr:m';
    case 'year':
    case 'y':
      return 'qdr:y';
    default:
      return undefined;
  }
}

function mapStandardTimeRange(timeRange: string): 'day' | 'week' | 'month' | 'year' | undefined {
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

async function querySerperWebSearch(params: {
  apiKey: string;
  query: string;
  includeDomains: string[];
  timeRange: string;
  fetchFn: typeof fetch;
}): Promise<RawSearchHit[]> {
  const { apiKey, query, includeDomains, timeRange, fetchFn } = params;
  const hasInlineSite = /\bsite:/i.test(query);
  const effectiveQuery =
    !hasInlineSite && includeDomains.length === 1 ? `site:${includeDomains[0]} ${query}` : query;
  const tbs = mapSerperTbs(timeRange);

  const resp = await fetchFn('https://google.serper.dev/search', {
    method: 'POST',
    headers: {
      accept: 'application/json',
      'content-type': 'application/json',
      'x-api-key': apiKey,
    },
    // Strictly cap `num: 10` so every Serper query consumes 1 credit ($0.001) instead of 2 credits!
    body: JSON.stringify({
      q: effectiveQuery,
      num: 10,
      ...(tbs ? { tbs } : {}),
    }),
    signal: AbortSignal.timeout(12_000),
  });
  if (resp.status === 429) {
    const retryMs = parseRetryAfterHeaderMs(resp.headers.get('retry-after'));
    await resp.body?.cancel().catch(() => undefined);
    throw new SearchProviderRateLimitError('serper', retryMs);
  }
  if (!resp.ok) {
    await resp.body?.cancel().catch(() => undefined);
    throw new Error(`serper_http_${resp.status}`);
  }

  const json = (await resp.json()) as {
    knowledgeGraph?: { title?: string; website?: string; description?: string };
    organic?: Array<{ link?: string; title?: string; snippet?: string }>;
  };
  const out: RawSearchHit[] = [];
  if (typeof json.knowledgeGraph?.website === 'string') {
    const canon = canonicalizeSearchResultUrl(json.knowledgeGraph.website);
    if (canon) {
      out.push({
        url: canon,
        title: cleanProviderText(json.knowledgeGraph.title) || humanizeUrlTitle(canon),
        snippet: cleanProviderText(json.knowledgeGraph.description),
      });
    }
  }
  for (const r of json.organic ?? []) {
    if (typeof r.link !== 'string') continue;
    const canon = canonicalizeSearchResultUrl(r.link);
    if (!canon) continue;
    out.push({
      url: canon,
      title: cleanProviderText(r.title) || humanizeUrlTitle(canon),
      snippet: cleanProviderText(r.snippet),
    });
  }
  return out;
}

async function queryBraveWebSearch(params: {
  apiKey: string;
  query: string;
  count: number;
  timeRange: string;
  fetchFn: typeof fetch;
}): Promise<RawSearchHit[]> {
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
  if (resp.status === 429) {
    const retryMs = parseRetryAfterHeaderMs(resp.headers.get('retry-after'));
    await resp.body?.cancel().catch(() => undefined);
    throw new SearchProviderRateLimitError('brave', retryMs);
  }
  if (!resp.ok) {
    await resp.body?.cancel().catch(() => undefined);
    throw new Error(`brave_http_${resp.status}`);
  }
  const json = (await resp.json()) as {
    web?: { results?: Array<{ url?: string; title?: string; description?: string }> };
  };
  const out: RawSearchHit[] = [];
  for (const r of json.web?.results ?? []) {
    if (typeof r.url !== 'string') continue;
    const canon = canonicalizeSearchResultUrl(r.url);
    if (!canon) continue;
    out.push({
      url: canon,
      title: cleanProviderText(r.title) || humanizeUrlTitle(canon),
      snippet: cleanProviderText(r.description),
    });
  }
  return out;
}

async function queryTavilyWebSearch(params: {
  apiKey: string;
  query: string;
  count: number;
  includeDomains: string[];
  excludeDomains: string[];
  timeRange: string;
  fetchFn: typeof fetch;
}): Promise<RawSearchHit[]> {
  const { apiKey, query, count, includeDomains, excludeDomains, timeRange, fetchFn } = params;
  const tr = mapStandardTimeRange(timeRange);
  const resp = await fetchFn('https://api.tavily.com/search', {
    method: 'POST',
    headers: {
      accept: 'application/json',
      authorization: `Bearer ${apiKey}`,
      'content-type': 'application/json',
    },
    // Strictly `search_depth: "basic"` (1 credit) so fallback queries cost half of `advanced` (2 credits).
    body: JSON.stringify({
      query,
      max_results: Math.min(10, Math.max(1, count)),
      search_depth: 'basic',
      ...(includeDomains.length > 0 ? { include_domains: includeDomains } : {}),
      ...(excludeDomains.length > 0 ? { exclude_domains: excludeDomains } : {}),
      ...(tr ? { time_range: tr } : {}),
    }),
    signal: AbortSignal.timeout(15_000),
  });
  if (resp.status === 429) {
    const retryMs = parseRetryAfterHeaderMs(resp.headers.get('retry-after'));
    await resp.body?.cancel().catch(() => undefined);
    throw new SearchProviderRateLimitError('tavily', retryMs);
  }
  if (!resp.ok) {
    await resp.body?.cancel().catch(() => undefined);
    throw new Error(`tavily_http_${resp.status}`);
  }
  const json = (await resp.json()) as {
    results?: Array<{ url?: string; title?: string; content?: string }>;
  };
  const out: RawSearchHit[] = [];
  for (const r of json.results ?? []) {
    if (typeof r.url !== 'string') continue;
    const canon = canonicalizeSearchResultUrl(r.url);
    if (!canon) continue;
    out.push({
      url: canon,
      title: cleanProviderText(r.title) || humanizeUrlTitle(canon),
      snippet: cleanProviderText(r.content),
    });
  }
  return out;
}

async function querySearxngSearch(params: {
  searxngBaseUrl: string;
  query: string;
  count: number;
  timeRange: string;
  fetchFn: typeof fetch;
}): Promise<RawSearchHit[]> {
  const { searxngBaseUrl, query, count, timeRange, fetchFn } = params;
  const base = new URL(searxngBaseUrl);
  if (base.protocol !== 'https:' && base.protocol !== 'http:') {
    throw new Error('invalid_searxng_url');
  }
  const searchUrl = new URL('/search', base);
  searchUrl.searchParams.set('q', query);
  searchUrl.searchParams.set('format', 'json');
  const tr = mapStandardTimeRange(timeRange);
  if (tr) searchUrl.searchParams.set('time_range', tr);

  const resp = await fetchFn(searchUrl.toString(), {
    method: 'GET',
    headers: { accept: 'application/json' },
    signal: AbortSignal.timeout(12_000),
  });
  if (resp.status === 429) {
    const retryMs = parseRetryAfterHeaderMs(resp.headers.get('retry-after'));
    await resp.body?.cancel().catch(() => undefined);
    throw new SearchProviderRateLimitError('searxng', retryMs);
  }
  if (!resp.ok) {
    await resp.body?.cancel().catch(() => undefined);
    throw new Error(`searxng_http_${resp.status}`);
  }
  const json = (await resp.json()) as {
    results?: Array<{ url?: string; title?: string; content?: string }>;
  };
  const out: RawSearchHit[] = [];
  for (const r of (json.results ?? []).slice(0, count * 2)) {
    if (typeof r.url !== 'string') continue;
    const canon = canonicalizeSearchResultUrl(r.url);
    if (!canon) continue;
    out.push({
      url: canon,
      title: cleanProviderText(r.title) || humanizeUrlTitle(canon),
      snippet: cleanProviderText(r.content),
    });
  }
  return out;
}

const initializedSearchCacheDbs = new WeakSet<D1Database>();
let searchCacheWriteCounter = 0;

async function ensureSearchCacheTable(metaDb: D1Database): Promise<void> {
  if (initializedSearchCacheDbs.has(metaDb)) return;
  await metaDb.batch([
    metaDb.prepare(
      `CREATE TABLE IF NOT EXISTS search_cache (
        cache_key TEXT PRIMARY KEY,
        payload_json TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL
      )`,
    ),
    metaDb.prepare('CREATE INDEX IF NOT EXISTS idx_search_cache_expires ON search_cache(expires_at)'),
  ]);
  initializedSearchCacheDbs.add(metaDb);
}

async function readCachedExternalLists(
  metaDb: D1Database,
  cacheKey: string,
  now: number,
): Promise<Array<{ provider: string; items: RawSearchHit[] }> | null> {
  try {
    await ensureSearchCacheTable(metaDb);
    const row = await metaDb
      .prepare('SELECT payload_json FROM search_cache WHERE cache_key = ? AND expires_at > ? LIMIT 1')
      .bind(cacheKey, now)
      .first<{ payload_json: string }>();
    if (!row?.payload_json) return null;
    const parsed = JSON.parse(row.payload_json) as unknown;
    return Array.isArray(parsed) ? (parsed as Array<{ provider: string; items: RawSearchHit[] }>) : null;
  } catch {
    return null;
  }
}

async function writeCachedExternalLists(
  metaDb: D1Database,
  cacheKey: string,
  lists: Array<{ provider: string; items: RawSearchHit[] }>,
  now: number,
  ttlMs: number,
): Promise<void> {
  try {
    await ensureSearchCacheTable(metaDb);
    const shouldPruneExpired = (++searchCacheWriteCounter & 15) === 1;
    const upsertStmt = metaDb
      .prepare(
        `INSERT INTO search_cache (cache_key, payload_json, created_at, expires_at)
         VALUES (?, ?, ?, ?)
         ON CONFLICT(cache_key) DO UPDATE SET
           payload_json = excluded.payload_json,
           created_at = excluded.created_at,
           expires_at = excluded.expires_at`,
      )
      .bind(cacheKey, JSON.stringify(lists), now, now + ttlMs);
    if (shouldPruneExpired) {
      await metaDb.batch([metaDb.prepare('DELETE FROM search_cache WHERE expires_at <= ?').bind(now), upsertStmt]);
    } else {
      await upsertStmt.run();
    }
  } catch {
    // Cache persistence is best-effort and never fails a search call.
  }
}

function countDomainFilteredHits(
  lists: Array<{ provider: string; items: RawSearchHit[] }>,
  includeDomains: string[],
  excludeDomains: string[],
  sitePrefixes: string[] = [],
): number {
  const seen = new Set<string>();
  for (const { items } of lists) {
    for (const item of items) {
      try {
        const host = new URL(item.url).hostname;
        if (includeDomains.length > 0 && !hostMatchesDomainRule(host, includeDomains)) continue;
        if (excludeDomains.length > 0 && hostMatchesDomainRule(host, excludeDomains)) continue;
        if (!urlMatchesSitePrefixes(item.url, sitePrefixes)) continue;
        seen.add(item.url);
      } catch {
        // ignore
      }
    }
  }
  return seen.size;
}

export async function executeSearchCall(params: {
  payload: SearchRequestPayload;
  env: SearchBindings;
  executeHubFetch: HubFetchExecutor;
  providerFetchFn?: typeof fetch;
  source?: string;
}): Promise<{ status: number; via: string; body: Record<string, unknown> }> {
  const { payload, env, executeHubFetch, source = 'search' } = params;
  const providerFetchFn = params.providerFetchFn ?? fetch;
  const enforcePacing = params.providerFetchFn === undefined;

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

  const rawMode = typeof payload.mode === 'string' ? payload.mode.trim().toLowerCase() : '';
  const explicitProviders: Set<string> | null = Array.isArray(payload.providers)
    ? new Set(
        payload.providers
          .filter((p): p is string => typeof p === 'string')
          .map((p) => p.trim().toLowerCase())
          .filter(Boolean),
      )
    : null;
  // Default to `'waterfall'` (Serper runs alone first; Brave only runs as fallback if Serper returns <3 hits).
  // Pass `mode: "rrf"` (or `federate: true`) to fuse providers in parallel, or `mode: "serper"` / `providers: ["serper"]` to skip Brave completely.
  const waterfallMode = payload.federate !== true && rawMode !== 'rrf';
  const braveDisabled =
    env.SEARCH_DISABLE_BRAVE === 'true' ||
    env.SEARCH_DISABLE_BRAVE === '1' ||
    rawMode === 'serper' ||
    (explicitProviders !== null && !explicitProviders.has('brave'));

  const rawMaxAge = payload.max_age_ms ?? payload.maxAgeMs;
  const cacheMaxAgeMs =
    payload.noCache === true
      ? 0
      : typeof rawMaxAge === 'number' && Number.isFinite(rawMaxAge)
        ? Math.max(0, Math.floor(rawMaxAge))
        : DEFAULT_SEARCH_CACHE_MAX_AGE_MS;

  const explicitCollectionsPassed = payload.collectionId !== undefined || Array.isArray(payload.collections) || payload.collections === false;
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

  const hasSerper = Boolean(env.SERPER_API_KEY?.trim()) && (explicitProviders === null || explicitProviders.has('serper'));
  const hasBrave = Boolean(env.BRAVE_API_KEY?.trim()) && !braveDisabled;
  const hasTavily =
    Boolean(env.TAVILY_API_KEY?.trim()) &&
    rawMode !== 'serper' &&
    (explicitProviders === null || explicitProviders.has('tavily'));
  const hasSearxng = Boolean(env.SEARXNG_URL?.trim()) && (explicitProviders === null || explicitProviders.has('searxng'));
  const hasExternalProvider = hasSerper || hasBrave || hasTavily || hasSearxng;
  const hasD1Search = Boolean(env.SEARCH);

  // Always consult the Edge-crawled default D1 FTS5 collection at $0 when SEARCH D1 is bound unless disabled/overridden.
  if (hasD1Search && !explicitCollectionsPassed) {
    requestedCollections.push('default');
  }

  const edgeMapSpec = extractEdgeMapDomains(query, includeDomains);
  const canEdgeMap = edgeMapSpec.domains.length > 0;
  const effectiveIncludeDomains = includeDomains.length > 0 ? includeDomains : edgeMapSpec.siteDomains;

  const unhonoredOptions: string[] = [];
  if (wantsAnswer) {
    unhonoredOptions.push('include_answer');
  }
  if (timeRange && requestedCollections.length > 0 && !hasExternalProvider) {
    unhonoredOptions.push('time_range');
  }

  if (!hasExternalProvider && !canEdgeMap && (!hasD1Search || requestedCollections.length === 0)) {
    return {
      status: 503,
      via: 'hub',
      body: {
        ok: false,
        error: 'search_providers_not_configured',
        message: 'Configure SERPER_API_KEY, BRAVE_API_KEY, TAVILY_API_KEY, SEARXNG_URL, or bind SEARCH D1 to enable /v1/search.',
      },
    };
  }

  const providerLists: Array<{ provider: string; items: RawSearchHit[] }> = [];
  const collectionLists: Array<{ provider: string; items: RawSearchHit[] }> = [];
  const edgeMapLists: Array<{ provider: string; items: RawSearchHit[] }> = [];
  const edgeMapVia: string[] = [];
  const externalLists: Array<{ provider: string; items: RawSearchHit[] }> = [];
  const externalVia: string[] = [];
  const providerErrors: Array<{ provider: string; error: string }> = [];
  const viaParts: string[] = [];

  // Tier 0a ($0): Private SEARCH D1 FTS5 corpus populated by EdgeFetch HAOS nodes.
  const runCollectionSearch = async () => {
    if (!hasD1Search || requestedCollections.length === 0) return;
    const idx = new D1FtsSearchIndex(env.SEARCH!);
    const ftsQuery = edgeMapSpec.filterTerms || query;
    await Promise.all(
      requestedCollections.slice(0, 5).map(async (coll) => {
        try {
          const hits = await idx.searchCollection({ collectionId: coll, query: ftsQuery, limit: maxResults * 3 });
          const seenCollUrls = new Set<string>();
          const filteredItems: RawSearchHit[] = [];
          for (const h of hits) {
            const canon = canonicalizeSearchResultUrl(h.url);
            if (!canon || seenCollUrls.has(canon)) continue;
            try {
              const host = new URL(canon).hostname;
              if (effectiveIncludeDomains.length > 0 && !hostMatchesDomainRule(host, effectiveIncludeDomains)) continue;
              if (excludeDomains.length > 0 && hostMatchesDomainRule(host, excludeDomains)) continue;
              if (!urlMatchesSitePrefixes(canon, edgeMapSpec.sitePrefixes)) continue;
            } catch {
              continue;
            }
            seenCollUrls.add(canon);
            filteredItems.push({
              url: canon,
              title: cleanProviderText(h.title || h.heading) || humanizeUrlTitle(canon),
              snippet: cleanProviderText(h.snippet || h.text.slice(0, 320)),
            });
          }
          if (filteredItems.length > 0 || explicitCollectionsPassed) {
            collectionLists.push({
              provider: `collection:${coll}`,
              items: filteredItems,
            });
          }
        } catch {
          // Ignore empty/uninitialized collection tables
        }
      }),
    );
  };

  // Tier 0b ($0): Direct HAOS Edge-Node Domain Map (`/llms.txt` + `/sitemap.xml`) when 1-2 domains are targeted!
  const runEdgeMapSearch = async () => {
    if (!canEdgeMap) return;
    const mapTargets = edgeMapSpec.siteUrls.length > 0 ? edgeMapSpec.siteUrls : edgeMapSpec.domains.map((d) => `https://${d}/`);
    await Promise.all(
      mapTargets.map(async (targetMapUrl) => {
        const domain = (() => {
          try {
            return new URL(targetMapUrl).hostname;
          } catch {
            return targetMapUrl;
          }
        })();
        try {
          const mapOut = await executeMapCall({
            payload: {
              url: targetMapUrl,
              ...(edgeMapSpec.filterTerms ? { search: edgeMapSpec.filterTerms } : {}),
              limit: Math.max(10, maxResults * 2),
              fastEdgeMap: hasExternalProvider,
              target: payload.target ?? 'auto',
              ...(payload.site !== undefined ? { site: payload.site } : {}),
            },
            executeHubFetch,
            source: `${source}:edge-map`,
          });
          if (mapOut.status === 200 && Array.isArray(mapOut.body.entries) && mapOut.body.entries.length > 0) {
            const queryTokens = [
              ...new Set(
                (edgeMapSpec.filterTerms.toLowerCase().match(/[\p{L}\p{N}_]+/gu) ?? []).filter(
                  (t) => t.length >= 2 && !EDGE_MAP_QUERY_STOPWORDS.has(t),
                ),
              ),
            ];
            const mappedItems: RawSearchHit[] = [];
            for (const rawEntry of mapOut.body.entries as Array<{ url?: string; title?: string; description?: string; source?: string }>) {
              if (typeof rawEntry.url !== 'string') continue;
              const entrySource = rawEntry.source ?? 'sitemap';
              const cleanTitle = cleanProviderText(rawEntry.title);
              const cleanDesc = cleanProviderText(rawEntry.description);
              // Skip bare homepage/seed filler that carries neither a curated title nor keyword signal.
              if (entrySource === 'seed' || (entrySource === 'homepage' && !cleanTitle && !edgeMapSpec.filterTerms)) {
                continue;
              }
              const canon = canonicalizeSearchResultUrl(rawEntry.url);
              if (!canon || !urlMatchesSitePrefixes(canon, edgeMapSpec.sitePrefixes)) continue;
              const hayLower = `${canon} ${cleanTitle} ${cleanDesc}`.toLowerCase();
              const matchedTokens = queryTokens.filter((t) => hayLower.includes(t)).length;
              const coverage = queryTokens.length > 0 ? matchedTokens / queryTokens.length : 1;
              // Sitemap entries matching only 1 generic word out of a 3+ term technical query (e.g. "storage" on `/plans`)
              // are marked weak filler (`rrfWeight: 0.2`) so full-text Serper/Brave/FTS5 hits always outrank them.
              const isWeakMultiTermMatch = queryTokens.length >= 3 && coverage < 0.5;
              const isUntitledMapHit = !cleanTitle;
              const rrfWeight = isWeakMultiTermMatch
                ? 0.2
                : hasExternalProvider && entrySource !== 'llms.txt'
                  ? 0.8
                  : 1.0;
              mappedItems.push({
                url: canon,
                title: cleanTitle || humanizeUrlTitle(canon),
                snippet: cleanDesc || (cleanTitle ? `Listed in ${entrySource} on ${domain}` : ''),
                isFiller: isUntitledMapHit || isWeakMultiTermMatch,
                rrfWeight,
              });
            }
            if (mappedItems.length > 0) {
              edgeMapLists.push({ provider: `edge-map:${mapOut.via}`, items: mappedItems });
              edgeMapVia.push(`edge-map:${mapOut.via}`);
            }
          }
        } catch (e) {
          providerErrors.push({ provider: `edge-map:${domain}`, error: e instanceof Error ? e.message : String(e) });
        }
      }),
    );
  };

  // Tier 1+: External JSON Search APIs (with 24h META D1 cache + polite QPS pacing + Tavily basic fallback).
  const runExternalSearch = async () => {
    if (!hasExternalProvider) return;
    const now = Date.now();
    const activeProviderSig = [
      hasSerper ? 'serper' : '',
      hasBrave ? 'brave' : '',
      hasSearxng ? 'searxng' : '',
      hasTavily ? 'tavily' : '',
      waterfallMode ? 'wf' : 'fed',
    ]
      .filter(Boolean)
      .join(',');
    const cacheKey =
      env.META && cacheMaxAgeMs > 0 && enforcePacing
        ? await sha256HexString(
            JSON.stringify({
              v: 2,
              p: activeProviderSig,
              q: query.toLowerCase(),
              tr: timeRange,
              inc: includeDomains,
              exc: excludeDomains,
            }),
          )
        : '';

    const cachedExternal = cacheKey && env.META ? await readCachedExternalLists(env.META, cacheKey, now) : null;
    if (cachedExternal && cachedExternal.length > 0) {
      for (const list of cachedExternal) {
        externalLists.push(list);
      }
      externalVia.push(`cache:d1(${cachedExternal.map((c) => c.provider).join('+')})`);
      return;
    }

    const freshExternal: Array<{ provider: string; items: RawSearchHit[] }> = [];
    const minSatisfiedHits = Math.min(3, maxResults);

    const callSerper = async () => {
      if (!hasSerper) return;
      try {
        const items = await runWithProviderPoliteness('serper', DEFAULT_PROVIDER_GAP_MS, enforcePacing, () =>
          querySerperWebSearch({
            apiKey: env.SERPER_API_KEY!.trim(),
            query,
            includeDomains,
            timeRange,
            fetchFn: providerFetchFn,
          }),
        );
        freshExternal.push({ provider: 'serper', items });
      } catch (e) {
        providerErrors.push({ provider: 'serper', error: e instanceof Error ? e.message : String(e) });
      }
    };

    const callBrave = async () => {
      if (!hasBrave) return;
      try {
        const items = await runWithProviderPoliteness('brave', BRAVE_MIN_GAP_MS, enforcePacing, () =>
          queryBraveWebSearch({
            apiKey: env.BRAVE_API_KEY!.trim(),
            query,
            count: maxResults * 2,
            timeRange,
            fetchFn: providerFetchFn,
          }),
        );
        freshExternal.push({ provider: 'brave', items });
      } catch (e) {
        providerErrors.push({ provider: 'brave', error: e instanceof Error ? e.message : String(e) });
      }
    };

    const callSearxng = async () => {
      if (!hasSearxng) return;
      try {
        const items = await runWithProviderPoliteness('searxng', DEFAULT_PROVIDER_GAP_MS, enforcePacing, () =>
          querySearxngSearch({
            searxngBaseUrl: env.SEARXNG_URL!.trim(),
            query,
            count: maxResults * 2,
            timeRange,
            fetchFn: providerFetchFn,
          }),
        );
        freshExternal.push({ provider: 'searxng', items });
      } catch (e) {
        providerErrors.push({ provider: 'searxng', error: e instanceof Error ? e.message : String(e) });
      }
    };

    if (waterfallMode) {
      await callSerper();
      if (countDomainFilteredHits(freshExternal, effectiveIncludeDomains, excludeDomains, edgeMapSpec.sitePrefixes) < minSatisfiedHits) {
        await callSearxng();
      }
      if (countDomainFilteredHits(freshExternal, effectiveIncludeDomains, excludeDomains, edgeMapSpec.sitePrefixes) < minSatisfiedHits) {
        await callBrave();
      }
    } else {
      await Promise.all([callSerper(), callBrave(), callSearxng()]);
    }

    // Tavily (`basic` = 1 credit) acts as automatic fallback when primary APIs are unconfigured or return thin/failed hits!
    if (
      hasTavily &&
      countDomainFilteredHits(freshExternal, effectiveIncludeDomains, excludeDomains, edgeMapSpec.sitePrefixes) < minSatisfiedHits
    ) {
      try {
        const items = await runWithProviderPoliteness('tavily', DEFAULT_PROVIDER_GAP_MS, enforcePacing, () =>
          queryTavilyWebSearch({
            apiKey: env.TAVILY_API_KEY!.trim(),
            query,
            count: maxResults * 2,
            includeDomains,
            excludeDomains,
            timeRange,
            fetchFn: providerFetchFn,
          }),
        );
        freshExternal.push({ provider: 'tavily', items });
      } catch (e) {
        providerErrors.push({ provider: 'tavily', error: e instanceof Error ? e.message : String(e) });
      }
    }

    for (const list of freshExternal) {
      externalLists.push(list);
      externalVia.push(list.provider);
    }

    if (cacheKey && env.META && countDomainFilteredHits(freshExternal, effectiveIncludeDomains, excludeDomains) > 0) {
      await writeCachedExternalLists(env.META, cacheKey, freshExternal, now, cacheMaxAgeMs);
    }
  };

  // Execute all active discovery tiers concurrently so `edge-map` (~1.5s) and `Serper` (~0.6s) overlap instead of serializing!
  // When an external SERP provider already satisfied `minSatisfiedHits`, cap any still-running `edge-map` probe to a 2.5s
  // grace window so `Crawl-delay: 10` origins (e.g. `docs.python.org`) never stall `search` for 50s+.
  const edgeMapPromise = runEdgeMapSearch();
  await Promise.all([runCollectionSearch(), runExternalSearch()]);
  const satisfiedExternalCount = countDomainFilteredHits(
    externalLists,
    effectiveIncludeDomains,
    excludeDomains,
    edgeMapSpec.sitePrefixes,
  );
  if (hasExternalProvider && satisfiedExternalCount >= Math.min(3, maxResults)) {
    await Promise.race([edgeMapPromise, new Promise<void>((r) => setTimeout(r, 2_500))]);
  } else {
    await edgeMapPromise;
  }

  for (const em of edgeMapLists) providerLists.push(em);
  for (const v of edgeMapVia) viaParts.push(v);
  for (const ext of externalLists) providerLists.push(ext);
  for (const v of externalVia) viaParts.push(v);
  for (const cl of collectionLists) {
    providerLists.push(cl);
    if (cl.items.length > 0) viaParts.push(cl.provider);
  }

  const foreignLocaleSegRe =
    /^\/(ja|ko|zh(?:-[a-z]{2,4})?|es(?:-[a-z]{2})?|fr(?:-[a-z]{2})?|de(?:-[a-z]{2})?|pt(?:-[a-z]{2})?|ru|uk|pl|it|tr|vi|id|ar|nl|sv|cs|hu|th|he|hi|ro|el|da|fi|no)(?=\/)/i;
  const enLocaleSegRe = /^\/en(?:-[a-z]{2})?(?=\/)/i;
  const preferEnglishCanonical =
    !/[^\x00-\x7f]/.test(query) &&
    !foreignLocaleSegRe.test(query) &&
    !edgeMapSpec.sitePrefixes.some((p) => {
      try {
        return foreignLocaleSegRe.test(new URL(p).pathname);
      } catch {
        return false;
      }
    });

  const analyzeResultLocale = (urlStr: string): { isForeignLocale: boolean; canonicalKey: string } => {
    try {
      const u = new URL(urlStr);
      let p = u.pathname;
      let isForeignLocale = false;
      if (foreignLocaleSegRe.test(p)) {
        isForeignLocale = true;
        p = p.replace(foreignLocaleSegRe, '');
      } else if (enLocaleSegRe.test(p)) {
        p = p.replace(enLocaleSegRe, '');
      }
      const unversioned = p.replace(/^\/(?:dev|latest|stable|main|v?\d+(?:\.\d+){0,2})(?=\/)/i, '').replace(/\/+$/, '');
      return {
        isForeignLocale,
        canonicalKey: `${u.hostname.toLowerCase()}${unversioned.toLowerCase() || '/'}${u.search}`,
      };
    } catch {
      return { isForeignLocale: false, canonicalKey: urlStr.toLowerCase() };
    }
  };

  // Reciprocal Rank Fusion (RRF, k = 60) across all active providers + domain allow/block filtering.
  const fused = new Map<
    string,
    {
      url: string;
      title: string;
      content: string;
      rrfScore: number;
      providers: string[];
      isFiller: boolean;
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
      if (effectiveIncludeDomains.length > 0 && !hostMatchesDomainRule(host, effectiveIncludeDomains)) return;
      if (excludeDomains.length > 0 && hostMatchesDomainRule(host, excludeDomains)) return;
      if (!urlMatchesSitePrefixes(item.url, edgeMapSpec.sitePrefixes)) return;

      const isSyntheticMapSnippet = (s: string) => /^Listed in \S+ on \S+$/i.test(s);
      const rrfAdd = (item.rrfWeight ?? 1) / (RRF_K + rankIdx + 1);
      const existing = fused.get(item.url);
      if (existing) {
        existing.rrfScore += rrfAdd;
        if (!existing.providers.includes(provider)) existing.providers.push(provider);
        if (
          item.snippet &&
          (!existing.content || (isSyntheticMapSnippet(existing.content) && !isSyntheticMapSnippet(item.snippet)))
        ) {
          existing.content = item.snippet;
        }
        if (!item.isFiller) {
          existing.isFiller = false;
          if (item.title) existing.title = item.title;
        }
      } else {
        fused.set(item.url, {
          url: item.url,
          title: item.title,
          content: item.snippet,
          rrfScore: rrfAdd,
          providers: [provider],
          isFiller: Boolean(item.isFiller),
        });
      }
    });
  }

  let fusedEntries = [...fused.values()];
  if (preferEnglishCanonical && fusedEntries.length > 1) {
    const englishCanonicalKeys = new Set<string>();
    const annotated = fusedEntries.map((entry) => {
      const loc = analyzeResultLocale(entry.url);
      if (!loc.isForeignLocale) {
        englishCanonicalKeys.add(loc.canonicalKey);
      } else {
        entry.rrfScore *= 0.6;
      }
      return { entry, ...loc };
    });
    const primary = annotated
      .filter((a) => !a.isForeignLocale || !englishCanonicalKeys.has(a.canonicalKey))
      .map((a) => a.entry);
    const duplicateMirrors = annotated
      .filter((a) => a.isForeignLocale && englishCanonicalKeys.has(a.canonicalKey))
      .map((a) => ({ ...a.entry, isFiller: true }));
    fusedEntries = [...primary, ...duplicateMirrors];
  }

  const sortedAll = fusedEntries.sort((a, b) => b.rrfScore - a.rrfScore || a.url.localeCompare(b.url));
  const nonFiller = sortedAll.filter((r) => !r.isFiller);
  const ranked = (nonFiller.length >= maxResults ? nonFiller : sortedAll).slice(0, maxResults);

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

  let via = viaParts.join('+') || providerLists.map((p) => p.provider).join('+') || 'search';

  // Optional live page fetch + BM25 chunk reranking — ALWAYS prioritizing HAOS EdgeFetch nodes (`target: "auto"` -> `agent:site-*` first!).
  if (includeRawContent && results.length > 0) {
    const extractOut = await executeExtractCall({
      payload: {
        urls: results.map((r) => r.url),
        query,
        chunksPerSource,
        maxAgeMs: 3_600_000,
        ephemeral: true,
        target: payload.target ?? 'auto',
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
      cached: Boolean(viaParts.some((v) => v.startsWith('cache:d1'))),
      results,
      ...(unhonoredOptions.length > 0 ? { unhonoredOptions } : {}),
      ...(providerErrors.length > 0 ? { providerErrors } : {}),
    },
  };
}
