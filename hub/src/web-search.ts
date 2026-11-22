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

import { listRegisteredAdapters } from './extractors/registry';
import { sha256HexString } from './ingest';
import { executeMapCall, type HubFetchExecutor } from './map-crawl';
import {
  getActiveRequestTracer,
  sanitizeErrorMessageForSpan,
  sanitizeUrlForSpan,
  setActiveSpanAttribute,
  type ActiveSpanHandle,
  type RequestTracer,
  type TraceContext,
} from './otel';
import { decodeHtmlEntities } from './scrape';
import { D1FtsSearchIndex, executeExtractCall, resolveUserCollectionId } from './search-index';
import type { OptionalStorageBindings } from './storage';

const RRF_K = 60;
const DEFAULT_SEARCH_CACHE_MAX_AGE_MS = 24 * 60 * 60 * 1_000; // 24h SERP cache
const BRAVE_MIN_GAP_MS = 1_050; // Polite 1 req/s pacing for Brave Search API
const DEFAULT_PROVIDER_GAP_MS = 50;
const DEFAULT_429_COOLDOWN_MS = 15_000;
const MAX_429_COOLDOWN_MS = 300_000;
const MAX_SCOPED_QUERY_CHARS = 480;

export type SearchTopic = 'general' | 'news' | 'auto';
export type SearchQualityTier = 'adapter' | 'known_good' | 'standard' | 'demoted';

export interface SearchHostHealthSnapshot {
  okCount: number;
  challengeCount: number;
  rateLimitCount: number;
  error5xxCount: number;
}

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
  qualityTier?: SearchQualityTier;
  rawContent?: string;
  chunks?: unknown[];
}

export interface SearchRequestPayload {
  query?: unknown;
  q?: unknown;
  topic?: unknown;
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

function safeDecodeURIComponent(raw: string): string {
  try {
    return decodeURIComponent(raw);
  } catch {
    return raw;
  }
}

function stripProviderInlineTagsLinear(raw: string): string {
  if (!raw.includes('<')) return raw;
  let out = '';
  let i = 0;
  while (i < raw.length) {
    const lt = raw.indexOf('<', i);
    if (lt < 0) {
      out += raw.slice(i);
      break;
    }
    out += raw.slice(i, lt);
    const gt = raw.indexOf('>', lt + 1);
    if (gt < 0) {
      out += raw.slice(lt);
      break;
    }
    out += ' ';
    i = gt + 1;
  }
  return out;
}

function cleanProviderText(raw: string | undefined): string {
  if (!raw) return '';
  return decodeHtmlEntities(stripProviderInlineTagsLinear(raw))
    .replace(/[\u200b\u200e\u200f\ufeff]/g, '')
    .replace(/\s+/g, ' ')
    .trim();
}

function humanizeUrlTitle(urlStr: string): string {
  try {
    const u = new URL(urlStr);
    const segments = u.pathname
      .split('/')
      .map((s) => safeDecodeURIComponent(s).trim())
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
  const activeTracer = getActiveRequestTracer();
  const runInTrace = () => (activeTracer ? activeTracer.run(fn) : fn());
  if (!enforcePacing) {
    return runInTrace();
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
      return await runInTrace();
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

async function runWithProviderSpan<T>(params: {
  tracer?: RequestTracer | null;
  provider: 'serper' | 'brave' | 'tavily' | 'searxng';
  method: 'GET' | 'POST';
  requestUrl: string;
  fn: (span?: ActiveSpanHandle) => Promise<T>;
}): Promise<T> {
  const { tracer, provider, method, requestUrl, fn } = params;
  if (!tracer) return fn();
  return tracer.withSpan(
    `edgefetch.search.${provider}`,
    {
      kind: 3,
      attributes: {
        'search.provider': provider,
        'http.request.method': method,
        'url.full': sanitizeUrlForSpan(requestUrl),
      },
    },
    async (span) => {
      try {
        return await fn(span);
      } catch (err) {
        span.setStatus(false, sanitizeErrorMessageForSpan(err, `${provider}_error`));
        throw err;
      }
    },
  );
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

export function buildDomainScopedQuery(
  query: string,
  includeDomains: string[] = [],
  excludeDomains: string[] = [],
): string {
  const trimmed = query.trim();
  const hasInlineSite = /\bsite:/i.test(trimmed);
  let scoped = trimmed;

  if (!hasInlineSite) {
    if (includeDomains.length === 1) {
      const candidate = `site:${includeDomains[0]} ${trimmed}`;
      if (candidate.length <= MAX_SCOPED_QUERY_CHARS) {
        scoped = candidate;
      }
    } else if (includeDomains.length >= 2 && includeDomains.length <= 10) {
      const fullOr = `(${includeDomains.map((d) => `site:${d}`).join(' OR ')}) ${trimmed}`;
      if (fullOr.length <= MAX_SCOPED_QUERY_CHARS) {
        scoped = fullOr;
      } else {
        const fitted: string[] = [];
        for (const d of includeDomains) {
          const next = [...fitted, d];
          const cand =
            next.length === 1
              ? `site:${next[0]} ${trimmed}`
              : `(${next.map((x) => `site:${x}`).join(' OR ')}) ${trimmed}`;
          if (cand.length <= MAX_SCOPED_QUERY_CHARS) {
            fitted.push(d);
            scoped = cand;
          } else {
            break;
          }
        }
      }
    }
  }

  for (const ex of excludeDomains.slice(0, 5)) {
    if (!ex) continue;
    const tok = `-site:${ex}`;
    if (scoped.toLowerCase().includes(tok.toLowerCase())) continue;
    if (scoped.length + 1 + tok.length <= MAX_SCOPED_QUERY_CHARS) {
      scoped = `${scoped} ${tok}`;
    }
  }

  return scoped;
}

const TECHNICAL_NON_NEWS_RE =
  /\b(?:hacker\s+news\s+api|news\s+api\s+docs?|rss\s+spec|atom\s+spec|release\s+notes)\b/i;
const EXPLICIT_NEWS_INTENT_RE =
  /\b(?:top\s+news|breaking\s+news|latest\s+news|news\s+today|today'?s\s+news|headlines\s+today|today'?s\s+headlines|top\s+headlines|latest\s+headlines|breaking\s+headlines|daily\s+news|local\s+news|world\s+news|national\s+news|news\s+headlines|current\s+events|[a-z0-9._-]+\s+news\s+today)\b/i;
const FRESH_HEADLINES_RE = /\b(?:headlines|top\s+stories|news\s+stories|breaking\s+stories)\b/i;

export function normalizeSearchTopic(raw: unknown): SearchTopic {
  if (typeof raw !== 'string') return 'auto';
  const v = raw.trim().toLowerCase();
  if (v === 'news') return 'news';
  if (v === 'general') return 'general';
  return 'auto';
}

export function detectNewsSearchIntent(
  query: string,
  timeRange = '',
  topic: SearchTopic = 'auto',
): boolean {
  if (topic === 'news') return true;
  if (topic === 'general') return false;
  const q = query.trim();
  if (!q) return false;
  if (TECHNICAL_NON_NEWS_RE.test(q) && !/\b(?:breaking\s+news|news\s+today|headlines\s+today)\b/i.test(q)) {
    return false;
  }
  if (EXPLICIT_NEWS_INTENT_RE.test(q)) return true;
  const tr = timeRange.trim().toLowerCase();
  if ((tr === 'day' || tr === 'd') && FRESH_HEADLINES_RE.test(q)) {
    return true;
  }
  return false;
}

const BUILTIN_NEWS_FEED_ADAPTER_DOMAINS = [
  'npr.org',
  'feeds.npr.org',
  'bbc.com',
  'bbc.co.uk',
  'bbci.co.uk',
  'cbsnews.com',
  'nbcnews.com',
  'abcnews.go.com',
  'theguardian.com',
  'aljazeera.com',
  'dw.com',
  'arstechnica.com',
];

const KNOWN_OPEN_PUBLIC_DOMAINS = [
  'pbs.org',
  'wikipedia.org',
  'wikimedia.org',
  'arxiv.org',
  'nih.gov',
  'cdc.gov',
  'fda.gov',
  'sec.gov',
  'nasa.gov',
  'noaa.gov',
  'nist.gov',
  'who.int',
  'europa.eu',
  'ietf.org',
  'rfc-editor.org',
  'w3.org',
  'mozilla.org',
  'stlpr.org',
];

const SOCIAL_LOGIN_WALL_DOMAINS = [
  'facebook.com',
  'm.facebook.com',
  'instagram.com',
  'threads.net',
  'tiktok.com',
  'pinterest.com',
  'x.com',
  'twitter.com',
];

const VIDEO_HUB_DOMAINS = ['youtube.com', 'youtu.be'];

const HARD_ANTIBOT_PAYWALL_DOMAINS = [
  'apnews.com',
  'reuters.com',
  'wsj.com',
  'nytimes.com',
  'bloomberg.com',
  'ft.com',
];

const VIDEO_WRAPPER_PATH_RE = /\/(?:videos?|watch|live-stream|shorts)(?:\/|$)/i;

const GENERIC_NEWS_HUB_SEGMENTS = new Set([
  'news',
  'us',
  'uk',
  'world',
  'international',
  'national',
  'politics',
  'business',
  'technology',
  'tech',
  'science',
  'science_and_environment',
  'health',
  'en',
  'latest',
  'top-news',
  'breaking-news',
  'us-news',
  'uk-news',
  'world-news',
  'local',
  'moneywatch',
  'sections',
]);

let cachedAdapterExactDomains: Set<string> | null = null;
let cachedAdapterSuffixes: string[] | null = null;

function ensureAdapterDomainLookup(): { exact: Set<string>; suffixes: string[] } {
  if (cachedAdapterExactDomains && cachedAdapterSuffixes) {
    return { exact: cachedAdapterExactDomains, suffixes: cachedAdapterSuffixes };
  }
  const exact = new Set<string>(BUILTIN_NEWS_FEED_ADAPTER_DOMAINS);
  const suffixes: string[] = [];
  try {
    for (const entry of listRegisteredAdapters()) {
      for (const rawDom of entry.domains) {
        const d = rawDom.trim().toLowerCase().replace(/\.+$/, '');
        if (!d) continue;
        if (d.startsWith('*.') && !d.slice(2).includes('*')) {
          suffixes.push(d.slice(1)); // `.wikipedia.org`
        } else if (!d.includes('*')) {
          exact.add(d);
          if (d.startsWith('www.') && d.indexOf('.', 4) > 4) {
            exact.add(d.slice(4));
          }
        }
      }
    }
  } catch {
    // Fallback to built-in domains if registry unavailable
  }
  cachedAdapterExactDomains = exact;
  cachedAdapterSuffixes = suffixes;
  return { exact, suffixes };
}

function hostMatchesRegisteredAdapter(normHost: string): boolean {
  const { exact, suffixes } = ensureAdapterDomainLookup();
  if (exact.has(normHost)) return true;
  if (normHost.startsWith('www.') && exact.has(normHost.slice(4))) return true;
  for (const d of BUILTIN_NEWS_FEED_ADAPTER_DOMAINS) {
    if (normHost === d || normHost.endsWith(`.${d}`)) return true;
  }
  return suffixes.some((suf) => normHost.endsWith(suf) && normHost.length > suf.length);
}

function isGovEduMilHost(normHost: string): boolean {
  return (
    normHost.endsWith('.gov') ||
    normHost.endsWith('.mil') ||
    normHost.endsWith('.edu') ||
    normHost.endsWith('.gov.uk') ||
    normHost.endsWith('.ac.uk') ||
    normHost.endsWith('.gov.au') ||
    normHost.endsWith('.edu.au')
  );
}

export function isGenericNewsHubUrl(urlStr: string): boolean {
  try {
    const u = new URL(urlStr);
    const segs = u.pathname
      .split('/')
      .filter(Boolean)
      .map((s) => s.toLowerCase());
    if (segs.length === 0) return true;
    if (segs.length === 1) {
      return GENERIC_NEWS_HUB_SEGMENTS.has(segs[0]!);
    }
    if (
      segs.length === 2 &&
      (segs[0] === 'news' || segs[0] === 'sections' || segs[0] === 'category' || segs[0] === 'topics') &&
      GENERIC_NEWS_HUB_SEGMENTS.has(segs[1]!)
    ) {
      return true;
    }
    return false;
  } catch {
    return false;
  }
}

function isNonArticleUtilityWidgetInNewsMode(urlStr: string, normHost: string, queryLower: string): boolean {
  try {
    const u = new URL(urlStr);
    const pathLower = u.pathname.toLowerCase();
    // Static NWS point-forecast widget when user asked for general/local news rather than weather/storms
    if (
      (normHost === 'forecast.weather.gov' || (normHost.endsWith('weather.gov') && /\/(?:mapclick|zipcity)\.php$/i.test(pathLower))) &&
      !/\b(?:weather|forecast|storm|tornado|flood|hurricane|blizzard|warning|temperature|snow|rain)\b/.test(queryLower)
    ) {
      return true;
    }
    // High-school / league schedule & roster directories when query did not ask for sports schedules/rosters
    if (
      (hostMatchesDomainRule(normHost, ['maxpreps.com', 'hudl.com']) ||
        /\/(?:schedule|standings|roster|scoreboard)(?:\/|$)/i.test(pathLower)) &&
      !/\b(?:schedule|standings|roster|scores?|volleyball|football|basketball|baseball|soccer|hockey|athletics)\b/.test(queryLower)
    ) {
      return true;
    }
    return false;
  } catch {
    return false;
  }
}

export interface HostQualityOptions {
  isExplicitDomainTarget?: boolean;
  isNewsTopic?: boolean;
  getHostHealth?: ((hostname: string) => SearchHostHealthSnapshot | null) | undefined;
  snippetLength?: number;
  hasDeeperArticleUrls?: boolean;
  query?: string;
}

export function classifySearchResultQuality(
  urlStr: string,
  hostname: string,
  options: HostQualityOptions = {},
): { factor: number; qualityTier: SearchQualityTier } {
  const normHost = hostname.toLowerCase().replace(/\.+$/, '');
  const isExplicit = Boolean(options.isExplicitDomainTarget);
  const isNews = Boolean(options.isNewsTopic);
  let factor = 1.0;
  let qualityTier: SearchQualityTier = 'standard';

  let pathname = '/';
  try {
    pathname = new URL(urlStr).pathname || '/';
  } catch {
    // ignore
  }

  // 1. Base host tier (before explicit-domain floor and path adjustments)
  if (hostMatchesDomainRule(normHost, SOCIAL_LOGIN_WALL_DOMAINS)) {
    factor = 0.28;
    qualityTier = 'demoted';
  } else if (hostMatchesDomainRule(normHost, VIDEO_HUB_DOMAINS)) {
    factor = isNews ? 0.35 : 0.45;
    qualityTier = 'demoted';
  } else if (hostMatchesDomainRule(normHost, HARD_ANTIBOT_PAYWALL_DOMAINS)) {
    factor = 0.4;
    qualityTier = 'demoted';
  } else if (hostMatchesRegisteredAdapter(normHost)) {
    factor = 1.38;
    qualityTier = 'adapter';
  } else if (hostMatchesDomainRule(normHost, KNOWN_OPEN_PUBLIC_DOMAINS) || isGovEduMilHost(normHost)) {
    factor = 1.32;
    qualityTier = 'known_good';
  }

  // 2. Dynamic host-health telemetry boost / challenge demotion
  if (options.getHostHealth) {
    try {
      const health = options.getHostHealth(normHost) ?? (normHost.startsWith('www.') ? options.getHostHealth(normHost.slice(4)) : null);
      if (health) {
        if (health.challengeCount >= 2 && health.okCount === 0) {
          factor = 0.35;
          qualityTier = 'demoted';
        } else if (health.okCount >= 2 && health.challengeCount === 0) {
          if (factor === 1.0) {
            factor = 1.2;
            qualityTier = 'known_good';
          } else if (factor > 1.0) {
            factor = Math.min(1.4, Number((factor * 1.04).toFixed(4)));
          }
        }
      }
    } catch {
      // Host health callback is strictly best-effort
    }
  }

  // 3. Explicit caller domain target (`site:` or `includeDomains`) waives domain-level penalties
  if (isExplicit && factor < 1.0) {
    factor = 1.0;
    qualityTier = 'standard';
  }

  // 4. Path-level adjustments (prefer article paths over `/video/` wrappers, utility widgets, or bare empty hubs)
  if (VIDEO_WRAPPER_PATH_RE.test(pathname) && (isNews || isExplicit)) {
    factor = Number((factor * 0.45).toFixed(4));
    if (factor < 0.7) qualityTier = 'demoted';
  } else if (isNews && isNonArticleUtilityWidgetInNewsMode(urlStr, normHost, (options.query ?? '').toLowerCase())) {
    factor = 0.55;
    qualityTier = 'demoted';
  }

  if (
    isNews &&
    (options.hasDeeperArticleUrls ?? false) &&
    options.snippetLength !== undefined &&
    options.snippetLength < 25 &&
    isGenericNewsHubUrl(urlStr)
  ) {
    factor = Number((factor * 0.55).toFixed(4));
    if (factor < 0.7 && qualityTier === 'standard') qualityTier = 'demoted';
  }

  return { factor, qualityTier };
}

export function computeHostQualityFactor(
  urlStr: string,
  hostname: string,
  options: HostQualityOptions = {},
): number {
  return classifySearchResultQuality(urlStr, hostname, options).factor;
}

interface UsStateSpec {
  name: string;
  abbr: string;
  ambiguousWordAbbr?: boolean;
  metros?: string[];
  domains?: string[];
}

const US_STATES: readonly UsStateSpec[] = [
  { name: 'west virginia', abbr: 'WV', metros: ['charleston, wv', 'morgantown'] },
  { name: 'north carolina', abbr: 'NC', metros: ['charlotte', 'raleigh'], domains: ['wral.com', 'charlotteobserver.com'] },
  { name: 'south carolina', abbr: 'SC', metros: ['charleston, sc', 'columbia, sc'], domains: ['postandcourier.com'] },
  { name: 'north dakota', abbr: 'ND', metros: ['fargo', 'bismarck'] },
  { name: 'south dakota', abbr: 'SD', metros: ['sioux falls', 'rapid city'] },
  { name: 'new hampshire', abbr: 'NH', metros: ['manchester, nh', 'concord, nh'], domains: ['wmur.com'] },
  { name: 'new jersey', abbr: 'NJ', metros: ['newark', 'trenton', 'jersey city'], domains: ['nj.com'] },
  { name: 'new mexico', abbr: 'NM', metros: ['albuquerque', 'santa fe'], domains: ['abqjournal.com', 'kob.com'] },
  { name: 'new york', abbr: 'NY', metros: ['nyc', 'manhattan', 'brooklyn', 'albany', 'buffalo'] },
  { name: 'rhode island', abbr: 'RI', metros: ['providence'], domains: ['providencejournal.com', 'wpri.com'] },
  { name: 'alabama', abbr: 'AL', metros: ['birmingham', 'montgomery', 'huntsville'], domains: ['al.com'] },
  { name: 'alaska', abbr: 'AK', metros: ['anchorage', 'juneau'], domains: ['adn.com'] },
  { name: 'arizona', abbr: 'AZ', metros: ['phoenix', 'tucson', 'maricopa'], domains: ['azcentral.com', 'abc15.com'] },
  { name: 'arkansas', abbr: 'AR', metros: ['little rock', 'fayetteville, ar'], domains: ['arkansasonline.com'] },
  { name: 'california', abbr: 'CA', metros: ['los angeles', 'san francisco', 'san diego', 'sacramento'] },
  { name: 'colorado', abbr: 'CO', ambiguousWordAbbr: true, metros: ['denver', 'boulder'], domains: ['denverpost.com', '9news.com'] },
  { name: 'connecticut', abbr: 'CT', metros: ['hartford', 'new haven'], domains: ['ctinsider.com', 'courant.com'] },
  { name: 'delaware', abbr: 'DE', ambiguousWordAbbr: true, metros: ['wilmington, de', 'dover, de'], domains: ['delawareonline.com'] },
  { name: 'florida', abbr: 'FL', metros: ['miami', 'orlando', 'tampa', 'jacksonville'], domains: ['tampabay.com', 'miamiherald.com'] },
  { name: 'georgia', abbr: 'GA', metros: ['atlanta', 'savannah'], domains: ['ajc.com', '11alive.com', 'wsbtv.com'] },
  { name: 'hawaii', abbr: 'HI', ambiguousWordAbbr: true, metros: ['honolulu', 'maui'], domains: ['staradvertiser.com', 'hawaiinewsnow.com'] },
  { name: 'idaho', abbr: 'ID', ambiguousWordAbbr: true, metros: ['boise'], domains: ['idahostatesman.com', 'ktvb.com'] },
  {
    name: 'illinois',
    abbr: 'IL',
    metros: ['chicago', 'chicagoland', 'kane county', 'dupage county', 'cook county', 'naperville', 'elgin'],
    domains: ['dailyherald.com', 'chicagotribune.com', 'suntimes.com', 'abc7chicago.com', 'nbcchicago.com', 'wgntv.com', 'cbschicago.com', 'capitolnewsillinois.com'],
  },
  { name: 'indiana', abbr: 'IN', ambiguousWordAbbr: true, metros: ['indianapolis'], domains: ['indystar.com', 'wthr.com'] },
  { name: 'iowa', abbr: 'IA', metros: ['des moines', 'cedar rapids'], domains: ['desmoinesregister.com', 'kcci.com'] },
  { name: 'kansas', abbr: 'KS', metros: ['wichita', 'topeka', 'overland park', 'johnson county, ks'], domains: ['kansas.com', 'cjonline.com'] },
  { name: 'kentucky', abbr: 'KY', metros: ['louisville', 'lexington, ky'], domains: ['courier-journal.com', 'kentucky.com'] },
  { name: 'louisiana', abbr: 'LA', ambiguousWordAbbr: true, metros: ['new orleans', 'baton rouge'], domains: ['nola.com', 'theadvocate.com'] },
  { name: 'maine', abbr: 'ME', ambiguousWordAbbr: true, metros: ['portland, me', 'bangor, me'], domains: ['pressherald.com', 'bangordailynews.com'] },
  { name: 'maryland', abbr: 'MD', metros: ['baltimore', 'annapolis', 'charles county, md', 'waldorf, md'], domains: ['baltimoresun.com', 'thebaynet.com', 'somdnews.com'] },
  { name: 'massachusetts', abbr: 'MA', ambiguousWordAbbr: true, metros: ['boston', 'worcester'], domains: ['bostonglobe.com', 'masslive.com', 'wcvb.com'] },
  { name: 'michigan', abbr: 'MI', metros: ['detroit', 'grand rapids', 'lansing'], domains: ['freep.com', 'mlive.com', 'detroitnews.com'] },
  { name: 'minnesota', abbr: 'MN', metros: ['minneapolis', 'st. paul', 'twin cities'], domains: ['startribune.com', 'kare11.com', 'mprnews.org'] },
  { name: 'mississippi', abbr: 'MS', ambiguousWordAbbr: true, metros: ['jackson, ms', 'biloxi'], domains: ['clarionledger.com'] },
  {
    name: 'missouri',
    abbr: 'MO',
    metros: ['st. louis', 'saint louis', 'st louis', 'wentzville', 'o\'fallon, mo', 'st. peters', 'jefferson city'],
    domains: ['stltoday.com', 'ksdk.com', 'kmov.com', 'firstalert4.com', 'fox2now.com', 'kmox.com', 'stlpr.org', 'missouriindependent.com', 'komu.com', 'ky3.com', 'kfvs12.com', 'kshb.com', 'kmbc.com'],
  },
  { name: 'montana', abbr: 'MT', metros: ['billings', 'bozeman', 'missoula'] },
  { name: 'nebraska', abbr: 'NE', metros: ['omaha', 'lincoln, ne'], domains: ['omaha.com', 'ketv.com'] },
  { name: 'nevada', abbr: 'NV', metros: ['las vegas', 'reno'], domains: ['reviewjournal.com', 'rgj.com'] },
  { name: 'ohio', abbr: 'OH', ambiguousWordAbbr: true, metros: ['columbus, oh', 'cleveland', 'cincinnati'], domains: ['cleveland.com', 'dispatch.com', 'wcpo.com'] },
  { name: 'oklahoma', abbr: 'OK', ambiguousWordAbbr: true, metros: ['oklahoma city', 'tulsa'], domains: ['oklahoman.com', 'tulsaworld.com', 'koco.com'] },
  { name: 'oregon', abbr: 'OR', ambiguousWordAbbr: true, metros: ['portland, or', 'eugene', 'salem, or'], domains: ['oregonlive.com', 'kgw.com', 'opb.org'] },
  { name: 'pennsylvania', abbr: 'PA', ambiguousWordAbbr: true, metros: ['philadelphia', 'pittsburgh', 'harrisburg'], domains: ['inquirer.com', 'post-gazette.com', 'pennlive.com'] },
  { name: 'tennessee', abbr: 'TN', metros: ['nashville', 'memphis', 'knoxville'], domains: ['tennessean.com', 'wsmv.com'] },
  { name: 'texas', abbr: 'TX', metros: ['houston', 'dallas', 'austin', 'san antonio'], domains: ['texastribune.org', 'dallasnews.com', 'houstonchronicle.com'] },
  { name: 'utah', abbr: 'UT', metros: ['salt lake city', 'provo'], domains: ['sltrib.com', 'ksl.com'] },
  { name: 'vermont', abbr: 'VT', metros: ['burlington, vt', 'montpelier'], domains: ['vtdigger.org'] },
  { name: 'virginia', abbr: 'VA', metros: ['richmond, va', 'norfolk, va', 'virginia beach', 'roanoke'], domains: ['virginiamercury.com', 'richmond.com', 'pilotonline.com'] },
  { name: 'washington', abbr: 'WA', metros: ['seattle', 'spokane', 'tacoma'], domains: ['seattletimes.com', 'king5.com', 'komonews.com'] },
  { name: 'wisconsin', abbr: 'WI', metros: ['milwaukee', 'madison, wi', 'green bay'], domains: ['jsonline.com', 'wisn.com'] },
  { name: 'wyoming', abbr: 'WY', metros: ['cheyenne', 'casper'] },
];

function textMentionsStateFullName(textLower: string, stateName: string): boolean {
  if (stateName === 'virginia') {
    return /(?<!west\s)\bvirginia\b/.test(textLower);
  }
  if (stateName === 'washington') {
    if (/\bwashington\s*,?\s*d\.?c\.?\b/.test(textLower) && !/\bwashington\s+state\b/.test(textLower)) {
      return false;
    }
  }
  const escaped = stateName.replace(/\s+/g, '\\s+');
  return new RegExp(`\\b${escaped}\\b`).test(textLower);
}

function hitMatchesUsState(
  state: UsStateSpec,
  titleAndSnippet: string,
  titleSnippetUrlLower: string,
  normHost: string,
): boolean {
  if (textMentionsStateFullName(titleSnippetUrlLower, state.name)) return true;
  if (state.domains && hostMatchesDomainRule(normHost, state.domains)) return true;
  if (state.metros?.some((m) => titleSnippetUrlLower.includes(m))) return true;
  const commaAbbrRe = new RegExp(`,\\s*${state.abbr}(?:\\b|\\.)`, 'i');
  if (commaAbbrRe.test(titleAndSnippet)) return true;
  if (!state.ambiguousWordAbbr) {
    const upperAbbrRe = new RegExp(`\\b${state.abbr}\\b`);
    if (upperAbbrRe.test(titleAndSnippet)) return true;
  }
  return false;
}

export function extractExplicitQueryUsStates(query: string): UsStateSpec[] {
  const qLower = query.toLowerCase();
  const matched: UsStateSpec[] = [];
  for (const st of US_STATES) {
    if (textMentionsStateFullName(qLower, st.name)) {
      matched.push(st);
    }
  }
  return matched;
}

export function computeUsStateDisambiguationFactor(
  queryStates: readonly UsStateSpec[],
  hit: { title: string; snippet: string; url: string; hostname: string },
): number {
  if (queryStates.length === 0 || queryStates.length > 2) return 1.0;
  const normHost = hit.hostname.toLowerCase().replace(/\.+$/, '');
  const titleAndSnippet = `${hit.title} ${hit.snippet}`;
  const fullCombinedLower = `${titleAndSnippet} ${hit.url}`.toLowerCase();

  if (queryStates.some((st) => hitMatchesUsState(st, titleAndSnippet, fullCombinedLower, normHost))) {
    return 1.25;
  }

  const targetNames = new Set(queryStates.map((s) => s.name));
  const titleSnippetLower = titleAndSnippet.toLowerCase();
  for (const other of US_STATES) {
    if (targetNames.has(other.name)) continue;
    if (hitMatchesUsState(other, titleAndSnippet, titleSnippetLower, normHost)) {
      return 0.4;
    }
  }

  return 1.0;
}

function formatNewsAttributionPrefix(sourceRaw?: string, dateRaw?: string): string {
  const src = cleanProviderText(sourceRaw);
  const dt = cleanProviderText(dateRaw);
  if (src && dt) return `[${src} · ${dt}] `;
  if (src) return `[${src}] `;
  if (dt) return `[${dt}] `;
  return '';
}

async function querySerperWebSearch(params: {
  apiKey: string;
  query: string;
  includeDomains: string[];
  excludeDomains: string[];
  timeRange: string;
  isNewsTopic: boolean;
  fetchFn: typeof fetch;
  tracer?: RequestTracer | null;
}): Promise<RawSearchHit[]> {
  const { apiKey, query, includeDomains, excludeDomains, timeRange, isNewsTopic, fetchFn, tracer } = params;
  const effectiveQuery = buildDomainScopedQuery(query, includeDomains, excludeDomains);
  const tbs = mapSerperTbs(timeRange);
  const endpoint = isNewsTopic ? 'https://google.serper.dev/news' : 'https://google.serper.dev/search';

  return runWithProviderSpan({
    tracer,
    provider: 'serper',
    method: 'POST',
    requestUrl: endpoint,
    fn: async (span) => {
      const resp = await fetchFn(endpoint, {
        method: 'POST',
        headers: {
          accept: 'application/json',
          'content-type': 'application/json',
          'x-api-key': apiKey,
        },
        // Strictly cap `num: 10` so every Serper `/search` or `/news` query consumes 1 credit ($0.001) instead of 2 credits!
        body: JSON.stringify({
          q: effectiveQuery,
          num: 10,
          ...(tbs ? { tbs } : {}),
        }),
        signal: AbortSignal.timeout(12_000),
      });
      span?.setAttribute('http.response.status_code', resp.status);
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
        news?: Array<{ link?: string; title?: string; snippet?: string; date?: string; source?: string }>;
        organic?: Array<{ link?: string; title?: string; snippet?: string; date?: string; source?: string }>;
      };
      const out: RawSearchHit[] = [];
      const seen = new Set<string>();
      if (!isNewsTopic && typeof json.knowledgeGraph?.website === 'string') {
        const canon = canonicalizeSearchResultUrl(json.knowledgeGraph.website);
        if (canon) {
          seen.add(canon);
          out.push({
            url: canon,
            title: cleanProviderText(json.knowledgeGraph.title) || humanizeUrlTitle(canon),
            snippet: cleanProviderText(json.knowledgeGraph.description),
          });
        }
      }
      for (const r of json.news ?? []) {
        if (typeof r.link !== 'string') continue;
        const canon = canonicalizeSearchResultUrl(r.link);
        if (!canon || seen.has(canon)) continue;
        seen.add(canon);
        const cleanSnippet = cleanProviderText(r.snippet);
        const attrPrefix = formatNewsAttributionPrefix(r.source, r.date);
        const fullSnippet =
          attrPrefix && !cleanSnippet.startsWith('[')
            ? cleanSnippet
              ? `${attrPrefix}${cleanSnippet}`
              : attrPrefix.trim()
            : cleanSnippet;
        out.push({
          url: canon,
          title: cleanProviderText(r.title) || humanizeUrlTitle(canon),
          snippet: fullSnippet,
        });
      }
      for (const r of json.organic ?? []) {
        if (typeof r.link !== 'string') continue;
        const canon = canonicalizeSearchResultUrl(r.link);
        if (!canon || seen.has(canon)) continue;
        seen.add(canon);
        const cleanSnippet = cleanProviderText(r.snippet);
        const attrPrefix = isNewsTopic ? formatNewsAttributionPrefix(r.source, r.date) : '';
        const fullSnippet =
          attrPrefix && !cleanSnippet.startsWith('[')
            ? cleanSnippet
              ? `${attrPrefix}${cleanSnippet}`
              : attrPrefix.trim()
            : cleanSnippet;
        out.push({
          url: canon,
          title: cleanProviderText(r.title) || humanizeUrlTitle(canon),
          snippet: fullSnippet,
        });
      }
      span?.setAttribute('search.result_count', out.length);
      return out;
    },
  });
}

async function queryBraveWebSearch(params: {
  apiKey: string;
  query: string;
  includeDomains: string[];
  excludeDomains: string[];
  count: number;
  timeRange: string;
  isNewsTopic: boolean;
  fetchFn: typeof fetch;
  tracer?: RequestTracer | null;
}): Promise<RawSearchHit[]> {
  const { apiKey, query, includeDomains, excludeDomains, count, timeRange, isNewsTopic, fetchFn, tracer } = params;
  const effectiveQuery = buildDomainScopedQuery(query, includeDomains, excludeDomains);
  const u = new URL(
    isNewsTopic
      ? 'https://api.search.brave.com/res/v1/news/search'
      : 'https://api.search.brave.com/res/v1/web/search',
  );
  u.searchParams.set('q', effectiveQuery);
  u.searchParams.set('count', String(Math.min(20, Math.max(1, count))));
  const freshness = mapBraveFreshness(timeRange);
  if (freshness) u.searchParams.set('freshness', freshness);
  const requestUrl = u.toString();

  return runWithProviderSpan({
    tracer,
    provider: 'brave',
    method: 'GET',
    requestUrl,
    fn: async (span) => {
      const resp = await fetchFn(requestUrl, {
        method: 'GET',
        headers: {
          accept: 'application/json',
          'x-subscription-token': apiKey,
        },
        signal: AbortSignal.timeout(12_000),
      });
      span?.setAttribute('http.response.status_code', resp.status);
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
        results?: Array<{
          url?: string;
          title?: string;
          description?: string;
          age?: string;
          meta_url?: { hostname?: string; netloc?: string };
        }>;
        news?: {
          results?: Array<{
            url?: string;
            title?: string;
            description?: string;
            age?: string;
            meta_url?: { hostname?: string; netloc?: string };
          }>;
        };
        web?: { results?: Array<{ url?: string; title?: string; description?: string; age?: string }> };
      };
      const out: RawSearchHit[] = [];
      const seen = new Set<string>();
      for (const r of json.results ?? json.news?.results ?? []) {
        if (typeof r.url !== 'string') continue;
        const canon = canonicalizeSearchResultUrl(r.url);
        if (!canon || seen.has(canon)) continue;
        seen.add(canon);
        const cleanDesc = cleanProviderText(r.description);
        const sourceLabel = r.meta_url?.netloc || r.meta_url?.hostname;
        const attrPrefix = isNewsTopic ? formatNewsAttributionPrefix(sourceLabel, r.age) : '';
        const fullSnippet =
          attrPrefix && !cleanDesc.startsWith('[')
            ? cleanDesc
              ? `${attrPrefix}${cleanDesc}`
              : attrPrefix.trim()
            : cleanDesc;
        out.push({
          url: canon,
          title: cleanProviderText(r.title) || humanizeUrlTitle(canon),
          snippet: fullSnippet,
        });
      }
      for (const r of json.web?.results ?? []) {
        if (typeof r.url !== 'string') continue;
        const canon = canonicalizeSearchResultUrl(r.url);
        if (!canon || seen.has(canon)) continue;
        seen.add(canon);
        out.push({
          url: canon,
          title: cleanProviderText(r.title) || humanizeUrlTitle(canon),
          snippet: cleanProviderText(r.description),
        });
      }
      span?.setAttribute('search.result_count', out.length);
      return out;
    },
  });
}

async function queryTavilyWebSearch(params: {
  apiKey: string;
  query: string;
  count: number;
  includeDomains: string[];
  excludeDomains: string[];
  timeRange: string;
  isNewsTopic: boolean;
  fetchFn: typeof fetch;
  tracer?: RequestTracer | null;
}): Promise<RawSearchHit[]> {
  const { apiKey, query, count, includeDomains, excludeDomains, timeRange, isNewsTopic, fetchFn, tracer } = params;
  const tr = mapStandardTimeRange(timeRange);
  const endpoint = 'https://api.tavily.com/search';

  return runWithProviderSpan({
    tracer,
    provider: 'tavily',
    method: 'POST',
    requestUrl: endpoint,
    fn: async (span) => {
      const resp = await fetchFn(endpoint, {
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
          ...(isNewsTopic ? { topic: 'news' } : {}),
          ...(includeDomains.length > 0 ? { include_domains: includeDomains } : {}),
          ...(excludeDomains.length > 0 ? { exclude_domains: excludeDomains } : {}),
          ...(tr ? { time_range: tr } : {}),
        }),
        signal: AbortSignal.timeout(15_000),
      });
      span?.setAttribute('http.response.status_code', resp.status);
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
      span?.setAttribute('search.result_count', out.length);
      return out;
    },
  });
}

async function querySearxngSearch(params: {
  searxngBaseUrl: string;
  query: string;
  includeDomains: string[];
  excludeDomains: string[];
  count: number;
  timeRange: string;
  isNewsTopic: boolean;
  fetchFn: typeof fetch;
  tracer?: RequestTracer | null;
}): Promise<RawSearchHit[]> {
  const { searxngBaseUrl, query, includeDomains, excludeDomains, count, timeRange, isNewsTopic, fetchFn, tracer } = params;
  const effectiveQuery = buildDomainScopedQuery(query, includeDomains, excludeDomains);
  const base = new URL(searxngBaseUrl);
  if (base.protocol !== 'https:' && base.protocol !== 'http:') {
    throw new Error('invalid_searxng_url');
  }
  const searchUrl = new URL('/search', base);
  searchUrl.searchParams.set('q', effectiveQuery);
  searchUrl.searchParams.set('format', 'json');
  if (isNewsTopic) searchUrl.searchParams.set('categories', 'news');
  const tr = mapStandardTimeRange(timeRange);
  if (tr) searchUrl.searchParams.set('time_range', tr);
  const requestUrl = searchUrl.toString();

  return runWithProviderSpan({
    tracer,
    provider: 'searxng',
    method: 'GET',
    requestUrl,
    fn: async (span) => {
      const resp = await fetchFn(requestUrl, {
        method: 'GET',
        headers: { accept: 'application/json' },
        signal: AbortSignal.timeout(12_000),
      });
      span?.setAttribute('http.response.status_code', resp.status);
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
      span?.setAttribute('search.result_count', out.length);
      return out;
    },
  });
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
  getHostHealth?: (hostname: string) => SearchHostHealthSnapshot | null;
  source?: string;
  userId?: string;
  tracer?: RequestTracer | TraceContext;
}): Promise<{ status: number; via: string; body: Record<string, unknown> }> {
  const activeTracer = getActiveRequestTracer(params.tracer);
  const runSearchCall = async (): Promise<{ status: number; via: string; body: Record<string, unknown> }> => {
  const { payload, env, executeHubFetch, getHostHealth, source = 'search', userId = 'owner' } = params;
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
  const requestedTopic = normalizeSearchTopic(payload.topic);
  const isNewsTopic = detectNewsSearchIntent(query, timeRange, requestedTopic);
  const effectiveTopic: 'news' | 'general' = isNewsTopic ? 'news' : 'general';
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
  if (typeof payload.collectionId === 'string' && payload.collectionId.trim()) {
    const resolved = resolveUserCollectionId(payload.collectionId, userId);
    if (!resolved.ok && resolved.status === 403) {
      return { status: 403, via: 'hub', body: { ok: false, error: 'forbidden_collection', message: 'Unauthorized collectionId' } };
    }
    if (resolved.ok) requestedCollections.push(resolved.scopedId);
  }
  if (Array.isArray(payload.collections)) {
    for (const c of payload.collections) {
      if (typeof c === 'string' && c.trim()) {
        const resolved = resolveUserCollectionId(c, userId);
        if (!resolved.ok && resolved.status === 403) {
          return { status: 403, via: 'hub', body: { ok: false, error: 'forbidden_collection', message: 'Unauthorized collectionId' } };
        }
        if (resolved.ok && !requestedCollections.includes(resolved.scopedId)) {
          requestedCollections.push(resolved.scopedId);
        }
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
    const defColl = resolveUserCollectionId('default', userId);
    if (defColl.ok) requestedCollections.push(defColl.scopedId);
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
    const collTracer = getActiveRequestTracer() ?? activeTracer;
    await Promise.all(
      requestedCollections.slice(0, 5).map((coll) => {
        const execColl = async () => {
          try {
            const hits = await idx.searchCollection({
              collectionId: coll,
              query: ftsQuery,
              limit: maxResults * 3,
              ...(collTracer ? { tracer: collTracer } : {}),
            });
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
        };
        return collTracer ? collTracer.run(execColl) : execColl();
      }),
    );
  };

  // Tier 0b ($0): Direct HAOS Edge-Node Domain Map (`/llms.txt` + `/sitemap.xml`) when 1-2 domains are targeted!
  const runEdgeMapSearch = async () => {
    if (!canEdgeMap) return;
    const mapTracer = getActiveRequestTracer() ?? activeTracer;
    const mapTargets = edgeMapSpec.siteUrls.length > 0 ? edgeMapSpec.siteUrls : edgeMapSpec.domains.map((d) => `https://${d}/`);
    await Promise.all(
      mapTargets.map((targetMapUrl) => {
        const execMap = async () => {
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
            ...(mapTracer ? { tracer: mapTracer } : {}),
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
        };
        return mapTracer ? mapTracer.run(execMap) : execMap();
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
              v: 3,
              p: activeProviderSig,
              topic: effectiveTopic,
              q: query.toLowerCase(),
              tr: timeRange,
              inc: includeDomains,
              exc: excludeDomains,
            }),
          )
        : '';

    const cacheStartMs = Date.now();
    const cachedExternal = cacheKey && env.META ? await readCachedExternalLists(env.META, cacheKey, now) : null;
    if (cachedExternal && cachedExternal.length > 0) {
      for (const list of cachedExternal) {
        externalLists.push(list);
      }
      externalVia.push(`cache:d1(${cachedExternal.map((c) => c.provider).join('+')})`);
      const extTracer = getActiveRequestTracer() ?? activeTracer;
      if (extTracer) {
        const cacheSpan = extTracer.startSpan('edgefetch.search.cache', {
          kind: 1,
          startTimeMs: cacheStartMs,
          attributes: {
            'db.system': 'sqlite',
            'cache.hit': true,
            'cache.tier': 'd1-search-cache',
            'search.cache.providers': cachedExternal.map((c) => c.provider).join(','),
            'search.hit_count': cachedExternal.reduce((acc, c) => acc + c.items.length, 0),
          },
        });
        cacheSpan.setStatus(true);
        cacheSpan.end();
      }
      return;
    }

    const freshExternal: Array<{ provider: string; items: RawSearchHit[] }> = [];
    const minSatisfiedHits = Math.min(3, maxResults);
    const providerTracer = getActiveRequestTracer() ?? activeTracer;

    const callSerper = async () => {
      if (!hasSerper) return;
      try {
        const items = await runWithProviderPoliteness('serper', DEFAULT_PROVIDER_GAP_MS, enforcePacing, () =>
          querySerperWebSearch({
            apiKey: env.SERPER_API_KEY!.trim(),
            query,
            includeDomains,
            excludeDomains,
            timeRange,
            isNewsTopic,
            fetchFn: providerFetchFn,
            tracer: providerTracer,
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
            includeDomains,
            excludeDomains,
            count: maxResults * 2,
            timeRange,
            isNewsTopic,
            fetchFn: providerFetchFn,
            tracer: providerTracer,
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
            includeDomains,
            excludeDomains,
            count: maxResults * 2,
            timeRange,
            isNewsTopic,
            fetchFn: providerFetchFn,
            tracer: providerTracer,
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
            isNewsTopic,
            fetchFn: providerFetchFn,
            tracer: providerTracer,
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

  let fusedEntries = [...fused.values()].map((e) => ({
    ...e,
    qualityTier: 'standard' as SearchQualityTier,
  }));
  const hasDeeperArticleUrls = isNewsTopic && fusedEntries.some((e) => !isGenericNewsHubUrl(e.url));
  const queryUsStates = extractExplicitQueryUsStates(query);

  for (const entry of fusedEntries) {
    let entryHost = '';
    try {
      entryHost = new URL(entry.url).hostname;
    } catch {
      continue;
    }
    const isExplicitDomainTarget =
      effectiveIncludeDomains.length > 0 && hostMatchesDomainRule(entryHost, effectiveIncludeDomains);
    const { factor, qualityTier } = classifySearchResultQuality(entry.url, entryHost, {
      isExplicitDomainTarget,
      isNewsTopic,
      getHostHealth,
      snippetLength: entry.content.trim().length,
      hasDeeperArticleUrls,
      query,
    });
    const stateFactor =
      queryUsStates.length > 0
        ? computeUsStateDisambiguationFactor(queryUsStates, {
            title: entry.title,
            snippet: entry.content,
            url: entry.url,
            hostname: entryHost,
          })
        : 1.0;
    entry.rrfScore *= factor * stateFactor;
    entry.qualityTier = stateFactor < 0.7 && qualityTier === 'standard' ? 'demoted' : qualityTier;
  }

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
    qualityTier: r.qualityTier,
  }));

  let via = viaParts.join('+') || providerLists.map((p) => p.provider).join('+') || 'search';

  // Optional live page fetch + BM25 chunk reranking — ALWAYS prioritizing HAOS EdgeFetch nodes (`target: "auto"` -> `agent:site-*` first!).
  if (includeRawContent && results.length > 0) {
    const extractOut = await executeExtractCall({
      payload: {
        urls: results.map((r) => r.url),
        query,
        chunksPerSource,
        includeRawContent: true,
        maxAgeMs: 3_600_000,
        ephemeral: true,
        target: payload.target ?? 'auto',
        site: payload.site,
      },
      env,
      executeHubFetch,
      source: `${source}:enrich`,
      ...(activeTracer ? { tracer: activeTracer } : {}),
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

  const cachedFlag = Boolean(viaParts.some((v) => v.startsWith('cache:d1')));
  setActiveSpanAttribute('search.mode', waterfallMode ? 'waterfall' : 'rrf', activeTracer ?? undefined);
  setActiveSpanAttribute('search.topic', effectiveTopic, activeTracer ?? undefined);
  setActiveSpanAttribute('search.query_length', query.length, activeTracer ?? undefined);
  setActiveSpanAttribute('search.cached', cachedFlag, activeTracer ?? undefined);
  setActiveSpanAttribute('search.result_count', results.length, activeTracer ?? undefined);

  return {
    status: 200,
    via,
    body: {
      ok: true,
      query,
      topic: effectiveTopic,
      cached: cachedFlag,
      results,
      ...(unhonoredOptions.length > 0 ? { unhonoredOptions } : {}),
      ...(providerErrors.length > 0 ? { providerErrors } : {}),
    },
  };
  };
  return activeTracer ? activeTracer.run(runSearchCall) : runSearchCall();
}
