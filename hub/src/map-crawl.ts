/**
 * Site URL discovery (`POST /v1/map`), async site `crawl` (`POST /v1/crawl`, `GET/DELETE /v1/crawl/:id`, `CrawlWorkflow`),
 * signed HMAC-SHA256 webhook delivery, and Markdown change-tracking diffs (`PR V2-2`).
 */

import { WorkflowEntrypoint, type WorkflowEvent, type WorkflowStep } from 'cloudflare:workers';
import { getActiveCallerAuthContext } from './oauth';
import { cloudflareOverflowFetch, isSafePublicHostname } from './overflow';
import { getActiveRequestTracer, sanitizeUrlForSpan, type RequestTracer, type TraceContext } from './otel';
import { getRegistrableDomain, hasPrivateSharedHostingSuffix, isPublicOrPrivateSuffix } from './psl';
import {
  asciiLower,
  compileSafeUserRegex,
  compileSafeUserRegexUnion,
  isTagNameBoundary,
  MAX_HTML_SCAN_CHARS,
  replacePairedHtmlElementsLinear,
  stripHtmlCommentsLinear,
  stripHtmlTagsLinear,
  stripHtmlTagsQuoteAwareLinear,
} from './safe-input';
import {
  cleanPdfMarkdown,
  decodeHtmlEntities,
  decodeMarkdownEntities,
  extractHtmlDocument,
  extractMarkdownLinksAndImages,
  extractPdfTitle,
  formatDelimitedTableToMarkdown,
  formatFeedXmlToMarkdown,
  formatGitPatchToMarkdown,
  formatIcalendarToMarkdown,
  formatSourceCodeUrlToMarkdown,
  formatVcardToMarkdown,
  parseLlmsTxt,
  parseMarkdownFrontmatter,
  recordCompanionMdUrl,
  sanitizeInlineHtmlInMarkdown,
  SCRAPE_PIPELINE_VERSION,
  tryParseJsonPayloadForScrape,
} from './scrape';
import {
  COLLECTION_ID_RE,
  D1FtsSearchIndex,
  ensureD1ColumnIfMissing,
  INTERNAL_COLLECTION_ID_RE,
  resolveUserCollectionId,
} from './search-index';
import {
  r2DerivedKey,
  r2PrivateDerivedKey,
  readVerifiedArtifactFromR2,
  sanitizeStorageUserId,
  type ArtifactRetention,
  type OptionalStorageBindings,
} from './storage';
import { getCachedWikipediaSitemapUrls, isWikipediaHost, setCachedWikipediaSitemapUrls } from './wikipedia';

export const MAX_CONCURRENT_MAPS_PER_USER = 4;
export const MAX_CONCURRENT_EXTRACTS_PER_USER = 4;
export const MAX_CONCURRENT_EXTRACT_URLS_PER_USER = 16;

const inFlightMapsByUser = new Map<string, number>();
const inFlightExtractsByUser = new Map<string, number>();
const inFlightExtractUrlsByUser = new Map<string, number>();

export function countExtractPayloadUrls(payload: unknown): number {
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) return 1;
  const obj = payload as { urls?: unknown; url?: unknown };
  if (Array.isArray(obj.urls)) {
    const seen = new Set<string>();
    for (const u of obj.urls) {
      if (typeof u === 'string' && u.trim()) {
        seen.add(u.trim());
      }
    }
    return Math.max(1, seen.size || obj.urls.length);
  }
  return 1;
}

export function tryAcquireUserMapSlot(userId: string | undefined): (() => void) | null {
  const key = (userId ?? '').trim() || 'owner';
  const cur = inFlightMapsByUser.get(key) ?? 0;
  if (cur >= MAX_CONCURRENT_MAPS_PER_USER) return null;
  inFlightMapsByUser.set(key, cur + 1);
  let released = false;
  return () => {
    if (released) return;
    released = true;
    const next = (inFlightMapsByUser.get(key) ?? 1) - 1;
    if (next <= 0) inFlightMapsByUser.delete(key);
    else inFlightMapsByUser.set(key, next);
  };
}

export function tryAcquireUserExtractSlots(
  userId: string | undefined,
  urlFanout: number,
): (() => void) | null {
  const key = (userId ?? '').trim() || 'owner';
  const cost = Math.max(1, Math.floor(urlFanout));
  const curReqs = inFlightExtractsByUser.get(key) ?? 0;
  const curUrls = inFlightExtractUrlsByUser.get(key) ?? 0;
  if (curReqs >= MAX_CONCURRENT_EXTRACTS_PER_USER || curUrls + cost > MAX_CONCURRENT_EXTRACT_URLS_PER_USER) {
    return null;
  }
  inFlightExtractsByUser.set(key, curReqs + 1);
  inFlightExtractUrlsByUser.set(key, curUrls + cost);
  let released = false;
  return () => {
    if (released) return;
    released = true;
    const nextReqs = (inFlightExtractsByUser.get(key) ?? 1) - 1;
    if (nextReqs <= 0) inFlightExtractsByUser.delete(key);
    else inFlightExtractsByUser.set(key, nextReqs);
    const nextUrls = (inFlightExtractUrlsByUser.get(key) ?? cost) - cost;
    if (nextUrls <= 0) inFlightExtractUrlsByUser.delete(key);
    else inFlightExtractUrlsByUser.set(key, nextUrls);
  };
}

export type HubFetchExecutor = (
  target: 'auto' | 'agent' | 'container',
  body: string,
  site?: string,
  source?: string,
  artifactRetention?: ArtifactRetention | 'off',
  hydrateInline?: boolean,
  collectionId?: string,
  crawlId?: string,
) => Promise<{ status: number; via: string; bodyText: string; retryAfter?: string }>;

function isSafeDomainHost(hostname: string, selfHost?: string): boolean {
  return isSafePublicHostname(hostname, selfHost);
}

function validatePublicHttpsUrl(raw: unknown, selfHost?: string): { ok: true; url: URL } | { ok: false; message: string } {
  if (typeof raw !== 'string' || !raw.trim()) {
    return { ok: false, message: 'url must be a non-empty https:// string' };
  }
  let u: URL;
  try {
    u = new URL(raw.trim());
  } catch {
    return { ok: false, message: `invalid URL: ${raw}` };
  }
  if (u.protocol !== 'https:' || (u.port && u.port !== '443') || u.username || u.password) {
    return { ok: false, message: 'only public https:// URLs on port 443 without credentials are permitted' };
  }
  if (!isSafeDomainHost(u.hostname, selfHost)) {
    return { ok: false, message: `disallowed hostname: ${u.hostname}` };
  }
  u.hash = '';
  return { ok: true, url: u };
}

function matchesHostScope(candidateHost: string, rootHost: string, allowSubdomains: boolean): boolean {
  const ch = candidateHost.toLowerCase().replace(/\.+$/, '');
  const rh = rootHost.toLowerCase().replace(/\.+$/, '');
  if (ch === rh) return true;
  const bareRoot = rh.startsWith('www.') ? rh.slice(4) : rh;
  if (ch === `www.${bareRoot}` || ch === bareRoot) return true;
  return allowSubdomains && ch.endsWith(`.${bareRoot}`);
}

/** Extracts `Sitemap:` URLs declared inside a `/robots.txt` file. */
export function extractRobotsSitemaps(robotsText: string, origin: string): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  for (const rawLine of robotsText.split(/\r?\n/)) {
    const line = rawLine.replace(/#.*$/, '').trim();
    const m = /^sitemap\s*:\s*(\S+)$/i.exec(line);
    if (!m?.[1]) continue;
    try {
      const u = new URL(m[1], origin);
      if (u.protocol === 'https:' && !seen.has(u.toString())) {
        seen.add(u.toString());
        out.push(u.toString());
        if (out.length >= 10) break;
      }
    } catch {
      // ignore malformed sitemap directive
    }
  }
  return out;
}

function safeDecodeURIComponent(raw: string): string {
  try {
    return decodeURIComponent(raw);
  } catch {
    return raw;
  }
}

function unwrapXmlCdataLinear(raw: string): string {
  if (!raw.includes('<![CDATA[')) return raw;
  let out = '';
  let pos = 0;
  while (pos < raw.length) {
    const start = raw.indexOf('<![CDATA[', pos);
    if (start < 0) {
      out += raw.slice(pos);
      break;
    }
    out += raw.slice(pos, start);
    const end = raw.indexOf(']]>', start + 9);
    if (end < 0) {
      out += raw.slice(start + 9);
      break;
    }
    out += raw.slice(start + 9, end);
    pos = end + 3;
  }
  return out;
}

/** Parses XML `<sitemapindex>` and `<urlset>` `<loc>` entries in guaranteed linear O(N) time (`R3-H1`). */
export function parseSitemapXml(xmlText: string): { isIndex: boolean; locs: string[] } {
  const bounded = xmlText.length > 4 * 1024 * 1024 ? xmlText.slice(0, 4 * 1024 * 1024) : xmlText;
  const isIndex = /<\s*sitemapindex\b/i.test(bounded.slice(0, 4_096));
  const locs: string[] = [];
  const seen = new Set<string>();
  const lower = asciiLower(bounded);
  let pos = 0;

  while (pos < bounded.length && locs.length < 5_000) {
    const openIdx = lower.indexOf('<loc', pos);
    if (openIdx < 0) break;
    const afterName = openIdx + 4;
    if (afterName >= bounded.length) break;
    const boundaryCode = bounded.charCodeAt(afterName);
    if (!isTagNameBoundary(boundaryCode)) {
      pos = afterName;
      continue;
    }
    const openGt = bounded.indexOf('>', afterName);
    if (openGt < 0) break;
    if (bounded.charCodeAt(openGt - 1) === 0x2f /* self-closing <loc/> */) {
      pos = openGt + 1;
      continue;
    }
    const closeIdx = lower.indexOf('</loc', openGt + 1);
    if (closeIdx < 0) break;
    const afterCloseName = closeIdx + 5;
    if (afterCloseName >= bounded.length) break;
    const closeGt = bounded.indexOf('>', afterCloseName);
    if (closeGt < 0) break;

    // Handle malformed unclosed `<loc>` before a valid `<loc>...</loc>` by taking the last `<loc...>` before `closeIdx`.
    let innerStart = openGt + 1;
    if (closeIdx - innerStart > 2_048) {
      const nestedLoc = lower.lastIndexOf('<loc', closeIdx - 1);
      if (nestedLoc > openIdx && nestedLoc + 4 < closeIdx && isTagNameBoundary(bounded.charCodeAt(nestedLoc + 4))) {
        const nestedGt = bounded.indexOf('>', nestedLoc + 4);
        if (nestedGt > nestedLoc && nestedGt < closeIdx) {
          innerStart = nestedGt + 1;
        }
      }
    }

    pos = closeGt + 1;
    if (closeIdx - innerStart > 8_192) continue;
    const raw = unwrapXmlCdataLinear(bounded.slice(innerStart, closeIdx))
      .replace(/&amp;/g, '&')
      .trim();
    if (!raw || seen.has(raw)) continue;
    try {
      const u = new URL(raw);
      if (u.protocol === 'https:') {
        u.hash = '';
        const clean = u.toString();
        if (!seen.has(clean)) {
          seen.add(clean);
          locs.push(clean);
        }
      }
    } catch {
      // ignore invalid URL
    }
  }
  return { isIndex, locs };
}

async function decodeXmlOrGzipBody(bodyStr: string, bodyEncoding?: string, urlHint = ''): Promise<string> {
  if (!bodyStr) return '';
  const looksGzip = bodyEncoding === 'base64' || urlHint.toLowerCase().endsWith('.gz');
  if (!looksGzip) return bodyStr;
  try {
    const binStr = atob(bodyStr);
    const bytes = new Uint8Array(binStr.length);
    for (let i = 0; i < binStr.length; i++) bytes[i] = binStr.charCodeAt(i);
    if (bytes.length >= 2 && bytes[0] === 0x1f && bytes[1] === 0x8b) {
      const stream = new Blob([bytes]).stream().pipeThrough(new DecompressionStream('gzip'));
      const ab = await new Response(stream).arrayBuffer();
      return new TextDecoder('utf-8', { fatal: false }).decode(ab.slice(0, 4 << 20));
    }
    return new TextDecoder('utf-8', { fatal: false }).decode(bytes);
  } catch {
    return bodyStr;
  }
}

export interface MapRequestPayload {
  url?: unknown;
  search?: unknown;
  limit?: unknown;
  includeSubdomains?: unknown;
  ignoreSitemap?: unknown;
  sitemap?: unknown;
  ignoreQueryParameters?: unknown;
  deduplicateSimilarURLs?: unknown;
  includePaths?: unknown;
  excludePaths?: unknown;
  regexOnFullURL?: unknown;
  fastEdgeMap?: unknown;
  target?: unknown;
  site?: unknown;
}

function extractAnchorTitlesFromHtml(html: string, baseUrl: string): Map<string, string> {
  const titles = new Map<string, string>();
  const cleanedHtml = stripHtmlTagsLinear(
    stripHtmlCommentsLinear(html, MAX_HTML_SCAN_CHARS),
    ['script', 'style', 'svg', 'noscript', 'template'],
    ' ',
    MAX_HTML_SCAN_CHARS,
  );
  replacePairedHtmlElementsLinear(
    cleanedHtml,
    ['a'],
    (_full, _t, attrStr, inner) => {
      const hrefMatch = /\bhref[ \t\r\n]*=[ \t\r\n]*(?:"([^"]*)"|'([^']*)'|([^\s>"']+))/i.exec(attrStr);
      const rawHref = (hrefMatch?.[1] ?? hrefMatch?.[2] ?? hrefMatch?.[3] ?? '').trim();
      if (!rawHref || rawHref.startsWith('#') || /^(?:javascript|mailto|tel|data):/i.test(rawHref)) return '';
      let resolved: string;
      try {
        const u = new URL(decodeHtmlEntities(rawHref), baseUrl);
        if (u.protocol !== 'https:' && u.protocol !== 'http:') return '';
        u.hash = '';
        resolved = u.toString();
      } catch {
        return '';
      }
      if (titles.has(resolved)) return '';
      const label = decodeHtmlEntities(stripHtmlTagsQuoteAwareLinear(inner, ' ', 1200))
        .replace(/[#¶§🔗]+$/g, '')
        .replace(/\s+/g, ' ')
        .trim();
      if (
        label.length >= 3 &&
        label.length <= 140 &&
        !/^https?:\/\//i.test(label) &&
        !/^(?:read more|learn more|click here|see more|more|link|here|view|open|next|prev|previous|\d+)$/i.test(label)
      ) {
        titles.set(resolved, label);
      }
      return '';
    },
    { maxChars: MAX_HTML_SCAN_CHARS, maxInnerChars: 600 },
  );
  return titles;
}

/**
 * Executes `POST /v1/map` + MCP `map`: discovers URLs across `/robots.txt` `Sitemap:`, `/sitemap.xml` (including
 * `<sitemapindex>` + `.xml.gz`), `/llms.txt`, and root homepage `<a href>` links politely through `executeHubFetch`.
 */
export async function executeMapCall(params: {
  payload: MapRequestPayload;
  executeHubFetch: HubFetchExecutor;
  selfHost?: string;
  source?: string;
  tracer?: RequestTracer | TraceContext;
}): Promise<{ status: number; via: string; body: Record<string, unknown> }> {
  const { payload, executeHubFetch, selfHost, source = 'map' } = params;
  const activeTracer = getActiveRequestTracer(params.tracer);
  const check = validatePublicHttpsUrl(payload.url, selfHost);
  if (!check.ok) {
    return { status: 400, via: 'hub', body: { ok: false, error: 'invalid_url', message: check.message } };
  }
  const incCheck = validateCrawlPathPatterns(payload.includePaths, 'includePaths');
  if (!incCheck.ok) {
    return { status: 400, via: 'hub', body: { ok: false, status: 400, error: incCheck.error, message: incCheck.message } };
  }
  const excCheck = validateCrawlPathPatterns(payload.excludePaths, 'excludePaths');
  if (!excCheck.ok) {
    return { status: 400, via: 'hub', body: { ok: false, status: 400, error: excCheck.error, message: excCheck.message } };
  }
  const mapIncludePaths = incCheck.patterns;
  const mapExcludePaths = excCheck.patterns;
  const mapRegexOnFullURL = Boolean(payload.regexOnFullURL);
  const rootUrl = check.url;
  const origin = rootUrl.origin;
  const rootHost = rootUrl.hostname;
  const includeSubdomains = Boolean(payload.includeSubdomains);
  const fastEdgeMap = Boolean(payload.fastEdgeMap);
  const rawSitemapMode = typeof payload.sitemap === 'string' ? payload.sitemap.trim().toLowerCase() : '';
  const sitemapMode: 'include' | 'skip' | 'only' =
    rawSitemapMode === 'only' ? 'only' : rawSitemapMode === 'skip' || Boolean(payload.ignoreSitemap) || fastEdgeMap ? 'skip' : 'include';
  const ignoreSitemap = sitemapMode === 'skip';
  const sitemapOnly = sitemapMode === 'only';
  const ignoreQueryParameters = Boolean(payload.ignoreQueryParameters);
  const deduplicateSimilarURLs = payload.deduplicateSimilarURLs !== false;
  const searchFilter = typeof payload.search === 'string' ? payload.search.trim().toLowerCase() : '';
  const limit =
    typeof payload.limit === 'number' && Number.isFinite(payload.limit)
      ? Math.min(5_000, Math.max(1, Math.floor(payload.limit)))
      : 500;
  const target: 'auto' | 'agent' | 'container' =
    payload.target === 'agent' || payload.target === 'container' ? payload.target : 'auto';
  const site = typeof payload.site === 'string' && payload.site.trim() ? payload.site.trim() : undefined;

  const trimmedSubpath = rootUrl.pathname.replace(/\/+$/, '');
  const subpathSegments = trimmedSubpath.split('/').filter(Boolean);
  const isGitHubRepoSubpath = rootHost.toLowerCase() === 'github.com' && subpathSegments.length >= 2;
  const shouldProbeSubpathLlms =
    !sitemapOnly &&
    Boolean(trimmedSubpath) &&
    !isGitHubRepoSubpath &&
    !trimmedSubpath.toLowerCase().endsWith('/llms.txt') &&
    (subpathSegments.length === 1 || /\b(docs?|api|reference|guides?|manual|sdk|dev|developers)\b/i.test(trimmedSubpath));
  const subLlmsUrl = shouldProbeSubpathLlms ? `${origin}${trimmedSubpath}/llms.txt` : '';

  const isWikiRootHost = isWikipediaHost(rootHost);
  const cachedWikiSitemapUrls = !ignoreSitemap && isWikiRootHost ? getCachedWikipediaSitemapUrls(rootHost) : null;
  const wikiAllowedSitemapUrl = `${origin}/w/rest.php/site/v1/sitemap/0`;

  const seedRequests: Array<Record<string, unknown>> = sitemapOnly
    ? []
    : isGitHubRepoSubpath
      ? [{ id: 'home', url: rootUrl.toString(), kind: 'page' }]
      : isWikiRootHost
        ? [{ id: 'home', url: rootUrl.toString(), kind: 'page' }]
        : [
            { id: 'home', url: rootUrl.toString(), kind: 'page' },
            { id: 'llms', url: `${origin}/llms.txt`, kind: 'text', accept: 'text/plain' },
            ...(subLlmsUrl ? [{ id: 'llms-sub', url: subLlmsUrl, kind: 'text', accept: 'text/plain' }] : []),
          ];
  if (!ignoreSitemap && !isGitHubRepoSubpath) {
    if (isWikiRootHost) {
      if (!cachedWikiSitemapUrls) {
        seedRequests.push({ id: 'wiki-sitemap', url: wikiAllowedSitemapUrl, kind: 'text', accept: 'application/xml' });
      }
    } else {
      seedRequests.push(
        { id: 'robots', url: `${origin}/robots.txt`, kind: 'text', accept: 'text/plain' },
        { id: 'sitemap', url: `${origin}/sitemap.xml`, kind: 'text', accept: 'application/xml' },
        { id: 'sitemap-index', url: `${origin}/sitemap-index.xml`, kind: 'text', accept: 'application/xml' },
      );
    }
  }

  const seedPayloadJson = JSON.stringify({
    maxSeconds: fastEdgeMap ? 10 : 30,
    options: { includeBody: true, respectRobots: true, pauseMs: 250, pauseJitterMs: 0 },
    requests: seedRequests,
  });
  const callSeed = (seedTarget: 'auto' | 'agent' | 'container') =>
    executeHubFetch(
      seedTarget,
      seedPayloadJson,
      site,
      source,
      'off',
      false,
    );
  let seedRes = await (activeTracer ? activeTracer.run(() => callSeed(target)) : callSeed(target));
  if (seedRes.status !== 200) {
    return { status: seedRes.status, via: seedRes.via, body: { ok: false, error: 'map_fetch_failed' } };
  }

  let parsed = JSON.parse(seedRes.bodyText) as { results?: Array<Record<string, unknown>> };
  if (
    target === 'auto' &&
    seedRequests.length > 0 &&
    ((parsed.results ?? []).length === 0 ||
      (parsed.results ?? []).every((r) => !r || r.outcome === 'not_tried' || (r.status === 0 && !r.outcome)))
  ) {
    const retryRes = await (activeTracer ? activeTracer.run(() => callSeed('container')) : callSeed('container')).catch(() => null);
    if (retryRes && retryRes.status === 200) {
      seedRes = retryRes;
      parsed = JSON.parse(retryRes.bodyText) as { results?: Array<Record<string, unknown>> };
    }
  }
  const byId = new Map<string, Record<string, unknown>>();
  for (const r of parsed.results ?? []) {
    if (typeof r.id === 'string') byId.set(r.id, r);
  }

  // If the requested seed URL itself followed a safe HTTPS redirect (e.g. `https://bun.sh/` -> `https://bun.com/`),
  // accept URLs scoped to EITHER the requested `rootHost` OR the verified redirect destination host (excluding PSL public/private
  // suffixes and shared multi-tenant/cloud-storage platforms so a redirecting shortener cannot widen scope across tenants!).
  const SHARED_MULTI_TENANT_REDIRECT_HOSTS = [
    'github.com',
    'gitlab.com',
    'bitbucket.org',
    'linkedin.com',
    'x.com',
    'twitter.com',
    'medium.com',
    'substack.com',
    'youtube.com',
    'reddit.com',
    'ashbyhq.com',
    'greenhouse.io',
    'lever.co',
    'smartrecruiters.com',
    'myworkdayjobs.com',
    'myworkdaysite.com',
    'workable.com',
    'rippling.com',
    's3.amazonaws.com',
    'amazonaws.com',
    'storage.googleapis.com',
    'huggingface.co',
    'docs.google.com',
    'drive.google.com',
    'notion.so',
    'notion.site',
    'dropbox.com',
  ];
  const isSharedMultiTenantHost = (h: string): boolean => {
    const lh = h.toLowerCase().replace(/\.+$/, '');
    return SHARED_MULTI_TENANT_REDIRECT_HOSTS.some((d) => lh === d || lh.endsWith(`.${d}`));
  };
  const homeItem = byId.get('home');
  const redirectProbeItem = [homeItem, byId.get('sitemap'), byId.get('llms')].find(
    (it) => it?.outcome === 'ok' && typeof it.finalUrl === 'string' && it.finalUrl.trim().length > 0,
  );
  let redirectedRootUrl: URL | null = null;
  if (redirectProbeItem && typeof redirectProbeItem.finalUrl === 'string') {
    const redirCheck = validatePublicHttpsUrl(redirectProbeItem.finalUrl, selfHost);
    const destHost = redirCheck.ok ? redirCheck.url.hostname.toLowerCase().replace(/\.+$/, '') : '';
    if (
      redirCheck.ok &&
      destHost &&
      destHost !== rootHost.toLowerCase() &&
      !isPublicOrPrivateSuffix(destHost) &&
      !isSharedMultiTenantHost(destHost)
    ) {
      redirectedRootUrl =
        redirectProbeItem === homeItem
          ? redirCheck.url
          : new URL(trimmedSubpath || '/', redirCheck.url.origin);
    }
  }
  // Developer tools on `.sh`/`.io`/`.ai`/`.dev`/`.app` often rebrand canonical URLs in `/sitemap.xml` & `/llms.txt` to
  // `<same-brand>.com` while continuing to serve `200 OK` on the original domain without a `301` (`https://bun.sh/` -> `https://bun.com/`).
  // Allow parsing `<same-brand>.com` URLs ONLY from seed documents served directly by `rootHost` itself, without making cross-origin
  // child-sitemap fetches or writing to `companionMdUrlCache`.
  const rootRegistrable =
    !hasPrivateSharedHostingSuffix(rootHost) && !isPublicOrPrivateSuffix(rootHost) && !isSharedMultiTenantHost(rootHost)
      ? getRegistrableDomain(rootHost)
      : null;
  const rootSldCandidate =
    rootRegistrable && !rootRegistrable.endsWith('.com') ? (rootRegistrable.split('.')[0] ?? '') : '';
  const sameBrandComHost =
    rootSldCandidate.length >= 3 &&
    /^[a-z0-9-]+$/.test(rootSldCandidate) &&
    !isPublicOrPrivateSuffix(`${rootSldCandidate}.com`) &&
    !isSharedMultiTenantHost(`${rootSldCandidate}.com`)
      ? `${rootSldCandidate}.com`
      : null;
  const matchesSameBrandComFromRoot = (
    candidateHost: string,
    sourceItemHost: string | undefined,
    allowSubdomains: boolean,
  ): boolean =>
    Boolean(
      sameBrandComHost &&
        sourceItemHost &&
        sourceItemHost.toLowerCase().replace(/\.+$/, '') === rootHost.toLowerCase().replace(/\.+$/, '') &&
        matchesHostScope(candidateHost, sameBrandComHost, allowSubdomains),
    );

  const redirectedHostIsPrivateShared =
    redirectedRootUrl !== null && hasPrivateSharedHostingSuffix(redirectedRootUrl.hostname);
  const matchesSingleScopedHost = (
    candidateHost: string,
    scopeHost: string,
    allowSubdomains: boolean,
    exactOnly = false,
  ): boolean =>
    exactOnly
      ? candidateHost.toLowerCase().replace(/\.+$/, '') === scopeHost.toLowerCase().replace(/\.+$/, '')
      : matchesHostScope(candidateHost, scopeHost, allowSubdomains);
  const effectiveHomeBaseUrl = redirectedRootUrl ? redirectedRootUrl.toString() : rootUrl.toString();
  const matchesEffectiveHostScope = (candidateHost: string, allowSubdomains: boolean): boolean =>
    matchesHostScope(candidateHost, rootHost, allowSubdomains) ||
    (redirectedRootUrl !== null &&
      matchesSingleScopedHost(
        candidateHost,
        redirectedRootUrl.hostname,
        allowSubdomains,
        redirectedHostIsPrivateShared,
      ));
  const resolveVerifiedSeedUrl = (item: Record<string, unknown> | undefined, fallbackUrlStr: string): URL => {
    if (item && item.outcome === 'ok' && typeof item.finalUrl === 'string' && item.finalUrl.trim()) {
      const chk = validatePublicHttpsUrl(item.finalUrl, selfHost);
      if (chk.ok && matchesEffectiveHostScope(chk.url.hostname, true)) {
        return chk.url;
      }
    }
    return new URL(fallbackUrlStr);
  };

  const sourcesReport: Array<{ source: string; url: string; status: number; outcome: string; urlsFound: number }> = [];
  const discovered = new Map<string, { url: string; title?: string; description?: string; source: string }>();
  const verifiedCompanionMdKeys = new Set<string>();
  const dedupeKeyToCanonical = new Map<string, string>();
  const ghRepoPrefix =
    isGitHubRepoSubpath ? `/${subpathSegments[0]!.toLowerCase()}/${subpathSegments[1]!.toLowerCase()}` : '';
  const stripTrackingParams = (u: URL): void => {
    for (const k of [...u.searchParams.keys()]) {
      const lk = k.toLowerCase();
      if (
        lk.startsWith('utm_') ||
        lk === 'gclid' ||
        lk === 'fbclid' ||
        lk === 'msclkid' ||
        lk === 'mc_cid' ||
        lk === 'mc_eid' ||
        lk === '_hsenc' ||
        lk === '_hsmi' ||
        lk === 'ref_src' ||
        lk === 'spm'
      ) {
        u.searchParams.delete(k);
      }
    }
  };
  const addUrl = (
    rawCandidate: string,
    src: string,
    title?: string,
    description?: string,
    baseOriginOverride?: string,
    sourceItemHost?: string,
  ): string | null => {
    try {
      const u = new URL(rawCandidate, baseOriginOverride ?? origin);
      if (u.protocol !== 'https:' || (u.port && u.port !== '443')) return null;
      const isSameBrandComTwin = matchesSameBrandComFromRoot(u.hostname, sourceItemHost, includeSubdomains);
      if (!isSameBrandComTwin && !matchesEffectiveHostScope(u.hostname, includeSubdomains)) return null;
      if (
        !isSameBrandComTwin &&
        sourceItemHost &&
        !matchesSingleScopedHost(
          u.hostname,
          sourceItemHost,
          includeSubdomains,
          hasPrivateSharedHostingSuffix(sourceItemHost),
        )
      ) {
        return null;
      }
      if (ghRepoPrefix && u.hostname.toLowerCase() === 'github.com') {
        const lp = u.pathname.toLowerCase();
        if (lp !== ghRepoPrefix && !lp.startsWith(`${ghRepoPrefix}/`)) {
          return null;
        }
      }
      u.hash = '';
      if (ignoreQueryParameters) {
        u.search = '';
      } else {
        stripTrackingParams(u);
      }
      const clean = u.toString();
      const simKey = deduplicateSimilarURLs
        ? `${u.origin}${u.pathname.length > 1 ? u.pathname.replace(/\/+$/, '') : u.pathname}${u.search}`
        : clean;
      const canonicalKey = dedupeKeyToCanonical.get(simKey) ?? clean;
      if (
        sourceItemHost &&
        canonicalKey.toLowerCase().endsWith('.md') &&
        matchesSingleScopedHost(
          u.hostname,
          sourceItemHost,
          false,
          hasPrivateSharedHostingSuffix(sourceItemHost),
        )
      ) {
        verifiedCompanionMdKeys.add(canonicalKey);
      }
      const existing = discovered.get(canonicalKey);
      const cleanDesc = description ? decodeHtmlEntities(description).trim() : '';
      if (!existing) {
        dedupeKeyToCanonical.set(simKey, clean);
        discovered.set(clean, {
          url: clean,
          ...(title ? { title: decodeHtmlEntities(title) } : {}),
          ...(cleanDesc ? { description: cleanDesc } : {}),
          source: src,
        });
        return clean;
      }
      const isCuratedLlms = src === 'llms.txt' || src === 'subpath-llms.txt';
      if ((!existing.title || isCuratedLlms) && title) {
        existing.title = decodeHtmlEntities(title);
      }
      if (!existing.description && cleanDesc) {
        existing.description = cleanDesc;
      }
      if (isCuratedLlms && existing.source !== 'llms.txt' && existing.source !== 'subpath-llms.txt') {
        existing.source = src;
      }
      return canonicalKey;
    } catch {
      return null;
    }
  };
  if (!sitemapOnly) {
    const seedHost = redirectedRootUrl ? redirectedRootUrl.hostname : rootHost;
    addUrl(effectiveHomeBaseUrl, 'seed', undefined, undefined, effectiveHomeBaseUrl, seedHost);
  }

  if (homeItem) {
    const homeSeen = new Set<string>();
    if (homeItem.outcome === 'ok' && typeof homeItem.body === 'string') {
      const verifiedHomeUrl = resolveVerifiedSeedUrl(homeItem, rootUrl.toString());
      const homeBaseStr = verifiedHomeUrl.toString();
      const anchorTitles = extractAnchorTitlesFromHtml(homeItem.body, homeBaseStr);
      const ext = extractHtmlDocument(homeItem.body, { baseUrl: homeBaseStr, onlyMainContent: false });
      const homeLinks =
        ext.links.length > 0
          ? ext.links
          : extractMarkdownLinksAndImages(homeItem.body, homeBaseStr, false).links;
      for (const l of homeLinks) {
        const key = addUrl(l, 'homepage', anchorTitles.get(l), undefined, homeBaseStr, verifiedHomeUrl.hostname);
        if (key) homeSeen.add(key);
      }
    }
    sourcesReport.push({
      source: 'homepage',
      url: rootUrl.toString(),
      status: typeof homeItem.status === 'number' ? homeItem.status : 0,
      outcome: String(homeItem.outcome ?? 'unknown'),
      urlsFound: homeSeen.size,
    });
  }

  for (const [id, srcLabel, llmsTargetUrl] of [
    ['llms', 'llms.txt', `${origin}/llms.txt`],
    ...(subLlmsUrl ? ([['llms-sub', 'subpath-llms.txt', subLlmsUrl]] as const) : []),
  ] as const) {
    const llmsItem = byId.get(id);
    if (!llmsItem) continue;
    const llmsSeen = new Set<string>();
    if (llmsItem.outcome === 'ok' && typeof llmsItem.body === 'string') {
      const verifiedLlmsUrl = resolveVerifiedSeedUrl(llmsItem, llmsTargetUrl);
      const effectiveLlmsUrl = verifiedLlmsUrl.toString();
      const llmsDoc = parseLlmsTxt(llmsItem.body, effectiveLlmsUrl, { recordCompanionCache: false });
      if (llmsDoc) {
        for (const l of llmsDoc.links) {
          const noteSummary = [l.section, l.notes].filter(Boolean).join(' — ');
          const key = addUrl(l.url, srcLabel, l.title, noteSummary || undefined, effectiveLlmsUrl, verifiedLlmsUrl.hostname);
          if (key) llmsSeen.add(key);
        }
      }
    }
    sourcesReport.push({
      source: srcLabel,
      url: llmsTargetUrl,
      status: typeof llmsItem.status === 'number' ? llmsItem.status : 0,
      outcome: String(llmsItem.outcome ?? 'unknown'),
      urlsFound: llmsSeen.size,
    });
  }

  if (!ignoreSitemap) {
    const childSitemaps = new Set<string>();
    const robotsItem = byId.get('robots');
    if (robotsItem) {
      let sitemapsFound = 0;
      if (robotsItem.outcome === 'ok' && typeof robotsItem.body === 'string') {
        const verifiedRobotsUrl = resolveVerifiedSeedUrl(robotsItem, `${origin}/robots.txt`);
        for (const sm of extractRobotsSitemaps(robotsItem.body, verifiedRobotsUrl.origin)) {
          let isSameBrandRobotsSm = false;
          try {
            const smHost = new URL(sm).hostname;
            isSameBrandRobotsSm = matchesSameBrandComFromRoot(smHost, verifiedRobotsUrl.hostname, true);
            if (
              !isSameBrandRobotsSm &&
              !matchesSingleScopedHost(
                smHost,
                verifiedRobotsUrl.hostname,
                true,
                hasPrivateSharedHostingSuffix(verifiedRobotsUrl.hostname),
              )
            ) {
              continue;
            }
          } catch {
            continue;
          }
          sitemapsFound++;
          if (
            !isSameBrandRobotsSm &&
            sm !== `${origin}/sitemap.xml` &&
            sm !== `${origin}/sitemap-index.xml` &&
            sm !== `${verifiedRobotsUrl.origin}/sitemap.xml` &&
            sm !== `${verifiedRobotsUrl.origin}/sitemap-index.xml`
          ) {
            childSitemaps.add(sm);
          }
        }
      }
      sourcesReport.push({
        source: 'robots.txt',
        url: `${origin}/robots.txt`,
        status: typeof robotsItem.status === 'number' ? robotsItem.status : 0,
        outcome: String(robotsItem.outcome ?? 'unknown'),
        urlsFound: sitemapsFound,
      });
    }

    if (isWikiRootHost) {
      if (cachedWikiSitemapUrls) {
        const wikiCacheSeen = new Set<string>();
        for (const loc of cachedWikiSitemapUrls) {
          const key = addUrl(loc, 'sitemap', undefined, undefined, origin, rootHost);
          if (key) wikiCacheSeen.add(key);
        }
        sourcesReport.push({
          source: 'wikipedia-sitemap-cache',
          url: wikiAllowedSitemapUrl,
          status: 200,
          outcome: 'ok',
          urlsFound: wikiCacheSeen.size,
        });
      } else {
        const wikiSmItem = byId.get('wiki-sitemap');
        if (wikiSmItem) {
          let found = 0;
          if (wikiSmItem.outcome === 'ok' && typeof wikiSmItem.body === 'string') {
            const xml = await decodeXmlOrGzipBody(wikiSmItem.body, wikiSmItem.bodyEncoding as string | undefined, wikiAllowedSitemapUrl);
            const parsedSm = parseSitemapXml(xml);
            if (parsedSm.isIndex) {
              for (const loc of parsedSm.locs) {
                childSitemaps.add(loc);
                found++;
              }
            } else {
              setCachedWikipediaSitemapUrls(rootHost, parsedSm.locs);
              const wikiSeen = new Set<string>();
              for (const loc of parsedSm.locs) {
                const key = addUrl(loc, 'sitemap', undefined, undefined, origin, rootHost);
                if (key) wikiSeen.add(key);
              }
              found = wikiSeen.size;
            }
          }
          sourcesReport.push({
            source: 'wikipedia-sitemap',
            url: wikiAllowedSitemapUrl,
            status: typeof wikiSmItem.status === 'number' ? wikiSmItem.status : 0,
            outcome: String(wikiSmItem.outcome ?? 'unknown'),
            urlsFound: found,
          });
        }
      }
    }

    for (const [smId, smUrl] of [
      ['sitemap', `${origin}/sitemap.xml`],
      ['sitemap-index', `${origin}/sitemap-index.xml`],
    ] as const) {
      const smItem = byId.get(smId);
      if (!smItem) continue;
      let found = 0;
      if (smItem.outcome === 'ok' && typeof smItem.body === 'string') {
        const verifiedSmUrl = resolveVerifiedSeedUrl(smItem, smUrl);
        const xml = await decodeXmlOrGzipBody(smItem.body, smItem.bodyEncoding as string | undefined, verifiedSmUrl.toString());
        const parsedSm = parseSitemapXml(xml);
        if (parsedSm.isIndex) {
          for (const loc of parsedSm.locs) {
            try {
              const locHost = new URL(loc, verifiedSmUrl.origin).hostname;
              if (
                !matchesSingleScopedHost(
                  locHost,
                  verifiedSmUrl.hostname,
                  true,
                  hasPrivateSharedHostingSuffix(verifiedSmUrl.hostname),
                )
              ) {
                continue;
              }
            } catch {
              continue;
            }
            childSitemaps.add(new URL(loc, verifiedSmUrl.origin).toString());
            found++;
          }
        } else {
          const smSeen = new Set<string>();
          for (const loc of parsedSm.locs) {
            const key = addUrl(loc, 'sitemap', undefined, undefined, verifiedSmUrl.origin, verifiedSmUrl.hostname);
            if (key) smSeen.add(key);
          }
          found = smSeen.size;
        }
      }
      sourcesReport.push({
        source: smId,
        url: smUrl,
        status: typeof smItem.status === 'number' ? smItem.status : 0,
        outcome: String(smItem.outcome ?? 'unknown'),
        urlsFound: found,
      });
    }

    const pathHintTokens = trimmedSubpath
      .toLowerCase()
      .split('/')
      .map((s) => s.trim())
      .filter((s) => s.length >= 2);
    const searchHintTokens = searchFilter
      .split(/\s+/)
      .map((s) => s.trim())
      .filter((s) => s.length >= 2);

    const scoreChildSitemap = (smUrl: string): number => {
      const lower = smUrl.toLowerCase();
      let score = 0;
      for (const pt of pathHintTokens) {
        if (lower.includes(pt)) score += 10;
      }
      for (const st of searchHintTokens) {
        if (lower.includes(st)) score += 6;
      }
      if (
        score === 0 &&
        /(?:^|[-_/])(?:authors?|archives?|tags?|users?|categories)(?:[-_.\d]|$)/i.test(lower)
      ) {
        score -= 8;
      }
      return score;
    };

    const extractSitemapSeq = (smUrl: string): number => {
      const m = /(?:^|[-_/])(\d{1,5})\.xml(?:\.gz)?(?:$|[?#])/i.exec(smUrl);
      return m?.[1] ? Number(m[1]) : -1;
    };

    const toFetchSitemaps = [...childSitemaps]
      .filter((u) => {
        try {
          return matchesEffectiveHostScope(new URL(u).hostname, true);
        } catch {
          return false;
        }
      })
      .map((u, idx) => ({ url: u, score: scoreChildSitemap(u), seq: extractSitemapSeq(u), idx }))
      .filter((x) => Boolean(searchFilter) || discovered.size < limit || x.score > 0)
      .sort((a, b) => {
        if (b.score !== a.score) return b.score - a.score;
        const aUnnumbered = a.seq < 0 ? 1 : 0;
        const bUnnumbered = b.seq < 0 ? 1 : 0;
        if (aUnnumbered !== bUnnumbered) return bUnnumbered - aUnnumbered;
        if (a.seq >= 0 && b.seq >= 0 && b.seq !== a.seq) return b.seq - a.seq;
        return a.idx - b.idx;
      })
      .slice(0, 5)
      .map((x) => x.url);

    if (toFetchSitemaps.length > 0 && (Boolean(searchFilter) || pathHintTokens.length > 0 || discovered.size < limit)) {
      const callSub = () =>
        executeHubFetch(
          target,
          JSON.stringify({
            maxSeconds: 25,
            options: { includeBody: true, respectRobots: true, pauseMs: 200, pauseJitterMs: 0 },
            requests: toFetchSitemaps.map((u, idx) => ({
              id: `csm-${idx}`,
              url: u,
              kind: 'text',
              accept: 'application/xml',
            })),
          }),
          site,
          `${source}:child-sitemaps`,
          'off',
          false,
        );
      const subRes = await (activeTracer ? activeTracer.run(callSub) : callSub());
      if (subRes.status === 200) {
        const subParsed = JSON.parse(subRes.bodyText) as { results?: Array<Record<string, unknown>> };
        const wikiCollectedChildLocs: string[] = [];
        for (const sr of subParsed.results ?? []) {
          const srUrl = typeof sr.url === 'string' ? sr.url : '';
          let found = 0;
          if (sr.outcome === 'ok' && typeof sr.body === 'string' && srUrl) {
            const verifiedChildSmUrl = resolveVerifiedSeedUrl(sr, srUrl);
            const xml = await decodeXmlOrGzipBody(sr.body, sr.bodyEncoding as string | undefined, verifiedChildSmUrl.toString());
            const p = parseSitemapXml(xml);
            if (!p.isIndex) {
              const csmSeen = new Set<string>();
              for (const loc of p.locs) {
                if (isWikiRootHost && wikiCollectedChildLocs.length < 5_000) wikiCollectedChildLocs.push(loc);
                const key = addUrl(
                  loc,
                  'sitemap',
                  undefined,
                  undefined,
                  verifiedChildSmUrl.origin,
                  verifiedChildSmUrl.hostname,
                );
                if (key) csmSeen.add(key);
              }
              found = csmSeen.size;
            }
          }
          if (srUrl) {
            sourcesReport.push({
              source: 'child-sitemap',
              url: srUrl,
              status: typeof sr.status === 'number' ? sr.status : 0,
              outcome: String(sr.outcome ?? 'unknown'),
              urlsFound: found,
            });
          }
        }
        if (isWikiRootHost && !cachedWikiSitemapUrls && wikiCollectedChildLocs.length > 0) {
          setCachedWikipediaSitemapUrls(rootHost, wikiCollectedChildLocs);
        }
      }
    }
  }

  // Merge companion `.md` and `/index.md` entries (e.g. from `/llms.txt`) onto their canonical HTML twins
  // (`.../foo` + `.../foo.md`, `.../bar/` + `.../bar/index.md`) so `map` preserves curated `llms.txt` titles without duplicates.
  const wantsExplicitMd = /\.md\b/i.test(searchFilter);
  for (const [key, entry] of [...discovered.entries()]) {
    if (!key.toLowerCase().endsWith('.md')) continue;
    // Only cache companion `.md` URLs in the shared isolate cache when discovered from a verified same-host response
    // matching `rootHost` (preventing cross-origin redirect cache poisoning!).
    try {
      const mdHost = new URL(key).hostname;
      if (verifiedCompanionMdKeys.has(key) && matchesHostScope(mdHost, rootHost, includeSubdomains)) {
        recordCompanionMdUrl(key);
      }
    } catch {
      // ignore invalid URL
    }
    const candidateTwins: string[] = [];
    if (/\/index\.md$/i.test(key)) {
      const dirWithSlash = key.slice(0, -'index.md'.length);
      const dirNoSlash =
        dirWithSlash.endsWith('/') && dirWithSlash.length > origin.length + 1
          ? dirWithSlash.slice(0, -1)
          : dirWithSlash;
      candidateTwins.push(dirWithSlash, dirNoSlash);
    }
    const baseTwinUrl = key.slice(0, -3);
    candidateTwins.push(baseTwinUrl, `${baseTwinUrl}/`);
    const twin = candidateTwins.map((c) => discovered.get(c)).find((t) => t && t.url !== key);
    if (twin) {
      if (!twin.title && entry.title) {
        twin.title = entry.title;
      }
      if (!twin.description && entry.description) {
        twin.description = entry.description;
      }
      if (!wantsExplicitMd) {
        discovered.delete(key);
      }
    }
  }

  const includeOutsidePath = Boolean((payload as { includeOutsidePath?: unknown }).includeOutsidePath);
  const subpathPrefix = trimmedSubpath ? `${origin}${trimmedSubpath}`.toLowerCase() : '';
  const redirectedTrimmedSubpath =
    redirectedRootUrl && redirectedRootUrl.pathname !== '/'
      ? redirectedRootUrl.pathname.replace(/\/+$/, '')
      : trimmedSubpath;
  const redirectedSubpathPrefix =
    redirectedRootUrl && redirectedTrimmedSubpath
      ? `${redirectedRootUrl.origin}${redirectedTrimmedSubpath}`.toLowerCase()
      : '';
  const sameBrandComSubpathPrefix =
    sameBrandComHost && trimmedSubpath ? `https://${sameBrandComHost}${trimmedSubpath}`.toLowerCase() : '';
  const isUnderSubpath = (urlStr: string): boolean => {
    if (!subpathPrefix) return true;
    const lower = urlStr.toLowerCase();
    if (lower === subpathPrefix || lower.startsWith(`${subpathPrefix}/`)) return true;
    if (redirectedSubpathPrefix && (lower === redirectedSubpathPrefix || lower.startsWith(`${redirectedSubpathPrefix}/`))) {
      return true;
    }
    if (sameBrandComSubpathPrefix && (lower === sameBrandComSubpathPrefix || lower.startsWith(`${sameBrandComSubpathPrefix}/`))) {
      return true;
    }
    return false;
  };

  // Tokenize URL paths and page titles on `/ - _ .` and camelCase boundaries so `search=voice` matches `voice` / `voice-agent`
  // and NEVER matches inside unrelated words like `/billing/manage/invoices/` ("invoices" -> token "invoices", not "voice").
  const tokenizeMapSegment = (raw: string): string[] => {
    const dec = safeDecodeURIComponent(raw);
    const whole = dec.toLowerCase().match(/[\p{L}\p{N}]+/gu) ?? [];
    const camelSplit = dec.replace(/([a-z\d])([A-Z])/g, '$1 $2');
    const split = camelSplit.toLowerCase().match(/[\p{L}\p{N}]+/gu) ?? [];
    return [...new Set([...whole, ...split])].filter(Boolean);
  };

  const matchesWholeMapToken = (tokens: string[], queryTerm: string): { matched: boolean; exact: boolean } => {
    const q = queryTerm.toLowerCase();
    for (const tok of tokens) {
      if (tok === q) return { matched: true, exact: true };
      // Allow plural/stem suffix (`voice` -> `voices`, `agent` -> `agents`) ONLY at the start of the token, never mid-word (`invoices`).
      if (q.length >= 4 && tok.startsWith(q) && tok.length <= q.length + 3) {
        return { matched: true, exact: false };
      }
    }
    return { matched: false, exact: false };
  };

  const extractUrlLocalePrefix = (pathname: string): string | null => {
    const regional = /^\/([a-z]{2}-[a-z]{2,4})(?:\/|$)/i.exec(pathname);
    if (regional?.[1]) return regional[1].toLowerCase();
    const translated2 = /^\/(de|fr|es|ja|ko|zh|pt|ru|it|nl|pl|tr|vi|id|th|ar|uk|cs|sv|da|fi|he)(?:\/|$)/i.exec(pathname);
    return translated2?.[1] ? translated2[1].toLowerCase() : null;
  };
  const rootLocale = extractUrlLocalePrefix(rootUrl.pathname);

  const scoreMapUrlQuality = (urlStr: string): number => {
    const lower = urlStr.toLowerCase();
    if (/\/(?:login|signup|contact\/report-content)\b/.test(lower)) return -30;
    if (/\/(?:actions|activity|pulse|stargazers|watchers|forks|network|security\/advisories|custom-properties)(?:\/|$)/.test(lower)) {
      return -15;
    }
    let localePenalty = 0;
    if (!rootLocale) {
      try {
        const candLocale = extractUrlLocalePrefix(new URL(urlStr).pathname);
        if (candLocale && (!searchFilter || !searchFilter.includes(candLocale))) {
          localePenalty = -18;
        }
      } catch {
        // ignore
      }
    }
    if (/\/blob\/[^/]+\/\.[a-z0-9]/.test(lower)) return -10 + localePenalty;
    if (/\/(?:readme\.md|docs\/|guide|getting-started|reference|api\/)/.test(lower)) return 10 + localePenalty;
    return localePenalty;
  };

  let items = [...discovered.values()];
  if (subpathPrefix && !includeOutsidePath) {
    items = items.filter((entry) => isUnderSubpath(entry.url));
  }
  if (mapIncludePaths.length > 0 || mapExcludePaths.length > 0) {
    items = items.filter((entry) => {
      try {
        return pathAllowed(new URL(entry.url), mapIncludePaths, mapExcludePaths, mapRegexOnFullURL);
      } catch {
        return false;
      }
    });
  }
  if (searchFilter) {
    const terms = (searchFilter.toLowerCase().match(/[\p{L}\p{N}]+/gu) ?? []).filter(Boolean);
    const scored = items
      .map((entry) => {
        const urlLower = entry.url.toLowerCase();
        let pathAndQuery = entry.url;
        try {
          const pu = new URL(entry.url);
          pathAndQuery = `${pu.pathname} ${pu.search}`;
        } catch {
          // ignore
        }
        const urlTokens = tokenizeMapSegment(pathAndQuery);
        const titleTokens = tokenizeMapSegment(entry.title ?? '');
        const descTokens = tokenizeMapSegment(entry.description ?? '');
        let hits = 0;
        let exactBonus = 0;
        for (const t of terms) {
          const uMatch = matchesWholeMapToken(urlTokens, t);
          const tMatch = matchesWholeMapToken(titleTokens, t);
          const dMatch = matchesWholeMapToken(descTokens, t);
          if (uMatch.matched || tMatch.matched || dMatch.matched) {
            hits++;
            if (uMatch.exact) exactBonus += 6;
            else if (tMatch.exact) exactBonus += 3;
            else if (dMatch.exact) exactBonus += 2;
          }
        }
        const underSubpath = subpathPrefix ? isUnderSubpath(entry.url) : false;
        const exactSubpathRoot =
          terms.length === 1 && (urlLower.endsWith(`/${terms[0]}/`) || urlLower.endsWith(`/${terms[0]}`)) ? 5 : 0;
        const score =
          (underSubpath ? 100 : 0) +
          hits * 20 +
          exactBonus +
          exactSubpathRoot +
          (entry.title ? 2 : 0) +
          scoreMapUrlQuality(entry.url);
        return { entry, hits, score };
      })
      .filter((x) => x.hits > 0);
    const strong = scored.filter((x) => terms.length <= 1 || x.hits === terms.length || x.hits >= 2);
    items = (strong.length > 0 ? strong : scored)
      .sort((a, b) => b.score - a.score || a.entry.url.length - b.entry.url.length || a.entry.url.localeCompare(b.entry.url))
      .map((x) => x.entry);
  } else if (subpathPrefix) {
    items.sort((a, b) => {
      const aUnder = isUnderSubpath(a.url) ? 1 : 0;
      const bUnder = isUnderSubpath(b.url) ? 1 : 0;
      if (aUnder !== bUnder) return bUnder - aUnder;
      const aSeed = a.source === 'seed' ? 1 : 0;
      const bSeed = b.source === 'seed' ? 1 : 0;
      if (aSeed !== bSeed) return bSeed - aSeed;
      const qDiff = scoreMapUrlQuality(b.url) - scoreMapUrlQuality(a.url);
      return qDiff || a.url.localeCompare(b.url);
    });
  } else {
    items.sort((a, b) => {
      const qDiff = scoreMapUrlQuality(b.url) - scoreMapUrlQuality(a.url);
      return qDiff || a.url.localeCompare(b.url);
    });
  }

  if (sourcesReport.length > 0 && sourcesReport.every((s) => s.outcome === 'not_tried')) {
    return {
      status: 503,
      via: seedRes.via,
      body: {
        ok: false,
        error: 'map_sources_not_tried',
        retryable: true,
        message: 'No discovery sources could be attempted within the request window; retry shortly.',
        url: rootUrl.toString(),
        sources: sourcesReport,
      },
    };
  }

  const sliced = items.slice(0, limit);
  return {
    status: 200,
    via: seedRes.via,
    body: {
      ok: true,
      url: rootUrl.toString(),
      total: sliced.length,
      links: sliced.map((x) => x.url),
      entries: sliced,
      sources: sourcesReport,
    },
  };
}

/** Computes a compact line-level Markdown diff for `formats: ["changes"]` change tracking (`Addition 8`). */
export function computeMarkdownChanges(prevMarkdown: string | null, nextMarkdown: string): {
  status: 'new' | 'same' | 'changed';
  addedCount: number;
  removedCount: number;
  diffPreview: string;
} {
  if (prevMarkdown === null) {
    return { status: 'new', addedCount: nextMarkdown.split('\n').length, removedCount: 0, diffPreview: '' };
  }
  const prevClean = prevMarkdown.replace(/\r\n/g, '\n').trim();
  const nextClean = nextMarkdown.replace(/\r\n/g, '\n').trim();
  if (prevClean === nextClean) {
    return { status: 'same', addedCount: 0, removedCount: 0, diffPreview: '' };
  }

  const prevSet = new Set(prevClean.split('\n').map((l) => l.trim()).filter(Boolean));
  const nextSet = new Set(nextClean.split('\n').map((l) => l.trim()).filter(Boolean));
  const added = [...nextSet].filter((l) => !prevSet.has(l));
  const removed = [...prevSet].filter((l) => !nextSet.has(l));
  const previewLines = [
    ...removed.slice(0, 15).map((l) => `- ${l}`),
    ...added.slice(0, 15).map((l) => `+ ${l}`),
  ];
  return {
    status: 'changed',
    addedCount: added.length,
    removedCount: removed.length,
    diffPreview: previewLines.join('\n').slice(0, 4_000),
  };
}

export type WebhookEventType =
  | 'crawl.started'
  | 'crawl.page'
  | 'crawl.completed'
  | 'crawl.failed'
  | 'agent.started'
  | 'agent.action'
  | 'agent.completed'
  | 'agent.failed'
  | 'agent.cancelled';

export interface WebhookConfig {
  url: string;
  secret?: string;
  events?: WebhookEventType[];
  metadata?: Record<string, unknown>;
}

export async function signWebhookPayload(secret: string, timestampSec: number, rawJson: string): Promise<string> {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sigBuf = await crypto.subtle.sign('HMAC', key, enc.encode(`${timestampSec}.${rawJson}`));
  return [...new Uint8Array(sigBuf)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

/** Delivers an SSRF-validated, HMAC-SHA256 signed webhook event (`X-EdgeFetch-Signature: sha256=<hex>`). */
export async function deliverSignedWebhook(params: {
  webhook: WebhookConfig;
  defaultSecret?: string;
  event: WebhookEventType;
  crawlId: string;
  data: Record<string, unknown>;
  selfHost?: string;
  fetchFn?: typeof fetch;
  tracer?: RequestTracer | TraceContext;
}): Promise<{ delivered: boolean; status?: number }> {
  const { webhook, defaultSecret, event, crawlId, data, selfHost, fetchFn = fetch } = params;
  if (Array.isArray(webhook.events) && webhook.events.length > 0 && !webhook.events.includes(event)) {
    return { delivered: false };
  }
  const urlCheck = validatePublicHttpsUrl(webhook.url, selfHost);
  if (!urlCheck.ok) {
    return { delivered: false };
  }

  const signingSecret = (webhook.secret ?? defaultSecret ?? '').trim();
  const activeTracer = getActiveRequestTracer(params.tracer);

  const runDelivery = async (): Promise<{ delivered: boolean; status?: number }> => {
    const tsSec = Math.floor(Date.now() / 1000);
    const bodyJson = JSON.stringify({
      event,
      crawlId,
      timestamp: tsSec,
      ...(webhook.metadata ? { metadata: webhook.metadata } : {}),
      data,
    });

    const headers = new Headers({
      'content-type': 'application/json',
      'user-agent': 'EdgeFetch-Webhook/2.0',
      'x-edgefetch-event': event,
      'x-edgefetch-timestamp': String(tsSec),
    });
    if (signingSecret) {
      const sigHex = await signWebhookPayload(signingSecret, tsSec, bodyJson);
      headers.set('x-edgefetch-signature', `sha256=${sigHex}`);
    }

    try {
      const res = await fetchFn(urlCheck.url.toString(), {
        method: 'POST',
        headers,
        body: bodyJson,
        redirect: 'manual',
        signal: AbortSignal.timeout(10_000),
      });
      await res.body?.cancel().catch(() => undefined);
      return { delivered: res.status >= 200 && res.status < 300, status: res.status };
    } catch {
      return { delivered: false };
    }
  };

  if (!activeTracer) {
    return runDelivery();
  }
  return activeTracer.withSpan(
    'edgefetch.webhook',
    {
      kind: 3,
      attributes: {
        'webhook.event': event,
        'crawl.id': crawlId,
        'url.full': sanitizeUrlForSpan(urlCheck.url.toString()),
        'webhook.signed': Boolean(signingSecret),
      },
    },
    async (whSpan) => {
      const out = await runDelivery();
      if (out.status !== undefined) {
        whSpan.setAttribute('http.response.status_code', out.status);
      }
      whSpan.setAttribute('webhook.delivered', out.delivered);
      whSpan.setStatus(out.delivered);
      return out;
    },
  );
}

export interface CrawlJobOptions {
  userId?: string;
  limit: number;
  maxDepth: number;
  allowSubdomains: boolean;
  allowExternalLinks: boolean;
  crawlEntireDomain: boolean;
  regexOnFullURL: boolean;
  ignoreQueryParameters: boolean;
  deduplicateSimilarURLs: boolean;
  sitemap: 'include' | 'skip' | 'only';
  delayMs?: number;
  includePaths: string[];
  excludePaths: string[];
  collectionId?: string;
  renderMode?: 'off' | 'auto' | 'always';
  webhook?: WebhookConfig;
  target: 'auto' | 'agent' | 'container';
  site?: string;
}

export interface CrawlWorkflowParams {
  crawlId: string;
  rootUrl: string;
  userId?: string;
  options?: CrawlJobOptions;
  selfHost?: string;
}

export function validateCrawlPathPatterns(
  rawList: unknown,
  fieldName: 'includePaths' | 'excludePaths',
): { ok: true; patterns: string[] } | { ok: false; status: 400; error: 'invalid_pattern'; message: string } {
  if (rawList === undefined || rawList === null) {
    return { ok: true, patterns: [] };
  }
  if (!Array.isArray(rawList)) {
    return {
      ok: false,
      status: 400,
      error: 'invalid_pattern',
      message: `${fieldName} must be an array of pattern strings`,
    };
  }
  if (rawList.length > 20) {
    return {
      ok: false,
      status: 400,
      error: 'invalid_pattern',
      message: `${fieldName} exceeds maximum of 20 patterns`,
    };
  }
  const patterns: string[] = [];
  for (let i = 0; i < rawList.length; i++) {
    const p = rawList[i];
    if (typeof p !== 'string' || !p.trim() || p.length > 160) {
      return {
        ok: false,
        status: 400,
        error: 'invalid_pattern',
        message: `${fieldName}[${i}] must be a non-empty pattern string up to 160 characters`,
      };
    }
    const trimmed = p.trim();
    const isPlainPrefix = trimmed.startsWith('/') && !/[\\^$*+?()[\]{}|]/.test(trimmed);
    if (!isPlainPrefix && !compileSafeUserRegex(trimmed)) {
      return {
        ok: false,
        status: 400,
        error: 'invalid_pattern',
        message: `${fieldName}[${i}] is an invalid or unsafe regular expression: ${trimmed.slice(0, 80)}`,
      };
    }
    patterns.push(trimmed);
  }
  return { ok: true, patterns };
}

let lastCrawlSubject = '\u0000__UNSET__';
const lastCrawlSubjectCache = new Map<string, boolean>();
const crawlPatternSetWeakCache = new WeakMap<readonly string[], (subject: string) => boolean>();

function isPlainSlashPrefixPattern(p: string): boolean {
  if (!p.startsWith('/')) return false;
  for (let i = 1; i < p.length; i++) {
    const c = p.charCodeAt(i);
    if (
      c === 92 /* '\\' */ ||
      c === 94 /* '^' */ ||
      c === 36 /* '$' */ ||
      c === 42 /* '*' */ ||
      c === 43 /* '+' */ ||
      c === 63 /* '?' */ ||
      c === 40 /* '(' */ ||
      c === 41 /* ')' */ ||
      c === 91 /* '[' */ ||
      c === 93 /* ']' */ ||
      c === 123 /* '{' */ ||
      c === 125 /* '}' */ ||
      c === 124 /* '|' */
    ) {
      return false;
    }
  }
  return true;
}

export function matchesSafeCrawlPattern(target: string, pattern: string): boolean {
  if (!pattern || pattern.length > 160) return false;
  const boundedTarget = target.length > 2048 ? target.slice(0, 2048) : target;
  if (boundedTarget !== lastCrawlSubject) {
    lastCrawlSubject = boundedTarget;
    lastCrawlSubjectCache.clear();
  } else {
    const hit = lastCrawlSubjectCache.get(pattern);
    if (hit !== undefined) return hit;
  }

  let matched: boolean;
  if (isPlainSlashPrefixPattern(pattern)) {
    matched = boundedTarget.startsWith(pattern);
  } else {
    const safeRe = compileSafeUserRegex(pattern);
    matched = safeRe ? safeRe.test(boundedTarget) : false;
  }

  if (lastCrawlSubjectCache.size < 128) {
    lastCrawlSubjectCache.set(pattern, matched);
  }
  return matched;
}

function getCompiledCrawlPatternListMatcher(patterns: readonly string[]): (subject: string) => boolean {
  if (patterns.length === 0) return () => false;
  const cached = crawlPatternSetWeakCache.get(patterns);
  if (cached) return cached;

  const plainPrefixes: string[] = [];
  const regexPatterns: string[] = [];
  const seen = new Set<string>();
  for (const p of patterns) {
    if (!p || p.length > 160 || seen.has(p)) continue;
    seen.add(p);
    if (isPlainSlashPrefixPattern(p)) {
      plainPrefixes.push(p);
    } else {
      regexPatterns.push(p);
    }
  }

  const unionFn = regexPatterns.length > 0 ? compileSafeUserRegexUnion(regexPatterns, 2048) : null;
  const matcher = (rawSubject: string): boolean => {
    const bounded = rawSubject.length > 2048 ? rawSubject.slice(0, 2048) : rawSubject;
    for (let i = 0; i < plainPrefixes.length; i++) {
      if (bounded.startsWith(plainPrefixes[i]!)) return true;
    }
    if (unionFn) return unionFn(bounded);
    for (let i = 0; i < regexPatterns.length; i++) {
      if (matchesSafeCrawlPattern(bounded, regexPatterns[i]!)) return true;
    }
    return false;
  };
  crawlPatternSetWeakCache.set(patterns, matcher);
  return matcher;
}

function pathAllowed(
  candidateUrl: URL,
  includePaths: string[],
  excludePaths: string[],
  regexOnFullURL: boolean,
): boolean {
  const subject = regexOnFullURL ? candidateUrl.toString() : candidateUrl.pathname;
  if (excludePaths.length > 0 && getCompiledCrawlPatternListMatcher(excludePaths)(subject)) {
    return false;
  }
  if (includePaths.length === 0) return true;
  return getCompiledCrawlPatternListMatcher(includePaths)(subject);
}

const crawlsUserIdMigratedDbs = new WeakSet<object>();
const crawlsUserIdColumnVerifiedDbs = new WeakSet<object>();
const privateCrawlPagesMigratedDbs = new WeakSet<object>();
const memberJobRateWindows = new Map<string, { count: number; resetAt: number }>();
const MAX_MEMBER_JOBS_PER_MINUTE = 20;
const MAX_MEMBER_ACTIVE_CRAWLS = 4;

async function sha256HexLocal(input: string): Promise<string> {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(input));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

async function ensureCrawlsUserIdColumn(metaDb: D1Database): Promise<void> {
  const key = metaDb as unknown as object;
  if (crawlsUserIdMigratedDbs.has(key)) return;
  await ensureD1ColumnIfMissing({
    db: metaDb,
    table: 'crawls',
    column: 'user_id',
    alterSql: "ALTER TABLE crawls ADD COLUMN user_id TEXT NOT NULL DEFAULT 'owner'",
    cacheSet: crawlsUserIdColumnVerifiedDbs,
  });
  await metaDb
    .prepare('CREATE INDEX IF NOT EXISTS crawls_user_idx ON crawls(user_id, created_at DESC)')
    .run()
    .catch(() => undefined);
  crawlsUserIdMigratedDbs.add(key);
}

async function ensurePrivateCrawlPagesTable(metaDb: D1Database): Promise<void> {
  const key = metaDb as unknown as object;
  if (privateCrawlPagesMigratedDbs.has(key)) return;
  await metaDb
    .prepare(
      `CREATE TABLE IF NOT EXISTS private_crawl_pages (
         id INTEGER PRIMARY KEY AUTOINCREMENT,
         crawl_id TEXT NOT NULL,
         user_id TEXT NOT NULL,
         url TEXT NOT NULL,
         status INTEGER NOT NULL,
         outcome TEXT NOT NULL,
         title TEXT,
         content_sha256 TEXT,
         r2_key TEXT,
         markdown_inline TEXT,
         fetched_at INTEGER NOT NULL
       )`,
    )
    .run()
    .catch(() => undefined);
  await metaDb
    .prepare('CREATE INDEX IF NOT EXISTS private_crawl_pages_idx ON private_crawl_pages(crawl_id, user_id, fetched_at ASC)')
    .run()
    .catch(() => undefined);
  privateCrawlPagesMigratedDbs.add(key);
}

function checkMemberJobRateQuota(bucketKey: string, now: number): boolean {
  for (const [k, v] of memberJobRateWindows.entries()) {
    if (v.resetAt <= now) memberJobRateWindows.delete(k);
  }
  const cur = memberJobRateWindows.get(bucketKey);
  if (!cur) {
    memberJobRateWindows.set(bucketKey, { count: 1, resetAt: now + 60_000 });
    return true;
  }
  if (cur.count >= MAX_MEMBER_JOBS_PER_MINUTE) {
    return false;
  }
  cur.count++;
  return true;
}

export async function createCrawlJob(params: {
  payload: Record<string, unknown>;
  metaDb?: D1Database;
  selfHost?: string;
  userId?: string;
  now?: number;
}): Promise<
  | { ok: true; crawlId: string; rootUrl: string; options: CrawlJobOptions }
  | { ok: false; status: number; error: string; message: string }
> {
  const { payload, metaDb, selfHost, now = Date.now() } = params;
  const activeAuth = getActiveCallerAuthContext();
  const effectiveUserId = sanitizeStorageUserId(params.userId ?? activeAuth?.userId ?? 'owner');
  const isMemberCaller = activeAuth?.role === 'member' || (effectiveUserId !== 'owner' && activeAuth?.role !== 'owner');
  const urlCheck = validatePublicHttpsUrl(payload.url, selfHost);
  if (!urlCheck.ok) {
    return { ok: false, status: 400, error: 'invalid_url', message: urlCheck.message };
  }
  const incCheck = validateCrawlPathPatterns(payload.includePaths, 'includePaths');
  if (!incCheck.ok) {
    return incCheck;
  }
  const excCheck = validateCrawlPathPatterns(payload.excludePaths, 'excludePaths');
  if (!excCheck.ok) {
    return excCheck;
  }
  if (!metaDb) {
    return { ok: false, status: 503, error: 'tracking_not_configured', message: 'Async crawl requires META D1 binding' };
  }
  await ensureCrawlsUserIdColumn(metaDb);

  if (isMemberCaller) {
    if (!checkMemberJobRateQuota(`crawl:${effectiveUserId}`, now)) {
      return {
        ok: false,
        status: 429,
        error: 'rate_limited',
        message: 'Per-user crawl rate quota exceeded. Please wait before starting additional crawls.',
      };
    }
    const activeRow = await metaDb
      .prepare("SELECT COUNT(*) AS c FROM crawls WHERE user_id = ? AND status IN ('queued', 'running')")
      .bind(effectiveUserId)
      .first<{ c: number }>()
      .catch(() => null);
    if ((activeRow?.c ?? 0) >= MAX_MEMBER_ACTIVE_CRAWLS) {
      return {
        ok: false,
        status: 429,
        error: 'rate_limited',
        message: `Per-user concurrent crawl limit (${MAX_MEMBER_ACTIVE_CRAWLS}) reached.`,
      };
    }
  }

  let webhook: WebhookConfig | undefined;
  if (payload.webhook && typeof payload.webhook === 'object') {
    const w = payload.webhook as Record<string, unknown>;
    const whCheck = validatePublicHttpsUrl(w.url, selfHost);
    if (!whCheck.ok) {
      return { ok: false, status: 400, error: 'invalid_webhook_url', message: whCheck.message };
    }
    const allowedEvents = ['crawl.started', 'crawl.page', 'crawl.completed', 'crawl.failed'] as const;
    const evs = Array.isArray(w.events)
      ? w.events.filter((e): e is (typeof allowedEvents)[number] => allowedEvents.includes(e as never))
      : undefined;
    webhook = {
      url: whCheck.url.toString(),
      ...(typeof w.secret === 'string' && w.secret.trim() ? { secret: w.secret.trim() } : {}),
      ...(evs && evs.length > 0 ? { events: evs } : {}),
      ...(w.metadata && typeof w.metadata === 'object' ? { metadata: w.metadata as Record<string, unknown> } : {}),
    };
  }

  const crawlId = `crw_${crypto.randomUUID().replace(/-/g, '').slice(0, 24)}`;
  const rawColl = typeof payload.collectionId === 'string' ? payload.collectionId.trim() : crawlId;
  const rawMaxDepth =
    typeof payload.maxDepth === 'number' && Number.isFinite(payload.maxDepth)
      ? payload.maxDepth
      : typeof payload.maxDiscoveryDepth === 'number' && Number.isFinite(payload.maxDiscoveryDepth)
        ? payload.maxDiscoveryDepth
        : 2;
  const regexOnFullURL = Boolean(payload.regexOnFullURL);
  const rawSitemap = typeof payload.sitemap === 'string' ? payload.sitemap.trim().toLowerCase() : '';
  const sitemapMode: 'include' | 'skip' | 'only' =
    rawSitemap === 'skip' || payload.ignoreSitemap === true ? 'skip' : rawSitemap === 'only' ? 'only' : 'include';
  const delayMs =
    typeof payload.delay === 'number' && Number.isFinite(payload.delay) && payload.delay >= 0
      ? Math.min(30_000, Math.round(payload.delay * 1_000))
      : undefined;

  const options: CrawlJobOptions = {
    userId: effectiveUserId,
    limit: typeof payload.limit === 'number' && Number.isFinite(payload.limit) ? Math.min(200, Math.max(1, Math.floor(payload.limit))) : 25,
    maxDepth: Math.min(8, Math.max(0, Math.floor(rawMaxDepth))),
    allowSubdomains: Boolean(payload.allowSubdomains),
    allowExternalLinks: Boolean(payload.allowExternalLinks),
    crawlEntireDomain: typeof payload.crawlEntireDomain === 'boolean' ? payload.crawlEntireDomain : true,
    regexOnFullURL,
    ignoreQueryParameters: Boolean(payload.ignoreQueryParameters),
    deduplicateSimilarURLs: payload.deduplicateSimilarURLs !== false,
    sitemap: sitemapMode,
    ...(delayMs !== undefined ? { delayMs } : {}),
    includePaths: incCheck.patterns,
    excludePaths: excCheck.patterns,
    ...(COLLECTION_ID_RE.test(rawColl) || INTERNAL_COLLECTION_ID_RE.test(rawColl) ? { collectionId: rawColl } : {}),
    ...(payload.renderMode === 'auto' || payload.renderMode === 'always' || payload.renderMode === 'off'
      ? { renderMode: payload.renderMode }
      : {}),
    ...(webhook ? { webhook } : {}),
    target: payload.target === 'agent' || payload.target === 'container' ? payload.target : 'auto',
    ...(typeof payload.site === 'string' && payload.site.trim() ? { site: payload.site.trim() } : {}),
  };

  // Store options JSON WITHOUT raw caller webhook secrets in plaintext if a secret was provided (redact or keep in workflow).
  const storedOptions = {
    ...options,
    ...(options.webhook ? { webhook: { ...options.webhook, ...(options.webhook.secret ? { secret: undefined, hasSecret: true } : {}) } } : {}),
  };

  await metaDb
    .prepare(
      `INSERT INTO crawls (id, user_id, root_url, status, options_json, discovered_count, fetched_count, failed_count, created_at, updated_at)
       VALUES (?, ?, ?, 'queued', ?, 1, 0, 0, ?, ?)`,
    )
    .bind(crawlId, effectiveUserId, urlCheck.url.toString(), JSON.stringify(storedOptions), now, now)
    .run();

  return { ok: true, crawlId, rootUrl: urlCheck.url.toString(), options };
}

export async function executeCrawlJob(params: {
  crawlId: string;
  rootUrl: string;
  options: CrawlJobOptions;
  userId?: string;
  env: OptionalStorageBindings & { WEBHOOK_SECRET?: string };
  executeHubFetch: HubFetchExecutor;
  selfHost?: string;
  webhookFetchFn?: typeof fetch;
  waitUntilBounded?: boolean;
  maxRuntimeMs?: number;
  tracer?: RequestTracer | TraceContext;
}): Promise<{ status: 'completed' | 'cancelled' | 'failed'; fetchedCount: number; failedCount: number; discoveredCount: number }> {
  const activeTracer = getActiveRequestTracer(params.tracer);
  const runCrawl = async (): Promise<{ status: 'completed' | 'cancelled' | 'failed'; fetchedCount: number; failedCount: number; discoveredCount: number }> => {
  const { crawlId, rootUrl, options, env, executeHubFetch, selfHost } = params;
  const envFetch = env as { SAFE_PUBLIC_FETCH?: typeof fetch; SAFE_FETCH?: typeof fetch };
  const webhookFetchFn = params.webhookFetchFn ?? envFetch.SAFE_PUBLIC_FETCH ?? envFetch.SAFE_FETCH;
  const metaDb = env.META!;
  await ensureCrawlsUserIdColumn(metaDb);
  const rootParsed = new URL(rootUrl);
  const startedAt = Date.now();
  const runtimeBudgetMs =
    typeof params.maxRuntimeMs === 'number' && Number.isFinite(params.maxRuntimeMs) && params.maxRuntimeMs > 0
      ? params.maxRuntimeMs
      : params.waitUntilBounded
        ? 23_000
        : 120_000;

  const initialRow = await metaDb
    .prepare('SELECT status, user_id FROM crawls WHERE id = ? LIMIT 1')
    .bind(crawlId)
    .first<{ status: string; user_id?: string }>()
    .catch(() => null);
  const effectiveUserId = sanitizeStorageUserId(
    params.userId ?? options.userId ?? initialRow?.user_id ?? getActiveCallerAuthContext()?.userId ?? 'owner',
  );
  const isPrivateCrawl = effectiveUserId !== 'owner';
  if (isPrivateCrawl) {
    await ensurePrivateCrawlPagesTable(metaDb);
  }

  const isCancelled = async (): Promise<boolean> => {
    const row = await metaDb.prepare('SELECT status FROM crawls WHERE id = ? LIMIT 1').bind(crawlId).first<{ status: string }>();
    return row?.status === 'cancelled';
  };

  if (initialRow?.status === 'cancelled') {
    return { status: 'cancelled', fetchedCount: 0, failedCount: 0, discoveredCount: 1 };
  }

  await metaDb
    .prepare("UPDATE crawls SET status = 'running', updated_at = ? WHERE id = ? AND status != 'cancelled'")
    .bind(Date.now(), crawlId)
    .run();

  if (options.webhook) {
    await deliverSignedWebhook({
      webhook: options.webhook,
      defaultSecret: env.WEBHOOK_SECRET,
      event: 'crawl.started',
      crawlId,
      data: { rootUrl, limit: options.limit, maxDepth: options.maxDepth },
      selfHost,
      ...(webhookFetchFn ? { fetchFn: webhookFetchFn } : {}),
      ...(activeTracer ? { tracer: activeTracer } : {}),
    });
  }

  const visited = new Set<string>();
  let frontier: string[] = [];
  if (options.sitemap === 'include' || options.sitemap === 'only') {
    const mapSeed = await executeMapCall({
      payload: {
        url: rootUrl,
        limit: Math.min(options.limit * 2, 250),
        includeSubdomains: options.allowSubdomains,
        sitemap: options.sitemap,
        ignoreQueryParameters: options.ignoreQueryParameters,
        deduplicateSimilarURLs: options.deduplicateSimilarURLs,
      },
      executeHubFetch,
      selfHost,
      source: `crawl-sitemap:${crawlId}`,
      ...(activeTracer ? { tracer: activeTracer } : {}),
    }).catch(() => null);
    const seedLinks = Array.isArray(mapSeed?.body?.links) ? (mapSeed!.body.links as string[]) : [];
    for (const sl of seedLinks) {
      try {
        const su = new URL(sl);
        if (pathAllowed(su, options.includePaths, options.excludePaths, options.regexOnFullURL)) {
          visited.add(su.toString());
          frontier.push(su.toString());
        }
      } catch {
        // ignore
      }
    }
  }
  if (!visited.has(rootUrl) && options.sitemap !== 'only') {
    visited.add(rootUrl);
    frontier.unshift(rootUrl);
  }
  let fetchedCount = 0;
  let failedCount = 0;

  try {
    for (let depth = 0; depth <= options.maxDepth && frontier.length > 0 && fetchedCount + failedCount < options.limit; depth++) {
      if (depth > 0 && Date.now() - startedAt >= runtimeBudgetMs) {
        break;
      }
      if (await isCancelled()) {
        return { status: 'cancelled', fetchedCount, failedCount, discoveredCount: visited.size };
      }

      const remainingBudget = options.limit - (fetchedCount + failedCount);
      const wave = frontier.slice(0, Math.min(remainingBudget, 15));
      const nextFrontier: string[] = [];

      // Multi-user crawl isolation: when `effectiveUserId !== 'owner'`, NEVER trigger shared R2 raw artifact uploads,
      // shared R2 `r2DerivedKey` writes, or shared `META` `artifacts`/`pages`/`documents` ingest rows!
      const retention: ArtifactRetention | 'off' | undefined = isPrivateCrawl
        ? 'off'
        : env.ARTIFACTS
          ? 'stored'
          : undefined;
      const remainingRuntimeSec = Math.max(8, Math.min(45, Math.floor(Math.max(8_000, runtimeBudgetMs - (Date.now() - startedAt)) / 1_000)));
      const effectivePauseMs = options.delayMs !== undefined ? options.delayMs : 800;
      const call = {
        maxSeconds: remainingRuntimeSec,
        options: { includeBody: true, respectRobots: true, discoverLlms: false, pauseMs: effectivePauseMs, pauseJitterMs: 200 },
        requests: wave.map((u, idx) => ({
          id: `c-${depth}-${idx}`,
          url: u,
          kind: options.renderMode === 'always' ? 'render' : 'scrape',
          formats: ['markdown', 'links'],
          onlyMainContent: true,
          ...(options.renderMode ? { renderMode: options.renderMode } : {}),
        })),
      };

      const callWaveFetch = () =>
        executeHubFetch(
          options.target,
          JSON.stringify(call),
          options.site,
          `crawl:${crawlId}`,
          retention,
          true,
          isPrivateCrawl ? undefined : options.collectionId,
          isPrivateCrawl ? undefined : crawlId,
        );
      const fetchOut = await (activeTracer ? activeTracer.run(callWaveFetch) : callWaveFetch());

      if (fetchOut.status !== 200) {
        failedCount += wave.length;
        break;
      }

      const rootSubpathPrefix = rootParsed.pathname.replace(/\/+$/, '');
      const parsed = JSON.parse(fetchOut.bodyText) as { results?: Array<Record<string, unknown>> };
      for (const item of parsed.results ?? []) {
        const itemUrl = typeof item.url === 'string' ? item.url : '';
        if (item.outcome === 'ok') {
          fetchedCount++;
          const rawHtml = typeof item.body === 'string' && item.bodyEncoding !== 'base64' ? item.body : '';
          const isHtml = Boolean(
            rawHtml &&
              ((typeof item.contentType === 'string' && item.contentType.toLowerCase().includes('html')) ||
                /^\s*<!doctype\s+html|^\s*<html|<(head|body|main|article)\b/i.test(rawHtml)),
          );
          const ext = isHtml ? extractHtmlDocument(rawHtml, { baseUrl: itemUrl, onlyMainContent: true }) : undefined;
          const rawMdCandidate =
            (isHtml ? ext?.markdown : undefined) ||
            (typeof item.markdown === 'string' && item.markdown ? item.markdown : '') ||
            ext?.markdown ||
            (!isHtml ? rawHtml : '');
          const fm = parseMarkdownFrontmatter(rawMdCandidate);
          const md = sanitizeInlineHtmlInMarkdown(decodeMarkdownEntities(fm.body), itemUrl).trim();
          const mdAssets = !isHtml && rawMdCandidate ? extractMarkdownLinksAndImages(rawMdCandidate, itemUrl, false) : undefined;
          const itemLinks = Array.isArray(item.links) ? (item.links as string[]) : [];
          const links = isHtml
            ? (ext?.links && ext.links.length > 0 ? ext.links : itemLinks)
            : itemLinks.length > 0
              ? itemLinks
              : (mdAssets?.links ?? []);

          const resolvedPageTitle =
            ext?.title ||
            fm.title ||
            mdAssets?.title ||
            (typeof item.title === 'string' && item.title ? decodeHtmlEntities(item.title) : undefined);

          if (itemUrl) {
            await ensurePrivateCrawlPagesTable(metaDb);
            const pageFetchedAt = Date.now();
            const contentSha256 = md ? await sha256HexLocal(md) : null;
            let storedR2Key: string | null = null;
            if (env.ARTIFACTS && md && contentSha256) {
              storedR2Key = isPrivateCrawl
                ? r2PrivateDerivedKey(effectiveUserId, SCRAPE_PIPELINE_VERSION, 'markdown', contentSha256)
                : r2DerivedKey(SCRAPE_PIPELINE_VERSION, 'markdown', contentSha256);
              await env.ARTIFACTS.put(storedR2Key, md, {
                httpMetadata: { contentType: 'text/markdown; charset=utf-8' },
              }).catch(() => {
                storedR2Key = null;
              });
            }
            await metaDb
              .prepare(
                `INSERT INTO private_crawl_pages
                 (crawl_id, user_id, url, status, outcome, title, content_sha256, r2_key, markdown_inline, fetched_at)
                 VALUES (?, ?, ?, ?, 'ok', ?, ?, ?, ?, ?)`,
              )
              .bind(
                crawlId,
                effectiveUserId,
                itemUrl,
                typeof item.status === 'number' ? item.status : 200,
                resolvedPageTitle ?? null,
                contentSha256,
                storedR2Key,
                storedR2Key ? null : md.slice(0, 262_144),
                pageFetchedAt,
              )
              .run()
              .catch(() => undefined);

            if (env.SEARCH && options.collectionId && md && contentSha256) {
              const scopedColl = resolveUserCollectionId(
                options.collectionId,
                effectiveUserId,
                isPrivateCrawl ? 'private' : 'public',
              );
              if (scopedColl.ok) {
                const pageId = (await sha256HexLocal(`${effectiveUserId}:${itemUrl}`)).slice(0, 32);
                const idx = new D1FtsSearchIndex(env.SEARCH);
                await idx
                  .replacePageChunks({
                    collectionId: scopedColl.scopedId,
                    documentId: `${isPrivateCrawl ? 'privcrawl' : 'crawl'}:${contentSha256.slice(0, 32)}`,
                    pageId,
                    url: itemUrl,
                    title: resolvedPageTitle || itemUrl,
                    markdown: md,
                    fetchedAt: pageFetchedAt,
                  })
                  .catch(() => undefined);
              }
            }
          }

          if (options.webhook) {
            await deliverSignedWebhook({
              webhook: options.webhook,
              defaultSecret: env.WEBHOOK_SECRET,
              event: 'crawl.page',
              crawlId,
              data: {
                url: itemUrl,
                status: item.status ?? 200,
                title: resolvedPageTitle,
                markdownPreview: md.slice(0, 2_000),
              },
              selfHost,
              ...(webhookFetchFn ? { fetchFn: webhookFetchFn } : {}),
              ...(activeTracer ? { tracer: activeTracer } : {}),
            });
          }

          if (depth < options.maxDepth && options.sitemap !== 'only') {
            for (const lnk of links) {
              if (visited.size >= options.limit * 3) break;
              try {
                const lu = new URL(lnk, itemUrl);
                if (lu.protocol !== 'https:' || (lu.port && lu.port !== '443')) continue;
                const sameDomainOrSub = matchesHostScope(lu.hostname, rootParsed.hostname, options.allowSubdomains);
                if (!sameDomainOrSub) {
                  if (!options.allowExternalLinks || !isSafeDomainHost(lu.hostname, selfHost)) continue;
                }
                if (
                  sameDomainOrSub &&
                  !options.crawlEntireDomain &&
                  rootSubpathPrefix &&
                  rootSubpathPrefix !== '/' &&
                  lu.pathname !== rootSubpathPrefix &&
                  !lu.pathname.startsWith(`${rootSubpathPrefix}/`)
                ) {
                  continue;
                }
                if (!pathAllowed(lu, options.includePaths, options.excludePaths, options.regexOnFullURL)) continue;
                lu.hash = '';
                if (options.ignoreQueryParameters) {
                  lu.search = '';
                } else {
                  for (const k of [...lu.searchParams.keys()]) {
                    const lk = k.toLowerCase();
                    if (
                      lk.startsWith('utm_') ||
                      lk === 'gclid' ||
                      lk === 'fbclid' ||
                      lk === 'msclkid' ||
                      lk === 'mc_cid' ||
                      lk === 'mc_eid' ||
                      lk === '_hsenc' ||
                      lk === '_hsmi' ||
                      lk === 'ref_src' ||
                      lk === 'spm'
                    ) {
                      lu.searchParams.delete(k);
                    }
                  }
                }
                if (options.deduplicateSimilarURLs && lu.pathname.length > 1 && lu.pathname.endsWith('/')) {
                  lu.pathname = lu.pathname.replace(/\/+$/, '');
                }
                const clean = lu.toString();
                if (!visited.has(clean)) {
                  visited.add(clean);
                  nextFrontier.push(clean);
                }
              } catch {
                // ignore
              }
            }
          }
        } else {
          failedCount++;
          if (itemUrl) {
            await ensurePrivateCrawlPagesTable(metaDb);
            await metaDb
              .prepare(
                `INSERT INTO private_crawl_pages
                 (crawl_id, user_id, url, status, outcome, title, content_sha256, r2_key, markdown_inline, fetched_at)
                 VALUES (?, ?, ?, ?, ?, NULL, NULL, NULL, NULL, ?)`,
              )
              .bind(
                crawlId,
                effectiveUserId,
                itemUrl,
                typeof item.status === 'number' ? item.status : 0,
                typeof item.outcome === 'string' && item.outcome ? item.outcome : 'error',
                Date.now(),
              )
              .run()
              .catch(() => undefined);
          }
        }
      }

      const rootPrefix = rootParsed.pathname.endsWith('/') ? rootParsed.pathname : `${rootParsed.pathname}/`;
      if (options.includePaths.length === 0 && rootPrefix !== '/' && nextFrontier.length > 1) {
        nextFrontier.sort((a, b) => {
          const aIn = new URL(a).pathname.startsWith(rootPrefix) ? 1 : 0;
          const bIn = new URL(b).pathname.startsWith(rootPrefix) ? 1 : 0;
          return bIn - aIn;
        });
      }

      // Fetch rows get this crawl's id from the ingest manifest (executeHubFetch's crawlId). The old URL match here
      // also claimed other callers' fetches of the same URL from the last two minutes.

      await metaDb
        .prepare(
          `UPDATE crawls
           SET discovered_count = ?, fetched_count = ?, failed_count = ?, updated_at = ?
           WHERE id = ?`,
        )
        .bind(visited.size, fetchedCount, failedCount, Date.now(), crawlId)
        .run();

      frontier = nextFrontier;
    }

    if (await isCancelled()) {
      return { status: 'cancelled', fetchedCount, failedCount, discoveredCount: visited.size };
    }

    const doneNow = Date.now();
    await metaDb
      .prepare(
        `UPDATE crawls
         SET status = 'completed', discovered_count = ?, fetched_count = ?, failed_count = ?, updated_at = ?, finished_at = ?
         WHERE id = ? AND status != 'cancelled'`,
      )
      .bind(visited.size, fetchedCount, failedCount, doneNow, doneNow, crawlId)
      .run();

    if (options.webhook) {
      await deliverSignedWebhook({
        webhook: options.webhook,
        defaultSecret: env.WEBHOOK_SECRET,
        event: 'crawl.completed',
        crawlId,
        data: { rootUrl, discoveredCount: visited.size, fetchedCount, failedCount, collectionId: options.collectionId },
        selfHost,
        ...(webhookFetchFn ? { fetchFn: webhookFetchFn } : {}),
        ...(activeTracer ? { tracer: activeTracer } : {}),
      });
    }

    return { status: 'completed', fetchedCount, failedCount, discoveredCount: visited.size };
  } catch (e) {
    const failNow = Date.now();
    await metaDb
      .prepare("UPDATE crawls SET status = 'failed', updated_at = ?, finished_at = ? WHERE id = ?")
      .bind(failNow, failNow, crawlId)
      .run()
      .catch(() => undefined);
    if (options.webhook) {
      await deliverSignedWebhook({
        webhook: options.webhook,
        defaultSecret: env.WEBHOOK_SECRET,
        event: 'crawl.failed',
        crawlId,
        data: { rootUrl, error: e instanceof Error ? e.message : String(e) },
        selfHost,
        ...(webhookFetchFn ? { fetchFn: webhookFetchFn } : {}),
        ...(activeTracer ? { tracer: activeTracer } : {}),
      });
    }
    return { status: 'failed', fetchedCount, failedCount, discoveredCount: visited.size };
  }
  };
  return activeTracer ? activeTracer.run(runCrawl) : runCrawl();
}

export async function getCrawlJobStatus(params: {
  crawlId: string;
  metaDb?: D1Database;
  bucket?: R2Bucket;
  userId?: string;
  offset?: number;
  limit?: number;
  now?: number;
}): Promise<{ ok: true; crawl: Record<string, unknown> } | { ok: false; status: number; error: string }> {
  const { crawlId, metaDb, bucket, offset = 0, limit = 25, now = Date.now() } = params;
  if (!metaDb) return { ok: false, status: 503, error: 'tracking_not_configured' };
  await ensureCrawlsUserIdColumn(metaDb);
  const effectiveUserId = sanitizeStorageUserId(params.userId ?? getActiveCallerAuthContext()?.userId ?? 'owner');

  const row = await metaDb
    .prepare(
      `SELECT id, user_id, root_url, status, options_json, discovered_count, fetched_count, failed_count, created_at, updated_at, finished_at
       FROM crawls WHERE id = ? AND user_id = ? LIMIT 1`,
    )
    .bind(crawlId, effectiveUserId)
    .first<{
      id: string;
      user_id?: string;
      root_url: string;
      status: string;
      options_json: string;
      discovered_count: number;
      fetched_count: number;
      failed_count: number;
      created_at: number;
      updated_at: number;
      finished_at: number | null;
    }>();
  if (!row) return { ok: false, status: 404, error: 'crawl_not_found' };

  let parsedOpts: Record<string, unknown> = {};
  try {
    parsedOpts = JSON.parse(row.options_json) as Record<string, unknown>;
  } catch {
    // ignore
  }
  const configuredLimit =
    typeof parsedOpts.limit === 'number' && Number.isFinite(parsedOpts.limit) && parsedOpts.limit > 0
      ? Math.floor(parsedOpts.limit)
      : 25;

  const isPrivateCrawl = effectiveUserId !== 'owner';
  await ensurePrivateCrawlPagesTable(metaDb);

  // Reconcile live fetch counts from `fetches` AND `private_crawl_pages` so `fetchedCount`, `status`, and `data`
  // populate deterministically whether executed via `CrawlWorkflow`, `ctx.waitUntil`, or before `IngestWorkflow` finishes!
  const crawlPagesAgg = await metaDb
    .prepare(
      `SELECT
         SUM(CASE WHEN outcome = 'ok' THEN 1 ELSE 0 END) AS ok_cnt,
         SUM(CASE WHEN outcome != 'ok' THEN 1 ELSE 0 END) AS fail_cnt,
         MAX(fetched_at) AS last_fetched_at
       FROM private_crawl_pages
       WHERE crawl_id = ? AND user_id = ?`,
    )
    .bind(crawlId, effectiveUserId)
    .first<{ ok_cnt: number | null; fail_cnt: number | null; last_fetched_at: number | null }>()
    .catch(() => null);

  const fetchesAgg = isPrivateCrawl
    ? null
    : await metaDb
        .prepare(
          `SELECT
             SUM(CASE WHEN outcome = 'ok' THEN 1 ELSE 0 END) AS ok_cnt,
             SUM(CASE WHEN outcome != 'ok' THEN 1 ELSE 0 END) AS fail_cnt,
             MAX(fetched_at) AS last_fetched_at
           FROM fetches
           WHERE crawl_id = ?`,
        )
        .bind(crawlId)
        .first<{ ok_cnt: number | null; fail_cnt: number | null; last_fetched_at: number | null }>()
        .catch(() => null);

  const liveOk = Math.max(Number(fetchesAgg?.ok_cnt ?? 0), Number(crawlPagesAgg?.ok_cnt ?? 0));
  const liveFail = Math.max(Number(fetchesAgg?.fail_cnt ?? 0), Number(crawlPagesAgg?.fail_cnt ?? 0));
  const lastFetchedAt = Math.max(Number(fetchesAgg?.last_fetched_at ?? 0), Number(crawlPagesAgg?.last_fetched_at ?? 0));
  const effectiveFetched = Math.max(row.fetched_count, liveOk);
  const effectiveFailed = Math.max(row.failed_count, liveFail);
  const effectiveDiscovered = Math.max(row.discovered_count, effectiveFetched + effectiveFailed);
  let effectiveStatus = row.status;
  let effectiveUpdatedAt = Math.max(row.updated_at, lastFetchedAt);
  let effectiveFinishedAt = row.finished_at;

  if (
    (row.status === 'queued' || row.status === 'running') &&
    (effectiveFetched + effectiveFailed >= configuredLimit || now - effectiveUpdatedAt > 45_000)
  ) {
    effectiveStatus = effectiveFetched > 0 ? 'completed' : 'failed';
    effectiveUpdatedAt = now;
    effectiveFinishedAt = row.finished_at ?? (lastFetchedAt > 0 ? lastFetchedAt : now);
    await metaDb
      .prepare(
        `UPDATE crawls
         SET status = ?, discovered_count = ?, fetched_count = ?, failed_count = ?, updated_at = ?, finished_at = ?
         WHERE id = ? AND status IN ('queued', 'running')`,
      )
      .bind(
        effectiveStatus,
        effectiveDiscovered,
        effectiveFetched,
        effectiveFailed,
        effectiveUpdatedAt,
        effectiveFinishedAt,
        crawlId,
      )
      .run()
      .catch(() => undefined);
  }

  const safeOffset = Math.max(0, Math.floor(offset));
  const safeLimit = Math.min(50, Math.max(1, Math.floor(limit)));
  const data: Array<Record<string, unknown>> = [];
  let hasMoreRows = false;

  if (isPrivateCrawl) {
    const rawPrivRows =
      (
        await metaDb
          .prepare(
            `SELECT url, status, outcome, title, content_sha256, r2_key, markdown_inline, fetched_at
             FROM private_crawl_pages
             WHERE crawl_id = ? AND user_id = ?
             ORDER BY fetched_at ASC, id ASC
             LIMIT ? OFFSET ?`,
          )
          .bind(crawlId, effectiveUserId, safeLimit + 1, safeOffset)
          .all<{
            url: string;
            status: number;
            outcome: string;
            title: string | null;
            content_sha256: string | null;
            r2_key: string | null;
            markdown_inline: string | null;
            fetched_at: number;
          }>()
      ).results ?? [];
    hasMoreRows = rawPrivRows.length > safeLimit;
    const privRows = hasMoreRows ? rawPrivRows.slice(0, safeLimit) : rawPrivRows;
    const expectedPrivPrefix = `private/${effectiveUserId}/`;
    for (const pr of privRows) {
      let markdown: string | undefined;
      if (bucket && pr.r2_key && pr.r2_key.startsWith(expectedPrivPrefix)) {
        const mdObj = await bucket.get(pr.r2_key);
        if (mdObj) {
          markdown = await mdObj.text();
        }
      }
      if (markdown === undefined && typeof pr.markdown_inline === 'string') {
        markdown = pr.markdown_inline;
      }
      data.push({
        url: pr.url,
        status: pr.status,
        outcome: pr.outcome,
        visibility: 'private',
        ...(pr.title ? { title: pr.title } : {}),
        ...(markdown !== undefined ? { markdown } : {}),
        fetchedAt: pr.fetched_at,
      });
    }
  } else {
    const rawPageRows = (
      await metaDb
        .prepare(
          `SELECT p.url, f.status, f.outcome, f.content_sha256, f.blob_sha256, f.fetched_at, d.title, d.r2_key
           FROM fetches f
           JOIN pages p ON p.id = f.page_id
           LEFT JOIN documents d ON d.id = (
             SELECT id FROM documents
             WHERE content_sha256 = f.content_sha256 AND format = 'markdown'
             ORDER BY pipeline_version DESC
             LIMIT 1
           )
           WHERE f.crawl_id = ?
           ORDER BY f.fetched_at ASC
           LIMIT ? OFFSET ?`,
        )
        .bind(crawlId, safeLimit + 1, safeOffset)
        .all<{
          url: string;
          status: number;
          outcome: string;
          content_sha256: string | null;
          blob_sha256: string | null;
          fetched_at: number;
          title: string | null;
          r2_key: string | null;
        }>()
    ).results ?? [];
    hasMoreRows = rawPageRows.length > safeLimit;
    const pageRows = hasMoreRows ? rawPageRows.slice(0, safeLimit) : rawPageRows;

    const pdfCandidatePipelines = [...new Set([SCRAPE_PIPELINE_VERSION, 1])];
    for (const pr of pageRows ?? []) {
      let markdown: string | undefined;
      let derivedTitle: string | undefined;
      const isPdfPage = pr.url.toLowerCase().endsWith('.pdf');
      if (bucket && pr.content_sha256) {
        let mdObj: R2ObjectBody | null = null;
        if (pr.r2_key) {
          mdObj = await bucket.get(pr.r2_key);
        } else if (isPdfPage) {
          for (const pv of pdfCandidatePipelines) {
            mdObj = await bucket.get(r2DerivedKey(pv, 'markdown', pr.content_sha256));
            if (mdObj) break;
          }
        }
        if (mdObj) {
          markdown = await mdObj.text();
        } else if (pr.blob_sha256 && pr.outcome === 'ok') {
          // Fallback when Crawl is polled immediately before IngestWorkflow finishes or on older vCard/text rows.
          const rawLoaded = await readVerifiedArtifactFromR2({
            bucket,
            blobSha256: pr.blob_sha256,
            preferredRetention: 'stored',
            expectedContentSha256: pr.content_sha256,
          });
          if (rawLoaded.ok && rawLoaded.bytes.byteLength > 0 && rawLoaded.bytes.byteLength <= 262_144) {
            const rawText = new TextDecoder('utf-8', { fatal: false }).decode(rawLoaded.bytes);
            if (!rawText.slice(0, 64).includes('%PDF-')) {
              if (/^\s*<!doctype\s+html|^\s*<html/i.test(rawText)) {
                const ext = extractHtmlDocument(rawText, { baseUrl: pr.url, onlyMainContent: true });
                markdown = ext.markdown;
                derivedTitle = ext.title;
              } else if (/^BEGIN:VCARD\b/im.test(rawText.trim())) {
                const vc = formatVcardToMarkdown(rawText);
                markdown = vc.markdown;
                derivedTitle = vc.title;
              } else if (/^BEGIN:VCALENDAR\b/im.test(rawText.trim())) {
                const ics = formatIcalendarToMarkdown(rawText);
                markdown = ics ? ics.markdown : rawText.trim();
                derivedTitle = ics?.title;
              } else {
                const structuredFallback =
                  formatFeedXmlToMarkdown(rawText, pr.url) ??
                  tryParseJsonPayloadForScrape(rawText, undefined, pr.url) ??
                  formatDelimitedTableToMarkdown(rawText, undefined, pr.url) ??
                  formatGitPatchToMarkdown(rawText, undefined, pr.url) ??
                  formatSourceCodeUrlToMarkdown(rawText, undefined, pr.url);
                if (structuredFallback) {
                  markdown = structuredFallback.markdown;
                  derivedTitle = structuredFallback.title;
                } else {
                  markdown = rawText.trim();
                }
              }
            }
          }
        }
      }
      if (markdown !== undefined) {
        const fm = isPdfPage ? { body: markdown } : parseMarkdownFrontmatter(markdown);
        if (!derivedTitle && fm.title) derivedTitle = fm.title;
        let cleaned = sanitizeInlineHtmlInMarkdown(decodeMarkdownEntities(fm.body), pr.url);
        if (isPdfPage) {
          cleaned = cleanPdfMarkdown(cleaned);
        }
        markdown = cleaned.trim();
        if (!derivedTitle && !pr.title && markdown) {
          derivedTitle = isPdfPage
            ? extractPdfTitle(markdown, pr.url)
            : extractMarkdownLinksAndImages(markdown, pr.url, false).title;
        }
      }
      const resolvedTitle = pr.title ? decodeHtmlEntities(pr.title) : derivedTitle;
      data.push({
        url: pr.url,
        status: pr.status,
        outcome: pr.outcome,
        ...(resolvedTitle ? { title: resolvedTitle } : {}),
        ...(pr.blob_sha256 ? { artifactId: pr.blob_sha256 } : {}),
        ...(markdown !== undefined ? { markdown } : {}),
        fetchedAt: pr.fetched_at,
      });
    }

    // Fallback for `owner` crawls executed via `CrawlWorkflow` (or polled before `IngestWorkflow` writes `fetches` rows):
    if (data.length === 0) {
      const rawOwnerFallbackRows =
        (
          await metaDb
            .prepare(
              `SELECT url, status, outcome, title, content_sha256, r2_key, markdown_inline, fetched_at
               FROM private_crawl_pages
               WHERE crawl_id = ? AND user_id = 'owner'
               ORDER BY fetched_at ASC, id ASC
               LIMIT ? OFFSET ?`,
            )
            .bind(crawlId, safeLimit + 1, safeOffset)
            .all<{
              url: string;
              status: number;
              outcome: string;
              title: string | null;
              content_sha256: string | null;
              r2_key: string | null;
              markdown_inline: string | null;
              fetched_at: number;
            }>()
            .catch(() => ({ results: [] }))
        ).results ?? [];
      if (rawOwnerFallbackRows.length > 0) {
        hasMoreRows = rawOwnerFallbackRows.length > safeLimit;
        const ownerRows = hasMoreRows ? rawOwnerFallbackRows.slice(0, safeLimit) : rawOwnerFallbackRows;
        for (const orow of ownerRows) {
          let markdown: string | undefined;
          if (bucket && orow.r2_key && orow.r2_key.startsWith('derived/')) {
            const mdObj = await bucket.get(orow.r2_key);
            if (mdObj) {
              markdown = await mdObj.text();
            }
          }
          if (markdown === undefined && typeof orow.markdown_inline === 'string') {
            markdown = orow.markdown_inline;
          }
          if (markdown !== undefined) {
            markdown = sanitizeInlineHtmlInMarkdown(decodeMarkdownEntities(markdown), orow.url).trim();
          }
          data.push({
            url: orow.url,
            status: orow.status,
            outcome: orow.outcome,
            ...(orow.title ? { title: orow.title } : {}),
            ...(markdown !== undefined ? { markdown } : {}),
            fetchedAt: orow.fetched_at,
          });
        }
      }
    }
  }

  return {
    ok: true,
    crawl: {
      id: row.id,
      rootUrl: row.root_url,
      status: effectiveStatus,
      collectionId: parsedOpts.collectionId,
      discoveredCount: effectiveDiscovered,
      fetchedCount: effectiveFetched,
      failedCount: effectiveFailed,
      createdAt: row.created_at,
      updatedAt: effectiveUpdatedAt,
      finishedAt: effectiveFinishedAt,
      offset: safeOffset,
      limit: safeLimit,
      hasMore: hasMoreRows,
      nextOffset: hasMoreRows ? safeOffset + data.length : null,
      data,
    },
  };
}

export async function cancelCrawlJob(crawlId: string, metaDb?: D1Database, userId?: string): Promise<{ ok: boolean; status: number }> {
  if (!metaDb) return { ok: false, status: 503 };
  await ensureCrawlsUserIdColumn(metaDb);
  const effectiveUserId = sanitizeStorageUserId(userId ?? getActiveCallerAuthContext()?.userId ?? 'owner');
  const now = Date.now();
  const res = await metaDb
    .prepare(
      `UPDATE crawls
       SET status = 'cancelled', updated_at = ?, finished_at = COALESCE(finished_at, ?)
       WHERE id = ? AND user_id = ? AND status IN ('queued', 'running')`,
    )
    .bind(now, now, crawlId, effectiveUserId)
    .run();
  if ((res.meta?.changes ?? 0) === 0) {
    const exists = await metaDb
      .prepare('SELECT status FROM crawls WHERE id = ? AND user_id = ? LIMIT 1')
      .bind(crawlId, effectiveUserId)
      .first<{ status: string }>();
    if (!exists) return { ok: false, status: 404 };
  }
  return { ok: true, status: 200 };
}

export class CrawlWorkflow extends WorkflowEntrypoint<OptionalStorageBindings, CrawlWorkflowParams> {
  override async run(event: WorkflowEvent<CrawlWorkflowParams>, step: WorkflowStep): Promise<{ crawlId: string; status: string }> {
    const status = await step.do('check-crawl-record', async () => {
      if (!this.env.META) return 'unconfigured';
      const row = await this.env.META
        .prepare('SELECT status FROM crawls WHERE id = ? LIMIT 1')
        .bind(event.payload.crawlId)
        .first<{ status: string }>();
      return row?.status ?? 'missing';
    });
    if ((status === 'queued' || status === 'running') && event.payload.rootUrl && event.payload.options) {
      const finalStatus = await step.do('execute-crawl-job', async () => {
        const resolvedUserId = event.payload.userId ?? event.payload.options?.userId;
        const out = await executeCrawlJob({
          crawlId: event.payload.crawlId,
          rootUrl: event.payload.rootUrl,
          options: event.payload.options!,
          ...(resolvedUserId ? { userId: resolvedUserId } : {}),
          env: this.env,
          ...(event.payload.selfHost ? { selfHost: event.payload.selfHost } : {}),
          executeHubFetch: async (_target, body) => {
            const res = await cloudflareOverflowFetch(body, 'EdgeFetch/2.7 (bot@edgefetch.dev)', event.payload.selfHost ?? 'localhost');
            return { status: res.status, via: 'cf', bodyText: await res.text() };
          },
        });
        return out.status;
      });
      return { crawlId: event.payload.crawlId, status: finalStatus };
    }
    return { crawlId: event.payload.crawlId, status };
  }
}

/**
 * Translates natural-language crawl instructions (`prompt`) into structured `crawl` parameters
 * (`POST /v1/crawl/params-preview` & `/v2/crawl/params-preview`) with zero external dependencies.
 */
export function previewCrawlParams(payload: Record<string, unknown>, selfHost?: string): {
  ok: boolean;
  status: number;
  body: Record<string, unknown>;
} {
  const urlCheck = validatePublicHttpsUrl(payload.url, selfHost);
  if (!urlCheck.ok) {
    return { ok: false, status: 400, body: { ok: false, success: false, error: 'invalid_url', message: urlCheck.message } };
  }
  const prompt = typeof payload.prompt === 'string' ? payload.prompt.trim() : '';
  const lower = prompt.toLowerCase();

  const includePaths: string[] = [];
  const excludePaths: string[] = [];

  for (const m of prompt.matchAll(/(?:only|include|under)\s+((?:\/[a-zA-Z0-9._*-]+(?:\s*(?:,|and|or)\s*)?)+)/gi)) {
    for (const seg of m[1]!.split(/\s*(?:,|and|or)\s*/i)) {
      const clean = seg.trim();
      if (clean.startsWith('/') && !includePaths.includes(clean)) includePaths.push(clean);
    }
  }
  for (const m of prompt.matchAll(/(?:skip|exclude|ignore|avoid|without)\s+((?:\/[a-zA-Z0-9._*-]+(?:\s*(?:,|and|or)\s*)?)+)/gi)) {
    for (const seg of m[1]!.split(/\s*(?:,|and|or)\s*/i)) {
      const clean = seg.trim();
      if (clean.startsWith('/') && !excludePaths.includes(clean)) excludePaths.push(clean);
    }
  }

  const limitMatch = /\b(?:limit|max|up\s+to)\s+(\d{1,4})\s*(?:pages?|urls?)?\b/i.exec(prompt);
  const depthMatch = /\b(?:depth|levels?)\s*(?:of|:|=|up\s+to)?\s*(\d)\b/i.exec(prompt);
  const allowSubdomains = /\b(?:include|allow|across)\s+subdomains?\b/i.test(lower) && !/\bno\s+subdomains?\b/i.test(lower);
  const sitemapOnly = /\bsitemap\s+only\b/i.test(lower);
  const skipSitemap = /\b(?:skip|ignore|no)\s+sitemaps?\b/i.test(lower);

  const preview = {
    url: urlCheck.url.toString(),
    limit: limitMatch ? Math.min(200, Math.max(1, Number(limitMatch[1]))) : 25,
    maxDiscoveryDepth: depthMatch ? Math.min(8, Math.max(0, Number(depthMatch[1]))) : 2,
    allowSubdomains,
    crawlEntireDomain: includePaths.length === 0 && urlCheck.url.pathname === '/',
    sitemap: sitemapOnly ? 'only' : skipSitemap ? 'skip' : 'include',
    ...(includePaths.length > 0 ? { includePaths } : {}),
    ...(excludePaths.length > 0 ? { excludePaths } : {}),
  };

  return {
    ok: true,
    status: 200,
    body: {
      ok: true,
      success: true,
      data: preview,
    },
  };
}

export interface BatchScrapeJobRecord {
  id: string;
  userId?: string;
  status: 'scraping' | 'completed' | 'cancelled' | 'failed';
  total: number;
  completed: number;
  failed: number;
  createdAt: number;
  updatedAt: number;
  expiresAt: number;
  data: Array<Record<string, unknown>>;
  errors: Array<{ url: string; error: string }>;
}

const inMemoryBatchJobs = new Map<string, BatchScrapeJobRecord>();
const MAX_BATCH_JOBS = 128;
const MAX_BATCH_JOBS_PER_MEMBER = 16;
const MAX_ACTIVE_BATCHES_PER_MEMBER = 4;

export async function startOrExecuteBatchScrape(params: {
  payload: Record<string, unknown>;
  selfHost?: string;
  userId?: string;
  executeScrape: (scrapePayload: Record<string, unknown>) => Promise<{ status: number; body: Record<string, unknown> }>;
  waitUntil?: (p: Promise<unknown>) => void;
  tracer?: RequestTracer | TraceContext;
}): Promise<{ ok: true; status: number; job: BatchScrapeJobRecord } | { ok: false; status: number; error: string; message: string }> {
  const { payload, selfHost, executeScrape, waitUntil } = params;
  const activeAuth = getActiveCallerAuthContext();
  const effectiveUserId = sanitizeStorageUserId(params.userId ?? activeAuth?.userId ?? 'owner');
  const isMemberCaller = activeAuth?.role === 'member' || (effectiveUserId !== 'owner' && activeAuth?.role !== 'owner');
  const activeTracer = getActiveRequestTracer(params.tracer);
  if (!Array.isArray(payload.urls) || payload.urls.length === 0) {
    return { ok: false, status: 400, error: 'missing_urls', message: 'urls must be a non-empty array of public https:// URLs' };
  }
  if (payload.urls.length > 100) {
    return { ok: false, status: 400, error: 'too_many_urls', message: 'maximum 100 URLs per batch/scrape job' };
  }

  const now = Date.now();
  for (const [k, existingJob] of inMemoryBatchJobs.entries()) {
    if (existingJob.expiresAt <= now) inMemoryBatchJobs.delete(k);
  }

  if (isMemberCaller) {
    if (!checkMemberJobRateQuota(`batch:${effectiveUserId}`, now)) {
      return {
        ok: false,
        status: 429,
        error: 'rate_limited',
        message: 'Per-user batch scrape rate quota exceeded. Please wait before starting more batches.',
      };
    }
    let activeForUser = 0;
    for (const j of inMemoryBatchJobs.values()) {
      if ((j.userId ?? 'owner') === effectiveUserId && j.status === 'scraping') activeForUser++;
    }
    if (activeForUser >= MAX_ACTIVE_BATCHES_PER_MEMBER) {
      return {
        ok: false,
        status: 429,
        error: 'rate_limited',
        message: `Per-user concurrent batch scrape limit (${MAX_ACTIVE_BATCHES_PER_MEMBER}) reached.`,
      };
    }
  }

  const validUrls: string[] = [];
  const invalidErrors: Array<{ url: string; error: string }> = [];
  const ignoreInvalidURLs = Boolean(payload.ignoreInvalidURLs);

  for (const rawU of payload.urls) {
    const check = validatePublicHttpsUrl(rawU, selfHost);
    if (!check.ok) {
      if (!ignoreInvalidURLs) {
        return { ok: false, status: 400, error: 'invalid_url', message: check.message };
      }
      invalidErrors.push({ url: String(rawU), error: check.message });
    } else {
      validUrls.push(check.url.toString());
    }
  }

  const batchId = `bch_${crypto.randomUUID().replace(/-/g, '').slice(0, 24)}`;
  const {
    urls: _omitUrls,
    sync: _omitSync,
    ignoreInvalidURLs: _omitIgnore,
    interact: _omitInteract,
    sessionId: _omitSessionId,
    maxConcurrency,
    ...sharedScrapeOpts
  } = payload;
  const concurrency =
    typeof maxConcurrency === 'number' && Number.isFinite(maxConcurrency)
      ? Math.min(8, Math.max(1, Math.floor(maxConcurrency)))
      : 4;

  const job: BatchScrapeJobRecord = {
    id: batchId,
    userId: effectiveUserId,
    status: 'scraping',
    total: validUrls.length,
    completed: 0,
    failed: invalidErrors.length,
    createdAt: now,
    updatedAt: now,
    expiresAt: now + 24 * 60 * 60_000,
    data: [],
    errors: invalidErrors,
  };

  // Per-tenant batch job retention: evict ONLY this tenant's oldest job first so one user can NEVER evict another tenant's batch job!
  if (effectiveUserId !== 'owner') {
    const ownKeys: string[] = [];
    for (const [k, j] of inMemoryBatchJobs.entries()) {
      if ((j.userId ?? 'owner') === effectiveUserId) ownKeys.push(k);
    }
    while (ownKeys.length >= MAX_BATCH_JOBS_PER_MEMBER) {
      const victim = ownKeys.shift();
      if (victim) inMemoryBatchJobs.delete(victim);
    }
  }
  if (inMemoryBatchJobs.size >= MAX_BATCH_JOBS) {
    // Evict oldest job belonging to the tenant with the most retained jobs
    const countsByUser = new Map<string, number>();
    for (const j of inMemoryBatchJobs.values()) {
      const uid = j.userId ?? 'owner';
      countsByUser.set(uid, (countsByUser.get(uid) ?? 0) + 1);
    }
    let heaviestUser = effectiveUserId;
    let maxCount = 0;
    for (const [uid, cnt] of countsByUser.entries()) {
      if (cnt > maxCount) {
        maxCount = cnt;
        heaviestUser = uid;
      }
    }
    for (const [k, j] of inMemoryBatchJobs.entries()) {
      if ((j.userId ?? 'owner') === heaviestUser) {
        inMemoryBatchJobs.delete(k);
        break;
      }
    }
  }
  inMemoryBatchJobs.set(batchId, job);

  const runBatchCore = async () => {
    for (let i = 0; i < validUrls.length; i += concurrency) {
      if (job.status === 'cancelled') break;
      const chunk = validUrls.slice(i, i + concurrency);
      const results = await Promise.all(
        chunk.map((u) => {
          const runOne = async () => {
            const out = await executeScrape({ ...sharedScrapeOpts, url: u });
            return { u, out };
          };
          return activeTracer ? activeTracer.run(runOne) : runOne();
        }),
      );
      for (const { u, out } of results) {
        if (out.status === 200) {
          job.completed++;
          job.data.push(out.body);
        } else {
          job.failed++;
          job.errors.push({
            url: u,
            error: String(out.body.problem ?? out.body.message ?? out.body.error ?? `HTTP ${out.status}`),
          });
        }
      }
      job.updatedAt = Date.now();
    }
    if (job.status !== 'cancelled') {
      job.status = 'completed';
      job.updatedAt = Date.now();
    }
  };
  const runBatch = () => (activeTracer ? activeTracer.run(runBatchCore) : runBatchCore());

  if (payload.sync === true || !waitUntil) {
    await runBatch();
    return { ok: true, status: 200, job };
  }
  waitUntil(runBatch());
  return { ok: true, status: 202, job };
}

export function getBatchScrapeStatus(batchId: string, userId?: string): BatchScrapeJobRecord | null {
  const job = inMemoryBatchJobs.get(batchId);
  if (!job) return null;
  if (job.expiresAt <= Date.now()) {
    inMemoryBatchJobs.delete(batchId);
    return null;
  }
  const effectiveUserId = sanitizeStorageUserId(userId ?? getActiveCallerAuthContext()?.userId ?? 'owner');
  if ((job.userId ?? 'owner') !== effectiveUserId) {
    return null;
  }
  return job;
}

export function cancelBatchScrape(batchId: string, userId?: string): boolean {
  const job = inMemoryBatchJobs.get(batchId);
  if (!job) return false;
  const effectiveUserId = sanitizeStorageUserId(userId ?? getActiveCallerAuthContext()?.userId ?? 'owner');
  if ((job.userId ?? 'owner') !== effectiveUserId) {
    return false;
  }
  job.status = 'cancelled';
  job.updatedAt = Date.now();
  return true;
}
