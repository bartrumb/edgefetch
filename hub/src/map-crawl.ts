/**
 * Site URL discovery (`POST /v1/map`), async site `crawl` (`POST /v1/crawl`, `GET/DELETE /v1/crawl/:id`, `CrawlWorkflow`),
 * signed HMAC-SHA256 webhook delivery, and Markdown change-tracking diffs (`PR V2-2`).
 */

import { WorkflowEntrypoint, type WorkflowEvent, type WorkflowStep } from 'cloudflare:workers';
import { isSafePublicHostname } from './overflow';
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
import { COLLECTION_ID_RE } from './search-index';
import { r2DerivedKey, readVerifiedArtifactFromR2, type ArtifactRetention, type OptionalStorageBindings } from './storage';

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

/** Parses XML `<sitemapindex>` and `<urlset>` `<loc>` entries. */
export function parseSitemapXml(xmlText: string): { isIndex: boolean; locs: string[] } {
  const isIndex = /<\s*sitemapindex\b/i.test(xmlText);
  const locs: string[] = [];
  const seen = new Set<string>();
  const locRe = /<\s*loc\b[^>]*>([\s\S]*?)<\/\s*loc\s*>/gi;
  let m: RegExpExecArray | null;
  while ((m = locRe.exec(xmlText)) !== null) {
    const raw = m[1]!
      .replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, '$1')
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
          if (locs.length >= 5_000) break;
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
  fastEdgeMap?: unknown;
  target?: unknown;
  site?: unknown;
}

function extractAnchorTitlesFromHtml(html: string, baseUrl: string): Map<string, string> {
  const titles = new Map<string, string>();
  const cleanedHtml = html
    .replace(/<!--[\s\S]*?-->/g, '')
    .replace(/<(?:script|style|svg|noscript|template)\b(?:"[^"]*"|'[^']*'|[^>"'])*>[\s\S]*?<\/(?:script|style|svg|noscript|template)>/gi, ' ');
  for (const m of cleanedHtml.matchAll(/<a\b((?:"[^"]*"|'[^']*'|[^>"'])*)>([\s\S]{1,600}?)<\/a>/gi)) {
    const hrefMatch = /\bhref\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>"']+))/i.exec(m[1]!);
    const rawHref = (hrefMatch?.[1] ?? hrefMatch?.[2] ?? hrefMatch?.[3] ?? '').trim();
    if (!rawHref || rawHref.startsWith('#') || /^(?:javascript|mailto|tel|data):/i.test(rawHref)) continue;
    let resolved: string;
    try {
      const u = new URL(decodeHtmlEntities(rawHref), baseUrl);
      if (u.protocol !== 'https:' && u.protocol !== 'http:') continue;
      u.hash = '';
      resolved = u.toString();
    } catch {
      continue;
    }
    if (titles.has(resolved)) continue;
    const label = decodeHtmlEntities(m[2]!.replace(/<(?:"[^"]*"|'[^']*'|[^>"'])*>/g, ' '))
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
  }
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
}): Promise<{ status: number; via: string; body: Record<string, unknown> }> {
  const { payload, executeHubFetch, selfHost, source = 'map' } = params;
  const check = validatePublicHttpsUrl(payload.url, selfHost);
  if (!check.ok) {
    return { status: 400, via: 'hub', body: { ok: false, error: 'invalid_url', message: check.message } };
  }
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

  const seedRequests: Array<Record<string, unknown>> = sitemapOnly
    ? []
    : isGitHubRepoSubpath
      ? [{ id: 'home', url: rootUrl.toString(), kind: 'page' }]
      : [
          { id: 'home', url: rootUrl.toString(), kind: 'page' },
          { id: 'llms', url: `${origin}/llms.txt`, kind: 'text', accept: 'text/plain' },
          ...(subLlmsUrl ? [{ id: 'llms-sub', url: subLlmsUrl, kind: 'text', accept: 'text/plain' }] : []),
        ];
  if (!ignoreSitemap && !isGitHubRepoSubpath) {
    seedRequests.push(
      { id: 'robots', url: `${origin}/robots.txt`, kind: 'text', accept: 'text/plain' },
      { id: 'sitemap', url: `${origin}/sitemap.xml`, kind: 'text', accept: 'application/xml' },
      { id: 'sitemap-index', url: `${origin}/sitemap-index.xml`, kind: 'text', accept: 'application/xml' },
    );
  }

  const seedRes = await executeHubFetch(
    target,
    JSON.stringify({
      maxSeconds: fastEdgeMap ? 10 : 30,
      options: { includeBody: true, respectRobots: true, pauseMs: 250, pauseJitterMs: 0 },
      requests: seedRequests,
    }),
    site,
    source,
    'off',
    false,
  );
  if (seedRes.status !== 200) {
    return { status: seedRes.status, via: seedRes.via, body: { ok: false, error: 'map_fetch_failed' } };
  }

  const parsed = JSON.parse(seedRes.bodyText) as { results?: Array<Record<string, unknown>> };
  const byId = new Map<string, Record<string, unknown>>();
  for (const r of parsed.results ?? []) {
    if (typeof r.id === 'string') byId.set(r.id, r);
  }

  const sourcesReport: Array<{ source: string; url: string; status: number; outcome: string; urlsFound: number }> = [];
  const discovered = new Map<string, { url: string; title?: string; source: string }>();
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
  const addUrl = (rawCandidate: string, src: string, title?: string): boolean => {
    try {
      const u = new URL(rawCandidate, origin);
      if (u.protocol !== 'https:' || (u.port && u.port !== '443')) return false;
      if (!matchesHostScope(u.hostname, rootHost, includeSubdomains)) return false;
      if (ghRepoPrefix && u.hostname.toLowerCase() === 'github.com') {
        const lp = u.pathname.toLowerCase();
        if (lp !== ghRepoPrefix && !lp.startsWith(`${ghRepoPrefix}/`)) {
          return false;
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
      const existing = discovered.get(canonicalKey);
      if (!existing) {
        dedupeKeyToCanonical.set(simKey, clean);
        discovered.set(clean, { url: clean, ...(title ? { title: decodeHtmlEntities(title) } : {}), source: src });
        return true;
      }
      if (!existing.title && title) {
        existing.title = decodeHtmlEntities(title);
      }
      return false;
    } catch {
      return false;
    }
  };
  if (!sitemapOnly) {
    addUrl(rootUrl.toString(), 'seed');
  }

  const homeItem = byId.get('home');
  if (homeItem) {
    let found = 0;
    if (homeItem.outcome === 'ok' && typeof homeItem.body === 'string') {
      const anchorTitles = extractAnchorTitlesFromHtml(homeItem.body, rootUrl.toString());
      const ext = extractHtmlDocument(homeItem.body, { baseUrl: rootUrl.toString(), onlyMainContent: false });
      const homeLinks =
        ext.links.length > 0
          ? ext.links
          : extractMarkdownLinksAndImages(homeItem.body, rootUrl.toString(), false).links;
      for (const l of homeLinks) {
        if (addUrl(l, 'homepage', anchorTitles.get(l))) found++;
      }
    }
    sourcesReport.push({
      source: 'homepage',
      url: rootUrl.toString(),
      status: typeof homeItem.status === 'number' ? homeItem.status : 0,
      outcome: String(homeItem.outcome ?? 'unknown'),
      urlsFound: found,
    });
  }

  for (const [id, srcLabel, llmsTargetUrl] of [
    ['llms', 'llms.txt', `${origin}/llms.txt`],
    ...(subLlmsUrl ? ([['llms-sub', 'subpath-llms.txt', subLlmsUrl]] as const) : []),
  ] as const) {
    const llmsItem = byId.get(id);
    if (!llmsItem) continue;
    let found = 0;
    if (llmsItem.outcome === 'ok' && typeof llmsItem.body === 'string') {
      const llmsDoc = parseLlmsTxt(llmsItem.body, llmsTargetUrl);
      if (llmsDoc) {
        for (const l of llmsDoc.links) {
          if (addUrl(l.url, 'llms.txt', l.title)) found++;
        }
      }
    }
    sourcesReport.push({
      source: srcLabel,
      url: llmsTargetUrl,
      status: typeof llmsItem.status === 'number' ? llmsItem.status : 0,
      outcome: String(llmsItem.outcome ?? 'unknown'),
      urlsFound: found,
    });
  }

  if (!ignoreSitemap) {
    const childSitemaps = new Set<string>();
    const robotsItem = byId.get('robots');
    if (robotsItem) {
      let sitemapsFound = 0;
      if (robotsItem.outcome === 'ok' && typeof robotsItem.body === 'string') {
        for (const sm of extractRobotsSitemaps(robotsItem.body, origin)) {
          sitemapsFound++;
          if (sm !== `${origin}/sitemap.xml` && sm !== `${origin}/sitemap-index.xml`) childSitemaps.add(sm);
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

    for (const [smId, smUrl] of [
      ['sitemap', `${origin}/sitemap.xml`],
      ['sitemap-index', `${origin}/sitemap-index.xml`],
    ] as const) {
      const smItem = byId.get(smId);
      if (!smItem) continue;
      let found = 0;
      if (smItem.outcome === 'ok' && typeof smItem.body === 'string') {
        const xml = await decodeXmlOrGzipBody(smItem.body, smItem.bodyEncoding as string | undefined, smUrl);
        const parsedSm = parseSitemapXml(xml);
        if (parsedSm.isIndex) {
          for (const loc of parsedSm.locs) {
            childSitemaps.add(loc);
            found++;
          }
        } else {
          for (const loc of parsedSm.locs) {
            if (addUrl(loc, 'sitemap')) found++;
          }
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
          return matchesHostScope(new URL(u).hostname, rootHost, true);
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
      const subRes = await executeHubFetch(
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
      if (subRes.status === 200) {
        const subParsed = JSON.parse(subRes.bodyText) as { results?: Array<Record<string, unknown>> };
        for (const sr of subParsed.results ?? []) {
          const srUrl = typeof sr.url === 'string' ? sr.url : '';
          let found = 0;
          if (sr.outcome === 'ok' && typeof sr.body === 'string') {
            const xml = await decodeXmlOrGzipBody(sr.body, sr.bodyEncoding as string | undefined, srUrl);
            const p = parseSitemapXml(xml);
            if (!p.isIndex) {
              for (const loc of p.locs) {
                if (addUrl(loc, 'sitemap')) found++;
              }
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
      }
    }
  }

  // Merge companion `.md` and `/index.md` entries (e.g. from `/llms.txt`) onto their canonical HTML twins
  // (`.../foo` + `.../foo.md`, `.../bar/` + `.../bar/index.md`) so `map` preserves curated `llms.txt` titles without duplicates.
  const wantsExplicitMd = /\.md\b/i.test(searchFilter);
  for (const [key, entry] of [...discovered.entries()]) {
    if (!key.toLowerCase().endsWith('.md')) continue;
    recordCompanionMdUrl(key);
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
      if (!wantsExplicitMd) {
        discovered.delete(key);
      }
    }
  }

  const includeOutsidePath = Boolean((payload as { includeOutsidePath?: unknown }).includeOutsidePath);
  const subpathPrefix = trimmedSubpath ? `${origin}${trimmedSubpath}`.toLowerCase() : '';
  const isUnderSubpath = (urlStr: string): boolean => {
    if (!subpathPrefix) return true;
    const lower = urlStr.toLowerCase();
    return lower === subpathPrefix || lower.startsWith(`${subpathPrefix}/`);
  };

  // Tokenize URL paths and page titles on `/ - _ .` and camelCase boundaries so `search=voice` matches `voice` / `voice-agent`
  // and NEVER matches inside unrelated words like `/billing/manage/invoices/` ("invoices" -> token "invoices", not "voice").
  const tokenizeMapSegment = (raw: string): string[] => {
    const dec = (() => {
      try {
        return decodeURIComponent(raw);
      } catch {
        return raw;
      }
    })();
    const camelSplit = dec.replace(/([a-z\d])([A-Z])/g, '$1 $2');
    return (camelSplit.toLowerCase().match(/[\p{L}\p{N}]+/gu) ?? []).filter(Boolean);
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
  if (searchFilter) {
    const terms = (searchFilter.toLowerCase().match(/[\p{L}\p{N}]+/gu) ?? []).filter(Boolean);
    items = items
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
        let hits = 0;
        let exactBonus = 0;
        for (const t of terms) {
          const uMatch = matchesWholeMapToken(urlTokens, t);
          const tMatch = matchesWholeMapToken(titleTokens, t);
          if (uMatch.matched || tMatch.matched) {
            hits++;
            if (uMatch.exact) exactBonus += 6;
            else if (tMatch.exact) exactBonus += 3;
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
      .filter((x) => x.hits > 0 && (terms.length <= 1 || x.hits === terms.length || x.hits >= 2))
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
}): Promise<{ delivered: boolean; status?: number }> {
  const { webhook, defaultSecret, event, crawlId, data, selfHost, fetchFn = fetch } = params;
  if (Array.isArray(webhook.events) && webhook.events.length > 0 && !webhook.events.includes(event)) {
    return { delivered: false };
  }
  const urlCheck = validatePublicHttpsUrl(webhook.url, selfHost);
  if (!urlCheck.ok) {
    return { delivered: false };
  }

  const tsSec = Math.floor(Date.now() / 1000);
  const bodyJson = JSON.stringify({
    event,
    crawlId,
    timestamp: tsSec,
    ...(webhook.metadata ? { metadata: webhook.metadata } : {}),
    data,
  });

  const signingSecret = (webhook.secret ?? defaultSecret ?? '').trim();
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
}

export interface CrawlJobOptions {
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
  selfHost?: string;
}

function matchesSafeCrawlPattern(target: string, pattern: string): boolean {
  if (!pattern || pattern.length > 160) return false;
  if (pattern.startsWith('/') && !/[\\^$*+?()[\]{}|]/.test(pattern)) {
    return target.startsWith(pattern);
  }
  // Reject nested quantifiers to prevent ReDoS on user-supplied patterns
  if (/\([^)]*[+*][^)]*\)[+*?{]/.test(pattern)) {
    return target.includes(pattern);
  }
  try {
    return new RegExp(pattern).test(target);
  } catch {
    return target.startsWith(pattern);
  }
}

function pathAllowed(
  candidateUrl: URL,
  includePaths: string[],
  excludePaths: string[],
  regexOnFullURL: boolean,
): boolean {
  const subject = regexOnFullURL ? candidateUrl.toString() : candidateUrl.pathname;
  for (const ex of excludePaths) {
    if (matchesSafeCrawlPattern(subject, ex)) return false;
  }
  if (includePaths.length === 0) return true;
  return includePaths.some((inc) => matchesSafeCrawlPattern(subject, inc));
}

export async function createCrawlJob(params: {
  payload: Record<string, unknown>;
  metaDb?: D1Database;
  selfHost?: string;
  now?: number;
}): Promise<
  | { ok: true; crawlId: string; rootUrl: string; options: CrawlJobOptions }
  | { ok: false; status: number; error: string; message: string }
> {
  const { payload, metaDb, selfHost, now = Date.now() } = params;
  if (!metaDb) {
    return { ok: false, status: 503, error: 'tracking_not_configured', message: 'Async crawl requires META D1 binding' };
  }
  const urlCheck = validatePublicHttpsUrl(payload.url, selfHost);
  if (!urlCheck.ok) {
    return { ok: false, status: 400, error: 'invalid_url', message: urlCheck.message };
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
    includePaths: Array.isArray(payload.includePaths)
      ? payload.includePaths.filter((p): p is string => typeof p === 'string' && p.trim().length > 0 && p.length <= 160).slice(0, 20)
      : [],
    excludePaths: Array.isArray(payload.excludePaths)
      ? payload.excludePaths.filter((p): p is string => typeof p === 'string' && p.trim().length > 0 && p.length <= 160).slice(0, 20)
      : [],
    ...(COLLECTION_ID_RE.test(rawColl) ? { collectionId: rawColl } : {}),
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
      `INSERT INTO crawls (id, root_url, status, options_json, discovered_count, fetched_count, failed_count, created_at, updated_at)
       VALUES (?, ?, 'queued', ?, 1, 0, 0, ?, ?)`,
    )
    .bind(crawlId, urlCheck.url.toString(), JSON.stringify(storedOptions), now, now)
    .run();

  return { ok: true, crawlId, rootUrl: urlCheck.url.toString(), options };
}

export async function executeCrawlJob(params: {
  crawlId: string;
  rootUrl: string;
  options: CrawlJobOptions;
  env: OptionalStorageBindings & { WEBHOOK_SECRET?: string };
  executeHubFetch: HubFetchExecutor;
  selfHost?: string;
  webhookFetchFn?: typeof fetch;
  waitUntilBounded?: boolean;
  maxRuntimeMs?: number;
}): Promise<{ status: 'completed' | 'cancelled' | 'failed'; fetchedCount: number; failedCount: number; discoveredCount: number }> {
  const { crawlId, rootUrl, options, env, executeHubFetch, selfHost, webhookFetchFn } = params;
  const metaDb = env.META!;
  const rootParsed = new URL(rootUrl);
  const startedAt = Date.now();
  const runtimeBudgetMs =
    typeof params.maxRuntimeMs === 'number' && Number.isFinite(params.maxRuntimeMs) && params.maxRuntimeMs > 0
      ? params.maxRuntimeMs
      : params.waitUntilBounded
        ? 23_000
        : 120_000;

  const isCancelled = async (): Promise<boolean> => {
    const row = await metaDb.prepare('SELECT status FROM crawls WHERE id = ? LIMIT 1').bind(crawlId).first<{ status: string }>();
    return row?.status === 'cancelled';
  };

  if (await isCancelled()) {
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

      const retention: ArtifactRetention | undefined = env.ARTIFACTS ? 'stored' : undefined;
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

      const fetchOut = await executeHubFetch(
        options.target,
        JSON.stringify(call),
        options.site,
        `crawl:${crawlId}`,
        retention,
        true,
        options.collectionId,
        crawlId,
      );

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

          if (options.webhook) {
            await deliverSignedWebhook({
              webhook: options.webhook,
              defaultSecret: env.WEBHOOK_SECRET,
              event: 'crawl.page',
              crawlId,
              data: {
                url: itemUrl,
                status: item.status ?? 200,
                title:
                  ext?.title ||
                  fm.title ||
                  mdAssets?.title ||
                  (typeof item.title === 'string' && item.title ? decodeHtmlEntities(item.title) : undefined),
                markdownPreview: md.slice(0, 2_000),
              },
              selfHost,
              ...(webhookFetchFn ? { fetchFn: webhookFetchFn } : {}),
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
      });
    }
    return { status: 'failed', fetchedCount, failedCount, discoveredCount: visited.size };
  }
}

export async function getCrawlJobStatus(params: {
  crawlId: string;
  metaDb?: D1Database;
  bucket?: R2Bucket;
  offset?: number;
  limit?: number;
  now?: number;
}): Promise<{ ok: true; crawl: Record<string, unknown> } | { ok: false; status: number; error: string }> {
  const { crawlId, metaDb, bucket, offset = 0, limit = 25, now = Date.now() } = params;
  if (!metaDb) return { ok: false, status: 503, error: 'tracking_not_configured' };

  const row = await metaDb
    .prepare(
      `SELECT id, root_url, status, options_json, discovered_count, fetched_count, failed_count, created_at, updated_at, finished_at
       FROM crawls WHERE id = ? LIMIT 1`,
    )
    .bind(crawlId)
    .first<{
      id: string;
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

  // Reconcile live fetch counts from `fetches` so `fetchedCount` and `status` self-heal automatically even if
  // Cloudflare Workers' 30s `ctx.waitUntil` cap terminated a background crawl right after its last wave ingested.
  const aggRow = await metaDb
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

  const liveOk = Number(aggRow?.ok_cnt ?? 0);
  const liveFail = Number(aggRow?.fail_cnt ?? 0);
  const lastFetchedAt = Number(aggRow?.last_fetched_at ?? 0);
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
  const hasMoreRows = rawPageRows.length > safeLimit;
  const pageRows = hasMoreRows ? rawPageRows.slice(0, safeLimit) : rawPageRows;

  const pdfCandidatePipelines = [...new Set([SCRAPE_PIPELINE_VERSION, 1])];
  const data: Array<Record<string, unknown>> = [];
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

export async function cancelCrawlJob(crawlId: string, metaDb?: D1Database): Promise<{ ok: boolean; status: number }> {
  if (!metaDb) return { ok: false, status: 503 };
  const now = Date.now();
  const res = await metaDb
    .prepare(
      `UPDATE crawls
       SET status = 'cancelled', updated_at = ?, finished_at = COALESCE(finished_at, ?)
       WHERE id = ? AND status IN ('queued', 'running')`,
    )
    .bind(now, now, crawlId)
    .run();
  if ((res.meta?.changes ?? 0) === 0) {
    const exists = await metaDb.prepare('SELECT status FROM crawls WHERE id = ? LIMIT 1').bind(crawlId).first<{ status: string }>();
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

export async function startOrExecuteBatchScrape(params: {
  payload: Record<string, unknown>;
  selfHost?: string;
  executeScrape: (scrapePayload: Record<string, unknown>) => Promise<{ status: number; body: Record<string, unknown> }>;
  waitUntil?: (p: Promise<unknown>) => void;
}): Promise<{ ok: true; status: number; job: BatchScrapeJobRecord } | { ok: false; status: number; error: string; message: string }> {
  const { payload, selfHost, executeScrape, waitUntil } = params;
  if (!Array.isArray(payload.urls) || payload.urls.length === 0) {
    return { ok: false, status: 400, error: 'missing_urls', message: 'urls must be a non-empty array of public https:// URLs' };
  }
  if (payload.urls.length > 100) {
    return { ok: false, status: 400, error: 'too_many_urls', message: 'maximum 100 URLs per batch/scrape job' };
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

  const now = Date.now();
  const batchId = `bch_${crypto.randomUUID().replace(/-/g, '').slice(0, 24)}`;
  const { urls: _omitUrls, sync: _omitSync, ignoreInvalidURLs: _omitIgnore, maxConcurrency, ...sharedScrapeOpts } = payload;
  const concurrency =
    typeof maxConcurrency === 'number' && Number.isFinite(maxConcurrency)
      ? Math.min(8, Math.max(1, Math.floor(maxConcurrency)))
      : 4;

  const job: BatchScrapeJobRecord = {
    id: batchId,
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

  if (inMemoryBatchJobs.size >= MAX_BATCH_JOBS) {
    const oldest = inMemoryBatchJobs.keys().next().value;
    if (oldest) inMemoryBatchJobs.delete(oldest);
  }
  inMemoryBatchJobs.set(batchId, job);

  const runBatch = async () => {
    for (let i = 0; i < validUrls.length; i += concurrency) {
      if (job.status === 'cancelled') break;
      const chunk = validUrls.slice(i, i + concurrency);
      const results = await Promise.all(
        chunk.map(async (u) => {
          const out = await executeScrape({ ...sharedScrapeOpts, url: u });
          return { u, out };
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

  if (payload.sync === true || !waitUntil) {
    await runBatch();
    return { ok: true, status: 200, job };
  }
  waitUntil(runBatch());
  return { ok: true, status: 202, job };
}

export function getBatchScrapeStatus(batchId: string): BatchScrapeJobRecord | null {
  const job = inMemoryBatchJobs.get(batchId);
  if (!job) return null;
  if (job.expiresAt <= Date.now()) {
    inMemoryBatchJobs.delete(batchId);
    return null;
  }
  return job;
}

export function cancelBatchScrape(batchId: string): boolean {
  const job = inMemoryBatchJobs.get(batchId);
  if (!job) return false;
  job.status = 'cancelled';
  job.updatedAt = Date.now();
  return true;
}
