/**
 * Reliable, RFC 9309 robots-compliant Wikipedia & Wikimedia access helpers:
 *  - Tier 1: Article URL & title normalization (`space <-> underscore`, percent-encoding, language subdomain),
 *    24h default `maxAgeMs`, and MediaWiki Markdown cleanup (`[ ]`, `Edit links`, `[1][2]`, `[edit]`, Vector 2022 chrome).
 *  - Tier 2: Article resolver via `site:<lang>.wikipedia.org` search waterfall + at most 1 direct `/wiki/<Title>` guess
 *    (strictly excluding `Special:`, `Talk:`, `User:`, `Wikipedia:`, `File:`, `/w/`, and `/api/`), plus aggressive
 *    caching of Wikipedia's `robots.txt`-permitted `/w/rest.php/site/v1/sitemap/0` for `map`.
 *  - Tier 3: Per-caller per-host hourly single-article crawl guard (`200` articles/hour -> `outcome: "use_bulk_channel"`
 *    pointing to Wikimedia Enterprise, `dumps.wikimedia.org`, and Hugging Face `wikimedia/wikipedia`).
 */

export const DEFAULT_WIKIPEDIA_MAX_AGE_MS = 24 * 60 * 60_000; // 24 hours
export const DEFAULT_WIKIPEDIA_HOURLY_ARTICLE_LIMIT = 200;
const WIKIPEDIA_QUOTA_WINDOW_MS = 60 * 60_000; // 1 hour
const MAX_WIKIPEDIA_QUOTA_BUCKETS = 1_024;
const WIKIPEDIA_SITEMAP_CACHE_TTL_MS = 24 * 60 * 60_000; // 24 hours
const MAX_WIKIPEDIA_SITEMAP_CACHE_ENTRIES = 16;

export const WIKIPEDIA_BULK_CHANNELS = Object.freeze({
  wikimediaEnterprise: 'https://enterprise.wikimedia.com/',
  dumps: 'https://dumps.wikimedia.org/',
  huggingFaceDataset: 'https://huggingface.co/datasets/wikimedia/wikipedia',
});

const WIKIPEDIA_LANG_RE = /^[a-z]{2,3}(?:-[a-z0-9]{2,12})?$/i;

/**
 * MediaWiki non-article namespaces (English canonical + major localized Wikipedia equivalents).
 * Real articles containing colons (e.g. `Star_Wars:_Episode_IV`, `2001:_A_Space_Odyssey`) are preserved!
 */
const DISALLOWED_WIKIPEDIA_NAMESPACES = new Set([
  'special',
  'talk',
  'user',
  'user_talk',
  'wikipedia',
  'wikipedia_talk',
  'project',
  'project_talk',
  'file',
  'file_talk',
  'image',
  'image_talk',
  'media',
  'mediawiki',
  'mediawiki_talk',
  'template',
  'template_talk',
  'help',
  'help_talk',
  'category',
  'category_talk',
  'portal',
  'portal_talk',
  'draft',
  'draft_talk',
  'timedtext',
  'timedtext_talk',
  'module',
  'module_talk',
  'book',
  'book_talk',
  'gadget',
  'gadget_talk',
  'gadget_definition',
  'topic',
  // German (`de`)
  'spezial',
  'diskussion',
  'benutzer',
  'benutzerin',
  'benutzer_diskussion',
  'datei',
  'datei_diskussion',
  'vorlage',
  'hilfe',
  'kategorie',
  // French (`fr`)
  'spécial',
  'discussion',
  'utilisateur',
  'utilisatrice',
  'discussion_utilisateur',
  'fichier',
  'modèle',
  'aide',
  'catégorie',
  'portail',
  'projet',
  'sujet',
  // Spanish (`es`)
  'especial',
  'discusión',
  'usuario',
  'usuaria',
  'usuario_discusión',
  'archivo',
  'plantilla',
  'ayuda',
  'categoría',
  // Italian (`it`)
  'speciale',
  'discussione',
  'utente',
  'discussioni_utente',
  'template',
  'aiuto',
  'categoria',
  'progetto',
  // Portuguese (`pt`)
  'usuário',
  'usuária',
  'ficheiro',
  'predefinição',
  'ajuda',
  // Japanese / Russian / Chinese common Special/Talk/User prefixes
  '特別',
  'ノート',
  '利用者',
  'ファイル',
  ' служебная'.trim(),
  'обсуждение',
  'участник',
  'файл',
  'шаблон',
  'категория',
]);

export function isWikipediaHost(rawHost: string): boolean {
  const h = rawHost.trim().toLowerCase().replace(/\.+$/, '');
  return h === 'wikipedia.org' || (h.endsWith('.wikipedia.org') && h.length > '.wikipedia.org'.length);
}

export function isWikimediaHost(rawHost: string): boolean {
  const h = rawHost.trim().toLowerCase().replace(/\.+$/, '');
  if (!h) return false;
  const hasSubdomain = (suffix: string) => h.endsWith(suffix) && h.length > suffix.length;
  return (
    isWikipediaHost(h) ||
    h === 'wikimedia.org' ||
    hasSubdomain('.wikimedia.org') ||
    h === 'wiktionary.org' ||
    hasSubdomain('.wiktionary.org') ||
    h === 'wikibooks.org' ||
    hasSubdomain('.wikibooks.org') ||
    h === 'wikiquote.org' ||
    hasSubdomain('.wikiquote.org') ||
    h === 'wikisource.org' ||
    hasSubdomain('.wikisource.org') ||
    h === 'wikiversity.org' ||
    hasSubdomain('.wikiversity.org') ||
    h === 'wikivoyage.org' ||
    hasSubdomain('.wikivoyage.org') ||
    h === 'wikidata.org' ||
    hasSubdomain('.wikidata.org') ||
    h === 'mediawiki.org' ||
    hasSubdomain('.mediawiki.org')
  );
}

export function extractWikipediaLangFromHost(rawHost: string): string | null {
  const h = rawHost.trim().toLowerCase().replace(/\.+$/, '');
  if (!h.endsWith('.wikipedia.org')) return null;
  const sub = h.slice(0, -'.wikipedia.org'.length);
  // Handle mobile `<lang>.m.wikipedia.org` gracefully -> canonical `<lang>`
  const cleanSub = sub.endsWith('.m') ? sub.slice(0, -2) : sub;
  if (cleanSub === 'www' || !WIKIPEDIA_LANG_RE.test(cleanSub)) return null;
  return cleanSub;
}

export function normalizeWikipediaLang(rawLang: unknown, fallback = 'en'): string {
  if (typeof rawLang !== 'string') return fallback;
  const clean = rawLang.trim().toLowerCase();
  return WIKIPEDIA_LANG_RE.test(clean) ? clean : fallback;
}

function safeDecodeWikiSegment(seg: string): string {
  try {
    return decodeURIComponent(seg);
  } catch {
    return seg;
  }
}

function hasUnsafeWikiTitlePathSegments(rawOrDecoded: string): boolean {
  const parts = rawOrDecoded.split('/');
  for (const part of parts) {
    const clean = part.trim();
    if (!clean || clean === '.' || clean === '..') return true;
    if (/^(?:%2e|\.)+$/i.test(clean)) return true;
  }
  return false;
}

function encodeCanonicalWikiTitlePath(decodedTitle: string): string {
  // Normalize whitespace to underscores, capitalize first character per MediaWiki convention,
  // and encode path-unsafe characters while preserving `/` (`HTTP/2`), `:`, `(`, `)`, `,`, `-`, `_`, `.`.
  const underscored = decodedTitle.trim().replace(/\s+/g, '_').replace(/_+/g, '_');
  if (!underscored || underscored.startsWith(':') || hasUnsafeWikiTitlePathSegments(underscored)) return '';
  const firstCp = underscored.codePointAt(0)!;
  const firstChar = String.fromCodePoint(firstCp);
  const rest = underscored.slice(firstChar.length);
  const titled = `${firstChar.toUpperCase()}${rest}`;
  const segments = titled.split('/');
  if (segments.some((seg) => !seg || seg === '.' || seg === '..')) return '';
  return segments
    .map((part) =>
      encodeURIComponent(part)
        .replace(/%3A/gi, ':')
        .replace(/%28/gi, '(')
        .replace(/%29/gi, ')')
        .replace(/%2C/gi, ',')
        .replace(/%2F/gi, '/'),
    )
    .join('/');
}

export function isDisallowedWikipediaTitle(decodedTitle: string): boolean {
  const rawTrimmed = decodedTitle.trim();
  if (!rawTrimmed || rawTrimmed.startsWith(':') || hasUnsafeWikiTitlePathSegments(rawTrimmed)) return true;
  const trimmed = rawTrimmed.replace(/\s+/g, '_').replace(/^_+/, '');
  if (!trimmed || trimmed.startsWith(':')) return true;
  const colonIdx = trimmed.indexOf(':');
  if (colonIdx <= 0) return false;
  // MediaWiki normalizes spaces/underscores around namespace colons (`Special_:_Search` -> `Special:Search`).
  const prefix = trimmed.slice(0, colonIdx).replace(/_+$/, '').toLowerCase();
  if (!prefix) return true;
  if (DISALLOWED_WIKIPEDIA_NAMESPACES.has(prefix)) return true;
  if (prefix.endsWith('_talk') || prefix.endsWith('_diskussion') || prefix.endsWith('_discusión')) {
    return true;
  }
  return false;
}

export interface ParsedWikipediaArticle {
  lang: string;
  host: string;
  canonicalTitle: string;
  underscoredTitle: string;
  canonicalUrl: string;
}

/**
 * Parses and canonicalizes a `https://<lang>.wikipedia.org/wiki/<Title>` article URL.
 * Returns `null` for non-Wikipedia URLs, root `/`, `/w/*`, `/api/*`, or non-article namespaces (`Special:`, `Talk:`, `User:`, `Wikipedia:`, `File:`, etc.).
 */
export function parseWikipediaArticleUrl(rawUrl: string): ParsedWikipediaArticle | null {
  if (!rawUrl || typeof rawUrl !== 'string') return null;
  let u: URL;
  try {
    u = new URL(rawUrl.trim());
  } catch {
    return null;
  }
  if (u.protocol !== 'https:' && u.protocol !== 'http:') return null;
  const lang = extractWikipediaLangFromHost(u.hostname);
  if (!lang) return null;
  if (!u.pathname.startsWith('/wiki/') || u.pathname.length <= 6) return null;
  if (u.search && /[?&](?:action|oldid|diff|curid|veaction|printable)=/i.test(u.search)) {
    return null;
  }
  const rawSlug = u.pathname.slice('/wiki/'.length).replace(/\/+$/, '');
  if (!rawSlug || hasUnsafeWikiTitlePathSegments(rawSlug)) return null;
  const rawDecodedSlug = safeDecodeWikiSegment(rawSlug);
  if (!rawDecodedSlug || hasUnsafeWikiTitlePathSegments(rawDecodedSlug)) return null;
  const decoded = rawDecodedSlug.replace(/_/g, ' ').replace(/\s+/g, ' ').trim();
  if (!decoded || isDisallowedWikipediaTitle(decoded)) return null;
  const encodedSlug = encodeCanonicalWikiTitlePath(decoded);
  if (!encodedSlug) return null;
  const host = `${lang}.wikipedia.org`;
  const canonicalUrl = `https://${host}/wiki/${encodedSlug}`;
  try {
    if (new URL(canonicalUrl).pathname !== `/wiki/${encodedSlug}`) return null;
  } catch {
    return null;
  }
  const firstCp = decoded.codePointAt(0)!;
  const firstChar = String.fromCodePoint(firstCp);
  const canonicalTitle = `${firstChar.toUpperCase()}${decoded.slice(firstChar.length)}`;
  return {
    lang,
    host,
    canonicalTitle,
    underscoredTitle: canonicalTitle.replace(/ /g, '_'),
    canonicalUrl,
  };
}

/**
 * Resolves the canonical Wikipedia `/wiki/<Title>` URL for cached/revalidated MediaWiki responses
 * where internal `#REDIRECT [[Target]]` pages (e.g. `/wiki/HTTP2` -> `title: "HTTP/2 - Wikipedia"`)
 * were stored under the source URL in META D1 without a separate `finalUrl` column.
 */
export function resolveWikipediaCanonicalFinalUrl(params: {
  requestedUrl: string;
  storedFinalUrl?: string;
  title?: string;
  markdown?: string;
}): string {
  const { requestedUrl, storedFinalUrl, title, markdown } = params;
  if (storedFinalUrl && storedFinalUrl !== requestedUrl) {
    const parsedStored = parseWikipediaArticleUrl(storedFinalUrl);
    if (parsedStored) return parsedStored.canonicalUrl;
    return storedFinalUrl;
  }
  const reqWiki = parseWikipediaArticleUrl(requestedUrl);
  if (!reqWiki) return storedFinalUrl || requestedUrl;

  if (typeof title === 'string' && title.trim()) {
    const strippedTitle = title
      .trim()
      .replace(/\s+[–—-]\s+(?:Wikipedia|Wikipédia|Wikipedie|Wikipédia,.*|Wikipedia,.*)$/i, '')
      .trim();
    if (strippedTitle && !isDisallowedWikipediaTitle(strippedTitle)) {
      const slug = encodeCanonicalWikiTitlePath(strippedTitle);
      if (slug) {
        const cand = parseWikipediaArticleUrl(`https://${reqWiki.host}/wiki/${slug}`);
        if (cand) return cand.canonicalUrl;
      }
    }
  }

  if (typeof markdown === 'string' && markdown.startsWith('# ')) {
    const nl = markdown.indexOf('\n');
    const h1 = (nl === -1 ? markdown.slice(2) : markdown.slice(2, nl)).trim();
    if (h1 && !h1.includes('[') && !isDisallowedWikipediaTitle(h1)) {
      const slug = encodeCanonicalWikiTitlePath(h1);
      if (slug) {
        const cand = parseWikipediaArticleUrl(`https://${reqWiki.host}/wiki/${slug}`);
        if (cand) return cand.canonicalUrl;
      }
    }
  }

  return storedFinalUrl || requestedUrl;
}

/**
 * Builds a single direct-title guess URL (`https://<lang>.wikipedia.org/wiki/<Title>`) ONLY when `rawQuery`
 * looks like an article title (`<= 6` words and no search operators).
 */
export function buildWikipediaDirectTitleGuessUrl(rawQuery: string, lang = 'en'): string | null {
  const q = rawQuery.trim();
  if (!q || q.length > 120) return null;
  // Reject queries containing search operators or URL syntax
  if (/(?:^|\s)(?:site:|filetype:|intitle:|inurl:|OR\b|AND\b|NOT\b|-)|\bhttps?:\/\/|["*?]/i.test(q)) {
    return null;
  }
  const words = q.split(/\s+/).filter(Boolean);
  if (words.length === 0 || words.length > 6) return null;
  if (isDisallowedWikipediaTitle(q)) return null;
  const safeLang = normalizeWikipediaLang(lang, 'en');
  // Preserve acronyms/camelCase words while capitalizing the first letter (MediaWiki is case-insensitive on char 0 only;
  // Title_Cased_Query handles multi-word proper nouns cleanly while `/wiki/HTTP_2` redirects to `/wiki/HTTP/2`).
  const STOP_LOWER = new Set(['of', 'the', 'in', 'on', 'and', 'for', 'to', 'a', 'an', 'by', 'at', 'from', 'with']);
  const casedWords = words.map((w, idx) => {
    if (/[A-Z0-9/.+-]/.test(w.slice(1)) || /^[A-Z0-9]+$/.test(w)) {
      return idx === 0 ? `${w.charAt(0).toUpperCase()}${w.slice(1)}` : w;
    }
    const low = w.toLowerCase();
    if (idx > 0 && STOP_LOWER.has(low)) return low;
    return `${low.charAt(0).toUpperCase()}${low.slice(1)}`;
  });
  const encoded = encodeCanonicalWikiTitlePath(casedWords.join(' '));
  if (!encoded) return null;
  const candidate = `https://${safeLang}.wikipedia.org/wiki/${encoded}`;
  return parseWikipediaArticleUrl(candidate)?.canonicalUrl ?? null;
}

export function buildWikimediaRobotsSuggestion(rawHost: string): string {
  const h = rawHost.trim().toLowerCase().replace(/\.+$/, '');
  const lang = extractWikipediaLangFromHost(h) ?? 'en';
  const wikiHost = `${lang}.wikipedia.org`;
  return (
    `Wikipedia search and API paths are robots-disallowed. Use \`search\` with \`site:${wikiHost}\` (or \`wikipedia: true\`), ` +
    `or fetch \`https://${wikiHost}/wiki/<Title>\` directly. For bulk or structured corpus access, use Wikimedia Enterprise ` +
    `(${WIKIPEDIA_BULK_CHANNELS.wikimediaEnterprise}) or Wikimedia Dumps (${WIKIPEDIA_BULK_CHANNELS.dumps}).`
  );
}

const wikipediaCallerBuckets = new Map<string, number[]>();
let customHourlyLimitForTests: number | null = null;

export function resetWikipediaStateForTests(customHourlyLimit?: number | null): void {
  wikipediaCallerBuckets.clear();
  wikipediaSitemapCache.clear();
  customHourlyLimitForTests = typeof customHourlyLimit === 'number' && customHourlyLimit > 0 ? customHourlyLimit : null;
}

export interface WikipediaBulkChannelBlock {
  ok: false;
  outcome: 'use_bulk_channel';
  error: 'use_bulk_channel';
  retryable: false;
  host: string;
  limitPerHour: number;
  requestsInWindow: number;
  message: string;
  bulkChannels: typeof WIKIPEDIA_BULK_CHANNELS;
}

/**
 * Enforces the polite Tier 3 single-article ceiling (`200` live article requests per caller per Wikimedia host per hour).
 * Cached hits (`cached: true`) MUST NOT call this helper so $0 cache reads never consume quota.
 */
export function checkAndRecordWikipediaArticleQuota(params: {
  callerKey: string;
  host: string;
  now?: number;
  limitPerHour?: number;
}): { allowed: true; count: number; limitPerHour: number } | { allowed: false; block: WikipediaBulkChannelBlock } {
  const now = params.now ?? Date.now();
  const limit = params.limitPerHour ?? customHourlyLimitForTests ?? DEFAULT_WIKIPEDIA_HOURLY_ARTICLE_LIMIT;
  const host = params.host.trim().toLowerCase().replace(/\.+$/, '');
  const caller = (params.callerKey || 'owner').trim().slice(0, 96) || 'owner';
  const bucketKey = `${caller}|${host}`;
  const cutoff = now - WIKIPEDIA_QUOTA_WINDOW_MS;

  let stamps = wikipediaCallerBuckets.get(bucketKey);
  if (stamps) {
    let firstValid = 0;
    while (firstValid < stamps.length && stamps[firstValid]! <= cutoff) {
      firstValid++;
    }
    if (firstValid > 0) {
      stamps = stamps.slice(firstValid);
    }
    wikipediaCallerBuckets.delete(bucketKey);
  } else {
    stamps = [];
  }

  if (stamps.length >= limit) {
    wikipediaCallerBuckets.set(bucketKey, stamps);
    return {
      allowed: false,
      block: {
        ok: false,
        outcome: 'use_bulk_channel',
        error: 'use_bulk_channel',
        retryable: false,
        host,
        limitPerHour: limit,
        requestsInWindow: stamps.length,
        message:
          `Exceeded polite single-article limit (${limit} requests/hour on ${host}). ` +
          `For bulk or structured corpus work, use Wikimedia Enterprise (${WIKIPEDIA_BULK_CHANNELS.wikimediaEnterprise}), ` +
          `Wikimedia Dumps (${WIKIPEDIA_BULK_CHANNELS.dumps}), or the Hugging Face wikimedia/wikipedia dataset (${WIKIPEDIA_BULK_CHANNELS.huggingFaceDataset}).`,
        bulkChannels: WIKIPEDIA_BULK_CHANNELS,
      },
    };
  }

  stamps.push(now);
  while (wikipediaCallerBuckets.size >= MAX_WIKIPEDIA_QUOTA_BUCKETS) {
    const oldest = wikipediaCallerBuckets.keys().next().value;
    if (oldest === undefined) break;
    wikipediaCallerBuckets.delete(oldest);
  }
  wikipediaCallerBuckets.set(bucketKey, stamps);
  return { allowed: true, count: stamps.length, limitPerHour: limit };
}

const wikipediaSitemapCache = new Map<string, { urls: string[]; expiresAt: number }>();

export function getCachedWikipediaSitemapUrls(host: string, now = Date.now()): string[] | null {
  const key = host.trim().toLowerCase();
  const hit = wikipediaSitemapCache.get(key);
  if (!hit) return null;
  if (now >= hit.expiresAt) {
    wikipediaSitemapCache.delete(key);
    return null;
  }
  wikipediaSitemapCache.delete(key);
  wikipediaSitemapCache.set(key, hit);
  return hit.urls;
}

export function setCachedWikipediaSitemapUrls(host: string, urls: string[], now = Date.now()): void {
  const key = host.trim().toLowerCase();
  wikipediaSitemapCache.delete(key);
  while (wikipediaSitemapCache.size >= MAX_WIKIPEDIA_SITEMAP_CACHE_ENTRIES) {
    const oldest = wikipediaSitemapCache.keys().next().value;
    if (oldest === undefined) break;
    wikipediaSitemapCache.delete(oldest);
  }
  wikipediaSitemapCache.set(key, {
    urls: urls.slice(0, 5_000),
    expiresAt: now + WIKIPEDIA_SITEMAP_CACHE_TTL_MS,
  });
}

function stripMediaWikiInlineLinksLinear(ln: string): string {
  if (!ln.includes('](') || !ln.includes(')')) return ln;
  if (
    !ln.includes('wikidata.org/wiki/Special:EntityPage/') &&
    !ln.includes('action=edit') &&
    !ln.includes('#cite_note') &&
    !ln.includes('#cite_ref') &&
    !ln.includes('Wikipedia:Citation_needed') &&
    !ln.includes('Wikipedia:Please_clarify') &&
    !ln.includes('Wikipedia:Disputed_statement')
  ) {
    return ln;
  }

  let out = '';
  let lastEmit = 0;
  let searchPos = 0;
  const n = ln.length;

  while (searchPos < n) {
    const mid = ln.indexOf('](', searchPos);
    if (mid < 0) break;

    const scanCap = Math.min(n, mid + 2_050);
    let parenDepth = 1;
    let endParen = -1;
    let nextMid = -1;
    for (let p = mid + 2; p < scanCap; p++) {
      const ch = ln.charCodeAt(p);
      if (ch === 93 /* ']' */ && p + 1 < n && ln.charCodeAt(p + 1) === 40 /* '(' */) {
        nextMid = p;
        break;
      }
      if (ch === 40 /* '(' */) {
        parenDepth++;
      } else if (ch === 41 /* ')' */) {
        parenDepth--;
        if (parenDepth === 0) {
          endParen = p;
          break;
        }
      }
    }
    if (nextMid >= 0) {
      searchPos = nextMid;
      continue;
    }
    if (endParen < 0) {
      if (scanCap >= n) break;
      searchPos = scanCap;
      continue;
    }

    const isDoubleClose = mid > lastEmit && ln.charCodeAt(mid - 1) === 93 /* ']' */;
    const lblEnd = isDoubleClose ? mid - 1 : mid;
    const minBack = Math.max(lastEmit, lblEnd - 66);
    let openBr = -1;
    for (let b = lblEnd - 1; b >= minBack; b--) {
      const bc = ln.charCodeAt(b);
      if (bc === 91 /* '[' */) {
        openBr = b;
        break;
      }
      if (bc === 93 /* ']' */) break;
    }

    if (openBr >= 0 && lblEnd > openBr) {
      const hasDoubleOpen = isDoubleClose && openBr > lastEmit && ln.charCodeAt(openBr - 1) === 91 /* '[' */;
      if (!isDoubleClose || hasDoubleOpen) {
        const openStart = hasDoubleOpen ? openBr - 1 : openBr;
        const label = ln.slice(openBr + 1, lblEnd);
        const url = ln.slice(mid + 2, endParen);
        const isWikidataSitelink =
          !hasDoubleOpen &&
          /^https?:\/\/(?:www\.)?wikidata\.org\/wiki\/Special:EntityPage\//i.test(url);
        const isActionEdit = /[?&]action=edit(?:[&#]|$)/i.test(url) || /[?&]action=edit/i.test(url);
        const isCiteLink =
          (/^#cite_(?:note|ref)/i.test(url) ||
            /Wikipedia:(?:Citation_needed|Please_clarify|Disputed_statement)/i.test(url)) &&
          /^(?:\d{1,4}|[a-z]|(?:note|nb|lower-alpha|upper-alpha)[ \t]*\d{1,3}|citation needed|clarification needed|when\?|who\?|dubious[\s\S]{0,48})$/i.test(
            label,
          );

        if (isWikidataSitelink || isActionEdit || isCiteLink) {
          let cutStart = openStart;
          if (isWikidataSitelink || isActionEdit) {
            while (cutStart > lastEmit && (ln.charCodeAt(cutStart - 1) === 32 || ln.charCodeAt(cutStart - 1) === 9)) {
              cutStart--;
            }
          }
          out += ln.slice(lastEmit, cutStart);
          lastEmit = endParen + 1;
          searchPos = endParen + 1;
          continue;
        }
      }
    }

    searchPos = endParen + 1;
  }

  return lastEmit === 0 ? ln : out + ln.slice(lastEmit);
}

/**
 * Fence-aware linear **O(N)** MediaWiki Markdown cleanup (`< 5 ms` on 2 MiB articles; preserves GFM infobox tables & code blocks).
 * Strips `[ ]` toggle checkboxes, `"Edit links"` / Wikidata sitelinks lines, `[1][2]` footnote markers, `[edit]` links,
 * Vector 2022 UI chrome, reference back-link letter chains, and trailing MediaWiki navigation menus.
 */
export function cleanMediaWikiMarkdownLinear(rawMd: string): string {
  const bounded = rawMd.length > 2 * 1024 * 1024 ? rawMd.slice(0, 2 * 1024 * 1024) : rawMd;
  const lines = bounded.split('\n');
  const out: string[] = [];
  let inFence = false;
  let fenceChar = '';
  let fenceLen = 0;

  for (let i = 0; i < lines.length; i++) {
    let ln = lines[i]!;
    const trimmed = ln.trim();

    // Track CommonMark fenced code blocks so code examples inside technical articles (e.g. HTTP/2 frames) stay untouched.
    const fenceMatch = /^[ \t]{0,3}(`{3,}|~{3,})(.*)$/.exec(ln);
    if (fenceMatch) {
      const ticks = fenceMatch[1]!;
      const rest = fenceMatch[2] ?? '';
      if (!inFence) {
        if (!(ticks[0] === '`' && rest.includes('`'))) {
          inFence = true;
          fenceChar = ticks[0]!;
          fenceLen = ticks.length;
          out.push(ln);
          continue;
        }
      } else if (ticks[0] === fenceChar && ticks.length >= fenceLen && /^[ \t]*$/.test(rest)) {
        inFence = false;
        fenceChar = '';
        fenceLen = 0;
        out.push(ln);
        continue;
      }
    }
    if (inFence) {
      out.push(ln);
      continue;
    }

    // Cut trailing MediaWiki chrome footer from the first matching heading/chrome line onward
    if (/^(?:##+[ \t]+)?(?:Navigation menu|Namespaces|Views|Personal tools)\b/i.test(trimmed)) {
      break;
    }

    // Drop standalone Vector 2022 / Wikidata / language-switcher chrome lines (without touching `| ... |` infobox rows)
    if (!trimmed.startsWith('|')) {
      if (
        /^(?:\[[ \t]*\]|Edit links|Links bearbeiten|Modifier les liens|Editar enlaces|Modifica link|Toggle the table of contents|Move to sidebar|hide)$/i.test(
          trimmed,
        ) ||
        /^\[(?:Jump to content|Zum Inhalt springen|Aller au contenu)\]\(#[^)]*\)$/i.test(trimmed) ||
        /^\[[^\]]{1,64}\]\(https?:\/\/(?:www\.)?wikidata\.org\/wiki\/Special:EntityPage\/[^)]*\)$/i.test(trimmed) ||
        /^(?:From Wikipedia, the free encyclopedia|Aus Wikipedia, der freien Enzyklopädie|Un article de Wikipédia, l'encyclopédie libre\.?)$/i.test(
          trimmed,
        ) ||
        /^\d{1,4}[ \t]+(?:languages|language|Sprachen|langues|idiomas|lingue)$/i.test(trimmed) ||
        (i < 40 && /^(?:\*{1,2})?(?:Checked|Gesichtet|Vérifié|Revisado)(?:\*{1,2})?$/i.test(trimmed))
      ) {
        continue;
      }
    }

    if (ln.includes('[') && ln.includes(']')) {
      ln = stripMediaWikiInlineLinksLinear(ln);
      // Strip empty checkbox/toggle `[ ]` (`[   ]`) and unlinked `[edit]` / `[citation needed]` / `[1]` markers (never touching `[label](url)` or `[id]: url`!)
      ln = ln
        .replace(/(?<![ \t])[ \t]*\[[ \t]*\](?![(:])/g, '')
        .replace(
          /(?<![ \t])[ \t]*\[(?:edit|Bearbeiten(?:[ \t]*\|[ \t]*Quelltext bearbeiten)?|modifier(?:[ \t]*\|[ \t]*modifier le code)?|editar|citation needed|clarification needed|when\?|who\?|dubious[ \t]*[–-][ \t]*discuss)\](?![(:])/gi,
          '',
        )
        .replace(/\[(?:\d{1,4}|(?:note|nb)[ \t]*\d{1,3})\](?![(:])/gi, '');
    }

    // Clean reference list backlink prefixes (`^ a b c ...` or `^ [^1] ...`)
    const retrimmed = ln.trim();
    if (retrimmed.startsWith('^')) {
      const caretIdx = ln.indexOf('^');
      let p = caretIdx + 1;
      while (p < ln.length && (ln.charCodeAt(p) === 32 || ln.charCodeAt(p) === 9)) p++;
      if (p > caretIdx + 1) {
        const restAfterCaret = ln.slice(p);
        const fnBracket = /^\[\^[a-z0-9]{1,32}\][ \t]*/i.exec(restAfterCaret);
        if (fnBracket) {
          ln = `^ ${restAfterCaret.slice(fnBracket[0].length)}`;
        } else {
          let k = 0;
          let letterCount = 0;
          while (k + 1 < restAfterCaret.length) {
            const lc = restAfterCaret.charCodeAt(k) | 32;
            const sc = restAfterCaret.charCodeAt(k + 1);
            if (lc >= 97 && lc <= 122 && (sc === 32 || sc === 9)) {
              letterCount++;
              k += 2;
              while (k < restAfterCaret.length && (restAfterCaret.charCodeAt(k) === 32 || restAfterCaret.charCodeAt(k) === 9)) k++;
            } else {
              break;
            }
          }
          if (letterCount >= 2) {
            ln = `^ ${restAfterCaret.slice(k)}`;
          }
        }
      }
    }

    // If stripping `[Edit links]` or `[ ]` emptied a non-blank line completely, skip the newly-empty line
    if (trimmed.length > 0 && ln.trim().length === 0) {
      continue;
    }

    out.push(ln);
  }

  return out.join('\n').replace(/\n{3,}/g, '\n\n').trim();
}
