/**
 * EdgeFetch Contributor-Friendly Site Adapter SDK (`hub/src/extractors/types.ts`).
 *
 * Every built-in and community adapter lives in its own self-contained file under
 * `hub/src/extractors/providers/<category>/<slug>.ts` and exports `defineAdapter({ ... })`.
 *
 * Security & Ethics Invariant:
 *  - Adapters NEVER make raw `fetch()` calls. `resolveTwin()` returns a declarative `https://`
 *    `SiteExtractorTwin` descriptor that EdgeFetch executes through `executeHubFetch`, guaranteeing
 *    `robots.txt` checks, dial-time SSRF protection, per-host politeness, and OTLP tracing.
 *  - Zero paid B2B API keys: built-in adapters target public, keyless endpoints or structured HTML.
 */

export type AdapterCategory =
  | 'developer'
  | 'genai'
  | 'jobs'
  | 'finance'
  | 'public-records'
  | 'research-health'
  | 'commerce-social';

export interface PaginationInfo {
  page: number;
  returned: number;
  limit?: number;
  hasMore: boolean;
  nextUrl?: string;
}

export interface CatalogVariantRecord {
  variantId: string;
  sku: string | null;
  barcode?: string | null;
  title: string | null;
  options: string[];
  price: number | null;
  compareAt: number | null;
  currency: string | null;
  available: boolean | null;
  inventoryPolicy?: 'deny' | 'continue' | null;
  inventoryQuantity?: number | null;
  grams: number | null;
  image: string | null;
}

export interface CatalogRecord {
  platform: string;
  origin: string;
  productId: string;
  handle: string;
  url: string;
  title: string;
  vendor: string | null;
  productType: string | null;
  tags: string[];
  descriptionText?: string;
  publishedAt: string | null;
  updatedAt: string | null;
  images?: string[];
  options: Array<{ name: string; values: string[] }>;
  variants: CatalogVariantRecord[];
}

export interface CatalogSpec {
  platform: string;
  firstPage(origin: URL, opts?: { collection?: string }): string;
  nextPage(prev: {
    url: string;
    body: string;
    pageIndex: number;
    headers?: Record<string, string>;
  }): string | null;
  parsePage(
    body: string,
    origin: URL,
    opts?: { fields?: 'full' | 'lean'; headers?: Record<string, string> },
  ): { records: CatalogRecord[]; done: boolean };
  pauseMs: number;
  pageCap: number;
}

export interface TwinFormattedDoc {
  title: string;
  description?: string;
  author?: string;
  publishedTime?: string;
  markdown: string;
  links?: string[];
  records?: Array<Record<string, unknown>>;
  pagination?: PaginationInfo;
  total?: number;
  returned?: number;
  truncated?: boolean;
  nextCursor?: string;
}

export interface HtmlFragmentConverter {
  (htmlFragment: string, baseUrl?: string): {
    markdown: string;
    links: string[];
  };
}

export interface SiteExtractorTwin {
  id: string;
  fetchUrl: string;
  kind: 'json' | 'text';
  accept: string;
  formatTwin: (rawBody: string, originalUrl: string, htmlToMd: HtmlFragmentConverter) => TwinFormattedDoc | null;
}

export interface PostFetchSiteResult {
  extractorId: string;
  title?: string;
  description?: string;
  author?: string;
  publishedTime?: string;
  markdown: string;
  links?: string[];
  records?: Array<Record<string, unknown>>;
  pagination?: PaginationInfo;
  total?: number;
  returned?: number;
  truncated?: boolean;
  nextCursor?: string;
}

export interface TwinMatchContext {
  url: URL;
  urlStr: string;
  host: string;
  path: string;
  parts: string[];
}

export interface HtmlExtractContext {
  url: URL;
  baseUrl: string;
  host: string;
  path: string;
  parts: string[];
  rawHtml: string;
  currentMd: string;
  htmlToMd: HtmlFragmentConverter;
}

export interface SiteAdapter {
  /** Unique kebab-case identifier (e.g. `sec-edgar`, `socrata`, `npm-registry`). */
  id: string;
  /** Human-readable provider name shown in `GET /v1/extractors` and docs. */
  name: string;
  /** Functional category folder under `hub/src/extractors/providers/<category>/`. */
  category: AdapterCategory;
  /** Concise summary of what structured data or cleanup this adapter provides. */
  description: string;
  /**
   * Hostnames handled by this adapter:
   *  - Exact hostnames (`npmjs.com`, `www.npmjs.com`) are indexed in an O(1) `Map`.
   *  - Leading-wildcard suffixes (`*.stackexchange.com`, `*.myshopify.com`, `*.legistar.com`) match subdomains.
   *  - Prefix wildcards (`gitlab.*`) match host prefixes.
   */
  domains: string[];
  /**
   * Set `true` when the adapter detects a multi-domain platform engine on arbitrary custom domains
   * (e.g. Discourse `/t/<slug>/<id>`, Mastodon `/@user/<id>`, MediaWiki, Socrata, CKAN, ArcGIS, Shopify).
   */
  universalEngine?: boolean;
  /** One or more sample `https://` URLs used for documentation and automated self-tests. */
  exampleUrls: string[];
  /** Optional pre-fetch 1-hop upgrade to an official public JSON, Markdown, or patch endpoint. */
  resolveTwin?: (ctx: TwinMatchContext) => SiteExtractorTwin | null;
  /** Optional post-fetch HTML / DOM / Markdown extractor when live HTML was retrieved. */
  extractHtml?: (ctx: HtmlExtractContext) => PostFetchSiteResult | null;
  /** Optional polite full-store catalog pagination contract (`shopify`, `woocommerce`, etc.). */
  catalog?: CatalogSpec;
}

export interface AdapterCatalogEntry {
  id: string;
  name: string;
  category: AdapterCategory;
  description: string;
  modes: Array<'twin' | 'html' | 'ats' | 'catalog'>;
  domains: string[];
  universalEngine: boolean;
  exampleUrls: string[];
}

/** Type-safe helper for authoring self-contained adapters in `hub/src/extractors/providers/`. */
export function defineAdapter(adapter: SiteAdapter): SiteAdapter {
  return adapter;
}

export interface LinearOpenTagMatch {
  index: number;
  openEnd: number;
  openTag: string;
  attrStr: string;
  selfClosing: boolean;
}

function isHtmlTagBoundaryChar(code: number): boolean {
  return code === 62 || code === 47 || code === 32 || code === 9 || code === 10 || code === 13;
}

function isHtmlWsChar(code: number): boolean {
  return code === 32 || code === 9 || code === 10 || code === 13 || code === 12;
}

function isAttrNameChar(code: number): boolean {
  return (
    (code >= 97 && code <= 122) ||
    (code >= 65 && code <= 90) ||
    (code >= 48 && code <= 57) ||
    code === 45 ||
    code === 95 ||
    code === 58 ||
    code === 46
  );
}

/**
 * Strictly `O(attrStr.length)` linear HTML attribute value reader (never backtracks on unclosed quotes).
 */
export function getAttrValueLinear(attrStr: string, attrName: string): string | null {
  const target = attrName.toLowerCase();
  const n = attrStr.length;
  let i = 0;
  while (i < n) {
    while (i < n && isHtmlWsChar(attrStr.charCodeAt(i))) i++;
    if (i >= n) break;
    const nameStart = i;
    while (i < n && isAttrNameChar(attrStr.charCodeAt(i))) i++;
    if (i === nameStart) {
      i++;
      continue;
    }
    const curName = attrStr.slice(nameStart, i).toLowerCase();
    while (i < n && isHtmlWsChar(attrStr.charCodeAt(i))) i++;
    let val = '';
    if (i < n && attrStr.charCodeAt(i) === 61 /* '=' */) {
      i++;
      while (i < n && isHtmlWsChar(attrStr.charCodeAt(i))) i++;
      if (i < n) {
        const q = attrStr.charCodeAt(i);
        if (q === 34 /* '"' */ || q === 39 /* "'" */) {
          i++;
          const vStart = i;
          const closeQ = attrStr.indexOf(q === 34 ? '"' : "'", i);
          if (closeQ === -1) {
            val = attrStr.slice(vStart);
            i = n;
          } else {
            val = attrStr.slice(vStart, closeQ);
            i = closeQ + 1;
          }
        } else {
          const vStart = i;
          while (i < n && !isHtmlWsChar(attrStr.charCodeAt(i)) && attrStr.charCodeAt(i) !== 62) i++;
          val = attrStr.slice(vStart, i);
        }
      }
    }
    if (curName === target) return val;
  }
  return null;
}

/**
 * Strictly `O(attrStr.length)` whitespace-separated class/token matcher (e.g. `attrHasTokenLinear(attr, 'class', 's-prose')`).
 */
export function attrHasTokenLinear(attrStr: string, attrName: string, token: string): boolean {
  const val = getAttrValueLinear(attrStr, attrName);
  if (!val) return false;
  const target = token.toLowerCase();
  const parts = val.toLowerCase().split(/[ \t\r\n\f]+/);
  return parts.includes(target);
}

/**
 * Provably `O(N)` open-tag scanner (`<tagName ...>`): uses monotonic `cachedGt` + `nextLt` pointers so adversarial
 * runs of unclosed `<div role=main ` or `<span style="` finish in `< 1 ms` with zero backtracking.
 */
export function findOpenTagLinear(
  html: string,
  tagName: string,
  predicate?: (attrStr: string) => boolean,
  startPos = 0,
): LinearOpenTagMatch | null {
  const tagLower = tagName.toLowerCase();
  const tLen = tagLower.length;
  const n = html.length;
  let pos = Math.max(0, startPos);
  let cachedGt = html.indexOf('>', pos);
  if (cachedGt === -1) return null;

  while (pos < n) {
    const lt = html.indexOf('<', pos);
    if (lt === -1 || lt + 1 + tLen >= n) return null;

    let matched = true;
    for (let k = 0; k < tLen; k++) {
      let c = html.charCodeAt(lt + 1 + k);
      if (c >= 65 && c <= 90) c += 32;
      if (c !== tagLower.charCodeAt(k)) {
        matched = false;
        break;
      }
    }
    const afterName = lt + 1 + tLen;
    if (!matched || !isHtmlTagBoundaryChar(html.charCodeAt(afterName))) {
      pos = lt + 1;
      continue;
    }

    if (cachedGt < afterName) {
      cachedGt = html.indexOf('>', afterName);
      if (cachedGt === -1) return null;
    }
    const nextLt = html.indexOf('<', afterName);
    if (nextLt !== -1 && nextLt < cachedGt) {
      pos = nextLt;
      continue;
    }

    const selfClosing = cachedGt > afterName && html.charCodeAt(cachedGt - 1) === 47;
    const attrStr = html.slice(afterName, selfClosing ? cachedGt - 1 : cachedGt);
    if (!predicate || predicate(attrStr)) {
      return {
        index: lt,
        openEnd: cachedGt + 1,
        openTag: html.slice(lt, cachedGt + 1),
        attrStr,
        selfClosing,
      };
    }
    pos = cachedGt + 1;
  }
  return null;
}

/**
 * Provably `O(N)` multi-open-tag scanner (e.g. `<div id="answer-123">` or `<div class="file">`).
 */
export function findAllOpenTagsLinear(
  html: string,
  tagName: string,
  predicate?: (attrStr: string) => boolean,
  maxItems = 50,
): LinearOpenTagMatch[] {
  const out: LinearOpenTagMatch[] = [];
  let pos = 0;
  while (pos < html.length && out.length < maxItems) {
    const m = findOpenTagLinear(html, tagName, predicate, pos);
    if (!m) break;
    out.push(m);
    pos = m.openEnd;
  }
  return out;
}

function findCloseTagLinear(html: string, tagLower: string, startPos: number): { closeStart: number; closeEnd: number } | null {
  const tLen = tagLower.length;
  const n = html.length;
  let pos = Math.max(0, startPos);
  while (pos < n) {
    const lt = html.indexOf('<', pos);
    if (lt === -1 || lt + 2 + tLen >= n) return null;
    if (html.charCodeAt(lt + 1) !== 47 /* '/' */) {
      pos = lt + 1;
      continue;
    }
    let matched = true;
    for (let k = 0; k < tLen; k++) {
      let c = html.charCodeAt(lt + 2 + k);
      if (c >= 65 && c <= 90) c += 32;
      if (c !== tagLower.charCodeAt(k)) {
        matched = false;
        break;
      }
    }
    let p = lt + 2 + tLen;
    if (!matched) {
      pos = lt + 2;
      continue;
    }
    while (p < n && isHtmlWsChar(html.charCodeAt(p))) p++;
    if (p < n && html.charCodeAt(p) === 62 /* '>' */) {
      return { closeStart: lt, closeEnd: p + 1 };
    }
    pos = lt + 2;
  }
  return null;
}

/**
 * Provably `O(N)` paired element inner HTML extractor (`<tagName ...>inner</tagName>`).
 * Terminates immediately on missing `</tagName>` so unclosed `<h1><h1>...` pumps run in `< 0.5 ms`.
 */
export function findElementInnerLinear(
  html: string,
  tagName: string,
  predicate?: (attrStr: string) => boolean,
  startPos = 0,
): string | null {
  const tagLower = tagName.toLowerCase();
  const open = findOpenTagLinear(html, tagLower, predicate, startPos);
  if (!open) return null;
  if (open.selfClosing) return '';
  const close = findCloseTagLinear(html, tagLower, open.openEnd);
  if (!close) return null;
  return html.slice(open.openEnd, close.closeStart);
}

/**
 * Provably `O(N)` multi-element inner HTML/XML extractor (`<item>...</item>`, `<span class="comment-copy">...</span>`).
 */
export function findAllElementInnersLinear(
  html: string,
  tagName: string,
  predicate?: (attrStr: string) => boolean,
  maxItems = 100,
): string[] {
  const tagLower = tagName.toLowerCase();
  const out: string[] = [];
  let pos = 0;
  while (pos < html.length && out.length < maxItems) {
    const open = findOpenTagLinear(html, tagLower, predicate, pos);
    if (!open) break;
    if (open.selfClosing) {
      out.push('');
      pos = open.openEnd;
      continue;
    }
    const close = findCloseTagLinear(html, tagLower, open.openEnd);
    if (!close) break;
    out.push(html.slice(open.openEnd, close.closeStart));
    pos = close.closeEnd;
  }
  return out;
}

/**
 * Linear XML/RSS element text reader supporting optional `<![CDATA[...]]>` payloads without `RegExp` construction.
 */
export function extractXmlTagTextLinear(xml: string, tagName: string): string {
  const raw = findElementInnerLinear(xml, tagName);
  if (!raw) return '';
  const trimmed = raw.trim();
  if (trimmed.startsWith('<![CDATA[') && trimmed.endsWith(']]>')) {
    return trimmed.slice(9, -3).trim();
  }
  return trimmed;
}
