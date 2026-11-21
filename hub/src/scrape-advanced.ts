/**
 * Advanced `/v1/scrape` & `/v2/scrape` capabilities (`hub/src/scrape-advanced.ts`):
 *  - `$0` High-Precision Prompt Injection Guard (`checkPromptInjection: true` -> `403 SCRAPE_PROMPT_INJECTION_DETECTED`)
 *  - Structured E-Commerce `product` format (Schema.org `Product`, OpenGraph `product:*`, Shopify JSON)
 *  - Targeted `{ type: "attributes", selectors: [{ selector, attribute }] }` extraction
 *  - Inline browser `actions[]` normalizer (up to 50 steps: `click` `all`, `write`, `press`, `scroll`, `screenshot`, `scrape`, `executeJavascript`, `pdf`)
 *  - PDF `parsers` array (`parsers: []` raw base64 mode, `pages: true`, `pageMarkers: true`, `mode: "fast" | "auto" | "ocr"`)
 */

import { extractJsonLdObjects } from './extractors/utils';
import { validatePublicHttpsTargetUrl } from './overflow';
import {
  asciiLower,
  isTagNameBoundary,
  MAX_HTML_SCAN_CHARS,
  replaceHtmlTagsQuoteAwareLinear,
  replacePairedHtmlElementsLinear,
  scanHtmlTagsLinear,
  stripHtmlCommentsLinear,
  stripHtmlTagsLinear,
  stripHtmlTagsQuoteAwareLinear,
} from './safe-input';

const INJECTION_PATTERNS: Array<{ id: string; re: RegExp; weight: number }> = [
  {
    id: 'ignore_previous_instructions',
    re: /\b(?:ignore|disregard|forget|override)[ \t\r\n]{1,20}(?:all[ \t\r\n]{1,20})?(?:previous|prior|above|earlier|system|developer)[ \t\r\n]{1,20}(?:instructions?|prompts?|rules?|directives?|guidelines?)\b/i,
    weight: 3,
  },
  {
    id: 'new_system_role_override',
    re: /(?:^|\n)[ \t]{0,20}(?:\[?[ \t]{0,10}system[ \t]{0,10}(?:prompt|override|instruction)[ \t]{0,10}\]?|<[ \t]{0,10}system[ \t]{0,10}>|###[ \t]{0,10}system[ \t]{1,10}instruction)[ \t]{0,10}:/i,
    weight: 3,
  },
  {
    id: 'exfiltrate_secrets_or_tools',
    re: /\b(?:send|post|upload|exfiltrate|transmit|forward)[ \t\r\n]{1,20}(?:the[ \t\r\n]{1,20})?(?:api[_\s-]?key|token|secret|password|conversation|system[ \t\r\n]{1,10}prompt|ssh|env)[ \t\r\n]{1,20}(?:to|via)[ \t\r\n]{1,20}https?:\/\//i,
    weight: 4,
  },
  {
    id: 'tool_invocation_hijack',
    re: /\b(?:immediately[ \t\r\n]{1,20}call|you[ \t\r\n]{1,20}must[ \t\r\n]{1,20}now[ \t\r\n]{1,20}execute|invoke[ \t\r\n]{1,20}the[ \t\r\n]{1,20}tool|execute[ \t\r\n]{1,20}bash[ \t\r\n]{1,20}command)\b[^.\n]{0,80}\b(?:curl|wget|fetch_url|bash|rm[ \t]{1,10}-rf)\b/i,
    weight: 4,
  },
];

const HIDDEN_STYLE_TOKEN_RE = /(?:display[ \t]*:[ \t]*none|visibility[ \t]*:[ \t]*hidden|opacity[ \t]*:[ \t]*0(?![0-9.])|font-size[ \t]*:[ \t]*0(?![0-9.]))/i;
const HIDDEN_OVERRIDE_KEYWORD_RE = /\b(?:ignore|disregard|system[ \t\r\n]{1,10}prompt|assistant|tool|execute|instructions?)\b/i;

/**
 * Strips fenced code blocks (supporting 3+ backticks or tildes per CommonMark so 4-backtick fences cannot be broken out
 * of by inner 3-backtick lines!) and inline code spans in linear O(N) time (`H1`).
 */
function stripMarkdownCodeBlocksAndSpansLinear(md: string): string {
  const lines = md.split('\n');
  const proseLines: string[] = [];
  let openFenceChar = '';
  let openFenceLen = 0;

  for (const line of lines) {
    if (!openFenceChar) {
      const m = /^[ \t]{0,3}(`{3,}|~{3,})/.exec(line);
      if (m) {
        const fence = m[1]!;
        const ch = fence[0]!;
        // Info string for backtick fences cannot contain backticks in CommonMark
        if (ch !== '`' || !line.slice(m[0].length).includes('`')) {
          openFenceChar = ch;
          openFenceLen = fence.length;
          continue;
        }
      }
      proseLines.push(line);
    } else {
      const closeRe = openFenceChar === '`' ? /^[ \t]{0,3}(`{3,})[ \t\r]*$/ : /^[ \t]{0,3}(~{3,})[ \t\r]*$/;
      const cm = closeRe.exec(line);
      if (cm && cm[1]!.length >= openFenceLen) {
        openFenceChar = '';
        openFenceLen = 0;
      }
    }
  }

  // Strip inline code spans line-by-line (linear scan matching equal-length backtick runs)
  return proseLines
    .map((ln) => {
      if (ln.indexOf('`') < 0) return ln;
      let out = '';
      let i = 0;
      while (i < ln.length) {
        const tick = ln.indexOf('`', i);
        if (tick < 0) {
          out += ln.slice(i);
          break;
        }
        out += ln.slice(i, tick);
        let runEnd = tick + 1;
        while (runEnd < ln.length && ln.charCodeAt(runEnd) === 96) runEnd++;
        const runLen = runEnd - tick;
        // Find matching run of exact `runLen` backticks on this line
        let search = runEnd;
        let matchedEnd = -1;
        while (search < ln.length) {
          const nextTick = ln.indexOf('`', search);
          if (nextTick < 0) break;
          let nextEnd = nextTick + 1;
          while (nextEnd < ln.length && ln.charCodeAt(nextEnd) === 96) nextEnd++;
          if (nextEnd - nextTick === runLen) {
            matchedEnd = nextEnd;
            break;
          }
          search = nextEnd;
        }
        if (matchedEnd >= 0) {
          out += ' ';
          i = matchedEnd;
        } else {
          out += ln.slice(tick, runEnd);
          i = runEnd;
        }
      }
      return out;
    })
    .join('\n');
}

const INLINE_SPLIT_TAGS = new Set([
  'a',
  'abbr',
  'b',
  'bdi',
  'bdo',
  'cite',
  'del',
  'dfn',
  'em',
  'font',
  'i',
  'ins',
  'kbd',
  'mark',
  'q',
  's',
  'samp',
  'small',
  'span',
  'strike',
  'strong',
  'sub',
  'sup',
  'time',
  'u',
  'var',
  'wbr',
]);

function normalizeProseForInjectionScan(prose: string): string {
  let out = prose;
  if (out.includes('<!--')) {
    out = stripHtmlCommentsLinear(out, MAX_HTML_SCAN_CHARS);
  }
  if (out.includes('<')) {
    out = stripHtmlTagsLinear(out, ['script', 'style', 'noscript', 'template'], ' ', MAX_HTML_SCAN_CHARS);
    out = replaceHtmlTagsQuoteAwareLinear(
      out,
      (tag) => (INLINE_SPLIT_TAGS.has(tag.tagNameLower) ? '' : ' '),
      MAX_HTML_SCAN_CHARS,
      false,
    );
  }
  if (out.includes('&')) {
    out = out
      .replace(/&#(\d{1,7});/g, (_m, dec: string) => {
        const cp = Number(dec);
        return Number.isFinite(cp) && cp > 0 && cp <= 0x10ffff ? String.fromCodePoint(cp) : '';
      })
      .replace(/&#x([0-9a-fA-F]{1,6});/g, (_m, hex: string) => {
        const cp = parseInt(hex, 16);
        return Number.isFinite(cp) && cp > 0 && cp <= 0x10ffff ? String.fromCodePoint(cp) : '';
      })
      .replace(/&(?:nbsp|ensp|emsp|thinsp);/gi, ' ')
      .replace(/&shy;/gi, '')
      .replace(/&(?:zwj|zwnj);/gi, '')
      .replace(/&quot;/gi, '"')
      .replace(/&apos;/gi, "'")
      .replace(/&lt;/gi, '<')
      .replace(/&gt;/gi, '>')
      .replace(/&amp;/gi, '&');
  }
  return out.replace(/[\u00AD\u061C\u180E\u200B-\u200F\u202A-\u202E\u2060-\u206F\uFEFF\u{E0000}-\u{E01EF}]/gu, '');
}

/**
 * Scans extracted prose and raw HTML for indirect prompt-injection payloads while stripping fenced code blocks and
 * `<code>`/`<pre>` elements so security documentation discussing prompt injection does not false-positive (`H1`, `R3-M3`).
 */
export function detectPromptInjection(params: {
  markdown: string;
  rawHtml?: string;
}): { detected: boolean; triggers: string[] } {
  const boundedHtml = (params.rawHtml ?? '').slice(0, MAX_HTML_SCAN_CHARS);
  const boundedMd = params.markdown.slice(0, MAX_HTML_SCAN_CHARS);
  const triggers: string[] = [];
  let totalScore = 0;

  // 1. Invisible Unicode Tag ASCII smuggling (`U+E0000`–`U+E007F`) in raw source or Markdown
  if (/[\u{E0000}-\u{E007F}]{4,}/u.test(boundedHtml) || /[\u{E0000}-\u{E007F}]{4,}/u.test(boundedMd)) {
    triggers.push('unicode_tag_ascii_smuggling');
    totalScore += 4;
  }

  // 2. Hidden CSS / DOM subtree containing imperative LLM override phrases (strictly linear O(N) scan with monotonic close-tag & window cursors)
  if (boundedHtml) {
    const rawWithoutCode = stripHtmlTagsLinear(boundedHtml, ['pre', 'code'], ' ', MAX_HTML_SCAN_CHARS);
    const lowerWithoutCode = asciiLower(rawWithoutCode);
    const nextCloseByTag = new Map<string, number>();
    let scannedHiddenUpTo = 0;
    scanHtmlTagsLinear(
      rawWithoutCode,
      (tag) => {
        if (tag.isClosing || tag.isSelfClosing || tag.isDeclaration) return;
        if (tag.attrs.indexOf('style') < 0 && tag.attrs.indexOf('STYLE') < 0 && !/style/i.test(tag.attrs)) return;
        const attrs = parseOpenTagAttributes(tag.attrs);
        const styleVal = attrs.style ?? '';
        if (!styleVal || !HIDDEN_STYLE_TOKEN_RE.test(styleVal)) return;

        const closeNeedle = `</${tag.tagNameLower}`;
        let closeIdx = nextCloseByTag.get(tag.tagNameLower);
        if (closeIdx === undefined || (closeIdx >= 0 && closeIdx < tag.end)) {
          let searchFrom = closeIdx !== undefined && closeIdx >= 0 ? Math.max(tag.end, closeIdx) : tag.end;
          let found = -1;
          while (searchFrom < rawWithoutCode.length) {
            const cand = lowerWithoutCode.indexOf(closeNeedle, searchFrom);
            if (cand < 0) break;
            const afterIdx = cand + closeNeedle.length;
            if (afterIdx < rawWithoutCode.length && isTagNameBoundary(rawWithoutCode.charCodeAt(afterIdx))) {
              found = cand;
              break;
            }
            searchFrom = afterIdx;
          }
          closeIdx = found;
          nextCloseByTag.set(tag.tagNameLower, closeIdx);
        }

        const maxSearchEnd = Math.min(rawWithoutCode.length, tag.end + 1400);
        const sliceEnd = closeIdx >= 0 && closeIdx <= maxSearchEnd ? closeIdx : Math.min(rawWithoutCode.length, tag.end + 1200);
        const sliceStart = Math.max(tag.end, scannedHiddenUpTo - 64);
        if (sliceEnd <= sliceStart) return;
        scannedHiddenUpTo = Math.max(scannedHiddenUpTo, sliceEnd);
        const innerTxt = normalizeProseForInjectionScan(
          stripHtmlTagsQuoteAwareLinear(rawWithoutCode.slice(sliceStart, sliceEnd), ' ', 2000),
        );
        if (HIDDEN_OVERRIDE_KEYWORD_RE.test(innerTxt)) {
          triggers.push('hidden_css_instruction_injection');
          totalScore += 5;
          return false;
        }
        return undefined;
      },
      MAX_HTML_SCAN_CHARS,
      false,
    );
  }

  // 3. Prose scan (excluding fenced code blocks and inline code spans, stripping zero-width chars, entities, and inline HTML tags)
  const proseWithoutCode = normalizeProseForInjectionScan(stripMarkdownCodeBlocksAndSpansLinear(boundedMd));

  for (const pat of INJECTION_PATTERNS) {
    if (pat.re.test(proseWithoutCode)) {
      triggers.push(pat.id);
      totalScore += pat.weight;
    }
  }

  return {
    detected: totalScore >= 3,
    triggers: [...new Set(triggers)],
  };
}

function parseSimpleSelector(rawSelector: string): {
  tag?: string;
  id?: string;
  classes: string[];
  attrName?: string;
  attrVal?: string;
} | null {
  const s = rawSelector.trim();
  if (!s) return null;
  // Use last descendant segment (e.g. "main a.card" -> "a.card") for fast streaming regex match
  const leaf = s.split(/\s+|>|\+|~/).filter(Boolean).pop() ?? s;
  let rest = leaf;
  let attrName: string | undefined;
  let attrVal: string | undefined;
  const attrMatch = /\[([a-zA-Z0-9_:-]+)(?:=(?:"([^"]*)"|'([^']*)'|([^\]]*)))?\]/.exec(rest);
  if (attrMatch) {
    attrName = attrMatch[1]!.toLowerCase();
    attrVal = attrMatch[2] ?? attrMatch[3] ?? attrMatch[4];
    rest = rest.replace(attrMatch[0], '');
  }
  const idMatch = /#([a-zA-Z0-9_-]+)/.exec(rest);
  const id = idMatch?.[1];
  if (idMatch) rest = rest.replace(idMatch[0], '');
  const classes = [...rest.matchAll(/\.([a-zA-Z0-9_-]+)/g)].map((m) => m[1]!);
  rest = rest.replace(/\.[a-zA-Z0-9_-]+/g, '').trim();
  const tag = rest && rest !== '*' && /^[a-zA-Z][a-zA-Z0-9-]*$/.test(rest) ? rest.toLowerCase() : undefined;
  return { ...(tag ? { tag } : {}), ...(id ? { id } : {}), classes, ...(attrName ? { attrName } : {}), ...(attrVal !== undefined ? { attrVal } : {}) };
}

function parseOpenTagAttributes(attrChunk: string): Record<string, string> {
  const attrs: Record<string, string> = {};
  const re = /([a-zA-Z_:][a-zA-Z0-9_.:-]*)\s*(?:=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+)))?/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(attrChunk)) !== null) {
    const key = m[1]!.toLowerCase();
    const val = m[2] ?? m[3] ?? m[4] ?? '';
    attrs[key] = val.replace(/&amp;/g, '&').replace(/&quot;/g, '"').replace(/&#39;/g, "'");
  }
  return attrs;
}

/**
 * Extracts HTML attribute values for `{ type: "attributes", selectors: [{ selector, attribute }] }` without DOM bloat (`H1`).
 */
export function extractHtmlAttributesBySelectors(
  rawHtml: string,
  selectors: Array<{ selector: string; attribute: string }>,
): Record<string, unknown> {
  const cleanedHtml = stripHtmlTagsLinear(
    stripHtmlCommentsLinear(rawHtml, MAX_HTML_SCAN_CHARS),
    ['script', 'style', 'template'],
    '',
    MAX_HTML_SCAN_CHARS,
  );

  // Scan open tags ONCE linearly across all requested selectors
  const openTags: Array<{ tag: string; attrs: Record<string, string> }> = [];
  scanHtmlTagsLinear(
    cleanedHtml,
    (t) => {
      if (t.isClosing || t.isDeclaration) return;
      openTags.push({ tag: t.tagNameLower, attrs: parseOpenTagAttributes(t.attrs) });
      return openTags.length < 25_000 ? undefined : false;
    },
    MAX_HTML_SCAN_CHARS,
    false,
  );

  const results: Array<{ selector: string; attribute: string; values: string[] }> = [];
  for (const spec of selectors.slice(0, 25)) {
    const selStr = typeof spec.selector === 'string' ? spec.selector.trim() : '';
    const attrTarget = typeof spec.attribute === 'string' ? spec.attribute.trim().toLowerCase() : '';
    if (!selStr || !attrTarget) continue;
    const parsed = parseSimpleSelector(selStr);
    if (!parsed) {
      results.push({ selector: selStr, attribute: attrTarget, values: [] });
      continue;
    }

    const values: string[] = [];
    for (const item of openTags) {
      if (values.length >= 200) break;
      if (parsed.tag && item.tag !== parsed.tag) continue;
      const attrs = item.attrs;
      if (parsed.id && attrs.id !== parsed.id) continue;
      if (parsed.classes.length > 0) {
        const clsTokens = (attrs.class ?? '').split(/\s+/).filter(Boolean);
        if (!parsed.classes.every((c) => clsTokens.includes(c))) continue;
      }
      if (parsed.attrName) {
        if (!(parsed.attrName in attrs)) continue;
        if (parsed.attrVal !== undefined && attrs[parsed.attrName] !== parsed.attrVal) continue;
      }
      if (attrTarget in attrs && attrs[attrTarget] !== undefined) {
        values.push(attrs[attrTarget]!);
      }
    }
    results.push({ selector: selStr, attribute: attrTarget, values });
  }

  return { items: results };
}

function matchMetaContent(rawHtml: string, names: readonly string[]): string | undefined {
  const wanted = new Map<string, number>();
  names.forEach((n, idx) => wanted.set(n.toLowerCase(), idx));
  const hits = new Map<number, string>();
  scanHtmlTagsLinear(
    rawHtml,
    (tag) => {
      if (tag.isClosing || tag.tagNameLower !== 'meta') return;
      const attrs = parseOpenTagAttributes(tag.attrs);
      const key = (attrs.property ?? attrs.name ?? attrs.itemprop ?? '').toLowerCase();
      const orderIdx = wanted.get(key);
      if (orderIdx !== undefined && !hits.has(orderIdx) && attrs.content?.trim()) {
        hits.set(orderIdx, attrs.content.trim());
        if (orderIdx === 0) return false;
      }
      return undefined;
    },
    160_000,
    false,
  );
  for (let i = 0; i < names.length; i++) {
    const val = hits.get(i);
    if (val) return val;
  }
  return undefined;
}

function extractFirstHeadingTextLinear(rawBody: string, tagNameLower: string): string | undefined {
  let heading: string | undefined;
  replacePairedHtmlElementsLinear(
    rawBody,
    [tagNameLower],
    (_full, _t, _attrs, inner) => {
      if (heading === undefined) {
        const clean = stripHtmlTagsQuoteAwareLinear(inner, ' ', 8000).replace(/\s+/g, ' ').trim();
        if (clean) heading = clean;
      }
      return '';
    },
    { maxChars: 200_000, maxInnerChars: 8000 },
  );
  return heading;
}

/**
 * Extracts normalized e-commerce product metadata (`formats: ["product"]`) across Schema.org `Product`,
 * OpenGraph `product:*` / `og:*` tags, and embedded Shopify product JSON.
 */
export function extractStructuredProduct(params: {
  rawBody: string;
  finalUrl: string;
  fallbackTitle?: string;
  fallbackDescription?: string;
}): Record<string, unknown> | null {
  const { rawBody, finalUrl, fallbackTitle, fallbackDescription } = params;
  if (!rawBody) return null;

  const jsonLdList = extractJsonLdObjects(rawBody);
  const productLd = jsonLdList.find((obj) => {
    const t = obj['@type'];
    const types = Array.isArray(t) ? t.map(String) : typeof t === 'string' ? [t] : [];
    return types.some((x) => /^(?:Product|ProductGroup|IndividualProduct|SoftwareApplication)$/i.test(x.replace(/^schema:/i, '')));
  });

  if (productLd) {
    const brandRaw = productLd.brand;
    const brand =
      typeof brandRaw === 'string'
        ? brandRaw
        : brandRaw && typeof brandRaw === 'object' && typeof (brandRaw as { name?: unknown }).name === 'string'
          ? (brandRaw as { name: string }).name
          : undefined;

    const offersRaw = productLd.offers;
    const offerList = Array.isArray(offersRaw)
      ? (offersRaw as Array<Record<string, unknown>>)
      : offersRaw && typeof offersRaw === 'object'
        ? [offersRaw as Record<string, unknown>]
        : [];
    const primaryOffer = offerList[0] ?? {};
    const rawPrice = primaryOffer.price ?? primaryOffer.lowPrice;
    const price =
      typeof rawPrice === 'number'
        ? rawPrice
        : typeof rawPrice === 'string' && rawPrice.trim()
          ? Number(rawPrice.replace(/[^0-9.]/g, '')) || rawPrice.trim()
          : undefined;
    const currency = typeof primaryOffer.priceCurrency === 'string' ? primaryOffer.priceCurrency : undefined;
    const availability =
      typeof primaryOffer.availability === 'string'
        ? primaryOffer.availability.replace(/^https?:\/\/schema\.org\//i, '')
        : undefined;

    const imgsRaw = productLd.image;
    const images = (Array.isArray(imgsRaw) ? imgsRaw : imgsRaw ? [imgsRaw] : [])
      .map((im) => (typeof im === 'string' ? im : im && typeof im === 'object' && typeof (im as { url?: unknown }).url === 'string' ? (im as { url: string }).url : ''))
      .filter(Boolean);

    const ratingObj =
      productLd.aggregateRating && typeof productLd.aggregateRating === 'object'
        ? (productLd.aggregateRating as Record<string, unknown>)
        : null;

    return {
      title: typeof productLd.name === 'string' ? productLd.name : fallbackTitle,
      ...(typeof productLd.description === 'string' ? { description: productLd.description } : fallbackDescription ? { description: fallbackDescription } : {}),
      ...(brand ? { brand } : {}),
      ...(typeof productLd.sku === 'string' ? { sku: productLd.sku } : {}),
      ...(typeof productLd.gtin13 === 'string' ? { gtin: productLd.gtin13 } : typeof productLd.gtin === 'string' ? { gtin: productLd.gtin } : {}),
      ...(price !== undefined ? { price } : {}),
      ...(currency ? { currency } : {}),
      ...(availability ? { availability } : {}),
      url: typeof productLd.url === 'string' ? productLd.url : finalUrl,
      ...(images.length > 0 ? { images } : {}),
      ...(ratingObj?.ratingValue !== undefined ? { rating: Number(ratingObj.ratingValue) || ratingObj.ratingValue } : {}),
      ...(ratingObj?.reviewCount !== undefined ? { reviewCount: Number(ratingObj.reviewCount) || ratingObj.reviewCount } : {}),
      ...(offerList.length > 1
        ? {
            variants: offerList.slice(0, 30).map((o) => ({
              ...(typeof o.name === 'string' ? { name: o.name } : {}),
              ...(typeof o.sku === 'string' ? { sku: o.sku } : {}),
              ...(o.price !== undefined ? { price: Number(String(o.price).replace(/[^0-9.]/g, '')) || o.price } : {}),
              ...(typeof o.priceCurrency === 'string' ? { currency: o.priceCurrency } : {}),
              ...(typeof o.availability === 'string' ? { availability: o.availability.replace(/^https?:\/\/schema\.org\//i, '') } : {}),
            })),
          }
        : {}),
    };
  }

  // Fallback to OpenGraph `product:price:amount` / meta tags
  const ogPrice = matchMetaContent(rawBody, ['product:price:amount', 'og:price:amount', 'price']);
  const ogCurrency = matchMetaContent(rawBody, ['product:price:currency', 'og:price:currency', 'priceCurrency']);
  const ogBrand = matchMetaContent(rawBody, ['product:brand', 'og:brand', 'brand']);
  const ogAvail = matchMetaContent(rawBody, ['product:availability', 'og:availability', 'availability']);
  const ogImage = matchMetaContent(rawBody, ['og:image']);

  if (ogPrice || ogBrand || ogAvail) {
    return {
      title: matchMetaContent(rawBody, ['og:title']) ?? fallbackTitle,
      ...(fallbackDescription ? { description: fallbackDescription } : {}),
      ...(ogBrand ? { brand: ogBrand } : {}),
      ...(ogPrice ? { price: Number(ogPrice.replace(/[^0-9.]/g, '')) || ogPrice } : {}),
      ...(ogCurrency ? { currency: ogCurrency } : {}),
      ...(ogAvail ? { availability: ogAvail } : {}),
      ...(ogImage ? { images: [ogImage] } : {}),
      url: finalUrl,
    };
  }

  // Fallback for barcode / consumer packaged goods & microdata pages (e.g. Open Food Facts `/product/<gtin>`)
  const ogType = matchMetaContent(rawBody, ['og:type'])?.toLowerCase();
  const barcodeMatch = /\/product\/(\d{8,14})(?:\/|$)/i.exec(finalUrl);
  if (ogType === 'product' || ogType === 'og:product' || ogType?.includes('food') || barcodeMatch) {
    const titleCandidate =
      matchMetaContent(rawBody, ['og:title', 'twitter:title']) ??
      extractFirstHeadingTextLinear(rawBody, 'h1') ??
      fallbackTitle;
    if (titleCandidate) {
      const brandFromTitle = titleCandidate.includes('–')
        ? titleCandidate.split('–')[1]?.trim()
        : titleCandidate.includes(' - ')
          ? titleCandidate.split(' - ')[1]?.trim()
          : undefined;
      return {
        title: titleCandidate,
        ...(fallbackDescription ? { description: fallbackDescription } : {}),
        ...(brandFromTitle ? { brand: brandFromTitle } : {}),
        ...(barcodeMatch?.[1] ? { gtin: barcodeMatch[1] } : {}),
        ...(ogImage ? { images: [ogImage] } : {}),
        url: finalUrl,
      };
    }
  }

  return null;
}

const SUPPORTED_INLINE_ACTIONS = new Set([
  'wait',
  'click',
  'write',
  'fill',
  'type',
  'select',
  'press',
  'scroll',
  'navigate',
  'screenshot',
  'scrape',
  'executejavascript',
  'pdf',
]);

/**
 * Validates and normalizes up to 50 sequential inline browser `actions` on `/v1/scrape` or `/v1/interact`.
 */
export function normalizeInlineBrowserActions(
  rawActions: unknown,
  selfHost?: string,
  maxItems = 50,
): { ok: true; actions: Array<Record<string, unknown>> } | { ok: false; message: string } {
  if (!Array.isArray(rawActions) || rawActions.length === 0) {
    return { ok: true, actions: [] };
  }
  if (rawActions.length > maxItems) {
    return { ok: false, message: `maximum ${maxItems} browser actions permitted per request` };
  }

  const out: Array<Record<string, unknown>> = [];
  for (const rawAct of rawActions) {
    if (!rawAct || typeof rawAct !== 'object' || Array.isArray(rawAct)) continue;
    const a = rawAct as Record<string, unknown>;
    const rawType = typeof a.type === 'string' ? a.type.trim() : '';
    const lowerType = rawType.toLowerCase();
    if (!SUPPORTED_INLINE_ACTIONS.has(lowerType)) {
      return { ok: false, message: `unsupported action type: ${rawType}` };
    }
    if (lowerType === 'navigate') {
      const navCheck = validatePublicHttpsTargetUrl(a.url, selfHost);
      if (!navCheck.ok) {
        return { ok: false, message: `navigate action: ${navCheck.message}` };
      }
    }
    const rawMs =
      typeof a.waitMs === 'number' && Number.isFinite(a.waitMs)
        ? a.waitMs
        : typeof a.milliseconds === 'number' && Number.isFinite(a.milliseconds)
          ? a.milliseconds
          : undefined;
    const explicitWaitMs = rawMs !== undefined ? Math.min(15_000, Math.max(0, Math.floor(rawMs))) : undefined;
    const keyVal = typeof a.key === 'string' ? a.key.slice(0, 40) : undefined;
    const textVal =
      typeof a.value === 'string'
        ? a.value.slice(0, 4096)
        : typeof a.text === 'string'
          ? a.text.slice(0, 4096)
          : undefined;
    const effectiveWaitMs =
      explicitWaitMs !== undefined
        ? explicitWaitMs
        : lowerType === 'click'
          ? 1_000
          : lowerType === 'press' && (!keyVal || /^(?:enter|return)$/i.test(keyVal))
            ? 800
            : undefined;

    out.push({
      type: lowerType === 'executejavascript' ? 'executeJavascript' : lowerType,
      ...(typeof a.selector === 'string' ? { selector: a.selector.slice(0, 240) } : {}),
      ...(a.all === true ? { all: true } : {}),
      ...(textVal !== undefined ? { value: textVal, text: textVal } : {}),
      ...(keyVal !== undefined ? { key: keyVal } : {}),
      ...(typeof a.direction === 'string' && /^(?:up|down)$/i.test(a.direction.trim())
        ? { direction: a.direction.trim().toLowerCase() }
        : {}),
      ...(typeof a.script === 'string' ? { script: a.script.slice(0, 16_384) } : {}),
      ...(a.fullPage === true ? { fullPage: true } : {}),
      ...(typeof a.url === 'string' ? { url: a.url.trim() } : {}),
      ...(effectiveWaitMs !== undefined ? { waitMs: effectiveWaitMs } : {}),
    });
  }
  return { ok: true, actions: out };
}

export function parsePdfParserOptions(rawParsers: unknown): {
  skipPdfParsing: boolean;
  ocrModeOverride?: 'off' | 'auto' | 'always';
  maxPagesOverride?: number;
  includePagesArray: boolean;
  includePageMarkers: boolean;
} {
  if (!Array.isArray(rawParsers)) {
    return { skipPdfParsing: false, includePagesArray: false, includePageMarkers: false };
  }
  if (rawParsers.length === 0) {
    return { skipPdfParsing: true, includePagesArray: false, includePageMarkers: false };
  }
  let ocrModeOverride: 'off' | 'auto' | 'always' | undefined;
  let maxPagesOverride: number | undefined;
  let includePagesArray = false;
  let includePageMarkers = false;
  let sawPdfParser = false;

  for (const p of rawParsers) {
    if (p === 'pdf') {
      sawPdfParser = true;
    } else if (p && typeof p === 'object' && !Array.isArray(p)) {
      const po = p as Record<string, unknown>;
      if (po.type === 'pdf') {
        sawPdfParser = true;
        if (po.mode === 'fast') ocrModeOverride = 'off';
        else if (po.mode === 'ocr') ocrModeOverride = 'always';
        else if (po.mode === 'auto') ocrModeOverride = 'auto';
        if (typeof po.maxPages === 'number' && Number.isFinite(po.maxPages)) {
          maxPagesOverride = Math.min(500, Math.max(1, Math.floor(po.maxPages)));
        }
        if (po.pages === true) includePagesArray = true;
        if (po.pageMarkers === true) includePageMarkers = true;
      }
    }
  }
  return {
    skipPdfParsing: !sawPdfParser && rawParsers.length > 0 && !rawParsers.includes('image'),
    ...(ocrModeOverride ? { ocrModeOverride } : {}),
    ...(maxPagesOverride ? { maxPagesOverride } : {}),
    includePagesArray,
    includePageMarkers,
  };
}

export function splitPdfPagesAndMarkers(
  rawPdfMarkdown: string,
  includePageMarkers: boolean,
): { pages: string[]; markedMarkdown: string } {
  if (!rawPdfMarkdown) return { pages: [], markedMarkdown: '' };
  const rawPages = rawPdfMarkdown.includes('\f')
    ? rawPdfMarkdown
        .split('\f')
        .map((p) => p.trim())
        .filter(Boolean)
    : [rawPdfMarkdown.trim()];
  if (!includePageMarkers) {
    return { pages: rawPages, markedMarkdown: rawPdfMarkdown };
  }
  const marked = rawPages.map((p, idx) => `<!-- page ${idx + 1} -->\n\n${p}`).join('\n\n');
  return { pages: rawPages, markedMarkdown: marked };
}

export function encodeBodyToRawBase64(item: Record<string, unknown>): string | undefined {
  if (typeof item.bodyBase64 === 'string' && item.bodyBase64.length > 0) {
    return item.bodyBase64;
  }
  if (typeof item.body === 'string' && item.body.length > 0) {
    if (item.bodyEncoding === 'base64') {
      return item.body;
    }
    const bytes = new TextEncoder().encode(item.body);
    let bin = '';
    const chunk = 0x8000;
    for (let i = 0; i < bytes.length; i += chunk) {
      bin += String.fromCharCode(...bytes.subarray(i, i + chunk));
    }
    return btoa(bin);
  }
  return undefined;
}
