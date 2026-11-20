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

const INJECTION_PATTERNS: Array<{ id: string; re: RegExp; weight: number }> = [
  {
    id: 'ignore_previous_instructions',
    re: /\b(?:ignore|disregard|forget|override)\s+(?:all\s+)?(?:previous|prior|above|earlier|system|developer)\s+(?:instructions?|prompts?|rules?|directives?|guidelines?)\b/i,
    weight: 3,
  },
  {
    id: 'new_system_role_override',
    re: /(?:^|\n)\s*(?:\[?\s*system\s*(?:prompt|override|instruction)\s*\]?|<\s*system\s*>|###\s*system\s*instruction)\s*:/i,
    weight: 3,
  },
  {
    id: 'exfiltrate_secrets_or_tools',
    re: /\b(?:send|post|upload|exfiltrate|transmit|forward)\s+(?:the\s+)?(?:api[_\s-]?key|token|secret|password|conversation|system\s+prompt|ssh|env)\s+(?:to|via)\s+https?:\/\//i,
    weight: 4,
  },
  {
    id: 'tool_invocation_hijack',
    re: /\b(?:immediately\s+call|you\s+must\s+now\s+execute|invoke\s+the\s+tool|execute\s+bash\s+command)\b[^.\n]{0,80}\b(?:curl|wget|fetch_url|bash|rm\s+-rf)\b/i,
    weight: 4,
  },
];

/**
 * Scans extracted prose and raw HTML for indirect prompt-injection payloads while stripping fenced code blocks and
 * `<code>`/`<pre>` elements so security documentation discussing prompt injection does not false-positive.
 */
export function detectPromptInjection(params: {
  markdown: string;
  rawHtml?: string;
}): { detected: boolean; triggers: string[] } {
  const { markdown, rawHtml = '' } = params;
  const triggers: string[] = [];
  let totalScore = 0;

  // 1. Invisible Unicode Tag ASCII smuggling (`U+E0000`–`U+E007F`) in raw source
  if (/[\u{E0000}-\u{E007F}]{4,}/u.test(rawHtml)) {
    triggers.push('unicode_tag_ascii_smuggling');
    totalScore += 4;
  }

  // 2. Hidden CSS / DOM subtree containing imperative LLM override phrases
  const rawWithoutCode = rawHtml
    .replace(/<(?:pre|code)\b[^>]*>[\s\S]*?<\/(?:pre|code)>/gi, ' ')
    .slice(0, 250_000);
  for (const hiddenMatch of rawWithoutCode.matchAll(
    /<([a-z0-9]+)\b[^>]*style\s*=\s*(?:"[^"]*(?:display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0|font-size\s*:\s*0)[^"]*"|'[^']*(?:display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0|font-size\s*:\s*0)[^']*')[^>]*>([\s\S]{1,1200}?)<\/\1>/gi,
  )) {
    const innerTxt = hiddenMatch[2]!.replace(/<[^>]+>/g, ' ');
    if (/\b(?:ignore|disregard|system\s+prompt|assistant|tool|execute|instructions?)\b/i.test(innerTxt)) {
      triggers.push('hidden_css_instruction_injection');
      totalScore += 5;
      break;
    }
  }

  // 3. Prose scan (excluding fenced code blocks and inline code spans)
  const proseWithoutCode = markdown
    .replace(/```[\s\S]*?```/g, ' ')
    .replace(/~~~[\s\S]*?~~~/g, ' ')
    .replace(/`[^`\n]+`/g, ' ');

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
 * Extracts HTML attribute values for `{ type: "attributes", selectors: [{ selector, attribute }] }` without DOM bloat.
 */
export function extractHtmlAttributesBySelectors(
  rawHtml: string,
  selectors: Array<{ selector: string; attribute: string }>,
): Record<string, unknown> {
  const cleanedHtml = rawHtml
    .replace(/<!--[\s\S]*?-->/g, '')
    .replace(/<(?:script|style|template)\b[^>]*>[\s\S]*?<\/(?:script|style|template)>/gi, '');

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
    const tagPattern = parsed.tag ? parsed.tag.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') : '[a-zA-Z][a-zA-Z0-9-]*';
    const openRe = new RegExp(`<(${tagPattern})\\b((?:"[^"]*"|'[^']*'|[^>"'])*)>`, 'gi');
    let m: RegExpExecArray | null;
    while ((m = openRe.exec(cleanedHtml)) !== null && values.length < 200) {
      const attrs = parseOpenTagAttributes(m[2] ?? '');
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
  for (const name of names) {
    const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const m =
      new RegExp(`<meta\\b[^>]*(?:property|name|itemprop)\\s*=\\s*["']${escaped}["'][^>]*content\\s*=\\s*["']([^"']+)["']`, 'i').exec(
        rawHtml,
      ) ??
      new RegExp(`<meta\\b[^>]*content\\s*=\\s*["']([^"']+)["'][^>]*(?:property|name|itemprop)\\s*=\\s*["']${escaped}["']`, 'i').exec(
        rawHtml,
      );
    if (m?.[1]?.trim()) {
      return m[1].trim().replace(/&amp;/g, '&').replace(/&quot;/g, '"');
    }
  }
  return undefined;
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
      /<h1\b[^>]*>([\s\S]*?)<\/h1>/i.exec(rawBody)?.[1]?.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim() ??
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
