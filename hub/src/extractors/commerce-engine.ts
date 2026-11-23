/**
 * Reusable Commerce Normalization & Polite Catalog Engine Helpers (`hub/src/extractors/commerce-engine.ts`).
 *
 * Parameterized by declarative `catalog:` and commerce route definitions in `internal/extract/manifests/shopify.yaml`
 * and `internal/extract/manifests/woocommerce.yaml`, while exporting public normalization helpers for `scrape.ts`
 * and `catalog.ts`.
 *
 * Security & Complexity Invariants:
 *  - Zero `fetch()` calls, zero `eval`/`Function`.
 *  - Set-based O(N) image deduplication (`R5-H2`) and bounded `<= 250` variant/image caps.
 *  - Safe `%` URI decoding via `safeDecodeURIComponent` (`R5-Low`).
 */

import { isSafePublicHostname } from '../overflow';
import { safeDecodeURIComponent } from '../safe-input';
import {
  attrHasTokenLinear,
  findAllOpenTagsLinear,
  findElementInnerLinear,
  findOpenTagLinear,
  getAttrValueLinear,
  type CatalogRecord,
  type CatalogSpec,
  type CatalogVariantRecord,
  type HtmlExtractContext,
  type HtmlFragmentConverter,
  type PostFetchSiteResult,
  type TwinFormattedDoc,
} from './types';
import {
  extractJsonLdObjects,
  extractMetaContent,
  formatGfmTable,
  parseJsonObject,
  parseJsonValue,
  stripScriptsAndStyles,
  stripTagsInline,
} from './utils';

export interface DeclarativeCatalogConfig {
  platform: 'shopify' | 'woocommerce';
  pauseMs: number;
  pageCap: number;
  firstPageTemplate?: string;
  collectionPageTemplate?: string;
  perPage?: number;
  maxVariantsPerProduct?: number;
  maxImagesPerProduct?: number;
}

const DEFAULT_MAX_IMAGES_PER_PRODUCT = 250;
const DEFAULT_MAX_VARIANTS_PER_PRODUCT = 250;

/**
 * Sanitizes untrusted e-commerce text fields (`title`, `vendor`, `productType`, `tags`, `options`, `variants[].title`, `sku`)
 * non-destructively so product characters (`<`, `>`, `&`, `[`, `]`, `*`, `_`, `#`, `~`, `` ` ``, `|`) are preserved via escaping
 * rather than stripped, while HTML tags, entity smuggling, phishing links, emphasis breakouts, and ATX headings are impossible.
 */
export function sanitizeCommerceField(raw: unknown, maxLen = 400): string {
  if (typeof raw !== 'string') return '';
  let s = raw
    .replace(/\u001b\[[0-9;?]*[ -/]*[@-~]/g, '')
    .replace(
      /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F\u00AD\u061C\u180E\u200B-\u200F\u202A-\u202E\u2060-\u206F\uFEFF\u{E0000}-\u{E01EF}]/gu,
      '',
    )
    .replace(/[\r\n\t\u0085\u2028\u2029]+/g, ' ')
    .replace(/\s{2,}/g, ' ')
    .trim();
  if (!s) return '';
  if (s.length > maxLen) s = s.slice(0, maxLen).trim();
  // Non-destructively escape HTML `&`, `<`, `>` so `<USB-C>` or `<script>` is preserved as text, never stripped or executed
  if (s.includes('&')) {
    s = s.replace(/&/g, '&amp;');
  }
  if (s.includes('<')) {
    s = s.replace(/</g, '&lt;');
  }
  if (s.includes('>')) {
    s = s.replace(/>/g, '&gt;');
  }
  // Scrub dangerous URI schemes in `[label](javascript:...)` before non-destructively escaping Markdown punctuation
  if (s.includes('](')) {
    s = s.replace(/\]\(\s*(?:javascript|vbscript|data|file|blob):[^)]*\)/gi, '](#)');
  }
  // Escape Markdown inline syntax (`[`, `]`, `(`, `)`, `*`, `_`, `~`, `` ` ``, `#`) non-destructively
  if (s.includes('[') || s.includes(']')) {
    s = s
      .replace(/\]\s*\(/g, '\\] \\(')
      .replace(/\]\s*\[/g, '\\] \\[')
      .replace(/\]\s*:/g, '\\]:')
      .replace(/(?<!\\)\[/g, '\\[')
      .replace(/(?<!\\)\]/g, '\\]');
  }
  if (s.includes('*')) {
    s = s.replace(/(?<!\\)\*/g, '\\*');
  }
  if (s.includes('_')) {
    s = s.replace(/(?<!\\)_/g, '\\_');
  }
  if (s.includes('~')) {
    s = s.replace(/(?<!\\)~/g, '\\~');
  }
  if (s.includes('`')) {
    s = s.replace(/(?<!\\)`/g, '\\`');
  }
  if (s.includes('#')) {
    s = s.replace(/(?<!\\)#/g, '\\#');
  }
  return s;
}

/**
 * Sanitizes commerce timestamps (`publishedAt`, `updatedAt`) by stripping control/line-break characters and
 * escaping HTML/Markdown-unsafe characters (`&`, `<`, `>`, `[`, `]`, `(`, `)`, `*`, `_`, `#`, `` ` ``, `|`).
 */
export function sanitizeCommerceTimestamp(raw: unknown, maxLen = 96): string | null {
  if (typeof raw !== 'string') return null;
  let s = raw
    .replace(/\u001b\[[0-9;?]*[ -/]*[@-~]/g, '')
    .replace(
      /[\u0000-\u001F\u007F-\u009F\u00AD\u061C\u180E\u200B-\u200F\u2028-\u202E\u2060-\u206F\uFEFF\u{E0000}-\u{E01EF}]+/gu,
      ' ',
    )
    .replace(/\s{2,}/g, ' ')
    .trim();
  if (!s) return null;
  if (s.length > maxLen) s = s.slice(0, maxLen).trim();
  s = s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/\[/g, '\\[')
    .replace(/\]/g, '\\]')
    .replace(/\(/g, '\\(')
    .replace(/\)/g, '\\)')
    .replace(/\*/g, '\\*')
    .replace(/_/g, '\\_')
    .replace(/#/g, '\\#')
    .replace(/`/g, '\\`')
    .replace(/\|/g, '&#124;');
  return s || null;
}

function sanitizeCommerceSku(raw: unknown): string | null {
  if (typeof raw !== 'string') return null;
  const clean = sanitizeCommerceField(raw, 160);
  return clean || null;
}

function formatCommerceSkuDisplay(sku: string | null | undefined, escapePipesForProse = false): string {
  if (!sku) return '`-`';
  const prepared = escapePipesForProse ? sku.replace(/(?<!\\)\|/g, '\\|') : sku;
  if (!prepared.includes('\\') && !prepared.includes('&') && !prepared.includes('|')) {
    return `\`${prepared}\``;
  }
  return prepared;
}

function readHeaderCaseInsensitive(
  headers: Record<string, string | undefined> | Headers | undefined,
  target: string,
): string {
  if (!headers) return '';
  if (typeof (headers as Headers).get === 'function') {
    return ((headers as Headers).get(target) ?? '').trim();
  }
  const lower = target.toLowerCase();
  for (const [k, v] of Object.entries(headers as Record<string, string | undefined>)) {
    if (k.toLowerCase() === lower && typeof v === 'string') return v.trim();
  }
  return '';
}

export function isShopifyHtmlOrHeaders(
  rawHtml: string,
  headers?: Record<string, string | undefined> | Headers,
): boolean {
  if (headers) {
    if (
      readHeaderCaseInsensitive(headers, 'x-shopid') ||
      readHeaderCaseInsensitive(headers, 'x-shopify-stage') ||
      readHeaderCaseInsensitive(headers, 'x-sorting-hat-shopid')
    ) {
      return true;
    }
    const poweredBy =
      readHeaderCaseInsensitive(headers, 'powered-by') || readHeaderCaseInsensitive(headers, 'x-powered-by');
    if (poweredBy && /\bshopify\b/i.test(poweredBy)) {
      return true;
    }
  }
  if (!rawHtml) return false;
  const headSlice = rawHtml.slice(0, 120_000);
  return (
    /[a-z0-9-]\.myshopify\.com\b/i.test(headSlice) ||
    headSlice.includes('cdn.shopify.com') ||
    /Shopify\.shop\s*=/.test(headSlice) ||
    headSlice.includes('shopify-digital-wallet') ||
    headSlice.includes('ShopifyAnalytics') ||
    headSlice.includes('shopify-section')
  );
}

export function extractShopifyCurrencyFromHtml(rawHtml: string): string | null {
  if (!rawHtml) return null;
  const slice = rawHtml.slice(0, 120_000);
  const activeMatch = /Shopify\.currency\s*=\s*\{[^}]{0,240}?"active"\s*:\s*"([A-Z]{3})"/.exec(slice);
  if (activeMatch?.[1]) return activeMatch[1].toUpperCase();

  const metaCur =
    extractMetaContent(slice, 'og:price:currency') || extractMetaContent(slice, 'product:price:currency');
  if (/^[A-Z]{3}$/i.test(metaCur)) return metaCur.toUpperCase();

  const ldCur = /"priceCurrency"\s*:\s*"([A-Z]{3})"/i.exec(slice);
  if (ldCur?.[1]) return ldCur[1].toUpperCase();
  return null;
}

export function resolveCustomDomainShopifyProductTwinUrl(
  productUrl: string,
): { jsonUrl: string; jsUrl: string; handle: string } | null {
  let u: URL;
  try {
    u = new URL(productUrl);
  } catch {
    return null;
  }
  if (u.protocol !== 'https:' || u.username || u.password) return null;
  const parts = u.pathname.split('/').filter(Boolean);
  const prodIdx = parts.indexOf('products');
  if (prodIdx < 0 || !parts[prodIdx + 1]) return null;
  const rawSeg = safeDecodeURIComponent(parts[prodIdx + 1]!);
  if (rawSeg === null) return null;
  const handle = rawSeg.replace(/\.(?:json|js)$/i, '');
  if (!/^[A-Za-z0-9_-]{1,160}$/.test(handle)) return null;
  const encoded = encodeURIComponent(handle);
  return {
    jsonUrl: `${u.origin}/products/${encoded}.json`,
    jsUrl: `${u.origin}/products/${encoded}.js`,
    handle,
  };
}

/**
 * Validates and normalizes a commerce image/asset URL to a strictly public `http(s)://` URL:
 * rejects non-http(s) schemes, credentials (`user:pass@`), non-default ports (other than 80/443),
 * `localhost`, `.local`, `.internal`, and all IPv4/IPv6/decimal/octal/hex IP literals (`isSafePublicHostname`).
 */
export function normalizePublicCommerceImageUrl(raw: unknown): string | null {
  if (typeof raw !== 'string') return null;
  const s = raw.trim();
  if (!s || s.length > 2048 || /[\u0000-\u0020\u007F-\u009F\\]/.test(s)) return null;
  let candidate = s;
  if (s.startsWith('//')) {
    if (s.startsWith('///')) return null;
    candidate = `https:${s}`;
  } else if (!/^https:\/\//i.test(s)) {
    return null;
  }
  let u: URL;
  try {
    u = new URL(candidate);
  } catch {
    return null;
  }
  if (u.protocol !== 'https:') return null;
  if (u.username || u.password) return null;
  if (u.port !== '' && u.port !== '443') return null;
  if (!isSafePublicHostname(u.hostname)) return null;
  return u.toString();
}

function normalizeImageHttps(raw: unknown): string | null {
  return normalizePublicCommerceImageUrl(raw);
}

function stripNonPublicMarkdownImages(md: string): string {
  if (!md || !md.includes('![')) return md;
  return md.replace(/!\[([^\]]*)\]\(([^)\r\n]+)\)/g, (full, _alt: string, destPart: string) => {
    const trimmed = destPart.trim();
    const rawDest = trimmed.startsWith('<')
      ? trimmed.slice(1, trimmed.indexOf('>') > 0 ? trimmed.indexOf('>') : trimmed.length).trim()
      : (trimmed.split(/\s+/)[0] ?? '');
    return normalizePublicCommerceImageUrl(rawDest) ? full : '';
  });
}

function parseShopifyMoney(raw: unknown, isAjaxJs: boolean): number | null {
  if (raw === null || raw === undefined || raw === '') return null;
  if (typeof raw === 'number') {
    if (!Number.isFinite(raw) || raw < 0) return null;
    return isAjaxJs ? Math.round(raw) / 100 : raw;
  }
  if (typeof raw === 'string') {
    const trimmed = raw.trim();
    if (!trimmed) return null;
    if (isAjaxJs && /^\d+$/.test(trimmed)) {
      const cents = Number(trimmed);
      return Number.isFinite(cents) ? Math.round(cents) / 100 : null;
    }
    const n = parseFloat(trimmed.replace(/,/g, ''));
    return Number.isFinite(n) && n >= 0 ? n : null;
  }
  return null;
}

function cleanVariantTitle(rawTitle: unknown): string | null {
  if (typeof rawTitle !== 'string') return null;
  const cleaned = sanitizeCommerceField(rawTitle, 240);
  if (!cleaned || /^default(?:\s+title)?$/i.test(cleaned)) return null;
  return cleaned;
}

export function normalizeShopifyProductRecord(
  rawProd: Record<string, unknown>,
  originStr: string,
  opts?: {
    currency?: string | null;
    fields?: 'full' | 'lean';
    isAjaxJs?: boolean;
    ajaxVariantsById?: Map<string, Record<string, unknown>>;
    maxImages?: number;
    maxVariants?: number;
  },
): CatalogRecord | null {
  const title = typeof rawProd.title === 'string' ? sanitizeCommerceField(rawProd.title, 400) : '';
  if (!title) return null;

  const maxImages = Math.min(250, Math.max(1, opts?.maxImages ?? DEFAULT_MAX_IMAGES_PER_PRODUCT));
  const maxVariants = Math.min(250, Math.max(1, opts?.maxVariants ?? DEFAULT_MAX_VARIANTS_PER_PRODUCT));

  let cleanOrigin = originStr;
  try {
    cleanOrigin = new URL(originStr).origin;
  } catch {
    cleanOrigin = originStr.replace(/\/+$/, '');
  }

  const isAjaxJs =
    opts?.isAjaxJs ??
    (typeof rawProd.price === 'number' ||
      (Array.isArray(rawProd.variants) &&
        rawProd.variants.length > 0 &&
        typeof (rawProd.variants[0] as Record<string, unknown>)?.price === 'number'));

  const productId = String(rawProd.id ?? '');
  const handle = typeof rawProd.handle === 'string' ? rawProd.handle.trim() : '';
  const url = handle ? `${cleanOrigin}/products/${encodeURIComponent(handle)}` : cleanOrigin;
  const cleanVendor = typeof rawProd.vendor === 'string' ? sanitizeCommerceField(rawProd.vendor, 200) : '';
  const vendor = cleanVendor || null;
  const rawType =
    typeof rawProd.product_type === 'string'
      ? rawProd.product_type
      : typeof rawProd.type === 'string'
        ? rawProd.type
        : '';
  const cleanProductType = sanitizeCommerceField(rawType, 200);
  const productType = cleanProductType || null;

  const tags: string[] = Array.isArray(rawProd.tags)
    ? rawProd.tags.map((t) => sanitizeCommerceField(String(t ?? ''), 120)).filter(Boolean)
    : typeof rawProd.tags === 'string'
      ? rawProd.tags
          .split(',')
          .map((t) => sanitizeCommerceField(t, 120))
          .filter(Boolean)
      : [];

  const rawImages = Array.isArray(rawProd.images) ? rawProd.images : [];
  const imageById = new Map<string, string>();
  const imageByVariantId = new Map<string, string>();
  const allImageUrls: string[] = [];
  const seenImageUrls = new Set<string>();

  for (const img of rawImages) {
    if (typeof img === 'string') {
      const u = normalizeImageHttps(img);
      if (u && !seenImageUrls.has(u) && allImageUrls.length < maxImages) {
        seenImageUrls.add(u);
        allImageUrls.push(u);
      }
    } else if (img && typeof img === 'object') {
      const io = img as Record<string, unknown>;
      const u = normalizeImageHttps(io.src ?? io.url);
      if (!u) continue;
      if (!seenImageUrls.has(u) && allImageUrls.length < maxImages) {
        seenImageUrls.add(u);
        allImageUrls.push(u);
      }
      if (io.id !== undefined && io.id !== null && imageById.size < maxImages * 4) {
        imageById.set(String(io.id), u);
      }
      if (Array.isArray(io.variant_ids)) {
        for (const vid of io.variant_ids) {
          if (vid !== undefined && vid !== null && imageByVariantId.size < maxVariants * 4) {
            imageByVariantId.set(String(vid), u);
          }
        }
      }
    }
    if (allImageUrls.length >= maxImages && imageById.size >= maxImages * 4) {
      break;
    }
  }

  const options: Array<{ name: string; values: string[] }> = [];
  if (Array.isArray(rawProd.options)) {
    for (const opt of rawProd.options) {
      if (typeof opt === 'string') {
        const cleanOpt = sanitizeCommerceField(opt, 120);
        if (cleanOpt && !/^title$/i.test(cleanOpt)) {
          options.push({ name: cleanOpt, values: [] });
        }
      } else if (opt && typeof opt === 'object') {
        const oo = opt as Record<string, unknown>;
        const oName = typeof oo.name === 'string' ? sanitizeCommerceField(oo.name, 120) : '';
        const vals = Array.isArray(oo.values)
          ? oo.values
              .map((v) => sanitizeCommerceField(String(v ?? ''), 120))
              .filter((v) => Boolean(v) && !/^default title$/i.test(v))
          : [];
        if (oName && !(oName.toLowerCase() === 'title' && vals.length === 0)) {
          options.push({ name: oName, values: vals });
        }
      }
    }
  }

  const currency = opts?.currency && /^[A-Z]{3}$/i.test(opts.currency) ? opts.currency.toUpperCase() : null;

  const rawVariants = Array.isArray(rawProd.variants)
    ? (rawProd.variants as Array<Record<string, unknown>>).slice(0, maxVariants)
    : [];
  const variants: CatalogVariantRecord[] = rawVariants.map((rv) => {
    const variantId = String(rv.id ?? '');
    const ajaxV = variantId && opts?.ajaxVariantsById ? opts.ajaxVariantsById.get(variantId) : undefined;
    const merged = ajaxV ? { ...ajaxV, ...rv, available: rv.available ?? ajaxV.available } : rv;

    const sku = sanitizeCommerceSku(merged.sku);
    const barcode = sanitizeCommerceSku(merged.barcode);
    const vTitle = cleanVariantTitle(merged.title);

    const optValues = Array.isArray(merged.options)
      ? merged.options
          .map((o) => sanitizeCommerceField(String(o ?? ''), 120))
          .filter((o) => Boolean(o) && !/^default title$/i.test(o))
      : [merged.option1, merged.option2, merged.option3]
          .map((o) => (typeof o === 'string' ? sanitizeCommerceField(o, 120) : ''))
          .filter((o) => Boolean(o) && !/^default title$/i.test(o));

    const price = parseShopifyMoney(merged.price, isAjaxJs);
    const rawCompare = parseShopifyMoney(merged.compare_at_price, isAjaxJs);
    const compareAt = rawCompare !== null && rawCompare > 0 ? rawCompare : null;

    const available =
      typeof merged.available === 'boolean'
        ? merged.available
        : typeof ajaxV?.available === 'boolean'
          ? (ajaxV.available as boolean)
          : null;

    const rawPolicy = merged.inventory_policy ?? ajaxV?.inventory_policy;
    const inventoryPolicy: 'deny' | 'continue' | null =
      rawPolicy === 'continue' ? 'continue' : rawPolicy === 'deny' ? 'deny' : null;

    const rawQty = merged.inventory_quantity ?? ajaxV?.inventory_quantity;
    const inventoryQuantity = typeof rawQty === 'number' && Number.isFinite(rawQty) ? Math.trunc(rawQty) : null;

    const grams = typeof merged.grams === 'number' && Number.isFinite(merged.grams) ? Math.round(merged.grams) : null;

    const featImg = merged.featured_image;
    const directImg =
      typeof featImg === 'string'
        ? normalizeImageHttps(featImg)
        : featImg && typeof featImg === 'object'
          ? normalizeImageHttps((featImg as Record<string, unknown>).src ?? (featImg as Record<string, unknown>).url)
          : null;
    const image =
      directImg ??
      (merged.image_id !== undefined && merged.image_id !== null ? imageById.get(String(merged.image_id)) ?? null : null) ??
      (variantId ? imageByVariantId.get(variantId) ?? null : null);

    return {
      variantId,
      sku,
      ...(barcode !== null ? { barcode } : {}),
      title: vTitle,
      options: optValues,
      price,
      compareAt,
      currency,
      available,
      ...(inventoryPolicy !== null ? { inventoryPolicy } : {}),
      ...(inventoryQuantity !== null ? { inventoryQuantity } : {}),
      grams,
      image,
    };
  });

  const bodyHtml =
    typeof rawProd.body_html === 'string'
      ? rawProd.body_html
      : typeof rawProd.description === 'string'
        ? rawProd.description
        : '';
  const descriptionText = stripTagsInline(bodyHtml);
  const publishedAt = sanitizeCommerceTimestamp(rawProd.published_at);
  const updatedAt = sanitizeCommerceTimestamp(rawProd.updated_at);
  const lean = opts?.fields === 'lean';

  return {
    platform: 'shopify',
    origin: cleanOrigin,
    productId,
    handle,
    url,
    title,
    vendor,
    productType,
    tags,
    ...(!lean ? { descriptionText } : {}),
    publishedAt,
    updatedAt,
    ...(!lean ? { images: allImageUrls } : {}),
    options,
    variants,
  };
}

function formatMoneyDisplay(amount: number | null, currency: string | null): string {
  if (amount === null || !Number.isFinite(amount)) return '-';
  const fixed = Number.isInteger(amount) ? `${amount}.00` : amount.toFixed(2);
  if (!currency || currency === 'USD') return `$${fixed}`;
  return `${currency} ${fixed}`;
}

function formatVariantAvailability(v: CatalogVariantRecord): string {
  if (v.available === false) return 'Out of Stock';
  if (v.available === true) {
    if (
      v.inventoryPolicy === 'continue' &&
      v.inventoryQuantity !== undefined &&
      v.inventoryQuantity !== null &&
      v.inventoryQuantity <= 0
    ) {
      return 'Backorder / Preorder';
    }
    return 'Available';
  }
  return '-';
}

const defaultPlainConverter: HtmlFragmentConverter = (frag) => ({
  markdown: stripTagsInline(frag),
  links: [],
});

export function enrichShopifyProductFromJson(params: {
  rawJson: string;
  productUrl: string;
  htmlToMd?: HtmlFragmentConverter;
  currency?: string | null;
  isAjaxJs?: boolean;
  ajaxJsBody?: string;
}): TwinFormattedDoc | null {
  const data = parseJsonObject(params.rawJson);
  if (!data) return null;
  const prod =
    data.product && typeof data.product === 'object' && !Array.isArray(data.product)
      ? (data.product as Record<string, unknown>)
      : data;
  if (typeof prod.title !== 'string' || !prod.title.trim()) return null;

  let ajaxVariantsById: Map<string, Record<string, unknown>> | undefined;
  if (params.ajaxJsBody) {
    const ajaxObj = parseJsonObject(params.ajaxJsBody);
    if (ajaxObj && Array.isArray(ajaxObj.variants)) {
      ajaxVariantsById = new Map();
      for (const av of ajaxObj.variants as Array<Record<string, unknown>>) {
        if (av && av.id !== undefined) ajaxVariantsById.set(String(av.id), av);
      }
    }
  }

  const record = normalizeShopifyProductRecord(prod, params.productUrl, {
    currency: params.currency,
    isAjaxJs: params.isAjaxJs,
    ajaxVariantsById,
  });
  if (!record) return null;

  const htmlToMd = params.htmlToMd ?? defaultPlainConverter;
  const bodyHtml =
    typeof prod.body_html === 'string'
      ? prod.body_html
      : typeof prod.description === 'string'
        ? prod.description
        : '';
  const rawBodyMd = bodyHtml ? htmlToMd(bodyHtml, params.productUrl).markdown.trim() : '';
  const bodyMd = stripNonPublicMarkdownImages(rawBodyMd).trim();

  const rows = record.variants.slice(0, 60).map((v) => [
    v.title ?? record.title,
    v.sku ? formatCommerceSkuDisplay(v.sku) : '`-`',
    formatMoneyDisplay(v.price, v.currency),
    v.compareAt !== null ? formatMoneyDisplay(v.compareAt, v.currency) : '-',
    formatVariantAvailability(v),
  ]);

  const activeCur = record.variants[0]?.currency ?? params.currency ?? null;
  const bullets: string[] = [];
  if (record.vendor) bullets.push(`- **Brand / Vendor**: ${record.vendor}`);
  if (record.productType) bullets.push(`- **Product Type**: ${record.productType}`);
  if (record.tags.length > 0) bullets.push(`- **Tags**: ${record.tags.join(', ')}`);
  if (activeCur) bullets.push(`- **Currency**: ${activeCur}`);

  const sections = [`# ${record.title}`];
  if (bullets.length > 0) sections.push(bullets.join('\n'));
  if (rows.length > 0) {
    sections.push(
      `## Variants & Pricing\n\n${formatGfmTable(['Variant', 'SKU', 'Price', 'Compare At', 'Availability'], rows)}`,
    );
  }
  if (bodyMd) sections.push(`## Product Details\n\n${bodyMd}`);

  return {
    title: record.title,
    ...(record.descriptionText ? { description: record.descriptionText.slice(0, 260) } : {}),
    ...(record.vendor ? { author: record.vendor } : {}),
    ...(record.publishedAt ? { publishedTime: record.publishedAt } : {}),
    markdown: sections.join('\n\n'),
    links: [record.url],
    records: [record as unknown as Record<string, unknown>],
  };
}

export function formatShopifyProductsFeedTwin(rawBody: string, origUrl: string): TwinFormattedDoc | null {
  const data = parseJsonObject(rawBody);
  if (!data || !Array.isArray(data.products)) return null;

  let u: URL;
  try {
    u = new URL(origUrl);
  } catch {
    return null;
  }

  const page = Math.max(1, parseInt(u.searchParams.get('page') ?? '1', 10) || 1);
  const rawLimit = parseInt(u.searchParams.get('limit') ?? '', 10);
  const limit = Number.isFinite(rawLimit) && rawLimit > 0 ? Math.min(250, rawLimit) : 30;

  const rawProducts = data.products as Array<Record<string, unknown>>;
  const records: CatalogRecord[] = [];
  for (const rp of rawProducts) {
    if (rp && typeof rp === 'object') {
      const norm = normalizeShopifyProductRecord(rp, u.origin);
      if (norm) records.push(norm);
    }
  }

  const returned = records.length;
  const hasMore = returned > 0 && returned >= limit;
  let nextUrl: string | undefined;
  if (hasMore) {
    const nextU = new URL(u.toString());
    nextU.searchParams.set('page', String(page + 1));
    if (!nextU.searchParams.has('limit')) nextU.searchParams.set('limit', String(limit));
    nextUrl = nextU.toString();
  }

  const colMatch = /^\/collections\/([^/]+)\/products\.json$/i.exec(u.pathname);
  const decodedCol = colMatch?.[1] ? safeDecodeURIComponent(colMatch[1]) : null;
  const scopeLabel = decodedCol ? `${u.hostname} (${decodedCol})` : u.hostname;
  const totalVariants = records.reduce((acc, r) => acc + r.variants.length, 0);
  const title = `${scopeLabel} — Shopify Catalog Inventory (Page ${page}, ${returned} products)`;

  const summaryBullets = [
    `- **Store Origin**: ${u.origin}`,
    `- **Page**: ${page} (${returned} products, ${totalVariants} variants)`,
    `- **Has More Pages**: ${hasMore ? `Yes ([Page ${page + 1}](${nextUrl}))` : 'No'}`,
  ];

  const links: string[] = [];
  const rows = records.slice(0, 120).map((r) => {
    links.push(r.url);
    const prices = r.variants.map((v) => v.price).filter((p): p is number => p !== null);
    const minP = prices.length > 0 ? Math.min(...prices) : null;
    const maxP = prices.length > 0 ? Math.max(...prices) : null;
    const priceCell =
      minP === null
        ? '-'
        : minP === maxP
          ? formatMoneyDisplay(minP, r.variants[0]?.currency ?? null)
          : `${formatMoneyDisplay(minP, null)}–${formatMoneyDisplay(maxP, null)}`;
    const availCount = r.variants.filter((v) => v.available === true).length;
    const anyKnownAvail = r.variants.some((v) => v.available !== null);
    const availCell = anyKnownAvail ? `${availCount}/${r.variants.length} in stock` : `${r.variants.length} variants`;
    const updatedDisplay = r.updatedAt
      ? (/^\d{4}-\d{2}-\d{2}/.exec(r.updatedAt)?.[0] ?? r.updatedAt)
      : '-';
    return [
      `[${r.title}](${r.url})`,
      r.vendor ?? '-',
      r.productType || '-',
      String(r.variants.length),
      priceCell,
      availCell,
      updatedDisplay,
    ];
  });

  const tableSection =
    rows.length > 0
      ? formatGfmTable(['Product', 'Vendor', 'Type', 'Variants', 'Price', 'Stock', 'Updated'], rows)
      : 'No products returned on this page.';

  return {
    title,
    markdown: [`# ${title}`, summaryBullets.join('\n'), tableSection].join('\n\n'),
    links,
    records: records as unknown as Array<Record<string, unknown>>,
    pagination: {
      page,
      returned,
      limit,
      hasMore,
      ...(nextUrl ? { nextUrl } : {}),
    },
  };
}

function extractEmbeddedShopifyProductJson(rawHtml: string): string | null {
  const scriptOpens = findAllOpenTagsLinear(
    rawHtml,
    'script',
    (attr) => {
      const t = (getAttrValueLinear(attr, 'type') ?? '').toLowerCase();
      if (t && t !== 'application/json' && t !== 'text/json') return false;
      const id = getAttrValueLinear(attr, 'id') ?? '';
      return (
        attr.toLowerCase().includes('data-product-json') ||
        attr.toLowerCase().includes('data-product') ||
        /^productjson\b/i.test(id)
      );
    },
    12,
  );
  for (const sc of scriptOpens) {
    const closeIdx = rawHtml.toLowerCase().indexOf('</script>', sc.openEnd);
    if (closeIdx === -1) break;
    const candidate = rawHtml.slice(sc.openEnd, closeIdx).trim();
    const parsed = parseJsonObject(candidate);
    if (
      parsed &&
      (typeof parsed.title === 'string' ||
        (parsed.product && typeof (parsed.product as Record<string, unknown>).title === 'string'))
    ) {
      return candidate;
    }
  }

  const metaMarker = rawHtml.indexOf('var meta = {');
  if (metaMarker !== -1 && metaMarker < 200_000) {
    const startBrace = rawHtml.indexOf('{', metaMarker);
    const endScript = rawHtml.indexOf('</script>', startBrace);
    if (startBrace !== -1 && endScript !== -1 && endScript - startBrace < 200_000) {
      const block = rawHtml.slice(startBrace, endScript);
      const semiIdx = block.indexOf('};');
      if (semiIdx !== -1) {
        const jsonCandidate = block.slice(0, semiIdx + 1);
        const parsed = parseJsonObject(jsonCandidate);
        if (parsed?.product && typeof (parsed.product as Record<string, unknown>).id !== 'undefined') {
          const p = parsed.product as Record<string, unknown>;
          if (Array.isArray(p.variants) && p.variants.length > 0) {
            const firstV = p.variants[0] as Record<string, unknown>;
            const inferredTitle =
              typeof p.title === 'string'
                ? p.title
                : typeof firstV?.name === 'string'
                  ? firstV.name.split(' - ')[0]!.trim()
                  : '';
            if (inferredTitle) {
              return JSON.stringify({ ...p, title: inferredTitle });
            }
          }
        }
      }
    }
  }
  return null;
}

export function extractShopifyProductHtml(ctx: HtmlExtractContext, extractorId = 'shopify'): PostFetchSiteResult | null {
  const { url, path, rawHtml, htmlToMd } = ctx;
  if (!/\/products\/[^/]+/i.test(path)) return null;
  if (!isShopifyHtmlOrHeaders(rawHtml)) return null;

  const currency = extractShopifyCurrencyFromHtml(rawHtml);
  const embeddedJson = extractEmbeddedShopifyProductJson(rawHtml);
  if (embeddedJson) {
    const fromEmbedded = enrichShopifyProductFromJson({
      rawJson: embeddedJson,
      productUrl: url.toString(),
      htmlToMd,
      currency,
    });
    if (fromEmbedded) {
      return {
        extractorId,
        title: fromEmbedded.title,
        ...(fromEmbedded.description ? { description: fromEmbedded.description } : {}),
        ...(fromEmbedded.author ? { author: fromEmbedded.author } : {}),
        ...(fromEmbedded.publishedTime ? { publishedTime: fromEmbedded.publishedTime } : {}),
        markdown: fromEmbedded.markdown,
        links: fromEmbedded.links,
        records: fromEmbedded.records,
      };
    }
  }

  const ldObjects = extractJsonLdObjects(rawHtml);
  const prodLd = ldObjects.find((o) => /Product|ProductGroup/i.test(String(o['@type'] ?? '')));
  if (!prodLd || typeof prodLd.name !== 'string') return null;

  const title = sanitizeCommerceField(prodLd.name, 400);
  if (!title) return null;
  const brandObj = prodLd.brand as Record<string, unknown> | string | undefined;
  const brand =
    typeof brandObj === 'string'
      ? sanitizeCommerceField(brandObj, 200)
      : typeof brandObj?.name === 'string'
        ? sanitizeCommerceField(brandObj.name, 200)
        : '';
  const desc = typeof prodLd.description === 'string' ? sanitizeCommerceField(stripTagsInline(prodLd.description), 1200) : '';
  const rawOffers = prodLd.hasVariant ?? prodLd.offers;
  const offersList = Array.isArray(rawOffers)
    ? (rawOffers as Array<Record<string, unknown>>)
    : rawOffers && typeof rawOffers === 'object'
      ? [rawOffers as Record<string, unknown>]
      : [];

  const parts = path.split('/').filter(Boolean);
  const pIdx = parts.indexOf('products');
  const handle = pIdx >= 0 && parts[pIdx + 1] ? (safeDecodeURIComponent(parts[pIdx + 1]!) ?? '') : '';

  const variants: CatalogVariantRecord[] = [];
  const rows: Array<Array<string>> = [];
  for (let i = 0; i < Math.min(offersList.length, 60); i++) {
    const off = offersList[i]!;
    const subOffer =
      Array.isArray(off.offers) && off.offers[0] && typeof off.offers[0] === 'object'
        ? (off.offers[0] as Record<string, unknown>)
        : ((off.offers as Record<string, unknown> | undefined) ?? off);
    const rawVName = typeof off.name === 'string' ? off.name.trim() : '';
    const vTitle = rawVName && sanitizeCommerceField(rawVName, 240) !== title ? cleanVariantTitle(rawVName) : null;
    const skuRaw = off.sku ?? subOffer.sku;
    const sku = sanitizeCommerceSku(skuRaw);
    const barcodeRaw = off.gtin13 ?? off.gtin12 ?? off.gtin ?? subOffer.gtin13 ?? subOffer.gtin12;
    const barcode = sanitizeCommerceSku(barcodeRaw);
    const rawPrice = subOffer.price ?? subOffer.lowPrice;
    const priceNum =
      typeof rawPrice === 'number'
        ? rawPrice
        : typeof rawPrice === 'string'
          ? parseFloat(rawPrice.replace(/,/g, ''))
          : NaN;
    const price = Number.isFinite(priceNum) ? priceNum : null;
    const curRaw = typeof subOffer.priceCurrency === 'string' ? subOffer.priceCurrency.trim().toUpperCase() : '';
    const vCur = /^[A-Z]{3}$/.test(curRaw) ? curRaw : currency;
    const availRaw = String(subOffer.availability ?? '');
    const available = /InStock|PreOrder|BackOrder|OnlineOnly/i.test(availRaw)
      ? true
      : /OutOfStock|SoldOut|Discontinued/i.test(availRaw)
        ? false
        : null;
    const inventoryPolicy: 'continue' | 'deny' | null = /PreOrder|BackOrder/i.test(availRaw) ? 'continue' : null;
    const imgRaw = Array.isArray(off.image) ? off.image[0] : off.image;
    const image = normalizeImageHttps(
      typeof imgRaw === 'string' ? imgRaw : (imgRaw as Record<string, unknown> | undefined)?.url,
    );

    variants.push({
      variantId: String(off['@id'] ?? sku ?? i + 1),
      sku,
      ...(barcode ? { barcode } : {}),
      title: vTitle,
      options: vTitle ? [vTitle] : [],
      price,
      compareAt: null,
      currency: vCur,
      available,
      ...(inventoryPolicy ? { inventoryPolicy } : {}),
      grams: null,
      image,
    });

    const statusText =
      available === true
        ? inventoryPolicy === 'continue'
          ? 'Backorder / Preorder'
          : 'In Stock'
        : available === false
          ? 'Out of Stock'
          : availRaw.split('/').pop() || '-';
    rows.push([
      vTitle ?? title,
      sku ? formatCommerceSkuDisplay(sku) : '-',
      price !== null ? `${vCur ?? 'USD'} ${price.toFixed(2)}` : '-',
      statusText,
    ]);
  }

  const publishedAt = sanitizeCommerceTimestamp(prodLd.releaseDate ?? prodLd.datePublished);
  const updatedAt = sanitizeCommerceTimestamp(prodLd.dateModified);

  const record: CatalogRecord = {
    platform: 'shopify',
    origin: url.origin,
    productId: String(prodLd.productID ?? prodLd.sku ?? handle),
    handle,
    url: url.toString(),
    title,
    vendor: brand || null,
    productType: typeof prodLd.category === 'string' ? sanitizeCommerceField(prodLd.category, 200) || null : null,
    tags: [],
    descriptionText: desc,
    publishedAt,
    updatedAt,
    images: [],
    options: [],
    variants,
  };

  const bullets: string[] = [];
  if (brand) bullets.push(`- **Brand**: ${brand}`);
  const cleanTopSku = sanitizeCommerceSku(prodLd.sku);
  if (cleanTopSku) bullets.push(`- **SKU**: ${formatCommerceSkuDisplay(cleanTopSku, true)}`);

  const sections = [`# ${title}`];
  if (bullets.length > 0) sections.push(bullets.join('\n'));
  if (rows.length > 0) {
    sections.push(`## Pricing & Availability\n\n${formatGfmTable(['Variant', 'SKU', 'Price', 'Status'], rows)}`);
  }
  if (desc) sections.push(`## Description\n\n${desc}`);

  return {
    extractorId,
    title,
    ...(desc ? { description: desc.slice(0, 260) } : {}),
    ...(brand ? { author: brand } : {}),
    markdown: sections.join('\n\n'),
    records: [record as unknown as Record<string, unknown>],
  };
}

export function isWooCommerceHtmlOrHeaders(
  rawHtml: string,
  headers?: Record<string, string | undefined> | Headers,
): boolean {
  if (headers) {
    const linkHdr = readHeaderCaseInsensitive(headers, 'link');
    if (linkHdr.includes('/wp-json/wc/')) return true;
  }
  if (!rawHtml) return false;
  const slice = rawHtml.slice(0, 100_000);
  return (
    slice.includes('woocommerce-page') ||
    slice.includes('wc-block-grid') ||
    slice.includes('/plugins/woocommerce/') ||
    slice.includes('WooCommerce') ||
    slice.includes('wc_add_to_cart_params') ||
    slice.includes('/wp-json/wc/store/')
  );
}

export function resolveCustomDomainWooCommerceProductTwinUrl(
  productUrl: string,
): { slug: string; storeApiUrl: string } | null {
  let u: URL;
  try {
    u = new URL(productUrl);
  } catch {
    return null;
  }
  if (u.protocol !== 'https:' || u.username || u.password) return null;
  const m = /^(?:\/[a-z]{2}(?:-[a-z]{2})?)?\/product\/([a-z0-9._~%-]+)\/?$/i.exec(u.pathname);
  if (!m?.[1]) return null;
  const decoded = safeDecodeURIComponent(m[1]);
  const slug = (decoded ?? m[1]).trim();
  if (!slug || slug.length > 160 || slug.includes('/')) return null;
  return {
    slug,
    storeApiUrl: `${u.origin}/wp-json/wc/store/v1/products?slug=${encodeURIComponent(slug)}`,
  };
}

function scaleMinorUnitPrice(raw: unknown, minorUnit: number): number | null {
  if (raw === null || raw === undefined || raw === '') return null;
  const n = typeof raw === 'number' ? raw : typeof raw === 'string' ? Number(raw.trim()) : NaN;
  if (!Number.isFinite(n) || n < 0) return null;
  const factor = 10 ** Math.max(0, Math.min(8, minorUnit));
  return Math.round(n) / factor;
}

export function normalizeWooCommerceProductRecord(
  rawProd: Record<string, unknown>,
  originStr: string,
  opts?: { fields?: 'full' | 'lean'; maxImages?: number; maxVariants?: number },
): CatalogRecord | null {
  const title = sanitizeCommerceField(String(rawProd.name ?? rawProd.title ?? ''), 400);
  if (!title) return null;

  const maxImages = Math.min(250, Math.max(1, opts?.maxImages ?? DEFAULT_MAX_IMAGES_PER_PRODUCT));
  const maxVariants = Math.min(250, Math.max(1, opts?.maxVariants ?? DEFAULT_MAX_VARIANTS_PER_PRODUCT));

  let cleanOrigin = originStr;
  try {
    cleanOrigin = new URL(originStr).origin;
  } catch {
    cleanOrigin = originStr.replace(/\/+$/, '');
  }

  const productId = String(rawProd.id ?? '');
  const handle = typeof rawProd.slug === 'string' && rawProd.slug.trim() ? rawProd.slug.trim() : productId;
  const safePermalink = normalizePublicCommerceImageUrl(rawProd.permalink);
  const url = safePermalink ?? `${cleanOrigin}/product/${encodeURIComponent(handle)}/`;

  const prices = (rawProd.prices as Record<string, unknown> | undefined) ?? {};
  const minorUnit =
    typeof prices.currency_minor_unit === 'number' &&
    Number.isInteger(prices.currency_minor_unit) &&
    prices.currency_minor_unit >= 0 &&
    prices.currency_minor_unit <= 8
      ? prices.currency_minor_unit
      : 2;
  const curRaw = typeof prices.currency_code === 'string' ? prices.currency_code.trim().toUpperCase() : '';
  const currency = /^[A-Z]{3}$/.test(curRaw) ? curRaw : null;

  const basePrice = scaleMinorUnitPrice(prices.price ?? prices.sale_price, minorUnit);
  const regPrice = scaleMinorUnitPrice(prices.regular_price, minorUnit);
  const compareAt = regPrice !== null && basePrice !== null && regPrice > basePrice ? regPrice : null;

  const brands = Array.isArray(rawProd.brands) ? (rawProd.brands as Array<Record<string, unknown>>) : [];
  const vendor =
    brands[0] && typeof brands[0].name === 'string' && brands[0].name.trim()
      ? sanitizeCommerceField(brands[0].name, 200) || null
      : null;

  const categories = Array.isArray(rawProd.categories) ? (rawProd.categories as Array<Record<string, unknown>>) : [];
  const productType =
    categories[0] && typeof categories[0].name === 'string'
      ? sanitizeCommerceField(categories[0].name, 200) || null
      : typeof rawProd.type === 'string'
        ? sanitizeCommerceField(rawProd.type, 200) || null
        : null;

  const tags = Array.isArray(rawProd.tags)
    ? (rawProd.tags as Array<Record<string, unknown>>)
        .slice(0, 100)
        .map((t) => sanitizeCommerceField(String(t?.name ?? ''), 120))
        .filter(Boolean)
    : [];

  const images: string[] = [];
  if (Array.isArray(rawProd.images)) {
    const seenImg = new Set<string>();
    for (const img of rawProd.images as Array<Record<string, unknown>>) {
      const src = normalizePublicCommerceImageUrl(img?.src ?? img?.url);
      if (src && !seenImg.has(src)) {
        seenImg.add(src);
        images.push(src);
        if (images.length >= maxImages) break;
      }
    }
  }

  const options: Array<{ name: string; values: string[] }> = [];
  if (Array.isArray(rawProd.attributes)) {
    for (const attr of (rawProd.attributes as Array<Record<string, unknown>>).slice(0, 50)) {
      const aName = sanitizeCommerceField(String(attr?.name ?? ''), 120);
      const terms = Array.isArray(attr?.terms)
        ? (attr.terms as Array<Record<string, unknown>>)
            .slice(0, 100)
            .map((t) => sanitizeCommerceField(String(t?.name ?? ''), 120))
            .filter(Boolean)
        : [];
      if (aName) options.push({ name: aName, values: terms });
    }
  }

  const topSku = sanitizeCommerceSku(rawProd.sku);
  const topAvailable = typeof rawProd.is_in_stock === 'boolean' ? rawProd.is_in_stock : null;
  const rawVariations = Array.isArray(rawProd.variations)
    ? (rawProd.variations as Array<Record<string, unknown>>).slice(0, maxVariants)
    : [];

  const variants: CatalogVariantRecord[] =
    rawVariations.length > 0
      ? rawVariations.map((vr) => {
          const vId = String(vr.id ?? '');
          const vAttrs = Array.isArray(vr.attributes)
            ? (vr.attributes as Array<Record<string, unknown>>)
                .map((a) => sanitizeCommerceField(String(a?.value ?? ''), 120))
                .filter(Boolean)
            : [];
          return {
            variantId: vId,
            sku: sanitizeCommerceSku(vr.sku) ?? topSku,
            title: vAttrs.length > 0 ? vAttrs.join(' / ') : null,
            options: vAttrs,
            price: basePrice,
            compareAt,
            currency,
            available: typeof vr.is_in_stock === 'boolean' ? vr.is_in_stock : topAvailable,
            grams: null,
            image: images[0] ?? null,
          };
        })
      : [
          {
            variantId: productId,
            sku: topSku,
            title: null,
            options: [],
            price: basePrice,
            compareAt,
            currency,
            available: topAvailable,
            grams: null,
            image: images[0] ?? null,
          },
        ];

  const descHtml = String(rawProd.description || rawProd.short_description || '');
  const descriptionText = stripTagsInline(descHtml);
  const publishedAt = sanitizeCommerceTimestamp(rawProd.date_created_gmt ?? rawProd.date_created ?? rawProd.published_at);
  const updatedAt = sanitizeCommerceTimestamp(rawProd.date_modified_gmt ?? rawProd.date_modified ?? rawProd.updated_at);
  const lean = opts?.fields === 'lean';

  return {
    platform: 'woocommerce',
    origin: cleanOrigin,
    productId,
    handle,
    url,
    title,
    vendor,
    productType,
    tags,
    ...(!lean ? { descriptionText } : {}),
    publishedAt,
    updatedAt,
    ...(!lean ? { images } : {}),
    options,
    variants,
  };
}

export function enrichWooCommerceProductFromStoreApi(params: {
  rawJson: string;
  productUrl: string;
  slug: string;
  htmlToMd: HtmlFragmentConverter;
  fallbackBodyMd?: string;
}): TwinFormattedDoc | null {
  const parsed = parseJsonValue(params.rawJson);
  const candidates = Array.isArray(parsed)
    ? (parsed as Array<Record<string, unknown>>)
    : parsed && typeof parsed === 'object'
      ? [parsed as Record<string, unknown>]
      : [];
  if (candidates.length === 0) return null;

  const targetSlugLower = params.slug.toLowerCase();
  const matched =
    candidates.find((c) => typeof c?.slug === 'string' && c.slug.trim().toLowerCase() === targetSlugLower) ??
    (candidates.length === 1 ? candidates[0] : undefined);
  if (!matched || typeof matched !== 'object') return null;

  const rec = normalizeWooCommerceProductRecord(matched, params.productUrl);
  if (!rec) return null;

  const descHtml = typeof matched.description === 'string' ? matched.description : '';
  const apiBodyMd = descHtml ? stripNonPublicMarkdownImages(params.htmlToMd(descHtml, params.productUrl).markdown).trim() : '';
  const cleanedFallbackMd = stripNonPublicMarkdownImages((params.fallbackBodyMd ?? '').replace(/^#\s+[^\n]+\n+/, '')).trim();
  const bodyMd = apiBodyMd.length >= 80 ? apiBodyMd : cleanedFallbackMd || apiBodyMd;

  const metaLines: string[] = [];
  if (rec.vendor) metaLines.push(`- **Brand / Vendor**: ${rec.vendor}`);
  if (rec.productType) metaLines.push(`- **Category**: ${rec.productType}`);
  if (rec.tags.length > 0) metaLines.push(`- **Tags**: ${rec.tags.join(', ')}`);

  const rows = rec.variants.map((v) => [
    v.title ?? rec.title,
    v.sku ? formatCommerceSkuDisplay(v.sku) : '`-`',
    v.price !== null ? `${v.currency ?? 'USD'} ${v.price.toFixed(2)}` : '-',
    v.compareAt !== null ? `${v.currency ?? 'USD'} ${v.compareAt.toFixed(2)}` : '-',
    v.available === true ? 'In Stock' : v.available === false ? 'Out of Stock' : '-',
  ]);

  return {
    title: rec.title,
    ...(rec.descriptionText ? { description: rec.descriptionText.slice(0, 260) } : {}),
    ...(rec.vendor ? { author: rec.vendor } : {}),
    ...(rec.publishedAt ? { publishedTime: rec.publishedAt } : {}),
    markdown: [
      `# ${rec.title}`,
      metaLines.length > 0 ? metaLines.join('\n') : '',
      `## Variants & Pricing\n\n${formatGfmTable(['Variant', 'SKU', 'Price', 'Compare At', 'Stock'], rows)}`,
      bodyMd ? `## Product Details\n\n${bodyMd}` : '',
    ]
      .filter(Boolean)
      .join('\n\n'),
    links: [rec.url],
    records: [rec as unknown as Record<string, unknown>],
  };
}

export function formatWcStoreApiListTwin(rawBody: string, origUrl: string): TwinFormattedDoc | null {
  const parsed = parseJsonValue(rawBody);
  if (!Array.isArray(parsed)) return null;
  let u: URL;
  try {
    u = new URL(origUrl);
  } catch {
    return null;
  }
  const page = Math.max(1, parseInt(u.searchParams.get('page') ?? '1', 10) || 1);
  const perPage = Math.max(1, parseInt(u.searchParams.get('per_page') ?? '100', 10) || 100);

  const records: CatalogRecord[] = [];
  for (const item of parsed as Array<Record<string, unknown>>) {
    if (item && typeof item === 'object' && !Array.isArray(item)) {
      const norm = normalizeWooCommerceProductRecord(item, u.origin);
      if (norm) records.push(norm);
    }
  }

  const returned = records.length;
  const hasMore = returned >= perPage;
  let nextUrl: string | undefined;
  if (hasMore) {
    const nextU = new URL(u.toString());
    nextU.searchParams.set('page', String(page + 1));
    nextUrl = nextU.toString();
  }

  const title = `${u.hostname} — WooCommerce Catalog (Page ${page}, ${returned} products)`;
  const links: string[] = [];
  const rows = records.slice(0, 120).map((r) => {
    links.push(r.url);
    const v0 = r.variants[0];
    const priceStr =
      v0?.price !== null && v0?.price !== undefined ? `${v0.currency ?? 'USD'} ${v0.price.toFixed(2)}` : '-';
    const stockStr = v0?.available === true ? 'In Stock' : v0?.available === false ? 'Out of Stock' : '-';
    return [
      `[${r.title}](${r.url})`,
      v0?.sku ? formatCommerceSkuDisplay(v0.sku) : '`-`',
      r.productType || '-',
      priceStr,
      stockStr,
    ];
  });

  const tableMd =
    rows.length > 0
      ? formatGfmTable(['Product', 'SKU', 'Category', 'Price', 'Stock'], rows)
      : 'No products returned on this page.';

  return {
    title,
    markdown: `# ${title}\n\n${tableMd}`,
    links,
    records: records as unknown as Array<Record<string, unknown>>,
    pagination: {
      page,
      returned,
      limit: perPage,
      hasMore,
      ...(nextUrl ? { nextUrl } : {}),
    },
  };
}

export function formatWcStoreApiProductTwin(
  rawBody: string,
  origUrl: string,
  htmlToMd: HtmlFragmentConverter,
): TwinFormattedDoc | null {
  const obj = parseJsonObject(rawBody);
  if (!obj) return null;
  const rec = normalizeWooCommerceProductRecord(obj, origUrl);
  if (!rec) return null;
  const descHtml = typeof obj.description === 'string' ? obj.description : '';
  const bodyMd = descHtml ? stripNonPublicMarkdownImages(htmlToMd(descHtml, origUrl).markdown).trim() : '';
  const rows = rec.variants.map((v) => [
    v.title ?? rec.title,
    v.sku ? formatCommerceSkuDisplay(v.sku) : '`-`',
    v.price !== null ? `${v.currency ?? 'USD'} ${v.price.toFixed(2)}` : '-',
    v.available === true ? 'In Stock' : v.available === false ? 'Out of Stock' : '-',
  ]);
  return {
    title: rec.title,
    ...(rec.descriptionText ? { description: rec.descriptionText.slice(0, 260) } : {}),
    ...(rec.vendor ? { author: rec.vendor } : {}),
    ...(rec.publishedAt ? { publishedTime: rec.publishedAt } : {}),
    markdown: [
      `# ${rec.title}`,
      formatGfmTable(['Variant', 'SKU', 'Price', 'Stock'], rows),
      bodyMd ? `## Description\n\n${bodyMd}` : '',
    ]
      .filter(Boolean)
      .join('\n\n'),
    links: [rec.url],
    records: [rec as unknown as Record<string, unknown>],
  };
}

export function extractWooCommerceProductHtml(
  ctx: HtmlExtractContext,
  extractorId = 'woocommerce',
): PostFetchSiteResult | null {
  const { url, rawHtml } = ctx;
  if (!isWooCommerceHtmlOrHeaders(rawHtml)) return null;
  const bodyOpen = findOpenTagLinear(rawHtml, 'body');
  const isSingleProduct =
    (bodyOpen ? attrHasTokenLinear(bodyOpen.attrStr, 'class', 'single-product') : false) ||
    /\/product\/[^/]+/i.test(url.pathname);
  if (!isSingleProduct) return null;

  const ldObjects = extractJsonLdObjects(rawHtml);
  const prodLd = ldObjects.find((o) => /Product/i.test(String(o['@type'] ?? '')));
  const clean = stripScriptsAndStyles(rawHtml);

  const rawTitle =
    typeof prodLd?.name === 'string' && prodLd.name.trim()
      ? prodLd.name.trim()
      : stripTagsInline(findElementInnerLinear(clean, 'h1', (a) => attrHasTokenLinear(a, 'class', 'product_title')) ?? '');
  const title = sanitizeCommerceField(rawTitle, 400);
  if (!title) return null;

  const rawSku =
    typeof prodLd?.sku === 'string' && prodLd.sku.trim()
      ? prodLd.sku.trim()
      : stripTagsInline(findElementInnerLinear(clean, 'span', (a) => attrHasTokenLinear(a, 'class', 'sku')) ?? '');
  const sku = sanitizeCommerceSku(rawSku) ?? '';

  const rawOffers = prodLd?.offers;
  const offer = Array.isArray(rawOffers)
    ? (rawOffers[0] as Record<string, unknown> | undefined)
    : (rawOffers as Record<string, unknown> | undefined);
  const priceNum =
    typeof offer?.price === 'number'
      ? offer.price
      : typeof offer?.price === 'string'
        ? parseFloat(offer.price)
        : NaN;
  const price = Number.isFinite(priceNum) ? priceNum : null;
  const curRaw = typeof offer?.priceCurrency === 'string' ? offer.priceCurrency.trim().toUpperCase() : '';
  const currency = /^[A-Z]{3}$/.test(curRaw) ? curRaw : null;
  const availRaw = String(offer?.availability ?? '');
  const available = /InStock/i.test(availRaw) ? true : /OutOfStock/i.test(availRaw) ? false : null;
  const desc = typeof prodLd?.description === 'string' ? sanitizeCommerceField(stripTagsInline(prodLd.description), 1200) : '';

  if (price === null && !sku && !desc) return null;

  const ldImgRaw = Array.isArray(prodLd?.image) ? prodLd.image[0] : prodLd?.image;
  const safeImg = normalizePublicCommerceImageUrl(
    typeof ldImgRaw === 'string' ? ldImgRaw : (ldImgRaw as Record<string, unknown> | undefined)?.url,
  );
  const publishedAt = sanitizeCommerceTimestamp(prodLd?.releaseDate ?? prodLd?.datePublished);
  const updatedAt = sanitizeCommerceTimestamp(prodLd?.dateModified);

  const parts = url.pathname.split('/').filter(Boolean);
  const handle = parts[parts.length - 1] ?? title.toLowerCase().replace(/[^a-z0-9]+/g, '-');
  const record: CatalogRecord = {
    platform: 'woocommerce',
    origin: url.origin,
    productId: sku || handle,
    handle,
    url: url.toString(),
    title,
    vendor: null,
    productType: null,
    tags: [],
    descriptionText: desc,
    publishedAt,
    updatedAt,
    images: safeImg ? [safeImg] : [],
    options: [],
    variants: [
      {
        variantId: sku || handle,
        sku: sku || null,
        title: null,
        options: [],
        price,
        compareAt: null,
        currency,
        available,
        grams: null,
        image: safeImg,
      },
    ],
  };

  const bullets: string[] = [];
  if (sku) bullets.push(`- **SKU**: ${formatCommerceSkuDisplay(sku, true)}`);
  if (price !== null) bullets.push(`- **Price**: ${currency ?? 'USD'} ${price.toFixed(2)}`);
  if (available !== null) bullets.push(`- **Availability**: ${available ? 'In Stock' : 'Out of Stock'}`);

  return {
    extractorId,
    title,
    ...(desc ? { description: desc.slice(0, 260) } : {}),
    markdown: [`# ${title}`, bullets.join('\n'), desc ? `## Description\n\n${desc}` : ''].filter(Boolean).join('\n\n'),
    links: [url.toString()],
    records: [record as unknown as Record<string, unknown>],
  };
}

function readHeaderNumber(headers: Record<string, string> | undefined, key: string): number | null {
  if (!headers) return null;
  const lower = key.toLowerCase();
  for (const [k, v] of Object.entries(headers)) {
    if (k.toLowerCase() === lower) {
      const n = parseInt(v, 10);
      return Number.isFinite(n) && n >= 0 ? n : null;
    }
  }
  return null;
}

export const VALID_CATALOG_PLATFORMS: ReadonlySet<string> = new Set(['shopify', 'woocommerce']);

export function buildDeclarativeCatalogSpec(cfg: DeclarativeCatalogConfig): CatalogSpec {
  const rawPlatform = typeof cfg?.platform === 'string' ? cfg.platform.trim().toLowerCase() : '';
  if (!VALID_CATALOG_PLATFORMS.has(rawPlatform)) {
    throw new Error(
      `Unsupported declarative catalog platform "${String((cfg as { platform?: unknown })?.platform)}" (expected "shopify" or "woocommerce")`,
    );
  }
  const pauseMs = Math.max(250, cfg.pauseMs || 2000);
  const pageCap = Math.max(1, Math.min(1000, cfg.pageCap || 200));
  const maxImages = Math.min(250, Math.max(1, cfg.maxImagesPerProduct ?? DEFAULT_MAX_IMAGES_PER_PRODUCT));
  const maxVariants = Math.min(250, Math.max(1, cfg.maxVariantsPerProduct ?? DEFAULT_MAX_VARIANTS_PER_PRODUCT));

  if (rawPlatform === 'shopify') {
    const perPage = Math.min(250, Math.max(1, cfg.perPage ?? 250));
    const firstTpl = cfg.firstPageTemplate || `{origin}/products.json?limit=${perPage}&page=1`;
    const colTpl =
      cfg.collectionPageTemplate || `{origin}/collections/{collection}/products.json?limit=${perPage}&page=1`;
    return {
      platform: 'shopify',
      pauseMs,
      pageCap,
      firstPage(origin: URL, opts?: { collection?: string }): string {
        const pathColMatch = /^\/collections\/([A-Za-z0-9_-]+)/i.exec(origin.pathname);
        const col = opts?.collection?.trim() || pathColMatch?.[1] || '';
        if (col && /^[A-Za-z0-9_-]{1,160}$/.test(col)) {
          return colTpl
            .replace('{origin}', origin.origin)
            .replace('{collection}', encodeURIComponent(col));
        }
        return firstTpl.replace('{origin}', origin.origin);
      },
      parsePage(body: string, origin: URL, opts?: { fields?: 'full' | 'lean' }) {
        const parsed = parseJsonObject(body);
        if (!parsed || !Array.isArray(parsed.products)) {
          throw new Error('non_json_or_invalid_shopify_catalog');
        }
        const rawProducts = parsed.products as Array<Record<string, unknown>>;
        const records: CatalogRecord[] = [];
        for (const rp of rawProducts) {
          if (rp && typeof rp === 'object') {
            const norm = normalizeShopifyProductRecord(rp, origin.origin, {
              fields: opts?.fields,
              maxImages,
              maxVariants,
            });
            if (norm) records.push(norm);
          }
        }
        return {
          records,
          done: rawProducts.length === 0,
        };
      },
      nextPage(prev: { url: string; body: string; pageIndex: number }): string | null {
        const parsed = parseJsonObject(prev.body);
        if (!parsed || !Array.isArray(parsed.products) || parsed.products.length === 0) {
          return null;
        }
        try {
          const u = new URL(prev.url);
          const curPage = Math.max(1, parseInt(u.searchParams.get('page') ?? String(prev.pageIndex + 1), 10) || 1);
          u.searchParams.set('page', String(curPage + 1));
          if (!u.searchParams.has('limit')) u.searchParams.set('limit', String(perPage));
          return u.toString();
        } catch {
          return null;
        }
      },
    };
  }

  // WooCommerce Store API v1
  const perPage = Math.min(100, Math.max(1, cfg.perPage ?? 100));
  const firstTpl = cfg.firstPageTemplate || `{origin}/wp-json/wc/store/v1/products?per_page=${perPage}&page=1`;
  return {
    platform: 'woocommerce',
    pauseMs,
    pageCap,
    firstPage(origin: URL, opts?: { collection?: string }): string {
      const col = opts?.collection?.trim() ?? '';
      const catParam = col ? `&category=${encodeURIComponent(col)}` : '';
      return `${firstTpl.replace('{origin}', origin.origin)}${catParam}`;
    },
    parsePage(body: string, origin: URL, opts?: { fields?: 'full' | 'lean'; headers?: Record<string, string> }) {
      const parsed = parseJsonValue(body);
      if (!Array.isArray(parsed)) {
        throw new Error('non_json_or_invalid_woocommerce_catalog');
      }
      const items = parsed as Array<Record<string, unknown>>;
      const records: CatalogRecord[] = [];
      for (const item of items) {
        if (item && typeof item === 'object' && !Array.isArray(item)) {
          const norm = normalizeWooCommerceProductRecord(item, origin.origin, {
            fields: opts?.fields,
            maxImages,
            maxVariants,
          });
          if (norm) records.push(norm);
        }
      }
      const totalPages = readHeaderNumber(opts?.headers, 'x-wp-totalpages');
      const done = items.length === 0 || items.length < perPage || (totalPages !== null && totalPages <= 1);
      return { records, done };
    },
    nextPage(prev: { url: string; body: string; pageIndex: number; headers?: Record<string, string> }): string | null {
      const parsed = parseJsonValue(prev.body);
      if (!Array.isArray(parsed) || parsed.length === 0) return null;
      try {
        const u = new URL(prev.url);
        const pp = Math.max(1, parseInt(u.searchParams.get('per_page') ?? String(perPage), 10) || perPage);
        const curPage = Math.max(1, parseInt(u.searchParams.get('page') ?? String(prev.pageIndex + 1), 10) || 1);
        if (parsed.length < pp) return null;
        const totalPages = readHeaderNumber(prev.headers, 'x-wp-totalpages');
        if (totalPages !== null && curPage >= totalPages) return null;
        u.searchParams.set('page', String(curPage + 1));
        return u.toString();
      } catch {
        return null;
      }
    },
  };
}
