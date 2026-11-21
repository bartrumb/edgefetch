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

function normalizeImageHttps(raw: unknown): string | null {
  if (typeof raw !== 'string') return null;
  const s = raw.trim();
  if (!s) return null;
  if (s.startsWith('//')) return `https:${s}`;
  if (s.startsWith('https://') || s.startsWith('http://')) return s;
  return null;
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
  const cleaned = rawTitle.replace(/\s+/g, ' ').trim();
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
  const title = typeof rawProd.title === 'string' ? rawProd.title.replace(/\s+/g, ' ').trim() : '';
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
  const vendor = typeof rawProd.vendor === 'string' && rawProd.vendor.trim() ? rawProd.vendor.trim() : null;
  const rawType =
    typeof rawProd.product_type === 'string'
      ? rawProd.product_type
      : typeof rawProd.type === 'string'
        ? rawProd.type
        : '';
  const productType = rawType.trim() ? rawType.trim() : null;

  const tags: string[] = Array.isArray(rawProd.tags)
    ? rawProd.tags.map((t) => String(t ?? '').trim()).filter(Boolean)
    : typeof rawProd.tags === 'string'
      ? rawProd.tags
          .split(',')
          .map((t) => t.trim())
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
      if (typeof opt === 'string' && opt.trim() && !/^title$/i.test(opt.trim())) {
        options.push({ name: opt.trim(), values: [] });
      } else if (opt && typeof opt === 'object') {
        const oo = opt as Record<string, unknown>;
        const oName = typeof oo.name === 'string' ? oo.name.trim() : '';
        const vals = Array.isArray(oo.values)
          ? oo.values.map((v) => String(v ?? '').trim()).filter((v) => Boolean(v) && !/^default title$/i.test(v))
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

    const sku = typeof merged.sku === 'string' && merged.sku.trim() ? merged.sku.trim() : null;
    const barcode = typeof merged.barcode === 'string' && merged.barcode.trim() ? merged.barcode.trim() : null;
    const vTitle = cleanVariantTitle(merged.title);

    const optValues = Array.isArray(merged.options)
      ? merged.options.map((o) => String(o ?? '').trim()).filter((o) => Boolean(o) && !/^default title$/i.test(o))
      : [merged.option1, merged.option2, merged.option3]
          .map((o) => (typeof o === 'string' ? o.trim() : ''))
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
  const publishedAt = typeof rawProd.published_at === 'string' ? rawProd.published_at : null;
  const updatedAt = typeof rawProd.updated_at === 'string' ? rawProd.updated_at : null;
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
  const bodyMd = bodyHtml ? htmlToMd(bodyHtml, params.productUrl).markdown.trim() : '';

  const rows = record.variants.slice(0, 60).map((v) => [
    v.title ?? record.title,
    `\`${v.sku || '-'}\``,
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
    return [
      `[${r.title}](${r.url})`,
      r.vendor ?? '-',
      r.productType || '-',
      String(r.variants.length),
      priceCell,
      availCell,
      r.updatedAt ? r.updatedAt.slice(0, 10) : '-',
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

  const title = prodLd.name.trim();
  const brandObj = prodLd.brand as Record<string, unknown> | string | undefined;
  const brand =
    typeof brandObj === 'string' ? brandObj.trim() : typeof brandObj?.name === 'string' ? brandObj.name.trim() : '';
  const desc = typeof prodLd.description === 'string' ? stripTagsInline(prodLd.description) : '';
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
    const vTitle = rawVName && rawVName !== title ? cleanVariantTitle(rawVName) : null;
    const skuRaw = off.sku ?? subOffer.sku;
    const sku = typeof skuRaw === 'string' && skuRaw.trim() ? skuRaw.trim() : null;
    const barcodeRaw = off.gtin13 ?? off.gtin12 ?? off.gtin ?? subOffer.gtin13 ?? subOffer.gtin12;
    const barcode = typeof barcodeRaw === 'string' && barcodeRaw.trim() ? barcodeRaw.trim() : null;
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
      sku ? `\`${sku}\`` : '-',
      price !== null ? `${vCur ?? 'USD'} ${price.toFixed(2)}` : '-',
      statusText,
    ]);
  }

  const record: CatalogRecord = {
    platform: 'shopify',
    origin: url.origin,
    productId: String(prodLd.productID ?? prodLd.sku ?? handle),
    handle,
    url: url.toString(),
    title,
    vendor: brand || null,
    productType: typeof prodLd.category === 'string' ? prodLd.category : null,
    tags: [],
    descriptionText: desc,
    publishedAt: null,
    updatedAt: null,
    images: [],
    options: [],
    variants,
  };

  const bullets: string[] = [];
  if (brand) bullets.push(`- **Brand**: ${brand}`);
  if (typeof prodLd.sku === 'string' && prodLd.sku) bullets.push(`- **SKU**: \`${prodLd.sku}\``);

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
  const title = stripTagsInline(String(rawProd.name ?? rawProd.title ?? ''));
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
  const url =
    typeof rawProd.permalink === 'string' && rawProd.permalink.startsWith('http')
      ? rawProd.permalink
      : `${cleanOrigin}/product/${encodeURIComponent(handle)}/`;

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
    brands[0] && typeof brands[0].name === 'string' && brands[0].name.trim() ? stripTagsInline(brands[0].name) : null;

  const categories = Array.isArray(rawProd.categories) ? (rawProd.categories as Array<Record<string, unknown>>) : [];
  const productType =
    categories[0] && typeof categories[0].name === 'string'
      ? stripTagsInline(categories[0].name)
      : typeof rawProd.type === 'string'
        ? rawProd.type
        : null;

  const tags = Array.isArray(rawProd.tags)
    ? (rawProd.tags as Array<Record<string, unknown>>)
        .slice(0, 100)
        .map((t) => stripTagsInline(String(t?.name ?? '')))
        .filter(Boolean)
    : [];

  const images: string[] = [];
  if (Array.isArray(rawProd.images)) {
    const seenImg = new Set<string>();
    for (const img of rawProd.images as Array<Record<string, unknown>>) {
      const src = typeof img?.src === 'string' && img.src.startsWith('http') ? img.src : '';
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
      const aName = stripTagsInline(String(attr?.name ?? ''));
      const terms = Array.isArray(attr?.terms)
        ? (attr.terms as Array<Record<string, unknown>>)
            .slice(0, 100)
            .map((t) => stripTagsInline(String(t?.name ?? '')))
            .filter(Boolean)
        : [];
      if (aName) options.push({ name: aName, values: terms });
    }
  }

  const topSku = typeof rawProd.sku === 'string' && rawProd.sku.trim() ? rawProd.sku.trim() : null;
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
                .map((a) => String(a?.value ?? '').trim())
                .filter(Boolean)
            : [];
          return {
            variantId: vId,
            sku: typeof vr.sku === 'string' && vr.sku.trim() ? vr.sku.trim() : topSku,
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
    publishedAt: null,
    updatedAt: null,
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
  const apiBodyMd = descHtml ? params.htmlToMd(descHtml, params.productUrl).markdown.trim() : '';
  const cleanedFallbackMd = (params.fallbackBodyMd ?? '').replace(/^#\s+[^\n]+\n+/, '').trim();
  const bodyMd = apiBodyMd.length >= 80 ? apiBodyMd : cleanedFallbackMd || apiBodyMd;

  const metaLines: string[] = [];
  if (rec.vendor) metaLines.push(`- **Brand / Vendor**: ${rec.vendor}`);
  if (rec.productType) metaLines.push(`- **Category**: ${rec.productType}`);
  if (rec.tags.length > 0) metaLines.push(`- **Tags**: ${rec.tags.join(', ')}`);

  const rows = rec.variants.map((v) => [
    v.title ?? rec.title,
    `\`${v.sku || '-'}\``,
    v.price !== null ? `${v.currency ?? 'USD'} ${v.price.toFixed(2)}` : '-',
    v.compareAt !== null ? `${v.currency ?? 'USD'} ${v.compareAt.toFixed(2)}` : '-',
    v.available === true ? 'In Stock' : v.available === false ? 'Out of Stock' : '-',
  ]);

  return {
    title: rec.title,
    ...(rec.descriptionText ? { description: rec.descriptionText.slice(0, 260) } : {}),
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
    return [`[${r.title}](${r.url})`, `\`${v0?.sku || '-'}\``, r.productType || '-', priceStr, stockStr];
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
  const bodyMd = descHtml ? htmlToMd(descHtml, origUrl).markdown.trim() : '';
  const rows = rec.variants.map((v) => [
    v.title ?? rec.title,
    `\`${v.sku || '-'}\``,
    v.price !== null ? `${v.currency ?? 'USD'} ${v.price.toFixed(2)}` : '-',
    v.available === true ? 'In Stock' : v.available === false ? 'Out of Stock' : '-',
  ]);
  return {
    title: rec.title,
    ...(rec.descriptionText ? { description: rec.descriptionText.slice(0, 260) } : {}),
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

  const title =
    (typeof prodLd?.name === 'string' ? prodLd.name.trim() : '') ||
    stripTagsInline(findElementInnerLinear(clean, 'h1', (a) => attrHasTokenLinear(a, 'class', 'product_title')) ?? '');
  if (!title) return null;

  const sku =
    (typeof prodLd?.sku === 'string' && prodLd.sku.trim() ? prodLd.sku.trim() : '') ||
    stripTagsInline(findElementInnerLinear(clean, 'span', (a) => attrHasTokenLinear(a, 'class', 'sku')) ?? '');

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
  const desc = typeof prodLd?.description === 'string' ? stripTagsInline(prodLd.description) : '';

  if (price === null && !sku && !desc) return null;

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
    publishedAt: null,
    updatedAt: null,
    images: [],
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
        image: null,
      },
    ],
  };

  const bullets: string[] = [];
  if (sku) bullets.push(`- **SKU**: \`${sku}\``);
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

export function buildDeclarativeCatalogSpec(cfg: DeclarativeCatalogConfig): CatalogSpec {
  const pauseMs = Math.max(250, cfg.pauseMs || 2000);
  const pageCap = Math.max(1, Math.min(1000, cfg.pageCap || 200));
  const maxImages = Math.min(250, Math.max(1, cfg.maxImagesPerProduct ?? DEFAULT_MAX_IMAGES_PER_PRODUCT));
  const maxVariants = Math.min(250, Math.max(1, cfg.maxVariantsPerProduct ?? DEFAULT_MAX_VARIANTS_PER_PRODUCT));

  if (cfg.platform === 'shopify') {
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
