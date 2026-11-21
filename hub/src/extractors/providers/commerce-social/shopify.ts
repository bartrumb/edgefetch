import {
  defineAdapter,
  findAllOpenTagsLinear,
  getAttrValueLinear,
  type CatalogRecord,
  type CatalogSpec,
  type CatalogVariantRecord,
  type HtmlFragmentConverter,
  type TwinFormattedDoc,
} from '../../types';
import {
  extractJsonLdObjects,
  extractMetaContent,
  formatGfmTable,
  parseJsonObject,
  stripTagsInline,
} from '../../utils';

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

/**
 * Detects whether a storefront response (custom domain or `*.myshopify.com`) runs on Shopify using
 * response headers (`x-shopid`, `x-shopify-stage`, `powered-by: Shopify`) and HTML asset/runtime markers.
 */
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

/**
 * Extracts explicit active ISO-4217 currency code from Shopify HTML when present (`Shopify.currency.active` or `<meta>`).
 * Returns `null` when absent — never guesses `'USD'`!
 */
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

/**
 * Resolves declarative `.json` and `.js` product twin URLs for any custom-domain Shopify product path
 * (`/products/<handle>` or `/collections/<collection>/products/<handle>`).
 */
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
  const rawSeg = decodeURIComponent(parts[prodIdx + 1]!);
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

/**
 * Normalizes a raw Shopify product object (from `/products.json`, `/products/<h>.json`, or `/products/<h>.js`)
 * into EdgeFetch's neutral open-source `CatalogRecord` schema.
 */
export function normalizeShopifyProductRecord(
  rawProd: Record<string, unknown>,
  originStr: string,
  opts?: {
    currency?: string | null;
    fields?: 'full' | 'lean';
    isAjaxJs?: boolean;
    ajaxVariantsById?: Map<string, Record<string, unknown>>;
  },
): CatalogRecord | null {
  const title = typeof rawProd.title === 'string' ? rawProd.title.replace(/\s+/g, ' ').trim() : '';
  if (!title) return null;

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
  const rawType = typeof rawProd.product_type === 'string' ? rawProd.product_type : typeof rawProd.type === 'string' ? rawProd.type : '';
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

  for (const img of rawImages) {
    if (typeof img === 'string') {
      const u = normalizeImageHttps(img);
      if (u && !allImageUrls.includes(u)) allImageUrls.push(u);
    } else if (img && typeof img === 'object') {
      const io = img as Record<string, unknown>;
      const u = normalizeImageHttps(io.src ?? io.url);
      if (!u) continue;
      if (!allImageUrls.includes(u)) allImageUrls.push(u);
      if (io.id !== undefined && io.id !== null) {
        imageById.set(String(io.id), u);
      }
      if (Array.isArray(io.variant_ids)) {
        for (const vid of io.variant_ids) {
          if (vid !== undefined && vid !== null) {
            imageByVariantId.set(String(vid), u);
          }
        }
      }
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

  const currency =
    opts?.currency && /^[A-Z]{3}$/i.test(opts.currency) ? opts.currency.toUpperCase() : null;

  const rawVariants = Array.isArray(rawProd.variants) ? (rawProd.variants as Array<Record<string, unknown>>) : [];
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
    const inventoryQuantity =
      typeof rawQty === 'number' && Number.isFinite(rawQty) ? Math.trunc(rawQty) : null;

    const grams =
      typeof merged.grams === 'number' && Number.isFinite(merged.grams) ? Math.round(merged.grams) : null;

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

/**
 * Formats a Shopify product JSON payload (`/products/<handle>.json` or `/products/<handle>.js` or embedded JSON)
 * into a rich GFM document + normalized `records: [CatalogRecord]`.
 */
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

function formatShopifyProductsFeedTwin(rawBody: string, origUrl: string): TwinFormattedDoc | null {
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
  const scopeLabel = colMatch?.[1] ? `${u.hostname} (${decodeURIComponent(colMatch[1])})` : u.hostname;
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
  // 1. `<script type="application/json" data-product-json>` or `id="ProductJson-..."`
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
    if (parsed && (typeof parsed.title === 'string' || (parsed.product && typeof (parsed.product as Record<string, unknown>).title === 'string'))) {
      return candidate;
    }
  }

  // 2. `var meta = {"product":{...}};` emitted by ShopifyAnalytics
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
            const inferredTitle = typeof p.title === 'string' ? p.title : typeof firstV?.name === 'string' ? firstV.name.split(' - ')[0]!.trim() : '';
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

export const shopifyCatalogSpec: CatalogSpec = {
  platform: 'shopify',
  pauseMs: 2000,
  pageCap: 200,
  firstPage(origin: URL, opts?: { collection?: string }): string {
    const pathColMatch = /^\/collections\/([A-Za-z0-9_-]+)/i.exec(origin.pathname);
    const col = opts?.collection?.trim() || pathColMatch?.[1] || '';
    if (col && /^[A-Za-z0-9_-]{1,160}$/.test(col)) {
      return `${origin.origin}/collections/${encodeURIComponent(col)}/products.json?limit=250&page=1`;
    }
    return `${origin.origin}/products.json?limit=250&page=1`;
  },
  parsePage(body: string, origin: URL, opts?: { fields?: 'full' | 'lean' }): { records: CatalogRecord[]; done: boolean } {
    const parsed = parseJsonObject(body);
    if (!parsed || !Array.isArray(parsed.products)) {
      throw new Error('non_json_or_invalid_shopify_catalog');
    }
    const rawProducts = parsed.products as Array<Record<string, unknown>>;
    const records: CatalogRecord[] = [];
    for (const rp of rawProducts) {
      if (rp && typeof rp === 'object') {
        const norm = normalizeShopifyProductRecord(rp, origin.origin, { fields: opts?.fields });
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
      if (!u.searchParams.has('limit')) u.searchParams.set('limit', '250');
      return u.toString();
    } catch {
      return null;
    }
  },
};

export default defineAdapter({
  id: 'shopify',
  name: 'Shopify Universal Storefront & Catalogs',
  category: 'commerce-social',
  description:
    'Formats /products.json and /collections/<h>/products.json store inventories, upgrades *.myshopify.com and custom-domain /products/<handle> pages, and implements polite full-store catalog pulls.',
  domains: ['*.myshopify.com'],
  universalEngine: true,
  exampleUrls: [
    'https://allbirds.myshopify.com/products/mens-tree-runners',
    'https://allbirds.myshopify.com/products.json?limit=30&page=1',
  ],
  catalog: shopifyCatalogSpec,
  resolveTwin({ urlStr, host, path, parts }) {
    // 1. Storefront `/products.json` or `/collections/<handle>/products.json` on ANY domain
    if (
      /^\/products\.json$/i.test(path) ||
      (/^\/collections\/([A-Za-z0-9_-]{1,160})\/products\.json$/i.test(path) && parts.length === 3)
    ) {
      return {
        id: 'shopify-catalog-page',
        fetchUrl: urlStr,
        kind: 'json',
        accept: 'application/json',
        formatTwin: (rawBody, origUrl) => formatShopifyProductsFeedTwin(rawBody, origUrl),
      };
    }

    // 2. Explicit `/products/<handle>.json` or `/products/<handle>.js` on ANY domain, OR `/products/<handle>` on `*.myshopify.com`
    const isExplicitJsonOrJs = /\/products\/[A-Za-z0-9_-]{1,160}\.(?:json|js)$/i.test(path);
    if (!host.endsWith('.myshopify.com') && !isExplicitJsonOrJs) return null;

    const prodIdx = parts.indexOf('products');
    if (prodIdx < 0 || !parts[prodIdx + 1]) return null;
    const rawSeg = decodeURIComponent(parts[prodIdx + 1]!);
    const isJsEndpoint = /\.js$/i.test(rawSeg);
    const handle = rawSeg.replace(/\.(?:json|js)$/i, '');
    if (!/^[A-Za-z0-9_-]{1,160}$/.test(handle)) return null;

    const fetchUrl = isJsEndpoint
      ? `https://${host}/products/${encodeURIComponent(handle)}.js`
      : `https://${host}/products/${encodeURIComponent(handle)}.json`;

    return {
      id: 'shopify',
      fetchUrl,
      kind: 'json',
      accept: 'application/json',
      formatTwin: (rawBody, origUrl, htmlToMd) =>
        enrichShopifyProductFromJson({
          rawJson: rawBody,
          productUrl: origUrl,
          htmlToMd,
          isAjaxJs: isJsEndpoint,
        }),
    };
  },
  extractHtml({ url, path, rawHtml, htmlToMd }) {
    if (!/\/products\/[^/]+/i.test(path)) return null;
    if (!isShopifyHtmlOrHeaders(rawHtml)) return null;

    const currency = extractShopifyCurrencyFromHtml(rawHtml);

    // 1. Prefer embedded Shopify product JSON (`data-product-json` / `ProductJson` / `ShopifyAnalytics.meta`)
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
          extractorId: 'shopify',
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

    // 2. Fallback to Schema.org `Product` / `ProductGroup` JSON-LD
    const ldObjects = extractJsonLdObjects(rawHtml);
    const prodLd = ldObjects.find((o) => /Product|ProductGroup/i.test(String(o['@type'] ?? '')));
    if (!prodLd || typeof prodLd.name !== 'string') return null;

    const title = prodLd.name.trim();
    const brandObj = prodLd.brand as Record<string, unknown> | string | undefined;
    const brand = typeof brandObj === 'string' ? brandObj.trim() : typeof brandObj?.name === 'string' ? brandObj.name.trim() : '';
    const desc = typeof prodLd.description === 'string' ? stripTagsInline(prodLd.description) : '';
    const rawOffers = prodLd.hasVariant ?? prodLd.offers;
    const offersList = Array.isArray(rawOffers)
      ? (rawOffers as Array<Record<string, unknown>>)
      : rawOffers && typeof rawOffers === 'object'
        ? [rawOffers as Record<string, unknown>]
        : [];

    const parts = path.split('/').filter(Boolean);
    const pIdx = parts.indexOf('products');
    const handle = pIdx >= 0 && parts[pIdx + 1] ? decodeURIComponent(parts[pIdx + 1]!) : '';

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
      extractorId: 'shopify',
      title,
      ...(desc ? { description: desc.slice(0, 260) } : {}),
      ...(brand ? { author: brand } : {}),
      markdown: sections.join('\n\n'),
      records: [record as unknown as Record<string, unknown>],
    };
  },
});
