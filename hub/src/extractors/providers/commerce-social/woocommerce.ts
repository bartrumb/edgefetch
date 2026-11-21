import {
  attrHasTokenLinear,
  defineAdapter,
  findElementInnerLinear,
  findOpenTagLinear,
  type CatalogRecord,
  type CatalogSpec,
  type CatalogVariantRecord,
  type TwinFormattedDoc,
} from '../../types';
import {
  extractJsonLdObjects,
  formatGfmTable,
  parseJsonObject,
  parseJsonValue,
  stripScriptsAndStyles,
  stripTagsInline,
} from '../../utils';

export function isWooCommerceHtmlOrHeaders(
  rawHtml: string,
  headers?: Record<string, string | undefined> | Headers,
): boolean {
  if (headers) {
    const getH = (name: string): string => {
      if (typeof (headers as Headers).get === 'function') return ((headers as Headers).get(name) ?? '').trim();
      const lower = name.toLowerCase();
      for (const [k, v] of Object.entries(headers as Record<string, string | undefined>)) {
        if (k.toLowerCase() === lower && typeof v === 'string') return v.trim();
      }
      return '';
    };
    const linkHdr = getH('link');
    if (linkHdr.includes('/wp-json/wc/')) return true;
  }
  if (!rawHtml) return false;
  const slice = rawHtml.slice(0, 100_000);
  return (
    slice.includes('woocommerce-page') ||
    slice.includes('wc-block-grid') ||
    slice.includes('/plugins/woocommerce/') ||
    slice.includes('wc_add_to_cart_params') ||
    slice.includes('/wp-json/wc/store/')
  );
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
  opts?: { fields?: 'full' | 'lean' },
): CatalogRecord | null {
  const title = stripTagsInline(String(rawProd.name ?? rawProd.title ?? ''));
  if (!title) return null;

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
    brands[0] && typeof brands[0].name === 'string' && brands[0].name.trim()
      ? stripTagsInline(brands[0].name)
      : null;

  const categories = Array.isArray(rawProd.categories) ? (rawProd.categories as Array<Record<string, unknown>>) : [];
  const productType =
    categories[0] && typeof categories[0].name === 'string'
      ? stripTagsInline(categories[0].name)
      : typeof rawProd.type === 'string'
        ? rawProd.type
        : null;

  const tags = Array.isArray(rawProd.tags)
    ? (rawProd.tags as Array<Record<string, unknown>>)
        .map((t) => stripTagsInline(String(t?.name ?? '')))
        .filter(Boolean)
    : [];

  const images = Array.isArray(rawProd.images)
    ? (rawProd.images as Array<Record<string, unknown>>)
        .map((img) => (typeof img?.src === 'string' && img.src.startsWith('http') ? img.src : ''))
        .filter(Boolean)
    : [];

  const options: Array<{ name: string; values: string[] }> = [];
  if (Array.isArray(rawProd.attributes)) {
    for (const attr of rawProd.attributes as Array<Record<string, unknown>>) {
      const aName = stripTagsInline(String(attr?.name ?? ''));
      const terms = Array.isArray(attr?.terms)
        ? (attr.terms as Array<Record<string, unknown>>)
            .map((t) => stripTagsInline(String(t?.name ?? '')))
            .filter(Boolean)
        : [];
      if (aName) options.push({ name: aName, values: terms });
    }
  }

  const topSku = typeof rawProd.sku === 'string' && rawProd.sku.trim() ? rawProd.sku.trim() : null;
  const topAvailable = typeof rawProd.is_in_stock === 'boolean' ? rawProd.is_in_stock : null;
  const rawVariations = Array.isArray(rawProd.variations)
    ? (rawProd.variations as Array<Record<string, unknown>>)
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

export const woocommerceCatalogSpec: CatalogSpec = {
  platform: 'woocommerce',
  pauseMs: 2000,
  pageCap: 200,
  firstPage(origin: URL, opts?: { collection?: string }): string {
    const col = opts?.collection?.trim() ?? '';
    const catParam = col ? `&category=${encodeURIComponent(col)}` : '';
    return `${origin.origin}/wp-json/wc/store/v1/products?per_page=100&page=1${catParam}`;
  },
  parsePage(
    body: string,
    origin: URL,
    opts?: { fields?: 'full' | 'lean'; headers?: Record<string, string> },
  ): { records: CatalogRecord[]; done: boolean } {
    const parsed = parseJsonValue(body);
    if (!Array.isArray(parsed)) {
      throw new Error('non_json_or_invalid_woocommerce_catalog');
    }
    const items = parsed as Array<Record<string, unknown>>;
    const records: CatalogRecord[] = [];
    for (const item of items) {
      if (item && typeof item === 'object' && !Array.isArray(item)) {
        const norm = normalizeWooCommerceProductRecord(item, origin.origin, { fields: opts?.fields });
        if (norm) records.push(norm);
      }
    }
    const totalPages = readHeaderNumber(opts?.headers, 'x-wp-totalpages');
    const done = items.length === 0 || items.length < 100 || (totalPages !== null && totalPages <= 1);
    return { records, done };
  },
  nextPage(prev: { url: string; body: string; pageIndex: number; headers?: Record<string, string> }): string | null {
    const parsed = parseJsonValue(prev.body);
    if (!Array.isArray(parsed) || parsed.length === 0) return null;
    try {
      const u = new URL(prev.url);
      const perPage = Math.max(1, parseInt(u.searchParams.get('per_page') ?? '100', 10) || 100);
      const curPage = Math.max(1, parseInt(u.searchParams.get('page') ?? String(prev.pageIndex + 1), 10) || 1);
      if (parsed.length < perPage) return null;
      const totalPages = readHeaderNumber(prev.headers, 'x-wp-totalpages');
      if (totalPages !== null && curPage >= totalPages) return null;
      u.searchParams.set('page', String(curPage + 1));
      return u.toString();
    } catch {
      return null;
    }
  },
};

function formatWcStoreApiListTwin(rawBody: string, origUrl: string): TwinFormattedDoc | null {
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
      v0?.price !== null && v0?.price !== undefined
        ? `${v0.currency ?? 'USD'} ${v0.price.toFixed(2)}`
        : '-';
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

export default defineAdapter({
  id: 'woocommerce',
  name: 'WooCommerce Store API & Storefronts',
  category: 'commerce-social',
  description:
    'Formats public WooCommerce Store API (/wp-json/wc/store/v1/products) feeds, extracts WooCommerce product pages, and implements polite full-store catalog pulls.',
  domains: ['woocommerce.com'],
  universalEngine: true,
  exampleUrls: ['https://woocommerce.com/wp-json/wc/store/v1/products?per_page=20&page=1'],
  catalog: woocommerceCatalogSpec,
  resolveTwin({ urlStr, path }) {
    if (/^\/wp-json\/wc\/store\/v1\/products\/?$/i.test(path)) {
      return {
        id: 'woocommerce-catalog-page',
        fetchUrl: urlStr,
        kind: 'json',
        accept: 'application/json',
        formatTwin: (rawBody, origUrl) => formatWcStoreApiListTwin(rawBody, origUrl),
      };
    }
    if (/^\/wp-json\/wc\/store\/v1\/products\/\d+\/?$/i.test(path)) {
      return {
        id: 'woocommerce-product',
        fetchUrl: urlStr,
        kind: 'json',
        accept: 'application/json',
        formatTwin: (rawBody, origUrl, htmlToMd) => {
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
        },
      };
    }
    return null;
  },
  extractHtml({ url, rawHtml }) {
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
      extractorId: 'woocommerce',
      title,
      ...(desc ? { description: desc.slice(0, 260) } : {}),
      markdown: [`# ${title}`, bullets.join('\n'), desc ? `## Description\n\n${desc}` : ''].filter(Boolean).join('\n\n'),
      links: [url.toString()],
      records: [record as unknown as Record<string, unknown>],
    };
  },
});
