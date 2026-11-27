/**
 * Thin Commerce Normalization & Declarative Catalog WASM Bridge (`hub/src/extractors/commerce-engine.ts`).
 * Delegates field/timestamp sanitization, SSRF-safe image URL normalization, Shopify/WooCommerce
 * twin formatting, HTML extraction, and declarative catalog pagination to Go WASM (`internal/catalog/`).
 */
import { callCoreWasm, callCoreWasmRaw } from '../wasm-bridge';
import type {
  CatalogRecord,
  CatalogSpec,
  HtmlExtractContext,
  HtmlFragmentConverter,
  PostFetchSiteResult,
  TwinFormattedDoc,
} from './types';

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

export const VALID_CATALOG_PLATFORMS: ReadonlySet<string> = new Set(['shopify', 'woocommerce']);

type HeaderInput = Record<string, string | undefined> | Headers;

function headersToRecord(headers?: HeaderInput): Record<string, string> | undefined {
  if (!headers) return undefined;
  const out: Record<string, string> = {};
  if (typeof (headers as Headers).forEach === 'function') {
    (headers as Headers).forEach((v, k) => { out[k] = v; });
    return out;
  }
  for (const [k, v] of Object.entries(headers as Record<string, string | undefined>)) {
    if (typeof v === 'string') out[k] = v;
  }
  return out;
}

export function sanitizeCommerceField(raw: unknown, maxLen = 400): string {
  return typeof raw === 'string' ? (callCoreWasm<{ out: string }>('commerce_sanitize_field', { raw, maxLen }).out ?? '') : '';
}

export function sanitizeCommerceTimestamp(raw: unknown, maxLen = 96): string | null {
  return typeof raw === 'string' ? (callCoreWasm<{ out: string | null }>('commerce_sanitize_timestamp', { raw, maxLen }).out ?? null) : null;
}

export function normalizePublicCommerceImageUrl(raw: unknown): string | null {
  return typeof raw === 'string' ? (callCoreWasm<{ url: string | null }>('commerce_normalize_image_url', { raw }).url ?? null) : null;
}

export function isShopifyHtmlOrHeaders(rawHtml: string, headers?: HeaderInput): boolean {
  return callCoreWasmRaw<{ ok: boolean }>('commerce_is_shopify_html', { headers: headersToRecord(headers) }, String(rawHtml ?? '')).ok;
}

export function extractShopifyCurrencyFromHtml(rawHtml: string): string | null {
  return rawHtml ? (callCoreWasmRaw<{ currency: string | null }>('commerce_extract_shopify_currency', null, String(rawHtml)).currency ?? null) : null;
}

export function resolveCustomDomainShopifyProductTwinUrl(productUrl: string): { jsonUrl: string; jsUrl: string; handle: string } | null {
  return callCoreWasm<{ twin: { jsonUrl: string; jsUrl: string; handle: string } | null }>('commerce_resolve_shopify_twin', { productUrl: String(productUrl ?? '') }).twin ?? null;
}

export function resolveCustomDomainShopifyCollectionTwinUrl(pageUrl: string): { jsonUrl: string; handle: string } | null {
  return callCoreWasm<{ twin: { jsonUrl: string; handle: string } | null }>('commerce_resolve_shopify_collection_twin', { pageUrl: String(pageUrl ?? '') }).twin ?? null;
}

export function normalizeShopifyProductRecord(
  rawProd: Record<string, unknown>,
  originStr: string,
  opts?: { currency?: string | null; fields?: 'full' | 'lean'; isAjaxJs?: boolean; ajaxVariantsById?: Map<string, Record<string, unknown>>; maxImages?: number; maxVariants?: number },
): CatalogRecord | null {
  const wireOpts = opts && {
    ...(opts.currency ? { currency: opts.currency } : {}),
    ...(opts.fields ? { fields: opts.fields } : {}),
    ...(opts.isAjaxJs !== undefined ? { isAjaxJs: opts.isAjaxJs } : {}),
    ...(opts.ajaxVariantsById ? { ajaxVariantsById: Object.fromEntries(opts.ajaxVariantsById) } : {}),
    ...(opts.maxImages !== undefined ? { maxImages: opts.maxImages } : {}),
    ...(opts.maxVariants !== undefined ? { maxVariants: opts.maxVariants } : {}),
  };
  return callCoreWasm<{ record: CatalogRecord | null }>('commerce_normalize_shopify_record', { rawProd, origin: String(originStr ?? ''), opts: wireOpts }).record ?? null;
}

export function enrichShopifyProductFromJson(params: {
  rawJson: string; productUrl: string; htmlToMd?: HtmlFragmentConverter; currency?: string | null; isAjaxJs?: boolean; ajaxJsBody?: string;
}): TwinFormattedDoc | null {
  const meta = {
    productUrl: String(params.productUrl ?? ''),
    ...(params.currency ? { currency: params.currency } : {}),
    ...(params.isAjaxJs !== undefined ? { isAjaxJs: params.isAjaxJs } : {}),
    ...(params.ajaxJsBody ? { ajaxJsBody: params.ajaxJsBody } : {}),
  };
  return callCoreWasmRaw<{ doc: TwinFormattedDoc | null }>('commerce_enrich_shopify_json', meta, String(params.rawJson ?? '')).doc ?? null;
}

export function formatShopifyProductsFeedTwin(
  rawBody: string,
  origUrl: string,
  opts?: { twinUrl?: string; currency?: string | null },
): TwinFormattedDoc | null {
  const meta = {
    origUrl: String(origUrl ?? ''),
    ...(opts?.twinUrl ? { twinUrl: opts.twinUrl } : {}),
    ...(opts?.currency ? { currency: opts.currency } : {}),
  };
  return callCoreWasmRaw<{ doc: TwinFormattedDoc | null }>('commerce_format_shopify_feed', meta, String(rawBody ?? '')).doc ?? null;
}

export function extractShopifyProductHtml(ctx: HtmlExtractContext, extractorId = 'shopify'): PostFetchSiteResult | null {
  const loose = ctx as unknown as { html?: string; currentMarkdown?: string };
  const meta = {
    url: String(ctx.url),
    currentMarkdown: String(ctx.currentMd ?? loose.currentMarkdown ?? '').slice(0, 32_768),
    extractorId,
  };
  return callCoreWasmRaw<{ result: PostFetchSiteResult | null }>('commerce_extract_shopify_html', meta, String(ctx.rawHtml ?? loose.html ?? '')).result ?? null;
}

export function isWooCommerceHtmlOrHeaders(rawHtml: string, headers?: HeaderInput): boolean {
  return callCoreWasmRaw<{ ok: boolean }>('commerce_is_woocommerce_html', { headers: headersToRecord(headers) }, String(rawHtml ?? '')).ok;
}

export function resolveCustomDomainWooCommerceProductTwinUrl(productUrl: string): { slug: string; storeApiUrl: string } | null {
  return callCoreWasm<{ twin: { slug: string; storeApiUrl: string } | null }>('commerce_resolve_woocommerce_twin', { productUrl: String(productUrl ?? '') }).twin ?? null;
}

export function resolveCustomDomainWooCommerceCatalogTwinUrl(pageUrl: string): { kind: string; slug?: string; storeApiUrl: string } | null {
  return callCoreWasm<{ twin: { kind: string; slug?: string; storeApiUrl: string } | null }>('commerce_resolve_woocommerce_catalog_twin', { pageUrl: String(pageUrl ?? '') }).twin ?? null;
}

export function normalizeWooCommerceProductRecord(
  rawProd: Record<string, unknown>,
  originStr: string,
  opts?: { fields?: 'full' | 'lean'; maxImages?: number; maxVariants?: number },
): CatalogRecord | null {
  return callCoreWasm<{ record: CatalogRecord | null }>('commerce_normalize_woocommerce_record', { rawProd, origin: String(originStr ?? ''), opts }).record ?? null;
}

export function enrichWooCommerceProductFromStoreApi(params: {
  rawJson: string; productUrl: string; slug: string; htmlToMd: HtmlFragmentConverter; fallbackBodyMd?: string;
}): TwinFormattedDoc | null {
  const meta = {
    productUrl: String(params.productUrl ?? ''),
    slug: String(params.slug ?? ''),
    ...(params.fallbackBodyMd ? { fallbackBodyMd: params.fallbackBodyMd.slice(0, 32_768) } : {}),
  };
  return callCoreWasmRaw<{ doc: TwinFormattedDoc | null }>('commerce_enrich_woocommerce_json', meta, String(params.rawJson ?? '')).doc ?? null;
}

export function formatWcStoreApiListTwin(rawBody: string, origUrl: string, twinUrl?: string): TwinFormattedDoc | null {
  const meta = {
    origUrl: String(origUrl ?? ''),
    ...(twinUrl ? { twinUrl } : {}),
  };
  return callCoreWasmRaw<{ doc: TwinFormattedDoc | null }>('commerce_format_wc_list', meta, String(rawBody ?? '')).doc ?? null;
}

export function formatWcStoreApiProductTwin(rawBody: string, origUrl: string, _htmlToMd: HtmlFragmentConverter): TwinFormattedDoc | null {
  return callCoreWasmRaw<{ doc: TwinFormattedDoc | null }>('commerce_format_wc_product', { origUrl: String(origUrl ?? '') }, String(rawBody ?? '')).doc ?? null;
}

export function extractWooCommerceProductHtml(ctx: HtmlExtractContext, extractorId = 'woocommerce'): PostFetchSiteResult | null {
  const loose = ctx as unknown as { html?: string; currentMarkdown?: string };
  const meta = {
    url: String(ctx.url),
    currentMarkdown: String(ctx.currentMd ?? loose.currentMarkdown ?? '').slice(0, 32_768),
    extractorId,
  };
  return callCoreWasmRaw<{ result: PostFetchSiteResult | null }>('commerce_extract_woocommerce_html', meta, String(ctx.rawHtml ?? loose.html ?? '')).result ?? null;
}

export function extractWooCommerceCatalogHtml(ctx: HtmlExtractContext, extractorId = 'woocommerce'): PostFetchSiteResult | null {
  const loose = ctx as unknown as { html?: string; currentMarkdown?: string };
  const meta = {
    url: String(ctx.url),
    currentMarkdown: String(ctx.currentMd ?? loose.currentMarkdown ?? '').slice(0, 32_768),
    extractorId,
  };
  return callCoreWasmRaw<{ result: PostFetchSiteResult | null }>('commerce_extract_woocommerce_catalog_html', meta, String(ctx.rawHtml ?? loose.html ?? '')).result ?? null;
}

export function isSquarespaceCommerceHtmlOrHeaders(rawHtml: string, headers?: HeaderInput): boolean {
  return callCoreWasmRaw<{ ok: boolean }>('commerce_is_squarespace_html', { headers: headersToRecord(headers) }, String(rawHtml ?? '')).ok;
}

export function resolveSquarespaceCommerceTwinUrl(pageUrl: string): string | null {
  return callCoreWasm<{ twinUrl: string | null }>('commerce_resolve_squarespace_twin', { pageUrl: String(pageUrl ?? '') }).twinUrl ?? null;
}

export function formatSquarespaceCommerceJson(rawBody: string, origUrl: string): TwinFormattedDoc | null {
  return callCoreWasmRaw<{ doc: TwinFormattedDoc | null }>('commerce_format_squarespace_json', { origUrl: String(origUrl ?? '') }, String(rawBody ?? '')).doc ?? null;
}

export function extractSquarespaceCommerceHtml(ctx: HtmlExtractContext, extractorId = 'squarespace-commerce'): PostFetchSiteResult | null {
  const loose = ctx as unknown as { html?: string; currentMarkdown?: string };
  const meta = {
    url: String(ctx.url),
    currentMarkdown: String(ctx.currentMd ?? loose.currentMarkdown ?? '').slice(0, 32_768),
    extractorId,
  };
  return callCoreWasmRaw<{ result: PostFetchSiteResult | null }>('commerce_extract_squarespace_html', meta, String(ctx.rawHtml ?? loose.html ?? '')).result ?? null;
}

export function isBigCommerceHtmlOrHeaders(rawHtml: string, headers?: HeaderInput): boolean {
  return callCoreWasmRaw<{ ok: boolean }>('commerce_is_bigcommerce_html', { headers: headersToRecord(headers) }, String(rawHtml ?? '')).ok;
}

export function extractBigCommerceHtml(ctx: HtmlExtractContext, extractorId = 'bigcommerce-store'): PostFetchSiteResult | null {
  const loose = ctx as unknown as { html?: string; currentMarkdown?: string };
  const meta = {
    url: String(ctx.url),
    currentMarkdown: String(ctx.currentMd ?? loose.currentMarkdown ?? '').slice(0, 32_768),
    extractorId,
  };
  return callCoreWasmRaw<{ result: PostFetchSiteResult | null }>('commerce_extract_bigcommerce_html', meta, String(ctx.rawHtml ?? loose.html ?? '')).result ?? null;
}

export function formatBigCommerceXmlSitemap(rawBody: string, origUrl: string): TwinFormattedDoc | null {
  return callCoreWasmRaw<{ doc: TwinFormattedDoc | null }>('commerce_format_bigcommerce_sitemap', { origUrl: String(origUrl ?? '') }, String(rawBody ?? '')).doc ?? null;
}

export function isSfccDemandwareHtmlOrHeaders(rawHtml: string, headers?: HeaderInput): boolean {
  return callCoreWasmRaw<{ ok: boolean }>('commerce_is_sfcc_html', { headers: headersToRecord(headers) }, String(rawHtml ?? '')).ok;
}

export function resolveSfccProductVariationTwinUrl(pageUrl: string, rawHtml: string): { variationUrl: string; pid: string } | null {
  return callCoreWasmRaw<{ twin: { variationUrl: string; pid: string } | null }>('commerce_resolve_sfcc_twin', { pageUrl: String(pageUrl ?? '') }, String(rawHtml ?? '')).twin ?? null;
}

export function formatSfccProductVariationJson(
  rawBody: string,
  origUrl: string,
  fallbackHtml = '',
  fallbackMd = '',
): TwinFormattedDoc | null {
  const meta = {
    origUrl: String(origUrl ?? ''),
    ...(fallbackHtml ? { fallbackHtml: String(fallbackHtml).slice(0, 512_000) } : {}),
    ...(fallbackMd ? { fallbackMd: String(fallbackMd).slice(0, 32_768) } : {}),
  };
  return callCoreWasmRaw<{ doc: TwinFormattedDoc | null }>('commerce_format_sfcc_variation', meta, String(rawBody ?? '')).doc ?? null;
}

export function extractSfccProductHtml(ctx: HtmlExtractContext, extractorId = 'sfcc-demandware'): PostFetchSiteResult | null {
  const loose = ctx as unknown as { html?: string; currentMarkdown?: string };
  const meta = {
    url: String(ctx.url),
    currentMarkdown: String(ctx.currentMd ?? loose.currentMarkdown ?? '').slice(0, 32_768),
    extractorId,
  };
  return callCoreWasmRaw<{ result: PostFetchSiteResult | null }>('commerce_extract_sfcc_html', meta, String(ctx.rawHtml ?? loose.html ?? '')).result ?? null;
}

export function isMagento2HtmlOrHeaders(rawHtml: string, headers?: HeaderInput): boolean {
  return callCoreWasmRaw<{ ok: boolean }>('commerce_is_magento2_html', { headers: headersToRecord(headers) }, String(rawHtml ?? '')).ok;
}

export function isShopware6HtmlOrHeaders(rawHtml: string, headers?: HeaderInput): boolean {
  return callCoreWasmRaw<{ ok: boolean }>('commerce_is_shopware6_html', { headers: headersToRecord(headers) }, String(rawHtml ?? '')).ok;
}

export function resolveMagento2RenderInfoTwinUrl(pageUrl: string, rawHtml: string): string | null {
  return callCoreWasmRaw<{ twinUrl: string | null }>('commerce_resolve_magento2_twin', { pageUrl: String(pageUrl ?? '') }, String(rawHtml ?? '')).twinUrl ?? null;
}

export function formatMagento2RenderInfoJson(rawBody: string, origUrl: string, fallbackHtml = ''): TwinFormattedDoc | null {
  const meta = {
    origUrl: String(origUrl ?? ''),
    ...(fallbackHtml ? { fallbackHtml: String(fallbackHtml).slice(0, 512_000) } : {}),
  };
  return callCoreWasmRaw<{ doc: TwinFormattedDoc | null }>('commerce_format_magento2_render_info', meta, String(rawBody ?? '')).doc ?? null;
}

export function extractMagento2ProductHtml(ctx: HtmlExtractContext, extractorId = 'shopware-magento'): PostFetchSiteResult | null {
  const loose = ctx as unknown as { html?: string; currentMarkdown?: string };
  const meta = {
    url: String(ctx.url),
    currentMarkdown: String(ctx.currentMd ?? loose.currentMarkdown ?? '').slice(0, 32_768),
    extractorId,
  };
  return callCoreWasmRaw<{ result: PostFetchSiteResult | null }>('commerce_extract_magento2_html', meta, String(ctx.rawHtml ?? loose.html ?? '')).result ?? null;
}

export function extractShopware6ProductHtml(ctx: HtmlExtractContext, extractorId = 'shopware-magento'): PostFetchSiteResult | null {
  const loose = ctx as unknown as { html?: string; currentMarkdown?: string };
  const meta = {
    url: String(ctx.url),
    currentMarkdown: String(ctx.currentMd ?? loose.currentMarkdown ?? '').slice(0, 32_768),
    extractorId,
  };
  return callCoreWasmRaw<{ result: PostFetchSiteResult | null }>('commerce_extract_shopware6_html', meta, String(ctx.rawHtml ?? loose.html ?? '')).result ?? null;
}

export function buildDeclarativeCatalogSpec(cfg: DeclarativeCatalogConfig): CatalogSpec {
  const rawPlatform = typeof cfg?.platform === 'string' ? cfg.platform.trim().toLowerCase() : '';
  if (!VALID_CATALOG_PLATFORMS.has(rawPlatform)) {
    throw new Error(`Unsupported declarative catalog platform "${String((cfg as { platform?: unknown })?.platform)}" (expected "shopify" or "woocommerce")`);
  }
  const normalizedCfg: DeclarativeCatalogConfig = {
    ...cfg,
    platform: rawPlatform as 'shopify' | 'woocommerce',
    pauseMs: Math.max(250, cfg.pauseMs || 2000),
    pageCap: Math.max(1, Math.min(1000, cfg.pageCap || 200)),
  };
  return {
    platform: normalizedCfg.platform,
    pauseMs: normalizedCfg.pauseMs,
    pageCap: normalizedCfg.pageCap,
    firstPage(origin: URL, opts?: { collection?: string }): string {
      const res = callCoreWasm<{ ok: boolean; url?: string; error?: string }>('commerce_spec_first_page', { config: normalizedCfg, origin: origin.toString(), collection: opts?.collection ?? '' });
      if (!res.ok || !res.url) throw new Error(res.error || 'invalid_catalog_spec');
      return res.url;
    },
    parsePage(body: string, origin: URL, opts?: { fields?: 'full' | 'lean'; headers?: Record<string, string> }) {
      const res = callCoreWasmRaw<{ ok: boolean; records?: CatalogRecord[]; done?: boolean; error?: string }>('commerce_spec_parse_page', { config: normalizedCfg, origin: origin.origin, fields: opts?.fields ?? 'full', headers: opts?.headers }, String(body ?? ''));
      if (!res.ok || !res.records) throw new Error(res.error || 'non_json_or_invalid_catalog');
      return { records: res.records, done: Boolean(res.done) };
    },
    nextPage(prev: { url: string; body: string; pageIndex: number; headers?: Record<string, string> }): string | null {
      return callCoreWasmRaw<{ nextUrl: string | null }>('commerce_spec_next_page', { config: normalizedCfg, url: prev.url, pageIndex: prev.pageIndex, headers: prev.headers }, String(prev.body ?? '')).nextUrl ?? null;
    },
  };
}
