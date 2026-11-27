/**
 * Declarative YAML v2 Site Adapter Bridge (`hub/src/extractors/declarative.ts`).
 *
 * Delegates all YAML/JSON manifest parsing, M2/H7 host-claim & twin validation, URL route matching,
 * pre-fetch twin resolution/formatting, and all 10 post-fetch HTML DOM/XML/hydration modes directly to the
 * single Go implementation (`internal/extract/declarative.go` + `internal/extract/declarative_html.go`)
 * compiled into `edgefetch-core.wasm` — zero `yaml` or `htmlparser2` runtime dependencies.
 */

import compiledBundleJson from '../../../internal/extract/manifests/compiled.json';
import { callCoreWasm, callCoreWasmRaw, callCoreWasmRawMetaPair } from '../wasm-bridge';
import {
  buildDeclarativeCatalogSpec,
  enrichShopifyProductFromJson,
  formatBigCommerceXmlSitemap,
  formatMagento2RenderInfoJson,
  formatSfccProductVariationJson,
  formatShopifyProductsFeedTwin,
  formatSquarespaceCommerceJson,
  formatWcStoreApiListTwin,
  formatWcStoreApiProductTwin,
  VALID_CATALOG_PLATFORMS,
  type DeclarativeCatalogConfig,
} from './commerce-engine';
import type {
  AdapterCategory,
  HtmlExtractContext,
  HtmlFragmentConverter,
  PostFetchSiteResult,
  SiteAdapter,
  SiteExtractorTwin,
  TwinFormattedDoc,
  TwinMatchContext,
} from './types';

export type DeclarativeCharset =
  | 'alnum'
  | 'alnum_dash'
  | 'slug'
  | 'pkg'
  | 'model_slug'
  | 'doi_rest'
  | 'safe_subpath'
  | 'digits'
  | 'socrata_4x4'
  | 'cve_id'
  | 'openalex_work'
  | 'pmc_id'
  | 'nct_id'
  | 'npm_scope'
  | 'npm_pkg'
  | 'at_handle'
  | 'url_seg'
  | 'arxiv_id'
  | 'leading_digits_slug'
  | 'brew_id'
  | 'cpsc_recall_num';

export type DeclarativeParamTransform =
  | 'lower'
  | 'upper'
  | 'pad10_zero'
  | 'strip_leading_zeros'
  | 'leading_digits'
  | 'strip_dashes';

export interface DeclarativeParamSegment {
  param: string;
  charset?: DeclarativeCharset;
  allowValues?: string[];
  reserved?: string[];
  stripPrefix?: string;
  stripSuffix?: string;
  minLen?: number;
  maxLen?: number;
  greedy?: boolean;
  optional?: boolean;
  transform?: DeclarativeParamTransform;
}

export type DeclarativeSegmentSpec = string | DeclarativeParamSegment;

export interface DeclarativeQueryParamSpec {
  name?: string;
  names?: string[];
  param: string;
  charset?: DeclarativeCharset;
  minLen?: number;
  maxLen?: number;
  optional?: boolean;
  default?: string;
  transform?: DeclarativeParamTransform;
}

export interface DeclarativeHostSubdomainSpec {
  suffix: string;
  param: string;
  reserved?: string[];
  stripOptional2LetterRegion?: boolean;
}

export interface DeclarativeHostMapSpec {
  param: string;
  exact?: Record<string, string>;
  stripWww?: boolean;
  suffixSubdomain?: string;
}

export interface DeclarativeScanSegmentSpec {
  afterLiteral?: string;
  lastOrBeforeLiteral?: string;
  param: string;
  charset?: DeclarativeCharset;
  stripPrefix?: string;
  stripSuffix?: string;
  minLen?: number;
  maxLen?: number;
  transform?: DeclarativeParamTransform;
}

export interface DeclarativeSplitSegmentSpec {
  delimiter: string;
  leftParam: string;
  leftMinSegs?: number;
  afterLiteral?: string;
  rightParam?: string;
  tailParam?: string;
}

export interface DeclarativeDerivedParamSpec {
  fromParam: string;
  transform: DeclarativeParamTransform;
}

export interface DeclarativeMatchSpec {
  anyOf?: DeclarativeMatchSpec[];
  hosts?: string[];
  excludeHosts?: string[];
  socrataHost?: boolean;
  hostSubdomain?: DeclarativeHostSubdomainSpec;
  hostMap?: DeclarativeHostMapSpec;
  optionalLeadingLocale?: boolean;
  exactSegments?: boolean | number;
  minSegments?: number;
  maxSegments?: number;
  pathPrefix?: string;
  pathSuffix?: string;
  pathEquals?: string[];
  pathContainsSegment?: string;
  excludeSegmentSuffixes?: string[];
  allSegmentsCharset?: DeclarativeCharset;
  reservedFirstSegment?: string[];
  scanSegment?: DeclarativeScanSegmentSpec;
  splitOnSegment?: DeclarativeSplitSegmentSpec;
  arcgisRestLayer?: boolean;
  pathSegments?: DeclarativeSegmentSpec[];
  queryParams?: DeclarativeQueryParamSpec[];
  derivedParams?: Record<string, DeclarativeDerivedParamSpec>;
  defaults?: Record<string, string>;
}

export interface DeclarativePathOverrideSpec {
  matchPaths: string[];
  newPath: string;
}

export interface DeclarativeTwinSpec {
  id?: string;
  fetchUrl: string;
  rawPathParams?: string[];
  overridePathIf?: DeclarativePathOverrideSpec;
  setQueryParams?: Record<string, string>;
  defaultQueryParams?: Record<string, string>;
  kind: 'json' | 'text';
  accept: string;
  maxBytes?: number;
}

export interface DeclarativeDynamicKeyPath {
  base: string;
  keyVar: string;
  subPath?: string;
}

export interface DeclarativeSubFieldsJoin {
  fields: string[];
  sep: string;
  fallbackField?: string;
}

export type DeclarativeVarFormat =
  | 'trim'
  | 'strip_tags'
  | 'jats_abstract'
  | 'int_comma'
  | 'usd_compact'
  | 'usd_per_million_tokens'
  | 'date_parts'
  | 'bool_map'
  | 'array_len'
  | 'array_len_comma'
  | 'object_keys'
  | 'epoch_sec_date'
  | 'epoch_ms_date'
  | 'inverted_abstract'
  | 'gitlab_blob_html'
  | 'html_to_md'
  | 'se_markdown'
  | 'strip_leading_h1'
  | 'fiscal_mmdd'
  | 'pubchem_toc'
  | 'nested_sub_values'
  | 'bytes_human';

export interface DeclarativeNestedSubValuesSpec {
  arrayPath: string;
  subArrayField: string;
  valueField: string;
  excludeValues?: string[];
  limit?: number;
  join?: string;
}

export interface DeclarativeReplaceSpec {
  from: string;
  to: string;
}

export interface DeclarativeFindInArray {
  arrayPath: string;
  langField: string;
  langValue: string;
  valueField: string;
}

export interface DeclarativeVarSpec {
  paths?: string[];
  dynamicKeyPath?: DeclarativeDynamicKeyPath;
  nestedSubValues?: DeclarativeNestedSubValuesSpec;
  tocHeading?: string;
  findInArrayLang?: DeclarativeFindInArray;
  template?: string;
  whenVars?: string[];
  whenAnyVars?: string[];
  fallbackVar?: string;
  firstNonMatchingKey?: string;
  subField?: string;
  subFieldsJoin?: DeclarativeSubFieldsJoin;
  itemWrap?: string;
  join?: string;
  limit?: number;
  format?: DeclarativeVarFormat;
  trueValue?: string;
  falseValue?: string;
  stripFrontmatter?: boolean;
  stripPrefix?: string;
  stripSuffix?: string;
  replaceAll?: DeclarativeReplaceSpec;
  excludeEquals?: string;
  equalsVar?: string;
  trim?: boolean;
  upper?: boolean;
  lower?: boolean;
  requireHttps?: boolean;
  requireHttpPrefix?: boolean;
  sliceMax?: number;
  default?: string;
  fallbackTemplate?: string;
}

export interface DeclarativeBulletSpec {
  label?: string;
  template: string;
  whenVar?: string;
  unlessVar?: string;
}

export interface DeclarativeTableColumn {
  header: string;
  paths?: string[];
  template?: string;
  format?: DeclarativeVarFormat;
  trueValue?: string;
  falseValue?: string;
  subField?: string;
  join?: string;
  limit?: number;
  maxLen?: number;
  default?: string;
}

export interface DeclarativeSectionFilterSpec {
  field: string;
  equals?: string;
  notEquals?: string;
  truthy?: boolean;
}

export interface DeclarativeDedupeSpec {
  keyFields: string[];
  keepFirst?: boolean;
}

export interface DeclarativeParallelArraysSpec {
  keysPath: string;
  valuesPaths: Record<string, string>;
}

export interface DeclarativeSortSpec {
  field: string;
  order?: 'asc' | 'desc';
}

export interface DeclarativePaginationMetaSpec {
  totalPath?: string;
  nextCursorPath?: string;
  hasMorePath?: string;
}

export interface DeclarativeTreeCommentsSpec {
  childrenPath: string;
  authorField: string;
  bodyField: string;
  scoreField?: string;
  maxDepth?: number;
  maxNodes?: number;
}

export interface DeclarativeSectionSpec {
  heading?: string;
  whenVar?: string;
  unlessVar?: string;
  bodyVar?: string;
  codeVar?: string;
  codeLang?: string;
  codeLangVar?: string;
  markdownTemplate?: string;
  arrayPath?: string;
  parallelArrays?: DeclarativeParallelArraysSpec;
  filter?: DeclarativeSectionFilterSpec;
  dedupe?: DeclarativeDedupeSpec;
  sort?: DeclarativeSortSpec;
  limit?: number;
  columns?: DeclarativeTableColumn[];
  itemVars?: Record<string, DeclarativeVarSpec>;
  requireItemVar?: string;
  collectLinkVars?: string[];
  itemTemplate?: string;
  itemHeadingTemplate?: string;
  itemBodyVar?: string;
  linkTemplate?: string;
  treeComments?: DeclarativeTreeCommentsSpec;
  paginationMeta?: DeclarativePaginationMetaSpec;
  emptyText?: string;
}

export interface DeclarativeXmlItemVarSpec {
  tags?: string[];
  attr?: { tag?: string; attr: string; whenAttrEquals?: { attr: string; value: string } };
  format?: 'strip_tags' | 'html_to_md' | 'jats_abstract' | 'trim';
  sliceMax?: number;
}

export interface DeclarativeXmlSpec {
  mode?: 'feed_entries' | 'jats_article' | 'items_table';
  rootTitleTag?: string;
  rootDescriptionTag?: string;
  itemTag?: string;
  limit?: number;
  itemVars?: Record<string, DeclarativeXmlItemVarSpec>;
  columns?: DeclarativeTableColumn[];
  itemHeadingTemplate?: string;
  itemMetaTemplate?: string;
  itemBodyVar?: string;
  linkVar?: string;
}

export type DeclarativeCommerceMode =
  | 'shopify_product'
  | 'shopify_product_js'
  | 'shopify_catalog_page'
  | 'woocommerce_catalog_page'
  | 'woocommerce_product'
  | 'squarespace_json'
  | 'bigcommerce_sitemap'
  | 'sfcc_variation'
  | 'magento2_render_info';

export interface DeclarativeCodeByPathSpec {
  pathParam: string;
  rawIfMarkdown?: boolean;
}

export interface DeclarativeExtractSpec {
  commerceMode?: DeclarativeCommerceMode;
  jsonMode?: 'nuget_registration' | 'paylocity_feed';
  icimsPortal?: boolean;
  textMode?: 'yaml_frontmatter_card' | 'ietf_rfc' | 'code_by_path' | 'git_patch' | 'plain_markdown' | 'html_document';
  pathParam?: string;
  codeByPath?: DeclarativeCodeByPathSpec;
  xml?: DeclarativeXmlSpec;
  jsonSource?: 'raw' | 'inertia_data_page';
  wrapRootArrayAs?: string;
  unwrapFirstArrayElement?: boolean;
  rootPath?: string;
  rejectIfFieldTruthy?: string;
  requireFieldEquals?: { path: string; value: string };
  requireFields?: string[];
  requireAnyFields?: string[];
  requireVars?: string[];
  requireNonEmptyVars?: string[];
  vars?: Record<string, DeclarativeVarSpec>;
  titleTemplate?: string;
  titleFallbackTemplate?: string;
  descriptionVar?: string;
  descriptionTemplate?: string;
  authorVar?: string;
  publishedTimeVar?: string;
  onlyBodyAlreadyTitled?: boolean;
  bullets?: DeclarativeBulletSpec[];
  bodyVar?: string;
  sections?: DeclarativeSectionSpec[];
  linksVars?: string[];
  recordFields?: Record<string, string>;
}

export interface DeclarativeRouteSpec {
  match: DeclarativeMatchSpec;
  twin: DeclarativeTwinSpec;
  extract: DeclarativeExtractSpec;
}

export interface DeclarativeHtmlVarSpec {
  selector?: string;
  meta?: string;
  allMeta?: string;
  dlKey?: string;
  dlSelector?: string;
  jsonLdField?: string;
  jsonLdTypes?: string[];
  attr?: string;
  mode?: 'text' | 'html_to_md' | 'inner_html' | 'outer_html' | 'attr' | 'count' | 'table_md';
  join?: string;
  limit?: number;
  stripPrefix?: string;
  stripSuffix?: string;
  replaceAll?: DeclarativeReplaceSpec;
  requireHttps?: boolean;
  sliceMax?: number;
  default?: string;
  template?: string;
  whenVars?: string[];
  fallbackVar?: string;
}

export type DeclarativeHtmlMode =
  | 'dom'
  | 'embedded_json'
  | 'xml_items_table'
  | 'markdown_clean'
  | 'gist_files'
  | 'stackexchange_html'
  | 'reddit_shreddit'
  | 'icims_portal'
  | 'shopify_html'
  | 'woocommerce_html'
  | 'xenforo_html'
  | 'squarespace_html'
  | 'bigcommerce_html'
  | 'sfcc_html'
  | 'shopware_magento_html'
  | 'sram_docs_html'
  | 'bosch_help_html'
  | 'ukg_pro_html'
  | 'paylocity_html'
  | 'dover_html'
  | 'sitecore_jss_html'
  | 'giant_liv_html';

export interface DeclarativeHtmlRouteSpec {
  id?: string;
  match?: DeclarativeMatchSpec;
  requireHtmlSubstrings?: string[];
  mode: DeclarativeHtmlMode;
  cleanPreset?: 'ietf_rfc' | 'mediawiki' | 'jsr_Tabs';
  scriptId?: string;
  dataAttr?: string;
  extract?: DeclarativeExtractSpec;
  xml?: DeclarativeXmlSpec;
  vars?: Record<string, DeclarativeHtmlVarSpec>;
  requireNonEmptyVars?: string[];
  titleTemplate?: string;
  descriptionVar?: string;
  authorVar?: string;
  publishedTimeVar?: string;
  bullets?: DeclarativeBulletSpec[];
  bodyVar?: string;
  includeCurrentMdSectionHeading?: string;
  itemSelector?: string;
  itemLimit?: number;
  itemVars?: Record<string, DeclarativeHtmlVarSpec>;
  columns?: DeclarativeTableColumn[];
  itemHeadingTemplate?: string;
  itemBodyVar?: string;
  linkVar?: string;
}

export interface DeclarativeAdapterManifest {
  id: string;
  name: string;
  category: AdapterCategory;
  description: string;
  domains: string[];
  universalEngine?: boolean;
  exampleUrls: string[];
  match?: DeclarativeMatchSpec;
  twin?: DeclarativeTwinSpec;
  extract?: DeclarativeExtractSpec;
  routes?: DeclarativeRouteSpec[];
  htmlRoutes?: DeclarativeHtmlRouteSpec[];
  catalog?: DeclarativeCatalogConfig;
}

export interface CompiledManifestBundle {
  version: number;
  manifests: DeclarativeAdapterManifest[];
}

export function matchesApprovedWildcard(rawWildcard: string, rawCandidate: string): boolean {
  return callCoreWasm<{ ok: boolean }>('matches_approved_wildcard', {
    wildcard: String(rawWildcard ?? ''),
    candidate: String(rawCandidate ?? ''),
  }).ok;
}

export function matchDeclarativeRoute(
  match: DeclarativeMatchSpec,
  ctx: TwinMatchContext | { url: URL; host: string; path: string; parts: string[] },
): Record<string, string> | null {
  const res = callCoreWasm<{ ok: boolean; params?: Record<string, string> }>('match_declarative_route', {
    match,
    url: ctx.url.toString(),
  });
  return res.ok && res.params ? res.params : null;
}

export function isSafeDeclarativeTwinUrl(fetchUrl: string): boolean {
  if (typeof fetchUrl !== 'string' || !fetchUrl) return false;
  return callCoreWasm<{ ok: boolean }>('is_safe_twin_url', { url: fetchUrl }).ok;
}

const defaultHtmlFragmentToMd: HtmlFragmentConverter = (frag: string, base?: string) => {
  const res = callCoreWasm<{ markdown: string; links: string[] }>('extract_html', {
    html: `<!doctype html><html><body>${String(frag ?? '')}</body></html>`,
    baseUrl: String(base ?? ''),
    onlyMainContent: false,
    includeImages: true,
  });
  return { markdown: res.markdown ?? '', links: res.links ?? [] };
};

function sanitizeMetaWasm(text: string, maxLen: number): string {
  return callCoreWasm<{ out: string }>('sanitize_meta', { text: String(text ?? ''), maxLen }).out;
}

function formatCommerceTwinDoc(
  mode: DeclarativeCommerceMode,
  rawBody: string,
  origUrl: string,
  htmlToMd: HtmlFragmentConverter = defaultHtmlFragmentToMd,
  twinFetchUrl?: string,
): TwinFormattedDoc | null {
  let commDoc: TwinFormattedDoc | null = null;
  switch (mode) {
    case 'shopify_product':
      commDoc = enrichShopifyProductFromJson({ rawJson: rawBody, productUrl: origUrl, htmlToMd, isAjaxJs: false });
      break;
    case 'shopify_product_js':
      commDoc = enrichShopifyProductFromJson({ rawJson: rawBody, productUrl: origUrl, htmlToMd, isAjaxJs: true });
      break;
    case 'shopify_catalog_page':
      commDoc = formatShopifyProductsFeedTwin(
        rawBody,
        origUrl,
        twinFetchUrl ? { twinUrl: twinFetchUrl } : undefined,
      );
      break;
    case 'woocommerce_catalog_page':
      commDoc = formatWcStoreApiListTwin(
        rawBody,
        origUrl,
        twinFetchUrl && twinFetchUrl !== origUrl ? twinFetchUrl : undefined,
      );
      break;
    case 'woocommerce_product':
      commDoc = formatWcStoreApiProductTwin(rawBody, origUrl, htmlToMd);
      break;
    case 'squarespace_json':
      commDoc = formatSquarespaceCommerceJson(rawBody, origUrl);
      break;
    case 'bigcommerce_sitemap':
      commDoc = formatBigCommerceXmlSitemap(rawBody, origUrl);
      break;
    case 'sfcc_variation':
      commDoc = formatSfccProductVariationJson(rawBody, origUrl);
      break;
    case 'magento2_render_info':
      commDoc = formatMagento2RenderInfoJson(rawBody, origUrl);
      break;
  }
  if (!commDoc) return null;
  return {
    ...commDoc,
    title: sanitizeMetaWasm(commDoc.title, 400),
    ...(commDoc.description ? { description: sanitizeMetaWasm(commDoc.description, 600) } : {}),
    ...(commDoc.author ? { author: sanitizeMetaWasm(commDoc.author, 240) } : {}),
    ...(commDoc.publishedTime ? { publishedTime: sanitizeMetaWasm(commDoc.publishedTime, 120) } : {}),
    ...(commDoc.links ? { links: commDoc.links.filter((l) => isSafeDeclarativeTwinUrl(l.trim())) } : {}),
  };
}

export function formatJsonWithExtractSpec(
  rawBody: string,
  ext: DeclarativeExtractSpec,
  params: Record<string, string>,
  origUrl: string,
  htmlToMd?: HtmlFragmentConverter,
): TwinFormattedDoc | null {
  if (ext?.commerceMode) {
    return formatCommerceTwinDoc(ext.commerceMode, String(rawBody ?? ''), String(origUrl ?? ''), htmlToMd);
  }
  const res = callCoreWasmRaw<{ ok: boolean; doc?: TwinFormattedDoc }>(
    'format_json_extract_spec',
    {
      extract: ext,
      params: params ?? {},
      origUrl: String(origUrl ?? ''),
    },
    String(rawBody ?? ''),
  );
  return res.ok && res.doc ? res.doc : null;
}

export function validateDeclarativeManifestObject(m: DeclarativeAdapterManifest): DeclarativeAdapterManifest {
  if (!m || typeof m !== 'object' || Array.isArray(m)) {
    throw new Error('Declarative manifest root must be an object');
  }
  if (m.catalog !== undefined) {
    if (!m.catalog || typeof m.catalog !== 'object' || Array.isArray(m.catalog)) {
      throw new Error(`[${String(m.id ?? 'unknown')}] catalog must be a valid object`);
    }
    if (typeof m.catalog.platform !== 'string' || !VALID_CATALOG_PLATFORMS.has(m.catalog.platform)) {
      throw new Error(
        `[${String(m.id ?? 'unknown')}] unsupported catalog.platform "${String((m.catalog as { platform?: unknown }).platform)}" (expected "shopify" or "woocommerce")`,
      );
    }
  }
  const res = callCoreWasm<{ ok: boolean; error?: string; manifest?: DeclarativeAdapterManifest }>('validate_manifest', {
    raw: JSON.stringify(m),
    isJson: true,
  });
  if (!res.ok || !res.manifest) {
    throw new Error(res.error || 'Invalid declarative manifest');
  }
  return res.manifest;
}

export function parseDeclarativeManifest(input: DeclarativeAdapterManifest | string): DeclarativeAdapterManifest {
  if (typeof input !== 'string') {
    return validateDeclarativeManifestObject(input);
  }
  const res = callCoreWasm<{ ok: boolean; error?: string; manifest?: DeclarativeAdapterManifest }>('validate_manifest', {
    raw: input,
    isJson: false,
  });
  if (!res.ok || !res.manifest) {
    throw new Error(res.error || 'Invalid declarative YAML manifest');
  }
  return res.manifest;
}

function buildAdapterFromValidatedManifest(manifest: DeclarativeAdapterManifest, isBuiltIn: boolean): SiteAdapter {
  const hasRoutes = Boolean(
    (manifest.routes && manifest.routes.length > 0) || (manifest.match && manifest.twin && manifest.extract),
  );
  const hasHtmlRoutes = Boolean(manifest.htmlRoutes && manifest.htmlRoutes.length > 0);
  const catalogSpec = manifest.catalog ? buildDeclarativeCatalogSpec(manifest.catalog) : undefined;

  const manifestSelector = isBuiltIn ? { adapterId: manifest.id } : { manifest };

  return {
    id: manifest.id,
    name: manifest.name,
    category: manifest.category,
    description: manifest.description,
    domains: [...manifest.domains],
    ...(manifest.universalEngine ? { universalEngine: true } : {}),
    exampleUrls: [...manifest.exampleUrls],
    ...(hasRoutes
      ? {
          resolveTwin(ctx: TwinMatchContext): SiteExtractorTwin | null {
            const reqUrl = ctx.url.toString();
            const resolved = callCoreWasm<{
              matched: boolean;
              id?: string;
              adapterId?: string;
              fetchUrl?: string;
              kind?: 'json' | 'text';
              accept?: string;
              rawAccept?: string;
              maxBytes?: number;
              commerceMode?: DeclarativeCommerceMode;
            }>('manifest_resolve_twin', { ...manifestSelector, url: reqUrl });
            if (!resolved.matched || !resolved.fetchUrl || !resolved.kind) return null;
            return {
              id: resolved.id || manifest.id,
              fetchUrl: resolved.fetchUrl,
              kind: resolved.kind,
              accept:
                resolved.rawAccept ||
                resolved.accept ||
                (resolved.kind === 'json' ? 'application/json' : 'text/plain'),
              maxBytes:
                typeof resolved.maxBytes === 'number' && resolved.maxBytes > 0
                  ? resolved.maxBytes
                  : resolved.kind === 'json'
                    ? 2 * 1024 * 1024
                    : 4 * 1024 * 1024,
              formatTwin: (rawBody: string, originalUrl: string, htmlToMd: HtmlFragmentConverter) => {
                if (resolved.commerceMode) {
                  return formatCommerceTwinDoc(
                    resolved.commerceMode,
                    String(rawBody ?? ''),
                    String(originalUrl || reqUrl),
                    htmlToMd,
                    resolved.fetchUrl,
                  );
                }
                const fmt = callCoreWasmRaw<{ ok: boolean; doc?: TwinFormattedDoc }>(
                  'manifest_format_twin',
                  {
                    ...manifestSelector,
                    url: reqUrl,
                    origUrl: String(originalUrl || reqUrl),
                  },
                  String(rawBody ?? ''),
                );
                return fmt.ok && fmt.doc ? fmt.doc : null;
              },
            };
          },
        }
      : {}),
    ...(hasHtmlRoutes
      ? {
          extractHtml(ctx: HtmlExtractContext): PostFetchSiteResult | null {
            const ext = callCoreWasmRawMetaPair<{ ok: boolean; result?: PostFetchSiteResult }>(
              'manifest_extract_html',
              {
                ...manifestSelector,
                baseUrl: String(ctx.baseUrl || ctx.url.toString()),
              },
              String(ctx.rawHtml ?? ''),
              String(ctx.currentMd ?? ''),
            );
            return ext.ok && ext.result && ext.result.markdown.trim() ? ext.result : null;
          },
        }
      : {}),
    ...(catalogSpec ? { catalog: catalogSpec } : {}),
  };
}

export function compileDeclarativeAdapter(manifestOrYaml: DeclarativeAdapterManifest | string): SiteAdapter {
  const manifest = parseDeclarativeManifest(manifestOrYaml);
  return buildAdapterFromValidatedManifest(manifest, false);
}

export function compileValidatedManifestSet(manifests: readonly DeclarativeAdapterManifest[]): SiteAdapter[] {
  const validatedList: DeclarativeAdapterManifest[] = [];
  for (const raw of manifests) {
    validatedList.push(validateDeclarativeManifestObject(raw));
  }
  const setRes = callCoreWasm<{ ok: boolean; error?: string }>('validate_manifest_set', {
    manifests: validatedList,
  });
  if (!setRes.ok) {
    throw new Error(setRes.error || 'Manifest set validation failed');
  }
  return validatedList.map((m) => buildAdapterFromValidatedManifest(m, true));
}

const COMPILED_BUNDLE = compiledBundleJson as unknown as CompiledManifestBundle;

export const DECLARATIVE_SITE_ADAPTERS: readonly SiteAdapter[] = (COMPILED_BUNDLE.manifests ?? []).map((m) =>
  buildAdapterFromValidatedManifest(m, true),
);
