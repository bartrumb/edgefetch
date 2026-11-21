/**
 * Shared Go + TypeScript Declarative YAML v2 Site Adapter Engine (`hub/src/extractors/declarative.ts`).
 *
 * Compiles canonical zero-code YAML manifests in `internal/extract/manifests/<id>.yaml` (and their
 * checked canonical `internal/extract/manifests/compiled.json` bundle shared with `internal/extract/declarative.go`
 * via `//go:embed`) into standard `SiteAdapter` definitions covering pre-fetch twins, post-fetch HTML/DOM
 * extractors (`parseHtmlDoc`), XML/RSS/JATS feeds, and polite storefront catalogs (`commerce-engine.ts`).
 *
 * Security & Complexity Invariants (Round 6 Hardened):
 *  - Zero arbitrary code execution (`eval`, `Function`), zero `fetch()` escape, and zero backtracking regexes.
 *  - YAML manifests are parsed strictly with `maxAliasCount: 0, merge: false, uniqueKeys: true` and AST-checked
 *    to reject anchors (`&`), aliases (`*`), explicit tags (`!`), non-ASCII keys, and unknown schema keys.
 *  - Host-claim validation (`M2`) forbids broad TLD/eTLD wildcards (`*`, `*.com`, `*.co.uk`) and forbids `{host}`
 *    interpolation outside same-origin `https://{host}/...` unless `domains` is a strict exact-host list.
 *  - Resolved `fetchUrl` targets are strictly validated as public `https://` URLs (rejecting `localhost.`,
 *    `.internal.`, `.nip.io`, numeric TLDs like `127.1`, credentials, fragments, and non-443 ports).
 */

import { isAlias, isMap, isPair, isScalar, isSeq, parseDocument as parseYamlDocument } from 'yaml';

import compiledBundleJson from '../../../internal/extract/manifests/compiled.json';

import {
  buildDeclarativeCatalogSpec,
  enrichShopifyProductFromJson,
  extractShopifyProductHtml,
  extractWooCommerceProductHtml,
  formatShopifyProductsFeedTwin,
  formatWcStoreApiListTwin,
  formatWcStoreApiProductTwin,
  type DeclarativeCatalogConfig,
} from './commerce-engine';
import {
  attrHasTokenLinear,
  extractXmlTagTextLinear,
  findAllElementInnersLinear,
  findAllOpenTagsLinear,
  findElementInnerLinear,
  findOpenTagLinear,
  getAttrValueLinear,
  type AdapterCategory,
  type HtmlExtractContext,
  type HtmlFragmentConverter,
  type PostFetchSiteResult,
  type SiteAdapter,
  type SiteExtractorTwin,
  type TwinFormattedDoc,
  type TwinMatchContext,
} from './types';
import {
  compileLinearRegex,
  decodeBasicEntities,
  detectFenceLang,
  extractAllMetaContents,
  extractBalancedDivAt,
  extractJsonLdObjects,
  extractMetaContent,
  formatGfmTable,
  formatUsdCompact,
  formatYamlFrontmatterCard,
  parseHtmlDoc,
  parseJsonObject,
  parseJsonValue,
  safeFence,
  stripScriptsAndStyles,
  stripTagsInline,
  unescapeHrefUrl,
  type HtmlNode,
} from './utils';

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
  | 'arxiv_id';

export type DeclarativeParamTransform = 'lower' | 'upper' | 'pad10_zero' | 'strip_leading_zeros';

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
  exactSegments?: boolean;
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
  | 'bytes_human'
  | 'inverted_abstract'
  | 'gitlab_blob_html'
  | 'html_to_md'
  | 'se_markdown'
  | 'strip_leading_h1'
  | 'fiscal_mmdd'
  | 'pubchem_toc'
  | 'nested_sub_values';

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

export interface DeclarativeVarSpec {
  paths?: string[];
  dynamicKeyPath?: DeclarativeDynamicKeyPath;
  nestedSubValues?: DeclarativeNestedSubValuesSpec;
  tocHeading?: string;
  findInArrayLang?: { arrayPath: string; langField: string; langValue: string; valueField: string };
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
  fallbackVar?: string;
  format?: 'usd_compact' | 'int_comma' | 'strip_tags' | 'paired_percent' | 'bytes_human';
  outcomesField?: string;
  pricesField?: string;
  defaultOutcomes?: string[];
  stripPrefix?: string;
  code?: boolean;
  sliceMax?: number;
}

export interface DeclarativeSectionFilterSpec {
  requireField?: string;
  excludeFieldPrefix?: { field: string; prefix: string };
  excludeFieldSuffixes?: { field: string; suffixes: string[] };
  tagFilterParam?: { param: string; skipIfEquals?: string; tagsField: string };
}

export interface DeclarativeDedupeSpec {
  keyPaths: string[];
  mergeTextPaths?: string[];
  mergeTargetVar?: string;
  mergeSep?: string;
  mergeLimit?: number;
  orBoolPaths?: string[];
  orBoolTargetField?: string;
}

export interface DeclarativeParallelArraysSpec {
  basePath: string;
  fields: Record<string, string>;
  priorityFilterAfter?: { index: number; field: string; allowValues: string[] };
}

export interface DeclarativeSortSpec {
  boolDescField?: string;
  numDescField?: string;
}

export interface DeclarativePaginationMetaSpec {
  totalPath?: string;
  cursorMode?: 'offset' | 'last_id';
  idField?: string;
}

export interface DeclarativeTreeCommentsSpec {
  childrenPath: string;
  authorPath: string;
  htmlTextPath: string;
  maxDepth?: number;
  maxItems?: number;
}

export interface DeclarativeSectionSpec {
  heading: string;
  headingTemplate?: string;
  whenVar?: string;
  unlessVar?: string;
  textVar?: string;
  arrayPath?: string;
  parallelArrays?: DeclarativeParallelArraysSpec;
  minItems?: number;
  emptyText?: string;
  filter?: DeclarativeSectionFilterSpec;
  dedupeBy?: DeclarativeDedupeSpec;
  sortBy?: DeclarativeSortSpec;
  columns?: DeclarativeTableColumn[];
  listArrayPath?: string;
  subsectionsArrayPath?: string;
  subsectionHeadingTemplate?: string;
  subsectionAltHeadingTemplate?: string;
  subsectionAltWhenVar?: string;
  subsectionBodyVar?: string;
  subsectionSubkeys?: string[];
  treeComments?: DeclarativeTreeCommentsSpec;
  limit?: number;
  indentField?: string;
  indentOffset?: number;
  maxIndent?: number;
  itemTemplate?: string;
  requireItemVar?: string;
  itemVars?: Record<string, DeclarativeVarSpec>;
  collectLinkVars?: string[];
  linkScanLimit?: number;
  recordFields?: Record<string, string>;
  paginationMeta?: DeclarativePaginationMetaSpec;
}

export interface DeclarativeFindInArray {
  arrayPath: string;
  matchField?: string;
  matchFields?: string[];
  endsWithField?: string;
  matchTemplate: string;
  endsWithTemplate?: string;
  ignoreCase?: boolean;
}

export interface DeclarativeXmlItemVarSpec {
  tags: string[];
  splitColonPart?: 0 | 1;
  sliceMax?: number;
  default?: string;
}

export interface DeclarativeXmlSpec {
  mode: 'items_table' | 'jats_article';
  requireAnyTags?: string[];
  itemTag?: string;
  channelTitleFallbackParam?: string;
  firstItemVars?: Record<string, string[]>;
  titleTemplate?: string;
  emptyText?: string;
  limit?: number;
  requireItemVar?: string;
  itemVars?: Record<string, DeclarativeXmlItemVarSpec>;
  columns?: Array<{ header: string; template: string }>;
  collectLinkVar?: string;
  recordFields?: Record<string, string>;
  emitTotals?: boolean;
}

export type DeclarativeCommerceMode =
  | 'shopify_product'
  | 'shopify_product_js'
  | 'shopify_catalog_page'
  | 'woocommerce_catalog_page'
  | 'woocommerce_product';

export interface DeclarativeCodeByPathSpec {
  sourceVar: string;
  pathParam: string;
  rawIfMarkdown?: boolean;
}

export interface DeclarativeExtractSpec {
  commerceMode?: DeclarativeCommerceMode;
  icimsPortal?: boolean;
  textMode?: 'yaml_frontmatter_card' | 'code_or_markdown_by_path' | 'raw';
  pathParam?: string;
  xml?: DeclarativeXmlSpec;
  jsonSource?: 'raw' | 'inertia_data_page';
  wrapRootArrayAs?: string;
  unwrapFirstArrayElement?: boolean;
  rootPath?: string;
  rejectIfFieldTruthy?: string;
  requireFieldEquals?: { path: string; value: string };
  requireArrayItemField?: { arrayPath: string; field: string };
  findInArray?: DeclarativeFindInArray;
  fallbackExtract?: DeclarativeExtractSpec;
  requireFields?: string[];
  requireAnyFields?: string[];
  requireVars?: string[];
  vars?: Record<string, DeclarativeVarSpec>;
  codeByPath?: DeclarativeCodeByPathSpec;
  titleTemplate?: string;
  titleWhenVar?: string;
  titleFallbackTemplate?: string;
  descriptionVar?: string;
  descriptionTemplate?: string;
  authorVar?: string;
  authorTemplate?: string;
  publishedTimeVar?: string;
  blockquoteTemplate?: string;
  blockquoteWhenVar?: string;
  metaLine?: DeclarativeBulletSpec[];
  metaLineItalic?: boolean;
  footerItalicTemplate?: string;
  footerItalicWhenVar?: string;
  introVar?: string;
  bullets?: DeclarativeBulletSpec[];
  objectLinksPath?: string;
  bodyVar?: string;
  sections?: DeclarativeSectionSpec[];
  linksVars?: string[];
  linkTemplates?: string[];
}

export interface DeclarativeRouteSpec {
  match: DeclarativeMatchSpec;
  twin: DeclarativeTwinSpec;
  extract: DeclarativeExtractSpec;
}

export interface DeclarativeHtmlVarSpec {
  jsonLdPaths?: string[];
  embeddedPaths?: string[];
  metaKeys?: string[];
  allMetaKey?: string;
  cssText?: string[];
  cssAttr?: { selector: string; attr: string };
  cssAllText?: { selector: string; limit?: number; dedupe?: boolean; join?: string };
  cssHtmlToMd?: string[];
  regexExtract?: {
    source: 'clean_html' | 'doc_text_and_img_alts';
    pattern: string;
    group?: number;
    transform?: 'upper' | 'lower';
  };
  template?: string;
  whenVars?: string[];
  whenAnyVars?: string[];
  fallbackVar?: string;
  fallbackTemplate?: string;
  default?: string;
  join?: string;
  limit?: number;
  format?: 'strip_tags' | 'free_or_currency' | 'strip_leading_h1';
  currencyVar?: string;
  stripPrefix?: string;
  stripSuffix?: string;
  stripRegexSuffix?: string;
  replaceAll?: DeclarativeReplaceSpec;
  sliceMax?: number;
  minLen?: number;
  trim?: boolean;
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
  | 'woocommerce_html';

export interface DeclarativeHtmlRouteSpec {
  id?: string;
  match: DeclarativeMatchSpec;
  mode: DeclarativeHtmlMode;
  // For `dom`:
  jsonLdTypes?: string[];
  embeddedBalancedKey?: string;
  vars?: Record<string, DeclarativeHtmlVarSpec>;
  requireVars?: string[];
  requireBulletsOrVars?: string[];
  titleTemplate?: string;
  titleWhenVar?: string;
  titleFallbackTemplate?: string;
  descriptionVar?: string;
  authorVar?: string;
  publishedTimeVar?: string;
  blockquoteTemplate?: string;
  blockquoteWhenVar?: string;
  metaItalicTemplate?: string;
  metaItalicWhenVar?: string;
  introVar?: string;
  bullets?: DeclarativeBulletSpec[];
  bodyVar?: string;
  bodyFallbackHeading?: string;
  sections?: Array<{ heading: string; textVar: string }>;
  appendCurrentMdDelta?: { baseVar?: string; minExtraChars: number };
  linkTemplates?: string[];
  preserveBodyLinksFromVar?: string;
  // For `embedded_json`:
  scriptId?: string;
  dataAttr?: string;
  extract?: DeclarativeExtractSpec;
  // For `xml_items_table`:
  xml?: DeclarativeXmlSpec;
  // For `markdown_clean`:
  cleanPreset?: 'ietf_rfc' | 'jsr_io' | 'mediawiki';
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

const VALID_ID_RE = /^[a-z0-9][a-z0-9_-]{0,63}$/;
const VALID_CATEGORIES = new Set<string>([
  'developer',
  'genai',
  'jobs',
  'finance',
  'public-records',
  'research-health',
  'commerce-social',
]);

const FORBIDDEN_BROAD_SUFFIXES = new Set([
  'com',
  'org',
  'net',
  'io',
  'gov',
  'edu',
  'mil',
  'int',
  'uk',
  'de',
  'fr',
  'jp',
  'au',
  'ca',
  'us',
  'eu',
  'ai',
  'co',
  'app',
  'dev',
  'co.uk',
  'org.uk',
  'gov.uk',
  'ac.uk',
  'com.au',
  'org.au',
  'gov.au',
  'co.jp',
  'com.br',
]);

const KNOWN_SOCRATA_HOSTS = new Set([
  'data.cityofnewyork.us',
  'data.sfgov.org',
  'data.sf.gov',
  'data.seattle.gov',
  'data.cityofchicago.org',
  'data.lacity.org',
  'data.wa.gov',
  'data.nj.gov',
  'data.colorado.gov',
  'data.texas.gov',
  'data.ny.gov',
  'data.ct.gov',
  'data.oregon.gov',
  'data.austintexas.gov',
  'data.nola.gov',
  'data.cincinnati-oh.gov',
  'data.cambridgema.gov',
  'data.montgomerycountymd.gov',
  'data.brla.gov',
  'data.cdc.gov',
  'data.cms.gov',
  'data.medicare.gov',
]);

function isAsciiAlnum(code: number): boolean {
  return (code >= 97 && code <= 122) || (code >= 65 && code <= 90) || (code >= 48 && code <= 57);
}

function isIdentChar(code: number): boolean {
  return isAsciiAlnum(code) || code === 95 /* '_' */;
}

function isAsciiPrintableKey(s: string): boolean {
  if (!s) return false;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c < 0x20 || c > 0x7e) return false;
  }
  return true;
}

function stripInvisibleAndNul(s: string): string {
  if (!s) return '';
  let clean = '';
  for (const ch of s) {
    const cp = ch.codePointAt(0) ?? 0;
    if (
      cp === 0 ||
      (cp >= 0xe0000 && cp <= 0xe007f) ||
      (cp >= 0x202a && cp <= 0x202e) ||
      (cp >= 0x2066 && cp <= 0x2069)
    ) {
      continue;
    }
    clean += ch;
  }
  return clean;
}

function sanitizeSingleLineMeta(s: string): string {
  if (!s) return '';
  const clean = stripInvisibleAndNul(s)
    .replace(/[\r\n\t]+/g, ' ')
    .replace(/<(?=[A-Za-z/!?])/g, '&lt;')
    .replace(/\]\(\s*(?:javascript|vbscript|data):[^)]*\)/gi, '](#)')
    .replace(/\s+/g, ' ')
    .trim();
  return clean;
}

const DANGEROUS_HTML_TAG_NAMES = new Set([
  'script',
  'iframe',
  'object',
  'embed',
  'svg',
  'style',
  'math',
  'base',
  'meta',
  'link',
  'form',
  'input',
  'textarea',
  'xmp',
  'plaintext',
]);

function isDangerousTagSlice(tagInner: string): boolean {
  let i = 0;
  const n = tagInner.length;
  if (i < n && tagInner.charCodeAt(i) === 47 /* '/' */) i++;
  const start = i;
  while (i < n) {
    const c = tagInner.charCodeAt(i);
    if ((c >= 97 && c <= 122) || (c >= 65 && c <= 90) || (c >= 48 && c <= 57) || c === 45) i++;
    else break;
  }
  const tagName = tagInner.slice(start, i).toLowerCase();
  if (DANGEROUS_HTML_TAG_NAMES.has(tagName)) return true;
  if (!tagName) return false;
  const rest = tagInner.slice(i).toLowerCase();
  return /\bon[a-z]+\s*=/.test(rest) || /(?:href|src|xlink:href|formaction)\s*=\s*["']?\s*(?:javascript|vbscript|data):/.test(rest);
}

function escapeDangerousRawHtmlInLineLinear(line: string): string {
  const firstLt = line.indexOf('<');
  if (firstLt === -1 && !line.includes('](')) return line;
  let out = '';
  let i = 0;
  const n = line.length;
  let nextGtHint = -2; // -2 = uncomputed, -1 = none left
  let nextLtHint = -2;

  while (i < n) {
    const ch = line.charCodeAt(i);
    // Preserve inline backtick code spans verbatim
    if (ch === 96 /* '`' */) {
      let tickLen = 1;
      while (i + tickLen < n && line.charCodeAt(i + tickLen) === 96) tickLen++;
      const fence = line.slice(i, i + tickLen);
      const closeIdx = line.indexOf(fence, i + tickLen);
      if (closeIdx !== -1) {
        out += line.slice(i, closeIdx + tickLen);
        i = closeIdx + tickLen;
        continue;
      }
      out += fence;
      i += tickLen;
      continue;
    }
    if (ch === 60 /* '<' */) {
      if (nextGtHint !== -1 && nextGtHint <= i) {
        nextGtHint = line.indexOf('>', i + 1);
      }
      if (nextLtHint !== -1 && nextLtHint <= i) {
        nextLtHint = line.indexOf('<', i + 1);
      }
      if (nextGtHint !== -1 && nextGtHint > i + 1 && (nextLtHint === -1 || nextGtHint < nextLtHint)) {
        const inner = line.slice(i + 1, nextGtHint);
        if (isDangerousTagSlice(inner)) {
          out += '&lt;';
          i++;
          continue;
        }
      } else if (i + 1 < n) {
        // Unclosed dangerous tag like `<script src=...` without `>`
        let j = i + 1;
        if (j < n && line.charCodeAt(j) === 47) j++;
        const s0 = j;
        while (j < n && j - s0 < 16) {
          const c = line.charCodeAt(j);
          if ((c >= 97 && c <= 122) || (c >= 65 && c <= 90)) j++;
          else break;
        }
        if (DANGEROUS_HTML_TAG_NAMES.has(line.slice(s0, j).toLowerCase())) {
          out += '&lt;';
          i++;
          continue;
        }
      }
    }
    out += line[i]!;
    i++;
  }
  if (out.includes('](')) {
    out = out.replace(/\]\(\s*(?:javascript|vbscript|data):[^)\r\n]*\)/gi, '](#)');
  }
  return out;
}

function escapeDangerousRawHtmlOutsideFences(s: string): string {
  if (!s || (!s.includes('<') && !s.includes('\0') && !s.includes(']('))) return s;
  const noNul = stripInvisibleAndNul(s);
  if (!noNul.includes('<') && !noNul.includes('](')) return noNul;
  const lines = noNul.split('\n');
  let inFence = false;
  for (let i = 0; i < lines.length; i++) {
    const ln = lines[i]!;
    const trimmed = ln.trimStart();
    if (trimmed.startsWith('```') || trimmed.startsWith('~~~')) {
      inFence = !inFence;
      continue;
    }
    if (inFence) continue;
    lines[i] = escapeDangerousRawHtmlInLineLinear(ln);
  }
  return lines.join('\n');
}

function expandTemplate(tmpl: string, lookup: (key: string) => string): string {
  if (!tmpl || !tmpl.includes('{')) return tmpl || '';
  let out = '';
  const n = tmpl.length;
  let i = 0;
  while (i < n) {
    if (tmpl.charCodeAt(i) !== 123 /* '{' */) {
      out += tmpl[i]!;
      i++;
      continue;
    }
    let j = i + 1;
    while (j < n && isIdentChar(tmpl.charCodeAt(j))) {
      j++;
    }
    if (j > i + 1 && j < n && tmpl.charCodeAt(j) === 125 /* '}' */) {
      out += lookup(tmpl.slice(i + 1, j));
      i = j + 1;
    } else {
      out += '{';
      i++;
    }
  }
  return out;
}

function applyParamTransform(val: string, transform?: DeclarativeParamTransform): string {
  if (!transform) return val;
  switch (transform) {
    case 'lower':
      return val.toLowerCase();
    case 'upper':
      return val.toUpperCase();
    case 'pad10_zero':
      return val.trim().padStart(10, '0');
    case 'strip_leading_zeros': {
      const stripped = val.trim().replace(/^0+/, '');
      return stripped || '0';
    }
    default:
      return val;
  }
}

function isValidDoiRest(val: string): boolean {
  if (!val.startsWith('10.')) return false;
  const slashIdx = val.indexOf('/');
  if (slashIdx < 7 || slashIdx > 12) return false;
  for (let i = 3; i < slashIdx; i++) {
    const c = val.charCodeAt(i);
    if (c < 48 || c > 57) return false;
  }
  const suffix = val.slice(slashIdx + 1);
  if (!suffix) return false;
  for (let i = 0; i < suffix.length; i++) {
    const c = suffix.charCodeAt(i);
    if (c <= 0x20 || c === 0x7f) return false;
  }
  return true;
}

function isValidSafeSubpath(val: string): boolean {
  const parts = val.split('/');
  if (parts.length === 0) return false;
  for (const seg of parts) {
    if (!seg || seg === '.' || seg === '..') return false;
    for (let i = 0; i < seg.length; i++) {
      const c = seg.charCodeAt(i);
      if (c <= 0x20 || c >= 0x7f || c === 63 || c === 35 || c === 92) {
        return false;
      }
    }
  }
  return true;
}

function isValidSocrata4x4(val: string): boolean {
  if (val.length !== 9 || val.charCodeAt(4) !== 45 /* '-' */) return false;
  let hasDigit = false;
  for (let i = 0; i < 9; i++) {
    if (i === 4) continue;
    const c = val.charCodeAt(i);
    if (c >= 48 && c <= 57) {
      hasDigit = true;
    } else if (!((c >= 97 && c <= 122) || (c >= 65 && c <= 90))) {
      return false;
    }
  }
  return hasDigit;
}

function validateDeclarativeParam(
  val: string,
  charset: DeclarativeCharset | undefined,
  allowValues: string[] | undefined,
  reserved: string[] | undefined,
  minLen = 1,
  maxLen = 160,
): boolean {
  const lo = minLen > 0 ? minLen : 1;
  const hi = maxLen > 0 ? maxLen : 160;
  if (val.length < lo || val.length > hi) return false;
  if (allowValues && allowValues.length > 0 && !allowValues.includes(val)) {
    return false;
  }
  if (reserved && reserved.length > 0) {
    const lower = val.toLowerCase();
    for (const r of reserved) {
      if (lower === r.toLowerCase()) return false;
    }
  }
  const cs = charset ?? 'pkg';
  switch (cs) {
    case 'alnum':
      for (let i = 0; i < val.length; i++) {
        if (!isAsciiAlnum(val.charCodeAt(i))) return false;
      }
      return true;
    case 'digits':
      for (let i = 0; i < val.length; i++) {
        const c = val.charCodeAt(i);
        if (c < 48 || c > 57) return false;
      }
      return true;
    case 'alnum_dash':
    case 'slug':
      for (let i = 0; i < val.length; i++) {
        const c = val.charCodeAt(i);
        if (!isAsciiAlnum(c) && c !== 95 && c !== 45) return false;
      }
      return true;
    case 'pkg':
      if (val === '.' || val === '..') return false;
      for (let i = 0; i < val.length; i++) {
        const c = val.charCodeAt(i);
        if (!isAsciiAlnum(c) && c !== 95 && c !== 45 && c !== 46) return false;
      }
      return true;
    case 'model_slug':
    case 'url_seg':
      if (val === '.' || val === '..') return false;
      for (let i = 0; i < val.length; i++) {
        const c = val.charCodeAt(i);
        if (!isAsciiAlnum(c) && c !== 95 && c !== 45 && c !== 46 && c !== 58 && c !== 126) return false;
      }
      return true;
    case 'npm_scope':
      return /^@[a-z0-9-~][a-z0-9-._~]*$/i.test(val);
    case 'npm_pkg':
      return /^[a-z0-9-~][a-z0-9-._~]*$/i.test(val);
    case 'at_handle':
      return val.length >= 2 && val.startsWith('@') && !val.includes('/') && !val.includes(' ');
    case 'socrata_4x4':
      return isValidSocrata4x4(val);
    case 'cve_id':
      return /^CVE-\d{4}-\d{4,}$/i.test(val);
    case 'openalex_work':
      return /^W\d{5,15}$/i.test(val);
    case 'pmc_id':
      return /^PMC\d+$/i.test(val);
    case 'nct_id':
      return /^NCT\d{8}$/i.test(val);
    case 'arxiv_id':
      return /^[A-Za-z0-9._/-]{4,64}$/.test(val) && !val.includes('..');
    case 'doi_rest':
      return isValidDoiRest(val);
    case 'safe_subpath':
      return isValidSafeSubpath(val);
    default:
      return false;
  }
}

function safeDecodeSeg(s: string): string | null {
  try {
    return decodeURIComponent(s);
  } catch {
    return null;
  }
}

function matchesHostPatternLinear(host: string, rawPat: string): boolean {
  const pat = rawPat.trim().toLowerCase();
  if (!pat) return false;
  if (!pat.includes('*')) return host === pat;
  if (pat.startsWith('*.') && !pat.slice(2).includes('*')) {
    const suf = pat.slice(1); // `.example.com`
    return host.endsWith(suf) && host.length > suf.length;
  }
  if (pat.endsWith('.*') && !pat.slice(0, -2).includes('*')) {
    const pre = pat.slice(0, -1); // `gitlab.`
    return host.startsWith(pre) && host.length > pre.length;
  }
  // Multi-wildcard linear segment scan (e.g. `*.fa.*oraclecloud.com`, `data.*.gov`)
  const parts = pat.split('*');
  if (parts[0] && !host.startsWith(parts[0])) return false;
  if (parts[parts.length - 1] && !host.endsWith(parts[parts.length - 1]!)) return false;
  let cursor = parts[0]?.length ?? 0;
  const endBound = host.length - (parts[parts.length - 1]?.length ?? 0);
  if (cursor > endBound) return false;
  for (let i = 1; i < parts.length - 1; i++) {
    const mid = parts[i]!;
    if (!mid) continue;
    const idx = host.indexOf(mid, cursor);
    if (idx === -1 || idx + mid.length > endBound) return false;
    cursor = idx + mid.length;
  }
  return true;
}

function isLikelySocrataHost(host: string): boolean {
  if (KNOWN_SOCRATA_HOSTS.has(host)) return true;
  if (host.endsWith('.socrata.com') && host.length > '.socrata.com'.length) return true;
  return /^data\.[a-z0-9-]+\.(?:gov|org|us)$/i.test(host);
}

function isArcgisRestLayerPath(pathname: string): boolean {
  const clean = pathname.replace(/\/+$/, '');
  const lower = clean.toLowerCase();
  const restIdx = lower.indexOf('/rest/services/');
  if (restIdx === -1) return false;
  const tail = clean.slice(restIdx + '/rest/services/'.length);
  const segs = tail.split('/').filter(Boolean);
  if (segs.length < 2) return false;
  const last = segs[segs.length - 1]!.toLowerCase();
  const prev = segs[segs.length - 2]!.toLowerCase();
  if (last === 'featureserver' || last === 'mapserver') return true;
  if (/^\d+$/.test(last) && (prev === 'featureserver' || prev === 'mapserver')) return segs.length >= 3;
  return false;
}

export function matchDeclarativeRoute(
  spec: DeclarativeMatchSpec,
  ctx: { url: URL; host: string; path: string; parts: string[] },
): Record<string, string> | null {
  if (spec.anyOf && spec.anyOf.length > 0) {
    for (const sub of spec.anyOf) {
      const m = matchDeclarativeRoute(sub, ctx);
      if (m) return m;
    }
    return null;
  }

  const host = ctx.host.toLowerCase();
  if (spec.hosts && spec.hosts.length > 0) {
    if (!spec.hosts.some((hp) => matchesHostPatternLinear(host, hp))) return null;
  }
  if (spec.excludeHosts && spec.excludeHosts.length > 0) {
    if (spec.excludeHosts.some((hp) => matchesHostPatternLinear(host, hp))) return null;
  }
  if (spec.socrataHost && !isLikelySocrataHost(host)) {
    return null;
  }

  const params: Record<string, string> = {
    host,
    origin: ctx.url.origin,
    ...(spec.defaults ?? {}),
  };

  if (spec.hostSubdomain) {
    const suf = spec.hostSubdomain.suffix.toLowerCase();
    if (!host.endsWith(suf) || host.length <= suf.length) return null;
    let sub = host.slice(0, -suf.length);
    if (spec.hostSubdomain.stripOptional2LetterRegion) {
      const dotIdx = sub.lastIndexOf('.');
      if (dotIdx > 0 && sub.length - dotIdx - 1 === 2) {
        sub = sub.slice(0, dotIdx);
      }
    }
    if (!/^[a-z0-9-]+$/i.test(sub)) return null;
    if (spec.hostSubdomain.reserved?.some((r) => r.toLowerCase() === sub.toLowerCase())) return null;
    params[spec.hostSubdomain.param] = sub;
  }

  if (spec.hostMap) {
    const normH = spec.hostMap.stripWww ? host.replace(/^www\./, '') : host;
    let mapped = spec.hostMap.exact?.[normH] ?? '';
    if (!mapped && spec.hostMap.suffixSubdomain) {
      const suf = spec.hostMap.suffixSubdomain.toLowerCase();
      if (normH.endsWith(suf) && normH.length > suf.length) {
        const sub = normH.slice(0, -suf.length);
        if (/^[a-z0-9.-]+$/i.test(sub)) mapped = sub;
      }
    }
    if (!mapped) return null;
    params[spec.hostMap.param] = mapped;
  }

  const reqPath = ctx.path ?? ctx.url?.pathname ?? '/';
  const pathLower = reqPath.toLowerCase();
  if (spec.pathPrefix && !pathLower.startsWith(spec.pathPrefix.toLowerCase())) return null;
  if (spec.pathSuffix && !pathLower.endsWith(spec.pathSuffix.toLowerCase())) return null;
  if (spec.pathEquals && spec.pathEquals.length > 0) {
    if (!spec.pathEquals.some((pe) => pe.toLowerCase() === pathLower)) return null;
  }
  if (spec.arcgisRestLayer && !isArcgisRestLayerPath(reqPath)) return null;

  let activeParts = Array.isArray(ctx.parts) ? ctx.parts : reqPath.split('/').filter(Boolean);
  if (spec.optionalLeadingLocale && activeParts.length >= 2 && /^[a-z]{2}(?:-[A-Za-z]{2,4})?$/.test(activeParts[0]!)) {
    activeParts = activeParts.slice(1);
  }

  if (spec.minSegments !== undefined && activeParts.length < spec.minSegments) return null;
  if (spec.maxSegments !== undefined && activeParts.length > spec.maxSegments) return null;

  if (spec.reservedFirstSegment && activeParts.length > 0) {
    const firstLower = (safeDecodeSeg(activeParts[0]!) ?? activeParts[0]!).toLowerCase();
    if (spec.reservedFirstSegment.some((r) => r.toLowerCase() === firstLower)) return null;
  }

  if (spec.excludeSegmentSuffixes && spec.excludeSegmentSuffixes.length > 0) {
    for (const rp of activeParts) {
      const dec = (safeDecodeSeg(rp) ?? rp).toLowerCase();
      if (spec.excludeSegmentSuffixes.some((suf) => dec.endsWith(suf.toLowerCase()))) return null;
    }
  }

  if (spec.allSegmentsCharset) {
    if (activeParts.length === 0) return null;
    for (const rp of activeParts) {
      const dec = safeDecodeSeg(rp);
      if (dec === null || !validateDeclarativeParam(dec, spec.allSegmentsCharset, undefined, undefined, 1, 160)) {
        return null;
      }
    }
    params.joinedPath = activeParts.map((p) => safeDecodeSeg(p) ?? p).join('/');
  }

  if (spec.pathContainsSegment) {
    const want = spec.pathContainsSegment.toLowerCase();
    if (!activeParts.some((p) => (safeDecodeSeg(p) ?? p).toLowerCase() === want)) return null;
  }

  if (spec.splitOnSegment) {
    const sp = spec.splitOnSegment;
    const idx = activeParts.findIndex((p) => (safeDecodeSeg(p) ?? p) === sp.delimiter);
    const minLeft = sp.leftMinSegs ?? 1;
    if (idx < minLeft) return null;
    const leftDecoded: string[] = [];
    for (let i = 0; i < idx; i++) {
      const d = safeDecodeSeg(activeParts[i]!);
      if (!d) return null;
      leftDecoded.push(d);
    }
    const leftVal = leftDecoded.join('/');
    if (!isValidSafeSubpath(leftVal)) return null;
    params[sp.leftParam] = leftVal;

    let rightStart = idx + 1;
    if (sp.afterLiteral) {
      if ((safeDecodeSeg(activeParts[rightStart] ?? '') ?? '') !== sp.afterLiteral) return null;
      rightStart++;
    }
    const minTail = sp.tailParam ? 2 : 1;
    if (activeParts.length < rightStart + minTail) return null;
    if (sp.rightParam) {
      const rightDecoded: string[] = [];
      for (let i = rightStart; i < activeParts.length; i++) {
        const d = safeDecodeSeg(activeParts[i]!);
        if (!d) return null;
        rightDecoded.push(d);
      }
      const rightVal = rightDecoded.join('/');
      if (!isValidSafeSubpath(rightVal)) return null;
      params[sp.rightParam] = rightVal;
    }
    if (sp.tailParam) {
      const tailDecoded: string[] = [];
      for (let i = rightStart + 1; i < activeParts.length; i++) {
        const d = safeDecodeSeg(activeParts[i]!);
        if (!d) return null;
        tailDecoded.push(d);
      }
      const tailVal = tailDecoded.join('/');
      if (!isValidSafeSubpath(tailVal)) return null;
      params[sp.tailParam] = tailVal;
    }
  }

  if (spec.scanSegment) {
    const sc = spec.scanSegment;
    let candidateRaw: string | undefined;
    if (sc.lastOrBeforeLiteral) {
      if (activeParts.length === 0) return null;
      const lastDec = safeDecodeSeg(activeParts[activeParts.length - 1]!) ?? '';
      if (lastDec.toLowerCase() === sc.lastOrBeforeLiteral.toLowerCase()) {
        if (activeParts.length < 2) return null;
        candidateRaw = activeParts[activeParts.length - 2];
      } else {
        candidateRaw = activeParts[activeParts.length - 1];
      }
    } else if (sc.afterLiteral) {
      const wantLit = sc.afterLiteral.toLowerCase();
      const litIdx = activeParts.findIndex((p) => (safeDecodeSeg(p) ?? p).toLowerCase() === wantLit);
      if (litIdx === -1 || !activeParts[litIdx + 1]) return null;
      candidateRaw = activeParts[litIdx + 1];
    } else {
      for (const rp of activeParts) {
        const dec = safeDecodeSeg(rp);
        if (dec && validateDeclarativeParam(dec, sc.charset, undefined, undefined, sc.minLen, sc.maxLen)) {
          candidateRaw = rp;
          break;
        }
      }
    }
    if (!candidateRaw) return null;
    let dec = safeDecodeSeg(candidateRaw);
    if (dec === null) return null;
    if (sc.stripPrefix && dec.toLowerCase().startsWith(sc.stripPrefix.toLowerCase())) {
      dec = dec.slice(sc.stripPrefix.length);
    }
    if (sc.stripSuffix && dec.toLowerCase().endsWith(sc.stripSuffix.toLowerCase())) {
      dec = dec.slice(0, -sc.stripSuffix.length);
    }
    if (!validateDeclarativeParam(dec, sc.charset, undefined, undefined, sc.minLen, sc.maxLen)) return null;
    params[sc.param] = applyParamTransform(dec, sc.transform);
  }

  if (spec.pathSegments !== undefined) {
    const segSpecs = spec.pathSegments;
    const minRequired = segSpecs.filter((s) => !(typeof s === 'object' && s.optional)).length;
    const lastSpec = segSpecs[segSpecs.length - 1];
    const hasGreedy = Boolean(lastSpec && typeof lastSpec === 'object' && lastSpec.greedy);
    const exact = spec.exactSegments ?? true;

    if (hasGreedy) {
      if (activeParts.length < minRequired) return null;
    } else if (exact) {
      if (activeParts.length < minRequired || activeParts.length > segSpecs.length) return null;
    } else {
      if (activeParts.length < minRequired) return null;
    }

    for (let idx = 0; idx < segSpecs.length; idx++) {
      const seg = segSpecs[idx]!;
      if (idx >= activeParts.length) {
        if (typeof seg === 'object' && seg.optional) continue;
        return null;
      }
      if (typeof seg === 'string') {
        const dec = safeDecodeSeg(activeParts[idx]!);
        if (dec === null || dec !== seg) return null;
        continue;
      }
      const rawCandidate =
        seg.greedy && idx === segSpecs.length - 1 ? activeParts.slice(idx).join('/') : activeParts[idx]!;
      let decoded = safeDecodeSeg(rawCandidate);
      if (decoded === null) return null;
      if (seg.stripPrefix && decoded.toLowerCase().startsWith(seg.stripPrefix.toLowerCase())) {
        decoded = decoded.slice(seg.stripPrefix.length);
      }
      if (seg.stripSuffix && decoded.toLowerCase().endsWith(seg.stripSuffix.toLowerCase())) {
        decoded = decoded.slice(0, -seg.stripSuffix.length);
      }
      if (!validateDeclarativeParam(decoded, seg.charset, seg.allowValues, seg.reserved, seg.minLen, seg.maxLen)) {
        return null;
      }
      params[seg.param] = applyParamTransform(decoded, seg.transform);
    }
  }

  if (spec.queryParams && spec.queryParams.length > 0) {
    for (const qp of spec.queryParams) {
      const keys = qp.names && qp.names.length > 0 ? qp.names : qp.name ? [qp.name] : [];
      let qVal = '';
      for (const k of keys) {
        const got = ctx.url.searchParams.get(k);
        if (got !== null && got !== '') {
          qVal = got;
          break;
        }
      }
      if (!qVal) {
        if (qp.optional) {
          if (qp.default !== undefined) params[qp.param] = qp.default;
          continue;
        }
        return null;
      }
      if (!validateDeclarativeParam(qVal, qp.charset, undefined, undefined, qp.minLen, qp.maxLen)) {
        return null;
      }
      params[qp.param] = applyParamTransform(qVal, qp.transform);
    }
  }

  if (spec.derivedParams) {
    for (const [targetKey, dSpec] of Object.entries(spec.derivedParams)) {
      const srcVal = params[dSpec.fromParam] ?? '';
      params[targetKey] = applyParamTransform(srcVal, dSpec.transform);
    }
  }

  return params;
}

export function isSafeDeclarativeTwinUrl(fetchUrl: string): boolean {
  if (!fetchUrl.startsWith('https://')) return false;
  if (/[\s\\]/.test(fetchUrl)) return false;
  try {
    const u = new URL(fetchUrl);
    if (u.protocol !== 'https:' || u.username || u.password || u.hash) return false;
    if (u.port && u.port !== '443') return false;
    const h = u.hostname.toLowerCase().replace(/\.+$/, '');
    if (
      !h ||
      h === 'localhost' ||
      h.endsWith('.localhost') ||
      h.endsWith('.local') ||
      h.endsWith('.internal') ||
      h.endsWith('.nip.io') ||
      h.endsWith('.sslip.io') ||
      h.endsWith('.xip.io') ||
      !h.includes('.') ||
      h.includes(':')
    ) {
      return false;
    }
    const labels = h.split('.');
    if (labels.some((l) => !l)) return false;
    const tld = labels[labels.length - 1]!;
    // Reject all IPv4, octal/hex IPv4, and shorthand numeric hosts (`127.1`, `0x7f.1`, `127.0.0.1`)
    if (tld.charCodeAt(0) >= 48 && tld.charCodeAt(0) <= 57) return false;
    return true;
  } catch {
    return false;
  }
}

function buildResolvedTwinUrl(route: DeclarativeRouteSpec, ctx: TwinMatchContext, params: Record<string, string>): string | null {
  const twin = route.twin;
  let candidateUrlStr = '';

  if (twin.fetchUrl === '{requestUrl}') {
    const cloned = new URL(ctx.url.toString());
    cloned.hash = '';
    cloned.username = '';
    cloned.password = '';
    cloned.hostname = cloned.hostname.toLowerCase().replace(/\.+$/, '');
    if (twin.overridePathIf) {
      const cleanCur = cloned.pathname.replace(/\/+$/, '') || '/';
      if (twin.overridePathIf.matchPaths.some((mp) => (mp.replace(/\/+$/, '') || '/').toLowerCase() === cleanCur.toLowerCase())) {
        cloned.pathname = twin.overridePathIf.newPath;
      }
    }
    if (twin.defaultQueryParams) {
      for (const [k, v] of Object.entries(twin.defaultQueryParams)) {
        if (!cloned.searchParams.has(k)) cloned.searchParams.set(k, v);
      }
    }
    if (twin.setQueryParams) {
      for (const [k, v] of Object.entries(twin.setQueryParams)) {
        cloned.searchParams.set(k, v);
      }
    }
    candidateUrlStr = cloned.toString();
  } else {
    const rawSet = new Set(twin.rawPathParams ?? []);
    const cleanHost = ctx.host.toLowerCase().replace(/\.+$/, '');
    candidateUrlStr = expandTemplate(twin.fetchUrl, (key) => {
      if (key === 'host') return cleanHost;
      if (key === 'origin') return `https://${cleanHost}`;
      if (key === 'baseCleanUrl') return `https://${cleanHost}${ctx.path.replace(/\/+$/, '')}`;
      const val = params[key] ?? '';
      if (rawSet.has(key)) {
        return val
          .split('/')
          .filter((seg) => seg !== '' && seg !== '.' && seg !== '..')
          .map((seg) => encodeURIComponent(seg))
          .join('/');
      }
      return encodeURIComponent(val);
    });
  }

  return isSafeDeclarativeTwinUrl(candidateUrlStr) ? candidateUrlStr : null;
}

function getByDotPath(root: unknown, dotPath: string): unknown {
  if (!dotPath || root === null || root === undefined) return root;
  let cur: unknown = root;
  for (const seg of dotPath.split('.')) {
    if (cur === null || cur === undefined || typeof cur !== 'object') return undefined;
    if (Array.isArray(cur)) {
      const idx = Number(seg);
      if (!Number.isInteger(idx) || idx < 0 || idx >= cur.length) return undefined;
      cur = cur[idx];
    } else {
      cur = (cur as Record<string, unknown>)[seg];
    }
  }
  return cur;
}

function scalarToString(val: unknown): string {
  if (typeof val === 'string') return val;
  if (typeof val === 'number' && Number.isFinite(val)) return String(val);
  if (typeof val === 'boolean') return val ? 'true' : 'false';
  return '';
}

function toFiniteNumber(val: unknown): number | null {
  if (typeof val === 'number') return Number.isFinite(val) ? val : null;
  if (typeof val === 'string') {
    const trimmed = val.trim();
    if (!trimmed) return null;
    const n = Number(trimmed);
    return Number.isFinite(n) ? n : null;
  }
  return null;
}

function formatBytesHuman(val: unknown): string {
  const bytes = toFiniteNumber(val);
  if (bytes === null || bytes <= 0) return '-';
  if (bytes > 1_048_576) return `${(bytes / 1_048_576).toFixed(1)} MB`;
  return `${Math.round(bytes / 1024)} KB`;
}

function reconstructInvertedAbstract(inv: unknown): string {
  if (!inv || typeof inv !== 'object' || Array.isArray(inv)) return '';
  const words: string[] = [];
  let entries = 0;
  for (const [token, positions] of Object.entries(inv as Record<string, unknown>)) {
    if (++entries > 5_000) break;
    if (!Array.isArray(positions)) continue;
    for (const pos of positions) {
      if (typeof pos === 'number' && Number.isInteger(pos) && pos >= 0 && pos < 10_000) {
        words[pos] = token;
      }
    }
  }
  return words.filter(Boolean).join(' ').trim();
}

function extractGitlabBlobPlainSource(htmlVal: unknown): string {
  if (typeof htmlVal !== 'string' || !htmlVal) return '';
  const preInner = findElementInnerLinear(htmlVal, 'pre');
  const codeInner = preInner ? (findElementInnerLinear(preInner, 'code') ?? preInner) : null;
  if (!codeInner) return '';
  let stripped = '';
  let i = 0;
  const n = codeInner.length;
  let cachedGt = codeInner.indexOf('>');
  while (i < n) {
    if (codeInner.charCodeAt(i) !== 60 /* '<' */) {
      stripped += codeInner[i]!;
      i++;
      continue;
    }
    if (cachedGt < i + 1) {
      cachedGt = codeInner.indexOf('>', i + 1);
    }
    if (cachedGt === -1) {
      stripped += codeInner.slice(i);
      break;
    }
    i = cachedGt + 1;
  }
  const plain = decodeBasicEntities(stripped.replace(/&#x000A;/gi, '\n'))
    .replace(/\r\n/g, '\n')
    .trimEnd();
  return plain.trim() ? plain : '';
}

function cleanStackExchangeMarkdown(rawMd: string): string {
  const decoded = decodeBasicEntities(rawMd.replace(/\r\n/g, '\n'));
  const lines = decoded.split('\n');
  let inFence = false;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!;
    if (/^\s*(?:```|~~~)/.test(line)) {
      inFence = !inFence;
      continue;
    }
    if (inFence || /^(?: {4}|\t)/.test(line)) continue;
    lines[i] = line
      .replace(/^(\s*\[\d+\]:\s+)\/\//, '$1https://')
      .replace(/<\/?(?:sub|sup|kbd)\s*>/gi, '');
  }
  return lines.join('\n').trim();
}

function lookupPubchemTocField(rootObj: Record<string, unknown>, targetHeading: string): string {
  let found = '';
  const walk = (secs: unknown, depth: number) => {
    if (found || depth > 8 || !Array.isArray(secs)) return;
    for (const rawS of secs) {
      if (found || !rawS || typeof rawS !== 'object') continue;
      const s = rawS as Record<string, unknown>;
      if (s.TOCHeading === targetHeading) {
        const infoArr = Array.isArray(s.Information) ? (s.Information as Array<Record<string, unknown>>) : [];
        const valObj = infoArr[0]?.Value as Record<string, unknown> | undefined;
        const strArr = Array.isArray(valObj?.StringWithMarkup)
          ? (valObj.StringWithMarkup as Array<Record<string, unknown>>)
          : [];
        const firstStr = typeof strArr[0]?.String === 'string' ? strArr[0].String.trim() : '';
        if (firstStr) {
          found = firstStr;
          return;
        }
      }
      if (s.Section) walk(s.Section, depth + 1);
    }
  };
  walk(rootObj.Section, 0);
  return found;
}

function isLikelyHtmlSoft404(rawBody: string): boolean {
  const trimmed = rawBody.trimStart();
  if (!trimmed) return true;
  const prefix = trimmed.slice(0, 64).toLowerCase();
  return prefix.startsWith('<!doctype html') || prefix.startsWith('<html');
}

function stripLeadingYamlFrontmatter(s: string): string {
  const norm = s.replaceAll('\r\n', '\n');
  if (!norm.startsWith('---')) return s;
  const window = norm.slice(0, 1510);
  const closeIdx = window.indexOf('\n---', 3);
  if (closeIdx === -1) return s;
  let afterDash = closeIdx + 4;
  if (afterDash >= norm.length || norm.charCodeAt(afterDash) !== 10) return s;
  while (afterDash < norm.length && norm.charCodeAt(afterDash) === 10) {
    afterDash++;
  }
  return norm.slice(afterDash);
}

function stripXmlNamespaceTagsLinear(input: string): string {
  if (!input.includes('<')) return input;
  let out = '';
  let i = 0;
  const n = input.length;
  let cachedGt = input.indexOf('>');
  if (cachedGt === -1) return input;
  while (i < n) {
    if (input.charCodeAt(i) !== 60 /* '<' */) {
      out += input[i]!;
      i++;
      continue;
    }
    if (cachedGt < i + 1) {
      cachedGt = input.indexOf('>', i + 1);
      if (cachedGt === -1) {
        out += input.slice(i);
        break;
      }
    }
    const inner = input.slice(i + 1, cachedGt).trim().toLowerCase();
    if (inner.startsWith('jats:') || inner.startsWith('/jats:')) {
      out += ' ';
    } else {
      out += input.slice(i, cachedGt + 1);
    }
    i = cachedGt + 1;
  }
  return out;
}

function formatJatsAbstract(raw: string): string {
  const withoutJats = stripXmlNamespaceTagsLinear(raw);
  let cleaned = stripTagsInline(withoutJats);
  if (cleaned.length >= 9 && cleaned.slice(0, 8).toLowerCase() === 'abstract') {
    const nextCode = cleaned.charCodeAt(8);
    if (nextCode === 32 || nextCode === 9) {
      cleaned = cleaned.slice(9).trim();
    }
  }
  return cleaned;
}

function collapseNewlinesWithIndent(s: string, indent: string): string {
  let out = '';
  let prevNl = false;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c === 13) continue;
    if (c === 10) {
      if (!prevNl) {
        out += `\n${indent}`;
        prevNl = true;
      }
      continue;
    }
    prevNl = false;
    out += s[i]!;
  }
  return out;
}

function stripLeadingMarkdownH1(md: string): string {
  const norm = md.replace(/\r\n/g, '\n');
  if (!norm.startsWith('# ')) return md;
  const nl = norm.indexOf('\n');
  if (nl === -1) return md;
  return norm.slice(nl + 1).trim() || md;
}

const defaultHtmlToMd: HtmlFragmentConverter = (frag) => ({
  markdown: stripTagsInline(frag),
  links: [],
});

function formatExtractedJsonValue(
  raw: unknown,
  spec: DeclarativeVarSpec,
  origUrl: string,
  htmlToMd: HtmlFragmentConverter,
): string {
  if (raw === null || raw === undefined) return '';

  switch (spec.format) {
    case 'int_comma': {
      const n = toFiniteNumber(raw);
      return n !== null ? Math.round(n).toLocaleString('en-US') : '';
    }
    case 'usd_compact':
      return formatUsdCompact(raw);
    case 'usd_per_million_tokens': {
      const n = toFiniteNumber(raw);
      if (n === null || n < 0) return '';
      if (n === 0) return '$0.00 / 1M tokens';
      return `$${(n * 1_000_000).toFixed(2)} / 1M tokens`;
    }
    case 'date_parts': {
      if (!Array.isArray(raw) || raw.length === 0) return '';
      const parts: string[] = [];
      for (let idx = 0; idx < raw.length; idx++) {
        const n = toFiniteNumber(raw[idx]);
        if (n === null) continue;
        const iv = Math.trunc(n);
        parts.push(idx === 0 ? String(iv) : String(iv).padStart(2, '0'));
      }
      return parts.join('-');
    }
    case 'array_len':
      return Array.isArray(raw) ? String(raw.length) : '';
    case 'array_len_comma':
      return Array.isArray(raw) ? raw.length.toLocaleString('en-US') : '';
    case 'object_keys': {
      if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return '';
      const allKeys = Object.keys(raw as Record<string, unknown>);
      if (allKeys.length === 0) return '';
      const cap = spec.limit && spec.limit > 0 ? allKeys.slice(0, spec.limit) : allKeys.slice(0, 200);
      const wrapped = spec.itemWrap ? cap.map((k) => `${spec.itemWrap}${k}${spec.itemWrap}`) : cap;
      return spec.join !== undefined ? wrapped.join(spec.join) : wrapped.join(', ');
    }
    case 'epoch_sec_date': {
      const n = toFiniteNumber(raw);
      if (n === null || n <= 0) return '';
      try {
        return new Date(n * 1000).toISOString().slice(0, 10);
      } catch {
        return '';
      }
    }
    case 'bytes_human':
      return formatBytesHuman(raw);
    case 'inverted_abstract':
      return reconstructInvertedAbstract(raw);
    case 'gitlab_blob_html':
      return extractGitlabBlobPlainSource(raw);
    case 'html_to_md': {
      const s = typeof raw === 'string' ? raw : '';
      return s.trim() ? htmlToMd(s, origUrl).markdown.trim() : '';
    }
    case 'se_markdown': {
      const s = typeof raw === 'string' ? raw : '';
      return s.trim() ? cleanStackExchangeMarkdown(s) : '';
    }
    case 'fiscal_mmdd': {
      const s = typeof raw === 'string' ? raw.trim() : '';
      return s.length === 4 ? `${s.slice(0, 2)}/${s.slice(2)}` : '';
    }
    default:
      break;
  }

  if (Array.isArray(raw)) {
    const hardCap = spec.limit && spec.limit > 0 ? Math.min(500, spec.limit) : 500;
    const sliced = raw.slice(0, hardCap);
    const items: string[] = [];
    for (const el of sliced) {
      let itemStr = '';
      if (spec.subFieldsJoin) {
        if (el && typeof el === 'object' && !Array.isArray(el)) {
          const obj = el as Record<string, unknown>;
          const subParts = spec.subFieldsJoin.fields
            .map((f) => obj[f])
            .filter((x): x is string => typeof x === 'string' && x.length > 0);
          itemStr =
            subParts.length > 0
              ? subParts.join(spec.subFieldsJoin.sep)
              : spec.subFieldsJoin.fallbackField
                ? scalarToString(obj[spec.subFieldsJoin.fallbackField])
                : '';
        }
      } else if (spec.subField) {
        if (el && typeof el === 'object') {
          itemStr = scalarToString(getByDotPath(el, spec.subField));
        }
      } else {
        itemStr = scalarToString(el);
      }
      if (itemStr) {
        items.push(spec.itemWrap ? `${spec.itemWrap}${itemStr}${spec.itemWrap}` : itemStr);
      }
    }
    if (items.length === 0) return '';
    return spec.join !== undefined ? items.join(spec.join) : items[0]!;
  }

  return scalarToString(raw);
}

function renderTableColumnCell(
  itemObj: Record<string, unknown>,
  col: DeclarativeTableColumn,
  rowLookup: (k: string) => string,
): string {
  if (col.template !== undefined) {
    const rendered = stripInvisibleAndNul(expandTemplate(col.template, rowLookup).trim());
    if (!rendered) return '-';
    return col.code ? `\`${rendered}\`` : rendered;
  }

  if (col.format === 'paired_percent') {
    const rawOutcomes = col.outcomesField ? itemObj[col.outcomesField] : undefined;
    const rawPrices = col.pricesField ? itemObj[col.pricesField] : undefined;
    const parsedOutcomes = typeof rawOutcomes === 'string' ? parseJsonValue(rawOutcomes) : rawOutcomes;
    const parsedPrices = typeof rawPrices === 'string' ? parseJsonValue(rawPrices) : rawPrices;
    const outcomes = Array.isArray(parsedOutcomes)
      ? parsedOutcomes.slice(0, 50).map(scalarToString)
      : (col.defaultOutcomes ?? []);
    const prices = Array.isArray(parsedPrices) ? parsedPrices.slice(0, 50).map((p) => toFiniteNumber(p)) : [];
    const summary = outcomes
      .map((o, idx) => {
        const pr = prices[idx];
        return pr !== null && pr !== undefined ? `${o}: ${(pr * 100).toFixed(1)}%` : o;
      })
      .join(' · ');
    return summary || '-';
  }

  let val = '';
  for (const p of col.paths ?? []) {
    const raw = getByDotPath(itemObj, p);
    if (raw === null || raw === undefined) continue;
    if (col.format === 'usd_compact') {
      val = formatUsdCompact(raw);
    } else if (col.format === 'int_comma') {
      const n = toFiniteNumber(raw);
      val = n !== null ? Math.round(n).toLocaleString('en-US') : '';
    } else if (col.format === 'bytes_human') {
      val = formatBytesHuman(raw);
    } else if (col.format === 'strip_tags') {
      val = stripTagsInline(scalarToString(raw));
    } else {
      val = scalarToString(raw).trim();
    }
    if (val) break;
  }
  if (col.stripPrefix && val.toLowerCase().startsWith(col.stripPrefix.toLowerCase())) {
    val = val.slice(col.stripPrefix.length);
  }
  if (!val && col.fallbackVar) {
    val = rowLookup(col.fallbackVar).trim();
  }
  val = stripInvisibleAndNul(val);
  if (col.sliceMax && col.sliceMax > 0 && val.length > col.sliceMax) {
    val = val.slice(0, col.sliceMax);
  }
  if (!val) return '-';
  return col.code ? `\`${val}\`` : val;
}

function formatXmlTwinOrHtml(
  rawXml: string,
  xmlSpec: DeclarativeXmlSpec,
  params: Record<string, string>,
): TwinFormattedDoc | null {
  const cleanXml = stripInvisibleAndNul(rawXml.replace(/^\ufeff/, ''));
  if (!cleanXml.trim()) return null;

  if (xmlSpec.requireAnyTags && xmlSpec.requireAnyTags.length > 0) {
    const head = cleanXml.slice(0, 24_000).toLowerCase();
    const ok = xmlSpec.requireAnyTags.some((t) => head.includes(`<${t.toLowerCase()}`));
    if (!ok) return null;
  }

  if (xmlSpec.mode === 'jats_article') {
    const title = sanitizeSingleLineMeta(stripTagsInline(findElementInnerLinear(cleanXml, 'article-title') ?? ''));
    if (!title) return null;
    const abs = stripTagsInline(findElementInnerLinear(cleanXml, 'abstract') ?? '');
    const bodyBlocks: string[] = [];
    const bodyXml = findElementInnerLinear(cleanXml, 'body') ?? '';
    for (const sec of findAllElementInnersLinear(bodyXml, 'sec', undefined, 60)) {
      const secTitle = stripTagsInline(findElementInnerLinear(sec, 'title') ?? '');
      const paras = findAllElementInnersLinear(sec, 'p', undefined, 100)
        .map((p) => stripTagsInline(p))
        .filter(Boolean);
      if (paras.length > 0 && bodyBlocks.length < 30) {
        bodyBlocks.push(secTitle ? `## ${secTitle}\n\n${paras.join('\n\n')}` : paras.join('\n\n'));
      }
    }
    const pmcid = params.pmcid ?? '';
    const sections = [`# ${title}`];
    if (pmcid) sections.push(`- **PMCID**: \`${pmcid}\``);
    if (abs) sections.push(`## Abstract\n\n${abs}`);
    if (bodyBlocks.length > 0) sections.push(...bodyBlocks);
    return {
      title,
      markdown: escapeDangerousRawHtmlOutsideFences(sections.join('\n\n')),
    };
  }

  // `items_table` mode
  const itemTag = xmlSpec.itemTag || 'item';
  const blocks = findAllElementInnersLinear(cleanXml, itemTag, undefined, 500);
  const topVars: Record<string, string> = { ...params, itemCount: String(blocks.length) };

  if (xmlSpec.channelTitleFallbackParam) {
    const chanHeader = cleanXml.slice(0, 4_000);
    const firstItemIdx = chanHeader.toLowerCase().indexOf(`<${itemTag.toLowerCase()}`);
    const chanScope = firstItemIdx !== -1 ? chanHeader.slice(0, firstItemIdx) : chanHeader;
    topVars.channelTitle =
      stripTagsInline(findElementInnerLinear(chanScope, 'title') ?? '') ||
      (params[xmlSpec.channelTitleFallbackParam] ?? '');
  }

  if (xmlSpec.firstItemVars && blocks[0]) {
    for (const [vName, tagList] of Object.entries(xmlSpec.firstItemVars)) {
      let got = '';
      for (const tg of tagList) {
        got = stripTagsInline(extractXmlTagTextLinear(blocks[0], tg));
        if (got) break;
      }
      topVars[vName] = got || params.host || '';
    }
  }

  const title = sanitizeSingleLineMeta(
    expandTemplate(xmlSpec.titleTemplate ?? '{host} ({itemCount})', (k) => topVars[k] ?? ''),
  );
  if (!title) return null;

  if (blocks.length === 0) {
    if (!xmlSpec.emptyText) return null;
    return {
      title,
      markdown: `# ${title}\n\n${xmlSpec.emptyText}`,
      links: [],
    };
  }

  const limit = xmlSpec.limit && xmlSpec.limit > 0 ? Math.min(200, xmlSpec.limit) : 100;
  const rows: string[][] = [];
  const links: string[] = [];
  const records: Array<Record<string, unknown>> = [];

  for (const b of blocks.slice(0, limit)) {
    const rowVars: Record<string, string> = { ...topVars };
    for (const [ivName, ivSpec] of Object.entries(xmlSpec.itemVars ?? {})) {
      let rawVal = '';
      for (const tg of ivSpec.tags) {
        rawVal = stripTagsInline(extractXmlTagTextLinear(b, tg));
        if (rawVal) break;
      }
      if (rawVal && ivSpec.splitColonPart !== undefined) {
        const cIdx = rawVal.indexOf(':');
        if (cIdx > 0) {
          rawVal = ivSpec.splitColonPart === 0 ? rawVal.slice(0, cIdx).trim() : rawVal.slice(cIdx + 1).trim();
        } else if (ivSpec.splitColonPart === 0) {
          rawVal = ivSpec.default ?? '';
        }
      }
      if (ivSpec.sliceMax && ivSpec.sliceMax > 0 && rawVal.length > ivSpec.sliceMax) {
        rawVal = rawVal.slice(0, ivSpec.sliceMax);
      }
      rowVars[ivName] = rawVal || (ivSpec.default ?? '');
    }

    if (xmlSpec.requireItemVar && !(rowVars[xmlSpec.requireItemVar] ?? '').trim()) continue;

    if (xmlSpec.collectLinkVar) {
      const linkVal = (rowVars[xmlSpec.collectLinkVar] ?? '').trim();
      if (linkVal.startsWith('https://')) links.push(linkVal);
    }

    if (xmlSpec.recordFields) {
      const rec: Record<string, unknown> = {};
      for (const [rk, tpl] of Object.entries(xmlSpec.recordFields)) {
        const rv = expandTemplate(tpl, (k) => rowVars[k] ?? '').trim();
        rec[rk] = rv || null;
      }
      records.push(rec);
    }

    rows.push(
      (xmlSpec.columns ?? []).map((c) => {
        if (c.template.includes('[{') && c.template.includes(']({')) {
          // If link URL is not https://, fall back to plain label
          const openBr = c.template.indexOf('[{');
          const midBr = c.template.indexOf('}]({', openBr);
          const endBr = c.template.indexOf('})', midBr);
          if (openBr === 0 && midBr > 2 && endBr === c.template.length - 2) {
            const labelVar = c.template.slice(2, midBr);
            const urlVar = c.template.slice(midBr + 4, endBr);
            const lTxt = rowVars[labelVar] ?? '';
            const uTxt = rowVars[urlVar] ?? '';
            return uTxt.startsWith('https://') ? `[${lTxt}](${uTxt})` : lTxt || '-';
          }
        }
        return expandTemplate(c.template, (k) => rowVars[k] ?? '').trim() || '-';
      }),
    );
  }

  if (rows.length === 0) return null;
  const headers = (xmlSpec.columns ?? []).map((c) => c.header);
  const tableMd = formatGfmTable(headers, rows);

  return {
    title,
    markdown: escapeDangerousRawHtmlOutsideFences(`# ${title}\n\n${tableMd}`),
    links,
    ...(records.length > 0 ? { records } : {}),
    ...(xmlSpec.emitTotals
      ? {
          total: blocks.length,
          returned: rows.length,
          truncated: blocks.length > rows.length,
        }
      : {}),
  };
}

function parseInertiaDataPageJson(rawHtml: string): unknown {
  const doc = parseHtmlDoc(rawHtml);
  const el = doc.first('[data-page]');
  const attr = el?.attr('data-page');
  if (!attr) return null;
  return parseJsonValue(decodeBasicEntities(attr));
}

function parseIcimsPortalHtml(
  rawHtml: string,
  origUrl: string,
  htmlToMd: HtmlFragmentConverter,
): TwinFormattedDoc | null {
  let u: URL;
  try {
    u = new URL(origUrl);
  } catch {
    return null;
  }

  const hostSlug = u.hostname.split('.')[0] ?? u.hostname;
  const isSingleJob = /\/jobs\/\d+(?:\/|$)/i.test(u.pathname);
  const doc = parseHtmlDoc(rawHtml);

  if (isSingleJob) {
    const ldObjects = extractJsonLdObjects(rawHtml);
    const jobLd = ldObjects.find((o) => /JobPosting/i.test(String(o['@type'] ?? '')));

    const title = sanitizeSingleLineMeta(
      (typeof jobLd?.title === 'string' ? stripTagsInline(jobLd.title) : '') ||
        doc.text('h1.iCIMS_Header') ||
        doc.text('h1'),
    );
    if (!title) return null;

    const orgObj = jobLd?.hiringOrganization as Record<string, unknown> | string | undefined;
    const company = sanitizeSingleLineMeta(
      (typeof orgObj === 'string'
        ? stripTagsInline(orgObj)
        : typeof orgObj?.name === 'string'
          ? stripTagsInline(orgObj.name)
          : '') || hostSlug,
    );

    const rawLocs = Array.isArray(jobLd?.jobLocation)
      ? jobLd.jobLocation
      : jobLd?.jobLocation
        ? [jobLd.jobLocation]
        : [];
    const locations: string[] = [];
    for (const loc of rawLocs) {
      if (loc && typeof loc === 'object') {
        const addr = ((loc as Record<string, unknown>).address ?? loc) as Record<string, unknown>;
        const parts = [addr.addressLocality, addr.addressRegion, addr.addressCountry]
          .map((x) => (typeof x === 'string' ? x.trim() : ''))
          .filter(Boolean);
        if (parts.length > 0) locations.push(parts.join(', '));
      }
    }

    const descHtml =
      (typeof jobLd?.description === 'string' && jobLd.description.trim() ? jobLd.description : '') ||
      doc.html('div.iCIMS_JobContent') ||
      doc.html('div.iCIMS_InfoMsg_Job');
    const bodyMd = descHtml ? htmlToMd(descHtml, origUrl).markdown.trim() : '';
    if (!bodyMd && !jobLd) return null;

    const posted = typeof jobLd?.datePosted === 'string' ? jobLd.datePosted.slice(0, 10) : '';
    const empType = typeof jobLd?.employmentType === 'string' ? jobLd.employmentType : '';
    const canonicalJobUrl = new URL(u.toString());
    canonicalJobUrl.searchParams.delete('in_iframe');

    const bullets = [`- **Company**: ${company}`];
    if (locations.length > 0) bullets.push(`- **Location**: ${locations.join('; ')}`);
    if (empType) bullets.push(`- **Employment Type**: ${empType}`);
    if (posted) bullets.push(`- **Posted**: ${posted}`);

    return {
      title: `${title} @ ${company}`,
      ...(posted ? { publishedTime: posted } : {}),
      markdown: escapeDangerousRawHtmlOutsideFences(
        [`# ${title} @ ${company}`, bullets.join('\n'), bodyMd].filter(Boolean).join('\n\n'),
      ),
      links: [canonicalJobUrl.toString()],
    };
  }

  const cardsByJobId = new Map<string, HtmlNode>();
  for (const card of doc.select('li.iCIMS_JobCardItem, div.iCIMS_JobCardItem', 200)) {
    for (const cardLink of card.select('a[href*="/jobs/"]', 8)) {
      const href = unescapeHrefUrl(cardLink.attr('href') ?? '');
      const idM = /\/jobs\/(\d+)\//i.exec(href);
      if (idM?.[1] && !cardsByJobId.has(idM[1])) {
        cardsByJobId.set(idM[1], card);
        break;
      }
    }
  }

  interface IcimsCard {
    id: string;
    title: string;
    url: string;
    location: string;
    pay: string;
    postedAt: string;
  }
  const byId = new Map<string, IcimsCard>();

  for (const ao of doc.select('a.iCIMS_Anchor, a[href*="/jobs/"]', 200)) {
    const rawHref = unescapeHrefUrl(ao.attr('href') ?? '');
    const idMatch = /\/jobs\/(\d+)\//i.exec(rawHref);
    if (!idMatch?.[1]) continue;
    const jobId = idMatch[1];
    if (byId.has(jobId)) continue;

    const rawTitleAttr = (ao.attr('title') ?? '').replace(/^\d+\s*-\s*/, '').trim();
    const linkTitle = sanitizeSingleLineMeta(
      (ao.text('h3') || ao.text()).replace(/^(?:Job\s+Title|Title)\s*/i, '').trim() || rawTitleAttr,
    );
    if (!linkTitle) continue;

    let resolvedUrl = '';
    try {
      const targetU = new URL(rawHref, u.origin);
      targetU.searchParams.delete('in_iframe');
      if (targetU.protocol === 'https:') resolvedUrl = targetU.toString();
    } catch {
      continue;
    }
    if (!resolvedUrl) continue;

    let location = '';
    let pay = '';
    let postedAt = '';
    const cardNode = cardsByJobId.get(jobId);
    if (cardNode) {
      for (const span of cardNode.select('span[title]', 12)) {
        const tVal = (span.attr('title') ?? '').trim();
        if (/^\d{1,2}\/\d{1,2}\/\d{4}\b/.test(tVal)) {
          postedAt = tVal.split(/\s+/)[0] ?? tVal;
          break;
        }
      }
      for (const dlPairs of [cardNode.dlMap('div.iCIMS_JobHeaderTag'), cardNode.dlMap()]) {
        for (const [dtTxt, ddTxt] of Object.entries(dlPairs)) {
          if (!ddTxt) continue;
          if (!location && dtTxt.includes('location')) {
            location = ddTxt;
          } else if (!pay && (dtTxt.includes('salary') || dtTxt.includes('pay') || dtTxt.includes('compensation'))) {
            pay = ddTxt;
          }
        }
        if (location && pay) break;
      }
    }

    byId.set(jobId, { id: jobId, title: linkTitle, url: resolvedUrl, location, pay, postedAt });
  }

  const jobs = [...byId.values()];
  if (jobs.length === 0) {
    const plainBody = doc.text();
    const explicitZero =
      /\b(?:no\s+results\s+found|sorry,\s+no\s+jobs|currently\s+no\s+open\s+positions|there\s+are\s+currently\s+no\s+open|0\s+results\s+available)\b/i.test(
        plainBody,
      );
    if (!explicitZero) return null;
    const emptyTitle = `${hostSlug} — iCIMS Career Portal (0 open roles)`;
    return {
      title: emptyTitle,
      markdown: `# ${emptyTitle}\n\nNo open positions currently listed.`,
      links: [],
      records: [],
      total: 0,
      returned: 0,
      truncated: false,
    };
  }

  const plainHeader = doc.text().slice(0, 80_000);
  const pageMatch = /\bPage\s+(\d+)\s+of\s+(\d+)\b/i.exec(plainHeader);
  const curPage = pageMatch?.[1] ? Math.max(1, parseInt(pageMatch[1], 10) || 1) : 1;
  const totalPages = pageMatch?.[2] ? Math.max(1, parseInt(pageMatch[2], 10) || 1) : 1;
  const hasNextRel = doc.first('[rel="next"]') !== null;
  const hasMorePages = curPage < totalPages || (totalPages === 1 && hasNextRel);

  const portalHeading = doc.text('h1.iCIMS_Header');
  const companyLabel = sanitizeSingleLineMeta(
    portalHeading ? portalHeading.replace(/\s*Career\s+Listings\s*$/i, '').trim() || hostSlug : hostSlug,
  );

  const links = jobs.map((j) => j.url);
  const rows = jobs.slice(0, 100).map((j) => [
    `[${j.title}](${j.url})`,
    `\`${j.id}\``,
    j.location || '-',
    j.pay || '-',
  ]);
  const isTruncated = hasMorePages || jobs.length > rows.length;
  const title =
    totalPages > 1
      ? `${companyLabel} — iCIMS Career Portal (Page ${curPage} of ${totalPages}, ${rows.length} shown)`
      : `${companyLabel} — iCIMS Career Portal (${jobs.length} open roles)`;

  return {
    title,
    markdown: `# ${title}\n\n${formatGfmTable(['Role', 'Job ID', 'Location', 'Salary'], rows)}`,
    links,
    records: jobs.map((j) => ({
      id: j.id,
      title: j.title,
      company: companyLabel,
      url: j.url,
      ...(j.location ? { location: j.location, locations: [j.location] } : {}),
      ...(j.pay ? { payRaw: j.pay, salary: j.pay } : {}),
      ...(j.postedAt ? { postedAt: j.postedAt } : {}),
      source: 'icims',
    })),
    ...(!hasMorePages ? { total: jobs.length } : {}),
    returned: rows.length,
    truncated: isTruncated,
    ...(hasMorePages ? { nextCursor: `pr=${curPage}` } : jobs.length > rows.length ? { nextCursor: String(rows.length) } : {}),
  };
}

function formatTextRouteTwin(
  rawBody: string,
  ext: DeclarativeExtractSpec,
  params: Record<string, string>,
  origUrl: string,
  htmlToMd: HtmlFragmentConverter,
): TwinFormattedDoc | null {
  if (ext.icimsPortal) {
    return parseIcimsPortalHtml(rawBody, origUrl, htmlToMd);
  }
  if (ext.xml) {
    return formatXmlTwinOrHtml(rawBody, ext.xml, params);
  }
  if (ext.jsonSource === 'inertia_data_page') {
    const inertiaVal = parseInertiaDataPageJson(rawBody);
    return formatParsedJsonWithSpec(inertiaVal, ext, params, origUrl, htmlToMd);
  }

  const cleanBody = rawBody.replace(/^\ufeff/, '');
  if (isLikelyHtmlSoft404(cleanBody)) return null;
  const sanitized = stripInvisibleAndNul(cleanBody);
  const fallbackTitle = sanitizeSingleLineMeta(
    expandTemplate(ext.titleTemplate ?? '', (k) => params[k] ?? ''),
  );

  if (ext.textMode === 'yaml_frontmatter_card') {
    const card = formatYamlFrontmatterCard(sanitized, fallbackTitle);
    return {
      ...card,
      title: sanitizeSingleLineMeta(card.title),
      ...(card.description ? { description: sanitizeSingleLineMeta(card.description) } : {}),
      markdown: escapeDangerousRawHtmlOutsideFences(card.markdown),
    };
  }
  if (ext.textMode === 'code_or_markdown_by_path') {
    const filePath = ext.pathParam ? (params[ext.pathParam] ?? '') : '';
    const { lang, isMarkdown } = detectFenceLang(filePath);
    if (isMarkdown) {
      const card = formatYamlFrontmatterCard(sanitized, fallbackTitle);
      return {
        ...card,
        title: sanitizeSingleLineMeta(card.title),
        ...(card.description ? { description: sanitizeSingleLineMeta(card.description) } : {}),
        markdown: escapeDangerousRawHtmlOutsideFences(card.markdown),
      };
    }
    return {
      title: fallbackTitle,
      markdown: `# ${fallbackTitle}\n\n${safeFence(sanitized, lang)}`,
    };
  }
  const trimmed = sanitized.trim();
  if (!trimmed) return null;
  const md = fallbackTitle && !trimmed.startsWith('# ') ? `# ${fallbackTitle}\n\n${trimmed}` : trimmed;
  return { title: fallbackTitle, markdown: escapeDangerousRawHtmlOutsideFences(md) };
}

export function formatJsonWithExtractSpec(
  rawBody: string,
  ext: DeclarativeExtractSpec,
  params: Record<string, string>,
  origUrl: string,
  htmlToMd: HtmlFragmentConverter = defaultHtmlToMd,
): TwinFormattedDoc | null {
  if (ext.commerceMode) {
    switch (ext.commerceMode) {
      case 'shopify_product':
        return enrichShopifyProductFromJson({ rawJson: rawBody, productUrl: origUrl, htmlToMd, isAjaxJs: false });
      case 'shopify_product_js':
        return enrichShopifyProductFromJson({ rawJson: rawBody, productUrl: origUrl, htmlToMd, isAjaxJs: true });
      case 'shopify_catalog_page':
        return formatShopifyProductsFeedTwin(rawBody, origUrl);
      case 'woocommerce_catalog_page':
        return formatWcStoreApiListTwin(rawBody, origUrl);
      case 'woocommerce_product':
        return formatWcStoreApiProductTwin(rawBody, origUrl, htmlToMd);
    }
  }

  const parsed = ext.jsonSource === 'inertia_data_page' ? parseInertiaDataPageJson(rawBody) : parseJsonValue(rawBody);
  return formatParsedJsonWithSpec(parsed, ext, params, origUrl, htmlToMd);
}

function formatParsedJsonWithSpec(
  initialVal: unknown,
  ext: DeclarativeExtractSpec,
  params: Record<string, string>,
  origUrl: string,
  htmlToMd: HtmlFragmentConverter,
): TwinFormattedDoc | null {
  let rootVal = initialVal;
  if (rootVal === null || rootVal === undefined) return null;

  if (ext.wrapRootArrayAs && Array.isArray(rootVal)) {
    rootVal = { [ext.wrapRootArrayAs]: rootVal };
  }
  if (ext.unwrapFirstArrayElement && Array.isArray(rootVal)) {
    if (rootVal.length === 0) return null;
    rootVal = rootVal[0];
  }
  if (!rootVal || typeof rootVal !== 'object' || Array.isArray(rootVal)) return null;
  let rootObj = rootVal as Record<string, unknown>;

  if (ext.rootPath) {
    const sub = getByDotPath(rootObj, ext.rootPath);
    if (!sub || typeof sub !== 'object' || Array.isArray(sub)) return null;
    rootObj = sub as Record<string, unknown>;
  }

  if (ext.rejectIfFieldTruthy && Boolean(getByDotPath(rootObj, ext.rejectIfFieldTruthy))) {
    return null;
  }
  if (ext.requireFieldEquals) {
    const got = scalarToString(getByDotPath(rootObj, ext.requireFieldEquals.path));
    if (got !== ext.requireFieldEquals.value) return null;
  }
  if (ext.requireArrayItemField) {
    const checkArr = getByDotPath(rootObj, ext.requireArrayItemField.arrayPath);
    if (!Array.isArray(checkArr)) return null;
    if (checkArr.length > 0) {
      const firstEl = checkArr[0];
      if (!firstEl || typeof firstEl !== 'object' || !getByDotPath(firstEl, ext.requireArrayItemField.field)) {
        return null;
      }
    }
  }

  if (ext.findInArray) {
    const fia = ext.findInArray;
    const arr = getByDotPath(rootObj, fia.arrayPath);
    if (!Array.isArray(arr)) return null;
    const want = expandTemplate(fia.matchTemplate, (k) => params[k] ?? '');
    if (!want) {
      return ext.fallbackExtract ? formatParsedJsonWithSpec(initialVal, ext.fallbackExtract, params, origUrl, htmlToMd) : null;
    }
    const wantLower = want.toLowerCase();
    const wantEnds = fia.endsWithTemplate ? expandTemplate(fia.endsWithTemplate, (k) => params[k] ?? '') : '';
    const mFields = fia.matchFields ?? (fia.matchField ? [fia.matchField] : []);

    const hit = arr.find((el) => {
      if (!el || typeof el !== 'object' || Array.isArray(el)) return false;
      const obj = el as Record<string, unknown>;
      for (const mf of mFields) {
        const got = scalarToString(getByDotPath(obj, mf));
        if (!got) continue;
        if (fia.ignoreCase ? got.toLowerCase() === wantLower : got === want) return true;
      }
      if (fia.endsWithField && wantEnds) {
        const gotEnd = scalarToString(getByDotPath(obj, fia.endsWithField));
        if (gotEnd.endsWith(wantEnds)) return true;
      }
      return false;
    });

    if (!hit || typeof hit !== 'object' || Array.isArray(hit)) {
      return ext.fallbackExtract ? formatParsedJsonWithSpec(initialVal, ext.fallbackExtract, params, origUrl, htmlToMd) : null;
    }
    rootObj = hit as Record<string, unknown>;
  }

  for (const rf of ext.requireFields ?? []) {
    const rv = getByDotPath(rootObj, rf);
    if (typeof rv !== 'string' && typeof rv !== 'number') return null;
    if (typeof rv === 'string' && !rv) return null;
  }
  if (ext.requireAnyFields && ext.requireAnyFields.length > 0) {
    const anyOk = ext.requireAnyFields.some((f) => {
      const v = getByDotPath(rootObj, f);
      return Array.isArray(v) ? v.length > 0 : Boolean(v);
    });
    if (!anyOk) return null;
  }

  const varsMap = ext.vars ?? {};
  const resolved = new Map<string, string>();
  const visiting = new Set<string>();

  const evalVar = (
    spec: DeclarativeVarSpec,
    activeObj: Record<string, unknown>,
    varLookup: (k: string) => string,
  ): string => {
    let val = '';
    if (spec.template !== undefined) {
      const allOk = (spec.whenVars ?? []).every((w) => varLookup(w) !== '');
      const anyOk = !spec.whenAnyVars || spec.whenAnyVars.length === 0 || spec.whenAnyVars.some((w) => varLookup(w) !== '');
      if (allOk && anyOk) {
        val = expandTemplate(spec.template, varLookup);
      } else if (spec.fallbackVar) {
        val = varLookup(spec.fallbackVar);
      }
    } else if (spec.format === 'bool_map') {
      const truthy = (spec.paths ?? []).some((p) => {
        const r = getByDotPath(activeObj, p);
        if (typeof r === 'string' && p.endsWith('exports')) return r.includes('types');
        return Boolean(r);
      });
      val = truthy ? (spec.trueValue ?? 'true') : (spec.falseValue ?? 'false');
    } else if (spec.format === 'pubchem_toc' && spec.tocHeading) {
      val = lookupPubchemTocField(activeObj, spec.tocHeading);
    } else if (spec.nestedSubValues) {
      const nsv = spec.nestedSubValues;
      const outer = getByDotPath(activeObj, nsv.arrayPath);
      if (Array.isArray(outer)) {
        const collected: string[] = [];
        const excl = new Set(nsv.excludeValues ?? []);
        const maxItems = nsv.limit && nsv.limit > 0 ? nsv.limit : 30;
        for (const w of outer.slice(0, 100)) {
          if (!w || typeof w !== 'object') continue;
          const inner = getByDotPath(w, nsv.subArrayField);
          if (!Array.isArray(inner)) continue;
          for (const d of inner.slice(0, 50)) {
            if (!d || typeof d !== 'object') continue;
            const v = scalarToString(getByDotPath(d, nsv.valueField)).trim();
            if (v && !excl.has(v) && !collected.includes(v)) {
              collected.push(v);
              if (collected.length >= maxItems) break;
            }
          }
          if (collected.length >= maxItems) break;
        }
        val = collected.join(nsv.join ?? ', ');
      }
    } else if (spec.findInArrayLang) {
      const fl = spec.findInArrayLang;
      const arr = getByDotPath(activeObj, fl.arrayPath);
      if (Array.isArray(arr)) {
        const exact = arr.find(
          (d) => d && typeof d === 'object' && (d as Record<string, unknown>)[fl.langField] === fl.langValue,
        ) as Record<string, unknown> | undefined;
        const first = arr.find(
          (d) => d && typeof d === 'object' && typeof (d as Record<string, unknown>)[fl.valueField] === 'string',
        ) as Record<string, unknown> | undefined;
        val = scalarToString((exact ?? first)?.[fl.valueField]);
      }
    } else if (spec.dynamicKeyPath) {
      const keyVal = varLookup(spec.dynamicKeyPath.keyVar);
      if (keyVal) {
        const baseObj = getByDotPath(activeObj, spec.dynamicKeyPath.base);
        if (baseObj && typeof baseObj === 'object' && !Array.isArray(baseObj)) {
          let entry = (baseObj as Record<string, unknown>)[keyVal];
          if (spec.dynamicKeyPath.subPath) {
            entry = entry && typeof entry === 'object' ? getByDotPath(entry, spec.dynamicKeyPath.subPath) : undefined;
          }
          val = formatExtractedJsonValue(entry, spec, origUrl, htmlToMd);
        }
      }
    } else {
      for (const p of spec.paths ?? []) {
        const raw = getByDotPath(activeObj, p);
        if (raw === null || raw === undefined) continue;
        if (spec.firstNonMatchingKey) {
          if (typeof raw === 'object' && !Array.isArray(raw)) {
            const keys = Object.keys(raw as Record<string, unknown>);
            val = keys.find((k) => !k.includes(spec.firstNonMatchingKey!)) ?? keys[0] ?? '';
            if (val) break;
          }
          continue;
        }
        const formatted = formatExtractedJsonValue(raw, spec, origUrl, htmlToMd);
        if (spec.excludeEquals && formatted === spec.excludeEquals) continue;
        if (spec.equalsVar) {
          const wantEq = varLookup(spec.equalsVar);
          if (!wantEq || formatted !== wantEq) continue;
        }
        if (formatted !== '') {
          val = formatted;
          break;
        }
      }
    }

    if (val === '') {
      if (spec.fallbackTemplate !== undefined) {
        val = expandTemplate(spec.fallbackTemplate, varLookup);
      } else if (spec.default !== undefined) {
        val = spec.default;
      }
    }
    if (spec.stripPrefix && val.startsWith(spec.stripPrefix)) {
      val = val.slice(spec.stripPrefix.length);
    }
    if (spec.stripSuffix && val.endsWith(spec.stripSuffix)) {
      val = val.slice(0, -spec.stripSuffix.length);
    }
    if (spec.replaceAll && val) {
      val = val.replaceAll(spec.replaceAll.from, spec.replaceAll.to);
    }
    if (spec.stripFrontmatter && val) {
      val = stripLeadingYamlFrontmatter(val);
    }
    if (spec.format === 'strip_leading_h1' && val) {
      val = stripLeadingMarkdownH1(val);
    } else if (spec.format === 'trim') {
      val = val.trim();
    } else if (spec.format === 'strip_tags') {
      val = stripTagsInline(val);
    } else if (spec.format === 'jats_abstract') {
      val = formatJatsAbstract(val);
    }
    if (spec.trim) val = val.trim();
    if (spec.upper) val = val.toUpperCase();
    if (spec.lower) val = val.toLowerCase();
    val = stripInvisibleAndNul(val);
    if (spec.requireHttps && !val.startsWith('https://')) val = '';
    if (spec.requireHttpPrefix && !val.startsWith('http://') && !val.startsWith('https://')) val = '';
    if (spec.sliceMax && spec.sliceMax > 0 && val.length > spec.sliceMax) {
      val = val.slice(0, spec.sliceMax);
    }
    return val;
  };

  function lookup(name: string): string {
    if (resolved.has(name)) return resolved.get(name)!;
    const spec = varsMap[name];
    if (spec) {
      if (visiting.has(name)) return '';
      visiting.add(name);
      const v = evalVar(spec, rootObj, lookup);
      visiting.delete(name);
      resolved.set(name, v);
      return v;
    }
    return params[name] ?? '';
  }

  for (const name of Object.keys(varsMap)) {
    lookup(name);
  }
  for (const reqVar of ext.requireVars ?? []) {
    if (!lookup(reqVar).trim()) return null;
  }

  let title = '';
  if (ext.titleWhenVar) {
    title = lookup(ext.titleWhenVar)
      ? expandTemplate(ext.titleTemplate ?? '', lookup)
      : expandTemplate(ext.titleFallbackTemplate ?? '', lookup);
  } else {
    title = expandTemplate(ext.titleTemplate ?? '', lookup);
    if (!title.trim() && ext.titleFallbackTemplate) {
      title = expandTemplate(ext.titleFallbackTemplate, lookup);
    }
  }
  title = sanitizeSingleLineMeta(title);
  if (!title) return null;

  if (ext.codeByPath) {
    const plain = lookup(ext.codeByPath.sourceVar);
    if (!plain.trim()) return null;
    const fp = params[ext.codeByPath.pathParam] ?? '';
    const { lang, isMarkdown } = detectFenceLang(fp);
    const md =
      isMarkdown && ext.codeByPath.rawIfMarkdown
        ? plain.trim()
        : `# ${title}\n\n${safeFence(plain, lang)}`;
    return {
      title,
      markdown: escapeDangerousRawHtmlOutsideFences(md),
    };
  }

  const collectedLinks: string[] = [];
  const pushLink = (uStr: string) => {
    const clean = uStr.trim();
    if (clean.startsWith('https://') && !/[\s<>]/.test(clean) && !collectedLinks.includes(clean) && collectedLinks.length < 2_000) {
      collectedLinks.push(clean);
    }
  };

  const collectedRecords: Array<Record<string, unknown>> = [];
  let paginationTotal: number | undefined;
  let paginationReturned: number | undefined;
  let paginationTruncated: boolean | undefined;
  let paginationNextCursor: string | undefined;

  const metaParts: string[] = [];
  for (const ml of ext.metaLine ?? []) {
    if (ml.whenVar && !lookup(ml.whenVar)) continue;
    if (ml.unlessVar && lookup(ml.unlessVar)) continue;
    const rendered = expandTemplate(ml.template, lookup).trim();
    if (rendered) {
      metaParts.push(ml.label ? `**${ml.label}**: ${rendered}` : rendered);
    }
  }

  const bulletLines: string[] = [];
  for (const b of ext.bullets ?? []) {
    if (b.whenVar && !lookup(b.whenVar)) continue;
    if (b.unlessVar && lookup(b.unlessVar)) continue;
    const rendered = expandTemplate(b.template, lookup).trim();
    if (rendered) {
      bulletLines.push(b.label ? `- **${b.label}**: ${rendered}` : `- ${rendered}`);
    }
  }
  if (ext.objectLinksPath) {
    const linksObj = getByDotPath(rootObj, ext.objectLinksPath);
    if (linksObj && typeof linksObj === 'object' && !Array.isArray(linksObj)) {
      for (const [label, href] of Object.entries(linksObj as Record<string, unknown>).slice(0, 50)) {
        if (typeof href === 'string' && href.startsWith('https://') && !/[\s<>]/.test(href)) {
          bulletLines.push(`- **${sanitizeSingleLineMeta(label)}**: ${href}`);
        }
      }
    }
  }

  const blockquote =
    ext.blockquoteTemplate && (!ext.blockquoteWhenVar || lookup(ext.blockquoteWhenVar))
      ? expandTemplate(ext.blockquoteTemplate, lookup).trim()
      : '';
  const footerItalic =
    ext.footerItalicTemplate && (!ext.footerItalicWhenVar || lookup(ext.footerItalicWhenVar))
      ? expandTemplate(ext.footerItalicTemplate, lookup).trim()
      : '';

  const intro = ext.introVar ? lookup(ext.introVar).trim() : '';
  const bodyText = ext.bodyVar ? lookup(ext.bodyVar).trim() : '';

  const renderedSections: string[] = [];
  for (const sec of ext.sections ?? []) {
    if (sec.whenVar && !lookup(sec.whenVar)) continue;
    if (sec.unlessVar && lookup(sec.unlessVar)) continue;

    const resolveHeading = (extraVars?: Record<string, string>) => {
      const tpl = sec.headingTemplate ?? sec.heading;
      if (!tpl) return '';
      return sanitizeSingleLineMeta(expandTemplate(tpl, (k) => extraVars?.[k] ?? lookup(k)));
    };

    if (sec.textVar) {
      const txt = lookup(sec.textVar).trim();
      if (txt) {
        const h = resolveHeading();
        renderedSections.push(h ? `## ${h}\n\n${txt}` : txt);
      }
      continue;
    }

    if (sec.treeComments) {
      const tc = sec.treeComments;
      const topChildren = getByDotPath(rootObj, tc.childrenPath);
      if (!Array.isArray(topChildren) || topChildren.length === 0) continue;
      const maxDepth = tc.maxDepth ?? 2;
      const maxItems = Math.min(200, tc.maxItems ?? 60);
      const commentLines: string[] = [];
      const walkTree = (nodes: unknown[], depth: number) => {
        for (const rawNode of nodes) {
          if (commentLines.length >= maxItems) return;
          if (!rawNode || typeof rawNode !== 'object' || Array.isArray(rawNode)) continue;
          const c = rawNode as Record<string, unknown>;
          const cTextHtml = scalarToString(getByDotPath(c, tc.htmlTextPath));
          if (!cTextHtml.trim()) continue;
          const cAuthor = sanitizeSingleLineMeta(scalarToString(getByDotPath(c, tc.authorPath))) || 'user';
          const cMd = htmlToMd(cTextHtml, origUrl).markdown.trim();
          if (cMd) {
            const indent = '  '.repeat(Math.min(4, depth));
            const compact = depth === 0 ? cMd.replace(/\n+/g, `\n${indent}  `) : stripTagsInline(cTextHtml);
            commentLines.push(`${indent}- **${cAuthor}**: ${compact}`);
          }
          if (depth < maxDepth) {
            const sub = getByDotPath(c, tc.childrenPath);
            if (Array.isArray(sub)) walkTree(sub, depth + 1);
          }
        }
      };
      walkTree(topChildren, 0);
      if (commentLines.length > 0) {
        const h = resolveHeading({ topCount: String(topChildren.length) });
        renderedSections.push(h ? `## ${h}\n\n${commentLines.join('\n')}` : commentLines.join('\n'));
      }
      continue;
    }

    // Prepare array items (from `arrayPath`, `listArrayPath`, `subsectionsArrayPath`, or `parallelArrays`)
    const arrSourcePath = sec.arrayPath ?? sec.listArrayPath ?? sec.subsectionsArrayPath;
    let rawArr: Array<Record<string, unknown>> | null = null;

    if (sec.parallelArrays) {
      const pa = sec.parallelArrays;
      const base = pa.basePath ? getByDotPath(rootObj, pa.basePath) : rootObj;
      if (base && typeof base === 'object' && !Array.isArray(base)) {
        const colMap: Record<string, unknown[]> = {};
        let maxLen = 0;
        for (const [alias, srcKey] of Object.entries(pa.fields)) {
          const a = getByDotPath(base, srcKey);
          if (Array.isArray(a)) {
            colMap[alias] = a;
            if (a.length > maxLen) maxLen = a.length;
          } else {
            colMap[alias] = [];
          }
        }
        const zipped: Array<Record<string, unknown>> = [];
        const capZip = Math.min(maxLen, 500);
        const allowSet = pa.priorityFilterAfter ? new Set(pa.priorityFilterAfter.allowValues) : null;
        for (let i = 0; i < capZip; i++) {
          const rowObj: Record<string, unknown> = {};
          for (const alias of Object.keys(pa.fields)) {
            rowObj[alias] = colMap[alias]?.[i];
          }
          if (
            pa.priorityFilterAfter &&
            allowSet &&
            zipped.length >= pa.priorityFilterAfter.index &&
            !allowSet.has(scalarToString(rowObj[pa.priorityFilterAfter.field]))
          ) {
            continue;
          }
          zipped.push(rowObj);
          if (sec.limit && sec.limit > 0 && zipped.length >= sec.limit) break;
        }
        rawArr = zipped;
      }
    } else if (arrSourcePath !== undefined) {
      const got = getByDotPath(rootObj, arrSourcePath);
      if (Array.isArray(got)) {
        rawArr = got.filter((x): x is Record<string, unknown> => Boolean(x && typeof x === 'object' && !Array.isArray(x)));
      }
    }

    if (!rawArr) continue;

    // Filtering
    if (sec.filter) {
      const flt = sec.filter;
      if (flt.requireField) {
        rawArr = rawArr.filter((it) => {
          const v = getByDotPath(it, flt.requireField!);
          return typeof v === 'string' ? v.trim() !== '' : Boolean(v);
        });
      }
      if (flt.excludeFieldPrefix) {
        const { field, prefix } = flt.excludeFieldPrefix;
        rawArr = rawArr.filter((it) => !scalarToString(getByDotPath(it, field)).startsWith(prefix));
      }
      if (flt.excludeFieldSuffixes) {
        const { field, suffixes } = flt.excludeFieldSuffixes;
        rawArr = rawArr.filter((it) => {
          const s = scalarToString(getByDotPath(it, field));
          return s !== '' && !suffixes.some((sf) => s.endsWith(sf));
        });
      }
      if (flt.tagFilterParam) {
        const tagVal = (params[flt.tagFilterParam.param] ?? '').toLowerCase();
        if (tagVal && tagVal !== (flt.tagFilterParam.skipIfEquals ?? '').toLowerCase()) {
          const subFiltered = rawArr.filter((it) => {
            const tArr = getByDotPath(it, flt.tagFilterParam!.tagsField);
            return Array.isArray(tArr) && tArr.some((t) => scalarToString(t).toLowerCase().includes(tagVal));
          });
          if (subFiltered.length > 0) rawArr = subFiltered;
        }
      }
    }

    // Deduplication / multi-location merging (`rippling`, `workable-board`)
    if (sec.dedupeBy) {
      const dd = sec.dedupeBy;
      const map = new Map<string, { item: Record<string, unknown>; texts: Set<string>; flag: boolean }>();
      for (const it of rawArr) {
        let key = '';
        for (const kp of dd.keyPaths) {
          key = scalarToString(getByDotPath(it, kp)).trim();
          if (key) break;
        }
        if (!key) continue;
        let locPiece = '';
        for (const mp of dd.mergeTextPaths ?? []) {
          if (mp.includes('+')) {
            locPiece = mp
              .split('+')
              .map((f) => scalarToString(getByDotPath(it, f.trim())).trim())
              .filter(Boolean)
              .join(', ');
          } else {
            locPiece = scalarToString(getByDotPath(it, mp)).trim();
          }
          if (locPiece) break;
        }
        const boolHit = (dd.orBoolPaths ?? []).some((bp) => {
          const bv = getByDotPath(it, bp);
          return typeof bv === 'string' ? /remote/i.test(bv) : Boolean(bv);
        });
        const existing = map.get(key);
        if (existing) {
          if (locPiece) existing.texts.add(locPiece);
          if (boolHit) existing.flag = true;
        } else {
          map.set(key, {
            item: { ...it },
            texts: new Set(locPiece ? [locPiece] : []),
            flag: boolHit,
          });
        }
      }
      rawArr = [...map.values()].map((entry) => {
        const mergedStr = [...entry.texts].slice(0, dd.mergeLimit ?? 4).join(dd.mergeSep ?? '; ');
        const clone: Record<string, unknown> = { ...entry.item };
        if (dd.mergeTargetVar) clone[dd.mergeTargetVar] = mergedStr;
        if (dd.orBoolTargetField) clone[dd.orBoolTargetField] = entry.flag;
        return clone;
      });
    }

    // Sorting (`stackexchange-qa`)
    if (sec.sortBy) {
      const sb = sec.sortBy;
      rawArr = [...rawArr].sort((a, b) => {
        if (sb.boolDescField) {
          const ba = Boolean(getByDotPath(a, sb.boolDescField));
          const bb = Boolean(getByDotPath(b, sb.boolDescField));
          if (ba !== bb) return ba ? -1 : 1;
        }
        if (sb.numDescField) {
          const na = toFiniteNumber(getByDotPath(a, sb.numDescField)) ?? 0;
          const nb = toFiniteNumber(getByDotPath(b, sb.numDescField)) ?? 0;
          return nb - na;
        }
        return 0;
      });
    }

    if (sec.minItems && rawArr.length < sec.minItems) continue;

    // Update `{dedupCount}` / `{filteredCount}` in title if placeholder used
    if (title.includes('{dedupCount}')) {
      title = sanitizeSingleLineMeta(title.replaceAll('{dedupCount}', String(rawArr.length)));
    }

    if (rawArr.length === 0) {
      if (sec.emptyText) {
        const h = resolveHeading({ count: '0' });
        renderedSections.push(h ? `## ${h}\n\n${sec.emptyText}` : sec.emptyText);
        if (sec.paginationMeta) {
          paginationTotal = 0;
          paginationReturned = 0;
          paginationTruncated = false;
        }
      }
      continue;
    }

    const evalRowMap = (itemObj: Record<string, unknown>, idx: number): Record<string, string> => {
      const itemMap: Record<string, string> = {
        index1: String(idx + 1),
      };
      const rowLookup = (k: string): string => (k in itemMap ? itemMap[k]! : lookup(k));
      for (const [ivName, ivSpec] of Object.entries(sec.itemVars ?? {})) {
        itemMap[ivName] = evalVar(ivSpec, itemObj, rowLookup);
      }
      return itemMap;
    };

    // Pre-scan links up to `linkScanLimit` (e.g. Greenhouse/Lever scan up to 2,000 links while displaying 120 table rows)
    if (sec.collectLinkVars && sec.collectLinkVars.length > 0 && sec.linkScanLimit && sec.linkScanLimit > (sec.limit ?? 100)) {
      const scanCap = Math.min(2_000, sec.linkScanLimit);
      for (let i = 0; i < Math.min(rawArr.length, scanCap); i++) {
        const rm = evalRowMap(rawArr[i]!, i);
        for (const lv of sec.collectLinkVars) {
          if (rm[lv]) pushLink(rm[lv]!);
        }
      }
    }

    const sliceCap = sec.limit && sec.limit > 0 ? Math.min(500, sec.limit) : Math.min(500, rawArr.length);
    const sliced = rawArr.slice(0, sliceCap);

    // Table section
    if (sec.columns && sec.columns.length > 0) {
      const headers = sec.columns.map((c) => c.header);
      const rows: string[][] = [];
      for (let i = 0; i < sliced.length; i++) {
        const itemObj = sliced[i]!;
        const itemMap = evalRowMap(itemObj, i);
        if (sec.requireItemVar && !(itemMap[sec.requireItemVar] ?? '').trim()) continue;
        const rowLookup = (k: string): string => (k in itemMap ? itemMap[k]! : lookup(k));

        for (const lv of sec.collectLinkVars ?? []) {
          if (itemMap[lv]) pushLink(itemMap[lv]!);
        }
        if (sec.recordFields) {
          const rec: Record<string, unknown> = {};
          for (const [rk, tpl] of Object.entries(sec.recordFields)) {
            const rv = expandTemplate(tpl, rowLookup).trim();
            rec[rk] = rv && rv !== '-' ? rv : null;
          }
          collectedRecords.push(rec);
        }
        rows.push(sec.columns.map((col) => renderTableColumnCell(itemObj, col, rowLookup)));
      }
      if (rows.length > 0) {
        const h = resolveHeading({ count: String(rawArr.length), shownCount: String(rows.length) });
        const tbl = formatGfmTable(headers, rows);
        renderedSections.push(h ? `## ${h}\n\n${tbl}` : tbl);

        if (sec.paginationMeta) {
          const pm = sec.paginationMeta;
          const rawTot = pm.totalPath ? toFiniteNumber(getByDotPath(rootObj, pm.totalPath)) : null;
          const total = rawTot !== null ? Math.max(Math.trunc(rawTot), rawArr.length) : rawArr.length;
          const returned = rows.length;
          const truncated = total > returned;
          paginationTotal = total;
          paginationReturned = returned;
          paginationTruncated = truncated;
          if (truncated) {
            if (pm.cursorMode === 'last_id' && pm.idField && sliced[returned - 1]) {
              paginationNextCursor = scalarToString(sliced[returned - 1]![pm.idField]) || String(returned);
            } else {
              paginationNextCursor = String(returned);
            }
          }
        }
      }
      continue;
    }

    // Subsections array (`stackexchange-qa`, `discourse-topic`, `openfda` labels)
    if (sec.subsectionsArrayPath !== undefined) {
      const subBlocks: string[] = [];
      for (let i = 0; i < sliced.length; i++) {
        const itemObj = sliced[i]!;
        const itemMap = evalRowMap(itemObj, i);
        if (sec.requireItemVar && !(itemMap[sec.requireItemVar] ?? '').trim()) continue;
        const rowLookup = (k: string): string => (k in itemMap ? itemMap[k]! : lookup(k));
        const useAlt = Boolean(sec.subsectionAltWhenVar && rowLookup(sec.subsectionAltWhenVar));
        const headTpl = useAlt
          ? (sec.subsectionAltHeadingTemplate ?? sec.subsectionHeadingTemplate ?? '')
          : (sec.subsectionHeadingTemplate ?? '');
        const subH = sanitizeSingleLineMeta(expandTemplate(headTpl, rowLookup));

        if (sec.subsectionSubkeys && sec.subsectionSubkeys.length > 0) {
          const lines: string[] = subH ? [`## ${subH}`] : [];
          for (const sk of sec.subsectionSubkeys) {
            const rawV = itemObj[sk];
            const txt = Array.isArray(rawV)
              ? scalarToString(rawV[0]).trim()
              : typeof rawV === 'string'
                ? rawV.trim()
                : '';
            if (txt) {
              lines.push(`### ${sk.replaceAll('_', ' ')}\n\n${txt.slice(0, 1200)}`);
            }
          }
          if (lines.length > 1) subBlocks.push(lines.join('\n\n'));
        } else if (sec.subsectionBodyVar) {
          const bodyVal = rowLookup(sec.subsectionBodyVar).trim();
          if (bodyVal) {
            // Also harvest links if body came from htmlToMd on Discourse cooked HTML
            if (typeof itemObj.cooked === 'string' && itemObj.cooked.includes('href=')) {
              for (const l of htmlToMd(itemObj.cooked, origUrl).links) pushLink(l);
            }
            subBlocks.push(subH ? `## ${subH}\n\n${bodyVal}` : bodyVal);
          }
        }
      }
      if (subBlocks.length > 0) renderedSections.push(...subBlocks);
      continue;
    }

    // Indented / bulleted list section
    if (sec.itemTemplate) {
      const maxInd = sec.maxIndent && sec.maxIndent > 0 ? sec.maxIndent : 6;
      const h = resolveHeading({ count: String(rawArr.length) });
      const lines: string[] = h ? [`## ${h}`] : [];
      for (let i = 0; i < sliced.length; i++) {
        const itemObj = sliced[i]!;
        const itemMap = evalRowMap(itemObj, i);
        if (sec.requireItemVar && !(itemMap[sec.requireItemVar] ?? '').trim()) continue;
        for (const lv of sec.collectLinkVars ?? []) {
          if (itemMap[lv]) pushLink(itemMap[lv]!);
        }
        let depth = 0;
        if (sec.indentField) {
          const rawDepth = toFiniteNumber(getByDotPath(itemObj, sec.indentField));
          if (rawDepth !== null) {
            depth = Math.max(0, Math.min(maxInd, Math.trunc(rawDepth) + (sec.indentOffset ?? 0)));
          }
        }
        const indent = '  '.repeat(depth);
        if (sec.requireItemVar) {
          itemMap[sec.requireItemVar] = collapseNewlinesWithIndent(itemMap[sec.requireItemVar]!, `${indent}  `);
        }
        const rendered = expandTemplate(sec.itemTemplate, (k) => (k in itemMap ? itemMap[k]! : lookup(k)));
        lines.push(`${indent}- ${rendered}`);
      }
      const minLines = h ? 2 : 1;
      if (lines.length >= minLines) {
        renderedSections.push(lines.join('\n'));
      }
    }
  }

  const blocks: string[] = [];
  const onlyBodyAlreadyTitled =
    bodyText !== '' &&
    bodyText.startsWith('# ') &&
    metaParts.length === 0 &&
    blockquote === '' &&
    intro === '' &&
    bulletLines.length === 0 &&
    renderedSections.length === 0;
  if (!onlyBodyAlreadyTitled) {
    blocks.push(`# ${title}`);
  }
  if (metaParts.length > 0) {
    const joinedMeta = metaParts.join(' · ');
    blocks.push(ext.metaLineItalic ? `*${joinedMeta}*` : joinedMeta);
  }
  if (blockquote) blocks.push(blockquote);
  if (intro) blocks.push(intro);
  if (bulletLines.length > 0) blocks.push(bulletLines.join('\n'));
  if (bodyText) blocks.push(bodyText);
  if (footerItalic) blocks.push(`*${footerItalic}*`);
  blocks.push(...renderedSections);

  for (const lv of ext.linksVars ?? []) {
    pushLink(lookup(lv));
  }
  for (const lt of ext.linkTemplates ?? []) {
    pushLink(expandTemplate(lt, lookup));
  }

  const description = sanitizeSingleLineMeta(
    ext.descriptionTemplate
      ? expandTemplate(ext.descriptionTemplate, lookup)
      : ext.descriptionVar
        ? lookup(ext.descriptionVar)
        : '',
  );
  const author = sanitizeSingleLineMeta(
    ext.authorTemplate
      ? expandTemplate(ext.authorTemplate, lookup)
      : ext.authorVar
        ? lookup(ext.authorVar)
        : '',
  );
  const publishedTime = sanitizeSingleLineMeta(ext.publishedTimeVar ? lookup(ext.publishedTimeVar) : '');

  return {
    title,
    ...(description ? { description } : {}),
    ...(author ? { author } : {}),
    ...(publishedTime ? { publishedTime } : {}),
    markdown: escapeDangerousRawHtmlOutsideFences(blocks.join('\n\n')),
    ...(collectedLinks.length > 0 ? { links: collectedLinks } : {}),
    ...(collectedRecords.length > 0 ? { records: collectedRecords } : {}),
    ...(paginationTotal !== undefined ? { total: paginationTotal } : {}),
    ...(paginationReturned !== undefined ? { returned: paginationReturned } : {}),
    ...(paginationTruncated !== undefined ? { truncated: paginationTruncated } : {}),
    ...(paginationNextCursor !== undefined ? { nextCursor: paginationNextCursor } : {}),
  };
}

// ── Post-Fetch HTML Route Execution (`extractHtml`) ─────────────────────────────────────────────

const COMPILED_LINEAR_REGEX_CACHE = new Map<string, ReturnType<typeof compileLinearRegex>>();

function getCachedLinearRegex(pattern: string) {
  let hit = COMPILED_LINEAR_REGEX_CACHE.get(pattern);
  if (hit === undefined) {
    hit = compileLinearRegex(pattern, 'i');
    COMPILED_LINEAR_REGEX_CACHE.set(pattern, hit);
  }
  return hit;
}

function extractBalancedJsonAfterKeyLinear(src: string, keyName: string): Record<string, unknown> | null {
  const needle = `"${keyName}"`;
  const idx = src.indexOf(needle);
  if (idx < 0) return null;
  const openIdx = src.indexOf('{', idx + needle.length);
  if (openIdx < 0) return null;
  let depth = 0;
  let inStr = false;
  let esc = false;
  const endCap = Math.min(src.length, openIdx + 120_000);
  for (let i = openIdx; i < endCap; i++) {
    const ch = src.charCodeAt(i);
    if (inStr) {
      if (esc) esc = false;
      else if (ch === 92 /* '\\' */) esc = true;
      else if (ch === 34 /* '"' */) inStr = false;
      continue;
    }
    if (ch === 34) inStr = true;
    else if (ch === 123 /* '{' */) depth++;
    else if (ch === 125 /* '}' */) {
      depth--;
      if (depth === 0) {
        return parseJsonObject(src.slice(openIdx, i + 1));
      }
    }
  }
  return null;
}

function stripTagsPreservingNewlinesLinear(s: string): string {
  if (!s.includes('<')) return s;
  let out = '';
  let i = 0;
  const n = s.length;
  let nextGt = -2;
  while (i < n) {
    if (s.charCodeAt(i) !== 60 /* '<' */) {
      out += s[i]!;
      i++;
      continue;
    }
    if (nextGt !== -1 && nextGt <= i) {
      nextGt = s.indexOf('>', i + 1);
    }
    if (nextGt === -1) {
      out += s.slice(i);
      break;
    }
    i = nextGt + 1;
  }
  return out;
}

function runMarkdownCleanPreset(
  preset: 'ietf_rfc' | 'jsr_io' | 'mediawiki',
  ctx: HtmlExtractContext,
  extractorId: string,
): PostFetchSiteResult | null {
  if (preset === 'ietf_rfc') {
    const preBlocks = findAllElementInnersLinear(
      ctx.rawHtml,
      'pre',
      (a) => attrHasTokenLinear(a, 'class', 'newpage'),
      400,
    );
    const sourceText =
      preBlocks.length > 0
        ? preBlocks.map((inner) => decodeBasicEntities(stripTagsPreservingNewlinesLinear(inner))).join('\n')
        : ctx.currentMd;
    if (!sourceText || sourceText.trim().length < 80) return null;

    const cleanedLines: string[] = [];
    for (const rawLine of sourceText.replace(/\r\n/g, '\n').replace(/\f/g, '\n').split('\n')) {
      const rTrim = rawLine.trimEnd();
      if (/\[Page\s+\d+\]$/i.test(rTrim)) continue;
      const fullTrim = rTrim.trimStart();
      if (
        fullTrim.startsWith('RFC ') &&
        /\b(?:January|February|March|April|May|June|July|August|September|October|November|December)\s+\d{4}$/i.test(
          fullTrim,
        ) &&
        fullTrim.includes('  ')
      ) {
        continue;
      }
      if (rawLine === fullTrim) {
        const secMatch = /^(\d+(?:\.\d+){0,3})\.\s+([A-Z][^\r\n]{1,90})$/.exec(fullTrim);
        if (secMatch) {
          const depth = Math.min(4, secMatch[1]!.split('.').length + 1);
          cleanedLines.push(`\n${'#'.repeat(depth)} ${secMatch[1]}. ${secMatch[2]}\n`);
          continue;
        }
      }
      cleanedLines.push(rawLine);
    }

    const md = cleanedLines.join('\n').replace(/\n{3,}/g, '\n\n').trim();
    const title = sanitizeSingleLineMeta(stripTagsInline(findElementInnerLinear(ctx.rawHtml, 'title') ?? ''));
    return {
      extractorId,
      ...(title ? { title } : {}),
      markdown: escapeDangerousRawHtmlOutsideFences(title && !md.startsWith('# ') ? `# ${title}\n\n${md}` : md),
    };
  }

  if (preset === 'jsr_io') {
    if (!ctx.currentMd) return null;
    let body = ctx.currentMd;
    const skipIdx = body.toLowerCase().indexOf('skip to main content');
    if (skipIdx !== -1 && skipIdx < 1500) {
      const h1Idx = body.indexOf('\n# ', skipIdx);
      if (h1Idx !== -1) {
        const lineStart = body.lastIndexOf('\n', skipIdx);
        body = (lineStart === -1 ? '' : body.slice(0, lineStart)) + body.slice(h1Idx);
      }
    }
    const outLines: string[] = [];
    for (const ln of body.split('\n')) {
      const tr = ln.trim();
      if (/^Published\s+/i.test(tr)) continue;
      if ((tr.startsWith('[Overview](') || tr.startsWith('Overview')) && (tr.includes('Docs') || tr.includes('Versions') || tr.includes('Score'))) {
        continue;
      }
      outLines.push(ln);
    }
    const cleaned = outLines.join('\n').replace(/\n{3,}/g, '\n\n').trim();
    if (cleaned && cleaned !== ctx.currentMd.trim()) {
      return { extractorId, markdown: escapeDangerousRawHtmlOutsideFences(cleaned) };
    }
    return null;
  }

  // `mediawiki`
  if (
    !ctx.host.endsWith('.wikipedia.org') &&
    ctx.host !== 'wiki.archlinux.org' &&
    !/\bcontent=["']MediaWiki\b/i.test(ctx.rawHtml.slice(0, 4000))
  ) {
    return null;
  }
  const cleaned = ctx.currentMd
    .replace(/\s*\[(?:edit|citation needed|clarification needed|when\?|who\?|dubious\s*[–-]\s*discuss)\]/gi, '')
    .replace(/^\s*\^\s+(?:\[\^[a-z0-9]+\]\s*|(?:[a-z]\s+){2,})/gim, '^ ')
    .replace(/\n+(?:##+\s+)?(?:Navigation menu|Namespaces|Views|Personal tools)\b[\s\S]*$/i, '')
    .replace(/\n{3,}/g, '\n\n')
    .trim();
  if (cleaned && cleaned !== ctx.currentMd) {
    return { extractorId, markdown: escapeDangerousRawHtmlOutsideFences(cleaned) };
  }
  return null;
}

function runGistHtmlExtractor(ctx: HtmlExtractContext, extractorId: string): PostFetchSiteResult | null {
  const doc = parseHtmlDoc(ctx.rawHtml);
  const desc = sanitizeSingleLineMeta(doc.text('div[itemprop="about"]'));
  const titleRaw = sanitizeSingleLineMeta(
    doc
      .text('title')
      .replace(/\s*·\s*GitHub\s*$/i, '')
      .trim(),
  );
  const files: string[] = [];

  for (const box of doc.select('div.file', 20)) {
    const name = sanitizeSingleLineMeta(box.text('strong.gist-blob-name'));
    if (!name) continue;
    const mdArticleHtml = box.html('article.markdown-body');
    if (mdArticleHtml) {
      files.push(`## ${name}\n\n${ctx.htmlToMd(mdArticleHtml, ctx.baseUrl).markdown.trim()}`);
      continue;
    }
    const codeLines = box.select('td.blob-code-inner', 2_000).map((td) => td.text());
    if (codeLines.length > 0) {
      const { lang } = detectFenceLang(name);
      files.push(`## ${name}\n\n${safeFence(codeLines.join('\n'), lang)}`);
    }
  }

  if (files.length === 0) return null;
  const title = titleRaw || desc || 'GitHub Gist';
  const sections = [`# ${title}`];
  if (desc && desc !== title) sections.push(desc);
  sections.push(files.join('\n\n'));
  return {
    extractorId,
    title,
    ...(desc ? { description: desc } : {}),
    markdown: escapeDangerousRawHtmlOutsideFences(sections.join('\n\n')),
  };
}

function runStackExchangeHtmlExtractor(ctx: HtmlExtractContext, extractorId: string): PostFetchSiteResult | null {
  const cleanHtml = stripScriptsAndStyles(ctx.rawHtml);
  const qHeaderOpen = findOpenTagLinear(cleanHtml, 'div', (a) => getAttrValueLinear(a, 'id') === 'question-header');
  const qHeaderInner = qHeaderOpen ? extractBalancedDivAt(cleanHtml, qHeaderOpen.index) : null;
  const h1Inner = findElementInnerLinear(qHeaderInner ?? cleanHtml, 'h1');
  const title = sanitizeSingleLineMeta(
    stripTagsInline(h1Inner ?? '').replace(/\s*\[(?:duplicate|closed)\]\s*$/i, ''),
  );

  const qOpen = findOpenTagLinear(cleanHtml, 'div', (a) => getAttrValueLinear(a, 'id') === 'question');
  if (!qOpen || !title) return null;
  const qInner = extractBalancedDivAt(cleanHtml, qOpen.index);
  if (!qInner) return null;

  const extractPostBody = (block: string): string => {
    const bodyOpen = findOpenTagLinear(
      block,
      'div',
      (a) =>
        attrHasTokenLinear(a, 'class', 's-prose') ||
        attrHasTokenLinear(a, 'class', 'js-post-body') ||
        attrHasTokenLinear(a, 'class', 'post-text'),
    );
    if (!bodyOpen) return '';
    const inner = extractBalancedDivAt(block, bodyOpen.index);
    return inner ? ctx.htmlToMd(inner, ctx.baseUrl).markdown.trim() : '';
  };

  const extractComments = (block: string): string[] => {
    const out: string[] = [];
    for (const cm of findAllElementInnersLinear(block, 'span', (a) => attrHasTokenLinear(a, 'class', 'comment-copy'), 6)) {
      const txt = stripTagsInline(cm);
      if (txt && out.length < 6) out.push(`> - *Comment*: ${txt}`);
    }
    return out;
  };

  const qScore =
    getAttrValueLinear(qOpen.attrStr, 'data-score') ??
    stripTagsInline(findElementInnerLinear(qInner, 'div', (a) => attrHasTokenLinear(a, 'class', 'js-vote-count')) ?? '');
  const tags = findAllElementInnersLinear(qInner, 'a', (a) => attrHasTokenLinear(a, 'class', 'post-tag'), 16)
    .map((inner) => stripTagsInline(inner))
    .filter((t, i, a) => Boolean(t) && a.indexOf(t) === i)
    .slice(0, 8);

  const qMd = extractPostBody(qInner);
  if (!qMd) return null;

  const sections: string[] = [`# ${title}`];
  const qMeta: string[] = [];
  if (qScore) qMeta.push(`**Votes**: ${qScore}`);
  if (tags.length > 0) qMeta.push(`**Tags**: ${tags.map((t) => `\`${t}\``).join(', ')}`);
  if (qMeta.length > 0) sections.push(qMeta.join(' · '));
  sections.push(`## Question\n\n${qMd}`);
  const qComments = extractComments(qInner);
  if (qComments.length > 0) sections.push(qComments.join('\n'));

  const answers: Array<{ accepted: boolean; score: number; md: string; comments: string[] }> = [];
  const ansOpens = findAllOpenTagsLinear(
    cleanHtml,
    'div',
    (a) => /^answer-\d+$/i.test(getAttrValueLinear(a, 'id') ?? ''),
    12,
  );
  for (const am of ansOpens) {
    const aInner = extractBalancedDivAt(cleanHtml, am.index);
    if (!aInner) continue;
    const accepted =
      attrHasTokenLinear(am.attrStr, 'class', 'accepted-answer') ||
      attrHasTokenLinear(am.attrStr, 'class', 'js-accepted-answer') ||
      /\bjs-accepted-answer-indicator\b/i.test(aInner.slice(0, 2000));
    const scoreRaw =
      getAttrValueLinear(am.attrStr, 'data-score') ??
      stripTagsInline(findElementInnerLinear(aInner, 'div', (a) => attrHasTokenLinear(a, 'class', 'js-vote-count')) ?? '0');
    const score = parseInt(scoreRaw, 10) || 0;
    const md = extractPostBody(aInner);
    if (!md) continue;
    answers.push({ accepted, score, md, comments: extractComments(aInner) });
  }

  answers.sort((a, b) => (a.accepted !== b.accepted ? (a.accepted ? -1 : 1) : b.score - a.score));
  for (let i = 0; i < Math.min(answers.length, 8); i++) {
    const a = answers[i]!;
    const heading = a.accepted ? `## ✅ Accepted Answer (Score: ${a.score})` : `## Answer ${i + 1} (Score: ${a.score})`;
    sections.push(`${heading}\n\n${a.md}`);
    if (a.comments.length > 0) sections.push(a.comments.join('\n'));
  }

  return {
    extractorId,
    title,
    markdown: escapeDangerousRawHtmlOutsideFences(sections.join('\n\n')),
  };
}

function runRedditShredditExtractor(ctx: HtmlExtractContext, extractorId: string): PostFetchSiteResult | null {
  const doc = parseHtmlDoc(ctx.rawHtml);
  const shPost = doc.first('shreddit-post');
  if (!shPost) return null;

  const pTitle = sanitizeSingleLineMeta(decodeBasicEntities(shPost.attr('post-title') ?? ''));
  if (!pTitle) return null;
  const author = sanitizeSingleLineMeta(decodeBasicEntities(shPost.attr('author') ?? ''));
  const score = (shPost.attr('score') ?? '').trim();
  const sub = sanitizeSingleLineMeta(decodeBasicEntities(shPost.attr('subreddit-prefixed-name') ?? ''));
  const bodyHtml = shPost.html();
  const bodyMd = bodyHtml ? ctx.htmlToMd(bodyHtml, ctx.baseUrl).markdown.trim() : '';

  const sections = [`# ${pTitle}`];
  const meta = [sub, author ? `u/${author}` : '', score ? `${score} upvotes` : ''].filter(Boolean);
  if (meta.length > 0) sections.push(`*${meta.join(' · ')}*`);
  if (bodyMd) sections.push(bodyMd);

  const comments: string[] = [];
  for (const cm of doc.select('shreddit-comment', 25)) {
    const cAuthor = sanitizeSingleLineMeta(decodeBasicEntities(cm.attr('author') ?? 'user')) || 'user';
    const cScore = (cm.attr('score') ?? '').trim();
    const cDepth = Math.min(5, Math.max(0, parseInt(cm.attr('depth') ?? '0', 10) || 0));
    const cHtml = cm.html();
    const cMd = cHtml ? ctx.htmlToMd(cHtml, ctx.baseUrl).markdown.trim().replace(/\n+/g, ' ') : '';
    if (cMd) comments.push(`${'  '.repeat(cDepth)}- **u/${cAuthor}**${cScore ? ` (${cScore})` : ''}: ${cMd}`);
  }
  if (comments.length > 0) sections.push(`## Comments\n\n${comments.join('\n')}`);

  return {
    extractorId,
    title: pTitle,
    ...(author ? { author: `u/${author}` } : {}),
    markdown: escapeDangerousRawHtmlOutsideFences(sections.join('\n\n')),
  };
}

function runDomHtmlRoute(
  hr: DeclarativeHtmlRouteSpec,
  ctx: HtmlExtractContext,
  params: Record<string, string>,
  extractorId: string,
): PostFetchSiteResult | null {
  const doc = parseHtmlDoc(ctx.rawHtml);
  const cleanHtml = stripScriptsAndStyles(ctx.rawHtml);

  let ldObj: Record<string, unknown> | undefined;
  if (hr.jsonLdTypes && hr.jsonLdTypes.length > 0) {
    const ldList = extractJsonLdObjects(ctx.rawHtml);
    const lowerTypes = hr.jsonLdTypes.map((t) => t.toLowerCase());
    ldObj = ldList.find((o) => {
      const tVal = String(o['@type'] ?? '').toLowerCase();
      return lowerTypes.some((want) => tVal.includes(want));
    });
  }

  const embeddedObj = hr.embeddedBalancedKey
    ? extractBalancedJsonAfterKeyLinear(ctx.rawHtml, hr.embeddedBalancedKey) ?? undefined
    : undefined;

  const varsMap = hr.vars ?? {};
  const resolved = new Map<string, string>();
  const visiting = new Set<string>();
  const bodyLinksByVar = new Map<string, string[]>();

  const lookup = (name: string): string => {
    if (resolved.has(name)) return resolved.get(name)!;
    const spec = varsMap[name];
    if (!spec) return params[name] ?? '';
    if (visiting.has(name)) return '';
    visiting.add(name);
    const v = evalHtmlVar(name, spec);
    visiting.delete(name);
    resolved.set(name, v);
    return v;
  };

  const formatDomRaw = (raw: unknown, spec: DeclarativeHtmlVarSpec): string => {
    if (raw === null || raw === undefined) return '';
    if (Array.isArray(raw)) {
      const items = raw
        .slice(0, spec.limit ?? 20)
        .map((el) => {
          if (el && typeof el === 'object' && !Array.isArray(el)) {
            const o = el as Record<string, unknown>;
            return scalarToString(o.name ?? o.value ?? '');
          }
          return scalarToString(el);
        })
        .filter(Boolean);
      return items.length > 0 ? items.join(spec.join ?? ', ') : '';
    }
    return scalarToString(raw);
  };

  const evalHtmlVar = (varName: string, spec: DeclarativeHtmlVarSpec): string => {
    let val = '';

    if (spec.template !== undefined) {
      const allOk = (spec.whenVars ?? []).every((w) => lookup(w) !== '');
      const anyOk = !spec.whenAnyVars || spec.whenAnyVars.length === 0 || spec.whenAnyVars.some((w) => lookup(w) !== '');
      if (allOk && anyOk) {
        val = expandTemplate(spec.template, lookup);
      } else if (spec.fallbackVar) {
        val = lookup(spec.fallbackVar);
      }
    } else {
      if (!val && embeddedObj && spec.embeddedPaths) {
        for (const ep of spec.embeddedPaths) {
          const got = formatDomRaw(getByDotPath(embeddedObj, ep), spec).trim();
          if (got) {
            val = got;
            break;
          }
        }
      }
      if (!val && ldObj && spec.jsonLdPaths) {
        for (const lp of spec.jsonLdPaths) {
          const got = formatDomRaw(getByDotPath(ldObj, lp), spec).trim();
          if (got) {
            val = got;
            break;
          }
        }
      }
      if (!val && spec.allMetaKey) {
        const all = extractAllMetaContents(ctx.rawHtml, spec.allMetaKey).slice(0, spec.limit ?? 20);
        if (all.length > 0) val = all.join(spec.join ?? ', ');
      }
      if (!val && spec.metaKeys) {
        for (const mk of spec.metaKeys) {
          let got = extractMetaContent(ctx.rawHtml, mk);
          if (got && spec.stripRegexSuffix) {
            const re = getCachedLinearRegex(spec.stripRegexSuffix);
            if (re) {
              const m = re.exec(got);
              if (m && m.index !== undefined) got = got.slice(0, m.index).trim();
            }
          }
          if (got) {
            val = got;
            break;
          }
        }
      }
      if (!val && spec.cssText) {
        for (const sel of spec.cssText) {
          const got = doc.text(sel);
          if (got) {
            val = got;
            break;
          }
        }
      }
      if (!val && spec.cssAttr) {
        val = (doc.attrOf(spec.cssAttr.selector, spec.cssAttr.attr) ?? '').trim();
      }
      if (!val && spec.cssAllText) {
        const ca = spec.cssAllText;
        const rawList = doc.select(ca.selector, ca.limit ?? 50).map((n) => n.text()).filter(Boolean);
        const list = ca.dedupe !== false ? [...new Set(rawList)] : rawList;
        const capped = spec.limit ? list.slice(0, spec.limit) : list;
        if (capped.length > 0) val = capped.join(ca.join ?? ', ');
      }
      if (!val && spec.cssHtmlToMd) {
        for (const sel of spec.cssHtmlToMd) {
          const inner = doc.html(sel);
          if (inner && inner.trim()) {
            const conv = ctx.htmlToMd(inner, ctx.baseUrl);
            const md = conv.markdown.trim();
            if (md) {
              val = md;
              bodyLinksByVar.set(varName, conv.links);
              break;
            }
          }
        }
        // Fallback if JSON-LD description HTML existed (e.g. SmartRecruiters)
        if (!val && ldObj && spec.jsonLdPaths) {
          for (const lp of spec.jsonLdPaths) {
            const rawHtmlFrag = getByDotPath(ldObj, lp);
            if (typeof rawHtmlFrag === 'string' && rawHtmlFrag.trim()) {
              const conv = ctx.htmlToMd(rawHtmlFrag, ctx.baseUrl);
              if (conv.markdown.trim()) {
                val = conv.markdown.trim();
                bodyLinksByVar.set(varName, conv.links);
                break;
              }
            }
          }
        }
      }
      if (!val && spec.regexExtract) {
        const rx = spec.regexExtract;
        const re = getCachedLinearRegex(rx.pattern);
        if (re) {
          const corpus =
            rx.source === 'doc_text_and_img_alts'
              ? `${doc.text()} ${doc
                  .select('img[alt]', 80)
                  .map((n) => n.attr('alt') ?? '')
                  .join(' ')}`
              : cleanHtml.slice(0, 200_000);
          const m = re.exec(corpus);
          const grp = m?.[rx.group ?? 1] ?? '';
          if (grp) {
            val = rx.transform === 'upper' ? grp.toUpperCase() : rx.transform === 'lower' ? grp.toLowerCase() : grp;
          }
        }
      }
    }

    if (val === '') {
      if (spec.fallbackVar) val = lookup(spec.fallbackVar);
      if (val === '' && spec.fallbackTemplate !== undefined) val = expandTemplate(spec.fallbackTemplate, lookup);
      if (val === '' && spec.default !== undefined) val = spec.default;
    }
    if (spec.stripPrefix && val.toLowerCase().startsWith(spec.stripPrefix.toLowerCase())) {
      val = val.slice(spec.stripPrefix.length).trim();
    }
    if (spec.stripSuffix && val.toLowerCase().endsWith(spec.stripSuffix.toLowerCase())) {
      val = val.slice(0, -spec.stripSuffix.length).trim();
    }
    if (spec.replaceAll && val) {
      val = val.replaceAll(spec.replaceAll.from, spec.replaceAll.to);
    }
    if (spec.format === 'strip_tags') {
      val = stripTagsInline(val);
    } else if (spec.format === 'strip_leading_h1') {
      val = stripLeadingMarkdownH1(val);
    } else if (spec.format === 'free_or_currency' && val !== '') {
      const n = Number(val);
      const cur = spec.currencyVar ? lookup(spec.currencyVar) || 'USD' : 'USD';
      val = n === 0 ? 'Free' : `${cur} ${val}`;
    }
    if (spec.trim !== false) val = val.trim();
    val = stripInvisibleAndNul(val);
    if (spec.minLen && val.length < spec.minLen) return '';
    if (spec.sliceMax && spec.sliceMax > 0 && val.length > spec.sliceMax) {
      val = val.slice(0, spec.sliceMax);
    }
    return val;
  };

  for (const k of Object.keys(varsMap)) lookup(k);
  for (const rv of hr.requireVars ?? []) {
    if (!lookup(rv).trim()) return null;
  }

  let title = '';
  if (hr.titleWhenVar) {
    title = lookup(hr.titleWhenVar)
      ? expandTemplate(hr.titleTemplate ?? '', lookup)
      : expandTemplate(hr.titleFallbackTemplate ?? '', lookup);
  } else {
    title = expandTemplate(hr.titleTemplate ?? '', lookup);
    if (!title.trim() && hr.titleFallbackTemplate) {
      title = expandTemplate(hr.titleFallbackTemplate, lookup);
    }
  }
  title = sanitizeSingleLineMeta(title);

  const bulletLines: string[] = [];
  for (const b of hr.bullets ?? []) {
    if (b.whenVar && !lookup(b.whenVar)) continue;
    if (b.unlessVar && lookup(b.unlessVar)) continue;
    const rendered = expandTemplate(b.template, lookup).trim();
    if (rendered) {
      bulletLines.push(b.label ? `- **${b.label}**: ${rendered}` : `- ${rendered}`);
    }
  }

  if (hr.requireBulletsOrVars && hr.requireBulletsOrVars.length > 0) {
    const hasBullet = bulletLines.length > 0;
    const hasAnyVar = hr.requireBulletsOrVars.some((v) => lookup(v).trim() !== '');
    if (!hasBullet && !hasAnyVar) return null;
  }

  const blocks: string[] = [];
  const bodyVal = hr.bodyVar ? lookup(hr.bodyVar).trim() : '';
  const bodyStartsH1 = bodyVal.startsWith('# ');

  if (hr.blockquoteTemplate && (!hr.blockquoteWhenVar || lookup(hr.blockquoteWhenVar))) {
    const bq = expandTemplate(hr.blockquoteTemplate, lookup).trim();
    if (bodyStartsH1 && bq) {
      blocks.push(bq);
    } else {
      if (title) blocks.push(`# ${title}`);
      if (bq) blocks.push(bq);
    }
  } else if (title) {
    blocks.push(`# ${title}`);
  }

  if (hr.metaItalicTemplate && (!hr.metaItalicWhenVar || lookup(hr.metaItalicWhenVar))) {
    const mi = expandTemplate(hr.metaItalicTemplate, lookup).trim();
    if (mi) blocks.push(`*${mi}*`);
  }
  if (hr.introVar) {
    const iv = lookup(hr.introVar).trim();
    if (iv) blocks.push(iv);
  }
  if (bulletLines.length > 0) blocks.push(bulletLines.join('\n'));
  if (bodyVal) {
    if (hr.bodyFallbackHeading && !bodyVal.startsWith('#')) {
      blocks.push(`## ${hr.bodyFallbackHeading}\n\n${bodyVal}`);
    } else {
      blocks.push(bodyVal);
    }
  }
  for (const sec of hr.sections ?? []) {
    const txt = lookup(sec.textVar).trim();
    if (txt) blocks.push(`## ${sec.heading}\n\n${txt}`);
  }

  if (hr.appendCurrentMdDelta && ctx.currentMd) {
    const baseLen = hr.appendCurrentMdDelta.baseVar ? lookup(hr.appendCurrentMdDelta.baseVar).length : 0;
    if (ctx.currentMd.length > baseLen + hr.appendCurrentMdDelta.minExtraChars) {
      blocks.push(stripLeadingMarkdownH1(ctx.currentMd).trim());
    }
  }

  if (blocks.length === 0 || (blocks.length === 1 && title && blocks[0] === `# ${title}`)) {
    return null;
  }

  const links: string[] = [];
  if (hr.preserveBodyLinksFromVar) {
    for (const l of bodyLinksByVar.get(hr.preserveBodyLinksFromVar) ?? []) {
      if (l.startsWith('https://') && !links.includes(l)) links.push(l);
    }
  }
  for (const lt of hr.linkTemplates ?? []) {
    const uStr = expandTemplate(lt, lookup).trim();
    if (uStr.startsWith('https://') && !links.includes(uStr)) links.push(uStr);
  }

  const description = sanitizeSingleLineMeta(hr.descriptionVar ? lookup(hr.descriptionVar) : '');
  const author = sanitizeSingleLineMeta(hr.authorVar ? lookup(hr.authorVar) : '');
  const publishedTime = sanitizeSingleLineMeta(hr.publishedTimeVar ? lookup(hr.publishedTimeVar) : '');

  return {
    extractorId,
    ...(title ? { title } : {}),
    ...(description ? { description } : {}),
    ...(author ? { author } : {}),
    ...(publishedTime ? { publishedTime } : {}),
    markdown: escapeDangerousRawHtmlOutsideFences(blocks.join('\n\n').trim()),
    ...(links.length > 0 ? { links } : {}),
  };
}

function executeDeclarativeHtmlRoute(
  manifest: DeclarativeAdapterManifest,
  hr: DeclarativeHtmlRouteSpec,
  ctx: HtmlExtractContext,
): PostFetchSiteResult | null {
  const params = matchDeclarativeRoute(hr.match, ctx);
  if (!params) return null;
  const extractorId = hr.id || manifest.id;

  switch (hr.mode) {
    case 'shopify_html':
      return extractShopifyProductHtml(ctx, extractorId);
    case 'woocommerce_html':
      return extractWooCommerceProductHtml(ctx, extractorId);
    case 'icims_portal': {
      const formatted = parseIcimsPortalHtml(ctx.rawHtml, ctx.url.toString(), ctx.htmlToMd);
      if (!formatted) return null;
      return {
        extractorId,
        title: formatted.title,
        ...(formatted.publishedTime ? { publishedTime: formatted.publishedTime } : {}),
        markdown: formatted.markdown,
        links: formatted.links,
        records: formatted.records,
        ...(formatted.total !== undefined ? { total: formatted.total } : {}),
        ...(formatted.returned !== undefined ? { returned: formatted.returned } : {}),
        ...(formatted.truncated !== undefined ? { truncated: formatted.truncated } : {}),
        ...(formatted.nextCursor !== undefined ? { nextCursor: formatted.nextCursor } : {}),
      };
    }
    case 'xml_items_table': {
      if (!hr.xml) return null;
      const formatted = formatXmlTwinOrHtml(ctx.rawHtml, hr.xml, params);
      if (!formatted) return null;
      return {
        extractorId,
        title: formatted.title,
        markdown: formatted.markdown,
        links: formatted.links,
      };
    }
    case 'markdown_clean':
      return hr.cleanPreset ? runMarkdownCleanPreset(hr.cleanPreset, ctx, extractorId) : null;
    case 'gist_files':
      return runGistHtmlExtractor(ctx, extractorId);
    case 'stackexchange_html':
      return runStackExchangeHtmlExtractor(ctx, extractorId);
    case 'reddit_shreddit':
      return runRedditShredditExtractor(ctx, extractorId);
    case 'embedded_json': {
      if (!hr.extract) return null;
      let jsonVal: unknown = null;
      if (hr.scriptId) {
        const rawScript = findElementInnerLinear(
          ctx.rawHtml,
          'script',
          (a) => getAttrValueLinear(a, 'id') === hr.scriptId,
        );
        if (rawScript) jsonVal = parseJsonValue(rawScript);
      } else if (hr.dataAttr) {
        const doc = parseHtmlDoc(ctx.rawHtml);
        const rawAttr = doc.first(`[${hr.dataAttr}]`)?.attr(hr.dataAttr);
        if (rawAttr) jsonVal = parseJsonValue(decodeBasicEntities(rawAttr));
      }
      if (!jsonVal) return null;
      const formatted = formatParsedJsonWithSpec(jsonVal, hr.extract, params, ctx.baseUrl, ctx.htmlToMd);
      if (!formatted) return null;
      return {
        extractorId,
        title: formatted.title,
        ...(formatted.description ? { description: formatted.description } : {}),
        ...(formatted.author ? { author: formatted.author } : {}),
        ...(formatted.publishedTime ? { publishedTime: formatted.publishedTime } : {}),
        markdown: formatted.markdown,
        ...(formatted.links ? { links: formatted.links } : {}),
      };
    }
    case 'dom':
      return runDomHtmlRoute(hr, ctx, params, extractorId);
  }
}

// ── Strict YAML / Schema / M2 Host-Claim Validation ─────────────────────────────────────────────

const TOP_LEVEL_MANIFEST_KEYS = new Set([
  'id',
  'name',
  'category',
  'description',
  'domains',
  'universalEngine',
  'exampleUrls',
  'match',
  'twin',
  'extract',
  'routes',
  'htmlRoutes',
  'catalog',
]);

function assertSafeYamlAstNode(node: unknown, pathLabel: string): void {
  if (!node || typeof node !== 'object') return;
  if (isAlias(node)) {
    throw new Error(`YAML alias (*alias) is forbidden in declarative manifest (${pathLabel})`);
  }
  const anyNode = node as { anchor?: string; tag?: string };
  if (anyNode.anchor) {
    throw new Error(`YAML anchor (&${anyNode.anchor}) is forbidden in declarative manifest (${pathLabel})`);
  }
  if (anyNode.tag) {
    throw new Error(`Explicit YAML tag (${anyNode.tag}) is forbidden in declarative manifest (${pathLabel})`);
  }
  if (isMap(node)) {
    for (const item of node.items) {
      if (isPair(item)) {
        assertSafeYamlAstNode(item.key, pathLabel);
        if (isScalar(item.key)) {
          const kStr = String(item.key.value ?? '');
          if (kStr === '<<') {
            throw new Error(`YAML merge key (<<) is forbidden in declarative manifest (${pathLabel})`);
          }
          if (!isAsciiPrintableKey(kStr)) {
            throw new Error(`Non-ASCII YAML key "${kStr}" is forbidden in declarative manifest (${pathLabel})`);
          }
        }
        assertSafeYamlAstNode(item.value, `${pathLabel}.${String((item.key as { value?: unknown })?.value ?? '')}`);
      }
    }
  } else if (isSeq(node)) {
    node.items.forEach((child, idx) => assertSafeYamlAstNode(child, `${pathLabel}[${idx}]`));
  }
}

function assertValidDomainPattern(manifestId: string, rawPat: string): void {
  if (typeof rawPat !== 'string' || !rawPat.trim()) {
    throw new Error(`[${manifestId}] domain pattern must be a non-empty string`);
  }
  const pat = rawPat.trim().toLowerCase();
  if (!isAsciiPrintableKey(pat) || /[\s/\\:?#@]/.test(pat)) {
    throw new Error(`[${manifestId}] invalid characters in domain pattern "${rawPat}"`);
  }
  if (pat === '*' || pat === '*.*') {
    throw new Error(`[${manifestId}] overly broad wildcard domain "${rawPat}" is forbidden (M2)`);
  }
  if (pat.startsWith('*.')) {
    const rest = pat.slice(2);
    if (!rest.includes('.') || FORBIDDEN_BROAD_SUFFIXES.has(rest)) {
      throw new Error(`[${manifestId}] overly broad TLD/eTLD wildcard "${rawPat}" is forbidden (M2)`);
    }
  }
  if (pat.endsWith('.*')) {
    const pre = pat.slice(0, -2);
    if (!pre || pre.includes('*') || pre.length < 3) {
      throw new Error(`[${manifestId}] invalid prefix wildcard "${rawPat}" (M2)`);
    }
  }
}

function assertValidTwinFetchUrlM2(manifest: DeclarativeAdapterManifest, fetchUrl: string, routeIdx: number): void {
  if (typeof fetchUrl !== 'string' || !fetchUrl.trim()) {
    throw new Error(`[${manifest.id}] route ${routeIdx} missing twin.fetchUrl`);
  }
  if (fetchUrl === '{requestUrl}') return;
  if (!fetchUrl.startsWith('https://') && !fetchUrl.startsWith('{origin}/')) {
    throw new Error(`[${manifest.id}] route ${routeIdx} fetchUrl must start with https:// (got "${fetchUrl}")`);
  }
  const hasWildcardOrUniversal =
    Boolean(manifest.universalEngine) || manifest.domains.some((d) => d.includes('*'));
  if ((fetchUrl.includes('{host}') || fetchUrl.includes('{origin}')) && hasWildcardOrUniversal) {
    const sameOriginOk = fetchUrl.startsWith('https://{host}/') || fetchUrl.startsWith('{origin}/');
    if (!sameOriginOk) {
      throw new Error(
        `[${manifest.id}] route ${routeIdx} cannot interpolate {host}/{origin} into non-origin URL "${fetchUrl}" when wildcard domains or universalEngine are enabled (M2)`,
      );
    }
  }
  // Static host validation when fetchUrl does not start with dynamic `{host}` / `{origin}`
  if (!fetchUrl.startsWith('https://{host}') && !fetchUrl.startsWith('{origin}')) {
    const sampleCheck = expandTemplate(fetchUrl, () => 'sample');
    if (!isSafeDeclarativeTwinUrl(sampleCheck)) {
      throw new Error(`[${manifest.id}] route ${routeIdx} fetchUrl failed public HTTPS safety validation: "${fetchUrl}"`);
    }
  }
}

export function validateDeclarativeManifestObject(m: DeclarativeAdapterManifest): DeclarativeAdapterManifest {
  if (!m || typeof m !== 'object' || Array.isArray(m)) {
    throw new Error('Declarative manifest root must be an object');
  }
  for (const k of Object.keys(m)) {
    if (!isAsciiPrintableKey(k) || !TOP_LEVEL_MANIFEST_KEYS.has(k)) {
      throw new Error(`[${String((m as { id?: unknown }).id ?? 'unknown')}] unknown top-level manifest key "${k}"`);
    }
  }
  if (typeof m.id !== 'string' || !VALID_ID_RE.test(m.id)) {
    throw new Error(`Invalid manifest id "${String(m.id)}" (expected lowercase kebab-case)`);
  }
  if (typeof m.name !== 'string' || m.name.trim().length < 2) {
    throw new Error(`[${m.id}] missing valid name`);
  }
  if (typeof m.category !== 'string' || !VALID_CATEGORIES.has(m.category)) {
    throw new Error(`[${m.id}] invalid category "${String(m.category)}"`);
  }
  if (typeof m.description !== 'string' || m.description.trim().length < 10) {
    throw new Error(`[${m.id}] description must be at least 10 chars`);
  }
  if (!Array.isArray(m.domains) || m.domains.length === 0) {
    throw new Error(`[${m.id}] domains must be a non-empty string array`);
  }
  for (const d of m.domains) {
    assertValidDomainPattern(m.id, d);
  }
  if (!Array.isArray(m.exampleUrls) || m.exampleUrls.length === 0) {
    throw new Error(`[${m.id}] exampleUrls must be a non-empty array of https:// URLs`);
  }
  for (const ex of m.exampleUrls) {
    if (typeof ex !== 'string' || !ex.startsWith('https://')) {
      throw new Error(`[${m.id}] exampleUrl must start with https:// (got "${String(ex)}")`);
    }
  }

  const hasSingleTwin = Boolean(m.match || m.twin || m.extract);
  if (hasSingleTwin && (!m.match || !m.twin || !m.extract)) {
    throw new Error(`[${m.id}] single-route manifest must define all three of match, twin, and extract`);
  }
  const routes: DeclarativeRouteSpec[] =
    m.routes && m.routes.length > 0
      ? m.routes
      : m.match && m.twin && m.extract
        ? [{ match: m.match, twin: m.twin, extract: m.extract }]
        : [];
  const hasHtml = Boolean(m.htmlRoutes && m.htmlRoutes.length > 0);
  const hasCatalog = Boolean(m.catalog);

  if (routes.length === 0 && !hasHtml && !hasCatalog) {
    throw new Error(`[${m.id}] manifest must define at least one of routes, match/twin/extract, htmlRoutes, or catalog`);
  }

  routes.forEach((r, idx) => {
    if (!r.twin || (r.twin.kind !== 'json' && r.twin.kind !== 'text')) {
      throw new Error(`[${m.id}] route ${idx} twin.kind must be "json" or "text"`);
    }
    if (r.twin.id !== undefined && !VALID_ID_RE.test(r.twin.id)) {
      throw new Error(`[${m.id}] route ${idx} invalid twin.id "${String(r.twin.id)}"`);
    }
    assertValidTwinFetchUrlM2(m, r.twin.fetchUrl, idx);
    for (const seg of r.match?.pathSegments ?? []) {
      if (typeof seg === 'object') {
        if (seg.reserved && !seg.reserved.every((x) => typeof x === 'string')) {
          throw new Error(`[${m.id}] route ${idx} param "${seg.param}" reserved values must all be strings`);
        }
        if (seg.allowValues && !seg.allowValues.every((x) => typeof x === 'string')) {
          throw new Error(`[${m.id}] route ${idx} param "${seg.param}" allowValues must all be strings`);
        }
      }
    }
  });

  for (const hr of m.htmlRoutes ?? []) {
    if (hr.id !== undefined && !VALID_ID_RE.test(hr.id)) {
      throw new Error(`[${m.id}] invalid htmlRoute id "${String(hr.id)}"`);
    }
  }

  return m;
}

/** Parses a raw YAML manifest string (rejecting anchors, aliases, merge keys, explicit tags, and unknown keys) or validates an object manifest. */
export function parseDeclarativeManifest(input: DeclarativeAdapterManifest | string): DeclarativeAdapterManifest {
  if (typeof input !== 'string') {
    return validateDeclarativeManifestObject(input);
  }
  const doc = parseYamlDocument(input, {
    merge: false,
    uniqueKeys: true,
    schema: 'core',
  });
  if (doc.errors.length > 0) {
    throw new Error(`Invalid declarative YAML syntax: ${doc.errors[0]!.message}`);
  }
  assertSafeYamlAstNode(doc.contents, 'root');
  const parsed = doc.toJS({ maxAliasCount: 0 }) as unknown;
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error('Invalid declarative adapter YAML manifest: root must be a mapping');
  }
  return validateDeclarativeManifestObject(parsed as DeclarativeAdapterManifest);
}

/** Compiles a canonical declarative YAML string or manifest object into an executable `SiteAdapter`. */
export function compileDeclarativeAdapter(manifestOrYaml: DeclarativeAdapterManifest | string): SiteAdapter {
  const manifest = parseDeclarativeManifest(manifestOrYaml);
  const routes: DeclarativeRouteSpec[] =
    manifest.routes && manifest.routes.length > 0
      ? manifest.routes
      : manifest.match && manifest.twin && manifest.extract
        ? [{ match: manifest.match, twin: manifest.twin, extract: manifest.extract }]
        : [];
  const htmlRoutes = manifest.htmlRoutes ?? [];
  const catalogSpec = manifest.catalog ? buildDeclarativeCatalogSpec(manifest.catalog) : undefined;

  return {
    id: manifest.id,
    name: manifest.name,
    category: manifest.category,
    description: manifest.description,
    domains: [...manifest.domains],
    ...(manifest.universalEngine ? { universalEngine: true } : {}),
    exampleUrls: [...manifest.exampleUrls],
    ...(routes.length > 0
      ? {
          resolveTwin(ctx: TwinMatchContext): SiteExtractorTwin | null {
            for (const route of routes) {
              const params = matchDeclarativeRoute(route.match, ctx);
              if (!params) continue;
              const fetchUrl = buildResolvedTwinUrl(route, ctx, params);
              if (!fetchUrl) continue;
              return {
                id: route.twin.id || manifest.id,
                fetchUrl,
                kind: route.twin.kind,
                accept: route.twin.accept,
                formatTwin: (rawBody: string, originalUrl: string, htmlToMd: HtmlFragmentConverter) =>
                  route.twin.kind === 'text' || route.extract.textMode || route.extract.xml || route.extract.icimsPortal
                    ? formatTextRouteTwin(rawBody, route.extract, params, originalUrl, htmlToMd)
                    : formatJsonWithExtractSpec(rawBody, route.extract, params, originalUrl, htmlToMd),
              };
            }
            return null;
          },
        }
      : {}),
    ...(htmlRoutes.length > 0
      ? {
          extractHtml(ctx: HtmlExtractContext): PostFetchSiteResult | null {
            for (const hr of htmlRoutes) {
              const out = executeDeclarativeHtmlRoute(manifest, hr, ctx);
              if (out && out.markdown.trim()) return out;
            }
            return null;
          },
        }
      : {}),
    ...(catalogSpec ? { catalog: catalogSpec } : {}),
  };
}

export function compileValidatedManifestSet(manifests: readonly DeclarativeAdapterManifest[]): SiteAdapter[] {
  const seenManifestIds = new Set<string>();
  const twinOwnerById = new Map<string, string>();
  const compiled: SiteAdapter[] = [];

  for (const m of manifests) {
    if (seenManifestIds.has(m.id)) {
      throw new Error(`Duplicate declarative adapter manifest id "${m.id}" (M2)`);
    }
    seenManifestIds.add(m.id);
    const routes =
      m.routes && m.routes.length > 0
        ? m.routes
        : m.match && m.twin && m.extract
          ? [{ match: m.match, twin: m.twin, extract: m.extract }]
          : [];
    for (const r of routes) {
      const tid = r.twin.id || m.id;
      const prevOwner = twinOwnerById.get(tid);
      if (prevOwner && prevOwner !== m.id) {
        throw new Error(`Duplicate twin id "${tid}" claimed by both "${prevOwner}" and "${m.id}" (M2)`);
      }
      twinOwnerById.set(tid, m.id);
    }
    compiled.push(compileDeclarativeAdapter(m));
  }

  return compiled;
}

const COMPILED_BUNDLE = compiledBundleJson as unknown as CompiledManifestBundle;

export const DECLARATIVE_SITE_ADAPTERS: readonly SiteAdapter[] = compileValidatedManifestSet(
  COMPILED_BUNDLE.manifests ?? [],
);
