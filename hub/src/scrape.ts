/**
 * Markdown derivation pipeline (`SCRAPE_PIPELINE_VERSION` imported from `./storage`), `llms.txt` parser, `maxAgeMs` verified cache lookup,
 * and `POST /v1/scrape` + MCP `scrape` execution (`PR S6`).
 *
 * Security Invariants:
 *  - `deriveMarkdownDocument` NEVER reuses or derives from unverified artifacts (`isContentVerifiedInMetaD1` must be true).
 *  - Derived outputs are stored deterministically at `derived/<pipelineVersion>/markdown/<contentSha256>` in `ARTIFACTS` R2
 *    and tracked in `META` D1 `documents` with `(content_sha256, format, pipeline_version)` uniqueness.
 */

import {
  applyPostFetchSiteExtractor,
  enrichShopifyProductFromJson,
  enrichWooCommerceProductFromStoreApi,
  extractShopifyCurrencyFromHtml,
  extractWooCommerceCatalogHtml,
  findRegisteredAdapterById,
  formatMagento2RenderInfoJson,
  formatSfccProductVariationJson,
  formatShopifyProductsFeedTwin,
  formatSquarespaceCommerceJson,
  formatWcStoreApiListTwin,
  isMagento2HtmlOrHeaders,
  isSfccDemandwareHtmlOrHeaders,
  isShopifyHtmlOrHeaders,
  isSquarespaceCommerceHtmlOrHeaders,
  isWooCommerceHtmlOrHeaders,
  resolveCustomDomainShopifyCollectionTwinUrl,
  resolveCustomDomainShopifyProductTwinUrl,
  resolveCustomDomainWooCommerceCatalogTwinUrl,
  resolveCustomDomainWooCommerceProductTwinUrl,
  resolveMagento2RenderInfoTwinUrl,
  resolveSfccProductVariationTwinUrl,
  resolveSiteExtractorTwin,
  resolveSquarespaceCommerceTwinUrl,
  type PaginationInfo,
  type PostFetchSiteResult,
  type TwinFormattedDoc,
  hasHtmlSiteAdapterForHost,
} from './extractors/registry';
import { tryFetchCmsAutoTwin, type CmsAutoTwinResult } from './extractors/cms-twins';
import {
  checkUnboundedTwinEndpointGuard,
  enrichCpscRecallFromSaferProducts,
  enrichDockerHubTags,
  enrichZendeskArticleAttachments,
  fetchGovInfoSummaryFallback,
  type FetchBoundedTwinFn,
} from './extractors/twin-companions';
import {
  distillCapturedJsonResponses,
  type HydratedFrameworkStateResult,
} from './extractors/framework-hydration';
import {
  extractUniversalSchemaOrg,
  inspectRawSchemaOrgJsonLdLinear,
  percentEncodeUnsafeRecordUrlChars,
  sanitizeSchemaHttpsUrl,
  type UniversalSchemaOrgResult,
} from './extractors/schema-org';
import {
  detectSiteFrameworkLinear,
  extractInertiaPagePropsLinear,
  type BrowserFrameworkGlobals,
} from './framework-detect';
import {
  asciiLower,
  escapeRegexLiteral,
  isTagNameBoundary,
  MAX_HTML_SCAN_CHARS,
  replaceHtmlOpenTagsLinear,
  replaceHtmlTagBlocksLinear,
  replaceHtmlTagsQuoteAwareLinear,
  replacePairedHtmlElementsLinear,
  scanHtmlTagsLinear,
  stripHtmlCommentsLinear,
  stripHtmlTagsLinear,
  stripHtmlTagsQuoteAwareLinear,
} from './safe-input';
import { isContentVerifiedInMetaD1, sha256HexBytes, sha256HexString } from './ingest';
import {
  analyzeUrlRedirect,
  buildBlockedInfo,
  chunkJsonRecords,
  detectWorkdayRedirectStub,
  extractJobPostingJsonLd,
  formatJobPostingHeaderMarkdown,
  hasExecutableScriptTag,
  inspectRawJobPostingJsonLdLinear,
  isThinScriptedPage,
  resolveAtsPreFetchSpec,
  type StructuredJobPosting,
} from './jobs';
import { computeMarkdownChanges } from './map-crawl';
import {
  DNS_NOT_FOUND_MESSAGE,
  isDnsNotFoundError,
  isSsrfBlockedError,
  MARKDOWN_FOR_AGENTS_ACCEPT,
  resolveValidatedFinalUrl,
  scrubResolverIpFromError,
  SSRF_BLOCKED_INFO,
  validatePublicHttpsTargetUrl,
} from './overflow';
import { getActiveRequestTracer, sanitizeUrlForSpan, setActiveSpanAttribute, type RequestTracer, type TraceContext } from './otel';
import {
  capExtractedTitleLength,
  chunkMarkdownForSearch,
  D1FtsSearchIndex,
  rankChunksInMemory,
  resolveUserCollectionId,
  sanitizeExtractedTitle,
} from './search-index';
import {
  hasAnyCallerCookies,
  hasAnyCallerHeader,
  INLINE_HYDRATION_BUDGET_BYTES,
  isPrivateRequestPayload,
  isValidSha256Hex,
  MAX_ARTIFACT_CONTENT_BYTES,
  normalizeCallerHeadersRecord,
  normalizeVisibility,
  primeSanitizedMarkdownCache,
  r2ArtifactKey,
  r2DerivedKey,
  r2PrivateDerivedKey,
  r2PrivateScrapeCacheKey,
  readVerifiedArtifactFromR2,
  sanitizeStorageUserId,
  SCRAPE_PIPELINE_VERSION,
  writeArtifactToR2,
  writePrivateArtifactToR2,
  type ArtifactRetention,
  type OptionalStorageBindings,
} from './storage';
import {
  classifyContentState,
  classifyWafAndChallenge,
  hasExternalOrWidgetIframeLinear,
  isEligibleForWaybackFallback,
  recoverSsrHydrationContent,
  refineBlockedInfo,
  tryFetchWaybackSnapshot,
  type ContentState,
  type WafClassification,
} from './waf';
import {
  isEligibleForExternalSpaFallback,
  normalizeSpaFallbackMode,
  tryExternalSpaFallback,
  type SpaFallbackProvider,
  type SpaFallbackSuccess,
} from './spa-fallback';
import {
  checkAndRecordWikipediaArticleQuota,
  cleanMediaWikiMarkdownLinear,
  DEFAULT_WIKIPEDIA_MAX_AGE_MS,
  isWikipediaHost,
  parseWikipediaArticleUrl,
  resolveWikipediaCanonicalFinalUrl,
} from './wikipedia';
import {
  extractJsonWithOptionalLlm,
  resolveLlmConfig,
  summarizeMarkdownWithOptionalLlm,
  type LlmEnvBindings,
} from './llm';
import {
  cleanFenceInfoStringLinear,
  cutMarkdownToSanitizerBudget,
  detectPromptInjection,
  encodeBodyToRawBase64,
  escapeAllResidualLtInProseLinear,
  escapeGfmTaskListCheckboxesLinear,
  escapeMarkdownFallbackLinear,
  extractHtmlAttributesBySelectors,
  extractStructuredProduct,
  isAsciiSpaceOrTabOnly,
  isDisallowedMarkdownLinkDestination,
  MAX_SANITIZER_WASM_UTF8_BYTES,
  neutralizeAllUnsafeMarkdownLinksLinear,
  normalizeInlineBrowserActions,
  parsePdfParserOptions,
  recognizeAndHardenMarkdownFences,
  sanitizeMarkdownPageSlice,
  sanitizePlainMetadataText,
  splitPdfPagesAndMarkers,
  stripInvisibleSmugglingChars,
  trimAsciiWhitespaceLinear,
  trimTrailingAsciiWhitespaceLinear,
} from './scrape-advanced';
import {
  acquireIsolateByteBudget,
  callCoreWasm,
  callCoreWasmRaw,
  callCoreWasmRawString,
  isWasmInputBudgetExceededError,
  MAX_WASM_INPUT_BYTES,
} from './wasm-bridge';

const SCRAPE_UTF8_ENCODER = new TextEncoder();
function exactUtf8ByteLen(s: string): number {
  if (s.length * 3 <= MAX_WASM_INPUT_BYTES) return s.length;
  if (s.length > MAX_WASM_INPUT_BYTES) return s.length;
  return SCRAPE_UTF8_ENCODER.encode(s).byteLength;
}

export { recognizeAndHardenMarkdownFences, sanitizeMarkdownPageSlice, stripInvisibleSmugglingChars } from './scrape-advanced';
export { SCRAPE_PIPELINE_VERSION } from './storage';

export interface ScrapedImage {
  url: string;
  alt?: string;
}

export interface BrandingProfile {
  title?: string;
  description?: string;
  canonicalUrl?: string;
  favicon?: string;
  logo?: string;
  ogImage?: string;
  themeColor?: string;
  colors?: string[];
  fonts?: string[];
}

export interface LlmsLinkItem {
  section?: string;
  title: string;
  url: string;
  notes?: string;
}

export interface ParsedLlmsTxt {
  sourceUrl: string;
  title?: string;
  summary?: string;
  fullTxtUrl?: string;
  links: LlmsLinkItem[];
}

export interface ExtractedDocument {
  title?: string;
  description?: string;
  author?: string;
  publishedTime?: string;
  modifiedTime?: string;
  siteName?: string;
  wordCount?: number;
  language?: string;
  canonicalUrl?: string;
  markdownAlternateUrl?: string;
  favicon?: string;
  extractorId?: string;
  records?: Array<Record<string, unknown>>;
  preferRecordAvailability?: boolean;
  pagination?: PaginationInfo;
  total?: number;
  returned?: number;
  truncated?: boolean;
  nextCursor?: string;
  inertiaHydrated?: boolean;
  warnings?: string[];
  markdown: string;
  text: string;
  links: string[];
  images: ScrapedImage[];
  branding: BrandingProfile;
}

const URL_ONLY_TAG_ATTRS = new Set(['href', 'src', 'srcset', 'data-src', 'data-srcset', 'action', 'poster']);

function unescapeUrlAttrAmpOnly(raw: string): string {
  return raw.includes('&') ? raw.replace(/&(?:amp|#0*38|#x0*26);/gi, '&') : raw;
}

export function decodeHtmlEntities(input: string): string {
  if (!input || !input.includes('&')) return input;
  const { text: bounded } = cutMarkdownToSanitizerBudget(input);
  return callCoreWasmRawString('decode_html_entities', null, bounded);
}

function parseTagAttrs(tag: string): Record<string, string> {
  if (tag.length > 65_536) tag = tag.slice(0, 65_536);
  const attrs: Record<string, string> = {};
  const re = /(?<![a-zA-Z0-9_:-])([a-zA-Z0-9_:-]+)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+))/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(tag)) !== null) {
    const key = m[1]!.toLowerCase();
    if (!(key in attrs)) {
      const val = m[2] ?? m[3] ?? m[4] ?? '';
      attrs[key] = URL_ONLY_TAG_ATTRS.has(key) ? unescapeUrlAttrAmpOnly(val) : decodeHtmlEntities(val);
    }
  }
  return attrs;
}

function cleanInlineHtml(fragment: string): string {
  const stripped = replaceHtmlTagsQuoteAwareLinear(fragment, (t) => (!t.isClosing && t.tagNameLower === 'wbr' ? '' : ' '));
  return stripInvisibleSmugglingChars(decodeHtmlEntities(stripped))
    .replace(/\s+/g, ' ')
    .replace(/(?<!\[) +([,.;:!?)]}])/g, '$1')
    .replace(/ +([’'](?:s|t|re|ve|ll|d|m)\b)/gi, '$1')
    .replace(/\( +(?=[^\s)])/g, '(')
    .replace(/\[\s+(\d{1,4})\s*\]/g, '[$1]')
    .trim();
}

function countTextWords(text: string): number {
  const trimmed = text.trim();
  if (!trimmed) return 0;
  return (trimmed.match(/[\p{L}\p{N}_'-]+/gu) ?? []).length;
}

export function splitMarkdownByCodeFences(rawMd: string): string[] {
  return recognizeAndHardenMarkdownFences(rawMd, { harden: false }).segments;
}

export function makeSafeCodeFence(code: string, lang = '', preferTilde = false): string {
  return callCoreWasm<{ out: string }>('make_safe_fence', {
    code: String(code ?? ''),
    lang: String(lang ?? ''),
    preferTilde: Boolean(preferTilde),
  }).out;
}

export function decodeMarkdownEntities(md: string): string {
  if (!md || !md.includes('&')) return md;
  const { text: bounded } = cutMarkdownToSanitizerBudget(md);
  return callCoreWasmRawString('decode_markdown_entities', null, bounded);
}

function safeDecodeURIComponent(raw: string): string {
  try {
    return decodeURIComponent(raw);
  } catch {
    return raw;
  }
}

export function cleanPdfMarkdown(md: string): string {
  if (!md) return md;
  const { text: bounded } = cutMarkdownToSanitizerBudget(md);
  return callCoreWasmRawString('clean_pdf_markdown', null, bounded);
}

export function sanitizeScrapedMetadataField(raw: string | undefined, maxLen = 2_000): string | undefined {
  if (!raw || typeof raw !== 'string') return undefined;
  const out = callCoreWasm<{ out: string }>('sanitize_scraped_meta', { raw, maxLen }).out;
  return out || undefined;
}

export function sanitizeScrapedTimestampField(raw: string | undefined, maxLen = 128): string | undefined {
  if (!raw || typeof raw !== 'string') return undefined;
  const out = callCoreWasm<{ out: string }>('sanitize_scraped_ts', { raw, maxLen }).out;
  return out || undefined;
}

export function redactPiiText(text: string): string {
  return redactPiiTextReportingCut(text).text;
}

/** `redactPiiText` that also reports whether the input had to be cut to the WASM sanitizer budget first. */
export function redactPiiTextReportingCut(text: string): { text: string; cut: boolean } {
  if (!text) return { text, cut: false };
  const { text: bounded, cut } = cutMarkdownToSanitizerBudget(text);
  return { text: callCoreWasmRawString('redact_pii', null, bounded), cut };
}

/** Bounds `s` to the sanitizer budget every downstream WASM text helper enforces, reporting whether it was cut. */
function boundToSanitizerBudget(s: string): { text: string; cut: boolean } {
  if (!s) return { text: s, cut: false };
  const res = cutMarkdownToSanitizerBudget(s);
  return res.cut ? { text: trimTrailingAsciiWhitespaceLinear(res.text), cut: true } : { text: s, cut: false };
}

function sanitizeScrapedTextOut(rawText: string): string {
  if (!rawText) return rawText;
  return neutralizeAllUnsafeMarkdownLinksLinear(stripInvisibleSmugglingChars(decodeHtmlEntities(rawText))).replace(
    /<(?=[a-zA-Z!/\?]|[ \t]*(?:javascript|vbscript|data|file|blob):)/gi,
    '&lt;',
  );
}

export function extractLargestUrlFromSrcset(srcset: string | undefined): string | undefined {
  if (!srcset || !srcset.trim()) return undefined;
  const url = callCoreWasm<{ url: string }>('extract_largest_srcset', { srcset }).url;
  return url || undefined;
}

export function extractHtmlDocument(
  rawHtml: string,
  options:
    | {
        baseUrl?: string;
        onlyMainContent?: boolean;
        redactPii?: boolean;
        includeImages?: boolean;
        includeTags?: readonly string[];
        excludeTags?: readonly string[];
        /** Strip hidden subtrees even with `onlyMainContent: false` (Go `StripHiddenSubtrees`). */
        stripHiddenSubtrees?: boolean;
      }
    | string = {},
): ExtractedDocument {
  const optsObj =
    typeof options === 'string'
      ? { baseUrl: options }
      : typeof options === 'object' && options !== null
        ? options
        : {};
  const {
    baseUrl,
    onlyMainContent = true,
    redactPii = false,
    includeImages = true,
    includeTags,
    excludeTags,
    stripHiddenSubtrees = false,
  } = optsObj;

  const rawDoc = callCoreWasmRaw<{
    doc: {
      title?: string;
      description?: string;
      author?: string;
      publishedTime?: string;
      modifiedTime?: string;
      siteName?: string;
      wordCount?: number;
      language?: string;
      canonicalUrl?: string;
      markdownAlternateUrl?: string;
      favicon?: string;
      extractorId?: string;
      records?: Array<Record<string, unknown>>;
      total?: number;
      returned?: number;
      truncated?: boolean;
      nextCursor?: string;
      inertiaHydrated?: boolean;
      markdown?: string;
      text?: string;
      links?: string[];
      images?: ScrapedImage[];
      branding?: BrandingProfile;
    };
  }>(
    'extract_html_full',
    {
      ...(baseUrl ? { baseUrl } : {}),
      onlyMainContent: Boolean(onlyMainContent),
      includeImages: Boolean(includeImages),
      ...(includeTags && includeTags.length > 0 ? { includeTags: [...includeTags] } : {}),
      ...(excludeTags && excludeTags.length > 0 ? { excludeTags: [...excludeTags] } : {}),
      redactPii: Boolean(redactPii),
      ...(stripHiddenSubtrees ? { stripHiddenSubtrees: true } : {}),
    },
    String(rawHtml ?? ''),
  ).doc;

  if (rawDoc.extractorId) {
    setActiveSpanAttribute('edgefetch.adapter_id', rawDoc.extractorId);
  }

  return {
    ...(rawDoc.title ? { title: rawDoc.title } : {}),
    ...(rawDoc.description ? { description: rawDoc.description } : {}),
    ...(rawDoc.author ? { author: rawDoc.author } : {}),
    ...(rawDoc.publishedTime ? { publishedTime: rawDoc.publishedTime } : {}),
    ...(rawDoc.modifiedTime ? { modifiedTime: rawDoc.modifiedTime } : {}),
    ...(rawDoc.siteName ? { siteName: rawDoc.siteName } : {}),
    ...(rawDoc.wordCount && rawDoc.wordCount > 0 ? { wordCount: rawDoc.wordCount } : {}),
    ...(rawDoc.language ? { language: rawDoc.language } : {}),
    ...(rawDoc.canonicalUrl ? { canonicalUrl: rawDoc.canonicalUrl } : {}),
    ...(rawDoc.markdownAlternateUrl ? { markdownAlternateUrl: rawDoc.markdownAlternateUrl } : {}),
    ...(rawDoc.favicon ? { favicon: rawDoc.favicon } : {}),
    ...(rawDoc.extractorId ? { extractorId: rawDoc.extractorId } : {}),
    ...(rawDoc.records !== undefined ? { records: rawDoc.records } : {}),
    ...(rawDoc.total !== undefined ? { total: rawDoc.total } : {}),
    ...(rawDoc.returned !== undefined ? { returned: rawDoc.returned } : {}),
    ...(rawDoc.truncated ? { truncated: true } : {}),
    ...(rawDoc.nextCursor ? { nextCursor: rawDoc.nextCursor } : {}),
    ...(rawDoc.inertiaHydrated ? { inertiaHydrated: true } : {}),
    markdown: rawDoc.markdown ?? '',
    text: rawDoc.text ?? '',
    links: rawDoc.links ?? [],
    images: rawDoc.images ?? [],
    branding: rawDoc.branding ?? {},
  };
}

export function formatInertiaPagePropsToMarkdown(
  inertiaObj: Record<string, unknown>,
  baseUrl?: string,
  _htmlToMd?: (frag: string, base?: string) => { markdown: string; links: string[] },
): { title?: string; description?: string; markdown: string } | null {
  if (!inertiaObj || typeof inertiaObj !== 'object') return null;
  const doc = callCoreWasm<{ doc: { title?: string; description?: string; markdown: string } | null }>(
    'format_payload',
    { kind: 'inertia_props', props: inertiaObj, url: baseUrl ?? '' },
  ).doc;
  if (!doc || !doc.markdown) return null;
  return {
    ...(doc.title ? { title: doc.title } : {}),
    ...(doc.description ? { description: doc.description } : {}),
    markdown: doc.markdown,
  };
}

const COMPANION_MD_TTL_MS = 30 * 60_000;
const MAX_COMPANION_MD_ENTRIES = 2_048;
const companionMdUrlCache = new Map<string, { mdUrl: string; expiresAt: number }>();

export function resetCompanionMdCacheForTests(): void {
  companionMdUrlCache.clear();
}

export function recordCompanionMdUrl(mdUrlStr: string, now = Date.now()): void {
  if (!mdUrlStr || !/\.md$/i.test(mdUrlStr)) return;
  let u: URL;
  try {
    u = new URL(mdUrlStr);
  } catch {
    return;
  }
  if (
    u.protocol !== 'https:' ||
    u.username ||
    u.password ||
    (u.port && u.port !== '443') ||
    u.search ||
    u.hash
  ) {
    return;
  }
  const cleanMd = u.toString();
  const keys: string[] = [];
  if (/\/index\.md$/i.test(u.pathname)) {
    const dirWithSlash = `${u.origin}${u.pathname.slice(0, -'index.md'.length)}`;
    keys.push(dirWithSlash);
    if (dirWithSlash.endsWith('/') && dirWithSlash.length > u.origin.length + 1) {
      keys.push(dirWithSlash.slice(0, -1));
    }
  } else {
    const withoutExt = `${u.origin}${u.pathname.slice(0, -3)}`;
    keys.push(withoutExt, `${withoutExt}/`);
  }
  const expiresAt = now + COMPANION_MD_TTL_MS;
  for (const key of keys) {
    if (companionMdUrlCache.size >= MAX_COMPANION_MD_ENTRIES && !companionMdUrlCache.has(key)) {
      const oldest = companionMdUrlCache.keys().next().value;
      if (oldest !== undefined) companionMdUrlCache.delete(oldest);
    }
    companionMdUrlCache.set(key, { mdUrl: cleanMd, expiresAt });
  }
}

export function lookupCompanionMdUrl(pageUrlStr: string, now = Date.now()): string | undefined {
  if (!pageUrlStr || /\.md(?:$|[?#])/i.test(pageUrlStr)) return undefined;
  let key = pageUrlStr;
  try {
    const u = new URL(pageUrlStr);
    u.hash = '';
    key = u.toString();
  } catch {
    return undefined;
  }
  const hit = companionMdUrlCache.get(key);
  if (!hit) return undefined;
  if (now >= hit.expiresAt) {
    companionMdUrlCache.delete(key);
    return undefined;
  }
  return hit.mdUrl;
}

function isSameHttpsOriginAs(candidateUrl: string, expectedOriginLower: string): boolean {
  if (!expectedOriginLower) return false;
  try {
    const u = new URL(candidateUrl);
    return (
      u.protocol === 'https:' &&
      !u.username &&
      !u.password &&
      (!u.port || u.port === '443') &&
      u.origin.toLowerCase() === expectedOriginLower
    );
  } catch {
    return false;
  }
}

function recordCompanionMdLinksFromLlmsPayload(
  llmsPayload: unknown,
  allowedOriginsLower: ReadonlySet<string>,
  now = Date.now(),
): void {
  if (!llmsPayload || typeof llmsPayload !== 'object' || allowedOriginsLower.size === 0) return;
  const obj = llmsPayload as {
    llmsTxtUrl?: unknown;
    companionMdUrl?: unknown;
    matchedEntry?: { url?: unknown };
    relatedLinks?: Array<{ url?: unknown }>;
  };
  let effectiveOrigin = '';
  if (typeof obj.llmsTxtUrl === 'string') {
    try {
      const lu = new URL(obj.llmsTxtUrl);
      const lo = lu.origin.toLowerCase();
      if (
        lu.protocol === 'https:' &&
        !lu.username &&
        !lu.password &&
        (!lu.port || lu.port === '443') &&
        (lu.pathname === '/llms.txt' || lu.pathname === '/.well-known/llms.txt') &&
        allowedOriginsLower.has(lo)
      ) {
        effectiveOrigin = lo;
      }
    } catch {
      effectiveOrigin = '';
    }
  }
  if (!effectiveOrigin) {
    effectiveOrigin = allowedOriginsLower.values().next().value ?? '';
  }
  const recordIfSameOrigin = (urlVal: unknown): void => {
    if (typeof urlVal === 'string' && isSameHttpsOriginAs(urlVal, effectiveOrigin)) {
      recordCompanionMdUrl(urlVal, now);
    }
  };
  recordIfSameOrigin(obj.companionMdUrl);
  recordIfSameOrigin(obj.matchedEntry?.url);
  if (Array.isArray(obj.relatedLinks)) {
    for (const rel of obj.relatedLinks) {
      recordIfSameOrigin(rel?.url);
    }
  }
}

export function parseLlmsTxt(
  raw: string,
  sourceUrl: string,
  options?: { recordCompanionCache?: boolean },
): ParsedLlmsTxt | null {
  const res = callCoreWasm<{ ok: boolean; doc?: ParsedLlmsTxt }>('parse_llms_txt', {
    raw: String(raw ?? ''),
    sourceUrl: String(sourceUrl ?? ''),
  });
  if (!res.ok || !res.doc) return null;
  if (options?.recordCompanionCache !== false) {
    let sourceOriginLower = '';
    try {
      const su = new URL(sourceUrl);
      if (su.protocol === 'https:' && !su.username && !su.password && (!su.port || su.port === '443')) {
        sourceOriginLower = su.origin.toLowerCase();
      }
    } catch {
      sourceOriginLower = '';
    }
    if (sourceOriginLower) {
      for (const link of res.doc.links ?? []) {
        if (link.url.toLowerCase().endsWith('.md') && isSameHttpsOriginAs(link.url, sourceOriginLower)) {
          recordCompanionMdUrl(link.url);
        }
      }
    }
  }
  return {
    sourceUrl: res.doc.sourceUrl || sourceUrl,
    ...(res.doc.title ? { title: res.doc.title } : {}),
    ...(res.doc.summary ? { summary: res.doc.summary } : {}),
    ...(res.doc.fullTxtUrl ? { fullTxtUrl: res.doc.fullTxtUrl } : {}),
    links: res.doc.links ?? [],
  };
}

export function extractStructuredJsonFromPageWithDiagnostics(
  rawHtml: string,
  doc: ExtractedDocument,
  schema?: Record<string, unknown>,
): { data: Record<string, unknown>; unmatchedFields: string[]; warnings: string[] } {
  const normalizedDoc =
    typeof (doc as unknown) === 'string'
      ? { markdown: String(doc), text: String(doc), links: [], images: [], branding: {} }
      : doc && typeof doc === 'object'
        ? doc
        : { markdown: '', text: '', links: [], images: [], branding: {} };
  const res = callCoreWasm<{
    result: Record<string, unknown>;
    matchedFields?: string[];
    unfilledFields?: string[];
  }>('extract_structured_json', {
    rawHtml: String(rawHtml ?? ''),
    doc: normalizedDoc,
    ...(schema ? { schema } : {}),
  });
  const unmatchedFields = res.unfilledFields ?? [];
  const warnings: string[] = [];
  if (unmatchedFields.length > 0) {
    warnings.push(
      `Keyless heuristic schema extraction could not match [${unmatchedFields.join(', ')}] from page structure; use the 'agent' tool (BYO-LLM) or configure an LLM provider for semantic JSON-Schema extraction.`,
    );
  }
  return { data: res.result ?? {}, unmatchedFields, warnings };
}

export function extractStructuredJsonFromPage(
  rawHtml: string,
  doc: ExtractedDocument,
  schema?: Record<string, unknown>,
): Record<string, unknown> {
  return extractStructuredJsonFromPageWithDiagnostics(rawHtml, doc, schema).data;
}

export type DeriveDocumentResult =
  | {
      status: 'derived' | 'cached';
      documentId: string;
      contentSha256: string;
      pipelineVersion: number;
      r2Key: string;
      bytes: number;
      title?: string;
      language?: string;
      markdown?: string;
    }
  | {
      status: 'unverified' | 'expired' | 'unsupported';
      contentSha256: string;
    };

export function extractPdfTitle(md: string, urlStr?: string): string | undefined {
  const title = callCoreWasm<{ title: string }>('extract_pdf_title', {
    md: String(md ?? ''),
    url: urlStr ?? '',
  }).title;
  return title || undefined;
}

export function formatVcardToMarkdown(raw: string): { title?: string; markdown: string } {
  const doc = callCoreWasmRaw<{ doc: { title?: string; markdown: string } | null }>(
    'format_payload',
    { kind: 'vcard' },
    String(raw ?? ''),
  ).doc;
  return {
    ...(doc?.title ? { title: doc.title } : {}),
    markdown: doc?.markdown ?? '# Contact Card (vCard)',
  };
}

/**
 * Derives clean Markdown from a VERIFIED stored R2 artifact (`isContentVerifiedInMetaD1 === true`), writes the derived
 * Markdown to `derived/<pipelineVersion>/markdown/<contentSha256>` in `ARTIFACTS` R2, and upserts `META` D1 `documents`.
 */
export async function deriveMarkdownDocument(params: {
  bucket: R2Bucket;
  metaDb: D1Database;
  blobSha256: string;
  contentSha256: string;
  contentType?: string;
  baseUrl?: string;
  pipelineVersion?: number;
  now?: number;
  alreadyVerified?: boolean;
  preloadedBytes?: Uint8Array;
  includeMarkdown?: boolean;
}): Promise<DeriveDocumentResult> {
  const {
    bucket,
    metaDb,
    blobSha256,
    contentSha256,
    contentType = 'text/html',
    baseUrl,
    pipelineVersion = SCRAPE_PIPELINE_VERSION,
    now = Date.now(),
    alreadyVerified = false,
    preloadedBytes,
    includeMarkdown = false,
  } = params;

  if (!isValidSha256Hex(contentSha256) || !isValidSha256Hex(blobSha256)) {
    return { status: 'unverified', contentSha256 };
  }

  // SECURITY GATE: Never derive or index unverified agent claims.
  if (!alreadyVerified) {
    const verified = await isContentVerifiedInMetaD1(metaDb, contentSha256);
    if (!verified) {
      return { status: 'unverified', contentSha256 };
    }
  }

  const ctLower = contentType.toLowerCase();
  if (
    ctLower &&
    !ctLower.startsWith('text/') &&
    !ctLower.includes('html') &&
    !ctLower.includes('markdown') &&
    !ctLower.includes('xml') &&
    !ctLower.includes('json') &&
    !(baseUrl && isLikelyPdfUrl(baseUrl))
  ) {
    return { status: 'unsupported', contentSha256 };
  }

  const r2Key = r2DerivedKey(pipelineVersion, 'markdown', contentSha256);
  const docId = `doc_${(await sha256HexString(`${contentSha256}:markdown:${pipelineVersion}`)).slice(0, 32)}`;

  const existingDoc = await metaDb
    .prepare(
      `SELECT id, r2_key, bytes, title, language
       FROM documents
       WHERE content_sha256 = ? AND format = 'markdown' AND pipeline_version = ?
       LIMIT 1`,
    )
    .bind(contentSha256, pipelineVersion)
    .first<{ id: string; r2_key: string; bytes: number; title: string | null; language: string | null }>();

  if (existingDoc) {
    if (includeMarkdown) {
      const cachedObj = await bucket.get(existingDoc.r2_key);
      if (cachedObj) {
        const cachedMd = await cachedObj.text();
        return {
          status: 'cached',
          documentId: existingDoc.id,
          contentSha256,
          pipelineVersion,
          r2Key: existingDoc.r2_key,
          bytes: existingDoc.bytes,
          ...(existingDoc.title ? { title: existingDoc.title } : {}),
          ...(existingDoc.language ? { language: existingDoc.language } : {}),
          markdown: cachedMd,
        };
      }
    } else {
      const existsInR2 =
        typeof (bucket as { list?: unknown }).list === 'function'
          ? await bucket
              .list({ prefix: existingDoc.r2_key, limit: 4 })
              .then((l) => l.objects.some((o) => o.key === existingDoc.r2_key))
              .catch(() => false)
          : (await bucket.head(existingDoc.r2_key)) !== null;
      if (existsInR2) {
        return {
          status: 'cached',
          documentId: existingDoc.id,
          contentSha256,
          pipelineVersion,
          r2Key: existingDoc.r2_key,
          bytes: existingDoc.bytes,
          ...(existingDoc.title ? { title: existingDoc.title } : {}),
          ...(existingDoc.language ? { language: existingDoc.language } : {}),
        };
      }
    }
  }

  let rawBytes: Uint8Array;
  if (preloadedBytes) {
    rawBytes = preloadedBytes;
  } else {
    const loaded = await readVerifiedArtifactFromR2({
      bucket,
      blobSha256,
      preferredRetention: 'stored',
      expectedContentSha256: contentSha256,
    });
    if (!loaded.ok) {
      return { status: 'expired', contentSha256 };
    }
    rawBytes = loaded.bytes;
  }
  if (hasPdfMagicHeader(rawBytes)) {
    return { status: 'unsupported', contentSha256 };
  }

  const rawText = new TextDecoder('utf-8', { fatal: false }).decode(rawBytes);
  if (detectUnsupportedBinaryPayload({ rawBody: rawText, contentType, url: baseUrl })) {
    return { status: 'unsupported', contentSha256 };
  }
  let markdown: string;
  let title: string | undefined;
  let language: string | undefined;

  const isHtmlDoc = ctLower.includes('html') || /^\s*<!doctype\s+html|^\s*<html/i.test(rawText);
  if (isHtmlDoc) {
    const extracted = extractHtmlDocument(rawText, { baseUrl, onlyMainContent: true });
    markdown = extracted.markdown;
    title = extracted.title;
    language = extracted.language;
  } else if (ctLower.includes('vcard') || /^BEGIN:VCARD\b/im.test(rawText.trim())) {
    const vc = formatVcardToMarkdown(rawText);
    markdown = vc.markdown;
    title = vc.title;
  } else if (ctLower.includes('calendar') || /^BEGIN:VCALENDAR\b/im.test(rawText.trim())) {
    const ics = formatIcalendarToMarkdown(rawText);
    markdown = ics ? ics.markdown : rawText.trim();
    title = ics?.title;
  } else {
    const feedDoc = formatFeedXmlToMarkdown(rawText, baseUrl);
    const jsonDoc = !feedDoc ? tryParseJsonPayloadForScrape(rawText, contentType, baseUrl ?? '') : null;
    const csvDoc = !feedDoc && !jsonDoc ? formatDelimitedTableToMarkdown(rawText, contentType, baseUrl) : null;
    const patchDoc = !feedDoc && !jsonDoc && !csvDoc ? formatGitPatchToMarkdown(rawText, contentType, baseUrl) : null;
    const srcDoc = !feedDoc && !jsonDoc && !csvDoc && !patchDoc ? formatSourceCodeUrlToMarkdown(rawText, contentType, baseUrl) : null;
    if (feedDoc) {
      markdown = feedDoc.markdown;
      title = feedDoc.title;
    } else if (jsonDoc) {
      markdown = jsonDoc.markdown;
      title = jsonDoc.title;
    } else if (csvDoc) {
      markdown = csvDoc.markdown;
      title = csvDoc.title;
    } else if (patchDoc) {
      markdown = patchDoc.markdown;
      title = patchDoc.title;
    } else if (srcDoc) {
      markdown = srcDoc.markdown;
      title = srcDoc.title;
    } else {
      const isPdfDoc = Boolean(baseUrl && isLikelyPdfUrl(baseUrl));
      const fm = isPdfDoc ? { body: rawText.trim() } : parseMarkdownFrontmatter(rawText.trim());
      title = fm.title;
      let cleaned = sanitizeInlineHtmlInMarkdown(decodeMarkdownEntities(fm.body), baseUrl);
      if (isPdfDoc) {
        cleaned = cleanPdfMarkdown(cleaned);
      }
      markdown = cleaned.trim();
      if (!title && markdown) {
        title = isPdfDoc
          ? extractPdfTitle(markdown, baseUrl)
          : extractMarkdownLinksAndImages(markdown, baseUrl ?? 'https://example.com/', false).title;
      }
    }
  }
  if (!isHtmlDoc) {
    markdown = sanitizeInlineHtmlInMarkdown(markdown, baseUrl).trim();
  }
  if (title) {
    title = sanitizeExtractedTitle(title, baseUrl ?? 'https://example.com/', false);
  }

  const cappedMetaTitle = title ? capExtractedTitleLength(title, 200) : '';
  const mdBytes = new TextEncoder().encode(markdown);
  await bucket.put(r2Key, mdBytes, {
    httpMetadata: { contentType: 'text/markdown; charset=utf-8' },
    customMetadata: {
      contentSha256,
      pipelineVersion: String(pipelineVersion),
      ...(cappedMetaTitle ? { title: cappedMetaTitle } : {}),
    },
  });

  await metaDb
    .prepare(
      `INSERT INTO documents (id, content_sha256, format, pipeline_version, r2_key, title, language, bytes, created_at)
       VALUES (?, ?, 'markdown', ?, ?, ?, ?, ?, ?)
       ON CONFLICT(content_sha256, format, pipeline_version) DO UPDATE SET
         r2_key = excluded.r2_key,
         title = COALESCE(excluded.title, documents.title),
         language = COALESCE(excluded.language, documents.language),
         bytes = excluded.bytes`,
    )
    .bind(docId, contentSha256, pipelineVersion, r2Key, title ?? null, language ?? null, mdBytes.byteLength, now)
    .run();

  return {
    status: 'derived',
    documentId: docId,
    contentSha256,
    pipelineVersion,
    r2Key,
    bytes: mdBytes.byteLength,
    ...(title ? { title } : {}),
    ...(language ? { language } : {}),
    ...(includeMarkdown ? { markdown } : {}),
  };
}

export async function lookupCachedScrape(params: {
  bucket: R2Bucket;
  metaDb: D1Database;
  url: string;
  maxAgeMs: number;
  pipelineVersion?: number;
  now?: number;
}): Promise<{
  markdown: string;
  contentSha256: string;
  documentId: string;
  pipelineVersion: number;
  title?: string;
  language?: string;
  status: number;
  lastFetchedAt: number;
} | null> {
  const { bucket, metaDb, url, maxAgeMs, pipelineVersion = SCRAPE_PIPELINE_VERSION, now = Date.now() } = params;
  if (!(maxAgeMs > 0)) return null;

  const pageRow = await metaDb
    .prepare(
      `SELECT p.id, p.latest_status, p.latest_outcome, p.latest_content_sha256, p.last_fetched_at, p.latest_fetch_id, f.content_sha256 AS fetch_content_sha256
       FROM pages p
       LEFT JOIN fetches f ON f.id = p.latest_fetch_id
       WHERE p.url = ?
       LIMIT 1`,
    )
    .bind(url)
    .first<{
      id: string;
      latest_status: number | null;
      latest_outcome: string | null;
      latest_content_sha256: string | null;
      last_fetched_at: number | null;
      latest_fetch_id: string | null;
      fetch_content_sha256: string | null;
    }>();

  if (
    !pageRow ||
    pageRow.latest_outcome !== 'ok' ||
    !pageRow.latest_content_sha256 ||
    !pageRow.last_fetched_at ||
    now - pageRow.last_fetched_at > maxAgeMs ||
    (pageRow.latest_fetch_id && pageRow.latest_status !== 304 && pageRow.fetch_content_sha256 !== pageRow.latest_content_sha256)
  ) {
    return null;
  }

  if (pageRow.latest_status === 304 && pageRow.latest_fetch_id) {
    const latestNon304 = await metaDb
      .prepare(
        `SELECT content_sha256
         FROM fetches
         WHERE page_id = ? AND status != 304
         ORDER BY fetched_at DESC, rowid DESC
         LIMIT 1`,
      )
      .bind(pageRow.id)
      .first<{ content_sha256: string | null }>();
    if (latestNon304 && latestNon304.content_sha256 !== pageRow.latest_content_sha256) {
      return null;
    }
  }

  const [verified, docRow] = await Promise.all([
    isContentVerifiedInMetaD1(metaDb, pageRow.latest_content_sha256),
    metaDb
      .prepare(
        `SELECT id, r2_key, title, language
         FROM documents
         WHERE content_sha256 = ? AND format = 'markdown' AND pipeline_version = ?
         LIMIT 1`,
      )
      .bind(pageRow.latest_content_sha256, pipelineVersion)
      .first<{ id: string; r2_key: string; title: string | null; language: string | null }>(),
  ]);

  if (!verified || !docRow) return null;
  const obj = await bucket.get(docRow.r2_key);
  if (!obj) return null;
  const markdown = await obj.text();

  return {
    markdown,
    contentSha256: pageRow.latest_content_sha256,
    documentId: docRow.id,
    pipelineVersion,
    ...(docRow.title ? { title: docRow.title } : {}),
    ...(docRow.language ? { language: docRow.language } : {}),
    status: pageRow.latest_status ?? 200,
    lastFetchedAt: pageRow.last_fetched_at,
  };
}

export interface PrivateCachedScrapeRecord {
  url: string;
  finalUrl?: string;
  markdown: string;
  contentSha256: string;
  rawContentSha256?: string;
  blobSha256?: string;
  documentId: string;
  pipelineVersion: number;
  title?: string;
  description?: string;
  language?: string;
  favicon?: string;
  canonicalUrl?: string;
  contentType?: string;
  wordCount?: number;
  rendered?: boolean;
  renderedVia?: string;
  blockedTrackers?: number;
  contentState?: string;
  extractorId?: string;
  detected?: Record<string, unknown>;
  etag?: string;
  lastModified?: string;
  links?: string[];
  images?: ScrapedImage[];
  pages?: string[];
  status: number;
  lastFetchedAt: number;
  optionsHash?: string;
}

function defaultFaviconForUrl(urlStr: string): string | undefined {
  try {
    const u = new URL(urlStr);
    return `${u.origin}/favicon.ico`;
  } catch {
    return undefined;
  }
}

function canonicalizeCookiesValue(val: unknown): unknown {
  if (val === null || val === undefined) return val;
  if (typeof val === 'string') return val.trim();
  if (Array.isArray(val)) return val.map((item) => canonicalizeCookiesValue(item));
  if (typeof val === 'object') {
    const entries = Object.entries(val as Record<string, unknown>)
      .filter(([, v]) => v !== undefined)
      .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
      .map(([k, v]) => [k, canonicalizeCookiesValue(v)] as const);
    return Object.fromEntries(entries);
  }
  return val;
}

export async function hashCallerCookies(cookies: unknown): Promise<string> {
  return sha256HexString(JSON.stringify(canonicalizeCookiesValue(cookies)));
}

function r2PublicOptionsScrapeCacheKey(pipelineVersion: number, cacheKeySha256: string): string {
  return `derived/${pipelineVersion}/scrape-cache/${cacheKeySha256}.json`;
}

// Public options-cache index in META D1. A lookup checks this row before reading R2, because a blind GET on a missing key
// is an R2 `NoSuchKey`, which Workers Observability logs as an error-level `r2_get` span on every cold scrape. Writes
// upsert the row. `pages` cannot be the gate: inline (non-artifact) scrapes write this cache without a `pages` row.
const SCRAPE_CACHE_INDEX_DDL =
  'CREATE TABLE IF NOT EXISTS scrape_cache_index (r2_key TEXT PRIMARY KEY, last_fetched_at INTEGER NOT NULL)';
const scrapeCacheIndexReady = new WeakSet<object>();
async function ensureScrapeCacheIndex(metaDb: D1Database): Promise<boolean> {
  const key = metaDb as unknown as object;
  if (scrapeCacheIndexReady.has(key)) return true;
  try {
    await metaDb.prepare(SCRAPE_CACHE_INDEX_DDL).run();
    scrapeCacheIndexReady.add(key);
    return true;
  } catch {
    return false;
  }
}

export async function lookupOptionsScrapeCache(params: {
  bucket: R2Bucket;
  isPrivate: boolean;
  userId: string;
  url: string;
  optionsHash: string;
  maxAgeMs: number;
  pipelineVersion: number;
  metaDb?: D1Database;
  now: number;
}): Promise<PrivateCachedScrapeRecord | null> {
  const { bucket, isPrivate, userId, url, optionsHash, maxAgeMs, pipelineVersion, metaDb, now } = params;
  if (!(maxAgeMs > 0)) return null;
  const combinedHash = await sha256HexString(`${url}|${optionsHash}`);
  const r2Key = isPrivate
    ? r2PrivateScrapeCacheKey(userId, pipelineVersion, combinedHash)
    : r2PublicOptionsScrapeCacheKey(pipelineVersion, combinedHash);
  if (!isPrivate && metaDb && (await ensureScrapeCacheIndex(metaDb))) {
    const indexRow = await metaDb
      .prepare('SELECT last_fetched_at FROM scrape_cache_index WHERE r2_key = ? LIMIT 1')
      .bind(r2Key)
      .first<{ last_fetched_at: number | null }>()
      .catch(() => undefined);
    // `null` = no index row, so no entry was written: skip R2. `undefined` (query failed) falls through to the R2 read.
    if (indexRow === null) return null;
    if (indexRow && typeof indexRow.last_fetched_at === 'number' && now - indexRow.last_fetched_at > maxAgeMs) return null;
  }
  const obj = await bucket.get(r2Key).catch(() => null);
  if (!obj) return null;
  try {
    const parsed = (await obj.json()) as PrivateCachedScrapeRecord;
    if (
      !parsed ||
      parsed.url !== url ||
      parsed.optionsHash !== optionsHash ||
      typeof parsed.markdown !== 'string' ||
      typeof parsed.lastFetchedAt !== 'number' ||
      now - parsed.lastFetchedAt > maxAgeMs
    ) {
      return null;
    }
    if (!isPrivate && metaDb) {
      const pageRow = await metaDb
        .prepare(
          `SELECT p.id, p.last_fetched_at, p.latest_outcome, p.latest_status, p.latest_content_sha256, p.latest_fetch_id, f.content_sha256 AS fetch_content_sha256
           FROM pages p
           LEFT JOIN fetches f ON f.id = p.latest_fetch_id
           WHERE p.url = ?
           LIMIT 1`,
        )
        .bind(url)
        .first<{
          id: string;
          last_fetched_at: number | null;
          latest_outcome: string | null;
          latest_status: number | null;
          latest_content_sha256: string | null;
          latest_fetch_id: string | null;
          fetch_content_sha256: string | null;
        }>()
        .catch(() => null);
      let effectivePageSha =
        pageRow?.latest_fetch_id && pageRow.latest_status !== 304
          ? pageRow.fetch_content_sha256
          : (pageRow?.fetch_content_sha256 ?? pageRow?.latest_content_sha256);
      if (pageRow && pageRow.latest_status === 304 && pageRow.latest_fetch_id && !pageRow.fetch_content_sha256) {
        const latestNon304 = await metaDb
          .prepare(
            `SELECT content_sha256
             FROM fetches
             WHERE page_id = ? AND status != 304
             ORDER BY fetched_at DESC, rowid DESC
             LIMIT 1`,
          )
          .bind(pageRow.id)
          .first<{ content_sha256: string | null }>()
          .catch(() => null);
        if (latestNon304) {
          effectivePageSha = latestNon304.content_sha256 ?? null;
        }
      }
      const hasPageSha = typeof effectivePageSha === 'string' && effectivePageSha.length > 0;
      const hasCachedRawSha =
        typeof parsed.rawContentSha256 === 'string' && parsed.rawContentSha256.length > 0;
      if (pageRow) {
        if (hasPageSha && hasCachedRawSha && effectivePageSha !== parsed.rawContentSha256) {
          return null;
        }
        if (hasCachedRawSha) {
          if (
            typeof pageRow.last_fetched_at === 'number' &&
            pageRow.last_fetched_at >= parsed.lastFetchedAt &&
            (pageRow.latest_outcome !== 'ok' || !hasPageSha)
          ) {
            return null;
          }
        } else if (
          typeof pageRow.last_fetched_at === 'number' &&
          (pageRow.last_fetched_at > parsed.lastFetchedAt + 50 ||
            (pageRow.last_fetched_at >= parsed.lastFetchedAt &&
              (pageRow.latest_outcome !== 'ok' || !hasPageSha)))
        ) {
          return null;
        }
      }
    }
    return parsed;
  } catch {
    return null;
  }
}

export async function writeOptionsScrapeCache(params: {
  bucket: R2Bucket;
  isPrivate: boolean;
  userId: string;
  optionsHash: string;
  record: PrivateCachedScrapeRecord;
  metaDb?: D1Database;
}): Promise<void> {
  const { bucket, isPrivate, userId, optionsHash, record, metaDb } = params;
  const combinedHash = await sha256HexString(`${record.url}|${optionsHash}`);
  const r2Key = isPrivate
    ? r2PrivateScrapeCacheKey(userId, record.pipelineVersion, combinedHash)
    : r2PublicOptionsScrapeCacheKey(record.pipelineVersion, combinedHash);
  await bucket.put(r2Key, JSON.stringify({ ...record, optionsHash }), {
    httpMetadata: { contentType: 'application/json' },
    ...(isPrivate
      ? {
          customMetadata: {
            userId: sanitizeStorageUserId(userId),
            visibility: 'private',
          },
        }
      : {}),
  });
  if (!isPrivate && metaDb && (await ensureScrapeCacheIndex(metaDb))) {
    await metaDb
      .prepare(
        `INSERT INTO scrape_cache_index (r2_key, last_fetched_at) VALUES (?, ?)
         ON CONFLICT(r2_key) DO UPDATE SET last_fetched_at = excluded.last_fetched_at`,
      )
      .bind(r2Key, record.lastFetchedAt)
      .run()
      .catch(() => undefined);
  }
}

export async function deleteOptionsScrapeCache(params: {
  bucket: R2Bucket;
  isPrivate: boolean;
  userId: string;
  url: string;
  optionsHash: string;
  pipelineVersion: number;
}): Promise<void> {
  const { bucket, isPrivate, userId, url, optionsHash, pipelineVersion } = params;
  const combinedHash = await sha256HexString(`${url}|${optionsHash}`);
  const r2Key = isPrivate
    ? r2PrivateScrapeCacheKey(userId, pipelineVersion, combinedHash)
    : r2PublicOptionsScrapeCacheKey(pipelineVersion, combinedHash);
  await bucket.delete(r2Key);
}

export async function lookupPrivateCachedScrape(params: {
  bucket: R2Bucket;
  userId: string;
  url: string;
  maxAgeMs: number;
  pipelineVersion?: number;
  now?: number;
}): Promise<PrivateCachedScrapeRecord | null> {
  const { bucket, userId, url, maxAgeMs, pipelineVersion = SCRAPE_PIPELINE_VERSION, now = Date.now() } = params;
  if (!(maxAgeMs > 0) || !userId) return null;
  const urlSha = await sha256HexString(url);
  const key = r2PrivateScrapeCacheKey(userId, pipelineVersion, urlSha);
  const obj = await bucket.get(key).catch(() => null);
  if (!obj) return null;
  try {
    const parsed = (await obj.json()) as PrivateCachedScrapeRecord;
    if (
      !parsed ||
      parsed.url !== url ||
      typeof parsed.markdown !== 'string' ||
      typeof parsed.lastFetchedAt !== 'number' ||
      now - parsed.lastFetchedAt > maxAgeMs
    ) {
      return null;
    }
    return parsed;
  } catch {
    return null;
  }
}

export async function writePrivateCachedScrape(params: {
  bucket: R2Bucket;
  userId: string;
  url: string;
  markdown: string;
  rawBytes?: Uint8Array;
  title?: string;
  language?: string;
  status?: number;
  pipelineVersion?: number;
  optionsHash?: string;
  writeUrlCache?: boolean;
  now?: number;
}): Promise<{ blobSha256?: string; contentSha256: string; markdownSha256: string; documentId: string }> {
  const {
    bucket,
    userId,
    url,
    markdown,
    rawBytes,
    title,
    language,
    status = 200,
    pipelineVersion = SCRAPE_PIPELINE_VERSION,
    optionsHash,
    writeUrlCache = true,
    now = Date.now(),
  } = params;
  const markdownSha256 = await sha256HexString(markdown);
  let blobSha256: string | undefined;
  let contentSha256 = markdownSha256;
  if (rawBytes && rawBytes.byteLength > 0) {
    const writtenRaw = await writePrivateArtifactToR2({
      bucket,
      userId,
      rawBytes,
      retention: 'stored',
    });
    blobSha256 = writtenRaw.blobSha256;
    contentSha256 = writtenRaw.contentSha256;
  }
  await bucket.put(r2PrivateDerivedKey(userId, pipelineVersion, 'markdown', markdownSha256), markdown, {
    httpMetadata: { contentType: 'text/markdown; charset=utf-8' },
    customMetadata: {
      pipelineVersion: String(pipelineVersion),
      userId: sanitizeStorageUserId(userId),
      visibility: 'private',
    },
  });
  if (contentSha256 !== markdownSha256) {
    await bucket.put(r2PrivateDerivedKey(userId, pipelineVersion, 'markdown', contentSha256), markdown, {
      httpMetadata: { contentType: 'text/markdown; charset=utf-8' },
      customMetadata: {
        pipelineVersion: String(pipelineVersion),
        userId: sanitizeStorageUserId(userId),
        visibility: 'private',
      },
    });
  }
  const safeUser = sanitizeStorageUserId(userId);
  const documentId = `pdoc_${(await sha256HexString(`${safeUser}:${contentSha256}:${pipelineVersion}`)).slice(0, 32)}`;
  if (writeUrlCache) {
    const urlSha = await sha256HexString(url);
    const cacheEntry: PrivateCachedScrapeRecord = {
      url,
      markdown,
      contentSha256,
      ...(blobSha256 ? { blobSha256 } : {}),
      documentId,
      pipelineVersion,
      ...(title ? { title } : {}),
      ...(language ? { language } : {}),
      status,
      lastFetchedAt: now,
      ...(optionsHash ? { optionsHash } : {}),
    };
    await bucket.put(r2PrivateScrapeCacheKey(userId, pipelineVersion, urlSha), JSON.stringify(cacheEntry), {
      httpMetadata: { contentType: 'application/json' },
      customMetadata: {
        userId: safeUser,
        visibility: 'private',
      },
    });
  }
  return { ...(blobSha256 ? { blobSha256 } : {}), contentSha256, markdownSha256, documentId };
}

/**
 * `R5`: Looks up stored `etag` / `last_modified` + verified derived Markdown in `META` D1 + `ARTIFACTS` R2 when
 * `maxAgeMs` has expired (or `maxAgeMs === 0`), enabling `If-None-Match` / `If-Modified-Since` -> `304 Not Modified`
 * millisecond revalidation without re-downloading or re-chunking unchanged pages.
 */
export async function lookupRevalidationCandidate(params: {
  bucket: R2Bucket;
  metaDb: D1Database;
  url: string;
  pipelineVersion?: number;
}): Promise<{
  etag?: string;
  lastModified?: string;
  markdown: string;
  contentSha256: string;
  documentId: string;
  pipelineVersion: number;
  title?: string;
  language?: string;
} | null> {
  const { bucket, metaDb, url, pipelineVersion = SCRAPE_PIPELINE_VERSION } = params;
  const pageRow = await metaDb
    .prepare(
      `SELECT p.id, p.latest_outcome, p.latest_status, p.latest_content_sha256, p.etag, p.last_modified, p.latest_fetch_id, f.via AS fetch_via, f.content_sha256 AS fetch_content_sha256
       FROM pages p
       LEFT JOIN fetches f ON f.id = p.latest_fetch_id
       WHERE p.url = ?
       LIMIT 1`,
    )
    .bind(url)
    .first<{
      id: string;
      latest_outcome: string | null;
      latest_status: number | null;
      latest_content_sha256: string | null;
      etag: string | null;
      last_modified: string | null;
      latest_fetch_id: string | null;
      fetch_via: string | null;
      fetch_content_sha256: string | null;
    }>();

  if (
    !pageRow ||
    pageRow.latest_outcome !== 'ok' ||
    !pageRow.latest_content_sha256 ||
    (!pageRow.etag && !pageRow.last_modified) ||
    (pageRow.latest_fetch_id &&
      pageRow.latest_status !== 304 &&
      pageRow.fetch_via === 'container' &&
      pageRow.fetch_content_sha256 !== pageRow.latest_content_sha256)
  ) {
    return null;
  }

  if (pageRow.latest_status === 304 && pageRow.latest_fetch_id) {
    const latestNon304 = await metaDb
      .prepare(
        `SELECT via, content_sha256
         FROM fetches
         WHERE page_id = ? AND status != 304
         ORDER BY fetched_at DESC, rowid DESC
         LIMIT 1`,
      )
      .bind(pageRow.id)
      .first<{ via: string | null; content_sha256: string | null }>();
    if (
      latestNon304 &&
      latestNon304.via === 'container' &&
      latestNon304.content_sha256 !== pageRow.latest_content_sha256
    ) {
      return null;
    }
  }

  const [verified, docRow] = await Promise.all([
    isContentVerifiedInMetaD1(metaDb, pageRow.latest_content_sha256),
    metaDb
      .prepare(
        `SELECT id, r2_key, title, language
         FROM documents
         WHERE content_sha256 = ? AND format = 'markdown' AND pipeline_version = ?
         LIMIT 1`,
      )
      .bind(pageRow.latest_content_sha256, pipelineVersion)
      .first<{ id: string; r2_key: string; title: string | null; language: string | null }>(),
  ]);
  if (!verified || !docRow) return null;
  const obj = await bucket.get(docRow.r2_key);
  if (!obj) return null;
  const markdown = await obj.text();

  return {
    ...(pageRow.etag ? { etag: pageRow.etag } : {}),
    ...(pageRow.last_modified ? { lastModified: pageRow.last_modified } : {}),
    markdown,
    contentSha256: pageRow.latest_content_sha256,
    documentId: docRow.id,
    pipelineVersion,
    ...(docRow.title ? { title: docRow.title } : {}),
    ...(docRow.language ? { language: docRow.language } : {}),
  };
}

export async function touchRevalidatedPage(metaDb: D1Database, url: string, now = Date.now()): Promise<void> {
  await metaDb
    .prepare('UPDATE pages SET last_fetched_at = ? WHERE url = ?')
    .bind(now, url)
    .run()
    .catch(() => undefined);
}

export type ScrapeFormatInput =
  | 'markdown'
  | 'text'
  | 'summary'
  | 'product'
  | 'rawBase64'
  | 'html'
  | 'rawHtml'
  | 'links'
  | 'images'
  | 'branding'
  | 'llmsTxt'
  | 'screenshot'
  | 'changes'
  | { type: 'json'; prompt?: string; schema?: Record<string, unknown> }
  | { type: 'attributes'; selectors: Array<{ selector: string; attribute: string }> }
  | { type: 'screenshot'; fullPage?: boolean; quality?: number; viewport?: { width?: number; height?: number } }
  | { type: 'changeTracking'; modes?: Array<'git-diff' | 'json'>; tag?: string };

export interface ScrapeRequestPayload {
  url?: unknown;
  formats?: unknown;
  onlyMainContent?: unknown;
  includeImages?: unknown;
  includeTags?: unknown;
  excludeTags?: unknown;
  maxChars?: unknown;
  defaultMaxChars?: unknown;
  maxAgeMs?: unknown;
  maxAge?: unknown;
  discoverLlmsTxt?: unknown;
  preferOriginMarkdown?: unknown;
  redactPii?: unknown;
  checkPromptInjection?: unknown;
  query?: unknown;
  jsonFilter?: unknown;
  headers?: unknown;
  renderMode?: unknown;
  blockTrackers?: unknown;
  mobile?: unknown;
  location?: unknown;
  actions?: unknown;
  parsers?: unknown;
  llm?: unknown;
  waitForMs?: unknown;
  waitFor?: unknown;
  timeout?: unknown;
  waitSelector?: unknown;
  maxPages?: unknown;
  ocr?: unknown;
  waybackFallback?: unknown;
  spaFallback?: unknown;
  noCache?: unknown;
  ephemeral?: unknown;
  atsLiteBoard?: unknown;
  visibility?: unknown;
  collectionId?: unknown;
  target?: unknown;
  site?: unknown;
}

const MAX_MARKDOWN_SANITIZE_CHARS = 8 * 1024 * 1024;

function isLazyPlaceholderImageUrl(urlStr: string): boolean {
  const trimmed = urlStr.trim();
  if (!trimmed || trimmed.startsWith('data:')) return true;
  return /(?:^|[/_-])placeholder(?:[-_]{1,2}[a-z0-9_-]+)?\.(?:png|gif|svg|webp|jpe?g|avif)(?:$|[?#])/i.test(trimmed);
}

function isTinyOrAvatarImageUrl(urlStr: string, alt = ''): boolean {
  if (isLazyPlaceholderImageUrl(urlStr)) return true;
  if (/\b(avatar|gravatar|author[-_]?photo|author[-_]?image|1x1|pixel|spacer)\b/i.test(`${alt} ${urlStr}`)) {
    return true;
  }
  const dimMatches = [...urlStr.matchAll(/[?&](?:w|width|h|height)=(\d{1,4})\b/gi)];
  for (const m of dimMatches) {
    const dim = Number(m[1]);
    if (Number.isFinite(dim) && dim > 0 && dim <= 4) return true;
  }
  return false;
}

export function sanitizeInlineHtmlInMarkdown(md: string, baseUrl?: string, allowPdfPageMarkers = false): string {
  if (!md) return '';
  const meta = {
    baseUrl: baseUrl ?? '',
    allowPdfPageMarkers: Boolean(allowPdfPageMarkers),
  };
  if (md.length <= MAX_SANITIZER_WASM_UTF8_BYTES) {
    try {
      return callCoreWasmRawString('sanitize_markdown', meta, md);
    } catch (err) {
      if (!isWasmInputBudgetExceededError(err)) {
        return escapeMarkdownFallbackLinear(md);
      }
    }
  }
  const { text: boundedMd } = cutMarkdownToSanitizerBudget(md);
  try {
    return callCoreWasmRawString('sanitize_markdown', meta, boundedMd);
  } catch {
    return escapeMarkdownFallbackLinear(boundedMd);
  }
}

export function parseMarkdownFrontmatter(md: string): { title?: string; description?: string; body: string } {
  if (!md || !md.startsWith('---')) return { body: md };
  if (md.length > 65_536) {
    const head = md.slice(0, 65_536);
    const parsedHead = callCoreWasm<{ title?: string; description?: string; body: string }>('parse_frontmatter', { md: head });
    const consumedPrefix = head.length - (parsedHead.body ?? head).length;
    return {
      ...(parsedHead.title ? { title: parsedHead.title } : {}),
      ...(parsedHead.description ? { description: parsedHead.description } : {}),
      body: consumedPrefix > 0 ? md.slice(consumedPrefix) : md,
    };
  }
  const res = callCoreWasm<{ title?: string; description?: string; body: string }>('parse_frontmatter', { md });
  return {
    ...(res.title ? { title: res.title } : {}),
    ...(res.description ? { description: res.description } : {}),
    body: res.body ?? md,
  };
}

export function extractMarkdownLinksAndImages(
  md: string,
  baseUrl: string,
  includeImages: boolean,
): { links: string[]; images: ScrapedImage[]; title?: string; description?: string } {
  const { text: bounded } = cutMarkdownToSanitizerBudget(String(md ?? ''));
  const res = callCoreWasmRaw<{
    links?: string[];
    images?: ScrapedImage[];
    title?: string;
    description?: string;
  }>(
    'extract_md_links_images',
    {
      baseUrl: String(baseUrl ?? ''),
      includeImages: Boolean(includeImages),
    },
    bounded,
  );
  return {
    links: res.links ?? [],
    images: res.images ?? [],
    ...(res.title ? { title: res.title } : {}),
    ...(res.description ? { description: res.description } : {}),
  };
}

export function sanitizeRecordUrlsDeep<T>(
  value: T,
  depth = 0,
  memo?: WeakMap<object, unknown>,
  inStack?: WeakSet<object>,
): T {
  if (depth > 16 || value === null || value === undefined) return value;
  if (typeof value === 'string') {
    const trimmed = value.trim();
    if (/^https?:\/\/\S+$/i.test(trimmed)) {
      const encoded = percentEncodeUnsafeRecordUrlChars(trimmed);
      return (encoded === value ? value : encoded) as unknown as T;
    }
    return value;
  }
  if (typeof value !== 'object') return value;
  const obj = value as object;
  const cache = memo ?? new WeakMap<object, unknown>();
  const stack = inStack ?? new WeakSet<object>();
  if (stack.has(obj)) return (Array.isArray(value) ? [] : {}) as unknown as T;
  if (cache.has(obj)) return cache.get(obj) as T;
  stack.add(obj);
  try {
    if (Array.isArray(value)) {
      let changed = false;
      const out = new Array<unknown>(value.length);
      for (let i = 0; i < value.length; i++) {
        const orig = value[i];
        const next = sanitizeRecordUrlsDeep(orig, depth + 1, cache, stack);
        if (next !== orig) changed = true;
        out[i] = next;
      }
      const res = (changed ? out : value) as unknown as T;
      cache.set(obj, res);
      return res;
    }
    const src = value as Record<string, unknown>;
    let cloned: Record<string, unknown> | null = null;
    const keys = Object.keys(src);
    for (let i = 0; i < keys.length; i++) {
      const k = keys[i]!;
      const orig = src[k];
      const next = sanitizeRecordUrlsDeep(orig, depth + 1, cache, stack);
      if (next !== orig) {
        if (!cloned) cloned = { ...src };
        cloned[k] = next;
      }
    }
    const res = (cloned ?? value) as unknown as T;
    cache.set(obj, res);
    return res;
  } finally {
    stack.delete(obj);
  }
}

function nonEmptyTrimmedStr(val: unknown): string | undefined {
  if (typeof val !== 'string') return undefined;
  const trimmed = val.trim();
  return trimmed ? trimmed : undefined;
}

function normalizeProductPriceFromRecord(val: unknown): number | string | undefined {
  if (typeof val === 'number' && Number.isFinite(val) && val > 0) return val;
  if (typeof val === 'string') {
    const trimmed = val.trim();
    if (!trimmed) return undefined;
    if (/^\d+(?:\.\d+)?$/.test(trimmed)) {
      const parsed = Number(trimmed);
      if (Number.isFinite(parsed) && parsed > 0) return parsed;
    }
    return trimmed;
  }
  return undefined;
}

function normalizeProductAvailabilityFromRecord(val: unknown): string | undefined {
  if (typeof val === 'boolean') return val ? 'InStock' : 'OutOfStock';
  if (typeof val !== 'string') return undefined;
  const stripped = val.trim().replace(/^https?:\/\/schema\.org\//i, '');
  if (!stripped) return undefined;
  const low = stripped.toLowerCase().replace(/\s+/g, ' ');
  if (
    low.includes('not in stock') ||
    low.includes('not-in-stock') ||
    low.includes('not instock') ||
    low.includes('not available') ||
    low.includes('no longer available') ||
    low.includes('out of stock') ||
    low.includes('outofstock') ||
    low.includes('sold out') ||
    low.includes('unavailable')
  ) {
    return 'OutOfStock';
  }
  if (low.includes('preorder') || low.includes('pre-order')) return 'PreOrder';
  if (low.includes('backorder') || low.includes('back-order')) return 'BackOrder';
  if (low.includes('in stock') || low.includes('instock') || low === 'available') return 'InStock';
  return stripped;
}

function isProductBearingRecord(record: Record<string, unknown>): boolean {
  if (typeof record.platform === 'string' && record.platform.trim()) return true;
  if (Array.isArray(record.variants) && record.variants.length > 0) return true;
  for (const k of ['sku', 'gtin', 'gtin13', 'mpn', 'price', 'availability', 'available', 'priceCurrency', 'currency', 'vendor', 'brand']) {
    const v = record[k];
    if (v !== undefined && v !== null && v !== '') return true;
  }
  return false;
}

export function backfillProductFromRecord(
  productOut: Record<string, unknown> | null,
  record: Record<string, unknown> | undefined,
  ctx: {
    finalUrl: string;
    fallbackTitle?: string;
    fallbackDescription?: string;
    preferRecordAvailability?: boolean;
  },
): Record<string, unknown> | null {
  if (!record || typeof record !== 'object' || Array.isArray(record)) return productOut;
  if (!productOut && !isProductBearingRecord(record)) return null;

  const variantsRaw = Array.isArray(record.variants)
    ? record.variants.filter((v): v is Record<string, unknown> => Boolean(v && typeof v === 'object' && !Array.isArray(v)))
    : [];
  const v0 = variantsRaw[0];
  const out: Record<string, unknown> = productOut ? { ...productOut } : {};

  if (!nonEmptyTrimmedStr(out.url)) {
    out.url = sanitizeSchemaHttpsUrl(record.url, ctx.finalUrl) ?? ctx.finalUrl;
  }
  if (!nonEmptyTrimmedStr(out.title)) {
    const t = nonEmptyTrimmedStr(record.title) ?? nonEmptyTrimmedStr(record.name) ?? nonEmptyTrimmedStr(ctx.fallbackTitle);
    if (t) out.title = t;
  }
  if (!nonEmptyTrimmedStr(out.description)) {
    const d =
      nonEmptyTrimmedStr(record.descriptionText) ??
      nonEmptyTrimmedStr(record.description) ??
      nonEmptyTrimmedStr(ctx.fallbackDescription);
    if (d) out.description = d;
  }
  if (!nonEmptyTrimmedStr(out.brand)) {
    const b = nonEmptyTrimmedStr(record.brand) ?? nonEmptyTrimmedStr(record.vendor) ?? nonEmptyTrimmedStr(record.manufacturer);
    if (b) out.brand = b;
  }
  if (!nonEmptyTrimmedStr(out.sku)) {
    const s = nonEmptyTrimmedStr(record.sku) ?? nonEmptyTrimmedStr(v0?.sku);
    if (s) out.sku = s;
  }
  if (!nonEmptyTrimmedStr(out.mpn)) {
    const m = nonEmptyTrimmedStr(record.mpn);
    if (m) out.mpn = m;
  }
  if (!nonEmptyTrimmedStr(out.gtin)) {
    const g =
      nonEmptyTrimmedStr(record.gtin) ??
      nonEmptyTrimmedStr(record.gtin13) ??
      nonEmptyTrimmedStr(record.upc) ??
      nonEmptyTrimmedStr(record.ean) ??
      nonEmptyTrimmedStr(v0?.barcode);
    if (g) out.gtin = g;
  }
  if (out.price === undefined || out.price === null || out.price === '') {
    const p = normalizeProductPriceFromRecord(record.price ?? v0?.price);
    if (p !== undefined) out.price = p;
  }
  if (!nonEmptyTrimmedStr(out.currency)) {
    const c =
      nonEmptyTrimmedStr(record.currency) ??
      nonEmptyTrimmedStr(record.priceCurrency) ??
      nonEmptyTrimmedStr(v0?.currency);
    if (c) out.currency = c;
  }
  const topAvail = normalizeProductAvailabilityFromRecord(record.availability ?? record.available);
  let variantAggAvail: string | undefined;
  if (!topAvail && variantsRaw.length > 0) {
    const normAvails: string[] = [];
    for (const vr of variantsRaw) {
      const va = normalizeProductAvailabilityFromRecord(vr.availability ?? vr.available);
      if (va) normAvails.push(va);
    }
    if (normAvails.length === 1) {
      variantAggAvail = normAvails[0];
    } else if (normAvails.length > 1) {
      variantAggAvail =
        normAvails.find((a) => a === 'InStock') ??
        normAvails.find((a) => a === 'PreOrder') ??
        normAvails.find((a) => a === 'BackOrder') ??
        normAvails[0];
    }
  }
  const recordAvail = topAvail ?? variantAggAvail;
  const existingAvail = normalizeProductAvailabilityFromRecord(out.availability);
  if (ctx.preferRecordAvailability && recordAvail) {
    out.availability = recordAvail;
  } else if (existingAvail) {
    out.availability = existingAvail;
  } else if (recordAvail) {
    out.availability = recordAvail;
  }
  if (!Array.isArray(out.images) || out.images.length === 0) {
    const imgSet = new Set<string>();
    const rawCandidates: unknown[] = [];
    if (Array.isArray(record.images)) rawCandidates.push(...record.images);
    if (record.image !== undefined) rawCandidates.push(record.image);
    if (v0?.image !== undefined) rawCandidates.push(v0.image);
    for (const cand of rawCandidates) {
      const urlCand =
        typeof cand === 'string'
          ? cand
          : cand && typeof cand === 'object' && !Array.isArray(cand)
            ? (cand as Record<string, unknown>).url ?? (cand as Record<string, unknown>).src
            : undefined;
      const safe = sanitizeSchemaHttpsUrl(urlCand, ctx.finalUrl);
      if (safe) imgSet.add(safe);
      if (imgSet.size >= 20) break;
    }
    if (imgSet.size > 0) out.images = [...imgSet];
  }
  if ((!Array.isArray(out.variants) || out.variants.length === 0) && variantsRaw.length > 0) {
    const mappedVariants = variantsRaw.slice(0, 30).map((vr) => {
      const vm: Record<string, unknown> = {};
      const vn = nonEmptyTrimmedStr(vr.title) ?? nonEmptyTrimmedStr(vr.name);
      if (vn) vm.name = vn;
      const vs = nonEmptyTrimmedStr(vr.sku);
      if (vs) vm.sku = vs;
      const vp = normalizeProductPriceFromRecord(vr.price);
      if (vp !== undefined) vm.price = vp;
      const vc = nonEmptyTrimmedStr(vr.currency) ?? nonEmptyTrimmedStr(vr.priceCurrency);
      if (vc) vm.currency = vc;
      const va = normalizeProductAvailabilityFromRecord(vr.availability ?? vr.available);
      if (va) vm.availability = va;
      return vm;
    });
    if (mappedVariants.length > 0) out.variants = mappedVariants;
  }

  return Object.keys(out).length > 0 ? out : null;
}

const MAX_NODE_SUPPLIED_LINKS = 1_000;

/**
 * Returns `item` with node-supplied `links` / `favicon` passed through `sanitizeSchemaHttpsUrl` (https-only, public
 * host, unsafe-char percent-encoding): unsafe / private / non-https entries are dropped, duplicates collapsed.
 */
export function sanitizeNodeSuppliedUrls<T extends Record<string, unknown>>(item: T, baseUrl: string): T {
  const out: Record<string, unknown> = { ...item };
  if ('links' in item) {
    const links: string[] = [];
    if (Array.isArray(item.links)) {
      const seen = new Set<string>();
      for (const raw of item.links) {
        if (links.length >= MAX_NODE_SUPPLIED_LINKS) break;
        if (typeof raw !== 'string' || !raw || raw.length > 8_192) continue;
        const safe = sanitizeSchemaHttpsUrl(raw, baseUrl);
        if (safe && !seen.has(safe)) {
          seen.add(safe);
          links.push(safe);
        }
      }
    }
    out.links = links;
  }
  if ('favicon' in item) {
    const safeFavicon =
      typeof item.favicon === 'string' && item.favicon && item.favicon.length <= 8_192
        ? sanitizeSchemaHttpsUrl(item.favicon, baseUrl)
        : undefined;
    if (safeFavicon) out.favicon = safeFavicon;
    else delete out.favicon;
  }
  if ('images' in item) {
    // Node-supplied images get the same URL treatment as links; alt text is kept as plain bounded text.
    const images: Array<{ url: string; alt?: string }> = [];
    if (Array.isArray(item.images)) {
      const seen = new Set<string>();
      for (const raw of item.images as unknown[]) {
        if (images.length >= MAX_NODE_SUPPLIED_LINKS) break;
        const rawUrl = typeof raw === 'string' ? raw : raw && typeof raw === 'object' ? (raw as { url?: unknown }).url : undefined;
        if (typeof rawUrl !== 'string' || !rawUrl || rawUrl.length > 8_192) continue;
        const safe = sanitizeSchemaHttpsUrl(rawUrl, baseUrl);
        if (!safe || seen.has(safe)) continue;
        seen.add(safe);
        const rawAlt = raw && typeof raw === 'object' ? (raw as { alt?: unknown }).alt : undefined;
        const alt = typeof rawAlt === 'string' ? sanitizeScrapedMetadataField(rawAlt, 300) : undefined;
        images.push(alt ? { url: safe, alt } : { url: safe });
      }
    }
    out.images = images;
  }
  return out as T;
}

export function redactPiiDeep<T>(
  value: T,
  depth = 0,
  memo?: WeakMap<object, unknown>,
  inStack?: WeakSet<object>,
): T {
  if (depth > 16 || value === null || value === undefined) return value;
  if (typeof value === 'string') {
    let redacted = redactPiiText(value);
    if (redacted !== value && /^https?:\/\/\S+$/i.test(value.trim())) {
      redacted = percentEncodeUnsafeRecordUrlChars(redacted);
    }
    return redacted as unknown as T;
  }
  if (typeof value !== 'object') return value;
  const obj = value as object;
  const cache = memo ?? new WeakMap<object, unknown>();
  const stack = inStack ?? new WeakSet<object>();
  if (stack.has(obj)) return (Array.isArray(value) ? [] : {}) as unknown as T;
  if (cache.has(obj)) return cache.get(obj) as T;
  stack.add(obj);
  try {
    if (Array.isArray(value)) {
      let changed = false;
      const out = new Array<unknown>(value.length);
      for (let i = 0; i < value.length; i++) {
        const orig = value[i];
        const next = redactPiiDeep(orig, depth + 1, cache, stack);
        if (next !== orig) changed = true;
        out[i] = next;
      }
      const res = (changed ? out : value) as unknown as T;
      cache.set(obj, res);
      return res;
    }
    const src = value as Record<string, unknown>;
    let cloned: Record<string, unknown> | null = null;
    const keys = Object.keys(src);
    for (let i = 0; i < keys.length; i++) {
      const k = keys[i]!;
      const orig = src[k];
      const next = redactPiiDeep(orig, depth + 1, cache, stack);
      if (next !== orig) {
        if (!cloned) cloned = { ...src };
        cloned[k] = next;
      }
    }
    const res = (cloned ?? value) as unknown as T;
    cache.set(obj, res);
    return res;
  } finally {
    stack.delete(obj);
  }
}

export function closeUnclosedCodeAfterSlice(sliced: string, allowPdfPageMarkers = false): string {
  return sanitizeMarkdownPageSlice(sliced, 0, sliced, allowPdfPageMarkers);
}

export function sliceMarkdownWithOffsetAndMaxChars(
  fullMd: string,
  offset = 0,
  maxChars?: number,
  allowPdfPageMarkers = false,
): {
  markdown: string;
  truncated: boolean;
  offset: number;
  totalChars: number;
  nextOffset: number | null;
  remainingChars: number;
} {
  const totalChars = fullMd.length;
  const safeOffset = Math.min(totalChars, Math.max(0, Math.floor(offset)));
  const windowSrc = safeOffset > 0 ? fullMd.slice(safeOffset) : fullMd;
  if (maxChars !== undefined && windowSrc.length > maxChars) {
    let cut = maxChars;
    const minCut = Math.floor(maxChars * 0.6);
    const paraBreak = windowSrc.lastIndexOf('\n\n', cut);
    const lineBreak = windowSrc.lastIndexOf('\n', cut);
    const spaceBreak = windowSrc.lastIndexOf(' ', cut);
    if (paraBreak >= minCut) cut = paraBreak;
    else if (lineBreak >= minCut) cut = lineBreak;
    else if (spaceBreak >= minCut) cut = spaceBreak;
    const rawSliced = trimTrailingAsciiWhitespaceLinear(windowSrc.slice(0, cut));
    const step = rawSliced.length > 0 ? rawSliced.length : cut;
    const nextOffset = Math.min(totalChars, safeOffset + step);
    const remainingChars = Math.max(0, totalChars - nextOffset);
    const closed = sanitizeMarkdownPageSlice(fullMd, safeOffset, rawSliced, allowPdfPageMarkers);
    return {
      markdown: closed,
      truncated: true,
      offset: safeOffset,
      totalChars,
      nextOffset,
      remainingChars,
    };
  }
  const cleanSlice = sanitizeMarkdownPageSlice(fullMd, safeOffset, windowSrc, allowPdfPageMarkers);
  return {
    markdown: cleanSlice,
    truncated: false,
    offset: safeOffset,
    totalChars,
    nextOffset: null,
    remainingChars: 0,
  };
}

export function collapseAnimatedCounterTickersLinear(prose: string): string {
  if (!prose || (!prose.includes(',') && !/\d{4}/.test(prose))) return prose;
  return callCoreWasm<{ out: string }>('collapse_tickers', { prose }).out;
}

export function finalizeScrapedMarkdown(
  rawMd: string,
  opts: {
    isPdf: boolean;
    includeImages: boolean;
    maxChars?: number;
    baseUrl?: string;
    preserveOriginMarkdown?: boolean;
    allowPdfPageMarkers?: boolean;
  },
): {
  markdown: string;
  truncated?: boolean;
  totalChars?: number;
  nextOffset?: number;
  remainingChars?: number;
  /** Part of the input was cut to the 4 MiB sanitizer budget (before or after sanitizing) and is not retrievable. */
  sourceTruncated?: boolean;
  /** Raw input length in chars when `sourceTruncated` (informational; not a pagination coordinate). */
  sourceChars?: number;
  frontmatterTitle?: string;
  frontmatterDescription?: string;
} {
  const { text: boundedInput, cut: cutBySanitizerBudget } = cutMarkdownToSanitizerBudget(rawMd);
  const fm = opts.isPdf ? { body: boundedInput } : parseMarkdownFrontmatter(boundedInput);
  const fmMeta = {
    ...(fm.title ? { frontmatterTitle: fm.title } : {}),
    ...(fm.description ? { frontmatterDescription: fm.description } : {}),
  };
  const runFinalize = (body: string): string =>
    callCoreWasmRaw<{ markdown: string }>(
      'finalize_markdown',
      {
        baseUrl: opts.baseUrl ?? '',
        options: {
          baseUrl: opts.baseUrl ?? '',
          includeImages: Boolean(opts.includeImages),
          isPdf: Boolean(opts.isPdf),
          preserveOriginMarkdown: Boolean(opts.preserveOriginMarkdown),
          allowPdfPageMarkers: Boolean(opts.allowPdfPageMarkers),
        },
      },
      body,
    ).markdown ?? '';
  let md = '';
  // Sanitizing can grow a document (e.g. every `<` becomes `&lt;`, so a 3.6 MB `a < b` doc becomes 5.4M chars).
  // Every downstream WASM helper (redactPiiText, stripInvisible, neutralize*, decodeHtmlEntities, the read_artifact
  // re-sanitizer) silently cuts input at the sanitizer budget, so the output is bounded to that budget HERE and the
  // cut is reported as truncation (instead of being lost later with no flag).
  let cutAfterSanitize = false;
  try {
    let body = fm.body;
    md = runFinalize(body);
    for (let attempt = 0; attempt < 3 && cutMarkdownToSanitizerBudget(md).cut; attempt++) {
      // Re-sanitize a proportionally shorter prefix of the input so the full sanitizer (not a raw cut) closes fences.
      const mdBytes = SCRAPE_UTF8_ENCODER.encode(md).byteLength;
      const bodyBytes = SCRAPE_UTF8_ENCODER.encode(body).byteLength;
      const targetBytes = Math.floor(bodyBytes * (MAX_SANITIZER_WASM_UTF8_BYTES / mdBytes) * 0.95);
      const shorter = cutMarkdownToSanitizerBudget(body, Math.max(1, targetBytes)).text;
      if (!shorter || shorter.length >= body.length) break;
      body = shorter;
      md = runFinalize(body);
      cutAfterSanitize = true;
    }
    const bounded = cutMarkdownToSanitizerBudget(md);
    if (bounded.cut) {
      md = trimTrailingAsciiWhitespaceLinear(bounded.text);
      cutAfterSanitize = true;
    }
  } catch {
    const escapedFull = escapeMarkdownFallbackLinear(fm.body);
    const escapedBounded = cutMarkdownToSanitizerBudget(escapedFull);
    const escapedFallback = escapedBounded.text;
    const overMax = Boolean(opts.maxChars && escapedFallback.length > opts.maxChars);
    const outMd = overMax ? escapedFallback.slice(0, opts.maxChars) : escapedFallback;
    const fallbackTruncated = cutBySanitizerBudget || escapedBounded.cut || escapedFallback.length < escapedFull.length || overMax;
    return {
      markdown: outMd,
      ...(fallbackTruncated
        ? {
            truncated: true,
            totalChars: escapedFallback.length,
            nextOffset: outMd.length,
            remainingChars: Math.max(0, escapedFallback.length - outMd.length),
            ...(cutBySanitizerBudget || escapedBounded.cut ? { sourceTruncated: true, sourceChars: rawMd.length } : {}),
          }
        : {}),
      ...fmMeta,
    };
  }
  const sourceTruncated = cutBySanitizerBudget || cutAfterSanitize;
  // Pagination coordinates are sanitized-output chars: the same units `read_artifact` (`format: 'markdown'`) serves
  // from the stored sanitized Markdown. Input that never reached the sanitizer is reported via `sourceTruncated` /
  // `sourceChars` (raw input chars), never mixed into `totalChars` / `remainingChars` (nothing can fetch it).
  const sourceMeta = sourceTruncated ? { sourceTruncated: true as const, sourceChars: rawMd.length } : {};
  if (opts.maxChars && md.length > opts.maxChars) {
    const totalChars = md.length;
    let cut = opts.maxChars;
    const minCut = Math.floor(opts.maxChars * 0.6);
    const paraBreak = md.lastIndexOf('\n\n', cut);
    const lineBreak = md.lastIndexOf('\n', cut);
    const spaceBreak = md.lastIndexOf(' ', cut);
    if (paraBreak >= minCut) cut = paraBreak;
    else if (lineBreak >= minCut) cut = lineBreak;
    else if (spaceBreak >= minCut) cut = spaceBreak;
    const rawSliced = trimTrailingAsciiWhitespaceLinear(md.slice(0, cut));
    const nextOffset = rawSliced.length > 0 ? rawSliced.length : cut;
    const remainingChars = Math.max(0, totalChars - nextOffset);
    const sliced = sanitizeMarkdownPageSlice(md, 0, rawSliced, Boolean(opts.allowPdfPageMarkers));
    return { markdown: sliced, truncated: true, totalChars, nextOffset, remainingChars, ...sourceMeta, ...fmMeta };
  }
  if (sourceTruncated) {
    return {
      markdown: md,
      truncated: true,
      totalChars: md.length,
      nextOffset: md.length,
      remainingChars: 0,
      ...sourceMeta,
      ...fmMeta,
    };
  }
  return { markdown: md, ...fmMeta };
}

interface PdfOcrContainerReply {
  ok?: boolean;
  sha256?: string;
  bytes?: number;
  pageCount?: number;
  totalChars?: number;
  markdown?: string;
  ocr?: {
    mode?: string;
    engine?: string | null;
    pagesAttempted?: number;
    pagesOcred?: number;
    pagesSkipped?: number;
    skippedReason?: string | null;
  };
  error?: string;
  message?: string;
}

function decodeBase64ToBytes(b64: string): Uint8Array {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) {
    out[i] = bin.charCodeAt(i);
  }
  return out;
}

function hasPdfMagicHeader(bytes: Uint8Array): boolean {
  const limit = Math.min(bytes.byteLength, 1024);
  for (let i = 0; i <= limit - 5; i++) {
    if (
      bytes[i] === 0x25 && // %
      bytes[i + 1] === 0x50 && // P
      bytes[i + 2] === 0x44 && // D
      bytes[i + 3] === 0x46 && // F
      bytes[i + 4] === 0x2d // -
    ) {
      return true;
    }
  }
  return false;
}

const CODE_EXT_LANG_MAP: Record<string, string> = {
  ts: 'ts',
  tsx: 'tsx',
  js: 'js',
  jsx: 'jsx',
  mjs: 'js',
  cjs: 'js',
  json: 'json',
  jsonc: 'jsonc',
  py: 'python',
  go: 'go',
  rs: 'rust',
  rb: 'ruby',
  java: 'java',
  kt: 'kotlin',
  cs: 'csharp',
  cpp: 'cpp',
  c: 'c',
  h: 'c',
  sh: 'bash',
  bash: 'bash',
  zsh: 'zsh',
  ps1: 'powershell',
  yml: 'yaml',
  yaml: 'yaml',
  toml: 'toml',
  sql: 'sql',
  html: 'html',
  css: 'css',
  scss: 'scss',
  xml: 'xml',
  proto: 'protobuf',
  graphql: 'graphql',
};

function parseGitHubBlobRawTarget(urlStr: string): {
  rawUrl: string;
  repoSlug: string;
  filePath: string;
  fenceLang: string;
  isMarkdown: boolean;
} | null {
  let u: URL;
  try {
    u = new URL(urlStr);
  } catch {
    return null;
  }
  if (u.hostname.toLowerCase() !== 'github.com') return null;
  const parts = u.pathname.split('/').filter(Boolean);
  if (parts.length < 5 || parts[2] !== 'blob') return null;
  const owner = parts[0]!;
  const repo = parts[1]!;
  if (['orgs', 'settings', 'sponsors', 'users', 'login', 'marketplace'].includes(owner.toLowerCase())) {
    return null;
  }
  const restParts = parts.slice(3);
  let filePath = restParts.slice(1).join('/');
  if (restParts[0] === 'refs' && (restParts[1] === 'heads' || restParts[1] === 'tags') && restParts.length >= 4) {
    filePath = restParts.slice(3).join('/');
  }
  if (!filePath) return null;
  const baseName = filePath.split('/').pop() ?? filePath;
  const extMatch = /\.([a-z0-9]+)$/i.exec(baseName);
  const ext = extMatch?.[1]?.toLowerCase() ?? '';
  const isMarkdown = ext === 'md' || ext === 'mdx' || ext === 'markdown';
  const fenceLang =
    baseName.toLowerCase() === 'dockerfile'
      ? 'dockerfile'
      : baseName.toLowerCase() === 'makefile'
        ? 'makefile'
        : (CODE_EXT_LANG_MAP[ext] ?? ext);
  return {
    rawUrl: `https://raw.githubusercontent.com/${owner}/${repo}/${restParts.join('/')}`,
    repoSlug: `${owner}/${repo}`,
    filePath,
    fenceLang,
    isMarkdown,
  };
}

function parseGitHubCommitPatchTarget(urlStr: string): {
  patchUrl: string;
  repoSlug: string;
  sha: string;
} | null {
  let u: URL;
  try {
    u = new URL(urlStr);
  } catch {
    return null;
  }
  if (u.hostname.toLowerCase() !== 'github.com') return null;
  const parts = u.pathname.split('/').filter(Boolean);
  if (parts.length !== 4 || parts[2] !== 'commit') return null;
  const owner = parts[0]!;
  const repo = parts[1]!;
  const sha = parts[3]!;
  if (['orgs', 'settings', 'sponsors', 'users', 'login', 'marketplace'].includes(owner.toLowerCase())) {
    return null;
  }
  if (!/^[0-9a-f]{7,40}$/i.test(sha)) return null;
  return {
    patchUrl: `https://github.com/${owner}/${repo}/commit/${sha}.patch`,
    repoSlug: `${owner}/${repo}`,
    sha,
  };
}

function encodeBytesToBase64(bytes: Uint8Array): string {
  let bin = '';
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    bin += String.fromCharCode(...bytes.subarray(i, i + chunk));
  }
  return btoa(bin);
}

export function formatIcalendarToMarkdown(raw: string): { title?: string; description?: string; markdown: string } | null {
  if (!raw || !/^BEGIN:VCALENDAR\b/im.test(raw.slice(0, 512))) return null;
  const doc = callCoreWasmRaw<{ doc: { title?: string; description?: string; markdown: string } | null }>(
    'format_payload',
    { kind: 'icalendar' },
    raw,
  ).doc;
  if (!doc || !doc.markdown) return null;
  return {
    ...(doc.title ? { title: doc.title } : {}),
    ...(doc.description ? { description: doc.description } : {}),
    markdown: doc.markdown,
  };
}

export function formatGitPatchToMarkdown(
  rawBody: string,
  contentType?: unknown,
  urlStr?: string,
): { title?: string; description?: string; markdown: string } | null {
  if (!rawBody) return null;
  const ctLower = typeof contentType === 'string' ? contentType.toLowerCase() : '';
  const isPatchCt = ctLower.includes('x-patch') || ctLower.includes('x-diff');
  const isPatchUrl = Boolean(urlStr && /\.(?:patch|diff)(?:$|[?#])/i.test(urlStr));
  const normalized = rawBody.replace(/\r\n/g, '\n');
  const head = normalized.slice(0, 2_048);
  const isFormatPatch = /^From [0-9a-f]{40} /m.test(head) && /^Subject:/m.test(head) && /\ndiff --git /m.test(normalized);
  const isUnifiedDiff =
    /^diff --git a\//m.test(head) || (/^---\s+\S+/m.test(head) && /^\+\+\+\s+\S+/m.test(head) && /^@@\s+-/m.test(head));
  if (!isPatchCt && !isPatchUrl && !isFormatPatch && !isUnifiedDiff) {
    return null;
  }
  const doc = callCoreWasmRaw<{ doc: { title?: string; description?: string; markdown: string } | null }>(
    'format_payload',
    { kind: 'git_patch', url: urlStr ?? '' },
    rawBody,
  ).doc;
  if (!doc || !doc.markdown) return null;
  return {
    ...(doc.title ? { title: doc.title } : {}),
    ...(doc.description ? { description: doc.description } : {}),
    markdown: doc.markdown,
  };
}

export function formatSourceCodeUrlToMarkdown(
  rawBody: string,
  contentType?: unknown,
  urlStr?: string,
): { title: string; description?: string; markdown: string } | null {
  if (!urlStr || !rawBody) return null;
  const doc = callCoreWasmRaw<{ doc: { title?: string; description?: string; markdown: string } | null }>(
    'format_payload',
    {
      kind: 'source_code',
      url: urlStr,
      contentType: typeof contentType === 'string' ? contentType : '',
    },
    rawBody,
  ).doc;
  if (!doc || !doc.markdown) return null;
  return {
    title: doc.title || 'Source Code',
    ...(doc.description ? { description: doc.description } : {}),
    markdown: doc.markdown,
  };
}

export function formatFeedXmlToMarkdown(
  rawXml: string,
  baseUrl?: string,
): { title?: string; description?: string; markdown: string; links: string[] } | null {
  if (!rawXml || !/^\ufeff?\s*</.test(rawXml)) return null;
  const res = callCoreWasmRaw<{
    doc: { title?: string; description?: string; markdown: string } | null;
    links?: string[];
  }>(
    'format_payload',
    {
      kind: 'feed_xml',
      url: baseUrl ?? '',
    },
    rawXml,
  );
  if (!res.doc || !res.doc.markdown) return null;
  return {
    ...(res.doc.title ? { title: res.doc.title } : {}),
    ...(res.doc.description ? { description: res.doc.description } : {}),
    markdown: res.doc.markdown,
    links: res.links ?? [],
  };
}

const SKIP_SPECULATIVE_LLMS_HOSTS = new Set([
  'news.ycombinator.com',
  'npmjs.com',
  'www.npmjs.com',
  'registry.npmjs.org',
  'crates.io',
  'www.crates.io',
  'rubygems.org',
  'www.rubygems.org',
  'packagist.org',
  'www.packagist.org',
  'hex.pm',
  'www.hex.pm',
  'pypi.org',
  'www.pypi.org',
  'huggingface.co',
  'www.huggingface.co',
  'arxiv.org',
  'export.arxiv.org',
  'github.com',
  'gist.github.com',
  'raw.githubusercontent.com',
  'gitlab.com',
  'codeberg.org',
  'gitea.com',
  'lobste.rs',
  'bsky.app',
  'public.api.bsky.app',
  'stackoverflow.com',
  'www.stackoverflow.com',
  'serverfault.com',
  'superuser.com',
  'askubuntu.com',
  'datatracker.ietf.org',
  'rfc-editor.org',
  'www.rfc-editor.org',
  'pubmed.ncbi.nlm.nih.gov',
  'pmc.ncbi.nlm.nih.gov',
  'dev.to',
  'www.dev.to',
  'youtube.com',
  'www.youtube.com',
  'm.youtube.com',
  'youtu.be',
]);

const ORIGIN_LLMS_ABSENT_TTL_MS = 30 * 60_000;
const MAX_ORIGIN_LLMS_CACHE_ENTRIES = 512;
const originLlmsAbsentCache = new Map<string, number>();

export function resetOriginLlmsCacheForTests(): void {
  originLlmsAbsentCache.clear();
}

function recordOriginLlmsAbsent(origin: string, now = Date.now()): void {
  if (!origin) return;
  if (originLlmsAbsentCache.size >= MAX_ORIGIN_LLMS_CACHE_ENTRIES && !originLlmsAbsentCache.has(origin)) {
    const oldest = originLlmsAbsentCache.keys().next().value;
    if (oldest !== undefined) originLlmsAbsentCache.delete(oldest);
  }
  originLlmsAbsentCache.set(origin.toLowerCase(), now + ORIGIN_LLMS_ABSENT_TTL_MS);
}

function isOriginLlmsKnownAbsent(origin: string, now = Date.now()): boolean {
  const key = origin.toLowerCase();
  const exp = originLlmsAbsentCache.get(key);
  if (exp === undefined) return false;
  if (now >= exp) {
    originLlmsAbsentCache.delete(key);
    return false;
  }
  return true;
}

function shouldAutoProbeOriginLlms(u: URL, now = Date.now()): boolean {
  const host = u.hostname.toLowerCase();
  if (
    SKIP_SPECULATIVE_LLMS_HOSTS.has(host) ||
    host.endsWith('.wikipedia.org') ||
    host.endsWith('.wikimedia.org') ||
    host.endsWith('.reddit.com') ||
    host === 'reddit.com'
  ) {
    return false;
  }
  if (isOriginLlmsKnownAbsent(u.origin, now)) {
    return false;
  }
  const path = u.pathname.toLowerCase();
  if (
    /\.(?:json|ipynb|xml|rss|atom|pdf|vcf|vcard|ics|csv|tsv|patch|diff|toml|yaml|yml|py|rs|go|ts|tsx|js|jsx|sh|sql|txt|md)(?:$|\.)/.test(
      path,
    ) ||
    /\/(?:rss|feed|atom)\/?$/.test(path)
  ) {
    return false;
  }
  return true;
}

export function formatDelimitedTableToMarkdown(
  rawBody: string,
  contentType?: unknown,
  urlStr?: string,
): {
  title?: string;
  description?: string;
  markdown: string;
  rowCount: number;
  columnCount: number;
} | null {
  const ctLower = typeof contentType === 'string' ? contentType.toLowerCase() : '';
  const isTsvCt = ctLower.includes('tab-separated-values') || ctLower.includes('text/tsv');
  const isCsvCt = ctLower.includes('text/csv') || ctLower.includes('application/csv');
  const isTsvUrl = Boolean(urlStr && /\.tsv(?:$|[?#])/i.test(urlStr));
  const isCsvUrl = Boolean(urlStr && /\.csv(?:$|[?#])/i.test(urlStr));
  if (!isCsvCt && !isTsvCt && !isCsvUrl && !isTsvUrl) {
    return null;
  }
  const sep = isTsvCt || isTsvUrl ? '\t' : ',';
  let fileLabel = '';
  if (urlStr) {
    try {
      const seg = safeDecodeURIComponent(new URL(urlStr).pathname.split('/').filter(Boolean).pop() ?? '');
      if (seg) fileLabel = seg;
    } catch {
      // ignore
    }
  }
  const doc = callCoreWasmRaw<{
    doc: {
      title?: string;
      description?: string;
      markdown: string;
      structured?: { rowCount?: number; columnCount?: number };
    } | null;
  }>(
    'format_payload',
    {
      kind: 'delimited',
      sep,
      titleHint: fileLabel,
    },
    rawBody,
  ).doc;
  if (!doc || !doc.markdown) return null;
  return {
    ...(doc.title ? { title: doc.title } : {}),
    ...(doc.description ? { description: doc.description } : {}),
    markdown: doc.markdown,
    rowCount: doc.structured?.rowCount ?? 0,
    columnCount: doc.structured?.columnCount ?? 0,
  };
}

export function detectUnsupportedBinaryPayload(params: {
  rawBody: string;
  contentType?: unknown;
  url?: string;
  bodyEncoding?: unknown;
  isPdf?: boolean;
}): string | null {
  if (params.isPdf) return null;
  const ct = typeof params.contentType === 'string' ? params.contentType.split(';')[0]!.trim().toLowerCase() : '';
  if (params.bodyEncoding === 'base64') {
    if (
      ct &&
      ((/^(?:image|audio|video|font)\//.test(ct) && ct !== 'image/svg+xml') ||
        /^application\/(?:x-)?(?:gzip|tar|gtar|zip|bzip2|xz|zstd|7z-compressed|rar|rar-compressed|octet-stream|wasm|java-archive|x-msdownload|x-executable|x-apple-diskimage|msword|vnd\.ms-|vnd\.openxmlformats)/i.test(
          ct,
        ))
    ) {
      return `Unsupported binary content-type "${ct}" for Markdown extraction`;
    }
    return `Unsupported binary payload${ct ? ` (${ct})` : ''} for Markdown extraction`;
  }
  let sampleEnd = Math.min(params.rawBody.length, 2_048);
  if (sampleEnd < params.rawBody.length && sampleEnd > 0) {
    const lastCode = params.rawBody.charCodeAt(sampleEnd - 1);
    if (lastCode >= 0xd800 && lastCode <= 0xdbff) {
      sampleEnd--;
    }
  }
  const sample = params.rawBody.slice(0, sampleEnd);
  let sampleBytes: Uint8Array;
  if (!sample.includes('\ufffd')) {
    sampleBytes = SCRAPE_UTF8_ENCODER.encode(sample);
  } else {
    // Map UTF-8 replacement char U+FFFD (`0xfffd`) to invalid high byte `0xff` so binary ratio checks trigger identically
    const parts = sample.split('\ufffd');
    const encodedParts = parts.map((p) => SCRAPE_UTF8_ENCODER.encode(p));
    let totalLen = parts.length - 1;
    for (const ep of encodedParts) totalLen += ep.byteLength;
    sampleBytes = new Uint8Array(totalLen);
    let offset = 0;
    for (let i = 0; i < encodedParts.length; i++) {
      if (i > 0) sampleBytes[offset++] = 0xff;
      const ep = encodedParts[i]!;
      sampleBytes.set(ep, offset);
      offset += ep.byteLength;
    }
  }
  const res = callCoreWasm<{ unsupported: boolean; reason?: string }>('detect_binary', {
    dataBase64: encodeBytesToBase64(sampleBytes),
    contentType: typeof params.contentType === 'string' ? params.contentType : '',
    url: params.url ?? '',
  });
  return res.unsupported ? (res.reason || 'Unsupported binary payload for Markdown extraction') : null;
}

export function deriveQuickMarkdownFromRawBytes(bytes: Uint8Array, baseUrl?: string): string | null {
  if (bytes.byteLength === 0 || hasPdfMagicHeader(bytes)) return null;
  const out = callCoreWasm<{ out: string }>('format_payload', {
    kind: 'quick_bytes',
    dataBase64: encodeBytesToBase64(bytes),
    url: baseUrl ?? '',
  }).out;
  return out || null;
}

export function formatJupyterNotebookToMarkdown(
  parsed: unknown,
  fallbackTitle?: string,
): { title?: string; description?: string; markdown: string } | null {
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return null;
  const doc = callCoreWasmRaw<{ doc: { title?: string; description?: string; markdown: string } | null }>(
    'format_payload',
    {
      kind: 'ipynb',
      url: fallbackTitle ?? '',
    },
    JSON.stringify(parsed),
  ).doc;
  if (!doc || !doc.markdown) return null;
  const finalTitle = doc.title || fallbackTitle;
  const md = finalTitle && !doc.markdown.startsWith('# ') ? `# ${finalTitle}\n\n${doc.markdown}` : doc.markdown;
  return {
    ...(finalTitle ? { title: finalTitle } : {}),
    ...(doc.description ? { description: doc.description } : {}),
    markdown: md,
  };
}

export function formatOpenApiSpecToMarkdown(
  parsed: unknown,
): { title?: string; description?: string; markdown: string } | null {
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return null;
  const doc = callCoreWasmRaw<{ doc: { title?: string; description?: string; markdown: string } | null }>(
    'format_payload',
    {
      kind: 'openapi',
    },
    JSON.stringify(parsed),
  ).doc;
  if (!doc || !doc.markdown) return null;
  return {
    ...(doc.title ? { title: doc.title } : {}),
    ...(doc.description ? { description: doc.description } : {}),
    markdown: doc.markdown,
  };
}

const MAX_JSON_SCRAPE_JS_PARSE_CHARS = 2 * 1024 * 1024;
const LARGE_JSON_SNIFF_CHARS = 64 * 1024;

/**
 * Bounded sniff (no JS parse) for JSON too large to `JSON.parse` on the edge: reports an OpenAPI / Swagger spec
 * when a top-level-looking `"openapi"` / `"swagger"` key appears in the head, and a Jupyter notebook when
 * `"nbformat"` appears in the head or tail (notebooks serialize `cells` first and `nbformat` last) or the URL is
 * `.ipynb`. The Go formatters re-validate the full document, so a false positive just falls back to the preview.
 */
export function sniffLargeStructuredJsonKind(trimmed: string, finalUrl: string): 'openapi' | 'ipynb' | null {
  if (!trimmed.startsWith('{')) return null;
  const head = trimmed.slice(0, LARGE_JSON_SNIFF_CHARS);
  if (/^\{\s*"(?:openapi|swagger)"\s*:\s*"/.test(head) || /[{,]\s*"(?:openapi|swagger)"\s*:\s*"\d/.test(head)) {
    return 'openapi';
  }
  const tail = trimmed.length > LARGE_JSON_SNIFF_CHARS ? trimmed.slice(-LARGE_JSON_SNIFF_CHARS) : '';
  const nbKey = /[{,]\s*"nbformat"\s*:\s*\d/;
  if (nbKey.test(head) || nbKey.test(tail) || (/\.ipynb(?:$|[?#])/i.test(finalUrl) && /"cells"\s*:\s*\[/.test(head))) {
    return 'ipynb';
  }
  return null;
}

export function tryParseJsonPayloadForScrape(
  rawBody: string,
  contentType: unknown,
  finalUrl: string,
): {
  parsed: unknown;
  markdown: string;
  title?: string;
  description?: string;
  /** Set when a > 2 MiB OpenAPI spec / notebook was formatted by its dedicated Go formatter without a JS parse. */
  structuredKind?: 'openapi' | 'ipynb';
} | null {
  const ctLower = typeof contentType === 'string' ? contentType.toLowerCase() : '';
  const looksJsonCt = ctLower.includes('json');
  const looksJsonUrl = /\.(?:json|ipynb)(?:$|[?#])/i.test(finalUrl);
  const trimmed = rawBody.replace(/^\ufeff/, '').trim();
  if ((!looksJsonCt && !looksJsonUrl) || (!trimmed.startsWith('{') && !trimmed.startsWith('['))) {
    return null;
  }
  let parsed: unknown = null;
  if (trimmed.length <= MAX_JSON_SCRAPE_JS_PARSE_CHARS) {
    try {
      parsed = JSON.parse(trimmed);
    } catch {
      return null;
    }
  } else {
    // Too large for a JS parse: hand OpenAPI specs / notebooks straight to their Go formatters (raw input, within
    // the 4 MiB WASM input budget enforced upstream) instead of degrading them to the generic JSON preview.
    const kind = sniffLargeStructuredJsonKind(trimmed, finalUrl);
    if (kind) {
      try {
        const structured = callCoreWasmRaw<{ doc: { title?: string; description?: string; markdown: string } | null }>(
          'format_payload',
          { kind, url: finalUrl },
          trimmed,
        ).doc;
        if (structured?.markdown) {
          const title = structured.title;
          const md =
            kind === 'ipynb' && title && !structured.markdown.startsWith('# ')
              ? `# ${title}\n\n${structured.markdown}`
              : structured.markdown;
          return {
            parsed: null,
            markdown: md,
            structuredKind: kind,
            ...(title ? { title } : {}),
            ...(structured.description ? { description: structured.description } : {}),
          };
        }
      } catch {
        // Fall through to the generic bounded JSON preview below.
      }
    }
  }
  const doc = callCoreWasmRaw<{ doc: { title?: string; description?: string; markdown: string } | null }>(
    'format_payload',
    {
      kind: 'json_scrape',
      url: finalUrl,
    },
    trimmed,
  ).doc;
  if (!doc || !doc.markdown) return null;
  return {
    parsed,
    markdown: doc.markdown,
    ...(doc.title ? { title: doc.title } : {}),
    ...(doc.description ? { description: doc.description } : {}),
  };
}

function isLikelyPdfUrl(urlStr: string): boolean {
  try {
    const u = new URL(urlStr);
    if (/\.pdf$/i.test(u.pathname)) return true;
    return /^(?:export\.)?arxiv\.org$/i.test(u.hostname) && /^\/pdf\/[A-Za-z0-9._/-]+$/.test(u.pathname);
  } catch {
    return false;
  }
}

function buildRobotsAlternativeHint(urlStr: string): string | undefined {
  try {
    const u = new URL(urlStr);
    const host = u.hostname.toLowerCase();
    if (host === 'pypi.org') {
      const m = /^\/pypi\/([^/]+)(?:\/[^/]+)?\/json\/?$/i.exec(u.pathname);
      if (m?.[1]) {
        return `pypi.org disallows /pypi/*/json in robots.txt; scrape https://pypi.org/project/${m[1]}/ instead.`;
      }
    }
    if (host === 'github.com') {
      const m = /^\/([^/]+)\/([^/]+)\/tree\/([^/]+)(?:\/(.+))?$/i.exec(u.pathname);
      if (m?.[1] && m[2] && m[3]) {
        const sub = m[4] ? `${m[4].replace(/\/+$/, '')}/README.md` : 'README.md';
        return `github.com disallows /*/tree/ in robots.txt; use map on https://github.com/${m[1]}/${m[2]} or scrape https://github.com/${m[1]}/${m[2]}/blob/${m[3]}/${sub}.`;
      }
    }
  } catch {
    // ignore
  }
  return undefined;
}

export function extractYouTubeWatchMetadataFromHtml(
  rawHtml: string,
): { title: string; author?: string; description?: string; markdown: string } | null {
  if (!rawHtml || !rawHtml.includes('"videoDetails"')) return null;
  const meta = callCoreWasm<{
    meta: { title?: string; author?: string; description?: string; markdown?: string } | null;
  }>('extract_youtube', { rawHtml, url: '', includeTranscript: false }).meta;
  if (!meta || !meta.title || !meta.markdown) return null;
  return {
    title: meta.title,
    ...(meta.author ? { author: meta.author } : {}),
    ...(meta.description ? { description: meta.description } : {}),
    markdown: meta.markdown,
  };
}

function matchesAdapterDomainPattern(hostLower: string, patternRaw: string): boolean {
  const pat = patternRaw.trim().toLowerCase().replace(/\.$/, '');
  if (!pat) return false;
  if (pat.startsWith('*.')) {
    const suffix = pat.slice(1); // e.g. ".legistar.com"
    return suffix.length > 1 && hostLower.length > suffix.length && hostLower.endsWith(suffix);
  }
  return hostLower === pat;
}

const NON_DECLARATIVE_ATS_TRUSTED_HOSTS: Record<string, readonly string[]> = {
  'greenhouse-board': [
    'boards-api.greenhouse.io',
    'boards-api.eu.greenhouse.io',
    'boards.greenhouse.io',
    'job-boards.greenhouse.io',
  ],
  'greenhouse-eu-board': [
    'boards-api.eu.greenhouse.io',
    'boards-api.greenhouse.io',
    'eu-boards.greenhouse.io',
    'job-boards.eu.greenhouse.io',
  ],
  'greenhouse-job': [
    'boards-api.greenhouse.io',
    'boards-api.eu.greenhouse.io',
    'boards.greenhouse.io',
    'job-boards.greenhouse.io',
    'eu-boards.greenhouse.io',
    'job-boards.eu.greenhouse.io',
  ],
  'ashby-board': ['api.ashbyhq.com', 'jobs.ashbyhq.com'],
  'ashby-job': ['api.ashbyhq.com', 'jobs.ashbyhq.com'],
  'lever-board': ['api.lever.co', 'api.eu.lever.co', 'jobs.lever.co', 'jobs.eu.lever.co'],
  'lever-eu-board': ['api.eu.lever.co', 'api.lever.co', 'jobs.eu.lever.co', 'jobs.lever.co'],
  'lever-job': ['api.lever.co', 'api.eu.lever.co', 'jobs.lever.co', 'jobs.eu.lever.co'],
  'workable-board': ['apply.workable.com'],
  'workable-job': ['apply.workable.com'],
  'gem-board': ['api.gem.com', 'jobs.gem.com'],
  'rippling-board': ['api.rippling.com', 'ats.rippling.com'],
  'rippling-job': ['api.rippling.com', 'ats.rippling.com'],
  'weworkremotely-feed': ['weworkremotely.com', 'www.weworkremotely.com'],
  'himalayas-feed': ['himalayas.app', 'www.himalayas.app'],
  'workingnomads-feed': ['workingnomads.com', 'www.workingnomads.com'],
};

const WORKDAY_HOST_TENANT_RE = /^([a-z0-9-]+)\.(?:wd\d+\.)?(myworkday(?:jobs|site)\.com)$/;

export function isTrustedTwinRedirectUrl(
  twinId: string | undefined,
  initialFetchUrl: string,
  item: Record<string, unknown>,
  selfHost?: string,
): boolean {
  const rawFinal =
    typeof item.finalUrl === 'string' && item.finalUrl.trim()
      ? item.finalUrl.trim()
      : typeof item.url === 'string' && item.url.trim()
        ? item.url.trim()
        : '';
  if (!rawFinal) return true;
  const checked = validatePublicHttpsTargetUrl(rawFinal, selfHost);
  if (!checked.ok) return false;
  const finalHost = checked.url.hostname.toLowerCase().replace(/\.$/, '');
  let initHost = '';
  try {
    initHost = new URL(initialFetchUrl).hostname.toLowerCase().replace(/\.$/, '');
  } catch {
    return false;
  }
  if (finalHost === initHost) return true;
  if (!twinId) return false;
  if (twinId === 'workday-job' || twinId === 'workday-board') {
    const initM = WORKDAY_HOST_TENANT_RE.exec(initHost);
    const finalM = WORKDAY_HOST_TENANT_RE.exec(finalHost);
    return Boolean(initM && finalM && initM[1] === finalM[1] && initM[2] === finalM[2]);
  }
  const atsHosts = NON_DECLARATIVE_ATS_TRUSTED_HOSTS[twinId];
  if (atsHosts) {
    return atsHosts.includes(finalHost);
  }
  const adapterMeta = findRegisteredAdapterById(twinId);
  if (!adapterMeta || !Array.isArray(adapterMeta.domains)) return false;
  return (
    adapterMeta.domains.every((d) => !d.includes('*')) &&
    adapterMeta.domains.some((dom) => matchesAdapterDomainPattern(finalHost, dom))
  );
}

function parsePolite5xxRetryDelayMs(rawRetryAfter: string | undefined, nowMs: number): number | null {
  if (!rawRetryAfter || !rawRetryAfter.trim()) return 200;
  const trimmed = rawRetryAfter.trim();
  if (/^\d+(?:\.\d+)?$/.test(trimmed)) {
    const sec = Number(trimmed);
    if (!Number.isFinite(sec) || sec > 2) return null;
    return Math.min(2_000, Math.max(0, Math.round(sec * 1_000)));
  }
  const parsedDate = Date.parse(trimmed);
  if (Number.isFinite(parsedDate)) {
    const deltaMs = parsedDate - nowMs;
    if (deltaMs > 2_000) return null;
    return Math.min(2_000, Math.max(0, deltaMs));
  }
  return 200;
}

async function runPdfOcrFallback(params: {
  url: string;
  ocrParam: 'auto' | 'always';
  maxOcrPages: number;
  redactPii: boolean;
  headers?: unknown;
  target: 'auto' | 'agent' | 'container';
  site?: string;
  source: string;
  selfHost?: string;
  isPrivate?: boolean;
  userId?: string;
  ephemeral?: boolean;
  env: OptionalStorageBindings;
  executeHubFetch: (
    target: 'auto' | 'agent' | 'container',
    body: string,
    site?: string,
    source?: string,
    artifactRetention?: ArtifactRetention | 'off',
    hydrateInline?: boolean,
    collectionId?: string,
  ) => Promise<{ status: number; via: string; bodyText: string; retryAfter?: string }>;
}): Promise<
  | {
      ok: true;
      via: string;
      finalUrl: string;
      status: number;
      contentSha256?: string;
      artifactId?: string;
      markdown: string;
      pdfEngine: string;
      ocr?: PdfOcrContainerReply['ocr'];
    }
  | {
      ok: false;
      originFailure?: { status: number; via: string; body: Record<string, unknown>; retryAfter?: string };
      error: string;
    }
> {
  const { url, ocrParam, maxOcrPages, redactPii, headers, target, site, source, selfHost, isPrivate, userId, ephemeral, env, executeHubFetch } = params;
  const hasService = Boolean(env.PDF_OCR);
  const ocrUrlBase = env.PDF_OCR_URL?.trim().replace(/\/+$/, '') ?? '';
  const ocrToken = env.PDF_OCR_TOKEN?.trim() ?? '';
  if (!hasService && (!ocrUrlBase || !ocrToken)) {
    return { ok: false, error: 'pdf_ocr_unconfigured' };
  }

  const normalizedHeaders = normalizeCallerHeadersRecord(headers);
  const rawFetchCall = {
    maxSeconds: 110,
    options: {
      includeBody: true,
      respectRobots: true,
      maxBytes: 16 * 1024 * 1024,
      timeoutMs: 95_000,
    },
    requests: [
      {
        id: 'pdf-ocr-1',
        url,
        kind: 'binary',
        accept: 'application/pdf,*/*;q=0.8',
        ...(Object.keys(normalizedHeaders).length > 0 ? { headers: normalizedHeaders } : {}),
      },
    ],
  };

  const privatePdf = Boolean(isPrivate) || Boolean(ephemeral) || (userId !== undefined && sanitizeStorageUserId(userId) !== 'owner');
  const retention: ArtifactRetention | 'off' = !privatePdf && env.ARTIFACTS ? 'transient' : 'off';
  const hydrateInline = privatePdf || !env.ARTIFACTS;
  const fetchRes = await executeHubFetch(
    target,
    JSON.stringify(rawFetchCall),
    site,
    `${source}:pdf-bytes`,
    retention,
    hydrateInline,
  );
  if (fetchRes.status !== 200) {
    let errJson: Record<string, unknown> = { ok: false, error: 'scrape_failed' };
    try {
      errJson = { ok: false, ...(JSON.parse(fetchRes.bodyText) as Record<string, unknown>) };
    } catch {
      // ignore
    }
    return {
      ok: false,
      originFailure: {
        status: fetchRes.status,
        via: fetchRes.via,
        body: errJson,
        ...(fetchRes.retryAfter ? { retryAfter: fetchRes.retryAfter } : {}),
      },
      error: `hub_fetch_${fetchRes.status}`,
    };
  }

  const parsed = JSON.parse(fetchRes.bodyText) as { results?: Array<Record<string, unknown>> };
  const item = parsed.results?.[0] ?? {};
  if (item.outcome !== 'ok') {
    return {
      ok: false,
      originFailure: {
        status: item.status === 429 ? 429 : 422,
        via: fetchRes.via,
        body: {
          ok: false,
          url,
          outcome: item.outcome ?? 'error',
          status: item.status ?? 0,
          problem: item.problem ?? 'Origin PDF download did not return HTTP 2xx',
        },
      },
      error: String(item.problem ?? 'origin_not_ok'),
    };
  }

  let pdfBytes: Uint8Array | null = null;
  const rawArt = item.artifact as { blobSha256?: string; contentSha256?: string; retention?: string } | undefined;
  const art = !privatePdf ? rawArt : undefined;
  if (!privatePdf && art?.blobSha256 && env.ARTIFACTS) {
    const loaded = await readVerifiedArtifactFromR2({
      bucket: env.ARTIFACTS,
      blobSha256: art.blobSha256,
      preferredRetention: art.retention === 'stored' ? 'stored' : 'transient',
      expectedContentSha256: art.contentSha256,
    });
    if (loaded.ok) {
      pdfBytes = loaded.bytes;
    }
  }
  if (!pdfBytes && typeof item.bodyBase64 === 'string' && item.bodyBase64.length > 0) {
    pdfBytes = decodeBase64ToBytes(item.bodyBase64);
  }
  if (!pdfBytes && typeof item.body === 'string' && item.body.length > 0) {
    pdfBytes = item.bodyEncoding === 'base64' ? decodeBase64ToBytes(item.body) : new TextEncoder().encode(item.body);
  }
  if (!pdfBytes && privatePdf && rawArt?.blobSha256 && env.ARTIFACTS) {
    const rawRet: ArtifactRetention = rawArt.retention === 'stored' ? 'stored' : 'transient';
    const loaded = await readVerifiedArtifactFromR2({
      bucket: env.ARTIFACTS,
      blobSha256: rawArt.blobSha256,
      preferredRetention: rawRet,
      expectedContentSha256: rawArt.contentSha256,
    });
    await env.ARTIFACTS.delete(r2ArtifactKey(rawRet, rawArt.blobSha256)).catch(() => {});
    if (loaded.ok) {
      pdfBytes = loaded.bytes;
    }
  }
  if (!pdfBytes || pdfBytes.byteLength === 0 || !hasPdfMagicHeader(pdfBytes)) {
    return { ok: false, error: 'not_a_pdf_payload' };
  }

  let privateBlobSha: string | undefined;
  let privateContentSha: string | undefined;
  if (Boolean(isPrivate) && !Boolean(ephemeral) && env.ARTIFACTS && userId) {
    try {
      const writtenPriv = await writePrivateArtifactToR2({
        bucket: env.ARTIFACTS,
        userId,
        rawBytes: pdfBytes,
        retention: 'stored',
      });
      privateBlobSha = writtenPriv.blobSha256;
      privateContentSha = writtenPriv.contentSha256;
    } catch {
      // non-fatal
    }
  }

  const qs = new URLSearchParams({
    ocr: ocrParam,
    maxOcrPages: String(Math.min(500, Math.max(1, maxOcrPages))),
    maxSeconds: '300',
  });
  const bodyPayload = pdfBytes.slice().buffer as ArrayBuffer;

  let ocrRes: Response;
  try {
    if (env.PDF_OCR) {
      ocrRes = await env.PDF_OCR.fetch(`http://pdf-ocr/ocr?${qs}`, {
        method: 'POST',
        headers: {
          'content-type': 'application/pdf',
          'content-length': String(pdfBytes.byteLength),
          'x-pdf-bytes': String(pdfBytes.byteLength),
        },
        body: bodyPayload,
        signal: AbortSignal.timeout(300_000),
      });
    } else {
      ocrRes = await fetch(`${ocrUrlBase}/ocr?${qs}`, {
        method: 'POST',
        headers: {
          authorization: `Bearer ${ocrToken}`,
          'content-type': 'application/pdf',
          'content-length': String(pdfBytes.byteLength),
          'x-pdf-bytes': String(pdfBytes.byteLength),
        },
        body: bodyPayload,
        signal: AbortSignal.timeout(300_000),
      });
    }
  } catch (e) {
    return { ok: false, error: e instanceof Error ? e.message : String(e) };
  }

  if (!ocrRes.ok) {
    const errText = await ocrRes.text().catch(() => '');
    return { ok: false, error: `pdf_ocr_http_${ocrRes.status}:${errText.slice(0, 200)}` };
  }

  const ocrJson = (await ocrRes.json().catch(() => ({}))) as PdfOcrContainerReply;
  const rawMd = typeof ocrJson.markdown === 'string' ? ocrJson.markdown : '';
  const finalMd = redactPii ? redactPiiText(rawMd) : rawMd;
  const pagesOcred = ocrJson.ocr?.pagesOcred ?? 0;

  return {
    ok: true,
    via: `${fetchRes.via}+pdf-ocr`,
    finalUrl: resolveValidatedFinalUrl(item.finalUrl, url, selfHost),
    status: typeof item.status === 'number' ? item.status : 200,
    contentSha256: privateContentSha ?? ocrJson.sha256 ?? art?.contentSha256,
    artifactId: privatePdf ? privateBlobSha : art?.blobSha256,
    markdown: finalMd,
    pdfEngine: pagesOcred > 0 ? 'pymupdf-tesseract-ocr' : 'pymupdf',
    ocr: ocrJson.ocr,
  };
}

export async function executeScrapeCall(params: {
  payload: ScrapeRequestPayload;
  env: OptionalStorageBindings;
  executeHubFetch: (
    target: 'auto' | 'agent' | 'container',
    body: string,
    site?: string,
    source?: string,
    artifactRetention?: ArtifactRetention | 'off',
    hydrateInline?: boolean,
    collectionId?: string,
  ) => Promise<{ status: number; via: string; bodyText: string; retryAfter?: string }>;
  source?: string;
  selfHost?: string;
  userId?: string;
  now?: number;
  sleepFn?: (ms: number) => Promise<void>;
  tracer?: RequestTracer | TraceContext;
}): Promise<{ status: number; body: Record<string, unknown>; via: string; retryAfter?: string }> {
  const activeTracer = getActiveRequestTracer(params.tracer);
  const runScrape = async (): Promise<{ status: number; body: Record<string, unknown>; via: string; retryAfter?: string }> => {
  const {
    payload,
    env,
    executeHubFetch,
    source = 'scrape',
    selfHost,
    userId = 'owner',
    now = Date.now(),
    sleepFn = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms)),
  } = params;
  const visibility = normalizeVisibility(payload.visibility, payload.headers, {
    cookies: (payload as { cookies?: unknown }).cookies,
    preferMcp:
      (payload as { useConnectedMcp?: unknown }).useConnectedMcp === true ||
      (payload as { preferMcp?: unknown }).preferMcp === true,
    hasAuthContext: Boolean((payload as { auth?: unknown }).auth),
    userId,
  });
  const isPrivateScrape = visibility === 'private' || sanitizeStorageUserId(userId) !== 'owner';
  const urlCheck = validatePublicHttpsTargetUrl(payload.url, selfHost);
  if (!urlCheck.ok) {
    return { status: 400, via: 'hub', body: { ok: false, error: 'invalid_url', message: urlCheck.message } };
  }
  let parsedUrl = urlCheck.url;
  let normalizedUrl = urlCheck.normalized;
  const prelimWikiArticle = parseWikipediaArticleUrl(normalizedUrl);
  if (prelimWikiArticle && (/%20/i.test(parsedUrl.pathname) || /\s/.test(parsedUrl.pathname))) {
    normalizedUrl = prelimWikiArticle.canonicalUrl;
    parsedUrl = new URL(normalizedUrl);
  }
  const parsedWikiArticle = prelimWikiArticle ? parseWikipediaArticleUrl(normalizedUrl) : null;
  const unboundedBlocked = checkUnboundedTwinEndpointGuard(parsedUrl, normalizedUrl);
  if (unboundedBlocked) {
    return unboundedBlocked;
  }

  const rawFormats = Array.isArray(payload.formats) && payload.formats.length > 0 ? payload.formats : ['markdown'];
  const stringFormats = new Set<string>();
  let jsonSchemaSpec: { prompt?: string; schema?: Record<string, unknown> } | undefined;
  let attributesSpec: Array<{ selector: string; attribute: string }> | undefined;
  let screenshotSpec: { fullPage?: boolean; quality?: number; viewport?: { width?: number; height?: number } } | undefined;
  let changeTrackingSpec: { modes?: string[]; tag?: string } | undefined;

  for (const f of rawFormats) {
    if (typeof f === 'string') {
      if (f === 'changeTracking') {
        stringFormats.add('changes');
        changeTrackingSpec = {};
      } else {
        stringFormats.add(f);
      }
    } else if (f && typeof f === 'object' && !Array.isArray(f)) {
      const fObj = f as Record<string, unknown>;
      if (fObj.type === 'json') {
        jsonSchemaSpec = {
          ...(typeof fObj.prompt === 'string' && fObj.prompt.trim() ? { prompt: fObj.prompt.trim() } : {}),
          ...(fObj.schema && typeof fObj.schema === 'object' ? { schema: fObj.schema as Record<string, unknown> } : {}),
        };
      } else if (fObj.type === 'attributes' && Array.isArray(fObj.selectors)) {
        attributesSpec = fObj.selectors
          .filter((s): s is { selector: string; attribute: string } => Boolean(s && typeof s === 'object'))
          .slice(0, 25);
      } else if (fObj.type === 'screenshot') {
        stringFormats.add('screenshot');
        screenshotSpec = {
          ...(typeof fObj.fullPage === 'boolean' ? { fullPage: fObj.fullPage } : {}),
          ...(typeof fObj.quality === 'number' && Number.isFinite(fObj.quality)
            ? { quality: Math.min(100, Math.max(1, Math.floor(fObj.quality))) }
            : {}),
          ...(fObj.viewport && typeof fObj.viewport === 'object'
            ? { viewport: fObj.viewport as { width?: number; height?: number } }
            : {}),
        };
      } else if (fObj.type === 'changeTracking') {
        stringFormats.add('changes');
        changeTrackingSpec = {
          ...(Array.isArray(fObj.modes) ? { modes: fObj.modes.map(String) } : {}),
          ...(typeof fObj.tag === 'string' ? { tag: fObj.tag } : {}),
        };
      }
    }
  }
  if (stringFormats.size === 0 && !jsonSchemaSpec && !attributesSpec) {
    stringFormats.add('markdown');
  }

  const inlineActionsParsed = normalizeInlineBrowserActions(payload.actions, selfHost, 50);
  if (!inlineActionsParsed.ok) {
    return { status: 400, via: 'hub', body: { ok: false, error: 'invalid_action', message: inlineActionsParsed.message } };
  }
  const inlineActions = inlineActionsParsed.actions;

  const pdfParserOpts = parsePdfParserOptions(payload.parsers);
  const mobileEmulation = Boolean(payload.mobile);
  const checkPromptInjection = Boolean(payload.checkPromptInjection);

  const locationObj =
    payload.location && typeof payload.location === 'object' && !Array.isArray(payload.location)
      ? (payload.location as Record<string, unknown>)
      : null;
  const locationLanguages = Array.isArray(locationObj?.languages)
    ? locationObj!.languages
        .filter((l): l is string => typeof l === 'string' && /^[A-Za-z]{2}(?:-[A-Za-z0-9]{2,8})?$/.test(l.trim()))
        .map((l) => l.trim())
    : [];
  const acceptLanguageOpt = locationLanguages.length > 0 ? locationLanguages.join(', ') : undefined;

  const normalizedCallerHeaders = normalizeCallerHeadersRecord(payload.headers);
  const hasCallerAcceptLanguage = Object.keys(normalizedCallerHeaders).some(
    (k) => k.toLowerCase() === 'accept-language',
  );
  const mergedHeaders: Record<string, string> = {
    ...(acceptLanguageOpt && !hasCallerAcceptLanguage ? { 'Accept-Language': acceptLanguageOpt } : {}),
    ...normalizedCallerHeaders,
  };
  let callerExplicitAccept: string | undefined;
  for (const [hk, hv] of Object.entries(mergedHeaders)) {
    if (hk.toLowerCase() === 'accept' && typeof hv === 'string' && hv.trim()) {
      callerExplicitAccept = hv.trim();
      break;
    }
  }
  if (!callerExplicitAccept && typeof (payload as Record<string, unknown>).accept === 'string') {
    const rawPayloadAccept = String((payload as Record<string, unknown>).accept).trim();
    if (rawPayloadAccept) callerExplicitAccept = rawPayloadAccept;
  }
  const hasCallerHeaders = hasAnyCallerHeader(payload.headers);
  const callerCookiesRaw = (payload as { cookies?: unknown }).cookies;
  const hasCallerCookies = hasAnyCallerCookies(callerCookiesRaw);
  const hasCallerHeadersOrCookies = hasCallerHeaders || hasCallerCookies;

  const onlyMainContent = typeof payload.onlyMainContent === 'boolean' ? payload.onlyMainContent : true;
  const includeImages = typeof payload.includeImages === 'boolean' ? payload.includeImages : true;
  const includeTags = Array.isArray(payload.includeTags)
    ? payload.includeTags.filter((s): s is string => typeof s === 'string' && s.trim().length > 0).slice(0, 25)
    : [];
  const excludeTags = Array.isArray(payload.excludeTags)
    ? payload.excludeTags.filter((s): s is string => typeof s === 'string' && s.trim().length > 0).slice(0, 25)
    : [];
  const maxChars = resolveScrapeMaxChars(payload);
  const explicitDiscoverLlms = typeof payload.discoverLlmsTxt === 'boolean' ? payload.discoverLlmsTxt : undefined;
  const discoverLlmsTxt = explicitDiscoverLlms ?? true;
  const goDiscoverLlms =
    stringFormats.has('llmsTxt') ||
    (explicitDiscoverLlms !== false && shouldAutoProbeOriginLlms(parsedUrl, now));
  const redactPii = Boolean(payload.redactPii);
  const spaFallbackMode = normalizeSpaFallbackMode(payload.spaFallback);
  const rawWaitFor =
    typeof payload.waitForMs === 'number' && Number.isFinite(payload.waitForMs)
      ? payload.waitForMs
      : typeof payload.waitFor === 'number' && Number.isFinite(payload.waitFor)
        ? payload.waitFor
        : undefined;
  const waitForMsOpt = rawWaitFor !== undefined ? Math.min(15_000, Math.max(0, Math.floor(rawWaitFor))) : undefined;
  const waitSelectorOpt =
    typeof payload.waitSelector === 'string' && payload.waitSelector.trim()
      ? payload.waitSelector.trim().slice(0, 200)
      : undefined;
  const rawMaxAge =
    typeof payload.maxAgeMs === 'number' && Number.isFinite(payload.maxAgeMs)
      ? payload.maxAgeMs
      : typeof payload.maxAge === 'number' && Number.isFinite(payload.maxAge)
        ? payload.maxAge
        : parsedWikiArticle
          ? DEFAULT_WIKIPEDIA_MAX_AGE_MS
          : 0;
  const maxAgeMs = payload.noCache === true ? 0 : Math.max(0, Math.floor(rawMaxAge));
  const timeoutMsOpt =
    typeof payload.timeout === 'number' && Number.isFinite(payload.timeout)
      ? Math.min(120_000, Math.max(1_000, Math.floor(payload.timeout)))
      : 95_000;
  const maxPagesCap =
    pdfParserOpts.maxPagesOverride ??
    (typeof payload.maxPages === 'number' && Number.isFinite(payload.maxPages)
      ? Math.min(500, Math.max(1, Math.floor(payload.maxPages)))
      : 60);
  const ocrMode: 'auto' | 'always' | 'off' =
    pdfParserOpts.ocrModeOverride ??
    (payload.ocr === 'always' || payload.ocr === 'off' ? payload.ocr : 'auto');
  const hasPdfOcr = Boolean(env.PDF_OCR || (env.PDF_OCR_URL?.trim() && env.PDF_OCR_TOKEN?.trim()));
  const target: 'auto' | 'agent' | 'container' =
    payload.target === 'agent' || payload.target === 'container'
      ? payload.target
      : inlineActions.length > 0
        ? 'agent'
        : 'auto';
  const site = typeof payload.site === 'string' && payload.site.trim() ? payload.site.trim() : undefined;

  const focusQuery = typeof payload.query === 'string' ? payload.query.trim() : '';
  const applyQueryFocus = (
    fullMarkdown: string,
  ): { markdown: string; chunks: Array<{ ordinal: number; heading: string; text: string; score: number }>; queryFiltered: boolean } => {
    if (!focusQuery || !fullMarkdown.trim()) {
      return { markdown: fullMarkdown, chunks: [], queryFiltered: false };
    }
    const allChunks = chunkMarkdownForSearch(fullMarkdown);
    const ranked = rankChunksInMemory(allChunks, focusQuery, 5);
    if (ranked.length === 0) {
      return { markdown: fullMarkdown, chunks: [], queryFiltered: false };
    }
    const focused = [...ranked]
      .sort((a, b) => a.ordinal - b.ordinal)
      .map((c) => {
        const trimmed = c.text.trim();
        if (!c.heading || /^#{1,6}\s+/.test(trimmed)) return trimmed;
        return `## ${c.heading}\n${trimmed}`;
      })
      .join('\n\n...\n\n');
    return { markdown: focused, chunks: ranked, queryFiltered: true };
  };

  const preferOriginMarkdown = payload.preferOriginMarkdown !== false;
  const blockTrackersOpt = typeof payload.blockTrackers === 'boolean' ? payload.blockTrackers : undefined;
  const rawRenderModeStrEarly = typeof payload.renderMode === 'string' ? payload.renderMode.trim().toLowerCase() : '';
  const requestedRenderModeEarly: 'always' | 'auto' | 'off' =
    inlineActions.length > 0 || mobileEmulation || Boolean(screenshotSpec) || stringFormats.has('screenshot')
      ? 'always'
      : rawRenderModeStrEarly === 'always' || rawRenderModeStrEarly === 'browser'
        ? 'always'
        : rawRenderModeStrEarly === 'off'
          ? 'off'
          : 'auto';
  const sortedFormatsForCache = [...stringFormats].sort();
  // `jsonFilter` changes the returned Markdown, so it is part of the cache identity (L-01). Trimmed like
  // `jsonFilterStr` below; a blank filter is no filter.
  const jsonFilterForCache = typeof payload.jsonFilter === 'string' ? payload.jsonFilter.trim() : '';
  const locationCacheKey = locationObj
    ? `${typeof locationObj.country === 'string' ? locationObj.country.trim().toUpperCase() : ''}|${locationLanguages.join(',')}`
    : '';
  const hasNonDefaultCacheOptionsWithoutRedact =
    !onlyMainContent ||
    requestedRenderModeEarly === 'always' ||
    (rawRenderModeStrEarly !== '' && rawRenderModeStrEarly !== 'auto') ||
    blockTrackersOpt === false ||
    Boolean(mobileEmulation) ||
    Boolean(locationCacheKey) ||
    hasCallerHeadersOrCookies ||
    includeTags.length > 0 ||
    excludeTags.length > 0 ||
    waitForMsOpt !== undefined ||
    Boolean(waitSelectorOpt) ||
    !includeImages ||
    Boolean(jsonFilterForCache) ||
    sortedFormatsForCache.join(',') !== 'markdown' ||
    ocrMode !== 'auto' ||
    pdfParserOpts.includePagesArray ||
    pdfParserOpts.includePageMarkers ||
    pdfParserOpts.ocrModeOverride !== undefined ||
    pdfParserOpts.maxPagesOverride !== undefined ||
    maxPagesCap !== 60;
  const hasNonDefaultCacheOptions = hasNonDefaultCacheOptionsWithoutRedact || Boolean(redactPii);
  const cookiesCacheHash = hasCallerCookies ? await hashCallerCookies(callerCookiesRaw) : undefined;
  const scrapeOptionsHash = await sha256HexString(
    JSON.stringify({
      v: SCRAPE_PIPELINE_VERSION,
      onlyMainContent,
      renderMode: rawRenderModeStrEarly || requestedRenderModeEarly,
      ...(blockTrackersOpt === false ? { blockTrackers: false } : {}),
      mobile: Boolean(mobileEmulation),
      location: locationCacheKey,
      formats: sortedFormatsForCache,
      includeTags: [...includeTags],
      excludeTags: [...excludeTags],
      waitForMs: waitForMsOpt ?? 0,
      waitSelector: waitSelectorOpt ?? '',
      includeImages,
      preferOriginMarkdown,
      redactPii: Boolean(payload.redactPii),
      ...(parsedWikiArticle ? { mwClean: 2 } : {}),
      // Only present when set, so the hash of every request without `jsonFilter` / `cookies` / PDF/OCR options is unchanged.
      ...(jsonFilterForCache ? { jsonFilter: jsonFilterForCache } : {}),
      ...(cookiesCacheHash ? { cookies: cookiesCacheHash } : {}),
      ...(ocrMode !== 'auto' ? { ocrMode } : {}),
      ...(pdfParserOpts.includePagesArray ? { pdfPages: true } : {}),
      ...(pdfParserOpts.includePageMarkers ? { pdfPageMarkers: true } : {}),
      ...(pdfParserOpts.ocrModeOverride ? { pdfMode: pdfParserOpts.ocrModeOverride } : {}),
      ...(maxPagesCap !== 60 ? { maxPages: maxPagesCap } : {}),
    }),
  );

  // Serve from verified META D1 + ARTIFACTS R2 cache when maxAgeMs is satisfied and only markdown/metadata are requested.
  const needsLiveHtmlForHashedOptions =
    !preferOriginMarkdown ||
    stringFormats.has('html') ||
    stringFormats.has('rawHtml') ||
    stringFormats.has('rawBase64') ||
    stringFormats.has('product') ||
    stringFormats.has('links') ||
    stringFormats.has('images') ||
    stringFormats.has('branding') ||
    stringFormats.has('llmsTxt') ||
    stringFormats.has('changes') ||
    inlineActions.length > 0 ||
    includeTags.length > 0 ||
    excludeTags.length > 0;

  const needsLiveHtml =
    needsLiveHtmlForHashedOptions ||
    checkPromptInjection ||
    Boolean(callerExplicitAccept) ||
    pdfParserOpts.skipPdfParsing ||
    Boolean(jsonSchemaSpec) ||
    Boolean(attributesSpec);

  const baseOptionsCacheEligible =
    preferOriginMarkdown &&
    !hasCallerHeaders &&
    !stringFormats.has('html') &&
    !stringFormats.has('rawHtml') &&
    !stringFormats.has('rawBase64') &&
    !stringFormats.has('product') &&
    !stringFormats.has('branding') &&
    !stringFormats.has('screenshot') &&
    !stringFormats.has('llmsTxt') &&
    !stringFormats.has('changes') &&
    !stringFormats.has('summary') &&
    inlineActions.length === 0;

  const canUseOptionsR2Cache =
    baseOptionsCacheEligible &&
    !checkPromptInjection &&
    !callerExplicitAccept &&
    !pdfParserOpts.skipPdfParsing &&
    !jsonSchemaSpec &&
    !attributesSpec;

  const hasCustomContentScoping = !onlyMainContent || includeTags.length > 0 || excludeTags.length > 0;
  const needsDomForTwin =
    hasCustomContentScoping ||
    stringFormats.has('html') ||
    stringFormats.has('rawHtml') ||
    stringFormats.has('images') ||
    stringFormats.has('branding') ||
    stringFormats.has('screenshot') ||
    stringFormats.has('llmsTxt') ||
    stringFormats.has('changes') ||
    inlineActions.length > 0 ||
    pdfParserOpts.skipPdfParsing ||
    includeTags.length > 0 ||
    excludeTags.length > 0 ||
    Boolean(attributesSpec);

  const deleteOptionsScrapeCacheIfNoCache = async (opts?: { force?: boolean }): Promise<void> => {
    if (baseOptionsCacheEligible && payload.ephemeral !== true && (Boolean(payload.noCache) || opts?.force === true) && env.ARTIFACTS) {
      await deleteOptionsScrapeCache({
        bucket: env.ARTIFACTS,
        isPrivate: isPrivateScrape,
        userId,
        url: normalizedUrl,
        optionsHash: scrapeOptionsHash,
        pipelineVersion: SCRAPE_PIPELINE_VERSION,
      }).catch(() => undefined);
      if (isPrivateScrape && !hasCallerHeadersOrCookies && !needsLiveHtmlForHashedOptions && !hasNonDefaultCacheOptionsWithoutRedact) {
        const urlSha = await sha256HexString(normalizedUrl);
        await env.ARTIFACTS.delete(r2PrivateScrapeCacheKey(userId, SCRAPE_PIPELINE_VERSION, urlSha)).catch(() => undefined);
      }
    }
  };
  const putDerivedMarkdownForScrape = async (mdSha: string, mdContent: string, ver = SCRAPE_PIPELINE_VERSION): Promise<void> => {
    if (!env.ARTIFACTS || payload.ephemeral === true) return;
    await primeSanitizedMarkdownCache(mdSha, mdContent, {
      userId,
      privateOnly: isPrivateScrape,
      pipelineVersion: ver,
    });
    const derivedKey = isPrivateScrape
      ? r2PrivateDerivedKey(userId, ver, 'markdown', mdSha)
      : r2DerivedKey(ver, 'markdown', mdSha);
    await env.ARTIFACTS
      .put(derivedKey, mdContent, {
        httpMetadata: { contentType: 'text/markdown; charset=utf-8' },
        customMetadata: {
          pipelineVersion: String(ver),
          ...(isPrivateScrape
            ? {
                userId: sanitizeStorageUserId(userId),
                visibility: 'private',
              }
            : {}),
        },
      })
      .catch(() => undefined);
  };

  let prevMarkdownForChanges: string | null = null;
  if (stringFormats.has('changes') && !hasCallerHeaders && !hasCallerCookies && env.ARTIFACTS && (isPrivateScrape || env.META)) {
    const prevHit = isPrivateScrape
      ? await lookupPrivateCachedScrape({
          bucket: env.ARTIFACTS,
          userId,
          url: normalizedUrl,
          maxAgeMs: 365 * 24 * 60 * 60_000,
          pipelineVersion: SCRAPE_PIPELINE_VERSION,
          now,
        })
      : await lookupCachedScrape({
          bucket: env.ARTIFACTS,
          metaDb: env.META!,
          url: normalizedUrl,
          maxAgeMs: 365 * 24 * 60 * 60_000,
          pipelineVersion: SCRAPE_PIPELINE_VERSION,
          now,
        });
    if (prevHit) {
      prevMarkdownForChanges = prevHit.markdown;
    }
  }

  if (canUseOptionsR2Cache && ocrMode !== 'always' && maxAgeMs > 0 && env.ARTIFACTS && (isPrivateScrape || env.META || hasNonDefaultCacheOptions || parsedWikiArticle !== null)) {
    const cacheStartMs = Date.now();
    const optHit = await lookupOptionsScrapeCache({
      bucket: env.ARTIFACTS,
      isPrivate: isPrivateScrape,
      userId,
      url: normalizedUrl,
      optionsHash: scrapeOptionsHash,
      maxAgeMs,
      pipelineVersion: SCRAPE_PIPELINE_VERSION,
      ...(env.META ? { metaDb: env.META } : {}),
      now,
    });
    const hit: (PrivateCachedScrapeRecord | Awaited<ReturnType<typeof lookupCachedScrape>>) =
      optHit ??
      (!hasCallerHeadersOrCookies && !needsLiveHtml && !hasNonDefaultCacheOptionsWithoutRedact
        ? isPrivateScrape
          ? await lookupPrivateCachedScrape({
              bucket: env.ARTIFACTS,
              userId,
              url: normalizedUrl,
              maxAgeMs,
              pipelineVersion: SCRAPE_PIPELINE_VERSION,
              now,
            }).then((privHit) =>
              privHit && privHit.optionsHash === scrapeOptionsHash ? privHit : null,
            )
          : env.META && !hasNonDefaultCacheOptionsWithoutRedact
            ? await lookupCachedScrape({
                bucket: env.ARTIFACTS,
                metaDb: env.META,
                url: normalizedUrl,
                maxAgeMs,
                pipelineVersion: SCRAPE_PIPELINE_VERSION,
                now,
              })
            : null
        : null);
    if (hit) {
      const cacheVia = isPrivateScrape ? 'cache:private-r2' : 'cache:r2-d1';
      const richHitEarly = hit as Partial<PrivateCachedScrapeRecord>;
      if (activeTracer) {
        const cacheSpan = activeTracer.startSpan('cache:r2-d1', {
          kind: 1,
          startTimeMs: cacheStartMs,
          attributes: {
            'cache.hit': true,
            'cache.tier': isPrivateScrape ? 'private-r2' : 'r2-d1',
            'cache.revalidated': false,
            'url.full': sanitizeUrlForSpan(normalizedUrl),
            'http.response.status_code': hit.status,
            'edgefetch.pipeline_version': hit.pipelineVersion,
          },
        });
        cacheSpan.setStatus(true);
        cacheSpan.end();
        activeTracer.setAttribute('edgefetch.via', cacheVia);
        activeTracer.setAttribute('edgefetch.cached', true);
        if (Boolean(richHitEarly.rendered) && typeof richHitEarly.blockedTrackers === 'number') {
          activeTracer.setAttribute('browser.blocked_trackers', Math.max(0, Math.floor(richHitEarly.blockedTrackers)));
        }
      }
      const rawHitMd = parsedWikiArticle ? cleanMediaWikiMarkdownLinear(hit.markdown) : hit.markdown;
      const fullCached = finalizeScrapedMarkdown(redactPii ? redactPiiText(rawHitMd) : rawHitMd, {
        isPdf: isLikelyPdfUrl(normalizedUrl),
        includeImages,
        allowPdfPageMarkers: pdfParserOpts.includePageMarkers,
      }).markdown;
      const focused = applyQueryFocus(fullCached);
      const shaped = finalizeScrapedMarkdown(focused.markdown, {
        isPdf: false,
        includeImages,
        maxChars,
        allowPdfPageMarkers: pdfParserOpts.includePageMarkers,
      });
      let cachedMarkdownArtifactId: string | undefined;
      if (shaped.truncated && fullCached && payload.ephemeral !== true) {
        const cachedMdSha = await sha256HexString(fullCached);
        await putDerivedMarkdownForScrape(cachedMdSha, fullCached, hit.pipelineVersion);
        cachedMarkdownArtifactId = `md:${cachedMdSha}`;
      }
      const richHit = hit as Partial<PrivateCachedScrapeRecord>;
      const rawCachedTitle = hit.title || (isLikelyPdfUrl(normalizedUrl) ? extractPdfTitle(fullCached, normalizedUrl) : undefined);
      const cachedFinalUrl = parsedWikiArticle
        ? resolveWikipediaCanonicalFinalUrl({
            requestedUrl: normalizedUrl,
            storedFinalUrl: richHit.finalUrl,
            title: rawCachedTitle,
            markdown: fullCached,
          })
        : richHit.finalUrl || normalizedUrl;
      const cachedTitle = sanitizeScrapedMetadataField(
        rawCachedTitle ? (redactPii ? redactPiiText(rawCachedTitle) : rawCachedTitle) : undefined,
        512,
      );
      const cachedDesc = sanitizeScrapedMetadataField(
        richHit.description ? (redactPii ? redactPiiText(richHit.description) : richHit.description) : undefined,
        2_000,
      );
      const cachedWordCount = redactPii ? (fullCached ? countTextWords(fullCached) : 0) : (richHit.wordCount ?? (fullCached ? countTextWords(fullCached) : 0));
      const cachedFavicon = richHit.favicon ?? defaultFaviconForUrl(cachedFinalUrl);
      const cachedContentType =
        richHit.contentType ?? (isLikelyPdfUrl(normalizedUrl) ? 'application/pdf' : 'text/html; charset=utf-8');
      const cachedRendered = Boolean(richHit.rendered);
      const cachedWikiFinal = parseWikipediaArticleUrl(cachedFinalUrl) ?? parsedWikiArticle;
      const cachedExtractorId = richHit.extractorId ?? (cachedWikiFinal ? 'mediawiki' : undefined);
      const cachedDetected =
        richHit.detected ??
        (cachedWikiFinal ? { generators: ['MediaWiki'], adapter: 'mediawiki' } : undefined);
      const privBlobSha = 'blobSha256' in hit ? hit.blobSha256 : undefined;
      return {
        status: 200,
        via: cacheVia,
        body: {
          ok: true,
          cached: true,
          ...(isPrivateScrape ? { visibility: 'private' as const } : {}),
          pipelineVersion: hit.pipelineVersion,
          documentId: hit.documentId,
          contentSha256: hit.contentSha256,
          ...(privBlobSha ? { artifactId: privBlobSha } : {}),
          url: normalizedUrl,
          finalUrl: cachedFinalUrl,
          ...(cachedTitle ? { title: cachedTitle } : {}),
          status: hit.status,
          via: cacheVia,
          ...(cachedExtractorId ? { extractorId: cachedExtractorId } : {}),
          ...(cachedDetected ? { detected: cachedDetected } : {}),
          contentState: richHit.contentState ?? 'active',
          rendered: cachedRendered,
          ...(richHit.renderedVia ? { renderedVia: richHit.renderedVia } : {}),
          ...(cachedWordCount > 0 ? { wordCount: cachedWordCount } : {}),
          ...(cachedFavicon ? { favicon: cachedFavicon } : {}),
          contentType: cachedContentType,
          ...(stringFormats.has('markdown') ? { markdown: shaped.markdown } : {}),
          ...(stringFormats.has('text') ? { text: sanitizeScrapedTextOut(shaped.markdown) } : {}),
          ...(pdfParserOpts.includePagesArray && Array.isArray(richHit.pages)
            ? { pages: redactPii ? richHit.pages.map((pg) => redactPiiText(pg)) : richHit.pages }
            : {}),
          ...(stringFormats.has('links') && richHit.links ? { links: richHit.links } : {}),
          ...(stringFormats.has('images') && richHit.images ? { images: richHit.images } : {}),
          ...(focused.queryFiltered ? { queryFiltered: true, chunks: focused.chunks } : {}),
          ...(shaped.truncated
            ? {
                truncated: true,
                totalChars: shaped.totalChars,
                nextOffset: shaped.nextOffset ?? shaped.markdown.length,
                remainingChars: shaped.remainingChars ?? Math.max(0, (shaped.totalChars ?? 0) - (shaped.nextOffset ?? shaped.markdown.length)),
                ...(cachedMarkdownArtifactId ? { markdownArtifactId: cachedMarkdownArtifactId } : {}),
              }
            : {}),
          metadata: {
            ...(cachedTitle ? { title: cachedTitle } : {}),
            ...(cachedDesc ? { description: cachedDesc } : {}),
            ...(cachedWordCount > 0 ? { wordCount: cachedWordCount } : {}),
            ...(hit.language ? { language: hit.language } : {}),
            ...(cachedFavicon ? { favicon: cachedFavicon } : {}),
            canonicalUrl: richHit.canonicalUrl ?? cachedFinalUrl,
            contentType: cachedContentType,
            lastFetchedAt: hit.lastFetchedAt,
            ...(cachedRendered && typeof richHit.blockedTrackers === 'number'
              ? { blockedTrackers: richHit.blockedTrackers }
              : {}),
          },
        },
      };
    }
  }

  // Direct PDF OCR path when caller explicitly requests `ocr: "always"` (`kb-fetch --ocr` / MCP `scrape`).
  if (ocrMode === 'always' && hasPdfOcr) {
    const forcedOcr = await runPdfOcrFallback({
      url: normalizedUrl,
      ocrParam: 'always',
      maxOcrPages: maxPagesCap,
      redactPii,
      headers: payload.headers,
      target,
      site,
      source,
      selfHost,
      isPrivate: isPrivateScrape,
      userId,
      ephemeral: Boolean(payload.ephemeral),
      env,
      executeHubFetch,
    });
    if (forcedOcr.ok) {
      const fullOcrMd = finalizeScrapedMarkdown(forcedOcr.markdown, { isPdf: true, includeImages }).markdown;
      if (checkPromptInjection) {
        const piForcedOcr = detectPromptInjection({ markdown: fullOcrMd });
        if (piForcedOcr.detected) {
          await deleteOptionsScrapeCacheIfNoCache({ force: true });
          return {
            status: 403,
            via: forcedOcr.via,
            body: {
              ok: false,
              ...(isPrivateScrape ? { visibility: 'private' as const } : {}),
              url: normalizedUrl,
              finalUrl: forcedOcr.finalUrl,
              error: 'SCRAPE_PROMPT_INJECTION_DETECTED',
              message: `Prompt injection guard blocked page content (${piForcedOcr.triggers.join(', ')})`,
              triggers: piForcedOcr.triggers,
            },
          };
        }
      }
      const shaped = finalizeScrapedMarkdown(fullOcrMd, { isPdf: false, includeImages, maxChars });
      let ocrMdArtifactId: string | undefined;
      if (env.ARTIFACTS && fullOcrMd && payload.ephemeral !== true && (shaped.truncated || isPrivateScrape)) {
        const mdSha = await sha256HexString(fullOcrMd);
        await putDerivedMarkdownForScrape(mdSha, fullOcrMd);
        if (shaped.truncated) ocrMdArtifactId = `md:${mdSha}`;
      }
      await deleteOptionsScrapeCacheIfNoCache();
      return {
        status: 200,
        via: forcedOcr.via,
        body: {
          ok: true,
          cached: false,
          ...(isPrivateScrape ? { visibility: 'private' as const } : {}),
          pipelineVersion: SCRAPE_PIPELINE_VERSION,
          url: normalizedUrl,
          finalUrl: forcedOcr.finalUrl,
          status: forcedOcr.status,
          via: forcedOcr.via,
          ...(forcedOcr.contentSha256 ? { contentSha256: forcedOcr.contentSha256 } : {}),
          ...(forcedOcr.artifactId ? { artifactId: forcedOcr.artifactId } : {}),
          ...(ocrMdArtifactId ? { markdownArtifactId: ocrMdArtifactId } : {}),
          ...(stringFormats.has('markdown') ? { markdown: shaped.markdown } : {}),
          ...(stringFormats.has('text') ? { text: sanitizeScrapedTextOut(shaped.markdown) } : {}),
          ...(shaped.truncated
            ? {
                truncated: true,
                totalChars: shaped.totalChars,
                nextOffset: shaped.nextOffset ?? shaped.markdown.length,
                remainingChars: shaped.remainingChars ?? Math.max(0, (shaped.totalChars ?? 0) - (shaped.nextOffset ?? shaped.markdown.length)),
              }
            : {}),
          pdfEngine: forcedOcr.pdfEngine,
          ...(forcedOcr.ocr ? { ocr: forcedOcr.ocr } : {}),
          ...(stringFormats.has('changes') ? { changes: computeMarkdownChanges(prevMarkdownForChanges, fullOcrMd) } : {}),
          metadata: { contentType: 'application/pdf' },
        },
      };
    }
    if (forcedOcr.originFailure) {
      await deleteOptionsScrapeCacheIfNoCache();
      return forcedOcr.originFailure;
    }
  }

  const agentFormats = [...stringFormats].filter((f) =>
    ['markdown', 'text', 'html', 'rawHtml', 'rawBase64', 'links', 'images', 'branding', 'screenshot'].includes(f),
  );
  if (pdfParserOpts.skipPdfParsing && !agentFormats.includes('rawBase64')) {
    agentFormats.push('rawBase64');
  }
  if (agentFormats.length === 0) agentFormats.push('markdown');

  const rawRenderModeStr = typeof payload.renderMode === 'string' ? payload.renderMode.trim().toLowerCase() : '';
  const renderMode: 'always' | 'auto' | 'off' | undefined =
    inlineActions.length > 0 || mobileEmulation || Boolean(screenshotSpec)
      ? 'always'
      : rawRenderModeStr === 'always' || rawRenderModeStr === 'browser'
        ? 'always'
        : rawRenderModeStr === 'auto' || rawRenderModeStr === 'off'
          ? rawRenderModeStr
          : stringFormats.has('screenshot')
            ? 'always'
            : undefined;
  const effectiveRenderMode: 'always' | 'auto' | 'off' = renderMode ?? 'auto';
  const jsonFilterStr = typeof payload.jsonFilter === 'string' ? payload.jsonFilter.trim() : '';
  const waybackFallback = Boolean(payload.waybackFallback);
  let scopedUserCollectionId: string | undefined;
  if (typeof payload.collectionId === 'string' && payload.collectionId.trim()) {
    const resolvedColl = resolveUserCollectionId(payload.collectionId, userId, visibility);
    if (!resolvedColl.ok) {
      return {
        status: resolvedColl.status,
        via: 'hub',
        body: { ok: false, error: resolvedColl.error, message: 'Invalid or unauthorized collectionId' },
      };
    }
    scopedUserCollectionId = resolvedColl.scopedId;
  }
  const collectionId = isPrivateScrape ? undefined : scopedUserCollectionId;
  const retentionMode: ArtifactRetention | 'off' | undefined =
    payload.ephemeral === true || isPrivateScrape
      ? 'off'
      : env.ARTIFACTS && env.META && blockTrackersOpt !== false
        ? 'stored'
        : env.ARTIFACTS
          ? 'transient'
          : undefined;

  if (parsedWikiArticle) {
    const wikiQuota = checkAndRecordWikipediaArticleQuota({
      callerKey: userId || source,
      host: parsedWikiArticle.host,
      now,
    });
    if (!wikiQuota.allowed) {
      return {
        status: 429,
        via: 'policy',
        body: { ...wikiQuota.block },
      };
    }
  }

  // R5: Look up stored ETag / Last-Modified validators in META D1 (or options-scoped R2 cache on Wikipedia refresh) when a verified derived document already exists.
  const d1RevalCandidate =
    !isPrivateScrape &&
    !hasCallerHeaders &&
    !hasCallerCookies &&
    !needsLiveHtml &&
    !hasNonDefaultCacheOptionsWithoutRedact &&
    !Boolean(payload.noCache) &&
    renderMode !== 'always' &&
    !scopedUserCollectionId &&
    env.ARTIFACTS &&
    env.META
      ? await lookupRevalidationCandidate({
          bucket: env.ARTIFACTS,
          metaDb: env.META,
          url: normalizedUrl,
          pipelineVersion: SCRAPE_PIPELINE_VERSION,
        })
      : null;
  const optRevalCandidate =
    !d1RevalCandidate &&
    parsedWikiArticle !== null &&
    canUseOptionsR2Cache &&
    !Boolean(payload.noCache) &&
    ocrMode !== 'always' &&
    renderMode !== 'always' &&
    !scopedUserCollectionId &&
    env.ARTIFACTS
      ? await lookupOptionsScrapeCache({
          bucket: env.ARTIFACTS,
          isPrivate: isPrivateScrape,
          userId,
          url: normalizedUrl,
          optionsHash: scrapeOptionsHash,
          maxAgeMs: 365 * 24 * 60 * 60_000,
          pipelineVersion: SCRAPE_PIPELINE_VERSION,
          now,
        }).then((rec) => (rec && (rec.etag || rec.lastModified) ? rec : null))
      : null;
  const revalCandidate = d1RevalCandidate ?? optRevalCandidate;

  const rawBase64Explicit = stringFormats.has('rawBase64');
  const rawBase64Requested = rawBase64Explicit || pdfParserOpts.skipPdfParsing;
  const fetchCall = {
    maxSeconds: Math.max(30, Math.ceil(timeoutMsOpt / 1_000) + 15),
    options: {
      includeBody: true,
      respectRobots: true,
      maxBytes: 16 * 1024 * 1024,
      maxInlineBodyBytes: rawBase64Requested ? INLINE_HYDRATION_BUDGET_BYTES : MAX_WASM_INPUT_BYTES,
      timeoutMs: timeoutMsOpt,
      discoverLlms: goDiscoverLlms,
    },
    requests: [
      {
        id: 'scrape-1',
        url: normalizedUrl,
        kind: pdfParserOpts.skipPdfParsing ? 'binary' : renderMode === 'always' ? 'render' : 'scrape',
        ...(!pdfParserOpts.skipPdfParsing
          ? {
              accept:
                callerExplicitAccept ??
                (!preferOriginMarkdown ||
                stringFormats.has('html') ||
                stringFormats.has('rawHtml') ||
                hasHtmlSiteAdapterForHost(normalizedUrl)
                  ? 'text/html,application/xhtml+xml;q=0.9,*/*;q=0.8'
                  : MARKDOWN_FOR_AGENTS_ACCEPT),
            }
          : callerExplicitAccept
            ? { accept: callerExplicitAccept }
            : {}),
        formats: agentFormats,
        onlyMainContent,
        // A Go node that extracts an over-budget page itself (primary agent path or offload) applies these too and
        // confirms with `contentScopingApplied`; see `nodeResultSatisfiesRequest`.
        ...(includeTags.length > 0 ? { includeTags } : {}),
        ...(excludeTags.length > 0 ? { excludeTags } : {}),
        ...(jsonFilterStr ? { jsonFilter: jsonFilterStr } : {}),
        discoverLlms: goDiscoverLlms,
        preferLlmsMarkdown: !needsLiveHtml && !hasCustomContentScoping && renderMode !== 'always',
        redactPii,
        ...(revalCandidate?.etag ? { ifNoneMatch: revalCandidate.etag } : {}),
        ...(revalCandidate?.lastModified ? { ifModifiedSince: revalCandidate.lastModified } : {}),
        renderMode: renderMode === 'always' ? 'always' : 'off',
        ...(blockTrackersOpt !== undefined ? { blockTrackers: blockTrackersOpt } : {}),
        ...(mobileEmulation ? { mobile: true } : {}),
        ...(screenshotSpec?.fullPage ? { screenshotFullPage: true } : {}),
        ...(screenshotSpec?.quality ? { screenshotQuality: screenshotSpec.quality } : {}),
        ...(typeof screenshotSpec?.viewport?.width === 'number' ? { viewportWidth: Math.floor(screenshotSpec.viewport.width) } : {}),
        ...(typeof screenshotSpec?.viewport?.height === 'number' ? { viewportHeight: Math.floor(screenshotSpec.viewport.height) } : {}),
        ...(acceptLanguageOpt ? { acceptLanguage: acceptLanguageOpt } : {}),
        ...(waitForMsOpt !== undefined ? { waitForMs: waitForMsOpt } : {}),
        ...(waitSelectorOpt ? { waitSelector: waitSelectorOpt } : {}),
        ...(maxPagesCap ? { maxPages: maxPagesCap } : {}),
        ...(Object.keys(mergedHeaders).length > 0 ? { headers: mergedHeaders } : {}),
        ...(inlineActions.length > 0 ? { interact: { actions: inlineActions } } : {}),
      },
    ],
  };

  const htmlFragToMd = (frag: string, fragBase?: string) => {
    const sub = extractHtmlDocument(frag, {
      baseUrl: fragBase,
      onlyMainContent: false,
      includeImages,
    });
    return { markdown: sub.markdown, links: sub.links };
  };

  const fetchBoundedTwin: FetchBoundedTwinFn = async ({ url: epUrl, tag, kind, accept, trustAdapterId }) => {
    const epRes = await executeHubFetch(
      target,
      JSON.stringify({
        maxSeconds: 25,
        options: {
          includeBody: true,
          respectRobots: true,
          maxBytes: MAX_WASM_INPUT_BYTES,
          maxInlineBodyBytes: MAX_WASM_INPUT_BYTES,
        },
        requests: [{ id: tag, url: epUrl, kind, accept }],
      }),
      site,
      `${source}:${tag}`,
      retentionMode,
      true,
      collectionId,
    );
    if (epRes.status !== 200) return null;
    const epParsed = JSON.parse(epRes.bodyText) as { results?: Array<Record<string, unknown>> };
    const epItem = epParsed.results?.[0];
    if (!epItem || epItem.outcome !== 'ok' || !isTrustedTwinRedirectUrl(trustAdapterId, epUrl, epItem, selfHost)) {
      return null;
    }
    const epBody = typeof epItem.body === 'string' && epItem.bodyEncoding !== 'base64' ? epItem.body : '';
    if (!epBody.trim()) return null;
    return { item: epItem, body: epBody, via: epRes.via };
  };

  // Pre-fetch ATS API adapters (`P1` Ashby, `P2` Workday CXS `GET`/`POST`, Greenhouse, Lever) — runs even when
  // `renderMode: "browser"` / `"always"` is passed so client-hydrated ATS boards always resolve cleanly via their official APIs.
  const canUseAtsAdapter =
    !hasCustomContentScoping &&
    inlineActions.length === 0 &&
    !stringFormats.has('html') &&
    !stringFormats.has('rawHtml') &&
    !stringFormats.has('rawBase64') &&
    !stringFormats.has('screenshot') &&
    !stringFormats.has('branding') &&
    !attributesSpec &&
    !jsonSchemaSpec;
  const atsSpec = canUseAtsAdapter
    ? resolveAtsPreFetchSpec(normalizedUrl, { liteBoard: payload.atsLiteBoard === true })
    : null;
  if (atsSpec) {
    try {
      const atsRes = await executeHubFetch(
        target,
        JSON.stringify({
          maxSeconds: 45,
          options: {
            includeBody: true,
            respectRobots: true,
            maxBytes: MAX_WASM_INPUT_BYTES,
            maxInlineBodyBytes: MAX_WASM_INPUT_BYTES,
          },
          requests: [
            {
              id: `ats-${atsSpec.id}`,
              url: atsSpec.fetchUrl,
              method: atsSpec.method,
              ...(atsSpec.requestBody ? { requestBody: atsSpec.requestBody } : {}),
              ...(atsSpec.contentType ? { contentType: atsSpec.contentType } : {}),
              kind: atsSpec.kind,
              accept: atsSpec.accept,
            },
          ],
        }),
        site,
        `${source}:ats:${atsSpec.id}`,
        retentionMode,
        true,
        collectionId,
      );
      const atsVia = atsRes.via;
      if (atsRes.status === 200) {
        let atsParsed: { results?: Array<Record<string, unknown>> } | null = JSON.parse(atsRes.bodyText) as {
          results?: Array<Record<string, unknown>>;
        };
        // Drop the multi-MiB raw hub JSON envelope immediately so V8 can reclaim it before WASM formatting.
        (atsRes as { bodyText: string }).bodyText = '';
        const atsItem = atsParsed.results?.[0];
        atsParsed = null;
        let atsBody = typeof atsItem?.body === 'string' && atsItem.bodyEncoding !== 'base64' ? atsItem.body : '';
        if (atsItem && 'body' in atsItem) {
          delete atsItem.body;
        }
        if (
          atsItem &&
          isTrustedTwinRedirectUrl(atsSpec.id, atsSpec.fetchUrl, atsItem, selfHost) &&
          (atsItem.outcome === 'ok' || (atsItem.truncated === true && atsItem.status === 200)) &&
          atsBody.trim().length > 0
        ) {
          const filteredBoard =
            jsonFilterStr && atsSpec.id.endsWith('-board')
              ? chunkJsonRecords({
                  rawBody: atsBody,
                  contentType: 'application/json',
                  url: normalizedUrl,
                  jsonFilter: jsonFilterStr,
                  htmlToMd: htmlFragToMd,
                })
              : null;
          const formatted = atsSpec.format(atsBody, normalizedUrl, htmlFragToMd);
          atsBody = '';
          if (filteredBoard || (formatted && formatted.markdown.trim().length > 0)) {
            const rawAtsMd = filteredBoard ? filteredBoard.markdown : formatted!.markdown;
            const cleanAtsMd = redactPii ? redactPiiText(rawAtsMd) : rawAtsMd;
            const atsShapedFull = finalizeScrapedMarkdown(cleanAtsMd, {
              isPdf: false,
              includeImages,
              baseUrl: normalizedUrl,
            });
            const atsFocused = applyQueryFocus(atsShapedFull.markdown);
            const atsShaped =
              atsFocused.queryFiltered || maxChars !== undefined
                ? finalizeScrapedMarkdown(atsFocused.markdown, {
                    isPdf: false,
                    includeImages,
                    maxChars,
                    baseUrl: normalizedUrl,
                  })
                : atsShapedFull;
            const atsArt = !isPrivateScrape ? (atsItem.artifact as { blobSha256?: string; contentSha256?: string } | undefined) : undefined;
            const rawAtsTitle = filteredBoard ? filteredBoard.title : formatted!.title;
            const atsTitle = sanitizeScrapedMetadataField(
              rawAtsTitle ? (redactPii ? redactPiiText(rawAtsTitle) : rawAtsTitle) : undefined,
              512,
            );
            const atsDesc = sanitizeScrapedMetadataField(
              formatted?.description ? (redactPii ? redactPiiText(formatted.description) : formatted.description) : undefined,
              2_000,
            );
            const atsJobPostingOut = formatted?.jobPosting
              ? redactPii
                ? redactPiiDeep(sanitizeRecordUrlsDeep(formatted.jobPosting))
                : sanitizeRecordUrlsDeep(formatted.jobPosting)
              : undefined;
            const atsJobsOut =
              formatted?.jobs && !filteredBoard
                ? redactPii
                  ? redactPiiDeep(sanitizeRecordUrlsDeep(formatted.jobs))
                  : sanitizeRecordUrlsDeep(formatted.jobs)
                : undefined;
            const atsFilteredChunksOut = filteredBoard
              ? redactPii
                ? redactPiiDeep(filteredBoard.chunks)
                : filteredBoard.chunks
              : undefined;
            if (checkPromptInjection) {
              const piAts = detectPromptInjection({
                markdown: [
                  atsTitle ?? '',
                  atsDesc ?? '',
                  atsShapedFull.markdown,
                  atsJobPostingOut ? JSON.stringify(atsJobPostingOut) : '',
                  atsJobsOut ? JSON.stringify(atsJobsOut) : '',
                ]
                  .filter(Boolean)
                  .join('\n\n'),
              });
              if (piAts.detected) {
                await deleteOptionsScrapeCacheIfNoCache({ force: true });
                return {
                  status: 403,
                  via: atsVia,
                  body: {
                    ok: false,
                    ...(isPrivateScrape ? { visibility: 'private' as const } : {}),
                    url: normalizedUrl,
                    finalUrl: normalizedUrl,
                    error: 'SCRAPE_PROMPT_INJECTION_DETECTED',
                    message: `Prompt injection guard blocked page content (${piAts.triggers.join(', ')})`,
                    triggers: piAts.triggers,
                  },
                };
              }
            }
            let atsMdArtifactId: string | undefined;
            if (atsShaped.truncated && env.ARTIFACTS && atsShapedFull.markdown && payload.ephemeral !== true) {
              const mdSha = await sha256HexString(atsShapedFull.markdown);
              await putDerivedMarkdownForScrape(mdSha, atsShapedFull.markdown);
              atsMdArtifactId = `md:${mdSha}`;
            }
            setActiveSpanAttribute('edgefetch.adapter_id', atsSpec.id, activeTracer ?? undefined);
            await deleteOptionsScrapeCacheIfNoCache();
            return {
              status: 200,
              via: atsVia,
              body: {
                ok: true,
                cached: false,
                ...(isPrivateScrape ? { visibility: 'private' as const } : {}),
                pipelineVersion: SCRAPE_PIPELINE_VERSION,
                url: normalizedUrl,
                finalUrl: normalizedUrl,
                status: atsItem.status ?? 200,
                via: atsVia,
                extractorId: atsSpec.id,
                detected: { generators: [], adapter: atsSpec.id },
                rendered: false,
                contentState: 'active' as const,
                ...(atsArt?.contentSha256 ? { contentSha256: atsArt.contentSha256 } : {}),
                ...(atsArt?.blobSha256 ? { artifactId: atsArt.blobSha256 } : {}),
                ...(atsMdArtifactId ? { markdownArtifactId: atsMdArtifactId } : {}),
                ...(atsJobPostingOut ? { jobPosting: atsJobPostingOut } : {}),
                ...(atsJobsOut ? { jobs: atsJobsOut } : {}),
                ...(formatted?.total !== undefined && !filteredBoard ? { total: formatted.total } : {}),
                ...(formatted?.returned !== undefined && !filteredBoard ? { returned: formatted.returned } : {}),
                ...(formatted?.nextCursor !== undefined && !filteredBoard ? { nextCursor: formatted.nextCursor } : {}),
                ...(filteredBoard && atsFilteredChunksOut
                  ? {
                      chunks: atsFilteredChunksOut,
                      recordCount: filteredBoard.matchedRecords,
                      totalRecords: filteredBoard.totalRecords,
                    }
                  : {}),
                ...(stringFormats.has('markdown') ? { markdown: atsShaped.markdown } : {}),
                ...(stringFormats.has('text') ? { text: sanitizeScrapedTextOut(atsShaped.markdown) } : {}),
                ...(stringFormats.has('links') && formatted?.links ? { links: formatted.links } : {}),
                ...(atsFocused.queryFiltered ? { queryFiltered: true, chunks: atsFocused.chunks } : {}),
                ...(atsShaped.truncated
                  ? {
                      truncated: true,
                      totalChars: atsShaped.totalChars,
                      nextOffset: atsShaped.nextOffset ?? atsShaped.markdown.length,
                      remainingChars: atsShaped.remainingChars ?? Math.max(0, (atsShaped.totalChars ?? 0) - (atsShaped.nextOffset ?? atsShaped.markdown.length)),
                    }
                  : formatted?.truncated !== undefined && !filteredBoard
                    ? { truncated: formatted.truncated }
                    : {}),
                metadata: {
                  title: atsTitle,
                  ...(atsDesc ? { description: atsDesc } : {}),
                  ...(formatted?.publishedTime ? { publishedTime: formatted.publishedTime } : {}),
                  wordCount: countTextWords(atsShapedFull.markdown),
                  alternateMarkdownUrl: atsSpec.fetchUrl,
                  contentType: atsItem.contentType ?? atsSpec.accept,
                },
              },
            };
          }
        } else if (
          atsItem &&
          atsItem.outcome !== 'challenge' &&
          atsItem.outcome !== 'robots_disallowed' &&
          atsItem.outcome !== 'content_signal_disallowed' &&
          !atsItem.waf &&
          isTrustedTwinRedirectUrl(atsSpec.id, atsSpec.fetchUrl, atsItem, selfHost) &&
          /^(?:greenhouse(?:-eu)?|ashby|lever(?:-eu)?|workable|gem|workday)-(?:board|job)$/.test(atsSpec.id) &&
          !classifyWafAndChallenge({
            status: typeof atsItem.status === 'number' ? atsItem.status : 0,
            rawBody: atsBody,
          }) &&
          (atsItem.status === 404 ||
            atsItem.status === 410 ||
            // Workday CXS returns structured JSON `{"errorCode":"S22","errorCaseId":"...","httpStatus":403,"message":"permission denied"}`
            // for closed/unpublished job requisitions and HTTP 422 / 500 JSON errors when `{tenant}`/`{site}`
            // does not exist on that `wdN` cluster — verify exact schema so WAF 403/422 HTML challenges never match!
            (() => {
              if (
                (atsSpec.id !== 'workday-job' && atsSpec.id !== 'workday-board') ||
                (atsItem.status !== 403 && atsItem.status !== 422 && atsItem.status !== 500) ||
                atsBody.length > 2048 ||
                !atsBody.trimStart().startsWith('{')
              ) {
                return false;
              }
              if (typeof atsItem.contentType === 'string' && atsItem.contentType && !/json/i.test(atsItem.contentType)) {
                return false;
              }
              try {
                const parsedErr = JSON.parse(atsBody) as Record<string, unknown>;
                if (!parsedErr || typeof parsedErr !== 'object') {
                  return false;
                }
                const hasCaseId = typeof parsedErr.errorCaseId === 'string' && parsedErr.errorCaseId.length > 0;
                const isCxsCode = typeof parsedErr.errorCode === 'string' && /^S\d{1,4}$/.test(parsedErr.errorCode);
                if (atsSpec.id === 'workday-job' && atsItem.status === 403) {
                  return hasCaseId && parsedErr.errorCode === 'S22' && parsedErr.httpStatus === 403;
                }
                if (atsItem.status === 422) {
                  return hasCaseId && isCxsCode && parsedErr.httpStatus === 422;
                }
                if (atsItem.status === 500) {
                  return (
                    (hasCaseId && isCxsCode && parsedErr.httpStatus === 500) ||
                    (parsedErr.errorCode === 'INTERNAL_SERVER_ERROR' &&
                      typeof parsedErr.message === 'string' &&
                      parsedErr.message.length > 0)
                  );
                }
                return false;
              } catch {
                return false;
              }
            })())
        ) {
          // Authoritative hosted ATS API returned 404/410 (or Workday CXS structured S22/422/500): return immediately instead of triple-fetching
          // (`ats-*` -> `twin-*` -> HTML `scrape-1` -> 14s headless Chromium `auto-render-1` on `?error=true`)!
          const isSingleJobSpec = atsSpec.id.endsWith('-job');
          const upstreamStatus = Number(atsItem.status);
          const statusOut = upstreamStatus === 403 || upstreamStatus === 422 || upstreamStatus === 500 ? 404 : upstreamStatus;
          setActiveSpanAttribute('edgefetch.adapter_id', atsSpec.id, activeTracer ?? undefined);
          setActiveSpanAttribute('edgefetch.outcome', 'not_found', activeTracer ?? undefined);
          await deleteOptionsScrapeCacheIfNoCache();
          return {
            status: statusOut,
            via: atsRes.via,
            body: {
              ok: false,
              url: normalizedUrl,
              finalUrl: normalizedUrl,
              outcome: 'not_found',
              error: 'not_found',
              retryable: false,
              status: statusOut,
              ...(statusOut !== upstreamStatus ? { upstreamStatus } : {}),
              extractorId: atsSpec.id,
              ...(isSingleJobSpec
                ? {
                    contentState: 'closed_posting' as const,
                    contentStateReason: `ATS posting API returned HTTP ${upstreamStatus} (closed or unpublished)`,
                  }
                : {}),
              problem: `HTTP ${upstreamStatus}`,
            },
          };
        }
      }
    } catch {
      // Fall through cleanly if the ATS API endpoint fails or is unreachable.
    }
  }

  // Single-hop GitHub `/blob/<ref>/<path>` raw upgrade: fetch `raw.githubusercontent.com` directly (~2 KB) instead of
  // downloading 350 KB `github.com` HTML first (and avoiding `github.com` `/*/blob/` non-default branch robots blocks).
  const directGhBlob = !needsLiveHtml && !hasCustomContentScoping && renderMode !== 'always' ? parseGitHubBlobRawTarget(normalizedUrl) : null;
  if (directGhBlob) {
    try {
      const ghDirectRes = await executeHubFetch(
        target,
        JSON.stringify({
          maxSeconds: 30,
          options: {
            includeBody: true,
            respectRobots: true,
            maxBytes: MAX_WASM_INPUT_BYTES,
            maxInlineBodyBytes: MAX_WASM_INPUT_BYTES,
          },
          requests: [{ id: 'gh-raw-1', url: directGhBlob.rawUrl, kind: 'text', accept: 'text/plain' }],
        }),
        site,
        `${source}:github-raw`,
        retentionMode,
        true,
        collectionId,
      );
      if (ghDirectRes.status === 200) {
        const ghParsed = JSON.parse(ghDirectRes.bodyText) as { results?: Array<Record<string, unknown>> };
        const ghItem = ghParsed.results?.[0];
        const ghBody = typeof ghItem?.body === 'string' && ghItem.bodyEncoding !== 'base64' ? ghItem.body : '';
        if (
          ghItem &&
          isTrustedTwinRedirectUrl(undefined, directGhBlob.rawUrl, ghItem, selfHost) &&
          ghItem.outcome === 'ok' &&
          ghBody.trim().length > 0 &&
          !/^\s*<!doctype\s+html|^\s*<html/i.test(ghBody)
        ) {
          const cleanGhBody = redactPii ? redactPiiText(ghBody) : ghBody;
          let ghStructuredTitle: string | undefined;
          let ghStructuredDesc: string | undefined;
          let ghFullMd: string;
          if (directGhBlob.isMarkdown) {
            ghFullMd = cleanGhBody;
          } else if (/\.(?:ipynb|json)$/i.test(directGhBlob.filePath)) {
            let parsedGhJson: unknown = null;
            try {
              parsedGhJson = JSON.parse(cleanGhBody.replace(/^\ufeff/, ''));
            } catch {
              parsedGhJson = null;
            }
            const nbDoc = parsedGhJson
              ? formatJupyterNotebookToMarkdown(parsedGhJson, `${directGhBlob.repoSlug}/${directGhBlob.filePath}`)
              : null;
            const oaDoc = !nbDoc && parsedGhJson ? formatOpenApiSpecToMarkdown(parsedGhJson) : null;
            const richDoc = nbDoc ?? oaDoc;
            if (richDoc) {
              ghFullMd = richDoc.markdown;
              ghStructuredTitle = richDoc.title;
              ghStructuredDesc = richDoc.description;
            } else {
              ghFullMd = `# ${directGhBlob.repoSlug}/${directGhBlob.filePath}\n\n${makeSafeCodeFence(cleanGhBody, directGhBlob.fenceLang)}`;
            }
          } else {
            ghFullMd = `# ${directGhBlob.repoSlug}/${directGhBlob.filePath}\n\n${makeSafeCodeFence(cleanGhBody, directGhBlob.fenceLang)}`;
          }
          const ghShapedFull = finalizeScrapedMarkdown(ghFullMd, {
            isPdf: false,
            includeImages,
            baseUrl: directGhBlob.rawUrl,
          });
          const ghFocused = applyQueryFocus(ghShapedFull.markdown);
          const ghShaped =
            ghFocused.queryFiltered || maxChars !== undefined
              ? finalizeScrapedMarkdown(ghFocused.markdown, {
                  isPdf: false,
                  includeImages,
                  maxChars,
                  baseUrl: directGhBlob.rawUrl,
                })
              : ghShapedFull;
          const ghArt = !isPrivateScrape ? (ghItem.artifact as { blobSha256?: string; contentSha256?: string } | undefined) : undefined;
          let ghMdArtifactId: string | undefined;
          if (ghShaped.truncated && env.ARTIFACTS && ghShapedFull.markdown && payload.ephemeral !== true) {
            const mdSha = await sha256HexString(ghShapedFull.markdown);
            await putDerivedMarkdownForScrape(mdSha, ghShapedFull.markdown);
            ghMdArtifactId = `md:${mdSha}`;
          }
          await deleteOptionsScrapeCacheIfNoCache();
          return {
            status: 200,
            via: ghDirectRes.via,
            body: {
              ok: true,
              cached: false,
              ...(isPrivateScrape ? { visibility: 'private' as const } : {}),
              pipelineVersion: SCRAPE_PIPELINE_VERSION,
              url: normalizedUrl,
              finalUrl: normalizedUrl,
              status: ghItem.status ?? 200,
              via: ghDirectRes.via,
              ...(ghArt?.contentSha256 ? { contentSha256: ghArt.contentSha256 } : {}),
              ...(ghArt?.blobSha256 ? { artifactId: ghArt.blobSha256 } : {}),
              ...(ghMdArtifactId ? { markdownArtifactId: ghMdArtifactId } : {}),
              ...(stringFormats.has('markdown') ? { markdown: ghShaped.markdown } : {}),
              ...(stringFormats.has('text') ? { text: sanitizeScrapedTextOut(cleanGhBody) } : {}),
              ...(ghFocused.queryFiltered ? { queryFiltered: true, chunks: ghFocused.chunks } : {}),
              ...(ghShaped.truncated
                ? {
                    truncated: true,
                    totalChars: ghShaped.totalChars,
                    nextOffset: ghShaped.nextOffset ?? ghShaped.markdown.length,
                    remainingChars: ghShaped.remainingChars ?? Math.max(0, (ghShaped.totalChars ?? 0) - (ghShaped.nextOffset ?? ghShaped.markdown.length)),
                  }
                : {}),
              metadata: {
                title: sanitizeScrapedMetadataField(ghStructuredTitle ?? `${directGhBlob.repoSlug}/${directGhBlob.filePath}`, 512),
                ...(sanitizeScrapedMetadataField(ghStructuredDesc, 2_000)
                  ? { description: sanitizeScrapedMetadataField(ghStructuredDesc, 2_000) }
                  : {}),
                alternateMarkdownUrl: directGhBlob.rawUrl,
                contentType: ghItem.contentType ?? 'text/plain; charset=utf-8',
              },
            },
          };
        }
      }
    } catch {
      // Fall through to standard HTML fetch if direct raw fetch fails.
    }
  }

  // Single-hop GitHub `/commit/<sha>` patch upgrade: fetch `<sha>.patch` (~5 KB, allowed by `github.com/robots.txt`)
  // instead of GitHub's heavy HTML diff view (which frequently times out or returns HTTP 503 on large commits).
  const directGhCommit = !needsLiveHtml && !hasCustomContentScoping && renderMode !== 'always' ? parseGitHubCommitPatchTarget(normalizedUrl) : null;
  if (directGhCommit) {
    try {
      const ghPatchRes = await executeHubFetch(
        target,
        JSON.stringify({
          maxSeconds: 30,
          options: {
            includeBody: true,
            respectRobots: true,
            maxBytes: MAX_WASM_INPUT_BYTES,
            maxInlineBodyBytes: MAX_WASM_INPUT_BYTES,
          },
          requests: [{ id: 'gh-patch-1', url: directGhCommit.patchUrl, kind: 'text', accept: 'text/plain' }],
        }),
        site,
        `${source}:github-patch`,
        retentionMode,
        true,
        collectionId,
      );
      if (ghPatchRes.status === 200) {
        const ghPatchParsed = JSON.parse(ghPatchRes.bodyText) as { results?: Array<Record<string, unknown>> };
        const ghPatchItem = ghPatchParsed.results?.[0];
        const ghPatchBody =
          typeof ghPatchItem?.body === 'string' && ghPatchItem.bodyEncoding !== 'base64' ? ghPatchItem.body : '';
        if (
          ghPatchItem &&
          isTrustedTwinRedirectUrl(undefined, directGhCommit.patchUrl, ghPatchItem, selfHost) &&
          ghPatchItem.outcome === 'ok' &&
          ghPatchBody.trim().length > 0
        ) {
          const cleanPatchRaw = redactPii ? redactPiiText(ghPatchBody) : ghPatchBody;
          const patchDoc = formatGitPatchToMarkdown(cleanPatchRaw, 'text/x-patch', normalizedUrl);
          if (patchDoc) {
            const patchShapedFull = finalizeScrapedMarkdown(patchDoc.markdown, {
              isPdf: false,
              includeImages: false,
              baseUrl: normalizedUrl,
            });
            const patchFocused = applyQueryFocus(patchShapedFull.markdown);
            const patchShaped =
              patchFocused.queryFiltered || maxChars !== undefined
                ? finalizeScrapedMarkdown(patchFocused.markdown, {
                    isPdf: false,
                    includeImages: false,
                    maxChars,
                    baseUrl: normalizedUrl,
                  })
                : patchShapedFull;
            const ghPatchArt = !isPrivateScrape ? (ghPatchItem.artifact as { blobSha256?: string; contentSha256?: string } | undefined) : undefined;
            let patchMdArtifactId: string | undefined;
            if (patchShaped.truncated && env.ARTIFACTS && patchShapedFull.markdown && payload.ephemeral !== true) {
              const mdSha = await sha256HexString(patchShapedFull.markdown);
              await putDerivedMarkdownForScrape(mdSha, patchShapedFull.markdown);
              patchMdArtifactId = `md:${mdSha}`;
            }
            await deleteOptionsScrapeCacheIfNoCache();
            return {
              status: 200,
              via: ghPatchRes.via,
              body: {
                ok: true,
                cached: false,
                ...(isPrivateScrape ? { visibility: 'private' as const } : {}),
                pipelineVersion: SCRAPE_PIPELINE_VERSION,
                url: normalizedUrl,
                finalUrl: normalizedUrl,
                status: ghPatchItem.status ?? 200,
                via: ghPatchRes.via,
                ...(ghPatchArt?.contentSha256 ? { contentSha256: ghPatchArt.contentSha256 } : {}),
                ...(ghPatchArt?.blobSha256 ? { artifactId: ghPatchArt.blobSha256 } : {}),
                ...(patchMdArtifactId ? { markdownArtifactId: patchMdArtifactId } : {}),
                ...(stringFormats.has('markdown') ? { markdown: patchShaped.markdown } : {}),
                ...(stringFormats.has('text') ? { text: sanitizeScrapedTextOut(cleanPatchRaw) } : {}),
                ...(patchFocused.queryFiltered ? { queryFiltered: true, chunks: patchFocused.chunks } : {}),
                ...(patchShaped.truncated
                  ? {
                      truncated: true,
                      totalChars: patchShaped.totalChars,
                      nextOffset: patchShaped.nextOffset ?? patchShaped.markdown.length,
                      remainingChars: patchShaped.remainingChars ?? Math.max(0, (patchShaped.totalChars ?? 0) - (patchShaped.nextOffset ?? patchShaped.markdown.length)),
                    }
                  : {}),
                metadata: {
                  title: sanitizeScrapedMetadataField(patchDoc.title ?? `${directGhCommit.repoSlug}@${directGhCommit.sha.slice(0, 10)}`, 512),
                  ...(sanitizeScrapedMetadataField(patchDoc.description, 2_000)
                    ? { description: sanitizeScrapedMetadataField(patchDoc.description, 2_000) }
                    : {}),
                  alternateMarkdownUrl: directGhCommit.patchUrl,
                  contentType: ghPatchItem.contentType ?? 'text/x-patch; charset=utf-8',
                },
              },
            };
          }
        }
      }
    } catch {
      // Fall through to standard HTML fetch if `.patch` fetch fails.
    }
  }

  // Modular Site Extractor Registry 1-hop JSON / raw / patch twin upgrade (`npm`, `crates.io`, `huggingface.co`,
  // `gitlab.com`, `codeberg.org`, Discourse `/t/<slug>/<id>.json`, `lobste.rs`, Bluesky ATProto, Mastodon, `dev.to`, etc.).
  // Skip when `atsSpec` already queried the ATS API above (or on Greenhouse `?error=true` closed-job redirects)
  // so non-existent boards and closed redirects never double-fetch the JSON endpoint!
  const isGreenhouseErrorRedirect = /\.greenhouse\.io\//i.test(normalizedUrl) && /[?&]error=true(?:&|#|$)/i.test(normalizedUrl);
  const registryTwin =
    !atsSpec && !isGreenhouseErrorRedirect && !needsDomForTwin && renderMode !== 'always'
      ? resolveSiteExtractorTwin(normalizedUrl)
      : null;
  let reusedTwinFetchRes: Awaited<ReturnType<typeof executeHubFetch>> | null = null;
  if (registryTwin) {
    try {
      const twinRes = await executeHubFetch(
        target,
        JSON.stringify({
          maxSeconds: 30,
          options: {
            includeBody: true,
            respectRobots: true,
            maxBytes: registryTwin.maxBytes ?? MAX_WASM_INPUT_BYTES,
            maxInlineBodyBytes: MAX_WASM_INPUT_BYTES,
          },
          requests: [{ id: `twin-${registryTwin.id}`, url: registryTwin.fetchUrl, kind: registryTwin.kind, accept: registryTwin.accept }],
        }),
        site,
        `${source}:extractor:${registryTwin.id}`,
        retentionMode,
        true,
        collectionId,
      );
      let twinVia = twinRes.via;
      let twinItem: Record<string, unknown> | undefined;
      let twinBody = '';
      let activeFetchUrl = registryTwin.fetchUrl;
      let activeAccept = registryTwin.accept;
      let formatted: TwinFormattedDoc | null = null;
      const companionWarnings: string[] = [];

      if (twinRes.status === 200) {
        const twinParsed = JSON.parse(twinRes.bodyText) as { results?: Array<Record<string, unknown>> };
        twinItem = twinParsed.results?.[0];
        twinBody = typeof twinItem?.body === 'string' && twinItem.bodyEncoding !== 'base64' ? twinItem.body : '';
        if (
          twinItem &&
          twinItem.outcome === 'ok' &&
          twinBody.trim().length > 0 &&
          isTrustedTwinRedirectUrl(registryTwin.id, registryTwin.fetchUrl, twinItem, selfHost) &&
          !isTwinRedirectedToErrorPage(registryTwin.fetchUrl, twinItem)
        ) {
          formatted = registryTwin.formatTwin(twinBody, normalizedUrl, htmlFragToMd);
        } else if (registryTwin.fetchUrl === normalizedUrl && twinItem && twinItem.outcome !== 'ok') {
          reusedTwinFetchRes = twinRes;
        }
      }

      const govPrimaryOversized = twinItem?.bodyOmitted === true || twinItem?.truncated === true;
      if (
        registryTwin.id === 'us-cfr-govinfo' &&
        !registryTwin.fetchUrl.includes('/wssearch/getContentDetail') &&
        (!formatted || formatted.markdown.trim().length === 0 || govPrimaryOversized)
      ) {
        const govFallback = await fetchGovInfoSummaryFallback({
          normalizedUrl,
          primaryBodyOmitted: govPrimaryOversized,
          fetchBoundedTwin,
          htmlToMd: htmlFragToMd,
        });
        if (govFallback) {
          formatted = govFallback.formatted;
          twinItem = govFallback.twinItem;
          twinBody = govFallback.rawBody;
          activeFetchUrl = govFallback.fetchUrl;
          activeAccept = govFallback.accept;
          twinVia = govFallback.via;
          companionWarnings.push(...govFallback.warnings);
        } else if (govPrimaryOversized && formatted && formatted.markdown.trim().length > 0) {
          companionWarnings.push(
            'govinfo.gov full HTML document exceeded the 4 MiB WASM input budget; returned truncated primary HTML.',
          );
        }
      }

      if (formatted && twinItem && formatted.markdown.trim().length > 0) {
        if (registryTwin.id === 'zendesk-hc') {
          formatted = await enrichZendeskArticleAttachments({
            normalizedUrl,
            twinFetchUrl: activeFetchUrl,
            formatted,
            fetchBoundedTwin,
          });
        } else if (registryTwin.id === 'docker-hub' && !activeFetchUrl.includes('/tags')) {
          formatted = await enrichDockerHubTags({
            normalizedUrl,
            twinFetchUrl: activeFetchUrl,
            formatted,
            fetchBoundedTwin,
            htmlToMd: htmlFragToMd,
          });
        }
        setActiveSpanAttribute('edgefetch.adapter_id', registryTwin.id, activeTracer ?? undefined);
        const rawMd = redactPii ? redactPiiText(formatted.markdown) : formatted.markdown;
        const twinShapedFull = finalizeScrapedMarkdown(rawMd, {
          isPdf: false,
          includeImages,
          baseUrl: normalizedUrl,
        });
        const twinFocused = applyQueryFocus(twinShapedFull.markdown);
        const twinShaped =
          twinFocused.queryFiltered || maxChars !== undefined
            ? finalizeScrapedMarkdown(twinFocused.markdown, {
                isPdf: false,
                includeImages,
                maxChars,
                baseUrl: normalizedUrl,
              })
            : twinShapedFull;
        const twinArt = !isPrivateScrape ? (twinItem.artifact as { blobSha256?: string; contentSha256?: string } | undefined) : undefined;
        let twinMdArtifactId: string | undefined;
        if (twinShaped.truncated && env.ARTIFACTS && twinShapedFull.markdown && payload.ephemeral !== true) {
          const mdSha = await sha256HexString(twinShapedFull.markdown);
          await putDerivedMarkdownForScrape(mdSha, twinShapedFull.markdown);
          twinMdArtifactId = `md:${mdSha}`;
        }
        const twinJobPosting =
          registryTwin.kind === 'text' && /JobPosting/i.test(twinBody)
            ? extractJobPostingJsonLd(twinBody, normalizedUrl, twinShapedFull.markdown)
            : null;
        if (checkPromptInjection) {
          const piTwin = detectPromptInjection({
            markdown: [formatted.title ?? '', twinShapedFull.markdown, twinJobPosting ? JSON.stringify(twinJobPosting) : '']
              .filter(Boolean)
              .join('\n'),
          });
          if (piTwin.detected) {
            await deleteOptionsScrapeCacheIfNoCache({ force: true });
            return {
              status: 403,
              via: twinVia,
              body: {
                ok: false,
                success: false,
                ...(isPrivateScrape ? { visibility: 'private' as const } : {}),
                code: 'SCRAPE_PROMPT_INJECTION_DETECTED',
                error: 'SCRAPE_PROMPT_INJECTION_DETECTED',
                message: `Prompt injection guard triggered (${piTwin.triggers.join(', ')})`,
                triggers: piTwin.triggers,
                url: normalizedUrl,
              },
            };
          }
        }
        const twinLlmResolved =
          stringFormats.has('summary') || Boolean(jsonSchemaSpec)
            ? resolveLlmConfig({
                env: env as OptionalStorageBindings & LlmEnvBindings,
                requestLlm: payload.llm,
                selfHost,
              })
            : { ok: true as const, config: null };
        const twinLlmCfg = twinLlmResolved.ok ? twinLlmResolved.config : null;
        let twinSummaryOut: string | undefined;
        if (stringFormats.has('summary')) {
          const sumRes = await summarizeMarkdownWithOptionalLlm({
            markdown: twinShapedFull.markdown,
            title: formatted.title,
            llmConfig: twinLlmCfg,
            ...(activeTracer ? { tracer: activeTracer } : {}),
          });
          twinSummaryOut = sumRes.summary;
        }
        let twinJsonOut: Record<string, unknown> | undefined;
        let twinJsonExtractionMode: 'heuristic' | 'llm' | undefined;
        const twinWarnings: string[] = [...companionWarnings];
        if (jsonSchemaSpec) {
          const twinDoc: ExtractedDocument = {
            markdown: twinShapedFull.markdown,
            text: twinShapedFull.markdown,
            title: formatted.title,
            description: formatted.description,
            canonicalUrl: normalizedUrl,
            ...(Array.isArray(formatted.records) ? { records: formatted.records } : {}),
            links: formatted.links ?? [],
            images: [],
            branding: { title: formatted.title, description: formatted.description, canonicalUrl: normalizedUrl },
          };
          const heuristicDiag = extractStructuredJsonFromPageWithDiagnostics(twinBody, twinDoc, jsonSchemaSpec.schema);
          if (twinLlmCfg && (jsonSchemaSpec.prompt || jsonSchemaSpec.schema)) {
            const llmJ = await extractJsonWithOptionalLlm({
              markdown: twinShapedFull.markdown,
              title: formatted.title,
              url: normalizedUrl,
              prompt: jsonSchemaSpec.prompt,
              schema: jsonSchemaSpec.schema,
              llmConfig: twinLlmCfg,
              heuristicFallback: heuristicDiag.data,
              ...(activeTracer ? { tracer: activeTracer } : {}),
            });
            twinJsonOut = llmJ.data;
            twinJsonExtractionMode = llmJ.viaLlm ? 'llm' : 'heuristic';
            if (!llmJ.viaLlm && heuristicDiag.warnings.length > 0) {
              twinWarnings.push(...heuristicDiag.warnings);
            }
          } else {
            twinJsonOut = heuristicDiag.data;
            twinJsonExtractionMode = 'heuristic';
            if (heuristicDiag.warnings.length > 0) {
              twinWarnings.push(...heuristicDiag.warnings);
            }
          }
        }
        let twinProductOut = stringFormats.has('product')
          ? extractStructuredProduct({
              rawBody: twinBody,
              finalUrl: normalizedUrl,
              fallbackTitle: formatted.title,
              fallbackDescription: formatted.description,
            })
          : null;
        if (stringFormats.has('product') && formatted.records?.[0]) {
          twinProductOut = backfillProductFromRecord(twinProductOut, formatted.records[0], {
            finalUrl: normalizedUrl,
            fallbackTitle: formatted.title,
            fallbackDescription: formatted.description,
          });
        }
        const twinRawBase64Out = stringFormats.has('rawBase64') ? encodeBodyToRawBase64(twinItem) : undefined;
        const twinHeaders =
          twinItem.headers && typeof twinItem.headers === 'object' && !Array.isArray(twinItem.headers)
            ? (twinItem.headers as Record<string, string | undefined>)
            : undefined;
        const twinDetected = detectSiteFrameworkLinear({
          url: normalizedUrl,
          ...(twinHeaders ? { headers: twinHeaders } : {}),
        });
        const twinDetectedWithAdapter: Record<string, unknown> = {
          ...twinDetected,
          adapter: registryTwin.id,
        };
        const twinRecordsOut =
          formatted.records !== undefined
            ? redactPii
              ? redactPiiDeep(sanitizeRecordUrlsDeep(formatted.records))
              : sanitizeRecordUrlsDeep(formatted.records)
            : undefined;
        const twinPaginationOut =
          formatted.pagination !== undefined
            ? redactPii
              ? redactPiiDeep(formatted.pagination)
              : formatted.pagination
            : undefined;
        const twinSafeSummary =
          twinSummaryOut !== undefined ? (redactPii ? redactPiiText(twinSummaryOut) : twinSummaryOut) : undefined;
        const twinSafeProduct = twinProductOut
          ? sanitizeRecordUrlsDeep(redactPii ? redactPiiDeep(twinProductOut) : twinProductOut)
          : null;
        const twinSafeJson = twinJsonOut
          ? sanitizeRecordUrlsDeep(redactPii ? redactPiiDeep(twinJsonOut) : twinJsonOut)
          : undefined;
        const twinTitleOut = sanitizeScrapedMetadataField(
          formatted.title ? (redactPii ? redactPiiText(formatted.title) : formatted.title) : undefined,
          512,
        );
        const twinDescOut = sanitizeScrapedMetadataField(
          formatted.description ? (redactPii ? redactPiiText(formatted.description) : formatted.description) : undefined,
          2_000,
        );
        const twinAuthorOut = sanitizeScrapedMetadataField(
          formatted.author ? (redactPii ? redactPiiText(formatted.author) : formatted.author) : undefined,
          256,
        );
        // Adapter output goes through the same Go content-state classifier as normal scrapes, so an adapter that
        // formatted a soft-404 / login / closed-posting page is labelled accordingly instead of always `active`.
        const twinContentState = classifyContentState({
          status: typeof twinItem.status === 'number' ? twinItem.status : 200,
          url: normalizedUrl,
          finalUrl: typeof twinItem.finalUrl === 'string' && twinItem.finalUrl ? twinItem.finalUrl : normalizedUrl,
          title: formatted.title ?? '',
          markdown: twinShapedFull.markdown,
          rendered: false,
          ...(twinJobPosting?.validThrough ? { validThrough: twinJobPosting.validThrough } : {}),
          nowMs: Date.now(),
        });
        const twinSafeJobPosting = twinJobPosting
          ? redactPii
            ? redactPiiDeep(sanitizeRecordUrlsDeep(twinJobPosting))
            : sanitizeRecordUrlsDeep(twinJobPosting)
          : null;
        await deleteOptionsScrapeCacheIfNoCache();
        return {
          status: 200,
          via: twinVia,
          body: {
            ok: true,
            cached: false,
            ...(isPrivateScrape ? { visibility: 'private' as const } : {}),
            pipelineVersion: SCRAPE_PIPELINE_VERSION,
            url: normalizedUrl,
            finalUrl: normalizedUrl,
            status: twinItem.status ?? 200,
            via: twinVia,
            extractorId: registryTwin.id,
            detected: twinDetectedWithAdapter,
            rendered: false,
            contentState: twinContentState.state,
            ...(twinContentState.reason ? { contentStateReason: twinContentState.reason } : {}),
            ...(twinArt?.contentSha256 ? { contentSha256: twinArt.contentSha256 } : {}),
            ...(twinArt?.blobSha256 ? { artifactId: twinArt.blobSha256 } : {}),
            ...(twinMdArtifactId ? { markdownArtifactId: twinMdArtifactId } : {}),
            ...(twinSafeJobPosting ? { jobPosting: twinSafeJobPosting } : {}),
            ...(twinRecordsOut !== undefined ? { records: twinRecordsOut } : {}),
            ...(twinPaginationOut !== undefined ? { pagination: twinPaginationOut } : {}),
            ...(formatted.total !== undefined ? { total: formatted.total } : {}),
            ...(formatted.returned !== undefined ? { returned: formatted.returned } : {}),
            ...(formatted.nextCursor !== undefined ? { nextCursor: formatted.nextCursor } : {}),
            ...(stringFormats.has('markdown') ? { markdown: twinShaped.markdown } : {}),
            ...(stringFormats.has('text') ? { text: sanitizeScrapedTextOut(twinShaped.markdown) } : {}),
            ...(twinSafeSummary !== undefined ? { summary: twinSafeSummary } : {}),
            ...(twinSafeProduct ? { product: twinSafeProduct } : {}),
            ...(twinRawBase64Out ? { rawBase64: twinRawBase64Out } : {}),
            ...(twinSafeJson ? { json: twinSafeJson } : {}),
            ...(twinJsonExtractionMode ? { jsonExtractionMode: twinJsonExtractionMode } : {}),
            ...(twinWarnings.length > 0 ? { warnings: twinWarnings } : {}),
            ...(stringFormats.has('links') && formatted.links ? { links: formatted.links } : {}),
            ...(twinFocused.queryFiltered ? { queryFiltered: true, chunks: twinFocused.chunks } : {}),
            ...(twinShaped.truncated
              ? {
                  truncated: true,
                  totalChars: twinShaped.totalChars,
                  nextOffset: twinShaped.nextOffset ?? twinShaped.markdown.length,
                  remainingChars: twinShaped.remainingChars ?? Math.max(0, (twinShaped.totalChars ?? 0) - (twinShaped.nextOffset ?? twinShaped.markdown.length)),
                }
              : formatted.truncated !== undefined
                ? { truncated: formatted.truncated }
                : {}),
            metadata: {
              title: twinTitleOut,
              ...(twinDescOut ? { description: twinDescOut } : {}),
              ...(twinAuthorOut ? { author: twinAuthorOut } : {}),
              ...(sanitizeScrapedTimestampField(formatted.publishedTime, 128)
                ? { publishedTime: sanitizeScrapedTimestampField(formatted.publishedTime, 128) }
                : {}),
              alternateMarkdownUrl: activeFetchUrl,
              contentType: twinItem.contentType ?? activeAccept,
            },
          },
        };
      }
    } catch {
      // Fall through cleanly to standard HTML fetch when twin endpoint is absent or fails.
    }
  }

  // Single-hop companion `.md` fast-path when `/llms.txt` (from an earlier `map` or `scrape`) already proved a `.md` twin exists.
  const cachedCompanionUrl =
    discoverLlmsTxt && !needsLiveHtml && !hasCustomContentScoping && renderMode !== 'always' ? lookupCompanionMdUrl(normalizedUrl, now) : undefined;
  if (cachedCompanionUrl) {
    try {
      const compRes = await executeHubFetch(
        target,
        JSON.stringify({
          maxSeconds: 25,
          options: { includeBody: true, respectRobots: true },
          requests: [
            {
              id: 'companion-md-1',
              url: cachedCompanionUrl,
              kind: 'text',
              accept: 'text/markdown',
            },
          ],
        }),
        site,
        `${source}:companion-md`,
        retentionMode,
        true,
        collectionId,
      );
      if (compRes.status === 200) {
        const compParsed = JSON.parse(compRes.bodyText) as { results?: Array<Record<string, unknown>> };
        const compItem = compParsed.results?.[0];
        const compBody = typeof compItem?.body === 'string' && compItem.bodyEncoding !== 'base64' ? compItem.body : '';
        if (
          compItem?.outcome === 'ok' &&
          isTrustedTwinRedirectUrl(undefined, cachedCompanionUrl, compItem, selfHost) &&
          compBody.trim().length >= 32 &&
          !/^\s*<!doctype\s+html|^\s*<html/i.test(compBody)
        ) {
          const cleanCompRaw = redactPii ? redactPiiText(compBody) : compBody;
          const compShapedFull = finalizeScrapedMarkdown(cleanCompRaw, {
            isPdf: false,
            includeImages,
            baseUrl: normalizedUrl,
          });
          const compAssets = extractMarkdownLinksAndImages(compShapedFull.markdown, normalizedUrl, includeImages);
          const compFocused = applyQueryFocus(compShapedFull.markdown);
          const compShaped =
            compFocused.queryFiltered || maxChars !== undefined
              ? finalizeScrapedMarkdown(compFocused.markdown, {
                  isPdf: false,
                  includeImages,
                  maxChars,
                  baseUrl: normalizedUrl,
                })
              : compShapedFull;
          const compArt = !isPrivateScrape ? (compItem.artifact as { blobSha256?: string; contentSha256?: string } | undefined) : undefined;
          let compMdArtifactId: string | undefined;
          if (compShaped.truncated && env.ARTIFACTS && compShapedFull.markdown && payload.ephemeral !== true) {
            const mdSha = await sha256HexString(compShapedFull.markdown);
            await putDerivedMarkdownForScrape(mdSha, compShapedFull.markdown);
            compMdArtifactId = `md:${mdSha}`;
          }
          const compTitle = sanitizeScrapedMetadataField(compShapedFull.frontmatterTitle || compAssets.title, 512);
          const compDesc = sanitizeScrapedMetadataField(compShapedFull.frontmatterDescription || compAssets.description, 2_000);
          const compWords = countTextWords(compShapedFull.markdown);
          await deleteOptionsScrapeCacheIfNoCache();
          return {
            status: 200,
            via: compRes.via,
            body: {
              ok: true,
              cached: false,
              ...(isPrivateScrape ? { visibility: 'private' as const } : {}),
              pipelineVersion: SCRAPE_PIPELINE_VERSION,
              url: normalizedUrl,
              finalUrl: normalizedUrl,
              status: compItem.status ?? 200,
              via: compRes.via,
              ...(compArt?.contentSha256 ? { contentSha256: compArt.contentSha256 } : {}),
              ...(compArt?.blobSha256 ? { artifactId: compArt.blobSha256 } : {}),
              ...(compMdArtifactId ? { markdownArtifactId: compMdArtifactId } : {}),
              ...(stringFormats.has('markdown') ? { markdown: compShaped.markdown } : {}),
              ...(stringFormats.has('text') ? { text: sanitizeScrapedTextOut(compShaped.markdown) } : {}),
              ...(compFocused.queryFiltered ? { queryFiltered: true, chunks: compFocused.chunks } : {}),
              ...(compShaped.truncated
                ? {
                    truncated: true,
                    totalChars: compShaped.totalChars,
                    nextOffset: compShaped.nextOffset ?? compShaped.markdown.length,
                    remainingChars: compShaped.remainingChars ?? Math.max(0, (compShaped.totalChars ?? 0) - (compShaped.nextOffset ?? compShaped.markdown.length)),
                  }
                : {}),
              llms: {
                found: true,
                companionMdUrl: cachedCompanionUrl,
                usedCompanionMd: true,
              },
              metadata: {
                ...(compTitle ? { title: compTitle } : {}),
                ...(compDesc ? { description: compDesc } : {}),
                ...(compWords > 0 ? { wordCount: compWords } : {}),
                alternateMarkdownUrl: cachedCompanionUrl,
                contentType: compItem.contentType ?? 'text/markdown; charset=utf-8',
              },
            },
          };
        }
      }
    } catch {
      // Fall through to standard HTML scrape if direct companion .md fetch fails.
    }
  }

  const formatExternalSpaResponse = async (
    spa: SpaFallbackSuccess,
  ): Promise<{ status: number; via: string; body: Record<string, unknown> }> => {
    const safeSpaFinalUrl = resolveValidatedFinalUrl(spa.finalUrl, normalizedUrl, selfHost);
    const cleanRaw = redactPii ? redactPiiText(spa.markdown) : spa.markdown;
    const spaFull = finalizeScrapedMarkdown(cleanRaw, {
      isPdf: false,
      includeImages,
      baseUrl: safeSpaFinalUrl,
    });
    if (checkPromptInjection) {
      const piSpa = detectPromptInjection({
        markdown: [spa.title ?? '', spa.description ?? '', spaFull.markdown, spa.markdown].filter(Boolean).join('\n\n'),
      });
      if (piSpa.detected) {
        await deleteOptionsScrapeCacheIfNoCache({ force: true });
        return {
          status: 403,
          via: spa.via,
          body: {
            ok: false,
            ...(isPrivateScrape ? { visibility: 'private' as const } : {}),
            url: normalizedUrl,
            finalUrl: safeSpaFinalUrl,
            error: 'SCRAPE_PROMPT_INJECTION_DETECTED',
            message: `Prompt injection guard blocked page content (${piSpa.triggers.join(', ')})`,
            triggers: piSpa.triggers,
          },
        };
      }
    }
    const spaFocused = applyQueryFocus(spaFull.markdown);
    const spaShaped =
      spaFocused.queryFiltered || maxChars !== undefined
        ? finalizeScrapedMarkdown(spaFocused.markdown, { isPdf: false, includeImages, maxChars, baseUrl: safeSpaFinalUrl })
        : spaFull;
    const redir = analyzeUrlRedirect(normalizedUrl, safeSpaFinalUrl);
    return {
      status: 200,
      via: spa.via,
      body: {
        ok: true,
        cached: false,
        ...(isPrivateScrape ? { visibility: 'private' as const } : {}),
        pipelineVersion: SCRAPE_PIPELINE_VERSION,
        url: normalizedUrl,
        finalUrl: safeSpaFinalUrl,
        ...(redir.redirected
          ? {
              redirected: true,
              ...(redir.redirectNote ? { redirectNote: redir.redirectNote } : {}),
              ...(redir.filtersMayBeLost ? { filtersMayBeLost: true } : {}),
            }
          : {}),
        status: spa.status,
        via: spa.via,
        renderedVia: spa.provider,
        contentState: 'active' as const,
        ...(stringFormats.has('markdown') ? { markdown: spaShaped.markdown } : {}),
        ...(stringFormats.has('text') ? { text: sanitizeScrapedTextOut(spaShaped.markdown) } : {}),
        ...(stringFormats.has('links') && spa.links ? { links: spa.links } : {}),
        ...(spaFocused.queryFiltered ? { queryFiltered: true, chunks: spaFocused.chunks } : {}),
        ...(spaShaped.truncated
          ? {
              truncated: true,
              totalChars: spaShaped.totalChars,
              nextOffset: spaShaped.nextOffset ?? spaShaped.markdown.length,
              remainingChars: spaShaped.remainingChars ?? Math.max(0, (spaShaped.totalChars ?? 0) - (spaShaped.nextOffset ?? spaShaped.markdown.length)),
            }
          : {}),
        metadata: {
          ...(sanitizeScrapedMetadataField(spa.title, 512) ? { title: sanitizeScrapedMetadataField(spa.title, 512) } : {}),
          ...(sanitizeScrapedMetadataField(spa.description, 2_000)
            ? { description: sanitizeScrapedMetadataField(spa.description, 2_000) }
            : {}),
          wordCount: countTextWords(spaFull.markdown),
          contentType: 'text/html; charset=utf-8',
        },
      },
    };
  };

  const fetchRes =
    reusedTwinFetchRes ?? (await executeHubFetch(target, JSON.stringify(fetchCall), site, source, retentionMode, true, collectionId));
  if (fetchRes.status !== 200) {
    await deleteOptionsScrapeCacheIfNoCache();
    let errJson: Record<string, unknown> = { ok: false, error: 'scrape_failed' };
    try {
      errJson = { ok: false, ...(JSON.parse(fetchRes.bodyText) as Record<string, unknown>) };
    } catch {
      // ignore
    }
    if (
      isEligibleForExternalSpaFallback({
        mode: spaFallbackMode,
        status: fetchRes.status,
        errorCode: errJson.error,
        problem: typeof errJson.message === 'string' ? errJson.message : '',
      })
    ) {
      const spaOut = await tryExternalSpaFallback({
        url: normalizedUrl,
        env,
        mode: spaFallbackMode,
        robotsAlreadyVerified: false,
        onlyMainContent,
        waitForMs: waitForMsOpt,
        waitSelector: waitSelectorOpt,
        noCache: Boolean(payload.noCache),
        ...(selfHost ? { selfHost } : {}),
        ...(activeTracer ? { tracer: activeTracer } : {}),
      });
      if (spaOut) {
        return await formatExternalSpaResponse(spaOut);
      }
    }
    return {
      status: fetchRes.status,
      via: fetchRes.via,
      body: errJson,
      ...(fetchRes.retryAfter ? { retryAfter: fetchRes.retryAfter } : {}),
    };
  }

  let fetchResUsed = fetchRes;
  let parsedReply = JSON.parse(fetchResUsed.bodyText) as {
    results?: Array<Record<string, unknown>>;
  };
  let item: Record<string, unknown> = parsedReply.results?.[0] ?? {};

  // Polite 1-retry on transient origin HTTP `502`/`503`/`504` (NEVER on WAF challenges, robots/SSRF/DNS blocks, or Retry-After > 2s!)
  if (
    item.outcome !== 'ok' &&
    (item.status === 502 || item.status === 503 || item.status === 504) &&
    timeoutMsOpt > 1_000
  ) {
    const firstProb = String(item.problem ?? '');
    const firstRawBody = typeof item.body === 'string' && item.bodyEncoding !== 'base64' ? item.body : '';
    const firstWaf =
      (item.waf && typeof item.waf === 'object' ? (item.waf as WafClassification) : null) ??
      classifyWafAndChallenge({ status: Number(item.status), rawBody: firstRawBody });
    const isRobotsOrPolicyBlock =
      item.outcome === 'challenge' ||
      item.outcome === 'robots_disallowed' ||
      item.outcome === 'content_signal_disallowed' ||
      item.outcome === 'skip' ||
      Boolean(firstWaf) ||
      /robots\.txt|content-signal/i.test(firstProb) ||
      isDnsNotFoundError(item.outcome, firstProb) ||
      isSsrfBlockedError(item.outcome, firstProb);
    const itemHdrs =
      item.headers && typeof item.headers === 'object' && !Array.isArray(item.headers)
        ? (item.headers as Record<string, string | undefined>)
        : undefined;
    const rawRetryAfterHdr =
      typeof item.retryAfter === 'string' && item.retryAfter.trim()
        ? item.retryAfter
        : (itemHdrs?.['retry-after'] ?? itemHdrs?.['Retry-After'] ?? fetchResUsed.retryAfter);
    const retryDelayMs = !isRobotsOrPolicyBlock ? parsePolite5xxRetryDelayMs(rawRetryAfterHdr, now) : null;
    if (retryDelayMs !== null) {
      if (retryDelayMs > 0) {
        await sleepFn(retryDelayMs);
      }
      const retryRes = await executeHubFetch(
        target,
        JSON.stringify(fetchCall),
        site,
        `${source}:retry-5xx`,
        retentionMode,
        true,
        collectionId,
      );
      if (retryRes.status === 200) {
        fetchResUsed = retryRes;
        parsedReply = JSON.parse(fetchResUsed.bodyText) as { results?: Array<Record<string, unknown>> };
        item = parsedReply.results?.[0] ?? {};
      }
    }
  }
  let postFetchNow = params.now ?? Date.now();

  const isPdfResponse =
    typeof item.pdfEngine === 'string' ||
    (typeof item.contentType === 'string' && item.contentType.toLowerCase().includes('application/pdf')) ||
    isLikelyPdfUrl(resolveValidatedFinalUrl(item.finalUrl, normalizedUrl, selfHost));

  if (item.outcome !== 'ok') {
    await deleteOptionsScrapeCacheIfNoCache();
    if (ocrMode !== 'off' && hasPdfOcr && item.outcome === 'error' && isPdfResponse) {
      const rescued = await runPdfOcrFallback({
        url: normalizedUrl,
        ocrParam: 'auto',
        maxOcrPages: maxPagesCap,
        redactPii,
        headers: payload.headers,
        target,
        site,
        source,
        selfHost,
        isPrivate: isPrivateScrape,
        userId,
        ephemeral: Boolean(payload.ephemeral),
        env,
        executeHubFetch,
      });
      if (rescued.ok && rescued.markdown.trim().length > 0) {
        const fullRescuedMd = finalizeScrapedMarkdown(rescued.markdown, { isPdf: true, includeImages }).markdown;
        if (checkPromptInjection) {
          const piRescuedOcr = detectPromptInjection({ markdown: fullRescuedMd });
          if (piRescuedOcr.detected) {
            await deleteOptionsScrapeCacheIfNoCache({ force: true });
            return {
              status: 403,
              via: rescued.via,
              body: {
                ok: false,
                ...(isPrivateScrape ? { visibility: 'private' as const } : {}),
                url: normalizedUrl,
                finalUrl: rescued.finalUrl,
                error: 'SCRAPE_PROMPT_INJECTION_DETECTED',
                message: `Prompt injection guard blocked page content (${piRescuedOcr.triggers.join(', ')})`,
                triggers: piRescuedOcr.triggers,
              },
            };
          }
        }
        const shaped = finalizeScrapedMarkdown(fullRescuedMd, { isPdf: false, includeImages, maxChars });
        let rescuedMdArtifactId: string | undefined;
        if (env.ARTIFACTS && fullRescuedMd && payload.ephemeral !== true && (shaped.truncated || isPrivateScrape)) {
          const mdSha = await sha256HexString(fullRescuedMd);
          await putDerivedMarkdownForScrape(mdSha, fullRescuedMd);
          if (shaped.truncated) rescuedMdArtifactId = `md:${mdSha}`;
        }
        return {
          status: 200,
          via: rescued.via,
          body: {
            ok: true,
            cached: false,
            ...(isPrivateScrape ? { visibility: 'private' as const } : {}),
            pipelineVersion: SCRAPE_PIPELINE_VERSION,
            url: normalizedUrl,
            finalUrl: rescued.finalUrl,
            status: rescued.status,
            via: rescued.via,
            ...(rescued.contentSha256 ? { contentSha256: rescued.contentSha256 } : {}),
            ...(rescued.artifactId ? { artifactId: rescued.artifactId } : {}),
            ...(rescuedMdArtifactId ? { markdownArtifactId: rescuedMdArtifactId } : {}),
            ...(stringFormats.has('markdown') ? { markdown: shaped.markdown } : {}),
            ...(stringFormats.has('text') ? { text: sanitizeScrapedTextOut(shaped.markdown) } : {}),
            ...(shaped.truncated
              ? { truncated: true, totalChars: shaped.totalChars, nextOffset: shaped.nextOffset ?? shaped.markdown.length }
              : {}),
            pdfEngine: rescued.pdfEngine,
            ...(rescued.ocr ? { ocr: rescued.ocr } : {}),
            metadata: { contentType: 'application/pdf' },
          },
        };
      }
    }
    const problemText = String(item.problem ?? 'Origin scrape did not return HTTP 2xx');
    const rawErrBody = typeof item.body === 'string' && item.bodyEncoding !== 'base64' ? item.body : '';
    const isPaymentRequiredErr = item.status === 402 || item.outcome === 'payment_required';
    const errWaf = isPaymentRequiredErr
      ? null
      : ((item.waf && typeof item.waf === 'object' ? (item.waf as WafClassification) : null) ??
        classifyWafAndChallenge({ status: typeof item.status === 'number' ? item.status : 0, rawBody: rawErrBody }));

    // Ethical External Heavy-SPA Fallback (`Crawl4AI` / `Firecrawl`) on local browser/transport failure (NEVER on robots.txt, 403, 429, or challenges!)
    if (
      isEligibleForExternalSpaFallback({
        mode: spaFallbackMode,
        outcome: item.outcome,
        status: item.status,
        problem: problemText,
        waf: errWaf,
      })
    ) {
      const spaOut = await tryExternalSpaFallback({
        url: normalizedUrl,
        env,
        mode: spaFallbackMode,
        robotsAlreadyVerified: false,
        onlyMainContent,
        waitForMs: waitForMsOpt,
        waitSelector: waitSelectorOpt,
        noCache: Boolean(payload.noCache),
        ...(selfHost ? { selfHost } : {}),
        ...(activeTracer ? { tracer: activeTracer } : {}),
      });
      if (spaOut) {
        return await formatExternalSpaResponse(spaOut);
      }
    }

    // R8: Opt-in Internet Archive (`Wayback CDX`) link-rot fallback — strictly ONLY on 5xx / DNS-dead failures, NEVER on robots/403/429/challenges!
    if (
      waybackFallback &&
      isEligibleForWaybackFallback({
        outcome: item.outcome,
        status: item.status,
        problem: problemText,
        waf: errWaf,
      })
    ) {
      const wb = await tryFetchWaybackSnapshot({
        url: normalizedUrl,
        target,
        site,
        source,
        artifactRetention: retentionMode === 'off' ? 'off' : 'transient',
        executeHubFetch,
      });
      if (wb) {
        const wbDoc = extractHtmlDocument(wb.rawBody, {
          baseUrl: normalizedUrl,
          onlyMainContent,
          redactPii,
          includeImages,
          ...(includeTags.length > 0 ? { includeTags } : {}),
          ...(excludeTags.length > 0 ? { excludeTags } : {}),
        });
        const cleanWbMd = wbDoc.markdown.trim() || wb.rawBody.trim();
        const wbFull = finalizeScrapedMarkdown(redactPii ? redactPiiText(cleanWbMd) : cleanWbMd, {
          isPdf: false,
          includeImages,
          baseUrl: normalizedUrl,
        });
        if (checkPromptInjection) {
          const piWb = detectPromptInjection({
            markdown: [wbDoc.title ?? '', wbDoc.description ?? '', cleanWbMd].filter(Boolean).join('\n\n'),
            rawHtml: wb.rawBody,
          });
          if (piWb.detected) {
            await deleteOptionsScrapeCacheIfNoCache({ force: true });
            return {
              status: 403,
              via: wb.via,
              body: {
                ok: false,
                url: normalizedUrl,
                finalUrl: normalizedUrl,
                error: 'SCRAPE_PROMPT_INJECTION_DETECTED',
                message: `Prompt injection guard blocked page content (${piWb.triggers.join(', ')})`,
                triggers: piWb.triggers,
              },
            };
          }
        }
        const wbFocused = applyQueryFocus(wbFull.markdown);
        const wbShaped =
          wbFocused.queryFiltered || maxChars !== undefined
            ? finalizeScrapedMarkdown(wbFocused.markdown, { isPdf: false, includeImages, maxChars, baseUrl: normalizedUrl })
            : wbFull;
        return {
          status: 200,
          via: wb.via,
          body: {
            ok: true,
            cached: false,
            ...(isPrivateScrape ? { visibility: 'private' as const } : {}),
            pipelineVersion: SCRAPE_PIPELINE_VERSION,
            url: normalizedUrl,
            finalUrl: normalizedUrl,
            status: 200,
            via: wb.via,
            contentSource: 'wayback',
            waybackSnapshotUrl: wb.snapshotUrl,
            waybackTimestamp: wb.timestamp,
            ...(stringFormats.has('markdown') ? { markdown: wbShaped.markdown } : {}),
            ...(stringFormats.has('text') ? { text: sanitizeScrapedTextOut(wbDoc.text || wbShaped.markdown) } : {}),
            ...(stringFormats.has('links') ? { links: wbDoc.links } : {}),
            ...(wbFocused.queryFiltered ? { queryFiltered: true, chunks: wbFocused.chunks } : {}),
            metadata: {
              ...(wbDoc.title ? { title: wbDoc.title } : {}),
              ...(wbDoc.description ? { description: wbDoc.description } : {}),
              wordCount: countTextWords(wbFull.markdown),
              contentType: wb.contentType,
            },
          },
        };
      }
    }

    const scrubbedProblem = scrubResolverIpFromError(problemText);
    if (!isPaymentRequiredErr && !errWaf && isDnsNotFoundError(item.outcome, scrubbedProblem)) {
      setActiveSpanAttribute('edgefetch.outcome', 'dns_not_found', activeTracer ?? undefined);
      return {
        status: 502,
        via: fetchResUsed.via,
        body: {
          ok: false,
          url: normalizedUrl,
          outcome: 'dns_not_found',
          error: 'dns_not_found',
          retryable: false,
          status: 502,
          message: DNS_NOT_FOUND_MESSAGE,
          problem: scrubbedProblem || DNS_NOT_FOUND_MESSAGE,
        },
      };
    }
    if (!isPaymentRequiredErr && !errWaf && isSsrfBlockedError(item.outcome, scrubbedProblem)) {
      setActiveSpanAttribute('edgefetch.outcome', 'blocked', activeTracer ?? undefined);
      return {
        status: 403,
        via: fetchResUsed.via,
        body: {
          ok: false,
          url: normalizedUrl,
          outcome: 'blocked',
          error: 'blocked',
          retryable: false,
          status: item.status ?? 403,
          message: SSRF_BLOCKED_INFO.message,
          blocked: { ...SSRF_BLOCKED_INFO },
        },
      };
    }

    const effectiveOutcome = isPaymentRequiredErr
      ? 'payment_required'
      : errWaf
        ? 'challenge'
        : item.status === 404 && (item.outcome === 'gone' || item.outcome === 'error')
          ? 'not_found'
          : (item.outcome ?? 'error');
    if (errWaf?.vendor) {
      setActiveSpanAttribute('edgefetch.waf.vendor', errWaf.vendor, activeTracer ?? undefined);
    }
    setActiveSpanAttribute('edgefetch.outcome', String(effectiveOutcome), activeTracer ?? undefined);
    const effectiveProb = errWaf ? errWaf.summary : scrubbedProblem;
    const robotsHint =
      /robots\.txt disallowed/i.test(effectiveProb) && !/^robots_unreachable\b/i.test(effectiveProb)
        ? buildRobotsAlternativeHint(normalizedUrl)
        : undefined;
    const itemPaymentHeaders =
      item.paymentHeaders && typeof item.paymentHeaders === 'object' && !Array.isArray(item.paymentHeaders)
        ? (item.paymentHeaders as Record<string, string | undefined>)
        : undefined;
    const rawBlockedInfo = buildBlockedInfo(normalizedUrl, effectiveOutcome, effectiveProb, item.status, {
      headers: itemPaymentHeaders,
      rawBody: rawErrBody,
    });
    const itemHeadersObj =
      item.headers && typeof item.headers === 'object' && !Array.isArray(item.headers)
        ? (item.headers as Record<string, unknown>)
        : undefined;
    const itemHeaderRetryAfter =
      typeof itemHeadersObj?.['retry-after'] === 'string' && itemHeadersObj['retry-after'].trim()
        ? itemHeadersObj['retry-after'].trim()
        : typeof itemHeadersObj?.['Retry-After'] === 'string' && itemHeadersObj['Retry-After'].trim()
          ? itemHeadersObj['Retry-After'].trim()
          : undefined;
    const rawRetryAfter =
      typeof item.retryAfter === 'string' && item.retryAfter.trim()
        ? item.retryAfter.trim()
        : (itemHeaderRetryAfter ??
          (typeof fetchResUsed.retryAfter === 'string' && fetchResUsed.retryAfter.trim()
            ? fetchResUsed.retryAfter.trim()
            : undefined));
    const blockedInfo = refineBlockedInfo({
      url: normalizedUrl,
      outcome: effectiveOutcome,
      problem: effectiveProb,
      status: item.status,
      retryAfter: rawRetryAfter,
      baseBlocked: rawBlockedInfo,
    });
    const retryAfterOut =
      item.status === 429
        ? rawRetryAfter ??
          (typeof (blockedInfo as { retryAfterSeconds?: unknown } | undefined)?.retryAfterSeconds === 'number' &&
          Number.isFinite((blockedInfo as { retryAfterSeconds: number }).retryAfterSeconds)
            ? String(Math.max(0, Math.floor((blockedInfo as { retryAfterSeconds: number }).retryAfterSeconds)))
            : typeof (blockedInfo as { retryAfter?: unknown } | undefined)?.retryAfter === 'string' &&
                (blockedInfo as { retryAfter: string }).retryAfter.trim()
              ? (blockedInfo as { retryAfter: string }).retryAfter.trim()
              : undefined)
        : undefined;
    return {
      status: isPaymentRequiredErr
        ? 402
        : item.status === 429
          ? 429
          : effectiveOutcome === 'challenge'
            ? 403
            : 422,
      via: fetchResUsed.via,
      ...(retryAfterOut ? { retryAfter: retryAfterOut } : {}),
      body: {
        ok: false,
        ...(isPrivateScrape ? { visibility: 'private' as const } : {}),
        url: normalizedUrl,
        outcome: effectiveOutcome,
        status: item.status ?? (isPaymentRequiredErr ? 402 : 0),
        problem: effectiveProb,
        ...(errWaf ? { waf: errWaf } : {}),
        ...(robotsHint ? { hint: robotsHint } : {}),
        ...(blockedInfo ? { blocked: blockedInfo } : {}),
      },
    };
  }

  // R5: `304 Not Modified` conditional revalidation hit — refresh `pages.last_fetched_at` in META D1 (or options R2 cache) and serve verified R2 Markdown!
  if (item.status === 304 && revalCandidate && (env.META || optRevalCandidate)) {
    const touchReval = async (): Promise<void> => {
      const revalNow = params.now ?? Date.now();
      if (d1RevalCandidate && env.META) {
        await touchRevalidatedPage(env.META, normalizedUrl, revalNow);
      }
      if (optRevalCandidate && env.ARTIFACTS && payload.ephemeral !== true) {
        await writeOptionsScrapeCache({
          bucket: env.ARTIFACTS,
          isPrivate: isPrivateScrape,
          userId,
          optionsHash: scrapeOptionsHash,
          ...(env.META ? { metaDb: env.META } : {}),
          record: { ...optRevalCandidate, lastFetchedAt: revalNow },
        }).catch(() => undefined);
      } else if (d1RevalCandidate && parsedWikiArticle && env.ARTIFACTS && payload.ephemeral !== true) {
        await writeOptionsScrapeCache({
          bucket: env.ARTIFACTS,
          isPrivate: isPrivateScrape,
          userId,
          optionsHash: scrapeOptionsHash,
          ...(env.META ? { metaDb: env.META } : {}),
          record: {
            url: normalizedUrl,
            finalUrl: normalizedUrl,
            markdown: cleanMediaWikiMarkdownLinear(d1RevalCandidate.markdown),
            contentSha256: d1RevalCandidate.contentSha256,
            rawContentSha256: d1RevalCandidate.contentSha256,
            documentId: d1RevalCandidate.documentId,
            pipelineVersion: d1RevalCandidate.pipelineVersion,
            ...(d1RevalCandidate.title ? { title: d1RevalCandidate.title } : {}),
            ...(d1RevalCandidate.language ? { language: d1RevalCandidate.language } : {}),
            ...(d1RevalCandidate.etag ? { etag: d1RevalCandidate.etag } : {}),
            ...(d1RevalCandidate.lastModified ? { lastModified: d1RevalCandidate.lastModified } : {}),
            extractorId: 'mediawiki',
            detected: { generators: ['MediaWiki'], adapter: 'mediawiki' },
            status: 200,
            lastFetchedAt: revalNow,
          },
        }).catch(() => undefined);
      }
    };
    if (activeTracer) {
      await activeTracer.withSpan(
        'cache:r2-d1',
        {
          kind: 1,
          attributes: {
            'cache.hit': true,
            'cache.tier': isPrivateScrape ? 'private-r2' : 'r2-d1',
            'cache.revalidated': true,
            'http.response.status_code': 304,
            'url.full': sanitizeUrlForSpan(normalizedUrl),
            'edgefetch.pipeline_version': revalCandidate.pipelineVersion,
          },
        },
        touchReval,
      );
      activeTracer.setAttribute('edgefetch.cached', true);
      activeTracer.setAttribute('edgefetch.revalidated', true);
    } else {
      await touchReval();
    }
    const rawRevalMd = parsedWikiArticle ? cleanMediaWikiMarkdownLinear(revalCandidate.markdown) : revalCandidate.markdown;
    const fullReval = finalizeScrapedMarkdown(
      redactPii ? redactPiiText(rawRevalMd) : rawRevalMd,
      { isPdf: isLikelyPdfUrl(normalizedUrl), includeImages },
    ).markdown;
    const revalFocused = applyQueryFocus(fullReval);
    const revalShaped = finalizeScrapedMarkdown(revalFocused.markdown, { isPdf: false, includeImages, maxChars });
    const rawRevalTitle = revalCandidate.title || (isLikelyPdfUrl(normalizedUrl) ? extractPdfTitle(fullReval, normalizedUrl) : undefined);
    const revalTitle = sanitizeScrapedMetadataField(
      rawRevalTitle ? (redactPii ? redactPiiText(rawRevalTitle) : rawRevalTitle) : undefined,
      512,
    );
    const revalWordCount = fullReval ? countTextWords(fullReval) : 0;
    const revalFinalUrl = parsedWikiArticle
      ? resolveWikipediaCanonicalFinalUrl({
          requestedUrl: normalizedUrl,
          title: rawRevalTitle,
          markdown: fullReval,
        })
      : normalizedUrl;
    const revalFavicon = defaultFaviconForUrl(revalFinalUrl);
    const revalContentType = isLikelyPdfUrl(normalizedUrl) ? 'application/pdf' : 'text/html; charset=utf-8';
    return {
      status: 200,
      via: `${fetchResUsed.via}+cache:304`,
      body: {
        ok: true,
        cached: true,
        revalidated: true,
        ...(isPrivateScrape ? { visibility: 'private' as const } : {}),
        originStatus: 304,
        pipelineVersion: revalCandidate.pipelineVersion,
        documentId: revalCandidate.documentId,
        contentSha256: revalCandidate.contentSha256,
        url: normalizedUrl,
        finalUrl: revalFinalUrl,
        ...(revalTitle ? { title: revalTitle } : {}),
        status: 200,
        via: `${fetchResUsed.via}+cache:304`,
        ...(parsedWikiArticle
          ? {
              extractorId: 'mediawiki',
              detected: { generators: ['MediaWiki'], adapter: 'mediawiki' },
            }
          : {}),
        contentState: 'active',
        rendered: false,
        ...(revalWordCount > 0 ? { wordCount: revalWordCount } : {}),
        ...(revalFavicon ? { favicon: revalFavicon } : {}),
        contentType: revalContentType,
        ...(stringFormats.has('markdown') ? { markdown: revalShaped.markdown } : {}),
        ...(stringFormats.has('text') ? { text: sanitizeScrapedTextOut(revalShaped.markdown) } : {}),
        ...(revalFocused.queryFiltered ? { queryFiltered: true, chunks: revalFocused.chunks } : {}),
        ...(revalShaped.truncated
          ? {
              truncated: true,
              totalChars: revalShaped.totalChars,
              nextOffset: revalShaped.nextOffset ?? revalShaped.markdown.length,
              remainingChars: revalShaped.remainingChars ?? Math.max(0, (revalShaped.totalChars ?? 0) - (revalShaped.nextOffset ?? revalShaped.markdown.length)),
              markdownArtifactId: `md:${revalCandidate.contentSha256}`,
            }
          : {}),
        metadata: {
          ...(revalTitle ? { title: revalTitle } : {}),
          ...(revalWordCount > 0 ? { wordCount: revalWordCount } : {}),
          ...(revalCandidate.language ? { language: revalCandidate.language } : {}),
          ...(revalFavicon ? { favicon: revalFavicon } : {}),
          canonicalUrl: normalizedUrl,
          contentType: revalContentType,
          lastFetchedAt: now,
        },
      },
    };
  }

  let rawBodyStr = typeof item.body === 'string' && item.bodyEncoding !== 'base64' ? item.body : '';
  let finalUrl = resolveValidatedFinalUrl(item.finalUrl, normalizedUrl, selfHost);

  const buildOverBudgetEdgeResponse = async (
    rawForArtifact: string,
    curItem: Record<string, unknown>,
    viaUsed: string,
  ): Promise<{ status: number; via: string; body: Record<string, unknown> }> => {
    await deleteOptionsScrapeCacheIfNoCache();
    let overArt = !isPrivateScrape
      ? (curItem.artifact as { blobSha256?: string; contentSha256?: string } | undefined)
      : undefined;
    if (!overArt?.blobSha256 && env.ARTIFACTS && payload.ephemeral !== true && rawForArtifact.length > 0) {
      try {
        const rawBytes = SCRAPE_UTF8_ENCODER.encode(rawForArtifact);
        if (rawBytes.byteLength <= MAX_ARTIFACT_CONTENT_BYTES) {
          const effRet: ArtifactRetention = retentionMode === 'stored' ? 'stored' : 'transient';
          const stored = isPrivateScrape
            ? await writePrivateArtifactToR2({
                bucket: env.ARTIFACTS,
                userId,
                rawBytes,
                retention: effRet,
              })
            : await writeArtifactToR2({
                bucket: env.ARTIFACTS,
                rawBytes,
                retention: effRet,
              });
          overArt = {
            blobSha256: stored.blobSha256,
            contentSha256: stored.contentSha256,
          };
        }
      } catch {
        // Non-fatal if R2 artifact storage fails.
      }
    }
    const overFinalUrl = resolveValidatedFinalUrl(curItem.finalUrl, normalizedUrl, selfHost);
    const overTitle =
      typeof curItem.title === 'string' && curItem.title.trim()
        ? sanitizeScrapedMetadataField(redactPii ? redactPiiText(curItem.title) : curItem.title, 512)
        : undefined;
    const overCt = typeof curItem.contentType === 'string' ? curItem.contentType : undefined;
    const isOverOriginMarkdown = Boolean(
      curItem.contentSource === 'origin-markdown' ||
        (rawForArtifact &&
          !/^(?:<!doctype\b|<html\b)/i.test(rawForArtifact.trimStart().slice(0, 64)) &&
          typeof overCt === 'string' &&
          /^text\/(?:x-)?markdown\s*(?:;|$)/i.test(overCt.trim())),
    );
    if (isOverOriginMarkdown && rawForArtifact.length > 0) {
      const cleanOverRaw = redactPii ? redactPiiText(rawForArtifact) : rawForArtifact;
      const cutSanitized = finalizeScrapedMarkdown(cleanOverRaw, {
        isPdf: false,
        includeImages,
        maxChars,
        baseUrl: overFinalUrl,
        preserveOriginMarkdown: true,
      });
      return {
        status: 200,
        via: viaUsed,
        body: {
          ok: true,
          cached: false,
          ...(isPrivateScrape ? { visibility: 'private' as const } : {}),
          pipelineVersion: SCRAPE_PIPELINE_VERSION,
          url: normalizedUrl,
          finalUrl: overFinalUrl,
          status: typeof curItem.status === 'number' ? curItem.status : 200,
          via: viaUsed,
          contentSource: 'origin-markdown' as const,
          contentState: 'active' as const,
          rendered: false,
          truncated: true,
          // Sanitized-output coordinates (never raw-body chars, which no page read can serve); the raw body that
          // never reached the sanitizer is reported as `sourceChars`.
          totalChars: cutSanitized.totalChars ?? cutSanitized.markdown.length,
          nextOffset: cutSanitized.nextOffset ?? cutSanitized.markdown.length,
          remainingChars:
            cutSanitized.remainingChars ??
            Math.max(0, (cutSanitized.totalChars ?? cutSanitized.markdown.length) - (cutSanitized.nextOffset ?? cutSanitized.markdown.length)),
          sourceTruncated: true,
          sourceChars: rawForArtifact.length,
          ...(overArt?.contentSha256 ? { contentSha256: overArt.contentSha256 } : {}),
          ...(overArt?.blobSha256 ? { artifactId: overArt.blobSha256 } : {}),
          ...(stringFormats.has('markdown') ? { markdown: cutSanitized.markdown } : {}),
          ...(stringFormats.has('text') ? { text: sanitizeScrapedTextOut(cutSanitized.markdown) } : {}),
          metadata: {
            ...(overTitle ? { title: overTitle } : {}),
            ...(overCt ? { contentType: overCt } : {}),
          },
        },
      };
    }
    return {
      status: 200,
      via: viaUsed,
      body: {
        ok: true,
        cached: false,
        ...(isPrivateScrape ? { visibility: 'private' as const } : {}),
        pipelineVersion: SCRAPE_PIPELINE_VERSION,
        url: normalizedUrl,
        finalUrl: overFinalUrl,
        status: typeof curItem.status === 'number' ? curItem.status : 200,
        via: viaUsed,
        edgeBudgetExceeded: true,
        contentState: 'active' as const,
        rendered: false,
        ...(overArt?.contentSha256 ? { contentSha256: overArt.contentSha256 } : {}),
        ...(overArt?.blobSha256 ? { artifactId: overArt.blobSha256 } : {}),
        ...(stringFormats.has('markdown') ? { markdown: '' } : {}),
        ...(stringFormats.has('text') ? { text: '' } : {}),
        warnings: [
          'Document too large for edge processing (> 4 MiB WASM input budget); raw artifact stored without truncated sanitization.',
        ],
        metadata: {
          ...(overTitle ? { title: overTitle } : {}),
          ...(overCt ? { contentType: overCt } : {}),
        },
      },
    };
  };

  // Step 1 + Step 2: Over-budget (> 4 MiB) raw bodies NEVER enter Worker WASM or get truncated before sanitization.
  // Offload to a connected Go node (`target: 'agent'`) when available, or store the raw artifact and return a clear warning.
  const rawBodyOverBudget =
    !isPdfResponse &&
    !rawBase64Explicit &&
    rawBodyStr.length > 0 &&
    exactUtf8ByteLen(rawBodyStr) > MAX_WASM_INPUT_BYTES;
  // The Go node's over-budget extractor produces sanitized markdown only: it does not receive or apply
  // `includeTags` / `excludeTags`, and it returns no raw body for html/rawHtml/product/attributes/json.
  // `jsonFilter` is sent with the offload request and applied on the node to JSON record arrays.
  // Tag-scoped requests: node markdown is only acceptable when the node confirms it applied the include/exclude tags
  // (`contentScopingApplied`); an older node ignores the fields, which would leak excluded content. For other
  // edge-only formats, accept the node markdown but say which formats are unavailable.
  const nodeOffloadBlockedByScoping = includeTags.length > 0 || excludeTags.length > 0;
  /**
   * Whether a node-extracted item (primary agent path or offload) can be returned for this request: it must carry
   * non-empty in-budget markdown and, for tag-scoped requests, confirm the node applied the tags.
   */
  const nodeResultSatisfiesRequest = (nodeItem: Record<string, unknown> | undefined): boolean => {
    if (!nodeItem || nodeItem.outcome !== 'ok' || nodeItem.markdownOverBudget === true) return false;
    const md = typeof nodeItem.markdown === 'string' ? nodeItem.markdown : '';
    if (md.trim().length === 0 || exactUtf8ByteLen(md) > MAX_WASM_INPUT_BYTES) return false;
    return !nodeOffloadBlockedByScoping || nodeItem.contentScopingApplied === true;
  };
  const nodeOffloadMissingFormats = [
    ...(['html', 'rawHtml', 'product'] as const).filter((f) => stringFormats.has(f)),
    ...(attributesSpec ? ['attributes'] : []),
    ...(jsonSchemaSpec ? ['json'] : []),
  ];
  const nodeOffloadWarnings: string[] = [];
  if (
    rawBodyOverBudget &&
    item.extractedOnNode !== true &&
    !fetchResUsed.via.startsWith('agent') &&
    target !== 'container'
  ) {
    try {
      const offloadCall = {
        ...fetchCall,
        options: {
          ...fetchCall.options,
          maxInlineBodyBytes: MAX_WASM_INPUT_BYTES,
        },
        // The node applies `jsonFilter` itself (same Go record chunker as the edge's `chunkJsonRecords`).
        requests: jsonFilterStr ? fetchCall.requests.map((r) => ({ ...r, jsonFilter: jsonFilterStr })) : fetchCall.requests,
      };
      const nodeRes = await executeHubFetch(
        'agent',
        JSON.stringify(offloadCall),
        site,
        `${source}:offload-node`,
        retentionMode,
        false,
        collectionId,
      );
      if (nodeRes.status === 200) {
        const nodeParsed = JSON.parse(nodeRes.bodyText) as { results?: Array<Record<string, unknown>> };
        const nodeItem = nodeParsed.results?.[0];
        // Accept the node result only when it actually produced in-budget markdown. An empty or over-budget node
        // result (e.g. an unformattable >4 MiB sitemap, or origin markdown the node also could not fit) would
        // otherwise discard the raw body and return an empty 200; keeping the raw body lets the edge fallback below
        // cut+sanitize origin markdown or flag `edgeBudgetExceeded` with a warning.
        if (nodeItem && nodeResultSatisfiesRequest(nodeItem)) {
          rawBodyStr = '';
          fetchResUsed = nodeRes;
          item = nodeItem;
          postFetchNow = params.now ?? Date.now();
          finalUrl = resolveValidatedFinalUrl(item.finalUrl, normalizedUrl, selfHost);
          if (nodeOffloadMissingFormats.length > 0) {
            nodeOffloadWarnings.push(
              `Document over the 4 MiB edge budget was extracted on a Go node; ${nodeOffloadMissingFormats.join(', ')} ` +
                'require edge processing of the raw page and are unavailable for this response.',
            );
          }
        }
      }
    } catch {
      // Fall through to clean over-budget warning + stored R2 artifact below when no Go node is reachable.
    }
  }

  // Primary agent path: the first fetch itself went to a Go node, which extracted the over-budget page natively and
  // omitted the raw body. Apply the same acceptance rules as the offload path above: an empty node result (e.g. an
  // unformattable sitemap) or tag-scoped markdown the node did not confirm scoping for must not be returned as a
  // normal success; return the flagged over-budget response instead. (`markdownOverBudget` is handled just below.)
  if (item.extractedOnNode === true && item.markdownOverBudget !== true && !nodeResultSatisfiesRequest(item)) {
    const rawToStore = rawBodyStr;
    rawBodyStr = '';
    return buildOverBudgetEdgeResponse(rawToStore, { ...item, markdown: '', text: '' }, fetchResUsed.via);
  }
  if (item.extractedOnNode === true && nodeOffloadMissingFormats.length > 0 && nodeOffloadWarnings.length === 0) {
    nodeOffloadWarnings.push(
      `Document over the 4 MiB edge budget was extracted on a Go node; ${nodeOffloadMissingFormats.join(', ')} ` +
        'require edge processing of the raw page and are unavailable for this response.',
    );
  }

  const nodeMdStr = typeof item.markdown === 'string' ? item.markdown : '';
  if (
    item.markdownOverBudget === true ||
    (!isPdfResponse &&
      !rawBase64Explicit &&
      ((item.bodyOmitted === true && item.extractedOnNode !== true) ||
        (rawBodyStr.length > 0 && exactUtf8ByteLen(rawBodyStr) > MAX_WASM_INPUT_BYTES) ||
        (nodeMdStr.length > 0 && exactUtf8ByteLen(nodeMdStr) > MAX_WASM_INPUT_BYTES)))
  ) {
    const rawToStore = rawBodyStr;
    rawBodyStr = '';
    return buildOverBudgetEdgeResponse(rawToStore, item, fetchResUsed.via);
  }

  // Step 3: Per-isolate in-flight byte semaphore (`MAX_ISOLATE_IN_FLIGHT_BYTES` = 12 MiB) prevents concurrent
  // multi-MiB requests in the same 128 MiB Worker isolate from stacking in V8 + WASM linear memory.
  const estWorkBytes = Math.min(
    MAX_WASM_INPUT_BYTES,
    Math.max(65_536, rawBodyStr.length > 0 ? rawBodyStr.length : nodeMdStr.length),
  );
  const isolateLease = await acquireIsolateByteBudget(estWorkBytes, 200);
  if (!isolateLease) {
    await deleteOptionsScrapeCacheIfNoCache();
    // Same constraint as the over-budget offload: the node markdown ignores include/exclude tags and carries no raw
    // body, so requests that need those get the retryable 429 below instead of a silently different response.
    if (
      !nodeOffloadBlockedByScoping &&
      nodeOffloadMissingFormats.length === 0 &&
      // An in-budget body is not re-extracted by the node's over-budget path, so `jsonFilter` would not apply.
      !jsonFilterStr &&
      item.extractedOnNode !== true &&
      !fetchResUsed.via.startsWith('agent') &&
      target !== 'container' &&
      rawBodyStr.length >= 1_048_576
    ) {
      try {
        const busyOffloadRes = await executeHubFetch(
          'agent',
          JSON.stringify({
            ...fetchCall,
            options: { ...fetchCall.options, maxInlineBodyBytes: MAX_WASM_INPUT_BYTES },
          }),
          site,
          `${source}:busy-offload`,
          retentionMode,
          false,
          collectionId,
        );
        if (busyOffloadRes.status === 200) {
          const busyParsed = JSON.parse(busyOffloadRes.bodyText) as { results?: Array<Record<string, unknown>> };
          const busyItem = busyParsed.results?.[0];
          if (busyItem?.outcome === 'ok' && typeof busyItem.markdown === 'string' && busyItem.markdown.length < 524_288) {
            const smallLease = await acquireIsolateByteBudget(Math.max(65_536, busyItem.markdown.length), 100);
            if (smallLease) {
              rawBodyStr = '';
              fetchResUsed = busyOffloadRes;
              item = busyItem;
              finalUrl = resolveValidatedFinalUrl(item.finalUrl, normalizedUrl, selfHost);
              try {
                // The busy shortcut must apply the same guards as the main pipeline before returning node
                // content: WAF/challenge interstitials, the prompt-injection gate, and content-state classification.
                const busyStatus = typeof busyItem.status === 'number' ? busyItem.status : 200;
                const busyRawTitle = typeof busyItem.title === 'string' ? busyItem.title : '';
                const busyWaf =
                  (busyItem.waf && typeof busyItem.waf === 'object' ? (busyItem.waf as WafClassification) : null) ??
                  classifyWafAndChallenge({ status: busyStatus, rawBody: busyItem.markdown });
                if (busyWaf) {
                  return {
                    status: 403,
                    via: busyOffloadRes.via,
                    body: {
                      ok: false,
                      url: normalizedUrl,
                      finalUrl,
                      outcome: 'challenge',
                      status: busyStatus,
                      problem: busyWaf.summary,
                      waf: busyWaf,
                    },
                  };
                }
                if (checkPromptInjection) {
                  const piBusy = detectPromptInjection({ markdown: `${busyRawTitle}\n${busyItem.markdown}` });
                  if (piBusy.detected) {
                    await deleteOptionsScrapeCacheIfNoCache({ force: true });
                    return {
                      status: 403,
                      via: busyOffloadRes.via,
                      body: {
                        ok: false,
                        url: normalizedUrl,
                        finalUrl,
                        error: 'SCRAPE_PROMPT_INJECTION_DETECTED',
                        message: `Prompt injection guard blocked page content (${piBusy.triggers.join(', ')})`,
                        triggers: piBusy.triggers,
                      },
                    };
                  }
                }
                const busyContentState = classifyContentState({
                  status: busyStatus,
                  url: normalizedUrl,
                  finalUrl,
                  title: busyRawTitle,
                  markdown: busyItem.markdown,
                  rendered: false,
                  nowMs: Date.now(),
                });
                const safeNodeMd = finalizeScrapedMarkdown(
                  redactPii ? redactPiiText(busyItem.markdown) : busyItem.markdown,
                  { isPdf: false, includeImages, maxChars, baseUrl: finalUrl },
                );
                const nodeTitle = sanitizeScrapedMetadataField(
                  typeof busyItem.title === 'string' ? (redactPii ? redactPiiText(busyItem.title) : busyItem.title) : undefined,
                  512,
                );
                const nodeArt = !isPrivateScrape
                  ? (busyItem.artifact as { blobSha256?: string; contentSha256?: string } | undefined)
                  : undefined;
                return {
                  status: 200,
                  via: busyOffloadRes.via,
                  body: {
                    ok: true,
                    cached: false,
                    ...(isPrivateScrape ? { visibility: 'private' as const } : {}),
                    pipelineVersion: SCRAPE_PIPELINE_VERSION,
                    url: normalizedUrl,
                    finalUrl,
                    ...(nodeTitle ? { title: nodeTitle } : {}),
                    status: busyItem.status ?? 200,
                    via: busyOffloadRes.via,
                    extractedOnNode: true,
                    contentState: busyContentState.state,
                    ...(busyContentState.reason ? { contentStateReason: busyContentState.reason } : {}),
                    rendered: false,
                    ...(nodeArt?.contentSha256 ? { contentSha256: nodeArt.contentSha256 } : {}),
                    ...(nodeArt?.blobSha256 ? { artifactId: nodeArt.blobSha256 } : {}),
                    ...(stringFormats.has('markdown') ? { markdown: safeNodeMd.markdown } : {}),
                    ...(stringFormats.has('text') ? { text: sanitizeScrapedTextOut(safeNodeMd.markdown) } : {}),
                    metadata: {
                      ...(nodeTitle ? { title: nodeTitle } : {}),
                      ...(typeof busyItem.contentType === 'string' ? { contentType: busyItem.contentType } : {}),
                    },
                  },
                };
              } finally {
                smallLease.release();
              }
            }
          }
        }
      } catch {
        // Fall through to HTTP 429 rejection below.
      }
    }
    rawBodyStr = '';
    return {
      status: 429,
      via: 'hub',
      retryAfter: '1',
      body: {
        ok: false,
        url: normalizedUrl,
        outcome: 'rate_limited',
        error: 'isolate_memory_busy',
        retryable: true,
        status: 429,
        message: 'Worker isolate memory budget busy with concurrent multi-MiB documents; retry shortly.',
      },
    };
  }

  try {
  let renderedViaOut: 'browser' | 'browser-auto' | SpaFallbackProvider | undefined =
    renderMode === 'always'
      ? 'browser'
      : item.rendered === true && (!rawBodyStr || hasExecutableScriptTag(rawBodyStr) || hasExternalOrWidgetIframeLinear(rawBodyStr).found)
        ? 'browser-auto'
        : undefined;

  const rawTrimmedHead = rawBodyStr ? rawBodyStr.trimStart().slice(0, 64) : '';
  const looksLikeHtmlDocument = /^(?:<!doctype\b|<html\b)/i.test(rawTrimmedHead);
  const isOriginMarkdown = Boolean(
    item.contentSource === 'origin-markdown' ||
      (rawBodyStr &&
        !isPdfResponse &&
        !looksLikeHtmlDocument &&
        typeof item.contentType === 'string' &&
        /^text\/(?:x-)?markdown\s*(?:;|$)/i.test(item.contentType.trim())),
  );
  // Step 1: NEVER slice `rawBodyStr` prior to sanitization! If an origin-markdown document is between
  // `MAX_HTML_SCAN_CHARS` (2 MiB) and `MAX_WASM_INPUT_BYTES` (4 MiB), sanitize the ENTIRE document first
  // and apply `MAX_HTML_SCAN_CHARS` afterwards via fence-safe `finalizeScrapedMarkdown` slicing.
  // When the over-budget body was extracted on a Go node, `rawBodyStr` is cleared and the node's (unsanitized,
  // in-budget) Markdown is the origin-markdown body; it must still flow through the edge sanitizer below.
  const originMarkdownBody =
    rawBodyStr || (isOriginMarkdown && item.extractedOnNode === true && typeof item.markdown === 'string' ? item.markdown : '');
  const originMdCapTruncated = isOriginMarkdown && originMarkdownBody.length > MAX_HTML_SCAN_CHARS;

  // R2 & R3 (`R3-M3`): Guard against HTTP 200 WAF/CAPTCHA interstitials on BOTH HTML AND `origin-markdown` responses!
  const wafSourceStr = rawBodyStr || (typeof item.markdown === 'string' ? item.markdown : '');
  const okWafMatch =
    (item.waf && typeof item.waf === 'object' ? (item.waf as WafClassification) : null) ??
    (!isPdfResponse && wafSourceStr
      ? classifyWafAndChallenge({ status: typeof item.status === 'number' ? item.status : 200, rawBody: wafSourceStr })
      : null);
  if (okWafMatch) {
    await deleteOptionsScrapeCacheIfNoCache();
    setActiveSpanAttribute('edgefetch.waf.vendor', okWafMatch.vendor, activeTracer ?? undefined);
    setActiveSpanAttribute('edgefetch.outcome', 'challenge', activeTracer ?? undefined);
    const blockedInfo = refineBlockedInfo({
      url: finalUrl,
      outcome: 'challenge',
      problem: okWafMatch.summary,
      status: item.status,
      baseBlocked: buildBlockedInfo(finalUrl, 'challenge', okWafMatch.summary, item.status),
    });
    return {
      status: 403,
      via: fetchResUsed.via,
      body: {
        ok: false,
        url: normalizedUrl,
        finalUrl,
        outcome: 'challenge',
        status: item.status ?? 200,
        problem: okWafMatch.summary,
        waf: okWafMatch,
        ...(blockedInfo ? { blocked: blockedInfo } : {}),
      },
    };
  }

  // P2: Workday `{"widget":"redirect","url":"/Workday","externalSpa":true}` stub rescue -> CXS API or browser follow.
  const wdStub = !isPdfResponse && rawBodyStr ? detectWorkdayRedirectStub(rawBodyStr, finalUrl) : null;
  if (wdStub) {
    const stubAts = canUseAtsAdapter ? resolveAtsPreFetchSpec(wdStub.redirectUrl) : null;
    if (stubAts) {
      try {
        const stubRes = await executeHubFetch(
          target,
          JSON.stringify({
            maxSeconds: 45,
            // Bodies over the WASM budget are omitted by the fetcher (the stub rescue then falls back) instead of
            // being pulled whole into the isolate.
            options: { includeBody: true, respectRobots: true, maxBytes: 16_777_216, maxInlineBodyBytes: MAX_WASM_INPUT_BYTES },
            requests: [
              {
                id: `ats-${stubAts.id}`,
                url: stubAts.fetchUrl,
                method: stubAts.method,
                ...(stubAts.requestBody ? { requestBody: stubAts.requestBody } : {}),
                ...(stubAts.contentType ? { contentType: stubAts.contentType } : {}),
                kind: stubAts.kind,
                accept: stubAts.accept,
              },
            ],
          }),
          site,
          `${source}:workday-stub:${stubAts.id}`,
          retentionMode,
          true,
          collectionId,
        );
        if (stubRes.status === 200) {
          const stubParsed = JSON.parse(stubRes.bodyText) as { results?: Array<Record<string, unknown>> };
          const stubItem = stubParsed.results?.[0];
          const stubBody = typeof stubItem?.body === 'string' && stubItem.bodyEncoding !== 'base64' ? stubItem.body : '';
          const stubFormatted =
            stubItem &&
            isTrustedTwinRedirectUrl(stubAts.id, stubAts.fetchUrl, stubItem, selfHost) &&
            (stubItem.outcome === 'ok' || (stubItem.truncated === true && stubItem.status === 200)) &&
            stubBody
              ? stubAts.format(stubBody, wdStub.redirectUrl, htmlFragToMd)
              : null;
          if (stubFormatted && stubFormatted.markdown.trim().length > 0 && !hasCustomContentScoping) {
            setActiveSpanAttribute('edgefetch.adapter_id', stubAts.id, activeTracer ?? undefined);
            const stubRedirect = analyzeUrlRedirect(normalizedUrl, wdStub.redirectUrl);
            const cleanStubMd = redactPii ? redactPiiText(stubFormatted.markdown) : stubFormatted.markdown;
            const stubShapedFull = finalizeScrapedMarkdown(cleanStubMd, { isPdf: false, includeImages, baseUrl: wdStub.redirectUrl });
            const stubShaped =
              maxChars !== undefined
                ? finalizeScrapedMarkdown(cleanStubMd, { isPdf: false, includeImages, maxChars, baseUrl: wdStub.redirectUrl })
                : stubShapedFull;
            const stubJobPostingOut = stubFormatted.jobPosting
              ? redactPii
                ? redactPiiDeep(sanitizeRecordUrlsDeep(stubFormatted.jobPosting))
                : sanitizeRecordUrlsDeep(stubFormatted.jobPosting)
              : undefined;
            const stubJobsOut = stubFormatted.jobs
              ? redactPii
                ? redactPiiDeep(sanitizeRecordUrlsDeep(stubFormatted.jobs))
                : sanitizeRecordUrlsDeep(stubFormatted.jobs)
              : undefined;
            const stubTitleOut = sanitizeScrapedMetadataField(
              stubFormatted.title ? (redactPii ? redactPiiText(stubFormatted.title) : stubFormatted.title) : undefined,
              512,
            );
            if (checkPromptInjection) {
              const piStub = detectPromptInjection({
                markdown: [
                  stubTitleOut ?? '',
                  stubShapedFull.markdown,
                  stubJobPostingOut ? JSON.stringify(stubJobPostingOut) : '',
                  stubJobsOut ? JSON.stringify(stubJobsOut) : '',
                ]
                  .filter(Boolean)
                  .join('\n\n'),
              });
              if (piStub.detected) {
                await deleteOptionsScrapeCacheIfNoCache({ force: true });
                return {
                  status: 403,
                  via: stubRes.via,
                  body: {
                    ok: false,
                    ...(isPrivateScrape ? { visibility: 'private' as const } : {}),
                    url: normalizedUrl,
                    finalUrl: wdStub.redirectUrl,
                    error: 'SCRAPE_PROMPT_INJECTION_DETECTED',
                    message: `Prompt injection guard blocked page content (${piStub.triggers.join(', ')})`,
                    triggers: piStub.triggers,
                  },
                };
              }
            }
            await deleteOptionsScrapeCacheIfNoCache();
            return {
              status: 200,
              via: stubRes.via,
              body: {
                ok: true,
                cached: false,
                ...(isPrivateScrape ? { visibility: 'private' as const } : {}),
                pipelineVersion: SCRAPE_PIPELINE_VERSION,
                url: normalizedUrl,
                finalUrl: wdStub.redirectUrl,
                ...(stubRedirect.redirected ? stubRedirect : {}),
                status: stubItem?.status ?? 200,
                via: stubRes.via,
                extractorId: stubAts.id,
                contentState: 'active' as const,
                ...(stubJobPostingOut ? { jobPosting: stubJobPostingOut } : {}),
                ...(stubJobsOut ? { jobs: stubJobsOut } : {}),
                ...(stubFormatted.total !== undefined ? { total: stubFormatted.total } : {}),
                ...(stubFormatted.returned !== undefined ? { returned: stubFormatted.returned } : {}),
                ...(stubFormatted.nextCursor !== undefined ? { nextCursor: stubFormatted.nextCursor } : {}),
                ...(stringFormats.has('markdown') ? { markdown: stubShaped.markdown } : {}),
                ...(stringFormats.has('text') ? { text: sanitizeScrapedTextOut(stubShaped.markdown) } : {}),
                ...(stringFormats.has('links') && stubFormatted.links ? { links: stubFormatted.links } : {}),
                ...(stubShaped.truncated
                  ? {
                      truncated: true,
                      totalChars: stubShaped.totalChars,
                      nextOffset: stubShaped.nextOffset ?? stubShaped.markdown.length,
                      remainingChars: stubShaped.remainingChars ?? Math.max(0, (stubShaped.totalChars ?? 0) - (stubShaped.nextOffset ?? stubShaped.markdown.length)),
                    }
                  : stubFormatted.truncated !== undefined
                    ? { truncated: stubFormatted.truncated }
                    : {}),
                metadata: {
                  title: stubTitleOut,
                  wordCount: countTextWords(stubShaped.markdown),
                  alternateMarkdownUrl: stubAts.fetchUrl,
                  contentType: 'application/json',
                },
              },
            };
          }
        }
      } catch {
        // Fall back to browser follow below if CXS stub resolution fails.
      }
    }
    if (effectiveRenderMode !== 'off' && target !== 'container') {
      try {
        const wdBrowserRes = await executeHubFetch(
          'agent',
          JSON.stringify({
            maxSeconds: 45,
            options: {
              includeBody: true,
              respectRobots: true,
              maxBytes: 16 * 1024 * 1024,
              maxInlineBodyBytes: MAX_WASM_INPUT_BYTES,
              timeoutMs: 40_000,
            },
            requests: [
              {
                id: 'wd-stub-render-1',
                url: wdStub.redirectUrl,
                kind: 'render',
                renderMode: 'always',
                ...(blockTrackersOpt !== undefined ? { blockTrackers: blockTrackersOpt } : {}),
                ...(acceptLanguageOpt ? { acceptLanguage: acceptLanguageOpt } : {}),
                ...(Object.keys(mergedHeaders).length > 0 ? { headers: mergedHeaders } : {}),
                formats: agentFormats,
                onlyMainContent,
                waitSelector: '[data-automation-id="jobTitle"], [data-automation-id="jobFoundText"]',
                waitForMs: 2_200,
              },
            ],
          }),
          site,
          `${source}:workday-stub-render`,
          retentionMode,
          true,
          collectionId,
        );
        if (wdBrowserRes.status === 200) {
          const wdBrowserParsed = JSON.parse(wdBrowserRes.bodyText) as { results?: Array<Record<string, unknown>> };
          const wdBrowserItem = wdBrowserParsed.results?.[0];
          const wdBrowserBody =
            typeof wdBrowserItem?.body === 'string' && wdBrowserItem.bodyEncoding !== 'base64' ? wdBrowserItem.body : '';
          if (wdBrowserItem?.outcome === 'ok' && wdBrowserBody) {
            fetchResUsed = wdBrowserRes;
            item = wdBrowserItem;
            postFetchNow = params.now ?? Date.now();
            rawBodyStr = wdBrowserBody;
            finalUrl = resolveValidatedFinalUrl(wdBrowserItem.finalUrl, wdStub.redirectUrl, selfHost);
            renderedViaOut = 'browser-auto';
          }
        }
      } catch {
        // Keep original payload if no browser agent is available.
      }
    }
  }

  const rawBodyOverWasmBudgetForRawBase64 =
    rawBase64Explicit && !isPdfResponse && rawBodyStr.length > 0 && exactUtf8ByteLen(rawBodyStr) > MAX_WASM_INPUT_BYTES;
  const rawBase64OnlyRequest =
    stringFormats.size === 1 && stringFormats.has('rawBase64') && !jsonSchemaSpec && !attributesSpec;
  const shouldSkipPdfEarlyReturn = isPdfResponse && pdfParserOpts.skipPdfParsing;
  if (shouldSkipPdfEarlyReturn || (rawBase64Explicit && rawBase64OnlyRequest && rawBodyOverWasmBudgetForRawBase64)) {
    if (!isPdfResponse && checkPromptInjection && rawBodyStr.length > 0) {
      const piRawCheck = detectPromptInjection({ markdown: '', rawHtml: rawBodyStr });
      if (piRawCheck.detected) {
        await deleteOptionsScrapeCacheIfNoCache({ force: true });
        return {
          status: 403,
          via: fetchResUsed.via,
          body: {
            ok: false,
            ...(isPrivateScrape ? { visibility: 'private' as const } : {}),
            url: normalizedUrl,
            finalUrl,
            error: 'SCRAPE_PROMPT_INJECTION_DETECTED',
            message: `Prompt injection guard blocked page content (${piRawCheck.triggers.join(', ')})`,
            triggers: piRawCheck.triggers,
          },
        };
      }
    }
    await deleteOptionsScrapeCacheIfNoCache();
    const rawB64 = encodeBodyToRawBase64(item);
    // `parsers: []` (and rawBase64-only >4 MiB responses) return early, so they need their own artifact reference and
    // omission warning: without them a body too large to return inline produced `ok: true` with neither `rawBase64`
    // nor any way to fetch the bytes.
    const skipArt = !isPrivateScrape
      ? (item.artifact as { blobSha256?: string; contentSha256?: string } | undefined)
      : undefined;
    const skipOmitted = rawB64 === undefined && (item.bodyBase64Omitted === true || item.bodyOmitted === true);
    return {
      status: 200,
      via: fetchResUsed.via,
      body: {
        ok: true,
        cached: false,
        ...(isPrivateScrape ? { visibility: 'private' as const } : {}),
        pipelineVersion: SCRAPE_PIPELINE_VERSION,
        url: normalizedUrl,
        finalUrl,
        status: item.status ?? 200,
        via: fetchResUsed.via,
        ...(rawB64 ? { rawBase64: rawB64 } : {}),
        ...(skipArt?.contentSha256 ? { contentSha256: skipArt.contentSha256 } : {}),
        ...(skipArt?.blobSha256 ? { artifactId: skipArt.blobSha256 } : {}),
        ...(skipOmitted
          ? {
              warnings: [
                'rawBase64 was requested but the body was too large to return inline (batch body budget); ' +
                  (skipArt?.blobSha256 ? 'fetch the stored artifact via artifactId instead.' : 'no stored artifact is available for this request.'),
              ],
            }
          : {}),
        metadata: {
          contentType: isPdfResponse ? 'application/pdf' : item.contentType,
        },
      },
    };
  }
  let precomputedRawBase64: string | undefined;
  if (rawBodyOverWasmBudgetForRawBase64) {
    if (checkPromptInjection && rawBodyStr.length > 0) {
      const piRawCheck = detectPromptInjection({ markdown: '', rawHtml: rawBodyStr });
      if (piRawCheck.detected) {
        await deleteOptionsScrapeCacheIfNoCache({ force: true });
        return {
          status: 403,
          via: fetchResUsed.via,
          body: {
            ok: false,
            ...(isPrivateScrape ? { visibility: 'private' as const } : {}),
            url: normalizedUrl,
            finalUrl,
            error: 'SCRAPE_PROMPT_INJECTION_DETECTED',
            message: `Prompt injection guard blocked page content (${piRawCheck.triggers.join(', ')})`,
            triggers: piRawCheck.triggers,
          },
        };
      }
    }
    precomputedRawBase64 = encodeBodyToRawBase64(item);
    rawBodyStr = '';
    nodeOffloadWarnings.push(
      'Document over the 4 MiB edge budget; edge WASM formats could not be processed and rawBase64 was returned directly.',
    );
  }

  if (!isOriginMarkdown && rawBodyStr && /^\s*(?:<!doctype\s+html|<html\b)/i.test(rawBodyStr)) {
    item.contentType = 'text/html; charset=utf-8';
  }
  const binaryScrapeProblem = rawBase64Explicit
    ? null
    : detectUnsupportedBinaryPayload({
        rawBody: rawBodyStr,
        contentType: item.contentType,
        url: finalUrl,
        bodyEncoding: item.bodyEncoding,
        isPdf: isPdfResponse,
      });
  if (binaryScrapeProblem) {
    await deleteOptionsScrapeCacheIfNoCache();
    return {
      status: 422,
      via: fetchResUsed.via,
      body: {
        ok: false,
        ...(isPrivateScrape ? { visibility: 'private' as const } : {}),
        url: normalizedUrl,
        finalUrl,
        outcome: 'skip',
        status: item.status ?? 200,
        problem: binaryScrapeProblem,
      },
    };
  }
  // Links / favicon produced on a Go node are untrusted input to the Hub: run them through the same https-only,
  // public-host URL sanitizer the edge applies to extracted URLs before they reach `links` / `favicon` / `json`.
  if (item.extractedOnNode === true || fetchResUsed.via.startsWith('agent')) {
    item = sanitizeNodeSuppliedUrls(item, finalUrl);
  }
  let isHtmlBody = Boolean(
    !isOriginMarkdown &&
      rawBodyStr &&
      !isPdfResponse &&
      ((typeof item.contentType === 'string' && item.contentType.toLowerCase().includes('html')) ||
        /^\s*<!doctype\s+html|^\s*<html|<(head|body|main|article)\b/i.test(rawBodyStr)),
  );
  let extracted: ExtractedDocument | undefined = isHtmlBody
    ? extractHtmlDocument(rawBodyStr, {
        baseUrl: finalUrl,
        onlyMainContent,
        redactPii,
        includeImages,
        ...(includeTags.length > 0 ? { includeTags } : {}),
        ...(excludeTags.length > 0 ? { excludeTags } : {}),
      })
    : item.extractedOnNode === true
      ? {
          markdown: typeof item.markdown === 'string' ? item.markdown : '',
          text: typeof item.text === 'string' ? item.text : typeof item.markdown === 'string' ? item.markdown : '',
          ...(typeof item.title === 'string' && item.title ? { title: item.title } : {}),
          ...(typeof item.description === 'string' && item.description ? { description: item.description } : {}),
          ...(typeof item.favicon === 'string' && item.favicon ? { favicon: item.favicon } : {}),
          ...(typeof item.extractorId === 'string' && item.extractorId ? { extractorId: item.extractorId } : {}),
          ...(Array.isArray(item.records) ? { records: item.records as Array<Record<string, unknown>> } : {}),
          links: Array.isArray(item.links) ? (item.links as string[]) : [],
          images: Array.isArray(item.images) ? (item.images as ScrapedImage[]) : [],
          branding:
            item.branding && typeof item.branding === 'object'
              ? (item.branding as ExtractedDocument['branding'])
              : { canonicalUrl: finalUrl },
        }
      : undefined;

  const readItemHeaders = (): Record<string, string | undefined> | undefined =>
    item.headers && typeof item.headers === 'object' && !Array.isArray(item.headers)
      ? (item.headers as Record<string, string | undefined>)
      : undefined;

  // Custom-Domain Commerce Enrichment (Shopify, WooCommerce, Squarespace, SFCC/Demandware, Magento 2):
  // when an HTML page matches platform structural markers, politely fetch bounded same-origin JSON/Store API
  // companions via `executeHubFetch` (respectRobots + MAX_WASM_INPUT_BYTES + strict redirect trust), failing open to HTML.
  let customShopifyDoc: TwinFormattedDoc | null = null;
  let customCommerceLiveTwin = false;
  let customCommerceId: string | null = null;
  let prelimHostLower = '';
  let prelimUrlObj: URL | null = null;
  try {
    prelimUrlObj = new URL(finalUrl);
    prelimHostLower = prelimUrlObj.hostname.toLowerCase();
  } catch {
    prelimUrlObj = null;
    prelimHostLower = '';
  }
  const ytWatchStaticMeta =
    isHtmlBody &&
    !isPdfResponse &&
    (prelimHostLower === 'youtube.com' || prelimHostLower === 'www.youtube.com' || prelimHostLower === 'm.youtube.com') &&
    prelimUrlObj?.pathname === '/watch' &&
    rawBodyStr.includes('"videoDetails"')
      ? extractYouTubeWatchMetadataFromHtml(rawBodyStr)
      : null;
  if (
    ytWatchStaticMeta &&
    ytWatchStaticMeta.markdown.trim() &&
    (!extracted || !extracted.extractorId) &&
    countTextWords(extracted?.markdown ?? '') < countTextWords(ytWatchStaticMeta.markdown)
  ) {
    extracted = {
      ...(extracted ?? { markdown: '', text: '', links: [], images: [], branding: { canonicalUrl: finalUrl } }),
      title: ytWatchStaticMeta.title,
      ...(ytWatchStaticMeta.author ? { author: ytWatchStaticMeta.author } : {}),
      ...(ytWatchStaticMeta.description ? { description: ytWatchStaticMeta.description } : {}),
      markdown: ytWatchStaticMeta.markdown,
      text: ytWatchStaticMeta.markdown,
    };
  }
  const fetchCommerceTwinBody = async (epUrl: string, tag: string, trustAdapterId?: string): Promise<string> => {
    const epRes = await executeHubFetch(
      target,
      JSON.stringify({
        maxSeconds: 25,
        options: {
          includeBody: true,
          respectRobots: true,
          maxBytes: MAX_WASM_INPUT_BYTES,
          maxInlineBodyBytes: MAX_WASM_INPUT_BYTES,
        },
        requests: [{ id: tag, url: epUrl, kind: 'json', accept: 'application/json' }],
      }),
      site,
      `${source}:${tag}`,
      retentionMode,
      true,
      collectionId,
    );
    if (epRes.status !== 200) return '';
    const epParsed = JSON.parse(epRes.bodyText) as { results?: Array<Record<string, unknown>> };
    const epItem = epParsed.results?.[0];
    if (!epItem || !isTrustedTwinRedirectUrl(trustAdapterId, epUrl, epItem, selfHost)) return '';
    return epItem.outcome === 'ok' && typeof epItem.body === 'string' && epItem.bodyEncoding !== 'base64'
      ? epItem.body
      : '';
  };

  if (
    !hasCustomContentScoping &&
    isHtmlBody &&
    !isPdfResponse &&
    prelimHostLower &&
    !prelimHostLower.endsWith('.myshopify.com') &&
    isShopifyHtmlOrHeaders(rawBodyStr, readItemHeaders())
  ) {
    const htmlCurrency = extractShopifyCurrencyFromHtml(rawBodyStr);
    const shopTwin = resolveCustomDomainShopifyProductTwinUrl(finalUrl);
    if (shopTwin) {
      try {
        const jsonBody = await fetchCommerceTwinBody(shopTwin.jsonUrl, 'shopify-product-json', undefined);
        if (jsonBody.trim()) {
          let needsJsEnrich = true;
          try {
            const parsedJ = JSON.parse(jsonBody) as {
              product?: { variants?: Array<Record<string, unknown>> };
              variants?: Array<Record<string, unknown>>;
            };
            const firstVar = (parsedJ.product?.variants ?? parsedJ.variants)?.[0];
            if (firstVar && typeof firstVar.available === 'boolean') {
              needsJsEnrich = false;
            }
          } catch {
            needsJsEnrich = false;
          }
          const jsBody = needsJsEnrich
            ? await fetchCommerceTwinBody(shopTwin.jsUrl, 'shopify-product-js', undefined).catch(() => '')
            : '';
          customShopifyDoc = enrichShopifyProductFromJson({
            rawJson: jsonBody,
            productUrl: finalUrl,
            htmlToMd: htmlFragToMd,
            currency: htmlCurrency,
            ...(jsBody.trim() ? { ajaxJsBody: jsBody } : {}),
          });
          if (customShopifyDoc) {
            customCommerceId = 'shopify';
            customCommerceLiveTwin = true;
          }
        } else {
          const jsBody = await fetchCommerceTwinBody(shopTwin.jsUrl, 'shopify-product-js', undefined).catch(() => '');
          if (jsBody.trim()) {
            customShopifyDoc = enrichShopifyProductFromJson({
              rawJson: jsBody,
              productUrl: finalUrl,
              htmlToMd: htmlFragToMd,
              currency: htmlCurrency,
              isAjaxJs: true,
            });
            if (customShopifyDoc) {
              customCommerceId = 'shopify';
              customCommerceLiveTwin = true;
            }
          }
        }
      } catch {
        // Gracefully keep standard HTML / JSON-LD extraction if .json / .js endpoints fail.
      }
    } else {
      const shopColTwin = resolveCustomDomainShopifyCollectionTwinUrl(finalUrl);
      if (shopColTwin) {
        try {
          const jsonBody = await fetchCommerceTwinBody(shopColTwin.jsonUrl, 'shopify-collection-json', undefined);
          if (jsonBody.trim()) {
            const formattedCol = formatShopifyProductsFeedTwin(jsonBody, finalUrl, {
              twinUrl: shopColTwin.jsonUrl,
              currency: htmlCurrency,
            });
            if (formattedCol && Array.isArray(formattedCol.records) && formattedCol.records.length > 0) {
              customShopifyDoc = formattedCol;
              customCommerceId = 'shopify';
              customCommerceLiveTwin = true;
            }
          }
        } catch {
          // Fail open to standard HTML extraction on 404/robots/empty.
        }
      }
    }
  } else if (
    !hasCustomContentScoping &&
    isHtmlBody &&
    !isPdfResponse &&
    prelimHostLower &&
    isWooCommerceHtmlOrHeaders(rawBodyStr, readItemHeaders())
  ) {
    const wooTwin = resolveCustomDomainWooCommerceProductTwinUrl(finalUrl);
    if (wooTwin) {
      try {
        const wcJsonBody = await fetchCommerceTwinBody(wooTwin.storeApiUrl, 'woocommerce-product-json', undefined);
        if (wcJsonBody.trim()) {
          customShopifyDoc = enrichWooCommerceProductFromStoreApi({
            rawJson: wcJsonBody,
            productUrl: finalUrl,
            slug: wooTwin.slug,
            htmlToMd: htmlFragToMd,
            ...(extracted?.markdown ? { fallbackBodyMd: extracted.markdown } : {}),
          });
          if (customShopifyDoc) {
            customCommerceId = 'woocommerce';
            customCommerceLiveTwin = true;
          }
        }
      } catch {
        // Gracefully keep standard HTML extraction if WooCommerce Store API is disabled or unreachable.
      }
    } else {
      const wooCatTwin = resolveCustomDomainWooCommerceCatalogTwinUrl(finalUrl);
      if (wooCatTwin) {
        try {
          const wcListBody = await fetchCommerceTwinBody(wooCatTwin.storeApiUrl, 'woocommerce-catalog-json', undefined);
          if (wcListBody.trim()) {
            const formattedList = formatWcStoreApiListTwin(wcListBody, finalUrl, wooCatTwin.storeApiUrl);
            if (formattedList && Array.isArray(formattedList.records) && formattedList.records.length > 0) {
              customShopifyDoc = formattedList;
              customCommerceId = 'woocommerce';
              customCommerceLiveTwin = true;
            }
          }
        } catch {
          // Fail open to HTML catalog fallback below.
        }
        if (!customShopifyDoc && prelimUrlObj) {
          const catHtmlRes = extractWooCommerceCatalogHtml(
            {
              url: prelimUrlObj,
              baseUrl: finalUrl,
              host: prelimHostLower,
              path: prelimUrlObj.pathname,
              parts: prelimUrlObj.pathname.split('/').filter(Boolean),
              rawHtml: rawBodyStr,
              currentMd: extracted?.markdown ?? '',
              htmlToMd: htmlFragToMd,
            },
            'woocommerce',
          );
          if (catHtmlRes && catHtmlRes.markdown.trim()) {
            customShopifyDoc = {
              title: catHtmlRes.title ?? '',
              ...(catHtmlRes.description ? { description: catHtmlRes.description } : {}),
              markdown: catHtmlRes.markdown,
              ...(catHtmlRes.links ? { links: catHtmlRes.links } : {}),
              ...(catHtmlRes.records ? { records: catHtmlRes.records } : {}),
            };
            customCommerceId = 'woocommerce';
          }
        }
      }
    }
  } else if (
    !hasCustomContentScoping &&
    isHtmlBody &&
    !isPdfResponse &&
    prelimHostLower &&
    isSquarespaceCommerceHtmlOrHeaders(rawBodyStr, readItemHeaders())
  ) {
    const sqTwinUrl = resolveSquarespaceCommerceTwinUrl(finalUrl);
    if (sqTwinUrl) {
      try {
        const sqJsonBody = await fetchCommerceTwinBody(sqTwinUrl, 'squarespace-json', undefined);
        if (sqJsonBody.trim()) {
          const sqDoc = formatSquarespaceCommerceJson(sqJsonBody, finalUrl);
          if (sqDoc && sqDoc.markdown.trim()) {
            customShopifyDoc = sqDoc;
            customCommerceId = 'squarespace-commerce';
            customCommerceLiveTwin = true;
          }
        }
      } catch {
        // Fail open cleanly to squarespace_html / SSR hydration.
      }
    }
  } else if (
    !hasCustomContentScoping &&
    isHtmlBody &&
    !isPdfResponse &&
    prelimHostLower &&
    isSfccDemandwareHtmlOrHeaders(rawBodyStr, readItemHeaders())
  ) {
    const sfccTwin = resolveSfccProductVariationTwinUrl(finalUrl, rawBodyStr);
    if (sfccTwin) {
      try {
        const sfccJsonBody = await fetchCommerceTwinBody(sfccTwin.variationUrl, 'sfcc-variation-json', undefined);
        if (sfccJsonBody.trim()) {
          const sfccDoc = formatSfccProductVariationJson(sfccJsonBody, finalUrl, rawBodyStr, extracted?.markdown ?? '');
          if (sfccDoc && sfccDoc.markdown.trim()) {
            customShopifyDoc = sfccDoc;
            customCommerceId = 'sfcc-demandware';
            customCommerceLiveTwin = true;
          }
        }
      } catch {
        // Fail open cleanly to sfcc_html geometry/JSON-LD extraction.
      }
    }
  } else if (
    !hasCustomContentScoping &&
    isHtmlBody &&
    !isPdfResponse &&
    prelimHostLower &&
    isMagento2HtmlOrHeaders(rawBodyStr, readItemHeaders())
  ) {
    const firstRec = extracted?.records?.[0] as Record<string, unknown> | undefined;
    const firstVars = Array.isArray(firstRec?.variants) ? (firstRec.variants as Array<Record<string, unknown>>) : [];
    const hasRichInlineSwatches =
      extracted?.extractorId === 'shopware-magento' &&
      (firstVars.length > 1 || (firstVars.length === 1 && typeof firstVars[0]?.price === 'number'));
    if (!hasRichInlineSwatches) {
      const magTwinUrl = resolveMagento2RenderInfoTwinUrl(finalUrl, rawBodyStr);
      if (magTwinUrl) {
        try {
          const magJsonBody = await fetchCommerceTwinBody(magTwinUrl, 'magento2-render-info', undefined);
          if (magJsonBody.trim()) {
            const magDoc = formatMagento2RenderInfoJson(magJsonBody, finalUrl, rawBodyStr);
            if (magDoc && magDoc.markdown.trim()) {
              customShopifyDoc = magDoc;
              customCommerceId = 'shopware-magento';
              customCommerceLiveTwin = true;
            }
          }
        } catch {
          // Fail open cleanly to shopware_magento_html.
        }
      }
    }
  }

  // Tier 1A: Universal Schema.org JSON-LD (`FAQPage`, `QAPage`, `DiscussionForumPosting`, `ItemList`, `Article`, `Event`, `SoftwareApplication`, `Dataset`)
  let universalSchemaDoc: UniversalSchemaOrgResult | null =
    !hasCustomContentScoping && isHtmlBody && !isPdfResponse && !customShopifyDoc
      ? extractUniversalSchemaOrg(rawBodyStr, finalUrl, htmlFragToMd)
      : null;
  let rawSchemaOrgPiStrings =
    checkPromptInjection && isHtmlBody && /ld\+json/i.test(rawBodyStr)
      ? inspectRawSchemaOrgJsonLdLinear(rawBodyStr)
      : '';
  const initialExtractedWords = countTextWords(extracted?.markdown ?? '');
  const hydratedFromUniversalSchema = Boolean(
    universalSchemaDoc?.markdown &&
      !extracted?.extractorId &&
      ((initialExtractedWords < 80 && countTextWords(universalSchemaDoc.markdown) >= Math.max(25, initialExtractedWords * 2)) ||
        (initialExtractedWords < 120 &&
          (universalSchemaDoc.schemaType === 'FAQPage' ||
            universalSchemaDoc.schemaType === 'QAPage' ||
            universalSchemaDoc.schemaType === 'DiscussionForumPosting' ||
            (universalSchemaDoc.records && universalSchemaDoc.records.length >= 2)))),
  );

  // Tier 1B: CMS Auto-Twins (`wordpress-rest` `/wp-json/wp/v2/(posts|pages)/<id>` & `gatsby-page-data` `/page-data/.../page-data.json`)
  // Politely upgrades thin CMS/SSG pages on the exact same HTTPS origin respecting `robots.txt`.
  let cmsTwinDoc: CmsAutoTwinResult | null = null;
  if (
    !hasCustomContentScoping &&
    isHtmlBody &&
    !isPdfResponse &&
    !customShopifyDoc &&
    !extracted?.extractorId &&
    !hydratedFromUniversalSchema &&
    effectiveRenderMode !== 'always' &&
    !needsDomForTwin &&
    initialExtractedWords < 120
  ) {
    cmsTwinDoc = await tryFetchCmsAutoTwin({
      rawHtml: rawBodyStr,
      finalUrl,
      currentWordCount: initialExtractedWords,
      selfHost,
      htmlToMd: htmlFragToMd,
      fetchSameOriginJson: async (epUrl, tag) => {
        const epRes = await executeHubFetch(
          target,
          JSON.stringify({
            maxSeconds: 25,
            options: { includeBody: true, respectRobots: true },
            requests: [{ id: tag, url: epUrl, kind: 'json', accept: 'application/json' }],
          }),
          site,
          `${source}:${tag}`,
          retentionMode,
          true,
          collectionId,
        );
        if (epRes.status !== 200) return '';
        const epParsed = JSON.parse(epRes.bodyText) as { results?: Array<Record<string, unknown>> };
        const epItem = epParsed.results?.[0];
        if (!epItem || !isTrustedTwinRedirectUrl(undefined, epUrl, epItem, selfHost)) return '';
        return epItem.outcome === 'ok' && typeof epItem.body === 'string' && epItem.bodyEncoding !== 'base64'
          ? epItem.body
          : '';
      },
    });
  }

  let cpscRecallDoc: Awaited<ReturnType<typeof enrichCpscRecallFromSaferProducts>> = null;
  if (
    !hasCustomContentScoping &&
    isHtmlBody &&
    !isPdfResponse &&
    !customShopifyDoc &&
    !cmsTwinDoc &&
    effectiveRenderMode !== 'always' &&
    !needsDomForTwin &&
    (extracted?.extractorId === 'cpsc-recalls' ||
      ((prelimHostLower === 'www.cpsc.gov' || prelimHostLower === 'cpsc.gov') && /^\/recalls\/\d{4}\//i.test(parsedUrl.pathname)))
  ) {
    cpscRecallDoc = await enrichCpscRecallFromSaferProducts({
      finalUrl,
      rawHtml: rawBodyStr,
      extractedMarkdown: extracted?.markdown,
      fetchBoundedTwin,
      htmlToMd: htmlFragToMd,
    });
  }

  // Tier 2 (`R6` v2): SSR Hydration State Recovery (`__NEXT_DATA__`, linear RSC `__next_f.push`, Nuxt 3 `devalue`, Remix, Apollo, Angular `ng-state`, Wix, Squarespace, Substack, Inertia)
  // Extracts both rich prose AND homogeneous `records[]` BEFORE paying headless Chromium latency!
  let ssrHydrated: HydratedFrameworkStateResult | null = null;
  if (!hasCustomContentScoping && isHtmlBody && !isPdfResponse && !customShopifyDoc && !cmsTwinDoc && !hydratedFromUniversalSchema) {
    if (extracted?.inertiaHydrated && extracted.markdown.trim()) {
      ssrHydrated = {
        ...(extracted.title ? { title: extracted.title } : {}),
        ...(extracted.description ? { description: extracted.description } : {}),
        markdown: extracted.markdown,
        framework: 'inertia',
      };
    } else if (initialExtractedWords < 80 || (!extracted?.records && initialExtractedWords < 120)) {
      const candidateHydration = recoverSsrHydrationContent(rawBodyStr, finalUrl, htmlFragToMd);
      if (
        candidateHydration &&
        ((initialExtractedWords < 80 && countTextWords(candidateHydration.markdown) > initialExtractedWords * 2) ||
          (candidateHydration.records && candidateHydration.records.length >= 3 && initialExtractedWords < 120))
      ) {
        ssrHydrated = candidateHydration;
      } else if (
        initialExtractedWords < 50 &&
        (rawBodyStr.includes('data-page="{&quot;component&quot;') || rawBodyStr.includes("data-page='{\"component\""))
      ) {
        const inertiaPage = extractInertiaPagePropsLinear(rawBodyStr);
        const inertiaDoc = inertiaPage ? formatInertiaPagePropsToMarkdown(inertiaPage, finalUrl, htmlFragToMd) : null;
        if (inertiaDoc && inertiaDoc.markdown.trim()) {
          ssrHydrated = {
            ...(inertiaDoc.title ? { title: inertiaDoc.title } : {}),
            ...(inertiaDoc.description ? { description: inertiaDoc.description } : {}),
            markdown: inertiaDoc.markdown,
            framework: 'inertia',
          };
        }
      }
    }
  }

  let safeCanonicalUrl: string | undefined;
  let crossOriginCanonical = false;
  if (extracted?.canonicalUrl) {
    const canonVal = validatePublicHttpsTargetUrl(extracted.canonicalUrl);
    if (canonVal.ok) {
      safeCanonicalUrl = canonVal.url.toString();
      try {
        const finalHostLower = new URL(finalUrl).hostname.toLowerCase();
        const finalHostNorm = finalHostLower.replace(/^www\./, '');
        const canonHostNorm = canonVal.url.hostname.toLowerCase().replace(/^www\./, '');
        if (canonHostNorm && finalHostNorm && canonHostNorm !== finalHostNorm) {
          crossOriginCanonical = true;
        } else if (isWikipediaHost(finalHostLower)) {
          // MediaWiki resolves internal `#REDIRECT [[Target]]` pages (e.g. `/wiki/HTTP2` -> `/wiki/HTTP/2`)
          // via HTTP 200 + `<link rel="canonical" href="https://<lang>.wikipedia.org/wiki/HTTP/2">`.
          const canonWiki = parseWikipediaArticleUrl(safeCanonicalUrl);
          if (canonWiki && canonWiki.host === finalHostLower) {
            finalUrl = canonWiki.canonicalUrl;
          }
        }
      } catch {
        // ignore
      }
    }
  }

  // P2b: Hydrate thin ATS / Workday SPA HTML shells directly from `<script type="application/ld+json">` `JobPosting`
  // when present (e.g. when Workday CXS `/wday/cxs/.../job/...` returned 403 on a locale/slug variant), avoiding a 12.5s headless Chromium spin!
  let hydratedFromJobPostingJsonLd = false;
  const shouldInspectJobPostingJsonLd =
    isHtmlBody &&
    /JobPosting/i.test(rawBodyStr) &&
    (checkPromptInjection || (!hasCustomContentScoping && !customShopifyDoc && !ssrHydrated && countTextWords(extracted?.markdown ?? '') < 50));
  const rawJobLdInspection = shouldInspectJobPostingJsonLd
    ? inspectRawJobPostingJsonLdLinear(rawBodyStr)
    : { descriptionHtml: '', rawDecodedStringsForPiCheck: '' };
  let rawJsonLdStringsForPiCheck = checkPromptInjection ? rawJobLdInspection.rawDecodedStringsForPiCheck : '';
  if (
    !hasCustomContentScoping &&
    isHtmlBody &&
    !customShopifyDoc &&
    !ssrHydrated &&
    countTextWords(extracted?.markdown ?? '') < 50 &&
    /JobPosting/i.test(rawBodyStr)
  ) {
    const preJp = extractJobPostingJsonLd(rawBodyStr, finalUrl, extracted?.markdown ?? '');
    if (preJp?.title) {
      const ldDescHtml = rawJobLdInspection.descriptionHtml;
      const ldBodyMd = ldDescHtml ? htmlFragToMd(ldDescHtml, finalUrl).markdown.trim() : '';
      if (extracted && countTextWords(ldBodyMd) >= 20) {
        const headerMd = formatJobPostingHeaderMarkdown(preJp);
        const fullLdMd = [`# ${preJp.title}`, ...(headerMd ? [headerMd] : []), ldBodyMd].filter(Boolean).join('\n\n');
        extracted = {
          ...extracted,
          title: extracted.title || preJp.title,
          markdown: fullLdMd,
          text: fullLdMd,
        };
        hydratedFromJobPostingJsonLd = true;
      }
    }
  }

  // P3: Automatic browser switch when a `<script>`-bearing or thin external/widget `<iframe>` (e.g. `#icims_content_iframe`) HTML page yields < 80 words.
  // Never waste headless Chromium on URLs already identifiable as closed ATS job postings (e.g. Greenhouse `?error=true` redirects or Workday shells missing JobPosting JSON-LD)!
  let autoBrowserUnavailable = false;
  const isDeadWorkdayJobShell =
    atsSpec?.id === 'workday-job' &&
    !hydratedFromJobPostingJsonLd &&
    countTextWords(extracted?.markdown ?? '') < 20 &&
    !/JobPosting/i.test(rawBodyStr);
  const preRenderClosedCheck = isHtmlBody
    ? classifyContentState({
        status: typeof item.status === 'number' ? item.status : 200,
        url: normalizedUrl,
        finalUrl,
        title: extracted?.title,
        markdown: extracted?.markdown ?? '',
        rawHtml: rawBodyStr,
        rendered: false,
        nowMs: now,
      })
    : null;
  const hasThinExternalIframe =
    isHtmlBody && !customShopifyDoc && countTextWords(extracted?.markdown ?? '') < 50 && hasExternalOrWidgetIframeLinear(rawBodyStr).found;
  if (
    isHtmlBody &&
    !customShopifyDoc &&
    !cmsTwinDoc &&
    !cpscRecallDoc &&
    !hydratedFromUniversalSchema &&
    !ssrHydrated &&
    !hydratedFromJobPostingJsonLd &&
    !ytWatchStaticMeta &&
    extracted?.extractorId !== 'nfpa' &&
    !isDeadWorkdayJobShell &&
    preRenderClosedCheck?.state !== 'closed_posting' &&
    effectiveRenderMode === 'auto' &&
    item.rendered !== true &&
    target !== 'container' &&
    (isThinScriptedPage(rawBodyStr, extracted?.markdown ?? '') || hasThinExternalIframe)
  ) {
    try {
      const autoBrowserRes = await executeHubFetch(
        'agent',
        JSON.stringify({
          maxSeconds: 45,
          options: {
            includeBody: true,
            respectRobots: true,
            maxBytes: 16 * 1024 * 1024,
            maxInlineBodyBytes: MAX_WASM_INPUT_BYTES,
            timeoutMs: 40_000,
          },
          requests: [
            {
              id: 'auto-render-1',
              url: finalUrl,
              kind: 'render',
              renderMode: 'always',
              ...(blockTrackersOpt !== undefined ? { blockTrackers: blockTrackersOpt } : {}),
              ...(acceptLanguageOpt ? { acceptLanguage: acceptLanguageOpt } : {}),
              ...(Object.keys(mergedHeaders).length > 0 ? { headers: mergedHeaders } : {}),
              formats: agentFormats,
              onlyMainContent,
              redactPii,
              waitForMs:
                typeof payload.waitForMs === 'number' && Number.isFinite(payload.waitForMs)
                  ? Math.min(15_000, Math.max(0, Math.floor(payload.waitForMs)))
                  : 1_800,
              ...(typeof payload.waitSelector === 'string' && payload.waitSelector.trim()
                ? { waitSelector: payload.waitSelector.trim().slice(0, 200) }
                : {}),
            },
          ],
        }),
        site,
        `${source}:browser-auto`,
        retentionMode,
        true,
        collectionId,
      );
      const autoBrowserFetchNow = params.now ?? Date.now();
      if (autoBrowserRes.status === 200) {
        const autoParsed = JSON.parse(autoBrowserRes.bodyText) as { results?: Array<Record<string, unknown>> };
        const autoItem = autoParsed.results?.[0];
        const autoHtml = typeof autoItem?.body === 'string' && autoItem.bodyEncoding !== 'base64' ? autoItem.body : '';
        if (autoItem?.outcome === 'ok' && autoHtml) {
          const autoFinalUrl = resolveValidatedFinalUrl(autoItem.finalUrl, finalUrl, selfHost);
          const autoExtracted = extractHtmlDocument(autoHtml, {
            baseUrl: autoFinalUrl,
            onlyMainContent,
            redactPii,
            includeImages,
            ...(includeTags.length > 0 ? { includeTags } : {}),
            ...(excludeTags.length > 0 ? { excludeTags } : {}),
          });
          const hasAutoCapturedJson = Array.isArray(autoItem.capturedJson) && autoItem.capturedJson.length > 0;
          if (countTextWords(autoExtracted.markdown) > countTextWords(extracted?.markdown ?? '') || hasAutoCapturedJson) {
            fetchResUsed = autoBrowserRes;
            item = sanitizeNodeSuppliedUrls({ ...autoItem, contentType: 'text/html; charset=utf-8' }, autoFinalUrl);
            postFetchNow = autoBrowserFetchNow;
            rawBodyStr = autoHtml;
            finalUrl = autoFinalUrl;
            isHtmlBody = true;
            extracted = autoExtracted;
            renderedViaOut = 'browser-auto';
            if (!hasCustomContentScoping && !universalSchemaDoc && /ld\+json/i.test(autoHtml)) {
              universalSchemaDoc = extractUniversalSchemaOrg(autoHtml, autoFinalUrl, htmlFragToMd);
            }
            if (checkPromptInjection && /ld\+json/i.test(autoHtml)) {
              const autoSchemaPi = inspectRawSchemaOrgJsonLdLinear(autoHtml);
              if (autoSchemaPi) {
                rawSchemaOrgPiStrings = [rawSchemaOrgPiStrings, autoSchemaPi].filter(Boolean).join('\n');
              }
            }
            if (checkPromptInjection && /JobPosting/i.test(autoHtml)) {
              const autoJobPi = inspectRawJobPostingJsonLdLinear(autoHtml).rawDecodedStringsForPiCheck;
              if (autoJobPi) {
                rawJsonLdStringsForPiCheck = [rawJsonLdStringsForPiCheck, autoJobPi].filter(Boolean).join('\n');
              }
            }
          }
        }
      } else if (
        autoBrowserRes.status === 503 ||
        autoBrowserRes.bodyText.includes('browser_worker_required') ||
        autoBrowserRes.bodyText.includes('fat_agent_required')
      ) {
        autoBrowserUnavailable = true;
      }
    } catch {
      // Gracefully keep static HTML extraction when no `browser-v1` agent is connected.
    }
  }

  // Tier 3 (Phase 2 v2.7.8): Distill same-origin `200 OK` `application/json` XHR/Fetch payloads captured during CDP rendering!
  const cdpJsonDistilled =
    !hasCustomContentScoping && Array.isArray(item.capturedJson) && item.capturedJson.length > 0
      ? distillCapturedJsonResponses(item.capturedJson, finalUrl)
      : null;

  let alternateMarkdownUrl: string | undefined;
  let alternateMarkdownBody: string | undefined;
  const itemLlmsMeta =
    item.llms && typeof item.llms === 'object'
      ? (item.llms as { usedCompanionMd?: unknown; companionMdUrl?: unknown })
      : undefined;
  const goCompanionMd =
    discoverLlmsTxt &&
    !needsLiveHtml &&
    !hasCustomContentScoping &&
    renderMode !== 'always' &&
    itemLlmsMeta?.usedCompanionMd === true &&
    typeof item.markdown === 'string' &&
    item.markdown.trim().length >= 32 &&
    !/^\s*<!doctype\s+html|^\s*<html/i.test(item.markdown)
      ? item.markdown.trim()
      : undefined;

  const ghBlobTarget =
    isHtmlBody && !goCompanionMd && !needsLiveHtml && !hasCustomContentScoping && renderMode !== 'always' ? parseGitHubBlobRawTarget(finalUrl) : null;
  if (goCompanionMd) {
    alternateMarkdownBody = redactPii ? redactPiiText(goCompanionMd) : goCompanionMd;
    if (typeof itemLlmsMeta?.companionMdUrl === 'string' && itemLlmsMeta.companionMdUrl) {
      alternateMarkdownUrl = itemLlmsMeta.companionMdUrl;
    } else if (extracted?.markdownAlternateUrl) {
      alternateMarkdownUrl = extracted.markdownAlternateUrl;
    }
  } else if (ghBlobTarget) {
    try {
      const ghRawRes = await executeHubFetch(
        target,
        JSON.stringify({
          maxSeconds: 30,
          options: {
            includeBody: true,
            respectRobots: true,
            maxBytes: MAX_WASM_INPUT_BYTES,
            maxInlineBodyBytes: MAX_WASM_INPUT_BYTES,
          },
          requests: [{ id: 'gh-raw-1', url: ghBlobTarget.rawUrl, kind: 'text', accept: 'text/plain' }],
        }),
        site,
        `${source}:github-raw`,
        retentionMode ?? (env.ARTIFACTS ? 'transient' : 'off'),
        true,
      );
      if (ghRawRes.status === 200) {
        const ghParsed = JSON.parse(ghRawRes.bodyText) as { results?: Array<Record<string, unknown>> };
        const ghItem = ghParsed.results?.[0];
        const ghBody = typeof ghItem?.body === 'string' && ghItem.bodyEncoding !== 'base64' ? ghItem.body : '';
        if (
          ghItem &&
          isTrustedTwinRedirectUrl(undefined, ghBlobTarget.rawUrl, ghItem, selfHost) &&
          ghItem.outcome === 'ok' &&
          ghBody.trim().length > 0 &&
          !/^\s*<!doctype\s+html|^\s*<html/i.test(ghBody)
        ) {
          alternateMarkdownUrl = ghBlobTarget.rawUrl;
          const cleanGhBody = redactPii ? redactPiiText(ghBody) : ghBody;
          alternateMarkdownBody = ghBlobTarget.isMarkdown
            ? cleanGhBody
            : `# ${ghBlobTarget.repoSlug}/${ghBlobTarget.filePath}\n\n${makeSafeCodeFence(cleanGhBody, ghBlobTarget.fenceLang)}`;
        }
      }
    } catch {
      // Fall back to HTML extraction if raw.githubusercontent.com fetch fails.
    }
  } else if (isHtmlBody && discoverLlmsTxt && extracted?.markdownAlternateUrl && !needsLiveHtml && !hasCustomContentScoping && renderMode !== 'always') {
    try {
      const altUrl = new URL(extracted.markdownAlternateUrl);
      const baseHost = new URL(finalUrl).hostname.toLowerCase();
      if (altUrl.protocol === 'https:' && altUrl.hostname.toLowerCase() === baseHost) {
        const altRes = await executeHubFetch(
          target,
          JSON.stringify({
            maxSeconds: 30,
            options: { includeBody: true, respectRobots: true, maxInlineBodyBytes: MAX_WASM_INPUT_BYTES },
            requests: [{ id: 'alt-md-1', url: altUrl.toString(), kind: 'text', accept: 'text/plain' }],
          }),
          site,
          `${source}:alt-md`,
          retentionMode ?? (env.ARTIFACTS ? 'transient' : 'off'),
          true,
        );
        if (altRes.status === 200) {
          const altParsed = JSON.parse(altRes.bodyText) as { results?: Array<Record<string, unknown>> };
          const altItem = altParsed.results?.[0];
          const altText = typeof altItem?.body === 'string' && altItem.bodyEncoding !== 'base64' ? altItem.body.trim() : '';
          if (
            altItem &&
            isTrustedTwinRedirectUrl(undefined, altUrl.toString(), altItem, selfHost) &&
            altItem.outcome === 'ok' &&
            altText.length >= 32 &&
            !/^\s*<!doctype\s+html|^\s*<html/i.test(altText)
          ) {
            alternateMarkdownUrl = altUrl.toString();
            alternateMarkdownBody = redactPii ? redactPiiText(altText) : altText;
          }
        }
      }
    } catch {
      // Fall back to extracted HTML Markdown if companion .md fetch fails.
    }
  }

  const vcardFormatted =
    !isOriginMarkdown &&
    !isHtmlBody &&
    !isPdfResponse &&
    !alternateMarkdownBody &&
    ((typeof item.contentType === 'string' && item.contentType.toLowerCase().includes('vcard')) ||
      /^BEGIN:VCARD\b/im.test(rawBodyStr.trim()))
      ? formatVcardToMarkdown(rawBodyStr)
      : null;
  const icsFormatted =
    !isOriginMarkdown && !isHtmlBody && !isPdfResponse && !alternateMarkdownBody && !vcardFormatted
      ? formatIcalendarToMarkdown(rawBodyStr)
      : null;
  const feedFormatted =
    !isOriginMarkdown && !isHtmlBody && !isPdfResponse && !alternateMarkdownBody && !vcardFormatted && !icsFormatted
      ? formatFeedXmlToMarkdown(rawBodyStr, finalUrl)
      : null;
  const jsonFormatted =
    !isOriginMarkdown && !isHtmlBody && !isPdfResponse && !alternateMarkdownBody && !vcardFormatted && !icsFormatted && !feedFormatted
      ? tryParseJsonPayloadForScrape(rawBodyStr, item.contentType, finalUrl)
      : null;
  const isNotebookOrOpenApiJson = Boolean(
    jsonFormatted?.structuredKind ||
      (jsonFormatted?.parsed &&
        typeof jsonFormatted.parsed === 'object' &&
        !Array.isArray(jsonFormatted.parsed) &&
        ('openapi' in (jsonFormatted.parsed as Record<string, unknown>) ||
          'swagger' in (jsonFormatted.parsed as Record<string, unknown>) ||
          'nbformat' in (jsonFormatted.parsed as Record<string, unknown>))),
  );
  const jsonRecordsFormatted =
    !isOriginMarkdown &&
    !isHtmlBody &&
    !isPdfResponse &&
    !alternateMarkdownBody &&
    !vcardFormatted &&
    !icsFormatted &&
    !feedFormatted &&
    !isNotebookOrOpenApiJson
      ? chunkJsonRecords({
          rawBody: rawBodyStr,
          contentType: item.contentType,
          url: finalUrl,
          ...(jsonFilterStr ? { jsonFilter: jsonFilterStr } : {}),
          htmlToMd: htmlFragToMd,
        })
      : null;
  const csvFormatted =
    !isOriginMarkdown && !isHtmlBody && !isPdfResponse && !alternateMarkdownBody && !vcardFormatted && !icsFormatted && !feedFormatted && !jsonFormatted
      ? formatDelimitedTableToMarkdown(rawBodyStr, item.contentType, finalUrl)
      : null;
  const patchFormatted =
    !isOriginMarkdown &&
    !isHtmlBody &&
    !isPdfResponse &&
    !alternateMarkdownBody &&
    !vcardFormatted &&
    !icsFormatted &&
    !feedFormatted &&
    !jsonFormatted &&
    !csvFormatted
      ? formatGitPatchToMarkdown(rawBodyStr, item.contentType, finalUrl)
      : null;
  const sourceCodeFormatted =
    !isOriginMarkdown &&
    !isHtmlBody &&
    !isPdfResponse &&
    !alternateMarkdownBody &&
    !vcardFormatted &&
    !icsFormatted &&
    !feedFormatted &&
    !jsonFormatted &&
    !csvFormatted &&
    !patchFormatted
      ? formatSourceCodeUrlToMarkdown(rawBodyStr, item.contentType, finalUrl)
      : null;

  const structuredTextFormatted =
    vcardFormatted ||
    icsFormatted ||
    feedFormatted ||
    jsonRecordsFormatted ||
    jsonFormatted ||
    csvFormatted ||
    patchFormatted ||
    sourceCodeFormatted;

  if (cmsTwinDoc && !alternateMarkdownUrl) {
    alternateMarkdownUrl = cmsTwinDoc.twinUrl;
  } else if (cpscRecallDoc && !alternateMarkdownUrl) {
    alternateMarkdownUrl = cpscRecallDoc.twinUrl;
  }

  // P4: Extract structured schema.org `JobPosting` JSON-LD on HTML pages and surface key facts (pay, workplace, location) at the top.
  const htmlJobPosting: StructuredJobPosting | null =
    !hasCustomContentScoping && isHtmlBody
      ? extractJobPostingJsonLd(rawBodyStr, finalUrl, extracted?.markdown ?? '')
      : null;

  let markdown = isOriginMarkdown
    ? originMarkdownBody
    : alternateMarkdownBody ||
      customShopifyDoc?.markdown ||
      cmsTwinDoc?.markdown ||
      cpscRecallDoc?.doc.markdown ||
      ssrHydrated?.markdown ||
      (hydratedFromUniversalSchema ? universalSchemaDoc?.markdown : undefined) ||
      structuredTextFormatted?.markdown ||
      (isHtmlBody ? extracted?.markdown : undefined) ||
      // Node-supplied Markdown for an HTML body comes from a legacy extractor that can leak script text and hidden
      // (display:none) content; when the hub's own HTML extraction is empty, never fall back to it for HTML bodies.
      (!isHtmlBody && typeof item.markdown === 'string' && item.markdown) ||
      extracted?.markdown ||
      (isHtmlBody ? '' : rawBodyStr);
  // A browser-rendered DOM whose content lives entirely in header/aside/footer (small app shells) yields no main
  // content. Rather than return nothing, re-extract that rendered DOM with the hub's own extractor without main-content
  // stripping (scripts and hidden subtrees are still removed). Static HTML keeps the meta-description fallback, since
  // its non-main content is usually just navigation.
  if (
    isHtmlBody &&
    !markdown.trim() &&
    (item.rendered === true || renderedViaOut !== undefined) &&
    onlyMainContent &&
    includeTags.length === 0 &&
    excludeTags.length === 0
  ) {
    const fullPage = extractHtmlDocument(rawBodyStr, { baseUrl: finalUrl, onlyMainContent: false, stripHiddenSubtrees: true, redactPii, includeImages });
    if (fullPage.markdown.trim()) markdown = fullPage.markdown;
  }
  if (cdpJsonDistilled?.markdown && countTextWords(markdown) < 80 && !alternateMarkdownBody && !customShopifyDoc) {
    markdown = [markdown.trim(), cdpJsonDistilled.markdown].filter(Boolean).join('\n\n');
  } else if (
    universalSchemaDoc?.headerMarkdown &&
    !hydratedFromUniversalSchema &&
    !htmlJobPosting &&
    isHtmlBody &&
    !alternateMarkdownBody &&
    !customShopifyDoc &&
    !cmsTwinDoc &&
    countTextWords(markdown) < 60
  ) {
    const topHeadingMatch = /^(#\s+[^\n]+)\n+([\s\S]*)$/.exec(markdown.trim());
    markdown = topHeadingMatch
      ? `${topHeadingMatch[1]}\n\n${universalSchemaDoc.headerMarkdown}\n\n${topHeadingMatch[2]}`
      : [universalSchemaDoc.title ? `# ${universalSchemaDoc.title}` : '', universalSchemaDoc.headerMarkdown, markdown.trim()]
          .filter(Boolean)
          .join('\n\n');
  }
  if (htmlJobPosting && isHtmlBody && !alternateMarkdownBody && !customShopifyDoc) {
    const jpHeader = formatJobPostingHeaderMarkdown(htmlJobPosting);
    if (jpHeader && !/\*\*Compensation\*\*:/.test(markdown.slice(0, 400))) {
      const topHeadingMatch = /^(#\s+[^\n]+)\n+([\s\S]*)$/.exec(markdown.trim());
      markdown = topHeadingMatch
        ? `${topHeadingMatch[1]}\n\n${jpHeader}\n\n${topHeadingMatch[2]}`
        : `# ${htmlJobPosting.title}\n\n${jpHeader}\n\n${markdown}`;
    }
  }
  let textOut = isOriginMarkdown
    ? originMarkdownBody
    : alternateMarkdownBody ||
      customShopifyDoc?.markdown ||
      cmsTwinDoc?.markdown ||
      cpscRecallDoc?.doc.markdown ||
      ssrHydrated?.markdown ||
      (hydratedFromUniversalSchema ? universalSchemaDoc?.markdown : undefined) ||
      (cdpJsonDistilled?.markdown && countTextWords(extracted?.text ?? '') < 80 ? markdown : undefined) ||
      feedFormatted?.markdown ||
      vcardFormatted?.markdown ||
      icsFormatted?.markdown ||
      jsonRecordsFormatted?.markdown ||
      (jsonFormatted || csvFormatted || patchFormatted || sourceCodeFormatted ? rawBodyStr : undefined) ||
      (isHtmlBody ? extracted?.text : undefined) ||
      (typeof item.text === 'string' && item.text) ||
      extracted?.text ||
      '';
  let viaOut = fetchResUsed.via;
  let pdfEngineOut = typeof item.pdfEngine === 'string' ? item.pdfEngine : undefined;
  let ocrReportOut: PdfOcrContainerReply['ocr'] | undefined;
  let contentSourceOut: 'origin-markdown' | 'meta-description' | 'ssr-hydration' | undefined = isOriginMarkdown
    ? 'origin-markdown'
    : ssrHydrated
      ? 'ssr-hydration'
      : undefined;

  // Automatic PDF OCR fallback when Poppler `pdftotext` returns empty / scanned-image output (<100 non-whitespace chars).
  if (ocrMode === 'auto' && hasPdfOcr && isPdfResponse && markdown.replace(/\s+/g, '').length < 100) {
    const autoOcr = await runPdfOcrFallback({
      url: finalUrl,
      ocrParam: 'auto',
      maxOcrPages: maxPagesCap,
      redactPii,
      headers: payload.headers,
      target,
      site,
      source,
      selfHost,
      isPrivate: isPrivateScrape,
      userId,
      ephemeral: Boolean(payload.ephemeral),
      env,
      executeHubFetch,
    });
    if (autoOcr.ok && autoOcr.markdown.replace(/\s+/g, '').length > markdown.replace(/\s+/g, '').length) {
      markdown = autoOcr.markdown;
      textOut = autoOcr.markdown;
      viaOut = autoOcr.via;
      pdfEngineOut = autoOcr.pdfEngine;
      ocrReportOut = autoOcr.ocr;
    }
  }

  const preSanitizeMarkdownChars = markdown.length;
  let preSanitizeRedactCut = false;
  // A `text` output cut to the sanitizer budget by a downstream WASM helper must surface as `truncated: true`.
  let textOutBudgetCut = false;
  if (redactPii) {
    const mdRedacted = redactPiiTextReportingCut(markdown);
    markdown = mdRedacted.text;
    preSanitizeRedactCut = mdRedacted.cut;
    const textRedacted = redactPiiTextReportingCut(textOut);
    textOut = textRedacted.text;
    textOutBudgetCut = textRedacted.cut;
  }
  let fullShaped = finalizeScrapedMarkdown(markdown, {
    isPdf: isPdfResponse,
    includeImages,
    maxChars: undefined,
    baseUrl: finalUrl,
    preserveOriginMarkdown: isOriginMarkdown,
  });
  if (isOriginMarkdown && fullShaped.frontmatterTitle && fullShaped.markdown && !/^#[ \t]+\S/m.test(fullShaped.markdown)) {
    fullShaped = {
      ...fullShaped,
      markdown: `# ${fullShaped.frontmatterTitle}\n\n${fullShaped.markdown}`,
    };
  }
  const boundedCleanMd = boundToSanitizerBudget(redactPii ? redactPiiText(fullShaped.markdown) : fullShaped.markdown);
  let rawCleanMarkdown = boundedCleanMd.text;
  if (boundedCleanMd.cut || preSanitizeRedactCut || fullShaped.truncated) {
    // Any cut so far (redaction input cut, sanitizer budget, post-redaction growth) is a truncation of the whole
    // document; totals are in sanitized-output chars, i.e. the stored Markdown artifact `read_artifact` pages over.
    fullShaped = {
      ...fullShaped,
      ...(boundedCleanMd.cut ? { markdown: rawCleanMarkdown } : {}),
      truncated: true,
      totalChars: rawCleanMarkdown.length,
      nextOffset: rawCleanMarkdown.length,
      remainingChars: 0,
      sourceTruncated: true,
      sourceChars: fullShaped.sourceChars ?? preSanitizeMarkdownChars,
    };
  }
  const mdAssets = !isHtmlBody && !isPdfResponse ? extractMarkdownLinksAndImages(rawCleanMarkdown, finalUrl, includeImages) : undefined;

  // P1: Short-term / general fallback — when extracted HTML Markdown has < 50 words and `<meta name="description">` / `og:description`
  // holds substantive text (>= 40 words and > 2x the extracted body), rescue `metadata.description` with `contentSource: "meta-description"`.
  const prelimDescription = extracted?.description || (typeof item.description === 'string' && item.description ? decodeHtmlEntities(item.description) : undefined);
  const prelimTitle = extracted?.title || (typeof item.title === 'string' && item.title ? decodeHtmlEntities(item.title) : undefined);
  const bodyWordsBeforeRescue = countTextWords(rawCleanMarkdown);
  const metaDescWords = prelimDescription ? countTextWords(prelimDescription) : 0;
  if (
    !hasCustomContentScoping &&
    isHtmlBody &&
    !isPdfResponse &&
    !customShopifyDoc &&
    !ssrHydrated &&
    bodyWordsBeforeRescue < 50 &&
    prelimDescription &&
    metaDescWords >= 18 &&
    metaDescWords > bodyWordsBeforeRescue * 2
  ) {
    const cleanDesc = redactPii ? redactPiiText(prelimDescription) : prelimDescription;
    const cleanTitle = prelimTitle ? (redactPii ? redactPiiText(prelimTitle) : prelimTitle) : '';
    const rescuedMd = [cleanTitle ? `# ${cleanTitle}` : '', cleanDesc].filter(Boolean).join('\n\n');
    fullShaped = finalizeScrapedMarkdown(rescuedMd, {
      isPdf: false,
      includeImages,
      maxChars: undefined,
      baseUrl: finalUrl,
    });
    rawCleanMarkdown = fullShaped.markdown;
    textOut = cleanDesc;
    contentSourceOut = 'meta-description';
  }

  // Ethical Heavy-SPA Fallback (`Crawl4AI` / `Firecrawl`) when a `200 OK` `<script>` or external-iframe SPA shell remained thin (`< 50` words)
  // even after SSR hydration + local browser attempt, provided there is NO WAF challenge, login wall, soft-404, or closed posting!
  const isThinIframeShellAfterLocal =
    isHtmlBody && !customShopifyDoc && countTextWords(rawCleanMarkdown) < 50 && hasExternalOrWidgetIframeLinear(rawBodyStr).found;
  if (
    isHtmlBody &&
    !isPdfResponse &&
    !customShopifyDoc &&
    !ssrHydrated &&
    !ytWatchStaticMeta &&
    extracted?.extractorId !== 'nfpa' &&
    effectiveRenderMode !== 'off' &&
    countTextWords(rawCleanMarkdown) < 50 &&
    (isThinScriptedPage(rawBodyStr, rawCleanMarkdown) || isThinIframeShellAfterLocal)
  ) {
    const preState = classifyContentState({
      status: typeof item.status === 'number' ? item.status : 200,
      title: prelimTitle,
      markdown: rawCleanMarkdown,
      rawHtml: rawBodyStr,
      rendered: Boolean(item.rendered === true || renderedViaOut !== undefined),
      nowMs: now,
    });
    if (
      isEligibleForExternalSpaFallback({
        mode: spaFallbackMode,
        outcome: 'ok',
        status: item.status ?? 200,
        waf: okWafMatch,
        contentState: preState.state === 'empty_shell' ? 'active' : preState.state,
        isThinSpa200: true,
      })
    ) {
      const spaOut = await tryExternalSpaFallback({
        url: finalUrl,
        env,
        mode: spaFallbackMode,
        robotsAlreadyVerified: true,
        onlyMainContent,
        waitForMs: waitForMsOpt,
        waitSelector: waitSelectorOpt,
        noCache: Boolean(payload.noCache),
        ...(selfHost ? { selfHost } : {}),
        ...(activeTracer ? { tracer: activeTracer } : {}),
      });
      if (spaOut && countTextWords(spaOut.markdown) > countTextWords(rawCleanMarkdown)) {
        const safeSpaFinalUrl = resolveValidatedFinalUrl(spaOut.finalUrl, finalUrl, selfHost);
        const cleanSpaMd = redactPii ? redactPiiText(spaOut.markdown) : spaOut.markdown;
        fullShaped = finalizeScrapedMarkdown(cleanSpaMd, {
          isPdf: false,
          includeImages,
          maxChars: undefined,
          baseUrl: safeSpaFinalUrl,
        });
        rawCleanMarkdown = fullShaped.markdown;
        textOut = rawCleanMarkdown;
        finalUrl = safeSpaFinalUrl;
        viaOut = spaOut.via;
        renderedViaOut = spaOut.provider;
        contentSourceOut = undefined;
      }
    }
  }

  // P5: When `query` is combined with a JSON record array, rank across the per-record chunks directly so fields never bleed across records!
  const focused =
    jsonRecordsFormatted && focusQuery
      ? (() => {
          const ranked = rankChunksInMemory(jsonRecordsFormatted.chunks, focusQuery, 5);
          if (ranked.length === 0) return { markdown: rawCleanMarkdown, chunks: [], queryFiltered: false };
          return {
            markdown: [...ranked]
              .sort((a, b) => a.ordinal - b.ordinal)
              .map((c) => c.text)
              .join('\n\n---\n\n'),
            chunks: ranked,
            queryFiltered: true,
          };
        })()
      : applyQueryFocus(rawCleanMarkdown);
  const effectiveOutMaxChars =
    maxChars ?? (originMdCapTruncated && rawCleanMarkdown.length > MAX_HTML_SCAN_CHARS ? MAX_HTML_SCAN_CHARS : undefined);
  const shaped: ReturnType<typeof finalizeScrapedMarkdown> = focused.queryFiltered
    ? finalizeScrapedMarkdown(focused.markdown, {
        isPdf: false,
        includeImages,
        maxChars: effectiveOutMaxChars,
        baseUrl: finalUrl,
        preserveOriginMarkdown: isOriginMarkdown,
      })
    : effectiveOutMaxChars !== undefined
      ? (() => {
          // Page the already-sanitized document directly (same fence-safe slicer `read_artifact` uses), so
          // `nextOffset` / `totalChars` are offsets into exactly the Markdown stored as the `md:` artifact.
          const page = sliceMarkdownWithOffsetAndMaxChars(rawCleanMarkdown, 0, effectiveOutMaxChars);
          if (page.truncated) {
            return {
              markdown: page.markdown,
              truncated: true,
              totalChars: page.totalChars,
              nextOffset: page.nextOffset ?? page.totalChars,
              remainingChars: page.remainingChars,
              ...(fullShaped.sourceTruncated ? { sourceTruncated: true, sourceChars: fullShaped.sourceChars } : {}),
            };
          }
          return { ...fullShaped, markdown: page.markdown };
        })()
      : fullShaped;
  markdown = shaped.markdown;
  if (stringFormats.has('text') && !isOriginMarkdown && !hydratedFromJobPostingJsonLd) {
    const boundedText = boundToSanitizerBudget(textOut);
    textOut = boundedText.text;
    textOutBudgetCut = textOutBudgetCut || boundedText.cut;
  }
  textOut = !stringFormats.has('text')
    ? markdown
    : sanitizeScrapedTextOut(isOriginMarkdown || hydratedFromJobPostingJsonLd ? markdown : textOut);

  let llmsPayload: unknown = item.llms;
  if (llmsPayload && typeof llmsPayload === 'object') {
    const rawLlmsObj = llmsPayload as Record<string, unknown>;
    if (rawLlmsObj.found === false) {
      recordOriginLlmsAbsent(parsedUrl.origin, now);
    } else {
      const allowedLlmsOrigins = new Set<string>([parsedUrl.origin.toLowerCase()]);
      try {
        const fu = new URL(finalUrl);
        if (fu.protocol === 'https:' && (!fu.port || fu.port === '443')) {
          allowedLlmsOrigins.add(fu.origin.toLowerCase());
        }
      } catch {
        // ignore invalid finalUrl
      }
      recordCompanionMdLinksFromLlmsPayload(llmsPayload, allowedLlmsOrigins, now);
      if (rawLlmsObj.usedCompanionMd === true && !goCompanionMd) {
        llmsPayload = {
          ...rawLlmsObj,
          usedCompanionMd: Boolean(
            alternateMarkdownBody &&
              typeof rawLlmsObj.companionMdUrl === 'string' &&
              alternateMarkdownUrl === rawLlmsObj.companionMdUrl,
          ),
        };
      }
    }
  }
  if (!llmsPayload && stringFormats.has('llmsTxt')) {
    try {
      const llmsOriginUrl = `${parsedUrl.origin}/llms.txt`;
      const llmsRes = await executeHubFetch(
        target,
        JSON.stringify({
          maxSeconds: 20,
          options: { includeBody: true, respectRobots: true, maxInlineBodyBytes: MAX_WASM_INPUT_BYTES },
          requests: [{ id: 'llms-1', url: llmsOriginUrl, kind: 'text', accept: 'text/plain' }],
        }),
        site,
        `${source}:llms`,
        retentionMode ?? (env.ARTIFACTS ? 'transient' : 'off'),
        true,
      );
      if (llmsRes.status === 200) {
        const llmsReply = JSON.parse(llmsRes.bodyText) as { results?: Array<Record<string, unknown>> };
        const llmsItem = llmsReply.results?.[0];
        const llmsFinalSameOrigin =
          typeof llmsItem?.finalUrl !== 'string' ||
          !llmsItem.finalUrl.trim() ||
          isSameHttpsOriginAs(llmsItem.finalUrl, parsedUrl.origin.toLowerCase());
        if (llmsItem?.outcome === 'ok' && typeof llmsItem.body === 'string' && llmsFinalSameOrigin) {
          const parsedLlms = parseLlmsTxt(llmsItem.body, llmsOriginUrl);
          if (parsedLlms) {
            llmsPayload = {
              found: true,
              llmsTxtUrl: llmsOriginUrl,
              ...(parsedLlms.title ? { siteTitle: parsedLlms.title } : {}),
              ...(parsedLlms.summary ? { summary: parsedLlms.summary } : {}),
              ...(parsedLlms.fullTxtUrl ? { fullTxtUrl: parsedLlms.fullTxtUrl } : {}),
              relatedLinks: parsedLlms.links.slice(0, 25),
            };
          } else {
            recordOriginLlmsAbsent(parsedUrl.origin, now);
          }
        } else {
          recordOriginLlmsAbsent(parsedUrl.origin, now);
        }
      }
    } catch {
      // Best-effort /llms.txt discovery
    }
  }

  const baseHtmlLinks = extracted?.links ?? (Array.isArray(item.links) ? item.links : []);
  const cmsOrHydratedLinks =
    isHtmlBody && (cmsTwinDoc || cpscRecallDoc || ssrHydrated || hydratedFromUniversalSchema) && stringFormats.has('links')
      ? [...extractMarkdownLinksAndImages(rawCleanMarkdown, finalUrl, false).links, ...(cpscRecallDoc?.doc.links ?? [])]
      : [];
  const resolvedLinks = isHtmlBody
    ? cmsOrHydratedLinks.length > 0
      ? [...new Set([...(baseHtmlLinks as string[]), ...cmsOrHydratedLinks])]
      : baseHtmlLinks
    : feedFormatted && feedFormatted.links.length > 0
      ? feedFormatted.links
      : Array.isArray(item.links) && item.links.length > 0
        ? item.links
        : (mdAssets?.links ?? extracted?.links ?? []);
  const resolvedImages = !includeImages
    ? []
    : isHtmlBody
      ? (extracted?.images ?? [])
      : Array.isArray(item.images) && item.images.length > 0
        ? (item.images as ScrapedImage[]).filter((img) => !isTinyOrAvatarImageUrl(img.url ?? '', img.alt ?? ''))
        : (mdAssets?.images ?? extracted?.images ?? []);

  const rawResolvedTitle =
    customShopifyDoc?.title ||
    cmsTwinDoc?.title ||
    cpscRecallDoc?.doc.title ||
    ssrHydrated?.title ||
    extracted?.title ||
    universalSchemaDoc?.title ||
    structuredTextFormatted?.title ||
    fullShaped.frontmatterTitle ||
    mdAssets?.title ||
    (typeof item.title === 'string' && item.title ? decodeHtmlEntities(item.title) : undefined) ||
    (typeof (llmsPayload as { matchedEntry?: { title?: string } } | undefined)?.matchedEntry?.title === 'string'
      ? decodeHtmlEntities((llmsPayload as { matchedEntry: { title: string } }).matchedEntry.title)
      : undefined) ||
    (isPdfResponse ? extractPdfTitle(rawCleanMarkdown, finalUrl) : undefined);
  const rawResolvedDescription =
    customShopifyDoc?.description ||
    cmsTwinDoc?.description ||
    cpscRecallDoc?.doc.description ||
    ssrHydrated?.description ||
    extracted?.description ||
    universalSchemaDoc?.description ||
    (structuredTextFormatted as { description?: string } | null)?.description ||
    fullShaped.frontmatterDescription ||
    mdAssets?.description ||
    (typeof item.description === 'string' && item.description ? decodeHtmlEntities(item.description) : undefined);
  const resolvedTitle = sanitizeScrapedMetadataField(
    rawResolvedTitle ? (redactPii ? redactPiiText(rawResolvedTitle) : rawResolvedTitle) : undefined,
    512,
  );
  const resolvedDescription = sanitizeScrapedMetadataField(
    rawResolvedDescription
      ? redactPii
        ? redactPiiText(rawResolvedDescription)
        : rawResolvedDescription
      : undefined,
    2_000,
  );

  // R4: Classify `contentState` ("active" | "closed_posting" | "soft_404" | "login_wall" | "empty_shell") with anti-false-positive vetoes!
  const contentStateCheck: { state: ContentState; reason?: string } = classifyContentState({
    status: typeof item.status === 'number' ? item.status : 200,
    url: normalizedUrl,
    finalUrl,
    title: resolvedTitle,
    markdown: rawCleanMarkdown,
    ...(isHtmlBody ? { rawHtml: rawBodyStr } : {}),
    rendered: Boolean(item.rendered === true || renderedViaOut !== undefined),
    ...(htmlJobPosting?.validThrough ? { validThrough: htmlJobPosting.validThrough } : {}),
    nowMs: now,
  });

  const nonEmptyUniversalRecords =
    (cmsTwinDoc?.records && cmsTwinDoc.records.length > 0 ? cmsTwinDoc.records : undefined) ??
    (ssrHydrated?.records && ssrHydrated.records.length > 0 ? ssrHydrated.records : undefined) ??
    (cdpJsonDistilled?.records && cdpJsonDistilled.records.length > 0 ? cdpJsonDistilled.records : undefined) ??
    (universalSchemaDoc?.records && universalSchemaDoc.records.length > 0 ? universalSchemaDoc.records : undefined);
  const universalStructuredOut =
    cmsTwinDoc?.structured ??
    ssrHydrated?.structured ??
    cdpJsonDistilled?.structured ??
    universalSchemaDoc?.structured;

  // Same precedence as the response's `records` output below: custom-domain Shopify / adapter records first, so
  // `product` and `json` schema fields such as `sku` can be filled from them.
  const recordsForJson = [customShopifyDoc?.records, extracted?.records, nonEmptyUniversalRecords].find(
    (r): r is NonNullable<typeof r> => Array.isArray(r) && r.length > 0,
  );
  const recordsFromLiveTwin =
    recordsForJson !== undefined &&
    ((customCommerceLiveTwin && recordsForJson === customShopifyDoc?.records) ||
      (Boolean(cmsTwinDoc?.records?.length) && recordsForJson === cmsTwinDoc?.records));

  let productOut: Record<string, unknown> | null = null;
  if (stringFormats.has('product')) {
    productOut = extractStructuredProduct({
      rawBody: rawBodyStr,
      finalUrl,
      fallbackTitle: resolvedTitle,
      fallbackDescription: resolvedDescription,
    });
    if (recordsForJson?.[0]) {
      productOut = backfillProductFromRecord(productOut, recordsForJson[0], {
        finalUrl,
        fallbackTitle: resolvedTitle,
        fallbackDescription: resolvedDescription,
        preferRecordAvailability: recordsFromLiveTwin,
      });
    }
  }

  const attributesOut =
    attributesSpec && isHtmlBody ? extractHtmlAttributesBySelectors(rawBodyStr, attributesSpec) : undefined;
  const docForJson: ExtractedDocument | undefined = jsonSchemaSpec
    ? {
        markdown: rawCleanMarkdown,
        text: textOut || rawCleanMarkdown,
        title: resolvedTitle,
        description: resolvedDescription,
        language: extracted?.language,
        canonicalUrl: extracted?.canonicalUrl ?? finalUrl,
        favicon: (typeof item.favicon === 'string' && item.favicon) || extracted?.favicon,
        ...(recordsForJson ? { records: recordsForJson } : {}),
        ...(recordsFromLiveTwin ? { preferRecordAvailability: true } : {}),
        links: resolvedLinks as string[],
        images: resolvedImages as ScrapedImage[],
        branding: extracted?.branding ?? {
          title: resolvedTitle,
          description: resolvedDescription,
          canonicalUrl: extracted?.canonicalUrl ?? finalUrl,
        },
      }
    : undefined;

  let structuredJsonOut: Record<string, unknown> | undefined;
  let remainingUnmatchedJsonFields: string[] = [];
  if (jsonSchemaSpec && docForJson) {
    const heuristicDiag = extractStructuredJsonFromPageWithDiagnostics(rawBodyStr, docForJson, jsonSchemaSpec.schema);
    structuredJsonOut = heuristicDiag.data;
    const pickedKeys = new Set<string>();
    if (jsonFormatted?.parsed && typeof jsonFormatted.parsed === 'object' && !Array.isArray(jsonFormatted.parsed)) {
      const srcObj = jsonFormatted.parsed as Record<string, unknown>;
      const props =
        jsonSchemaSpec.schema && typeof jsonSchemaSpec.schema.properties === 'object' && jsonSchemaSpec.schema.properties !== null
          ? Object.keys(jsonSchemaSpec.schema.properties as Record<string, unknown>)
          : Object.keys(srcObj);
      const directPicked: Record<string, unknown> = {};
      for (const k of props) {
        if (k in srcObj && srcObj[k] !== undefined) {
          directPicked[k] = srcObj[k];
          pickedKeys.add(k);
        }
      }
      structuredJsonOut = { ...structuredJsonOut, ...directPicked };
    }
    remainingUnmatchedJsonFields = heuristicDiag.unmatchedFields.filter((f) => !pickedKeys.has(f));
  }

  if (checkPromptInjection) {
    const serializedJobPosting = htmlJobPosting ? JSON.stringify(htmlJobPosting) : '';
    const serializedCommerceRecords = customShopifyDoc?.records ? JSON.stringify(customShopifyDoc.records) : '';
    const serializedExtractedRecords = extracted?.records ? JSON.stringify(extracted.records) : '';
    const serializedUniversalRecords = nonEmptyUniversalRecords ? JSON.stringify(nonEmptyUniversalRecords) : '';
    const serializedUniversalStructured = universalStructuredOut ? JSON.stringify(universalStructuredOut) : '';
    const serializedProduct = productOut ? JSON.stringify(productOut) : '';
    const serializedAttributes = attributesOut ? JSON.stringify(attributesOut) : '';
    const serializedHeuristicJson = structuredJsonOut ? JSON.stringify(structuredJsonOut) : '';
    const mdForInjectionCheck = [
      resolvedTitle,
      resolvedDescription,
      rawCleanMarkdown,
      rawJsonLdStringsForPiCheck,
      rawSchemaOrgPiStrings,
      cmsTwinDoc?.rawDecodedStringsForPiCheck,
      ssrHydrated?.rawDecodedStringsForPiCheck,
      cdpJsonDistilled?.rawDecodedStringsForPiCheck,
      serializedJobPosting,
      serializedCommerceRecords,
      serializedExtractedRecords,
      serializedUniversalRecords,
      serializedUniversalStructured,
      serializedProduct,
      serializedAttributes,
      serializedHeuristicJson,
    ]
      .filter(Boolean)
      .join('\n\n');
    const piCheck = detectPromptInjection({
      markdown: mdForInjectionCheck,
      ...(isHtmlBody || isOriginMarkdown ? { rawHtml: rawBodyStr } : {}),
    });
    if (piCheck.detected) {
      await deleteOptionsScrapeCacheIfNoCache({ force: true });
      return {
        status: 403,
        via: viaOut,
        body: {
          ok: false,
          url: normalizedUrl,
          finalUrl,
          error: 'SCRAPE_PROMPT_INJECTION_DETECTED',
          message: `Prompt injection guard blocked page content (${piCheck.triggers.join(', ')})`,
          triggers: piCheck.triggers,
        },
      };
    }
  }

  let pdfPagesArray: string[] | undefined;
  let fullMarkedPdfMarkdown: string | undefined;
  if (isPdfResponse && (pdfParserOpts.includePagesArray || pdfParserOpts.includePageMarkers)) {
    const rawPdfSource = typeof item.markdown === 'string' && item.markdown ? item.markdown : rawCleanMarkdown;
    const splitPdf = splitPdfPagesAndMarkers(rawPdfSource, pdfParserOpts.includePageMarkers);
    if (pdfParserOpts.includePagesArray) {
      pdfPagesArray = splitPdf.pages;
    }
    if (pdfParserOpts.includePageMarkers && splitPdf.markedMarkdown) {
      const markedFull = finalizeScrapedMarkdown(splitPdf.markedMarkdown, {
        isPdf: true,
        includeImages,
        baseUrl: finalUrl,
        allowPdfPageMarkers: true,
      });
      fullMarkedPdfMarkdown = markedFull.markdown;
      markdown = finalizeScrapedMarkdown(splitPdf.markedMarkdown, {
        isPdf: true,
        includeImages,
        maxChars,
        baseUrl: finalUrl,
        allowPdfPageMarkers: true,
      }).markdown;
    }
  }

  const llmResolved =
    stringFormats.has('summary') || Boolean(jsonSchemaSpec)
      ? resolveLlmConfig({
          env: env as OptionalStorageBindings & LlmEnvBindings,
          requestLlm: payload.llm,
          selfHost,
        })
      : { ok: true as const, config: null };
  const activeLlmConfig = llmResolved.ok ? llmResolved.config : null;

  let summaryOut: string | undefined;
  if (stringFormats.has('summary')) {
    const sumRes = await summarizeMarkdownWithOptionalLlm({
      markdown: rawCleanMarkdown.slice(0, 32_768),
      title: resolvedTitle,
      llmConfig: activeLlmConfig,
      ...(activeTracer ? { tracer: activeTracer } : {}),
    });
    summaryOut = sumRes.summary;
  }

  const wantRawBase64Out = rawBase64Explicit || (isPdfResponse && pdfParserOpts.skipPdfParsing);
  const rawBase64Out = precomputedRawBase64 ?? (wantRawBase64Out ? encodeBodyToRawBase64(item) : undefined);

  let jsonExtractionModeOut: 'heuristic' | 'llm' | undefined;
  const scrapeWarnings: string[] = [...(extracted?.warnings ?? []), ...nodeOffloadWarnings];
  if (wantRawBase64Out && rawBase64Out === undefined && (item.bodyBase64Omitted === true || item.bodyOmitted === true)) {
    scrapeWarnings.push(
      'rawBase64 was requested but the body was too large to return inline (batch body budget); fetch the stored artifact instead.',
    );
  }
  if (autoBrowserUnavailable && renderedViaOut === undefined && countTextWords(rawCleanMarkdown) < 50) {
    scrapeWarnings.push(
      'Page appears to require JavaScript rendering, but no connected worker advertises browser-v1. Enable allow_no_sandbox_browser in the Home Assistant add-on configuration or run a Docker worker with --security-opt seccomp=./deploy/seccomp/chromium-sandbox.json.',
    );
  }
  if (jsonSchemaSpec && docForJson) {
    if (activeLlmConfig && (jsonSchemaSpec.prompt || jsonSchemaSpec.schema)) {
      const llmExt = await extractJsonWithOptionalLlm({
        markdown: rawCleanMarkdown,
        title: resolvedTitle,
        url: finalUrl,
        prompt: jsonSchemaSpec.prompt,
        schema: jsonSchemaSpec.schema,
        heuristicFallback: structuredJsonOut ?? {},
        llmConfig: activeLlmConfig,
        ...(activeTracer ? { tracer: activeTracer } : {}),
      });
      structuredJsonOut = llmExt.data;
      jsonExtractionModeOut = llmExt.viaLlm ? 'llm' : 'heuristic';
      if (!llmExt.viaLlm && remainingUnmatchedJsonFields.length > 0) {
        scrapeWarnings.push(
          `Keyless heuristic schema extraction could not match [${remainingUnmatchedJsonFields.join(', ')}] from page structure; use the 'agent' tool (BYO-LLM) or configure an LLM provider for semantic JSON-Schema extraction.`,
        );
      }
    } else {
      jsonExtractionModeOut = 'heuristic';
      if (remainingUnmatchedJsonFields.length > 0) {
        scrapeWarnings.push(
          `Keyless heuristic schema extraction could not match [${remainingUnmatchedJsonFields.join(', ')}] from page structure; use the 'agent' tool (BYO-LLM) or configure an LLM provider for semantic JSON-Schema extraction.`,
        );
      }
    }
  }

  const writeNow = params.now ?? Date.now();
  let art = !isPrivateScrape ? (item.artifact as { blobSha256?: string; contentSha256?: string } | undefined) : undefined;
  let markdownArtifactId: string | undefined;
  if (isPrivateScrape && payload.ephemeral !== true && rawCleanMarkdown) {
    if (env.ARTIFACTS && !Boolean(payload.noCache) && item.truncated !== true) {
      try {
        const rawBytesForPrivate =
          typeof item.bodyBase64 === 'string' && item.bodyBase64.length > 0
            ? decodeBase64ToBytes(item.bodyBase64)
            : typeof item.body === 'string' && item.bodyEncoding === 'base64' && item.body.length > 0
              ? decodeBase64ToBytes(item.body)
              : rawBodyStr
                ? new TextEncoder().encode(rawBodyStr)
                : new TextEncoder().encode(rawCleanMarkdown);
        const privStored = await writePrivateCachedScrape({
          bucket: env.ARTIFACTS,
          userId,
          url: normalizedUrl,
          markdown: rawCleanMarkdown,
          rawBytes: rawBytesForPrivate,
          ...(resolvedTitle ? { title: resolvedTitle } : {}),
          ...(extracted?.language ? { language: extracted.language } : {}),
          status: typeof item.status === 'number' ? item.status : 200,
          pipelineVersion: SCRAPE_PIPELINE_VERSION,
          optionsHash: scrapeOptionsHash,
          writeUrlCache: canUseOptionsR2Cache && !needsLiveHtml && !hasNonDefaultCacheOptionsWithoutRedact,
          now: postFetchNow,
        });
        art = {
          ...(privStored.blobSha256 ? { blobSha256: privStored.blobSha256 } : {}),
          contentSha256: privStored.contentSha256,
        };
        if (shaped.truncated) {
          markdownArtifactId = `md:${privStored.markdownSha256}`;
        }
      } catch {
        // Non-fatal if private R2 write fails
      }
    } else if (env.ARTIFACTS && shaped.truncated) {
      try {
        const mdContentSha = await sha256HexString(rawCleanMarkdown);
        await primeSanitizedMarkdownCache(mdContentSha, rawCleanMarkdown, {
          userId,
          privateOnly: true,
          pipelineVersion: SCRAPE_PIPELINE_VERSION,
        });
        await env.ARTIFACTS.put(
          r2PrivateDerivedKey(userId, SCRAPE_PIPELINE_VERSION, 'markdown', mdContentSha),
          rawCleanMarkdown,
          {
            httpMetadata: { contentType: 'text/markdown; charset=utf-8' },
            customMetadata: {
              pipelineVersion: String(SCRAPE_PIPELINE_VERSION),
              userId: sanitizeStorageUserId(userId),
              visibility: 'private',
            },
          },
        );
        markdownArtifactId = `md:${mdContentSha}`;
      } catch {
        // Non-fatal if private derived R2 write fails
      }
    }
    if (scopedUserCollectionId && env.SEARCH) {
      try {
        const idx = new D1FtsSearchIndex(env.SEARCH);
        const privPageId = `pg_${(await sha256HexString(`${sanitizeStorageUserId(userId)}:${normalizedUrl}`)).slice(0, 32)}`;
        const privDocId = `pdoc_${(await sha256HexString(`${sanitizeStorageUserId(userId)}:${rawCleanMarkdown}`)).slice(0, 32)}`;
        await idx.replacePageChunks({
          collectionId: scopedUserCollectionId,
          documentId: privDocId,
          pageId: privPageId,
          url: normalizedUrl,
          title: resolvedTitle || normalizedUrl,
          markdown: rawCleanMarkdown,
          fetchedAt: writeNow,
        });
      } catch {
        // Non-fatal if FTS5 indexing fails
      }
    }
  } else if (!isPrivateScrape && payload.ephemeral !== true && shaped.truncated && env.ARTIFACTS && rawCleanMarkdown) {
    const usesUpgradedBody = Boolean(
      alternateMarkdownBody ||
        ocrReportOut ||
        structuredTextFormatted ||
        contentSourceOut ||
        htmlJobPosting ||
        customShopifyDoc ||
        cmsTwinDoc ||
        cpscRecallDoc ||
        hydratedFromUniversalSchema ||
        universalSchemaDoc?.headerMarkdown ||
        cdpJsonDistilled?.markdown,
    );
    const computedCleanMdSha = await sha256HexString(rawCleanMarkdown);
    const mdContentSha =
      !usesUpgradedBody && art?.contentSha256 && isValidSha256Hex(art.contentSha256)
        ? art.contentSha256
        : computedCleanMdSha;
    try {
      await primeSanitizedMarkdownCache(mdContentSha, rawCleanMarkdown, {
        userId,
        privateOnly: false,
        pipelineVersion: SCRAPE_PIPELINE_VERSION,
        rawSha256: computedCleanMdSha,
      });
      await env.ARTIFACTS.put(r2DerivedKey(SCRAPE_PIPELINE_VERSION, 'markdown', mdContentSha), rawCleanMarkdown, {
        httpMetadata: { contentType: 'text/markdown; charset=utf-8' },
        customMetadata: { pipelineVersion: String(SCRAPE_PIPELINE_VERSION) },
      });
      markdownArtifactId = `md:${mdContentSha}`;
    } catch {
      // Non-fatal if R2 derived cache write fails.
    }
  }

  const redirectAnalysis = analyzeUrlRedirect(normalizedUrl, finalUrl);
  const computedChanges = stringFormats.has('changes')
    ? computeMarkdownChanges(prevMarkdownForChanges, rawCleanMarkdown)
    : undefined;

  const actionOutputsObj =
    inlineActions.length > 0 ||
    Array.isArray(item.actionScreenshots) ||
    Array.isArray(item.actionScrapes) ||
    Array.isArray(item.javascriptReturns) ||
    typeof item.pdfBase64 === 'string'
      ? {
          ...(Array.isArray(item.actionScreenshots) ? { screenshots: item.actionScreenshots } : {}),
          ...(Array.isArray(item.actionScrapes) ? { scrapes: item.actionScrapes } : {}),
          ...(Array.isArray(item.javascriptReturns) ? { javascriptReturns: item.javascriptReturns } : {}),
          ...(typeof item.pdfBase64 === 'string' && item.pdfBase64 ? { pdfs: [item.pdfBase64] } : {}),
        }
      : undefined;

  const itemGlobals =
    (item.frameworkGlobals ?? item.globals) &&
    typeof (item.frameworkGlobals ?? item.globals) === 'object' &&
    !Array.isArray(item.frameworkGlobals ?? item.globals)
      ? ((item.frameworkGlobals ?? item.globals) as BrowserFrameworkGlobals)
      : undefined;
  const finalHeadersForDetect = readItemHeaders();
  const detectedStack = !isPdfResponse
    ? detectSiteFrameworkLinear({
        url: finalUrl,
        body: isOriginMarkdown || isHtmlBody ? rawBodyStr : '',
        ...(isOriginMarkdown ? { contentSource: 'origin-markdown' as const } : isHtmlBody ? { contentSource: 'html' as const } : {}),
        ...(finalHeadersForDetect ? { headers: finalHeadersForDetect } : {}),
        ...(itemGlobals ? { globals: itemGlobals } : {}),
      })
    : null;
  const hasDetectedStack = Boolean(
    detectedStack &&
      (detectedStack.platform ||
        detectedStack.framework ||
        detectedStack.generators.length > 0 ||
        (detectedStack.contentFlags && detectedStack.contentFlags.length > 0)),
  );

  const parsedFinalWiki = parseWikipediaArticleUrl(finalUrl);
  const extractorIdOut =
    customCommerceId ??
    cmsTwinDoc?.extractorId ??
    cpscRecallDoc?.extractorId ??
    extracted?.extractorId ??
    (parsedFinalWiki ? 'mediawiki' : undefined);
  const detectedWithAdapter: Record<string, unknown> | null = detectedStack
    ? {
        ...detectedStack,
        ...(extractorIdOut ? { adapter: extractorIdOut } : {}),
      }
    : extractorIdOut
      ? { generators: [], adapter: extractorIdOut }
      : null;
  const hasDetectedOut = Boolean(
    hasDetectedStack || Boolean(extractorIdOut),
  );
  if (extractorIdOut) {
    setActiveSpanAttribute('edgefetch.adapter_id', extractorIdOut, activeTracer ?? undefined);
  }
  const rawAdapterRecords = customShopifyDoc?.records ?? extracted?.records ?? nonEmptyUniversalRecords;
  const urlSafeAdapterRecords = rawAdapterRecords !== undefined ? sanitizeRecordUrlsDeep(rawAdapterRecords) : undefined;
  const adapterRecordsOut =
    urlSafeAdapterRecords !== undefined
      ? redactPii
        ? redactPiiDeep(urlSafeAdapterRecords)
        : urlSafeAdapterRecords
      : undefined;
  const rawAdapterPagination = customShopifyDoc?.pagination ?? extracted?.pagination;
  const adapterPaginationOut =
    rawAdapterPagination !== undefined ? (redactPii ? redactPiiDeep(rawAdapterPagination) : rawAdapterPagination) : undefined;
  const safeUniversalStructuredOut =
    universalStructuredOut !== undefined
      ? redactPii
        ? redactPiiDeep(sanitizeRecordUrlsDeep(universalStructuredOut))
        : sanitizeRecordUrlsDeep(universalStructuredOut)
      : undefined;
  const safeHtmlJobPosting = htmlJobPosting
    ? redactPii
      ? redactPiiDeep(sanitizeRecordUrlsDeep(htmlJobPosting))
      : sanitizeRecordUrlsDeep(htmlJobPosting)
    : null;
  const safeProductOut = productOut
    ? sanitizeRecordUrlsDeep(redactPii ? redactPiiDeep(productOut) : productOut)
    : null;
  const safeAttributesOut = attributesOut ? (redactPii ? redactPiiDeep(attributesOut) : attributesOut) : undefined;
  const safeStructuredJsonOut = structuredJsonOut
    ? redactPii
      ? redactPiiDeep(sanitizeRecordUrlsDeep(structuredJsonOut))
      : sanitizeRecordUrlsDeep(structuredJsonOut)
    : undefined;
  const safeSummaryOut = summaryOut !== undefined ? (redactPii ? redactPiiText(summaryOut) : summaryOut) : undefined;
  const adapterTotalOut =
    customShopifyDoc?.total ??
    extracted?.total ??
    cmsTwinDoc?.total ??
    ssrHydrated?.total ??
    cdpJsonDistilled?.total ??
    universalSchemaDoc?.total;
  const adapterReturnedOut =
    customShopifyDoc?.returned ??
    extracted?.returned ??
    cmsTwinDoc?.returned ??
    ssrHydrated?.returned ??
    cdpJsonDistilled?.returned ??
    universalSchemaDoc?.returned;
  const adapterTruncatedOut =
    customShopifyDoc?.truncated ??
    extracted?.truncated ??
    cmsTwinDoc?.truncated ??
    ssrHydrated?.truncated ??
    cdpJsonDistilled?.truncated;
  const adapterNextCursorOut =
    customShopifyDoc?.nextCursor ??
    extracted?.nextCursor ??
    cmsTwinDoc?.nextCursor ??
    ssrHydrated?.nextCursor ??
    cdpJsonDistilled?.nextCursor;
  const rawResolvedAuthor = customShopifyDoc?.author ?? extracted?.author ?? universalSchemaDoc?.author;
  const resolvedAuthor = sanitizeScrapedMetadataField(
    rawResolvedAuthor ? (redactPii ? redactPiiText(rawResolvedAuthor) : rawResolvedAuthor) : undefined,
    256,
  );
  const resolvedPublishedTime = sanitizeScrapedTimestampField(
    customShopifyDoc?.publishedTime ??
      cmsTwinDoc?.publishedTime ??
      cpscRecallDoc?.doc.publishedTime ??
      extracted?.publishedTime ??
      htmlJobPosting?.datePosted ??
      universalSchemaDoc?.publishedTime,
    128,
  );
  const resolvedModifiedTime = sanitizeScrapedTimestampField(
    cmsTwinDoc?.modifiedTime ?? extracted?.modifiedTime ?? universalSchemaDoc?.modifiedTime,
    128,
  );
  const rawResolvedSiteName = extracted?.siteName ?? htmlJobPosting?.hiringOrganization ?? universalSchemaDoc?.siteName;
  const resolvedSiteName = sanitizeScrapedMetadataField(
    rawResolvedSiteName ? (redactPii ? redactPiiText(rawResolvedSiteName) : rawResolvedSiteName) : undefined,
    256,
  );

  const resolvedFavicon = (typeof item.favicon === 'string' && item.favicon) || extracted?.favicon || defaultFaviconForUrl(finalUrl);
  const resolvedContentType = isPdfResponse ? 'application/pdf' : (typeof item.contentType === 'string' ? item.contentType : undefined);
  const resolvedWordCount = rawCleanMarkdown ? countTextWords(rawCleanMarkdown) : undefined;
  const resolvedRendered = Boolean(renderMode === 'always' || renderedViaOut !== undefined);

  if (baseOptionsCacheEligible && payload.ephemeral !== true && Boolean(payload.noCache) && env.ARTIFACTS) {
    await deleteOptionsScrapeCacheIfNoCache();
  } else if (
    canUseOptionsR2Cache &&
    payload.ephemeral !== true &&
    !Boolean(payload.noCache) &&
    item.truncated !== true &&
    // Transient "temporarily unavailable" pages (maintenance / "try again later") are never cached as content.
    contentStateCheck.state !== 'temporarily_unavailable' &&
    env.ARTIFACTS &&
    rawCleanMarkdown
  ) {
    let rawBodyShaForCache: string | undefined =
      art?.contentSha256 && isValidSha256Hex(art.contentSha256)
        ? art.contentSha256
        : typeof item.contentSha256 === 'string' && isValidSha256Hex(item.contentSha256)
          ? item.contentSha256
          : typeof rawBodyStr === 'string' && rawBodyStr.length > 0
            ? await sha256HexString(rawBodyStr)
            : undefined;
    if (!rawBodyShaForCache) {
      const b64 =
        typeof item.bodyBase64 === 'string' && item.bodyBase64.length > 0
          ? item.bodyBase64
          : typeof item.body === 'string' && item.bodyEncoding === 'base64' && item.body.length > 0
            ? item.body
            : '';
      if (b64) {
        try {
          rawBodyShaForCache = await sha256HexBytes(decodeBase64ToBytes(b64));
        } catch {
          rawBodyShaForCache = undefined;
        }
      }
    }
    const contentShaForCache = rawBodyShaForCache ?? (await sha256HexString(rawCleanMarkdown));
    const docIdForCache = `doc_${(await sha256HexString(`${contentShaForCache}:${SCRAPE_PIPELINE_VERSION}:${scrapeOptionsHash}`)).slice(0, 32)}`;
    await writeOptionsScrapeCache({
      bucket: env.ARTIFACTS,
      isPrivate: isPrivateScrape,
      userId,
      optionsHash: scrapeOptionsHash,
      ...(env.META ? { metaDb: env.META } : {}),
      record: {
        url: normalizedUrl,
        finalUrl,
        markdown: fullMarkedPdfMarkdown ?? rawCleanMarkdown,
        ...(pdfPagesArray ? { pages: pdfPagesArray } : {}),
        contentSha256: contentShaForCache,
        ...(rawBodyShaForCache ? { rawContentSha256: rawBodyShaForCache } : {}),
        ...(art?.blobSha256 ? { blobSha256: art.blobSha256 } : {}),
        documentId: docIdForCache,
        pipelineVersion: SCRAPE_PIPELINE_VERSION,
        ...(resolvedTitle ? { title: resolvedTitle } : {}),
        ...(resolvedDescription ? { description: resolvedDescription } : {}),
        ...(extracted?.language ? { language: extracted.language } : {}),
        ...(resolvedFavicon ? { favicon: resolvedFavicon } : {}),
        canonicalUrl: safeCanonicalUrl ?? extracted?.canonicalUrl ?? finalUrl,
        ...(resolvedContentType ? { contentType: resolvedContentType } : {}),
        ...(resolvedWordCount !== undefined ? { wordCount: resolvedWordCount } : {}),
        rendered: resolvedRendered,
        ...(renderedViaOut ? { renderedVia: renderedViaOut } : {}),
        ...(resolvedRendered && typeof item.blockedTrackers === 'number'
          ? { blockedTrackers: item.blockedTrackers }
          : {}),
        contentState: contentStateCheck.state,
        ...(extractorIdOut ? { extractorId: extractorIdOut } : {}),
        ...(hasDetectedOut && detectedWithAdapter ? { detected: detectedWithAdapter } : {}),
        ...(finalHeadersForDetect?.etag ? { etag: finalHeadersForDetect.etag } : {}),
        ...(finalHeadersForDetect?.['last-modified'] ? { lastModified: finalHeadersForDetect['last-modified'] } : {}),
        ...(stringFormats.has('links') ? { links: resolvedLinks } : {}),
        ...(stringFormats.has('images') ? { images: resolvedImages } : {}),
        status: typeof item.status === 'number' ? item.status : 200,
        lastFetchedAt: postFetchNow,
      },
    }).catch(() => undefined);
  }

  const screenshotArtifactMeta =
    typeof item.screenshotBase64 === 'string' && item.screenshotBase64 && env.ARTIFACTS && payload.ephemeral !== true
      ? await storeScreenshotArtifactIfEnabled({
          screenshotBase64: item.screenshotBase64,
          bucket: env.ARTIFACTS,
          userId,
          privateOnly: isPrivateScrape,
        })
      : undefined;

  const out: Record<string, unknown> = {
    ok: true,
    cached: false,
    ...(isPrivateScrape ? { visibility: 'private' as const } : {}),
    pipelineVersion: SCRAPE_PIPELINE_VERSION,
    url: normalizedUrl,
    finalUrl,
    ...(resolvedTitle ? { title: resolvedTitle } : {}),
    ...(safeCanonicalUrl && safeCanonicalUrl !== finalUrl ? { canonicalUrl: safeCanonicalUrl } : {}),
    ...(crossOriginCanonical ? { crossOriginCanonical: true } : {}),
    ...(redirectAnalysis.redirected ? redirectAnalysis : {}),
    status: item.status ?? 200,
    via: viaOut,
    ...(item.extractedOnNode === true ? { extractedOnNode: true } : {}),
    ...(extractorIdOut ? { extractorId: extractorIdOut } : {}),
    ...(hasDetectedOut && detectedWithAdapter ? { detected: detectedWithAdapter } : {}),
    contentState: contentStateCheck.state,
    ...(contentStateCheck.reason ? { contentStateReason: contentStateCheck.reason } : {}),
    ...(contentSourceOut ? { contentSource: contentSourceOut } : {}),
    rendered: resolvedRendered,
    ...(renderedViaOut ? { renderedVia: renderedViaOut } : {}),
    ...(resolvedWordCount !== undefined ? { wordCount: resolvedWordCount } : {}),
    ...(resolvedFavicon ? { favicon: resolvedFavicon } : {}),
    ...(resolvedContentType ? { contentType: resolvedContentType } : {}),
    ...(scrapeWarnings.length > 0 ? { warnings: scrapeWarnings } : {}),
    ...(safeHtmlJobPosting ? { jobPosting: safeHtmlJobPosting } : {}),
    ...(safeUniversalStructuredOut ? { structured: safeUniversalStructuredOut } : {}),
    ...(adapterRecordsOut !== undefined ? { records: adapterRecordsOut } : {}),
    ...(adapterPaginationOut !== undefined ? { pagination: adapterPaginationOut } : {}),
    ...(adapterTotalOut !== undefined ? { total: adapterTotalOut } : {}),
    ...(adapterReturnedOut !== undefined ? { returned: adapterReturnedOut } : {}),
    ...(adapterTruncatedOut !== undefined ? { truncated: adapterTruncatedOut } : {}),
    ...(adapterNextCursorOut !== undefined ? { nextCursor: adapterNextCursorOut } : {}),
    ...(art?.contentSha256 ? { contentSha256: art.contentSha256 } : {}),
    ...(art?.blobSha256 ? { artifactId: art.blobSha256 } : {}),
    ...(markdownArtifactId ? { markdownArtifactId } : {}),
    ...(stringFormats.has('markdown') ? { markdown } : {}),
    ...(stringFormats.has('text') ? { text: textOut } : {}),
    ...(safeSummaryOut !== undefined ? { summary: safeSummaryOut } : {}),
    ...(safeProductOut ? { product: safeProductOut } : {}),
    ...(safeAttributesOut ? { attributes: safeAttributesOut } : {}),
    ...(rawBase64Out ? { rawBase64: rawBase64Out } : {}),
    ...(pdfPagesArray ? { pages: pdfPagesArray } : {}),
    ...(actionOutputsObj && Object.keys(actionOutputsObj).length > 0 ? { actions: actionOutputsObj } : {}),
    ...(focused.queryFiltered
      ? { queryFiltered: true, chunks: redactPii ? redactPiiDeep(focused.chunks) : focused.chunks }
      : jsonRecordsFormatted
        ? {
            chunks: redactPii ? redactPiiDeep(jsonRecordsFormatted.chunks) : jsonRecordsFormatted.chunks,
            recordCount: jsonRecordsFormatted.matchedRecords,
            totalRecords: jsonRecordsFormatted.totalRecords,
          }
        : {}),
    ...(shaped.truncated || (textOutBudgetCut && stringFormats.has('text'))
      ? (() => {
          // One coordinate system: sanitized-output chars (what `read_artifact` serves for `markdownArtifactId`).
          // Raw input length (e.g. a 2-4 MiB origin-markdown body) is only reported as `sourceChars`.
          const effTotal = shaped.totalChars ?? markdown.length;
          const effNext = shaped.nextOffset ?? markdown.length;
          return {
            truncated: true,
            totalChars: effTotal,
            nextOffset: effNext,
            remainingChars: shaped.remainingChars ?? Math.max(0, effTotal - effNext),
            ...(shaped.sourceTruncated ? { sourceTruncated: true, sourceChars: shaped.sourceChars } : {}),
          };
        })()
      : adapterTruncatedOut === true
        ? { truncated: true }
        : {}),
    ...(stringFormats.has('rawHtml') || stringFormats.has('html') ? { rawHtml: rawBodyStr, html: rawBodyStr } : {}),
    ...(stringFormats.has('links') ? { links: resolvedLinks } : {}),
    ...(stringFormats.has('images') ? { images: resolvedImages } : {}),
    ...(stringFormats.has('branding')
      ? {
          branding: (() => {
            const base = {
              ...(extracted?.branding ?? {}),
              ...(item.branding && typeof item.branding === 'object' ? (item.branding as Record<string, unknown>) : {}),
            };
            if (Array.isArray(base.fonts)) {
              const cleanFonts = base.fonts
                .filter((f): f is string => typeof f === 'string')
                .map((f) => f.trim().replace(/^["']|["']$/g, ''))
                .filter(
                  (f) =>
                    f &&
                    !/^var\s*\(/i.test(f) &&
                    !/^(sans-serif|serif|monospace|cursive|fantasy|inherit|initial|unset|revert|system-ui|ui-sans-serif|ui-serif|ui-monospace|-apple-system|blinkmacsystemfont)$/i.test(
                      f,
                    ),
                );
              if (cleanFonts.length > 0) base.fonts = [...new Set(cleanFonts)];
              else delete base.fonts;
            }
            return base;
          })(),
        }
      : {}),
    ...(safeStructuredJsonOut ? { json: safeStructuredJsonOut } : {}),
    ...(jsonExtractionModeOut ? { jsonExtractionMode: jsonExtractionModeOut } : {}),
    ...(typeof item.screenshotBase64 === 'string' && item.screenshotBase64
      ? {
          screenshotBase64: item.screenshotBase64,
          screenshot: `data:image/png;base64,${item.screenshotBase64}`,
          ...(screenshotArtifactMeta ?? {}),
        }
      : {}),
    ...(pdfEngineOut ? { pdfEngine: pdfEngineOut } : {}),
    ...(ocrReportOut ? { ocr: ocrReportOut } : {}),
    ...(computedChanges
      ? {
          changes: computedChanges,
          ...(changeTrackingSpec
            ? {
                changeTracking: {
                  changeStatus: computedChanges.status,
                  ...(changeTrackingSpec.tag ? { tag: changeTrackingSpec.tag } : {}),
                  ...(computedChanges.diffPreview ? { diff: { text: computedChanges.diffPreview } } : {}),
                },
              }
            : {}),
        }
      : {}),
    ...(llmsPayload ? { llms: llmsPayload, ...(stringFormats.has('llmsTxt') ? { llmsTxt: llmsPayload } : {}) } : {}),
    metadata: {
      ...(resolvedTitle ? { title: resolvedTitle } : {}),
      ...(resolvedDescription ? { description: resolvedDescription } : {}),
      ...(resolvedAuthor ? { author: resolvedAuthor } : {}),
      ...(resolvedPublishedTime ? { publishedTime: resolvedPublishedTime } : {}),
      ...(resolvedModifiedTime ? { modifiedTime: resolvedModifiedTime } : {}),
      ...(resolvedSiteName ? { siteName: resolvedSiteName } : {}),
      ...(resolvedWordCount !== undefined ? { wordCount: resolvedWordCount } : {}),
      ...(extracted?.language ? { language: extracted.language } : {}),
      ...(resolvedFavicon ? { favicon: resolvedFavicon } : {}),
      ...((safeCanonicalUrl ?? extracted?.canonicalUrl) ? { canonicalUrl: safeCanonicalUrl ?? extracted?.canonicalUrl } : {}),
      ...(crossOriginCanonical ? { crossOriginCanonical: true } : {}),
      ...(alternateMarkdownUrl ? { alternateMarkdownUrl } : {}),
      ...(contentSourceOut ? { contentSource: contentSourceOut } : {}),
      ...(resolvedContentType ? { contentType: resolvedContentType } : {}),
      ...(resolvedRendered || typeof item.blockedTrackers === 'number'
        ? { blockedTrackers: typeof item.blockedTrackers === 'number' ? item.blockedTrackers : 0 }
        : {}),
    },
  };

  if ((resolvedRendered || typeof item.blockedTrackers === 'number') && activeTracer) {
    setActiveSpanAttribute(
      'browser.blocked_trackers',
      typeof item.blockedTrackers === 'number' && Number.isFinite(item.blockedTrackers)
        ? Math.max(0, Math.floor(item.blockedTrackers))
        : 0,
      activeTracer,
    );
  }

  return { status: 200, via: viaOut, body: out };
  } catch (wasmErr) {
    if (isWasmInputBudgetExceededError(wasmErr)) {
      const fallbackRaw = rawBodyStr;
      rawBodyStr = '';
      return buildOverBudgetEdgeResponse(fallbackRaw, item, fetchResUsed.via);
    }
    throw wasmErr;
  } finally {
    isolateLease.release();
  }
  };
  const rawScrapeResult = await (activeTracer ? activeTracer.run(runScrape) : runScrape());
  const recordsBudget = resolveScrapeMaxChars(params.payload);
  const scrapeResult =
    recordsBudget !== undefined && Array.isArray(rawScrapeResult.body.records)
      ? { ...rawScrapeResult, body: capInlineRecordsToBudget(rawScrapeResult.body, recordsBudget) }
      : rawScrapeResult;
  if (
    scrapeResult.body.visibility !== 'private' &&
    isPrivateRequestPayload(params.payload, params.userId ?? 'owner')
  ) {
    return { ...scrapeResult, body: { ...scrapeResult.body, visibility: 'private' as const } };
  }
  return scrapeResult;
}

/**
 * True when a twin fetch was redirected to the origin's error page (`/error`, `/404`, `/not-found`, ...), which many
 * sites serve with HTTP 200. Such a body must never be formatted as the requested document: GovInfo redirects a
 * missing `/content/pkg/.../html/*.htm` to `/error`, and the "Page Not Found" text came back as `ok: true`.
 */
export function isTwinRedirectedToErrorPage(fetchUrl: string, item: Record<string, unknown> | undefined): boolean {
  const finalUrl = typeof item?.finalUrl === 'string' ? item.finalUrl : '';
  if (!finalUrl || finalUrl === fetchUrl) return false;
  try {
    const finalPath = new URL(finalUrl).pathname;
    if (finalPath === new URL(fetchUrl).pathname) return false;
    return /^\/(?:[a-z]{2}(?:[-_][a-z]{2})?\/)?(?:errors?|40[34]|not-?found|page-?not-?found|notfound)(?:[/.]|$)/i.test(finalPath);
  } catch {
    return false;
  }
}

/** The scrape's inline character budget: explicit `maxChars`, else the caller's `defaultMaxChars` (MCP), else none. */
export function resolveScrapeMaxChars(payload: Pick<ScrapeRequestPayload, 'maxChars' | 'defaultMaxChars'>): number | undefined {
  return typeof payload.maxChars === 'number' && Number.isFinite(payload.maxChars)
    ? Math.min(500_000, Math.max(500, Math.floor(payload.maxChars)))
    : typeof payload.defaultMaxChars === 'number' && Number.isFinite(payload.defaultMaxChars)
      ? Math.min(500_000, Math.max(500, Math.floor(payload.defaultMaxChars)))
      : undefined;
}

/**
 * Keeps inline `records[]` (catalog / twin / adapter rows) within the same character budget as `markdown`. A Shopify
 * collection asked for `maxChars: 600` returned 50 full products (~439 KB) inline, more than an MCP client accepts in
 * one tool result. Whole records are kept from the front while they fit; the body then says how many were dropped and
 * where to get the rest. Callers without a budget (REST without `maxChars`) keep the full array.
 */
export function capInlineRecordsToBudget(body: Record<string, unknown>, budgetChars: number): Record<string, unknown> {
  const records = body.records;
  if (!Array.isArray(records) || records.length === 0) return body;
  if (JSON.stringify(records).length <= budgetChars) return body;
  const kept: unknown[] = [];
  let used = 2; // the enclosing [ ]
  for (const rec of records) {
    const len = JSON.stringify(rec).length + (kept.length > 0 ? 1 : 0);
    if (used + len > budgetChars) break;
    kept.push(rec);
    used += len;
  }
  return {
    ...body,
    records: kept,
    recordsTruncated: true,
    recordsReturned: kept.length,
    recordsTotal: records.length,
    recordsHint:
      `records[] trimmed to ${kept.length} of ${records.length} to fit maxChars ${budgetChars}. ` +
      'Raise maxChars (up to 500000), follow pagination when present, or page the raw response with read_artifact(artifactId).',
  };
}

export function extractYouTubeTranscriptFromHtml(rawHtml: string): string {
  if (!rawHtml) return '';
  return callCoreWasm<{ transcript?: string }>('extract_youtube', {
    rawHtml,
    url: '',
    includeTranscript: true,
  }).transcript ?? '';
}

export interface InteractRequestPayload {
  url?: unknown;
  sessionId?: unknown;
  keepSession?: unknown;
  closeSession?: unknown;
  actions?: unknown;
  formats?: unknown;
  blockTrackers?: unknown;
  waitForMs?: unknown;
  waitSelector?: unknown;
  maxChars?: unknown;
  offset?: unknown;
  site?: unknown;
  visibility?: unknown;
}

const interactSessionSnapshotCache = new Map<string, { url: string; markdownSha: string; updatedAt: number }>();

function rememberInteractSessionSnapshot(key: string, url: string, markdownSha: string): void {
  const now = Date.now();
  for (const [k, v] of interactSessionSnapshotCache.entries()) {
    if (now - v.updatedAt > 30 * 60_000) interactSessionSnapshotCache.delete(k);
  }
  interactSessionSnapshotCache.delete(key);
  interactSessionSnapshotCache.set(key, { url, markdownSha, updatedAt: now });
  if (interactSessionSnapshotCache.size > 256) {
    const oldest = interactSessionSnapshotCache.keys().next().value;
    if (oldest !== undefined) interactSessionSnapshotCache.delete(oldest);
  }
}

function splitCompositeSessionId(raw: unknown): { siteId?: string; agentSessionId?: string; sigHex?: string; malformed?: boolean } {
  if (typeof raw !== 'string' || !raw.trim()) return {};
  const clean = raw.trim();
  const parts = clean.split('.');
  if (parts.length === 3) {
    const [sitePartRaw, sessPart, sigPart] = parts;
    const sitePart = sitePartRaw!.toLowerCase();
    if (
      /^[a-z0-9][a-z0-9_-]{0,31}$/.test(sitePart) &&
      /^[A-Za-z0-9_-]{4,80}$/.test(sessPart!) &&
      /^[0-9a-f]{24,64}$/i.test(sigPart!)
    ) {
      return { siteId: sitePart, agentSessionId: sessPart!, sigHex: sigPart!.toLowerCase() };
    }
    return { malformed: true };
  }
  if (parts.length === 2) {
    const [sitePartRaw, sessPart] = parts;
    const sitePart = sitePartRaw!.toLowerCase();
    if (/^[a-z0-9][a-z0-9_-]{0,31}$/.test(sitePart) && /^[A-Za-z0-9_-]{4,80}$/.test(sessPart!)) {
      return { siteId: sitePart, agentSessionId: sessPart! };
    }
    return { malformed: true };
  }
  if (/^[A-Za-z0-9_-]{4,80}$/.test(clean)) {
    return { agentSessionId: clean };
  }
  return { malformed: true };
}

function normalizeInteractPrincipal(principal?: string, source?: string): string {
  if (typeof principal === 'string' && principal.trim()) {
    return principal.trim();
  }
  const raw = (source ?? 'default').trim();
  const stripped = raw.replace(/^(?:mcp-interact|interact|mcp|compat|agent):/i, '').replace(/:interact$/i, '');
  return stripped || 'default';
}

const DEFAULT_INTERACT_HMAC_KEY_FALLBACK = 'edgefetch-default-interact-key';

async function storeScreenshotArtifactIfEnabled(params: {
  screenshotBase64: string;
  bucket?: R2Bucket;
  userId: string;
  privateOnly: boolean;
}): Promise<{ screenshotArtifactId: string; screenshotMimeType: 'image/png'; screenshotBytes: number } | undefined> {
  const { screenshotBase64, bucket, userId, privateOnly } = params;
  if (!bucket || !screenshotBase64) return undefined;
  const trimmed = screenshotBase64.trim();
  if (!trimmed || trimmed.length > Math.ceil((MAX_ARTIFACT_CONTENT_BYTES * 4) / 3) + 16) {
    return undefined;
  }
  try {
    const bin = atob(trimmed);
    if (bin.length === 0 || bin.length > MAX_ARTIFACT_CONTENT_BYTES) return undefined;
    const pngBytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) {
      pngBytes[i] = bin.charCodeAt(i);
    }
    const stored = await writeArtifactToR2({
      bucket,
      rawBytes: pngBytes,
      retention: 'transient',
      userId,
      privateOnly,
    });
    return {
      screenshotArtifactId: stored.blobSha256,
      screenshotMimeType: 'image/png',
      screenshotBytes: pngBytes.byteLength,
    };
  } catch {
    return undefined;
  }
}

async function computeInteractSessionMacHex(
  secret: string,
  userId: string,
  principal: string,
  siteId: string,
  agentSessionId: string,
): Promise<string> {
  const enc = new TextEncoder();
  const effectiveSecret = secret.trim() || DEFAULT_INTERACT_HMAC_KEY_FALLBACK;
  const safeUser = sanitizeStorageUserId(userId);
  const derivedKeyBytes = await crypto.subtle.digest('SHA-256', enc.encode(effectiveSecret));
  const key = await crypto.subtle.importKey('raw', derivedKeyBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const macBuf = await crypto.subtle.sign('HMAC', key, enc.encode(`ef-interact-v1|${safeUser}|${principal}|${siteId}|${agentSessionId}`));
  return Array.from(new Uint8Array(macBuf).subarray(0, 16), (b) => b.toString(16).padStart(2, '0')).join('');
}

function constantTimeHexEqual(a: string, b: string): boolean {
  if (a.length !== b.length || a.length === 0) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

/**
 * Executes `POST /v1/interact` + MCP `interact` (`firecrawl_interact` parity) against a `browser-v1` worker
 * node. Composite `<siteId>.<efsess_id>[.<hmac32>]` tokens ensure follow-up turns route back to the exact node holding
 * the tab AND prevent cross-caller session hijacking on multi-client OAuth Hubs.
 */
export async function executeInteractCall(params: {
  payload: InteractRequestPayload;
  env: OptionalStorageBindings;
  executeHubFetch: (
    target: 'auto' | 'agent' | 'container',
    body: string,
    site?: string,
    source?: string,
    artifactRetention?: ArtifactRetention | 'off',
    hydrateInline?: boolean,
  ) => Promise<{ status: number; via: string; bodyText: string; retryAfter?: string }>;
  source?: string;
  selfHost?: string;
  principal?: string;
  userId?: string;
  sessionSigningSecret?: string;
  tracer?: RequestTracer | TraceContext;
}): Promise<{ status: number; via: string; body: Record<string, unknown> }> {
  const activeTracer = getActiveRequestTracer(params.tracer);
  const runInteract = async (): Promise<{ status: number; via: string; body: Record<string, unknown> }> => {
  const { payload, env, executeHubFetch, source = 'interact', selfHost, principal, userId = 'owner', sessionSigningSecret } = params;
  const isPrivateInteract = normalizeVisibility(payload.visibility) === 'private' || sanitizeStorageUserId(userId) !== 'owner';
  const interactRetention: ArtifactRetention | 'off' | undefined = isPrivateInteract
    ? 'off'
    : env.ARTIFACTS
      ? 'transient'
      : undefined;
  const interactShouldIngest = !isPrivateInteract;
  const privInteractField = isPrivateInteract ? { visibility: 'private' as const } : {};
  const effectivePrincipal = normalizeInteractPrincipal(principal, source);
  const signingSecret =
    typeof sessionSigningSecret === 'string' && sessionSigningSecret.trim()
      ? sessionSigningSecret.trim()
      : DEFAULT_INTERACT_HMAC_KEY_FALLBACK;
  const parsedSession = splitCompositeSessionId(payload.sessionId);
  if (parsedSession.malformed) {
    return { status: 400, via: 'hub', body: { ok: false, ...privInteractField, error: 'invalid_session_id', message: 'malformed interact sessionId' } };
  }
  if (parsedSession.agentSessionId) {
    if (!parsedSession.siteId || !parsedSession.sigHex) {
      return {
        status: 403,
        via: 'hub',
        body: { ok: false, ...privInteractField, error: 'session_principal_mismatch', message: 'interact sessionId is missing caller ownership signature' },
      };
    }
    const expectedSig = await computeInteractSessionMacHex(
      signingSecret,
      userId,
      effectivePrincipal,
      parsedSession.siteId,
      parsedSession.agentSessionId,
    );
    if (!constantTimeHexEqual(parsedSession.sigHex, expectedSig)) {
      return {
        status: 403,
        via: 'hub',
        body: { ok: false, ...privInteractField, error: 'session_principal_mismatch', message: 'interact sessionId belongs to a different caller principal' },
      };
    }
    const resumedSessionHash = await sha256HexString(`${parsedSession.siteId.toLowerCase()}:${parsedSession.agentSessionId}`);
    setActiveSpanAttribute('edgefetch.interact.session_hash', resumedSessionHash, activeTracer ?? undefined);
  }
  const rawUrl = typeof payload.url === 'string' ? payload.url.trim() : '';

  let normalizedUrl = '';
  if (rawUrl) {
    const urlCheck = validatePublicHttpsTargetUrl(rawUrl, selfHost);
    if (!urlCheck.ok) {
      return { status: 400, via: 'hub', body: { ok: false, ...privInteractField, error: 'invalid_url', message: urlCheck.message } };
    }
    normalizedUrl = urlCheck.normalized;
  } else if (!parsedSession.agentSessionId) {
    return {
      status: 400,
      via: 'hub',
      body: { ok: false, ...privInteractField, error: 'missing_url_or_session', message: 'provide url (new session) or sessionId (resume/close session)' },
    };
  }

  const parsedInteractActions = normalizeInlineBrowserActions(payload.actions, selfHost, 50);
  if (!parsedInteractActions.ok) {
    return {
      status: 400,
      via: 'hub',
      body: { ok: false, ...privInteractField, error: parsedInteractActions.message.includes('maximum') ? 'too_many_actions' : 'invalid_action', message: parsedInteractActions.message },
    };
  }
  const actions: Array<Record<string, unknown>> = parsedInteractActions.actions;
  const agentActions: Array<Record<string, unknown>> = [...parsedInteractActions.actions];
  setActiveSpanAttribute('edgefetch.interact.action_count', actions.length, activeTracer ?? undefined);
  if (normalizedUrl) {
    setActiveSpanAttribute('url.full', sanitizeUrlForSpan(normalizedUrl), activeTracer ?? undefined);
  }

  const topWaitForMs =
    typeof payload.waitForMs === 'number' && Number.isFinite(payload.waitForMs)
      ? Math.min(15_000, Math.max(0, Math.floor(payload.waitForMs)))
      : undefined;
  const topWaitSelector =
    typeof payload.waitSelector === 'string' && payload.waitSelector.trim()
      ? payload.waitSelector.trim().slice(0, 200)
      : undefined;
  // Go's `Execute` only applies top-level `waitForMs`/`waitSelector` during initial `url` navigation before `actions`;
  // append a trailing settle wait when resuming a session (`!normalizedUrl`) or after running `actions`.
  if ((actions.length > 0 || !normalizedUrl) && (topWaitSelector || (topWaitForMs !== undefined && topWaitForMs > 0))) {
    agentActions.push({
      type: 'wait',
      ...(topWaitSelector ? { selector: topWaitSelector } : {}),
      waitMs: topWaitForMs ?? (topWaitSelector ? 5_000 : 900),
    });
  }

  const formats = Array.isArray(payload.formats)
    ? payload.formats.filter((f): f is string => typeof f === 'string')
    : ['markdown'];
  const interactMaxChars =
    typeof payload.maxChars === 'number' && Number.isFinite(payload.maxChars) && payload.maxChars > 0
      ? Math.min(500_000, Math.max(100, Math.floor(payload.maxChars)))
      : undefined;
  const interactOffset =
    typeof payload.offset === 'number' && Number.isFinite(payload.offset) && payload.offset >= 0
      ? Math.floor(payload.offset)
      : 0;
  const hasInteractSlicePaging = interactMaxChars !== undefined || interactOffset > 0;
  const keepSession = Boolean(payload.keepSession);
  const closeSession = Boolean(payload.closeSession);
  const explicitSite = typeof payload.site === 'string' && payload.site.trim() ? payload.site.trim().toLowerCase() : undefined;
  const pinnedSite = parsedSession.siteId ?? explicitSite;

  const call = {
    maxSeconds: 60,
    options: {
      includeBody: true,
      respectRobots: true,
      maxBytes: 16 * 1024 * 1024,
      timeoutMs: 45_000,
    },
    requests: [
      {
        id: 'interact-1',
        url: normalizedUrl,
        kind: 'render',
        renderMode: 'always',
        ...(typeof payload.blockTrackers === 'boolean' ? { blockTrackers: payload.blockTrackers } : {}),
        formats: formats.length > 0 ? formats : ['markdown'],
        ...(topWaitForMs !== undefined ? { waitForMs: topWaitForMs } : {}),
        ...(topWaitSelector ? { waitSelector: topWaitSelector } : {}),
        interact: {
          ...(parsedSession.agentSessionId ? { sessionId: parsedSession.agentSessionId } : {}),
          keepSession,
          closeSession,
          actions: agentActions,
        },
      },
    ],
  };

  const fetchRes = await executeHubFetch('agent', JSON.stringify(call), pinnedSite, source, interactRetention, interactShouldIngest);
  if (fetchRes.status !== 200) {
    let errJson: Record<string, unknown> = { ok: false, error: 'interact_failed' };
    try {
      errJson = { ok: false, ...(JSON.parse(fetchRes.bodyText) as Record<string, unknown>) };
    } catch {
      // ignore
    }
    return { status: fetchRes.status, via: fetchRes.via, body: { ...errJson, ...privInteractField } };
  }

  const parsed = JSON.parse(fetchRes.bodyText) as { results?: Array<Record<string, unknown>> };
  const item = parsed.results?.[0] ?? {};
  const describeAction = (a: Record<string, unknown>, index: number, status: 'ok' | 'error' | 'skipped', error?: string) => ({
    index,
    type: String(a.type ?? ''),
    ...(typeof a.selector === 'string' ? { selector: a.selector } : {}),
    ...(typeof a.url === 'string' ? { url: a.url } : {}),
    status,
    ...(error ? { error } : {}),
  });

  if (item.outcome !== 'ok') {
    const isYouTubeUrl =
      Boolean(normalizedUrl) &&
      (() => {
        try {
          const h = new URL(normalizedUrl).hostname.toLowerCase();
          return h === 'youtube.com' || h.endsWith('.youtube.com') || h === 'youtu.be';
        } catch {
          return false;
        }
      })();
    // YouTube blocks headless Chromium (`HeadlessChrome`) with HTTP 401/403 while permitting polite plain HTTP watch-page
    // fetches (`ytInitialPlayerResponse.videoDetails`), so stateless metadata/transcript probes degrade gracefully to HTTP scrape.
    if (isYouTubeUrl && actions.length === 0 && !keepSession && !closeSession && !parsedSession.agentSessionId) {
      const ytFallback = await executeHubFetch(
        'auto',
        JSON.stringify({
          maxSeconds: 30,
          options: { includeBody: true, respectRobots: true, discoverLlms: false },
          requests: [{ id: 'yt-watch-1', url: normalizedUrl, kind: 'scrape', formats: ['markdown'], onlyMainContent: true, discoverLlms: false }],
        }),
        pinnedSite,
        `${source}:youtube-fallback`,
        interactRetention,
        interactShouldIngest,
      );
      if (ytFallback.status === 200) {
        const ytParsed = JSON.parse(ytFallback.bodyText) as { results?: Array<Record<string, unknown>> };
        const ytItem = ytParsed.results?.[0];
        const ytRawHtml = typeof ytItem?.body === 'string' && ytItem.bodyEncoding !== 'base64' ? ytItem.body : '';
        if (ytItem?.outcome === 'ok' && ytRawHtml) {
          const ytDoc = extractHtmlDocument(ytRawHtml, { baseUrl: normalizedUrl, onlyMainContent: true });
          const ytTranscript = extractYouTubeTranscriptFromHtml(ytRawHtml);
          const requestedTranscript = formats.includes('transcript');
          const wantMarkdown = formats.includes('markdown');
          const ytPaged = sliceMarkdownWithOffsetAndMaxChars(ytDoc.markdown, interactOffset, interactMaxChars);
          return {
            status: 200,
            via: ytFallback.via,
            body: {
              ok: true,
              ...privInteractField,
              via: ytFallback.via,
              finalUrl: normalizedUrl,
              status: ytItem.status ?? 200,
              rendered: false,
              actions: [],
              ...(wantMarkdown || (requestedTranscript && !ytTranscript) ? { markdown: ytPaged.markdown } : {}),
              ...(hasInteractSlicePaging || ytPaged.truncated
                ? {
                    truncated: ytPaged.truncated,
                    offset: ytPaged.offset,
                    totalChars: ytPaged.totalChars,
                    nextOffset: ytPaged.nextOffset,
                    remainingChars: ytPaged.remainingChars,
                  }
                : {}),
              ...(requestedTranscript ? { transcript: ytTranscript || null } : {}),
              ...(requestedTranscript && !ytTranscript
                ? {
                    formatWarnings: {
                      transcript:
                        'YouTube blocks headless Chromium (HTTP 401) and disallows /api/timedtext in robots.txt; returning extracted watch-page title, channel, duration, and description.',
                    },
                  }
                : {}),
              metadata: { title: ytDoc.title },
            },
          };
        }
      }
    }

    const rawProb = String(item.problem ?? 'Browser interact step failed');
    const prob = scrubResolverIpFromError(rawProb);
    if (isDnsNotFoundError(item.outcome, prob)) {
      return {
        status: 502,
        via: fetchRes.via,
        body: {
          ok: false,
          ...privInteractField,
          ...(normalizedUrl ? { url: normalizedUrl } : {}),
          outcome: 'dns_not_found',
          error: 'dns_not_found',
          retryable: false,
          status: 502,
          message: DNS_NOT_FOUND_MESSAGE,
          problem: prob || DNS_NOT_FOUND_MESSAGE,
        },
      };
    }
    if (isSsrfBlockedError(item.outcome, prob)) {
      return {
        status: 403,
        via: fetchRes.via,
        body: {
          ok: false,
          ...privInteractField,
          ...(normalizedUrl ? { url: normalizedUrl } : {}),
          outcome: 'blocked',
          error: 'blocked',
          retryable: false,
          status: item.status ?? 403,
          message: SSRF_BLOCKED_INFO.message,
          blocked: { ...SSRF_BLOCKED_INFO },
        },
      };
    }
    const actFail = /interact action (\d+) \(([^)]+)\):\s*(.+)/i.exec(prob);
    const failedIdx = actFail ? Number(actFail[1]) : -1;
    const failedDetail = actFail?.[3]?.trim() ?? prob;
    const actionResults =
      failedIdx >= 0 && actions.length > 0
        ? actions.map((a, idx) =>
            idx < failedIdx
              ? describeAction(a, idx, 'ok')
              : idx === failedIdx
                ? describeAction(a, idx, 'error', failedDetail)
                : describeAction(a, idx, 'skipped'),
          )
        : undefined;

    // P8 & P10: Surface any partial rendered DOM/Markdown/transcript captured before the failed action + structured `blocked` guidance!
    const partialHtml = typeof item.body === 'string' && item.bodyEncoding !== 'base64' ? item.body : '';
    const partialFinalUrl = resolveValidatedFinalUrl(item.finalUrl, normalizedUrl, selfHost);
    const partialDoc = partialHtml ? extractHtmlDocument(partialHtml, { baseUrl: partialFinalUrl || undefined, onlyMainContent: true }) : undefined;
    const partialTranscript = partialHtml ? extractYouTubeTranscriptFromHtml(partialHtml) : '';
    const partialMd = partialDoc?.markdown ? partialDoc.markdown.trim() : '';
    const errSiteMatch = /^agent:(?:[a-z0-9_-]+\+)*([a-z0-9_-]+)/i.exec(fetchRes.via);
    const errActualSite = (errSiteMatch?.[1] ?? pinnedSite ?? 'default').toLowerCase();
    const errAgentSid = typeof item.sessionId === 'string' && item.sessionId ? item.sessionId : undefined;
    if (errAgentSid) {
      const errSessionHash = await sha256HexString(`${errActualSite}:${errAgentSid}`);
      setActiveSpanAttribute('edgefetch.interact.session_hash', errSessionHash, activeTracer ?? undefined);
    }
    const errSig = errAgentSid
      ? await computeInteractSessionMacHex(signingSecret, userId, effectivePrincipal, errActualSite, errAgentSid)
      : undefined;
    const errPublicSid = errAgentSid && errSig ? `${errActualSite}.${errAgentSid}.${errSig}` : errAgentSid;
    const blockedInfo = refineBlockedInfo({
      url: partialFinalUrl || normalizedUrl,
      outcome: item.outcome,
      problem: prob,
      status: item.status,
      retryAfter: typeof item.retryAfter === 'string' ? item.retryAfter : fetchRes.retryAfter,
      baseBlocked: buildBlockedInfo(partialFinalUrl || normalizedUrl, item.outcome, prob, item.status),
    });

    return {
      status: item.outcome === 'challenge' ? 403 : 422,
      via: fetchRes.via,
      body: {
        ok: false,
        ...privInteractField,
        outcome: item.outcome ?? 'error',
        status: item.status ?? 0,
        problem: prob,
        ...(partialFinalUrl ? { finalUrl: partialFinalUrl } : {}),
        ...(errPublicSid ? { sessionId: errPublicSid } : {}),
        ...(actionResults ? { actions: actionResults } : {}),
        ...(partialMd && formats.includes('markdown') ? { markdown: partialMd, partial: true } : {}),
        ...(partialTranscript && formats.includes('transcript') ? { transcript: partialTranscript, partial: true } : {}),
        ...(partialHtml && (formats.includes('html') || formats.includes('rawHtml')) ? { html: partialHtml } : {}),
        ...(partialDoc?.title || typeof item.blockedTrackers === 'number'
          ? {
              metadata: {
                ...(partialDoc?.title ? { title: partialDoc.title } : {}),
                ...(typeof item.blockedTrackers === 'number' ? { blockedTrackers: item.blockedTrackers } : {}),
              },
            }
          : {}),
        ...(blockedInfo ? { blocked: blockedInfo } : {}),
      },
    };
  }

  const siteMatch = /^agent:(?:[a-z0-9_-]+\+)*([a-z0-9_-]+)/i.exec(fetchRes.via);
  const actualSite = (siteMatch?.[1] ?? pinnedSite ?? 'default').toLowerCase();
  const returnedAgentSid = typeof item.sessionId === 'string' && item.sessionId ? item.sessionId : undefined;
  if (returnedAgentSid) {
    const okSessionHash = await sha256HexString(`${actualSite}:${returnedAgentSid}`);
    setActiveSpanAttribute('edgefetch.interact.session_hash', okSessionHash, activeTracer ?? undefined);
  }
  const sessionSig = returnedAgentSid
    ? await computeInteractSessionMacHex(signingSecret, userId, effectivePrincipal, actualSite, returnedAgentSid)
    : undefined;
  const publicSessionId = returnedAgentSid && sessionSig ? `${actualSite}.${returnedAgentSid}.${sessionSig}` : returnedAgentSid;

  const rawHtml = typeof item.body === 'string' && item.bodyEncoding !== 'base64' ? item.body : '';
  const finalUrl = resolveValidatedFinalUrl(item.finalUrl, normalizedUrl, selfHost);
  const interactRedirect = normalizedUrl ? analyzeUrlRedirect(normalizedUrl, finalUrl) : { redirected: false };
  const wantMarkdown = formats.includes('markdown');
  const requestedTranscript = formats.includes('transcript');
  const extracted = rawHtml ? extractHtmlDocument(rawHtml, { baseUrl: finalUrl || undefined, onlyMainContent: true }) : undefined;
  const transcript = (requestedTranscript || wantMarkdown) && rawHtml ? extractYouTubeTranscriptFromHtml(rawHtml) : '';
  let markdown =
    extracted?.markdown ||
    (typeof item.markdown === 'string' && item.markdown ? sanitizeInlineHtmlInMarkdown(item.markdown, finalUrl || undefined).trim() : '');
  if (wantMarkdown && transcript && !/^#{2,3}\s*Transcript\b/im.test(markdown)) {
    const cleanTranscript = sanitizeInlineHtmlInMarkdown(transcript, finalUrl || undefined).trim();
    if (cleanTranscript) {
      markdown = markdown ? `${markdown}\n\n## Transcript\n\n${cleanTranscript}` : `## Transcript\n\n${cleanTranscript}`;
    }
  }
  const fallbackTitle =
    !extracted && rawHtml
      ? (() => {
          let t: string | undefined;
          replacePairedHtmlElementsLinear(
            rawHtml,
            ['title'],
            (_f, _tag, _a, inner) => {
              if (t === undefined) t = cleanInlineHtml(inner);
              return '';
            },
            { maxChars: MAX_HTML_SCAN_CHARS, maxInnerChars: 4_096 },
          );
          return t;
        })()
      : undefined;
  const rawGoActionResults: Array<Record<string, unknown>> | undefined = Array.isArray(item.actionResults)
    ? (item.actionResults as Array<Record<string, unknown>>)
    : Array.isArray((item.interact as Record<string, unknown> | undefined)?.actionResults)
      ? ((item.interact as Record<string, unknown>).actionResults as Array<Record<string, unknown>>)
      : Array.isArray(item.actions)
        ? (item.actions as Array<Record<string, unknown>>)
        : undefined;

  const interactWarnings: string[] = [];
  const actionResults = actions.map((a, idx) => {
    const base = describeAction(a, idx, 'ok') as Record<string, unknown>;
    const goAct = rawGoActionResults?.[idx];
    if (goAct && typeof goAct === 'object') {
      if (typeof goAct.urlChanged === 'boolean') base.urlChanged = goAct.urlChanged;
      if (typeof goAct.domChanged === 'boolean') base.domChanged = goAct.domChanged;
      if (typeof goAct.beforeUrl === 'string' && goAct.beforeUrl.trim()) {
        const beforeCheck = validatePublicHttpsTargetUrl(goAct.beforeUrl, selfHost);
        if (beforeCheck.ok) base.beforeUrl = beforeCheck.normalized;
      }
      if (typeof goAct.afterUrl === 'string' && goAct.afterUrl.trim()) {
        const afterCheck = validatePublicHttpsTargetUrl(goAct.afterUrl, selfHost);
        if (afterCheck.ok) base.afterUrl = afterCheck.normalized;
      }
      if (typeof goAct.effect === 'string') base.effect = goAct.effect;
      if (typeof goAct.warning === 'string' && goAct.warning.trim()) interactWarnings.push(goAct.warning.trim());
    }
    const actType = String(a.type ?? '').toLowerCase();
    if ((actType === 'click' || actType === 'press') && base.urlChanged === false && base.domChanged === false) {
      base.effect = 'no_effect';
      const selDesc = typeof a.selector === 'string' ? ` on "${a.selector}"` : typeof a.key === 'string' ? ` ("${a.key}")` : '';
      interactWarnings.push(
        `Action ${idx} (${actType}${selDesc}) produced no URL or DOM change (no_effect). Verify the selector, element interactivity, or wait condition.`,
      );
    }
    return base;
  });

  const hasClickOrPress = actions.some((a) => {
    const t = String(a.type ?? '').toLowerCase();
    return t === 'click' || t === 'press';
  });
  const currentMdSha = await sha256HexString(markdown);
  const resumedCacheKey = parsedSession.agentSessionId && parsedSession.siteId ? `${parsedSession.siteId}:${parsedSession.agentSessionId}` : undefined;
  const prevSnap = resumedCacheKey ? interactSessionSnapshotCache.get(resumedCacheKey) : undefined;

  if (hasClickOrPress && interactWarnings.length === 0) {
    const beforeHtml =
      typeof item.beforeBody === 'string'
        ? item.beforeBody
        : typeof item.initialBody === 'string'
          ? item.initialBody
          : undefined;
    const beforeMd =
      typeof item.beforeMarkdown === 'string'
        ? item.beforeMarkdown.trim()
        : typeof item.initialMarkdown === 'string'
          ? item.initialMarkdown.trim()
          : beforeHtml
            ? extractHtmlDocument(beforeHtml, { baseUrl: normalizedUrl || finalUrl || undefined, onlyMainContent: true }).markdown.trim()
            : undefined;
    const topNoDomChange = item.domChanged === false && item.urlChanged === false;
    const sameAsBeforeTurn =
      prevSnap !== undefined &&
      (!finalUrl || finalUrl === prevSnap.url) &&
      currentMdSha === prevSnap.markdownSha;
    const sameAsInitialInSingleTurn =
      beforeMd !== undefined &&
      (!normalizedUrl || finalUrl === normalizedUrl) &&
      beforeMd === markdown.trim();
    if (topNoDomChange || sameAsBeforeTurn || sameAsInitialInSingleTurn) {
      interactWarnings.push(
        'Click/press actions completed, but neither finalUrl nor extracted Markdown changed. The target element may be non-interactive, hidden, or require a longer waitForMs/waitSelector.',
      );
    }
  }

  if (returnedAgentSid && !closeSession) {
    rememberInteractSessionSnapshot(`${actualSite}:${returnedAgentSid}`, finalUrl || normalizedUrl, currentMdSha);
  } else if (resumedCacheKey && closeSession) {
    interactSessionSnapshotCache.delete(resumedCacheKey);
  }

  const formatWarnings: Record<string, string> = {};
  if (requestedTranscript && !transcript) {
    formatWarnings.transcript = 'No timed caption/transcript segments found on page; returning extracted page Markdown.';
  }
  const pagedMd = sliceMarkdownWithOffsetAndMaxChars(markdown, interactOffset, interactMaxChars);
  const interactScreenshotArtifact =
    typeof item.screenshotBase64 === 'string' && item.screenshotBase64 && env.ARTIFACTS
      ? await storeScreenshotArtifactIfEnabled({
          screenshotBase64: item.screenshotBase64,
          bucket: env.ARTIFACTS,
          userId,
          privateOnly: true,
        })
      : undefined;

  const interactBlockedTrackers =
    typeof item.blockedTrackers === 'number' && Number.isFinite(item.blockedTrackers)
      ? Math.max(0, Math.floor(item.blockedTrackers))
      : 0;
  if (activeTracer) {
    setActiveSpanAttribute('browser.blocked_trackers', interactBlockedTrackers, activeTracer);
  }

  return {
    status: 200,
    via: fetchRes.via,
    body: {
      ok: true,
      ...privInteractField,
      via: fetchRes.via,
      ...(finalUrl ? { finalUrl } : {}),
      ...(interactRedirect.redirected ? interactRedirect : {}),
      status: item.status ?? 200,
      rendered: true,
      ...(publicSessionId ? { sessionId: publicSessionId } : {}),
      ...(closeSession ? { closed: true } : {}),
      actions: actionResults,
      ...(interactWarnings.length > 0 ? { warnings: [...new Set(interactWarnings)] } : {}),
      ...(wantMarkdown || (requestedTranscript && !transcript) ? { markdown: pagedMd.markdown } : {}),
      ...(hasInteractSlicePaging || pagedMd.truncated
        ? {
            truncated: pagedMd.truncated,
            offset: pagedMd.offset,
            totalChars: pagedMd.totalChars,
            nextOffset: pagedMd.nextOffset,
            remainingChars: pagedMd.remainingChars,
          }
        : {}),
      ...(requestedTranscript ? { transcript: transcript || null } : transcript ? { transcript } : {}),
      ...(Object.keys(formatWarnings).length > 0 ? { formatWarnings } : {}),
      ...(formats.includes('html') || formats.includes('rawHtml') ? { html: rawHtml } : {}),
      ...(typeof item.screenshotBase64 === 'string' && item.screenshotBase64
        ? {
            screenshotBase64: item.screenshotBase64,
            ...(interactScreenshotArtifact ?? {}),
          }
        : {}),
      metadata: {
        title: sanitizeScrapedMetadataField(
          extracted?.title || (typeof item.title === 'string' && item.title ? decodeHtmlEntities(item.title) : undefined) || fallbackTitle,
          512,
        ),
        blockedTrackers: interactBlockedTrackers,
      },
    },
  };
  };
  return activeTracer ? activeTracer.run(runInteract) : runInteract();
}
