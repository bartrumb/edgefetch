/**
 * Job & ATS Intelligence Layer (`hub/src/jobs.ts`):
 *
 * Thin WASI bridge & async scrape/search orchestrator delegating all pure-CPU domain logic —
 * compensation & workplace normalization, Schema.org `JobPosting` JSON-LD extraction, EEO/AI
 * boilerplate classification, JSON record chunking, 18+ ATS board/posting specs & parsers,
 * company/domain anti-spoofing filters, redirect filter-loss analysis, HTTP `402` (`x402`/`L402`)
 * payment-term sanitization, and ethical blocked suggestions — to Go `internal/jobs` via
 * `edgefetch-core.wasm` (`cmd/edgefetch-wasm/reactor_jobs.go`).
 */

import { getActiveCallerAuthContext } from './oauth';
import { getActiveRequestTracer, type RequestTracer, type TraceContext } from './otel';
import { compileSafeUserRegex } from './safe-input';
import type { OptionalStorageBindings } from './storage';
import { callCoreWasm, callCoreWasmRaw, callCoreWasmRawMetaPair } from './wasm-bridge';

export type PayPeriod = 'year' | 'month' | 'week' | 'day' | 'hour';
export type PayBasis = 'base' | 'ote' | 'total';
export type WorkplaceType = 'remote' | 'hybrid' | 'onsite' | 'unknown';
export type AtsBoardStatus = 'ok' | 'empty_board' | 'wrong_slug' | 'blocked_or_down' | 'not_found' | 'budget_exhausted';

export interface DiscoveredAtsBoard {
  domain?: string;
  platform: string;
  slug: string;
  boardUrl: string;
  discoveredFrom: string;
  boardStatus?: AtsBoardStatus;
  tried?: string[];
  total?: number;
  returned?: number;
  truncated?: boolean;
  nextCursor?: string;
}

export interface NormalizedPay {
  min: number | null;
  max: number | null;
  currency: string;
  period: PayPeriod;
  basis: PayBasis;
  raw?: string;
}

export interface StructuredJobPosting {
  title: string;
  hiringOrganization?: string;
  jobLocation?: string[];
  jobLocationType?: string;
  workplaceType: WorkplaceType;
  baseSalary?: NormalizedPay | null;
  pay?: NormalizedPay | null;
  datePosted?: string;
  validThrough?: string;
  employmentType?: string;
  url?: string;
  applyUrl?: string;
  source?: string;
}

export interface X402ExtraMetadata {
  name?: string;
  version?: string;
  decimals?: number;
}

export interface X402PaymentTerms {
  x402Version?: number;
  scheme?: string;
  price?: string;
  amount?: string;
  maxAmountRequired?: string;
  asset?: string;
  currency?: string;
  network?: string;
  payTo?: string;
  resource?: string;
  description?: string;
  invoice?: string;
  macaroon?: string;
  extra?: X402ExtraMetadata;
  [k: string]: unknown;
}

export interface BlockedSuggestion {
  reason: 'robots' | 'challenge' | 'content-signal' | 'payment_required';
  host?: string;
  signal?: string;
  price?: string;
  terms?: X402PaymentTerms;
  suggestion: string;
}

export interface RedirectAnalysis {
  redirected: boolean;
  redirectNote?: string;
  filtersMayBeLost?: boolean;
}

export type HtmlToMdFn = (html: string, baseUrl?: string) => { markdown: string; links: string[] };

export interface AtsFormattedDoc {
  title: string;
  description?: string;
  publishedTime?: string;
  markdown: string;
  links?: string[];
  jobPosting?: StructuredJobPosting;
  jobs?: StructuredJobRecord[];
  total?: number;
  returned?: number;
  truncated?: boolean;
  nextCursor?: string;
}

export interface AtsPreFetchSpec {
  id: string;
  fetchUrl: string;
  method: 'GET' | 'POST';
  requestBody?: string;
  contentType?: string;
  kind: 'json' | 'text';
  accept: string;
  format: (rawBody: string, originalUrl: string, htmlToMd?: HtmlToMdFn) => AtsFormattedDoc | null;
}

export interface StructuredJobRecord {
  title: string;
  company: string;
  url: string;
  applyUrl: string;
  workplaceType: WorkplaceType;
  locations: string[];
  pay: NormalizedPay | null;
  payUnknown?: boolean;
  matchedOn?: 'phrase' | 'all_tokens' | 'company_filter';
  postedAt: string | null;
  postedLabel?: string;
  source: string;
  employmentType?: string;
  snippet?: string;
}

export type VerifiedPostingStatus = 'live' | 'closed' | 'board_gone' | 'unknown';

export interface VerifiedJobResult {
  url: string;
  status: VerifiedPostingStatus;
  reason?: string;
  platform?: string;
  slug?: string;
  resolvedBoardUrl?: string;
  boardStatus?: AtsBoardStatus;
  similarOpenRoles?: Array<{ title: string; url: string }>;
}

export interface JobsToolPayload {
  mode?: unknown;
  verify?: unknown;
  urls?: unknown;
  query?: unknown;
  company?: unknown;
  domains?: unknown;
  remote?: unknown;
  locations?: unknown;
  minBase?: unknown;
  minBaseMode?: unknown;
  strictPay?: unknown;
  postedWithinDays?: unknown;
  limit?: unknown;
  offset?: unknown;
  cursor?: unknown;
  includeBuiltIn?: unknown;
  includePublicFeeds?: unknown;
  exclude?: unknown;
  target?: unknown;
  site?: unknown;
}

export interface AtsPostingIdentity {
  platform: string;
  slug: string;
  boardUrl: string;
  postingId: string;
  roleTokens: string[];
}

export const PUBLIC_JOB_FEEDS = [
  { id: 'weworkremotely' as const, url: 'https://weworkremotely.com/remote-jobs.rss' },
  { id: 'himalayas' as const, url: 'https://himalayas.app/jobs/api?limit=50' },
  { id: 'workingnomads' as const, url: 'https://www.workingnomads.com/api/exposed_jobs/' },
] as const;

export const MAX_JOBS_CONCURRENT_SCRAPES = 4;
export const MAX_JOBS_TOTAL_SCRAPES = 40;
export const JOBS_CACHE_TTL_MS = 5 * 60 * 1_000;
export const MAX_JOBS_CACHE_ENTRIES = 128;
export const JOBS_PER_ITEM_TIMEOUT_MS = 18_000;
/**
 * Wall-clock budget for one jobs call. MCP clients give up at 60 s; a broad (no company/domains) search spent ~4 s on
 * SERP queries and then ~19 s per candidate-board scrape, so it was cancelled at 60 s with nothing returned. After this
 * budget no new board scrape starts, in-flight scrapes are capped to the time left, and the call returns what it has.
 */
export const JOBS_WALL_BUDGET_MS = 40_000;
/**
 * Broad searches (no `company` / `domains`) scrape at most this many candidate boards/postings per call and hand back a
 * `continueCursor` for the rest, so results arrive in chunks well inside the client timeout instead of one call trying
 * to cover every candidate (~19 s per board scrape).
 */
export const JOBS_BROAD_CHUNK_URLS = 6;
const JOBS_CONTINUATION_PREFIX = 'jc1.';
const MAX_JOBS_CONTINUATION_URLS = 60;

/** Continuation state for a chunked broad jobs search: the query it belongs to and the candidates not yet scraped. */
export interface JobsContinuation {
  q: string;
  b: string[];
  p: string[];
}

function bytesToBase64Url(bytes: Uint8Array): string {
  let bin = '';
  for (const byte of bytes) bin += String.fromCharCode(byte);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function encodeJobsContinuation(state: JobsContinuation): string {
  return JOBS_CONTINUATION_PREFIX + bytesToBase64Url(new TextEncoder().encode(JSON.stringify(state)));
}

/**
 * Decodes a `continueCursor`. Returns null unless it is well-formed, belongs to `expectedQuery`, and every URL is an
 * `https://` URL (callers additionally keep only known multi-tenant ATS hosts), so a hand-made cursor cannot steer the
 * hub at arbitrary sites.
 */
export function decodeJobsContinuation(raw: string, expectedQuery: string): JobsContinuation | null {
  if (!raw.startsWith(JOBS_CONTINUATION_PREFIX) || raw.length > 16_384) return null;
  try {
    const b64 = raw.slice(JOBS_CONTINUATION_PREFIX.length).replace(/-/g, '+').replace(/_/g, '/');
    const bin = atob(b64 + '='.repeat((4 - (b64.length % 4)) % 4));
    const parsed = JSON.parse(new TextDecoder().decode(Uint8Array.from(bin, (c) => c.charCodeAt(0)))) as Partial<JobsContinuation>;
    if (!parsed || parsed.q !== expectedQuery || !Array.isArray(parsed.b) || !Array.isArray(parsed.p)) return null;
    const clean = (list: unknown[]): string[] =>
      list.filter((u): u is string => typeof u === 'string' && u.length <= 2_048 && u.startsWith('https://')).slice(0, MAX_JOBS_CONTINUATION_URLS);
    return { q: parsed.q, b: clean(parsed.b), p: clean(parsed.p) };
  } catch {
    return null;
  }
}

const MAX_JOBS_QUERY_CHARS = 256;
const REMOTE_LOCATION_TOKENS = new Set(['remote', 'anywhere', 'work from home', 'wfh']);

// ── Pure-CPU Domain Wrappers (Delegated to Go `internal/jobs` via WASI) ─────────────────────────

export function inferPayBasis(labelOrContext: string): PayBasis {
  return callCoreWasm<{ basis: PayBasis }>('jobs_infer_pay_basis', {
    context: String(labelOrContext ?? ''),
  }).basis;
}

export function normalizePeriod(rawPeriod: unknown): PayPeriod {
  return callCoreWasm<{ period: PayPeriod }>('jobs_normalize_period', {
    period: typeof rawPeriod === 'string' ? rawPeriod : '',
  }).period;
}

export function formatNormalizedPay(pay: NormalizedPay | null | undefined): string {
  if (!pay || (pay.min === null && pay.max === null)) return '';
  return callCoreWasm<{ out: string }>('jobs_format_pay', { pay }).out;
}

export function parsePayFromText(text: string): NormalizedPay | null {
  if (!text) return null;
  const bounded = text.length > 65_536 ? text.slice(0, 65_536) : text;
  return callCoreWasm<{ pay: NormalizedPay | null }>('jobs_parse_pay', { text: bounded }).pay ?? null;
}

export function inferWorkplaceType(text: string): WorkplaceType {
  return callCoreWasm<{ workplaceType: WorkplaceType }>('jobs_infer_workplace', {
    text: String(text ?? ''),
  }).workplaceType;
}

function inferWorkdayWorkplaceType(remoteType: string, locText: string, title: string): WorkplaceType {
  return callCoreWasm<{ workplaceType: WorkplaceType }>('jobs_infer_workplace', {
    workday: true,
    remoteType,
    locText,
    title,
  }).workplaceType;
}

export function inspectRawJobPostingJsonLdLinear(rawHtml: string): {
  descriptionHtml: string;
  rawDecodedStringsForPiCheck: string;
} {
  if (!rawHtml || !/ld\+json/i.test(rawHtml)) return { descriptionHtml: '', rawDecodedStringsForPiCheck: '' };
  return callCoreWasmRaw<{ descriptionHtml: string; rawDecodedStringsForPiCheck: string }>(
    'jobs_inspect_jsonld',
    null,
    rawHtml,
  );
}

export function extractJobPostingJsonLd(
  rawHtml: string,
  baseUrl?: string,
  fallbackProse = '',
): StructuredJobPosting | null {
  if (!rawHtml || !/ld\+json/i.test(rawHtml)) return null;
  const boundedProse = fallbackProse.length > 65_536 ? fallbackProse.slice(0, 65_536) : fallbackProse;
  return (
    callCoreWasmRaw<{ jobPosting: StructuredJobPosting | null }>(
      'jobs_extract_jsonld',
      { baseUrl: baseUrl ?? '', fallbackProse: boundedProse },
      rawHtml,
    ).jobPosting ?? null
  );
}

export function formatJobPostingHeaderMarkdown(jp: StructuredJobPosting): string {
  return callCoreWasm<{ markdown: string }>('jobs_format_header_md', { jobPosting: jp }).markdown;
}

export function isJobLegalBoilerplateChunk(text: string, heading = ''): boolean {
  return callCoreWasm<{ boilerplate: boolean }>('jobs_is_legal_boilerplate', {
    text: String(text ?? ''),
    heading: String(heading ?? ''),
  }).boilerplate;
}

export function salvageAshbyBoardFromTruncatedJson(raw: string): {
  salvaged: true;
  organizationName?: string;
  jobs: Array<Record<string, unknown>>;
} | null {
  if (!raw) return null;
  return (
    callCoreWasmRaw<{
      salvaged: { salvaged: true; organizationName?: string; jobs: Array<Record<string, unknown>> } | null;
    }>('jobs_salvage_ashby', null, raw).salvaged ?? null
  );
}

export function resolveAtsPreFetchSpec(urlStr: string, opts?: { liteBoard?: boolean }): AtsPreFetchSpec | null {
  if (!urlStr) return null;
  let effectiveUrl = String(urlStr);
  if (opts?.liteBoard) {
    try {
      const u = new URL(effectiveUrl);
      if (u.hostname.toLowerCase().endsWith('.greenhouse.io') && !u.searchParams.has('content')) {
        u.searchParams.set('content', 'false');
        effectiveUrl = u.toString();
      }
    } catch {
      // ignore
    }
  }
  const spec = callCoreWasm<{
    spec: Omit<AtsPreFetchSpec, 'format'> | null;
  }>('jobs_resolve_ats_spec', { url: effectiveUrl }).spec;
  if (!spec) return null;
  return {
    ...spec,
    format: (rawBody: string, originalUrl: string, _htmlToMd?: HtmlToMdFn) => {
      if (typeof rawBody !== 'string' || !rawBody) return null;
      return (
        callCoreWasmRaw<{ result: AtsFormattedDoc | null }>(
          'jobs_format_ats',
          { specUrl: effectiveUrl, origUrl: String(originalUrl || urlStr), nowMs: Date.now() },
          rawBody,
        ).result ?? null
      );
    },
  };
}

export function parsePublicJobFeedRecords(
  feedId: 'weworkremotely' | 'himalayas' | 'workingnomads',
  rawBody: string,
): StructuredJobRecord[] {
  if (!rawBody) return [];
  return (
    callCoreWasmRaw<{ records: StructuredJobRecord[] }>('jobs_parse_public_feed', { feedId }, rawBody).records ?? []
  );
}

export function detectWorkdayRedirectStub(rawBody: string, baseUrl: string): { redirectUrl: string } | null {
  if (!rawBody || rawBody.length > 65_536) return null;
  return callCoreWasm<{ stub: { redirectUrl: string } | null }>('jobs_detect_workday_stub', {
    rawBody,
    baseUrl: String(baseUrl ?? ''),
  }).stub;
}

export function hasExecutableScriptTag(rawHtml: string): boolean {
  if (!rawHtml) return false;
  return callCoreWasmRaw<{ hasScript: boolean }>('jobs_has_executable_script', null, rawHtml).hasScript;
}

export function isThinScriptedPage(rawHtml: string, extractedMarkdown: string): boolean {
  if (!rawHtml || !hasExecutableScriptTag(rawHtml)) return false;
  const md = String(extractedMarkdown ?? '');
  const mdBounded = md.length > 524_288 ? md.slice(0, 524_288) : md;
  return callCoreWasmRawMetaPair<{ thin: boolean }>(
    'jobs_is_thin_scripted',
    {},
    '<script>1</script>',
    mdBounded,
  ).thin;
}

export function chunkJsonRecords(params: {
  rawBody: string;
  contentType?: unknown;
  url?: string;
  jsonFilter?: string;
  htmlToMd: HtmlToMdFn;
}): {
  title: string;
  totalRecords: number;
  matchedRecords: number;
  chunks: Array<{ ordinal: number; heading: string; text: string; recordId?: string }>;
  markdown: string;
} | null {
  if (typeof params.rawBody !== 'string' || !params.rawBody) return null;
  let effectiveFilter = params.jsonFilter ?? '';
  if (effectiveFilter) {
    for (const rawPart of effectiveFilter.split(/\s*(?:&&|,)\s*/)) {
      const m = /^([A-Za-z0-9_.-]+)\s*(~=|~)\s*(.+)$/.exec(rawPart.trim());
      if (!m) continue;
      const val = m[3]!.trim().replace(/^(['"])([\s\S]*)\1$/, '$2');
      if (!compileSafeUserRegex(val, 'i') && (/[\\^$.*+?()[\]{}|]/.test(val) || val.length > 256)) {
        effectiveFilter = `${m[1]}~=(a+)+`;
        break;
      }
    }
  }
  return (
    callCoreWasmRaw<{
      result: {
        title: string;
        totalRecords: number;
        matchedRecords: number;
        chunks: Array<{ ordinal: number; heading: string; text: string; recordId?: string }>;
        markdown: string;
      } | null;
    }>(
      'jobs_chunk_json_records',
      {
        contentType: typeof params.contentType === 'string' ? params.contentType : '',
        url: params.url ?? '',
        jsonFilter: effectiveFilter,
      },
      params.rawBody,
    ).result ?? null
  );
}

export function analyzeUrlRedirect(requestedUrl: string, finalUrl?: string): RedirectAnalysis {
  if (!finalUrl || !requestedUrl) return { redirected: false };
  return callCoreWasm<{ analysis: RedirectAnalysis }>('jobs_analyze_redirect', {
    requestedUrl: String(requestedUrl),
    finalUrl: String(finalUrl),
  }).analysis;
}

function extractPaymentHeadersRecord(
  headers?: Headers | Record<string, string | undefined>,
): Record<string, string> | undefined {
  if (!headers) return undefined;
  const out: Record<string, string> = {};
  let count = 0;
  if (typeof (headers as Headers).get === 'function') {
    for (const k of ['payment-required', 'x-payment-required', 'www-authenticate']) {
      const v = (headers as Headers).get(k);
      if (typeof v === 'string' && v.trim()) {
        out[k] = v.trim();
        count++;
      }
    }
  } else {
    for (const [k, v] of Object.entries(headers as Record<string, string | undefined>)) {
      const low = k.toLowerCase();
      if (
        (low === 'payment-required' || low === 'x-payment-required' || low === 'www-authenticate') &&
        typeof v === 'string' &&
        v.trim()
      ) {
        out[low] = v.trim();
        count++;
      }
    }
  }
  return count > 0 ? out : undefined;
}

export function parseX402PaymentTerms(
  status: unknown,
  headers?: Headers | Record<string, string | undefined>,
  rawBody?: string,
  expectedHost?: string,
): { price?: string; terms: X402PaymentTerms } | null {
  if (status !== 402) return null;
  return (
    callCoreWasm<{ result: { price?: string; terms: X402PaymentTerms } | null }>('jobs_parse_x402', {
      status: 402,
      headers: extractPaymentHeadersRecord(headers),
      rawBody: typeof rawBody === 'string' && rawBody.length <= 65_536 ? rawBody : '',
      expectedHost: expectedHost ?? '',
    }).result ?? null
  );
}

export function buildBlockedInfo(
  urlStr: string,
  outcome?: unknown,
  problem?: unknown,
  status?: unknown,
  paymentContext?: { headers?: Headers | Record<string, string | undefined>; rawBody?: string },
): BlockedSuggestion | null {
  const numStatus = typeof status === 'number' && Number.isFinite(status) ? status : 0;
  const rawBody = paymentContext?.rawBody;
  return (
    callCoreWasm<{ blocked: BlockedSuggestion | null }>('jobs_build_blocked', {
      url: String(urlStr ?? ''),
      outcome: typeof outcome === 'string' ? outcome : '',
      problem: typeof problem === 'string' ? problem : '',
      status: numStatus,
      headers: extractPaymentHeadersRecord(paymentContext?.headers),
      rawBody: typeof rawBody === 'string' && rawBody.length <= 65_536 ? rawBody : '',
    }).blocked ?? null
  );
}

export function classifyAtsBoardStatus(params: {
  httpStatus: number;
  requestedUrl: string;
  finalUrl?: string;
  contentState?: string;
  jobCount?: number;
}): AtsBoardStatus {
  return callCoreWasm<{ status: AtsBoardStatus }>('jobs_classify_board_status', params).status;
}

export function discoverAtsBoardsFromHtml(params: {
  sourceUrl: string;
  finalUrl?: string;
  rawHtml?: string;
  links?: string[];
}): DiscoveredAtsBoard[] {
  return (
    callCoreWasmRaw<{ boards: DiscoveredAtsBoard[] }>(
      'jobs_discover_boards',
      {
        sourceUrl: params.sourceUrl,
        finalUrl: params.finalUrl ?? '',
        links: (params.links ?? []).slice(0, 500),
      },
      String(params.rawHtml ?? ''),
    ).boards ?? []
  );
}

export function parseAtsPostingIdentity(urlStr: string): AtsPostingIdentity | null {
  if (!urlStr) return null;
  return callCoreWasm<{ identity: AtsPostingIdentity | null }>('jobs_parse_posting_identity', {
    url: String(urlStr),
  }).identity;
}

export function expandCompanyFilterTokens(rawCompany: string): string[] {
  if (!rawCompany) return [];
  const bounded = rawCompany.length > 512 ? rawCompany.slice(0, 512) : rawCompany;
  return callCoreWasm<{ tokens: string[] }>('jobs_expand_company_tokens', { company: bounded }).tokens ?? [];
}

export function matchesAllowedCompanyOrDomain(
  job: StructuredJobRecord,
  allowedTokens: Set<string>,
  allowedBoardPrefixes: string[],
): boolean {
  const cappedCompany = typeof job.company === 'string' ? (job.company.length > 512 ? job.company.slice(0, 512) : job.company) : '';
  const cappedUrl = typeof job.url === 'string' ? (job.url.length > 2048 ? job.url.slice(0, 2048) : job.url) : '';
  return callCoreWasm<{ matched: boolean }>('jobs_match_company', {
    job: {
      title: '',
      company: cappedCompany,
      url: cappedUrl,
      applyUrl: cappedUrl,
      workplaceType: job.workplaceType ?? 'unknown',
      locations: [],
      pay: null,
      postedAt: null,
      source: job.source ?? '',
    },
    allowedTokens: [...allowedTokens].slice(0, 128).map((t) => (t.length > 256 ? t.slice(0, 256) : t)),
    allowedBoardPrefixes: allowedBoardPrefixes.slice(0, 64),
  }).matched;
}

export function parseSmartRecruitersBoardScrape(origUrl: string, body: Record<string, unknown>): StructuredJobRecord[] {
  const md = typeof body.markdown === 'string' ? body.markdown : '';
  const rawHtml = typeof body.rawHtml === 'string' ? body.rawHtml : typeof body.html === 'string' ? body.html : '';
  const links = Array.isArray(body.links) ? (body.links as string[]) : [];
  return (
    callCoreWasm<{ records: StructuredJobRecord[] }>('jobs_parse_smartrecruiters_board', {
      origUrl: String(origUrl ?? ''),
      markdown: md,
      rawHtml,
      links,
    }).records ?? []
  );
}

// ── Internal WASI URL & Matching Helpers Used by `executeJobsCall` ──────────────────────────────

function classifyFullBoardKey(urlStr: string): {
  key: string;
  platform: string;
  slug: string;
  isBoard: boolean;
  boardUrl: string;
} | null {
  return callCoreWasm<{
    info: { key: string; platform: string; slug: string; isBoard: boolean; boardUrl: string } | null;
  }>('jobs_url_helpers', { kind: 'classify_full_board', url: urlStr }).info;
}

function isSmartRecruitersBoardUrl(urlStr: string): { org: string; boardUrl: string } | null {
  return callCoreWasm<{ info: { org: string; boardUrl: string } | null }>('jobs_url_helpers', {
    kind: 'is_smartrecruiters_board',
    url: urlStr,
  }).info;
}

function inferCompanyFromAtsUrl(urlStr: string): string {
  return callCoreWasm<{ company: string }>('jobs_url_helpers', { kind: 'infer_company_ats', url: urlStr }).company;
}

function isKnownMultiTenantAtsHost(host: string): boolean {
  return callCoreWasm<{ ok: boolean }>('jobs_url_helpers', { kind: 'is_multitenant_ats', host }).ok;
}

function extractRegistrableBrandInfo(hostname: string): {
  sld: string;
  tld: string;
  registrableDomain: string;
  joinedRegistrable: string;
  isVettedTld: boolean;
} | null {
  return callCoreWasm<{
    info: { sld: string; tld: string; registrableDomain: string; joinedRegistrable: string; isVettedTld: boolean } | null;
  }>('jobs_url_helpers', { kind: 'registrable_brand', host: hostname }).info;
}

function isValidAtsSlug(slug: string): boolean {
  return callCoreWasm<{ ok: boolean }>('jobs_url_helpers', { kind: 'valid_ats_slug', slug }).ok;
}

function isValidAshbySlug(slug: string): boolean {
  return callCoreWasm<{ ok: boolean }>('jobs_url_helpers', { kind: 'valid_ashby_slug', slug }).ok;
}

function normalizeDottedCorporateAbbreviations(raw: string): string {
  return callCoreWasm<{ out: string }>('jobs_url_helpers', { kind: 'norm_corp_abbrev', jobCompany: raw }).out;
}

function matchesAtsTenantSlugAgainstToken(
  rawSlug: string,
  tok: string,
  opts?: { host?: string; jobCompany?: string; segmentedTokens?: Set<string>; allowAshbySpaces?: boolean },
): boolean {
  return callCoreWasm<{ ok: boolean }>('jobs_url_helpers', {
    kind: 'match_tenant_slug',
    slug: rawSlug,
    token: tok,
    host: opts?.host ?? '',
    jobCompany: opts?.jobCompany ?? '',
    segmentedTokens: opts?.segmentedTokens ? [...opts.segmentedTokens] : [],
    allowAshbySpaces: opts?.allowAshbySpaces === true,
  }).ok;
}

function findSimilarRoles(
  openRoles: Array<{ title: string; url: string }>,
  roleTokens: string[],
): Array<{ title: string; url: string }> {
  if (openRoles.length === 0 || roleTokens.length === 0) return [];
  return (
    callCoreWasm<{ roles: Array<{ title: string; url: string }> }>('jobs_find_similar_roles', {
      openRoles: openRoles.slice(0, 500),
      roleTokens: roleTokens.slice(0, 32),
    }).roles ?? []
  );
}

function isKnownAtsPostingHostWithUnresolvedSlug(urlStr: string): { platform: string; rawSlug: string } | null {
  return callCoreWasm<{ info: { platform: string; rawSlug: string } | null }>('jobs_unresolved_ats_host', {
    url: urlStr,
  }).info;
}

function buildCompactSlugFallbackBoards(grp: {
  platform: string;
  slug: string;
  boardUrl: string;
}): Array<{ slug: string; boardUrl: string }> {
  if (!/\s/.test(grp.slug)) return [];
  return (
    callCoreWasm<{ fallbacks: Array<{ slug: string; boardUrl: string }> }>('jobs_compact_slug_fallbacks', {
      platform: grp.platform,
      slug: grp.slug,
    }).fallbacks ?? []
  );
}

function canonicalJobKey(company: string, title: string): string {
  return callCoreWasm<{ key: string }>('jobs_url_helpers', {
    kind: 'canonical_key',
    jobCompany: company,
    title,
  }).key;
}

function extractWorkdayReqId(uStr: string): string {
  return callCoreWasm<{ reqId: string }>('jobs_url_helpers', { kind: 'workday_req_id', url: uStr }).reqId;
}

function matchesJobQueryRelevance(
  title: string,
  snippet: string | undefined,
  query: string,
): 'phrase' | 'all_tokens' | null {
  return callCoreWasm<{ rel: 'phrase' | 'all_tokens' | null }>('jobs_url_helpers', {
    kind: 'query_relevance',
    title,
    snippet: snippet ?? '',
    query,
  }).rel;
}

function matchesGeoLocationsFilter(jobLocations: string[], geoFilters: string[]): boolean {
  if (jobLocations.length === 0 || geoFilters.length === 0) return false;
  return callCoreWasm<{ ok: boolean }>('jobs_url_helpers', {
    kind: 'geo_filter',
    locations: jobLocations.slice(0, 32),
    geoFilters: geoFilters.slice(0, 32),
  }).ok;
}

function isJobLabelKnownStale(label: string | undefined, maxDays: number): boolean {
  if (!label) return false;
  return callCoreWasm<{ stale: boolean }>('jobs_url_helpers', {
    kind: 'label_stale',
    label,
    maxDays,
  }).stale;
}

// ── Per-Isolate TTL Cache & In-Flight Deduplication ─────────────────────────────────────────────

interface JobsScrapeResponse {
  status: number;
  body: Record<string, unknown>;
}

interface JobsCachePartition {
  lru: Map<string, { expiresAt: number; value: JobsScrapeResponse }>;
  inFlight: Map<string, Promise<JobsScrapeResponse>>;
}

const SHARED_JOBS_CACHE_PARTITION: JobsCachePartition = {
  lru: new Map(),
  inFlight: new Map(),
};
const TEST_SCOPED_JOBS_PARTITIONS = new WeakMap<object, JobsCachePartition>();

export function resetJobsCacheForTests(): void {
  SHARED_JOBS_CACHE_PARTITION.lru.clear();
  SHARED_JOBS_CACHE_PARTITION.inFlight.clear();
}

function resolveJobsCachePartition(
  env: (OptionalStorageBindings & Record<string, unknown>) | undefined,
  rawExecuteScrape: unknown,
): JobsCachePartition {
  if (
    env &&
    ('AGENT_HUB' in env ||
      'CALLER_TOKEN' in env ||
      'META' in env ||
      'ARTIFACTS' in env ||
      'SERPER_API_KEY' in env ||
      'SEARXNG_URL' in env ||
      'SAFE_PUBLIC_FETCH' in env ||
      env.JOBS_SHARED_CACHE === true)
  ) {
    return SHARED_JOBS_CACHE_PARTITION;
  }
  const keyObj =
    env && typeof env === 'object' && Object.keys(env).length > 0
      ? (env as object)
      : (rawExecuteScrape as object);
  if (!keyObj || (typeof keyObj !== 'object' && typeof keyObj !== 'function')) {
    return SHARED_JOBS_CACHE_PARTITION;
  }
  let part = TEST_SCOPED_JOBS_PARTITIONS.get(keyObj);
  if (!part) {
    part = { lru: new Map(), inFlight: new Map() };
    TEST_SCOPED_JOBS_PARTITIONS.set(keyObj, part);
  }
  return part;
}

function cloneJobsScrapeResponse(res: JobsScrapeResponse): JobsScrapeResponse {
  const body = res.body ?? {};
  return {
    status: res.status,
    body: {
      ...body,
      ...(Array.isArray(body.jobs)
        ? {
            jobs: (body.jobs as StructuredJobRecord[]).map((j) => ({
              ...j,
              locations: Array.isArray(j.locations) ? [...j.locations] : [],
              ...(j.pay ? { pay: { ...j.pay } } : {}),
            })),
          }
        : {}),
      ...(Array.isArray(body.links) ? { links: [...(body.links as string[])] } : {}),
    },
  };
}

function buildJobsScrapeCacheKey(args: Record<string, unknown>, callerCacheScope = 'public|public'): string | null {
  const rawUrl = typeof args.url === 'string' ? args.url.trim() : '';
  if (!rawUrl.startsWith('https://')) return null;
  let canonicalUrl = rawUrl;
  try {
    const u = new URL(rawUrl);
    u.hash = '';
    const host = u.hostname.toLowerCase();
    const parts = u.pathname.split('/').filter(Boolean);
    if (host === 'jobs.ashbyhq.com' && parts.length === 1 && !u.searchParams.has('offset')) {
      canonicalUrl = `https://jobs.ashbyhq.com/${encodeURIComponent(decodeURIComponent(parts[0]!).toLowerCase())}`;
    } else if (
      (host === 'boards.greenhouse.io' || host === 'job-boards.greenhouse.io') &&
      parts.length === 1 &&
      !u.searchParams.has('offset')
    ) {
      const ghLite = u.searchParams.get('content')?.toLowerCase() === 'false';
      canonicalUrl = ghLite
        ? `https://job-boards.greenhouse.io/${parts[0]!.toLowerCase()}?content=false`
        : `https://job-boards.greenhouse.io/${parts[0]!.toLowerCase()}`;
    } else if (host === 'jobs.lever.co' && parts.length === 1 && !u.searchParams.has('offset')) {
      canonicalUrl = `https://jobs.lever.co/${parts[0]!.toLowerCase()}`;
    } else if (host === 'ats.rippling.com' && parts.length >= 1) {
      const idx = /^[a-z]{2}(?:-[A-Za-z]{2,4})?$/.test(parts[0]!) && parts.length >= 2 ? 1 : 0;
      const org = parts[idx];
      const rest = parts.slice(idx + 1);
      if (org && (rest.length === 0 || (rest.length === 1 && rest[0] === 'jobs'))) {
        canonicalUrl = `https://ats.rippling.com/${org.toLowerCase()}/jobs`;
      } else {
        canonicalUrl = u.toString();
      }
    } else {
      canonicalUrl = u.toString();
    }
  } catch {
    return null;
  }
  const fmts = Array.isArray(args.formats) ? [...(args.formats as string[])].sort().join(',') : 'markdown';
  const siteKey = typeof args.site === 'string' ? args.site.trim().toLowerCase() : '';
  const targetKey = typeof args.target === 'string' ? args.target.trim().toLowerCase() : '';
  const liteSuffix = args.atsLiteBoard === true ? '|lite' : '';
  return `${callerCacheScope}|${canonicalUrl}|${fmts}|${targetKey}|${siteKey}${liteSuffix}`;
}

function readJobsScrapeCache(partition: JobsCachePartition, key: string, now = Date.now()): JobsScrapeResponse | null {
  const hit = partition.lru.get(key);
  if (!hit) return null;
  if (hit.expiresAt <= now) {
    partition.lru.delete(key);
    return null;
  }
  partition.lru.delete(key);
  partition.lru.set(key, hit);
  return cloneJobsScrapeResponse(hit.value);
}

const MAX_JOBS_CACHE_TOTAL_RECORDS = 8_000;

function approxCachedJobsCount(res: JobsScrapeResponse): number {
  const jobs = res.body?.jobs;
  return Array.isArray(jobs) ? jobs.length : 1;
}

function writeJobsScrapeCache(partition: JobsCachePartition, key: string, value: JobsScrapeResponse, now = Date.now()): void {
  if (value.status !== 200 || value.body?.ok !== true) return;
  let totalRecords = 0;
  for (const [k, v] of partition.lru.entries()) {
    if (v.expiresAt <= now) {
      partition.lru.delete(k);
    } else if (k !== key) {
      totalRecords += approxCachedJobsCount(v.value);
    }
  }
  partition.lru.delete(key);
  const cloned = cloneJobsScrapeResponse(value);
  totalRecords += approxCachedJobsCount(cloned);
  partition.lru.set(key, { expiresAt: now + JOBS_CACHE_TTL_MS, value: cloned });
  while (partition.lru.size > MAX_JOBS_CACHE_ENTRIES || (partition.lru.size > 1 && totalRecords > MAX_JOBS_CACHE_TOTAL_RECORDS)) {
    const oldest = partition.lru.keys().next().value;
    if (oldest === undefined) break;
    const evicted = partition.lru.get(oldest);
    if (evicted) totalRecords -= approxCachedJobsCount(evicted.value);
    partition.lru.delete(oldest);
  }
}

function withJobsItemTimeout(promise: Promise<JobsScrapeResponse>, timeoutMs = JOBS_PER_ITEM_TIMEOUT_MS): Promise<JobsScrapeResponse> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeoutPromise = new Promise<JobsScrapeResponse>((resolve) => {
    timer = setTimeout(() => {
      resolve({ status: 504, body: { ok: false, error: 'jobs_item_timeout', message: 'ATS enrichment timed out' } });
    }, timeoutMs);
  });
  return Promise.race([
    promise.catch(() => ({ status: 502, body: { ok: false, error: 'jobs_item_failed' } })),
    timeoutPromise,
  ]).finally(() => {
    if (timer !== undefined) clearTimeout(timer);
  });
}

function isClosedSchemeDowngradeResult(urlStr: string, res: JobsScrapeResponse | null | undefined): boolean {
  if (!res) return false;
  const body = res.body ?? {};
  const blockedObj = body.blocked as Record<string, unknown> | undefined;
  const prob = typeof body.problem === 'string' ? body.problem : typeof body.message === 'string' ? body.message : '';
  const isDowngrade =
    blockedObj?.reason === 'scheme_downgrade' ||
    body.blockedReason === 'scheme_downgrade' ||
    body.outcome === 'scheme_downgrade' ||
    /scheme_downgrade|https-to-http\s+redirect\s+downgrade/i.test(prob);
  if (!isDowngrade) return false;
  return /rippling\.com/i.test(urlStr) || Boolean(parseAtsPostingIdentity(urlStr));
}

// ── Async Batch Verification & Multi-Wave ATS Search Orchestration ──────────────────────────────

async function executeJobsVerifyMode(params: {
  urls: string[];
  payload: JobsToolPayload;
  executeScrape: (args: Record<string, unknown>) => Promise<{ status: number; body: Record<string, unknown> }>;
  tracer?: RequestTracer | TraceContext;
  didExhaustBudget?: () => boolean;
}): Promise<{ status: number; body: Record<string, unknown> }> {
  const { urls, payload, executeScrape, didExhaustBudget } = params;
  const activeTracer = getActiveRequestTracer(params.tracer);
  const resolvedAdapterIds = new Set<string>();
  const parsedItems = urls.slice(0, 100).map((rawUrl) => ({
    url: rawUrl,
    identity: parseAtsPostingIdentity(rawUrl),
  }));

  const boardGroups = new Map<string, { boardUrl: string; platform: string; slug: string }>();
  for (const it of parsedItems) {
    if (!it.identity) continue;
    const key = `${it.identity.platform}:${it.identity.slug.toLowerCase()}`;
    if (!boardGroups.has(key)) {
      boardGroups.set(key, {
        boardUrl: it.identity.boardUrl,
        platform: it.identity.platform,
        slug: it.identity.slug,
      });
    }
  }

  interface VerifyBoardSnapshot {
    boardStatus: AtsBoardStatus;
    failureReason?: string;
    resolvedSlug?: string;
    resolvedBoardUrl?: string;
    truncated: boolean;
    boardIncomplete: boolean;
    openLinksLower: string[];
    openRoles: Array<{ title: string; url: string }>;
  }

  const boardSnapshots = new Map<string, VerifyBoardSnapshot>();

  const buildSnapshotFromScrape = (
    grp: { boardUrl: string; platform: string; slug: string },
    sc: { status: number; body: Record<string, unknown> } | null,
  ): VerifyBoardSnapshot => {
    if (!sc || sc.status !== 200 || sc.body?.ok !== true) {
      const hitBudget = sc?.body?.error === 'jobs_scrape_budget_exceeded';
      const hitTimeout = sc?.body?.error === 'jobs_item_timeout' || sc?.status === 504;
      const upstreamStatus =
        typeof sc?.body?.status === 'number' && sc.body.status > 0 ? sc.body.status : (sc?.status ?? 0);
      const bStatus: AtsBoardStatus = hitBudget
        ? 'budget_exhausted'
        : classifyAtsBoardStatus({
            httpStatus: upstreamStatus,
            requestedUrl: grp.boardUrl,
            finalUrl: typeof sc?.body?.finalUrl === 'string' ? sc.body.finalUrl : undefined,
          });
      const failureReason = hitBudget
        ? 'budget_exhausted'
        : hitTimeout
          ? 'timeout'
          : bStatus === 'wrong_slug'
            ? 'unresolved_slug'
            : 'board_blocked_or_down';
      return {
        boardStatus: bStatus,
        failureReason,
        truncated: false,
        boardIncomplete: false,
        openLinksLower: [],
        openRoles: [],
      };
    }

    const cState = typeof sc.body.contentState === 'string' ? sc.body.contentState : undefined;
    const rawJobs = Array.isArray(sc.body.jobs) ? (sc.body.jobs as StructuredJobRecord[]) : [];
    const rawRecords = Array.isArray(sc.body.records) ? (sc.body.records as Array<Record<string, unknown>>) : [];
    const rawLinks = Array.isArray(sc.body.links) ? (sc.body.links as string[]) : [];

    const openRoles: Array<{ title: string; url: string }> = [];
    for (const rj of rawJobs) {
      if (rj?.title && rj?.url) openRoles.push({ title: rj.title, url: rj.url });
    }
    if (openRoles.length === 0) {
      for (const rc of rawRecords) {
        if (typeof rc?.title === 'string' && typeof rc?.url === 'string') {
          openRoles.push({ title: rc.title, url: rc.url });
        }
      }
    }

    const openLinksLower = [
      ...rawLinks.map((l) => String(l).toLowerCase()),
      ...openRoles.map((r) => r.url.toLowerCase()),
    ];
    const bStatus = classifyAtsBoardStatus({
      httpStatus: sc.status,
      requestedUrl: grp.boardUrl,
      finalUrl: typeof sc.body.finalUrl === 'string' ? sc.body.finalUrl : undefined,
      contentState: cState,
      jobCount: Math.max(openRoles.length, rawLinks.length),
    });
    const totalNum = typeof sc.body.total === 'number' && Number.isFinite(sc.body.total) ? sc.body.total : undefined;
    const extId = typeof sc.body.extractorId === 'string' ? sc.body.extractorId : '';
    const resolvedAts = extId || resolveAtsPreFetchSpec(grp.boardUrl)?.id || grp.platform;
    if (resolvedAts) resolvedAdapterIds.add(resolvedAts);
    const linksCoverFullBoard =
      totalNum !== undefined &&
      rawLinks.length >= totalNum &&
      extId !== 'workday-board' &&
      extId !== 'icims';

    return {
      boardStatus: bStatus,
      ...(bStatus === 'wrong_slug'
        ? { failureReason: 'unresolved_slug' }
        : bStatus === 'blocked_or_down'
          ? { failureReason: 'board_blocked_or_down' }
          : {}),
      truncated: sc.body.truncated === true,
      boardIncomplete: sc.body.truncated === true && !linksCoverFullBoard,
      openLinksLower,
      openRoles,
    };
  };

  const groupEntries = [...boardGroups.entries()];
  for (let i = 0; i < groupEntries.length; i += 2) {
    const batch = groupEntries.slice(i, i + 2);
    const outs = await Promise.all(
      batch.map(([, grp]) =>
        executeScrape({
          url: grp.boardUrl,
          renderMode: 'auto',
          ephemeral: true,
          atsLiteBoard: true,
          formats: ['markdown', 'links'],
          ...(payload.target ? { target: payload.target } : {}),
          ...(payload.site ? { site: payload.site } : {}),
        }).catch(() => null),
      ),
    );
    for (let j = 0; j < batch.length; j++) {
      const [key, grp] = batch[j]!;
      let snap = buildSnapshotFromScrape(grp, outs[j] ?? null);
      if ((snap.boardStatus === 'wrong_slug' || snap.boardStatus === 'blocked_or_down') && /\s/.test(grp.slug)) {
        for (const fb of buildCompactSlugFallbackBoards(grp)) {
          const fbRes = await executeScrape({
            url: fb.boardUrl,
            renderMode: 'auto',
            ephemeral: true,
            atsLiteBoard: true,
            formats: ['markdown', 'links'],
            ...(payload.target ? { target: payload.target } : {}),
            ...(payload.site ? { site: payload.site } : {}),
          }).catch(() => null);
          const fbSnap = buildSnapshotFromScrape({ ...grp, slug: fb.slug, boardUrl: fb.boardUrl }, fbRes);
          if (fbSnap.boardStatus === 'ok' || fbSnap.boardStatus === 'empty_board') {
            snap = { ...fbSnap, resolvedSlug: fb.slug, resolvedBoardUrl: fb.boardUrl };
            break;
          }
        }
      }
      boardSnapshots.set(key, snap);
    }
  }

  const results: VerifiedJobResult[] = [];
  for (const item of parsedItems) {
    if (!item.identity) {
      const unresolvedAts = isKnownAtsPostingHostWithUnresolvedSlug(item.url);
      if (unresolvedAts && /\s/.test(unresolvedAts.rawSlug)) {
        const compactSlug = unresolvedAts.rawSlug.replace(/\s+/g, '').toLowerCase();
        const rewrittenUrl = item.url.replace(/\/\/([^/]+)\/[^/]+/, `//$1/${compactSlug}`);
        const recoveredIdentity = rewrittenUrl !== item.url ? parseAtsPostingIdentity(rewrittenUrl) : null;
        if (recoveredIdentity) {
          item.identity = recoveredIdentity;
          const recKey = `${recoveredIdentity.platform}:${recoveredIdentity.slug.toLowerCase()}`;
          if (!boardSnapshots.has(recKey)) {
            const recRes = await executeScrape({
              url: recoveredIdentity.boardUrl,
              renderMode: 'auto',
              ephemeral: true,
              atsLiteBoard: true,
              formats: ['markdown', 'links'],
              ...(payload.target ? { target: payload.target } : {}),
              ...(payload.site ? { site: payload.site } : {}),
            }).catch(() => null);
            boardSnapshots.set(
              recKey,
              buildSnapshotFromScrape(
                { boardUrl: recoveredIdentity.boardUrl, platform: recoveredIdentity.platform, slug: recoveredIdentity.slug },
                recRes,
              ),
            );
          }
        }
      }
    }

    if (!item.identity) {
      const unresolvedAts = isKnownAtsPostingHostWithUnresolvedSlug(item.url);
      const direct = await executeScrape({
        url: item.url,
        renderMode: 'auto',
        ephemeral: true,
        atsLiteBoard: true,
        formats: ['markdown'],
        ...(payload.target ? { target: payload.target } : {}),
        ...(payload.site ? { site: payload.site } : {}),
      }).catch(() => null);
      if (!direct) {
        results.push({ url: item.url, status: 'unknown', reason: unresolvedAts ? 'unresolved_slug' : 'fetch_failed' });
      } else if (direct.body?.error === 'jobs_scrape_budget_exceeded') {
        results.push({ url: item.url, status: 'unknown', reason: 'budget_exhausted', boardStatus: 'budget_exhausted' });
      } else if (direct.body?.error === 'jobs_item_timeout' || direct.status === 504) {
        results.push({ url: item.url, status: 'unknown', reason: unresolvedAts ? 'unresolved_slug' : 'timeout' });
      } else if (
        direct.status === 404 ||
        direct.status === 410 ||
        direct.body?.status === 404 ||
        direct.body?.status === 410 ||
        direct.body?.contentState === 'closed_posting' ||
        direct.body?.contentState === 'soft_404' ||
        isClosedSchemeDowngradeResult(item.url, direct)
      ) {
        results.push({
          url: item.url,
          status: unresolvedAts ? 'board_gone' : 'closed',
          ...(unresolvedAts ? { platform: unresolvedAts.platform, slug: unresolvedAts.rawSlug, reason: 'unresolved_slug' } : {}),
        });
      } else if (direct.status === 200 && direct.body?.ok === true && direct.body?.contentState !== 'empty_shell') {
        if (typeof direct.body.extractorId === 'string' && direct.body.extractorId) {
          resolvedAdapterIds.add(direct.body.extractorId);
        }
        results.push({ url: item.url, status: 'live' });
      } else {
        results.push({
          url: item.url,
          status: 'unknown',
          reason: unresolvedAts ? 'unresolved_slug' : 'fetch_failed',
          ...(unresolvedAts ? { platform: unresolvedAts.platform, slug: unresolvedAts.rawSlug } : {}),
        });
      }
      continue;
    }

    const key = `${item.identity.platform}:${item.identity.slug.toLowerCase()}`;
    const snap = boardSnapshots.get(key);
    if (!snap || snap.boardStatus === 'blocked_or_down' || snap.boardStatus === 'budget_exhausted') {
      const unknownReason =
        snap?.boardStatus === 'budget_exhausted'
          ? 'budget_exhausted'
          : /\s/.test(item.identity.slug)
            ? 'unresolved_slug'
            : (snap?.failureReason ?? 'board_blocked_or_down');
      results.push({
        url: item.url,
        status: 'unknown',
        reason: unknownReason,
        platform: item.identity.platform,
        slug: snap?.resolvedSlug ?? item.identity.slug,
        ...(snap?.resolvedBoardUrl ? { resolvedBoardUrl: snap.resolvedBoardUrl } : {}),
        ...(snap?.boardStatus === 'budget_exhausted' ? { boardStatus: 'budget_exhausted' as const } : {}),
      });
      continue;
    }
    if (snap.boardStatus === 'wrong_slug') {
      results.push({
        url: item.url,
        status: 'board_gone',
        reason: 'unresolved_slug',
        platform: item.identity.platform,
        slug: snap.resolvedSlug ?? item.identity.slug,
      });
      continue;
    }

    const idLower = item.identity.postingId.toLowerCase();
    const cleanOrigLower = item.url.replace(/\/+$/, '').toLowerCase();
    const isMatch = snap.openLinksLower.some(
      (lnk) =>
        lnk.replace(/\/+$/, '') === cleanOrigLower ||
        lnk.includes(`/${idLower}`) ||
        lnk.endsWith(`=${idLower}`),
    );

    if (isMatch) {
      results.push({
        url: item.url,
        status: 'live',
        platform: item.identity.platform,
        slug: snap.resolvedSlug ?? item.identity.slug,
        ...(snap.resolvedBoardUrl ? { resolvedBoardUrl: snap.resolvedBoardUrl } : {}),
      });
      continue;
    }

    if (snap.boardIncomplete) {
      const wdCheck = await executeScrape({
        url: item.url,
        renderMode: 'auto',
        ephemeral: true,
        atsLiteBoard: true,
        formats: ['markdown'],
        ...(payload.target ? { target: payload.target } : {}),
        ...(payload.site ? { site: payload.site } : {}),
      }).catch(() => null);
      if (wdCheck?.body?.error === 'jobs_scrape_budget_exceeded') {
        results.push({
          url: item.url,
          status: 'unknown',
          reason: 'budget_exhausted',
          platform: item.identity.platform,
          slug: snap.resolvedSlug ?? item.identity.slug,
          boardStatus: 'budget_exhausted',
        });
        continue;
      }
      if (wdCheck?.body?.error === 'jobs_item_timeout' || wdCheck?.status === 504) {
        results.push({
          url: item.url,
          status: 'unknown',
          reason: 'timeout',
          platform: item.identity.platform,
          slug: snap.resolvedSlug ?? item.identity.slug,
        });
        continue;
      }
      if (
        wdCheck?.status === 200 &&
        wdCheck.body?.ok === true &&
        wdCheck.body?.contentState !== 'closed_posting' &&
        wdCheck.body?.contentState !== 'soft_404'
      ) {
        const wdExtId =
          typeof wdCheck.body.extractorId === 'string' ? wdCheck.body.extractorId : resolveAtsPreFetchSpec(item.url)?.id;
        if (wdExtId) resolvedAdapterIds.add(wdExtId);
        results.push({
          url: item.url,
          status: 'live',
          platform: item.identity.platform,
          slug: snap.resolvedSlug ?? item.identity.slug,
        });
        continue;
      }
    }

    const similar = findSimilarRoles(snap.openRoles, item.identity.roleTokens);
    results.push({
      url: item.url,
      status: 'closed',
      platform: item.identity.platform,
      slug: snap.resolvedSlug ?? item.identity.slug,
      ...(snap.resolvedBoardUrl ? { resolvedBoardUrl: snap.resolvedBoardUrl } : {}),
      ...(similar.length > 0 ? { similarOpenRoles: similar } : {}),
    });
  }

  activeTracer?.setAttribute('edgefetch.jobs.mode', 'verify');
  activeTracer?.setAttribute('edgefetch.jobs.boards_discovered', boardGroups.size);
  activeTracer?.setAttribute('edgefetch.jobs.jobs_returned', results.length);
  if (resolvedAdapterIds.size > 0) {
    activeTracer?.setAttribute('edgefetch.adapter_id', [...resolvedAdapterIds].join(','));
  }

  const verifyHitBudget = Boolean(didExhaustBudget?.());
  return {
    status: 200,
    body: {
      ok: true,
      mode: 'verify',
      boardsFetched: boardGroups.size,
      checked: results.length,
      ...(verifyHitBudget
        ? {
            budgetExhausted: true,
            notes: [`Scrape budget (${MAX_JOBS_TOTAL_SCRAPES}) exhausted before all postings could be verified.`],
          }
        : {}),
      results,
    },
  };
}

export async function executeJobsCall(params: {
  payload: JobsToolPayload;
  env: OptionalStorageBindings & Record<string, unknown>;
  executeSearch: (args: Record<string, unknown>) => Promise<{ status: number; body: Record<string, unknown> }>;
  executeScrape: (args: Record<string, unknown>) => Promise<{ status: number; body: Record<string, unknown> }>;
  userId?: string;
  authTier?: string;
  tracer?: RequestTracer | TraceContext;
  /** Overrides `JOBS_WALL_BUDGET_MS` (tests). */
  wallBudgetMs?: number;
}): Promise<{ status: number; body: Record<string, unknown> }> {
  const activeTracer = getActiveRequestTracer(params.tracer);
  const activeCallerCtx = getActiveCallerAuthContext();
  const resolvedCallerId = (params.userId ?? activeCallerCtx?.userId ?? '').trim() || 'public';
  const resolvedAuthTier = (
    params.authTier ??
    activeCallerCtx?.role ??
    (resolvedCallerId === 'owner' ? 'owner' : resolvedCallerId === 'public' ? 'public' : 'member')
  ).trim();
  const callerCacheScope = `${resolvedAuthTier}|${resolvedCallerId}`;

  const runJobs = async (): Promise<{ status: number; body: Record<string, unknown> }> => {
    const { payload, env } = params;
    const rawExecuteSearch = params.executeSearch;
    const executeSearch = (args: Record<string, unknown>) =>
      activeTracer ? activeTracer.run(() => rawExecuteSearch(args)) : rawExecuteSearch(args);
    const rawExecuteScrape = params.executeScrape;
    const cachePartition = resolveJobsCachePartition(params.env, rawExecuteScrape);

    let activeScrapes = 0;
    let totalScrapesUsed = 0;
    let budgetExhausted = false;
    const wallBudgetMs =
      typeof params.wallBudgetMs === 'number' && Number.isFinite(params.wallBudgetMs) && params.wallBudgetMs > 0
        ? params.wallBudgetMs
        : JOBS_WALL_BUDGET_MS;
    const wallDeadlineAt = Date.now() + wallBudgetMs;
    let timeBudgetExhausted = false;
    /** True once the call's wall-clock budget is spent; also marks the scrape budget exhausted so later waves stop. */
    const overWallBudget = (): boolean => {
      if (Date.now() < wallDeadlineAt) return false;
      timeBudgetExhausted = true;
      budgetExhausted = true;
      return true;
    };
    const remainingItemTimeoutMs = (): number =>
      Math.max(500, Math.min(JOBS_PER_ITEM_TIMEOUT_MS, wallDeadlineAt - Date.now()));
    const scrapeWaitQueue: Array<() => void> = [];
    const activeHostScrapes = new Set<string>();
    const hostWaitQueues = new Map<string, Array<() => void>>();

    const resolveEffectiveScrapeHost = (args: Record<string, unknown>): string => {
      const rawUrl = typeof args.url === 'string' ? args.url.trim() : '';
      if (!rawUrl) return '';
      try {
        const spec = resolveAtsPreFetchSpec(rawUrl);
        return new URL(spec?.fetchUrl ?? rawUrl).hostname.toLowerCase();
      } catch {
        return '';
      }
    };
    const wakeNextHostWaiter = (host: string): void => {
      const hq = hostWaitQueues.get(host);
      if (hq && hq.length > 0) {
        hq.shift()?.();
        if (hq.length === 0) hostWaitQueues.delete(host);
      } else if (hq) {
        hostWaitQueues.delete(host);
      }
    };
    const wakeAllWaiters = (): void => {
      while (scrapeWaitQueue.length > 0) {
        scrapeWaitQueue.shift()?.();
      }
      for (const q of hostWaitQueues.values()) {
        while (q.length > 0) {
          q.shift()?.();
        }
      }
      hostWaitQueues.clear();
    };

    const executeScrape = async (
      args: Record<string, unknown>,
    ): Promise<{ status: number; body: Record<string, unknown> }> => {
      const cacheKey = args.noCache === true ? null : buildJobsScrapeCacheKey(args, callerCacheScope);
      if (cacheKey) {
        if (args.atsLiteBoard === true) {
          const fullBoardKey = buildJobsScrapeCacheKey({ ...args, atsLiteBoard: false }, callerCacheScope);
          if (fullBoardKey) {
            const fullCached = readJobsScrapeCache(cachePartition, fullBoardKey);
            if (fullCached) return fullCached;
          }
        }
        const cached = readJobsScrapeCache(cachePartition, cacheKey);
        if (cached) return cached;
        const existingFlight = cachePartition.inFlight.get(cacheKey);
        if (existingFlight) {
          const sharedRes = await withJobsItemTimeout(existingFlight);
          return cloneJobsScrapeResponse(sharedRes);
        }
      }

      const effectiveHost = resolveEffectiveScrapeHost(args);
      if (effectiveHost) {
        while (activeHostScrapes.has(effectiveHost)) {
          if (totalScrapesUsed >= MAX_JOBS_TOTAL_SCRAPES || overWallBudget()) {
            budgetExhausted = true;
            wakeAllWaiters();
            return { status: 429, body: { ok: false, error: 'jobs_scrape_budget_exceeded' } };
          }
          await new Promise<void>((resolve) => {
            let q = hostWaitQueues.get(effectiveHost);
            if (!q) {
              q = [];
              hostWaitQueues.set(effectiveHost, q);
            }
            q.push(resolve);
          });
          if (cacheKey) {
            const cachedAfterHostWait = readJobsScrapeCache(cachePartition, cacheKey);
            if (cachedAfterHostWait) {
              if (!activeHostScrapes.has(effectiveHost)) wakeNextHostWaiter(effectiveHost);
              return cachedAfterHostWait;
            }
            const flightAfterHostWait = cachePartition.inFlight.get(cacheKey);
            if (flightAfterHostWait) {
              if (!activeHostScrapes.has(effectiveHost)) wakeNextHostWaiter(effectiveHost);
              const sharedRes = await withJobsItemTimeout(flightAfterHostWait);
              return cloneJobsScrapeResponse(sharedRes);
            }
          }
        }
        activeHostScrapes.add(effectiveHost);
      }

      let acquiredGlobal = false;
      let flightPromise: Promise<JobsScrapeResponse> | null = null;
      try {
        while (activeScrapes >= MAX_JOBS_CONCURRENT_SCRAPES) {
          if (totalScrapesUsed >= MAX_JOBS_TOTAL_SCRAPES || overWallBudget()) {
            budgetExhausted = true;
            wakeAllWaiters();
            return { status: 429, body: { ok: false, error: 'jobs_scrape_budget_exceeded' } };
          }
          await new Promise<void>((resolve) => scrapeWaitQueue.push(resolve));
          if (cacheKey) {
            const cachedAfterWait = readJobsScrapeCache(cachePartition, cacheKey);
            if (cachedAfterWait) {
              if (activeScrapes < MAX_JOBS_CONCURRENT_SCRAPES) scrapeWaitQueue.shift()?.();
              return cachedAfterWait;
            }
            const flightAfterWait = cachePartition.inFlight.get(cacheKey);
            if (flightAfterWait) {
              if (activeScrapes < MAX_JOBS_CONCURRENT_SCRAPES) scrapeWaitQueue.shift()?.();
              const sharedRes = await withJobsItemTimeout(flightAfterWait);
              return cloneJobsScrapeResponse(sharedRes);
            }
          }
        }
        if (totalScrapesUsed >= MAX_JOBS_TOTAL_SCRAPES || overWallBudget()) {
          budgetExhausted = true;
          wakeAllWaiters();
          return { status: 429, body: { ok: false, error: 'jobs_scrape_budget_exceeded' } };
        }
        activeScrapes++;
        acquiredGlobal = true;
        totalScrapesUsed++;
        const runSingle = (): Promise<JobsScrapeResponse> =>
          withJobsItemTimeout(
            Promise.resolve().then(() => (activeTracer ? activeTracer.run(() => rawExecuteScrape(args)) : rawExecuteScrape(args))),
            remainingItemTimeoutMs(),
          );
        flightPromise = runSingle();
        if (cacheKey) cachePartition.inFlight.set(cacheKey, flightPromise);
        const out = await flightPromise;
        if (cacheKey && out.status === 200 && out.body?.ok === true) {
          writeJobsScrapeCache(cachePartition, cacheKey, out);
        }
        return cacheKey ? cloneJobsScrapeResponse(out) : out;
      } finally {
        if (cacheKey && flightPromise && cachePartition.inFlight.get(cacheKey) === flightPromise) {
          cachePartition.inFlight.delete(cacheKey);
        }
        if (acquiredGlobal) {
          activeScrapes--;
          if (totalScrapesUsed >= MAX_JOBS_TOTAL_SCRAPES || timeBudgetExhausted) wakeAllWaiters();
          else scrapeWaitQueue.shift()?.();
        }
        if (effectiveHost) {
          activeHostScrapes.delete(effectiveHost);
          if (totalScrapesUsed >= MAX_JOBS_TOTAL_SCRAPES || timeBudgetExhausted) wakeAllWaiters();
          else wakeNextHostWaiter(effectiveHost);
        }
      }
    };

    const rawVerifyArray = Array.isArray(payload.verify)
      ? payload.verify
      : payload.mode === 'verify' && Array.isArray(payload.urls)
        ? payload.urls
        : null;
    if (rawVerifyArray !== null || payload.mode === 'verify') {
      const cleanVerifyUrls = (rawVerifyArray ?? [])
        .slice(0, 100)
        .filter((u): u is string => typeof u === 'string' && u.length <= 2_048 && u.trim().startsWith('https://'))
        .map((u) => u.trim());
      if (cleanVerifyUrls.length === 0) {
        activeTracer?.setAttribute('edgefetch.jobs.mode', 'verify');
        activeTracer?.setAttribute('edgefetch.jobs.boards_discovered', 0);
        activeTracer?.setAttribute('edgefetch.jobs.jobs_returned', 0);
        return {
          status: 400,
          body: {
            ok: false,
            error: 'missing_verify_urls',
            message: 'Provide one or more `https://` posting URLs in `verify` (or `mode: "verify", urls: [...]`).',
          },
        };
      }
      return executeJobsVerifyMode({
        urls: cleanVerifyUrls,
        payload,
        executeScrape,
        ...(activeTracer ? { tracer: activeTracer } : {}),
        didExhaustBudget: () => budgetExhausted,
      });
    }

    if (typeof payload.query === 'string' && payload.query.length > 4_096) {
      return {
        status: 400,
        body: { ok: false, error: 'invalid_query', message: `\`query\` must be at most ${MAX_JOBS_QUERY_CHARS} characters.` },
      };
    }
    const rawQueryTrimmed = typeof payload.query === 'string' ? payload.query.trim() : '';
    if (rawQueryTrimmed.length > MAX_JOBS_QUERY_CHARS) {
      return {
        status: 400,
        body: { ok: false, error: 'invalid_query', message: `\`query\` must be at most ${MAX_JOBS_QUERY_CHARS} characters.` },
      };
    }
    const query = rawQueryTrimmed;

    if (typeof payload.company === 'string' && payload.company.length > 4_096) {
      return {
        status: 400,
        body: { ok: false, error: 'invalid_company', message: '`company` must be at most 128 characters.' },
      };
    }
    const rawCompanyTrimmed = typeof payload.company === 'string' ? payload.company.trim() : '';
    if (rawCompanyTrimmed.length > 128) {
      return {
        status: 400,
        body: { ok: false, error: 'invalid_company', message: '`company` must be at most 128 characters.' },
      };
    }
    const companyFilter = rawCompanyTrimmed;

    const domainsInput = Array.isArray(payload.domains)
      ? payload.domains
          .slice(0, 25)
          .filter((d): d is string => typeof d === 'string' && d.length <= 256 && d.trim().length > 0)
          .map((d) => d.trim().replace(/^https?:\/\//i, '').replace(/\/.*$/, '').toLowerCase())
          .filter((d) => /^[a-z0-9.-]+\.[a-z]{2,}$/i.test(d))
          .slice(0, 10)
      : [];

    if (!query && !companyFilter && domainsInput.length === 0) {
      activeTracer?.setAttribute('edgefetch.jobs.mode', 'search');
      activeTracer?.setAttribute('edgefetch.jobs.boards_discovered', 0);
      activeTracer?.setAttribute('edgefetch.jobs.jobs_returned', 0);
      return {
        status: 400,
        body: { ok: false, error: 'missing_query', message: 'Provide at least `query`, `company`, or `domains`.' },
      };
    }

    const rawLocationsFilter = Array.isArray(payload.locations)
      ? payload.locations
          .slice(0, 32)
          .filter((x): x is string => typeof x === 'string')
          .map((s) => (s.length > 160 ? s.slice(0, 160) : s).trim().toLowerCase())
          .filter((s) => s.length > 0)
      : [];
    const geoLocationsFilter = rawLocationsFilter.filter((s) => !REMOTE_LOCATION_TOKENS.has(s));
    const hasRemoteInLocations = rawLocationsFilter.some((s) => REMOTE_LOCATION_TOKENS.has(s));
    const rawWantRemote = payload.remote === true ? true : payload.remote === false ? false : undefined;
    const wantRemote = rawWantRemote !== undefined ? rawWantRemote : hasRemoteInLocations ? true : undefined;

    const minBase =
      typeof payload.minBase === 'number' && Number.isFinite(payload.minBase) && payload.minBase > 0 ? payload.minBase : undefined;
    const minBaseMode: 'floor' | 'ceiling' | 'overlap' =
      payload.minBaseMode === 'ceiling' ? 'ceiling' : payload.minBaseMode === 'overlap' ? 'overlap' : 'floor';
    const strictPay = payload.strictPay === true;
    const postedWithinDays =
      typeof payload.postedWithinDays === 'number' && Number.isFinite(payload.postedWithinDays) && payload.postedWithinDays > 0
        ? payload.postedWithinDays
        : undefined;
    const limit =
      typeof payload.limit === 'number' && Number.isFinite(payload.limit) ? Math.min(50, Math.max(1, Math.floor(payload.limit))) : 20;
    const rawCursorStr = typeof payload.cursor === 'string' ? payload.cursor.trim() : '';
    const cursorIcimsPage = /^pr=(\d+)$/i.exec(rawCursorStr)?.[1];
    const boardStartOffset =
      typeof payload.offset === 'number' && Number.isFinite(payload.offset) && payload.offset >= 0
        ? Math.min(10_000, Math.floor(payload.offset))
        : /^\d+$/.test(rawCursorStr)
          ? Math.min(10_000, parseInt(rawCursorStr, 10))
          : 0;
    const hasCompanyOrDomainScope = Boolean(companyFilter) || domainsInput.length > 0;
    // Chunked broad search: a `continueCursor` from the previous call resumes with its unscraped candidates and skips
    // the SERP / Built In / public-feed steps that already ran. Bound to the same query + remote flag.
    const continuationKey = JSON.stringify([query.toLowerCase(), wantRemote ?? null]);
    const resumeState = !hasCompanyOrDomainScope ? decodeJobsContinuation(rawCursorStr, continuationKey) : null;
    const includeBuiltIn = hasCompanyOrDomainScope ? payload.includeBuiltIn === true : payload.includeBuiltIn !== false;
    const excludeList = Array.isArray(payload.exclude)
      ? (payload.exclude as Array<Record<string, unknown>>)
          .slice(0, 200)
          .filter((x) => x && typeof x === 'object')
          .map((x) => ({
            company: typeof x.company === 'string' ? (x.company.length > 256 ? x.company.slice(0, 256) : x.company).trim().toLowerCase() : '',
            title: typeof x.title === 'string' ? (x.title.length > 256 ? x.title.slice(0, 256) : x.title).trim().toLowerCase() : '',
            url: typeof x.url === 'string' ? (x.url.length > 2_048 ? x.url.slice(0, 2_048) : x.url).trim().replace(/\/+$/, '').toLowerCase() : '',
          }))
      : [];

    const candidateUrls = new Set<string>();
    const notes: string[] = [];
    const discoveredBoards: DiscoveredAtsBoard[] = [];
    const failedProbeBoardKeys = new Set<string>();
    const sourcesUsed = new Set<string>();
    const resolvedAdapterIds = new Set<string>();

    if (domainsInput.length > 0) {
      const discoverSingleDomain = async (dom: string): Promise<void> => {
        const tried: string[] = [];
        const foundForDom: DiscoveredAtsBoard[] = [];
        let domHitBudgetCap = false;
        const explicitWdMatch = /^([a-z0-9-]+)\.(wd\d+)\.myworkday(?:jobs|site)\.com$/i.exec(dom);
        if (explicitWdMatch) {
          const wdTenant = explicitWdMatch[1]!.toLowerCase();
          const wdCapTenant = wdTenant.charAt(0).toUpperCase() + wdTenant.slice(1);
          const wdUpperTenant = wdTenant.toUpperCase();
          const candidateSites = [
            ...new Set(['External', wdCapTenant, `${wdCapTenant}ExternalCareerSite`, `${wdUpperTenant}ExternalCareerSite`, wdTenant]),
          ];
          for (const siteName of candidateSites) {
            const wdBoardUrl = `https://${dom}/${siteName}`;
            tried.push(wdBoardUrl);
            const r = await executeScrape({
              url: wdBoardUrl,
              renderMode: 'off',
              discoverLlmsTxt: false,
              preferOriginMarkdown: false,
              ephemeral: true,
              atsLiteBoard: true,
              formats: ['markdown', 'links'],
              ...(payload.target ? { target: payload.target } : {}),
              ...(payload.site ? { site: payload.site } : {}),
            }).catch(() => null);
            if (r?.body?.error === 'jobs_scrape_budget_exceeded') {
              domHitBudgetCap = true;
              break;
            }
            if (r && r.status === 200 && r.body?.ok === true) {
              const jobsArr = Array.isArray(r.body.jobs) ? (r.body.jobs as unknown[]) : [];
              const links = Array.isArray(r.body.links) ? (r.body.links as string[]) : [];
              if (jobsArr.length > 0 || links.length > 0) {
                const entry: DiscoveredAtsBoard = {
                  domain: dom,
                  platform: 'workday',
                  slug: `${wdTenant}/${siteName}`,
                  boardUrl: wdBoardUrl,
                  discoveredFrom: `direct-ats-domain:${dom}`,
                  boardStatus: 'ok',
                };
                foundForDom.push(entry);
                discoveredBoards.push(entry);
                candidateUrls.add(wdBoardUrl);
                return;
              }
            }
          }
          if (foundForDom.length === 0) {
            const finalStatus: AtsBoardStatus = domHitBudgetCap ? 'budget_exhausted' : 'not_found';
            discoveredBoards.push({
              domain: dom,
              platform: 'workday',
              slug: wdTenant,
              boardUrl: '',
              discoveredFrom: 'none',
              boardStatus: finalStatus,
              tried,
            });
          }
          return;
        }
        const domBrandInfo = extractRegistrableBrandInfo(dom);
        const baseSlug = (domBrandInfo?.sld ?? dom.split('.')[0] ?? '').toLowerCase();
        const canSlugProbe = isValidAtsSlug(baseSlug);
        const upperSlug = baseSlug.toUpperCase();
        const phase1Probes = canSlugProbe
          ? [
              { platform: 'greenhouse', slug: baseSlug, boardUrl: `https://boards.greenhouse.io/${baseSlug}` },
              { platform: 'ashby', slug: baseSlug, boardUrl: `https://jobs.ashbyhq.com/${baseSlug}` },
              { platform: 'lever', slug: baseSlug, boardUrl: `https://jobs.lever.co/${baseSlug}` },
              { platform: 'smartrecruiters', slug: baseSlug, boardUrl: `https://jobs.smartrecruiters.com/${baseSlug}` },
            ]
          : [];
        const phase2WorkdayProbes = canSlugProbe
          ? [
              { platform: 'workday', slug: `${baseSlug}/${upperSlug}ExternalCareerSite`, boardUrl: `https://${baseSlug}.wd5.myworkdayjobs.com/${upperSlug}ExternalCareerSite` },
              { platform: 'workday', slug: `${baseSlug}/${upperSlug}ExternalCareerSite`, boardUrl: `https://${baseSlug}.wd1.myworkdayjobs.com/${upperSlug}ExternalCareerSite` },
              { platform: 'workday', slug: `${baseSlug}/External`, boardUrl: `https://${baseSlug}.wd5.myworkdayjobs.com/External` },
              { platform: 'workday', slug: `${baseSlug}/External`, boardUrl: `https://${baseSlug}.wd1.myworkdayjobs.com/External` },
            ]
          : [];
        let ranPhase1SlugProbes = false;

        const runSlugProbeWave = async (wave: Array<{ platform: string; slug: string; boardUrl: string }>) => {
          for (const sp of wave) tried.push(sp.boardUrl);
          const probeResults = await Promise.all(
            wave.map(async (sp) => {
              const r = await executeScrape({
                url: sp.boardUrl,
                renderMode: 'off',
                discoverLlmsTxt: false,
                preferOriginMarkdown: false,
                ephemeral: true,
                atsLiteBoard: true,
                formats: ['markdown', 'links'],
                ...(payload.target ? { target: payload.target } : {}),
                ...(payload.site ? { site: payload.site } : {}),
              }).catch(() => null);
              if (r?.body?.error === 'jobs_scrape_budget_exceeded') domHitBudgetCap = true;
              return { sp, r };
            }),
          );
          for (const { sp, r } of probeResults) {
            if (!r || r.status !== 200 || r.body?.ok !== true) {
              if (r?.body?.error !== 'jobs_scrape_budget_exceeded') {
                const fk = classifyFullBoardKey(sp.boardUrl)?.key ?? sp.boardUrl.replace(/\/+$/, '').toLowerCase();
                failedProbeBoardKeys.add(fk);
              }
              continue;
            }
            if (foundForDom.some((existing) => existing.platform === sp.platform)) continue;
            const srJobs = sp.platform === 'smartrecruiters' ? parseSmartRecruitersBoardScrape(sp.boardUrl, r.body) : [];
            const links = Array.isArray(r.body.links) ? (r.body.links as string[]) : [];
            const jobsArr = Array.isArray(r.body.jobs) ? (r.body.jobs as unknown[]) : [];
            const cleanBoardPrefix = `${sp.boardUrl.replace(/\/+$/, '').toLowerCase()}/`;
            const hasBoardPostingLink = links.some((l) => typeof l === 'string' && l.toLowerCase().startsWith(cleanBoardPrefix));
            const hasRealJobs = sp.platform === 'smartrecruiters' ? srJobs.length > 0 : jobsArr.length > 0 || hasBoardPostingLink;
            if (hasRealJobs) {
              const entry: DiscoveredAtsBoard = {
                domain: dom,
                platform: sp.platform,
                slug: sp.slug,
                boardUrl: sp.boardUrl,
                discoveredFrom: `slug-probe:${dom}`,
                boardStatus: 'ok',
              };
              foundForDom.push(entry);
              discoveredBoards.push(entry);
              candidateUrls.add(sp.boardUrl);
            }
          }
        };

        for (const probePath of ['/careers', '/jobs', '/about/careers']) {
          const probeUrl = `https://${dom}${probePath}`;
          tried.push(probeUrl);
          const res = await executeScrape({
            url: probeUrl,
            renderMode: 'off',
            discoverLlmsTxt: false,
            preferOriginMarkdown: false,
            onlyMainContent: false,
            ephemeral: true,
            maxChars: 24_000,
            formats: ['markdown', 'rawHtml', 'links'],
            ...(payload.target ? { target: payload.target } : {}),
            ...(payload.site ? { site: payload.site } : {}),
          }).catch(() => null);
          if (res?.body?.error === 'jobs_scrape_budget_exceeded') {
            domHitBudgetCap = true;
            break;
          }
          if (!res || res.status !== 200 || res.body?.ok !== true) continue;
          const boards = discoverAtsBoardsFromHtml({
            sourceUrl: probeUrl,
            finalUrl: typeof res.body.finalUrl === 'string' ? res.body.finalUrl : probeUrl,
            rawHtml: typeof res.body.rawHtml === 'string' ? res.body.rawHtml : '',
            links: Array.isArray(res.body.links) ? (res.body.links as string[]) : [],
          });
          if (boards.length > 0) {
            for (const b of boards) {
              const entry: DiscoveredAtsBoard = { ...b, domain: dom };
              foundForDom.push(entry);
              discoveredBoards.push(entry);
              candidateUrls.add(entry.boardUrl);
            }
            return;
          }
          const finalProbeUrl = typeof res.body.finalUrl === 'string' && res.body.finalUrl ? res.body.finalUrl : probeUrl;
          let stayedOnCareersPath = false;
          try {
            stayedOnCareersPath = /^\/careers(?:\/|$)/i.test(new URL(finalProbeUrl).pathname);
          } catch {
            stayedOnCareersPath = false;
          }
          const probeContentState = typeof res.body.contentState === 'string' ? res.body.contentState : undefined;
          if (
            probePath === '/careers' &&
            domBrandInfo?.tld === 'com' &&
            stayedOnCareersPath &&
            probeContentState !== 'soft_404' &&
            canSlugProbe &&
            !ranPhase1SlugProbes &&
            !domHitBudgetCap
          ) {
            ranPhase1SlugProbes = true;
            await runSlugProbeWave(phase1Probes);
            if (foundForDom.length > 0 || domHitBudgetCap) return;
          }
        }

        if (canSlugProbe && !domHitBudgetCap) {
          if (!ranPhase1SlugProbes) {
            ranPhase1SlugProbes = true;
            await runSlugProbeWave(phase1Probes);
          }
          if (foundForDom.length === 0 && !domHitBudgetCap) {
            await runSlugProbeWave(phase2WorkdayProbes);
          }
          if (foundForDom.length === 0) {
            tried.push(`search:ats:${dom}`);
            const sr = await executeSearch({
              query: `(site:myworkdayjobs.com OR site:job-boards.greenhouse.io OR site:boards.greenhouse.io OR site:jobs.ashbyhq.com OR site:jobs.lever.co OR site:apply.workable.com OR site:jobs.smartrecruiters.com OR site:icims.com) "${baseSlug}"`,
              maxResults: 10,
              ...(env?.SERPER_API_KEY ? { mode: 'serper' } : {}),
            }).catch(() => null);
            const srHits = Array.isArray(sr?.body?.results) ? (sr!.body.results as Array<Record<string, unknown>>) : [];
            const hitLinks = srHits
              .map((h) => (typeof h.url === 'string' ? h.url.trim() : ''))
              .filter((u) => u.startsWith('https://'));
            if (hitLinks.length > 0) {
              const searchBoards = discoverAtsBoardsFromHtml({ sourceUrl: `search:${dom}`, links: hitLinks });
              const normBase = baseSlug.replace(/[^a-z0-9]+/g, '');
              for (const sb of searchBoards) {
                const rootBoardSlug = sb.slug.split('/')[0] ?? '';
                if (normBase && matchesAtsTenantSlugAgainstToken(rootBoardSlug, normBase)) {
                  const entry: DiscoveredAtsBoard = { ...sb, domain: dom };
                  foundForDom.push(entry);
                  discoveredBoards.push(entry);
                  candidateUrls.add(entry.boardUrl);
                }
              }
            }
          }
        }

        if (foundForDom.length === 0) {
          const finalStatus: AtsBoardStatus = domHitBudgetCap ? 'budget_exhausted' : 'not_found';
          discoveredBoards.push({
            domain: dom,
            platform: 'unknown',
            slug: baseSlug || dom,
            boardUrl: '',
            discoveredFrom: 'none',
            boardStatus: finalStatus,
            tried,
          });
          notes.push(
            domHitBudgetCap
              ? timeBudgetExhausted
                ? `Time budget (${Math.round(wallBudgetMs / 1_000)} s) reached before completing ATS board discovery for "${dom}".`
                : `Scrape budget (${MAX_JOBS_TOTAL_SCRAPES}) exhausted before completing ATS board discovery for "${dom}".`
              : `No ATS job board discovered for "${dom}" after probing ${tried.length} candidates.`,
          );
        }
      };

      const DOMAIN_DISCOVERY_CONCURRENCY = 4;
      for (let di = 0; di < domainsInput.length; di += DOMAIN_DISCOVERY_CONCURRENCY) {
        await Promise.all(domainsInput.slice(di, di + DOMAIN_DISCOVERY_CONCURRENCY).map((d) => discoverSingleDomain(d)));
      }
    }

    const companyTokensForSearch = companyFilter ? expandCompanyFilterTokens(companyFilter) : [];
    const primaryCompanySlug = companyTokensForSearch[0] && isValidAtsSlug(companyTokensForSearch[0]) ? companyTokensForSearch[0] : '';

    const atsGroups = [
      '(site:job-boards.greenhouse.io OR site:boards.greenhouse.io OR site:jobs.ashbyhq.com)',
      '(site:jobs.lever.co OR site:myworkdayjobs.com OR site:jobs.smartrecruiters.com)',
      '(site:apply.workable.com OR site:jobs.gem.com OR site:ats.rippling.com)',
    ];
    const cleanSearchQuery = query.replace(/["()]+/g, ' ').replace(/\bsite:/gi, ' ').replace(/\s+/g, ' ').trim().slice(0, 180);
    const cleanSearchCompany = companyFilter.replace(/["()]+/g, ' ').replace(/\bsite:/gi, ' ').replace(/\s+/g, ' ').trim().slice(0, 100);
    const dehyphenatedQuery =
      cleanSearchQuery.length <= 100 && cleanSearchQuery.includes('-')
        ? cleanSearchQuery.replace(/-+/g, ' ').replace(/\s+/g, ' ').trim()
        : '';
    const searchQueryExpr = cleanSearchQuery
      ? dehyphenatedQuery && dehyphenatedQuery.toLowerCase() !== cleanSearchQuery.toLowerCase()
        ? `("${cleanSearchQuery}" OR "${dehyphenatedQuery}")`
        : `"${cleanSearchQuery}"`
      : '';
    const coreTerms = [cleanSearchCompany ? `"${cleanSearchCompany}"` : '', searchQueryExpr, wantRemote ? 'remote' : '']
      .filter(Boolean)
      .join(' ');
    const scopedQueries = atsGroups.map((grp) => `${grp} ${coreTerms}`.trim());
    if (primaryCompanySlug) {
      const nonCompanyTerms = [searchQueryExpr, wantRemote ? 'remote' : ''].filter(Boolean).join(' ');
      const explicitWdHostsForCompany = domainsInput.filter((d) => {
        const m = /^([a-z0-9-]+)\.(wd\d+)\.myworkday(?:jobs|site)\.com$/i.exec(d);
        return Boolean(m && m[1]!.toLowerCase() === primaryCompanySlug.toLowerCase());
      });
      const wdSiteClauses =
        explicitWdHostsForCompany.length > 0
          ? explicitWdHostsForCompany.map((h) => `site:${h}`)
          : [`site:${primaryCompanySlug}.wd5.myworkdayjobs.com`, `site:${primaryCompanySlug}.wd1.myworkdayjobs.com`];
      scopedQueries.push(
        `(site:jobs.smartrecruiters.com/${primaryCompanySlug} OR ${wdSiteClauses.join(' OR ')}) ${nonCompanyTerms}`.trim(),
      );
    }

    const preWaveSegmentedTokens = new Set<string>();
    for (const rawSrc of [companyFilter, ...domainsInput]) {
      if (!rawSrc) continue;
      const ws = normalizeDottedCorporateAbbreviations(rawSrc).toLowerCase().match(/[a-z0-9]+/g) ?? [];
      if (ws.length >= 2 && ws.length <= 4) preWaveSegmentedTokens.add(ws.join('-'));
      const low = rawSrc.trim().toLowerCase();
      if (/^[a-z0-9_-]{2,128}$/.test(low) && (low.includes('-') || low.includes('_'))) {
        preWaveSegmentedTokens.add(low.replace(/_/g, '-'));
      }
    }
    const preWaveAllowedTokens = new Set<string>();
    if (companyFilter) {
      preWaveAllowedTokens.add(companyFilter);
      for (const expanded of expandCompanyFilterTokens(companyFilter)) preWaveAllowedTokens.add(expanded);
    }
    for (const dom of domainsInput) {
      preWaveAllowedTokens.add(dom);
      const explicitWd = /^([a-z0-9-]+)\.(wd\d+)\.myworkday(?:jobs|site)\.com$/i.exec(dom);
      if (explicitWd?.[1]) preWaveAllowedTokens.add(explicitWd[1].toLowerCase());
      for (const expanded of expandCompanyFilterTokens(dom)) preWaveAllowedTokens.add(expanded);
    }
    for (const db of discoveredBoards) {
      if (db.boardStatus !== 'not_found' && db.boardStatus !== 'budget_exhausted' && db.slug) {
        const rootSlug = (db.slug.split('/')[0] ?? '').toLowerCase().replace(/[^a-z0-9]+/g, '');
        if (rootSlug) preWaveAllowedTokens.add(rootSlug);
      }
    }
    const confirmedDiscoveredBoardUrls = discoveredBoards
      .filter((b) => b.boardUrl)
      .map((b) => b.boardUrl.replace(/\/+$/, '').toLowerCase());

    const matchesScopedAtsCandidateUrl = (u: string): boolean => {
      if (!hasCompanyOrDomainScope || preWaveAllowedTokens.size === 0) return true;
      return callCoreWasm<{ ok: boolean }>('jobs_url_helpers', {
        kind: 'match_scoped_candidate',
        url: u,
        hasScope: hasCompanyOrDomainScope,
        allowedTokens: [...preWaveAllowedTokens],
        segmentedTokens: [...preWaveSegmentedTokens],
        confirmedBoardUrls: confirmedDiscoveredBoardUrls,
        jobCompany: companyFilter,
      }).ok;
    };

    if (!resumeState && coreTerms && (domainsInput.length === 0 || Boolean(companyFilter))) {
      const searchMaxResults = postedWithinDays !== undefined ? 15 : 10;
      const searchCandidateCap =
        postedWithinDays !== undefined ? Math.min(40, Math.max(35, limit * 3)) : Math.min(40, Math.max(30, limit * 2));
      const searchResponses = await Promise.all(
        scopedQueries.map((sq) =>
          executeSearch({
            query: sq,
            maxResults: searchMaxResults,
            ...(env?.SERPER_API_KEY ? { mode: 'serper' } : {}),
          }).catch(() => ({ status: 500, body: {} as Record<string, unknown> })),
        ),
      );

      let addedSearchHits = 0;
      for (const sr of searchResponses) {
        const webResults = Array.isArray(sr.body?.results) ? (sr.body.results as Array<Record<string, unknown>>) : [];
        for (const hit of webResults) {
          const u = typeof hit.url === 'string' ? hit.url.trim() : '';
          if (u.startsWith('https://') && candidateUrls.size < searchCandidateCap) {
            let hitHost = '';
            try {
              hitHost = new URL(u).hostname.toLowerCase().replace(/\.+$/, '');
            } catch {
              hitHost = '';
            }
            if (hitHost && isKnownMultiTenantAtsHost(hitHost) && matchesScopedAtsCandidateUrl(u)) {
              candidateUrls.add(u);
              addedSearchHits++;
            }
          }
        }
      }
      if (addedSearchHits > 0) sourcesUsed.add('ats_search');
    }

    const companyWordsLower = companyFilter
      ? normalizeDottedCorporateAbbreviations(companyFilter).toLowerCase().match(/[a-z0-9]+/g) ?? []
      : [];
    const multiWordHyphenSlug =
      companyWordsLower.length >= 2 && companyWordsLower.length <= 4 && companyWordsLower.every((w) => w.length >= 2)
        ? companyWordsLower.join('-')
        : '';
    const multiWordSpaceAshbySlug =
      companyWordsLower.length >= 2 && companyWordsLower.length <= 4 && companyWordsLower.every((w) => w.length >= 2)
        ? companyWordsLower.join(' ')
        : '';

    const buildDirectCompanyProbeUrls = (): string[] => {
      if (!companyFilter || domainsInput.length > 0 || !primaryCompanySlug) return [];
      const outUrls: string[] = [];
      const primarySlug = primaryCompanySlug;
      const lowerSlug = primarySlug.toLowerCase();
      const rawTrimmedSlug = companyFilter.replace(/[^A-Za-z0-9_-]+/g, '');
      const srDisplaySlug = rawTrimmedSlug && rawTrimmedSlug.toLowerCase() === lowerSlug ? rawTrimmedSlug : primarySlug;
      const existingBoardKeys = new Set(
        [...candidateUrls]
          .map((u) => classifyFullBoardKey(u))
          .filter((x): x is NonNullable<typeof x> => Boolean(x?.isBoard))
          .map((x) => x.key),
      );
      const hasSmartRecruitersBoard = [...candidateUrls].some((u) => {
        const sr = isSmartRecruitersBoardUrl(u);
        return Boolean(sr && sr.org.toLowerCase() === lowerSlug);
      });
      if (!hasSmartRecruitersBoard) outUrls.push(`https://jobs.smartrecruiters.com/${srDisplaySlug}`);
      if (!existingBoardKeys.has(`greenhouse:${lowerSlug}`)) outUrls.push(`https://boards.greenhouse.io/${primarySlug}`);
      if (!existingBoardKeys.has(`ashby:${lowerSlug}`)) outUrls.push(`https://jobs.ashbyhq.com/${primarySlug}`);
      if (!existingBoardKeys.has(`lever:${lowerSlug}`)) outUrls.push(`https://jobs.lever.co/${primarySlug}`);
      if (multiWordHyphenSlug && isValidAtsSlug(multiWordHyphenSlug)) {
        if (!existingBoardKeys.has(`ashby:${multiWordHyphenSlug}`)) outUrls.push(`https://jobs.ashbyhq.com/${multiWordHyphenSlug}`);
        if (!existingBoardKeys.has(`greenhouse:${multiWordHyphenSlug}`)) outUrls.push(`https://boards.greenhouse.io/${multiWordHyphenSlug}`);
        if (!existingBoardKeys.has(`lever:${multiWordHyphenSlug}`)) outUrls.push(`https://jobs.lever.co/${multiWordHyphenSlug}`);
      }
      if (multiWordSpaceAshbySlug && isValidAshbySlug(multiWordSpaceAshbySlug)) {
        const callerSpaceSlug = companyFilter.trim().replace(/\s+/g, ' ');
        const titleSpaceSlug = companyWordsLower
          .map((w) => (w === 'ai' || w === 'us' || w === 'uk' || w === 'hq' ? w.toUpperCase() : w[0]!.toUpperCase() + w.slice(1)))
          .join(' ');
        const candidateSpaceSlugs = [...new Set([callerSpaceSlug, titleSpaceSlug, multiWordSpaceAshbySlug])].filter((s) =>
          isValidAshbySlug(s),
        );
        if (!existingBoardKeys.has(`ashby:${multiWordSpaceAshbySlug}`)) {
          for (const spSlug of candidateSpaceSlugs.slice(0, 2)) {
            outUrls.push(`https://jobs.ashbyhq.com/${encodeURIComponent(spSlug)}`);
          }
        }
      }
      return outUrls;
    };

    if (companyFilter && domainsInput.length === 0 && primaryCompanySlug) {
      const normSlug = primaryCompanySlug.toLowerCase().replace(/[^a-z0-9]+/g, '');
      const alreadyHasConfirmedCompanyAts = [...candidateUrls].some((u) => {
        const info = classifyFullBoardKey(u);
        const srBoard = !info ? isSmartRecruitersBoardUrl(u) : null;
        const srPostOrg =
          !info && !srBoard ? /^https:\/\/jobs\.smartrecruiters\.com\/([A-Za-z0-9_.-]+)\//i.exec(u)?.[1] : undefined;
        const root = (info?.slug.split('/')[0] ?? srBoard?.org ?? srPostOrg ?? '').toLowerCase();
        if (!root || !normSlug) return false;
        return matchesAtsTenantSlugAgainstToken(root, normSlug, {
          host: info?.platform === 'ashby' ? 'jobs.ashbyhq.com' : undefined,
          jobCompany: companyFilter,
          segmentedTokens: preWaveSegmentedTokens,
          allowAshbySpaces: info?.platform === 'ashby',
        });
      });
      if (!alreadyHasConfirmedCompanyAts) {
        for (const probeU of buildDirectCompanyProbeUrls()) candidateUrls.add(probeU);
      }
    }

    const collected: StructuredJobRecord[] = [];

    if (includeBuiltIn && query && !resumeState) {
      const builtInUrl = `https://builtin.com/jobs${wantRemote !== false ? '/remote' : ''}?search=${encodeURIComponent(query)}`;
      const biRes = await executeScrape({
        url: builtInUrl,
        renderMode: 'auto',
        ephemeral: true,
        formats: ['markdown', 'links'],
      }).catch(() => null);
      const biMd = typeof biRes?.body?.markdown === 'string' ? biRes.body.markdown : '';
      if (biRes?.status === 200 && biMd) {
        sourcesUsed.add('builtin');
        const biCards =
          callCoreWasm<{ records: StructuredJobRecord[] }>('jobs_parse_builtin_cards', {
            markdown: biMd,
            maxCards: Math.max(0, limit * 2 - collected.length),
            wantRemoteFalse: wantRemote === false,
          }).records ?? [];
        for (const c of biCards) collected.push(c);
      }
    }

    if (payload.includePublicFeeds === true && !resumeState) {
      const feedOuts = await Promise.all(
        PUBLIC_JOB_FEEDS.map(async (feed) => ({
          feed,
          fo: await executeScrape({
            url: feed.url,
            renderMode: 'auto',
            ephemeral: true,
            formats: ['markdown'],
            ...(payload.target ? { target: payload.target } : {}),
            ...(payload.site ? { site: payload.site } : {}),
          }).catch(() => null),
        })),
      );
      for (const { feed, fo } of feedOuts) {
        if (fo?.status === 200 && fo.body?.ok === true && Array.isArray(fo.body.jobs)) {
          sourcesUsed.add(`public_feed:${feed.id}`);
          for (const fj of fo.body.jobs as StructuredJobRecord[]) collected.push(fj);
        }
      }
    }

    if (resumeState) {
      for (const u of [...resumeState.b, ...resumeState.p]) {
        try {
          if (isKnownMultiTenantAtsHost(new URL(u).hostname.toLowerCase().replace(/\.+$/, ''))) candidateUrls.add(u);
        } catch {
          // skip malformed cursor entries
        }
      }
      sourcesUsed.add('ats_search_continuation');
    }
    const rawUrlList = [...candidateUrls].filter((u) => matchesScopedAtsCandidateUrl(u));
    const postingCountByBoard = new Map<string, { count: number; boardUrl: string; platform: string; slug: string; hasBoard: boolean }>();
    const smartRecruitersPostingOrgs = new Set<string>();
    for (const u of rawUrlList) {
      const info = classifyFullBoardKey(u);
      if (!info) {
        const srPostMatch = /^https:\/\/jobs\.smartrecruiters\.com\/([A-Za-z0-9_.-]+)\//i.exec(u);
        if (srPostMatch?.[1] && isValidAtsSlug(srPostMatch[1])) smartRecruitersPostingOrgs.add(srPostMatch[1]);
        continue;
      }
      const entry = postingCountByBoard.get(info.key) ?? {
        count: 0,
        boardUrl: info.boardUrl,
        platform: info.platform,
        slug: info.slug,
        hasBoard: false,
      };
      if (info.isBoard) entry.hasBoard = true;
      else entry.count++;
      postingCountByBoard.set(info.key, entry);
    }

    const promotedBoardUrls: string[] = [];
    for (const [bKey, meta] of postingCountByBoard.entries()) {
      if (failedProbeBoardKeys.has(bKey)) continue;
      const isScopedCompanyBoardMatch =
        hasCompanyOrDomainScope &&
        meta.count >= 1 &&
        (!bKey.startsWith('workday:') || !primaryCompanySlug || bKey.startsWith(`workday:${primaryCompanySlug.toLowerCase()}:`));
      if (
        !meta.hasBoard &&
        (isScopedCompanyBoardMatch ||
          (meta.count >= 2 && (bKey.startsWith('ashby:') || bKey.startsWith('rippling:') || bKey.startsWith('workday:'))))
      ) {
        promotedBoardUrls.push(meta.boardUrl);
        if (/\s/.test(meta.slug)) {
          for (const fb of buildCompactSlugFallbackBoards({ platform: meta.platform, slug: meta.slug, boardUrl: meta.boardUrl })) {
            const fbKey = classifyFullBoardKey(fb.boardUrl)?.key ?? fb.boardUrl.replace(/\/+$/, '').toLowerCase();
            if (!failedProbeBoardKeys.has(fbKey)) promotedBoardUrls.push(fb.boardUrl);
          }
        }
      }
    }
    if (hasCompanyOrDomainScope) {
      for (const srOrg of smartRecruitersPostingOrgs) {
        const srBoardUrl = `https://jobs.smartrecruiters.com/${srOrg}`;
        if (failedProbeBoardKeys.has(srBoardUrl.toLowerCase())) continue;
        const hasSrBoardAlready = rawUrlList.some((u) => u.replace(/\/+$/, '').toLowerCase() === srBoardUrl.toLowerCase());
        if (!hasSrBoardAlready) promotedBoardUrls.push(srBoardUrl);
      }
    }

    const boardWaveUrls = [
      ...new Set([
        ...promotedBoardUrls,
        ...rawUrlList.filter((u) => {
          const info = classifyFullBoardKey(u);
          return Boolean(info?.isBoard || isSmartRecruitersBoardUrl(u));
        }),
      ]),
    ];
    const postingWaveUrls = [
      ...new Set(
        rawUrlList.filter((u) => {
          const info = classifyFullBoardKey(u);
          if (info?.platform === 'greenhouse') {
            try {
              const parsedGh = new URL(u);
              const ghParts = parsedGh.pathname.split('/').filter(Boolean);
              if (ghParts.length === 1 && parsedGh.searchParams.get('error')?.toLowerCase() === 'true') return false;
            } catch {
              // ignore
            }
          }
          return !info?.isBoard && !isSmartRecruitersBoardUrl(u);
        }),
      ),
    ];

    // Broad searches scrape one chunk per call (boards first) and return the rest as a continuation cursor.
    let remainingContinuation: JobsContinuation | null = null;
    let candidatesInChunk = boardWaveUrls.length + postingWaveUrls.length;
    if (!hasCompanyOrDomainScope && candidatesInChunk > JOBS_BROAD_CHUNK_URLS) {
      const boardTake = Math.min(boardWaveUrls.length, JOBS_BROAD_CHUNK_URLS);
      const postingTake = Math.min(postingWaveUrls.length, JOBS_BROAD_CHUNK_URLS - boardTake);
      const restBoards = boardWaveUrls.splice(boardTake);
      const restPostings = postingWaveUrls.splice(postingTake);
      remainingContinuation = {
        q: continuationKey,
        b: restBoards.slice(0, MAX_JOBS_CONTINUATION_URLS),
        p: restPostings.slice(0, MAX_JOBS_CONTINUATION_URLS),
      };
      candidatesInChunk = boardWaveUrls.length + postingWaveUrls.length;
    }

    const fetchedCompleteBoards = new Set<string>();
    const fetchedQueriedWorkdayBoards = new Map<string, { matchedCount: number; reqIds: Set<string> }>();
    const preWaveNowMs = Date.now();
    const preWaveCutoffMs = postedWithinDays ? preWaveNowMs - postedWithinDays * 86_400_000 : null;

    const matchesPreEnrichJobFilters = (r: StructuredJobRecord): boolean => {
      const cleanKey = r.url.replace(/\/+$/, '').toLowerCase();
      const isExcl = excludeList.some((ex) => {
        if (ex.url && ex.url === cleanKey) return true;
        const compMatch = ex.company && r.company.toLowerCase().includes(ex.company);
        const titleMatch = ex.title && r.title.toLowerCase().includes(ex.title);
        return Boolean((ex.company && ex.title && compMatch && titleMatch) || (ex.company && !ex.title && compMatch));
      });
      if (isExcl) return false;
      if (query && matchesJobQueryRelevance(r.title, r.snippet, query) === null) return false;
      if (wantRemote === true && r.workplaceType !== 'remote' && !r.locations.some((l) => /remote/i.test(l))) return false;
      if (geoLocationsFilter.length > 0 && !matchesGeoLocationsFilter(r.locations, geoLocationsFilter)) return false;
      if (preWaveCutoffMs !== null && postedWithinDays !== undefined) {
        if (r.postedAt) {
          const ts = Date.parse(r.postedAt);
          if (!Number.isFinite(ts) || ts < preWaveCutoffMs) return false;
        } else if (isJobLabelKnownStale(r.postedLabel, postedWithinDays)) {
          return false;
        }
      }
      return true;
    };

    const smartRecruitersPostingsToEnrich: StructuredJobRecord[] = [];
    const unverifiedPayUrls = new Set<string>();
    const verifiedBoardJobUrls = new Set<string>();
    let anyBoardTruncated = false;
    let primaryNextCursor: string | undefined;

    const runCandidateWave = async (waveUrls: string[]): Promise<void> => {
      for (let i = 0; i < waveUrls.length; i += MAX_JOBS_CONCURRENT_SCRAPES) {
        const rawSlice = waveUrls.slice(i, i + MAX_JOBS_CONCURRENT_SCRAPES);
        const slice = rawSlice.filter((u) => {
          const info = classifyFullBoardKey(u);
          if (info && !info.isBoard && fetchedCompleteBoards.has(info.key)) return false;
          if (info?.platform === 'workday' && !info.isBoard) {
            const wdQueried = fetchedQueriedWorkdayBoards.get(info.key);
            if (wdQueried) {
              const reqId = extractWorkdayReqId(u);
              if ((reqId && wdQueried.reqIds.has(reqId)) || wdQueried.matchedCount >= limit) return false;
            }
          }
          return true;
        });
        if (slice.length === 0) continue;

        const batchOut = await Promise.all(
          slice.map((u) => {
            let scrapeUrl = u;
            const srBoard = isSmartRecruitersBoardUrl(u);
            const info = classifyFullBoardKey(u);
            if (/myworkday(?:jobs|site)\.com/i.test(u) && !/\/job\//i.test(u)) {
              try {
                const wdU = new URL(u);
                if (query && !wdU.searchParams.has('q')) wdU.searchParams.set('q', query);
                if (boardStartOffset > 0 && !wdU.searchParams.has('offset')) wdU.searchParams.set('offset', String(boardStartOffset));
                scrapeUrl = wdU.toString();
              } catch {
                scrapeUrl = u;
              }
            } else if (boardStartOffset > 0 && info?.isBoard) {
              try {
                const bU = new URL(u);
                if (!bU.searchParams.has('offset')) bU.searchParams.set('offset', String(boardStartOffset));
                scrapeUrl = bU.toString();
              } catch {
                scrapeUrl = u;
              }
            } else if (cursorIcimsPage && /\.icims\.com\/jobs\b/i.test(u) && !/\/jobs\/\d+/i.test(u)) {
              try {
                const icU = new URL(u);
                icU.searchParams.set('pr', cursorIcimsPage);
                scrapeUrl = icU.toString();
              } catch {
                scrapeUrl = u;
              }
            }
            const needLinks = Boolean(srBoard || info?.isBoard || discoveredBoards.some((b) => b.boardUrl === u));
            const isGhBoard = Boolean(info?.platform.startsWith('greenhouse') && info.isBoard);
            return executeScrape({
              url: scrapeUrl,
              renderMode: srBoard ? 'off' : 'auto',
              discoverLlmsTxt: false,
              preferOriginMarkdown: false,
              ephemeral: true,
              ...(isGhBoard ? { atsLiteBoard: true } : {}),
              formats: needLinks ? ['markdown', 'links'] : ['markdown'],
              ...(payload.target ? { target: payload.target } : {}),
              ...(payload.site ? { site: payload.site } : {}),
            }).catch(() => null);
          }),
        );

        for (let j = 0; j < slice.length; j++) {
          const origU = slice[j]!;
          const sc = batchOut[j];
          const discEntry = discoveredBoards.find((b) => b.boardUrl === origU);
          if (!sc || sc.status !== 200 || sc.body?.ok !== true) {
            if (isClosedSchemeDowngradeResult(origU, sc)) continue;
            if (discEntry) {
              if (sc?.body?.error === 'jobs_scrape_budget_exceeded') {
                discEntry.boardStatus = 'budget_exhausted';
              } else {
                const upstreamStatus =
                  typeof sc?.body?.status === 'number' && sc.body.status > 0 ? sc.body.status : (sc?.status ?? 0);
                discEntry.boardStatus = classifyAtsBoardStatus({
                  httpStatus: upstreamStatus,
                  requestedUrl: origU,
                  finalUrl: typeof sc?.body?.finalUrl === 'string' ? sc.body.finalUrl : undefined,
                });
              }
            }
            continue;
          }

          const cState = typeof sc.body.contentState === 'string' ? sc.body.contentState : undefined;
          // A maintenance page says nothing about the board: skip it without marking the board closed.
          if (cState === 'temporarily_unavailable') continue;
          if (cState === 'closed_posting' || cState === 'soft_404' || cState === 'login_wall') {
            if (discEntry) {
              discEntry.boardStatus = classifyAtsBoardStatus({
                httpStatus: sc.status,
                requestedUrl: origU,
                finalUrl: typeof sc.body.finalUrl === 'string' ? sc.body.finalUrl : undefined,
                contentState: cState,
              });
            }
            continue;
          }

          if (Array.isArray(sc.body.jobs)) {
            const fullInfo = classifyFullBoardKey(origU);
            if (fullInfo && sc.body.truncated !== true && boardStartOffset === 0) {
              fetchedCompleteBoards.add(fullInfo.key);
            }
            const boardExtId =
              typeof sc.body.extractorId === 'string' && sc.body.extractorId
                ? sc.body.extractorId
                : resolveAtsPreFetchSpec(origU)?.id;
            if (boardExtId) resolvedAdapterIds.add(boardExtId);
            const boardJobs = [...(sc.body.jobs as StructuredJobRecord[])];
            let knownBoardTotal: number | undefined =
              typeof sc.body.total === 'number' && Number.isFinite(sc.body.total) ? sc.body.total : undefined;
            let boardTruncated = sc.body.truncated === true;
            let boardNextCursor = typeof sc.body.nextCursor === 'string' ? sc.body.nextCursor : undefined;

            if (boardTruncated && boardNextCursor && /myworkday(?:jobs|site)\.com/i.test(origU)) {
              let nextOffset = parseInt(boardNextCursor, 10);
              const maxOffsetThisCall = boardStartOffset + 80;
              const enoughBoardMatches = minBase !== undefined ? Math.max(limit * 3, 18) : Math.max(limit * 2, 12);
              while (Number.isFinite(nextOffset) && nextOffset > boardStartOffset && nextOffset <= maxOffsetThisCall) {
                if (boardJobs.filter(matchesPreEnrichJobFilters).length >= enoughBoardMatches) break;
                let pageUrlStr = '';
                try {
                  const wdPageU = new URL(origU);
                  wdPageU.searchParams.set('offset', String(nextOffset));
                  if (query && !wdPageU.searchParams.has('q')) wdPageU.searchParams.set('q', query);
                  pageUrlStr = wdPageU.toString();
                } catch {
                  break;
                }
                const wdPageRes = await executeScrape({
                  url: pageUrlStr,
                  renderMode: 'off',
                  discoverLlmsTxt: false,
                  preferOriginMarkdown: false,
                  ephemeral: true,
                  formats: ['markdown'],
                  ...(payload.target ? { target: payload.target } : {}),
                  ...(payload.site ? { site: payload.site } : {}),
                }).catch(() => null);
                const moreJobs = Array.isArray(wdPageRes?.body?.jobs) ? (wdPageRes!.body.jobs as StructuredJobRecord[]) : [];
                if (wdPageRes?.status !== 200 || moreJobs.length === 0) {
                  boardTruncated =
                    knownBoardTotal !== undefined ? knownBoardTotal > boardStartOffset + boardJobs.length : moreJobs.length > 0;
                  if (boardTruncated) boardNextCursor = String(boardStartOffset + boardJobs.length);
                  break;
                }
                boardJobs.push(...moreJobs);
                if (typeof wdPageRes.body.total === 'number' && wdPageRes.body.total > 0) {
                  knownBoardTotal = Math.max(knownBoardTotal ?? 0, wdPageRes.body.total);
                }
                const endOffsetNow = boardStartOffset + boardJobs.length;
                boardTruncated =
                  knownBoardTotal !== undefined
                    ? knownBoardTotal > endOffsetNow
                    : wdPageRes.body.truncated === true || moreJobs.length >= 20;
                boardNextCursor = boardTruncated ? String(endOffsetNow) : undefined;
                if (!boardTruncated || !boardNextCursor) break;
                nextOffset = parseInt(boardNextCursor, 10);
              }
            }

            const effectiveEndOffset = boardStartOffset + boardJobs.length;
            const finalBoardTruncated = knownBoardTotal !== undefined ? knownBoardTotal > effectiveEndOffset : boardTruncated;
            const finalBoardNextCursor = finalBoardTruncated ? (boardNextCursor ?? String(effectiveEndOffset)) : undefined;
            if (finalBoardTruncated) {
              anyBoardTruncated = true;
              if (!primaryNextCursor && finalBoardNextCursor) primaryNextCursor = finalBoardNextCursor;
            }

            if (discEntry) {
              discEntry.boardStatus = classifyAtsBoardStatus({
                httpStatus: sc.status,
                requestedUrl: origU,
                finalUrl: typeof sc.body.finalUrl === 'string' ? sc.body.finalUrl : undefined,
                jobCount: boardJobs.length,
              });
              if (knownBoardTotal !== undefined) discEntry.total = knownBoardTotal;
              discEntry.returned = boardJobs.length;
              discEntry.truncated = finalBoardTruncated;
              if (finalBoardTruncated && finalBoardNextCursor) discEntry.nextCursor = finalBoardNextCursor;
            }
            for (const br of boardJobs) {
              if (br.source) {
                sourcesUsed.add(`ats:${br.source}`);
                resolvedAdapterIds.add(br.source);
              }
              collected.push(br);
            }
            if (fullInfo?.platform === 'workday' && boardStartOffset === 0) {
              const prevWd = fetchedQueriedWorkdayBoards.get(fullInfo.key);
              const reqIds = prevWd?.reqIds ?? new Set<string>();
              for (const br of boardJobs) {
                const rid = extractWorkdayReqId(br.url);
                if (rid) reqIds.add(rid);
              }
              const matchedHere = boardJobs.filter(matchesPreEnrichJobFilters).length;
              fetchedQueriedWorkdayBoards.set(fullInfo.key, {
                matchedCount: (prevWd?.matchedCount ?? 0) + matchedHere,
                reqIds,
              });
            }
            {
              const seenDetailDedup = new Set<string>();
              const detailCandidates: Array<{ rec: StructuredJobRecord; rank: number }> = [];
              for (const r of boardJobs) {
                const isWorkdayNeedsPay = r.source === 'workday' && r.pay === null && /\/job\//i.test(r.url);
                const isLiteGhNeedsDetail = r.source === 'greenhouse' && !r.snippet && /\/jobs\/\d+/i.test(r.url);
                if (!isWorkdayNeedsPay && !isLiteGhNeedsDetail) continue;
                if (!matchesPreEnrichJobFilters(r)) continue;
                const dk = canonicalJobKey(r.company, r.title);
                if (seenDetailDedup.has(dk)) continue;
                seenDetailDedup.add(dk);
                const rel = query ? matchesJobQueryRelevance(r.title, r.snippet, query) : 'company_filter';
                const rank = rel === 'phrase' ? 0 : rel === 'all_tokens' ? 1 : 2;
                detailCandidates.push({ rec: r, rank });
              }
              if (detailCandidates.length > 0) {
                detailCandidates.sort((a, b) => a.rank - b.rank);
                const maxDetailPerCall = minBase !== undefined ? 6 : 5;
                const remainingEnrichSlots = Math.max(0, 10 - smartRecruitersPostingsToEnrich.length);
                const detailCap = Math.min(limit, maxDetailPerCall, remainingEnrichSlots);
                for (const { rec: dRec } of detailCandidates.slice(0, detailCap)) {
                  smartRecruitersPostingsToEnrich.push(dRec);
                }
                for (const { rec: skippedRec } of detailCandidates.slice(detailCap)) {
                  if (skippedRec.pay === null) unverifiedPayUrls.add(skippedRec.url.toLowerCase());
                }
              }
            }
            continue;
          }

          if (isSmartRecruitersBoardUrl(origU)) {
            const srRecords = parseSmartRecruitersBoardScrape(origU, sc.body);
            if (discEntry) {
              discEntry.boardStatus = classifyAtsBoardStatus({
                httpStatus: sc.status,
                requestedUrl: origU,
                finalUrl: typeof sc.body.finalUrl === 'string' ? sc.body.finalUrl : undefined,
                jobCount: srRecords.length,
              });
              discEntry.total = srRecords.length;
              discEntry.returned = srRecords.length;
              discEntry.truncated = false;
            }
            if (srRecords.length > 0) {
              sourcesUsed.add('ats:smartrecruiters');
              resolvedAdapterIds.add('smartrecruiters');
              const matchingSr = query
                ? srRecords.filter((r) => matchesJobQueryRelevance(r.title, r.snippet, query) !== null)
                : srRecords;
              const srCap = Math.min(limit, 8, Math.max(0, 10 - smartRecruitersPostingsToEnrich.length));
              for (const r of matchingSr.slice(0, srCap)) smartRecruitersPostingsToEnrich.push(r);
              for (const r of matchingSr.slice(srCap)) {
                if (r.pay === null && matchesPreEnrichJobFilters(r)) {
                  unverifiedPayUrls.add(r.url.toLowerCase());
                }
              }
              for (const r of srRecords) collected.push(r);
            }
            continue;
          }

          if (
            Array.isArray(sc.body.records) &&
            (sc.body.extractorId === 'icims' || sc.body.extractorId === 'ukg-paylocity-dover')
          ) {
            const extId = sc.body.extractorId;
            const boardRecs = sc.body.records as Array<Record<string, unknown>>;
            const boardCoFallback = inferCompanyFromAtsUrl(origU);
            const isVerifiedBoard = Boolean(
              discEntry &&
                discEntry.discoveredFrom &&
                !discEntry.discoveredFrom.startsWith('slug-probe:') &&
                !discEntry.discoveredFrom.startsWith('search:'),
            );
            if (discEntry) {
              discEntry.boardStatus = classifyAtsBoardStatus({
                httpStatus: sc.status,
                requestedUrl: origU,
                finalUrl: typeof sc.body.finalUrl === 'string' ? sc.body.finalUrl : undefined,
                jobCount: boardRecs.length,
              });
              if (typeof sc.body.total === 'number') discEntry.total = sc.body.total;
              discEntry.returned = boardRecs.length;
              discEntry.truncated = Boolean(sc.body.truncated);
            }
            let defaultSource = extId === 'icims' ? 'icims' : 'ukg-paylocity-dover';
            if (extId === 'ukg-paylocity-dover') {
              if (/ultipro\.com/i.test(origU)) defaultSource = 'ukg';
              else if (/paylocity\.com/i.test(origU)) defaultSource = 'paylocity';
              else if (/dover\.(?:com|io)/i.test(origU)) defaultSource = 'dover';
            }
            sourcesUsed.add(`ats:${defaultSource}`);
            resolvedAdapterIds.add(extId);
            for (const rc of boardRecs) {
              const rTitle = typeof rc.title === 'string' ? rc.title.trim() : '';
              const rUrl =
                typeof rc.url === 'string' && rc.url.trim()
                  ? rc.url.trim()
                  : typeof rc.applyUrl === 'string'
                    ? rc.applyUrl.trim()
                    : '';
              if (!rTitle || !rUrl) continue;
              if (isVerifiedBoard) {
                verifiedBoardJobUrls.add(rUrl.replace(/\/+$/, '').toLowerCase());
              }
              const rApplyUrl = typeof rc.applyUrl === 'string' && rc.applyUrl.trim() ? rc.applyUrl.trim() : rUrl;
              const rLoc =
                typeof rc.location === 'string'
                  ? rc.location.trim()
                  : Array.isArray(rc.locations) && typeof rc.locations[0] === 'string'
                    ? rc.locations[0].trim()
                    : '';
              const rComp = typeof rc.company === 'string' && rc.company.trim() ? rc.company.trim() : boardCoFallback;
              const rDesc = typeof rc.description === 'string' ? rc.description.trim() : '';
              const payText = [rc.salary, rc.payRaw, rc.compensation, rDesc, rTitle]
                .filter((v): v is string => typeof v === 'string' && v.trim().length > 0)
                .join(' ');
              const rSource = typeof rc.source === 'string' && rc.source.trim() ? rc.source.trim() : defaultSource;
              collected.push({
                title: rTitle,
                company: rComp,
                url: rUrl,
                applyUrl: rApplyUrl,
                workplaceType: inferWorkdayWorkplaceType(rDesc, rLoc, rTitle),
                locations: rLoc ? [rLoc] : [],
                pay: payText ? parsePayFromText(payText) : null,
                postedAt: typeof rc.postedAt === 'string' ? rc.postedAt : null,
                source: rSource,
                ...(rDesc ? { snippet: rDesc.slice(0, 240) } : {}),
              });
            }
            continue;
          }

          const rawPageHtml =
            typeof sc.body.rawHtml === 'string' ? sc.body.rawHtml : typeof sc.body.html === 'string' ? sc.body.html : '';
          const md = typeof sc.body.markdown === 'string' ? sc.body.markdown : '';
          const jp =
            (sc.body.jobPosting as StructuredJobPosting | undefined) ??
            (rawPageHtml ? (extractJobPostingJsonLd(rawPageHtml, origU, md) ?? undefined) : undefined);
          const meta = (sc.body.metadata as Record<string, unknown> | undefined) ?? {};
          const rawTitle = (jp?.title || (typeof meta.title === 'string' ? meta.title : '')).replace(/\s*[@|–-]\s*[^@|–-]+$/, '').trim();
          if (!rawTitle) continue;
          const company = jp?.hiringOrganization || inferCompanyFromAtsUrl(origU);
          const pay = jp?.pay ?? parsePayFromText(md);
          const locs = jp?.jobLocation ?? [];
          const wp =
            jp?.workplaceType && jp.workplaceType !== 'unknown'
              ? jp.workplaceType
              : inferWorkplaceType(`${locs.join(' ')} ${md.slice(0, 400)}`);
          const postedAt = jp?.datePosted ?? (typeof meta.publishedTime === 'string' ? meta.publishedTime : null);
          const canonicalPostingUrl = (() => {
            if (jp?.url && jp.url.startsWith('https://')) {
              try {
                const parsedJpU = new URL(jp.url);
                const parsedOrigU = new URL(origU);
                if (parsedJpU.hostname.toLowerCase() === parsedOrigU.hostname.toLowerCase()) return parsedJpU.toString();
              } catch {
                // ignore
              }
            }
            try {
              return new URL(origU).toString();
            } catch {
              return origU;
            }
          })();
          const applyUrl = jp?.applyUrl || canonicalPostingUrl;
          const jobSource = jp?.source || (/smartrecruiters\.com/i.test(origU) ? 'smartrecruiters' : String(sc.body.extractorId ?? 'ats'));
          sourcesUsed.add(`ats:${jobSource}`);
          const postExtId =
            typeof sc.body.extractorId === 'string' && sc.body.extractorId
              ? sc.body.extractorId
              : resolveAtsPreFetchSpec(origU)?.id ?? (jobSource !== 'ats' ? jobSource : undefined);
          if (postExtId) resolvedAdapterIds.add(postExtId);

          collected.push({
            title: rawTitle,
            company,
            url: canonicalPostingUrl,
            applyUrl,
            workplaceType: wp,
            locations: locs,
            pay,
            postedAt,
            source: jobSource,
            ...(jp?.employmentType ? { employmentType: jp.employmentType } : {}),
            ...(md ? { snippet: md.slice(0, 240) } : {}),
          });
        }
      }
    };

    for (const waveUrls of [boardWaveUrls, postingWaveUrls]) {
      await runCandidateWave(waveUrls);
    }

    if (
      companyFilter &&
      domainsInput.length === 0 &&
      collected.length === 0 &&
      fetchedCompleteBoards.size === 0 &&
      !budgetExhausted
    ) {
      const alreadyTriedLower = new Set([...boardWaveUrls, ...postingWaveUrls].map((u) => u.replace(/\/+$/, '').toLowerCase()));
      const rescueUrls = buildDirectCompanyProbeUrls().filter((u) => {
        const clean = u.replace(/\/+$/, '').toLowerCase();
        if (alreadyTriedLower.has(clean)) return false;
        candidateUrls.add(u);
        return true;
      });
      if (rescueUrls.length > 0) await runCandidateWave(rescueUrls);
      if (
        collected.length === 0 &&
        fetchedCompleteBoards.size === 0 &&
        !budgetExhausted &&
        primaryCompanySlug &&
        isValidAtsSlug(primaryCompanySlug)
      ) {
        const wdTenant = primaryCompanySlug.toLowerCase();
        const rawTrimmed = companyFilter.replace(/[^A-Za-z0-9_-]+/g, '');
        const wdSite = rawTrimmed && rawTrimmed.toLowerCase() === wdTenant ? rawTrimmed : primaryCompanySlug;
        const wdRescueUrls = [
          `https://${wdTenant}.wd5.myworkdayjobs.com/${wdSite}`,
          `https://${wdTenant}.wd1.myworkdayjobs.com/${wdSite}`,
          `https://${wdTenant}.wd5.myworkdayjobs.com/External`,
          `https://${wdTenant}.wd1.myworkdayjobs.com/External`,
        ].filter((u) => {
          const clean = u.replace(/\/+$/, '').toLowerCase();
          if (alreadyTriedLower.has(clean)) return false;
          alreadyTriedLower.add(clean);
          candidateUrls.add(u);
          return true;
        });
        if (wdRescueUrls.length > 0) await runCandidateWave(wdRescueUrls);
      }
    }

    if (smartRecruitersPostingsToEnrich.length > 0 && !budgetExhausted) {
      for (let i = 0; i < smartRecruitersPostingsToEnrich.length; i += MAX_JOBS_CONCURRENT_SCRAPES) {
        const batch = smartRecruitersPostingsToEnrich.slice(i, i + MAX_JOBS_CONCURRENT_SCRAPES);
        const outs = await Promise.all(
          batch.map((srRec) =>
            executeScrape({
              url: srRec.url,
              renderMode: 'off',
              discoverLlmsTxt: false,
              preferOriginMarkdown: false,
              ephemeral: true,
              formats: ['markdown'],
              ...(payload.target ? { target: payload.target } : {}),
              ...(payload.site ? { site: payload.site } : {}),
            }).catch(() => null),
          ),
        );
        for (let j = 0; j < batch.length; j++) {
          const srRec = batch[j]!;
          const det = outs[j];
          if (!det) continue;
          const detState = typeof det.body?.contentState === 'string' ? det.body.contentState : undefined;
          if (detState === 'closed_posting' || (det.status === 200 && detState === 'soft_404')) {
            const dropIdx = collected.findIndex((c) => c.url.toLowerCase() === srRec.url.toLowerCase());
            if (dropIdx >= 0) collected.splice(dropIdx, 1);
            continue;
          }
          // Keep the listing, but don't enrich it from a maintenance page.
          if (detState === 'temporarily_unavailable') continue;
          if (det.status !== 200 || det.body?.ok !== true) continue;
          const detHtml =
            typeof det.body.rawHtml === 'string' ? det.body.rawHtml : typeof det.body.html === 'string' ? det.body.html : '';
          const detMd = typeof det.body.markdown === 'string' ? det.body.markdown : '';
          const jp =
            (det.body.jobPosting as StructuredJobPosting | undefined) ??
            (detHtml ? (extractJobPostingJsonLd(detHtml, srRec.url, detMd) ?? undefined) : undefined);
          const target = collected.find((c) => c.url.toLowerCase() === srRec.url.toLowerCase());
          if (!target) continue;
          if (jp?.title) target.title = jp.title;
          if (jp?.hiringOrganization) target.company = jp.hiringOrganization;
          if (jp?.jobLocation && jp.jobLocation.length > 0) target.locations = jp.jobLocation;
          if (jp?.workplaceType && jp.workplaceType !== 'unknown') target.workplaceType = jp.workplaceType;
          if (jp?.pay) target.pay = jp.pay;
          else if (!target.pay && detMd) target.pay = parsePayFromText(detMd);
          if (jp?.datePosted) {
            target.postedAt = jp.datePosted;
            delete target.postedLabel;
          }
          if (jp?.employmentType) target.employmentType = jp.employmentType;
          if (jp?.applyUrl) target.applyUrl = jp.applyUrl;
          if (!target.snippet && detMd) target.snippet = detMd.slice(0, 240);
        }
      }
    } else if (smartRecruitersPostingsToEnrich.length > 0 && budgetExhausted) {
      for (const unenriched of smartRecruitersPostingsToEnrich) {
        if (unenriched.pay === null) unverifiedPayUrls.add(unenriched.url.toLowerCase());
      }
    }

    const allowedCompanyTokens = new Set<string>();
    if (companyFilter) {
      allowedCompanyTokens.add(companyFilter);
      for (const expanded of expandCompanyFilterTokens(companyFilter)) allowedCompanyTokens.add(expanded);
    }
    for (const dom of domainsInput) {
      allowedCompanyTokens.add(dom);
      const explicitWd = /^([a-z0-9-]+)\.(wd\d+)\.myworkday(?:jobs|site)\.com$/i.exec(dom);
      if (explicitWd?.[1]) allowedCompanyTokens.add(explicitWd[1].toLowerCase());
    }
    for (const db of discoveredBoards) {
      const isVerifiedFirstPartyLink =
        Boolean(db.discoveredFrom) &&
        !db.discoveredFrom.startsWith('slug-probe:') &&
        !db.discoveredFrom.startsWith('search:');
      if (isVerifiedFirstPartyLink && db.boardStatus !== 'not_found' && db.boardStatus !== 'budget_exhausted' && db.slug) {
        const rootSlug = (db.slug.split('/')[0] ?? '').toLowerCase().replace(/[^a-z0-9]+/g, '');
        if (rootSlug) allowedCompanyTokens.add(rootSlug);
      }
    }
    const allowedBoardPrefixes = [
      ...new Set([
        ...discoveredBoards
          .filter(
            (b) =>
              Boolean(b.discoveredFrom) &&
              !b.discoveredFrom.startsWith('slug-probe:') &&
              !b.discoveredFrom.startsWith('search:') &&
              b.boardStatus !== 'not_found' &&
              b.boardStatus !== 'budget_exhausted' &&
              b.boardUrl,
          )
          .map((b) => b.boardUrl.replace(/\/+$/, '').toLowerCase()),
        ...verifiedBoardJobUrls,
      ]),
    ];

    const rankOut = callCoreWasm<{
      finalIndices: Array<{ index: number; matchedOn: 'phrase' | 'all_tokens' | 'company_filter'; payUnknown?: boolean }>;
      matchedTotal: number;
      payUnknownCount?: number;
    }>('jobs_filter_and_rank', {
      collected,
      query,
      hasCompanyOrDomainScope,
      allowedCompanyTokens: [...allowedCompanyTokens],
      allowedBoardPrefixes,
      excludeList,
      ...(wantRemote !== undefined ? { wantRemote } : {}),
      geoLocationsFilter,
      ...(minBase !== undefined ? { minBase } : {}),
      minBaseMode,
      strictPay,
      ...(postedWithinDays !== undefined ? { postedWithinDays } : {}),
      limit,
      nowMs: Date.now(),
    });

    const finalJobs: StructuredJobRecord[] = (rankOut.finalIndices ?? []).map((ri) => ({
      ...collected[ri.index]!,
      matchedOn: ri.matchedOn,
      ...(ri.payUnknown ? { payUnknown: true } : {}),
    }));
    const payUnknownCount = minBase !== undefined ? (rankOut.payUnknownCount ?? 0) : undefined;
    const payUnverifiedCount =
      minBase !== undefined && strictPay
        ? collected.filter((c) => c.pay === null && unverifiedPayUrls.has(c.url.toLowerCase())).length
        : 0;
    const responseTruncated = anyBoardTruncated || rankOut.matchedTotal > limit;
    const resolvedTopCursor = primaryNextCursor;

    if (anyBoardTruncated && resolvedTopCursor && !notes.some((n) => n.includes('cursor:'))) {
      notes.push(
        `Board listing was cut short; pass \`cursor: "${resolvedTopCursor}"\` (or \`offset: ${resolvedTopCursor}\`) to fetch the next page.`,
      );
    }
    if (remainingContinuation) {
      notes.push(
        `Checked ${candidatesInChunk} candidate job board(s)/posting(s) in this call; ` +
          `${remainingContinuation.b.length + remainingContinuation.p.length} more remain. ` +
          'Pass `cursor` = `continueCursor` with the same query to check the next chunk (no new web search).',
      );
    }
    if (timeBudgetExhausted && !notes.some((n) => n.includes('Time budget'))) {
      notes.push(
        `Time budget (${Math.round(wallBudgetMs / 1_000)} s) reached before all candidate boards could be checked; results are partial. ` +
          'Add `company` or `domains` to narrow the search.',
      );
    } else if (budgetExhausted && !notes.some((n) => n.includes('Scrape budget'))) {
      notes.push(`Scrape budget (${MAX_JOBS_TOTAL_SCRAPES}) exhausted before all candidate boards could be checked.`);
    }
    if (payUnverifiedCount > 0 && !notes.some((n) => n.includes('pay not verified'))) {
      notes.push(
        `${payUnverifiedCount} matching posting(s) past the detail enrichment limit had pay not verified and were excluded under \`strictPay\`.`,
      );
    }
    if (candidateUrls.size === 0 && collected.length === 0 && domainsInput.length === 0) {
      // Only blame configuration when no search provider is configured; otherwise the search ran and matched nothing.
      const hasSearchProvider = Boolean(
        env?.SERPER_API_KEY || env?.BRAVE_API_KEY || env?.TAVILY_API_KEY || env?.SEARXNG_URL || env?.SEARCH,
      );
      notes.push(
        hasSearchProvider
          ? timeBudgetExhausted
            ? 'No ATS job boards were found within the time budget. Add `company` or `domains` to narrow the search.'
            : 'The job-board search ran but matched no ATS boards for this query. Try a broader query, or add `company` or `domains`.'
          : 'No ATS search results returned: no search provider is configured on the Hub (set SERPER_API_KEY, BRAVE_API_KEY, TAVILY_API_KEY or SEARXNG_URL).',
      );
    }

    const boardsDiscoveredCount = discoveredBoards.filter((b) => b.boardStatus !== 'not_found' && Boolean(b.boardUrl)).length;
    activeTracer?.setAttribute('edgefetch.jobs.mode', 'search');
    activeTracer?.setAttribute('edgefetch.jobs.boards_discovered', boardsDiscoveredCount);
    activeTracer?.setAttribute('edgefetch.jobs.jobs_returned', finalJobs.length);
    if (resolvedAdapterIds.size > 0) {
      activeTracer?.setAttribute('edgefetch.adapter_id', [...resolvedAdapterIds].join(','));
    }

    return {
      status: 200,
      body: {
        ok: true,
        query,
        ...(companyFilter ? { company: companyFilter } : {}),
        ...(domainsInput.length > 0 ? { domains: domainsInput, discoveredBoards } : {}),
        ...(boardStartOffset > 0 ? { offset: boardStartOffset } : {}),
        ...(minBase !== undefined
          ? {
              minBaseMode,
              strictPay,
              payUnknownCount,
              ...(payUnverifiedCount > 0 ? { payUnverifiedCount } : {}),
            }
          : {}),
        ...(responseTruncated ? { truncated: true } : {}),
        ...(resolvedTopCursor ? { nextCursor: resolvedTopCursor } : {}),
        ...(budgetExhausted ? { budgetExhausted: true } : {}),
        ...(timeBudgetExhausted ? { timeBudgetExhausted: true } : {}),
        ...(remainingContinuation
          ? {
              continueCursor: encodeJobsContinuation(remainingContinuation),
              remainingCandidates: remainingContinuation.b.length + remainingContinuation.p.length,
            }
          : {}),
        sourcesUsed: [...sourcesUsed],
        count: finalJobs.length,
        candidatesChecked: candidateUrls.size,
        postingsEvaluated: collected.length,
        jobs: finalJobs,
        ...(notes.length > 0 ? { notes } : {}),
      },
    };
  };

  return activeTracer ? activeTracer.run(runJobs) : runJobs();
}
