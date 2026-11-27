/**
 * 1-Click Opt-In OTLP Structural Error Telemetry Exporter & `hub_settings` Store (`hub/src/dev-telemetry.ts`).
 *
 * Strict Privacy & Opt-In Invariants:
 *  1. Unattended default is ALWAYS `OFF` (`EDGEFETCH_DEV_TELEMETRY` unset / `0` / `false` -> `0` outbound telemetry).
 *  2. Console `DO_NOT_TRACK` (`https://consoledonottrack.com/` — any non-empty value not in `{'0','false','no','off','unset'}`)
 *     acts as an unconditional hard disable override even if `EDGEFETCH_DEV_TELEMETRY=1` or `/admin` toggle is ON!
 *  3. Exports ONLY failed (`status.code === 2` / `statusOk === false`) or verified WAF-failure spans, scrubbed to the exact 11
 *     allowlisted structural fields:
 *       `{ schemaVersion: 1, version, runtime, os, arch, mode, spanName, adapterId, wafVendor, httpStatus, errorClass }`
 *     — ZERO URLs, ZERO hostnames, ZERO paths, ZERO query strings, ZERO vault server/tool names, ZERO stack messages, ZERO tokens!
 */
import hubPkg from '../package.json';
import type { SqlStorageLike } from './oauth';
import type { OtlpSpanInput } from './otel';

export const DEFAULT_DEV_TELEMETRY_ENDPOINT = 'https://telemetry.edgefetch.dev/v1/dev-errors';
export const DEV_TELEMETRY_SETTING_KEY = 'dev_error_telemetry';
export const MAX_DEV_TELEMETRY_EVENTS_PER_POST = 8;
const MAX_INFLIGHT_DEV_TELEMETRY_EXPORTS = 4;

export const HUB_SETTINGS_SQLITE_SCHEMA = `
  CREATE TABLE IF NOT EXISTS hub_settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at INTEGER NOT NULL
  );
`;

export interface HubSettingsStore {
  getSetting(key: string): Promise<string | null>;
  setSetting(key: string, value: string, now?: number): Promise<void>;
}

export function createSqliteHubSettingsStore(sql: SqlStorageLike): HubSettingsStore {
  return {
    async getSetting(key: string): Promise<string | null> {
      const row = sql
        .exec<{ value: string }>('SELECT value FROM hub_settings WHERE key = ?', key)
        .toArray()[0];
      return typeof row?.value === 'string' ? row.value : null;
    },
    async setSetting(key: string, value: string, now = Date.now()): Promise<void> {
      sql.exec(
        'INSERT OR REPLACE INTO hub_settings (key, value, updated_at) VALUES (?, ?, ?)',
        key,
        value,
        now,
      );
    },
  };
}

export function createMemoryHubSettingsStore(): HubSettingsStore {
  const map = new Map<string, string>();
  return {
    async getSetting(key: string): Promise<string | null> {
      return map.get(key) ?? null;
    },
    async setSetting(key: string, value: string): Promise<void> {
      map.set(key, value);
    },
  };
}

export type TelemetryRuntime = 'workers' | 'node' | 'deno' | 'go';

export interface DevErrorReport {
  schemaVersion: 1;
  version: string;
  runtime: TelemetryRuntime;
  os: string;
  arch: string;
  mode: string;
  spanName: string;
  adapterId: string;
  wafVendor: string;
  httpStatus: number;
  errorClass: string;
}

export interface DevTelemetryEnvConfig {
  EDGEFETCH_DEV_TELEMETRY?: string;
  EDGEFETCH_DEV_TELEMETRY_ENDPOINT?: string;
  EDGEFETCH_DEV_TELEMETRY_URL?: string;
  DO_NOT_TRACK?: string;
  SAFE_PUBLIC_FETCH?: typeof fetch;
  SAFE_FETCH?: typeof fetch;
}

export interface DevTelemetrySettingsView {
  enabled: boolean;
  source: 'default_off' | 'env' | 'admin_opt_in' | 'admin_opt_out' | 'do_not_track';
  doNotTrack: boolean;
  endpoint: string;
  allowlistedFields: readonly string[];
}

export const DEV_ERROR_ALLOWLISTED_FIELDS = [
  'schemaVersion',
  'version',
  'runtime',
  'os',
  'arch',
  'mode',
  'spanName',
  'adapterId',
  'wafVendor',
  'httpStatus',
  'errorClass',
] as const;

const ALLOWLISTED_FIELD_SET: ReadonlySet<string> = new Set(DEV_ERROR_ALLOWLISTED_FIELDS);
const VALID_RUNTIMES: ReadonlySet<string> = new Set(['workers', 'node', 'deno', 'go']);
const DNT_EXPLICIT_DISABLE_VALUES: ReadonlySet<string> = new Set(['0', 'false', 'no', 'off', 'unset']);

export const KNOWN_TELEMETRY_OS: ReadonlySet<string> = new Set([
  'linux',
  'darwin',
  'win32',
  'windows',
  'freebsd',
  'openbsd',
  'netbsd',
  'android',
  'aix',
  'sunos',
  'cloudflare',
  'unknown',
]);

export const KNOWN_TELEMETRY_ARCH: ReadonlySet<string> = new Set([
  'x64',
  'amd64',
  'arm64',
  'aarch64',
  'arm',
  'ia32',
  '386',
  'riscv64',
  'ppc64',
  'ppc64le',
  's390x',
  'v8',
  'wasm32',
  'unknown',
]);

export const KNOWN_TELEMETRY_MODES: ReadonlySet<string> = new Set([
  'hub',
  'agent',
  'server',
  'serve',
  'mcp',
  'desktop',
  'cli',
  'portable',
  'worker',
  'container',
]);

export const KNOWN_TELEMETRY_WAF_VENDORS: ReadonlySet<string> = new Set([
  'cloudflare',
  'akamai',
  'datadome',
  'perimeterx',
  'aws-waf',
  'imperva',
  'vercel',
  'fastly',
  'kasada',
  'sucuri',
  'f5',
  'radware',
  'turnstile',
  'hcaptcha',
  'recaptcha',
  'generic',
]);

export const KNOWN_TELEMETRY_ERROR_CLASSES: ReadonlySet<string> = new Set([
  'waf_challenge',
  'waf_block',
  'rate_limited',
  'payment_required',
  'robots_disallowed',
  'ssrf_blocked',
  'timeout',
  'tls_error',
  'dns_error',
  'connect_error',
  'browser_error',
  'adapter_error',
  'http_401',
  'http_403',
  'http_404',
  'http_4xx',
  'http_5xx',
  'internal_error',
]);

/**
 * Exhaustive allowlist of static built-in EdgeFetch adapter, ATS, commerce, and pipeline extractor IDs.
 * Guarantees zero customer domains, zero hostnames, and zero private federated MCP server/tool slugs can ever be emitted!
 */
export const KNOWN_TELEMETRY_ADAPTER_IDS: ReadonlySet<string> = new Set([
  'apple-app-store',
  'arbeitnow',
  'arbeitnow-feed',
  'arcgis',
  'arxiv',
  'ashby',
  'atom',
  'bamboohr',
  'bamboohr-board',
  'bamboohr-breezy-recruitee',
  'bamboohr-job',
  'bicycleretailer',
  'big-cartel',
  'bigcommerce',
  'bigcommerce-store',
  'blogger',
  'bluesky',
  'bluesky-thread',
  'bosch-ebike-help',
  'breezy-hr',
  'breezyhr',
  'bubble',
  'bumm-de',
  'ckan',
  'clinicaltrials',
  'cornell-lii',
  'cpsc-recalls',
  'craft-cms',
  'crates-io',
  'datacite',
  'defuddle',
  'deps-dev',
  'dev-to',
  'discourse',
  'discourse-topic',
  'docker-hub',
  'dockerhub',
  'docsify',
  'docusaurus',
  'doi-crossref',
  'drupal',
  'duda',
  'enterprise-ats',
  'eur-lex',
  'fcc-id',
  'federal-register',
  'federalregister',
  'framer',
  'gem',
  'gem-ats',
  'gem-board',
  'generic',
  'ghost',
  'giant-liv-bikes',
  'github',
  'github-gist',
  'gitlab',
  'gitlab-blob-json',
  'gitlab-forgejo',
  'gitlab-readme-json',
  'godaddy-builder',
  'google-play',
  'greenhouse',
  'greenhouse-board',
  'greenhouse-eu-board',
  'greenhouse-job',
  'greenhouse-lever',
  'greenhouse-lever-boards',
  'hackernews',
  'hex-pm',
  'himalayas',
  'himalayas-feed',
  'homebrew',
  'homebrew-formulae',
  'huggingface',
  'huggingface-blob',
  'huggingface-card',
  'icims',
  'ietf-rfc',
  'internet-archive',
  'ipynb',
  'jazzhr',
  'jibe-careers',
  'jimdo',
  'jobicy',
  'jobicy-feed',
  'jobvite',
  'joomla',
  'jsonld',
  'jsr',
  'jsr-io',
  'kajabi',
  'legistar',
  'lemmy',
  'lever',
  'lever-board',
  'lever-eu-board',
  'lever-job',
  'llms-txt',
  'lobsters',
  'mastodon',
  'mastodon-status',
  'maven-central',
  'mcp-federated',
  'mediawiki',
  'mkdocs-material',
  'news-feeds',
  'nextra',
  'nfpa',
  'nhtsa-vpic-recalls',
  'nist-nvd',
  'notion',
  'npm',
  'npm-registry',
  'nuget',
  'nuget-gallery',
  'openalex',
  'openapi',
  'opencart',
  'openfda',
  'openfoodfacts',
  'openrouter',
  'oracle-hcm',
  'oracle-hcm-board',
  'oracle-hcm-job',
  'osv-ghsa',
  'packagist',
  'pdf',
  'pdf-ocr',
  'personio',
  'pinpoint',
  'pkg-go-dev',
  'pmc-europepmc',
  'podia',
  'polymarket',
  'pubchem',
  'public-job-feeds',
  'pubmed-europepmc',
  'pubmed-pmc',
  'pypi',
  'pypi-project',
  'recruitee',
  'reddit',
  'reddit-thread',
  'remoteok',
  'remoteok-feed',
  'rippling',
  'rippling-board',
  'rippling-job',
  'rss',
  'rubygems',
  'salesforce-experience-cloud',
  'sap-rmk',
  'sap-rmk-jibe',
  'sec-edgar',
  'sfcc-demandware',
  'shopify',
  'shopify-catalog-page',
  'shopware-magento',
  'sitemap',
  'smartrecruiters',
  'socrata',
  'square-online',
  'squarespace',
  'squarespace-commerce',
  'sram-docs',
  'sram-models',
  'ssr-hydration',
  'stackexchange',
  'stackexchange-qa',
  'storybook',
  'substack',
  'swagger-ui',
  'teachable',
  'teamtailor',
  'terraform-registry',
  'themuse',
  'themuse-feed',
  'thinkific',
  'tq-ebike',
  'typo3',
  'ukg-paylocity-dover',
  'unknown',
  'us-cfr-govinfo',
  'usaspending',
  'vitepress',
  'wayback',
  'webflow',
  'weworkremotely',
  'weworkremotely-feed',
  'wikidata-openlibrary',
  'wix',
  'woocommerce',
  'woocommerce-catalog-page',
  'woocommerce-product',
  'wordpress',
  'workable',
  'workable-board',
  'workable-job',
  'workatastartup-yc-mirror',
  'workday',
  'workday-board',
  'workday-cxs',
  'workday-job',
  'workingnomads',
  'workingnomads-feed',
  'xenforo-thread',
  'ycombinator',
  'youtube',
  'zendesk-hc',
]);

const SAFE_SEMVER_RE = /^(?:\d{1,3}\.\d{1,3}\.\d{1,4}(?:-(?:alpha|beta|rc)(?:\.\d{1,3})?)?|dev|unknown)$/;
const SAFE_SPAN_NAME_RE =
  /^(?:edgefetch\.(?:go|http|scrape|batch_scrape|ingest_tab|fetch|extract|search|collection_search|jobs|catalog|map|crawl|interact|agent|agents|browser|bug_report|mcp|mcp_registry|mcp_query|llm|dispatch|admin|oauth|artifacts|hub|spa_fallback|span|cache|overflow|ingest|webhook|capabilities|extractors|hosts)(?:\.[a-z0-9_]{1,24}){0,2}|cache:(?:r2-d1|private-r2|304))$/;

export function isTruthyTelemetryFlag(raw?: string | null): boolean {
  const clean = (raw ?? '').trim().toLowerCase();
  return clean === '1' || clean === 'true' || clean === 'yes' || clean === 'on';
}

export function isFalsyTelemetryFlag(raw?: string | null): boolean {
  const clean = (raw ?? '').trim().toLowerCase();
  return clean === '0' || clean === 'false' || clean === 'no' || clean === 'off';
}

/**
 * Per Console Do Not Track (`https://consoledonottrack.com/`), ANY non-empty `DO_NOT_TRACK` value
 * whose lowercase form is NOT an explicit disable token (`0`, `false`, `no`, `off`, `unset`) enables DNT!
 */
export function isDoNotTrackEnabled(raw?: string | null): boolean {
  const clean = (raw ?? '').trim().toLowerCase();
  return clean.length > 0 && !DNT_EXPLICIT_DISABLE_VALUES.has(clean);
}

function isDisallowedNonLoopbackEndpointIp(hostname: string): boolean {
  const clean = hostname.replace(/^\[|\]$/g, '').toLowerCase();
  if (clean === '127.0.0.1' || clean === 'localhost' || clean === '::1') return false;
  if (
    clean === '0.0.0.0' ||
    clean === '::' ||
    clean.startsWith('10.') ||
    clean.startsWith('169.254.') ||
    clean.startsWith('192.168.') ||
    clean.startsWith('100.64.') ||
    clean.startsWith('fe80:') ||
    clean.startsWith('fc') ||
    clean.startsWith('fd') ||
    clean.startsWith('::ffff:')
  ) {
    return true;
  }
  const m172 = /^172\.(\d{1,3})\./.exec(clean);
  if (m172) {
    const second = Number(m172[1]);
    if (second >= 16 && second <= 31) return true;
  }
  return false;
}

export function resolveDevTelemetryEndpoint(env?: DevTelemetryEnvConfig): string | null {
  const raw = (env?.EDGEFETCH_DEV_TELEMETRY_URL ?? env?.EDGEFETCH_DEV_TELEMETRY_ENDPOINT ?? '').trim();
  const target = raw || DEFAULT_DEV_TELEMETRY_ENDPOINT;
  let parsed: URL;
  try {
    parsed = new URL(target);
  } catch {
    return null;
  }
  if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') return null;
  if (parsed.username || parsed.password || parsed.hash) return null;
  if (isDisallowedNonLoopbackEndpointIp(parsed.hostname)) return null;
  parsed.search = '';
  if (!parsed.pathname || parsed.pathname === '/') {
    parsed.pathname = '/v1/dev-errors';
  }
  return parsed.toString();
}

export function resolveDevTelemetryState(params: {
  env?: DevTelemetryEnvConfig;
  dbSettingValue?: string | boolean | null;
}): DevTelemetrySettingsView {
  const endpoint = resolveDevTelemetryEndpoint(params.env) ?? DEFAULT_DEV_TELEMETRY_ENDPOINT;
  // `DO_NOT_TRACK` is an unconditional hard disable override across all settings & env vars!
  if (isDoNotTrackEnabled(params.env?.DO_NOT_TRACK)) {
    return {
      enabled: false,
      source: 'do_not_track',
      doNotTrack: true,
      endpoint,
      allowlistedFields: DEV_ERROR_ALLOWLISTED_FIELDS,
    };
  }

  const dbRaw =
    typeof params.dbSettingValue === 'boolean'
      ? params.dbSettingValue
        ? '1'
        : '0'
      : params.dbSettingValue;

  if (isTruthyTelemetryFlag(dbRaw)) {
    return {
      enabled: true,
      source: 'admin_opt_in',
      doNotTrack: false,
      endpoint,
      allowlistedFields: DEV_ERROR_ALLOWLISTED_FIELDS,
    };
  }
  if (isFalsyTelemetryFlag(dbRaw)) {
    return {
      enabled: false,
      source: 'admin_opt_out',
      doNotTrack: false,
      endpoint,
      allowlistedFields: DEV_ERROR_ALLOWLISTED_FIELDS,
    };
  }
  if (isTruthyTelemetryFlag(params.env?.EDGEFETCH_DEV_TELEMETRY)) {
    return {
      enabled: true,
      source: 'env',
      doNotTrack: false,
      endpoint,
      allowlistedFields: DEV_ERROR_ALLOWLISTED_FIELDS,
    };
  }
  return {
    enabled: false,
    source: 'default_off',
    doNotTrack: false,
    endpoint,
    allowlistedFields: DEV_ERROR_ALLOWLISTED_FIELDS,
  };
}

export function detectRuntimeEnvironment(): {
  runtime: TelemetryRuntime;
  os: string;
  arch: string;
} {
  const g = globalThis as Record<string, unknown>;
  const denoObj = g.Deno as { build?: { os?: string; arch?: string } } | undefined;
  if (denoObj && typeof denoObj === 'object') {
    const rawOs = (denoObj.build?.os ?? 'unknown').trim().toLowerCase();
    const rawArch = (denoObj.build?.arch ?? 'unknown').trim().toLowerCase();
    return {
      runtime: 'deno',
      os: KNOWN_TELEMETRY_OS.has(rawOs) ? rawOs : 'unknown',
      arch: KNOWN_TELEMETRY_ARCH.has(rawArch) ? rawArch : 'unknown',
    };
  }
  const navUa = typeof navigator !== 'undefined' && typeof navigator.userAgent === 'string' ? navigator.userAgent : '';
  if (navUa.includes('Cloudflare-Workers')) {
    return { runtime: 'workers', os: 'cloudflare', arch: 'v8' };
  }
  const proc = g.process as { versions?: { node?: string }; platform?: string; arch?: string } | undefined;
  if (proc?.versions?.node) {
    const rawOs = (proc.platform ?? 'unknown').trim().toLowerCase();
    const rawArch = (proc.arch ?? 'unknown').trim().toLowerCase();
    return {
      runtime: 'node',
      os: KNOWN_TELEMETRY_OS.has(rawOs) ? rawOs : 'unknown',
      arch: KNOWN_TELEMETRY_ARCH.has(rawArch) ? rawArch : 'unknown',
    };
  }
  return { runtime: 'workers', os: 'cloudflare', arch: 'v8' };
}

function normalizeSafeVersion(raw: string | undefined): string {
  const trimmed = (raw ?? '').trim().replace(/^v/i, '');
  if (!trimmed || /[/?#@\\\s]/.test(trimmed)) return 'unknown';
  // Strip SemVer `+buildmetadata` (`v2.7.0+host.internal.example` -> `2.7.0`) so build hostnames NEVER leak!
  const withoutBuildMeta = trimmed.split('+')[0] ?? '';
  return SAFE_SEMVER_RE.test(withoutBuildMeta) ? withoutBuildMeta : 'unknown';
}

function normalizeSafeSpanName(raw: unknown): string {
  if (typeof raw !== 'string') return 'edgefetch.span';
  const trimmed = raw.trim();
  if (!trimmed || trimmed.length > 96) return 'edgefetch.span';
  return SAFE_SPAN_NAME_RE.test(trimmed) ? trimmed : 'edgefetch.span';
}

function normalizeSafeAdapterId(raw: unknown): string {
  if (typeof raw !== 'string') return '';
  const first = (raw.split(',')[0] ?? '').trim();
  if (!first) return '';
  const lower = first.toLowerCase();
  if (
    lower.includes('://') ||
    lower.includes('/') ||
    lower.includes('\\') ||
    lower.includes('?') ||
    lower.includes('#') ||
    lower.includes('@') ||
    /\s/.test(lower)
  ) {
    return '';
  }
  // Scrub federated `mcp:<vault-slug>:<tool-name>` (`mcp-federation.ts:1308`) to static `'mcp-federated'` — ZERO customer slugs!
  if (lower.startsWith('mcp:')) {
    return 'mcp-federated';
  }
  return KNOWN_TELEMETRY_ADAPTER_IDS.has(lower) ? lower : '';
}

function normalizeSafeWafVendor(raw: unknown): string | null {
  if (typeof raw !== 'string') return '';
  const trimmed = raw.trim().toLowerCase();
  if (!trimmed) return '';
  // Reject malformed path/URL/dotted strings completely (`null` drops poisoned report)
  if (trimmed.includes('.') || trimmed.includes('/') || trimmed.includes('\\') || trimmed.includes(':') || /\s/.test(trimmed)) {
    return null;
  }
  return KNOWN_TELEMETRY_WAF_VENDORS.has(trimmed) ? trimmed : '';
}

export function classifyTelemetryErrorClass(params: {
  httpStatus: number;
  outcome?: string;
  wafVendor?: string;
  errorMessage?: string;
}): string {
  const out = (params.outcome ?? '').trim().toLowerCase();
  const waf = (params.wafVendor ?? '').trim().toLowerCase();
  const msg = (params.errorMessage ?? '').trim().toLowerCase();

  if (out === 'challenge') return 'waf_challenge';
  if (out === 'rate_limited') return 'rate_limited';
  if (out === 'payment_required') return 'payment_required';
  if (out === 'blocked') {
    return msg.includes('robots') ? 'robots_disallowed' : 'waf_block';
  }
  if (waf && KNOWN_TELEMETRY_WAF_VENDORS.has(waf)) {
    return params.httpStatus === 429 ? 'rate_limited' : 'waf_challenge';
  }
  if (msg.includes('robots')) return 'robots_disallowed';
  if (msg.includes('ssrf') || msg.includes('non-public') || msg.includes('private')) return 'ssrf_blocked';
  if (msg.includes('timeout') || msg.includes('timed out') || msg.includes('aborted')) return 'timeout';
  if (msg.includes('tls') || msg.includes('certificate')) return 'tls_error';
  if (msg.includes('dns') || msg.includes('enotfound')) return 'dns_error';
  if (msg.includes('econnrefused') || msg.includes('econnreset') || msg.includes('connect')) return 'connect_error';
  if (msg.includes('browser') || msg.includes('chromium') || msg.includes('cdp')) return 'browser_error';
  if (msg.includes('adapter') || msg.includes('extractor')) return 'adapter_error';

  if (params.httpStatus === 401) return 'http_401';
  if (params.httpStatus === 402) return 'payment_required';
  if (params.httpStatus === 403) return 'http_403';
  if (params.httpStatus === 404) return 'http_404';
  if (params.httpStatus === 429) return 'rate_limited';
  if (params.httpStatus >= 400 && params.httpStatus < 500) return 'http_4xx';
  if (params.httpStatus >= 500 && params.httpStatus < 600) return 'http_5xx';
  return 'internal_error';
}

export function validateDevErrorReport(candidate: unknown): { ok: true; value: DevErrorReport } | { ok: false; error: string } {
  if (!candidate || typeof candidate !== 'object' || Array.isArray(candidate)) {
    return { ok: false, error: 'event must be a JSON object' };
  }
  const obj = candidate as Record<string, unknown>;
  const keys = Object.keys(obj);
  if (keys.length !== ALLOWLISTED_FIELD_SET.size) {
    return { ok: false, error: 'unexpected or missing keys on telemetry event' };
  }
  for (const k of keys) {
    if (!ALLOWLISTED_FIELD_SET.has(k)) {
      return { ok: false, error: `disallowed key: ${k}` };
    }
  }
  for (const [, val] of Object.entries(obj)) {
    if (typeof val === 'string') {
      const lower = val.toLowerCase();
      if (
        lower.includes('http://') ||
        lower.includes('https://') ||
        lower.includes('://') ||
        lower.includes('/') ||
        lower.includes('\\') ||
        lower.includes('@') ||
        lower.includes('?') ||
        lower.includes('#')
      ) {
        return { ok: false, error: 'URL or path substring forbidden in telemetry field' };
      }
    }
  }
  if (obj.schemaVersion !== 1) {
    return { ok: false, error: 'schemaVersion must equal 1' };
  }
  if (typeof obj.version !== 'string' || !SAFE_SEMVER_RE.test(obj.version)) {
    return { ok: false, error: 'invalid version' };
  }
  if (typeof obj.runtime !== 'string' || !VALID_RUNTIMES.has(obj.runtime)) {
    return { ok: false, error: 'invalid runtime' };
  }
  if (typeof obj.os !== 'string' || !KNOWN_TELEMETRY_OS.has(obj.os)) {
    return { ok: false, error: 'invalid os' };
  }
  if (typeof obj.arch !== 'string' || !KNOWN_TELEMETRY_ARCH.has(obj.arch)) {
    return { ok: false, error: 'invalid arch' };
  }
  if (typeof obj.mode !== 'string' || !KNOWN_TELEMETRY_MODES.has(obj.mode)) {
    return { ok: false, error: 'invalid mode' };
  }
  if (typeof obj.spanName !== 'string' || !SAFE_SPAN_NAME_RE.test(obj.spanName)) {
    return { ok: false, error: 'invalid spanName' };
  }
  if (typeof obj.adapterId !== 'string' || (obj.adapterId !== '' && !KNOWN_TELEMETRY_ADAPTER_IDS.has(obj.adapterId))) {
    return { ok: false, error: 'invalid adapterId' };
  }
  if (typeof obj.wafVendor !== 'string' || (obj.wafVendor !== '' && !KNOWN_TELEMETRY_WAF_VENDORS.has(obj.wafVendor))) {
    return { ok: false, error: 'invalid wafVendor' };
  }
  if (typeof obj.httpStatus !== 'number' || !Number.isInteger(obj.httpStatus) || obj.httpStatus < 0 || obj.httpStatus > 599) {
    return { ok: false, error: 'invalid httpStatus' };
  }
  if (typeof obj.errorClass !== 'string' || !KNOWN_TELEMETRY_ERROR_CLASSES.has(obj.errorClass)) {
    return { ok: false, error: 'invalid errorClass' };
  }
  return {
    ok: true,
    value: {
      schemaVersion: 1,
      version: obj.version,
      runtime: obj.runtime as TelemetryRuntime,
      os: obj.os,
      arch: obj.arch,
      mode: obj.mode,
      spanName: obj.spanName,
      adapterId: obj.adapterId,
      wafVendor: obj.wafVendor,
      httpStatus: obj.httpStatus,
      errorClass: obj.errorClass,
    },
  };
}

/**
 * Scrubs an `OtlpSpanInput` to ONLY the 11 allowlisted structural fields when the span represents an error
 * (`statusOk === false` / `status.code === 2`) or verified WAF failure. Healthy spans return `null`.
 */
export function scrubSpanToDevErrorReport(
  span: OtlpSpanInput,
  meta?: {
    version?: string;
    runtime?: TelemetryRuntime;
    os?: string;
    arch?: string;
    mode?: string;
  },
): DevErrorReport | null {
  const attrs = span.attributes ?? {};
  const rawWaf =
    typeof attrs['edgefetch.waf.vendor'] === 'string'
      ? attrs['edgefetch.waf.vendor']
      : typeof attrs['waf.vendor'] === 'string'
        ? attrs['waf.vendor']
        : '';
  const wafVendor = normalizeSafeWafVendor(rawWaf);
  if (wafVendor === null) {
    return null;
  }

  const rawOutcome = (
    typeof attrs['crawler.outcome'] === 'string'
      ? attrs['crawler.outcome']
      : typeof attrs['edgefetch.outcome'] === 'string'
        ? attrs['edgefetch.outcome']
        : ''
  )
    .trim()
    .toLowerCase();
  const rawStatus = attrs['http.response.status_code'] ?? attrs['http.status_code'] ?? 0;
  const parsedStatus =
    typeof rawStatus === 'number'
      ? Math.floor(rawStatus)
      : typeof rawStatus === 'string' && /^\d{1,3}$/.test(rawStatus.trim())
        ? Number(rawStatus.trim())
        : 0;
  const httpStatus = Number.isInteger(parsedStatus) && parsedStatus >= 0 && parsedStatus <= 599 ? parsedStatus : 0;

  // Expected caller/origin domain outcomes (`not_found` 404, `gone` 410, `skip` robots.txt, `blocked` SSRF/policy) and
  // generic `edgefetch.mcp.tool` wrapper statuses (`mcp_tool_error` without an upstream WAF/5xx status) are NOT EdgeFetch bugs!
  if (
    !wafVendor &&
    (rawOutcome === 'not_found' ||
      rawOutcome === 'gone' ||
      rawOutcome === 'skip' ||
      rawOutcome === 'blocked' ||
      httpStatus === 404 ||
      httpStatus === 410 ||
      (span.name === 'edgefetch.mcp.tool' && span.errorMessage === 'mcp_tool_error' && httpStatus < 500 && rawOutcome !== 'error' && rawOutcome !== 'rate_limited'))
  ) {
    return null;
  }

  const isErrorOrWaf =
    span.statusOk === false ||
    Boolean(wafVendor) ||
    rawOutcome === 'challenge' ||
    rawOutcome === 'rate_limited' ||
    rawOutcome === 'error';

  if (!isErrorOrWaf) {
    return null;
  }

  if (meta?.os !== undefined && !KNOWN_TELEMETRY_OS.has(meta.os.trim().toLowerCase())) {
    return null;
  }
  if (meta?.arch !== undefined && !KNOWN_TELEMETRY_ARCH.has(meta.arch.trim().toLowerCase())) {
    return null;
  }
  if (meta?.mode !== undefined && !KNOWN_TELEMETRY_MODES.has(meta.mode.trim().toLowerCase())) {
    return null;
  }

  const detected = detectRuntimeEnvironment();
  const version = normalizeSafeVersion(meta?.version ?? (typeof hubPkg?.version === 'string' ? hubPkg.version : '2.8.15'));
  const runtime = meta?.runtime && VALID_RUNTIMES.has(meta.runtime) ? meta.runtime : detected.runtime;
  const os = meta?.os ? meta.os.trim().toLowerCase() : detected.os;
  const arch = meta?.arch ? meta.arch.trim().toLowerCase() : detected.arch;
  const mode = meta?.mode ? meta.mode.trim().toLowerCase() : 'hub';
  const spanName = normalizeSafeSpanName(span.name);
  const rawAdapter =
    typeof attrs['edgefetch.adapter_id'] === 'string'
      ? attrs['edgefetch.adapter_id']
      : typeof attrs['adapter.id'] === 'string'
        ? attrs['adapter.id']
        : '';
  const adapterId = normalizeSafeAdapterId(rawAdapter);

  const errorClass = classifyTelemetryErrorClass({
    httpStatus,
    outcome: rawOutcome,
    wafVendor,
    errorMessage: span.errorMessage,
  });

  const report: DevErrorReport = {
    schemaVersion: 1,
    version,
    runtime,
    os,
    arch,
    mode,
    spanName,
    adapterId,
    wafVendor,
    httpStatus,
    errorClass,
  };
  const checked = validateDevErrorReport(report);
  return checked.ok ? checked.value : null;
}

const hubTelemetrySettingCache = new WeakMap<object, { value: string | null; expiresAt: number }>();
let inflightDevTelemetryExports = 0;

async function resolveDbTelemetrySettingFromEnv(env: DevTelemetryEnvConfig): Promise<string | null | undefined> {
  const agentHub = (
    env as {
      AGENT_HUB?: {
        idFromName?: (name: string) => unknown;
        get?: (id: unknown) => { getHubSetting?: (key: string) => Promise<string | null> };
      };
    }
  ).AGENT_HUB;
  if (!agentHub || typeof agentHub !== 'object' || typeof agentHub.idFromName !== 'function' || typeof agentHub.get !== 'function') {
    return undefined;
  }
  const now = Date.now();
  const cached = hubTelemetrySettingCache.get(agentHub);
  if (cached && cached.expiresAt > now) {
    return cached.value;
  }
  try {
    const stub = agentHub.get(agentHub.idFromName('global'));
    if (stub && typeof stub.getHubSetting === 'function') {
      const val = await stub.getHubSetting(DEV_TELEMETRY_SETTING_KEY);
      hubTelemetrySettingCache.set(agentHub, { value: val, expiresAt: now + 5_000 });
      return val;
    }
  } catch {
    // ignore Coordinator lookup failure
  }
  return undefined;
}

/**
 * Exports scrubbed `status=ERROR` / WAF-failure spans asynchronously when opt-in telemetry is enabled.
 * Never throws and sends `0` bytes when disabled or when `DO_NOT_TRACK` is active.
 */
export async function flushDevErrorTelemetry(params: {
  env: DevTelemetryEnvConfig;
  spans: OtlpSpanInput[];
  dbSettingValue?: string | boolean | null;
  version?: string;
  mode?: string;
  fetchFn?: typeof fetch;
}): Promise<boolean> {
  if (params.spans.length === 0) return false;
  if (isDoNotTrackEnabled(params.env?.DO_NOT_TRACK)) return false;

  const effectiveDbSetting =
    params.dbSettingValue !== undefined ? params.dbSettingValue : await resolveDbTelemetrySettingFromEnv(params.env);

  const state = resolveDevTelemetryState({
    env: params.env,
    dbSettingValue: effectiveDbSetting,
  });
  if (!state.enabled) return false;

  const endpoint = resolveDevTelemetryEndpoint(params.env);
  if (!endpoint) return false;

  const seen = new Set<string>();
  const events: DevErrorReport[] = [];
  for (const sp of params.spans) {
    const scrubbed = scrubSpanToDevErrorReport(sp, {
      ...(params.version ? { version: params.version } : {}),
      ...(params.mode ? { mode: params.mode } : {}),
    });
    if (!scrubbed) continue;
    const dedupKey = `${scrubbed.spanName}|${scrubbed.adapterId}|${scrubbed.wafVendor}|${scrubbed.httpStatus}|${scrubbed.errorClass}`;
    if (seen.has(dedupKey)) continue;
    seen.add(dedupKey);
    events.push(scrubbed);
    if (events.length >= MAX_DEV_TELEMETRY_EVENTS_PER_POST) break;
  }
  if (events.length === 0) return false;
  if (inflightDevTelemetryExports >= MAX_INFLIGHT_DEV_TELEMETRY_EXPORTS) return false;

  const bodyStr = JSON.stringify(events.length === 1 ? events[0]! : { events });
  if (new TextEncoder().encode(bodyStr).byteLength > 8_192) {
    return false;
  }

  const doFetch = params.fetchFn ?? params.env.SAFE_PUBLIC_FETCH ?? params.env.SAFE_FETCH ?? fetch;
  const ctrl = new AbortController();
  const timer = setTimeout(() => {
    ctrl.abort(new DOMException('Dev error telemetry export timed out', 'TimeoutError'));
  }, 2_500);
  (timer as { unref?: () => void }).unref?.();

  inflightDevTelemetryExports++;
  try {
    const res = await doFetch(endpoint, {
      method: 'POST',
      redirect: 'manual',
      headers: { 'content-type': 'application/json' },
      body: bodyStr,
      signal: ctrl.signal,
    });
    await res.body?.cancel().catch(() => undefined);
    return res.ok;
  } catch {
    return false;
  } finally {
    inflightDevTelemetryExports = Math.max(0, inflightDevTelemetryExports - 1);
    clearTimeout(timer);
  }
}
