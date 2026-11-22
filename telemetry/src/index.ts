/**
 * Standalone Cloudflare Collector Worker (`telemetry.edgefetch.dev` — `telemetry/src/index.ts`).
 *
 * Routes:
 *  - `POST /v1/dev-errors`:
 *      1. Enforces `<= 8 KiB` (`8192` bytes) streaming body cap (`413` on overflow) + cross-origin simple-POST CSRF guard.
 *      2. Enforces two-tier token-bucket rate limit (`<= 30 req/min` per IPv4 or IPv6 `/64`, `<= 60 req/min` aggregate
 *         per IPv6 `/48`, non-evicting active-lockout map, plus bounded global new-fingerprint creation rate!).
 *      3. Enforces strict enum/allowlist schema validation (`400` if ANY unexpected key, URL/path substring, hostname,
 *         or unknown `spanName`/`adapterId`/`wafVendor`/`errorClass`/`os`/`arch`/`mode`/non-semver `version` appears!).
 *      4. Deduplicates fingerprints within each POST (`<= 8` events/POST) and upserts `error_fingerprints` in D1,
 *         evicting ONLY stale `count = 1` rows (`ORDER BY count ASC, last_seen_at ASC LIMIT 1`) when `maxRows` is full
 *         so multi-hit real regressions (`count >= 2`) can NEVER be blinded by single-hit floods!
 *  - `GET /v1/dev-errors/summary`:
 *      Bearer `TELEMETRY_ADMIN_TOKEN`-authenticated (`>= 24` chars, constant-time SHA-256 comparison) triage endpoint
 *      returning top broken adapters & WAF regressions sorted by `count DESC, last_seen_at DESC`.
 */

export interface D1PreparedStatementLike {
  bind(...values: unknown[]): D1PreparedStatementLike;
  all<T = Record<string, unknown>>(): Promise<{ results: T[] }>;
  first<T = Record<string, unknown>>(colName?: string): Promise<T | null>;
  run(): Promise<{ success: boolean }>;
}

export interface D1DatabaseLike {
  prepare(query: string): D1PreparedStatementLike;
}

export interface CollectorEnv {
  DB: D1DatabaseLike;
  TELEMETRY_ADMIN_TOKEN?: string;
  MAX_ERROR_FINGERPRINTS?: string;
}

export type CollectorRuntime = 'workers' | 'node' | 'deno' | 'go';

export interface ValidatedDevErrorEvent {
  schemaVersion: 1;
  version: string;
  runtime: CollectorRuntime;
  os: string;
  arch: string;
  mode: string;
  spanName: string;
  adapterId: string;
  wafVendor: string;
  httpStatus: number;
  errorClass: string;
}

export const MAX_INGEST_BODY_BYTES = 8_192; // Strict 8 KiB cap
export const RATE_LIMIT_CAPACITY = 30; // <= 30 req/min per IPv4 or IPv6 `/64`
export const IPV6_PREFIX48_RATE_LIMIT_CAPACITY = 60; // <= 60 req/min aggregate across an entire IPv6 `/48`
export const GLOBAL_NEW_FINGERPRINTS_PER_MIN = 250; // Bounds brand-new D1 row churn across distributed IPs
export const RATE_LIMIT_WINDOW_MS = 60_000;
export const DEFAULT_MAX_FINGERPRINT_ROWS = 10_000;
export const MIN_ADMIN_TOKEN_LENGTH = 24;
export const MAX_EVENTS_PER_POST = 8;
const MAX_IP_BUCKETS = 32_768;

const SECURITY_JSON_HEADERS: Record<string, string> = {
  'content-type': 'application/json; charset=utf-8',
  'cache-control': 'no-store',
  'x-content-type-options': 'nosniff',
  'x-frame-options': 'DENY',
  'referrer-policy': 'no-referrer',
  'content-security-policy': "default-src 'none'; frame-ancestors 'none'; base-uri 'none'",
};

function jsonResponse(data: unknown, status = 200, extraHeaders?: Record<string, string>): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: extraHeaders ? { ...SECURITY_JSON_HEADERS, ...extraHeaders } : SECURITY_JSON_HEADERS,
  });
}

// ── Two-Tier Per-IP & IPv6 `/64` + `/48` Token-Bucket Rate Limiter ─────────────────────────────────────────────────

interface TokenBucket {
  tokens: number;
  lastRefillMs: number;
}

const ipBuckets = new Map<string, TokenBucket>();
const ipv6Slash48Buckets = new Map<string, TokenBucket>();
let globalNewFpBucket: TokenBucket = { tokens: GLOBAL_NEW_FINGERPRINTS_PER_MIN, lastRefillMs: Date.now() };

export function resetCollectorRateLimiters(): void {
  ipBuckets.clear();
  ipv6Slash48Buckets.clear();
  globalNewFpBucket = { tokens: GLOBAL_NEW_FINGERPRINTS_PER_MIN, lastRefillMs: Date.now() };
}

function parseStrictIpv4(raw: string): string | null {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(raw);
  if (!m) return null;
  const octets: number[] = [];
  for (let i = 1; i <= 4; i++) {
    const part = m[i]!;
    if (part.length > 1 && part.startsWith('0')) return null;
    const n = Number(part);
    if (!Number.isInteger(n) || n < 0 || n > 255) return null;
    octets.push(n);
  }
  return octets.join('.');
}

function expandIpv6Hextets(raw: string): string[] | null {
  const zoneIdx = raw.indexOf('%');
  let clean = zoneIdx >= 0 ? raw.slice(0, zoneIdx) : raw;
  const lastColon = clean.lastIndexOf(':');
  if (lastColon >= 0 && clean.slice(lastColon + 1).includes('.')) {
    const v4 = parseStrictIpv4(clean.slice(lastColon + 1));
    if (!v4) return null;
    const nums = v4.split('.').map(Number);
    const hi = ((nums[0]! << 8) | nums[1]!).toString(16);
    const lo = ((nums[2]! << 8) | nums[3]!).toString(16);
    clean = `${clean.slice(0, lastColon)}:${hi}:${lo}`;
  }
  const halves = clean.split('::');
  if (halves.length > 2) return null;
  const left = halves[0] ? halves[0].split(':').filter(Boolean) : [];
  const right = halves.length === 2 && halves[1] ? halves[1].split(':').filter(Boolean) : [];
  const missing = 8 - (left.length + right.length);
  if ((halves.length === 1 && missing !== 0) || missing < 0) return null;
  const full = [...left, ...Array<string>(halves.length === 2 ? missing : 0).fill('0'), ...right];
  if (full.length !== 8) return null;
  const out: string[] = [];
  for (const h of full) {
    if (!/^[0-9a-f]{1,4}$/.test(h)) return null;
    out.push(h.padStart(4, '0'));
  }
  return out;
}

export function normalizeClientIpBuckets(rawIp: string | null | undefined): {
  primaryKey: string;
  ipv6Prefix48Key: string | null;
} {
  const trimmed = (rawIp ?? '').trim().toLowerCase();
  if (!trimmed) return { primaryKey: 'unknown', ipv6Prefix48Key: null };
  if (trimmed.includes(',') || /\s/.test(trimmed)) {
    return { primaryKey: 'invalid', ipv6Prefix48Key: null };
  }
  let clean = trimmed;
  if (clean.startsWith('[') && clean.includes(']')) {
    clean = clean.slice(1, clean.indexOf(']'));
  } else {
    const v4Port = /^(\d{1,3}(?:\.\d{1,3}){3}):\d{1,5}$/.exec(clean);
    if (v4Port) clean = v4Port[1]!;
  }
  if (clean.startsWith('::ffff:')) {
    const v4 = parseStrictIpv4(clean.slice('::ffff:'.length));
    if (v4) return { primaryKey: v4, ipv6Prefix48Key: null };
  }
  const directV4 = parseStrictIpv4(clean);
  if (directV4) {
    return { primaryKey: directV4, ipv6Prefix48Key: null };
  }
  if (clean.includes(':')) {
    const hextets = expandIpv6Hextets(clean);
    if (hextets) {
      const isZeros0to4 =
        hextets[0] === '0000' &&
        hextets[1] === '0000' &&
        hextets[2] === '0000' &&
        hextets[3] === '0000' &&
        hextets[4] === '0000';
      if (isZeros0to4 && hextets[5] === 'ffff') {
        const hi = parseInt(hextets[6]!, 16);
        const lo = parseInt(hextets[7]!, 16);
        const mappedV4 = `${(hi >> 8) & 0xff}.${hi & 0xff}.${(lo >> 8) & 0xff}.${lo & 0xff}`;
        return { primaryKey: mappedV4, ipv6Prefix48Key: null };
      }
      return {
        primaryKey: `${hextets.slice(0, 4).join(':')}::/64`,
        ipv6Prefix48Key: `${hextets.slice(0, 3).join(':')}::/48`,
      };
    }
  }
  return { primaryKey: 'invalid', ipv6Prefix48Key: null };
}

export function normalizeRateLimitClientIp(rawIp: string | null | undefined): string {
  return normalizeClientIpBuckets(rawIp).primaryKey;
}

function tryAcquireBucketToken(
  map: Map<string, TokenBucket>,
  key: string,
  capacity: number,
  nowMs: number,
): { ok: true; bucket: TokenBucket; isNew: boolean } | { ok: false; retryAfterSec: number } {
  const refillPerMs = capacity / RATE_LIMIT_WINDOW_MS;
  const existing = map.get(key);
  if (existing) {
    const elapsed = Math.max(0, nowMs - existing.lastRefillMs);
    const nextTokens = Math.min(capacity, existing.tokens + elapsed * refillPerMs);
    existing.tokens = nextTokens;
    existing.lastRefillMs = nowMs;
    if (nextTokens < 1) {
      const neededMs = (1 - nextTokens) / refillPerMs;
      return { ok: false, retryAfterSec: Math.max(1, Math.ceil(neededMs / 1_000)) };
    }
    return { ok: true, bucket: existing, isNew: false };
  }

  if (map.size >= MAX_IP_BUCKETS) {
    // Sweep expired/idle buckets first; NEVER evict an actively exhausted (`tokens < 1`) bucket within the 60s window!
    for (const [k, b] of map) {
      if (nowMs - b.lastRefillMs >= RATE_LIMIT_WINDOW_MS || b.tokens >= capacity - 1) {
        map.delete(k);
        if (map.size < MAX_IP_BUCKETS) break;
      }
    }
    if (map.size >= MAX_IP_BUCKETS) {
      return { ok: false, retryAfterSec: 5 };
    }
  }
  const created: TokenBucket = { tokens: capacity, lastRefillMs: nowMs };
  return { ok: true, bucket: created, isNew: true };
}

export function consumeIpRateLimit(
  rawIp: string | null | undefined,
  nowMs = Date.now(),
): { allowed: true; remaining: number } | { allowed: false; retryAfterSec: number } {
  const { primaryKey, ipv6Prefix48Key } = normalizeClientIpBuckets(rawIp);

  const p64Check = tryAcquireBucketToken(ipBuckets, primaryKey, RATE_LIMIT_CAPACITY, nowMs);
  if (!p64Check.ok) {
    return { allowed: false, retryAfterSec: p64Check.retryAfterSec };
  }

  let p48Check: { ok: true; bucket: TokenBucket; isNew: boolean } | null = null;
  if (ipv6Prefix48Key !== null) {
    const res48 = tryAcquireBucketToken(ipv6Slash48Buckets, ipv6Prefix48Key, IPV6_PREFIX48_RATE_LIMIT_CAPACITY, nowMs);
    if (!res48.ok) {
      return { allowed: false, retryAfterSec: res48.retryAfterSec };
    }
    p48Check = res48;
  }

  p64Check.bucket.tokens -= 1;
  if (!p64Check.isNew) ipBuckets.delete(primaryKey);
  ipBuckets.set(primaryKey, p64Check.bucket);

  let remaining = Math.floor(p64Check.bucket.tokens);
  if (p48Check && ipv6Prefix48Key !== null) {
    p48Check.bucket.tokens -= 1;
    if (!p48Check.isNew) ipv6Slash48Buckets.delete(ipv6Prefix48Key);
    ipv6Slash48Buckets.set(ipv6Prefix48Key, p48Check.bucket);
    remaining = Math.min(remaining, Math.floor(p48Check.bucket.tokens));
  }

  return { allowed: true, remaining };
}

function consumeGlobalNewFingerprintBudget(nowMs: number): boolean {
  const refillPerMs = GLOBAL_NEW_FINGERPRINTS_PER_MIN / RATE_LIMIT_WINDOW_MS;
  const elapsed = Math.max(0, nowMs - globalNewFpBucket.lastRefillMs);
  globalNewFpBucket.tokens = Math.min(
    GLOBAL_NEW_FINGERPRINTS_PER_MIN,
    globalNewFpBucket.tokens + elapsed * refillPerMs,
  );
  globalNewFpBucket.lastRefillMs = nowMs;
  if (globalNewFpBucket.tokens < 1) return false;
  globalNewFpBucket.tokens -= 1;
  return true;
}

// ── Streaming `<= 8 KiB` Body Reader ───────────────────────────────────────────────────────────────────────────────

async function readBodyCapped8KiB(
  request: Request,
): Promise<{ ok: true; text: string; byteLength: number } | { ok: false; status: 400 | 413; error: string }> {
  const clHeader = request.headers.get('content-length');
  if (clHeader !== null && clHeader.trim() !== '') {
    const cl = Number(clHeader);
    if (!Number.isFinite(cl) || cl < 0) {
      return { ok: false, status: 400, error: 'invalid_content_length' };
    }
    if (cl > MAX_INGEST_BODY_BYTES) {
      await request.body?.cancel().catch(() => undefined);
      return { ok: false, status: 413, error: 'payload_too_large' };
    }
  }
  if (!request.body) {
    return { ok: false, status: 400, error: 'empty_body' };
  }
  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (value && value.byteLength > 0) {
        total += value.byteLength;
        if (total > MAX_INGEST_BODY_BYTES) {
          await reader.cancel('exceeds 8 KiB').catch(() => undefined);
          return { ok: false, status: 413, error: 'payload_too_large' };
        }
        chunks.push(value);
      }
    }
  } catch {
    await reader.cancel().catch(() => undefined);
    return { ok: false, status: 400, error: 'body_read_error' };
  }
  if (total === 0) {
    return { ok: false, status: 400, error: 'empty_body' };
  }
  const merged = new Uint8Array(total);
  let offset = 0;
  for (const c of chunks) {
    merged.set(c, offset);
    offset += c.byteLength;
  }
  return { ok: true, text: new TextDecoder().decode(merged), byteLength: total };
}

// ── Strict Enum / Allowlist Schema Validation (Anti-PII, Zero-Hostname & Anti-Blinding) ────────────────────────────

const EVENT_ALLOWED_KEYS = new Set([
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
]);

const VALID_RUNTIMES = new Set<CollectorRuntime>(['workers', 'node', 'deno', 'go']);
const VERSION_RE = /^(?:\d{1,3}\.\d{1,3}\.\d{1,4}(?:-(?:alpha|beta|rc)(?:\.\d{1,3})?)?|dev|unknown)$/;
const SPAN_NAME_RE =
  /^(?:edgefetch\.(?:go|http|scrape|batch_scrape|ingest_tab|fetch|extract|search|collection_search|jobs|catalog|map|crawl|interact|agent|agents|browser|bug_report|mcp|mcp_registry|mcp_query|llm|dispatch|admin|oauth|artifacts|hub|spa_fallback|span|cache|overflow|ingest|webhook|capabilities|extractors|hosts)(?:\.[a-z0-9_]{1,24}){0,2}|cache:(?:r2-d1|private-r2|304))$/;

const VALID_OS = new Set([
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

const VALID_ARCH = new Set([
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

const VALID_MODES = new Set(['hub', 'agent', 'server', 'serve', 'mcp', 'desktop', 'cli', 'portable', 'worker', 'container']);

const VALID_WAF_VENDORS = new Set([
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

const VALID_ERROR_CLASSES = new Set([
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

const VALID_ADAPTER_IDS = new Set([
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
  'big-cartel',
  'bigcommerce',
  'blogger',
  'bluesky',
  'bluesky-thread',
  'breezy-hr',
  'breezyhr',
  'bubble',
  'ckan',
  'clinicaltrials',
  'craft-cms',
  'crates-io',
  'datacite',
  'defuddle',
  'deps-dev',
  'dev-to',
  'discourse',
  'discourse-topic',
  'dockerhub',
  'docsify',
  'docusaurus',
  'doi-crossref',
  'drupal',
  'duda',
  'enterprise-ats',
  'federalregister',
  'framer',
  'gem',
  'gem-ats',
  'gem-board',
  'generic',
  'ghost',
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
  'nist-nvd',
  'notion',
  'npm',
  'npm-registry',
  'nuget',
  'openalex',
  'openapi',
  'opencart',
  'openfda',
  'openfoodfacts',
  'openrouter',
  'oracle-hcm',
  'oracle-hcm-board',
  'oracle-hcm-job',
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
  'shopify',
  'shopify-catalog-page',
  'sitemap',
  'smartrecruiters',
  'socrata',
  'square-online',
  'squarespace',
  'ssr-hydration',
  'stackexchange',
  'stackexchange-qa',
  'storybook',
  'substack',
  'swagger-ui',
  'teachable',
  'teamtailor',
  'themuse',
  'themuse-feed',
  'thinkific',
  'typo3',
  'unknown',
  'usaspending',
  'vitepress',
  'wayback',
  'webflow',
  'weworkremotely',
  'weworkremotely-feed',
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
  'ycombinator',
  'youtube',
]);

function containsForbiddenUrlOrPii(val: string): boolean {
  const lower = val.toLowerCase();
  return (
    lower.includes('http://') ||
    lower.includes('https://') ||
    lower.includes('://') ||
    lower.includes('www.') ||
    lower.includes('?') ||
    lower.includes('#') ||
    lower.includes('@') ||
    lower.includes('/') ||
    lower.includes('\\')
  );
}

export function validateSingleErrorEvent(
  raw: unknown,
): { ok: true; event: ValidatedDevErrorEvent } | { ok: false; error: string } {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    return { ok: false, error: 'event must be a JSON object' };
  }
  if (Object.getPrototypeOf(raw) !== Object.prototype) {
    return { ok: false, error: 'invalid object prototype' };
  }
  const obj = raw as Record<string, unknown>;
  if (Object.prototype.hasOwnProperty.call(obj, '__proto__')) {
    return { ok: false, error: 'unexpected field "__proto__"' };
  }
  const keys = Object.keys(obj);
  for (const k of keys) {
    if (!EVENT_ALLOWED_KEYS.has(k)) {
      return { ok: false, error: `unexpected field "${k}"` };
    }
    const v = obj[k];
    if (typeof v === 'string' && containsForbiddenUrlOrPii(v)) {
      return { ok: false, error: `forbidden URL or path substring in "${k}"` };
    }
  }
  if (keys.length !== EVENT_ALLOWED_KEYS.size) {
    return { ok: false, error: 'missing required allowlist fields' };
  }
  if (obj.schemaVersion !== 1) {
    return { ok: false, error: 'schemaVersion must be 1' };
  }
  if (typeof obj.version !== 'string' || !VERSION_RE.test(obj.version)) {
    return { ok: false, error: 'invalid version' };
  }
  if (typeof obj.runtime !== 'string' || !VALID_RUNTIMES.has(obj.runtime as CollectorRuntime)) {
    return { ok: false, error: 'invalid runtime' };
  }
  if (typeof obj.os !== 'string' || !VALID_OS.has(obj.os)) {
    return { ok: false, error: 'invalid os' };
  }
  if (typeof obj.arch !== 'string' || !VALID_ARCH.has(obj.arch)) {
    return { ok: false, error: 'invalid arch' };
  }
  if (typeof obj.mode !== 'string' || !VALID_MODES.has(obj.mode)) {
    return { ok: false, error: 'invalid mode' };
  }
  if (typeof obj.spanName !== 'string' || !SPAN_NAME_RE.test(obj.spanName)) {
    return { ok: false, error: 'invalid spanName' };
  }
  if (typeof obj.adapterId !== 'string' || (obj.adapterId !== '' && !VALID_ADAPTER_IDS.has(obj.adapterId))) {
    return { ok: false, error: 'invalid adapterId' };
  }
  if (typeof obj.wafVendor !== 'string' || (obj.wafVendor !== '' && !VALID_WAF_VENDORS.has(obj.wafVendor))) {
    return { ok: false, error: 'invalid wafVendor' };
  }
  if (typeof obj.httpStatus !== 'number' || !Number.isInteger(obj.httpStatus) || obj.httpStatus < 0 || obj.httpStatus > 599) {
    return { ok: false, error: 'invalid httpStatus' };
  }
  if (typeof obj.errorClass !== 'string' || !VALID_ERROR_CLASSES.has(obj.errorClass)) {
    return { ok: false, error: 'invalid errorClass' };
  }

  return {
    ok: true,
    event: {
      schemaVersion: 1,
      version: obj.version,
      runtime: obj.runtime as CollectorRuntime,
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

export function validateIngestPayload(
  rawJson: unknown,
): { ok: true; events: ValidatedDevErrorEvent[] } | { ok: false; error: string } {
  if (!rawJson || typeof rawJson !== 'object' || Array.isArray(rawJson)) {
    return { ok: false, error: 'payload must be a JSON object' };
  }
  const obj = rawJson as Record<string, unknown>;
  const topKeys = Object.keys(obj);

  if (topKeys.length === 1 && topKeys[0] === 'events') {
    if (!Array.isArray(obj.events) || obj.events.length === 0 || obj.events.length > MAX_EVENTS_PER_POST) {
      return { ok: false, error: `events must be a non-empty array of <= ${MAX_EVENTS_PER_POST} items` };
    }
    const validated: ValidatedDevErrorEvent[] = [];
    for (let i = 0; i < obj.events.length; i++) {
      const v = validateSingleErrorEvent(obj.events[i]);
      if (!v.ok) return { ok: false, error: `events[${i}]: ${v.error}` };
      validated.push(v.event);
    }
    return { ok: true, events: validated };
  }

  const single = validateSingleErrorEvent(rawJson);
  if (!single.ok) return single;
  return { ok: true, events: [single.event] };
}

// ── Deterministic SHA-256 Fingerprint & Constant-Time Auth ─────────────────────────────────────────────────────────

const textEncoder = new TextEncoder();

export async function computeErrorFingerprint(ev: Pick<
  ValidatedDevErrorEvent,
  'version' | 'runtime' | 'spanName' | 'adapterId' | 'wafVendor' | 'httpStatus' | 'errorClass'
>): Promise<string> {
  const canonical = JSON.stringify([
    ev.version,
    ev.runtime,
    ev.spanName,
    ev.adapterId,
    ev.wafVendor,
    ev.httpStatus,
    ev.errorClass,
  ]);
  const digest = await crypto.subtle.digest('SHA-256', textEncoder.encode(canonical));
  const bytes = new Uint8Array(digest);
  let hex = '';
  for (let i = 0; i < bytes.length; i++) {
    hex += bytes[i]!.toString(16).padStart(2, '0');
  }
  return hex;
}

async function constantTimeSecretMatch(supplied: string, expected: string): Promise<boolean> {
  const [aBuf, bBuf] = await Promise.all([
    crypto.subtle.digest('SHA-256', textEncoder.encode(supplied)),
    crypto.subtle.digest('SHA-256', textEncoder.encode(expected)),
  ]);
  const a = new Uint8Array(aBuf);
  const b = new Uint8Array(bBuf);
  let diff = supplied.length === expected.length ? 0 : 1;
  for (let i = 0; i < a.length; i++) {
    diff |= a[i]! ^ b[i]!;
  }
  return diff === 0;
}

// ── Worker Entrypoint ──────────────────────────────────────────────────────────────────────────────────────────────

export default {
  async fetch(request: Request, env: CollectorEnv): Promise<Response> {
    const url = new URL(request.url);

    if (request.method === 'GET' && url.pathname === '/health') {
      return jsonResponse({ ok: true, service: 'edgefetch-telemetry' });
    }

    if (request.method === 'POST' && url.pathname === '/v1/dev-errors') {
      // Block browser cross-origin simple-POST CSRF (`Origin` header or non-JSON `Content-Type` like `text/plain`).
      const rawCt = request.headers.get('content-type');
      if (rawCt !== null && !rawCt.trim().toLowerCase().startsWith('application/json')) {
        await request.body?.cancel().catch(() => undefined);
        return jsonResponse({ ok: false, error: 'unsupported_media_type' }, 415);
      }
      if (request.headers.has('origin')) {
        await request.body?.cancel().catch(() => undefined);
        return jsonResponse({ ok: false, error: 'cross_origin_forbidden' }, 403);
      }

      const clientIp = request.headers.get('cf-connecting-ip') ?? 'unknown';
      const rl = consumeIpRateLimit(clientIp);
      if (!rl.allowed) {
        return jsonResponse(
          { ok: false, error: 'rate_limited', retryAfterSec: rl.retryAfterSec },
          429,
          { 'retry-after': String(rl.retryAfterSec) },
        );
      }

      const bodyRes = await readBodyCapped8KiB(request);
      if (!bodyRes.ok) {
        return jsonResponse({ ok: false, error: bodyRes.error }, bodyRes.status);
      }

      let parsedJson: unknown;
      try {
        parsedJson = JSON.parse(bodyRes.text);
      } catch {
        return jsonResponse({ ok: false, error: 'invalid_json' }, 400);
      }

      const validated = validateIngestPayload(parsedJson);
      if (!validated.ok) {
        return jsonResponse({ ok: false, error: 'invalid_schema', detail: validated.error }, 400);
      }

      const nowMs = Date.now();
      const rawMaxRows = Number(env.MAX_ERROR_FINGERPRINTS ?? DEFAULT_MAX_FINGERPRINT_ROWS);
      const maxRows =
        Number.isFinite(rawMaxRows) && rawMaxRows >= 1 ? Math.min(100_000, Math.floor(rawMaxRows)) : DEFAULT_MAX_FINGERPRINT_ROWS;

      // Deduplicate identical fingerprints within a single POST so sending 8 identical events increments `count` by 1, not 8!
      const uniqueEventsByFp = new Map<string, ValidatedDevErrorEvent>();
      for (const ev of validated.events) {
        const fp = await computeErrorFingerprint(ev);
        if (!uniqueEventsByFp.has(fp)) {
          uniqueEventsByFp.set(fp, ev);
        }
      }

      const acceptedFingerprints: string[] = [];
      let cachedRowCount: number | null = null;

      for (const [fp, ev] of uniqueEventsByFp) {
        const existing = await env.DB.prepare('SELECT count FROM error_fingerprints WHERE fingerprint = ?')
          .bind(fp)
          .first<{ count: number }>();

        if (existing) {
          await env.DB.prepare(
            `UPDATE error_fingerprints
             SET count = count + 1,
                 last_seen_at = MAX(last_seen_at, ?)
             WHERE fingerprint = ?`,
          )
            .bind(nowMs, fp)
            .run();
          acceptedFingerprints.push(fp);
          continue;
        }

        if (!consumeGlobalNewFingerprintBudget(nowMs)) {
          continue;
        }

        if (cachedRowCount === null) {
          const cntRow = await env.DB.prepare('SELECT COUNT(*) AS cnt FROM error_fingerprints').first<{ cnt: number }>();
          cachedRowCount = Number(cntRow?.cnt ?? 0);
        }

        if (cachedRowCount >= maxRows) {
          // Evict ONLY the lowest-value stale row (`count = 1` oldest first, falling back to `count ASC, last_seen_at ASC`)
          // so multi-hit real regressions (`count >= 2`) are NEVER evicted by single-hit noise!
          await env.DB.prepare(
            `DELETE FROM error_fingerprints
             WHERE fingerprint IN (
               SELECT fingerprint FROM error_fingerprints
               ORDER BY count ASC, last_seen_at ASC
               LIMIT 1
             )`,
          ).run();
          cachedRowCount = Math.max(0, cachedRowCount - 1);
        }

        await env.DB.prepare(
          `INSERT INTO error_fingerprints (
             fingerprint, schema_version, version, runtime, os, arch, mode,
             span_name, adapter_id, waf_vendor, http_status, error_class,
             count, first_seen_at, last_seen_at
           ) VALUES (?, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
           ON CONFLICT(fingerprint) DO UPDATE SET
             count = error_fingerprints.count + 1,
             last_seen_at = MAX(error_fingerprints.last_seen_at, excluded.last_seen_at)`,
        )
          .bind(
            fp,
            ev.version,
            ev.runtime,
            ev.os,
            ev.arch,
            ev.mode,
            ev.spanName,
            ev.adapterId,
            ev.wafVendor,
            ev.httpStatus,
            ev.errorClass,
            nowMs,
            nowMs,
          )
          .run();
        cachedRowCount += 1;
        acceptedFingerprints.push(fp);
      }

      return jsonResponse({ ok: true, accepted: acceptedFingerprints.length, fingerprints: acceptedFingerprints }, 202);
    }

    if (request.method === 'GET' && url.pathname === '/v1/dev-errors/summary') {
      const adminSecret = (env.TELEMETRY_ADMIN_TOKEN ?? '').trim();
      if (adminSecret.length < MIN_ADMIN_TOKEN_LENGTH) {
        return jsonResponse({ ok: false, error: 'admin_token_unconfigured' }, 503);
      }
      const authHdr = request.headers.get('authorization') ?? '';
      const bearerMatch = /^Bearer\s+(\S+)$/i.exec(authHdr);
      const supplied = bearerMatch?.[1] ?? '';
      if (!supplied || !(await constantTimeSecretMatch(supplied, adminSecret))) {
        return jsonResponse(
          { ok: false, error: 'unauthorized' },
          401,
          { 'www-authenticate': 'Bearer realm="edgefetch-telemetry"' },
        );
      }

      const rawLimit = Number(url.searchParams.get('limit') ?? 50);
      const limit = Number.isFinite(rawLimit) ? Math.max(1, Math.min(200, Math.floor(rawLimit))) : 50;
      const versionFilter = (url.searchParams.get('version') ?? '').trim();
      const adapterFilter = (url.searchParams.get('adapterId') ?? '').trim();
      const wafFilter = (url.searchParams.get('wafVendor') ?? '').trim();

      const whereClauses: string[] = [];
      const bindValues: unknown[] = [];
      if (versionFilter && VERSION_RE.test(versionFilter)) {
        whereClauses.push('version = ?');
        bindValues.push(versionFilter);
      }
      if (adapterFilter && VALID_ADAPTER_IDS.has(adapterFilter)) {
        whereClauses.push('adapter_id = ?');
        bindValues.push(adapterFilter);
      }
      if (wafFilter && VALID_WAF_VENDORS.has(wafFilter)) {
        whereClauses.push('waf_vendor = ?');
        bindValues.push(wafFilter);
      }
      const whereSql = whereClauses.length > 0 ? `WHERE ${whereClauses.join(' AND ')}` : '';

      const [itemsRes, totalsRow, adaptersRes, wafRes] = await Promise.all([
        env.DB.prepare(
          `SELECT fingerprint, version, runtime, os, arch, mode, span_name, adapter_id,
                  waf_vendor, http_status, error_class, count, first_seen_at, last_seen_at
           FROM error_fingerprints
           ${whereSql}
           ORDER BY count DESC, last_seen_at DESC
           LIMIT ?`,
        )
          .bind(...bindValues, limit)
          .all<{
            fingerprint: string;
            version: string;
            runtime: string;
            os: string;
            arch: string;
            mode: string;
            span_name: string;
            adapter_id: string;
            waf_vendor: string;
            http_status: number;
            error_class: string;
            count: number;
            first_seen_at: number;
            last_seen_at: number;
          }>(),
        env.DB.prepare(
          `SELECT COUNT(*) AS total_fingerprints, COALESCE(SUM(count), 0) AS total_occurrences
           FROM error_fingerprints ${whereSql}`,
        )
          .bind(...bindValues)
          .first<{ total_fingerprints: number; total_occurrences: number }>(),
        env.DB.prepare(
          `SELECT adapter_id AS adapterId, SUM(count) AS totalCount, MAX(last_seen_at) AS lastSeenAt
           FROM error_fingerprints
           WHERE adapter_id != ''
           GROUP BY adapter_id
           ORDER BY totalCount DESC, lastSeenAt DESC
           LIMIT 20`,
        ).all<{ adapterId: string; totalCount: number; lastSeenAt: number }>(),
        env.DB.prepare(
          `SELECT waf_vendor AS wafVendor, error_class AS errorClass, SUM(count) AS totalCount, MAX(last_seen_at) AS lastSeenAt
           FROM error_fingerprints
           WHERE waf_vendor != ''
           GROUP BY waf_vendor, error_class
           ORDER BY totalCount DESC, lastSeenAt DESC
           LIMIT 20`,
        ).all<{ wafVendor: string; errorClass: string; totalCount: number; lastSeenAt: number }>(),
      ]);

      return jsonResponse({
        ok: true,
        totalFingerprints: Number(totalsRow?.total_fingerprints ?? 0),
        totalOccurrences: Number(totalsRow?.total_occurrences ?? 0),
        topBrokenAdapters: adaptersRes.results,
        topWafRegressions: wafRes.results,
        items: itemsRes.results.map((r) => ({
          fingerprint: r.fingerprint,
          version: r.version,
          runtime: r.runtime,
          os: r.os,
          arch: r.arch,
          mode: r.mode,
          spanName: r.span_name,
          adapterId: r.adapter_id,
          wafVendor: r.waf_vendor,
          httpStatus: r.http_status,
          errorClass: r.error_class,
          count: r.count,
          firstSeenAt: r.first_seen_at,
          lastSeenAt: r.last_seen_at,
        })),
      });
    }

    return jsonResponse({ ok: false, error: 'not_found' }, 404);
  },
};
