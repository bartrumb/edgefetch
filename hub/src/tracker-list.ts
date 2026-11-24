/**
 * Runtime EasyPrivacy third-party tracker list fetcher, validator, storage adapter, and WebSocket distributor.
 *
 * Architecture & Safety Invariants:
 *  - Hub fetches at runtime (daily Cloudflare cron or delayed Portable/Deno timer); agents NEVER fetch filter lists.
 *  - Never bundled or committed to the repository.
 *  - Source: `https://easylist.to/easylist/easyprivacy.txt`
 *  - Licence: `https://easylist.to/pages/licence.html`
 *  - Conditional `If-None-Match` / `If-Modified-Since` requests (`304 Not Modified` makes zero state changes).
 *  - Hard `6-hour` minimum poll interval (`MIN_TRACKER_POLL_INTERVAL_MS`), enforced even across retries and errors.
 *  - Strict validation before activation (`200..10_240 KiB`, `text/plain`, `! Title: EasyPrivacy`, `! Version:`,
 *    `5,000..200,000` plain `||host^` rules, `<= 20%` delta from last good list); keeps previous good list on failure.
 *  - Hardcoded never-block allow-list for bot-challenge/WAF hosts, feature-flag/A-B SDKs, `selfHost`, and `EDGEFETCH_PUBLIC_ORIGIN`.
 */

import { isPublicOrPrivateSuffix } from './psl';

export const EASYPRIVACY_SOURCE_URL = 'https://easylist.to/easylist/easyprivacy.txt';
export const EASYPRIVACY_LICENCE_URL = 'https://easylist.to/pages/licence.html';
export const TRACKER_LIST_USER_AGENT = 'EdgeFetch/2.7';

export const MIN_TRACKER_POLL_INTERVAL_MS = 6 * 60 * 60_000; // 6 hours minimum between any two poll attempts
export const DAILY_TRACKER_POLL_INTERVAL_MS = 24 * 60 * 60_000; // 24 hours scheduled refresh cadence
export const INITIAL_PORTABLE_TRACKER_DELAY_MS = 3 * 60_000; // 3 minutes after portable/Deno start (never during startup)

export const MIN_TRACKER_LIST_BYTES = 200 * 1024; // 200 KiB minimum raw list size
export const MAX_TRACKER_LIST_BYTES = 10 * 1024 * 1024; // 10 MiB maximum raw list size
export const MIN_TRACKER_HOST_COUNT = 5_000;
export const MAX_TRACKER_HOST_COUNT = 200_000;
export const MAX_TRACKER_HOST_DELTA_RATIO = 0.2; // Reject > 20% jump or drop vs last good list

const R2_TRACKER_META_KEY = 'system/tracker-list/meta.json';
const R2_TRACKER_ATTEMPT_KEY = 'system/tracker-list/attempt.json';
const R2_TRACKER_HOSTS_GZ_KEY = 'system/tracker-list/hosts.txt.gz';
const MAX_SINGLE_WS_GZIP_B64_CHARS = 700_000; // Comfortably below 1 MiB WebSocket frame cap
const WS_CHUNK_B64_CHARS = 450_000;

/**
 * Code-pinned never-block suffix allow-list:
 *  - Bot-challenge & WAF providers (Cloudflare Turnstile, DataDome, PerimeterX/HUMAN, Akamai Bot Manager, Arkose Labs, reCAPTCHA, hCaptcha)
 *  - Feature-flag / A-B experimentation SDKs (LaunchDarkly, Optimizely, Statsig, Split, GrowthBook)
 */
export const NEVER_BLOCK_HOST_SUFFIXES: ReadonlySet<string> = new Set([
  // Bot-challenge & WAF hosts
  'challenges.cloudflare.com',
  'datadome.co',
  'captcha-delivery.com',
  'perimeterx.net',
  'px-cdn.net',
  'px-cloud.net',
  'pxchk.net',
  'humansecurity.com',
  'hsprotect.net',
  'akamaihd.net',
  'akamaized.net',
  'akstat.io',
  'go-mpulse.net',
  'arkoselabs.com',
  'funcaptcha.com',
  'recaptcha.net',
  'google.com',
  'gstatic.com',
  'hcaptcha.com',
  // Feature-flag / A-B SDKs
  'launchdarkly.com',
  'optimizely.com',
  'statsig.com',
  'statsigapi.net',
  'featureassets.org',
  'split.io',
  'growthbook.io',
]);

export interface TrackerListMetadata {
  version: string;
  lastModified: string | null;
  etag: string | null;
  fetchedAt: number;
  hostCount: number;
  rawParsedHostCount: number;
  sha256: string;
  sourceUrl: string;
  licenseUrl: string;
}

export interface StoredTrackerList {
  meta: TrackerListMetadata;
  hosts: string[];
  hostsGzipB64: string;
}

export interface TrackerListAdminStatus {
  enabled: boolean;
  version: string | null;
  lastModified: string | null;
  fetchedAt: number | null;
  hostCount: number;
  sha256: string | null;
  sourceUrl: string;
  licenseUrl: string;
}

interface AttemptRecord {
  lastAttemptAt: number;
}

export interface TrackerBucketLike {
  get(key: string): Promise<{
    arrayBuffer(): Promise<ArrayBuffer>;
    text(): Promise<string>;
  } | null>;
  put(key: string, value: Uint8Array | ArrayBuffer | string): Promise<unknown>;
}

const memoryCacheByBucket = new WeakMap<object, StoredTrackerList>();
const memoryAttemptByBucket = new WeakMap<object, number>();

export function isTrackerListDisabled(
  env?: { EDGEFETCH_TRACKER_LIST?: string },
  hubSettingValue?: string | null,
): boolean {
  for (const raw of [env?.EDGEFETCH_TRACKER_LIST, hubSettingValue]) {
    const clean = (raw ?? '').trim().toLowerCase();
    if (clean === 'off' || clean === 'false' || clean === '0' || clean === 'disabled' || clean === 'no') {
      return true;
    }
  }
  return false;
}

export function normalizeDomainHostCandidate(raw: string): string | null {
  let clean = raw.trim().toLowerCase();
  if (!clean) return null;
  if (clean.endsWith('.')) {
    clean = clean.slice(0, -1);
  }
  if (!clean || clean.length > 253 || clean.startsWith('.') || clean.endsWith('.') || !clean.includes('.')) {
    return null;
  }
  const labels = clean.split('.');
  if (labels.length < 2) return null;
  for (const label of labels) {
    if (label.length < 1 || label.length > 63 || label.startsWith('-') || label.endsWith('-')) {
      return null;
    }
    for (let i = 0; i < label.length; i++) {
      const code = label.charCodeAt(i);
      const isAlphaNum = (code >= 0x61 && code <= 0x7a) || (code >= 0x30 && code <= 0x39);
      if (!isAlphaNum && code !== 0x2d) {
        return null;
      }
    }
  }
  // Reject IPv4 literals and numeric-only TLDs per RFC 1123
  const tld = labels[labels.length - 1]!;
  let allDigits = true;
  for (let i = 0; i < tld.length; i++) {
    const code = tld.charCodeAt(i);
    if (code < 0x30 || code > 0x39) {
      allDigits = false;
      break;
    }
  }
  if (allDigits) return null;
  return clean;
}

export function resolveExtraNeverBlockHosts(params?: {
  selfHost?: string;
  publicOrigin?: string;
}): string[] {
  const out = new Set<string>();
  if (params?.selfHost) {
    const cleanSelf = normalizeDomainHostCandidate(params.selfHost.split(':')[0] ?? '');
    if (cleanSelf) out.add(cleanSelf);
  }
  if (params?.publicOrigin) {
    for (const part of params.publicOrigin.split(',')) {
      const trimmed = part.trim();
      if (!trimmed) continue;
      try {
        const u = new URL(trimmed);
        const h = normalizeDomainHostCandidate(u.hostname);
        if (h) out.add(h);
      } catch {
        const h = normalizeDomainHostCandidate(trimmed.split(':')[0] ?? '');
        if (h) out.add(h);
      }
    }
  }
  return [...out];
}

export function hostMatchesSuffixSet(host: string, set: ReadonlySet<string>): boolean {
  if (set.size === 0 || !host) return false;
  let cur = host;
  while (true) {
    if (set.has(cur)) return true;
    const dot = cur.indexOf('.');
    if (dot < 0) return false;
    cur = cur.slice(dot + 1);
  }
}

const PLAIN_HOST_RULE_RE = /^\|\|[a-z0-9.-]+\^$/;

export type ParsedTrackerListResult =
  | {
      ok: true;
      version: string;
      headerLastModified: string | null;
      rawParsedHostCount: number;
      hosts: string[];
    }
  | {
      ok: false;
      reason: string;
    };

export function parseAndValidateEasyPrivacyList(
  rawText: string,
  byteLength: number,
  options?: {
    previousHostCount?: number;
    extraNeverBlockHosts?: string[];
  },
): ParsedTrackerListResult {
  if (byteLength < MIN_TRACKER_LIST_BYTES) {
    return { ok: false, reason: `list too small (${byteLength} < ${MIN_TRACKER_LIST_BYTES} bytes)` };
  }
  if (byteLength > MAX_TRACKER_LIST_BYTES) {
    return { ok: false, reason: `list exceeds maximum size (${byteLength} > ${MAX_TRACKER_LIST_BYTES} bytes)` };
  }

  const headSample = rawText.slice(0, 512).trimStart().toLowerCase();
  if (headSample.startsWith('<!doctype') || headSample.startsWith('<html') || headSample.startsWith('<head')) {
    return { ok: false, reason: 'HTML document received instead of EasyPrivacy text list' };
  }

  const extraAllowSet = new Set<string>();
  for (const h of options?.extraNeverBlockHosts ?? []) {
    const clean = normalizeDomainHostCandidate(h);
    if (clean) extraAllowSet.add(clean);
  }

  let sawEasyPrivacyTitle = false;
  let version = '';
  let headerLastModified: string | null = null;
  let nonEmptyHeaderLinesSeen = 0;

  const parsedRawSet = new Set<string>();
  const survivingSet = new Set<string>();

  let lineStart = 0;
  const totalLen = rawText.length;
  while (lineStart <= totalLen) {
    let lineEnd = rawText.indexOf('\n', lineStart);
    if (lineEnd < 0) lineEnd = totalLen;
    let endTrim = lineEnd;
    if (endTrim > lineStart && rawText.charCodeAt(endTrim - 1) === 0x0d) {
      endTrim--;
    }
    const line = rawText.slice(lineStart, endTrim).trim();
    lineStart = lineEnd + 1;

    if (!line) continue;

    if (nonEmptyHeaderLinesSeen < 30 && (line.startsWith('!') || line.startsWith('['))) {
      nonEmptyHeaderLinesSeen++;
      if (/^!\s*Title\s*:\s*EasyPrivacy(?:\b|$)/i.test(line)) {
        // Require exact EasyPrivacy title prefix (reject "! Title: WrongList")
        const titleVal = line.slice(line.indexOf(':') + 1).trim();
        if (titleVal === 'EasyPrivacy' || titleVal.startsWith('EasyPrivacy ')) {
          sawEasyPrivacyTitle = true;
        }
      } else if (!version && /^!\s*Version\s*:/i.test(line)) {
        const verVal = line.slice(line.indexOf(':') + 1).trim();
        if (verVal && verVal.length <= 64 && /^[A-Za-z0-9._-]+$/.test(verVal)) {
          version = verVal;
        }
      } else if (!headerLastModified && /^!\s*Last\s+modified\s*:/i.test(line)) {
        const lmVal = line.slice(line.indexOf(':') + 1).trim();
        if (lmVal && lmVal.length <= 128) {
          headerLastModified = lmVal;
        }
      }
      continue;
    }

    // Fast skip comments, exceptions (`@@`), cosmetic rules (`#`), options (`$`), wildcards (`*`), and paths (`/`)
    if (line.charCodeAt(0) !== 0x7c || line.charCodeAt(1) !== 0x7c || line.charCodeAt(line.length - 1) !== 0x5e) {
      continue;
    }
    const lowerLine = line.toLowerCase();
    if (!PLAIN_HOST_RULE_RE.test(lowerLine)) {
      continue;
    }
    const rawHost = lowerLine.slice(2, -1);
    const host = normalizeDomainHostCandidate(rawHost);
    if (!host) continue;
    if (isPublicOrPrivateSuffix(host)) continue;

    parsedRawSet.add(host);
    if (hostMatchesSuffixSet(host, NEVER_BLOCK_HOST_SUFFIXES) || hostMatchesSuffixSet(host, extraAllowSet)) {
      continue;
    }
    survivingSet.add(host);
  }

  if (!sawEasyPrivacyTitle) {
    return { ok: false, reason: 'missing required "! Title: EasyPrivacy" header' };
  }
  if (!version) {
    return { ok: false, reason: 'missing required "! Version:" header' };
  }

  const rawParsedHostCount = parsedRawSet.size;
  const survivingCount = survivingSet.size;
  if (rawParsedHostCount < MIN_TRACKER_HOST_COUNT || survivingCount < MIN_TRACKER_HOST_COUNT) {
    return { ok: false, reason: `parsed host count (${survivingCount}) below minimum (${MIN_TRACKER_HOST_COUNT})` };
  }
  if (rawParsedHostCount > MAX_TRACKER_HOST_COUNT || survivingCount > MAX_TRACKER_HOST_COUNT) {
    return { ok: false, reason: `parsed host count (${survivingCount}) exceeds maximum (${MAX_TRACKER_HOST_COUNT})` };
  }

  const prevCount = options?.previousHostCount;
  if (typeof prevCount === 'number' && prevCount > 0) {
    const deltaRatio = Math.abs(survivingCount - prevCount) / prevCount;
    if (deltaRatio > MAX_TRACKER_HOST_DELTA_RATIO) {
      return {
        ok: false,
        reason: `parsed host count (${survivingCount}) differs from previous good list (${prevCount}) by ${(deltaRatio * 100).toFixed(1)}% (> 20%)`,
      };
    }
  }

  const hosts = [...survivingSet].sort();
  return {
    ok: true,
    version,
    headerLastModified,
    rawParsedHostCount,
    hosts,
  };
}

async function sha256HexUtf8(text: string): Promise<string> {
  const bytes = new TextEncoder().encode(text);
  const digest = await crypto.subtle.digest('SHA-256', bytes);
  return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, '0')).join('');
}

async function gzipBytes(raw: Uint8Array): Promise<Uint8Array> {
  const cs = new CompressionStream('gzip');
  const writer = cs.writable.getWriter();
  void writer.write(raw as unknown as BufferSource);
  void writer.close();
  const ab = await new Response(cs.readable).arrayBuffer();
  return new Uint8Array(ab);
}

async function gunzipBytesCapped(gz: Uint8Array, maxBytes: number): Promise<Uint8Array> {
  const ds = new DecompressionStream('gzip');
  const writer = ds.writable.getWriter();
  void writer.write(gz as unknown as BufferSource);
  void writer.close();
  const reader = ds.readable.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    if (value) {
      total += value.byteLength;
      if (total > maxBytes) {
        await reader.cancel('gunzip cap exceeded').catch(() => undefined);
        throw new Error('stored tracker list exceeds decompression cap');
      }
      chunks.push(value);
    }
  }
  const out = new Uint8Array(total);
  let offset = 0;
  for (const c of chunks) {
    out.set(c, offset);
    offset += c.byteLength;
  }
  return out;
}

function uint8ToBase64(bytes: Uint8Array): string {
  let bin = '';
  const chunkSize = 0x8000;
  for (let i = 0; i < bytes.length; i += chunkSize) {
    bin += String.fromCharCode(...bytes.subarray(i, i + chunkSize));
  }
  return btoa(bin);
}

export function buildTrackerListWsFrames(
  stored: StoredTrackerList,
  extraNeverBlockHosts?: string[],
): string[] {
  const allowExtra = extraNeverBlockHosts && extraNeverBlockHosts.length > 0 ? extraNeverBlockHosts : undefined;
  if (stored.hostsGzipB64.length <= MAX_SINGLE_WS_GZIP_B64_CHARS) {
    return [
      JSON.stringify({
        type: 'tracker_list',
        version: stored.meta.version,
        sha256: stored.meta.sha256,
        hostCount: stored.meta.hostCount,
        fetchedAt: stored.meta.fetchedAt,
        hostsGzipB64: stored.hostsGzipB64,
        ...(allowExtra ? { neverBlockHosts: allowExtra } : {}),
      }),
    ];
  }
  const totalChunks = Math.ceil(stored.hostsGzipB64.length / WS_CHUNK_B64_CHARS);
  const frames: string[] = [];
  for (let idx = 0; idx < totalChunks; idx++) {
    frames.push(
      JSON.stringify({
        type: 'tracker_list_chunk',
        version: stored.meta.version,
        sha256: stored.meta.sha256,
        hostCount: stored.meta.hostCount,
        fetchedAt: stored.meta.fetchedAt,
        chunkIndex: idx,
        totalChunks,
        data: stored.hostsGzipB64.slice(idx * WS_CHUNK_B64_CHARS, (idx + 1) * WS_CHUNK_B64_CHARS),
        ...(idx === 0 && allowExtra ? { neverBlockHosts: allowExtra } : {}),
      }),
    );
  }
  return frames;
}

export async function loadStoredTrackerList(bucket?: TrackerBucketLike | null): Promise<StoredTrackerList | null> {
  if (!bucket) return null;
  const cached = memoryCacheByBucket.get(bucket);
  if (cached) return cached;

  try {
    const [metaObj, gzObj] = await Promise.all([
      bucket.get(R2_TRACKER_META_KEY),
      bucket.get(R2_TRACKER_HOSTS_GZ_KEY),
    ]);
    if (!metaObj || !gzObj) return null;
    const meta = JSON.parse(await metaObj.text()) as TrackerListMetadata;
    if (!meta || typeof meta.version !== 'string' || !meta.version || typeof meta.sha256 !== 'string') {
      return null;
    }
    const gzBytes = new Uint8Array(await gzObj.arrayBuffer());
    const rawUtf8 = await gunzipBytesCapped(gzBytes, 16 * 1024 * 1024);
    const joined = new TextDecoder().decode(rawUtf8);
    const actualSha = await sha256HexUtf8(joined);
    if (actualSha !== meta.sha256) {
      return null;
    }
    const hosts = joined ? joined.split('\n').filter(Boolean) : [];
    if (hosts.length < MIN_TRACKER_HOST_COUNT) return null;
    const loaded: StoredTrackerList = {
      meta: {
        ...meta,
        sourceUrl: EASYPRIVACY_SOURCE_URL,
        licenseUrl: EASYPRIVACY_LICENCE_URL,
      },
      hosts,
      hostsGzipB64: uint8ToBase64(gzBytes),
    };
    memoryCacheByBucket.set(bucket, loaded);
    return loaded;
  } catch {
    return null;
  }
}

async function readLastAttemptAt(bucket: TrackerBucketLike): Promise<number> {
  const mem = memoryAttemptByBucket.get(bucket);
  if (typeof mem === 'number' && mem > 0) return mem;
  try {
    const obj = await bucket.get(R2_TRACKER_ATTEMPT_KEY);
    if (!obj) return 0;
    const parsed = JSON.parse(await obj.text()) as Partial<AttemptRecord>;
    return typeof parsed.lastAttemptAt === 'number' && Number.isFinite(parsed.lastAttemptAt) ? parsed.lastAttemptAt : 0;
  } catch {
    return 0;
  }
}

async function writeLastAttemptAt(bucket: TrackerBucketLike, ts: number): Promise<void> {
  memoryAttemptByBucket.set(bucket, ts);
  await bucket.put(R2_TRACKER_ATTEMPT_KEY, JSON.stringify({ lastAttemptAt: ts })).catch(() => undefined);
}

async function readCappedBodyBytes(
  res: Response,
  maxBytes: number,
): Promise<{ ok: true; bytes: Uint8Array } | { ok: false; reason: string }> {
  const clHdr = res.headers.get('content-length');
  if (clHdr) {
    const cl = Number(clHdr);
    if (Number.isFinite(cl) && cl > maxBytes) {
      await res.body?.cancel('content-length exceeds maxBytes').catch(() => undefined);
      return { ok: false, reason: `content-length (${cl}) exceeds ${maxBytes} bytes` };
    }
  }
  if (!res.body) {
    return { ok: false, reason: 'empty response body' };
  }
  const reader = res.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      if (value) {
        total += value.byteLength;
        if (total > maxBytes) {
          await reader.cancel('tracker list exceeds maxBytes').catch(() => undefined);
          return { ok: false, reason: `streamed response exceeds ${maxBytes} bytes` };
        }
        chunks.push(value);
      }
    }
  } catch (err) {
    return { ok: false, reason: err instanceof Error ? err.message : String(err) };
  }
  const out = new Uint8Array(total);
  let offset = 0;
  for (const c of chunks) {
    out.set(c, offset);
    offset += c.byteLength;
  }
  return { ok: true, bytes: out };
}

export interface RefreshTrackerListParams {
  bucket?: TrackerBucketLike | null;
  fetchFn: typeof fetch;
  env?: { EDGEFETCH_TRACKER_LIST?: string };
  hubSettingValue?: string | null;
  selfHost?: string;
  publicOrigin?: string;
  now?: number;
  forceAfter6hOverrideForTest?: boolean;
}

export interface RefreshTrackerListOutcome {
  ok: boolean;
  disabled?: boolean;
  rateLimited?: boolean;
  notModified?: boolean;
  updated: boolean;
  reason?: string;
  current: StoredTrackerList | null;
}

export async function refreshHubTrackerList(params: RefreshTrackerListParams): Promise<RefreshTrackerListOutcome> {
  const now = params.now ?? Date.now();
  if (isTrackerListDisabled(params.env, params.hubSettingValue)) {
    return { ok: true, disabled: true, updated: false, current: null };
  }
  if (!params.bucket) {
    return { ok: false, updated: false, reason: 'storage_bucket_unconfigured', current: null };
  }

  const existing = await loadStoredTrackerList(params.bucket);
  const lastAttempt = await readLastAttemptAt(params.bucket);
  if (!params.forceAfter6hOverrideForTest && lastAttempt > 0 && now - lastAttempt < MIN_TRACKER_POLL_INTERVAL_MS) {
    return { ok: true, rateLimited: true, updated: false, current: existing };
  }

  // Record attempt timestamp BEFORE issuing network fetch so retries after errors also respect the 6-hour floor!
  await writeLastAttemptAt(params.bucket, now);

  const reqHeaders = new Headers({
    'user-agent': TRACKER_LIST_USER_AGENT,
    accept: 'text/plain',
  });
  if (existing?.meta.etag) {
    reqHeaders.set('if-none-match', existing.meta.etag);
  }
  if (existing?.meta.lastModified) {
    reqHeaders.set('if-modified-since', existing.meta.lastModified);
  }

  let res: Response;
  try {
    res = await params.fetchFn(EASYPRIVACY_SOURCE_URL, {
      method: 'GET',
      headers: reqHeaders,
    });
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    console.warn(JSON.stringify({ event: 'tracker_list_fetch_failed', reason: msg }));
    return { ok: false, updated: false, reason: msg, current: existing };
  }

  if (res.status === 304) {
    if (!existing) {
      console.warn(JSON.stringify({ event: 'tracker_list_rejected', reason: 'unexpected_304_without_cached_list' }));
      return { ok: false, updated: false, reason: 'unexpected_304_without_cached_list', current: null };
    }
    return { ok: true, notModified: true, updated: false, current: existing };
  }

  if (res.status !== 200) {
    await res.body?.cancel().catch(() => undefined);
    const reason = `unexpected HTTP status ${res.status}`;
    console.warn(JSON.stringify({ event: 'tracker_list_rejected', reason }));
    return { ok: false, updated: false, reason, current: existing };
  }

  const ct = (res.headers.get('content-type') ?? '').trim().toLowerCase();
  if (!ct.startsWith('text/plain')) {
    await res.body?.cancel().catch(() => undefined);
    const reason = `invalid content-type "${ct}" (expected text/plain)`;
    console.warn(JSON.stringify({ event: 'tracker_list_rejected', reason }));
    return { ok: false, updated: false, reason, current: existing };
  }

  const readRes = await readCappedBodyBytes(res, MAX_TRACKER_LIST_BYTES);
  if (!readRes.ok) {
    console.warn(JSON.stringify({ event: 'tracker_list_rejected', reason: readRes.reason }));
    return { ok: false, updated: false, reason: readRes.reason, current: existing };
  }

  const rawText = new TextDecoder('utf-8', { fatal: false }).decode(readRes.bytes);
  const extraNeverBlockHosts = resolveExtraNeverBlockHosts({
    selfHost: params.selfHost,
    publicOrigin: params.publicOrigin,
  });

  const validated = parseAndValidateEasyPrivacyList(rawText, readRes.bytes.byteLength, {
    ...(existing ? { previousHostCount: existing.meta.hostCount } : {}),
    extraNeverBlockHosts,
  });
  if (!validated.ok) {
    console.warn(JSON.stringify({ event: 'tracker_list_rejected', reason: validated.reason }));
    return { ok: false, updated: false, reason: validated.reason, current: existing };
  }

  const joined = validated.hosts.join('\n');
  const sha256 = await sha256HexUtf8(joined);
  const gzBytes = await gzipBytes(new TextEncoder().encode(joined));
  const hostsGzipB64 = uint8ToBase64(gzBytes);

  const respLastMod = res.headers.get('last-modified')?.trim() || validated.headerLastModified || null;
  const respEtag = res.headers.get('etag')?.trim() || null;

  const meta: TrackerListMetadata = {
    version: validated.version,
    lastModified: respLastMod,
    etag: respEtag,
    fetchedAt: now,
    hostCount: validated.hosts.length,
    rawParsedHostCount: validated.rawParsedHostCount,
    sha256,
    sourceUrl: EASYPRIVACY_SOURCE_URL,
    licenseUrl: EASYPRIVACY_LICENCE_URL,
  };

  await Promise.all([
    params.bucket.put(R2_TRACKER_HOSTS_GZ_KEY, gzBytes),
    params.bucket.put(R2_TRACKER_META_KEY, JSON.stringify(meta)),
  ]);

  const nextStored: StoredTrackerList = {
    meta,
    hosts: validated.hosts,
    hostsGzipB64,
  };
  memoryCacheByBucket.set(params.bucket, nextStored);

  const changed = !existing || existing.meta.version !== meta.version || existing.meta.sha256 !== meta.sha256;
  return {
    ok: true,
    updated: changed,
    notModified: false,
    current: nextStored,
  };
}

export async function getTrackerListAdminStatus(params: {
  bucket?: TrackerBucketLike | null;
  env?: { EDGEFETCH_TRACKER_LIST?: string };
  hubSettingValue?: string | null;
}): Promise<TrackerListAdminStatus> {
  const disabled = isTrackerListDisabled(params.env, params.hubSettingValue);
  const stored = disabled ? null : await loadStoredTrackerList(params.bucket);
  return {
    enabled: !disabled,
    version: stored?.meta.version ?? null,
    lastModified: stored?.meta.lastModified ?? null,
    fetchedAt: stored?.meta.fetchedAt ?? null,
    hostCount: stored?.meta.hostCount ?? 0,
    sha256: stored?.meta.sha256 ?? null,
    sourceUrl: EASYPRIVACY_SOURCE_URL,
    licenseUrl: EASYPRIVACY_LICENCE_URL,
  };
}
