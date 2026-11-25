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

import { callCoreWasmRaw } from './wasm-bridge';

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

  // Single Go WASM pass (`internal/extract/tracker_validate.go`): parses all ~58k EasyPrivacy lines + ~44k PSL checks
  // in 1 boundary crossing (~8ms CPU) instead of 44,000 per-host JS<->WASM crossings.
  const out = callCoreWasmRaw<{
    ok: boolean;
    reason?: string;
    version?: string;
    headerLastModified?: string | null;
    rawParsedHostCount?: number;
    joinedHosts?: string;
  }>(
    'validate_easyprivacy',
    {
      byteLength,
      ...(typeof options?.previousHostCount === 'number' ? { previousHostCount: options.previousHostCount } : {}),
      ...(options?.extraNeverBlockHosts && options.extraNeverBlockHosts.length > 0
        ? { extraNeverBlockHosts: options.extraNeverBlockHosts }
        : {}),
    },
    rawText,
  );
  if (!out.ok || !out.version) {
    return { ok: false, reason: out.reason ?? 'invalid EasyPrivacy list' };
  }
  const hosts = out.joinedHosts ? out.joinedHosts.split('\n') : [];
  return {
    ok: true,
    version: out.version,
    headerLastModified: out.headerLastModified ?? null,
    rawParsedHostCount: out.rawParsedHostCount ?? hosts.length,
    hosts,
  };
}

async function sha256HexBytes(bytes: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', bytes as unknown as BufferSource);
  return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, '0')).join('');
}

function countNonEmptyNewlineLines(bytes: Uint8Array): number {
  let count = 0;
  let lineLen = 0;
  for (let i = 0; i < bytes.byteLength; i++) {
    const b = bytes[i]!;
    if (b === 0x0a) {
      if (lineLen > 0) count++;
      lineLen = 0;
    } else if (b !== 0x0d) {
      lineLen++;
    }
  }
  if (lineLen > 0) count++;
  return count;
}

async function gzipBytes(raw: Uint8Array): Promise<Uint8Array> {
  const cs = new CompressionStream('gzip');
  const writer = cs.writable.getWriter();
  void writer
    .write(raw as unknown as BufferSource)
    .then(() => writer.close())
    .catch(() => undefined);
  const ab = await new Response(cs.readable).arrayBuffer();
  return new Uint8Array(ab);
}

async function gunzipBytesCapped(gz: Uint8Array, maxBytes: number): Promise<Uint8Array> {
  const ds = new DecompressionStream('gzip');
  const writer = ds.writable.getWriter();
  void writer
    .write(gz as unknown as BufferSource)
    .then(() => writer.close())
    .catch(() => undefined);
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
    if (
      !meta ||
      typeof meta.version !== 'string' ||
      !meta.version ||
      typeof meta.sha256 !== 'string' ||
      !/^[0-9a-f]{64}$/i.test(meta.sha256)
    ) {
      return null;
    }
    const gzBytes = new Uint8Array(await gzObj.arrayBuffer());
    const rawUtf8 = await gunzipBytesCapped(gzBytes, 16 * 1024 * 1024);
    const actualSha = await sha256HexBytes(rawUtf8);
    if (actualSha !== meta.sha256.toLowerCase()) {
      return null;
    }
    const lineCount = countNonEmptyNewlineLines(rawUtf8);
    if (lineCount < MIN_TRACKER_HOST_COUNT || lineCount > MAX_TRACKER_HOST_COUNT) return null;
    const loaded: StoredTrackerList = {
      meta: {
        ...meta,
        sha256: actualSha,
        hostCount: lineCount,
        sourceUrl: EASYPRIVACY_SOURCE_URL,
        licenseUrl: EASYPRIVACY_LICENCE_URL,
      },
      hosts: [],
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
  fetchTimeoutMs?: number;
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

const DEFAULT_TRACKER_FETCH_TIMEOUT_MS = 20_000;
const MAX_TRACKER_REDIRECT_HOPS = 2;

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

  const timeoutMs =
    typeof params.fetchTimeoutMs === 'number' && params.fetchTimeoutMs > 0
      ? Math.floor(params.fetchTimeoutMs)
      : DEFAULT_TRACKER_FETCH_TIMEOUT_MS;
  const ac = new AbortController();
  const fetchTimer = setTimeout(() => ac.abort(new Error('tracker_list_fetch_timeout')), timeoutMs);

  let res: Response;
  let readRes: { ok: true; bytes: Uint8Array } | { ok: false; reason: string };
  try {
    let currentUrl = EASYPRIVACY_SOURCE_URL;
    let hop = 0;
    while (true) {
      try {
        res = await params.fetchFn(currentUrl, {
          method: 'GET',
          headers: reqHeaders,
          redirect: 'manual',
          signal: ac.signal,
        });
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        console.warn(JSON.stringify({ event: 'tracker_list_fetch_failed', reason: msg }));
        return { ok: false, updated: false, reason: msg, current: existing };
      }

      if (res.status === 301 || res.status === 302 || res.status === 303 || res.status === 307 || res.status === 308) {
        const loc = res.headers.get('location')?.trim() ?? '';
        await res.body?.cancel().catch(() => undefined);
        if (!loc || hop >= MAX_TRACKER_REDIRECT_HOPS) {
          const reason = !loc ? `redirect HTTP ${res.status} missing location` : 'too many redirects';
          console.warn(JSON.stringify({ event: 'tracker_list_rejected', reason }));
          return { ok: false, updated: false, reason, current: existing };
        }
        let nextUrl: URL;
        try {
          nextUrl = new URL(loc, currentUrl);
        } catch {
          const reason = 'invalid redirect location URL';
          console.warn(JSON.stringify({ event: 'tracker_list_rejected', reason }));
          return { ok: false, updated: false, reason, current: existing };
        }
        if (nextUrl.protocol !== 'https:' || nextUrl.hostname.toLowerCase() !== 'easylist.to') {
          const reason = `disallowed redirect host or scheme (${nextUrl.protocol}//${nextUrl.hostname})`;
          console.warn(JSON.stringify({ event: 'tracker_list_rejected', reason }));
          return { ok: false, updated: false, reason, current: existing };
        }
        currentUrl = nextUrl.toString();
        hop++;
        continue;
      }
      break;
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

    readRes = await readCappedBodyBytes(res, MAX_TRACKER_LIST_BYTES);
  } finally {
    clearTimeout(fetchTimer);
  }

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
  const joinedBytes = new TextEncoder().encode(joined);
  const sha256 = await sha256HexBytes(joinedBytes);
  const gzBytes = await gzipBytes(joinedBytes);
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

  memoryCacheByBucket.set(params.bucket, {
    meta,
    hosts: [],
    hostsGzipB64,
  });

  const nextStored: StoredTrackerList = {
    meta,
    hosts: validated.hosts,
    hostsGzipB64,
  };

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
