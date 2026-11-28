/**
 * Storage primitives, R2 object layout helpers, retention freshness checks, and `/v1/capabilities` metadata for
 * EdgeFetch's optional three-layer storage architecture (`ARTIFACTS` R2 + `META` D1 + `SEARCH` D1 FTS5).
 *
 * All storage bindings remain strictly optional so an existing single-binding `AgentHubDO` deployment continues
 * operating unchanged when `ARTIFACTS` / `META` / `SEARCH` / `INGEST` are unconfigured.
 */

import type { LlmEnvBindings } from './llm';
import { getActiveCallerAuthContext } from './oauth';
import { encodeBodyForWire } from './overflow';
import {
  computeMarkdownSliceCheckpoints,
  sanitizeFullMarkdownDocumentForArtifact,
  sanitizeMarkdownPageSlice,
  stripInvisibleSmugglingChars,
  type MarkdownSliceCheckpoint,
} from './scrape-advanced';
import { listConfiguredSpaFallbacks, type SpaFallbackEnv, type SpaFallbackProvider } from './spa-fallback';

export type ArtifactRetention = 'transient' | 'stored';
export type ArtifactVisibility = 'public' | 'private';

export interface IngestWorkflowParams {
  manifestKey: string;
  jobId: string;
  siteId?: string;
  collectionId?: string;
  via: string;
}

export interface OptionalStorageBindings extends SpaFallbackEnv, LlmEnvBindings {
  ARTIFACTS?: R2Bucket;
  META?: D1Database;
  SEARCH?: D1Database;
  INGEST?: {
    create(options?: { id?: string; params?: IngestWorkflowParams }): Promise<{ id: string }>;
  };
  CRAWL?: {
    create(options?: { id?: string; params?: unknown }): Promise<{ id: string }>;
  };
  /** Optional Service Binding (`PdfOcrService` for optional external worker) for PyMuPDF + Tesseract 5.5.0 PDF OCR. */
  PDF_OCR?: {
    fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response>;
  };
  /** Optional HTTP URL + token fallback for PDF OCR when running outside Service Bindings. */
  PDF_OCR_URL?: string;
  PDF_OCR_TOKEN?: string;
}

export const SCRAPE_PIPELINE_VERSION = 37;
export const SHA256_HEX_RE = /^[0-9a-f]{64}$/;
export const TRANSIENT_RETENTION_MS = 24 * 60 * 60_000; // 1 day (`tmp/` prefix lifecycle)
export const STORED_RETENTION_MS = 30 * 24 * 60 * 60_000; // 30 days (`raw/` prefix lifecycle)
export const MAX_ARTIFACT_CONTENT_BYTES = 16 << 20; // 16 MiB uncompressed ceiling
export const MAX_ARTIFACT_STORED_BYTES = 18 << 20; // 18 MiB gzip upload ceiling
export const INLINE_HYDRATION_BUDGET_BYTES = 18 << 20; // 18 MiB inline body hydration budget (stays under 20 MiB reply cap)
export const DEFAULT_ARTIFACT_PAGE_LIMIT = 65_536;
export const MAX_ARTIFACT_PAGE_LIMIT = 1 << 20; // 1 MiB per paged read
const UPLOAD_ID_RE = /^[A-Za-z0-9_.:-]{1,128}$/;

function bytesToHex(buf: ArrayBuffer | Uint8Array): string {
  const view = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let out = '';
  for (let i = 0; i < view.length; i++) {
    out += view[i]!.toString(16).padStart(2, '0');
  }
  return out;
}

export function isValidSha256Hex(raw: unknown): raw is string {
  return typeof raw === 'string' && SHA256_HEX_RE.test(raw);
}

export function isValidRetention(raw: unknown): raw is ArtifactRetention {
  return raw === 'transient' || raw === 'stored';
}

/**
 * Computes the R2 object key for a gzipped page artifact keyed by the SHA-256 of the compressed gzip bytes (`blobSha256`):
 *  - `transient` -> `tmp/sha256/<aa>/<blobSha256>.gz` (1-day lifecycle rule)
 *  - `stored`    -> `raw/sha256/<aa>/<blobSha256>.gz` (30-day lifecycle rule)
 */
export function r2ArtifactKey(retention: ArtifactRetention, blobSha256: string): string {
  if (!isValidSha256Hex(blobSha256)) {
    throw new Error('invalid blobSha256 (expected 64 lowercase hex characters)');
  }
  const prefix = retention === 'stored' ? 'raw' : 'tmp';
  return `${prefix}/sha256/${blobSha256.slice(0, 2)}/${blobSha256}.gz`;
}

/** Computes the transient R2 manifest key passed to `IngestWorkflow` (`tmp/manifests/<jobId>.json`). */
export function r2ManifestKey(jobId: string): string {
  if (!/^[A-Za-z0-9_-]{1,64}$/.test(jobId)) {
    throw new Error('invalid jobId');
  }
  return `tmp/manifests/${jobId}.json`;
}

/** Computes the R2 key for derived Markdown / extracted artifacts (`derived/<pipelineVersion>/<format>/<contentSha256>`). */
export function r2DerivedKey(pipelineVersion: number, format: string, contentSha256: string): string {
  if (!Number.isInteger(pipelineVersion) || pipelineVersion < 1) {
    throw new Error('invalid pipelineVersion');
  }
  if (!/^[a-z0-9_-]{1,24}$/.test(format)) {
    throw new Error('invalid derived format');
  }
  if (!isValidSha256Hex(contentSha256)) {
    throw new Error('invalid contentSha256');
  }
  return `derived/${pipelineVersion}/${format}/${contentSha256}`;
}

export function sanitizeStorageUserId(userId?: string): string {
  const trimmed = typeof userId === 'string' ? userId.trim() : '';
  if (!trimmed) return 'owner';
  const cleaned = trimmed.replace(/[^A-Za-z0-9_-]/g, '_').slice(0, 64);
  return cleaned || 'owner';
}

export interface NormalizeVisibilityOptions {
  cookies?: unknown;
  preferMcp?: unknown;
  hasAuthContext?: boolean;
  userId?: string;
}

const CALLER_HEADER_NAME_RE = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;
const UNSAFE_CALLER_HEADER_VALUE_RE = /[\x00-\x08\x0a-\x1f\x7f]|[^\x00-\xff]/;

function toCallerHeaderScalar(v: unknown): string | null {
  if (typeof v === 'string') return v;
  if (typeof v === 'number' || typeof v === 'boolean') return String(v);
  return null;
}

export function normalizeCallerHeadersRecord(headers: unknown): Record<string, string> {
  if (!headers || typeof headers !== 'object') return {};
  const out: Record<string, string> = {};
  const lowerToKey = new Map<string, string>();
  const setHeader = (rawKey: unknown, rawVal: unknown) => {
    const keyScalar = toCallerHeaderScalar(rawKey);
    const valScalar = toCallerHeaderScalar(rawVal);
    if (keyScalar === null || valScalar === null) return;
    const key = keyScalar.trim();
    const val = valScalar.trim();
    if (!key || !val) return;
    const lower = key.toLowerCase();
    if (lower === '__proto__' || !CALLER_HEADER_NAME_RE.test(key) || UNSAFE_CALLER_HEADER_VALUE_RE.test(val)) {
      return;
    }
    const prevKey = lowerToKey.get(lower);
    if (prevKey !== undefined && prevKey !== key) {
      delete out[prevKey];
    }
    lowerToKey.set(lower, key);
    out[key] = val;
  };
  if (Array.isArray(headers)) {
    for (const entry of headers) {
      if (!Array.isArray(entry) || entry.length < 2) continue;
      setHeader(entry[0], entry[1]);
    }
    return out;
  }
  if (typeof (headers as Headers).forEach === 'function' && typeof (headers as Headers).get === 'function') {
    (headers as Headers).forEach((v, k) => {
      setHeader(k, v);
    });
    return out;
  }
  for (const [k, v] of Object.entries(headers as Record<string, unknown>)) {
    setHeader(k, v);
  }
  return out;
}

export function hasAnyCallerHeader(headers: unknown): boolean {
  return Object.keys(normalizeCallerHeadersRecord(headers)).length > 0;
}

export function hasAnyCallerCookies(cookies: unknown): boolean {
  if (cookies === undefined || cookies === null) return false;
  if (typeof cookies === 'string') return cookies.trim().length > 0;
  if (Array.isArray(cookies)) return cookies.length > 0;
  if (typeof cookies === 'object') return Object.keys(cookies as Record<string, unknown>).length > 0;
  return false;
}

/**
 * Determines storage/cache visibility (`'public' | 'private'`).
 * Security Invariant (H4): ANY caller-supplied request header, custom cookie, `preferMcp`, explicit auth context,
 * or non-owner multi-user tenant (`userId !== 'owner'`) ALWAYS forces `'private'`, even if `raw === 'public'`.
 */
export function normalizeVisibility(
  raw: unknown,
  headers?: unknown,
  opts?: NormalizeVisibilityOptions,
): ArtifactVisibility {
  if (typeof raw === 'string' && raw.trim().toLowerCase() === 'private') {
    return 'private';
  }
  if (hasAnyCallerHeader(headers)) {
    return 'private';
  }
  if (opts && (opts.preferMcp === true || opts.hasAuthContext === true || hasAnyCallerCookies(opts.cookies))) {
    return 'private';
  }
  const effectiveUser = opts?.userId ?? getActiveCallerAuthContext()?.userId;
  if (effectiveUser && sanitizeStorageUserId(effectiveUser) !== 'owner') {
    return 'private';
  }
  if (typeof raw === 'string' && raw.trim().toLowerCase() === 'public') {
    return 'public';
  }
  return 'public';
}

export function isPrivateRequestPayload(payload: unknown, userId?: string): boolean {
  const obj =
    payload && typeof payload === 'object' && !Array.isArray(payload) ? (payload as Record<string, unknown>) : {};
  if (
    normalizeVisibility(obj.visibility, obj.headers, {
      cookies: obj.cookies,
      preferMcp: obj.useConnectedMcp === true || obj.preferMcp === true,
      hasAuthContext: Boolean(obj.auth),
      userId,
    }) === 'private'
  ) {
    return true;
  }
  const effectiveUser = userId ?? getActiveCallerAuthContext()?.userId;
  return Boolean(effectiveUser && sanitizeStorageUserId(effectiveUser) !== 'owner');
}

export function r2PrivateArtifactKey(userId: string, retention: ArtifactRetention, blobSha256: string): string {
  if (!isValidSha256Hex(blobSha256)) {
    throw new Error('invalid blobSha256 (expected 64 lowercase hex characters)');
  }
  const safeUser = sanitizeStorageUserId(userId);
  const prefix = retention === 'stored' ? 'raw' : 'tmp';
  return `private/${safeUser}/${prefix}/sha256/${blobSha256.slice(0, 2)}/${blobSha256}.gz`;
}

export function r2PrivateDerivedKey(
  userId: string,
  pipelineVersion: number,
  format: string,
  contentSha256: string,
): string {
  if (!Number.isInteger(pipelineVersion) || pipelineVersion < 1) {
    throw new Error('invalid pipelineVersion');
  }
  if (!/^[a-z0-9_-]{1,24}$/.test(format)) {
    throw new Error('invalid derived format');
  }
  if (!isValidSha256Hex(contentSha256)) {
    throw new Error('invalid contentSha256');
  }
  const safeUser = sanitizeStorageUserId(userId);
  return `private/${safeUser}/derived/${pipelineVersion}/${format}/${contentSha256}`;
}

export function r2PrivateScrapeCacheKey(userId: string, pipelineVersion: number, urlSha256: string): string {
  if (!Number.isInteger(pipelineVersion) || pipelineVersion < 1) {
    throw new Error('invalid pipelineVersion');
  }
  if (!isValidSha256Hex(urlSha256)) {
    throw new Error('invalid urlSha256');
  }
  const safeUser = sanitizeStorageUserId(userId);
  return `private/${safeUser}/cache/${pipelineVersion}/${urlSha256}.json`;
}

export async function writePrivateArtifactToR2(params: {
  bucket: R2Bucket;
  userId: string;
  rawBytes: Uint8Array;
  retention?: ArtifactRetention;
}): Promise<{ blobSha256: string; contentSha256: string; key: string }> {
  const { bucket, userId, rawBytes, retention = 'stored' } = params;
  const contentSha256 = bytesToHex(await crypto.subtle.digest('SHA-256', rawBytes as unknown as BufferSource));
  const gzStream = new Blob([rawBytes as unknown as BlobPart]).stream().pipeThrough(new CompressionStream('gzip') as unknown as TransformStream<Uint8Array, Uint8Array>);
  const gzBytes = new Uint8Array(await new Response(gzStream).arrayBuffer());
  const blobSha256 = bytesToHex(await crypto.subtle.digest('SHA-256', gzBytes));
  const key = r2PrivateArtifactKey(userId, retention, blobSha256);
  await bucket.put(key, gzBytes, {
    sha256: blobSha256,
    httpMetadata: { contentType: 'application/gzip' },
    customMetadata: {
      contentSha256,
      contentBytes: String(rawBytes.byteLength),
      retention,
      userId: sanitizeStorageUserId(userId),
      visibility: 'private',
    },
  });
  return { blobSha256, contentSha256, key };
}

export async function writeArtifactToR2(params: {
  bucket: R2Bucket;
  rawBytes: Uint8Array;
  retention?: ArtifactRetention;
  userId?: string;
  privateOnly?: boolean;
}): Promise<{ blobSha256: string; contentSha256: string; key: string }> {
  const { bucket, rawBytes, retention = 'transient', userId = 'owner', privateOnly = false } = params;
  if (privateOnly || sanitizeStorageUserId(userId) !== 'owner') {
    return writePrivateArtifactToR2({ bucket, userId, rawBytes, retention });
  }
  const contentSha256 = bytesToHex(await crypto.subtle.digest('SHA-256', rawBytes as unknown as BufferSource));
  const gzStream = new Blob([rawBytes as unknown as BlobPart]).stream().pipeThrough(new CompressionStream('gzip') as unknown as TransformStream<Uint8Array, Uint8Array>);
  const gzBytes = new Uint8Array(await new Response(gzStream).arrayBuffer());
  const blobSha256 = bytesToHex(await crypto.subtle.digest('SHA-256', gzBytes));
  const key = r2ArtifactKey(retention, blobSha256);
  await bucket.put(key, gzBytes, {
    sha256: blobSha256,
    httpMetadata: { contentType: 'application/gzip' },
    customMetadata: {
      contentSha256,
      contentBytes: String(rawBytes.byteLength),
      retention,
    },
  });
  return { blobSha256, contentSha256, key };
}

/**
 * R2 prefix lifecycle expiration starts at upload time, so content-addressed deduplication must refresh an existing
 * object whenever `head()` shows it is older than half its retention window (12h for `transient`, 15d for `stored`).
 */
export function shouldRefreshDedupedObject(uploadedAtMs: number, retention: ArtifactRetention, nowMs = Date.now()): boolean {
  const ttlMs = retention === 'stored' ? STORED_RETENTION_MS : TRANSIENT_RETENTION_MS;
  return nowMs - uploadedAtMs >= ttlMs / 2;
}

/** Sanitizes free-form user search text into a safe FTS5 `MATCH` expression (`"term1" OR "term2"`, max 12 Unicode terms). */
export function sanitizeFtsQuery(rawQuery: string): string {
  if (typeof rawQuery !== 'string') return '';
  const terms = rawQuery.match(/[\p{L}\p{N}_]+/gu);
  if (!terms || terms.length === 0) return '';
  const unique: string[] = [];
  const seen = new Set<string>();
  for (const t of terms) {
    const lower = t.toLowerCase();
    if (!seen.has(lower)) {
      seen.add(lower);
      unique.push(`"${t}"`);
      if (unique.length >= 12) break;
    }
  }
  return unique.join(' OR ');
}

export interface HubCapabilities {
  version: string;
  capabilities: {
    fetch: boolean;
    scrape: boolean;
    extract: boolean;
    map: boolean;
    crawl: boolean;
    interact: boolean;
    mcp: boolean;
    oauth: boolean;
    artifacts: boolean;
    tracking: boolean;
    ingestWorkflow: boolean;
    search: boolean;
    webSearch: boolean;
    pdfOcr: boolean;
    webBotAuth: boolean;
    spaFallback: boolean;
  };
  searchProviders: string[];
  spaFallbacks: SpaFallbackProvider[];
}

export function buildCapabilities(
  env: OptionalStorageBindings & {
    SERPER_API_KEY?: string;
    BRAVE_API_KEY?: string;
    TAVILY_API_KEY?: string;
    SEARXNG_URL?: string;
    CLOUDFLARE_ACCOUNT_ID?: string;
    CLOUDFLARE_WEBSEARCH_API_TOKEN?: string;
    CERAMIC_API_KEY?: string;
    BOT_SIGNING_PRIVATE_KEY?: string;
    BOT_SIGNING_PUBLIC_KEY?: string;
  },
  version = '2.8.22',
): HubCapabilities {
  const searchProviders: string[] = ['edge-map'];
  if (env.SEARCH) searchProviders.push('d1-fts5');
  if (env.SERPER_API_KEY?.trim()) searchProviders.push('serper');
  if (env.BRAVE_API_KEY?.trim()) searchProviders.push('brave');
  if (env.TAVILY_API_KEY?.trim()) searchProviders.push('tavily');
  if (env.SEARXNG_URL?.trim()) searchProviders.push('searxng');
  if (
    typeof env.AI?.websearch === 'function' ||
    (env.CLOUDFLARE_ACCOUNT_ID?.trim() && env.CLOUDFLARE_WEBSEARCH_API_TOKEN?.trim())
  ) {
    searchProviders.push('cloudflare');
  }
  if (env.CERAMIC_API_KEY?.trim()) searchProviders.push('ceramic');
  const spaFallbacks = listConfiguredSpaFallbacks(env);

  const hasWebProvider = Boolean(
    env.SERPER_API_KEY?.trim() ||
      env.BRAVE_API_KEY?.trim() ||
      env.TAVILY_API_KEY?.trim() ||
      env.SEARXNG_URL?.trim() ||
      searchProviders.includes('cloudflare') ||
      searchProviders.includes('ceramic'),
  );
  return {
    version,
    capabilities: {
      fetch: true,
      scrape: true,
      extract: true,
      map: true,
      crawl: Boolean(env.META),
      interact: true,
      mcp: true,
      oauth: true,
      artifacts: Boolean(env.ARTIFACTS),
      tracking: Boolean(env.META),
      ingestWorkflow: Boolean(env.INGEST),
      search: Boolean(env.SEARCH || hasWebProvider),
      webSearch: hasWebProvider,
      pdfOcr: Boolean(env.PDF_OCR || (env.PDF_OCR_URL?.trim() && env.PDF_OCR_TOKEN?.trim())),
      webBotAuth: Boolean(env.BOT_SIGNING_PRIVATE_KEY?.trim() || env.BOT_SIGNING_PUBLIC_KEY?.trim()),
      spaFallback: spaFallbacks.length > 0,
    },
    searchProviders,
    spaFallbacks,
  };
}

export interface AuthorizeArtifactUploadCallback {
  (params: {
    jobId: string;
    jobNonce: string;
    siteId: string;
    requestId: string;
    blobSha256?: string;
    confirmOnly?: boolean;
    retention: ArtifactRetention;
    storedBytes: number;
    contentBytes: number;
  }): Promise<{ ok: true } | { ok: false; status: number; error: string }>;
}

const MAX_RECENT_UPLOAD_CACHE = 1_024;
const recentArtifactUploads = new Map<string, number>();

const MAX_RECENT_DECODED_ITEMS = 16;
const MAX_RECENT_DECODED_SINGLE_BYTES = 1 << 20; // 1 MiB max per cached inline artifact
const MAX_RECENT_DECODED_TOTAL_BYTES = 8 << 20; // 8 MiB ceiling per bucket instance
const RECENT_DECODED_TTL_MS = 15_000;

interface RecentDecodedArtifactEntry {
  bytes: Uint8Array;
  contentSha256: string;
  expiresAt: number;
}

interface RecentDecodedBucketCache {
  entries: Map<string, RecentDecodedArtifactEntry>;
  totalBytes: number;
}

let recentDecodedByBucket = new WeakMap<object, RecentDecodedBucketCache>();

export function resetRecentArtifactUploadsForTests(): void {
  recentArtifactUploads.clear();
  recentDecodedByBucket = new WeakMap<object, RecentDecodedBucketCache>();
}

function rememberDecodedArtifactForHydration(
  bucket: R2Bucket,
  retention: ArtifactRetention,
  blobSha256: string,
  contentSha256: string,
  bytes: Uint8Array,
  nowMs: number,
): void {
  if (bytes.byteLength === 0 || bytes.byteLength > MAX_RECENT_DECODED_SINGLE_BYTES) return;
  const bucketObj = bucket as unknown as object;
  let state = recentDecodedByBucket.get(bucketObj);
  if (!state) {
    state = { entries: new Map(), totalBytes: 0 };
    recentDecodedByBucket.set(bucketObj, state);
  }
  for (const [k, v] of state.entries) {
    if (v.expiresAt <= nowMs) {
      state.totalBytes = Math.max(0, state.totalBytes - v.bytes.byteLength);
      state.entries.delete(k);
    }
  }
  const cacheKey = `${retention}:${blobSha256}`;
  const prev = state.entries.get(cacheKey);
  if (prev) {
    state.totalBytes = Math.max(0, state.totalBytes - prev.bytes.byteLength);
    state.entries.delete(cacheKey);
  }
  while (
    state.entries.size >= MAX_RECENT_DECODED_ITEMS ||
    state.totalBytes + bytes.byteLength > MAX_RECENT_DECODED_TOTAL_BYTES
  ) {
    const oldestKey = state.entries.keys().next().value;
    if (oldestKey === undefined) break;
    const oldest = state.entries.get(oldestKey);
    if (oldest) state.totalBytes = Math.max(0, state.totalBytes - oldest.bytes.byteLength);
    state.entries.delete(oldestKey);
  }
  state.entries.set(cacheKey, {
    bytes,
    contentSha256,
    expiresAt: nowMs + RECENT_DECODED_TTL_MS,
  });
  state.totalBytes += bytes.byteLength;
}

function lookupDecodedArtifactForHydration(
  bucket: R2Bucket,
  preferredRetention: ArtifactRetention,
  blobSha256: string,
  expectedContentSha256: string | undefined,
  nowMs: number,
): Uint8Array | null {
  const state = recentDecodedByBucket.get(bucket as unknown as object);
  if (!state) return null;
  const order: ArtifactRetention[] = preferredRetention === 'stored' ? ['stored', 'transient'] : ['transient', 'stored'];
  for (const ret of order) {
    const cacheKey = `${ret}:${blobSha256}`;
    const hit = state.entries.get(cacheKey);
    if (!hit) continue;
    if (hit.expiresAt <= nowMs) {
      state.totalBytes = Math.max(0, state.totalBytes - hit.bytes.byteLength);
      state.entries.delete(cacheKey);
      continue;
    }
    if (
      expectedContentSha256 &&
      (!isValidSha256Hex(expectedContentSha256) || hit.contentSha256 !== expectedContentSha256)
    ) {
      return null;
    }
    return hit.bytes;
  }
  return null;
}

function rememberUploadedArtifact(key: string, uploadedAtMs: number): void {
  recentArtifactUploads.delete(key);
  recentArtifactUploads.set(key, uploadedAtMs);
  while (recentArtifactUploads.size > MAX_RECENT_UPLOAD_CACHE) {
    const oldest = recentArtifactUploads.keys().next().value;
    if (oldest === undefined) break;
    recentArtifactUploads.delete(oldest);
  }
}

/**
 * Handles `PUT /agent/artifacts/<blobSha256>` streaming agent-compressed gzip artifacts directly into R2 with
 * atomic `sha256` verification and half-retention deduplication refresh (avoiding 404 `r2_head` OTEL error spans
 * on brand-new uploads when `metaDb` is bound).
 */
async function headR2ObjectWithoutMissingSpan(bucket: R2Bucket, targetKey: string): Promise<R2Object | null> {
  if (typeof (bucket as { list?: unknown }).list === 'function') {
    const listed = await bucket.list({ prefix: targetKey, limit: 4 }).catch(() => null);
    if (listed && Array.isArray(listed.objects)) {
      const exact = listed.objects.find((o) => o.key === targetKey);
      return exact ?? null;
    }
  }
  return bucket.head(targetKey).catch(() => null);
}

export async function handleAgentArtifactUpload(params: {
  request: Request;
  blobSha256: string;
  siteId: string;
  bucket?: R2Bucket;
  metaDb?: D1Database;
  authorizeJobUpload: AuthorizeArtifactUploadCallback;
  now?: number;
}): Promise<Response> {
  const { request, blobSha256, siteId, bucket, metaDb, authorizeJobUpload, now = Date.now() } = params;
  if (!bucket) {
    await request.body?.cancel().catch(() => undefined);
    return Response.json({ error: 'artifacts_not_configured' }, { status: 503 });
  }
  if (!isValidSha256Hex(blobSha256)) {
    await request.body?.cancel().catch(() => undefined);
    return Response.json({ error: 'invalid_blob_sha256' }, { status: 400 });
  }
  // Stored bytes are raw gzip, NOT an HTTP-compressed transport frame (reject Content-Encoding).
  if ((request.headers.get('content-encoding') ?? '').trim() !== '') {
    await request.body?.cancel().catch(() => undefined);
    return Response.json({ error: 'unexpected_content_encoding' }, { status: 400 });
  }

  const contentSha256 = (request.headers.get('x-content-sha256') ?? '').trim();
  if (!isValidSha256Hex(contentSha256)) {
    await request.body?.cancel().catch(() => undefined);
    return Response.json({ error: 'invalid_content_sha256' }, { status: 400 });
  }

  const rawContentLength = (request.headers.get('content-length') ?? '').trim();
  if (!/^\d+$/.test(rawContentLength)) {
    await request.body?.cancel().catch(() => undefined);
    return Response.json({ error: 'missing_content_length' }, { status: 411 });
  }
  const storedBytes = Number(rawContentLength);
  if (!Number.isSafeInteger(storedBytes) || storedBytes <= 0 || storedBytes > MAX_ARTIFACT_STORED_BYTES) {
    await request.body?.cancel().catch(() => undefined);
    return Response.json({ error: 'invalid_stored_bytes' }, { status: storedBytes > MAX_ARTIFACT_STORED_BYTES ? 413 : 400 });
  }

  const rawContentBytes = (request.headers.get('x-content-bytes') ?? '').trim();
  if (!/^\d+$/.test(rawContentBytes)) {
    await request.body?.cancel().catch(() => undefined);
    return Response.json({ error: 'invalid_content_bytes' }, { status: 400 });
  }
  const contentBytes = Number(rawContentBytes);
  if (!Number.isSafeInteger(contentBytes) || contentBytes < 0 || contentBytes > MAX_ARTIFACT_CONTENT_BYTES) {
    await request.body?.cancel().catch(() => undefined);
    return Response.json({ error: 'content_bytes_exceeds_limit' }, { status: contentBytes > MAX_ARTIFACT_CONTENT_BYTES ? 413 : 400 });
  }

  const rawRetention = (request.headers.get('x-artifact-retention') ?? '').trim();
  if (!isValidRetention(rawRetention)) {
    await request.body?.cancel().catch(() => undefined);
    return Response.json({ error: 'invalid_retention' }, { status: 400 });
  }

  const jobId = (request.headers.get('x-job-id') ?? '').trim();
  const jobNonce = (request.headers.get('x-job-nonce') ?? '').trim();
  const requestId = (request.headers.get('x-request-id') ?? '').trim();
  if (!UPLOAD_ID_RE.test(jobId) || !UPLOAD_ID_RE.test(jobNonce) || !UPLOAD_ID_RE.test(requestId)) {
    await request.body?.cancel().catch(() => undefined);
    return Response.json({ error: 'bad_job_or_request_headers' }, { status: 400 });
  }
  if (!request.body) {
    return Response.json({ error: 'empty_body' }, { status: 400 });
  }

  // 1. Authorize job + requestId + quota FIRST before reading `request.body` so invalid jobs are rejected in O(1),
  //    then verify SHA-256 proof-of-possession on `request.body` BEFORE deduplicating (`H6`) so an agent can never
  //    claim an existing `<victimBlob>` via deduplication without possessing the exact compressed bytes!
  const preAuthz = await authorizeJobUpload({
    jobId,
    jobNonce,
    siteId,
    requestId,
    retention: rawRetention,
    storedBytes,
    contentBytes,
  });
  if (!preAuthz.ok) {
    await request.body.cancel().catch(() => undefined);
    return Response.json({ error: preAuthz.error }, { status: preAuthz.status });
  }

  // Single-buffer streaming read directly into `Uint8Array(storedBytes)` (`Low` — avoids 36 MiB double-buffering!).
  const reader = request.body.getReader();
  const fullPayload = new Uint8Array(storedBytes);
  let actualReadBytes = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (value && value.byteLength > 0) {
        const nextTotal = actualReadBytes + value.byteLength;
        if (nextTotal > storedBytes || nextTotal > MAX_ARTIFACT_STORED_BYTES) {
          await reader.cancel('storedBytes exceeded').catch(() => undefined);
          return Response.json({ error: 'stored_bytes_mismatch' }, { status: 413 });
        }
        fullPayload.set(value, actualReadBytes);
        actualReadBytes = nextTotal;
      }
    }
  } catch {
    await reader.cancel().catch(() => undefined);
    return Response.json({ error: 'upload_stream_error' }, { status: 400 });
  }
  if (actualReadBytes !== storedBytes) {
    return Response.json({ error: 'content_length_mismatch' }, { status: 400 });
  }
  const actualBlobShaBuf = await crypto.subtle.digest('SHA-256', fullPayload);
  const actualBlobSha = Array.from(new Uint8Array(actualBlobShaBuf), (b) => b.toString(16).padStart(2, '0')).join('');
  if (actualBlobSha !== blobSha256) {
    return Response.json({ error: 'blob_sha256_mismatch' }, { status: 400 });
  }

  // Cryptographically verify gunzipped payload length (`contentBytes`) and `SHA-256(gunzipped) === contentSha256` BEFORE
  // confirming on the job or writing/updating R2 metadata (`EF-BLIND-02` — prevents `customMetadata.contentSha256` poisoning!).
  let gunzippedTotal = 0;
  const gunzipChunks: Uint8Array[] = [];
  try {
    const gzStream = new Blob([fullPayload])
      .stream()
      .pipeThrough(new DecompressionStream('gzip') as unknown as TransformStream<Uint8Array, Uint8Array>);
    const gzReader = gzStream.getReader();
    for (;;) {
      const { done, value } = await gzReader.read();
      if (done) break;
      if (value && value.byteLength > 0) {
        gunzippedTotal += value.byteLength;
        if (gunzippedTotal > MAX_ARTIFACT_CONTENT_BYTES || gunzippedTotal > contentBytes) {
          await gzReader.cancel('uncompressed size exceeded').catch(() => undefined);
          return Response.json(
            { error: gunzippedTotal > MAX_ARTIFACT_CONTENT_BYTES ? 'content_bytes_exceeds_limit' : 'content_bytes_mismatch' },
            { status: gunzippedTotal > MAX_ARTIFACT_CONTENT_BYTES ? 413 : 400 },
          );
        }
        gunzipChunks.push(value);
      }
    }
  } catch {
    return Response.json({ error: 'corrupt_gzip' }, { status: 400 });
  }
  if (gunzippedTotal !== contentBytes) {
    return Response.json({ error: 'content_bytes_mismatch' }, { status: 400 });
  }
  const gunzippedPayload = new Uint8Array(gunzippedTotal);
  let gzOff = 0;
  for (const chunk of gunzipChunks) {
    gunzippedPayload.set(chunk, gzOff);
    gzOff += chunk.byteLength;
  }
  const actualContentSha = bytesToHex(await crypto.subtle.digest('SHA-256', gunzippedPayload));
  if (actualContentSha !== contentSha256) {
    return Response.json({ error: 'content_sha256_mismatch' }, { status: 400 });
  }

  // Record `blobSha256` on the pending job ONLY after compressed + uncompressed proof-of-possession succeeded!
  await authorizeJobUpload({
    jobId,
    jobNonce,
    siteId,
    requestId,
    blobSha256,
    confirmOnly: true,
    retention: rawRetention,
    storedBytes: 0,
    contentBytes: 0,
  });

  const key = r2ArtifactKey(rawRetention, blobSha256);
  const cachedUploadAt = recentArtifactUploads.get(key);
  if (cachedUploadAt !== undefined && !shouldRefreshDedupedObject(cachedUploadAt, rawRetention, now)) {
    rememberDecodedArtifactForHydration(bucket, rawRetention, blobSha256, actualContentSha, gunzippedPayload, now);
    return Response.json({ ok: true, stored: false, deduplicated: true, key }, { status: 200 });
  }

  let existing: R2Object | null = null;
  let knownNewInMeta = false;
  if (metaDb) {
    const metaRow = await metaDb
      .prepare('SELECT retention, last_seen_at FROM artifacts WHERE blob_sha256 = ? LIMIT 1')
      .bind(blobSha256)
      .first<{ retention?: string | null; last_seen_at: number | null }>()
      .catch(() => null);
    const metaRet: ArtifactRetention = metaRow?.retention === 'stored' ? 'stored' : rawRetention;
    const canSatisfyRetention = metaRow?.retention === rawRetention || (rawRetention === 'transient' && metaRow?.retention === 'stored');
    if (canSatisfyRetention && metaRow?.last_seen_at && !shouldRefreshDedupedObject(metaRow.last_seen_at, metaRet, now)) {
      const checkKey = metaRet === 'stored' ? r2ArtifactKey('stored', blobSha256) : key;
      existing = await headR2ObjectWithoutMissingSpan(bucket, checkKey);
      if (existing && !shouldRefreshDedupedObject(existing.uploaded.getTime(), metaRet, now)) {
        rememberUploadedArtifact(key, existing.uploaded.getTime());
        rememberDecodedArtifactForHydration(bucket, metaRet, blobSha256, actualContentSha, gunzippedPayload, now);
        return Response.json({ ok: true, stored: false, deduplicated: true, key: checkKey }, { status: 200 });
      }
      if (checkKey !== key) {
        existing = null;
      }
    } else if (!metaRow) {
      // Brand-new content-addressed upload: skip `bucket.head(key)` so Cloudflare OTEL never
      // emits `r2_head ERROR: The specified key does not exist.` on every new page crawl.
      knownNewInMeta = true;
    } else {
      existing = await headR2ObjectWithoutMissingSpan(bucket, key);
      if (existing && !shouldRefreshDedupedObject(existing.uploaded.getTime(), rawRetention, now)) {
        rememberUploadedArtifact(key, existing.uploaded.getTime());
        rememberDecodedArtifactForHydration(bucket, rawRetention, blobSha256, actualContentSha, gunzippedPayload, now);
        return Response.json({ ok: true, stored: false, deduplicated: true, key }, { status: 200 });
      }
    }
  } else {
    existing = await headR2ObjectWithoutMissingSpan(bucket, key);
    if (existing && !shouldRefreshDedupedObject(existing.uploaded.getTime(), rawRetention, now)) {
      rememberUploadedArtifact(key, existing.uploaded.getTime());
      rememberDecodedArtifactForHydration(bucket, rawRetention, blobSha256, actualContentSha, gunzippedPayload, now);
      return Response.json({ ok: true, stored: false, deduplicated: true, key }, { status: 200 });
    }
  }

  try {
    const putOpts: R2PutOptions = {
      sha256: blobSha256,
      ...(existing || knownNewInMeta ? {} : { onlyIf: new Headers({ 'if-none-match': '*' }) }),
      httpMetadata: { contentType: 'application/gzip' },
      customMetadata: {
        contentSha256,
        contentBytes: String(contentBytes),
        retention: rawRetention,
      },
    };
    const stored = await bucket.put(key, fullPayload, putOpts);
    if (stored !== null) {
      rememberUploadedArtifact(key, now);
    }
    rememberDecodedArtifactForHydration(bucket, rawRetention, blobSha256, actualContentSha, gunzippedPayload, now);
    return Response.json({ ok: true, stored: stored !== null, deduplicated: stored === null, key }, { status: 200 });
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    const isBadDigest = /sha-?256|checksum|digest/i.test(msg);
    if (!isBadDigest) {
      // On a concurrent same-key write collision, check existence without `r2_head ERROR` span; otherwise let agent retry.
      const afterErr = await headR2ObjectWithoutMissingSpan(bucket, key);
      if (afterErr) {
        rememberUploadedArtifact(key, afterErr.uploaded.getTime());
        rememberDecodedArtifactForHydration(bucket, rawRetention, blobSha256, actualContentSha, gunzippedPayload, now);
        return Response.json({ ok: true, stored: false, deduplicated: true, key }, { status: 200 });
      }
    }
    return Response.json(
      { error: isBadDigest ? 'blob_sha256_mismatch' : 'r2_upload_failed', message: msg.slice(0, 180) },
      { status: isBadDigest ? 400 : 409 },
    );
  }
}

export type ReadArtifactResult =
  | {
      ok: true;
      bytes: Uint8Array;
      contentSha256: string;
      retention: ArtifactRetention;
    }
  | {
      ok: false;
      status: number;
      error: 'artifact_expired' | 'decompression_limit_exceeded' | 'content_hash_mismatch' | 'corrupt_gzip';
    };

/**
 * Streams and decompresses an R2 gzip artifact with a hard byte ceiling (`maxContentBytes`, defending against gzip
 * bombs) and verifies `SHA-256(uncompressed)` against `expectedContentSha256` / `customMetadata.contentSha256`.
 */
export async function readVerifiedArtifactFromR2(params: {
  bucket: R2Bucket;
  blobSha256: string;
  preferredRetention?: ArtifactRetention;
  expectedContentSha256?: string;
  maxContentBytes?: number;
  userId?: string;
  visibility?: ArtifactVisibility;
}): Promise<ReadArtifactResult> {
  const {
    bucket,
    blobSha256,
    preferredRetention,
    expectedContentSha256,
    maxContentBytes = MAX_ARTIFACT_CONTENT_BYTES,
    userId,
    visibility,
  } = params;
  if (!isValidSha256Hex(blobSha256)) {
    return { ok: false, status: 400, error: 'artifact_expired' };
  }

  const order: ArtifactRetention[] = preferredRetention
    ? preferredRetention === 'stored'
      ? ['stored', 'transient']
      : ['transient', 'stored']
    : ['transient', 'stored'];

  let obj: R2ObjectBody | null = null;
  let foundRetention: ArtifactRetention = order[0]!;
  if (userId) {
    for (const ret of order) {
      const privCandidate = await bucket.get(r2PrivateArtifactKey(userId, ret, blobSha256));
      if (privCandidate) {
        obj = privCandidate;
        foundRetention = ret;
        break;
      }
    }
  }
  if (!obj && visibility !== 'private') {
    for (const ret of order) {
      const candidate = await bucket.get(r2ArtifactKey(ret, blobSha256));
      if (candidate) {
        obj = candidate;
        foundRetention = ret;
        break;
      }
    }
  }
  if (!obj) {
    return { ok: false, status: 404, error: 'artifact_expired' };
  }

  const stream = obj.body.pipeThrough(new DecompressionStream('gzip') as unknown as TransformStream<Uint8Array, Uint8Array>);
  const reader = stream.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (value) {
        total += value.byteLength;
        if (total > maxContentBytes) {
          await reader.cancel('decompression bomb cap exceeded').catch(() => undefined);
          return { ok: false, status: 413, error: 'decompression_limit_exceeded' };
        }
        chunks.push(value);
      }
    }
  } catch {
    return { ok: false, status: 422, error: 'corrupt_gzip' };
  }

  const bytes = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) {
    bytes.set(c, off);
    off += c.byteLength;
  }

  const actualSha = bytesToHex(await crypto.subtle.digest('SHA-256', bytes));
  const metaSha = expectedContentSha256 ?? obj.customMetadata?.contentSha256;
  if (metaSha && isValidSha256Hex(metaSha) && actualSha !== metaSha) {
    return { ok: false, status: 422, error: 'content_hash_mismatch' };
  }

  return { ok: true, bytes, contentSha256: actualSha, retention: foundRetention };
}

/**
 * Whether a finished fetch goes to the ingest pipeline. `off` is the caller saying this response is throwaway, so it
 * writes no manifest and starts no Workflow.
 */
export function shouldIngestFetchReply(params: {
  status: number;
  retention: ArtifactRetention | 'off' | undefined;
  hasArtifacts: boolean;
  hasMeta: boolean;
}): boolean {
  return params.status === 200 && params.hasArtifacts && params.hasMeta && params.retention !== 'off';
}

/**
 * Hydrates inline `body` + `bodyEncoding` fields on a `FetchReply` JSON string from R2 up to `budgetBytes` (default
 * 18 MiB so total serialized JSON stays under the 20 MiB caller contract). Beyond the budget, sets `bodyOmitted: true`
 * while keeping `artifact` so callers can page remaining bodies via `GET /v1/artifacts/<blobSha256>`.
 */
export async function hydrateReplyBodiesFromR2(
  replyText: string,
  bucket: R2Bucket,
  budgetBytes = INLINE_HYDRATION_BUDGET_BYTES,
  maxPerItemBytes?: number,
  allowAbovePerItemCapIds?: ReadonlySet<string>,
): Promise<string> {
  let parsed: {
    results?: Array<{
      id?: string;
      kind?: string;
      body?: string;
      bodyBase64?: string;
      bodyEncoding?: 'utf-8' | 'base64';
      bodyOmitted?: boolean;
      extractedOnNode?: boolean;
      artifactError?: string;
      artifact?: {
        blobSha256?: string;
        contentSha256?: string;
        contentBytes?: number;
        retention?: string;
      };
      [k: string]: unknown;
    }>;
    [k: string]: unknown;
  };
  try {
    parsed = JSON.parse(replyText) as typeof parsed;
  } catch {
    return replyText;
  }
  if (
    !Array.isArray(parsed.results) ||
    !parsed.results.some(
      (r) => r?.artifact?.blobSha256 && r.body === undefined && !(typeof r.bodyBase64 === 'string' && r.bodyBase64.length > 0),
    )
  ) {
    return replyText;
  }

  let usedInlineBytes = 0;
  for (const r of parsed.results) {
    if (typeof r?.body === 'string') {
      usedInlineBytes += r.body.length;
    }
  }

  const hydNow = Date.now();
  for (const r of parsed.results) {
    const art = r?.artifact;
    if (!art?.blobSha256 || typeof r.body === 'string' || (typeof r.bodyBase64 === 'string' && r.bodyBase64.length > 0)) {
      continue;
    }
    const skipPerItemCap =
      r.kind === 'binary' || (typeof r.id === 'string' && Boolean(allowAbovePerItemCapIds?.has(r.id)));
    if (
      (!skipPerItemCap && r.extractedOnNode === true) ||
      (!skipPerItemCap &&
        maxPerItemBytes !== undefined &&
        maxPerItemBytes > 0 &&
        typeof art.contentBytes === 'number' &&
        art.contentBytes > maxPerItemBytes) ||
      (typeof art.contentBytes === 'number' && art.contentBytes > budgetBytes)
    ) {
      r.bodyOmitted = true;
      continue;
    }
    const prefRet: ArtifactRetention = art.retention === 'stored' ? 'stored' : 'transient';
    const fastBytes = isValidSha256Hex(art.blobSha256)
      ? lookupDecodedArtifactForHydration(bucket, prefRet, art.blobSha256, art.contentSha256, hydNow)
      : null;
    let rawBytes: Uint8Array;
    if (fastBytes) {
      rawBytes = fastBytes;
    } else {
      const loaded = await readVerifiedArtifactFromR2({
        bucket,
        blobSha256: art.blobSha256,
        preferredRetention: prefRet,
        expectedContentSha256: art.contentSha256,
      });
      if (!loaded.ok) {
        r.bodyOmitted = true;
        r.artifactError = loaded.error;
        continue;
      }
      rawBytes = loaded.bytes;
    }
    const encoded = encodeBodyForWire(rawBytes);
    if (usedInlineBytes + encoded.body.length > budgetBytes) {
      r.bodyOmitted = true;
      continue;
    }
    r.body = encoded.body;
    r.bodyEncoding = encoded.bodyEncoding;
    delete r.bodyOmitted;
    usedInlineBytes += encoded.body.length;
  }

  return JSON.stringify(parsed);
}

export interface ArtifactPageSlice {
  blobSha256: string;
  contentSha256: string;
  retention: ArtifactRetention;
  format?: 'raw' | 'markdown';
  totalChars: number;
  totalBytes: number;
  offset: number;
  limit: number;
  nextOffset: number | null;
  hasMore: boolean;
  bodyEncoding: 'utf-8' | 'base64';
  content: string;
}

const SHARED_UTF8_ENCODER = new TextEncoder();
const SHARED_UTF8_DECODER = new TextDecoder();

interface CachedSanitizedMarkdownEntry {
  rawSha256: string;
  cleanMd: string;
  byteLen: number;
  checkpoints: MarkdownSliceCheckpoint[];
}

interface SanitizedMarkdownLruPool {
  entries: Map<string, CachedSanitizedMarkdownEntry>;
  totalChars: number;
  readonly maxEntries: number;
  readonly maxChars: number;
}

type SanitizedMdCacheScope = { isPrivate: false } | { isPrivate: true; userKey: string };

const PUBLIC_SANITIZED_MD_MAX_ENTRIES = 32;
const PUBLIC_SANITIZED_MD_MAX_CHARS = 16 * 1024 * 1024;
const PRIVATE_USER_SANITIZED_MD_MAX_ENTRIES = 4;
const PRIVATE_USER_SANITIZED_MD_MAX_CHARS = 4 * 1024 * 1024;
const MAX_PRIVATE_SANITIZED_MD_USER_POOLS = 64;

const publicSanitizedMarkdownPool: SanitizedMarkdownLruPool = {
  entries: new Map<string, CachedSanitizedMarkdownEntry>(),
  totalChars: 0,
  maxEntries: PUBLIC_SANITIZED_MD_MAX_ENTRIES,
  maxChars: PUBLIC_SANITIZED_MD_MAX_CHARS,
};

const privateSanitizedMarkdownPoolsByUser = new Map<string, SanitizedMarkdownLruPool>();

/**
 * Resolves the isolated cache scope for a Markdown artifact:
 *  - Public (`privateOnly === false`) -> dedicated `'pub'` LRU pool (`publicSanitizedMarkdownPool`) that member traffic can NEVER evict.
 *  - Authenticated private (`privateOnly === true` with non-empty `scopeUserId`) -> isolated per-user LRU pool (`priv:<userKey>`).
 *  - Private WITHOUT a `userId` (`privateOnly === true` and missing/empty `scopeUserId`) -> `null` (NEVER cached or looked up under `'pub'`!).
 */
function resolveSanitizedMdCacheScope(scopeUserId: string | undefined, privateOnly: boolean): SanitizedMdCacheScope | null {
  if (!privateOnly) {
    return { isPrivate: false };
  }
  if (typeof scopeUserId !== 'string') return null;
  const cleaned = scopeUserId.trim().replace(/[^a-zA-Z0-9_-]/g, '').slice(0, 64);
  if (!cleaned) return null;
  return { isPrivate: true, userKey: cleaned };
}

function getSanitizedMdPoolForScope(scope: SanitizedMdCacheScope, createIfMissing: boolean): SanitizedMarkdownLruPool | null {
  if (!scope.isPrivate) {
    return publicSanitizedMarkdownPool;
  }
  const existing = privateSanitizedMarkdownPoolsByUser.get(scope.userKey);
  if (existing) {
    // Promote active user bucket in outer per-user LRU without touching `publicSanitizedMarkdownPool`
    privateSanitizedMarkdownPoolsByUser.delete(scope.userKey);
    privateSanitizedMarkdownPoolsByUser.set(scope.userKey, existing);
    return existing;
  }
  if (!createIfMissing) return null;
  while (privateSanitizedMarkdownPoolsByUser.size >= MAX_PRIVATE_SANITIZED_MD_USER_POOLS) {
    const oldestUser = privateSanitizedMarkdownPoolsByUser.keys().next().value;
    if (oldestUser === undefined) break;
    privateSanitizedMarkdownPoolsByUser.delete(oldestUser);
  }
  const created: SanitizedMarkdownLruPool = {
    entries: new Map<string, CachedSanitizedMarkdownEntry>(),
    totalChars: 0,
    maxEntries: PRIVATE_USER_SANITIZED_MD_MAX_ENTRIES,
    maxChars: PRIVATE_USER_SANITIZED_MD_MAX_CHARS,
  };
  privateSanitizedMarkdownPoolsByUser.set(scope.userKey, created);
  return created;
}

function upsertSanitizedMarkdownCache(
  scope: SanitizedMdCacheScope | null,
  docKey: string,
  rawSha256: string,
  cleanMd: string,
  byteLen?: number,
): CachedSanitizedMarkdownEntry {
  const entry: CachedSanitizedMarkdownEntry = {
    rawSha256,
    cleanMd,
    byteLen: byteLen ?? SHARED_UTF8_ENCODER.encode(cleanMd).byteLength,
    checkpoints: computeMarkdownSliceCheckpoints(cleanMd, 16_384),
  };
  if (!scope) {
    return entry;
  }
  const pool = getSanitizedMdPoolForScope(scope, true);
  if (!pool) return entry;

  const prev = pool.entries.get(docKey);
  if (prev) {
    pool.totalChars -= prev.cleanMd.length;
    pool.entries.delete(docKey);
  }
  if (cleanMd.length <= pool.maxChars) {
    while (pool.entries.size >= pool.maxEntries || pool.totalChars + cleanMd.length > pool.maxChars) {
      const oldestKey = pool.entries.keys().next().value;
      if (oldestKey === undefined) break;
      const oldest = pool.entries.get(oldestKey);
      if (oldest) pool.totalChars -= oldest.cleanMd.length;
      pool.entries.delete(oldestKey);
    }
    pool.entries.set(docKey, entry);
    pool.totalChars += cleanMd.length;
  }
  return entry;
}

type NodeCryptoModule = {
  createHash: (alg: string) => { update: (data: Uint8Array) => { digest: (enc: 'hex') => string } };
};

const NODE_CRYPTO_MOD: NodeCryptoModule | null = (() => {
  const g = globalThis as { process?: { getBuiltinModule?: (id: string) => unknown } };
  const mod = typeof g.process?.getBuiltinModule === 'function' ? g.process.getBuiltinModule('node:crypto') : null;
  return mod && typeof (mod as NodeCryptoModule).createHash === 'function' ? (mod as NodeCryptoModule) : null;
})();

async function sha256BytesHexNative(rawBytes: Uint8Array): Promise<string> {
  if (NODE_CRYPTO_MOD) {
    return NODE_CRYPTO_MOD.createHash('sha256').update(rawBytes).digest('hex');
  }
  return bytesToHex(await crypto.subtle.digest('SHA-256', rawBytes as unknown as BufferSource));
}

async function getOrSanitizeCachedMarkdownForBytes(
  scope: SanitizedMdCacheScope | null,
  docKey: string,
  rawBytes: Uint8Array,
  alreadySanitized = false,
): Promise<CachedSanitizedMarkdownEntry> {
  const rawSha256 = await sha256BytesHexNative(rawBytes);
  if (scope) {
    const pool = getSanitizedMdPoolForScope(scope, false);
    const hit = pool?.entries.get(docKey);
    if (pool && hit && hit.rawSha256 === rawSha256) {
      pool.entries.delete(docKey);
      pool.entries.set(docKey, hit);
      return hit;
    }
  }
  const rawMd = SHARED_UTF8_DECODER.decode(rawBytes);
  const preClean = alreadySanitized
    ? stripInvisibleSmugglingChars(rawMd.replace(/\0/g, '')).replace(/\r\n?/g, '\n')
    : rawMd;
  const cleanMd =
    alreadySanitized && !preClean.includes('```') && !preClean.includes('~~~')
      ? preClean
      : sanitizeFullMarkdownDocumentForArtifact(preClean);
  const cleanByteLen =
    alreadySanitized && cleanMd === rawMd ? rawBytes.byteLength : SHARED_UTF8_ENCODER.encode(cleanMd).byteLength;
  return upsertSanitizedMarkdownCache(scope, docKey, rawSha256, cleanMd, cleanByteLen);
}

/**
 * Primes the per-`sha` sanitized Markdown cache when `scrape.ts` / `deriveMarkdownDocument` writes an already-sanitized
 * `SCRAPE_PIPELINE_VERSION` (`33`) Markdown artifact to `derived/${SCRAPE_PIPELINE_VERSION}/markdown/${sha}` so subsequent
 * `read_artifact` page calls slice directly in `O(window)` (`< 2 ms` per page on `1 MiB` docs) with zero full-doc re-sanitization.
 */
export async function primeSanitizedMarkdownCache(
  sha: string,
  cleanMd: string,
  opts?: { userId?: string; privateOnly?: boolean; pipelineVersion?: number; rawSha256?: string },
): Promise<void> {
  if (!isValidSha256Hex(sha) || !cleanMd) return;
  const scope = resolveSanitizedMdCacheScope(opts?.userId, Boolean(opts?.privateOnly));
  if (!scope) return;
  const ver = Math.max(SCRAPE_PIPELINE_VERSION, opts?.pipelineVersion ?? SCRAPE_PIPELINE_VERSION);
  const docKey = `${sha}:${ver}`;
  const rawBytes = SHARED_UTF8_ENCODER.encode(cleanMd);
  const rawSha256 =
    opts?.rawSha256 && isValidSha256Hex(opts.rawSha256)
      ? opts.rawSha256
      : await sha256BytesHexNative(rawBytes);
  upsertSanitizedMarkdownCache(scope, docKey, rawSha256, cleanMd, rawBytes.byteLength);
}

export async function readArtifactPage(params: {
  bucket: R2Bucket;
  metaDb?: D1Database;
  blobSha256: string;
  retention?: ArtifactRetention;
  format?: 'raw' | 'markdown';
  pipelineVersion?: number;
  offset?: number;
  limit?: number;
  userId?: string;
  visibility?: ArtifactVisibility;
  deriveMarkdownFromRaw?: (bytes: Uint8Array) => string | null;
}): Promise<{ ok: true; page: ArtifactPageSlice } | { ok: false; status: number; via?: 'hub'; error: string; message?: string }> {
  const rawId = params.blobSha256.trim().toLowerCase();
  const isMdPrefixed = rawId.startsWith('md:');
  const cleanHex = isMdPrefixed ? rawId.slice(3) : rawId;
  const activeAuth = getActiveCallerAuthContext();
  const effectiveUserId = params.userId ?? activeAuth?.userId;
  const isNonOwnerMember =
    (effectiveUserId && sanitizeStorageUserId(effectiveUserId) !== 'owner' && activeAuth?.role !== 'owner') || false;
  const privateOnly = params.visibility === 'private' || isNonOwnerMember;
  const effectiveVisibility: ArtifactVisibility | undefined = privateOnly ? 'private' : params.visibility;
  if (!isValidSha256Hex(cleanHex)) {
    return {
      ok: false,
      status: 400,
      error: 'invalid_artifact_id',
      message: 'artifactId must be a 64-character lowercase hex SHA-256 (or md:<sha256> for derived Markdown).',
    };
  }

  const sliceMarkdownPageFromEntry = (
    entry: CachedSanitizedMarkdownEntry,
    contentSha: string,
    retention: ArtifactRetention = 'stored',
  ): { ok: true; page: ArtifactPageSlice } => {
    const mdText = entry.cleanMd;
    const totalChars = mdText.length;
    const safeOffset = Math.min(totalChars, Math.max(0, Math.floor(params.offset ?? 0)));
    const safeLimit = Math.min(
      MAX_ARTIFACT_PAGE_LIMIT,
      Math.max(1, Math.floor(params.limit ?? DEFAULT_ARTIFACT_PAGE_LIMIT)),
    );
    const end = Math.min(totalChars, safeOffset + safeLimit);
    const rawSlice = mdText.slice(safeOffset, end);
    const slice = sanitizeMarkdownPageSlice(mdText, safeOffset, rawSlice, false, entry.checkpoints);
    const hasMore = end < totalChars;
    return {
      ok: true,
      page: {
        blobSha256: rawId,
        contentSha256: contentSha,
        retention,
        format: 'markdown',
        totalChars,
        totalBytes: entry.byteLen,
        offset: safeOffset,
        limit: safeLimit,
        nextOffset: hasMore ? end : null,
        hasMore,
        bodyEncoding: 'utf-8',
        content: slice,
      },
    };
  };

  const wantsMarkdown = isMdPrefixed || params.format === 'markdown';
  if (wantsMarkdown) {
    // Clamp any caller-supplied `pipelineVersion < SCRAPE_PIPELINE_VERSION` (`33`) so callers can NEVER read stale derived objects!
    const callerVer =
      typeof params.pipelineVersion === 'number' && Number.isInteger(params.pipelineVersion)
        ? params.pipelineVersion
        : SCRAPE_PIPELINE_VERSION;
    const requiredVer = Math.max(SCRAPE_PIPELINE_VERSION, callerVer);
    const candidateShas: string[] = [];
    if (isMdPrefixed) candidateShas.push(cleanHex);
    if (params.metaDb && !privateOnly) {
      const row = await params.metaDb
        .prepare('SELECT content_sha256 FROM artifacts WHERE blob_sha256 = ? LIMIT 1')
        .bind(cleanHex)
        .first<{ content_sha256: string }>()
        .catch(() => null);
      if (row?.content_sha256 && isValidSha256Hex(row.content_sha256) && !candidateShas.includes(row.content_sha256)) {
        candidateShas.push(row.content_sha256);
      }
    }

    let rawLoadedCache: ReadArtifactResult | undefined;
    const loadRawOnce = async (): Promise<ReadArtifactResult> => {
      if (rawLoadedCache) return rawLoadedCache;
      rawLoadedCache = await readVerifiedArtifactFromR2({
        bucket: params.bucket,
        blobSha256: cleanHex,
        preferredRetention: params.retention,
        ...(effectiveUserId ? { userId: effectiveUserId } : {}),
        ...(effectiveVisibility ? { visibility: effectiveVisibility } : {}),
      });
      return rawLoadedCache;
    };

    if (candidateShas.length === 0) {
      const rawLoaded = await loadRawOnce();
      if (rawLoaded.ok) {
        candidateShas.push(rawLoaded.contentSha256);
      }
    }

    const readDerivedObjBytes = async (
      obj: { arrayBuffer?: () => Promise<ArrayBuffer>; text: () => Promise<string>; customMetadata?: Record<string, string> },
    ): Promise<{ rawBytes: Uint8Array; trustedPipelineVer: boolean }> => {
      const customVer = Number(obj.customMetadata?.pipelineVersion ?? 0);
      const rawBytes =
        typeof obj.arrayBuffer === 'function'
          ? new Uint8Array(await obj.arrayBuffer())
          : SHARED_UTF8_ENCODER.encode(await obj.text());
      return { rawBytes, trustedPipelineVer: customVer >= requiredVer };
    };

    const checkCachedMarkdownForSha = async (
      sha: string,
    ): Promise<{ rawBytes: Uint8Array; trustedPipelineVer: boolean } | null> => {
      if (effectiveUserId) {
        const privMdObj = await params.bucket.get(r2PrivateDerivedKey(effectiveUserId, requiredVer, 'markdown', sha));
        if (privMdObj) {
          return readDerivedObjBytes(privMdObj);
        }
      }
      if (privateOnly) return null;
      if (params.metaDb) {
        const docRow = await params.metaDb
          .prepare(
            `SELECT r2_key, pipeline_version FROM documents WHERE content_sha256 = ? AND format = 'markdown' AND pipeline_version >= ? ORDER BY pipeline_version DESC LIMIT 1`,
          )
          .bind(sha, requiredVer)
          .first<{ r2_key: string; pipeline_version?: number }>()
          .catch(() => null);
        if (docRow?.r2_key) {
          const obj = await params.bucket.get(docRow.r2_key);
          if (obj) {
            return readDerivedObjBytes(obj);
          }
        }
      }
      const mdObj = await params.bucket.get(r2DerivedKey(requiredVer, 'markdown', sha));
      if (mdObj) {
        return readDerivedObjBytes(mdObj);
      }
      return null;
    };

    const cacheScope = resolveSanitizedMdCacheScope(effectiveUserId, privateOnly);

    for (const sha of candidateShas) {
      const found = await checkCachedMarkdownForSha(sha);
      if (found !== null) {
        const entry = await getOrSanitizeCachedMarkdownForBytes(
          cacheScope,
          `${sha}:${requiredVer}`,
          found.rawBytes,
          found.trustedPipelineVer,
        );
        return sliceMarkdownPageFromEntry(entry, sha, 'stored');
      }
    }

    // If caller passed `md:<blobSha256>` (the scrape `artifactId`) or `format="markdown"` on a non-truncated scrape
    // whose derived Markdown wasn't materialized at `>= requiredVer`, load the raw R2 artifact and derive clean Markdown at `requiredVer`.
    const rawFallback = await loadRawOnce();
    if (rawFallback.ok) {
      if (!candidateShas.includes(rawFallback.contentSha256)) {
        const foundByRawContentSha = await checkCachedMarkdownForSha(rawFallback.contentSha256);
        if (foundByRawContentSha !== null) {
          const entry = await getOrSanitizeCachedMarkdownForBytes(
            cacheScope,
            `${rawFallback.contentSha256}:${requiredVer}`,
            foundByRawContentSha.rawBytes,
            foundByRawContentSha.trustedPipelineVer,
          );
          return sliceMarkdownPageFromEntry(entry, rawFallback.contentSha256, rawFallback.retention);
        }
      }
      if (params.deriveMarkdownFromRaw) {
        const derivedMd = params.deriveMarkdownFromRaw(rawFallback.bytes);
        if (derivedMd !== null) {
          const entry = await getOrSanitizeCachedMarkdownForBytes(
            cacheScope,
            `${rawFallback.contentSha256}:${requiredVer}`,
            SHARED_UTF8_ENCODER.encode(derivedMd),
            false,
          );
          if (!privateOnly || effectiveUserId) {
            const targetDerivedKey =
              privateOnly && effectiveUserId
                ? r2PrivateDerivedKey(effectiveUserId, requiredVer, 'markdown', rawFallback.contentSha256)
                : r2DerivedKey(requiredVer, 'markdown', rawFallback.contentSha256);
            await params.bucket
              .put(targetDerivedKey, entry.cleanMd, {
                httpMetadata: { contentType: 'text/markdown; charset=utf-8' },
                customMetadata: {
                  pipelineVersion: String(requiredVer),
                  ...(privateOnly && effectiveUserId
                    ? { userId: sanitizeStorageUserId(effectiveUserId), visibility: 'private' }
                    : {}),
                },
              })
              .catch(() => undefined);
          }
          return sliceMarkdownPageFromEntry(entry, rawFallback.contentSha256, rawFallback.retention);
        }
      }
    }

    if (isMdPrefixed) {
      return {
        ok: false,
        status: 404,
        via: 'hub',
        error: 'artifact_not_found',
        message: 'Artifact was not found or has expired.',
      };
    }
  }

  let expectedContentSha256: string | undefined;
  let dbRetention: ArtifactRetention | undefined;
  if (params.metaDb && !privateOnly) {
    const row = await params.metaDb
      .prepare('SELECT content_sha256, retention FROM artifacts WHERE blob_sha256 = ? LIMIT 1')
      .bind(cleanHex)
      .first<{ content_sha256: string; retention?: string }>()
      .catch(() => null);
    if (row?.content_sha256 && isValidSha256Hex(row.content_sha256)) {
      expectedContentSha256 = row.content_sha256;
    }
    if (isValidRetention(row?.retention)) {
      dbRetention = row.retention;
    }
  }

  const loaded = await readVerifiedArtifactFromR2({
    bucket: params.bucket,
    blobSha256: cleanHex,
    preferredRetention: params.retention ?? dbRetention,
    ...(expectedContentSha256 ? { expectedContentSha256 } : {}),
    ...(effectiveUserId ? { userId: effectiveUserId } : {}),
    ...(effectiveVisibility ? { visibility: effectiveVisibility } : {}),
  });
  if (!loaded.ok) {
    if (loaded.error === 'artifact_expired') {
      return {
        ok: false,
        status: 404,
        via: 'hub',
        error: 'artifact_not_found',
        message: 'Artifact was not found or has expired.',
      };
    }
    return {
      ok: false,
      status: loaded.status,
      via: 'hub',
      error: loaded.error,
    };
  }

  const encoded = encodeBodyForWire(loaded.bytes);
  const totalChars = encoded.body.length;
  const safeOffset = Math.min(totalChars, Math.max(0, Math.floor(params.offset ?? 0)));
  const safeLimit = Math.min(MAX_ARTIFACT_PAGE_LIMIT, Math.max(1, Math.floor(params.limit ?? DEFAULT_ARTIFACT_PAGE_LIMIT)));
  const end = Math.min(totalChars, safeOffset + safeLimit);
  const slice = encoded.body.slice(safeOffset, end);
  const hasMore = end < totalChars;

  return {
    ok: true,
    page: {
      blobSha256: cleanHex,
      contentSha256: loaded.contentSha256,
      retention: loaded.retention,
      format: 'raw',
      totalChars,
      totalBytes: loaded.bytes.byteLength,
      offset: safeOffset,
      limit: safeLimit,
      nextOffset: hasMore ? end : null,
      hasMore,
      bodyEncoding: encoded.bodyEncoding,
      content: slice,
    },
  };
}

/**
 * Authenticated `GET /v1/artifacts/<blobSha256>?offset=&limit=&format=text|json` handler.
 * Serves raw crawled content strictly as `text/plain; charset=utf-8` with `nosniff`, `CSP: sandbox`, and
 * `Content-Disposition: attachment` (never active HTML) unless JSON envelope format is requested.
 */
export async function handleArtifactGetRequest(params: {
  request: Request;
  url: URL;
  blobSha256: string;
  bucket?: R2Bucket;
  metaDb?: D1Database;
  userId?: string;
  pipelineVersion?: number;
  deriveMarkdownFromRaw?: (bytes: Uint8Array) => string | null;
}): Promise<Response> {
  const { request, url, blobSha256, bucket, metaDb, userId, pipelineVersion, deriveMarkdownFromRaw } = params;
  const rawVis = url.searchParams.get('visibility');
  const visibility: ArtifactVisibility | undefined = rawVis === 'private' ? 'private' : rawVis === 'public' ? 'public' : undefined;
  const isPrivateCaller = Boolean((userId && sanitizeStorageUserId(userId) !== 'owner') || visibility === 'private');
  const cacheControl = isPrivateCaller ? 'private, no-store' : 'no-store';
  if (!bucket) {
    return Response.json(
      { error: 'artifacts_not_configured', ...(isPrivateCaller ? { visibility: 'private' as const } : {}) },
      { status: 503, headers: { 'cache-control': cacheControl } },
    );
  }
  const cleanParamId = blobSha256.startsWith('md:') ? blobSha256.slice(3) : blobSha256;
  if (!isValidSha256Hex(cleanParamId)) {
    return Response.json(
      { error: 'invalid_blob_sha256', ...(isPrivateCaller ? { visibility: 'private' as const } : {}) },
      { status: 400, headers: { 'cache-control': cacheControl } },
    );
  }

  const rawRet = url.searchParams.get('retention');
  const retention: ArtifactRetention | undefined = rawRet === 'stored' ? 'stored' : rawRet === 'transient' ? 'transient' : undefined;
  const contentFormat: 'raw' | 'markdown' | undefined =
    url.searchParams.get('content') === 'markdown' || url.searchParams.get('format') === 'markdown' ? 'markdown' : undefined;
  const offset = url.searchParams.has('offset') ? Number(url.searchParams.get('offset')) : 0;
  const limit = url.searchParams.has('limit') ? Number(url.searchParams.get('limit')) : DEFAULT_ARTIFACT_PAGE_LIMIT;

  const out = await readArtifactPage({
    bucket,
    ...(metaDb ? { metaDb } : {}),
    blobSha256,
    ...(retention ? { retention } : {}),
    ...(contentFormat ? { format: contentFormat } : {}),
    ...(userId ? { userId } : {}),
    ...(visibility ? { visibility } : {}),
    ...(pipelineVersion !== undefined ? { pipelineVersion } : {}),
    ...(deriveMarkdownFromRaw ? { deriveMarkdownFromRaw } : {}),
    offset: Number.isFinite(offset) ? offset : 0,
    limit: Number.isFinite(limit) ? limit : DEFAULT_ARTIFACT_PAGE_LIMIT,
  });
  if (!out.ok) {
    return Response.json(
      {
        ok: false,
        ...(isPrivateCaller ? { visibility: 'private' as const } : {}),
        status: out.status,
        via: 'hub',
        error: out.error,
        ...(out.message ? { message: out.message } : {}),
      },
      { status: out.status, headers: { 'cache-control': cacheControl } },
    );
  }

  const wantsJson =
    url.searchParams.get('format') === 'json' || (request.headers.get('accept') ?? '').toLowerCase().includes('application/json');
  if (wantsJson) {
    return Response.json(
      { ...out.page, ...(isPrivateCaller ? { visibility: 'private' as const } : {}) },
      { status: 200, headers: { 'cache-control': cacheControl } },
    );
  }

  return new Response(out.page.content, {
    status: 200,
    headers: {
      'content-type': 'text/plain; charset=utf-8',
      'cache-control': cacheControl,
      'x-content-type-options': 'nosniff',
      'content-security-policy': 'sandbox',
      'content-disposition': `attachment; filename="${blobSha256.slice(0, 16)}.txt"`,
      'x-artifact-total-bytes': String(out.page.totalBytes),
      'x-artifact-total-chars': String(out.page.totalChars),
      'x-artifact-has-more': String(out.page.hasMore),
      ...(out.page.nextOffset !== null ? { 'x-artifact-next-offset': String(out.page.nextOffset) } : {}),
    },
  });
}
