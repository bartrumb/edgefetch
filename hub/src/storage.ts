/**
 * Storage primitives, R2 object layout helpers, retention freshness checks, and `/v1/capabilities` metadata for
 * EdgeFetch's optional three-layer storage architecture (`ARTIFACTS` R2 + `META` D1 + `SEARCH` D1 FTS5).
 *
 * All storage bindings remain strictly optional so an existing single-binding `AgentHubDO` deployment continues
 * operating unchanged when `ARTIFACTS` / `META` / `SEARCH` / `INGEST` are unconfigured.
 */

import { encodeBodyForWire } from './overflow';

export type ArtifactRetention = 'transient' | 'stored';

export interface IngestWorkflowParams {
  manifestKey: string;
  jobId: string;
  siteId?: string;
  via: string;
}

export interface OptionalStorageBindings {
  ARTIFACTS?: R2Bucket;
  META?: D1Database;
  SEARCH?: D1Database;
  INGEST?: {
    create(options?: { id?: string; params?: IngestWorkflowParams }): Promise<{ id: string }>;
  };
}

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
    mcp: boolean;
    oauth: boolean;
    artifacts: boolean;
    tracking: boolean;
    ingestWorkflow: boolean;
    search: boolean;
  };
}

export function buildCapabilities(env: OptionalStorageBindings, version = '1.2.0'): HubCapabilities {
  return {
    version,
    capabilities: {
      fetch: true,
      mcp: true,
      oauth: true,
      artifacts: Boolean(env.ARTIFACTS),
      tracking: Boolean(env.META),
      ingestWorkflow: Boolean(env.INGEST),
      search: Boolean(env.SEARCH),
    },
  };
}

export interface AuthorizeArtifactUploadCallback {
  (params: {
    jobId: string;
    jobNonce: string;
    siteId: string;
    requestId: string;
    retention: ArtifactRetention;
    storedBytes: number;
    contentBytes: number;
  }): Promise<{ ok: true } | { ok: false; status: number; error: string }>;
}

/**
 * Handles `PUT /agent/artifacts/<blobSha256>` streaming agent-compressed gzip artifacts directly into R2 with
 * atomic `sha256` + `If-None-Match: *` create-once verification and half-retention deduplication refresh.
 */
export async function handleAgentArtifactUpload(params: {
  request: Request;
  blobSha256: string;
  siteId: string;
  bucket?: R2Bucket;
  authorizeJobUpload: AuthorizeArtifactUploadCallback;
  now?: number;
}): Promise<Response> {
  const { request, blobSha256, siteId, bucket, authorizeJobUpload, now = Date.now() } = params;
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

  const authz = await authorizeJobUpload({
    jobId,
    jobNonce,
    siteId,
    requestId,
    retention: rawRetention,
    storedBytes,
    contentBytes,
  });
  if (!authz.ok) {
    await request.body.cancel().catch(() => undefined);
    return Response.json({ error: authz.error }, { status: authz.status });
  }

  const key = r2ArtifactKey(rawRetention, blobSha256);
  const existing = await bucket.head(key);
  if (existing && !shouldRefreshDedupedObject(existing.uploaded.getTime(), rawRetention, now)) {
    await request.body.cancel().catch(() => undefined);
    return Response.json({ ok: true, stored: false, deduplicated: true, key }, { status: 200 });
  }

  try {
    const putOpts: R2PutOptions = {
      sha256: blobSha256,
      ...(existing ? {} : { onlyIf: new Headers({ 'if-none-match': '*' }) }),
      httpMetadata: { contentType: 'application/gzip' },
      customMetadata: {
        contentSha256,
        contentBytes: String(contentBytes),
        retention: rawRetention,
      },
    };
    const stored = await bucket.put(key, request.body, putOpts);
    return Response.json({ ok: true, stored: stored !== null, deduplicated: stored === null, key }, { status: 200 });
  } catch (e) {
    // On a concurrent same-key write collision, check head() to see if another writer succeeded; otherwise let agent retry.
    const afterErr = await bucket.head(key).catch(() => null);
    if (afterErr) {
      return Response.json({ ok: true, stored: false, deduplicated: true, key }, { status: 200 });
    }
    const msg = e instanceof Error ? e.message : String(e);
    const isBadDigest = /sha-?256|checksum|digest/i.test(msg);
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
}): Promise<ReadArtifactResult> {
  const { bucket, blobSha256, preferredRetention, expectedContentSha256, maxContentBytes = MAX_ARTIFACT_CONTENT_BYTES } = params;
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
  for (const ret of order) {
    const candidate = await bucket.get(r2ArtifactKey(ret, blobSha256));
    if (candidate) {
      obj = candidate;
      foundRetention = ret;
      break;
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
 * Hydrates inline `body` + `bodyEncoding` fields on a `FetchReply` JSON string from R2 up to `budgetBytes` (default
 * 18 MiB so total serialized JSON stays under the 20 MiB caller contract). Beyond the budget, sets `bodyOmitted: true`
 * while keeping `artifact` so callers can page remaining bodies via `GET /v1/artifacts/<blobSha256>`.
 */
export async function hydrateReplyBodiesFromR2(
  replyText: string,
  bucket: R2Bucket,
  budgetBytes = INLINE_HYDRATION_BUDGET_BYTES,
): Promise<string> {
  let parsed: {
    results?: Array<{
      body?: string;
      bodyEncoding?: 'utf-8' | 'base64';
      bodyOmitted?: boolean;
      artifactError?: string;
      artifact?: {
        blobSha256?: string;
        contentSha256?: string;
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
  if (!Array.isArray(parsed.results) || !parsed.results.some((r) => r?.artifact?.blobSha256 && r.body === undefined)) {
    return replyText;
  }

  let usedInlineBytes = 0;
  for (const r of parsed.results) {
    if (typeof r?.body === 'string') {
      usedInlineBytes += r.body.length;
    }
  }

  for (const r of parsed.results) {
    const art = r?.artifact;
    if (!art?.blobSha256 || typeof r.body === 'string') continue;
    const prefRet: ArtifactRetention = art.retention === 'stored' ? 'stored' : 'transient';
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
    const encoded = encodeBodyForWire(loaded.bytes);
    if (usedInlineBytes + encoded.body.length > budgetBytes) {
      r.bodyOmitted = true;
      continue;
    }
    r.body = encoded.body;
    r.bodyEncoding = encoded.bodyEncoding;
    usedInlineBytes += encoded.body.length;
  }

  return JSON.stringify(parsed);
}

export interface ArtifactPageSlice {
  blobSha256: string;
  contentSha256: string;
  retention: ArtifactRetention;
  totalChars: number;
  totalBytes: number;
  offset: number;
  limit: number;
  nextOffset: number | null;
  hasMore: boolean;
  bodyEncoding: 'utf-8' | 'base64';
  content: string;
}

export async function readArtifactPage(params: {
  bucket: R2Bucket;
  metaDb?: D1Database;
  blobSha256: string;
  retention?: ArtifactRetention;
  offset?: number;
  limit?: number;
}): Promise<{ ok: true; page: ArtifactPageSlice } | { ok: false; status: number; error: string; message?: string }> {
  let expectedContentSha256: string | undefined;
  if (params.metaDb && isValidSha256Hex(params.blobSha256)) {
    const row = await params.metaDb
      .prepare('SELECT content_sha256 FROM artifacts WHERE blob_sha256 = ? LIMIT 1')
      .bind(params.blobSha256)
      .first<{ content_sha256: string }>()
      .catch(() => null);
    if (row?.content_sha256 && isValidSha256Hex(row.content_sha256)) {
      expectedContentSha256 = row.content_sha256;
    }
  }

  const loaded = await readVerifiedArtifactFromR2({
    bucket: params.bucket,
    blobSha256: params.blobSha256,
    preferredRetention: params.retention,
    ...(expectedContentSha256 ? { expectedContentSha256 } : {}),
  });
  if (!loaded.ok) {
    if (loaded.error === 'artifact_expired' && expectedContentSha256) {
      return {
        ok: false,
        status: 410,
        error: 'artifact_expired',
        message: 'Artifact retention window has expired in R2; re-fetch the target URL to regenerate it.',
      };
    }
    return {
      ok: false,
      status: loaded.status,
      error: loaded.error,
      ...(loaded.error === 'artifact_expired'
        ? { message: 'Artifact not found or expired in R2.' }
        : {}),
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
      blobSha256: params.blobSha256,
      contentSha256: loaded.contentSha256,
      retention: loaded.retention,
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
}): Promise<Response> {
  const { request, url, blobSha256, bucket, metaDb } = params;
  if (!bucket) {
    return Response.json({ error: 'artifacts_not_configured' }, { status: 503, headers: { 'cache-control': 'no-store' } });
  }
  if (!isValidSha256Hex(blobSha256)) {
    return Response.json({ error: 'invalid_blob_sha256' }, { status: 400, headers: { 'cache-control': 'no-store' } });
  }

  const rawRet = url.searchParams.get('retention');
  const retention: ArtifactRetention | undefined = rawRet === 'stored' ? 'stored' : rawRet === 'transient' ? 'transient' : undefined;
  const offset = url.searchParams.has('offset') ? Number(url.searchParams.get('offset')) : 0;
  const limit = url.searchParams.has('limit') ? Number(url.searchParams.get('limit')) : DEFAULT_ARTIFACT_PAGE_LIMIT;

  const out = await readArtifactPage({
    bucket,
    ...(metaDb ? { metaDb } : {}),
    blobSha256,
    ...(retention ? { retention } : {}),
    offset: Number.isFinite(offset) ? offset : 0,
    limit: Number.isFinite(limit) ? limit : DEFAULT_ARTIFACT_PAGE_LIMIT,
  });
  if (!out.ok) {
    return Response.json(
      { error: out.error, ...(out.message ? { message: out.message } : {}) },
      { status: out.status, headers: { 'cache-control': 'no-store' } },
    );
  }

  const wantsJson =
    url.searchParams.get('format') === 'json' || (request.headers.get('accept') ?? '').toLowerCase().includes('application/json');
  if (wantsJson) {
    return Response.json(out.page, { status: 200, headers: { 'cache-control': 'no-store' } });
  }

  return new Response(out.page.content, {
    status: 200,
    headers: {
      'content-type': 'text/plain; charset=utf-8',
      'cache-control': 'no-store',
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
