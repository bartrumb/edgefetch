/**
 * Storage primitives, R2 object layout helpers, retention freshness checks, and `/v1/capabilities` metadata for
 * EdgeFetch's optional three-layer storage architecture (`ARTIFACTS` R2 + `META` D1 + `SEARCH` D1 FTS5).
 *
 * All storage bindings remain strictly optional so an existing single-binding `AgentHubDO` deployment continues
 * operating unchanged when `ARTIFACTS` / `META` / `SEARCH` / `INGEST` are unconfigured.
 */

import { encodeBodyForWire } from './overflow';
import { listConfiguredSpaFallbacks, type SpaFallbackEnv, type SpaFallbackProvider } from './spa-fallback';

export type ArtifactRetention = 'transient' | 'stored';

export interface IngestWorkflowParams {
  manifestKey: string;
  jobId: string;
  siteId?: string;
  collectionId?: string;
  via: string;
}

export interface OptionalStorageBindings extends SpaFallbackEnv {
  ARTIFACTS?: R2Bucket;
  META?: D1Database;
  SEARCH?: D1Database;
  INGEST?: {
    create(options?: { id?: string; params?: IngestWorkflowParams }): Promise<{ id: string }>;
  };
  /** Optional Service Binding (`PdfOcrService` for optional external worker) for PyMuPDF + Tesseract 5.5.0 PDF OCR. */
  PDF_OCR?: {
    fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response>;
  };
  /** Optional HTTP URL + token fallback for PDF OCR when running outside Service Bindings. */
  PDF_OCR_URL?: string;
  PDF_OCR_TOKEN?: string;
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
    BOT_SIGNING_PRIVATE_KEY?: string;
    BOT_SIGNING_PUBLIC_KEY?: string;
  },
  version = '2.4.1',
): HubCapabilities {
  const searchProviders: string[] = ['edge-map'];
  if (env.SEARCH) searchProviders.push('d1-fts5');
  if (env.SERPER_API_KEY?.trim()) searchProviders.push('serper');
  if (env.BRAVE_API_KEY?.trim()) searchProviders.push('brave');
  if (env.TAVILY_API_KEY?.trim()) searchProviders.push('tavily');
  if (env.SEARXNG_URL?.trim()) searchProviders.push('searxng');
  const spaFallbacks = listConfiguredSpaFallbacks(env);

  const hasWebProvider = Boolean(
    env.SERPER_API_KEY?.trim() || env.BRAVE_API_KEY?.trim() || env.TAVILY_API_KEY?.trim() || env.SEARXNG_URL?.trim(),
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
    retention: ArtifactRetention;
    storedBytes: number;
    contentBytes: number;
  }): Promise<{ ok: true } | { ok: false; status: number; error: string }>;
}

const MAX_RECENT_UPLOAD_CACHE = 1_024;
const recentArtifactUploads = new Map<string, number>();

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
  const cachedUploadAt = recentArtifactUploads.get(key);
  if (cachedUploadAt !== undefined && !shouldRefreshDedupedObject(cachedUploadAt, rawRetention, now)) {
    await request.body.cancel().catch(() => undefined);
    return Response.json({ ok: true, stored: false, deduplicated: true, key }, { status: 200 });
  }

  let existing: R2Object | null = null;
  let knownNewInMeta = false;
  if (metaDb) {
    const metaRow = await metaDb
      .prepare('SELECT last_seen_at FROM artifacts WHERE blob_sha256 = ? AND retention = ? LIMIT 1')
      .bind(blobSha256, rawRetention)
      .first<{ last_seen_at: number | null }>()
      .catch(() => null);
    if (metaRow?.last_seen_at && !shouldRefreshDedupedObject(metaRow.last_seen_at, rawRetention, now)) {
      existing = await bucket.head(key);
      if (existing && !shouldRefreshDedupedObject(existing.uploaded.getTime(), rawRetention, now)) {
        rememberUploadedArtifact(key, existing.uploaded.getTime());
        await request.body.cancel().catch(() => undefined);
        return Response.json({ ok: true, stored: false, deduplicated: true, key }, { status: 200 });
      }
    } else {
      // Brand-new or due-for-refresh content-addressed upload: skip `bucket.head(key)` so Cloudflare OTEL never
      // emits `r2_head ERROR: The specified key does not exist.` on every new page crawl.
      knownNewInMeta = true;
    }
  } else {
    existing = await bucket.head(key);
    if (existing && !shouldRefreshDedupedObject(existing.uploaded.getTime(), rawRetention, now)) {
      rememberUploadedArtifact(key, existing.uploaded.getTime());
      await request.body.cancel().catch(() => undefined);
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
    const stored = await bucket.put(key, request.body, putOpts);
    if (stored !== null) {
      rememberUploadedArtifact(key, now);
    }
    return Response.json({ ok: true, stored: stored !== null, deduplicated: stored === null, key }, { status: 200 });
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    const isBadDigest = /sha-?256|checksum|digest/i.test(msg);
    if (!isBadDigest) {
      // On a concurrent same-key write collision, check head() to see if another writer succeeded; otherwise let agent retry.
      const afterErr = await bucket.head(key).catch(() => null);
      if (afterErr) {
        rememberUploadedArtifact(key, afterErr.uploaded.getTime());
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

const MAX_KNOWN_PIPELINE_VERSION = 25;

export async function readArtifactPage(params: {
  bucket: R2Bucket;
  metaDb?: D1Database;
  blobSha256: string;
  retention?: ArtifactRetention;
  format?: 'raw' | 'markdown';
  pipelineVersion?: number;
  offset?: number;
  limit?: number;
  deriveMarkdownFromRaw?: (bytes: Uint8Array) => string | null;
}): Promise<{ ok: true; page: ArtifactPageSlice } | { ok: false; status: number; error: string; message?: string }> {
  const rawId = params.blobSha256.trim().toLowerCase();
  const isMdPrefixed = rawId.startsWith('md:');
  const cleanHex = isMdPrefixed ? rawId.slice(3) : rawId;
  if (!isValidSha256Hex(cleanHex)) {
    return {
      ok: false,
      status: 400,
      error: 'invalid_artifact_id',
      message: 'artifactId must be a 64-character lowercase hex SHA-256 (or md:<sha256> for derived Markdown).',
    };
  }

  const sliceMarkdownPage = (mdText: string, contentSha: string, retention: ArtifactRetention = 'stored'): { ok: true; page: ArtifactPageSlice } => {
    const byteLen = new TextEncoder().encode(mdText).byteLength;
    const totalChars = mdText.length;
    const safeOffset = Math.min(totalChars, Math.max(0, Math.floor(params.offset ?? 0)));
    const safeLimit = Math.min(
      MAX_ARTIFACT_PAGE_LIMIT,
      Math.max(1, Math.floor(params.limit ?? DEFAULT_ARTIFACT_PAGE_LIMIT)),
    );
    const end = Math.min(totalChars, safeOffset + safeLimit);
    const slice = mdText.slice(safeOffset, end);
    const hasMore = end < totalChars;
    return {
      ok: true,
      page: {
        blobSha256: rawId,
        contentSha256: contentSha,
        retention,
        format: 'markdown',
        totalChars,
        totalBytes: byteLen,
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
    const topVer = params.pipelineVersion ?? 11;
    const candidateShas: string[] = [];
    if (isMdPrefixed) candidateShas.push(cleanHex);
    if (params.metaDb) {
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
      });
      return rawLoadedCache;
    };

    if (candidateShas.length === 0) {
      const rawLoaded = await loadRawOnce();
      if (rawLoaded.ok) {
        candidateShas.push(rawLoaded.contentSha256);
      }
    }

    const versionsToTry = params.metaDb
      ? [...new Set([topVer, Math.max(1, topVer - 1)])]
      : [
          topVer,
          ...Array.from({ length: MAX_KNOWN_PIPELINE_VERSION }, (_, idx) => MAX_KNOWN_PIPELINE_VERSION - idx).filter(
            (v) => v !== topVer,
          ),
        ];

    const checkCachedMarkdownForSha = async (sha: string): Promise<string | null> => {
      if (params.metaDb) {
        const docRow = await params.metaDb
          .prepare(
            `SELECT r2_key FROM documents WHERE content_sha256 = ? AND format = 'markdown' ORDER BY pipeline_version DESC LIMIT 1`,
          )
          .bind(sha)
          .first<{ r2_key: string }>()
          .catch(() => null);
        if (docRow?.r2_key) {
          const obj = await params.bucket.get(docRow.r2_key);
          if (obj) return await obj.text();
        }
      }
      for (const ver of versionsToTry) {
        const mdObj = await params.bucket.get(r2DerivedKey(ver, 'markdown', sha));
        if (mdObj) return await mdObj.text();
      }
      return null;
    };

    for (const sha of candidateShas) {
      const foundMd = await checkCachedMarkdownForSha(sha);
      if (foundMd !== null) {
        return sliceMarkdownPage(foundMd, sha, 'stored');
      }
    }

    // If caller passed `md:<blobSha256>` (the scrape `artifactId`) or `format="markdown"` on a non-truncated scrape
    // whose derived Markdown wasn't materialized yet, load the raw R2 artifact and derive clean Markdown on demand.
    const rawFallback = await loadRawOnce();
    if (rawFallback.ok) {
      if (!candidateShas.includes(rawFallback.contentSha256)) {
        const foundByRawContentSha = await checkCachedMarkdownForSha(rawFallback.contentSha256);
        if (foundByRawContentSha !== null) {
          return sliceMarkdownPage(foundByRawContentSha, rawFallback.contentSha256, rawFallback.retention);
        }
      }
      if (params.deriveMarkdownFromRaw) {
        const derivedMd = params.deriveMarkdownFromRaw(rawFallback.bytes);
        if (derivedMd !== null) {
          await params.bucket
            .put(r2DerivedKey(topVer, 'markdown', rawFallback.contentSha256), derivedMd, {
              httpMetadata: { contentType: 'text/markdown; charset=utf-8' },
            })
            .catch(() => undefined);
          return sliceMarkdownPage(derivedMd, rawFallback.contentSha256, rawFallback.retention);
        }
      }
    }

    if (isMdPrefixed) {
      return {
        ok: false,
        status: 404,
        error: 'artifact_expired',
        message: 'Derived Markdown artifact not found or expired in R2; re-scrape the URL to regenerate it.',
      };
    }
  }

  let expectedContentSha256: string | undefined;
  let dbRetention: ArtifactRetention | undefined;
  if (params.metaDb) {
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
  pipelineVersion?: number;
  deriveMarkdownFromRaw?: (bytes: Uint8Array) => string | null;
}): Promise<Response> {
  const { request, url, blobSha256, bucket, metaDb, pipelineVersion, deriveMarkdownFromRaw } = params;
  if (!bucket) {
    return Response.json({ error: 'artifacts_not_configured' }, { status: 503, headers: { 'cache-control': 'no-store' } });
  }
  const cleanParamId = blobSha256.startsWith('md:') ? blobSha256.slice(3) : blobSha256;
  if (!isValidSha256Hex(cleanParamId)) {
    return Response.json({ error: 'invalid_blob_sha256' }, { status: 400, headers: { 'cache-control': 'no-store' } });
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
    ...(pipelineVersion !== undefined ? { pipelineVersion } : {}),
    ...(deriveMarkdownFromRaw ? { deriveMarkdownFromRaw } : {}),
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
