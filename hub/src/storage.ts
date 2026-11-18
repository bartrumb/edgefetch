/**
 * Storage primitives, R2 object layout helpers, retention freshness checks, and `/v1/capabilities` metadata for
 * EdgeFetch's optional three-layer storage architecture (`ARTIFACTS` R2 + `META` D1 + `SEARCH` D1 FTS5).
 *
 * All storage bindings remain strictly optional so an existing single-binding `AgentHubDO` deployment continues
 * operating unchanged when `ARTIFACTS` / `META` / `SEARCH` / `INGEST` are unconfigured.
 */

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
const UPLOAD_ID_RE = /^[A-Za-z0-9_.:-]{1,128}$/;

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
