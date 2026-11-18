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
