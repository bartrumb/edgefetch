/**
 * R2 manifest writer + idempotent `IngestWorkflow` (`META` D1 tracking in chunks of 50 statements per `db.batch()`,
 * plus scheduled 90-day `fetches` history pruning).
 *
 * Follows Cloudflare Workflows & D1 limits strictly:
 *  - Workflow event & step return payloads stay tiny (< 8 KiB counts/keys; full manifests live in R2 `tmp/manifests/<jobId>.json`).
 *  - Every D1 write uses unique constraints (`ON CONFLICT DO UPDATE`) so Workflow retries and duplicate runs are 100% idempotent.
 *  - `fetches` never stores URL query strings or bodies (linking to `pages.id`).
 */
import { WorkflowEntrypoint, type WorkflowEvent, type WorkflowStep } from 'cloudflare:workers';
import { deriveMarkdownDocument, SCRAPE_PIPELINE_VERSION } from './scrape';
import { COLLECTION_ID_RE, D1FtsSearchIndex } from './search-index';
import {
  MAX_ARTIFACT_CONTENT_BYTES,
  isValidRetention,
  isValidSha256Hex,
  r2ArtifactKey,
  r2DerivedKey,
  r2ManifestKey,
  type ArtifactRetention,
  type IngestWorkflowParams,
  type OptionalStorageBindings,
} from './storage';

const TRACK_BATCH_CHUNK = 25; // Up to 3 statements per item (artifact + page + fetch) = <= 75 statements per D1 batch()
const FETCH_RETENTION_MS = 90 * 24 * 60 * 60_000; // 90-day default fetch history retention

export interface ManifestResultItem {
  id: string;
  url: string;
  kind?: string;
  status?: number;
  outcome?: string;
  problem?: string;
  contentType?: string;
  etag?: string;
  lastModified?: string;
  attempts?: number;
  durationMs?: number;
  timing?: {
    ttfbMs?: number;
  };
  artifact?: {
    blobSha256: string;
    contentSha256: string;
    contentBytes: number;
    storedBytes: number;
    encoding: 'gzip';
    retention: ArtifactRetention;
  };
}

export interface JobManifest {
  jobId: string;
  via: string;
  siteId?: string;
  crawlId?: string;
  collectionId?: string;
  fetchedAt: number;
  results: ManifestResultItem[];
}

function bytesToHex(buf: ArrayBuffer | Uint8Array): string {
  const view = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let out = '';
  for (let i = 0; i < view.length; i++) out += view[i]!.toString(16).padStart(2, '0');
  return out;
}

export async function sha256HexString(input: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(input));
  return bytesToHex(digest);
}

function classifyRobotsDecision(outcome?: string, problem?: string): 'allowed' | 'disallowed' | 'unreachable' | 'not_checked' {
  const p = (problem ?? '').toLowerCase();
  if (p.includes('robots.txt disallowed')) return 'disallowed';
  if (p.includes('robots.txt') && (p.includes('unreachable') || p.includes('returned http'))) return 'unreachable';
  if (outcome === 'not_tried') return 'not_checked';
  return 'allowed';
}

/**
 * Strips inline `body` fields from a completed reply and writes a compact JSON manifest to `tmp/manifests/<jobId>.json` in R2.
 */
export async function writeJobManifestToR2(params: {
  bucket: R2Bucket;
  jobId: string;
  via: string;
  siteId?: string;
  crawlId?: string;
  collectionId?: string;
  rawReplyText: string;
  now?: number;
}): Promise<{ ok: true; manifestKey: string; itemCount: number } | { ok: false; error: string }> {
  let parsed: { results?: Array<Record<string, unknown>> };
  try {
    parsed = JSON.parse(params.rawReplyText) as typeof parsed;
  } catch {
    return { ok: false, error: 'invalid_reply_json' };
  }
  if (!Array.isArray(parsed.results) || parsed.results.length === 0) {
    return { ok: false, error: 'empty_results' };
  }

  const cleanItems: ManifestResultItem[] = [];
  for (let i = 0; i < parsed.results.length; i++) {
    const r = parsed.results[i] ?? {};
    const url = typeof r.url === 'string' ? r.url : '';
    if (!url) continue;
    const rawId = typeof r.id === 'string' && r.id.trim() ? r.id.trim() : `req-${i + 1}`;
    const art = r.artifact as Record<string, unknown> | undefined;
    let cleanArtifact: ManifestResultItem['artifact'] | undefined;
    if (
      art &&
      isValidSha256Hex(art.blobSha256) &&
      isValidSha256Hex(art.contentSha256) &&
      typeof art.contentBytes === 'number' &&
      typeof art.storedBytes === 'number' &&
      isValidRetention(art.retention)
    ) {
      cleanArtifact = {
        blobSha256: art.blobSha256,
        contentSha256: art.contentSha256,
        contentBytes: Math.max(0, Math.floor(art.contentBytes)),
        storedBytes: Math.max(0, Math.floor(art.storedBytes)),
        encoding: 'gzip',
        retention: art.retention,
      };
    }

    const tm = r.timing as { ttfbMs?: unknown } | undefined;
    cleanItems.push({
      id: rawId,
      url,
      ...(typeof r.kind === 'string' ? { kind: r.kind } : {}),
      status: typeof r.status === 'number' ? Math.floor(r.status) : 0,
      outcome: typeof r.outcome === 'string' ? r.outcome : 'error',
      ...(typeof r.problem === 'string' && r.problem ? { problem: r.problem.slice(0, 500) } : {}),
      ...(typeof r.contentType === 'string' && r.contentType ? { contentType: r.contentType.slice(0, 160) } : {}),
      ...(typeof r.etag === 'string' && r.etag ? { etag: r.etag.slice(0, 200) } : {}),
      ...(typeof r.lastModified === 'string' && r.lastModified ? { lastModified: r.lastModified.slice(0, 120) } : {}),
      attempts: typeof r.attempts === 'number' ? Math.max(0, Math.floor(r.attempts)) : 1,
      durationMs: typeof r.durationMs === 'number' ? Math.max(0, Math.floor(r.durationMs)) : 0,
      ...(typeof tm?.ttfbMs === 'number' ? { timing: { ttfbMs: Math.max(0, Math.floor(tm.ttfbMs)) } } : {}),
      ...(cleanArtifact ? { artifact: cleanArtifact } : {}),
    });
  }

  if (cleanItems.length === 0) {
    return { ok: false, error: 'no_valid_items' };
  }

  const manifest: JobManifest = {
    jobId: params.jobId,
    via: params.via,
    ...(params.siteId ? { siteId: params.siteId } : {}),
    ...(params.crawlId ? { crawlId: params.crawlId } : {}),
    ...(params.collectionId && COLLECTION_ID_RE.test(params.collectionId) ? { collectionId: params.collectionId } : {}),
    fetchedAt: params.now ?? Date.now(),
    results: cleanItems,
  };

  const manifestKey = r2ManifestKey(params.jobId);
  await params.bucket.put(manifestKey, JSON.stringify(manifest), {
    httpMetadata: { contentType: 'application/json' },
  });
  return { ok: true, manifestKey, itemCount: cleanItems.length };
}

export async function loadManifestFromR2(bucket: R2Bucket, manifestKey: string): Promise<JobManifest> {
  const obj = await bucket.get(manifestKey);
  if (!obj) {
    throw new Error(`manifest not found in R2: ${manifestKey}`);
  }
  const parsed = (await obj.json()) as JobManifest;
  if (!parsed || typeof parsed.jobId !== 'string' || !Array.isArray(parsed.results)) {
    throw new Error(`invalid manifest payload at ${manifestKey}`);
  }
  return parsed;
}

/**
 * Writes one chunk (<= 25 items) of `JobManifest` into `META` D1 inside a single atomic `db.batch()`.
 * Idempotent under retries: re-running the same `(jobId, requestId)` updates in place without creating duplicates.
 */
export async function trackManifestChunkInMetaD1(
  metaDb: D1Database,
  manifest: Pick<JobManifest, 'jobId' | 'via' | 'siteId' | 'crawlId' | 'fetchedAt'>,
  items: ManifestResultItem[],
): Promise<{ tracked: number; rowsWritten: number }> {
  const stmts: D1PreparedStatement[] = [];
  const now = manifest.fetchedAt;

  for (const item of items) {
    let host = '';
    try {
      host = new URL(item.url).hostname.toLowerCase().replace(/\.+$/, '');
    } catch {
      continue;
    }
    if (!host) continue;

    const pageId = `pg_${(await sha256HexString(item.url)).slice(0, 32)}`;
    const fetchId = `ft_${(await sha256HexString(`${manifest.jobId}:${item.id}`)).slice(0, 32)}`;
    const contentSha = item.artifact?.contentSha256 ?? null;
    const blobSha = item.artifact?.blobSha256 ?? null;

    if (item.artifact) {
      const r2Key = r2ArtifactKey(item.artifact.retention, item.artifact.blobSha256);
      stmts.push(
        metaDb
          .prepare(
            `INSERT INTO artifacts
             (blob_sha256, content_sha256, r2_key, retention, encoding, stored_bytes, content_bytes, content_type, created_at, last_seen_at)
             VALUES (?, ?, ?, ?, 'gzip', ?, ?, ?, ?, ?)
             ON CONFLICT(blob_sha256) DO UPDATE SET
               last_seen_at = MAX(artifacts.last_seen_at, excluded.last_seen_at),
               retention = CASE WHEN artifacts.retention = 'stored' OR excluded.retention = 'stored' THEN 'stored' ELSE 'transient' END`,
          )
          .bind(
            item.artifact.blobSha256,
            item.artifact.contentSha256,
            r2Key,
            item.artifact.retention,
            item.artifact.storedBytes,
            item.artifact.contentBytes,
            item.contentType ?? null,
            now,
            now,
          ),
      );
    }

    stmts.push(
      metaDb
        .prepare(
          `INSERT INTO pages
           (id, url, host, latest_fetch_id, latest_status, latest_outcome, latest_content_sha256, etag, last_modified, first_seen_at, last_fetched_at, last_changed_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
           ON CONFLICT(url) DO UPDATE SET
             latest_fetch_id = excluded.latest_fetch_id,
             latest_status = excluded.latest_status,
             latest_outcome = excluded.latest_outcome,
             etag = COALESCE(excluded.etag, pages.etag),
             last_modified = COALESCE(excluded.last_modified, pages.last_modified),
             last_fetched_at = MAX(COALESCE(pages.last_fetched_at, 0), excluded.last_fetched_at),
             last_changed_at = CASE
               WHEN excluded.latest_content_sha256 IS NOT NULL AND pages.latest_content_sha256 IS NOT excluded.latest_content_sha256
                 THEN excluded.last_changed_at
               ELSE pages.last_changed_at
             END,
             latest_content_sha256 = COALESCE(excluded.latest_content_sha256, pages.latest_content_sha256)`,
        )
        .bind(
          pageId,
          item.url,
          host,
          fetchId,
          item.status ?? 0,
          item.outcome ?? 'error',
          contentSha,
          item.etag ?? null,
          item.lastModified ?? null,
          now,
          now,
          contentSha ? now : null,
        ),
    );

    const safeProblem = item.problem ? item.problem.replace(/\?[^\s]*/g, '').slice(0, 300) : null;
    stmts.push(
      metaDb
        .prepare(
          `INSERT INTO fetches
           (id, job_id, request_id, crawl_id, page_id, site_id, via, final_host, status, outcome, robots_decision, problem, attempts, duration_ms, ttfb_ms, content_sha256, blob_sha256, fetched_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
           ON CONFLICT(job_id, request_id) DO UPDATE SET
             status = excluded.status,
             outcome = excluded.outcome,
             duration_ms = excluded.duration_ms,
             content_sha256 = COALESCE(excluded.content_sha256, fetches.content_sha256),
             blob_sha256 = COALESCE(excluded.blob_sha256, fetches.blob_sha256)`,
        )
        .bind(
          fetchId,
          manifest.jobId,
          item.id,
          manifest.crawlId ?? null,
          pageId,
          manifest.siteId ?? null,
          manifest.via,
          host,
          item.status ?? 0,
          item.outcome ?? 'error',
          classifyRobotsDecision(item.outcome, item.problem),
          safeProblem,
          item.attempts ?? 1,
          item.durationMs ?? 0,
          item.timing?.ttfbMs ?? null,
          contentSha,
          blobSha,
          now,
        ),
    );
  }

  if (stmts.length === 0) return { tracked: 0, rowsWritten: 0 };
  const batchRes = await metaDb.batch(stmts);
  const rowsWritten = batchRes.reduce((sum, r) => sum + (r.meta?.rows_written ?? 0), 0);
  return { tracked: items.length, rowsWritten };
}

export type ArtifactRejectionReason =
  | 'decompression_limit_exceeded'
  | 'content_hash_mismatch'
  | 'content_bytes_mismatch'
  | 'corrupt_gzip';

export type ArtifactVerificationResult =
  | {
      status: 'verified';
      blobSha256: string;
      contentSha256: string;
      contentBytes: number;
      alreadyVerified: boolean;
    }
  | {
      status: 'expired';
      blobSha256: string;
      error: 'artifact_expired';
    }
  | {
      status: 'rejected';
      blobSha256: string;
      reason: ArtifactRejectionReason;
    };

export interface IngestPipelineOptions {
  maxContentBytes?: number;
  now?: number;
  searchWarnBytes?: number;
  searchMaxBytes?: number;
  searchInitialSizeBytes?: number;
  onSearchCapacityWarning?: (sizeBytes: number) => Promise<void> | void;
  onArtifactRejected?: (info: {
    jobId: string;
    siteId?: string;
    blobSha256: string;
    claimedContentSha256: string;
    reason: ArtifactRejectionReason;
  }) => Promise<void> | void;
}

/**
 * Checks whether at least one stored artifact in `META` D1 with `content_sha256` has passed streaming decompression
 * and SHA-256 verification (`verified_at IS NOT NULL`). Extraction (`S6`) and `SEARCH` indexing (`S7`) MUST check this
 * before reusing cached/stored content so unverified agent claims are never trusted.
 */
export async function isContentVerifiedInMetaD1(metaDb: D1Database, contentSha256: string): Promise<boolean> {
  if (!isValidSha256Hex(contentSha256)) return false;
  const row = await metaDb
    .prepare('SELECT 1 AS ok FROM artifacts WHERE content_sha256 = ? AND verified_at IS NOT NULL LIMIT 1')
    .bind(contentSha256)
    .first<{ ok: number }>();
  return row?.ok === 1;
}

async function rejectPoisonedArtifact(params: {
  bucket: R2Bucket;
  metaDb: D1Database;
  blobSha256: string;
  claimedContentSha256: string;
  reason: ArtifactRejectionReason;
}): Promise<void> {
  const { bucket, metaDb, blobSha256, claimedContentSha256, reason } = params;
  // Delete both raw/ and tmp/ keys from R2 so a poisoned or gzip-bomb payload can never be hydrated or reused.
  await Promise.all([
    bucket.delete(r2ArtifactKey('stored', blobSha256)).catch(() => undefined),
    bucket.delete(r2ArtifactKey('transient', blobSha256)).catch(() => undefined),
  ]);

  // Scrub FK references in `fetches`, clear unbacked `pages.latest_content_sha256`, and remove the bad `artifacts` row.
  await metaDb.batch([
    metaDb
      .prepare(
        `UPDATE fetches
         SET blob_sha256 = NULL,
             content_sha256 = NULL,
             outcome = 'error',
             problem = ?
         WHERE blob_sha256 = ?`,
      )
      .bind(`artifact verification failed: ${reason}`, blobSha256),
    metaDb
      .prepare(
        `UPDATE pages
         SET latest_content_sha256 = NULL
         WHERE latest_content_sha256 = ?
           AND NOT EXISTS (
             SELECT 1 FROM artifacts
             WHERE content_sha256 = ? AND blob_sha256 != ? AND verified_at IS NOT NULL
           )`,
      )
      .bind(claimedContentSha256, claimedContentSha256, blobSha256),
    metaDb.prepare('DELETE FROM artifacts WHERE blob_sha256 = ?').bind(blobSha256),
  ]);
}

/**
 * Streams a `stored` R2 gzip artifact through `DecompressionStream('gzip')` -> bounded byte cap -> `crypto.DigestStream('SHA-256')`
 * in O(chunk) memory without buffering 16 MiB in the Worker isolate.
 *  - Sets `artifacts.verified_at` in `META` D1 when `SHA-256(uncompressed)` and `contentBytes` match the agent's claim.
 *  - Deletes the R2 object and scrubs `META` D1 if decompression exceeds `maxContentBytes`, gzip is corrupt, or hashes mismatch.
 *  - Returns `{ status: 'expired', error: 'artifact_expired' }` cleanly if the R2 object is missing/expired.
 */
export async function verifyStoredArtifact(params: {
  bucket: R2Bucket;
  metaDb: D1Database;
  blobSha256: string;
  expectedContentSha256: string;
  expectedContentBytes?: number;
  maxContentBytes?: number;
  now?: number;
}): Promise<ArtifactVerificationResult> {
  const {
    bucket,
    metaDb,
    blobSha256,
    expectedContentSha256,
    expectedContentBytes,
    maxContentBytes = MAX_ARTIFACT_CONTENT_BYTES,
    now = Date.now(),
  } = params;

  const existingRow = await metaDb
    .prepare('SELECT content_sha256, content_bytes, verified_at FROM artifacts WHERE blob_sha256 = ? LIMIT 1')
    .bind(blobSha256)
    .first<{ content_sha256: string; content_bytes: number; verified_at: number | null }>();

  if (existingRow && existingRow.verified_at !== null && existingRow.content_sha256 === expectedContentSha256) {
    return {
      status: 'verified',
      blobSha256,
      contentSha256: existingRow.content_sha256,
      contentBytes: existingRow.content_bytes,
      alreadyVerified: true,
    };
  }

  let obj = await bucket.get(r2ArtifactKey('stored', blobSha256));
  if (!obj) {
    obj = await bucket.get(r2ArtifactKey('transient', blobSha256));
  }
  if (!obj) {
    return { status: 'expired', blobSha256, error: 'artifact_expired' };
  }

  const DigestStreamCtor = (
    crypto as unknown as {
      DigestStream: new (algo: string) => WritableStream<Uint8Array> & { readonly digest: Promise<ArrayBuffer> };
    }
  ).DigestStream;
  const digestStream = new DigestStreamCtor('SHA-256');
  const digestWriter = digestStream.getWriter();
  const decompressed = obj.body.pipeThrough(new DecompressionStream('gzip') as unknown as TransformStream<Uint8Array, Uint8Array>);
  const reader = decompressed.getReader();

  let totalBytes = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (value && value.byteLength > 0) {
        totalBytes += value.byteLength;
        if (totalBytes > maxContentBytes) {
          await reader.cancel('decompression bomb cap exceeded').catch(() => undefined);
          await digestWriter.abort('decompression bomb cap exceeded').catch(() => undefined);
          await rejectPoisonedArtifact({
            bucket,
            metaDb,
            blobSha256,
            claimedContentSha256: expectedContentSha256,
            reason: 'decompression_limit_exceeded',
          });
          return { status: 'rejected', blobSha256, reason: 'decompression_limit_exceeded' };
        }
        await digestWriter.write(value);
      }
    }
    await digestWriter.close();
  } catch {
    await reader.cancel('corrupt gzip').catch(() => undefined);
    await digestWriter.abort('corrupt gzip').catch(() => undefined);
    await rejectPoisonedArtifact({
      bucket,
      metaDb,
      blobSha256,
      claimedContentSha256: expectedContentSha256,
      reason: 'corrupt_gzip',
    });
    return { status: 'rejected', blobSha256, reason: 'corrupt_gzip' };
  }

  const actualSha256 = bytesToHex(await digestStream.digest);
  if (actualSha256 !== expectedContentSha256) {
    await rejectPoisonedArtifact({
      bucket,
      metaDb,
      blobSha256,
      claimedContentSha256: expectedContentSha256,
      reason: 'content_hash_mismatch',
    });
    return { status: 'rejected', blobSha256, reason: 'content_hash_mismatch' };
  }
  if (typeof expectedContentBytes === 'number' && totalBytes !== expectedContentBytes) {
    await rejectPoisonedArtifact({
      bucket,
      metaDb,
      blobSha256,
      claimedContentSha256: expectedContentSha256,
      reason: 'content_bytes_mismatch',
    });
    return { status: 'rejected', blobSha256, reason: 'content_bytes_mismatch' };
  }

  await metaDb
    .prepare(
      `UPDATE artifacts
       SET verified_at = COALESCE(verified_at, ?),
           content_bytes = ?,
           last_seen_at = MAX(last_seen_at, ?)
       WHERE blob_sha256 = ?`,
    )
    .bind(now, totalBytes, now, blobSha256)
    .run();

  return {
    status: 'verified',
    blobSha256,
    contentSha256: actualSha256,
    contentBytes: totalBytes,
    alreadyVerified: false,
  };
}

/**
 * Executes the full deterministic ingest pipeline (`load-manifest` -> `track-<n>` chunks -> `verify-<blobSha>`),
 * runnable both inside `IngestWorkflow.run()` (wrapping each phase in `step.do`) and directly in local `workerd` tests!
 */
export async function executeIngestPipeline(
  env: OptionalStorageBindings,
  params: IngestWorkflowParams,
  runStep: <T>(name: string, fn: () => Promise<T>) => Promise<T> = (_n, fn) => fn(),
  options: IngestPipelineOptions = {},
): Promise<{
  jobId: string;
  totalItems: number;
  chunks: number;
  verifiedCount: number;
  rejectedCount: number;
  expiredCount: number;
  derivedCount: number;
  indexedCount: number;
  capacityStoppedCount: number;
}> {
  if (!env.ARTIFACTS || !env.META) {
    return {
      jobId: params.jobId,
      totalItems: 0,
      chunks: 0,
      verifiedCount: 0,
      rejectedCount: 0,
      expiredCount: 0,
      derivedCount: 0,
      indexedCount: 0,
      capacityStoppedCount: 0,
    };
  }

  const summary = await runStep('load-manifest', async () => {
    const manifest = await loadManifestFromR2(env.ARTIFACTS!, params.manifestKey);
    const storedMap = new Map<
      string,
      { blobSha256: string; contentSha256: string; contentBytes: number; contentType?: string; url?: string }
    >();
    const pageMap = new Map<string, { pageId: string; url: string; contentSha256: string; fetchedAt: number }>();
    for (const item of manifest.results) {
      if (item.artifact && item.artifact.retention === 'stored') {
        storedMap.set(item.artifact.blobSha256, {
          blobSha256: item.artifact.blobSha256,
          contentSha256: item.artifact.contentSha256,
          contentBytes: item.artifact.contentBytes,
          ...(item.contentType ? { contentType: item.contentType } : {}),
          ...(item.url ? { url: item.url } : {}),
        });
        if (item.url && item.outcome === 'ok') {
          const pageId = `pg_${(await sha256HexString(item.url)).slice(0, 32)}`;
          pageMap.set(pageId, {
            pageId,
            url: item.url,
            contentSha256: item.artifact.contentSha256,
            fetchedAt: manifest.fetchedAt,
          });
        }
      }
    }
    const storedArtifacts = [...storedMap.values()].sort((a, b) => a.blobSha256.localeCompare(b.blobSha256));
    const indexPages = [...pageMap.values()].sort((a, b) => a.pageId.localeCompare(b.pageId));
    return {
      totalItems: manifest.results.length,
      chunks: Math.ceil(manifest.results.length / TRACK_BATCH_CHUNK),
      collectionId: params.collectionId ?? manifest.collectionId,
      storedArtifacts,
      indexPages,
    };
  });

  for (let c = 0; c < summary.chunks; c++) {
    await runStep(`track-${c}`, async () => {
      const manifest = await loadManifestFromR2(env.ARTIFACTS!, params.manifestKey);
      const slice = manifest.results.slice(c * TRACK_BATCH_CHUNK, (c + 1) * TRACK_BATCH_CHUNK);
      return await trackManifestChunkInMetaD1(env.META!, manifest, slice);
    });
  }

  let verifiedCount = 0;
  let rejectedCount = 0;
  let expiredCount = 0;
  let derivedCount = 0;
  const derivedDocsBySha = new Map<string, { documentId: string; title: string }>();

  for (const art of summary.storedArtifacts) {
    const verifyRes = await runStep(`verify-${art.blobSha256}`, async () => {
      return await verifyStoredArtifact({
        bucket: env.ARTIFACTS!,
        metaDb: env.META!,
        blobSha256: art.blobSha256,
        expectedContentSha256: art.contentSha256,
        expectedContentBytes: art.contentBytes,
        ...(options.maxContentBytes !== undefined ? { maxContentBytes: options.maxContentBytes } : {}),
        ...(options.now !== undefined ? { now: options.now } : {}),
      });
    });

    if (verifyRes.status === 'verified') {
      verifiedCount++;
      if (!derivedDocsBySha.has(verifyRes.contentSha256)) {
        const deriveRes = await runStep(`derive-${verifyRes.contentSha256}-v${SCRAPE_PIPELINE_VERSION}`, async () => {
          return await deriveMarkdownDocument({
            bucket: env.ARTIFACTS!,
            metaDb: env.META!,
            blobSha256: art.blobSha256,
            contentSha256: verifyRes.contentSha256,
            ...(art.contentType ? { contentType: art.contentType } : {}),
            ...(art.url ? { baseUrl: art.url } : {}),
            pipelineVersion: SCRAPE_PIPELINE_VERSION,
            ...(options.now !== undefined ? { now: options.now } : {}),
          });
        });
        if (deriveRes.status === 'derived' || deriveRes.status === 'cached') {
          derivedCount++;
          derivedDocsBySha.set(verifyRes.contentSha256, {
            documentId: deriveRes.documentId,
            title: deriveRes.title ?? '',
          });
        }
      }
    } else if (verifyRes.status === 'rejected') {
      rejectedCount++;
      if (options.onArtifactRejected) {
        await options.onArtifactRejected({
          jobId: params.jobId,
          ...(params.siteId ? { siteId: params.siteId } : {}),
          blobSha256: art.blobSha256,
          claimedContentSha256: art.contentSha256,
          reason: verifyRes.reason,
        });
      }
    } else {
      expiredCount++;
    }
  }

  let indexedCount = 0;
  let capacityStoppedCount = 0;
  const activeCollection = summary.collectionId && COLLECTION_ID_RE.test(summary.collectionId) ? summary.collectionId : undefined;

  if (env.SEARCH && activeCollection && derivedDocsBySha.size > 0) {
    const searchIndex = new D1FtsSearchIndex(env.SEARCH, {
      ...(options.searchWarnBytes !== undefined ? { warnBytes: options.searchWarnBytes } : {}),
      ...(options.searchMaxBytes !== undefined ? { maxBytes: options.searchMaxBytes } : {}),
      ...(options.searchInitialSizeBytes !== undefined ? { initialSizeBytes: options.searchInitialSizeBytes } : {}),
      ...(options.onSearchCapacityWarning ? { onCapacityWarning: options.onSearchCapacityWarning } : {}),
    });

    for (const pg of summary.indexPages) {
      const docInfo = derivedDocsBySha.get(pg.contentSha256);
      if (!docInfo) continue;
      const idxRes = await runStep(`index-${activeCollection}-${pg.pageId}`, async () => {
        const mdKey = r2DerivedKey(SCRAPE_PIPELINE_VERSION, 'markdown', pg.contentSha256);
        const mdObj = await env.ARTIFACTS!.get(mdKey);
        if (!mdObj) {
          return { status: 'missing_derived' as const };
        }
        const mdText = await mdObj.text();
        return await searchIndex.replacePageChunks({
          collectionId: activeCollection,
          documentId: docInfo.documentId,
          pageId: pg.pageId,
          url: pg.url,
          title: docInfo.title,
          markdown: mdText,
          fetchedAt: pg.fetchedAt,
        });
      });

      if (idxRes.status === 'indexed') {
        indexedCount++;
      } else if (idxRes.status === 'capacity_reached') {
        capacityStoppedCount++;
        break;
      }
    }
  }

  return {
    jobId: params.jobId,
    totalItems: summary.totalItems,
    chunks: summary.chunks,
    verifiedCount,
    rejectedCount,
    expiredCount,
    derivedCount,
    indexedCount,
    capacityStoppedCount,
  };
}

/** Deletes `fetches` history older than `retentionMs` (default 90 days) in bounded batches of `limit`. */
export async function pruneExpiredFetchHistory(
  metaDb: D1Database,
  nowMs = Date.now(),
  retentionMs = FETCH_RETENTION_MS,
  limit = 500,
): Promise<number> {
  const cutoff = nowMs - retentionMs;
  const res = await metaDb
    .prepare('DELETE FROM fetches WHERE id IN (SELECT id FROM fetches WHERE fetched_at < ? ORDER BY fetched_at ASC LIMIT ?)')
    .bind(cutoff, limit)
    .run();
  return res.meta?.changes ?? 0;
}

export class IngestWorkflow extends WorkflowEntrypoint<OptionalStorageBindings, IngestWorkflowParams> {
  override async run(event: WorkflowEvent<IngestWorkflowParams>, step: WorkflowStep): Promise<{ jobId: string; totalItems: number; chunks: number }> {
    return await executeIngestPipeline(
      this.env,
      event.payload,
      <T>(name: string, fn: () => Promise<T>) => step.do(name, () => fn() as never) as Promise<T>,
    );
  }
}
