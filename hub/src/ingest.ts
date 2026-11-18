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
import {
  isValidRetention,
  isValidSha256Hex,
  r2ArtifactKey,
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

/**
 * Executes the full deterministic ingest pipeline (`load-manifest` -> `track-<n>` chunks), runnable both inside
 * `IngestWorkflow.run()` (wrapping each phase in `step.do`) and directly in local `workerd` tests!
 */
export async function executeIngestPipeline(
  env: OptionalStorageBindings,
  params: IngestWorkflowParams,
  runStep: <T>(name: string, fn: () => Promise<T>) => Promise<T> = (_n, fn) => fn(),
): Promise<{ jobId: string; totalItems: number; chunks: number }> {
  if (!env.ARTIFACTS || !env.META) {
    return { jobId: params.jobId, totalItems: 0, chunks: 0 };
  }

  const summary = await runStep('load-manifest', async () => {
    const manifest = await loadManifestFromR2(env.ARTIFACTS!, params.manifestKey);
    return {
      totalItems: manifest.results.length,
      chunks: Math.ceil(manifest.results.length / TRACK_BATCH_CHUNK),
    };
  });

  for (let c = 0; c < summary.chunks; c++) {
    await runStep(`track-${c}`, async () => {
      const manifest = await loadManifestFromR2(env.ARTIFACTS!, params.manifestKey);
      const slice = manifest.results.slice(c * TRACK_BATCH_CHUNK, (c + 1) * TRACK_BATCH_CHUNK);
      return await trackManifestChunkInMetaD1(env.META!, manifest, slice);
    });
  }

  return { jobId: params.jobId, totalItems: summary.totalItems, chunks: summary.chunks };
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
