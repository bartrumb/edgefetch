/**
 * Polite Full-Store Catalog Coordinator (`hub/src/catalog.ts`).
 *
 * Thin Cloudflare R2/D1/semaphore/cooldown/LRU async coordinator delegating all pure-CPU storefront URL
 * validation, page evaluation (WAF/non-storefront/redirect/cooldown), record clamping, FNV-1a snapshot
 * hashing, `>50%` shrink-guard diffing, UCP discovery, NDJSON parsing, lean projection, and multi-attribute
 * record filtering to Go WASM (`internal/catalog/`).
 */

import { getCatalogAdapter, type CatalogRecord, type CatalogSpec, type CatalogVariantRecord } from './extractors/registry';
import { buildBlockedInfo, type BlockedSuggestion } from './jobs';
import { getActiveCallerAuthContext } from './oauth';
import { getActiveRequestTracer, type OtelEnvConfig, type RequestTracer, type TraceContext } from './otel';
import { ensureD1ColumnIfMissing } from './search-index';
import { sanitizeStorageUserId, type OptionalStorageBindings } from './storage';
import { callCoreWasm, callCoreWasmRaw } from './wasm-bridge';

export type CatalogRunStatus = 'running' | 'cooling_down' | 'complete' | 'partial' | 'challenged';

export interface CatalogVariantDiffCounts {
  added: number;
  removed: number;
  changed: number;
}

export interface CatalogSnapshotDiff {
  added: number;
  removed: number;
  changed: number;
  variantDiff?: CatalogVariantDiffCounts;
}

export interface CatalogUcpMetadata {
  advertised: boolean;
  endpoint: string;
}

export interface CatalogStatusSummary {
  ok: boolean;
  catalogId: string;
  status: CatalogRunStatus;
  platform: string;
  origin: string;
  collection?: string;
  fields?: 'full' | 'lean';
  products: number;
  variants: number;
  pages: number;
  pagesRead: number;
  pauseMs: number;
  durationMs: number;
  truncated?: boolean;
  reason?: string;
  resumeAt?: string;
  warning?: 'shrink';
  previousProducts?: number;
  artifactId?: string;
  diff?: CatalogSnapshotDiff | null;
  ucp?: CatalogUcpMetadata;
  blocked?: BlockedSuggestion;
  createdAt: string;
  updatedAt: string;
}

export interface CatalogRecordsResult {
  ok: boolean;
  catalogId: string;
  status: CatalogRunStatus;
  platform: string;
  origin: string;
  totalProducts: number;
  matchedProducts: number;
  offset: number;
  limit: number;
  returned: number;
  hasMore: boolean;
  records: Array<CatalogRecord | Record<string, unknown>>;
}

export interface CatalogCallPayload {
  url?: unknown;
  platform?: unknown;
  collection?: unknown;
  scope?: unknown;
  fields?: unknown;
  maxPages?: unknown;
  pauseMs?: unknown;
  sync?: unknown;
  catalogId?: unknown;
  catalogJobId?: unknown;
  offset?: unknown;
  cursor?: unknown;
  limit?: unknown;
  vendor?: unknown;
  productType?: unknown;
  tag?: unknown;
  availableOnly?: unknown;
  inStockOnly?: unknown;
  minPrice?: unknown;
  maxPrice?: unknown;
  query?: unknown;
  target?: unknown;
  site?: unknown;
}

export interface NormalizedHubPageResponse {
  status: number;
  outcome?: string;
  problem?: string;
  headers: Record<string, string>;
  body: string;
  finalUrl?: string;
  retryAfterMs?: number;
}

export interface CatalogHubFetchParams {
  url: string;
  kind?: 'json' | 'text';
  accept?: string;
  maxBytes?: number;
  timeoutMs?: number;
  target?: unknown;
  site?: unknown;
  tracer?: RequestTracer | TraceContext;
}

export type CatalogHubFetchFn = (args: CatalogHubFetchParams) => Promise<unknown>;

interface D1PreparedStatementLike {
  bind(...values: unknown[]): D1PreparedStatementLike;
  run(): Promise<unknown>;
  first<T = Record<string, unknown>>(): Promise<T | null>;
  all<T = Record<string, unknown>>(): Promise<{ results?: T[] }>;
}
interface D1DatabaseLike {
  prepare(query: string): D1PreparedStatementLike;
}
interface R2ObjectBodyLike {
  body?: ReadableStream<Uint8Array>;
  arrayBuffer?(): Promise<ArrayBuffer>;
  text(): Promise<string>;
}
interface R2BucketLike {
  put(key: string, value: string | Uint8Array | ArrayBuffer, options?: Record<string, unknown>): Promise<unknown>;
  get(key: string): Promise<R2ObjectBodyLike | null>;
}
interface SnapshotHashBundle {
  products: Record<string, string>;
  variants: Record<string, string>;
}
interface StoredCatalogRun {
  userId: string;
  summary: CatalogStatusSummary;
  hashes: SnapshotHashBundle | null;
  hashesBytes: number;
  hashesArtifactId?: string;
  records: CatalogRecord[] | null;
  retainedBytes: number;
}

export const MAX_CATALOG_IN_MEMORY_BYTES = 16 * 1024 * 1024;
export const MAX_GLOBAL_CATALOG_BYTES = 32 * 1024 * 1024;
export const MAX_PER_USER_CATALOG_BYTES = 8 * 1024 * 1024;
export const MAX_CACHED_CATALOG_RUNS = 16;
export const MAX_CACHED_CATALOG_RUNS_PER_USER = 4;
export const MAX_CONCURRENT_CATALOG_PER_PRINCIPAL = 2;
export const MAX_CONCURRENT_CATALOG_GLOBAL = 8;
export const MAX_CONCURRENT_CATALOG_NON_OWNER_GLOBAL = 6;
export const MAX_CONCURRENT_R2_RELOADS = 2;
export const MAX_CATALOG_TOTAL_SLEEP_MS = 120_000;
export const MAX_CATALOG_WALL_MS = 120_000;

const MAX_R2_DECOMPRESSED_BYTES = 32 * 1024 * 1024;
const MAX_R2_CACHEABLE_ARTIFACT_BYTES = 8 * 1024 * 1024;
const MAX_VARIANTS_PER_CATALOG_RUN = 50_000;
const MAX_COMPACT_HISTORY_RUNS = 256;
const MAX_COMPACT_HISTORY_RUNS_PER_USER = 32;
const VALID_CATALOG_ID_RE = /^[A-Za-z0-9_-]{1,80}$/;

const MEMORY_CATALOG_RUNS = new Map<string, StoredCatalogRun>();
const R2_RELOAD_LRU_CACHE = new Map<string, { records: CatalogRecord[]; bytes: number }>();
const INFLIGHT_R2_RELOADS = new Map<string, Promise<unknown>>();
const SHOPIFY_ORIGIN_CURRENCY_CACHE = new Map<string, { currency: string | null; expiresAt: number }>();
const SHOPIFY_ORIGIN_CURRENCY_TTL_MS = 30 * 60_000;
const ORIGIN_UCP_CACHE = new Map<string, { ucp: CatalogUcpMetadata | null; expiresAt: number }>();
const ORIGIN_UCP_TTL_MS = 30 * 60_000;

let activeR2Reloads = 0;
let peakR2ReloadsSeen = 0;
const r2ReloadWaitQueue: Array<() => void> = [];
const ACTIVE_CATALOG_BY_PRINCIPAL = new Map<string, number>();
let activeCatalogGlobal = 0;
let activeCatalogNonOwnerGlobal = 0;
const D1_INIT_CACHE = new WeakSet<object>();

export function projectLeanCatalogRecord(rec: CatalogRecord): Record<string, unknown> {
  return callCoreWasm<{ lean: Record<string, unknown> }>('catalog_project_lean', { record: rec }).lean;
}

export function approxHashBundleBytes(hashes: SnapshotHashBundle | null): number {
  return hashes ? callCoreWasm<{ bytes: number }>('catalog_approx_hash_bytes', { hashes }).bytes : 0;
}

export function computeCatalogVariantHash(v: CatalogVariantRecord): string {
  return callCoreWasm<{ hash: string }>('catalog_variant_hash', { variant: v }).hash;
}

export function computeCatalogProductHash(rec: CatalogRecord): string {
  return callCoreWasm<{ hash: string }>('catalog_product_hash', { record: rec }).hash;
}

export function computeCatalogSnapshotDiff(prev: SnapshotHashBundle, curr: SnapshotHashBundle): CatalogSnapshotDiff {
  return callCoreWasm<{ diff: CatalogSnapshotDiff }>('catalog_snapshot_diff', { prev, curr }).diff;
}

export function discoverUcpEndpointFromRobots(originStr: string, robotsText: string): CatalogUcpMetadata | null {
  if (!robotsText) return null;
  return callCoreWasmRaw<{ ucp: CatalogUcpMetadata | null }>('catalog_discover_ucp', { origin: String(originStr ?? '') }, String(robotsText)).ucp ?? null;
}

export function isSafeHttpsStoreUrl(urlStr: string, selfHost?: string): URL | null {
  if (typeof urlStr !== 'string' || !urlStr.trim()) return null;
  const res = callCoreWasm<{ ok: boolean; normalized?: string }>('catalog_validate_store_url', { url: urlStr, selfHost: selfHost ?? '' });
  if (!res.ok || !res.normalized) return null;
  try {
    return new URL(res.normalized);
  } catch {
    return null;
  }
}

export function getCatalogMemoryUsageForTests() {
  let recordsBytes = 0;
  let hashesBytes = 0;
  for (const v of MEMORY_CATALOG_RUNS.values()) {
    if (v.records !== null) recordsBytes += v.retainedBytes;
    if (v.hashes !== null) hashesBytes += v.hashesBytes;
  }
  let reloadCacheBytes = 0;
  for (const c of R2_RELOAD_LRU_CACHE.values()) reloadCacheBytes += c.bytes;
  return {
    runsCount: MEMORY_CATALOG_RUNS.size,
    recordsBytes,
    hashesBytes,
    reloadCacheBytes,
    totalBytes: recordsBytes + hashesBytes + reloadCacheBytes,
    maxBytes: MAX_GLOBAL_CATALOG_BYTES,
    activeR2Reloads,
    peakR2ReloadsSeen,
  };
}

export function resetCatalogStateForTests(): void {
  MEMORY_CATALOG_RUNS.clear();
  R2_RELOAD_LRU_CACHE.clear();
  INFLIGHT_R2_RELOADS.clear();
  ACTIVE_CATALOG_BY_PRINCIPAL.clear();
  SHOPIFY_ORIGIN_CURRENCY_CACHE.clear();
  ORIGIN_UCP_CACHE.clear();
  activeCatalogGlobal = 0;
  activeCatalogNonOwnerGlobal = 0;
  peakR2ReloadsSeen = 0;
}

function resolveCatalogTenantKey(params?: { userId?: string; principal?: string }) {
  const activeAuth = getActiveCallerAuthContext();
  const cleanUserId = typeof params?.userId === 'string' && params.userId.trim() ? sanitizeStorageUserId(params.userId.trim()) : '';
  const activeUserId = activeAuth ? sanitizeStorageUserId(activeAuth.userId) : '';
  return callCoreWasm<{ ownerKey: string; concurrencyBucketKey: string; isOwner: boolean }>('catalog_resolve_tenant', {
    cleanUserId,
    principal: String(params?.principal ?? ''),
    activeUserId,
    activeRole: activeAuth ? activeAuth.role : '',
  });
}

function withR2ReloadSemaphore<T>(fn: () => Promise<T>): Promise<T> {
  return new Promise<T>((resolveSlot, rejectSlot) => {
    const runTask = () => {
      activeR2Reloads++;
      if (activeR2Reloads > peakR2ReloadsSeen) peakR2ReloadsSeen = activeR2Reloads;
      Promise.resolve()
        .then(fn)
        .then(resolveSlot, rejectSlot)
        .finally(() => {
          activeR2Reloads = Math.max(0, activeR2Reloads - 1);
          r2ReloadWaitQueue.shift()?.();
        });
    };
    if (activeR2Reloads < MAX_CONCURRENT_R2_RELOADS) runTask();
    else r2ReloadWaitQueue.push(runTask);
  });
}

function coalesceSingleflightR2Reload<T>(key: string, loader: () => Promise<T>): Promise<T> {
  const existing = INFLIGHT_R2_RELOADS.get(key) as Promise<T> | undefined;
  if (existing) return existing;
  const p = withR2ReloadSemaphore(loader).finally(() => {
    if (INFLIGHT_R2_RELOADS.get(key) === p) INFLIGHT_R2_RELOADS.delete(key);
  });
  INFLIGHT_R2_RELOADS.set(key, p);
  return p;
}

function enforceGlobalCatalogMemoryBudget(protectedCatalogId?: string): void {
  const protectedEntry = protectedCatalogId ? MEMORY_CATALOG_RUNS.get(protectedCatalogId) : undefined;
  const activeUserId = protectedEntry?.userId;

  if (activeUserId) {
    const perUserCachedCap = activeUserId === 'owner' ? MAX_CACHED_CATALOG_RUNS_PER_USER * 2 : MAX_CACHED_CATALOG_RUNS_PER_USER;
    const perUserByteCap = activeUserId === 'owner' ? MAX_GLOBAL_CATALOG_BYTES : MAX_PER_USER_CATALOG_BYTES;
    let userRunCount = 0;
    let userCachedBodyRuns = 0;
    let userBytes = 0;
    for (const v of MEMORY_CATALOG_RUNS.values()) {
      if (v.userId !== activeUserId) continue;
      userRunCount++;
      if (v.records !== null) {
        userCachedBodyRuns++;
        userBytes += v.retainedBytes;
      }
      if (v.hashes !== null) userBytes += v.hashesBytes;
    }
    if (userCachedBodyRuns > perUserCachedCap || userBytes > perUserByteCap) {
      for (const [k, v] of MEMORY_CATALOG_RUNS.entries()) {
        if (k === protectedCatalogId || v.userId !== activeUserId || v.records === null) continue;
        userBytes -= v.retainedBytes;
        userCachedBodyRuns--;
        v.records = null;
        v.retainedBytes = 0;
        if (userCachedBodyRuns <= perUserCachedCap && userBytes <= perUserByteCap) break;
      }
    }
    if (userBytes > perUserByteCap) {
      for (const [k, v] of MEMORY_CATALOG_RUNS.entries()) {
        if (k === protectedCatalogId || v.userId !== activeUserId || v.hashes === null) continue;
        userBytes -= v.hashesBytes;
        v.hashes = null;
        v.hashesBytes = 0;
        if (userBytes <= perUserByteCap) break;
      }
    }
    if (userRunCount > MAX_COMPACT_HISTORY_RUNS_PER_USER) {
      for (const [k, v] of MEMORY_CATALOG_RUNS.entries()) {
        if (k === protectedCatalogId || v.userId !== activeUserId) continue;
        MEMORY_CATALOG_RUNS.delete(k);
        if (--userRunCount <= MAX_COMPACT_HISTORY_RUNS_PER_USER) break;
      }
    }
  }

  let cachedBodyRuns = 0;
  let globalBytes = 0;
  const cachedRunsByUser = new Map<string, number>();
  const bytesByUser = new Map<string, number>();
  for (const v of MEMORY_CATALOG_RUNS.values()) {
    if (v.records !== null) {
      cachedBodyRuns++;
      globalBytes += v.retainedBytes;
      cachedRunsByUser.set(v.userId, (cachedRunsByUser.get(v.userId) ?? 0) + 1);
      bytesByUser.set(v.userId, (bytesByUser.get(v.userId) ?? 0) + v.retainedBytes);
    }
    if (v.hashes !== null) {
      globalBytes += v.hashesBytes;
      bytesByUser.set(v.userId, (bytesByUser.get(v.userId) ?? 0) + v.hashesBytes);
    }
  }
  for (const c of R2_RELOAD_LRU_CACHE.values()) globalBytes += c.bytes;

  if (globalBytes > MAX_GLOBAL_CATALOG_BYTES) {
    for (const [rk, rv] of R2_RELOAD_LRU_CACHE.entries()) {
      globalBytes -= rv.bytes;
      R2_RELOAD_LRU_CACHE.delete(rk);
      if (globalBytes <= MAX_GLOBAL_CATALOG_BYTES) break;
    }
  }

  while (cachedBodyRuns > MAX_CACHED_CATALOG_RUNS || globalBytes > MAX_GLOBAL_CATALOG_BYTES) {
    let heaviestUser: string | null = null;
    let maxUserCached = 1;
    for (const [uid, cnt] of cachedRunsByUser) {
      if (cnt > maxUserCached) {
        maxUserCached = cnt;
        heaviestUser = uid;
      }
    }
    let victimRun: StoredCatalogRun | null = null;
    for (const [k, v] of MEMORY_CATALOG_RUNS.entries()) {
      if (k !== protectedCatalogId && v.records !== null && (heaviestUser === null || v.userId === heaviestUser)) {
        victimRun = v;
        break;
      }
    }
    if (!victimRun) {
      for (const [k, v] of MEMORY_CATALOG_RUNS.entries()) {
        if (k !== protectedCatalogId && v.records !== null) {
          victimRun = v;
          break;
        }
      }
    }
    if (!victimRun) break;
    globalBytes -= victimRun.retainedBytes;
    cachedBodyRuns--;
    cachedRunsByUser.set(victimRun.userId, Math.max(0, (cachedRunsByUser.get(victimRun.userId) ?? 1) - 1));
    bytesByUser.set(victimRun.userId, Math.max(0, (bytesByUser.get(victimRun.userId) ?? 0) - victimRun.retainedBytes));
    victimRun.records = null;
    victimRun.retainedBytes = 0;
  }

  while (globalBytes > MAX_GLOBAL_CATALOG_BYTES) {
    let heaviestByteUser: string | null = null;
    let maxBytes = 0;
    for (const [uid, b] of bytesByUser) {
      if (b > maxBytes) {
        maxBytes = b;
        heaviestByteUser = uid;
      }
    }
    let victimHashRun: StoredCatalogRun | null = null;
    for (const [k, v] of MEMORY_CATALOG_RUNS.entries()) {
      if (k !== protectedCatalogId && v.hashes !== null && (heaviestByteUser === null || v.userId === heaviestByteUser)) {
        victimHashRun = v;
        break;
      }
    }
    if (!victimHashRun) {
      for (const [k, v] of MEMORY_CATALOG_RUNS.entries()) {
        if (k !== protectedCatalogId && v.hashes !== null) {
          victimHashRun = v;
          break;
        }
      }
    }
    if (!victimHashRun) break;
    globalBytes -= victimHashRun.hashesBytes;
    bytesByUser.set(victimHashRun.userId, Math.max(0, (bytesByUser.get(victimHashRun.userId) ?? 0) - victimHashRun.hashesBytes));
    victimHashRun.hashes = null;
    victimHashRun.hashesBytes = 0;
  }

  if (globalBytes > MAX_GLOBAL_CATALOG_BYTES && protectedCatalogId) {
    const prot = MEMORY_CATALOG_RUNS.get(protectedCatalogId);
    if (prot) {
      if (prot.records !== null && prot.summary.artifactId) {
        globalBytes -= prot.retainedBytes;
        prot.records = null;
        prot.retainedBytes = 0;
      }
      if (globalBytes > MAX_GLOBAL_CATALOG_BYTES && prot.hashes !== null) {
        prot.hashes = null;
        prot.hashesBytes = 0;
      }
    }
  }

  while (MEMORY_CATALOG_RUNS.size > MAX_COMPACT_HISTORY_RUNS) {
    const totalByUser = new Map<string, number>();
    for (const v of MEMORY_CATALOG_RUNS.values()) totalByUser.set(v.userId, (totalByUser.get(v.userId) ?? 0) + 1);
    let heaviestUser: string | null = null;
    let heaviestCnt = 1;
    for (const [uid, cnt] of totalByUser) {
      if (cnt > heaviestCnt) {
        heaviestCnt = cnt;
        heaviestUser = uid;
      }
    }
    let victimKey: string | undefined;
    for (const [k, v] of MEMORY_CATALOG_RUNS.entries()) {
      if (k !== protectedCatalogId && (heaviestUser === null || v.userId === heaviestUser)) {
        victimKey = k;
        break;
      }
    }
    if (victimKey === undefined) {
      for (const k of MEMORY_CATALOG_RUNS.keys()) {
        if (k !== protectedCatalogId) {
          victimKey = k;
          break;
        }
      }
    }
    if (victimKey === undefined) break;
    MEMORY_CATALOG_RUNS.delete(victimKey);
  }
}

function rememberRunInMemory(catalogId: string, entry: StoredCatalogRun): void {
  entry.hashesBytes = entry.hashes ? approxHashBundleBytes(entry.hashes) : 0;
  if (MEMORY_CATALOG_RUNS.has(catalogId)) MEMORY_CATALOG_RUNS.delete(catalogId);
  MEMORY_CATALOG_RUNS.set(catalogId, entry);
  enforceGlobalCatalogMemoryBudget(catalogId);
}

function getMetaD1(env?: OptionalStorageBindings & Record<string, unknown>): D1DatabaseLike | null {
  const cand = env?.META as D1DatabaseLike | undefined;
  return cand && typeof cand.prepare === 'function' ? cand : null;
}

function getArtifactsR2(env?: OptionalStorageBindings & Record<string, unknown>): R2BucketLike | null {
  const cand = env?.ARTIFACTS as R2BucketLike | undefined;
  return cand && typeof cand.put === 'function' && typeof cand.get === 'function' ? cand : null;
}

async function ensureCatalogRunsTable(db: D1DatabaseLike): Promise<void> {
  const key = db as unknown as object;
  if (D1_INIT_CACHE.has(key)) return;
  await db
    .prepare(
      `CREATE TABLE IF NOT EXISTS catalog_runs (
        catalog_id TEXT PRIMARY KEY, user_id TEXT NOT NULL DEFAULT 'owner', origin TEXT NOT NULL,
        platform TEXT NOT NULL, collection TEXT NOT NULL DEFAULT '', status TEXT NOT NULL,
        products_count INTEGER NOT NULL DEFAULT 0, variants_count INTEGER NOT NULL DEFAULT 0,
        pages_read INTEGER NOT NULL DEFAULT 0, artifact_id TEXT, hashes_json TEXT,
        summary_json TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
      )`,
    )
    .run();
  await ensureD1ColumnIfMissing({
    db,
    table: 'catalog_runs',
    column: 'user_id',
    alterSql: "ALTER TABLE catalog_runs ADD COLUMN user_id TEXT NOT NULL DEFAULT 'owner'",
  });
  await db.prepare(`CREATE INDEX IF NOT EXISTS idx_catalog_runs_origin_status ON catalog_runs(origin, collection, status, created_at)`).run().catch(() => null);
  await db.prepare(`CREATE INDEX IF NOT EXISTS idx_catalog_runs_user ON catalog_runs(user_id, created_at DESC)`).run().catch(() => null);
  D1_INIT_CACHE.add(key);
}

function parseStoredCatalogSummary(rawJson: string): { summary: CatalogStatusSummary; ownerUserId: string } | null {
  try {
    const parsed = JSON.parse(rawJson) as Record<string, unknown>;
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return null;
    const ownerUserId = typeof parsed._ownerUserId === 'string' && parsed._ownerUserId.trim() ? parsed._ownerUserId.trim() : 'owner';
    const { _ownerUserId: _omitOwner, ...cleanSummary } = parsed;
    return { summary: cleanSummary as unknown as CatalogStatusSummary, ownerUserId };
  } catch {
    return null;
  }
}

async function persistCatalogRun(env: (OptionalStorageBindings & Record<string, unknown>) | undefined, entry: StoredCatalogRun): Promise<void> {
  rememberRunInMemory(entry.summary.catalogId, entry);
  const db = getMetaD1(env);
  if (!db) return;
  try {
    await ensureCatalogRunsTable(db);
    const s = entry.summary;
    const persistedSummaryJson = JSON.stringify({ ...s, _ownerUserId: entry.userId });
    await db
      .prepare(
        `INSERT OR REPLACE INTO catalog_runs (
          catalog_id, user_id, origin, platform, collection, status,
          products_count, variants_count, pages_read, artifact_id,
          hashes_json, summary_json, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .bind(
        s.catalogId,
        entry.userId,
        s.origin,
        s.platform,
        s.collection ?? '',
        s.status,
        s.products,
        s.variants,
        s.pagesRead,
        s.artifactId ?? null,
        entry.hashes ? JSON.stringify(entry.hashes) : null,
        persistedSummaryJson,
        s.createdAt,
        s.updatedAt,
      )
      .run();
  } catch {
    // Non-fatal fallback to in-memory store
  }
}

async function findPreviousCompleteCatalogRun(
  env: (OptionalStorageBindings & Record<string, unknown>) | undefined,
  userId: string,
  origin: string,
  collection: string,
  excludeCatalogId: string,
): Promise<{ productsCount: number; hashes: SnapshotHashBundle | null } | null> {
  const db = getMetaD1(env);
  if (db) {
    try {
      await ensureCatalogRunsTable(db);
      const rowsRes = await db
        .prepare(
          `SELECT catalog_id, user_id, products_count, hashes_json, summary_json FROM catalog_runs
           WHERE user_id = ? AND origin = ? AND collection = ? AND status = 'complete' AND catalog_id != ?
           ORDER BY created_at DESC LIMIT 10`,
        )
        .bind(userId, origin, collection, excludeCatalogId)
        .all<{ catalog_id: string; user_id?: string; products_count: number; hashes_json: string | null; summary_json: string }>();
      for (const row of rowsRes.results ?? []) {
        if (row.user_id && row.user_id !== userId) continue;
        const parsedEntry = parseStoredCatalogSummary(row.summary_json);
        if (parsedEntry && parsedEntry.ownerUserId !== userId) continue;
        if (!parsedEntry && userId !== 'owner') continue;
        if (parsedEntry?.summary.warning === 'shrink') continue;
        let hashes: SnapshotHashBundle | null = null;
        if (row.hashes_json) {
          try {
            hashes = JSON.parse(row.hashes_json) as SnapshotHashBundle;
          } catch {
            hashes = null;
          }
        }
        return { productsCount: Number(row.products_count) || 0, hashes };
      }
    } catch {
      // Fall through to in-memory lookup
    }
  }
  for (const item of [...MEMORY_CATALOG_RUNS.values()].reverse()) {
    if (
      item.userId === userId &&
      item.summary.catalogId !== excludeCatalogId &&
      item.summary.origin === origin &&
      (item.summary.collection ?? '') === collection &&
      item.summary.status === 'complete' &&
      item.summary.warning !== 'shrink'
    ) {
      let hashes = item.hashes;
      if (!hashes && item.hashesArtifactId) {
        const r2 = getArtifactsR2(env);
        if (r2) hashes = await reloadHashBundleFromR2(r2, item.hashesArtifactId);
      }
      return { productsCount: item.summary.products, hashes };
    }
  }
  return null;
}

function decodeBase64Utf8(b64: string): string {
  try {
    const bin = atob(b64);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return new TextDecoder('utf-8', { fatal: false }).decode(bytes);
  } catch {
    return '';
  }
}

function normalizeHubPageResponse(raw: unknown): NormalizedHubPageResponse | null {
  try {
    if (!raw || typeof raw !== 'object') return null;
    const obj = raw as Record<string, unknown>;
    const nestedBody = obj.body && typeof obj.body === 'object' && !Array.isArray(obj.body) ? (obj.body as Record<string, unknown>) : null;
    const firstResult =
      nestedBody && Array.isArray(nestedBody.results) && nestedBody.results[0] && typeof nestedBody.results[0] === 'object'
        ? (nestedBody.results[0] as Record<string, unknown>)
        : Array.isArray(obj.results) && obj.results[0] && typeof obj.results[0] === 'object'
          ? (obj.results[0] as Record<string, unknown>)
          : null;
    const target = firstResult ?? (nestedBody && typeof nestedBody.status === 'number' ? nestedBody : obj);
    const status = typeof target.status === 'number' ? target.status : typeof obj.status === 'number' ? obj.status : 0;
    const outcome = typeof target.outcome === 'string' ? target.outcome : typeof obj.outcome === 'string' ? obj.outcome : undefined;
    const problem = typeof target.problem === 'string' ? target.problem : typeof obj.problem === 'string' ? obj.problem : undefined;
    const rawHeaders = target.headers ?? obj.headers;
    const headers: Record<string, string> = {};
    if (rawHeaders && typeof (rawHeaders as Headers).forEach === 'function') {
      (rawHeaders as Headers).forEach((v, k) => {
        headers[k.toLowerCase()] = v;
      });
    } else if (rawHeaders && typeof rawHeaders === 'object' && !Array.isArray(rawHeaders)) {
      for (const [k, v] of Object.entries(rawHeaders as Record<string, unknown>)) {
        if (typeof v === 'string') headers[k.toLowerCase()] = v;
      }
    }
    let bodyStr = '';
    if (typeof target.body === 'string') {
      bodyStr = target.bodyEncoding === 'base64' ? decodeBase64Utf8(target.body) : target.body;
    } else if (typeof target.rawBody === 'string') {
      bodyStr = target.rawBody;
    } else if (target.body && typeof target.body === 'object') {
      bodyStr = JSON.stringify(target.body);
    }
    const retryAfterMs = typeof target.retryAfterMs === 'number' && Number.isFinite(target.retryAfterMs) ? target.retryAfterMs : undefined;
    const finalUrl = typeof target.finalUrl === 'string' ? target.finalUrl : undefined;
    return {
      status,
      ...(outcome ? { outcome } : {}),
      ...(problem ? { problem } : {}),
      headers,
      body: bodyStr,
      ...(finalUrl ? { finalUrl } : {}),
      ...(retryAfterMs !== undefined ? { retryAfterMs } : {}),
    };
  } catch {
    return null;
  }
}

function generateCatalogId(): string {
  const rand =
    typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function'
      ? crypto.randomUUID().replace(/-/g, '').slice(0, 16)
      : `${Date.now().toString(36)}${Math.random().toString(36).slice(2, 10)}`;
  return `cat_${rand}`;
}

const defaultSleep = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

async function readStreamUtf8Bounded(stream: ReadableStream<Uint8Array>, maxBytes: number): Promise<string> {
  const reader = stream.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    if (value && value.byteLength > 0) {
      total += value.byteLength;
      if (total > maxBytes) {
        await reader.cancel('R2 artifact exceeds decompressed byte limit').catch(() => undefined);
        throw new Error(`Catalog R2 artifact exceeds ${maxBytes} bytes limit`);
      }
      chunks.push(value);
    }
  }
  const merged = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) {
    merged.set(c, off);
    off += c.byteLength;
  }
  return new TextDecoder('utf-8', { fatal: false }).decode(merged);
}

async function readR2ObjectTextBounded(obj: R2ObjectBodyLike, key: string): Promise<string> {
  if (typeof obj.arrayBuffer === 'function') {
    const ab = await obj.arrayBuffer();
    const bytes = new Uint8Array(ab);
    const isGzip = (bytes.byteLength >= 2 && bytes[0] === 0x1f && bytes[1] === 0x8b) || key.endsWith('.gz');
    if (isGzip && typeof DecompressionStream === 'function') {
      const ds = new DecompressionStream('gzip') as unknown as ReadableWritablePair<Uint8Array, Uint8Array>;
      return readStreamUtf8Bounded((new Blob([bytes]).stream() as ReadableStream<Uint8Array>).pipeThrough(ds), MAX_R2_DECOMPRESSED_BYTES);
    }
    if (bytes.byteLength > MAX_R2_DECOMPRESSED_BYTES) throw new Error(`Catalog R2 artifact exceeds ${MAX_R2_DECOMPRESSED_BYTES} bytes limit`);
    return new TextDecoder('utf-8', { fatal: false }).decode(bytes);
  }
  if (obj.body && key.endsWith('.gz') && typeof DecompressionStream === 'function') {
    const ds = new DecompressionStream('gzip') as unknown as ReadableWritablePair<Uint8Array, Uint8Array>;
    return readStreamUtf8Bounded(obj.body.pipeThrough(ds), MAX_R2_DECOMPRESSED_BYTES);
  }
  const txt = await obj.text();
  if (new TextEncoder().encode(txt).byteLength > MAX_R2_DECOMPRESSED_BYTES) {
    throw new Error(`Catalog R2 artifact exceeds ${MAX_R2_DECOMPRESSED_BYTES} bytes limit`);
  }
  return txt;
}

async function reloadCatalogRecordsFromR2(r2: R2BucketLike, artifactId: string): Promise<CatalogRecord[]> {
  const cached = R2_RELOAD_LRU_CACHE.get(artifactId);
  if (cached) {
    R2_RELOAD_LRU_CACHE.delete(artifactId);
    R2_RELOAD_LRU_CACHE.set(artifactId, cached);
    return cached.records;
  }
  return coalesceSingleflightR2Reload(`records:${artifactId}`, async () => {
    const hitAfterWait = R2_RELOAD_LRU_CACHE.get(artifactId);
    if (hitAfterWait) return hitAfterWait.records;
    let loaded: CatalogRecord[] = [];
    let approxBytes = 64;
    try {
      const obj = await r2.get(artifactId);
      if (obj) {
        const ndjson = await readR2ObjectTextBounded(obj, artifactId);
        const parsed = callCoreWasmRaw<{ records: CatalogRecord[]; bytes: number }>('catalog_parse_ndjson', null, ndjson);
        loaded = parsed.records ?? [];
        approxBytes = parsed.bytes ?? 64;
      }
    } catch {
      // ignore R2 read/decompression errors -> return partial/empty cleanly
    }
    if (loaded.length > 0 && approxBytes <= MAX_R2_CACHEABLE_ARTIFACT_BYTES) {
      R2_RELOAD_LRU_CACHE.delete(artifactId);
      R2_RELOAD_LRU_CACHE.set(artifactId, { records: loaded, bytes: approxBytes });
      enforceGlobalCatalogMemoryBudget();
    }
    return loaded;
  });
}

async function reloadHashBundleFromR2(r2: R2BucketLike, hashesArtifactId: string): Promise<SnapshotHashBundle | null> {
  return coalesceSingleflightR2Reload(`hashes:${hashesArtifactId}`, async () => {
    try {
      const obj = await r2.get(hashesArtifactId);
      if (!obj) return null;
      const parsed = JSON.parse(await readR2ObjectTextBounded(obj, hashesArtifactId)) as SnapshotHashBundle;
      if (parsed && typeof parsed === 'object' && parsed.products && parsed.variants) return parsed;
    } catch {
      // ignore
    }
    return null;
  });
}

function awaitWithDeadline<T>(promise: Promise<T>, deadlineAt: number): Promise<{ timedOut: true } | { timedOut: false; value: T }> {
  const rem = deadlineAt - Date.now();
  if (rem <= 0) {
    promise.catch(() => undefined);
    return Promise.resolve({ timedOut: true });
  }
  return new Promise((resolveRace, rejectRace) => {
    let done = false;
    const timer = setTimeout(() => {
      if (!done) {
        done = true;
        resolveRace({ timedOut: true });
      }
    }, rem);
    (timer as unknown as { unref?: () => void }).unref?.();
    promise.then(
      (value) => {
        if (!done) {
          done = true;
          clearTimeout(timer);
          resolveRace({ timedOut: false, value });
        }
      },
      (err) => {
        if (!done) {
          done = true;
          clearTimeout(timer);
          rejectRace(err);
        }
      },
    );
  });
}

export async function getCatalogStatus(params: {
  catalogId: string;
  userId?: string;
  principal?: string;
  env?: OptionalStorageBindings & Record<string, unknown>;
}): Promise<{ status: number; body: Record<string, unknown> }> {
  const catalogId = params.catalogId.trim();
  if (!catalogId) return { status: 400, body: { ok: false, error: 'missing_catalog_id', message: 'Provide `catalogId`.' } };
  if (!VALID_CATALOG_ID_RE.test(catalogId)) return { status: 400, body: { ok: false, error: 'invalid_catalog_id', message: 'Malformed `catalogId`.' } };
  const { ownerKey } = resolveCatalogTenantKey({ userId: params.userId, principal: params.principal });
  const notFound = { status: 404, body: { ok: false, error: 'catalog_not_found', message: `No catalog run found with id "${catalogId}".` } };

  const mem = MEMORY_CATALOG_RUNS.get(catalogId);
  if (mem) return mem.userId !== ownerKey ? notFound : { status: 200, body: { ...mem.summary } };

  const db = getMetaD1(params.env);
  if (db) {
    try {
      await ensureCatalogRunsTable(db);
      const row = await db.prepare(`SELECT user_id, summary_json FROM catalog_runs WHERE catalog_id = ?`).bind(catalogId).first<{ user_id?: string; summary_json: string }>();
      if (row?.summary_json && (!row.user_id || row.user_id === ownerKey)) {
        const parsed = parseStoredCatalogSummary(row.summary_json);
        if (parsed && parsed.ownerUserId === ownerKey) return { status: 200, body: { ...parsed.summary } };
      }
    } catch {
      // ignore
    }
  }
  return notFound;
}

function rememberShopifyOriginCurrency(origin: string, currency: string | null, ttlMs: number, now = Date.now()): void {
  const cleanOrigin = origin.replace(/\/+$/, '');
  if (!SHOPIFY_ORIGIN_CURRENCY_CACHE.has(cleanOrigin) && SHOPIFY_ORIGIN_CURRENCY_CACHE.size >= 256) {
    const oldestKey = SHOPIFY_ORIGIN_CURRENCY_CACHE.keys().next().value;
    if (oldestKey !== undefined) SHOPIFY_ORIGIN_CURRENCY_CACHE.delete(oldestKey);
  }
  SHOPIFY_ORIGIN_CURRENCY_CACHE.set(cleanOrigin, { currency, expiresAt: now + ttlMs });
}

async function resolveShopifyOriginCurrency(
  origin: string,
  executeHubFetch: CatalogHubFetchFn,
  timeoutMs = 3_500,
  options?: {
    cacheNegative?: boolean;
    deadlineAt?: number;
    target?: unknown;
    site?: unknown;
    tracer?: RequestTracer | TraceContext;
  },
): Promise<string | null> {
  const cleanOrigin = origin.replace(/\/+$/, '');
  const now = Date.now();
  const cached = SHOPIFY_ORIGIN_CURRENCY_CACHE.get(cleanOrigin);
  if (cached && now < cached.expiresAt) return cached.currency;

  const activeTracer = getActiveRequestTracer(options?.tracer);
  for (const probePath of ['/meta.json', '/cart.js']) {
    const probeNow = Date.now();
    const remGlobalMs = options?.deadlineAt !== undefined ? options.deadlineAt - probeNow : timeoutMs;
    if (remGlobalMs < 250) break;
    const perProbeMs = Math.max(250, Math.min(timeoutMs, remGlobalMs));
    try {
      const callProbe = () =>
        executeHubFetch({
          url: `${cleanOrigin}${probePath}`,
          kind: 'json',
          accept: 'application/json',
          maxBytes: 65_536,
          timeoutMs: perProbeMs,
          ...(options?.target !== undefined ? { target: options.target } : {}),
          ...(options?.site !== undefined ? { site: options.site } : {}),
          ...(activeTracer ? { tracer: activeTracer } : {}),
        });
      const probeRace = await awaitWithDeadline(
        Promise.resolve().then(() => (activeTracer ? activeTracer.run(callProbe) : callProbe())),
        probeNow + perProbeMs,
      );
      if (probeRace.timedOut) continue;
      const normCurr = normalizeHubPageResponse(probeRace.value);
      if (normCurr && normCurr.status === 200 && normCurr.body) {
        const cand = callCoreWasmRaw<{ currency: string | null }>('catalog_parse_currency_probe', null, normCurr.body).currency ?? null;
        if (cand) {
          rememberShopifyOriginCurrency(cleanOrigin, cand, SHOPIFY_ORIGIN_CURRENCY_TTL_MS);
          return cand;
        }
      }
    } catch {
      // ignore failed probe
    }
  }
  if (options?.cacheNegative !== false) {
    rememberShopifyOriginCurrency(cleanOrigin, null, 5 * 60_000);
  }
  return null;
}

async function resolveOriginUcpFromRobots(
  origin: string,
  executeHubFetch: CatalogHubFetchFn,
  timeoutMs = 4_000,
  options?: {
    deadlineAt?: number;
    target?: unknown;
    site?: unknown;
    tracer?: RequestTracer | TraceContext;
  },
): Promise<CatalogUcpMetadata | undefined> {
  const cleanOrigin = origin.replace(/\/+$/, '');
  const now = Date.now();
  const cached = ORIGIN_UCP_CACHE.get(cleanOrigin);
  if (cached && now < cached.expiresAt) return cached.ucp ?? undefined;

  const remGlobalMs = options?.deadlineAt !== undefined ? options.deadlineAt - now : timeoutMs;
  if (remGlobalMs < 250) return undefined;
  const perProbeMs = Math.max(250, Math.min(timeoutMs, remGlobalMs));
  const activeTracer = getActiveRequestTracer(options?.tracer);
  try {
    const callRobotsCheck = () =>
      executeHubFetch({
        url: `${cleanOrigin}/robots.txt`,
        kind: 'text',
        accept: 'text/plain',
        timeoutMs: perProbeMs,
        ...(options?.target !== undefined ? { target: options.target } : {}),
        ...(options?.site !== undefined ? { site: options.site } : {}),
        ...(activeTracer ? { tracer: activeTracer } : {}),
      });
    const ucpRace = await awaitWithDeadline(
      Promise.resolve().then(() => (activeTracer ? activeTracer.run(callRobotsCheck) : callRobotsCheck())),
      now + perProbeMs,
    );
    if (!ucpRace.timedOut) {
      const normRobots = normalizeHubPageResponse(ucpRace.value);
      if (normRobots && normRobots.status === 200) {
        const found = normRobots.body ? discoverUcpEndpointFromRobots(cleanOrigin, normRobots.body) : null;
        if (!ORIGIN_UCP_CACHE.has(cleanOrigin) && ORIGIN_UCP_CACHE.size >= 256) {
          const oldestKey = ORIGIN_UCP_CACHE.keys().next().value;
          if (oldestKey !== undefined) ORIGIN_UCP_CACHE.delete(oldestKey);
        }
        ORIGIN_UCP_CACHE.set(cleanOrigin, { ucp: found, expiresAt: Date.now() + ORIGIN_UCP_TTL_MS });
        return found ?? undefined;
      }
    }
  } catch {
    // ignore failed UCP probe
  }
  return undefined;
}

function toStringArrayFilter(v?: string | string[]): string[] {
  if (Array.isArray(v)) return v.filter((s): s is string => typeof s === 'string');
  return typeof v === 'string' && v.trim() ? [v] : [];
}

export async function getCatalogRecords(params: {
  catalogId: string;
  userId?: string;
  principal?: string;
  offset?: number;
  cursor?: string;
  limit?: number;
  vendor?: string | string[];
  productType?: string | string[];
  tag?: string | string[];
  availableOnly?: boolean;
  inStockOnly?: boolean;
  minPrice?: number;
  maxPrice?: number;
  query?: string;
  fields?: 'full' | 'lean';
  env?: OptionalStorageBindings & Record<string, unknown>;
  executeHubFetch?: CatalogHubFetchFn;
}): Promise<{ status: number; body: Record<string, unknown> }> {
  const catalogId = params.catalogId.trim();
  if (!catalogId) return { status: 400, body: { ok: false, error: 'missing_catalog_id', message: 'Provide `catalogId`.' } };
  if (!VALID_CATALOG_ID_RE.test(catalogId)) return { status: 400, body: { ok: false, error: 'invalid_catalog_id', message: 'Malformed `catalogId`.' } };
  const { ownerKey } = resolveCatalogTenantKey({ userId: params.userId, principal: params.principal });
  const notFound = { status: 404, body: { ok: false, error: 'catalog_not_found', message: `No catalog run found with id "${catalogId}".` } };

  let summary: CatalogStatusSummary | null = null;
  let records: CatalogRecord[] | null = null;
  const mem = MEMORY_CATALOG_RUNS.get(catalogId);
  if (mem) {
    if (mem.userId !== ownerKey) return notFound;
    summary = mem.summary;
    records = mem.records;
  }

  const db = getMetaD1(params.env);
  if (!summary && db) {
    try {
      await ensureCatalogRunsTable(db);
      const row = await db.prepare(`SELECT user_id, summary_json FROM catalog_runs WHERE catalog_id = ?`).bind(catalogId).first<{ user_id?: string; summary_json: string }>();
      if (row?.summary_json && (!row.user_id || row.user_id === ownerKey)) {
        const parsed = parseStoredCatalogSummary(row.summary_json);
        if (parsed && parsed.ownerUserId === ownerKey) summary = parsed.summary;
      }
    } catch {
      // ignore
    }
  }
  if (!summary) return notFound;
  if (!records) {
    const r2 = getArtifactsR2(params.env);
    records = r2 && summary.artifactId ? await reloadCatalogRecordsFromR2(r2, summary.artifactId) : [];
  }

  const effectiveFields = params.fields ?? summary.fields ?? 'full';
  const baseFilter = {
    platform: summary.platform,
    offset: typeof params.offset === 'number' && Number.isFinite(params.offset) ? Math.max(0, Math.floor(params.offset)) : 0,
    ...(typeof params.cursor === 'string' && params.cursor.trim() ? { cursor: params.cursor.trim() } : {}),
    limit: typeof params.limit === 'number' && Number.isFinite(params.limit) ? Math.min(250, Math.max(1, Math.floor(params.limit))) : 50,
    vendors: toStringArrayFilter(params.vendor),
    productTypes: toStringArrayFilter(params.productType),
    tags: toStringArrayFilter(params.tag),
    availableOnly: params.availableOnly === true,
    inStockOnly: params.inStockOnly === true,
    ...(typeof params.minPrice === 'number' && Number.isFinite(params.minPrice) ? { minPrice: params.minPrice } : {}),
    ...(typeof params.maxPrice === 'number' && Number.isFinite(params.maxPrice) ? { maxPrice: params.maxPrice } : {}),
    query: typeof params.query === 'string' ? params.query : '',
    fields: effectiveFields,
  };

  type FilterOut = {
    totalProducts: number;
    matchedProducts: number;
    offset: number;
    limit: number;
    returned: number;
    hasMore: boolean;
    needsShopifyCurrency?: boolean;
    fullRecords?: CatalogRecord[];
    leanRecords?: Array<Record<string, unknown>>;
  };
  let filteredOut = callCoreWasm<FilterOut>('catalog_filter_records', { records, filter: baseFilter });
  if (filteredOut.needsShopifyCurrency && summary.origin && params.executeHubFetch) {
    const fallbackCurrency = await resolveShopifyOriginCurrency(summary.origin, params.executeHubFetch);
    if (fallbackCurrency) {
      filteredOut = callCoreWasm<FilterOut>('catalog_filter_records', { records, filter: { ...baseFilter, fallbackCurrency } });
    } else if (effectiveFields === 'lean' && filteredOut.fullRecords) {
      filteredOut.leanRecords = filteredOut.fullRecords.map(projectLeanCatalogRecord);
    }
  }

  const result: CatalogRecordsResult = {
    ok: true,
    catalogId,
    status: summary.status,
    platform: summary.platform,
    origin: summary.origin,
    totalProducts: filteredOut.totalProducts,
    matchedProducts: filteredOut.matchedProducts,
    offset: filteredOut.offset,
    limit: filteredOut.limit,
    returned: filteredOut.returned,
    hasMore: filteredOut.hasMore,
    records: effectiveFields === 'lean' ? (filteredOut.leanRecords ?? []) : (filteredOut.fullRecords ?? []),
  };
  return { status: 200, body: result as unknown as Record<string, unknown> };
}

export async function executeCatalogCall(params: {
  payload: CatalogCallPayload;
  env?: OptionalStorageBindings & Record<string, unknown>;
  executeHubFetch: CatalogHubFetchFn;
  selfHost?: string;
  principal?: string;
  userId?: string;
  devTelemetrySetting?: string | boolean | null | (() => Promise<string | boolean | null>);
  ctx?: { waitUntil?: (promise: Promise<unknown>) => void };
  sleepFn?: (ms: number) => Promise<void>;
  tracer?: RequestTracer | TraceContext;
  maxWallMs?: number;
}): Promise<{ status: number; body: Record<string, unknown> }> {
  const { payload, env, executeHubFetch } = params;
  const activeTracer = getActiveRequestTracer(params.tracer);
  const sleep = params.sleepFn ?? defaultSleep;

  const existingId =
    typeof payload.catalogId === 'string' && payload.catalogId.trim()
      ? payload.catalogId.trim()
      : typeof payload.catalogJobId === 'string' && payload.catalogJobId.trim()
        ? payload.catalogJobId.trim()
        : '';

  if (existingId && !payload.url) {
    const wantsRecords =
      payload.offset !== undefined ||
      payload.cursor !== undefined ||
      payload.limit !== undefined ||
      payload.vendor !== undefined ||
      payload.productType !== undefined ||
      payload.tag !== undefined ||
      payload.availableOnly !== undefined ||
      payload.inStockOnly !== undefined ||
      payload.minPrice !== undefined ||
      payload.maxPrice !== undefined ||
      payload.query !== undefined ||
      payload.fields === 'lean' ||
      payload.fields === 'full';
    if (wantsRecords) {
      return getCatalogRecords({
        catalogId: existingId,
        userId: params.userId,
        principal: params.principal,
        offset: typeof payload.offset === 'number' ? payload.offset : undefined,
        cursor: typeof payload.cursor === 'string' ? payload.cursor : undefined,
        limit: typeof payload.limit === 'number' ? payload.limit : undefined,
        vendor: typeof payload.vendor === 'string' || Array.isArray(payload.vendor) ? (payload.vendor as string | string[]) : undefined,
        productType: typeof payload.productType === 'string' || Array.isArray(payload.productType) ? (payload.productType as string | string[]) : undefined,
        tag: typeof payload.tag === 'string' || Array.isArray(payload.tag) ? (payload.tag as string | string[]) : undefined,
        availableOnly: payload.availableOnly === true,
        inStockOnly: payload.inStockOnly === true,
        minPrice: typeof payload.minPrice === 'number' ? payload.minPrice : undefined,
        maxPrice: typeof payload.maxPrice === 'number' ? payload.maxPrice : undefined,
        query: typeof payload.query === 'string' ? payload.query : undefined,
        fields: payload.fields === 'lean' ? 'lean' : payload.fields === 'full' ? 'full' : undefined,
        env,
        executeHubFetch,
      });
    }
    return getCatalogStatus({ catalogId: existingId, userId: params.userId, principal: params.principal, env });
  }

  const shopAdapter = getCatalogAdapter('shopify');
  const wcAdapter = getCatalogAdapter('woocommerce');
  const scopeObj = payload.scope && typeof payload.scope === 'object' ? (payload.scope as Record<string, unknown>) : undefined;
  const reqPause = typeof payload.pauseMs === 'number' && Number.isFinite(payload.pauseMs) ? Math.floor(payload.pauseMs) : undefined;
  const reqMaxPages = typeof payload.maxPages === 'number' && Number.isFinite(payload.maxPages) ? Math.floor(payload.maxPages) : undefined;

  const initRes = callCoreWasm<{
    ok: boolean;
    error?: string;
    message?: string;
    plan?: {
      origin: string;
      originWithCollection: string;
      collection?: string;
      fields: 'full' | 'lean';
      rawPlatform: string;
      initialPlatform: string;
      effectivePauseMs: number;
      maxPages: number;
      callerExplicitMaxPages: boolean;
      firstPageUrl: string;
    };
  }>('catalog_init_pull', {
    url: typeof payload.url === 'string' ? payload.url : '',
    platform: typeof payload.platform === 'string' ? payload.platform : 'auto',
    collection: typeof payload.collection === 'string' ? payload.collection : '',
    scopeCollection: typeof scopeObj?.collection === 'string' ? scopeObj.collection : '',
    fields: payload.fields === 'lean' ? 'lean' : 'full',
    ...(reqMaxPages !== undefined ? { maxPages: reqMaxPages } : {}),
    ...(reqPause !== undefined ? { pauseMs: reqPause } : {}),
    selfHost: params.selfHost ?? '',
    shopifyPauseMs: shopAdapter?.catalog?.pauseMs ?? 2000,
    shopifyPageCap: shopAdapter?.catalog?.pageCap ?? 200,
    wooPauseMs: wcAdapter?.catalog?.pauseMs ?? 1000,
    wooPageCap: wcAdapter?.catalog?.pageCap ?? 200,
  });

  if (!initRes.ok || !initRes.plan) {
    return { status: 400, body: { ok: false, error: initRes.error || 'invalid_url', message: initRes.message || 'Invalid catalog request.' } };
  }
  const plan = initRes.plan;
  const initialAdapter = getCatalogAdapter(plan.initialPlatform);
  if (!initialAdapter?.catalog) {
    return { status: 500, body: { ok: false, error: 'missing_catalog_adapter', message: `Catalog adapter "${plan.initialPlatform}" is not registered.` } };
  }

  const { ownerKey, concurrencyBucketKey, isOwner } = resolveCatalogTenantKey({ userId: params.userId, principal: params.principal });
  const activeForPrincipal = ACTIVE_CATALOG_BY_PRINCIPAL.get(concurrencyBucketKey) ?? 0;
  const nonOwnerPoolFull = !isOwner && activeCatalogNonOwnerGlobal >= MAX_CONCURRENT_CATALOG_NON_OWNER_GLOBAL;
  if (activeCatalogGlobal >= MAX_CONCURRENT_CATALOG_GLOBAL || nonOwnerPoolFull || activeForPrincipal >= MAX_CONCURRENT_CATALOG_PER_PRINCIPAL) {
    return {
      status: 429,
      body: { ok: false, error: 'catalog_busy', message: 'Too many concurrent catalog pulls are active. Wait for an active run to finish or poll its catalogId.' },
    };
  }
  activeCatalogGlobal++;
  if (!isOwner) activeCatalogNonOwnerGlobal++;
  ACTIVE_CATALOG_BY_PRINCIPAL.set(concurrencyBucketKey, activeForPrincipal + 1);
  let releasedConcurrencySlot = false;
  const releaseConcurrencySlot = () => {
    if (releasedConcurrencySlot) return;
    releasedConcurrencySlot = true;
    activeCatalogGlobal = Math.max(0, activeCatalogGlobal - 1);
    if (!isOwner) activeCatalogNonOwnerGlobal = Math.max(0, activeCatalogNonOwnerGlobal - 1);
    const curCount = ACTIVE_CATALOG_BY_PRINCIPAL.get(concurrencyBucketKey) ?? 0;
    if (curCount <= 1) ACTIVE_CATALOG_BY_PRINCIPAL.delete(concurrencyBucketKey);
    else ACTIVE_CATALOG_BY_PRINCIPAL.set(concurrencyBucketKey, curCount - 1);
  };

  const wantAsync = payload.sync === false && typeof params.ctx?.waitUntil === 'function';
  let activeSpec: CatalogSpec = initialAdapter.catalog;
  if (!wantAsync || plan.rawPlatform !== 'auto' || plan.initialPlatform === 'woocommerce') {
    activeTracer?.setAttribute('edgefetch.adapter_id', activeSpec.platform);
  }
  activeTracer?.setAttribute('edgefetch.catalog.sync', payload.sync !== false);

  let effectivePauseMs = plan.effectivePauseMs;
  const maxPages = plan.maxPages;
  const collection = plan.collection ?? '';
  const catalogId = generateCatalogId();
  const startedAtMs = Date.now();
  const effectiveMaxWallMs =
    typeof params.maxWallMs === 'number' && Number.isFinite(params.maxWallMs) && params.maxWallMs > 0
      ? Math.min(MAX_CATALOG_WALL_MS, Math.floor(params.maxWallMs))
      : MAX_CATALOG_WALL_MS;
  const syncDeadlineAt = startedAtMs + effectiveMaxWallMs;
  const createdAt = new Date(startedAtMs).toISOString();

  const currentEntry: StoredCatalogRun = {
    userId: ownerKey,
    summary: {
      ok: true,
      catalogId,
      status: 'running',
      platform: activeSpec.platform,
      origin: plan.origin,
      ...(collection ? { collection } : {}),
      ...(plan.fields === 'lean' ? { fields: 'lean' } : {}),
      products: 0,
      variants: 0,
      pages: 0,
      pagesRead: 0,
      pauseMs: effectivePauseMs,
      durationMs: 0,
      createdAt,
      updatedAt: createdAt,
    },
    hashes: { products: {}, variants: {} },
    hashesBytes: 64,
    records: [],
    retainedBytes: 0,
  };
  await persistCatalogRun(env, currentEntry);

  const runPull = async (pullTracer?: RequestTracer | TraceContext): Promise<CatalogStatusSummary> => {
    const resolvedPullTracer = getActiveRequestTracer(pullTracer);
    try {
      const byProductId = new Map<string, CatalogRecord>();
      const bytesByProductId = new Map<string, number>();
      let accumulatedBytes = 0;
      let totalVariantsCount = 0;
      let totalSleptMs = 0;
      let truncatedByBudget = false;
      let pagesRead = 0;
      let naturalCompletion = false;
      let finalStatus: CatalogRunStatus = 'partial';
      let stopReason: string | undefined;
      let blockedInfo: BlockedSuggestion | undefined;
      let currentUrl: string | null = plan.firstPageUrl;
      let triedAutoFallbackToWc = plan.rawPlatform !== 'auto' || activeSpec.platform === 'woocommerce';
      let autoFallbackFromShopify = false;
      let resolvedPlatformOut: string = activeSpec.platform;

      while (currentUrl && pagesRead < maxPages) {
        if (Date.now() >= syncDeadlineAt) {
          stopReason = 'time_budget_exceeded';
          truncatedByBudget = true;
          break;
        }
        if (pagesRead > 0) {
          if (totalSleptMs + effectivePauseMs > MAX_CATALOG_TOTAL_SLEEP_MS) {
            stopReason = 'sleep_budget_exceeded';
            truncatedByBudget = true;
            break;
          }
          if (Date.now() + effectivePauseMs >= syncDeadlineAt) {
            stopReason = 'time_budget_exceeded';
            truncatedByBudget = true;
            break;
          }
          totalSleptMs += effectivePauseMs;
          const sleepOut = await awaitWithDeadline(sleep(effectivePauseMs), syncDeadlineAt);
          if (sleepOut.timedOut || Date.now() >= syncDeadlineAt) {
            stopReason = 'time_budget_exceeded';
            truncatedByBudget = true;
            break;
          }
        }

        type CatalogPageEvalResult = {
          action: 'parsed' | 'cooldown' | 'fallback_wc' | 'halt';
          stopReason?: string;
          blockKind?: string;
          challenged?: boolean;
          unsupportedStore?: boolean;
          waitMs?: number;
          newPauseMs?: number;
          nextUrl?: string;
          done?: boolean;
          items?: Array<{ key: string; record: CatalogRecord; footprintBytes: number }>;
        };
        let strikes = 0;
        let evalOut: CatalogPageEvalResult | null = null;

        while (true) {
          const remBeforeFetchMs = syncDeadlineAt - Date.now();
          if (remBeforeFetchMs <= 0) {
            stopReason = 'time_budget_exceeded';
            truncatedByBudget = true;
            evalOut = null;
            break;
          }
          const callFetchPage = () =>
            executeHubFetch({
              url: currentUrl!,
              kind: 'json',
              accept: 'application/json',
              maxBytes: 16_777_216,
              timeoutMs: Math.min(30_000, remBeforeFetchMs),
              ...(payload.target !== undefined ? { target: payload.target } : {}),
              ...(payload.site !== undefined ? { site: payload.site } : {}),
              ...(resolvedPullTracer ? { tracer: resolvedPullTracer } : {}),
            });
          const fetchPromise = Promise.resolve()
            .then(() => (resolvedPullTracer ? resolvedPullTracer.run(callFetchPage) : callFetchPage()))
            .catch((err: unknown) => ({
              status: 0,
              outcome: 'network_error',
              problem: err instanceof Error ? err.message : String(err),
              headers: {},
              body: '',
            }));
          const fetchRace = await awaitWithDeadline(fetchPromise, syncDeadlineAt);
          if (fetchRace.timedOut) {
            stopReason = 'time_budget_exceeded';
            truncatedByBudget = true;
            evalOut = null;
            break;
          }
          const pageResp = normalizeHubPageResponse(fetchRace.value);
          if (!pageResp) {
            stopReason = strikes > 0 ? 'rate_limited' : 'empty_response';
            evalOut = null;
            break;
          }

          evalOut = callCoreWasmRaw<CatalogPageEvalResult>(
            'catalog_evaluate_page',
            {
              currentUrl,
              originWithCollection: plan.originWithCollection,
              collection,
              selfHost: params.selfHost ?? '',
              platform: activeSpec.platform,
              fields: plan.fields,
              pagesRead,
              triedAutoFallbackToWc,
              autoFallbackFromShopify,
              ...(reqPause !== undefined ? { reqPauseMs: reqPause } : {}),
              catalogCfg: { platform: activeSpec.platform, pauseMs: activeSpec.pauseMs, pageCap: activeSpec.pageCap },
              wooCatalogCfg: { platform: 'woocommerce', pauseMs: wcAdapter?.catalog?.pauseMs ?? 1000, pageCap: wcAdapter?.catalog?.pageCap ?? 200 },
              status: pageResp.status,
              outcome: pageResp.outcome ?? '',
              problem: pageResp.problem ?? '',
              headers: pageResp.headers,
              finalUrl: pageResp.finalUrl ?? '',
              ...(pageResp.retryAfterMs !== undefined ? { retryAfterMs: pageResp.retryAfterMs } : {}),
              nowMs: Date.now(),
            },
            pageResp.body,
          );

          if (evalOut.action === 'cooldown') {
            if (++strikes > 3) {
              stopReason = 'rate_limited';
              evalOut = null;
              break;
            }
            const waitMs = evalOut.waitMs ?? 30_000;
            if (totalSleptMs + waitMs > MAX_CATALOG_TOTAL_SLEEP_MS) {
              stopReason = 'sleep_budget_exceeded';
              truncatedByBudget = true;
              evalOut = null;
              break;
            }
            if (Date.now() + waitMs >= syncDeadlineAt) {
              stopReason = waitMs > MAX_CATALOG_TOTAL_SLEEP_MS ? 'sleep_budget_exceeded' : 'time_budget_exceeded';
              truncatedByBudget = true;
              evalOut = null;
              break;
            }
            totalSleptMs += waitMs;
            currentEntry.summary = {
              ...currentEntry.summary,
              status: 'cooling_down',
              resumeAt: new Date(Date.now() + waitMs).toISOString(),
              pages: pagesRead,
              pagesRead,
              durationMs: Date.now() - startedAtMs,
              updatedAt: new Date().toISOString(),
            };
            await persistCatalogRun(env, currentEntry);
            const coolSleep = await awaitWithDeadline(sleep(waitMs), syncDeadlineAt);
            if (coolSleep.timedOut || Date.now() >= syncDeadlineAt) {
              stopReason = 'time_budget_exceeded';
              truncatedByBudget = true;
              evalOut = null;
              break;
            }
            const { resumeAt: _cleared, ...restSummary } = currentEntry.summary;
            currentEntry.summary = { ...restSummary, status: 'running', updatedAt: new Date().toISOString() };
            await persistCatalogRun(env, currentEntry);
            continue;
          }

          if (evalOut.action === 'halt') {
            stopReason = evalOut.stopReason;
            if (evalOut.blockKind) {
              blockedInfo = buildBlockedInfo(currentUrl, pageResp.outcome ?? evalOut.blockKind, pageResp.problem, pageResp.status) ?? undefined;
            } else if (evalOut.challenged) {
              finalStatus = 'challenged';
              if (evalOut.stopReason === 'challenge') {
                blockedInfo = buildBlockedInfo(currentUrl, 'challenge', pageResp.problem || 'anti-bot challenge', pageResp.status) ?? undefined;
              }
            }
            if (evalOut.unsupportedStore) {
              resolvedPlatformOut = 'unknown';
              currentEntry.summary.platform = 'unknown';
              resolvedPullTracer?.setAttribute('edgefetch.adapter_id', 'unknown');
            }
            evalOut = null;
          }
          break;
        }

        if (!evalOut) break;
        if (evalOut.action === 'fallback_wc' && wcAdapter?.catalog && evalOut.nextUrl) {
          triedAutoFallbackToWc = true;
          autoFallbackFromShopify = true;
          activeSpec = wcAdapter.catalog;
          resolvedPlatformOut = activeSpec.platform;
          resolvedPullTracer?.setAttribute('edgefetch.adapter_id', activeSpec.platform);
          effectivePauseMs = evalOut.newPauseMs ?? effectivePauseMs;
          currentEntry.summary.platform = activeSpec.platform;
          currentEntry.summary.pauseMs = effectivePauseMs;
          currentUrl = evalOut.nextUrl;
          continue;
        }

        pagesRead++;
        let hitByteBudget = false;
        for (const item of evalOut.items ?? []) {
          const prevRec = byProductId.get(item.key);
          const prevVariants = prevRec ? prevRec.variants.length : 0;
          const prevBytes = bytesByProductId.get(item.key) ?? 0;
          if (
            accumulatedBytes - prevBytes + item.footprintBytes > MAX_CATALOG_IN_MEMORY_BYTES ||
            totalVariantsCount - prevVariants + item.record.variants.length > MAX_VARIANTS_PER_CATALOG_RUN
          ) {
            hitByteBudget = true;
            truncatedByBudget = true;
            stopReason = 'byte_budget';
            break;
          }
          accumulatedBytes = accumulatedBytes - prevBytes + item.footprintBytes;
          totalVariantsCount = totalVariantsCount - prevVariants + item.record.variants.length;
          bytesByProductId.set(item.key, item.footprintBytes);
          byProductId.set(item.key, item.record);
        }

        const currentRecords = [...byProductId.values()];
        currentEntry.records = currentRecords;
        currentEntry.retainedBytes = accumulatedBytes;
        currentEntry.summary = {
          ...currentEntry.summary,
          products: currentRecords.length,
          variants: totalVariantsCount,
          pages: pagesRead,
          pagesRead,
          durationMs: Date.now() - startedAtMs,
          updatedAt: new Date().toISOString(),
        };
        await persistCatalogRun(env, currentEntry);

        if (hitByteBudget) break;
        if (Date.now() >= syncDeadlineAt) {
          stopReason = 'time_budget_exceeded';
          truncatedByBudget = true;
          break;
        }
        if (evalOut.done || !evalOut.nextUrl) {
          naturalCompletion = true;
          break;
        }
        if (pagesRead >= maxPages) {
          stopReason = 'max_pages_reached';
          break;
        }
        currentUrl = evalOut.nextUrl;
      }

      if (finalStatus !== 'challenged') {
        if (naturalCompletion) finalStatus = 'complete';
        else {
          finalStatus = 'partial';
          if (!stopReason) stopReason = 'incomplete_pagination';
        }
      }

      const rawFinalRecords = [...byProductId.values()];
      const hasNullShopifyVariantCurrency =
        activeSpec.platform === 'shopify' && rawFinalRecords.some((rec) => rec.variants.some((v) => !v.currency));
      const wantCurrencyProbe = hasNullShopifyVariantCurrency && !truncatedByBudget && syncDeadlineAt - Date.now() >= 1_500;
      const wantUcpProbe = (finalStatus === 'complete' || pagesRead > 0) && !truncatedByBudget && syncDeadlineAt - Date.now() >= 1_000;

      const [resolvedCurr, ucpMeta] = await Promise.all([
        wantCurrencyProbe
          ? resolveShopifyOriginCurrency(plan.origin, executeHubFetch, 3_500, {
              cacheNegative: false,
              deadlineAt: syncDeadlineAt,
              ...(payload.target !== undefined ? { target: payload.target } : {}),
              ...(payload.site !== undefined ? { site: payload.site } : {}),
              ...(resolvedPullTracer ? { tracer: resolvedPullTracer } : {}),
            })
          : Promise.resolve<string | null>(null),
        wantUcpProbe
          ? resolveOriginUcpFromRobots(plan.origin, executeHubFetch, 4_000, {
              deadlineAt: syncDeadlineAt,
              ...(payload.target !== undefined ? { target: payload.target } : {}),
              ...(payload.site !== undefined ? { site: payload.site } : {}),
              ...(resolvedPullTracer ? { tracer: resolvedPullTracer } : {}),
            })
          : Promise.resolve<CatalogUcpMetadata | undefined>(undefined),
      ]);
      const detectedCurrency = resolvedCurr ?? '';

      const prevRun = await findPreviousCompleteCatalogRun(env, ownerKey, plan.origin, collection, catalogId);
      const r2 = getArtifactsR2(env);
      const finalized = callCoreWasm<{
        records: CatalogRecord[];
        totalVariants: number;
        hashes: SnapshotHashBundle;
        hashesBytes: number;
        diff: CatalogSnapshotDiff | null;
        ndjson: string;
        warning?: 'shrink';
        previousProducts?: number;
      }>('catalog_finalize_pull', {
        records: rawFinalRecords,
        detectedCurrency,
        ...(prevRun ? { prevProducts: prevRun.productsCount, prevHashes: prevRun.hashes } : {}),
        isComplete: finalStatus === 'complete',
        buildNdjson: Boolean(r2 && rawFinalRecords.length > 0),
      });

      let artifactId: string | undefined;
      let hashesArtifactId: string | undefined;
      const r2Prefix = ownerKey !== 'owner' && ownerKey !== 'anonymous' ? `private/${sanitizeStorageUserId(ownerKey)}/catalog` : 'catalog';
      if (r2 && finalized.records.length > 0) {
        const key = `${r2Prefix}/${catalogId}.ndjson`;
        await r2
          .put(key, finalized.ndjson, { httpMetadata: { contentType: 'application/x-ndjson; charset=utf-8' } })
          .then(() => {
            artifactId = key;
          })
          .catch(() => undefined);
        const hashesKey = `${r2Prefix}/${catalogId}.hashes.json`;
        await r2
          .put(hashesKey, JSON.stringify(finalized.hashes), { httpMetadata: { contentType: 'application/json; charset=utf-8' } })
          .then(() => {
            hashesArtifactId = hashesKey;
          })
          .catch(() => undefined);
      }

      const finishedNow = new Date().toISOString();
      const { resumeAt: _dropResume, ...cleanBase } = currentEntry.summary;
      const callerCappedSuccess = plan.callerExplicitMaxPages && stopReason === 'max_pages_reached' && finalized.records.length > 0;
      const finalSummary: CatalogStatusSummary = {
        ...cleanBase,
        ok: finalStatus === 'complete' || callerCappedSuccess,
        status: finalStatus,
        platform: resolvedPlatformOut,
        products: finalized.records.length,
        variants: finalized.totalVariants,
        pages: pagesRead,
        pagesRead,
        pauseMs: effectivePauseMs,
        durationMs: Date.now() - startedAtMs,
        ...(truncatedByBudget || stopReason === 'max_pages_reached' ? { truncated: true } : {}),
        ...(stopReason ? { reason: stopReason } : {}),
        ...(finalized.warning ? { warning: finalized.warning, previousProducts: finalized.previousProducts } : {}),
        ...(artifactId ? { artifactId } : {}),
        diff: finalized.diff ?? null,
        ...(ucpMeta ? { ucp: ucpMeta } : {}),
        ...(blockedInfo ? { blocked: blockedInfo } : {}),
        updatedAt: finishedNow,
      };

      currentEntry.summary = finalSummary;
      currentEntry.hashes = finalized.hashes;
      currentEntry.hashesBytes = finalized.hashesBytes;
      if (hashesArtifactId) currentEntry.hashesArtifactId = hashesArtifactId;
      currentEntry.records = artifactId ? null : finalized.records;
      currentEntry.retainedBytes = artifactId ? 0 : accumulatedBytes;
      await persistCatalogRun(env, currentEntry);
      resolvedPullTracer?.setAttribute('edgefetch.catalog.status', finalStatus);
      resolvedPullTracer?.setAttribute('edgefetch.catalog.pages_read', pagesRead);
      resolvedPullTracer?.setAttribute('edgefetch.catalog.products', finalized.records.length);
      return finalSummary;
    } finally {
      releaseConcurrencySlot();
    }
  };

  if (wantAsync) {
    const runWithTrace = () => {
      const execPull = () =>
        activeTracer
          ? activeTracer.withSpan(
              'edgefetch.catalog.run',
              { kind: 1, attributes: { 'edgefetch.adapter_id': activeSpec.platform, 'edgefetch.catalog.sync': false } },
              (_runSpan, runTracer) => runPull(runTracer),
            )
          : runPull();
      return execPull().finally(async () => {
        if (activeTracer && env) {
          const otelEnv = env as OtelEnvConfig & { SAFE_FETCH?: typeof fetch; SAFE_PUBLIC_FETCH?: typeof fetch };
          const resolvedDevTel =
            typeof params.devTelemetrySetting === 'function'
              ? await Promise.resolve(params.devTelemetrySetting()).catch(() => null)
              : params.devTelemetrySetting;
          await activeTracer
            .flush({ env: otelEnv, devTelemetrySetting: resolvedDevTel, ...(otelEnv.SAFE_FETCH ? { fetchFn: otelEnv.SAFE_FETCH } : {}) })
            .catch(() => false);
        }
      });
    };
    params.ctx!.waitUntil!(runWithTrace());
    return { status: 202, body: { ...currentEntry.summary } };
  }

  const completedSummary = await (activeTracer ? activeTracer.run(() => runPull(activeTracer)) : runPull());
  return { status: 200, body: { ...completedSummary } };
}
