/**
 * Polite Full-Store Catalog Engine (`hub/src/catalog.ts`):
 *
 *  - Sequential, single-host-at-a-time pagination through `CatalogSpec` adapters (`shopify`, `woocommerce`).
 *  - Every page executes through `executeHubFetch` (enforcing `robots.txt`, `Content-Signal`, Web Bot Auth, and SSRF guards).
 *  - 3-Strikes `429` cooldown (`status: 'cooling_down'`, `resumeAt`, honoring `Retry-After` / default `60s` on Shopify).
 *  - Immediate ethical halt on WAF/challenges or non-JSON bodies (`status: 'challenged'`, never bypassing).
 *  - All-or-nothing completion (`status: 'complete'` iff every page succeeded and natural end-of-catalog was reached).
 *  - Shrink Guard (`warning: 'shrink'`, `previousProducts`) when `< 50%` of prior `complete` snapshot for the same origin.
 *  - NDJSON artifact serialization in `ARTIFACTS` R2 + deterministic snapshot diff (`added`, `removed`, `changed`) ignoring `updatedAt`.
 */

import {
  getCatalogAdapter,
  type CatalogRecord,
  type CatalogSpec,
  type CatalogVariantRecord,
} from './extractors/registry';
import { buildBlockedInfo, type BlockedSuggestion } from './jobs';
import { isSafePublicHostname } from './overflow';
import type { OptionalStorageBindings } from './storage';

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
  records: CatalogRecord[];
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
  limit?: unknown;
  vendor?: unknown;
  productType?: unknown;
  availableOnly?: unknown;
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
  target?: unknown;
  site?: unknown;
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
  text(): Promise<string>;
}

interface R2BucketLike {
  put(key: string, value: string, options?: Record<string, unknown>): Promise<unknown>;
  get(key: string): Promise<R2ObjectBodyLike | null>;
}

interface SnapshotHashBundle {
  products: Record<string, string>;
  variants: Record<string, string>;
}

interface StoredCatalogRun {
  summary: CatalogStatusSummary;
  hashes: SnapshotHashBundle;
  records: CatalogRecord[] | null;
  retainedBytes: number;
}

export const MAX_CATALOG_IN_MEMORY_BYTES = 16 * 1024 * 1024;
export const MAX_GLOBAL_CATALOG_BYTES = 32 * 1024 * 1024;
export const MAX_CACHED_CATALOG_RUNS = 8;
export const MAX_CONCURRENT_CATALOG_PER_PRINCIPAL = 2;
export const MAX_CONCURRENT_CATALOG_GLOBAL = 8;
export const MAX_CATALOG_TOTAL_SLEEP_MS = 120_000;
export const MAX_CATALOG_WALL_MS = 180_000;
const MAX_RECORD_SERIALIZED_BYTES = 64 * 1024;
const MAX_IMAGES_PER_CATALOG_RECORD = 250;
const MAX_VARIANTS_PER_CATALOG_RECORD = 250;
const MAX_COMPACT_HISTORY_RUNS = 32;

const MEMORY_CATALOG_RUNS = new Map<string, StoredCatalogRun>();
const ACTIVE_CATALOG_BY_PRINCIPAL = new Map<string, number>();
let activeCatalogGlobal = 0;
const D1_INIT_CACHE = new WeakSet<object>();

function approxUtf8Bytes(s: string): number {
  let bytes = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c < 0x80) bytes += 1;
    else if (c < 0x800) bytes += 2;
    else if (c >= 0xd800 && c <= 0xdbff) {
      bytes += 4;
      i++;
    } else bytes += 3;
  }
  return bytes;
}

function clampCatalogRecord(rec: CatalogRecord): { record: CatalogRecord; bytes: number } {
  let desc = rec.descriptionText;
  if (typeof desc === 'string' && desc.length > 60_000) {
    desc = desc.slice(0, 60_000);
  }
  const images = Array.isArray(rec.images) ? rec.images.slice(0, MAX_IMAGES_PER_CATALOG_RECORD) : [];
  const variants = Array.isArray(rec.variants) ? rec.variants.slice(0, MAX_VARIANTS_PER_CATALOG_RECORD) : [];
  const tags = Array.isArray(rec.tags) ? rec.tags.slice(0, 128) : [];
  const options = Array.isArray(rec.options) ? rec.options.slice(0, 32) : [];

  let clamped: CatalogRecord = {
    ...rec,
    ...(desc !== undefined ? { descriptionText: desc } : {}),
    images,
    variants,
    tags,
    options,
  };
  let serialized = JSON.stringify(clamped);
  let bytes = approxUtf8Bytes(serialized);
  if (bytes > MAX_RECORD_SERIALIZED_BYTES) {
    if (typeof clamped.descriptionText === 'string' && clamped.descriptionText.length > 0) {
      const keepDesc = Math.max(0, Math.min(4_096, clamped.descriptionText.length - (bytes - MAX_RECORD_SERIALIZED_BYTES)));
      clamped = { ...clamped, descriptionText: clamped.descriptionText.slice(0, keepDesc) };
      serialized = JSON.stringify(clamped);
      bytes = approxUtf8Bytes(serialized);
    }
    if (bytes > MAX_RECORD_SERIALIZED_BYTES && clamped.variants.length > 32) {
      clamped = {
        ...clamped,
        variants: clamped.variants.slice(0, 32),
        ...(clamped.images ? { images: clamped.images.slice(0, 32) } : {}),
      };
      serialized = JSON.stringify(clamped);
      bytes = approxUtf8Bytes(serialized);
    }
  }
  return { record: clamped, bytes };
}

function rememberRunInMemory(catalogId: string, entry: StoredCatalogRun): void {
  if (MEMORY_CATALOG_RUNS.has(catalogId)) {
    MEMORY_CATALOG_RUNS.delete(catalogId);
  }
  MEMORY_CATALOG_RUNS.set(catalogId, entry);

  // Enforce LRU cap on full in-memory record bodies (`MAX_CACHED_CATALOG_RUNS = 8`, `MAX_GLOBAL_CATALOG_BYTES = 32 MiB`)
  let cachedBodyRuns = 0;
  let globalBytes = 0;
  for (const v of MEMORY_CATALOG_RUNS.values()) {
    if (v.records !== null) {
      cachedBodyRuns++;
      globalBytes += v.retainedBytes;
    }
  }
  if (cachedBodyRuns > MAX_CACHED_CATALOG_RUNS || globalBytes > MAX_GLOBAL_CATALOG_BYTES) {
    for (const [k, v] of MEMORY_CATALOG_RUNS.entries()) {
      if (k === catalogId || v.records === null) continue;
      globalBytes -= v.retainedBytes;
      cachedBodyRuns--;
      v.records = null;
      v.retainedBytes = 0;
      if (cachedBodyRuns <= MAX_CACHED_CATALOG_RUNS && globalBytes <= MAX_GLOBAL_CATALOG_BYTES) {
        break;
      }
    }
  }

  while (MEMORY_CATALOG_RUNS.size > MAX_COMPACT_HISTORY_RUNS) {
    const oldestKey = MEMORY_CATALOG_RUNS.keys().next().value;
    if (oldestKey === undefined) break;
    MEMORY_CATALOG_RUNS.delete(oldestKey);
  }
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
        catalog_id TEXT PRIMARY KEY,
        origin TEXT NOT NULL,
        platform TEXT NOT NULL,
        collection TEXT NOT NULL DEFAULT '',
        status TEXT NOT NULL,
        products_count INTEGER NOT NULL DEFAULT 0,
        variants_count INTEGER NOT NULL DEFAULT 0,
        pages_read INTEGER NOT NULL DEFAULT 0,
        artifact_id TEXT,
        hashes_json TEXT,
        summary_json TEXT NOT NULL,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
      )`,
    )
    .run();
  await db
    .prepare(
      `CREATE INDEX IF NOT EXISTS idx_catalog_runs_origin_status ON catalog_runs(origin, collection, status, created_at)`,
    )
    .run()
    .catch(() => null);
  D1_INIT_CACHE.add(key);
}

async function persistCatalogRun(
  env: (OptionalStorageBindings & Record<string, unknown>) | undefined,
  entry: StoredCatalogRun,
): Promise<void> {
  rememberRunInMemory(entry.summary.catalogId, entry);
  const db = getMetaD1(env);
  if (!db) return;
  try {
    await ensureCatalogRunsTable(db);
    const s = entry.summary;
    await db
      .prepare(
        `INSERT OR REPLACE INTO catalog_runs (
          catalog_id, origin, platform, collection, status,
          products_count, variants_count, pages_read, artifact_id,
          hashes_json, summary_json, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .bind(
        s.catalogId,
        s.origin,
        s.platform,
        s.collection ?? '',
        s.status,
        s.products,
        s.variants,
        s.pagesRead,
        s.artifactId ?? null,
        JSON.stringify(entry.hashes),
        JSON.stringify(s),
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
          `SELECT catalog_id, products_count, hashes_json, summary_json
           FROM catalog_runs
           WHERE origin = ? AND collection = ? AND status = 'complete' AND catalog_id != ?
           ORDER BY created_at DESC
           LIMIT 5`,
        )
        .bind(origin, collection, excludeCatalogId)
        .all<{ catalog_id: string; products_count: number; hashes_json: string | null; summary_json: string }>();
      const rows = rowsRes.results ?? [];
      for (const row of rows) {
        let parsedSummary: Record<string, unknown> | null = null;
        try {
          parsedSummary = JSON.parse(row.summary_json) as Record<string, unknown>;
        } catch {
          parsedSummary = null;
        }
        // Never use an already shrink-warned snapshot as the trusted baseline
        if (parsedSummary?.warning === 'shrink') continue;
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

  const memEntries = [...MEMORY_CATALOG_RUNS.values()].reverse();
  for (const item of memEntries) {
    if (
      item.summary.catalogId !== excludeCatalogId &&
      item.summary.origin === origin &&
      (item.summary.collection ?? '') === collection &&
      item.summary.status === 'complete' &&
      item.summary.warning !== 'shrink'
    ) {
      return {
        productsCount: item.summary.products,
        hashes: item.hashes,
      };
    }
  }
  return null;
}

function fnv1a64Hex(input: string): string {
  let h1 = 0x811c9dc5;
  let h2 = 0xc9dc5118;
  for (let i = 0; i < input.length; i++) {
    const c = input.charCodeAt(i);
    h1 ^= c;
    h1 = Math.imul(h1, 0x01000193);
    h2 ^= c ^ (i & 0xff);
    h2 = Math.imul(h2, 0x01000193);
  }
  return `${(h1 >>> 0).toString(16).padStart(8, '0')}${(h2 >>> 0).toString(16).padStart(8, '0')}`;
}

export function computeCatalogVariantHash(v: CatalogVariantRecord): string {
  const canonical = JSON.stringify({
    variantId: v.variantId,
    sku: v.sku ?? null,
    barcode: v.barcode ?? null,
    title: v.title ?? null,
    options: v.options,
    price: v.price,
    compareAt: v.compareAt,
    currency: v.currency,
    available: v.available,
    inventoryPolicy: v.inventoryPolicy ?? null,
    grams: v.grams,
    image: v.image,
  });
  return fnv1a64Hex(canonical);
}

/**
 * Computes a deterministic content hash for a `CatalogRecord` **explicitly ignoring `updatedAt` and `publishedAt`**
 * so Shopify inventory timestamp bumps do not trigger false `changed` diffs.
 */
export function computeCatalogProductHash(rec: CatalogRecord): string {
  const sortedVariantHashes = rec.variants
    .map((v) => `${v.variantId}:${computeCatalogVariantHash(v)}`)
    .sort();
  const canonical = JSON.stringify({
    productId: rec.productId,
    handle: rec.handle,
    title: rec.title,
    vendor: rec.vendor,
    productType: rec.productType,
    tags: [...rec.tags].sort(),
    options: rec.options,
    variants: sortedVariantHashes,
  });
  return fnv1a64Hex(canonical);
}

function buildSnapshotHashBundle(records: CatalogRecord[]): SnapshotHashBundle {
  const products: Record<string, string> = Object.create(null) as Record<string, string>;
  const variants: Record<string, string> = Object.create(null) as Record<string, string>;
  for (const r of records) {
    const pKey = r.productId || r.handle;
    if (!pKey) continue;
    products[pKey] = computeCatalogProductHash(r);
    for (const v of r.variants) {
      const vKey = `${pKey}::${v.variantId || v.sku || v.title || '0'}`;
      variants[vKey] = computeCatalogVariantHash(v);
    }
  }
  return { products, variants };
}

export function computeCatalogSnapshotDiff(
  prev: SnapshotHashBundle,
  curr: SnapshotHashBundle,
): CatalogSnapshotDiff {
  let added = 0;
  let removed = 0;
  let changed = 0;
  for (const [k, h] of Object.entries(curr.products)) {
    const prevH = Object.prototype.hasOwnProperty.call(prev.products, k) ? prev.products[k] : undefined;
    if (prevH === undefined) added++;
    else if (prevH !== h) changed++;
  }
  for (const k of Object.keys(prev.products)) {
    if (!Object.prototype.hasOwnProperty.call(curr.products, k)) removed++;
  }

  let vAdded = 0;
  let vRemoved = 0;
  let vChanged = 0;
  for (const [vk, vh] of Object.entries(curr.variants)) {
    const prevVh = Object.prototype.hasOwnProperty.call(prev.variants, vk) ? prev.variants[vk] : undefined;
    if (prevVh === undefined) vAdded++;
    else if (prevVh !== vh) vChanged++;
  }
  for (const vk of Object.keys(prev.variants)) {
    if (!Object.prototype.hasOwnProperty.call(curr.variants, vk)) vRemoved++;
  }

  return {
    added,
    removed,
    changed,
    variantDiff: {
      added: vAdded,
      removed: vRemoved,
      changed: vChanged,
    },
  };
}

/**
 * Inspects `robots.txt` text (or response headers) for advertised Shopify/Universal Commerce Protocol (UCP) endpoints
 * (`/.well-known/ucp` or `/api/ucp/mcp`), strictly treating `robots.txt` prose as untrusted data.
 */
export function discoverUcpEndpointFromRobots(originStr: string, robotsText: string): CatalogUcpMetadata | null {
  if (!robotsText) return null;
  const bounded = robotsText.slice(0, 32_768);
  const m = /(?:\/api\/ucp\/mcp|\/\.well-known\/ucp)\b/i.exec(bounded);
  if (!m?.[0]) return null;
  try {
    const endpoint = new URL(m[0], originStr).toString();
    return { advertised: true, endpoint };
  } catch {
    return null;
  }
}

export function isSafeHttpsStoreUrl(urlStr: string, selfHost?: string): URL | null {
  try {
    const trimmed = urlStr.trim();
    if (!trimmed) return null;
    const u = new URL(trimmed);
    if (u.protocol !== 'https:' || u.username || u.password) return null;
    if (u.port !== '' && u.port !== '443') return null;
    const host = u.hostname.toLowerCase();
    if (
      !host ||
      host.endsWith('.') ||
      !host.includes('.') ||
      host === 'localhost' ||
      host.endsWith('.localhost') ||
      host.endsWith('.local') ||
      host.endsWith('.internal') ||
      !isSafePublicHostname(host, selfHost)
    ) {
      return null;
    }
    return u;
  } catch {
    return null;
  }
}

function stripLeadingWww(host: string): string {
  return host.startsWith('www.') ? host.slice(4) : host;
}

function isAllowedStoreRedirectUrl(finalUrlStr: string, requestedOriginUrl: URL, selfHost?: string): boolean {
  const parsedFinal = isSafeHttpsStoreUrl(finalUrlStr, selfHost);
  if (!parsedFinal) return false;
  const reqHost = requestedOriginUrl.hostname.toLowerCase();
  const finHost = parsedFinal.hostname.toLowerCase();
  return finHost === reqHost || stripLeadingWww(finHost) === stripLeadingWww(reqHost);
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

function normalizeHeadersMap(raw: unknown): Record<string, string> {
  const out: Record<string, string> = {};
  if (!raw) return out;
  if (typeof (raw as Headers).forEach === 'function') {
    (raw as Headers).forEach((v, k) => {
      out[k.toLowerCase()] = v;
    });
    return out;
  }
  if (typeof raw === 'object' && !Array.isArray(raw)) {
    for (const [k, v] of Object.entries(raw as Record<string, unknown>)) {
      if (typeof v === 'string') out[k.toLowerCase()] = v;
    }
  }
  return out;
}

function normalizeHubPageResponse(raw: unknown): NormalizedHubPageResponse | null {
  if (!raw || typeof raw !== 'object') return null;
  const obj = raw as Record<string, unknown>;

  // Unwrap `{ status, body: { results: [item] } }` from `fetch_url` / `fetch_batch` style responses if needed
  const nestedBody = obj.body && typeof obj.body === 'object' && !Array.isArray(obj.body)
    ? (obj.body as Record<string, unknown>)
    : null;
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
  const headers = normalizeHeadersMap(target.headers ?? obj.headers);

  let bodyStr = '';
  if (typeof target.body === 'string') {
    bodyStr = target.bodyEncoding === 'base64' ? decodeBase64Utf8(target.body) : target.body;
  } else if (typeof target.rawBody === 'string') {
    bodyStr = target.rawBody;
  } else if (target.body && typeof target.body === 'object') {
    bodyStr = JSON.stringify(target.body);
  }

  const retryAfterMs =
    typeof target.retryAfterMs === 'number' && Number.isFinite(target.retryAfterMs)
      ? target.retryAfterMs
      : undefined;
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
}

function parseRetryAfterMs(resp: NormalizedHubPageResponse, defaultMs: number): number {
  if (resp.retryAfterMs !== undefined && resp.retryAfterMs > 0) {
    return Math.min(300_000, Math.max(1_000, Math.round(resp.retryAfterMs)));
  }
  const hdr = resp.headers['retry-after']?.trim();
  if (hdr) {
    if (/^\d+$/.test(hdr)) {
      const secs = parseInt(hdr, 10);
      if (Number.isFinite(secs) && secs > 0) {
        return Math.min(300_000, Math.max(1_000, secs * 1_000));
      }
    }
    const parsedDate = Date.parse(hdr);
    if (Number.isFinite(parsedDate)) {
      const delta = parsedDate - Date.now();
      if (delta > 0) return Math.min(300_000, Math.max(1_000, delta));
    }
  }
  return defaultMs;
}

function isChallengeResponse(resp: NormalizedHubPageResponse): boolean {
  const out = (resp.outcome ?? '').toLowerCase();
  if (out === 'challenge') return true;
  if (resp.headers['cf-mitigated']) return true;
  const prob = resp.problem ?? '';
  if (/challenge|cf-mitigated|turnstile|captcha|verify you are human/i.test(prob)) return true;
  const bodyHead = resp.body.slice(0, 4096);
  if (
    (resp.status === 403 || resp.status === 503 || resp.status === 200) &&
    /cf-mitigated|_cf_chl_opt|challenge-platform|turnstile|verify you are human/i.test(bodyHead)
  ) {
    return true;
  }
  return false;
}

function isRobotsOrSignalBlocked(resp: NormalizedHubPageResponse): 'robots_disallowed' | 'robots_unreachable' | 'content_signal_disallowed' | null {
  const out = (resp.outcome ?? '').toLowerCase();
  const prob = resp.problem ?? '';
  if (out === 'content_signal_disallowed' || /content-signal|ai-input\s*=\s*no/i.test(prob)) {
    return 'content_signal_disallowed';
  }
  if (out === 'robots_unreachable' || (/robots\.txt/i.test(prob) && /timed?\s*out|unreachable/i.test(prob))) {
    return 'robots_unreachable';
  }
  if (out === 'robots_disallowed' || /robots\.txt/i.test(prob)) {
    return 'robots_disallowed';
  }
  return null;
}

function generateCatalogId(): string {
  const rand = typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function'
    ? crypto.randomUUID().replace(/-/g, '').slice(0, 16)
    : `${Date.now().toString(36)}${Math.random().toString(36).slice(2, 10)}`;
  return `cat_${rand}`;
}

const defaultSleep = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

/**
 * Retrieves the live or completed status of a catalog job (`running`, `cooling_down`, `complete`, `partial`, `challenged`).
 */
export async function getCatalogStatus(params: {
  catalogId: string;
  env?: OptionalStorageBindings & Record<string, unknown>;
}): Promise<{ status: number; body: Record<string, unknown> }> {
  const catalogId = params.catalogId.trim();
  if (!catalogId) {
    return { status: 400, body: { ok: false, error: 'missing_catalog_id', message: 'Provide `catalogId`.' } };
  }

  const mem = MEMORY_CATALOG_RUNS.get(catalogId);
  if (mem) {
    return { status: 200, body: { ...mem.summary } };
  }

  const db = getMetaD1(params.env);
  if (db) {
    try {
      await ensureCatalogRunsTable(db);
      const row = await db
        .prepare(`SELECT summary_json FROM catalog_runs WHERE catalog_id = ?`)
        .bind(catalogId)
        .first<{ summary_json: string }>();
      if (row?.summary_json) {
        const parsed = JSON.parse(row.summary_json) as CatalogStatusSummary;
        return { status: 200, body: { ...parsed } };
      }
    } catch {
      // ignore
    }
  }

  return {
    status: 404,
    body: { ok: false, error: 'catalog_not_found', message: `No catalog run found with id "${catalogId}".` },
  };
}

/**
 * Pages and filters normalized `CatalogRecord` rows from an in-memory or R2 NDJSON catalog artifact
 * without pulling multi-megabyte raw JSON pages into agent context.
 */
export async function getCatalogRecords(params: {
  catalogId: string;
  offset?: number;
  limit?: number;
  vendor?: string | string[];
  productType?: string | string[];
  availableOnly?: boolean;
  query?: string;
  env?: OptionalStorageBindings & Record<string, unknown>;
}): Promise<{ status: number; body: Record<string, unknown> }> {
  const catalogId = params.catalogId.trim();
  if (!catalogId) {
    return { status: 400, body: { ok: false, error: 'missing_catalog_id', message: 'Provide `catalogId`.' } };
  }

  let summary: CatalogStatusSummary | null = null;
  let records: CatalogRecord[] | null = null;

  const mem = MEMORY_CATALOG_RUNS.get(catalogId);
  if (mem) {
    summary = mem.summary;
    records = mem.records;
  }

  const db = getMetaD1(params.env);
  if (!summary && db) {
    try {
      await ensureCatalogRunsTable(db);
      const row = await db
        .prepare(`SELECT summary_json FROM catalog_runs WHERE catalog_id = ?`)
        .bind(catalogId)
        .first<{ summary_json: string }>();
      if (row?.summary_json) {
        summary = JSON.parse(row.summary_json) as CatalogStatusSummary;
      }
    } catch {
      // ignore
    }
  }

  if (!summary) {
    return {
      status: 404,
      body: { ok: false, error: 'catalog_not_found', message: `No catalog run found with id "${catalogId}".` },
    };
  }

  if (!records) {
    records = [];
    const r2 = getArtifactsR2(params.env);
    if (r2 && summary.artifactId) {
      try {
        const obj = await r2.get(summary.artifactId);
        if (obj) {
          const ndjson = await obj.text();
          for (const line of ndjson.split('\n')) {
            const trimmed = line.trim();
            if (!trimmed) continue;
            try {
              records.push(JSON.parse(trimmed) as CatalogRecord);
            } catch {
              // skip malformed line
            }
          }
        }
      } catch {
        // ignore R2 read errors
      }
    }
  }

  const offset = typeof params.offset === 'number' && Number.isFinite(params.offset) ? Math.max(0, Math.floor(params.offset)) : 0;
  const limit =
    typeof params.limit === 'number' && Number.isFinite(params.limit)
      ? Math.min(250, Math.max(1, Math.floor(params.limit)))
      : 50;

  const vendorFilters = (
    Array.isArray(params.vendor) ? params.vendor : typeof params.vendor === 'string' && params.vendor.trim() ? [params.vendor] : []
  ).map((v) => v.trim().toLowerCase());

  const typeFilters = (
    Array.isArray(params.productType)
      ? params.productType
      : typeof params.productType === 'string' && params.productType.trim()
        ? [params.productType]
        : []
  ).map((t) => t.trim().toLowerCase());

  const queryLower = typeof params.query === 'string' ? params.query.trim().toLowerCase() : '';
  const availableOnly = params.availableOnly === true;

  const filtered = records.filter((r) => {
    if (vendorFilters.length > 0) {
      const rv = (r.vendor ?? '').toLowerCase();
      if (!vendorFilters.some((vf) => rv === vf || rv.includes(vf))) return false;
    }
    if (typeFilters.length > 0) {
      const rt = (r.productType ?? '').toLowerCase();
      if (!typeFilters.some((tf) => rt === tf || rt.includes(tf))) return false;
    }
    if (availableOnly) {
      if (!r.variants.some((v) => v.available === true)) return false;
    }
    if (queryLower) {
      const hay = [
        r.title,
        r.handle,
        r.vendor ?? '',
        r.productType ?? '',
        r.tags.join(' '),
        ...r.variants.map((v) => `${v.sku ?? ''} ${v.title ?? ''}`),
      ]
        .join(' ')
        .toLowerCase();
      if (!hay.includes(queryLower)) return false;
    }
    return true;
  });

  const sliced = filtered.slice(offset, offset + limit);
  const result: CatalogRecordsResult = {
    ok: true,
    catalogId,
    status: summary.status,
    platform: summary.platform,
    origin: summary.origin,
    totalProducts: records.length,
    matchedProducts: filtered.length,
    offset,
    limit,
    returned: sliced.length,
    hasMore: offset + sliced.length < filtered.length,
    records: sliced,
  };

  return { status: 200, body: result as unknown as Record<string, unknown> };
}

/**
 * Starts a polite full-store catalog pull OR polls/pages an existing `catalogId`.
 */
export async function executeCatalogCall(params: {
  payload: CatalogCallPayload;
  env?: OptionalStorageBindings & Record<string, unknown>;
  executeHubFetch: CatalogHubFetchFn;
  selfHost?: string;
  principal?: string;
  ctx?: { waitUntil?: (promise: Promise<unknown>) => void };
  sleepFn?: (ms: number) => Promise<void>;
}): Promise<{ status: number; body: Record<string, unknown> }> {
  const { payload, env, executeHubFetch } = params;
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
      payload.limit !== undefined ||
      payload.vendor !== undefined ||
      payload.productType !== undefined ||
      payload.availableOnly !== undefined ||
      payload.query !== undefined;
    if (wantsRecords) {
      return getCatalogRecords({
        catalogId: existingId,
        offset: typeof payload.offset === 'number' ? payload.offset : undefined,
        limit: typeof payload.limit === 'number' ? payload.limit : undefined,
        vendor:
          typeof payload.vendor === 'string' || Array.isArray(payload.vendor)
            ? (payload.vendor as string | string[])
            : undefined,
        productType:
          typeof payload.productType === 'string' || Array.isArray(payload.productType)
            ? (payload.productType as string | string[])
            : undefined,
        availableOnly: payload.availableOnly === true,
        query: typeof payload.query === 'string' ? payload.query : undefined,
        env,
      });
    }
    return getCatalogStatus({ catalogId: existingId, env });
  }

  const rawUrl = typeof payload.url === 'string' ? payload.url.trim() : '';
  const parsedUrl = isSafeHttpsStoreUrl(rawUrl, params.selfHost);
  if (!parsedUrl) {
    return {
      status: 400,
      body: {
        ok: false,
        error: 'invalid_url',
        message: 'Provide a valid public `https://` storefront URL in `url` (or `catalogId` to poll an existing run).',
      },
    };
  }

  const rawPlatform = typeof payload.platform === 'string' ? payload.platform.trim().toLowerCase() : 'auto';
  if (rawPlatform !== 'auto' && rawPlatform !== 'shopify' && rawPlatform !== 'woocommerce') {
    return {
      status: 400,
      body: {
        ok: false,
        error: 'invalid_platform',
        message: 'Supported `platform` values are `"auto"`, `"shopify"`, or `"woocommerce"`.',
      },
    };
  }

  const scopeObj = payload.scope && typeof payload.scope === 'object' ? (payload.scope as Record<string, unknown>) : undefined;
  const pathColMatch = /^\/collections\/([A-Za-z0-9_-]+)/i.exec(parsedUrl.pathname);
  const collection =
    (typeof payload.collection === 'string' && payload.collection.trim()
      ? payload.collection.trim()
      : typeof scopeObj?.collection === 'string' && scopeObj.collection.trim()
        ? scopeObj.collection.trim()
        : pathColMatch?.[1] ?? '');

  const fields: 'full' | 'lean' = payload.fields === 'lean' ? 'lean' : 'full';
  const originUrl = new URL(parsedUrl.origin);
  if (collection) {
    originUrl.pathname = `/collections/${encodeURIComponent(collection)}`;
  }

  // Resolve initial `CatalogSpec`
  const initialPlatform =
    rawPlatform !== 'auto'
      ? rawPlatform
      : parsedUrl.pathname.toLowerCase().includes('/wp-json/wc/store/')
        ? 'woocommerce'
        : 'shopify';

  const initialAdapter = getCatalogAdapter(initialPlatform);
  if (!initialAdapter?.catalog) {
    return {
      status: 500,
      body: { ok: false, error: 'missing_catalog_adapter', message: `Catalog adapter "${initialPlatform}" is not registered.` },
    };
  }

  // `R5-M4`: Per-principal (`2`) and global (`8`) active catalog pull concurrency guard
  const principalKey = (params.principal ?? 'anonymous').trim() || 'anonymous';
  const activeForPrincipal = ACTIVE_CATALOG_BY_PRINCIPAL.get(principalKey) ?? 0;
  if (activeCatalogGlobal >= MAX_CONCURRENT_CATALOG_GLOBAL || activeForPrincipal >= MAX_CONCURRENT_CATALOG_PER_PRINCIPAL) {
    return {
      status: 429,
      body: {
        ok: false,
        error: 'catalog_busy',
        message: 'Too many concurrent catalog pulls are active. Wait for an active run to finish or poll its catalogId.',
      },
    };
  }
  activeCatalogGlobal++;
  ACTIVE_CATALOG_BY_PRINCIPAL.set(principalKey, activeForPrincipal + 1);
  let releasedConcurrencySlot = false;
  const releaseConcurrencySlot = () => {
    if (releasedConcurrencySlot) return;
    releasedConcurrencySlot = true;
    activeCatalogGlobal = Math.max(0, activeCatalogGlobal - 1);
    const curCount = ACTIVE_CATALOG_BY_PRINCIPAL.get(principalKey) ?? 0;
    if (curCount <= 1) ACTIVE_CATALOG_BY_PRINCIPAL.delete(principalKey);
    else ACTIVE_CATALOG_BY_PRINCIPAL.set(principalKey, curCount - 1);
  };

  let activeSpec: CatalogSpec = initialAdapter.catalog;
  const reqPause = typeof payload.pauseMs === 'number' && Number.isFinite(payload.pauseMs) ? Math.floor(payload.pauseMs) : activeSpec.pauseMs;
  const computeEffectivePauseMs = (spec: CatalogSpec): number =>
    Math.min(30_000, Math.max(spec.platform === 'shopify' ? 2000 : spec.pauseMs, reqPause));

  let effectivePauseMs = computeEffectivePauseMs(activeSpec);
  const maxPages =
    typeof payload.maxPages === 'number' && Number.isFinite(payload.maxPages) && payload.maxPages >= 1
      ? Math.min(activeSpec.pageCap, Math.floor(payload.maxPages))
      : activeSpec.pageCap;

  const catalogId = generateCatalogId();
  const startedAtMs = Date.now();
  const createdAt = new Date(startedAtMs).toISOString();

  const currentEntry: StoredCatalogRun = {
    summary: {
      ok: true,
      catalogId,
      status: 'running',
      platform: activeSpec.platform,
      origin: parsedUrl.origin,
      ...(collection ? { collection } : {}),
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
    records: [],
    retainedBytes: 0,
  };

  await persistCatalogRun(env, currentEntry);

  const runPull = async (): Promise<CatalogStatusSummary> => {
    try {
    const byProductId = new Map<string, CatalogRecord>();
    const bytesByProductId = new Map<string, number>();
    let accumulatedBytes = 0;
    let totalSleptMs = 0;
    let truncatedByBudget = false;
    let pagesRead = 0;
    let naturalCompletion = false;
    let finalStatus: CatalogRunStatus = 'partial';
    let stopReason: string | undefined;
    let blockedInfo: BlockedSuggestion | undefined;
    let currentUrl: string | null = activeSpec.firstPage(originUrl, collection ? { collection } : undefined);
    let triedAutoFallbackToWc = rawPlatform !== 'auto' || activeSpec.platform === 'woocommerce';

    while (currentUrl && pagesRead < maxPages) {
      if (Date.now() - startedAtMs > MAX_CATALOG_WALL_MS) {
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
        totalSleptMs += effectivePauseMs;
        await sleep(effectivePauseMs);
      }

      let strikes = 0;
      let pageResp: NormalizedHubPageResponse | null = null;

      while (true) {
        const rawFetchOut = await executeHubFetch({
          url: currentUrl,
          kind: 'json',
          accept: 'application/json',
          maxBytes: 16_777_216,
          ...(payload.target !== undefined ? { target: payload.target } : {}),
          ...(payload.site !== undefined ? { site: payload.site } : {}),
        }).catch((err: unknown) => ({
          status: 0,
          outcome: 'network_error',
          problem: err instanceof Error ? err.message : String(err),
          headers: {},
          body: '',
        }));

        pageResp = normalizeHubPageResponse(rawFetchOut);
        if (!pageResp) {
          stopReason = strikes > 0 ? 'rate_limited' : 'empty_response';
          break;
        }

        // Reject cross-origin redirects to an unrelated host on `/products.json` or `/wp-json/wc/store/v1/products`
        // (allow only the same host or `www.`-equivalent of the requested store origin).
        if (pageResp.finalUrl && !isAllowedStoreRedirectUrl(pageResp.finalUrl, originUrl, params.selfHost)) {
          stopReason = 'cross_origin_redirect';
          pageResp = null;
          break;
        }

        // 1. Immediate ethical halt on `robots.txt` or `Content-Signal`
        const blockKind = isRobotsOrSignalBlocked(pageResp);
        if (blockKind) {
          stopReason = blockKind;
          blockedInfo =
            buildBlockedInfo(currentUrl, pageResp.outcome ?? blockKind, pageResp.problem, pageResp.status) ?? undefined;
          pageResp = null;
          break;
        }

        // 2. Immediate halt on WAF / bot challenge (`cf-mitigated`, `outcome: "challenge"`, Turnstile)
        if (isChallengeResponse(pageResp)) {
          finalStatus = 'challenged';
          stopReason = 'challenge';
          blockedInfo =
            buildBlockedInfo(currentUrl, 'challenge', pageResp.problem || 'anti-bot challenge', pageResp.status) ?? undefined;
          pageResp = null;
          break;
        }

        // 3. Polite 3-Strikes `429` Cooldown Handling
        if (pageResp.status === 429 || pageResp.outcome === 'rate_limited') {
          strikes++;
          if (strikes > 3) {
            stopReason = 'rate_limited';
            pageResp = null;
            break;
          }
          const defaultCooldownMs = activeSpec.platform === 'shopify' ? 60_000 : 30_000;
          const waitMs = parseRetryAfterMs(pageResp, defaultCooldownMs);
          if (totalSleptMs + waitMs > MAX_CATALOG_TOTAL_SLEEP_MS || Date.now() - startedAtMs + waitMs > MAX_CATALOG_WALL_MS) {
            stopReason = 'sleep_budget_exceeded';
            truncatedByBudget = true;
            pageResp = null;
            break;
          }
          totalSleptMs += waitMs;
          const resumeAt = new Date(Date.now() + waitMs).toISOString();
          currentEntry.summary = {
            ...currentEntry.summary,
            status: 'cooling_down',
            resumeAt,
            pages: pagesRead,
            pagesRead,
            durationMs: Date.now() - startedAtMs,
            updatedAt: new Date().toISOString(),
          };
          await persistCatalogRun(env, currentEntry);
          await sleep(waitMs);
          const { resumeAt: _cleared, ...restSummary } = currentEntry.summary;
          currentEntry.summary = {
            ...restSummary,
            status: 'running',
            updatedAt: new Date().toISOString(),
          };
          await persistCatalogRun(env, currentEntry);
          continue;
        }

        break;
      }

      if (!pageResp) {
        break;
      }

      // Platform `auto` fallback: if page 1 on `/products.json` returned 404/400/405, try WooCommerce Store API!
      if (
        pagesRead === 0 &&
        !triedAutoFallbackToWc &&
        (pageResp.status === 404 || pageResp.status === 400 || pageResp.status === 405)
      ) {
        triedAutoFallbackToWc = true;
        const wcAdapter = getCatalogAdapter('woocommerce');
        if (wcAdapter?.catalog) {
          activeSpec = wcAdapter.catalog;
          effectivePauseMs = computeEffectivePauseMs(activeSpec);
          currentEntry.summary.platform = activeSpec.platform;
          currentEntry.summary.pauseMs = effectivePauseMs;
          currentUrl = activeSpec.firstPage(originUrl, collection ? { collection } : undefined);
          continue;
        }
      }

      if (pageResp.status !== 200) {
        stopReason = `http_${pageResp.status || 'error'}`;
        break;
      }

      // Parse page strictly; non-JSON body on a 200 catalog feed is a bot wall / interstitial -> `challenged`!
      let parsedPage: { records: CatalogRecord[]; done: boolean };
      try {
        parsedPage = activeSpec.parsePage(pageResp.body, originUrl, {
          fields,
          headers: pageResp.headers,
        });
      } catch {
        // If `auto` mode got non-Shopify JSON on page 1 (e.g. a custom JSON object without `products`), try WooCommerce once if body was valid JSON; if HTML/non-JSON, halt as `challenged`!
        const trimmedBody = pageResp.body.trim();
        const looksLikeJson = trimmedBody.startsWith('{') || trimmedBody.startsWith('[');
        if (pagesRead === 0 && !triedAutoFallbackToWc && looksLikeJson) {
          triedAutoFallbackToWc = true;
          const wcAdapter = getCatalogAdapter('woocommerce');
          if (wcAdapter?.catalog) {
            activeSpec = wcAdapter.catalog;
            effectivePauseMs = computeEffectivePauseMs(activeSpec);
            currentEntry.summary.platform = activeSpec.platform;
            currentEntry.summary.pauseMs = effectivePauseMs;
            currentUrl = activeSpec.firstPage(originUrl, collection ? { collection } : undefined);
            continue;
          }
        }
        finalStatus = 'challenged';
        stopReason = 'non_json_body';
        break;
      }

      pagesRead++;
      let hitByteBudget = false;
      for (const rec of parsedPage.records) {
        const key = rec.productId || rec.handle || rec.url;
        const { record: clampedRec, bytes: recBytes } = clampCatalogRecord(rec);
        const prevBytes = bytesByProductId.get(key) ?? 0;
        if (accumulatedBytes - prevBytes + recBytes > MAX_CATALOG_IN_MEMORY_BYTES) {
          hitByteBudget = true;
          truncatedByBudget = true;
          stopReason = 'byte_budget';
          break;
        }
        accumulatedBytes = accumulatedBytes - prevBytes + recBytes;
        bytesByProductId.set(key, recBytes);
        byProductId.set(key, clampedRec);
      }

      const currentRecords = [...byProductId.values()];
      const currentVariantsCount = currentRecords.reduce((acc, r) => acc + r.variants.length, 0);
      currentEntry.records = currentRecords;
      currentEntry.retainedBytes = accumulatedBytes;
      currentEntry.summary = {
        ...currentEntry.summary,
        products: currentRecords.length,
        variants: currentVariantsCount,
        pages: pagesRead,
        pagesRead,
        durationMs: Date.now() - startedAtMs,
        updatedAt: new Date().toISOString(),
      };
      await persistCatalogRun(env, currentEntry);

      if (hitByteBudget) {
        break;
      }

      if (parsedPage.done) {
        naturalCompletion = true;
        break;
      }

      const nextUrl = activeSpec.nextPage({
        url: currentUrl,
        body: pageResp.body,
        pageIndex: pagesRead - 1,
        headers: pageResp.headers,
      });

      if (!nextUrl) {
        naturalCompletion = true;
        break;
      }

      if (pagesRead >= maxPages) {
        stopReason = 'max_pages_reached';
        break;
      }

      currentUrl = nextUrl;
    }

    if (finalStatus !== 'challenged') {
      if (naturalCompletion) {
        finalStatus = 'complete';
      } else {
        finalStatus = 'partial';
        if (!stopReason) stopReason = 'incomplete_pagination';
      }
    }

    const finalRecords = [...byProductId.values()];
    const totalVariants = finalRecords.reduce((acc, r) => acc + r.variants.length, 0);
    const currHashes = buildSnapshotHashBundle(finalRecords);

    // Optional lightweight `robots.txt` check for Shopify UCP / MCP endpoint advertisement
    let ucpMeta: CatalogUcpMetadata | undefined;
    if (finalStatus === 'complete' || pagesRead > 0) {
      const robotsOut = await executeHubFetch({
        url: `${parsedUrl.origin}/robots.txt`,
        kind: 'text',
        accept: 'text/plain',
        ...(payload.target !== undefined ? { target: payload.target } : {}),
        ...(payload.site !== undefined ? { site: payload.site } : {}),
      }).catch(() => null);
      const normRobots = normalizeHubPageResponse(robotsOut);
      if (normRobots && normRobots.status === 200 && normRobots.body) {
        ucpMeta = discoverUcpEndpointFromRobots(parsedUrl.origin, normRobots.body) ?? undefined;
      }
    }

    // Write NDJSON artifact to R2 when `ARTIFACTS` is bound
    let artifactId: string | undefined;
    const r2 = getArtifactsR2(env);
    if (r2 && finalRecords.length > 0) {
      const key = `catalog/${catalogId}.ndjson`;
      const ndjson = `${finalRecords.map((r) => JSON.stringify(r)).join('\n')}\n`;
      try {
        await r2.put(key, ndjson, {
          httpMetadata: { contentType: 'application/x-ndjson; charset=utf-8' },
        });
        artifactId = key;
      } catch {
        // Non-fatal if R2 put fails
      }
    }

    // Shrink Guard & Variant-Level Snapshot Diff against last trusted `complete` run for `(origin, collection)`
    let shrinkWarning: 'shrink' | undefined;
    let previousProducts: number | undefined;
    let diff: CatalogSnapshotDiff | null = null;

    const prevRun = await findPreviousCompleteCatalogRun(env, parsedUrl.origin, collection, catalogId);
    if (prevRun) {
      if (prevRun.productsCount > 0 && finalRecords.length < prevRun.productsCount * 0.5) {
        shrinkWarning = 'shrink';
        previousProducts = prevRun.productsCount;
      }
      if (prevRun.hashes && finalStatus === 'complete') {
        diff = computeCatalogSnapshotDiff(prevRun.hashes, currHashes);
      }
    }

    const finishedNow = new Date().toISOString();
    const { resumeAt: _dropResume, ...cleanBase } = currentEntry.summary;
    const finalSummary: CatalogStatusSummary = {
      ...cleanBase,
      ok: finalStatus === 'complete',
      status: finalStatus,
      platform: activeSpec.platform,
      products: finalRecords.length,
      variants: totalVariants,
      pages: pagesRead,
      pagesRead,
      pauseMs: effectivePauseMs,
      durationMs: Date.now() - startedAtMs,
      ...(truncatedByBudget || stopReason === 'max_pages_reached' ? { truncated: true } : {}),
      ...(stopReason ? { reason: stopReason } : {}),
      ...(shrinkWarning ? { warning: shrinkWarning, previousProducts } : {}),
      ...(artifactId ? { artifactId } : {}),
      diff,
      ...(ucpMeta ? { ucp: ucpMeta } : {}),
      ...(blockedInfo ? { blocked: blockedInfo } : {}),
      updatedAt: finishedNow,
    };

    currentEntry.summary = finalSummary;
    currentEntry.hashes = currHashes;
    // Flush full in-memory record bodies once persisted to `ARTIFACTS` R2 (`getCatalogRecords` reloads from R2 `artifactId`)
    if (artifactId) {
      currentEntry.records = null;
      currentEntry.retainedBytes = 0;
    } else {
      currentEntry.records = finalRecords;
      currentEntry.retainedBytes = accumulatedBytes;
    }
    await persistCatalogRun(env, currentEntry);
    return finalSummary;
    } finally {
      releaseConcurrencySlot();
    }
  };

  const wantAsync = payload.sync === false && typeof params.ctx?.waitUntil === 'function';
  if (wantAsync) {
    params.ctx!.waitUntil!(runPull());
    return {
      status: 202,
      body: { ...currentEntry.summary },
    };
  }

  const completedSummary = await runPull();
  return {
    status: 200,
    body: { ...completedSummary },
  };
}
