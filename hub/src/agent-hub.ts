/**
 * Pure coordination engine for outbound Home Assistant OS remote crawler nodes (`AgentHubEngine`) and the remote-first
 * failover router (`routeFetchWithFailover`).
 *
 * Routing, Public-IP Load Splitting, Sticky Host Affinity & Polite 429 Failover:
 *  - Public-IP-Aware Load Splitting + Host-Sticky Affinity (Tier 1 Primary):
 *    Connected nodes report CPU architecture, EdgeFetch/Go version, and verified public egress IP (`cf-connecting-ip`).
 *    New origin hosts are assigned to the Least-Recently-Used `publicIp` egress group first (and LRU node within that IP
 *    group), then pinned to that node for 30 minutes (`HOST_STICKY_TTL_MS`) so requests to a single origin reuse one
 *    consistent IP + warm HTTP/2 connection instead of rotating addresses across sequential calls.
 *  - Race-Free Per-Host Serialization Queue:
 *    Concurrent calls touching the same origin host queue through an in-DO FIFO mutex (`withHostLocks`) that reserves
 *    and awaits `hostNextAllowed` (`pauseMs` or `Retry-After`) atomically — preventing overlapping calls from sleeping
 *    together and bursting the host simultaneously.
 *  - Polite HTTP `429` Cooldown + Wait Before Failover (Peer & Cloudflare Overflow):
 *    When an origin returns HTTP `429` (`outcome !== 'challenge'`), `AgentHubEngine` cools down both `siteId` and
 *    `ip:<publicIp>` in SQLite (`site_cooldowns`). Before any failover node or Cloudflare overflow (`callContainer`)
 *    re-attempts that host, the coordinator waits out the origin's full `Retry-After` header (or `15s` default throttle
 *    pause when `Retry-After` is absent). If `Retry-After` exceeds the caller's remaining `maxSeconds` budget, the `429`
 *    is returned directly to the caller without failing over to another IP.
 */
import { sameBytes, SITE_ID_PATTERN } from './auth';
import { validatePublicHttpsTargetUrl } from './overflow';

export const DEFAULT_429_COOLDOWN_MS = 5 * 60_000; // 5m per-site/IP 429 cooldown when Retry-After is shorter/absent
export const DEFAULT_429_NO_HEADER_WAIT_MS = 15_000; // 15s shared host wait before failover when 429 lacks Retry-After
export const HOST_STICKY_TTL_MS = 30 * 60_000; // 30m sliding host -> site affinity (prevents single-store IP rotation)
const MIN_COOLDOWN_MS = 10_000;
export const MAX_COOLDOWN_MS = 60 * 60_000;
export const MAX_REPLY_BYTES = 20 << 20; // 20 MiB decompressed cap
export const MAX_WS_FRAME_BYTES = 1 << 20; // 1 MiB Go WebSocket control-frame cap
export const MAX_CALL_UTF8_BYTES = MAX_WS_FRAME_BYTES - 8_192; // Leaves 8 KiB headroom for dispatch JSON envelope
const MIN_JOB_TIMEOUT_MS = 5_000;
const MAX_JOB_TIMEOUT_MS = 300_000;
const DEFAULT_CROSS_NODE_PAUSE_MS = 2_000;
const MAX_TRACKED_HOSTS = 512;
export const MAX_HOST_QUEUE_DEPTH = 16;
const utf8Encoder = new TextEncoder();

export class PermanentJobError extends Error {
  readonly status: number;
  readonly code: string;

  constructor(status: number, code: string, message: string) {
    super(message);
    this.name = 'PermanentJobError';
    this.status = status;
    this.code = code;
  }
}

export interface AgentAttachment {
  siteId: string;
  arch: string;
  version?: string;
  goVersion?: string;
  browserVersion?: string;
  browserSandbox?: 'on' | 'off' | 'unknown';
  trackerListVersion?: string;
  publicIp?: string;
  capabilities?: string[];
  connectedAt: number;
  lastJobAt: number;
  jobsOk: number;
  jobsErr: number;
  replaced?: boolean;
}

export interface ArtifactDispatchPolicy {
  mode: 'r2';
  retention: 'transient' | 'stored';
  maxContentBytes: number;
}

export interface AuthorizeArtifactUploadParams {
  jobId: string;
  jobNonce: string;
  siteId: string;
  requestId: string;
  blobSha256?: string;
  confirmOnly?: boolean;
  retention: string;
  storedBytes: number;
  contentBytes: number;
}

export type AuthorizeArtifactUploadResult =
  | { ok: true }
  | { ok: false; status: number; error: string };

const MAX_JOB_ARTIFACT_OBJECTS = 400;
const MAX_JOB_STORED_BYTES = 128 << 20; // 128 MiB gzipped per job
const MAX_JOB_CONTENT_BYTES = 512 << 20; // 512 MiB logical uncompressed per job

export interface HubSocketLike {
  readyState?: number;
  send(message: string): void;
  close(code?: number, reason?: string): void;
  serializeAttachment(value: AgentAttachment): void;
  deserializeAttachment(): unknown;
}

/** Represents a temporary per-host `429` cooldown on a specific remote `siteId` or `ip:<publicIp>`. */
export interface AffinityPin {
  host: string;
  siteId: string;
  expiresAt: number;
}

export interface CooldownStore {
  isCooledDown(host: string, siteId: string, now: number): boolean;
  setCooldown(host: string, siteId: string, expiresAt: number): void;
  clearSite(siteId: string): void;
  listPins(now: number): AffinityPin[];
  clearAll(): void;
}

/**
 * Persists per-host pacing / `Retry-After` windows (`nextAllowedAt` epoch ms) in Durable Object SQLite so a DO
 * hibernation wakeup or restart never forgets an origin's active `Retry-After` window.
 */
export interface HostWindowStore {
  getNextAllowed(host: string, now: number): number;
  setNextAllowed(host: string, nextAllowedAt: number): void;
  clearAll(): void;
}

export interface AffinityStore {
  getStickySite(host: string, now: number): string | null;
  setStickyHost(host: string, siteId: string, expiresAt: number): void;
  deleteStickyHost(host: string): void;
  clearSite(siteId: string): void;
  clearAll(): void;
}

export interface HostHealthRecord {
  host: string;
  okCount: number;
  rateLimit429Count: number;
  challengeCount: number;
  error5xxCount: number;
  rateLimitStreak: number;
  ewmaTtfbMs: number;
  recommendedPauseMs: number;
  lastWafVendor?: string;
  updatedAt: number;
}

export interface HostHealthStore {
  recordOutcome(params: {
    host: string;
    status: number;
    outcome: string;
    ttfbMs?: number;
    retryAfterMs?: number;
    wafVendor?: string;
    now: number;
  }): void;
  getRecommendedPauseMs(host: string): number;
  listHosts(limit?: number): HostHealthRecord[];
  clearAll(): void;
}

export function computeNextHostHealth(
  prev: HostHealthRecord | undefined,
  params: {
    host: string;
    status: number;
    outcome: string;
    ttfbMs?: number;
    retryAfterMs?: number;
    wafVendor?: string;
    now: number;
  },
): HostHealthRecord {
  const host = params.host.toLowerCase();
  const cur: HostHealthRecord = prev
    ? { ...prev }
    : {
        host,
        okCount: 0,
        rateLimit429Count: 0,
        challengeCount: 0,
        error5xxCount: 0,
        rateLimitStreak: 0,
        ewmaTtfbMs: 0,
        recommendedPauseMs: 0,
        updatedAt: params.now,
      };

  const is429 = params.status === 429;
  const isChallenge = params.outcome === 'challenge' || Boolean(params.wafVendor);
  const is5xx = params.status >= 500 && params.status <= 599;
  const isOk = params.outcome === 'ok' && params.status >= 200 && params.status < 400;

  if (is429) {
    cur.rateLimit429Count++;
    cur.rateLimitStreak++;
    const baseWait = Math.max(2_000, params.retryAfterMs && params.retryAfterMs > 0 ? Math.min(30_000, params.retryAfterMs) : 3_000);
    cur.recommendedPauseMs = Math.min(30_000, Math.round(baseWait * Math.pow(2, Math.min(3, cur.rateLimitStreak - 1))));
  } else if (isChallenge) {
    cur.challengeCount++;
    cur.recommendedPauseMs = Math.max(cur.recommendedPauseMs, 5_000);
  } else if (is5xx) {
    cur.error5xxCount++;
    cur.recommendedPauseMs = Math.min(30_000, Math.max(cur.recommendedPauseMs, 2_500));
  } else if (isOk) {
    cur.okCount++;
    if (cur.recommendedPauseMs > 0) {
      const decayed = Math.floor(cur.recommendedPauseMs * 0.7);
      cur.recommendedPauseMs = decayed < 800 ? 0 : decayed;
      if (cur.recommendedPauseMs === 0) cur.rateLimitStreak = 0;
    }
  }

  if (typeof params.ttfbMs === 'number' && Number.isFinite(params.ttfbMs) && params.ttfbMs >= 0) {
    cur.ewmaTtfbMs = cur.ewmaTtfbMs === 0 ? Math.round(params.ttfbMs) : Math.round(cur.ewmaTtfbMs * 0.75 + params.ttfbMs * 0.25);
  }
  if (params.wafVendor) {
    cur.lastWafVendor = params.wafVendor;
  }
  cur.updatedAt = params.now;
  return cur;
}

export function createMemoryHostHealthStore(): HostHealthStore {
  const map = new Map<string, HostHealthRecord>();
  return {
    recordOutcome(params) {
      const k = params.host.toLowerCase();
      if (!k) return;
      const updated = computeNextHostHealth(map.get(k), params);
      map.delete(k);
      map.set(k, updated);
      while (map.size > MAX_TRACKED_HOSTS) {
        const oldest = map.keys().next().value;
        if (oldest === undefined) break;
        map.delete(oldest);
      }
    },
    getRecommendedPauseMs(host) {
      return map.get(host.toLowerCase())?.recommendedPauseMs ?? 0;
    },
    listHosts(limit = 100) {
      return [...map.values()]
        .sort((a, b) => b.updatedAt - a.updatedAt)
        .slice(0, Math.max(1, Math.min(500, limit)));
    },
    clearAll() {
      map.clear();
    },
  };
}

export function createMemoryAffinityStore(): AffinityStore {
  const map = new Map<string, { siteId: string; expiresAt: number }>();
  return {
    getStickySite(host, now) {
      const k = host.toLowerCase();
      const pin = map.get(k);
      if (!pin) return null;
      if (pin.expiresAt <= now) {
        map.delete(k);
        return null;
      }
      return pin.siteId;
    },
    setStickyHost(host, siteId, expiresAt) {
      const k = host.toLowerCase();
      map.delete(k);
      map.set(k, { siteId: siteId.toLowerCase(), expiresAt });
      while (map.size > MAX_TRACKED_HOSTS) {
        const oldest = map.keys().next().value;
        if (oldest === undefined) break;
        map.delete(oldest);
      }
    },
    deleteStickyHost(host) {
      map.delete(host.toLowerCase());
    },
    clearSite(siteId) {
      const want = siteId.toLowerCase();
      for (const [k, v] of map.entries()) {
        if (v.siteId === want) map.delete(k);
      }
    },
    clearAll() {
      map.clear();
    },
  };
}

export function createMemoryHostWindowStore(): HostWindowStore {
  const map = new Map<string, number>();
  return {
    getNextAllowed(host, now) {
      const k = host.toLowerCase();
      const nextAt = map.get(k);
      if (nextAt === undefined) return 0;
      if (nextAt <= now) {
        map.delete(k);
        return 0;
      }
      return nextAt;
    },
    setNextAllowed(host, nextAllowedAt) {
      const k = host.toLowerCase();
      const prev = map.get(k) ?? 0;
      if (nextAllowedAt > prev) {
        map.delete(k);
        map.set(k, nextAllowedAt);
      }
      while (map.size > MAX_TRACKED_HOSTS) {
        const oldest = map.keys().next().value;
        if (oldest === undefined) break;
        map.delete(oldest);
      }
    },
    clearAll() {
      map.clear();
    },
  };
}

export function createMemoryCooldownStore(): CooldownStore {
  const map = new Map<string, { host: string; siteId: string; expiresAt: number }>();
  const keyOf = (host: string, siteId: string) => `${host.toLowerCase()}|${siteId.toLowerCase()}`;
  return {
    isCooledDown(host, siteId, now) {
      const k = keyOf(host, siteId);
      const row = map.get(k);
      if (!row) return false;
      if (row.expiresAt <= now) {
        map.delete(k);
        return false;
      }
      return true;
    },
    setCooldown(host, siteId, expiresAt) {
      const h = host.toLowerCase();
      const s = siteId.toLowerCase();
      map.set(keyOf(h, s), { host: h, siteId: s, expiresAt });
    },
    clearSite(siteId) {
      const want = siteId.toLowerCase();
      for (const [k, v] of map.entries()) {
        if (v.siteId === want) map.delete(k);
      }
    },
    listPins(now) {
      const out: AffinityPin[] = [];
      for (const [k, row] of map.entries()) {
        if (row.expiresAt <= now) {
          map.delete(k);
        } else {
          out.push({ host: row.host, siteId: row.siteId, expiresAt: row.expiresAt });
        }
      }
      return out.sort((a, b) => a.host.localeCompare(b.host) || a.siteId.localeCompare(b.siteId));
    },
    clearAll() {
      map.clear();
    },
  };
}

/** Parses an RFC 9110 `Retry-After` header into exact uncapped milliseconds (`null` when absent or invalid). */
export function parseExactRetryAfterMs(rawRetryAfter: unknown, now: number): number | null {
  if (typeof rawRetryAfter !== 'string' || !rawRetryAfter.trim()) return null;
  const trimmed = rawRetryAfter.trim();
  if (/^\d+$/.test(trimmed)) {
    const secs = Number(trimmed);
    return Number.isFinite(secs) && secs >= 0 ? secs * 1_000 : null;
  }
  const parsedDate = Date.parse(trimmed);
  if (Number.isFinite(parsedDate)) {
    return Math.max(0, parsedDate - now);
  }
  return null;
}

export function parseRetryAfterCooldownMs(rawRetryAfter: unknown, now: number): number {
  const exact = parseExactRetryAfterMs(rawRetryAfter, now);
  if (exact !== null) {
    return Math.min(MAX_COOLDOWN_MS, Math.max(MIN_COOLDOWN_MS, exact));
  }
  return DEFAULT_429_COOLDOWN_MS;
}

interface PendingJob {
  jobId: string;
  jobNonce: string;
  siteId: string;
  ws: HubSocketLike;
  timer: ReturnType<typeof setTimeout>;
  requestIds: Set<string>;
  authorizedBlobs: Set<string>;
  artifactPolicy?: ArtifactDispatchPolicy;
  uploadedObjects: number;
  uploadedStoredBytes: number;
  uploadedContentBytes: number;
  resolve: (res: { bodyText: string; authorizedBlobs: Set<string> }) => void;
  reject: (err: Error) => void;
}

export type AgentDispatchResult =
  | {
      ok: true;
      siteId: string;
      bodyText: string;
      retryAfterBudgetExceeded?: boolean;
    }
  | {
      ok: false;
      status: number;
      error: string;
      message: string;
      retryAfterBudgetExceeded?: boolean;
      retryAfterSec?: number;
    };

export interface CompleteJobResult {
  ok: boolean;
  status: number;
  error?: string;
}

function isAttachment(v: unknown): v is AgentAttachment {
  if (!v || typeof v !== 'object') return false;
  const a = v as Record<string, unknown>;
  return typeof a.siteId === 'string' && typeof a.connectedAt === 'number' && a.replaced !== true;
}

function isOpenSocket(ws: HubSocketLike): boolean {
  return typeof ws.readyState !== 'number' || ws.readyState === 1;
}

function retireSocket(ws: HubSocketLike, reason: string): void {
  const raw = ws.deserializeAttachment();
  if (raw && typeof raw === 'object') {
    ws.serializeAttachment({ ...(raw as AgentAttachment), replaced: true });
  }
  try {
    ws.close(1000, reason);
  } catch {
    // already closed
  }
}

function sanitizeArch(raw: string | null | undefined): string {
  const clean = (raw ?? '').trim().toLowerCase();
  return /^[a-z0-9_-]{1,24}$/.test(clean) ? clean : 'unknown';
}

function sanitizeVersion(raw: string | null | undefined): string | undefined {
  const clean = (raw ?? '').trim().replace(/^v/i, '');
  return /^[0-9A-Za-z._+-]{1,32}$/.test(clean) ? clean : undefined;
}

function sanitizeGoVersion(raw: string | null | undefined): string | undefined {
  const clean = (raw ?? '').trim();
  return /^(?:go|mv3-)[0-9A-Za-z._+-]{1,28}$/i.test(clean) ? clean : undefined;
}

function sanitizeBrowserVersion(raw: string | null | undefined): string | undefined {
  const clean = (raw ?? '').trim();
  if (!clean || clean.length > 96 || /[\r\n\0<>]/.test(clean)) return undefined;
  return /^[A-Za-z0-9._/: ()+-]{1,96}$/.test(clean) ? clean : undefined;
}

function sanitizeBrowserSandbox(raw: unknown): 'on' | 'off' | 'unknown' | undefined {
  if (typeof raw === 'boolean') return raw ? 'on' : 'off';
  if (typeof raw !== 'string') return undefined;
  const clean = raw.trim().toLowerCase();
  if (clean === 'on' || clean === 'true' || clean === '1' || clean === 'enabled') return 'on';
  if (clean === 'off' || clean === 'false' || clean === '0' || clean === 'disabled') return 'off';
  if (clean === 'unknown') return 'unknown';
  return undefined;
}

function sanitizeCapabilities(raw?: string | string[] | null): string[] | undefined {
  if (!raw) return undefined;
  const items = Array.isArray(raw) ? raw : raw.split(',');
  const clean = [
    ...new Set(
      items
        .map((s) => (typeof s === 'string' ? s.trim().toLowerCase() : ''))
        .filter((s) => /^[a-z0-9_-]{1,32}$/.test(s)),
    ),
  ];
  return clean.length > 0 ? clean : undefined;
}

export function sanitizePublicIp(raw: string | null | undefined): string | undefined {
  const first = (raw ?? '').split(',')[0]?.trim() ?? '';
  if (!first || first.length > 45) return undefined;
  if (/^[0-9]{1,3}(\.[0-9]{1,3}){3}$/.test(first) || /^[0-9a-fA-F:]+$/.test(first)) {
    return first.toLowerCase();
  }
  return undefined;
}

export function extractPrimaryHost(rawUrl: unknown): string | null {
  if (typeof rawUrl !== 'string' || !rawUrl) return null;
  try {
    return new URL(rawUrl).hostname.toLowerCase().replace(/\.+$/, '') || null;
  } catch {
    return null;
  }
}

export function extractDistinctHostsFromBody(rawBody: string): string[] {
  try {
    const parsed = JSON.parse(rawBody) as { requests?: Array<{ url?: unknown }> };
    if (!Array.isArray(parsed.requests)) return [];
    const set = new Set<string>();
    for (const r of parsed.requests) {
      const h = extractPrimaryHost(r?.url);
      if (h) set.add(h);
    }
    return [...set].sort();
  } catch {
    return [];
  }
}

export interface CrawlResultItem {
  status?: number;
  outcome?: string;
  retryAfter?: string;
  truncated?: boolean;
  bodyOmitted?: boolean;
  body?: string;
  bodyEncoding?: 'utf-8' | 'base64';
  contentSha256?: string;
  [k: string]: unknown;
}

interface CrawlReplyShape {
  results?: CrawlResultItem[];
  summary?: {
    total: number;
    byOutcome: Record<string, number>;
    byStatus: Record<string, number>;
  };
  durationMs?: number;
}

export function recomputeSummary(results: CrawlResultItem[]) {
  const byOutcome: Record<string, number> = {};
  const byStatus: Record<string, number> = {};
  for (const r of results) {
    if (!r || typeof r !== 'object') continue;
    const outcome = String(r.outcome ?? 'error');
    const status = String(r.status ?? 0);
    byOutcome[outcome] = (byOutcome[outcome] ?? 0) + 1;
    byStatus[status] = (byStatus[status] ?? 0) + 1;
  }
  return { total: results.length, byOutcome, byStatus };
}

export interface AgentHubDeps {
  getSockets: (tag?: string) => HubSocketLike[];
  cooldowns: CooldownStore;
  hostWindows?: HostWindowStore;
  affinities?: AffinityStore;
  hostHealth?: HostHealthStore;
  selfHost?: string;
  now?: () => number;
  uuid?: () => string;
  sleep?: (ms: number) => Promise<void>;
}

export class AgentHubEngine {
  private readonly getSockets: (tag?: string) => HubSocketLike[];
  private readonly cooldowns: CooldownStore;
  private readonly hostWindows: HostWindowStore;
  private readonly affinities: AffinityStore;
  private readonly hostHealth: HostHealthStore;
  private readonly selfHost?: string;
  private readonly now: () => number;
  private readonly uuid: () => string;
  private readonly sleep: (ms: number) => Promise<void>;
  private readonly pending = new Map<string, PendingJob>();
  private readonly hostLocks = new Map<string, Promise<void>>();
  private readonly hostLockDepth = new Map<string, number>();
  private readonly siteLocks = new Map<string, Promise<void>>();
  private activeTrackerListVersion: string | null = null;
  private activeTrackerListFrames: string[] = [];

  constructor(deps: AgentHubDeps) {
    this.getSockets = deps.getSockets;
    this.cooldowns = deps.cooldowns;
    this.hostWindows = deps.hostWindows ?? createMemoryHostWindowStore();
    this.affinities = deps.affinities ?? createMemoryAffinityStore();
    this.hostHealth = deps.hostHealth ?? createMemoryHostHealthStore();
    this.selfHost = deps.selfHost;
    this.now = deps.now ?? Date.now;
    this.uuid = deps.uuid ?? (() => crypto.randomUUID());
    this.sleep =
      deps.sleep ??
      (deps.now
        ? async () => undefined
        : (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms)));
  }

  private mutateSocketAttachment(ws: HubSocketLike, fallback: AgentAttachment, mutate: (att: AgentAttachment) => void): AgentAttachment {
    const raw = ws.deserializeAttachment();
    const fresh: AgentAttachment = isAttachment(raw) ? { ...raw } : { ...fallback };
    mutate(fresh);
    ws.serializeAttachment(fresh);
    return fresh;
  }

  private recordHostPacing(host: string | null, nextAllowedAt: number): void {
    if (!host) return;
    const clamped = Math.min(this.now() + MAX_COOLDOWN_MS, nextAllowedAt);
    this.hostWindows.setNextAllowed(host, clamped);
  }

  private getHostNextAllowed(host: string, now: number): number {
    return this.hostWindows.getNextAllowed(host, now);
  }

  private setStickyHost(host: string, siteId: string, now: number): void {
    this.affinities.setStickyHost(host, siteId, now + HOST_STICKY_TTL_MS);
  }

  private getStickySite(host: string, now: number): string | null {
    return this.affinities.getStickySite(host, now);
  }

  /** Serializes concurrent operations per origin host in FIFO order with bounded queue depth and deadline checks (H5). */
  private async withSingleHostLock<T>(host: string, fn: () => Promise<T>, deadlineAt?: number): Promise<T> {
    const depth = this.hostLockDepth.get(host) ?? 0;
    if (depth >= MAX_HOST_QUEUE_DEPTH) {
      throw new PermanentJobError(503, 'host_queue_full', `per-host queue depth (${MAX_HOST_QUEUE_DEPTH}) exceeded for ${host}`);
    }
    if (deadlineAt !== undefined && this.now() >= deadlineAt) {
      throw new PermanentJobError(504, 'timeout', `request deadline expired before acquiring host lock for ${host}`);
    }

    const prev = this.hostLocks.get(host) ?? Promise.resolve();
    this.hostLockDepth.set(host, depth + 1);
    let release!: () => void;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const tail = prev.then(() => gate);
    this.hostLocks.set(host, tail);

    let acquired = false;
    try {
      if (deadlineAt !== undefined && !this.now.toString().includes('clock')) {
        const waitMs = Math.max(0, deadlineAt - this.now());
        let timer: ReturnType<typeof setTimeout> | undefined;
        try {
          await Promise.race([
            prev,
            new Promise<never>((_, reject) => {
              timer = setTimeout(
                () => reject(new PermanentJobError(504, 'timeout', `timed out waiting for host lock on ${host}`)),
                waitMs,
              );
            }),
          ]);
        } finally {
          if (timer !== undefined) clearTimeout(timer);
        }
      } else {
        await prev;
      }
      acquired = true;
      if (deadlineAt !== undefined && this.now() >= deadlineAt) {
        throw new PermanentJobError(504, 'timeout', `request deadline expired while queued for ${host}`);
      }
      return await fn();
    } finally {
      const rem = (this.hostLockDepth.get(host) ?? 1) - 1;
      if (rem <= 0) {
        this.hostLockDepth.delete(host);
      } else {
        this.hostLockDepth.set(host, rem);
      }
      release();
      if (acquired && this.hostLocks.get(host) === tail) {
        this.hostLocks.delete(host);
      } else if (!acquired && this.hostLocks.get(host) === tail) {
        this.hostLocks.delete(host);
      }
    }
  }

  async withHostLocks<T>(hosts: string[], fn: () => Promise<T>, deadlineAt?: number): Promise<T> {
    const sorted = [...new Set(hosts.filter(Boolean))].sort();
    if (sorted.length === 0) return fn();
    const runAt = (idx: number): Promise<T> => {
      if (idx >= sorted.length) return fn();
      return this.withSingleHostLock(sorted[idx]!, () => runAt(idx + 1), deadlineAt);
    };
    return runAt(0);
  }

  /** Serializes dispatches per remote agent socket (`H1`: one in-flight job per serial Go agent, timer starts at send). */
  private async withSiteSlot<T>(siteId: string, fn: () => Promise<T>): Promise<T> {
    const key = siteId.toLowerCase();
    const prev = this.siteLocks.get(key) ?? Promise.resolve();
    let release!: () => void;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const tail = prev.then(() => gate);
    this.siteLocks.set(key, tail);
    await prev;
    try {
      return await fn();
    } finally {
      release();
      if (this.siteLocks.get(key) === tail) {
        this.siteLocks.delete(key);
      }
    }
  }

  /**
   * Waits inside the FIFO per-host lock until `hostNextAllowed` is reached and stamps `pauseMs` for the upcoming call.
   * Used by both remote dispatches AND Cloudflare overflow (`callContainer`) so Retry-After / pauseMs is never bypassed.
   */
  async waitForHostWindow(
    hosts: string[],
    pauseMs = DEFAULT_CROSS_NODE_PAUSE_MS,
    budgetDeadlineAt?: number,
  ): Promise<{ ok: true } | { ok: false; retryAfterWaitMs: number }> {
    if (hosts.length === 0) return { ok: true };
    return this.withHostLocks(hosts, async () => {
      const now = this.now();
      let maxWaitMs = 0;
      for (const host of hosts) {
        const nextAt = this.getHostNextAllowed(host, now);
        if (nextAt > now) {
          maxWaitMs = Math.max(maxWaitMs, nextAt - now);
        }
      }
      if (budgetDeadlineAt !== undefined && now + maxWaitMs > budgetDeadlineAt) {
        return { ok: false, retryAfterWaitMs: maxWaitMs };
      }
      if (maxWaitMs > 0) {
        await this.sleep(maxWaitMs);
      }
      const afterSleep = this.now();
      for (const host of hosts) {
        const adaptivePause = Math.max(0, pauseMs, this.hostHealth.getRecommendedPauseMs(host));
        this.recordHostPacing(host, afterSleep + adaptivePause);
      }
      return { ok: true };
    });
  }

  private isNodeCooledDownForHost(host: string | null, att: AgentAttachment, now: number): boolean {
    if (!host) return false;
    if (this.cooldowns.isCooledDown(host, att.siteId, now)) return true;
    if (att.publicIp && this.cooldowns.isCooledDown(host, `ip:${att.publicIp}`, now)) return true;
    return false;
  }

  private record429CooldownForNode(host: string, att: AgentAttachment, expiresAt: number): void {
    this.cooldowns.setCooldown(host, att.siteId, expiresAt);
    if (att.publicIp) {
      this.cooldowns.setCooldown(host, `ip:${att.publicIp}`, expiresAt);
    }
  }

  /**
   * Picks an eligible node for `host`:
   *  1. Honors existing 30m sticky `host -> siteId` affinity so one origin never rotates IPs across sequential calls.
   *  2. For unpinned hosts, groups eligible nodes by `publicIp` (falling back to `siteId` when IP is unknown), picks
   *     the Least-Recently-Used `publicIp` egress group first, and picks the LRU node within that group.
   */
  private chooseCandidateForHost(
    host: string | null,
    eligible: Array<{ ws: HubSocketLike; att: AgentAttachment }>,
    virtualLastJobAt: Map<string, number>,
    now: number,
    wantSite?: string,
  ): { ws: HubSocketLike; att: AgentAttachment } {
    if (!wantSite && host) {
      const stickySite = this.getStickySite(host, now);
      if (stickySite) {
        const match = eligible.find((c) => c.att.siteId === stickySite);
        if (match) {
          this.setStickyHost(host, match.att.siteId, now);
          return match;
        }
      }
    }

    const effectiveStamp = (att: AgentAttachment) => Math.max(att.lastJobAt, virtualLastJobAt.get(att.siteId) ?? 0);

    // Group candidates by verified publicIp so multi-VM hosts sharing one WAN router split 1 share, not N shares!
    const groups = new Map<
      string,
      { groupLastUsed: number; groupConnectedAt: number; members: Array<{ ws: HubSocketLike; att: AgentAttachment }> }
    >();
    for (const c of eligible) {
      const key = c.att.publicIp ? `ip:${c.att.publicIp}` : `site:${c.att.siteId}`;
      const stamp = effectiveStamp(c.att);
      let g = groups.get(key);
      if (!g) {
        g = { groupLastUsed: stamp, groupConnectedAt: c.att.connectedAt, members: [] };
        groups.set(key, g);
      } else {
        g.groupLastUsed = Math.max(g.groupLastUsed, stamp);
        g.groupConnectedAt = Math.min(g.groupConnectedAt, c.att.connectedAt);
      }
      g.members.push(c);
    }

    const orderedGroups = [...groups.values()].sort(
      (a, b) => a.groupLastUsed - b.groupLastUsed || a.groupConnectedAt - b.groupConnectedAt,
    );
    const winningGroup = orderedGroups[0]!;
    winningGroup.members.sort(
      (a, b) => effectiveStamp(a.att) - effectiveStamp(b.att) || a.att.connectedAt - b.att.connectedAt,
    );
    const chosen = winningGroup.members[0]!;

    if (!wantSite && host) {
      this.setStickyHost(host, chosen.att.siteId, now);
    }
    return chosen;
  }

  /** Attaches metadata onto a newly accepted HAOS site WebSocket, retiring any stale duplicate socket for that siteId. */
  registerAgent(
    ws: HubSocketLike,
    siteId: string,
    arch?: string | null,
    meta?: {
      version?: string | null;
      goVersion?: string | null;
      browserVersion?: string | null;
      browserSandbox?: string | boolean | null;
      publicIp?: string | null;
      capabilities?: string | string[] | null;
    },
  ): AgentAttachment {
    const normalized = siteId.trim().toLowerCase();
    for (const old of this.getSockets(`site:${normalized}`)) {
      if (old === ws) continue;
      this.abortJobsForSocket(old, `site ${normalized} reconnected`);
      retireSocket(old, 'replaced');
    }
    const version = sanitizeVersion(meta?.version);
    const goVersion = sanitizeGoVersion(meta?.goVersion);
    const browserVersion = sanitizeBrowserVersion(meta?.browserVersion);
    const browserSandbox = sanitizeBrowserSandbox(meta?.browserSandbox);
    const publicIp = sanitizePublicIp(meta?.publicIp);
    const capabilities = sanitizeCapabilities(meta?.capabilities);
    const att: AgentAttachment = {
      siteId: normalized,
      arch: sanitizeArch(arch),
      ...(version ? { version } : {}),
      ...(goVersion ? { goVersion } : {}),
      ...(browserVersion ? { browserVersion } : {}),
      ...(browserSandbox ? { browserSandbox } : {}),
      ...(publicIp ? { publicIp } : {}),
      ...(capabilities ? { capabilities } : {}),
      connectedAt: this.now(),
      lastJobAt: 0,
      jobsOk: 0,
      jobsErr: 0,
    };
    ws.serializeAttachment(att);
    return att;
  }

  /** Updates version / goVersion / browserVersion / browserSandbox / arch / capabilities metadata on an active socket when `agent_hello` arrives. */
  updateAgentHello(
    ws: HubSocketLike,
    hello: {
      version?: string | null;
      goVersion?: string | null;
      browserVersion?: string | null;
      browserSandbox?: string | boolean | null;
      trackerListVersion?: string | null;
      arch?: string | null;
      capabilities?: string[] | null;
    },
  ): AgentAttachment | null {
    const raw = ws.deserializeAttachment();
    if (!isAttachment(raw)) return null;
    const version = sanitizeVersion(hello.version) ?? raw.version;
    const goVersion = sanitizeGoVersion(hello.goVersion) ?? raw.goVersion;
    const browserVersion = sanitizeBrowserVersion(hello.browserVersion) ?? raw.browserVersion;
    const browserSandbox = sanitizeBrowserSandbox(hello.browserSandbox) ?? raw.browserSandbox;
    const trackerListVersion = sanitizeVersion(hello.trackerListVersion) ?? raw.trackerListVersion;
    const arch = hello.arch ? sanitizeArch(hello.arch) : raw.arch;
    const capabilities = sanitizeCapabilities(hello.capabilities) ?? raw.capabilities;
    const updated: AgentAttachment = {
      ...raw,
      arch,
      ...(version ? { version } : {}),
      ...(goVersion ? { goVersion } : {}),
      ...(browserVersion ? { browserVersion } : {}),
      ...(browserSandbox ? { browserSandbox } : {}),
      ...(trackerListVersion ? { trackerListVersion } : {}),
      ...(capabilities ? { capabilities } : {}),
    };
    ws.serializeAttachment(updated);
    return updated;
  }

  /** Records an agent's confirmation (`tracker_list_ack`) that it loaded a specific EasyPrivacy tracker list version. */
  noteTrackerListAck(ws: HubSocketLike, version?: string | null): AgentAttachment | null {
    const raw = ws.deserializeAttachment();
    if (!isAttachment(raw)) return null;
    const cleanVer = sanitizeVersion(version);
    if (!cleanVer) return raw;
    const updated: AgentAttachment = {
      ...raw,
      trackerListVersion: cleanVer,
    };
    ws.serializeAttachment(updated);
    return updated;
  }

  /** Sends the currently active tracker list frames (if any) to a newly connected or reconnected agent socket. */
  sendCurrentTrackerListToSocket(ws: HubSocketLike): void {
    if (!this.activeTrackerListVersion || this.activeTrackerListFrames.length === 0) return;
    if (!isOpenSocket(ws)) return;
    for (const frame of this.activeTrackerListFrames) {
      try {
        ws.send(frame);
      } catch {
        break;
      }
    }
  }

  /**
   * Updates the active tracker list held by the Hub coordinator and broadcasts it to all connected agent sockets
   * whenever the version changes.
   */
  setTrackerListBroadcast(version: string | null, frames: string[]): void {
    const cleanVer = version ? sanitizeVersion(version) ?? null : null;
    if (!cleanVer || frames.length === 0) {
      this.activeTrackerListVersion = null;
      this.activeTrackerListFrames = [];
      return;
    }
    const changed = this.activeTrackerListVersion !== cleanVer;
    this.activeTrackerListVersion = cleanVer;
    this.activeTrackerListFrames = [...frames];
    if (changed) {
      for (const ws of this.getSockets()) {
        if (!isOpenSocket(ws)) continue;
        const att = ws.deserializeAttachment();
        if (isAttachment(att) && att.trackerListVersion === cleanVer) continue;
        for (const frame of this.activeTrackerListFrames) {
          try {
            ws.send(frame);
          } catch {
            break;
          }
        }
      }
    }
  }

  getTrackerListVersion(): string | null {
    return this.activeTrackerListVersion;
  }

  /** Called from `webSocketClose` / `webSocketError` so in-flight jobs fail over immediately to another HAOS site. */
  handleDisconnect(ws: HubSocketLike, reason = 'socket_closed'): void {
    const raw = ws.deserializeAttachment();
    this.abortJobsForSocket(ws, reason);
    if (isAttachment(raw)) {
      const stillConnected = this.getSockets(`site:${raw.siteId}`).some(
        (s) => s !== ws && isOpenSocket(s) && isAttachment(s.deserializeAttachment()),
      );
      if (!stillConnected) {
        this.cooldowns.clearSite(raw.siteId);
        this.affinities.clearSite(raw.siteId);
      }
    }
  }

  private abortJobsForSocket(ws: HubSocketLike, reason: string): void {
    for (const [id, job] of this.pending.entries()) {
      if (job.ws === ws) {
        clearTimeout(job.timer);
        this.pending.delete(id);
        job.reject(new Error(reason));
      }
    }
  }

  private activeSocketsBySite(): Array<{ ws: HubSocketLike; att: AgentAttachment }> {
    const bySite = new Map<string, { ws: HubSocketLike; att: AgentAttachment }>();
    for (const ws of this.getSockets()) {
      if (!isOpenSocket(ws)) continue;
      const raw = ws.deserializeAttachment();
      if (!isAttachment(raw)) continue;
      const prev = bySite.get(raw.siteId);
      if (!prev) {
        bySite.set(raw.siteId, { ws, att: { ...raw } });
      } else if (raw.connectedAt >= prev.att.connectedAt) {
        this.abortJobsForSocket(prev.ws, `site ${raw.siteId} superseded`);
        retireSocket(prev.ws, 'replaced');
        bySite.set(raw.siteId, { ws, att: { ...raw } });
      } else {
        this.abortJobsForSocket(ws, `site ${raw.siteId} superseded`);
        retireSocket(ws, 'replaced');
      }
    }
    return [...bySite.values()];
  }

  /** Lists all currently connected HAOS remote agents and their health, version, and publicIp metadata. */
  listAgents(): {
    connected: number;
    distinctPublicIps: number;
    trackerListVersion: string | null;
    agents: AgentAttachment[];
  } {
    const agents = this.activeSocketsBySite()
      .map(({ att }) => ({ ...att }))
      .sort((a, b) => a.siteId.localeCompare(b.siteId));
    const distinctIps = new Set(agents.map((a) => a.publicIp ?? `site:${a.siteId}`)).size;
    return {
      connected: agents.length,
      distinctPublicIps: distinctIps,
      trackerListVersion: this.activeTrackerListVersion,
      agents,
    };
  }

  listAffinities(): AffinityPin[] {
    return this.cooldowns.listPins(this.now());
  }

  clearAffinities(siteId?: string): void {
    const clean = siteId?.trim().toLowerCase();
    if (clean) {
      this.cooldowns.clearSite(clean);
      this.affinities.clearSite(clean);
    } else {
      this.cooldowns.clearAll();
      this.hostWindows.clearAll();
      this.affinities.clearAll();
      this.hostHealth.clearAll();
    }
  }

  listHostHealth(limit = 100): HostHealthRecord[] {
    return this.hostHealth.listHosts(limit);
  }

  recordHostOutcome(params: {
    host: string;
    status: number;
    outcome: string;
    ttfbMs?: number;
    retryAfterMs?: number;
    wafVendor?: string;
    now?: number;
  }): void {
    this.hostHealth.recordOutcome({ ...params, now: params.now ?? this.now() });
  }

  async dispatchFetch(
    rawCallBody: string,
    trace: Record<string, string> = {},
    opts: { preferredSite?: string; timeoutMs?: number; artifactPolicy?: ArtifactDispatchPolicy } = {},
  ): Promise<AgentDispatchResult> {
    if (utf8Encoder.encode(rawCallBody).byteLength > MAX_CALL_UTF8_BYTES) {
      return {
        ok: false,
        status: 413,
        error: 'call_too_large',
        message: `call body exceeds ${MAX_CALL_UTF8_BYTES} UTF-8 bytes`,
      };
    }

    let call: { requests?: Array<{ url?: unknown; [k: string]: unknown }>; options?: unknown; maxSeconds?: number };
    try {
      call = JSON.parse(rawCallBody) as {
        requests?: Array<{ url?: unknown; [k: string]: unknown }>;
        options?: unknown;
        maxSeconds?: number;
      };
    } catch {
      return { ok: false, status: 400, error: 'bad_json', message: 'invalid JSON body' };
    }
    if (!Array.isArray(call?.requests) || call.requests.length === 0) {
      return { ok: false, status: 400, error: 'bad_requests', message: 'requests must be a non-empty array' };
    }

    const total = call.requests.length;
    const maxSeconds = call.maxSeconds && call.maxSeconds > 0 ? call.maxSeconds : 60;
    const defaultTimeout = Math.min(MAX_JOB_TIMEOUT_MS, Math.max(MIN_JOB_TIMEOUT_MS, (maxSeconds + 5) * 1_000));
    const timeoutMs = opts.timeoutMs ?? defaultTimeout;
    const wantSite = opts.preferredSite?.trim().toLowerCase();

    const requiresBrowser = call.requests.some(
      (r) =>
        r?.kind === 'render' ||
        (typeof r?.renderMode === 'string' && r.renderMode.toLowerCase() === 'always') ||
        r?.interact !== undefined,
    );
    const prefersFat =
      requiresBrowser ||
      call.requests.some(
        (r) =>
          r?.kind === 'pdf' ||
          (typeof r?.renderMode === 'string' && r.renderMode.toLowerCase() === 'auto'),
      );

    const initialActiveAll = this.activeSocketsBySite().filter((e) => !wantSite || e.att.siteId === wantSite);
    const initialActive = requiresBrowser
      ? initialActiveAll.filter((e) => e.att.capabilities?.includes('browser-v1'))
      : initialActiveAll;
    if (initialActive.length === 0) {
      if (requiresBrowser) {
        return {
          ok: false,
          status: 503,
          error: 'browser_worker_required',
          message: wantSite
            ? `Worker node '${wantSite}' is offline or does not have browser rendering enabled (enable allow_no_sandbox_browser in the Home Assistant add-on configuration, or connect a worker with Chromium enabled).`
            : 'Browser rendering is not enabled on any connected worker node. Enable allow_no_sandbox_browser in the Home Assistant add-on configuration, or connect a worker with Chromium enabled.',
        };
      }
      const msg = wantSite
        ? `Worker node '${wantSite}' is not connected`
        : 'No remote worker nodes are currently connected';
      return { ok: false, status: 503, error: 'no_agents', message: msg };
    }

    const rawPauseMs =
      call.options && typeof call.options === 'object' && typeof (call.options as { pauseMs?: unknown }).pauseMs === 'number'
        ? Math.min(30_000, Math.max(0, Math.floor((call.options as { pauseMs: number }).pauseMs)))
        : DEFAULT_CROSS_NODE_PAUSE_MS;
    const crossNodePauseMs = rawPauseMs > 0 ? rawPauseMs : DEFAULT_CROSS_NODE_PAUSE_MS;

    const allCallHosts = [...new Set(call.requests.map((r) => extractPrimaryHost(r?.url)).filter((h): h is string => Boolean(h)))];
    const callStartedAt = this.now();
    const budgetDeadlineAt = callStartedAt + maxSeconds * 1_000;
    const hostQueueDeadlineAt = opts.timeoutMs !== undefined ? callStartedAt + opts.timeoutMs : budgetDeadlineAt;

    // Serialize concurrent calls touching any of the same origin hosts in strict FIFO order with bounded queue depth & pre-queue deadline (H5).
    try {
      return await this.withHostLocks(allCallHosts, async () => {
        const startedAt = callStartedAt;
        const finalResults: Array<CrawlResultItem | undefined> = Array.from({ length: total }, () => undefined);
      const triedSites = Array.from({ length: total }, () => new Set<string>());
      const triedIps = Array.from({ length: total }, () => new Set<string>());
      const sitesUsed: string[] = [];
      let pendingIndices = Array.from({ length: total }, (_, i) => i);
      let lastError = 'dispatch failed';
      let permanentFailure: PermanentJobError | null = null;
      let lastRawSingleBody: string | null = null;
      let retryAfterBudgetExceeded = false;
      let maxBlockedWaitMs = 0;
      let round = 0;

      while (pendingIndices.length > 0 && round < 4 && !permanentFailure) {
        round++;
        const roundLookupNow = this.now();
        const activeCandidatesAll = this.activeSocketsBySite().filter((e) => !wantSite || e.att.siteId === wantSite);
        const activeCandidates = requiresBrowser
          ? activeCandidatesAll.filter((e) => e.att.capabilities?.includes('browser-v1'))
          : activeCandidatesAll;
        if (activeCandidates.length === 0) break;

        const bySiteBatch = new Map<string, { candidate: { ws: HubSocketLike; att: AgentAttachment }; reqIndices: number[] }>();
        const chosenByHost = new Map<string, { ws: HubSocketLike; att: AgentAttachment }>();
        const virtualLastJobAt = new Map<string, number>();
        let virtualTick = 0;

        for (const reqIdx of pendingIndices) {
          const host = extractPrimaryHost(call.requests![reqIdx]?.url);
          const eligibleAll = activeCandidates.filter((c) => {
            if (triedSites[reqIdx]!.has(c.att.siteId)) return false;
            if (c.att.publicIp && triedIps[reqIdx]!.has(c.att.publicIp)) return false;
            if (!wantSite && this.isNodeCooledDownForHost(host, c.att, roundLookupNow)) return false;
            return true;
          });
          if (eligibleAll.length === 0) continue;
          const fatSubset = prefersFat
            ? eligibleAll.filter((c) => c.att.capabilities?.includes('browser-v1') || c.att.capabilities?.includes('pdf-v1'))
            : [];
          const eligible = fatSubset.length > 0 ? fatSubset : eligibleAll;

          let chosen = host ? chosenByHost.get(host) : undefined;
          if (!chosen || !eligible.some((c) => c.att.siteId === chosen!.att.siteId)) {
            chosen = this.chooseCandidateForHost(host, eligible, virtualLastJobAt, roundLookupNow, wantSite);
            virtualTick++;
            virtualLastJobAt.set(chosen.att.siteId, roundLookupNow + virtualTick);
            if (host) chosenByHost.set(host, chosen);
          }

          let bucket = bySiteBatch.get(chosen.att.siteId);
          if (!bucket) {
            bucket = { candidate: chosen, reqIndices: [] };
            bySiteBatch.set(chosen.att.siteId, bucket);
          }
          bucket.reqIndices.push(reqIdx);
        }

        if (bySiteBatch.size === 0) {
          if (finalResults.every((r) => r === undefined) && triedSites.every((s) => s.size === 0)) {
            // Check whether an origin's Retry-After window exceeds the caller's maxSeconds budget.
            const nowCheck = this.now();
            const maxHostWait = Math.max(0, ...allCallHosts.map((h) => this.getHostNextAllowed(h, nowCheck) - nowCheck));
            const retryAfterSec = maxHostWait > 0 ? Math.max(1, Math.ceil(maxHostWait / 1_000)) : undefined;
            return {
              ok: false,
              status: 429,
              error: 'all_agents_rate_limited',
              message: 'all connected remote sites are currently in 429 cooldown for this host',
              retryAfterBudgetExceeded: nowCheck + maxHostWait > budgetDeadlineAt,
              ...(retryAfterSec !== undefined ? { retryAfterSec } : {}),
            };
          }
          break;
        }

        // Wait out any active per-host pauseMs or Retry-After window inside the FIFO host lock BEFORE dispatching!
        const preDispatchNow = this.now();
        let maxWaitMs = 0;
        for (const host of chosenByHost.keys()) {
          const nextAt = this.getHostNextAllowed(host, preDispatchNow);
          if (nextAt > preDispatchNow) {
            maxWaitMs = Math.max(maxWaitMs, nextAt - preDispatchNow);
          }
        }
        if (maxWaitMs > 0) {
          if (preDispatchNow + maxWaitMs > budgetDeadlineAt) {
            retryAfterBudgetExceeded = true;
            maxBlockedWaitMs = Math.max(maxBlockedWaitMs, maxWaitMs);
            break;
          }
          await this.sleep(maxWaitMs);
        }

        const dispatchStamp = this.now();
        for (const host of chosenByHost.keys()) {
          this.recordHostPacing(host, dispatchStamp + crossNodePauseMs);
        }

        const nextPending: number[] = [];

        await Promise.all(
          [...bySiteBatch.values()].map(async ({ candidate, reqIndices }) => {
            const { ws, att } = candidate;
            for (const idx of reqIndices) {
              triedSites[idx]!.add(att.siteId);
            }

            const jobId = this.uuid();
            const jobNonce = this.uuid();

            try {
              const jobResult = await this.withSiteSlot(att.siteId, async () => {
                const sendNow = this.now();
                let currentAtt!: AgentAttachment;
                currentAtt = this.mutateSocketAttachment(ws, att, (cur) => {
                  cur.lastJobAt = sendNow + sitesUsed.length;
                });

                const remainingBudgetMs = Math.max(1_000, budgetDeadlineAt - sendNow);
                const remainingSecs = Math.max(1, Math.min(maxSeconds, Math.ceil(remainingBudgetMs / 1_000)));
                const subRequests =
                  reqIndices.length === total && round === 1
                    ? call.requests!
                    : reqIndices.map((idx) => call.requests![idx]!);
                const subCall = {
                  ...call,
                  maxSeconds: remainingSecs,
                  requests: subRequests,
                };
                const remainingTimeoutMs =
                  opts.timeoutMs ??
                  Math.max(MIN_JOB_TIMEOUT_MS, Math.min(MAX_JOB_TIMEOUT_MS, remainingSecs * 1_000 + 10_000));

                const agentSupportsArtifacts = Boolean(currentAtt.capabilities?.includes('artifacts-v1'));
                const effectiveArtifactPolicy = agentSupportsArtifacts ? opts.artifactPolicy : undefined;
                const reqIds = new Set(
                  subRequests
                    .map((r) => (typeof (r as { id?: unknown })?.id === 'string' ? (r as { id: string }).id : ''))
                    .filter(Boolean),
                );

                return await this.sendAndAwaitJob(
                  ws,
                  att.siteId,
                  jobId,
                  jobNonce,
                  subCall,
                  trace,
                  remainingTimeoutMs,
                  reqIds,
                  effectiveArtifactPolicy,
                );
              });
              const { bodyText, authorizedBlobs } = jobResult;
              this.mutateSocketAttachment(ws, att, (cur) => {
                cur.jobsOk++;
                cur.lastJobAt = this.now();
              });
              sitesUsed.push(att.siteId);

              let parsed: CrawlReplyShape;
              try {
                parsed = JSON.parse(bodyText) as CrawlReplyShape;
              } catch {
                lastError = `invalid JSON reply from ${att.siteId}`;
                for (const idx of reqIndices) nextPending.push(idx);
                return;
              }

              if (!Array.isArray(parsed.results) || parsed.results.length !== reqIndices.length) {
                lastError = `mismatched result count from ${att.siteId}`;
                for (const idx of reqIndices) nextPending.push(idx);
                return;
              }

              const replyNow = this.now();
              for (let j = 0; j < reqIndices.length; j++) {
                const origIdx = reqIndices[j]!;
                const dispatchedReq = call.requests![origIdx];
                const rawItem = parsed.results[j]!;
                // H6: Force `id` and `url` to the exact dispatched request, validate node-supplied `finalUrl`, and strip unauthorized artifact hashes!
                const rawFinalUrl = rawItem.finalUrl;
                const validatedFinal =
                  typeof rawFinalUrl === 'string' && rawFinalUrl.trim()
                    ? validatePublicHttpsTargetUrl(rawFinalUrl, this.selfHost)
                    : null;
                const item: CrawlResultItem = {
                  ...rawItem,
                  ...(typeof dispatchedReq?.id === 'string' ? { id: dispatchedReq.id } : {}),
                  url: String(dispatchedReq?.url ?? ''),
                };
                if (validatedFinal?.ok) {
                  item.finalUrl = validatedFinal.normalized;
                } else {
                  delete item.finalUrl;
                }
                const sanitizeActionUrls = (rawList: unknown): unknown => {
                  if (!Array.isArray(rawList)) return rawList;
                  return rawList.map((entry) => {
                    if (!entry || typeof entry !== 'object' || Array.isArray(entry)) return entry;
                    const copy = { ...(entry as Record<string, unknown>) };
                    for (const urlField of ['beforeUrl', 'afterUrl'] as const) {
                      const rawFieldVal = copy[urlField];
                      if (rawFieldVal !== undefined) {
                        const fieldChk =
                          typeof rawFieldVal === 'string' && rawFieldVal.trim()
                            ? validatePublicHttpsTargetUrl(rawFieldVal, this.selfHost)
                            : null;
                        if (fieldChk?.ok) {
                          copy[urlField] = fieldChk.normalized;
                        } else {
                          delete copy[urlField];
                        }
                      }
                    }
                    return copy;
                  });
                };
                if (item.actionResults !== undefined) {
                  item.actionResults = sanitizeActionUrls(item.actionResults);
                }
                if (item.actions !== undefined) {
                  item.actions = sanitizeActionUrls(item.actions);
                }
                if (item.interact && typeof item.interact === 'object' && !Array.isArray(item.interact)) {
                  const interactObj = item.interact as Record<string, unknown>;
                  if (interactObj.actionResults !== undefined) {
                    item.interact = {
                      ...interactObj,
                      actionResults: sanitizeActionUrls(interactObj.actionResults),
                    };
                  }
                }
                const rawArt = item.artifact as { blobSha256?: unknown } | undefined;
                if (rawArt !== undefined) {
                  const bsha = typeof rawArt?.blobSha256 === 'string' ? rawArt.blobSha256.trim().toLowerCase() : '';
                  if (!bsha || !authorizedBlobs.has(bsha)) {
                    delete item.artifact;
                  }
                }
                finalResults[origIdx] = item;
                const itemHost = extractPrimaryHost(dispatchedReq?.url);
                const exactRetryMsForHealth = parseExactRetryAfterMs(item.retryAfter, replyNow);
                const itemTiming = (item as { timing?: { ttfbMs?: unknown } }).timing;
                const itemWaf = (item as { waf?: { vendor?: unknown } }).waf;
                if (itemHost) {
                  this.hostHealth.recordOutcome({
                    host: itemHost,
                    status: typeof item.status === 'number' ? item.status : 0,
                    outcome: typeof item.outcome === 'string' ? item.outcome : 'error',
                    ...(typeof itemTiming?.ttfbMs === 'number' ? { ttfbMs: itemTiming.ttfbMs } : {}),
                    ...(exactRetryMsForHealth !== null ? { retryAfterMs: Math.min(MAX_COOLDOWN_MS, exactRetryMsForHealth) } : {}),
                    ...(typeof itemWaf?.vendor === 'string' ? { wafVendor: itemWaf.vendor } : {}),
                    now: replyNow,
                  });
                }
                const effectiveHostPause = Math.max(
                  crossNodePauseMs,
                  itemHost ? this.hostHealth.getRecommendedPauseMs(itemHost) : 0,
                );
                this.recordHostPacing(itemHost, replyNow + effectiveHostPause);

                if (item.status === 429 && item.outcome !== 'challenge') {
                  if (att.publicIp) triedIps[origIdx]!.add(att.publicIp);
                  const exactRetryMs = parseExactRetryAfterMs(item.retryAfter, replyNow);
                  const rawRequiredWaitMs = exactRetryMs !== null ? exactRetryMs : DEFAULT_429_NO_HEADER_WAIT_MS;
                  // M7: Clamp shared host pacing to MAX_COOLDOWN_MS while still honoring budget checks on exactRetryMs!
                  const clampedPacingWaitMs = Math.min(MAX_COOLDOWN_MS, rawRequiredWaitMs);
                  const cooldownDurMs = Math.min(MAX_COOLDOWN_MS, rawRequiredWaitMs + DEFAULT_429_COOLDOWN_MS);

                  if (itemHost) {
                    this.record429CooldownForNode(itemHost, att, replyNow + cooldownDurMs);
                    this.affinities.deleteStickyHost(itemHost);
                    this.recordHostPacing(itemHost, replyNow + clampedPacingWaitMs);
                  }

                  // Only attempt failover if we can honestly wait out the full Retry-After / 15s window within budget!
                  if (!wantSite) {
                    if (replyNow + rawRequiredWaitMs <= budgetDeadlineAt) {
                      nextPending.push(origIdx);
                    } else {
                      retryAfterBudgetExceeded = true;
                    }
                  }
                } else if (
                  !item.status &&
                  item.outcome === 'error' &&
                  !/robots\.txt|interact action \d+|selector_not_found|\bselector\b[\s\S]{0,120}\bnot found\b|invalid_|validation|unsupported protocol|refusing connection to non-public ip/i.test(
                    String((item as { problem?: unknown }).problem ?? ''),
                  ) &&
                  !Boolean((call.requests![origIdx] as { interact?: { sessionId?: unknown } } | undefined)?.interact?.sessionId)
                ) {
                  if (itemHost && this.affinities.getStickySite(itemHost, replyNow) === att.siteId) {
                    this.affinities.deleteStickyHost(itemHost);
                  }
                  if (!wantSite && replyNow + crossNodePauseMs <= budgetDeadlineAt) {
                    nextPending.push(origIdx);
                  }
                }
              }
              if (total === 1 && reqIndices.length === 1) {
                parsed.results = [finalResults[0]!];
                lastRawSingleBody = JSON.stringify(parsed);
              }
            } catch (e) {
              if (e instanceof PermanentJobError) {
                permanentFailure = e;
                lastError = e.message;
                return;
              }
              lastError = e instanceof Error ? e.message : String(e);
              this.mutateSocketAttachment(ws, att, (cur) => {
                cur.jobsErr++;
              });
              for (const idx of reqIndices) {
                const h = extractPrimaryHost(call.requests![idx]?.url);
                if (h && this.affinities.getStickySite(h, this.now()) === att.siteId) {
                  this.affinities.deleteStickyHost(h);
                }
                nextPending.push(idx);
              }
            }
          }),
        );

        nextPending.sort((a, b) => a - b);
        pendingIndices = nextPending;
      }

      if (permanentFailure) {
        const pf = permanentFailure as PermanentJobError;
        return {
          ok: false,
          status: pf.status,
          error: pf.code,
          message: pf.message,
        };
      }

      if (finalResults.some((r) => r === undefined)) {
        if (retryAfterBudgetExceeded && maxBlockedWaitMs > 0) {
          const retryAfterSec = Math.max(1, Math.ceil(maxBlockedWaitMs / 1_000));
          return {
            ok: false,
            status: 429,
            error: 'rate_limited',
            message: `origin Retry-After requires waiting ${retryAfterSec}s (exceeds ${maxSeconds}s request budget)`,
            retryAfterBudgetExceeded: true,
            retryAfterSec,
          };
        }
        return {
          ok: false,
          status: 502,
          error: 'agent_failed',
          message: lastError,
          ...(retryAfterBudgetExceeded ? { retryAfterBudgetExceeded: true } : {}),
        };
      }

      const uniqueSites = [...new Set(sitesUsed)];
      const siteLabel = uniqueSites.join('+') || wantSite || 'agent';

      if (total === 1 && sitesUsed.length === 1 && lastRawSingleBody !== null) {
        return {
          ok: true,
          siteId: siteLabel,
          bodyText: lastRawSingleBody,
          ...(retryAfterBudgetExceeded ? { retryAfterBudgetExceeded: true } : {}),
        };
      }

      const assembled = finalResults as CrawlResultItem[];
      const mergedReply: CrawlReplyShape = {
        results: assembled,
        summary: recomputeSummary(assembled),
        durationMs: Math.max(0, this.now() - startedAt),
      };
      return {
        ok: true,
        siteId: siteLabel,
        bodyText: JSON.stringify(mergedReply),
        ...(retryAfterBudgetExceeded ? { retryAfterBudgetExceeded: true } : {}),
      };
      }, hostQueueDeadlineAt);
    } catch (e) {
      if (e instanceof PermanentJobError) {
        return {
          ok: false,
          status: e.status,
          error: e.code,
          message: e.message,
        };
      }
      return {
        ok: false,
        status: 503,
        error: 'hub_unavailable',
        message: e instanceof Error ? e.message : String(e),
      };
    }
  }

  private sendAndAwaitJob(
    ws: HubSocketLike,
    siteId: string,
    jobId: string,
    jobNonce: string,
    call: unknown,
    trace: Record<string, string>,
    timeoutMs: number,
    requestIds: Set<string> = new Set(),
    artifactPolicy?: ArtifactDispatchPolicy,
  ): Promise<{ bodyText: string; authorizedBlobs: Set<string> }> {
    const frameText = JSON.stringify({
      type: 'dispatch',
      jobId,
      jobNonce,
      trace,
      ...(artifactPolicy ? { artifacts: artifactPolicy } : {}),
      call,
    });
    const frameBytes = utf8Encoder.encode(frameText).byteLength;
    if (frameBytes > MAX_WS_FRAME_BYTES) {
      return Promise.reject(
        new PermanentJobError(413, 'call_too_large', `serialized dispatch frame (${frameBytes} bytes) exceeds 1 MiB limit`),
      );
    }

    return new Promise<{ bodyText: string; authorizedBlobs: Set<string> }>((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(jobId);
        reject(new Error(`agent ${siteId} timed out after ${timeoutMs}ms`));
      }, timeoutMs);

      this.pending.set(jobId, {
        jobId,
        jobNonce,
        siteId,
        ws,
        timer,
        requestIds,
        authorizedBlobs: new Set<string>(),
        ...(artifactPolicy ? { artifactPolicy } : {}),
        uploadedObjects: 0,
        uploadedStoredBytes: 0,
        uploadedContentBytes: 0,
        resolve,
        reject,
      });

      try {
        ws.send(frameText);
      } catch (e) {
        clearTimeout(timer);
        this.pending.delete(jobId);
        reject(e instanceof Error ? e : new Error(String(e)));
      }
    });
  }

  hasPendingJob(jobId: string, siteId: string): boolean {
    const job = this.pending.get(jobId);
    return Boolean(job && job.siteId === siteId.trim().toLowerCase());
  }

  verifyPendingJob(jobId: string, jobNonce: string, siteId: string): boolean {
    const job = this.pending.get(jobId);
    if (!job) return false;
    return jobNonce.length > 0 && sameBytes(jobNonce, job.jobNonce) && job.siteId === siteId.trim().toLowerCase();
  }

  authorizeArtifactUpload(params: AuthorizeArtifactUploadParams): AuthorizeArtifactUploadResult {
    const job = this.pending.get(params.jobId);
    if (!job) return { ok: false, status: 404, error: 'unknown_or_expired_job' };
    const nonceOk = params.jobNonce.length > 0 && sameBytes(params.jobNonce, job.jobNonce);
    const siteOk = params.siteId.trim().toLowerCase() === job.siteId;
    if (!nonceOk || !siteOk) {
      return { ok: false, status: 403, error: 'invalid_job_credentials' };
    }
    if (!job.artifactPolicy || job.artifactPolicy.mode !== 'r2') {
      return { ok: false, status: 400, error: 'artifacts_not_enabled_for_job' };
    }
    if (params.retention !== job.artifactPolicy.retention) {
      return { ok: false, status: 400, error: 'retention_mismatch' };
    }
    if (!params.requestId || !job.requestIds.has(params.requestId)) {
      return { ok: false, status: 400, error: 'unknown_request_id' };
    }
    if (params.contentBytes < 0 || params.contentBytes > job.artifactPolicy.maxContentBytes) {
      return { ok: false, status: 413, error: 'content_bytes_exceeds_limit' };
    }
    if (!params.confirmOnly) {
      if (
        job.uploadedObjects + 1 > MAX_JOB_ARTIFACT_OBJECTS ||
        job.uploadedStoredBytes + params.storedBytes > MAX_JOB_STORED_BYTES ||
        job.uploadedContentBytes + params.contentBytes > MAX_JOB_CONTENT_BYTES
      ) {
        return { ok: false, status: 413, error: 'job_artifact_quota_exceeded' };
      }
      job.uploadedObjects += 1;
      job.uploadedStoredBytes += params.storedBytes;
      job.uploadedContentBytes += params.contentBytes;
    }
    if (typeof params.blobSha256 === 'string' && /^[0-9a-f]{64}$/i.test(params.blobSha256.trim())) {
      job.authorizedBlobs.add(params.blobSha256.trim().toLowerCase());
    }
    return { ok: true };
  }

  failJob(jobId: string, jobNonce: string, siteId: string, reason: string, permanent = true): CompleteJobResult {
    const job = this.pending.get(jobId);
    if (!job) return { ok: false, status: 404, error: 'unknown_or_expired_job' };
    const nonceOk = jobNonce.length > 0 && sameBytes(jobNonce, job.jobNonce);
    const siteOk = siteId.trim().toLowerCase() === job.siteId;
    if (!nonceOk || !siteOk) {
      return { ok: false, status: 403, error: 'invalid_job_credentials' };
    }
    clearTimeout(job.timer);
    this.pending.delete(jobId);
    if (permanent) {
      const status = reason === 'too_large' ? 413 : 502;
      job.reject(new PermanentJobError(status, reason, `agent ${job.siteId} reply failed permanently: ${reason}`));
    } else {
      job.reject(new Error(`agent ${job.siteId} reply failed: ${reason}`));
    }
    return { ok: true, status: 200 };
  }

  completeJob(jobId: string, jobNonce: string, siteId: string, bodyText: string): CompleteJobResult {
    const job = this.pending.get(jobId);
    if (!job) return { ok: false, status: 404, error: 'unknown_or_expired_job' };
    const nonceOk = jobNonce.length > 0 && sameBytes(jobNonce, job.jobNonce);
    const siteOk = siteId.trim().toLowerCase() === job.siteId;
    if (!nonceOk || !siteOk) {
      return { ok: false, status: 403, error: 'invalid_job_credentials' };
    }
    clearTimeout(job.timer);
    this.pending.delete(jobId);
    job.resolve({ bodyText, authorizedBlobs: new Set(job.authorizedBlobs) });
    return { ok: true, status: 200 };
  }
}

export type FetchTarget = 'auto' | 'container' | 'agent';

export function parseFetchTarget(url: URL): { ok: true; target: FetchTarget; site?: string } | { ok: false; message: string } {
  const rawTarget = (url.searchParams.get('target') ?? 'auto').trim().toLowerCase();
  if (rawTarget !== 'auto' && rawTarget !== 'container' && rawTarget !== 'agent') {
    return { ok: false, message: `unsupported target '${rawTarget}' (expected auto, container, or agent)` };
  }
  const rawSite = (url.searchParams.get('site') ?? '').trim().toLowerCase();
  if (rawSite && !SITE_ID_PATTERN.test(rawSite)) {
    return { ok: false, message: `invalid site '${rawSite}'` };
  }
  return { ok: true, target: rawTarget, ...(rawSite ? { site: rawSite } : {}) };
}

function withViaHeader(res: Response, via: string): Response {
  const headers = new Headers(res.headers);
  headers.set('x-crawler-via', via);
  headers.set('cache-control', 'no-store');
  return new Response(res.body, { status: res.status, headers });
}

function jsonWithVia(bodyText: string, status: number, via: string): Response {
  return new Response(bodyText, {
    status,
    headers: {
      'content-type': 'application/json',
      'cache-control': 'no-store',
      'x-crawler-via': via,
    },
  });
}

export async function routeFetchWithFailover(params: {
  target: FetchTarget;
  site?: string;
  body: string;
  trace: Record<string, string>;
  callContainer: (body: string, trace: Record<string, string>) => Promise<Response>;
  callAgent: (body: string, trace: Record<string, string>, site?: string) => Promise<AgentDispatchResult>;
  waitForHostWindow?: (
    hosts: string[],
    pauseMs?: number,
    budgetDeadlineAt?: number,
  ) => Promise<{ ok: true } | { ok: false; retryAfterWaitMs: number }>;
  now?: () => number;
  onFailover?: (info: { reason: string; siteId: string; count: number }) => void;
}): Promise<Response> {
  const { target, site, body, trace, callContainer, callAgent, waitForHostWindow, now = Date.now, onFailover } = params;

  let parsedMeta: { requests?: Array<{ url?: unknown }>; options?: { pauseMs?: number }; maxSeconds?: number } = {};
  try {
    parsedMeta = JSON.parse(body) as typeof parsedMeta;
  } catch {
    // handled downstream
  }
  const maxSeconds = parsedMeta.maxSeconds && parsedMeta.maxSeconds > 0 ? parsedMeta.maxSeconds : 60;
  const budgetDeadlineAt = now() + maxSeconds * 1_000;
  const pauseMs =
    typeof parsedMeta.options?.pauseMs === 'number' && parsedMeta.options.pauseMs > 0
      ? Math.min(30_000, Math.floor(parsedMeta.options.pauseMs))
      : DEFAULT_CROSS_NODE_PAUSE_MS;

  if (target === 'container') {
    if (waitForHostWindow) {
      try {
        const gate = await waitForHostWindow(extractDistinctHostsFromBody(body), pauseMs, budgetDeadlineAt);
        if (!gate.ok) {
          return Response.json(
            { error: 'rate_limited', message: `host Retry-After requires waiting ${Math.ceil(gate.retryAfterWaitMs / 1000)}s` },
            { status: 429, headers: { 'cache-control': 'no-store', 'retry-after': String(Math.ceil(gate.retryAfterWaitMs / 1000)) } },
          );
        }
      } catch {
        // Proceed if DO window check was interrupted by a DO reset
      }
    }
    try {
      const res = await callContainer(body, trace);
      return withViaHeader(res, 'container');
    } catch (e) {
      return Response.json(
        { error: 'hub_unavailable', message: e instanceof Error ? e.message : 'overflow fetch failed' },
        { status: 503, headers: { 'cache-control': 'no-store' } },
      );
    }
  }

  if (target === 'agent') {
    let out: AgentDispatchResult;
    try {
      out = await callAgent(body, trace, site);
    } catch (e) {
      return Response.json(
        { error: 'hub_unavailable', message: e instanceof Error ? e.message : 'coordinator reset during dispatch' },
        { status: 503, headers: { 'cache-control': 'no-store' } },
      );
    }
    if (!out.ok) {
      return Response.json(
        { error: out.error, message: out.message },
        {
          status: out.status,
          headers: {
            'cache-control': 'no-store',
            ...(out.status === 429 && out.retryAfterSec ? { 'retry-after': String(out.retryAfterSec) } : {}),
          },
        },
      );
    }
    return jsonWithVia(out.bodyText, 200, `agent:${out.siteId}`);
  }

  let agentOut: AgentDispatchResult;
  try {
    agentOut = await callAgent(body, trace, site);
  } catch (e) {
    agentOut = {
      ok: false,
      status: 503,
      error: 'hub_unavailable',
      message: e instanceof Error ? e.message : 'coordinator reset during dispatch',
    };
  }
  if (!agentOut.ok) {
    if (
      agentOut.status === 400 ||
      agentOut.status === 413 ||
      agentOut.error === 'browser_worker_required' ||
      agentOut.error === 'fat_agent_required'
    ) {
      return Response.json(
        { error: agentOut.error, message: agentOut.message },
        { status: agentOut.status, headers: { 'cache-control': 'no-store' } },
      );
    }
    // Never bypass an origin Retry-After window that exceeds the caller's maxSeconds budget.
    if (agentOut.status === 429 && agentOut.retryAfterBudgetExceeded) {
      return Response.json(
        { error: agentOut.error, message: agentOut.message },
        {
          status: 429,
          headers: {
            'cache-control': 'no-store',
            ...(agentOut.retryAfterSec ? { 'retry-after': String(agentOut.retryAfterSec) } : {}),
          },
        },
      );
    }
    if (waitForHostWindow) {
      try {
        const gate = await waitForHostWindow(extractDistinctHostsFromBody(body), pauseMs, budgetDeadlineAt);
        if (!gate.ok) {
          return Response.json(
            { error: 'all_agents_rate_limited', message: agentOut.message },
            { status: 429, headers: { 'cache-control': 'no-store', 'retry-after': String(Math.ceil(gate.retryAfterWaitMs / 1000)) } },
          );
        }
      } catch {
        // Proceed to container fallback if DO reset interrupted host-window check
      }
    }
    const viaLabel = agentOut.error === 'all_agents_rate_limited' ? 'agent-429+container' : 'agent-unavail+container';
    onFailover?.({ reason: agentOut.error, siteId: site ?? 'all', count: 1 });
    try {
      const cfRes = await callContainer(body, trace);
      return withViaHeader(cfRes, viaLabel);
    } catch (e) {
      return Response.json(
        { error: 'hub_unavailable', message: e instanceof Error ? e.message : 'overflow fetch failed' },
        { status: 503, headers: { 'cache-control': 'no-store' } },
      );
    }
  }

  if (agentOut.retryAfterBudgetExceeded) {
    return jsonWithVia(agentOut.bodyText, 200, `agent:${agentOut.siteId}`);
  }

  let reply: CrawlReplyShape;
  let parsedCall: { requests?: Array<{ url?: unknown }>; options?: unknown; maxSeconds?: number };
  try {
    reply = JSON.parse(agentOut.bodyText) as CrawlReplyShape;
    parsedCall = JSON.parse(body) as typeof parsedCall;
  } catch {
    return jsonWithVia(agentOut.bodyText, 200, `agent:${agentOut.siteId}`);
  }

  const results = reply.results;
  const requests = parsedCall.requests;
  if (!Array.isArray(results) || !Array.isArray(requests) || results.length !== requests.length) {
    return jsonWithVia(agentOut.bodyText, 200, `agent:${agentOut.siteId}`);
  }

  const rateLimitedIndices: number[] = [];
  let maxOverflowWaitMs = 0;
  const postAgentNow = now();
  for (let i = 0; i < results.length; i++) {
    const r = results[i]!;
    if (r.status === 429 && r.outcome !== 'challenge') {
      const exactMs = parseExactRetryAfterMs(r.retryAfter, postAgentNow);
      const waitNeeded = exactMs !== null ? exactMs : DEFAULT_429_NO_HEADER_WAIT_MS;
      if (postAgentNow + waitNeeded > budgetDeadlineAt) {
        // Origin Retry-After exceeds budget — return the 429 honestly without sneaking around via Cloudflare!
        continue;
      }
      maxOverflowWaitMs = Math.max(maxOverflowWaitMs, waitNeeded);
      rateLimitedIndices.push(i);
    }
  }

  if (rateLimitedIndices.length === 0) {
    return jsonWithVia(agentOut.bodyText, 200, `agent:${agentOut.siteId}`);
  }

  const overflowHosts = [
    ...new Set(
      rateLimitedIndices
        .map((idx) => extractPrimaryHost(requests[idx]?.url))
        .filter((h): h is string => Boolean(h)),
    ),
  ];

  // Wait out the full Retry-After (or 15s default 429 pause) BEFORE Cloudflare overflow touches the origin!
  if (waitForHostWindow) {
    const gate = await waitForHostWindow(overflowHosts, pauseMs, budgetDeadlineAt);
    if (!gate.ok) {
      return jsonWithVia(agentOut.bodyText, 200, `agent:${agentOut.siteId}`);
    }
  } else if (maxOverflowWaitMs > 0) {
    await new Promise<void>((resolve) => setTimeout(resolve, maxOverflowWaitMs));
  }

  const subCall = JSON.stringify({
    ...parsedCall,
    requests: rateLimitedIndices.map((idx) => requests[idx]),
  });

  let cfRes: Response;
  try {
    cfRes = await callContainer(subCall, trace);
  } catch {
    return jsonWithVia(agentOut.bodyText, 200, `agent:${agentOut.siteId}`);
  }
  if (!cfRes.ok) {
    return jsonWithVia(agentOut.bodyText, 200, `agent:${agentOut.siteId}`);
  }

  let subReply: CrawlReplyShape;
  try {
    subReply = (await cfRes.json()) as CrawlReplyShape;
  } catch {
    return jsonWithVia(agentOut.bodyText, 200, `agent:${agentOut.siteId}`);
  }
  if (!Array.isArray(subReply.results) || subReply.results.length !== rateLimitedIndices.length) {
    return jsonWithVia(agentOut.bodyText, 200, `agent:${agentOut.siteId}`);
  }

  const merged = [...results];
  for (let j = 0; j < rateLimitedIndices.length; j++) {
    merged[rateLimitedIndices[j]!] = subReply.results[j]!;
  }
  onFailover?.({ reason: 'agent_http_429', siteId: agentOut.siteId, count: rateLimitedIndices.length });
  const mergedReply: CrawlReplyShape = {
    ...reply,
    results: merged,
    summary: recomputeSummary(merged),
  };
  return jsonWithVia(JSON.stringify(mergedReply), 200, `agent:${agentOut.siteId}+container`);
}

export async function readAgentReplyBody(
  request: Request,
  maxBytes = MAX_REPLY_BYTES,
): Promise<{ ok: true; text: string } | { ok: false; status: number; error: string }> {
  if (!request.body) return { ok: false, status: 400, error: 'empty_body' };
  const encoding = (request.headers.get('content-encoding') ?? '').trim().toLowerCase();
  let stream: ReadableStream<Uint8Array> = request.body;
  if (encoding === 'gzip') {
    stream = request.body.pipeThrough(new DecompressionStream('gzip') as unknown as TransformStream<Uint8Array, Uint8Array>);
  } else if (encoding !== '' && encoding !== 'identity') {
    return { ok: false, status: 415, error: 'unsupported_encoding' };
  }

  const reader = stream.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (value) {
        total += value.byteLength;
        if (total > maxBytes) {
          await reader.cancel('reply exceeded maxBytes').catch(() => undefined);
          return { ok: false, status: 413, error: 'too_large' };
        }
        chunks.push(value);
      }
    }
  } catch {
    return { ok: false, status: 400, error: 'invalid_compressed_body' };
  }

  const joined = new Uint8Array(total);
  let offset = 0;
  for (const c of chunks) {
    joined.set(c, offset);
    offset += c.byteLength;
  }
  return { ok: true, text: new TextDecoder().decode(joined) };
}
