/**
 * Pure coordination engine for outbound Home Assistant OS remote crawler nodes (`AgentHubEngine`) and the remote-first
 * failover router (`routeFetchWithFailover`).
 *
 * Routing & load-balancing model:
 *  - Tier 1 (Primary): Load-balances requests across all connected remote HAOS nodes (`site-arm64`, `site-win-vm`,
 *    `site-x86`) via Least-Recently-Used (`lastJobAt` ascending) — sharding multi-URL batches across healthy nodes in
 *    parallel and placing any `(host, siteId)` that receives HTTP `429` into temporary cooldown (`Retry-After` or 5m)
 *    while failing over to remaining healthy remote nodes.
 *  - Tier 2 (Cloudflare Overflow): `CrawlerContainer` stays asleep ($0) during normal operation and is invoked in
 *    `target=auto` ONLY when all remote nodes hit HTTP `429` (or if zero remote nodes are reachable). Store `403`,
 *    `404`, `503`, and `cf-mitigated` challenges are never re-fired to Cloudflare.
 */
import { sameBytes, SITE_ID_PATTERN } from './auth';

export const DEFAULT_429_COOLDOWN_MS = 5 * 60_000; // 5m per-site 429 cooldown when Retry-After is absent
const MIN_COOLDOWN_MS = 10_000;
const MAX_COOLDOWN_MS = 30 * 60_000;
export const MAX_REPLY_BYTES = 20 << 20; // 20 MiB decompressed cap
const MIN_JOB_TIMEOUT_MS = 5_000;
const MAX_JOB_TIMEOUT_MS = 300_000;

export interface AgentAttachment {
  siteId: string;
  arch: string;
  connectedAt: number;
  lastJobAt: number;
  jobsOk: number;
  jobsErr: number;
  replaced?: boolean;
}

export interface HubSocketLike {
  readyState?: number;
  send(message: string): void;
  close(code?: number, reason?: string): void;
  serializeAttachment(value: AgentAttachment): void;
  deserializeAttachment(): unknown;
}

/** Represents a temporary per-host `429` cooldown on a specific remote `siteId` (aliased as `AffinityPin` for UI/MCP compatibility). */
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

export function parseRetryAfterCooldownMs(rawRetryAfter: unknown, now: number): number {
  if (typeof rawRetryAfter === 'string' && rawRetryAfter.trim()) {
    const trimmed = rawRetryAfter.trim();
    if (/^\d+$/.test(trimmed)) {
      const ms = Number(trimmed) * 1_000;
      return Math.min(MAX_COOLDOWN_MS, Math.max(MIN_COOLDOWN_MS, ms));
    }
    const parsedDate = Date.parse(trimmed);
    if (Number.isFinite(parsedDate)) {
      return Math.min(MAX_COOLDOWN_MS, Math.max(MIN_COOLDOWN_MS, parsedDate - now));
    }
  }
  return DEFAULT_429_COOLDOWN_MS;
}

interface PendingJob {
  jobId: string;
  jobNonce: string;
  siteId: string;
  ws: HubSocketLike;
  timer: ReturnType<typeof setTimeout>;
  resolve: (bodyText: string) => void;
  reject: (err: Error) => void;
}

export type AgentDispatchResult =
  | { ok: true; siteId: string; bodyText: string }
  | { ok: false; status: number; error: string; message: string };

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

export function extractPrimaryHost(rawUrl: unknown): string | null {
  if (typeof rawUrl !== 'string' || !rawUrl) return null;
  try {
    return new URL(rawUrl).hostname.toLowerCase().replace(/\.+$/, '') || null;
  } catch {
    return null;
  }
}

export interface CrawlResultItem {
  status?: number;
  outcome?: string;
  retryAfter?: string;
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
  now?: () => number;
  uuid?: () => string;
  sleep?: (ms: number) => Promise<void>;
}

const DEFAULT_CROSS_NODE_PAUSE_MS = 2_000;
const MAX_TRACKED_HOST_PACING = 512;

export class AgentHubEngine {
  private readonly getSockets: (tag?: string) => HubSocketLike[];
  private readonly cooldowns: CooldownStore;
  private readonly now: () => number;
  private readonly uuid: () => string;
  private readonly sleep: (ms: number) => Promise<void>;
  private readonly pending = new Map<string, PendingJob>();
  private readonly hostNextAllowed = new Map<string, number>();

  constructor(deps: AgentHubDeps) {
    this.getSockets = deps.getSockets;
    this.cooldowns = deps.cooldowns;
    this.now = deps.now ?? Date.now;
    this.uuid = deps.uuid ?? (() => crypto.randomUUID());
    this.sleep =
      deps.sleep ??
      (deps.now
        ? async () => undefined
        : (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms)));
  }

  private recordHostPacing(host: string | null, nextAllowedAt: number): void {
    if (!host) return;
    const prev = this.hostNextAllowed.get(host) ?? 0;
    if (nextAllowedAt > prev) {
      this.hostNextAllowed.delete(host);
      this.hostNextAllowed.set(host, nextAllowedAt);
    }
    while (this.hostNextAllowed.size > MAX_TRACKED_HOST_PACING) {
      const oldest = this.hostNextAllowed.keys().next().value;
      if (oldest === undefined) break;
      this.hostNextAllowed.delete(oldest);
    }
  }

  /** Attaches metadata onto a newly accepted HAOS site WebSocket, retiring any stale duplicate socket for that siteId. */
  registerAgent(ws: HubSocketLike, siteId: string, arch?: string | null): AgentAttachment {
    const normalized = siteId.trim().toLowerCase();
    for (const old of this.getSockets(`site:${normalized}`)) {
      if (old === ws) continue;
      this.abortJobsForSocket(old, `site ${normalized} reconnected`);
      retireSocket(old, 'replaced');
    }
    const att: AgentAttachment = {
      siteId: normalized,
      arch: sanitizeArch(arch),
      connectedAt: this.now(),
      lastJobAt: 0,
      jobsOk: 0,
      jobsErr: 0,
    };
    ws.serializeAttachment(att);
    return att;
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

  /**
   * Returns at most one active OPEN socket per `siteId` (the newest `connectedAt`), retiring any older half-open
   * TCP ghost sockets still lingering in `CLOSING` state inside Hibernating Durable Objects.
   */
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

  /** Lists all currently connected HAOS remote agents and their health counters. */
  listAgents(): { connected: number; agents: AgentAttachment[] } {
    const agents = this.activeSocketsBySite()
      .map(({ att }) => ({ ...att }))
      .sort((a, b) => a.siteId.localeCompare(b.siteId));
    return { connected: agents.length, agents };
  }

  /** Lists active per-host `429` remote site cooldowns (`(host, siteId) -> expiresAt`). */
  listAffinities(): AffinityPin[] {
    return this.cooldowns.listPins(this.now());
  }

  /** Clears `429` remote site cooldowns globally or for a single `siteId`. */
  clearAffinities(siteId?: string): void {
    const clean = siteId?.trim().toLowerCase();
    if (clean) {
      this.cooldowns.clearSite(clean);
    } else {
      this.cooldowns.clearAll();
    }
  }

  /**
   * Load-balances a `FetchCall` across connected remote HAOS nodes:
   *  - Orders healthy remote nodes by Least-Recently-Used (`lastJobAt` ascending, tie-broken by `connectedAt` ascending)
   *    so sequential requests and multi-URL batches spread evenly across all connected remote sites.
   *  - If a remote site returns HTTP `429` (`outcome !== 'challenge'`), places `(host, siteId)` into cooldown and
   *    automatically retries that item across remaining non-429 remote sites before returning `429` to the caller
   *    (allowing `routeFetchWithFailover` to reach out via Cloudflare ONLY after remote nodes get `429`).
   */
  async dispatchFetch(
    rawCallBody: string,
    trace: Record<string, string> = {},
    opts: { preferredSite?: string; timeoutMs?: number } = {},
  ): Promise<AgentDispatchResult> {
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
    const defaultTimeout = Math.min(
      MAX_JOB_TIMEOUT_MS,
      Math.max(MIN_JOB_TIMEOUT_MS, ((call.maxSeconds && call.maxSeconds > 0 ? call.maxSeconds : 60) + 5) * 1_000),
    );
    const timeoutMs = opts.timeoutMs ?? defaultTimeout;
    const wantSite = opts.preferredSite?.trim().toLowerCase();

    const initialActive = this.activeSocketsBySite().filter((e) => !wantSite || e.att.siteId === wantSite);
    if (initialActive.length === 0) {
      const msg = wantSite
        ? `HAOS agent site '${wantSite}' is not connected`
        : 'no HAOS remote agents are currently connected';
      return { ok: false, status: 503, error: 'no_agents', message: msg };
    }

    const rawPauseMs =
      call.options && typeof call.options === 'object' && typeof (call.options as { pauseMs?: unknown }).pauseMs === 'number'
        ? Math.min(30_000, Math.max(0, Math.floor((call.options as { pauseMs: number }).pauseMs)))
        : DEFAULT_CROSS_NODE_PAUSE_MS;
    const crossNodePauseMs = rawPauseMs > 0 ? rawPauseMs : DEFAULT_CROSS_NODE_PAUSE_MS;

    const startedAt = this.now();
    const finalResults: Array<CrawlResultItem | undefined> = Array.from({ length: total }, () => undefined);
    const triedSites = Array.from({ length: total }, () => new Set<string>());
    const sitesUsed: string[] = [];
    let pendingIndices = Array.from({ length: total }, (_, i) => i);
    let lastError = 'dispatch failed';
    let lastRawSingleBody: string | null = null;
    let round = 0;

    while (pendingIndices.length > 0 && round < 4) {
      round++;
      const now = this.now();
      const lruCandidates = this.activeSocketsBySite()
        .filter((e) => !wantSite || e.att.siteId === wantSite)
        .sort((a, b) => a.att.lastJobAt - b.att.lastJobAt || a.att.connectedAt - b.att.connectedAt);

      if (lruCandidates.length === 0) break;

      const bySiteBatch = new Map<string, { candidate: { ws: HubSocketLike; att: AgentAttachment }; reqIndices: number[] }>();
      const chosenByHost = new Map<string, { ws: HubSocketLike; att: AgentAttachment }>();
      let cursor = 0;

      for (const reqIdx of pendingIndices) {
        const host = extractPrimaryHost(call.requests[reqIdx]?.url);
        const eligible = lruCandidates.filter((c) => {
          if (triedSites[reqIdx]!.has(c.att.siteId)) return false;
          if (!wantSite && host && this.cooldowns.isCooledDown(host, c.att.siteId, now)) return false;
          return true;
        });
        if (eligible.length === 0) continue;

        // Group same-host URLs within a batch onto a single node so per-host PauseMs + PauseJitterMs holds across nodes,
        // while distinct hosts in the batch shard evenly across all healthy nodes.
        let chosen = host ? chosenByHost.get(host) : undefined;
        if (!chosen || !eligible.some((c) => c.att.siteId === chosen!.att.siteId)) {
          chosen = eligible[cursor % eligible.length]!;
          cursor++;
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
        // Every remaining request has either exhausted all connected remote sites or all remote sites are in 429 cooldown.
        if (finalResults.every((r) => r === undefined) && triedSites.every((s) => s.size === 0)) {
          return {
            ok: false,
            status: 429,
            error: 'all_agents_rate_limited',
            message: 'all connected remote sites are currently in 429 cooldown for this host',
          };
        }
        break;
      }

      // Enforce cluster-wide per-host pauseMs across back-to-back calls routed to different LRU nodes.
      let maxWaitMs = 0;
      const preDispatchNow = this.now();
      for (const host of chosenByHost.keys()) {
        const nextAt = this.hostNextAllowed.get(host) ?? 0;
        if (nextAt > preDispatchNow) {
          maxWaitMs = Math.max(maxWaitMs, nextAt - preDispatchNow);
        }
      }
      if (maxWaitMs > 0) {
        await this.sleep(Math.min(maxWaitMs, 30_000));
      }
      const dispatchStamp = this.now();
      for (const host of chosenByHost.keys()) {
        this.recordHostPacing(host, dispatchStamp + crossNodePauseMs);
      }

      const nextPending: number[] = [];

      await Promise.all(
        [...bySiteBatch.values()].map(async ({ candidate, reqIndices }) => {
          const { ws, att } = candidate;
          for (const idx of reqIndices) triedSites[idx]!.add(att.siteId);

          const jobId = this.uuid();
          const jobNonce = this.uuid();
          // Stamp monotonic LRU ordering across simultaneously dispatched shards so subsequent calls keep rotating cleanly.
          att.lastJobAt = this.now() + sitesUsed.length;
          ws.serializeAttachment(att);

          const subCall =
            reqIndices.length === total && round === 1
              ? call
              : {
                  ...call,
                  requests: reqIndices.map((idx) => call.requests![idx]),
                };

          try {
            const bodyText = await this.sendAndAwaitJob(ws, att.siteId, jobId, jobNonce, subCall, trace, timeoutMs);
            att.jobsOk++;
            att.lastJobAt = this.now();
            ws.serializeAttachment(att);
            sitesUsed.push(att.siteId);

            if (total === 1 && reqIndices.length === 1) {
              lastRawSingleBody = bodyText;
            }

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

            for (let j = 0; j < reqIndices.length; j++) {
              const origIdx = reqIndices[j]!;
              const item = parsed.results[j]!;
              finalResults[origIdx] = item;
              const itemHost = extractPrimaryHost(call.requests![origIdx]?.url);
              this.recordHostPacing(itemHost, this.now() + crossNodePauseMs);

              if (item.status === 429 && item.outcome !== 'challenge') {
                if (itemHost) {
                  const cdMs = parseRetryAfterCooldownMs(item.retryAfter, this.now());
                  this.cooldowns.setCooldown(itemHost, att.siteId, this.now() + cdMs);
                  if (item.retryAfter) {
                    this.recordHostPacing(itemHost, this.now() + Math.min(cdMs, 30_000));
                  }
                }
                if (!wantSite) {
                  nextPending.push(origIdx);
                }
              }
            }
          } catch (e) {
            lastError = e instanceof Error ? e.message : String(e);
            att.jobsErr++;
            ws.serializeAttachment(att);
            for (const idx of reqIndices) nextPending.push(idx);
          }
        }),
      );

      nextPending.sort((a, b) => a - b);
      pendingIndices = nextPending;
    }

    if (finalResults.some((r) => r === undefined)) {
      return { ok: false, status: 502, error: 'agent_failed', message: lastError };
    }

    const uniqueSites = [...new Set(sitesUsed)];
    const siteLabel = uniqueSites.join('+') || wantSite || 'agent';

    // Preserve exact byte-for-byte Go JSON reply in the common 1-request, single-try case.
    if (total === 1 && sitesUsed.length === 1 && lastRawSingleBody !== null) {
      return { ok: true, siteId: siteLabel, bodyText: lastRawSingleBody };
    }

    const assembled = finalResults as CrawlResultItem[];
    const mergedReply: CrawlReplyShape = {
      results: assembled,
      summary: recomputeSummary(assembled),
      durationMs: Math.max(0, this.now() - startedAt),
    };
    return { ok: true, siteId: siteLabel, bodyText: JSON.stringify(mergedReply) };
  }

  private sendAndAwaitJob(
    ws: HubSocketLike,
    siteId: string,
    jobId: string,
    jobNonce: string,
    call: unknown,
    trace: Record<string, string>,
    timeoutMs: number,
  ): Promise<string> {
    return new Promise<string>((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(jobId);
        reject(new Error(`agent ${siteId} timed out after ${timeoutMs}ms`));
      }, timeoutMs);

      this.pending.set(jobId, { jobId, jobNonce, siteId, ws, timer, resolve, reject });

      try {
        ws.send(JSON.stringify({ type: 'dispatch', jobId, jobNonce, trace, call }));
      } catch (e) {
        clearTimeout(timer);
        this.pending.delete(jobId);
        reject(e instanceof Error ? e : new Error(String(e)));
      }
    });
  }

  /** Pre-checks whether `jobId` is actively pending for `siteId` before streaming/decompressing `/agent/reply`. */
  hasPendingJob(jobId: string, siteId: string): boolean {
    const job = this.pending.get(jobId);
    return Boolean(job && job.siteId === siteId.trim().toLowerCase());
  }

  /** Verifies `jobNonce` + `siteId` in constant time and resolves the pending `dispatchFetch` call. */
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
    job.resolve(bodyText);
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

/**
 * Remote-first load-balanced execution router for `POST /fetch`:
 *  - `container`: Cloudflare Go container only (`x-crawler-via: container`).
 *  - `agent`: Remote HAOS node pool only (`x-crawler-via: agent:<siteId>`).
 *  - `auto` (default):
 *     1. Dispatches to the load-balanced remote HAOS pool (`AgentHubDO`) FIRST (`CrawlerContainer` stays asleep).
 *     2. Reaches out via Cloudflare (`callContainer`) ONLY if the remote pool gets HTTP `429` (`all_agents_rate_limited`
 *        or surviving `status === 429` results after trying remote nodes) — or if zero remote nodes are reachable.
 *     3. Store `200`, `304`, `403`, `404`, `503`, and `cf-mitigated` challenges stay strictly on the remote nodes and
 *        NEVER wake Cloudflare.
 */
export async function routeFetchWithFailover(params: {
  target: FetchTarget;
  site?: string;
  body: string;
  trace: Record<string, string>;
  callContainer: (body: string, trace: Record<string, string>) => Promise<Response>;
  callAgent: (body: string, trace: Record<string, string>, site?: string) => Promise<AgentDispatchResult>;
  onFailover?: (info: { reason: string; siteId: string; count: number }) => void;
}): Promise<Response> {
  const { target, site, body, trace, callContainer, callAgent, onFailover } = params;

  if (target === 'container') {
    const res = await callContainer(body, trace);
    return withViaHeader(res, 'container');
  }

  if (target === 'agent') {
    const out = await callAgent(body, trace, site);
    if (!out.ok) {
      return Response.json(
        { error: out.error, message: out.message },
        { status: out.status, headers: { 'cache-control': 'no-store' } },
      );
    }
    return jsonWithVia(out.bodyText, 200, `agent:${out.siteId}`);
  }

  // `target === 'auto'`: Load-balance across remote HAOS nodes first; reach out via Cloudflare ONLY on 429 (or 0 agents online).
  const agentOut = await callAgent(body, trace, site);
  if (!agentOut.ok) {
    if (agentOut.status === 400) {
      return Response.json(
        { error: agentOut.error, message: agentOut.message },
        { status: 400, headers: { 'cache-control': 'no-store' } },
      );
    }
    const viaLabel = agentOut.error === 'all_agents_rate_limited' ? 'agent-429+container' : 'agent-unavail+container';
    onFailover?.({ reason: agentOut.error, siteId: site ?? 'all', count: 1 });
    const cfRes = await callContainer(body, trace);
    return withViaHeader(cfRes, viaLabel);
  }

  let reply: CrawlReplyShape;
  let parsedCall: { requests?: unknown[]; options?: unknown; maxSeconds?: number };
  try {
    reply = JSON.parse(agentOut.bodyText) as CrawlReplyShape;
    parsedCall = JSON.parse(body) as { requests?: unknown[]; options?: unknown; maxSeconds?: number };
  } catch {
    return jsonWithVia(agentOut.bodyText, 200, `agent:${agentOut.siteId}`);
  }

  const results = reply.results;
  const requests = parsedCall.requests;
  if (!Array.isArray(results) || !Array.isArray(requests) || results.length !== requests.length) {
    return jsonWithVia(agentOut.bodyText, 200, `agent:${agentOut.siteId}`);
  }

  // ONLY reach out via Cloudflare for requests that still returned HTTP 429 after exhausting remote nodes.
  // Never re-fire 403, 404, 503, status=0 origin errors, or anti-bot challenges (`outcome === 'challenge'`).
  const rateLimitedIndices: number[] = [];
  for (let i = 0; i < results.length; i++) {
    const r = results[i]!;
    if (r.status === 429 && r.outcome !== 'challenge') {
      rateLimitedIndices.push(i);
    }
  }

  if (rateLimitedIndices.length === 0) {
    return jsonWithVia(agentOut.bodyText, 200, `agent:${agentOut.siteId}`);
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

/**
 * Streams and optionally gunzips an `POST /agent/reply` payload with a hard byte ceiling (`maxBytes`) so a malformed
 * or oversized stream aborts immediately with `413` before exhausting isolate memory.
 */
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
          await reader.cancel().catch(() => undefined);
          return { ok: false, status: 413, error: 'too_large' };
        }
        chunks.push(value);
      }
    }
  } catch {
    return { ok: false, status: 400, error: 'bad_gzip_or_stream' };
  }

  const combined = new Uint8Array(total);
  let offset = 0;
  for (const c of chunks) {
    combined.set(c, offset);
    offset += c.byteLength;
  }
  return { ok: true, text: new TextDecoder().decode(combined) };
}
