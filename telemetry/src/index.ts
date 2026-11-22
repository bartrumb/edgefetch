/**
 * Standalone Cloudflare Collector Worker (`telemetry.edgefetch.dev` — `telemetry/src/index.ts`).
 *
 * Routes:
 *  - `POST /v1/dev-errors`:
 *      1. Enforces `<= 8 KiB` (`8192` bytes) streaming body cap (`413` on overflow).
 *      2. Enforces per-IP token-bucket rate limit (`<= 30 req/min`, IPv6 `/64` bucketed, `429` + `Retry-After`).
 *      3. Enforces strict allowlist schema validation (`400` if ANY unexpected key or `http://` / `https://` / `://` URL
 *         substring appears in ANY field — anti-PII & anti-poisoning!).
 *      4. Computes deterministic SHA-256 `fingerprint` over `(version, runtime, spanName, adapterId, wafVendor, httpStatus, errorClass)`
 *         and upserts `error_fingerprints` in D1 (`count = count + 1`, `last_seen_at`, bounded row cap!).
 *  - `GET /v1/dev-errors/summary`:
 *      Bearer `TELEMETRY_ADMIN_TOKEN`-authenticated (`>= 24` chars, constant-time SHA-256 comparison) triage endpoint
 *      returning top broken adapters & WAF regressions sorted by `count DESC, last_seen_at DESC`.
 */

export interface D1PreparedStatementLike {
  bind(...values: unknown[]): D1PreparedStatementLike;
  all<T = Record<string, unknown>>(): Promise<{ results: T[] }>;
  first<T = Record<string, unknown>>(colName?: string): Promise<T | null>;
  run(): Promise<{ success: boolean }>;
}

export interface D1DatabaseLike {
  prepare(query: string): D1PreparedStatementLike;
}

export interface CollectorEnv {
  DB: D1DatabaseLike;
  TELEMETRY_ADMIN_TOKEN?: string;
  MAX_ERROR_FINGERPRINTS?: string;
}

export type CollectorRuntime = 'workers' | 'node' | 'deno' | 'go';

export interface ValidatedDevErrorEvent {
  schemaVersion: 1;
  version: string;
  runtime: CollectorRuntime;
  os: string;
  arch: string;
  mode: string;
  spanName: string;
  adapterId: string;
  wafVendor: string;
  httpStatus: number;
  errorClass: string;
}

export const MAX_INGEST_BODY_BYTES = 8_192; // Strict 8 KiB cap
export const RATE_LIMIT_CAPACITY = 30; // <= 30 req/min per IP bucket
export const RATE_LIMIT_WINDOW_MS = 60_000;
export const DEFAULT_MAX_FINGERPRINT_ROWS = 10_000;
export const MIN_ADMIN_TOKEN_LENGTH = 24;
const MAX_EVENTS_PER_POST = 16;
const MAX_IP_BUCKETS = 4_096;

const SECURITY_JSON_HEADERS: Record<string, string> = {
  'content-type': 'application/json; charset=utf-8',
  'cache-control': 'no-store',
  'x-content-type-options': 'nosniff',
  'x-frame-options': 'DENY',
  'referrer-policy': 'no-referrer',
  'content-security-policy': "default-src 'none'; frame-ancestors 'none'; base-uri 'none'",
};

function jsonResponse(data: unknown, status = 200, extraHeaders?: Record<string, string>): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: extraHeaders ? { ...SECURITY_JSON_HEADERS, ...extraHeaders } : SECURITY_JSON_HEADERS,
  });
}

// ── Per-IP Token-Bucket Rate Limiter (`<= 30 req/min`, IPv6 `/64` normalized) ───────────────────────────────────────

interface TokenBucket {
  tokens: number;
  lastRefillMs: number;
}

const ipBuckets = new Map<string, TokenBucket>();

export function resetCollectorRateLimiters(): void {
  ipBuckets.clear();
}

export function normalizeRateLimitClientIp(rawIp: string | null | undefined): string {
  const trimmed = (rawIp ?? '').trim().toLowerCase();
  if (!trimmed) return 'unknown';
  const noBrackets = trimmed.startsWith('[') && trimmed.endsWith(']') ? trimmed.slice(1, -1) : trimmed;
  if (noBrackets.startsWith('::ffff:')) {
    const v4 = noBrackets.slice('::ffff:'.length);
    if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(v4)) return v4;
  }
  if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(noBrackets)) {
    return noBrackets;
  }
  if (noBrackets.includes(':')) {
    // Canonicalize IPv6 to `/64` prefix (first 4 hextets) so rotating `/64` interface IDs share one bucket.
    const parts = noBrackets.split('::');
    if (parts.length <= 2) {
      const left = parts[0] ? parts[0].split(':').filter(Boolean) : [];
      const right = parts.length === 2 && parts[1] ? parts[1].split(':').filter(Boolean) : [];
      const missing = Math.max(0, 8 - (left.length + right.length));
      const full = [...left, ...Array<string>(missing).fill('0'), ...right]
        .slice(0, 4)
        .map((h) => h.padStart(4, '0'));
      if (full.length === 4) return `${full.join(':')}::/64`;
    }
  }
  return noBrackets.slice(0, 64);
}

export function consumeIpRateLimit(
  rawIp: string | null | undefined,
  nowMs = Date.now(),
): { allowed: true; remaining: number } | { allowed: false; retryAfterSec: number } {
  const key = normalizeRateLimitClientIp(rawIp);
  let bucket = ipBuckets.get(key);
  const refillPerMs = RATE_LIMIT_CAPACITY / RATE_LIMIT_WINDOW_MS;

  if (!bucket) {
    if (ipBuckets.size >= MAX_IP_BUCKETS) {
      // Evict oldest map entry (`O(1)`)
      const oldestKey = ipBuckets.keys().next().value;
      if (oldestKey !== undefined) ipBuckets.delete(oldestKey);
    }
    bucket = { tokens: RATE_LIMIT_CAPACITY - 1, lastRefillMs: nowMs };
    ipBuckets.set(key, bucket);
    return { allowed: true, remaining: Math.floor(bucket.tokens) };
  }

  const elapsed = Math.max(0, nowMs - bucket.lastRefillMs);
  bucket.tokens = Math.min(RATE_LIMIT_CAPACITY, bucket.tokens + elapsed * refillPerMs);
  bucket.lastRefillMs = nowMs;

  if (bucket.tokens < 1) {
    const neededMs = (1 - bucket.tokens) / refillPerMs;
    const retryAfterSec = Math.max(1, Math.ceil(neededMs / 1_000));
    return { allowed: false, retryAfterSec };
  }

  bucket.tokens -= 1;
  // Refresh insertion order for LRU behavior
  ipBuckets.delete(key);
  ipBuckets.set(key, bucket);
  return { allowed: true, remaining: Math.floor(bucket.tokens) };
}

// ── Streaming `<= 8 KiB` Body Reader ───────────────────────────────────────────────────────────────────────────────

async function readBodyCapped8KiB(
  request: Request,
): Promise<{ ok: true; text: string; byteLength: number } | { ok: false; status: 400 | 413; error: string }> {
  const clHeader = request.headers.get('content-length');
  if (clHeader !== null && clHeader.trim() !== '') {
    const cl = Number(clHeader);
    if (!Number.isFinite(cl) || cl < 0) {
      return { ok: false, status: 400, error: 'invalid_content_length' };
    }
    if (cl > MAX_INGEST_BODY_BYTES) {
      await request.body?.cancel().catch(() => undefined);
      return { ok: false, status: 413, error: 'payload_too_large' };
    }
  }
  if (!request.body) {
    return { ok: false, status: 400, error: 'empty_body' };
  }
  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (value && value.byteLength > 0) {
        total += value.byteLength;
        if (total > MAX_INGEST_BODY_BYTES) {
          await reader.cancel('exceeds 8 KiB').catch(() => undefined);
          return { ok: false, status: 413, error: 'payload_too_large' };
        }
        chunks.push(value);
      }
    }
  } catch {
    await reader.cancel().catch(() => undefined);
    return { ok: false, status: 400, error: 'body_read_error' };
  }
  if (total === 0) {
    return { ok: false, status: 400, error: 'empty_body' };
  }
  const merged = new Uint8Array(total);
  let offset = 0;
  for (const c of chunks) {
    merged.set(c, offset);
    offset += c.byteLength;
  }
  return { ok: true, text: new TextDecoder().decode(merged), byteLength: total };
}

// ── Strict Allowlist Schema Validation (Anti-PII & Anti-Poisoning) ─────────────────────────────────────────────────

const EVENT_ALLOWED_KEYS = new Set([
  'schemaVersion',
  'version',
  'runtime',
  'os',
  'arch',
  'mode',
  'spanName',
  'adapterId',
  'wafVendor',
  'httpStatus',
  'errorClass',
]);

const VALID_RUNTIMES = new Set<CollectorRuntime>(['workers', 'node', 'deno', 'go']);
const VERSION_RE = /^[A-Za-z0-9._+-]{1,32}$/;
const SHORT_TOKEN_RE = /^[a-z0-9_-]{1,32}$/;
const MODE_RE = /^[a-z0-9_,-]{1,32}$/;
const SPAN_NAME_RE = /^[A-Za-z0-9._:-]{1,96}$/;
const ADAPTER_ID_RE = /^[A-Za-z0-9._:-]{0,64}$/;
const WAF_VENDOR_RE = /^[a-z0-9_-]{0,32}$/;
const ERROR_CLASS_RE = /^[a-z0-9_:-]{1,64}$/;

function containsForbiddenUrlOrPii(val: string): boolean {
  const lower = val.toLowerCase();
  return (
    lower.includes('http://') ||
    lower.includes('https://') ||
    lower.includes('://') ||
    lower.includes('www.') ||
    lower.includes('?') ||
    lower.includes('#') ||
    lower.includes('@') ||
    lower.includes('/') ||
    lower.includes('\\')
  );
}

export function validateSingleErrorEvent(
  raw: unknown,
): { ok: true; event: ValidatedDevErrorEvent } | { ok: false; error: string } {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    return { ok: false, error: 'event must be a JSON object' };
  }
  if (Object.getPrototypeOf(raw) !== Object.prototype) {
    return { ok: false, error: 'invalid object prototype' };
  }
  const obj = raw as Record<string, unknown>;
  const keys = Object.keys(obj);
  for (const k of keys) {
    if (!EVENT_ALLOWED_KEYS.has(k)) {
      return { ok: false, error: `unexpected field "${k}"` };
    }
    const v = obj[k];
    if (typeof v === 'string' && containsForbiddenUrlOrPii(v)) {
      return { ok: false, error: `forbidden URL or path substring in "${k}"` };
    }
  }
  if (keys.length !== EVENT_ALLOWED_KEYS.size) {
    return { ok: false, error: 'missing required allowlist fields' };
  }
  if (obj.schemaVersion !== 1) {
    return { ok: false, error: 'schemaVersion must be 1' };
  }
  if (typeof obj.version !== 'string' || !VERSION_RE.test(obj.version)) {
    return { ok: false, error: 'invalid version' };
  }
  if (typeof obj.runtime !== 'string' || !VALID_RUNTIMES.has(obj.runtime as CollectorRuntime)) {
    return { ok: false, error: 'invalid runtime' };
  }
  if (typeof obj.os !== 'string' || !SHORT_TOKEN_RE.test(obj.os)) {
    return { ok: false, error: 'invalid os' };
  }
  if (typeof obj.arch !== 'string' || !SHORT_TOKEN_RE.test(obj.arch)) {
    return { ok: false, error: 'invalid arch' };
  }
  if (typeof obj.mode !== 'string' || !MODE_RE.test(obj.mode)) {
    return { ok: false, error: 'invalid mode' };
  }
  if (typeof obj.spanName !== 'string' || !SPAN_NAME_RE.test(obj.spanName)) {
    return { ok: false, error: 'invalid spanName' };
  }
  if (typeof obj.adapterId !== 'string' || !ADAPTER_ID_RE.test(obj.adapterId)) {
    return { ok: false, error: 'invalid adapterId' };
  }
  if (typeof obj.wafVendor !== 'string' || !WAF_VENDOR_RE.test(obj.wafVendor)) {
    return { ok: false, error: 'invalid wafVendor' };
  }
  if (typeof obj.httpStatus !== 'number' || !Number.isInteger(obj.httpStatus) || obj.httpStatus < 0 || obj.httpStatus > 599) {
    return { ok: false, error: 'invalid httpStatus' };
  }
  if (typeof obj.errorClass !== 'string' || !ERROR_CLASS_RE.test(obj.errorClass)) {
    return { ok: false, error: 'invalid errorClass' };
  }

  return {
    ok: true,
    event: {
      schemaVersion: 1,
      version: obj.version,
      runtime: obj.runtime as CollectorRuntime,
      os: obj.os,
      arch: obj.arch,
      mode: obj.mode,
      spanName: obj.spanName,
      adapterId: obj.adapterId,
      wafVendor: obj.wafVendor,
      httpStatus: obj.httpStatus,
      errorClass: obj.errorClass,
    },
  };
}

export function validateIngestPayload(
  rawJson: unknown,
): { ok: true; events: ValidatedDevErrorEvent[] } | { ok: false; error: string } {
  if (!rawJson || typeof rawJson !== 'object' || Array.isArray(rawJson)) {
    return { ok: false, error: 'payload must be a JSON object' };
  }
  const obj = rawJson as Record<string, unknown>;
  const topKeys = Object.keys(obj);

  if (topKeys.length === 1 && topKeys[0] === 'events') {
    if (!Array.isArray(obj.events) || obj.events.length === 0 || obj.events.length > MAX_EVENTS_PER_POST) {
      return { ok: false, error: `events must be a non-empty array of <= ${MAX_EVENTS_PER_POST} items` };
    }
    const validated: ValidatedDevErrorEvent[] = [];
    for (let i = 0; i < obj.events.length; i++) {
      const v = validateSingleErrorEvent(obj.events[i]);
      if (!v.ok) return { ok: false, error: `events[${i}]: ${v.error}` };
      validated.push(v.event);
    }
    return { ok: true, events: validated };
  }

  const single = validateSingleErrorEvent(rawJson);
  if (!single.ok) return single;
  return { ok: true, events: [single.event] };
}

// ── Deterministic SHA-256 Fingerprint & Constant-Time Auth ─────────────────────────────────────────────────────────

const textEncoder = new TextEncoder();

export async function computeErrorFingerprint(ev: Pick<
  ValidatedDevErrorEvent,
  'version' | 'runtime' | 'spanName' | 'adapterId' | 'wafVendor' | 'httpStatus' | 'errorClass'
>): Promise<string> {
  const canonical = JSON.stringify([
    ev.version,
    ev.runtime,
    ev.spanName,
    ev.adapterId,
    ev.wafVendor,
    ev.httpStatus,
    ev.errorClass,
  ]);
  const digest = await crypto.subtle.digest('SHA-256', textEncoder.encode(canonical));
  const bytes = new Uint8Array(digest);
  let hex = '';
  for (let i = 0; i < bytes.length; i++) {
    hex += bytes[i]!.toString(16).padStart(2, '0');
  }
  return hex;
}

async function constantTimeSecretMatch(supplied: string, expected: string): Promise<boolean> {
  const [aBuf, bBuf] = await Promise.all([
    crypto.subtle.digest('SHA-256', textEncoder.encode(supplied)),
    crypto.subtle.digest('SHA-256', textEncoder.encode(expected)),
  ]);
  const a = new Uint8Array(aBuf);
  const b = new Uint8Array(bBuf);
  let diff = supplied.length === expected.length ? 0 : 1;
  for (let i = 0; i < a.length; i++) {
    diff |= a[i]! ^ b[i]!;
  }
  return diff === 0;
}

// ── Worker Entrypoint ──────────────────────────────────────────────────────────────────────────────────────────────

export default {
  async fetch(request: Request, env: CollectorEnv): Promise<Response> {
    const url = new URL(request.url);

    if (request.method === 'GET' && url.pathname === '/health') {
      return jsonResponse({ ok: true, service: 'edgefetch-telemetry' });
    }

    if (request.method === 'POST' && url.pathname === '/v1/dev-errors') {
      const clientIp = request.headers.get('cf-connecting-ip') ?? 'unknown';
      const rl = consumeIpRateLimit(clientIp);
      if (!rl.allowed) {
        return jsonResponse(
          { ok: false, error: 'rate_limited', retryAfterSec: rl.retryAfterSec },
          429,
          { 'retry-after': String(rl.retryAfterSec) },
        );
      }

      const bodyRes = await readBodyCapped8KiB(request);
      if (!bodyRes.ok) {
        return jsonResponse({ ok: false, error: bodyRes.error }, bodyRes.status);
      }

      let parsedJson: unknown;
      try {
        parsedJson = JSON.parse(bodyRes.text);
      } catch {
        return jsonResponse({ ok: false, error: 'invalid_json' }, 400);
      }

      const validated = validateIngestPayload(parsedJson);
      if (!validated.ok) {
        return jsonResponse({ ok: false, error: 'invalid_schema', detail: validated.error }, 400);
      }

      const nowMs = Date.now();
      const rawMaxRows = Number(env.MAX_ERROR_FINGERPRINTS ?? DEFAULT_MAX_FINGERPRINT_ROWS);
      const maxRows = Number.isFinite(rawMaxRows) && rawMaxRows >= 1 ? Math.min(100_000, Math.floor(rawMaxRows)) : DEFAULT_MAX_FINGERPRINT_ROWS;

      const fingerprints: string[] = [];
      for (const ev of validated.events) {
        const fp = await computeErrorFingerprint(ev);
        fingerprints.push(fp);
        await env.DB.prepare(
          `INSERT INTO error_fingerprints (
             fingerprint, schema_version, version, runtime, os, arch, mode,
             span_name, adapter_id, waf_vendor, http_status, error_class,
             count, first_seen_at, last_seen_at
           ) VALUES (?, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
           ON CONFLICT(fingerprint) DO UPDATE SET
             count = error_fingerprints.count + 1,
             last_seen_at = MAX(error_fingerprints.last_seen_at, excluded.last_seen_at),
             os = excluded.os,
             arch = excluded.arch,
             mode = excluded.mode`,
        )
          .bind(
            fp,
            ev.version,
            ev.runtime,
            ev.os,
            ev.arch,
            ev.mode,
            ev.spanName,
            ev.adapterId,
            ev.wafVendor,
            ev.httpStatus,
            ev.errorClass,
            nowMs,
            nowMs,
          )
          .run();
      }

      // Bounded row cap: retain top `maxRows` most recent/frequent fingerprints, evicting oldest rows beyond cap.
      await env.DB.prepare(
        `DELETE FROM error_fingerprints
         WHERE fingerprint IN (
           SELECT fingerprint FROM error_fingerprints
           ORDER BY last_seen_at DESC, count DESC
           LIMIT -1 OFFSET ?
         )`,
      )
        .bind(maxRows)
        .run();

      return jsonResponse({ ok: true, accepted: fingerprints.length, fingerprints }, 202);
    }

    if (request.method === 'GET' && url.pathname === '/v1/dev-errors/summary') {
      const adminSecret = (env.TELEMETRY_ADMIN_TOKEN ?? '').trim();
      if (adminSecret.length < MIN_ADMIN_TOKEN_LENGTH) {
        return jsonResponse({ ok: false, error: 'admin_token_unconfigured' }, 503);
      }
      const authHdr = request.headers.get('authorization') ?? '';
      const bearerMatch = /^Bearer\s+(.+)$/i.exec(authHdr.trim());
      const supplied = bearerMatch?.[1]?.trim() ?? '';
      if (!supplied || !(await constantTimeSecretMatch(supplied, adminSecret))) {
        return jsonResponse(
          { ok: false, error: 'unauthorized' },
          401,
          { 'www-authenticate': 'Bearer realm="edgefetch-telemetry"' },
        );
      }

      const rawLimit = Number(url.searchParams.get('limit') ?? 50);
      const limit = Number.isFinite(rawLimit) ? Math.max(1, Math.min(200, Math.floor(rawLimit))) : 50;
      const versionFilter = (url.searchParams.get('version') ?? '').trim();
      const adapterFilter = (url.searchParams.get('adapterId') ?? '').trim();
      const wafFilter = (url.searchParams.get('wafVendor') ?? '').trim();

      const whereClauses: string[] = [];
      const bindValues: unknown[] = [];
      if (versionFilter && VERSION_RE.test(versionFilter)) {
        whereClauses.push('version = ?');
        bindValues.push(versionFilter);
      }
      if (adapterFilter && ADAPTER_ID_RE.test(adapterFilter)) {
        whereClauses.push('adapter_id = ?');
        bindValues.push(adapterFilter);
      }
      if (wafFilter && WAF_VENDOR_RE.test(wafFilter)) {
        whereClauses.push('waf_vendor = ?');
        bindValues.push(wafFilter);
      }
      const whereSql = whereClauses.length > 0 ? `WHERE ${whereClauses.join(' AND ')}` : '';

      const [itemsRes, totalsRow, adaptersRes, wafRes] = await Promise.all([
        env.DB.prepare(
          `SELECT fingerprint, version, runtime, os, arch, mode, span_name, adapter_id,
                  waf_vendor, http_status, error_class, count, first_seen_at, last_seen_at
           FROM error_fingerprints
           ${whereSql}
           ORDER BY count DESC, last_seen_at DESC
           LIMIT ?`,
        )
          .bind(...bindValues, limit)
          .all<{
            fingerprint: string;
            version: string;
            runtime: string;
            os: string;
            arch: string;
            mode: string;
            span_name: string;
            adapter_id: string;
            waf_vendor: string;
            http_status: number;
            error_class: string;
            count: number;
            first_seen_at: number;
            last_seen_at: number;
          }>(),
        env.DB.prepare(
          `SELECT COUNT(*) AS total_fingerprints, COALESCE(SUM(count), 0) AS total_occurrences
           FROM error_fingerprints ${whereSql}`,
        )
          .bind(...bindValues)
          .first<{ total_fingerprints: number; total_occurrences: number }>(),
        env.DB.prepare(
          `SELECT adapter_id AS adapterId, SUM(count) AS totalCount, MAX(last_seen_at) AS lastSeenAt
           FROM error_fingerprints
           WHERE adapter_id != ''
           GROUP BY adapter_id
           ORDER BY totalCount DESC, lastSeenAt DESC
           LIMIT 20`,
        ).all<{ adapterId: string; totalCount: number; lastSeenAt: number }>(),
        env.DB.prepare(
          `SELECT waf_vendor AS wafVendor, error_class AS errorClass, SUM(count) AS totalCount, MAX(last_seen_at) AS lastSeenAt
           FROM error_fingerprints
           WHERE waf_vendor != ''
           GROUP BY waf_vendor, error_class
           ORDER BY totalCount DESC, lastSeenAt DESC
           LIMIT 20`,
        ).all<{ wafVendor: string; errorClass: string; totalCount: number; lastSeenAt: number }>(),
      ]);

      return jsonResponse({
        ok: true,
        totalFingerprints: Number(totalsRow?.total_fingerprints ?? 0),
        totalOccurrences: Number(totalsRow?.total_occurrences ?? 0),
        topBrokenAdapters: adaptersRes.results,
        topWafRegressions: wafRes.results,
        items: itemsRes.results.map((r) => ({
          fingerprint: r.fingerprint,
          version: r.version,
          runtime: r.runtime,
          os: r.os,
          arch: r.arch,
          mode: r.mode,
          spanName: r.span_name,
          adapterId: r.adapter_id,
          wafVendor: r.waf_vendor,
          httpStatus: r.http_status,
          errorClass: r.error_class,
          count: r.count,
          firstSeenAt: r.first_seen_at,
          lastSeenAt: r.last_seen_at,
        })),
      });
    }

    return jsonResponse({ ok: false, error: 'not_found' }, 404);
  },
};
