/**
 * Deno Deploy Edge Hub Entrypoint (`hub/portable/deno-server.ts`).
 *
 * Bridges EdgeFetch's standard Web `fetch` Worker (`hub/src/index.ts`), `Deno.upgradeWebSocket` for outbound Go
 * `/agent/ws` nodes, `BroadcastChannel('edgefetch-hub-bus')` for cross-region isolate dispatch notifications, and
 * optional `TursoHttpD1Database` + `S3ArtifactBucket` storage bindings.
 */
import { mkdirSync } from 'node:fs';
import net from 'node:net';
import { dirname, join, resolve } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import {
  ACTIVITY_SQLITE_SCHEMA,
  createMemoryActivityStore,
  createSqliteActivityStore,
  sanitizeDetails,
  type ActivityStore,
  type HubEventInput,
} from '../src/activity-log.ts';
import {
  AgentHubEngine,
  createMemoryAffinityStore,
  createMemoryCooldownStore,
  createMemoryHostHealthStore,
  createMemoryHostWindowStore,
  type AgentAttachment,
  type ArtifactDispatchPolicy,
  type AuthorizeArtifactUploadParams,
  type HubSocketLike,
} from '../src/agent-hub.ts';
import { authorizeAgent } from '../src/auth.ts';
import hubWorker from '../src/index.ts';
import {
  createMemoryOAuthStore,
  createSqliteOAuthStore,
  OAUTH_SQLITE_SCHEMA,
  type OAuthClientRecord,
  type OAuthCodeRecord,
  type OAuthStore,
  type RotateRefreshParams,
  type SqlStorageLike,
} from '../src/oauth.ts';
import { validatePublicHttpsTargetUrl } from '../src/overflow.ts';
import { normalizeClientRateLimitIp } from '../src/safe-input.ts';
import { isPublicIpAddress } from './safe-fetch.ts';
import { S3ArtifactBucket } from './s3-bucket.ts';
import { TursoHttpD1Database } from './turso-d1.ts';

declare const Deno: {
  env: { get(key: string): string | undefined; toObject(): Record<string, string> };
  serve(
    options: { port?: number; hostname?: string },
    handler: (req: Request, info: { remoteAddr?: { hostname?: string } }) => Response | Promise<Response>,
  ): unknown;
  upgradeWebSocket(req: Request, options?: { protocol?: string }): { socket: WebSocket; response: Response };
  resolveDns?(query: string, recordType: 'A' | 'AAAA'): Promise<string[]>;
};

export const MAX_DENO_INFLIGHT_PER_IP = 16;
export const MAX_DENO_INFLIGHT_TOTAL = 128;
export const MAX_DENO_REQ_BODY_BYTES = 20 * 1024 * 1024; // 20 MiB inbound body cap matching `portable-server.ts`
export const MAX_DENO_SAFE_RESPONSE_BYTES = 32 * 1024 * 1024; // 32 MiB outbound response cap matching `safe-fetch.ts`
export const MAX_DENO_WS_CONNECTIONS = 128;
export const MAX_DENO_WS_PER_SITE = 16;
const MAX_DENO_WS_FRAME_BYTES = 1 * 1024 * 1024; // 1 MiB (`M6`)
const MAX_DENO_SAFE_HOPS = 5;
const MAX_DENO_BODY_IDLE_MS = 15_000;

const DENO_DEFAULT_SECURITY_HEADERS: ReadonlyArray<readonly [string, string]> = [
  ['x-content-type-options', 'nosniff'],
  ['x-frame-options', 'DENY'],
  ['referrer-policy', 'no-referrer'],
  ['content-security-policy', "default-src 'none'; frame-ancestors 'none'; base-uri 'none'"],
];

export interface DenoHubOptions {
  maxInflightPerIp?: number;
  maxInflightTotal?: number;
  maxReqBodyBytes?: number;
  envOverrides?: Record<string, string | undefined>;
}

class DenoPayloadTooLargeError extends Error {
  constructor(maxBytes: number) {
    super(`Request body exceeds ${maxBytes} bytes limit`);
    this.name = 'DenoPayloadTooLargeError';
  }
}

export function applyDenoSecurityHeaders(res: Response, isHttps = false): Response {
  let needsClone = false;
  for (const [k] of DENO_DEFAULT_SECURITY_HEADERS) {
    if (!res.headers.has(k)) {
      needsClone = true;
      break;
    }
  }
  if (isHttps && !res.headers.has('strict-transport-security')) {
    needsClone = true;
  }
  if (!needsClone) return res;
  try {
    for (const [k, v] of DENO_DEFAULT_SECURITY_HEADERS) {
      if (!res.headers.has(k)) res.headers.set(k, v);
    }
    if (isHttps && !res.headers.has('strict-transport-security')) {
      res.headers.set('strict-transport-security', 'max-age=31536000; includeSubDomains');
    }
    return res;
  } catch {
    // Immutable Headers (e.g. `Response.redirect`) -> clone headers onto a mutable `Response`
    const headers = new Headers(res.headers);
    for (const [k, v] of DENO_DEFAULT_SECURITY_HEADERS) {
      if (!headers.has(k)) headers.set(k, v);
    }
    if (isHttps && !headers.has('strict-transport-security')) {
      headers.set('strict-transport-security', 'max-age=31536000; includeSubDomains');
    }
    return new Response(res.body, {
      status: res.status,
      statusText: res.statusText,
      headers,
    });
  }
}

function capWebReadableStream(
  src: ReadableStream<Uint8Array>,
  maxBytes: number,
  idleOrTotalMs = MAX_DENO_BODY_IDLE_MS,
  onCapExceeded?: () => void,
): ReadableStream<Uint8Array> {
  let reader: ReadableStreamDefaultReader<Uint8Array> | null = null;
  let total = 0;
  let timer: ReturnType<typeof setTimeout> | null = null;
  let finished = false;
  const clearTimer = () => {
    if (timer) {
      clearTimeout(timer);
      timer = null;
    }
  };
  return new ReadableStream<Uint8Array>({
    async pull(ctrl) {
      if (finished) return;
      if (!reader) {
        reader = src.getReader();
        timer = setTimeout(() => {
          if (finished) return;
          finished = true;
          clearTimer();
          void reader?.cancel('Body stream timed out').catch(() => undefined);
          try {
            ctrl.error(new Error('Stream read timed out'));
          } catch {
            // ignore
          }
        }, idleOrTotalMs);
        timer.unref?.();
      }
      try {
        const { done, value } = await reader.read();
        if (done) {
          finished = true;
          clearTimer();
          ctrl.close();
          return;
        }
        if (value) {
          total += value.byteLength;
          if (total > maxBytes) {
            finished = true;
            clearTimer();
            onCapExceeded?.();
            await reader.cancel('Stream exceeds byte limit').catch(() => undefined);
            ctrl.error(new DenoPayloadTooLargeError(maxBytes));
            return;
          }
          ctrl.enqueue(value);
        }
      } catch (err) {
        finished = true;
        clearTimer();
        ctrl.error(err);
      }
    },
    async cancel(reason) {
      finished = true;
      clearTimer();
      await reader?.cancel(reason).catch(() => undefined);
    },
  });
}

class DenoHubSocket implements HubSocketLike {
  private attachment: AgentAttachment | null = null;
  constructor(
    readonly raw: WebSocket,
    readonly tags: string[],
  ) {}
  get readyState(): number {
    return this.raw.readyState;
  }
  send(message: string): void {
    if (this.raw.readyState === WebSocket.OPEN) {
      this.raw.send(message);
    }
  }
  close(code?: number, reason?: string): void {
    try {
      this.raw.close(code, reason);
    } catch {
      // ignore
    }
  }
  serializeAttachment(value: AgentAttachment): void {
    this.attachment = structuredClone(value);
  }
  deserializeAttachment(): unknown {
    return this.attachment ? structuredClone(this.attachment) : null;
  }
}

async function assertDenoResolvedPublicIp(hostname: string): Promise<void> {
  if (typeof Deno === 'undefined' || typeof Deno.resolveDns !== 'function') return;
  const [v4, v6] = await Promise.all([
    Deno.resolveDns(hostname, 'A').catch(() => [] as string[]),
    Deno.resolveDns(hostname, 'AAAA').catch(() => [] as string[]),
  ]);
  const ips = [...v4, ...v6];
  if (ips.length === 0) {
    throw new Error(`DNS resolution returned no A/AAAA records for ${hostname}`);
  }
  for (const ip of ips) {
    if (!isPublicIpAddress(ip)) {
      throw new Error(`SSRF blocked: ${hostname} resolved to non-public IP ${ip}`);
    }
  }
}

function createDenoSafeFetch(selfHost?: string, maxResponseBytes = MAX_DENO_SAFE_RESPONSE_BYTES): typeof fetch {
  return (async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const reqObj = input instanceof Request ? input : null;
    let currentUrl = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url;
    const callerRedirect = init?.redirect ?? reqObj?.redirect ?? 'follow';
    let method = (init?.method ?? reqObj?.method ?? 'GET').toUpperCase();
    if (method === 'CONNECT' || method === 'TRACE' || method === 'TRACK') {
      throw new Error(`HTTP ${method} is not allowed`);
    }
    const hasExplicitBody =
      (init?.body !== undefined && init.body !== null) ||
      (init?.body === undefined && reqObj !== null && reqObj.body !== null);
    if ((method === 'GET' || method === 'HEAD') && hasExplicitBody) {
      throw new TypeError(`Request with ${method} method cannot have body`);
    }
    let body = init?.body ?? (reqObj ? reqObj.body : undefined);
    const baseHeaders = new Headers(init?.headers ?? reqObj?.headers);
    for (const forbidden of [
      'host',
      ':authority',
      'content-length',
      'transfer-encoding',
      'connection',
      'keep-alive',
      'upgrade',
      'te',
      'trailer',
      'proxy-connection',
    ]) {
      baseHeaders.delete(forbidden);
    }
    const initialOrigin = new URL(currentUrl).origin;

    for (let hop = 0; hop <= MAX_DENO_SAFE_HOPS; hop++) {
      const check = validatePublicHttpsTargetUrl(currentUrl, selfHost);
      if (!check.ok) {
        throw new Error(`SSRF blocked outbound URL: ${check.message}`);
      }
      await assertDenoResolvedPublicIp(check.url.hostname);

      const hopHeaders = new Headers(baseHeaders);
      hopHeaders.delete('host');
      if (check.url.origin !== initialOrigin) {
        hopHeaders.delete('authorization');
        hopHeaders.delete('cookie');
        hopHeaders.delete('proxy-authorization');
        hopHeaders.delete('x-api-key');
        hopHeaders.delete('x-goog-api-key');
      }

      const res = await fetch(check.url.toString(), {
        ...init,
        method,
        headers: hopHeaders,
        body: method === 'GET' || method === 'HEAD' || method === 'OPTIONS' ? undefined : body,
        redirect: 'manual',
        signal: init?.signal ? AbortSignal.any([init.signal, AbortSignal.timeout(30_000)]) : AbortSignal.timeout(30_000),
      });

      if (res.status >= 100 && res.status < 200) {
        await res.body?.cancel().catch(() => undefined);
        throw new Error(`HTTP ${res.status} informational response is not allowed`);
      }

      if (res.status >= 300 && res.status < 400) {
        if (callerRedirect === 'manual') return res;
        await res.body?.cancel().catch(() => undefined);
        if (callerRedirect === 'error') {
          throw new TypeError(`Redirect mode is 'error' (HTTP ${res.status})`);
        }
        const loc = res.headers.get('location');
        if (!loc || hop === MAX_DENO_SAFE_HOPS) {
          throw new Error(`Too many or invalid redirects from ${check.url.origin}`);
        }
        currentUrl = new URL(loc, check.url).toString();
        if (res.status === 303 || ((res.status === 301 || res.status === 302) && method === 'POST')) {
          method = 'GET';
          body = undefined;
        }
        continue;
      }

      if (res.body !== null) {
        const cappedStream = capWebReadableStream(res.body, maxResponseBytes, 30_000);
        const wrapped = new Response(cappedStream, {
          status: res.status,
          statusText: res.statusText,
          headers: res.headers,
        });
        Object.defineProperty(wrapped, 'url', { value: check.url.toString(), configurable: true });
        return wrapped;
      }
      return res;
    }
    throw new Error('Max redirects exceeded');
  }) as typeof fetch;
}

function isTruthyDenoFlag(val: string | undefined): boolean {
  const clean = (val ?? '').trim().toLowerCase();
  return clean === '1' || clean === 'true' || clean === 'yes' || clean === 'on' || clean === 'fly';
}

function stripDenoIpPortAndBrackets(addr: string | undefined): string {
  let clean = (addr ?? '').trim();
  if (!clean) return '';
  if (clean.startsWith('[') && clean.includes(']')) {
    clean = clean.slice(1, clean.indexOf(']'));
  } else {
    const v4Port = /^(\d{1,3}(?:\.\d{1,3}){3}):\d{1,5}$/.exec(clean);
    if (v4Port) clean = v4Port[1]!;
  }
  if (clean.toLowerCase().startsWith('::ffff:')) {
    const v4 = clean.slice('::ffff:'.length);
    if (net.isIP(v4) === 4) return v4;
  }
  const zoneIdx = clean.indexOf('%');
  if (zoneIdx >= 0) clean = clean.slice(0, zoneIdx);
  return clean;
}

export function resolveDenoTrustedClientIp(
  req: Request,
  info: { remoteAddr?: { hostname?: string } } | undefined,
  trustProxy: boolean,
  trustFlyClientIp = false,
): string {
  if (trustProxy) {
    if (trustFlyClientIp) {
      const flyStr = req.headers.get('fly-client-ip');
      if (flyStr && !flyStr.includes(',')) {
        const flyCand = stripDenoIpPortAndBrackets(flyStr);
        if (flyCand && net.isIP(flyCand) !== 0) {
          return flyCand;
        }
      }
    }
    const rawXff = req.headers.get('x-forwarded-for') ?? '';
    const parts = rawXff
      .split(',')
      .map((p) => p.trim())
      .filter(Boolean);
    const rightmost = parts.length > 0 ? parts[parts.length - 1] : undefined;
    if (rightmost) {
      const candidate = stripDenoIpPortAndBrackets(rightmost);
      if (candidate && net.isIP(candidate) !== 0) {
        return candidate;
      }
    }
  }
  const sockCandidate = stripDenoIpPortAndBrackets(info?.remoteAddr?.hostname);
  return sockCandidate && net.isIP(sockCandidate) !== 0 ? sockCandidate : '127.0.0.1';
}

const STRICT_SINGLE_HOST_RE =
  /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*(?::([1-9]\d{0,4}))?$/;

export function parseStrictSingleHost(raw: string | undefined | null): string | null {
  if (typeof raw !== 'string') return null;
  if (raw.includes(',') || raw.includes('..') || raw.includes('[') || raw.includes(']')) return null;
  const trimmed = raw.trim();
  if (!trimmed || trimmed.length > 255 || /\s/.test(trimmed)) return null;
  const lower = trimmed.toLowerCase();
  const m = STRICT_SINGLE_HOST_RE.exec(lower);
  if (!m) return null;
  if (m[1] !== undefined) {
    const portNum = Number(m[1]);
    if (!Number.isInteger(portNum) || portNum < 1 || portNum > 65535) return null;
  }
  return lower;
}

function isLoopbackHostOnly(hostname: string): boolean {
  const h = hostname.trim().toLowerCase();
  return h === '127.0.0.1' || h === 'localhost' || h === '[::1]' || h === '::1';
}

export function resolvePublicOrigin(params: {
  canonicalOrigin: string;
  trustProxy: boolean;
  hasExplicitPublicOrigin: boolean;
  hostHeader?: string | null;
  forwardedHostHeader?: string | null;
  forwardedProtoHeader?: string | null;
}): { origin: string; trustedForwardedHost: string | null } {
  const baseOriginUrl = new URL(params.canonicalOrigin);
  if (typeof params.hostHeader === 'string' && params.hostHeader.trim() !== '') {
    if (params.hostHeader.includes(',')) {
      throw new Error('Multiple Host headers are not allowed');
    }
    void new URL(`http://${params.hostHeader.trim()}/`);
  }
  if (params.hasExplicitPublicOrigin || !params.trustProxy) {
    return { origin: baseOriginUrl.origin, trustedForwardedHost: null };
  }

  let proto = baseOriginUrl.protocol.replace(/:$/, '');
  const protoTokens = (params.forwardedProtoHeader ?? '')
    .split(',')
    .map((p) => p.trim().toLowerCase())
    .filter(Boolean);
  const rightmostProto = protoTokens.length > 0 ? protoTokens[protoTokens.length - 1] : undefined;
  if (rightmostProto === 'https' || rightmostProto === 'http') {
    proto = rightmostProto;
  }

  const validHost = parseStrictSingleHost(params.hostHeader);
  const validFwdHost = parseStrictSingleHost(params.forwardedHostHeader);
  let allowLoopbackHostOverride = false;
  if (validHost !== null && isLoopbackHostOnly(baseOriginUrl.hostname)) {
    try {
      allowLoopbackHostOverride = isLoopbackHostOnly(new URL(`http://${validHost}`).hostname);
    } catch {
      allowLoopbackHostOverride = false;
    }
  }
  const authority = allowLoopbackHostOverride && validHost !== null ? validHost : baseOriginUrl.host;
  const trustedForwardedHost =
    allowLoopbackHostOverride && validFwdHost !== null && validHost !== null && validFwdHost === validHost ? validFwdHost : null;

  return {
    origin: new URL(`${proto}://${authority}`).origin,
    trustedForwardedHost,
  };
}

function sanitizeDenoInboundRequest(
  req: Request,
  info: { remoteAddr?: { hostname?: string } } | undefined,
  trustProxy: boolean,
  canonicalOrigin: string,
  hasExplicitPublicOrigin: boolean,
  trustFlyClientIp = false,
  maxReqBodyBytes = MAX_DENO_REQ_BODY_BYTES,
  onBodyCapExceeded?: () => void,
): Request {
  let fallbackReqHost: string | null = null;
  try {
    fallbackReqHost = new URL(req.url).host;
  } catch {
    fallbackReqHost = null;
  }
  const { origin: targetOrigin, trustedForwardedHost } = resolvePublicOrigin({
    canonicalOrigin,
    trustProxy,
    hasExplicitPublicOrigin,
    hostHeader: req.headers.get('host') ?? fallbackReqHost,
    forwardedHostHeader: req.headers.get('x-forwarded-host'),
    forwardedProtoHeader: req.headers.get('x-forwarded-proto'),
  });

  const rawCl = req.headers.get('content-length');
  if (rawCl !== null && rawCl.trim() !== '') {
    const clNum = Number(rawCl);
    if (!Number.isFinite(clNum) || clNum < 0) {
      throw new Error('Malformed Content-Length header');
    }
    if (clNum > maxReqBodyBytes) {
      throw new DenoPayloadTooLargeError(maxReqBodyBytes);
    }
  }

  // Extract raw path + query from `req.url` without re-decoding malformed `%` sequences before `hubWorker` handles them
  const rawUrl = req.url;
  const schemeIdx = rawUrl.indexOf('://');
  const slashIdx = schemeIdx >= 0 ? rawUrl.indexOf('/', schemeIdx + 3) : -1;
  const rawPathAndQuery = slashIdx >= 0 ? rawUrl.slice(slashIdx) : '/';
  const cleanUrl = `${targetOrigin}${rawPathAndQuery}`;

  const trustedIp = resolveDenoTrustedClientIp(req, info, trustProxy, trustFlyClientIp);
  const headers = new Headers();
  req.headers.forEach((val, key) => {
    const lower = key.toLowerCase();
    // `R3-M9`: Strip client-supplied `cf-connecting-ip` / `x-real-ip` / `fly-client-ip` / `true-client-ip`,
    // and strip `x-forwarded-*` unless `EDGEFETCH_TRUST_PROXY=1`.
    if (
      lower === 'cf-connecting-ip' ||
      lower === 'x-real-ip' ||
      lower === 'fly-client-ip' ||
      lower === 'true-client-ip'
    ) {
      return;
    }
    if (!trustProxy && lower.startsWith('x-forwarded-')) return;
    if (lower === 'x-forwarded-host' && trustedForwardedHost === null) return;
    headers.append(key, val);
  });
  headers.set('cf-connecting-ip', trustedIp);
  headers.set('x-real-ip', trustedIp);

  const method = req.method.toUpperCase();
  const hasBody = method !== 'GET' && method !== 'HEAD' && method !== 'OPTIONS' && req.body !== null;
  return new Request(cleanUrl, {
    method,
    headers,
    ...(hasBody
      ? {
          body: capWebReadableStream(req.body!, maxReqBodyBytes, MAX_DENO_BODY_IDLE_MS, onBodyCapExceeded),
          duplex: 'half',
        }
      : {}),
  } as RequestInit);
}

const fallbackSharedOAuthStore: OAuthStore = createMemoryOAuthStore();
const fallbackSharedActivityStore: ActivityStore = createMemoryActivityStore();

function openDenoPersistentStores(dataDir: string): { oauth: OAuthStore; activity: ActivityStore; close: () => void } {
  try {
    const isMemory = dataDir.trim() === ':memory:';
    const sqlitePath = isMemory ? ':memory:' : join(resolve(dataDir), 'hub.sqlite');
    if (!isMemory) {
      mkdirSync(dirname(sqlitePath), { recursive: true });
    }
    const db = new DatabaseSync(sqlitePath);
    db.exec(`PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL; ${OAUTH_SQLITE_SCHEMA} ${ACTIVITY_SQLITE_SCHEMA}`);
    const sqlLike: SqlStorageLike = {
      exec: <T = Record<string, unknown>>(query: string, ...bindings: unknown[]) => {
        const stmt = db.prepare(query);
        const bound = bindings.map((v) => {
          if (v === undefined || v === null) return null;
          if (typeof v === 'boolean') return v ? 1 : 0;
          if (typeof v === 'number' || typeof v === 'bigint' || typeof v === 'string' || v instanceof Uint8Array) return v;
          return JSON.stringify(v);
        });
        const upper = query.trimStart().toUpperCase();
        if (upper.startsWith('SELECT') || upper.startsWith('WITH') || /\bRETURNING\b/i.test(query)) {
          const rows = stmt.all(...bound) as T[];
          return { toArray: () => rows };
        }
        stmt.run(...bound);
        return { toArray: () => [] as T[] };
      },
    };
    return {
      oauth: createSqliteOAuthStore(sqlLike),
      activity: createSqliteActivityStore(sqlLike),
      close: () => {
        try {
          db.close();
        } catch {
          // ignore
        }
      },
    };
  } catch {
    return {
      oauth: fallbackSharedOAuthStore,
      activity: fallbackSharedActivityStore,
      close: () => undefined,
    };
  }
}

export function startDenoHub(opts: DenoHubOptions = {}) {
  const rawEnvMap = Deno.env.toObject();
  const envMap: Record<string, string | undefined> = { ...rawEnvMap, ...(opts.envOverrides ?? {}) };
  const trustProxy = isTruthyDenoFlag(envMap.EDGEFETCH_TRUST_PROXY);
  const trustFlyClientIp =
    trustProxy &&
    ((envMap.EDGEFETCH_TRUST_PROXY ?? '').trim().toLowerCase() === 'fly' ||
      isTruthyDenoFlag(envMap.EDGEFETCH_TRUST_FLY_CLIENT_IP) ||
      Boolean(envMap.FLY_APP_NAME || envMap.FLY_ALLOC_ID || envMap.FLY_REGION));
  const maxInflightPerIp =
    typeof opts.maxInflightPerIp === 'number' && opts.maxInflightPerIp > 0
      ? Math.floor(opts.maxInflightPerIp)
      : MAX_DENO_INFLIGHT_PER_IP;
  const maxInflightTotal =
    typeof opts.maxInflightTotal === 'number' && opts.maxInflightTotal > 0
      ? Math.floor(opts.maxInflightTotal)
      : MAX_DENO_INFLIGHT_TOTAL;
  const maxReqBodyBytes =
    typeof opts.maxReqBodyBytes === 'number' && opts.maxReqBodyBytes > 0
      ? Math.floor(opts.maxReqBodyBytes)
      : MAX_DENO_REQ_BODY_BYTES;
  const inflightByIp = new Map<string, number>();
  let totalInflight = 0;
  let unauthInflight = 0;
  const maxUnauthInflight =
    maxInflightTotal >= 8 ? maxInflightTotal - Math.min(32, Math.floor(maxInflightTotal / 4)) : maxInflightTotal;
  const activeWsBySite = new Map<string, number>();
  const sockets = new Set<DenoHubSocket>();
  const lastHelloLogBySite = new Map<string, number>();
  const engine = new AgentHubEngine({
    getSockets: (tag) => {
      const all = [...sockets];
      return tag ? all.filter((s) => s.tags.includes(tag)) : all;
    },
    cooldowns: createMemoryCooldownStore(),
    hostWindows: createMemoryHostWindowStore(),
    affinities: createMemoryAffinityStore(),
    hostHealth: createMemoryHostHealthStore(),
  });
  const persistentStores = openDenoPersistentStores(envMap.EDGEFETCH_DATA_DIR || './.edgefetch-deno-data');
  const oauth: OAuthStore = persistentStores.oauth;
  const activity: ActivityStore = persistentStores.activity;
  const bus = typeof BroadcastChannel !== 'undefined' ? new BroadcastChannel('edgefetch-hub-bus') : null;
  void bus;

  const tursoUrl = envMap.TURSO_DATABASE_URL;
  const tursoToken = envMap.TURSO_AUTH_TOKEN;
  const metaDb = (envMap.META_TURSO_URL || tursoUrl)
    ? new TursoHttpD1Database({ url: envMap.META_TURSO_URL || tursoUrl!, authToken: tursoToken }).asD1Database()
    : undefined;
  const searchDb = (envMap.SEARCH_TURSO_URL || tursoUrl)
    ? new TursoHttpD1Database({ url: envMap.SEARCH_TURSO_URL || tursoUrl!, authToken: tursoToken }).asD1Database()
    : undefined;
  const s3Bucket =
    envMap.S3_ENDPOINT && envMap.S3_BUCKET && envMap.S3_ACCESS_KEY_ID && envMap.S3_SECRET_ACCESS_KEY
      ? new S3ArtifactBucket({
          endpoint: envMap.S3_ENDPOINT,
          bucket: envMap.S3_BUCKET,
          accessKeyId: envMap.S3_ACCESS_KEY_ID,
          secretAccessKey: envMap.S3_SECRET_ACCESS_KEY,
          region: envMap.S3_REGION || 'auto',
        }).asR2Bucket()
      : undefined;

  let explicitPublicOrigin: string | null = null;
  let selfHost: string | undefined;
  if (envMap.EDGEFETCH_PUBLIC_ORIGIN?.trim()) {
    try {
      const pubUrl = new URL(envMap.EDGEFETCH_PUBLIC_ORIGIN.trim());
      explicitPublicOrigin = pubUrl.origin;
      selfHost = pubUrl.hostname;
    } catch {
      explicitPublicOrigin = null;
      selfHost = undefined;
    }
  }
  const safePublicFetch = createDenoSafeFetch(selfHost);

  const stub = {
    fetch: async () => new Response('use deno upgrade handler', { status: 426 }),
    listAgents: async () => engine.listAgents(),
    listAffinities: async () => engine.listAffinities(),
    clearAffinities: async (siteId?: string) => engine.clearAffinities(siteId),
    listHostHealth: async (limit = 100) => engine.listHostHealth(limit),
    recordHostOutcome: async (p: Parameters<AgentHubEngine['recordHostOutcome']>[0]) => engine.recordHostOutcome(p),
    recordHubEvents: async (events: HubEventInput[]) => {
      for (const ev of events) await activity.recordEvent(ev);
    },
    clearHubEvents: async () => activity.clearEvents(),
    recordMcpCall: async (p: Parameters<ActivityStore['recordMcpCall']>[0]) => activity.recordMcpCall(p),
    getPortalState: async (now: number) => ({
      ...engine.listAgents(),
      affinities: engine.listAffinities(),
      grants: await oauth.listGrants(now),
      mcpClients: await activity.listMcpClients(),
      events: activity.listPortalEvents ? await activity.listPortalEvents(75, 75) : await activity.listEvents(150),
    }),
    waitForHostWindow: async (hosts: string[], pauseMs?: number, dl?: number) => engine.waitForHostWindow(hosts, pauseMs, dl),
    dispatchFetch: async (rawBody: string, trace: Record<string, string>, preferredSite?: string, artifactPolicy?: ArtifactDispatchPolicy) =>
      engine.dispatchFetch(rawBody, trace, { preferredSite, ...(artifactPolicy ? { artifactPolicy } : {}) }),
    hasPendingJob: async (jobId: string, siteId: string) => engine.hasPendingJob(jobId, siteId),
    verifyPendingJob: async (jobId: string, jobNonce: string, siteId: string) => engine.verifyPendingJob(jobId, jobNonce, siteId),
    authorizeArtifactUpload: async (p: AuthorizeArtifactUploadParams) => engine.authorizeArtifactUpload(p),
    failJob: async (jobId: string, jobNonce: string, siteId: string, reason: string, permanent = true) =>
      engine.failJob(jobId, jobNonce, siteId, reason, permanent),
    completeJob: async (jobId: string, jobNonce: string, siteId: string, bodyText: string) =>
      engine.completeJob(jobId, jobNonce, siteId, bodyText),
    oauthPutClient: (c: OAuthClientRecord) => oauth.putClient(c),
    oauthGetClient: (id: string) => oauth.getClient(id),
    oauthPutCode: (c: OAuthCodeRecord) => oauth.putCode(c),
    oauthConsumeCode: (h: string, now: number) => oauth.consumeCode(h, now),
    oauthPutTokenPair: (p: Parameters<OAuthStore['putTokenPair']>[0]) => oauth.putTokenPair(p),
    oauthGetAccessToken: (h: string, now: number) => oauth.getAccessToken(h, now),
    oauthConsumeRefreshToken: (h: string, now: number) => oauth.consumeRefreshToken(h, now),
    oauthRotateRefreshToken: (p: RotateRefreshParams) => oauth.rotateRefreshToken(p),
    oauthListGrants: (now: number) => oauth.listGrants(now),
    oauthRevokeGrant: (id: string) => oauth.revokeGrant(id),
    oauthRevokeByTokenHash: (h: string) => oauth.revokeByTokenHash(h),
    oauthCheckAuthLockout: (b: string, now: number, m?: number) => oauth.checkAuthLockout(b, now, m),
    oauthRecordAuthFailure: (b: string, now: number, w: number, m: number) => oauth.recordAuthFailure(b, now, w, m),
    oauthClearAuthFailures: (b: string) => oauth.clearAuthFailures(b),
  };

  const workerEnv: Record<string, unknown> = {
    ...envMap,
    SAFE_FETCH: safePublicFetch,
    SAFE_PUBLIC_FETCH: safePublicFetch,
    AGENT_HUB: {
      idFromName: () => ({ toString: () => 'deno-global' }),
      get: () => stub,
    },
    ...(metaDb ? { META: metaDb } : {}),
    ...(searchDb ? { SEARCH: searchDb } : {}),
    ...(s3Bucket ? { ARTIFACTS: s3Bucket } : {}),
  };

  const ctx = {
    waitUntil(p: Promise<unknown>) {
      p.catch(() => undefined);
    },
    passThroughOnException() {},
  } as unknown as ExecutionContext;

  const port = Number(envMap.PORT || 8787);
  const canonicalOrigin = explicitPublicOrigin ?? `http://hub.local:${port}`;
  return Deno.serve({ port }, async (req, info) => {
    const methodUpper = req.method.toUpperCase();
    let rawPathname = '/';
    try {
      const schemeIdx = req.url.indexOf('://');
      const slashIdx = schemeIdx >= 0 ? req.url.indexOf('/', schemeIdx + 3) : -1;
      const pathAndQ = slashIdx >= 0 ? req.url.slice(slashIdx) : '/';
      rawPathname = pathAndQ.split('?')[0] ?? '/';
    } catch {
      rawPathname = '/';
    }
    const isHealthProbe =
      (methodUpper === 'GET' || methodUpper === 'HEAD') && (rawPathname === '/health' || rawPathname === '/readyz');
    const hasCallerAuth = Boolean(
      req.headers.get('authorization') || req.headers.get('x-api-key') || req.headers.get('cookie'),
    );
    const clientBucket = normalizeClientRateLimitIp(resolveDenoTrustedClientIp(req, info, trustProxy, trustFlyClientIp));
    const curIpInflight = inflightByIp.get(clientBucket) ?? 0;
    const hitPerIpLimit = curIpInflight >= maxInflightPerIp;
    const hitGlobalLimit = isHealthProbe
      ? totalInflight >= maxInflightTotal + 64
      : totalInflight >= maxInflightTotal || (!hasCallerAuth && unauthInflight >= maxUnauthInflight);

    if (hitPerIpLimit || hitGlobalLimit) {
      await req.body?.cancel().catch(() => undefined);
      return applyDenoSecurityHeaders(
        Response.json(
          { error: 'too_many_requests', message: 'Too many concurrent in-flight requests' },
          {
            status: 429,
            headers: { 'cache-control': 'no-store', 'retry-after': '1' },
          },
        ),
        explicitPublicOrigin?.startsWith('https://') ?? false,
      );
    }

    totalInflight++;
    if (!hasCallerAuth && !isHealthProbe) unauthInflight++;
    inflightByIp.set(clientBucket, curIpInflight + 1);
    let slotReleased = false;
    const releaseInflightSlot = () => {
      if (slotReleased) return;
      slotReleased = true;
      totalInflight = Math.max(0, totalInflight - 1);
      if (!hasCallerAuth && !isHealthProbe) unauthInflight = Math.max(0, unauthInflight - 1);
      const rem = inflightByIp.get(clientBucket) ?? 0;
      if (rem <= 1) inflightByIp.delete(clientBucket);
      else inflightByIp.set(clientBucket, rem - 1);
    };

    let bodyCapExceeded = false;
    try {
      let cleanReq: Request;
      try {
        cleanReq = sanitizeDenoInboundRequest(
          req,
          info,
          trustProxy,
          canonicalOrigin,
          explicitPublicOrigin !== null,
          trustFlyClientIp,
          maxReqBodyBytes,
          () => {
            bodyCapExceeded = true;
          },
        );
      } catch (err) {
        await req.body?.cancel().catch(() => undefined);
        const isTooLarge = err instanceof DenoPayloadTooLargeError;
        return applyDenoSecurityHeaders(
          Response.json(
            {
              error: isTooLarge ? 'payload_too_large' : 'bad_request',
              message: err instanceof Error ? err.message : 'Malformed HTTP request or Host header',
            },
            { status: isTooLarge ? 413 : 400, headers: { 'cache-control': 'no-store' } },
          ),
          explicitPublicOrigin?.startsWith('https://') ?? false,
        );
      }

      const isHttpsReq = cleanReq.url.startsWith('https://');
      if (isHealthProbe) {
        return applyDenoSecurityHeaders(
          new Response(methodUpper === 'HEAD' ? null : '{"ok":true}', {
            status: 200,
            headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' },
          }),
          isHttpsReq,
        );
      }

      const url = new URL(cleanReq.url);
      if (url.pathname === '/agent/ws' && cleanReq.headers.get('upgrade')?.toLowerCase() === 'websocket') {
        const auth = authorizeAgent(cleanReq, workerEnv as never);
        if (!auth.ok) {
          return applyDenoSecurityHeaders(Response.json({ error: 'unauthorized' }, { status: 401 }), isHttpsReq);
        }
        const curSiteWs = activeWsBySite.get(auth.siteId) ?? 0;
        if (sockets.size >= MAX_DENO_WS_CONNECTIONS || curSiteWs >= MAX_DENO_WS_PER_SITE) {
          return applyDenoSecurityHeaders(
            Response.json(
              { error: 'too_many_requests', message: 'Too many active agent WebSocket connections' },
              { status: 429, headers: { 'retry-after': '5', 'cache-control': 'no-store' } },
            ),
            isHttpsReq,
          );
        }
        const offeredProtocols = (cleanReq.headers.get('sec-websocket-protocol') ?? '')
          .split(',')
          .map((p) => p.trim())
          .filter(Boolean);
        const chosenSubprotocol = offeredProtocols.includes('edgefetch-agent') ? 'edgefetch-agent' : undefined;
        const { socket, response } = Deno.upgradeWebSocket(
          req,
          chosenSubprotocol ? { protocol: chosenSubprotocol } : undefined,
        );
        const pubIp = resolveDenoTrustedClientIp(req, info, trustProxy, trustFlyClientIp);
        const hubSock = new DenoHubSocket(socket, [`site:${auth.siteId}`]);
        let wsTracked = false;
        socket.onopen = () => {
          wsTracked = true;
          sockets.add(hubSock);
          activeWsBySite.set(auth.siteId, (activeWsBySite.get(auth.siteId) ?? 0) + 1);
          const att = engine.registerAgent(hubSock, auth.siteId, cleanReq.headers.get('x-agent-arch')?.slice(0, 32) || null, {
            version: cleanReq.headers.get('x-agent-version')?.slice(0, 64) || null,
            publicIp: pubIp,
            capabilities: cleanReq.headers.get('x-agent-capabilities') || null,
          });
          hubSock.send(JSON.stringify({ type: 'hello', siteId: att.siteId }));
        };
        socket.onmessage = (ev) => {
          const byteLen =
            typeof ev.data === 'string'
              ? new TextEncoder().encode(ev.data).byteLength
              : ev.data instanceof ArrayBuffer
                ? ev.data.byteLength
                : 0;
          if (byteLen > MAX_DENO_WS_FRAME_BYTES) {
            hubSock.close(1009, 'Message too big');
            return;
          }
          if (typeof ev.data === 'string') {
            if (ev.data === 'ping') {
              hubSock.send('pong');
              return;
            }
            if (ev.data.length > 2048) return;
            try {
              const msg = JSON.parse(ev.data) as {
                type?: string;
                version?: string;
                arch?: string;
                goVersion?: string;
                capabilities?: string[];
                reconnectAttempt?: number;
              };
              if (msg.type === 'agent_hello' || msg.type === 'hello') {
                const updated = engine.updateAgentHello(hubSock, msg);
                const att = updated ?? (hubSock.deserializeAttachment() as AgentAttachment | null);
                const verifiedSiteId = att?.siteId ?? auth.siteId;
                const nowMs = Date.now();
                const lastLoggedAt = lastHelloLogBySite.get(verifiedSiteId) ?? 0;
                if (nowMs - lastLoggedAt >= 60_000) {
                  if (lastHelloLogBySite.size >= 512) lastHelloLogBySite.clear();
                  lastHelloLogBySite.set(verifiedSiteId, nowMs);
                  void activity.recordEvent({
                    level: 'info',
                    category: 'agent',
                    event: (msg.reconnectAttempt ?? 0) > 0 ? 'agent_reconnected' : 'agent_ready',
                    summary: `Remote node "${verifiedSiteId}" ready (${msg.goVersion ?? 'go'}, ${msg.arch ?? ''})`,
                    details: sanitizeDetails({
                      siteId: verifiedSiteId,
                      version: typeof msg.version === 'string' ? msg.version.slice(0, 64) : null,
                      arch: typeof msg.arch === 'string' ? msg.arch.slice(0, 32) : null,
                      goVersion: typeof msg.goVersion === 'string' ? msg.goVersion.slice(0, 32) : null,
                      capabilities: Array.isArray(msg.capabilities) ? msg.capabilities.slice(0, 16) : [],
                    }),
                  });
                }
              }
            } catch {
              // ignore malformed frame
            }
          }
        };
        socket.onclose = (ev) => {
          sockets.delete(hubSock);
          if (wsTracked) {
            wsTracked = false;
            const rem = activeWsBySite.get(auth.siteId) ?? 0;
            if (rem <= 1) activeWsBySite.delete(auth.siteId);
            else activeWsBySite.set(auth.siteId, rem - 1);
          }
          engine.handleDisconnect(hubSock, ev.reason || `closed_${ev.code}`);
        };
        return response;
      }

      const rawRes = await (hubWorker as { fetch(r: Request, e: unknown, c?: ExecutionContext): Promise<Response> }).fetch(
        cleanReq,
        workerEnv,
        ctx,
      );
      if (bodyCapExceeded && rawRes.status === 400) {
        return applyDenoSecurityHeaders(
          Response.json(
            { error: 'payload_too_large', message: `Request body exceeds ${maxReqBodyBytes} bytes limit` },
            { status: 413, headers: { 'cache-control': 'no-store' } },
          ),
          isHttpsReq,
        );
      }
      return applyDenoSecurityHeaders(rawRes, isHttpsReq);
    } catch (err) {
      if (err instanceof DenoPayloadTooLargeError) {
        return applyDenoSecurityHeaders(
          Response.json({ error: 'payload_too_large', message: err.message }, { status: 413, headers: { 'cache-control': 'no-store' } }),
          explicitPublicOrigin?.startsWith('https://') ?? false,
        );
      }
      return applyDenoSecurityHeaders(
        Response.json(
          { error: 'internal_error', message: err instanceof Error ? err.message : String(err) },
          { status: 500, headers: { 'cache-control': 'no-store' } },
        ),
        explicitPublicOrigin?.startsWith('https://') ?? false,
      );
    } finally {
      releaseInflightSlot();
    }
  });
}

if (typeof Deno !== 'undefined') {
  startDenoHub();
}
