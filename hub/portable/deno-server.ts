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
import { isPublicIpAddress } from './safe-fetch.ts';
import { S3ArtifactBucket } from './s3-bucket.ts';
import { TursoHttpD1Database } from './turso-d1.ts';

interface DenoServerHandle {
  addr?: { port?: number; hostname?: string };
  finished?: Promise<void>;
  shutdown?(): Promise<void>;
}

interface DenoRuntimeLike {
  env?: {
    get(key: string): string | undefined;
    toObject(): Record<string, string>;
  };
  serve?(
    options: {
      port?: number;
      hostname?: string;
      onListen?: (addr: { port: number; hostname: string }) => void;
    },
    handler: (req: Request, info: { remoteAddr?: { hostname?: string } }) => Response | Promise<Response>,
  ): DenoServerHandle;
  upgradeWebSocket?(req: Request, options?: { protocol?: string }): { socket: WebSocket; response: Response };
  resolveDns?(query: string, recordType: 'A' | 'AAAA'): Promise<string[]>;
}

function getDenoRuntime(): DenoRuntimeLike | undefined {
  return (globalThis as { Deno?: DenoRuntimeLike }).Deno;
}

const KNOWN_DENO_ENV_KEYS = [
  'PORT',
  'EDGEFETCH_DATA_DIR',
  'EDGEFETCH_TRUST_PROXY',
  'EDGEFETCH_PUBLIC_ORIGIN',
  'CALLER_TOKEN',
  'EDGEFETCH_CALLER_TOKEN',
  'EDGEFETCH_SERVER_TOKEN',
  'MCP_TOKEN',
  'AGENT_TOKEN',
  'EDGEFETCH_AGENT_TOKEN',
  'AGENT_TOKENS',
  'EDGEFETCH_AGENT_TOKENS',
  'USER_AGENT',
  'EDGEFETCH_USER_AGENT',
  'ROBOTS_BYPASS_HOSTS',
  'EDGEFETCH_ROBOTS_BYPASS_HOSTS',
  'OAUTH_REDIRECT_ALLOWLIST',
  'OTEL_EXPORTER_OTLP_ENDPOINT',
  'OTEL_EXPORTER_OTLP_HEADERS',
  'OTEL_SERVICE_NAME',
  'BOT_SIGNING_PRIVATE_KEY',
  'EDGEFETCH_BOT_SIGNING_KEY',
  'BOT_SIGNING_PUBLIC_KEY',
  'BOT_CONTACT_URL',
  'BOT_KEY_NBF',
  'EDGEFETCH_BOT_KEY_NBF',
  'BOT_KEY_EXP',
  'EDGEFETCH_BOT_KEY_EXP',
  'SERPER_API_KEY',
  'BRAVE_API_KEY',
  'TAVILY_API_KEY',
  'SEARXNG_URL',
  'WEBHOOK_SECRET',
  'CRAWL4AI_API_URL',
  'CRAWL4AI_API_TOKEN',
  'FIRECRAWL_API_URL',
  'FIRECRAWL_API_KEY',
  'SPA_FALLBACK_ORDER',
  'EDGEFETCH_LLM_PROVIDER',
  'EDGEFETCH_LLM_BASE_URL',
  'EDGEFETCH_LLM_API_KEY',
  'EDGEFETCH_LLM_MODEL',
  'EDGEFETCH_ALLOW_LOCAL_LLM_OVERRIDE',
  'OLLAMA_HOST',
  'OPENAI_API_KEY',
  'OPENROUTER_API_KEY',
  'ANTHROPIC_API_KEY',
  'GEMINI_API_KEY',
  'TURSO_DATABASE_URL',
  'TURSO_AUTH_TOKEN',
  'META_TURSO_URL',
  'META_TURSO_AUTH_TOKEN',
  'SEARCH_TURSO_URL',
  'SEARCH_TURSO_AUTH_TOKEN',
  'S3_ENDPOINT',
  'S3_BUCKET',
  'S3_ACCESS_KEY_ID',
  'S3_SECRET_ACCESS_KEY',
  'S3_REGION',
] as const;

function readDenoEnvMap(overrides?: Record<string, string | undefined>): Record<string, string> {
  const base: Record<string, string> = {};
  const denoEnv = getDenoRuntime()?.env;
  if (denoEnv) {
    let loadedAll = false;
    if (typeof denoEnv.toObject === 'function') {
      try {
        Object.assign(base, denoEnv.toObject());
        loadedAll = true;
      } catch {
        // Fallback below when `--allow-env` is scoped to specific keys
      }
    }
    if (!loadedAll && typeof denoEnv.get === 'function') {
      for (const k of KNOWN_DENO_ENV_KEYS) {
        try {
          const val = denoEnv.get(k);
          if (val !== undefined) base[k] = val;
        } catch {
          // ignore denied key
        }
      }
    }
  }
  if (overrides) {
    for (const [k, v] of Object.entries(overrides)) {
      if (v === undefined) delete base[k];
      else base[k] = v;
    }
  }
  return base;
}

const MAX_DENO_WS_FRAME_BYTES = 1 * 1024 * 1024; // 1 MiB (`M6`)
const MAX_DENO_SAFE_HOPS = 5;

export interface DenoSafeFetchOptions {
  allowExplicitLoopbackUrls?: boolean;
  fetchImpl?: typeof fetch;
  resolveDns?: (query: string, recordType: 'A' | 'AAAA') => Promise<string[]>;
}

function validateExplicitLoopbackTargetUrl(raw: string): URL | null {
  const trimmed = raw.trim();
  const authorityMatch = /^https?:\/\/([^/?#]+)/i.exec(trimmed);
  if (!authorityMatch) return null;
  const rawAuthority = authorityMatch[1]!;
  if (!rawAuthority || rawAuthority.includes('@')) return null;

  // Enforce strict literal authority allowlist BEFORE WHATWG `new URL(...)` normalization
  // so decimal/hex/octal/short IPv4 (e.g. 2130706433, 0x7f000001, 0177.0.0.1, 127.1),
  // non-canonical IPv6 (e.g. [0:0:0:0:0:0:0:1]), trailing dots, and invalid ports are rejected.
  const literalMatch = /^(127\.0\.0\.1|localhost|\[::1\])(?::([1-9]\d{0,4}))?$/i.exec(rawAuthority);
  if (!literalMatch) return null;
  if (literalMatch[2] !== undefined) {
    const port = Number(literalMatch[2]);
    if (!Number.isInteger(port) || port < 1 || port > 65535) return null;
  }

  let u: URL;
  try {
    u = new URL(trimmed);
  } catch {
    return null;
  }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') return null;
  if (u.username || u.password) return null;
  const h = u.hostname.toLowerCase();
  if (h !== '127.0.0.1' && h !== 'localhost' && h !== '[::1]') return null;
  return u;
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

async function assertDenoResolvedPublicIp(
  hostname: string,
  resolveDnsFn: ((query: string, recordType: 'A' | 'AAAA') => Promise<string[]>) | undefined = getDenoRuntime()?.resolveDns,
): Promise<void> {
  if (typeof resolveDnsFn !== 'function') return;
  const [v4, v6] = await Promise.all([
    resolveDnsFn(hostname, 'A').catch(() => [] as string[]),
    resolveDnsFn(hostname, 'AAAA').catch(() => [] as string[]),
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

export function createDenoSafeFetch(selfHost?: string, opts: DenoSafeFetchOptions = {}): typeof fetch {
  const doFetch = opts.fetchImpl ?? fetch;
  return (async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const reqObj = input instanceof Request ? input : null;
    let currentUrl = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url;
    const callerRedirect = init?.redirect ?? reqObj?.redirect ?? 'follow';
    let method = (init?.method ?? reqObj?.method ?? 'GET').toUpperCase();
    let body = init?.body ?? (reqObj ? reqObj.body : undefined);
    const currentHeaders = new Headers(init?.headers ?? reqObj?.headers);
    let initialOrigin = '';

    for (let hop = 0; hop <= MAX_DENO_SAFE_HOPS; hop++) {
      const allowLoopbackThisHop = hop === 0 && opts.allowExplicitLoopbackUrls === true;
      const loopbackUrl = allowLoopbackThisHop ? validateExplicitLoopbackTargetUrl(currentUrl) : null;
      let validatedUrl: URL;
      if (loopbackUrl) {
        validatedUrl = loopbackUrl;
      } else {
        const check = validatePublicHttpsTargetUrl(currentUrl, selfHost);
        if (!check.ok) {
          throw new Error(`SSRF blocked outbound URL: ${check.message}`);
        }
        validatedUrl = check.url;
        await assertDenoResolvedPublicIp(validatedUrl.hostname, opts.resolveDns);
      }

      if (hop === 0) {
        initialOrigin = validatedUrl.origin;
      }

      const hopHeaders = new Headers(currentHeaders);
      hopHeaders.delete('host');
      if (validatedUrl.origin !== initialOrigin) {
        hopHeaders.delete('authorization');
        hopHeaders.delete('cookie');
        hopHeaders.delete('proxy-authorization');
        hopHeaders.delete('x-api-key');
        hopHeaders.delete('x-goog-api-key');
      }

      const res = await doFetch(validatedUrl.toString(), {
        ...init,
        method,
        headers: hopHeaders,
        body: method === 'GET' || method === 'HEAD' || method === 'OPTIONS' ? undefined : body,
        redirect: 'manual',
        signal: init?.signal ? AbortSignal.any([init.signal, AbortSignal.timeout(30_000)]) : AbortSignal.timeout(30_000),
      });

      if (res.status >= 300 && res.status < 400) {
        if (callerRedirect === 'manual') return res;
        await res.body?.cancel().catch(() => undefined);
        if (callerRedirect === 'error') {
          throw new TypeError(`Redirect mode is 'error' (HTTP ${res.status})`);
        }
        const loc = res.headers.get('location');
        if (!loc || hop === MAX_DENO_SAFE_HOPS) {
          throw new Error(`Too many or invalid redirects from ${validatedUrl.origin}`);
        }
        currentUrl = new URL(loc, validatedUrl).toString();
        if (res.status === 303 || ((res.status === 301 || res.status === 302) && method === 'POST')) {
          method = 'GET';
          body = undefined;
          currentHeaders.delete('content-type');
          currentHeaders.delete('content-length');
        }
        continue;
      }
      return res;
    }
    throw new Error('Max redirects exceeded');
  }) as typeof fetch;
}

function isTruthyDenoFlag(val: string | undefined): boolean {
  const clean = (val ?? '').trim().toLowerCase();
  return clean === '1' || clean === 'true' || clean === 'yes' || clean === 'on';
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

function resolveDenoTrustedClientIp(
  req: Request,
  info: { remoteAddr?: { hostname?: string } } | undefined,
  trustProxy: boolean,
): string {
  if (trustProxy) {
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

  // Extract raw path + query from `req.url` without re-decoding malformed `%` sequences before `hubWorker` handles them
  const rawUrl = req.url;
  const schemeIdx = rawUrl.indexOf('://');
  const slashIdx = schemeIdx >= 0 ? rawUrl.indexOf('/', schemeIdx + 3) : -1;
  const rawPathAndQuery = slashIdx >= 0 ? rawUrl.slice(slashIdx) : '/';
  const cleanUrl = `${targetOrigin}${rawPathAndQuery}`;

  const trustedIp = resolveDenoTrustedClientIp(req, info, trustProxy);
  const headers = new Headers();
  req.headers.forEach((val, key) => {
    const lower = key.toLowerCase();
    // `R3-M9`: Strip client-supplied `cf-connecting-ip` / `x-real-ip`, and strip `x-forwarded-*` unless `EDGEFETCH_TRUST_PROXY=1`.
    if (lower === 'cf-connecting-ip' || lower === 'x-real-ip') return;
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
    ...(hasBody ? { body: req.body, duplex: 'half' } : {}),
  } as RequestInit);
}

function openDenoPersistentStores(
  dataDir: string,
  ephemeralStores = false,
): { oauth: OAuthStore; activity: ActivityStore; close: () => void } {
  if (ephemeralStores || dataDir === ':memory:') {
    return {
      oauth: createMemoryOAuthStore(),
      activity: createMemoryActivityStore(),
      close: () => {},
    };
  }
  try {
    const sqlitePath = join(resolve(dataDir), 'hub.sqlite');
    mkdirSync(dirname(sqlitePath), { recursive: true });
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
          // ignore close errors
        }
      },
    };
  } catch {
    return {
      oauth: createMemoryOAuthStore(),
      activity: createMemoryActivityStore(),
      close: () => {},
    };
  }
}

export interface DenoHubOptions {
  port?: number;
  hostname?: string;
  dataDir?: string;
  envOverrides?: Record<string, string | undefined>;
  ephemeralStores?: boolean;
  fetchImpl?: typeof fetch;
  resolveDns?: (query: string, recordType: 'A' | 'AAAA') => Promise<string[]>;
}

export interface DenoHubHandlerHandle {
  handler: (req: Request, info?: { remoteAddr?: { hostname?: string } }) => Promise<Response>;
  workerEnv: Record<string, unknown>;
  port: number;
  getBoundPort: () => number;
  setBoundPort: (port: number) => void;
  canonicalOrigin: () => string;
  flushPending: () => Promise<void>;
  close: () => Promise<void>;
}

export interface DenoHubInstance {
  server: DenoServerHandle;
  readonly port: number;
  workerEnv: Record<string, unknown>;
  handler: (req: Request, info?: { remoteAddr?: { hostname?: string } }) => Promise<Response>;
  flushPending: () => Promise<void>;
  close: () => Promise<void>;
}

export function createDenoHubHandler(options: DenoHubOptions = {}): DenoHubHandlerHandle {
  const envMap = readDenoEnvMap(options.envOverrides);
  const trustProxy = isTruthyDenoFlag(envMap.EDGEFETCH_TRUST_PROXY);
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
  const persistentStores = openDenoPersistentStores(
    options.dataDir ?? envMap.EDGEFETCH_DATA_DIR ?? './.edgefetch-deno-data',
    options.ephemeralStores,
  );
  const oauth: OAuthStore = persistentStores.oauth;
  const activity: ActivityStore = persistentStores.activity;
  const bus = typeof BroadcastChannel !== 'undefined' ? new BroadcastChannel('edgefetch-hub-bus') : null;

  const tursoUrl = envMap.TURSO_DATABASE_URL;
  const tursoToken = envMap.TURSO_AUTH_TOKEN;
  const metaDb = (envMap.META_TURSO_URL || tursoUrl)
    ? new TursoHttpD1Database({ url: envMap.META_TURSO_URL || tursoUrl!, authToken: envMap.META_TURSO_AUTH_TOKEN ?? tursoToken }).asD1Database()
    : undefined;
  const searchDb = (envMap.SEARCH_TURSO_URL || tursoUrl)
    ? new TursoHttpD1Database({ url: envMap.SEARCH_TURSO_URL || tursoUrl!, authToken: envMap.SEARCH_TURSO_AUTH_TOKEN ?? tursoToken }).asD1Database()
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
  const safeFetch = createDenoSafeFetch(selfHost, {
    allowExplicitLoopbackUrls: true,
    ...(options.fetchImpl ? { fetchImpl: options.fetchImpl } : {}),
    ...(options.resolveDns ? { resolveDns: options.resolveDns } : {}),
  });
  const safePublicFetch = createDenoSafeFetch(selfHost, {
    allowExplicitLoopbackUrls: false,
    ...(options.fetchImpl ? { fetchImpl: options.fetchImpl } : {}),
    ...(options.resolveDns ? { resolveDns: options.resolveDns } : {}),
  });

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
    SAFE_FETCH: safeFetch,
    SAFE_PUBLIC_FETCH: safePublicFetch,
    CALLER_TOKEN: envMap.CALLER_TOKEN ?? envMap.EDGEFETCH_CALLER_TOKEN ?? envMap.EDGEFETCH_SERVER_TOKEN,
    MCP_TOKEN: envMap.MCP_TOKEN,
    AGENT_TOKEN: envMap.AGENT_TOKEN ?? envMap.EDGEFETCH_AGENT_TOKEN,
    AGENT_TOKENS: envMap.AGENT_TOKENS ?? envMap.EDGEFETCH_AGENT_TOKENS,
    USER_AGENT: envMap.USER_AGENT ?? envMap.EDGEFETCH_USER_AGENT,
    ROBOTS_BYPASS_HOSTS: envMap.ROBOTS_BYPASS_HOSTS ?? envMap.EDGEFETCH_ROBOTS_BYPASS_HOSTS,
    OTEL_EXPORTER_OTLP_ENDPOINT: envMap.OTEL_EXPORTER_OTLP_ENDPOINT,
    OTEL_EXPORTER_OTLP_HEADERS: envMap.OTEL_EXPORTER_OTLP_HEADERS,
    OTEL_SERVICE_NAME: envMap.OTEL_SERVICE_NAME,
    BOT_SIGNING_PRIVATE_KEY: envMap.BOT_SIGNING_PRIVATE_KEY ?? envMap.EDGEFETCH_BOT_SIGNING_KEY,
    BOT_SIGNING_PUBLIC_KEY: envMap.BOT_SIGNING_PUBLIC_KEY,
    BOT_CONTACT_URL: envMap.BOT_CONTACT_URL,
    BOT_KEY_NBF: envMap.BOT_KEY_NBF ?? envMap.EDGEFETCH_BOT_KEY_NBF,
    BOT_KEY_EXP: envMap.BOT_KEY_EXP ?? envMap.EDGEFETCH_BOT_KEY_EXP,
    AGENT_HUB: {
      idFromName: () => ({ toString: () => 'deno-global' }),
      get: () => stub,
    },
    ...(metaDb ? { META: metaDb } : {}),
    ...(searchDb ? { SEARCH: searchDb } : {}),
    ...(s3Bucket ? { ARTIFACTS: s3Bucket } : {}),
  };

  const pendingWaitUntil = new Set<Promise<unknown>>();
  const ctx = {
    waitUntil(p: Promise<unknown>) {
      const tracked = Promise.resolve(p)
        .catch(() => undefined)
        .finally(() => {
          pendingWaitUntil.delete(tracked);
        });
      pendingWaitUntil.add(tracked);
    },
    passThroughOnException() {},
  } as unknown as ExecutionContext;

  const rawEnvPort = envMap.PORT !== undefined && envMap.PORT !== '' ? Number(envMap.PORT) : 8787;
  const port = options.port ?? (Number.isFinite(rawEnvPort) ? rawEnvPort : 8787);
  let boundPort = port;
  const canonicalOrigin = () => explicitPublicOrigin ?? `http://hub.local:${boundPort}`;

  const handler = async (req: Request, info?: { remoteAddr?: { hostname?: string } }): Promise<Response> => {
    const cleanReq = sanitizeDenoInboundRequest(req, info, trustProxy, canonicalOrigin(), explicitPublicOrigin !== null);
    const url = new URL(cleanReq.url);
    if (url.pathname === '/agent/ws' && cleanReq.headers.get('upgrade')?.toLowerCase() === 'websocket') {
      const auth = authorizeAgent(cleanReq, workerEnv as never);
      if (!auth.ok) {
        return Response.json({ error: 'unauthorized' }, { status: 401 });
      }
      const deno = getDenoRuntime();
      if (!deno || typeof deno.upgradeWebSocket !== 'function') {
        return Response.json({ error: 'websocket_upgrade_unavailable' }, { status: 501 });
      }
      const offeredProtocols = (cleanReq.headers.get('sec-websocket-protocol') ?? '')
        .split(',')
        .map((p) => p.trim())
        .filter(Boolean);
      const chosenSubprotocol = offeredProtocols.includes('edgefetch-agent') ? 'edgefetch-agent' : undefined;
      const { socket, response } = deno.upgradeWebSocket(
        req,
        chosenSubprotocol ? { protocol: chosenSubprotocol } : undefined,
      );
      const pubIp = resolveDenoTrustedClientIp(req, info, trustProxy);
      const hubSock = new DenoHubSocket(socket, [`site:${auth.siteId}`]);
      socket.onopen = () => {
        sockets.add(hubSock);
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
        engine.handleDisconnect(hubSock, ev.reason || `closed_${ev.code}`);
      };
      return response;
    }
    return (hubWorker as { fetch(r: Request, e: unknown, c?: ExecutionContext): Promise<Response> }).fetch(cleanReq, workerEnv, ctx);
  };

  const flushPending = async (): Promise<void> => {
    while (pendingWaitUntil.size > 0) {
      await Promise.allSettled([...pendingWaitUntil]);
    }
  };

  const close = async (): Promise<void> => {
    await flushPending();
    for (const sock of sockets) {
      sock.close(1001, 'shutdown');
    }
    sockets.clear();
    try {
      bus?.close();
    } catch {
      // ignore
    }
    persistentStores.close();
  };

  return {
    handler,
    workerEnv,
    port,
    getBoundPort: () => boundPort,
    setBoundPort: (p: number) => {
      if (Number.isFinite(p) && p > 0) boundPort = p;
    },
    canonicalOrigin,
    flushPending,
    close,
  };
}

export function startDenoHub(options: DenoHubOptions = {}): DenoHubInstance {
  const deno = getDenoRuntime();
  if (!deno || typeof deno.serve !== 'function') {
    throw new Error('Deno.serve is unavailable in this runtime; use createDenoHubHandler() instead.');
  }
  const created = createDenoHubHandler(options);
  const server = deno.serve(
    {
      port: created.port,
      ...(options.hostname ? { hostname: options.hostname } : {}),
      onListen: (addr) => {
        if (addr?.port) created.setBoundPort(addr.port);
      },
    },
    (req, info) => created.handler(req, info),
  );
  if (server.addr?.port) {
    created.setBoundPort(server.addr.port);
  }
  return {
    server,
    get port(): number {
      return server.addr?.port ?? created.getBoundPort();
    },
    workerEnv: created.workerEnv,
    handler: created.handler,
    flushPending: created.flushPending,
    close: async () => {
      await server.shutdown?.().catch(() => undefined);
      await created.close();
    },
  };
}

if (getDenoRuntime() !== undefined && (import.meta as { main?: boolean }).main === true) {
  startDenoHub();
}
