/**
 * Deno Deploy Edge Hub Entrypoint (`hub/portable/deno-server.ts`).
 *
 * Bridges EdgeFetch's standard Web `fetch` Worker (`hub/src/index.ts`), `Deno.upgradeWebSocket` for outbound Go
 * `/agent/ws` nodes, `BroadcastChannel('edgefetch-hub-bus')` for cross-region isolate dispatch notifications, and
 * optional `TursoHttpD1Database` + `S3ArtifactBucket` storage bindings.
 */
import dns from 'node:dns';
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
import { authorizeAgent, isValidSecretMatch } from '../src/auth.ts';
import {
  createMemoryHubSettingsStore,
  createSqliteHubSettingsStore,
  HUB_SETTINGS_SQLITE_SCHEMA,
  type HubSettingsStore,
} from '../src/dev-telemetry.ts';
import { resolveSessionSecret } from '../src/github-auth.ts';
import hubWorker from '../src/index.ts';
import {
  createMemoryMcpVaultStore,
  createSqliteMcpVaultStore,
  MCP_VAULT_SQLITE_SCHEMA,
  type McpVaultStore,
  type PendingMcpOAuthStateRow,
  type StoredMcpServerRow,
} from '../src/mcp-vault.ts';
import {
  ADMIN_COOKIE_NAME,
  createMemoryOAuthStore,
  createSqliteOAuthStore,
  OAUTH_SQLITE_SCHEMA,
  verifyAdminSessionCookie,
  type HubUserRecord,
  type OAuthClientRecord,
  type OAuthCodeRecord,
  type OAuthStore,
  type RotateRefreshParams,
  type SqlStorageLike,
  type UserRole,
} from '../src/oauth.ts';
import { markRequestVerifiedInProcess } from '../src/otel.ts';
import { validatePublicHttpsTargetUrl } from '../src/overflow.ts';
import { normalizeClientRateLimitIp } from '../src/safe-input.ts';
import {
  createSafeOutboundFetch,
  isPublicIpAddress,
  stripSensitiveCrossOriginHeaders,
  validateExplicitLoopbackTargetUrl,
  type LookupResolverFn,
} from './safe-fetch.ts';
import { S3ArtifactBucket } from './s3-bucket.ts';
import { NodeFsR2Bucket } from './node-adapters.ts';
import {
  buildTrackerListWsFrames,
  DAILY_TRACKER_POLL_INTERVAL_MS,
  INITIAL_PORTABLE_TRACKER_DELAY_MS,
  isTrackerListDisabled,
  loadStoredTrackerList,
  refreshHubTrackerList,
  resolveExtraNeverBlockHosts,
  type RefreshTrackerListOutcome,
} from '../src/tracker-list.ts';
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
  unrefTimer?(id: number): void;
}

function getDenoRuntime(): DenoRuntimeLike | undefined {
  return (globalThis as { Deno?: DenoRuntimeLike }).Deno;
}

const KNOWN_DENO_ENV_KEYS = [
  'PORT',
  'EDGEFETCH_DATA_DIR',
  'EDGEFETCH_TRUST_PROXY',
  'EDGEFETCH_TRUST_FLY_CLIENT_IP',
  'FLY_APP_NAME',
  'FLY_ALLOC_ID',
  'FLY_REGION',
  'RENDER_EXTERNAL_URL',
  'RENDER_EXTERNAL_HOSTNAME',
  'RAILWAY_PUBLIC_DOMAIN',
  'RAILWAY_STATIC_URL',
  'EDGEFETCH_PUBLIC_ORIGIN',
  'EDGEFETCH_MAX_CONNECTIONS_PER_IP',
  'SESSION_SECRET',
  'EDGEFETCH_SESSION_SECRET',
  'GITHUB_CLIENT_ID',
  'GITHUB_CLIENT_SECRET',
  'GITHUB_ALLOWED_USERS',
  'GITHUB_OWNER_ID',
  'GITHUB_OWNER_LOGIN',
  'SIGNUP_MODE',
  'VAULT_MASTER_KEY',
  'EDGEFETCH_VAULT_MASTER_KEY',
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
  'EDGEFETCH_DISABLE_UPDATE_CHECK',
  'EDGEFETCH_TRACKER_LIST',
  'EDGEFETCH_DEV_TELEMETRY',
  'EDGEFETCH_DEV_TELEMETRY_ENDPOINT',
  'EDGEFETCH_DEV_TELEMETRY_URL',
  'DO_NOT_TRACK',
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

export const MAX_DENO_INFLIGHT_PER_IP = 16;
export const MAX_DENO_INFLIGHT_TOTAL = 128;
export const MAX_DENO_REQ_BODY_BYTES = 20 * 1024 * 1024; // 20 MiB inbound body cap matching `portable-server.ts`
export const MAX_DENO_SAFE_RESPONSE_BYTES = 32 * 1024 * 1024; // 32 MiB outbound response cap matching `safe-fetch.ts`
export const MAX_DENO_WS_CONNECTIONS = 128;
export const MAX_DENO_WS_PER_SITE = 16;
export const MAX_DENO_WS_PER_IP = 32;
const MAX_DENO_WS_FRAME_BYTES = 1 * 1024 * 1024; // 1 MiB (`M6`)
const MAX_DENO_SAFE_HOPS = 5;
const MAX_DENO_BODY_IDLE_MS = 15_000;
const MAX_DENO_OUTBOUND_STREAM_IDLE_MS = 60_000;

const DENO_DEFAULT_SECURITY_HEADERS: ReadonlyArray<readonly [string, string]> = [
  ['x-content-type-options', 'nosniff'],
  ['x-frame-options', 'DENY'],
  ['referrer-policy', 'no-referrer'],
  ['content-security-policy', "default-src 'none'; frame-ancestors 'none'; base-uri 'none'"],
];

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
  let startedAt = 0;
  let finished = false;
  return new ReadableStream<Uint8Array>(
    {
      async pull(ctrl) {
        if (finished) return;
        if (!reader) {
          reader = src.getReader();
          startedAt = Date.now();
        }
        const remainingMs = Math.max(1, idleOrTotalMs - (Date.now() - startedAt));
        let readTimer: ReturnType<typeof setTimeout> | null = setTimeout(() => {
          if (finished) return;
          finished = true;
          readTimer = null;
          void reader?.cancel('Body stream timed out').catch(() => undefined);
          try {
            ctrl.error(new Error('Stream read timed out'));
          } catch {
            // ignore
          }
        }, remainingMs);
        readTimer.unref?.();
        getDenoRuntime()?.unrefTimer?.(readTimer as unknown as number);
        try {
          const { done, value } = await reader.read();
          if (finished) return;
          if (done) {
            finished = true;
            ctrl.close();
            return;
          }
          if (value) {
            total += value.byteLength;
            if (total > maxBytes) {
              finished = true;
              onCapExceeded?.();
              await reader.cancel('Stream exceeds byte limit').catch(() => undefined);
              ctrl.error(new DenoPayloadTooLargeError(maxBytes));
              return;
            }
            ctrl.enqueue(value);
          }
        } catch (err) {
          if (!finished) {
            finished = true;
            ctrl.error(err);
          }
        } finally {
          if (readTimer !== null) {
            clearTimeout(readTimer);
            readTimer = null;
          }
        }
      },
      async cancel(reason) {
        finished = true;
        if (reader) {
          await reader.cancel(reason).catch(() => undefined);
        } else {
          await src.cancel(reason).catch(() => undefined);
        }
      },
    },
    { highWaterMark: 0 },
  );
}

function guardDenoOutboundResponseStream(res: Response, maxBytes = MAX_DENO_SAFE_RESPONSE_BYTES): Response {
  if (!res.body || res.status === 101 || ('webSocket' in res && Boolean((res as { webSocket?: unknown }).webSocket))) {
    return res;
  }
  const src = res.body;
  let reader: ReadableStreamDefaultReader<Uint8Array> | null = null;
  let total = 0;
  let finished = false;
  let idleTimer: ReturnType<typeof setTimeout> | null = null;

  const clearIdleTimer = () => {
    if (idleTimer !== null) {
      clearTimeout(idleTimer);
      idleTimer = null;
    }
  };

  const armIdleTimer = (ctrl: ReadableStreamDefaultController<Uint8Array>) => {
    clearIdleTimer();
    idleTimer = setTimeout(() => {
      if (finished) return;
      finished = true;
      idleTimer = null;
      void reader?.cancel('Slow client response read timed out').catch(() => undefined);
      try {
        ctrl.error(new Error('Outbound response stream timed out waiting for client read'));
      } catch {
        // ignore
      }
    }, MAX_DENO_OUTBOUND_STREAM_IDLE_MS);
    idleTimer.unref?.();
    getDenoRuntime()?.unrefTimer?.(idleTimer as unknown as number);
  };

  const guarded = new ReadableStream<Uint8Array>(
    {
      start(ctrl) {
        armIdleTimer(ctrl);
      },
      async pull(ctrl) {
        if (finished) return;
        armIdleTimer(ctrl);
        if (!reader) reader = src.getReader();
        try {
          const { done, value } = await reader.read();
          if (finished) return;
          if (done) {
            finished = true;
            clearIdleTimer();
            ctrl.close();
            return;
          }
          if (value) {
            total += value.byteLength;
            if (total > maxBytes) {
              finished = true;
              clearIdleTimer();
              await reader.cancel('Outbound response exceeds byte limit').catch(() => undefined);
              ctrl.error(new Error(`Outbound response exceeds ${maxBytes} bytes limit`));
              return;
            }
            ctrl.enqueue(value);
          }
          armIdleTimer(ctrl);
        } catch (err) {
          finished = true;
          clearIdleTimer();
          try {
            ctrl.error(err);
          } catch {
            // ignore
          }
        }
      },
      async cancel(reason) {
        finished = true;
        clearIdleTimer();
        if (reader) {
          await reader.cancel(reason).catch(() => undefined);
        } else {
          await src.cancel(reason).catch(() => undefined);
        }
      },
    },
    { highWaterMark: 0 },
  );

  return new Response(guarded, {
    status: res.status,
    statusText: res.statusText,
    headers: new Headers(res.headers),
  });
}

export interface DenoSafeFetchOptions {
  allowExplicitLoopbackUrls?: boolean;
  fetchImpl?: typeof fetch;
  resolveDns?: (query: string, recordType: 'A' | 'AAAA') => Promise<string[]>;
  maxResponseBytes?: number;
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

async function resolveDenoDnsRecordsWithFallback(
  hostname: string,
  resolveDnsFn?: (query: string, recordType: 'A' | 'AAAA') => Promise<string[]>,
): Promise<string[]> {
  const activeResolveDns = resolveDnsFn ?? getDenoRuntime()?.resolveDns;
  if (typeof activeResolveDns === 'function') {
    const [v4, v6] = await Promise.all([
      activeResolveDns(hostname, 'A').catch(() => [] as string[]),
      activeResolveDns(hostname, 'AAAA').catch(() => [] as string[]),
    ]);
    return [...v4, ...v6];
  }
  // Fail-closed OS DNS fallback (`node:dns`) when `Deno.resolveDns` is unavailable (never fail open!).
  const lookedUp = await new Promise<dns.LookupAddress[]>((res, rej) => {
    dns.lookup(hostname, { all: true, verbatim: true }, (err, addrs) => {
      if (err) rej(err);
      else res(addrs);
    });
  }).catch(() => [] as dns.LookupAddress[]);
  return lookedUp.map((a) => a.address);
}

async function resolveValidatedDenoPublicIp(
  hostname: string,
  resolveDnsFn?: (query: string, recordType: 'A' | 'AAAA') => Promise<string[]>,
): Promise<{ pinnedIp: string; family: 4 | 6 }> {
  const ips = await resolveDenoDnsRecordsWithFallback(hostname, resolveDnsFn);
  if (ips.length === 0) {
    throw new Error(`DNS resolution returned no A/AAAA records for ${hostname}`);
  }
  for (const ip of ips) {
    if (!isPublicIpAddress(ip)) {
      throw new Error(`SSRF blocked: ${hostname} resolved to non-public IP ${ip}`);
    }
  }
  const pinnedIp = ips[0]!.trim().replace(/^\[|\]$/g, '');
  const family: 4 | 6 = net.isIP(pinnedIp) === 6 ? 6 : 4;
  return { pinnedIp, family };
}

function buildLookupFromDenoResolver(
  resolveDnsFn?: (query: string, recordType: 'A' | 'AAAA') => Promise<string[]>,
): LookupResolverFn {
  return async (hostname: string): Promise<dns.LookupAddress[]> => {
    const ips = await resolveDenoDnsRecordsWithFallback(hostname, resolveDnsFn);
    if (ips.length === 0) {
      throw new Error(`DNS resolution returned no A/AAAA records for ${hostname}`);
    }
    return ips.map((raw) => {
      const trimmed = typeof raw === 'string' ? raw.trim().replace(/^\[|\]$/g, '') : '';
      const fam = net.isIP(trimmed) === 6 ? 6 : 4;
      // Preserve raw string if invalid/whitespace/octal so `isPublicIpAddress` inside `createPublicOnlyLookup` rejects it cleanly!
      return { address: typeof raw === 'string' && isPublicIpAddress(raw) ? trimmed : String(raw), family: fam };
    });
  };
}

/**
 * Single-resolution SSRF-safe outbound `fetch` for Deno (`R7-H/M`):
 *  - When `opts.fetchImpl` is omitted (real runtime), delegates each validated hop to `createSafeOutboundFetch`
 *    which resolves DNS ONCE via `resolvePinnedPublicAddress` and dials the literal validated IP directly with
 *    TLS SNI `servername` + `tls.checkServerIdentity` — eliminating check-then-dial DNS rebinding TOCTOU completely!
 *  - Fails closed whenever DNS resolution is unavailable or returns 0 / non-public records.
 *  - Rejects trailing-dot FQDN hostnames (`https://example.com./`) and strips all sensitive auth/token/secret headers
 *    permanently across any cross-origin redirect (`a.example -> b.example -> a.example`).
 */
export function createDenoSafeFetch(
  selfHost?: string,
  optsOrMaxBytes: DenoSafeFetchOptions | number = {},
): typeof fetch {
  const opts: DenoSafeFetchOptions =
    typeof optsOrMaxBytes === 'number' ? { maxResponseBytes: optsOrMaxBytes } : optsOrMaxBytes;
  const maxResponseBytes = opts.maxResponseBytes ?? MAX_DENO_SAFE_RESPONSE_BYTES;
  const singlePassPinnedFetch = opts.fetchImpl
    ? null
    : createSafeOutboundFetch({
        resolver: buildLookupFromDenoResolver(opts.resolveDns),
        pinResolvedIp: true,
        allowExplicitLoopbackUrls: true,
        maxResponseBytes,
        defaultTimeoutMs: 30_000,
      });

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
    const currentHeaders = new Headers(init?.headers ?? reqObj?.headers);
    for (const forbidden of [
      'host',
      'content-length',
      'transfer-encoding',
      'connection',
      'keep-alive',
      'upgrade',
      'te',
      'trailer',
      'proxy-connection',
    ]) {
      try {
        currentHeaders.delete(forbidden);
      } catch {
        // ignore invalid header names
      }
    }

    for (let hop = 0; hop <= MAX_DENO_SAFE_HOPS; hop++) {
      const allowLoopbackThisHop = hop === 0 && opts.allowExplicitLoopbackUrls === true;
      const loopbackUrl = allowLoopbackThisHop ? validateExplicitLoopbackTargetUrl(currentUrl) : null;
      let validatedUrl: URL;
      let pinnedIp: string | undefined;
      if (loopbackUrl) {
        validatedUrl = loopbackUrl;
      } else {
        const check = validatePublicHttpsTargetUrl(currentUrl, selfHost);
        if (!check.ok) {
          throw new Error(`SSRF blocked outbound URL: ${check.message}`);
        }
        if (check.url.hostname.endsWith('.')) {
          throw new Error(`SSRF blocked outbound URL: disallowed trailing-dot hostname: ${check.url.hostname}`);
        }
        validatedUrl = check.url;
        if (opts.fetchImpl) {
          const resolved = await resolveValidatedDenoPublicIp(validatedUrl.hostname, opts.resolveDns);
          pinnedIp = resolved.pinnedIp;
        }
      }

      const hopHeaders = new Headers(currentHeaders);
      hopHeaders.delete('host');

      const hopCtrl = new AbortController();
      const hopTimer = setTimeout(() => {
        hopCtrl.abort(new DOMException('The operation timed out.', 'TimeoutError'));
      }, 30_000);
      hopTimer.unref?.();
      getDenoRuntime()?.unrefTimer?.(hopTimer as unknown as number);
      let res: Response;
      try {
        const hopInit: RequestInit & { pinnedIp?: string } = {
          ...init,
          method,
          headers: hopHeaders,
          body: method === 'GET' || method === 'HEAD' || method === 'OPTIONS' ? undefined : body,
          redirect: 'manual',
          signal: init?.signal ? AbortSignal.any([init.signal, hopCtrl.signal]) : hopCtrl.signal,
          ...(pinnedIp ? { pinnedIp } : {}),
        };
        if (opts.fetchImpl) {
          res = await opts.fetchImpl(validatedUrl.toString(), hopInit);
        } else {
          res = await singlePassPinnedFetch!(validatedUrl.toString(), hopInit);
        }
      } finally {
        clearTimeout(hopTimer);
      }

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
          throw new Error(`Too many or invalid redirects from ${validatedUrl.origin}`);
        }
        const nextUrl = new URL(loc, validatedUrl);
        if (nextUrl.origin !== validatedUrl.origin) {
          // Mutate `currentHeaders` permanently so cross-origin redirects (`a -> b -> a`) NEVER restore credentials!
          stripSensitiveCrossOriginHeaders(currentHeaders);
        }
        currentUrl = nextUrl.toString();
        if (res.status === 303 || ((res.status === 301 || res.status === 302) && method === 'POST')) {
          method = 'GET';
          body = undefined;
          currentHeaders.delete('content-type');
          currentHeaders.delete('content-length');
        }
        continue;
      }

      if (opts.fetchImpl && res.body !== null) {
        const cappedStream = capWebReadableStream(res.body, maxResponseBytes, 30_000);
        const wrapped = new Response(cappedStream, {
          status: res.status,
          statusText: res.statusText,
          headers: res.headers,
        });
        Object.defineProperty(wrapped, 'url', { value: validatedUrl.toString(), configurable: true });
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
const STRICT_FLY_APP_NAME_RE = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i;

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

export function resolveConfiguredPublicOrigin(env: Record<string, string | undefined>): string | null {
  const parseOriginCandidate = (rawUrl: string | undefined): string | null => {
    const trimmed = (rawUrl ?? '').trim();
    if (!trimmed) return null;
    try {
      const u = new URL(trimmed);
      if (u.protocol !== 'https:' && u.protocol !== 'http:') return null;
      if (u.username || u.password) return null;
      if (parseStrictSingleHost(u.host) === null && !isLoopbackHostOnly(u.hostname)) return null;
      return u.origin;
    } catch {
      return null;
    }
  };

  const explicit = parseOriginCandidate(env.EDGEFETCH_PUBLIC_ORIGIN);
  if (explicit) return explicit;

  const renderUrl = parseOriginCandidate(env.RENDER_EXTERNAL_URL);
  if (renderUrl) return renderUrl;

  const renderHost = parseStrictSingleHost(env.RENDER_EXTERNAL_HOSTNAME);
  if (renderHost && renderHost.includes('.')) {
    return `https://${renderHost}`;
  }

  const railwayDomain = parseStrictSingleHost(env.RAILWAY_PUBLIC_DOMAIN);
  if (railwayDomain && railwayDomain.includes('.')) {
    return `https://${railwayDomain}`;
  }

  const railwayStaticUrl = parseOriginCandidate(env.RAILWAY_STATIC_URL);
  if (railwayStaticUrl) return railwayStaticUrl;
  const railwayStaticHost = parseStrictSingleHost(env.RAILWAY_STATIC_URL);
  if (railwayStaticHost && railwayStaticHost.includes('.')) {
    return `https://${railwayStaticHost}`;
  }

  const flyApp = (env.FLY_APP_NAME ?? '').trim();
  if (flyApp && STRICT_FLY_APP_NAME_RE.test(flyApp)) {
    return `https://${flyApp.toLowerCase()}.fly.dev`;
  }

  return null;
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
  if (params.hasExplicitPublicOrigin) {
    return { origin: baseOriginUrl.origin, trustedForwardedHost: null };
  }

  const validHost = parseStrictSingleHost(params.hostHeader);
  let samePortLoopbackAuthority: string | null = null;
  if (validHost !== null && (isLoopbackHostOnly(baseOriginUrl.hostname) || baseOriginUrl.hostname === 'hub.local')) {
    try {
      const cand = new URL(`http://${validHost}`);
      const basePort = baseOriginUrl.port || (baseOriginUrl.protocol === 'https:' ? '443' : '80');
      const candPort = cand.port || '80';
      if (isLoopbackHostOnly(cand.hostname) && candPort === basePort) {
        samePortLoopbackAuthority = validHost;
      }
    } catch {
      samePortLoopbackAuthority = null;
    }
  }

  if (!params.trustProxy) {
    const authority = samePortLoopbackAuthority ?? baseOriginUrl.host;
    return {
      origin: new URL(`${baseOriginUrl.protocol}//${authority}`).origin,
      trustedForwardedHost: null,
    };
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

  const validFwdHost = parseStrictSingleHost(params.forwardedHostHeader);
  let allowLoopbackHostOverride = samePortLoopbackAuthority !== null;
  if (!allowLoopbackHostOverride && validHost !== null && isLoopbackHostOnly(baseOriginUrl.hostname)) {
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
  verifiedCallerAuth = false,
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
    // `R3-M9` & `R7`: Strip client-supplied `cf-connecting-ip` / `cf-ray` / `x-real-ip` / `fly-client-ip` / `true-client-ip` / `x-ef-verified-auth`,
    // and strip `x-forwarded-*` unless `EDGEFETCH_TRUST_PROXY=1`.
    if (
      lower === 'cf-connecting-ip' ||
      lower === 'cf-ray' ||
      lower === 'x-real-ip' ||
      lower === 'fly-client-ip' ||
      lower === 'true-client-ip' ||
      lower === 'x-ef-verified-auth'
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
  const webReq = new Request(cleanUrl, {
    method,
    headers,
    ...(hasBody
      ? {
          body: capWebReadableStream(req.body!, maxReqBodyBytes, MAX_DENO_BODY_IDLE_MS, onBodyCapExceeded),
          duplex: 'half',
        }
      : {}),
  } as RequestInit);
  if (verifiedCallerAuth) {
    markRequestVerifiedInProcess(webReq);
  }
  return webReq;
}

async function sha256Base64UrlDeno(input: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(input));
  const bytes = new Uint8Array(digest);
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]!);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

const fallbackSharedOAuthStore: OAuthStore = createMemoryOAuthStore();
const fallbackSharedMcpVaultStore: McpVaultStore = createMemoryMcpVaultStore();
const fallbackSharedActivityStore: ActivityStore = createMemoryActivityStore();

function openDenoPersistentStores(
  dataDir: string,
  ephemeralStores = false,
): {
  oauth: OAuthStore;
  mcpVault: McpVaultStore;
  activity: ActivityStore;
  settings: HubSettingsStore;
  close: () => void;
} {
  if (ephemeralStores || dataDir.trim() === ':memory:') {
    return {
      oauth: createMemoryOAuthStore(),
      mcpVault: createMemoryMcpVaultStore(),
      activity: createMemoryActivityStore(),
      settings: createMemoryHubSettingsStore(),
      close: () => {},
    };
  }
  try {
    const isMemory = dataDir.trim() === ':memory:';
    const sqlitePath = isMemory ? ':memory:' : join(resolve(dataDir), 'hub.sqlite');
    if (!isMemory) {
      mkdirSync(dirname(sqlitePath), { recursive: true });
    }
    const db = new DatabaseSync(sqlitePath);
    db.exec(
      `PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL; ${OAUTH_SQLITE_SCHEMA} ${MCP_VAULT_SQLITE_SCHEMA} ${ACTIVITY_SQLITE_SCHEMA} ${HUB_SETTINGS_SQLITE_SCHEMA}`,
    );
    try {
      db.exec('ALTER TABLE mcp_servers ADD COLUMN secret_version INTEGER NOT NULL DEFAULT 1');
    } catch {
      // already exists or table absent
    }
    try {
      db.exec('ALTER TABLE user_mcp_servers ADD COLUMN secret_version INTEGER NOT NULL DEFAULT 1');
    } catch {
      // already exists
    }
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
      mcpVault: createSqliteMcpVaultStore(sqlLike),
      activity: createSqliteActivityStore(sqlLike),
      settings: createSqliteHubSettingsStore(sqlLike),
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
      oauth: fallbackSharedOAuthStore,
      mcpVault: fallbackSharedMcpVaultStore,
      activity: fallbackSharedActivityStore,
      settings: createMemoryHubSettingsStore(),
      close: () => {},
    };
  }
}

export interface DenoHubOptions {
  port?: number;
  hostname?: string;
  dataDir?: string;
  env?: Record<string, string | undefined>;
  envOverrides?: Record<string, string | undefined>;
  ephemeralStores?: boolean;
  fetchImpl?: typeof fetch;
  safeFetchImpl?: typeof fetch;
  trackerFetchImpl?: typeof fetch;
  initialTrackerDelayMs?: number;
  resolveDns?: (query: string, recordType: 'A' | 'AAAA') => Promise<string[]>;
  maxInflightPerIp?: number;
  maxInflightTotal?: number;
  maxReqBodyBytes?: number;
}

export interface DenoHubHandlerHandle {
  handler: (req: Request, info?: { remoteAddr?: { hostname?: string } }) => Promise<Response>;
  workerEnv: Record<string, unknown>;
  port: number;
  getBoundPort: () => number;
  setBoundPort: (port: number) => void;
  canonicalOrigin: () => string;
  refreshTrackerListNow?: (opts?: { forceAfter6hOverrideForTest?: boolean }) => Promise<RefreshTrackerListOutcome>;
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
  const envMap = readDenoEnvMap({ ...options.env, ...options.envOverrides });
  const trustProxy = isTruthyDenoFlag(envMap.EDGEFETCH_TRUST_PROXY);
  const trustFlyClientIp =
    trustProxy &&
    ((envMap.EDGEFETCH_TRUST_PROXY ?? '').trim().toLowerCase() === 'fly' ||
      isTruthyDenoFlag(envMap.EDGEFETCH_TRUST_FLY_CLIENT_IP) ||
      Boolean(envMap.FLY_APP_NAME || envMap.FLY_ALLOC_ID || envMap.FLY_REGION));
  const hasExplicitDenoMaxInflightPerIp =
    typeof options.maxInflightPerIp === 'number' && options.maxInflightPerIp > 0;
  const maxInflightPerIp = hasExplicitDenoMaxInflightPerIp
    ? Math.floor(options.maxInflightPerIp!)
    : MAX_DENO_INFLIGHT_PER_IP;
  const maxInflightTotal =
    typeof options.maxInflightTotal === 'number' && options.maxInflightTotal > 0
      ? Math.floor(options.maxInflightTotal)
      : MAX_DENO_INFLIGHT_TOTAL;
  const maxReqBodyBytes =
    typeof options.maxReqBodyBytes === 'number' && options.maxReqBodyBytes > 0
      ? Math.floor(options.maxReqBodyBytes)
      : MAX_DENO_REQ_BODY_BYTES;
  const inflightByIp = new Map<string, number>();
  let totalInflight = 0;
  let unauthInflight = 0;
  const maxUnauthInflight =
    maxInflightTotal >= 8 ? maxInflightTotal - Math.min(32, Math.floor(maxInflightTotal / 4)) : maxInflightTotal;
  const activeWsBySite = new Map<string, number>();
  const activeWsByIp = new Map<string, number>();
  let pendingOrOpenWsCount = 0;
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
  const mcpVault: McpVaultStore = persistentStores.mcpVault;
  const activity: ActivityStore = persistentStores.activity;
  const settings: HubSettingsStore = persistentStores.settings;
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

  const explicitPublicOrigin = resolveConfiguredPublicOrigin(envMap);
  const selfHost = explicitPublicOrigin ? new URL(explicitPublicOrigin).hostname : undefined;
  const safeFetch = createDenoSafeFetch(selfHost, {
    allowExplicitLoopbackUrls: true,
    ...(options.fetchImpl ? { fetchImpl: options.fetchImpl } : {}),
    ...(options.resolveDns ? { resolveDns: options.resolveDns } : {}),
  });
  const safePublicFetch =
    options.safeFetchImpl ??
    createDenoSafeFetch(selfHost, {
      allowExplicitLoopbackUrls: false,
      ...(options.fetchImpl ? { fetchImpl: options.fetchImpl } : {}),
      ...(options.resolveDns ? { resolveDns: options.resolveDns } : {}),
    });

  const resolvedDataDir = options.dataDir ?? envMap.EDGEFETCH_DATA_DIR ?? './.edgefetch-deno-data';
  const trackerStorageBucket =
    s3Bucket ??
    (() => {
      if (options.ephemeralStores || resolvedDataDir.trim() === '' || resolvedDataDir.trim() === ':memory:') {
        return undefined;
      }
      try {
        return new NodeFsR2Bucket(join(resolve(resolvedDataDir), 'tracker-store'));
      } catch {
        return undefined;
      }
    })();

  const callerTokenSecret =
    envMap.CALLER_TOKEN ?? envMap.EDGEFETCH_CALLER_TOKEN ?? envMap.EDGEFETCH_SERVER_TOKEN;
  const mcpTokenSecret = envMap.MCP_TOKEN;
  const agentTokenSecret = envMap.AGENT_TOKEN ?? envMap.EDGEFETCH_AGENT_TOKEN;
  const agentTokensMapRaw = envMap.AGENT_TOKENS ?? envMap.EDGEFETCH_AGENT_TOKENS;

  const stub = {
    fetch: async () => new Response('use deno upgrade handler', { status: 426 }),
    listAgents: async () => engine.listAgents(),
    syncTrackerList: async (version: string | null, frames: string[]) => engine.setTrackerListBroadcast(version, frames),
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
      users: (await oauth.listUsers?.()) ?? [],
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
    oauthListGrants: (now: number, userId?: string) => oauth.listGrants(now, userId),
    oauthRevokeGrant: (id: string, userId?: string) => oauth.revokeGrant(id, userId),
    oauthRevokeByTokenHash: (h: string) => oauth.revokeByTokenHash(h),
    oauthUpsertUser: (u: HubUserRecord) => oauth.upsertUser?.(u) ?? u,
    oauthGetUser: (id: string) => oauth.getUser?.(id) ?? null,
    oauthListUsers: () => oauth.listUsers?.() ?? [],
    oauthCountUsers: () => oauth.countUsers?.() ?? 0,
    oauthUpdateUserRole: (id: string, role: UserRole, promotedByOwnerId?: string | null) =>
      oauth.updateUserRole?.(id, role, promotedByOwnerId) ?? false,
    oauthEnforcePinnedFounderOwners: (pinnedOwnerId: string) =>
      oauth.enforcePinnedFounderOwners?.(pinnedOwnerId) ?? 0,
    oauthCheckAuthLockout: (b: string, now: number, m?: number) => oauth.checkAuthLockout(b, now, m),
    oauthRecordAuthFailure: (b: string, now: number, w: number, m: number) => oauth.recordAuthFailure(b, now, w, m),
    oauthClearAuthFailures: (b: string) => oauth.clearAuthFailures(b),
    vaultListServers: (userId: string) => mcpVault.listServers(userId),
    vaultGetServer: (userId: string, slugOrDomain: string) => mcpVault.getServer(userId, slugOrDomain),
    vaultUpsertServer: (row: StoredMcpServerRow) => mcpVault.upsertServer(row),
    vaultDeleteServer: (userId: string, slug: string) => mcpVault.deleteServer(userId, slug),
    vaultPutOAuthState: (row: PendingMcpOAuthStateRow) => mcpVault.putOAuthState(row),
    vaultConsumeOAuthState: (stateHash: string, userId: string, now: number) =>
      mcpVault.consumeOAuthState(stateHash, userId, now),
    getHubSetting: (k: string) => settings.getSetting(k),
    setHubSetting: (k: string, v: string) => settings.setSetting(k, v),
  };

  const workerEnv: Record<string, unknown> = {
    ...envMap,
    SAFE_FETCH: safeFetch,
    SAFE_PUBLIC_FETCH: safePublicFetch,
    CALLER_TOKEN: callerTokenSecret,
    SESSION_SECRET: envMap.SESSION_SECRET ?? envMap.EDGEFETCH_SESSION_SECRET,
    GITHUB_CLIENT_ID: envMap.GITHUB_CLIENT_ID,
    GITHUB_CLIENT_SECRET: envMap.GITHUB_CLIENT_SECRET,
    GITHUB_ALLOWED_USERS: envMap.GITHUB_ALLOWED_USERS,
    GITHUB_OWNER_LOGIN: envMap.GITHUB_OWNER_LOGIN,
    SIGNUP_MODE: envMap.SIGNUP_MODE,
    VAULT_MASTER_KEY: envMap.VAULT_MASTER_KEY ?? envMap.EDGEFETCH_VAULT_MASTER_KEY,
    MCP_TOKEN: mcpTokenSecret,
    AGENT_TOKEN: agentTokenSecret,
    AGENT_TOKENS: agentTokensMapRaw,
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
    EDGEFETCH_PUBLIC_ORIGIN: explicitPublicOrigin ?? envMap.EDGEFETCH_PUBLIC_ORIGIN,
    AGENT_HUB: {
      idFromName: () => ({ toString: () => 'deno-global' }),
      get: () => stub,
    },
    ...(metaDb ? { META: metaDb } : {}),
    ...(searchDb ? { SEARCH: searchDb } : {}),
    ...(s3Bucket ? { ARTIFACTS: s3Bucket } : {}),
    ...(trackerStorageBucket ? { TRACKER_BUCKET: trackerStorageBucket } : {}),
  };

  const sessionSecret = resolveSessionSecret(workerEnv as {
    SESSION_SECRET?: string;
    CALLER_TOKEN?: string;
    GITHUB_CLIENT_ID?: string;
    GITHUB_CLIENT_SECRET?: string;
  });

  const hasVerifiedDenoCallerCredentials = async (req: Request, pathname: string): Promise<boolean> => {
    const authHdr = req.headers.get('authorization');
    const apiKeyHdr = req.headers.get('x-api-key');
    const agentTokHdr = req.headers.get('x-agent-token');
    const cookieHdr = req.headers.get('cookie');

    if (!authHdr && !apiKeyHdr && !agentTokHdr && !cookieHdr) {
      return false;
    }

    const bearerMatch = authHdr ? /^bearer\s+(\S+)$/i.exec(authHdr.trim()) : null;
    const bearerTok = bearerMatch?.[1] ?? null;
    const cleanApiKey = apiKeyHdr && !/\s/.test(apiKeyHdr.trim()) ? apiKeyHdr.trim() : null;
    const presentedCallerTok = bearerTok ?? cleanApiKey;

    if (presentedCallerTok && isValidSecretMatch(presentedCallerTok, callerTokenSecret, mcpTokenSecret)) {
      return true;
    }

    if (bearerTok && bearerTok.startsWith('efa_') && bearerTok.length >= 24 && bearerTok.length <= 128) {
      const tokenHash = await sha256Base64UrlDeno(bearerTok);
      const rec = await oauth.getAccessToken(tokenHash, Date.now());
      if (rec) return true;
    }

    if (pathname.startsWith('/agent/') && authorizeAgent(req, { AGENT_TOKEN: agentTokenSecret, AGENT_TOKENS: agentTokensMapRaw }).ok) {
      return true;
    }

    if (cookieHdr && cookieHdr.includes(`${ADMIN_COOKIE_NAME}=`) && sessionSecret) {
      const verifiedSession = await verifyAdminSessionCookie(cookieHdr, sessionSecret);
      if (verifiedSession.ok) return true;
    }

    return false;
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
  const defaultHost = options.hostname && options.hostname !== '0.0.0.0' && options.hostname !== '::' ? options.hostname : 'hub.local';
  const canonicalOrigin = () => explicitPublicOrigin ?? `http://${defaultHost}:${boundPort}`;

  const handler = async (req: Request, info?: { remoteAddr?: { hostname?: string } }): Promise<Response> => {
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
    const hasDenoAuthAttemptHeader = Boolean(
      req.headers.get('authorization') || req.headers.get('x-api-key') || req.headers.get('cookie'),
    );
    const hasCallerAuth = isHealthProbe ? false : await hasVerifiedDenoCallerCredentials(req, rawPathname);
    const isPublicDiscoveryRoute =
      !isHealthProbe &&
      !hasDenoAuthAttemptHeader &&
      (methodUpper === 'GET' || methodUpper === 'HEAD' || methodUpper === 'OPTIONS') &&
      (rawPathname === '/openapi.json' ||
        rawPathname.startsWith('/.well-known/') ||
        rawPathname === '/admin' ||
        rawPathname === '/admin/login' ||
        rawPathname === '/robots.txt');
    const clientBucket = normalizeClientRateLimitIp(resolveDenoTrustedClientIp(req, info, trustProxy, trustFlyClientIp));
    const curIpInflight = inflightByIp.get(clientBucket) ?? 0;
    const effectiveDenoInflightPerIp =
      !hasExplicitDenoMaxInflightPerIp && totalInflight < Math.floor(maxInflightTotal / 2)
        ? Math.max(maxInflightPerIp, Math.min(64, Math.floor(maxInflightTotal / 2)))
        : !hasExplicitDenoMaxInflightPerIp && (hasCallerAuth || isHealthProbe || isPublicDiscoveryRoute)
          ? Math.max(maxInflightPerIp, 32)
          : maxInflightPerIp;
    const hitPerIpLimit = curIpInflight >= effectiveDenoInflightPerIp;
    const hitGlobalLimit = isHealthProbe
      ? totalInflight >= maxInflightTotal + 64
      : isPublicDiscoveryRoute
        ? totalInflight >= maxInflightTotal + 32
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
    const countedInDenoUnauth = !hasCallerAuth && !isHealthProbe && !isPublicDiscoveryRoute;
    if (countedInDenoUnauth) unauthInflight++;
    inflightByIp.set(clientBucket, curIpInflight + 1);
    let slotReleased = false;
    const releaseInflightSlot = () => {
      if (slotReleased) return;
      slotReleased = true;
      totalInflight = Math.max(0, totalInflight - 1);
      if (countedInDenoUnauth) unauthInflight = Math.max(0, unauthInflight - 1);
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
          canonicalOrigin(),
          explicitPublicOrigin !== null,
          trustFlyClientIp,
          maxReqBodyBytes,
          () => {
            bodyCapExceeded = true;
          },
          hasCallerAuth,
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

      if ((methodUpper === 'GET' || methodUpper === 'HEAD' || methodUpper === 'OPTIONS') && req.body !== null) {
        await req.body.cancel().catch(() => undefined);
      }

      const isHttpsReq = cleanReq.url.startsWith('https://');
      const url = new URL(cleanReq.url);
      if ((methodUpper === 'GET' || methodUpper === 'HEAD') && url.pathname === '/readyz') {
        return applyDenoSecurityHeaders(
          new Response(methodUpper === 'HEAD' ? null : '{"ok":true}', {
            status: 200,
            headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' },
          }),
          isHttpsReq,
        );
      }

      if (url.pathname === '/agent/ws' && cleanReq.headers.get('upgrade')?.toLowerCase() === 'websocket') {
        const auth = authorizeAgent(cleanReq, workerEnv as never);
        if (!auth.ok) {
          return applyDenoSecurityHeaders(Response.json({ error: 'unauthorized' }, { status: 401 }), isHttpsReq);
        }
        const deno = getDenoRuntime();
        if (!deno || typeof deno.upgradeWebSocket !== 'function') {
          return applyDenoSecurityHeaders(Response.json({ error: 'websocket_upgrade_unavailable' }, { status: 501 }), isHttpsReq);
        }
        const curSiteWs = activeWsBySite.get(auth.siteId) ?? 0;
        const curIpWs = activeWsByIp.get(clientBucket) ?? 0;
        const perIpWsCap = trustProxy ? MAX_DENO_WS_CONNECTIONS : MAX_DENO_WS_PER_IP;
        if (pendingOrOpenWsCount >= MAX_DENO_WS_CONNECTIONS || curSiteWs >= MAX_DENO_WS_PER_SITE || curIpWs >= perIpWsCap) {
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
        const { socket, response } = deno.upgradeWebSocket(
          req,
          chosenSubprotocol ? { protocol: chosenSubprotocol } : undefined,
        );
        const pubIp = resolveDenoTrustedClientIp(req, info, trustProxy, trustFlyClientIp);
        const hubSock = new DenoHubSocket(socket, [`site:${auth.siteId}`]);

        // Reserve WS slot synchronously before `onopen` so concurrent upgrades cannot race past `MAX_DENO_WS_CONNECTIONS`!
        pendingOrOpenWsCount++;
        activeWsBySite.set(auth.siteId, curSiteWs + 1);
        activeWsByIp.set(clientBucket, curIpWs + 1);
        let wsSlotReleased = false;
        const releaseWsReservation = () => {
          if (wsSlotReleased) return;
          wsSlotReleased = true;
          pendingOrOpenWsCount = Math.max(0, pendingOrOpenWsCount - 1);
          const remSite = activeWsBySite.get(auth.siteId) ?? 0;
          if (remSite <= 1) activeWsBySite.delete(auth.siteId);
          else activeWsBySite.set(auth.siteId, remSite - 1);
          const remIp = activeWsByIp.get(clientBucket) ?? 0;
          if (remIp <= 1) activeWsByIp.delete(clientBucket);
          else activeWsByIp.set(clientBucket, remIp - 1);
        };

        socket.onopen = () => {
          sockets.add(hubSock);
          const att = engine.registerAgent(hubSock, auth.siteId, cleanReq.headers.get('x-agent-arch')?.slice(0, 32) || null, {
            version: cleanReq.headers.get('x-agent-version')?.slice(0, 64) || null,
            publicIp: pubIp,
            capabilities: cleanReq.headers.get('x-agent-capabilities') || null,
          });
          hubSock.send(JSON.stringify({ type: 'hello', siteId: att.siteId }));
          engine.sendCurrentTrackerListToSocket(hubSock);
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
              } else if (msg.type === 'tracker_list_ack') {
                engine.noteTrackerListAck(hubSock, msg.version);
              }
            } catch {
              // ignore malformed frame
            }
          }
        };
        socket.onerror = () => {
          if (!sockets.has(hubSock)) {
            releaseWsReservation();
          }
        };
        socket.onclose = (ev) => {
          sockets.delete(hubSock);
          releaseWsReservation();
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
        await rawRes.body?.cancel().catch(() => undefined);
        return applyDenoSecurityHeaders(
          Response.json(
            { error: 'payload_too_large', message: `Request body exceeds ${maxReqBodyBytes} bytes limit` },
            { status: 413, headers: { 'cache-control': 'no-store' } },
          ),
          isHttpsReq,
        );
      }
      return applyDenoSecurityHeaders(guardDenoOutboundResponseStream(rawRes), isHttpsReq);
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
  };

  const runDenoTrackerRefresh = async (overrideOpts?: {
    forceAfter6hOverrideForTest?: boolean;
  }): Promise<RefreshTrackerListOutcome> => {
    const settingVal = await settings.getSetting('tracker_list').catch(() => null);
    let currentSelfHost = selfHost;
    if (!currentSelfHost) {
      try {
        currentSelfHost = new URL(canonicalOrigin()).hostname;
      } catch {
        currentSelfHost = undefined;
      }
    }
    const out = await refreshHubTrackerList({
      bucket: trackerStorageBucket,
      fetchFn: options.trackerFetchImpl ?? safePublicFetch,
      env: envMap,
      hubSettingValue: settingVal,
      selfHost: currentSelfHost,
      publicOrigin: explicitPublicOrigin ?? undefined,
      ...(overrideOpts?.forceAfter6hOverrideForTest ? { forceAfter6hOverrideForTest: true } : {}),
    });
    if (out.current) {
      const extraAllow = resolveExtraNeverBlockHosts({
        selfHost: currentSelfHost,
        publicOrigin: explicitPublicOrigin ?? undefined,
      });
      engine.setTrackerListBroadcast(out.current.meta.version, buildTrackerListWsFrames(out.current, extraAllow));
    }
    return out;
  };

  let initialTrackerTimer: ReturnType<typeof setTimeout> | undefined;
  let dailyTrackerTimer: ReturnType<typeof setInterval> | undefined;
  if (trackerStorageBucket && !isTrackerListDisabled(envMap)) {
    void loadStoredTrackerList(trackerStorageBucket)
      .then((stored) => {
        if (!stored) return;
        const extraAllow = resolveExtraNeverBlockHosts({
          selfHost,
          publicOrigin: explicitPublicOrigin ?? undefined,
        });
        engine.setTrackerListBroadcast(stored.meta.version, buildTrackerListWsFrames(stored, extraAllow));
      })
      .catch(() => undefined);

    initialTrackerTimer = setTimeout(() => {
      void runDenoTrackerRefresh().catch(() => undefined);
    }, options.initialTrackerDelayMs ?? INITIAL_PORTABLE_TRACKER_DELAY_MS);
    (initialTrackerTimer as { unref?: () => void }).unref?.();
    getDenoRuntime()?.unrefTimer?.(initialTrackerTimer as unknown as number);

    dailyTrackerTimer = setInterval(() => {
      void runDenoTrackerRefresh().catch(() => undefined);
    }, DAILY_TRACKER_POLL_INTERVAL_MS);
    (dailyTrackerTimer as { unref?: () => void }).unref?.();
    getDenoRuntime()?.unrefTimer?.(dailyTrackerTimer as unknown as number);
  }

  const flushPending = async (): Promise<void> => {
    while (pendingWaitUntil.size > 0) {
      await Promise.allSettled([...pendingWaitUntil]);
    }
  };

  const close = async (): Promise<void> => {
    if (initialTrackerTimer) clearTimeout(initialTrackerTimer);
    if (dailyTrackerTimer) clearInterval(dailyTrackerTimer);
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
    refreshTrackerListNow: runDenoTrackerRefresh,
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
