/**
 * Portable Node.js 22.5+ / Docker / Fly.io / Railway / Render Hub entrypoint (`hub/dist/portable-server.mjs`).
 *
 * Runs the complete EdgeFetch Hub (`/admin` Control Center, OAuth 2.1, 15-tool `/mcp`, `.ipynb`/OpenAPI/Defuddle
 * extractors, `node:sqlite` FTS5 search, local `/data/artifacts` object store, `/agent/ws` Go worker fleet, and
 * vendor-agnostic OTLP trace export) with zero Cloudflare account, zero Postgres, and zero Redis!
 */
import { createHash } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { createServer, type IncomingMessage } from 'node:http';
import net from 'node:net';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { WebSocketServer } from 'ws';
import metaSchemaSql from '../migrations/meta/0001_tracking.sql';
import metaMultiUserSql from '../migrations/meta/0002_multiuser.sql';
import metaRound7Sql from '../migrations/meta/0003_round7_multiuser_hardening.sql';
import metaRound9Sql from '../migrations/meta/0004_round9_founder_pinning.sql';
import metaRound10Sql from '../migrations/meta/0005_round10_vault_and_oauth.sql';
import searchSchemaSql from '../migrations/search/0001_fts.sql';
import { authorizeAgent, isValidSecretMatch } from '../src/auth';
import { resolveSessionSecret } from '../src/github-auth';
import hubWorker from '../src/index';
import { ADMIN_COOKIE_NAME, verifyAdminSessionCookie, type OAuthTokenRecord } from '../src/oauth';
import { markRequestVerifiedInProcess } from '../src/otel';
import { normalizeClientRateLimitIp } from '../src/safe-input';
import { LocalAgentHubCoordinator, NodeFsR2Bucket, NodeSqliteD1Database } from './node-adapters';
import { S3ArtifactBucket } from './s3-bucket';
import { createSafeOutboundFetch, type LookupResolverFn } from './safe-fetch';
import { TursoHttpD1Database } from './turso-d1';

export const MAX_INFLIGHT_PER_IP = 16;
export const MAX_INFLIGHT_TOTAL = 128;
export const MAX_CONNECTIONS_PER_IP = 64;
export const MAX_CONNECTIONS_TOTAL = 1024;
export const MAX_TOTAL_SOCKETS = 256;
export const SOFT_GLOBAL_SOCKET_THRESHOLD = 128;
export const SOCKET_PRESSURE_THRESHOLD = 96;
export const MAX_ESTABLISHED_SOCKETS_PER_IP = 16;
export const MAX_REQUESTS_PER_CONNECTION = 64;
export const KEEP_ALIVE_TIMEOUT_MS = 4_000;
export const PRESSURE_IDLE_EVICT_AGE_MS = 250;
export const MAX_SOCKET_WRITABLE_BYTES = 2 * 1024 * 1024; // 2 MiB hard per-socket outbound buffer cap
export const SOCKET_RESUME_HIGH_WATER_BYTES = 65_536; // 64 KiB backpressure resume threshold
export const SOCKET_DRAIN_TIMEOUT_MS = 10_000; // 10s slow-read drain timeout
export const MAX_PIPELINED_BACKLOG = 8;
export const MAX_PREHEADER_SOCKETS_PER_IP = 32;
export const MAX_GLOBAL_PREHEADER_SOCKETS = 512;
export const LOOPBACK_RESERVED_CONNECTIONS = 32;
export const PUBLIC_DISCOVERY_RESERVED_INFLIGHT = 32;
export const FRESH_PREHEADER_GRACE_MS = 250;
export const SHARED_NAT_PREHEADER_EVICT_AGE_MS = 50;
export const PRE_HEADER_TIMEOUT_MS = 10_000;
export const FIRST_BYTE_PREHEADER_TIMEOUT_MS = 5_000;
export const MAX_AGENT_WS_CONNECTIONS = 128;
export const MAX_AGENT_WS_PER_SITE = 16;
const MAX_BODY_STREAM_IDLE_OR_TOTAL_MS = 15_000;

const DEFAULT_SECURITY_HEADERS: ReadonlyArray<readonly [string, string]> = [
  ['x-content-type-options', 'nosniff'],
  ['x-frame-options', 'DENY'],
  ['referrer-policy', 'no-referrer'],
  ['content-security-policy', "default-src 'none'; frame-ancestors 'none'; base-uri 'none'"],
];

export interface PortableHubOptions {
  port?: number;
  host?: string;
  dataDir?: string;
  migrationsDir?: string;
  env?: Record<string, string | undefined>;
  envOverrides?: Record<string, string | undefined>;
  dnsResolver?: LookupResolverFn;
  maxInflightPerIp?: number;
  maxInflightTotal?: number;
  maxConnectionsPerIp?: number;
  maxConnectionsTotal?: number;
  maxTotalSockets?: number;
  maxEstablishedSocketsPerIp?: number;
  maxRequestsPerConnection?: number;
  keepAliveTimeoutMs?: number;
  maxSocketWritableBytes?: number;
  socketDrainTimeoutMs?: number;
  maxPreHeaderSocketsPerIp?: number;
  maxGlobalPreHeaderSockets?: number;
  headersTimeoutMs?: number;
}

function isTruthyFlag(val: string | undefined): boolean {
  const clean = (val ?? '').trim().toLowerCase();
  return clean === '1' || clean === 'true' || clean === 'yes' || clean === 'on' || clean === 'fly';
}

function stripIpPortAndBrackets(addr: string | undefined): string {
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

function normalizeSocketIp(addr: string | undefined): string {
  const clean = stripIpPortAndBrackets(addr);
  if (!clean || net.isIP(clean) === 0) return '127.0.0.1';
  return clean;
}

const MAX_PORTABLE_REQ_BODY_BYTES = 20 * 1024 * 1024; // 20 MiB hard streaming ceiling on inbound Node HTTP bodies (`M8`)

export function resolveTrustedClientIp(
  req: IncomingMessage,
  trustProxy: boolean,
  trustFlyClientIp = false,
): string {
  if (trustProxy) {
    // On Fly.io edge proxy (`fly.toml`), Fly Proxy overwrites `Fly-Client-IP` with the authoritative client IP
    // (while appending Fly's own edge IP to `X-Forwarded-For`). Only trust `Fly-Client-IP` when Fly proxy mode is active.
    if (trustFlyClientIp) {
      const rawFlyIp = req.headers['fly-client-ip'];
      const flyStr = Array.isArray(rawFlyIp) ? rawFlyIp[rawFlyIp.length - 1] : rawFlyIp;
      if (typeof flyStr === 'string' && !flyStr.includes(',')) {
        const flyCand = stripIpPortAndBrackets(flyStr);
        if (flyCand && net.isIP(flyCand) !== 0) {
          return flyCand;
        }
      }
    }
    // M8 & R3-M4: Extract the RIGHTMOST comma-separated IP appended by the trusted reverse proxy, stripping `:port`
    // and falling back to socket IP if the rightmost token is malformed garbage (`X-Forwarded-For: 1.2.3.4, zz0`).
    const rawXff = req.headers['x-forwarded-for'];
    const joined = Array.isArray(rawXff) ? rawXff.join(',') : (rawXff ?? '');
    const parts = joined
      .split(',')
      .map((p) => p.trim())
      .filter(Boolean);
    const rightmost = parts.length > 0 ? parts[parts.length - 1] : undefined;
    if (rightmost) {
      const candidate = stripIpPortAndBrackets(rightmost);
      if (candidate && net.isIP(candidate) !== 0) {
        return candidate;
      }
    }
  }
  return normalizeSocketIp(req.socket?.remoteAddress);
}

/**
 * Pull-driven Web `ReadableStream` wrapper over Node `IncomingMessage` (`R3-M1`):
 * Keeps `req` paused until a route handler explicitly reads `request.body` AFTER authentication succeeds,
 * so unauthenticated 19 MiB uploads on `/mcp`, `/v1/scrape`, or `/agent/reply` buffer ZERO bytes in RAM!
 */
function safeNodeReqToWebStream(req: IncomingMessage): ReadableStream<Uint8Array> {
  let closed = false;
  let attached = false;
  let totalBytes = 0;
  let bodyDeadlineTimer: ReturnType<typeof setTimeout> | null = null;
  let ctrl!: ReadableStreamDefaultController<Uint8Array>;

  const cleanup = () => {
    if (bodyDeadlineTimer) {
      clearTimeout(bodyDeadlineTimer);
      bodyDeadlineTimer = null;
    }
    if (!attached) return;
    attached = false;
    req.removeListener('data', onData);
    req.removeListener('end', onEnd);
    req.removeListener('close', onEnd);
    req.removeListener('error', onErr);
  };

  const onData = (chunk: Buffer | Uint8Array) => {
    if (closed) return;
    totalBytes += chunk.byteLength;
    if (totalBytes > MAX_PORTABLE_REQ_BODY_BYTES) {
      closed = true;
      cleanup();
      req.pause();
      try {
        ctrl.error(new Error('Request body exceeds 20 MiB limit'));
      } catch {
        // ignore
      }
      req.destroy();
      return;
    }
    try {
      ctrl.enqueue(chunk instanceof Uint8Array ? chunk : new Uint8Array(chunk));
      if ((ctrl.desiredSize ?? 1) <= 0) {
        req.pause();
      }
    } catch {
      closed = true;
      cleanup();
      req.pause();
    }
  };

  const onEnd = () => {
    if (closed) return;
    closed = true;
    cleanup();
    try {
      ctrl.close();
    } catch {
      // ignore if already closed
    }
  };

  const onErr = (err: Error) => {
    if (closed) return;
    closed = true;
    cleanup();
    try {
      ctrl.error(err);
    } catch {
      // ignore
    }
  };

  req.pause();

  return new ReadableStream<Uint8Array>({
    start(c) {
      ctrl = c;
    },
    pull() {
      if (closed) return;
      if (!attached) {
        attached = true;
        bodyDeadlineTimer = setTimeout(() => {
          if (closed) return;
          closed = true;
          cleanup();
          req.pause();
          try {
            ctrl.error(new Error('Request body read timed out'));
          } catch {
            // ignore
          }
          req.destroy();
        }, MAX_BODY_STREAM_IDLE_OR_TOTAL_MS);
        bodyDeadlineTimer.unref?.();
        req.on('data', onData);
        req.once('end', onEnd);
        req.once('close', onEnd);
        req.once('error', onErr);
        if (req.complete && req.readableLength === 0) {
          onEnd();
          return;
        }
      }
      req.resume();
    },
    cancel() {
      closed = true;
      cleanup();
      req.pause();
    },
  });
}

const STRICT_SINGLE_HOST_RE =
  /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*(?::([1-9]\d{0,4}))?$/;
const STRICT_FLY_APP_NAME_RE = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i;

export function parseStrictSingleHost(raw: string | readonly string[] | undefined | null): string | null {
  if (Array.isArray(raw)) {
    if (raw.length !== 1) return null;
    raw = raw[0];
  }
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

/**
 * Resolves explicit or platform-injected public origin across `EDGEFETCH_PUBLIC_ORIGIN`, Render (`RENDER_EXTERNAL_URL` /
 * `RENDER_EXTERNAL_HOSTNAME`), Railway (`RAILWAY_PUBLIC_DOMAIN` / `RAILWAY_STATIC_URL`), and Fly.io (`FLY_APP_NAME`),
 * so `/admin` CSRF origin checks and `Secure` session cookies work out-of-the-box on 1-click deploys without trusting
 * client-spoofed `Host` headers!
 */
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

function isLoopbackHostOnly(hostname: string): boolean {
  const h = hostname.trim().toLowerCase();
  return h === '127.0.0.1' || h === 'localhost' || h === '[::1]' || h === '::1';
}

export function resolvePublicOrigin(params: {
  canonicalOrigin: string;
  trustProxy: boolean;
  hasExplicitPublicOrigin: boolean;
  hostHeader?: string | readonly string[] | null;
  forwardedHostHeader?: string | readonly string[] | null;
  forwardedProtoHeader?: string | readonly string[] | null;
}): { origin: string; trustedForwardedHost: string | null } {
  const baseOriginUrl = new URL(params.canonicalOrigin);

  // Reject malformed raw Host headers (`Host: [`) with 400 (`H3`), and reject duplicate Host headers.
  if (Array.isArray(params.hostHeader)) {
    if (params.hostHeader.length > 1) {
      throw new Error('Multiple Host headers are not allowed');
    }
    const first = params.hostHeader[0];
    if (typeof first === 'string' && first.trim() !== '') {
      void new URL(`http://${first.trim()}/`);
    }
  } else if (typeof params.hostHeader === 'string' && params.hostHeader.trim() !== '') {
    void new URL(`http://${params.hostHeader.trim()}/`);
  }

  // When an explicit or platform public origin is configured, strictly pin to `canonicalOrigin`.
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
  const rawProto = Array.isArray(params.forwardedProtoHeader)
    ? params.forwardedProtoHeader.join(',')
    : (params.forwardedProtoHeader ?? '');
  const protoTokens = rawProto
    .split(',')
    .map((p) => p.trim().toLowerCase())
    .filter(Boolean);
  const rightmostProto = protoTokens.length > 0 ? protoTokens[protoTokens.length - 1] : undefined;
  if (rightmostProto === 'https' || rightmostProto === 'http') {
    proto = rightmostProto;
  }

  // `R5-Low`: Even when `trustProxy === true` and `EDGEFETCH_PUBLIC_ORIGIN` is unset, NEVER let an arbitrary external
  // `Host: evil.test` override `baseOriginUrl.host` (preventing OAuth `/.well-known/oauth-authorization-server` issuer poisoning).
  // Only allow loopback-to-loopback authority substitution (`127.0.0.1` <-> `localhost`).
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

function incomingToWebRequest(
  req: IncomingMessage,
  canonicalOrigin: string,
  trustProxy: boolean,
  hasExplicitPublicOrigin = false,
  trustFlyClientIp = false,
  verifiedCallerAuth = false,
): Request {
  const { origin, trustedForwardedHost } = resolvePublicOrigin({
    canonicalOrigin,
    trustProxy,
    hasExplicitPublicOrigin,
    hostHeader: req.headers.host,
    forwardedHostHeader: req.headers['x-forwarded-host'],
    forwardedProtoHeader: req.headers['x-forwarded-proto'],
  });

  const rawTarget = req.url ?? '/';
  if (!rawTarget.startsWith('/') && rawTarget !== '*') {
    throw new Error('Malformed request-target');
  }
  const fullUrl = new URL(rawTarget === '*' ? '/' : rawTarget, origin).toString();

  const headers = new Headers();
  for (const [k, v] of Object.entries(req.headers)) {
    const lower = k.toLowerCase();
    // H4: Never trust client-supplied `cf-connecting-ip` / `cf-ray` / `x-real-ip` / `fly-client-ip` / `true-client-ip` / `x-ef-verified-auth`,
    // and strip `x-forwarded-*` unless `EDGEFETCH_TRUST_PROXY=1`.
    if (
      lower === 'cf-connecting-ip' ||
      lower === 'cf-ray' ||
      lower === 'x-real-ip' ||
      lower === 'fly-client-ip' ||
      lower === 'true-client-ip' ||
      lower === 'x-ef-verified-auth'
    ) {
      continue;
    }
    if (!trustProxy && lower.startsWith('x-forwarded-')) continue;
    if (lower === 'x-forwarded-host' && trustedForwardedHost === null) continue;
    if (Array.isArray(v)) {
      for (const item of v) headers.append(k, item);
    } else if (typeof v === 'string') {
      headers.set(k, v);
    }
  }
  const resolvedIp = resolveTrustedClientIp(req, trustProxy, trustFlyClientIp);
  headers.set('cf-connecting-ip', resolvedIp);
  headers.set('x-real-ip', resolvedIp);

  const method = (req.method ?? 'GET').toUpperCase();
  const hasBody = method !== 'GET' && method !== 'HEAD' && method !== 'OPTIONS';
  const webReq = new Request(fullUrl, {
    method,
    headers,
    ...(hasBody ? { body: safeNodeReqToWebStream(req), duplex: 'half' } : {}),
  } as RequestInit);
  if (verifiedCallerAuth) {
    markRequestVerifiedInProcess(webReq);
  }
  return webReq;
}

function singleHeaderString(val: string | string[] | undefined): string | null {
  if (typeof val === 'string') return val;
  if (Array.isArray(val) && val.length > 0) return val[0] ?? null;
  return null;
}

export function startPortableHub(opts: PortableHubOptions = {}) {
  const port = opts.port ?? Number(process.env.PORT || 8787);
  const host = opts.host ?? process.env.HOST ?? '0.0.0.0';
  const dataDir = resolve(opts.dataDir ?? process.env.EDGEFETCH_DATA_DIR ?? './.edgefetch-data');

  const mergedEnv = { ...process.env, ...(opts.env ?? {}), ...(opts.envOverrides ?? {}) };
  const trustProxy = isTruthyFlag(mergedEnv.EDGEFETCH_TRUST_PROXY);
  const trustFlyClientIp =
    trustProxy &&
    ((mergedEnv.EDGEFETCH_TRUST_PROXY ?? '').trim().toLowerCase() === 'fly' ||
      isTruthyFlag(mergedEnv.EDGEFETCH_TRUST_FLY_CLIENT_IP) ||
      Boolean(mergedEnv.FLY_APP_NAME || mergedEnv.FLY_ALLOC_ID || mergedEnv.FLY_REGION));
  const tursoUrl = mergedEnv.TURSO_DATABASE_URL;
  const tursoToken = mergedEnv.TURSO_AUTH_TOKEN;

  const coordinator = new LocalAgentHubCoordinator(join(dataDir, 'hub.sqlite'));
  const coordinatorNamespace = coordinator.asNamespace() as {
    idFromName: (name: string) => unknown;
    get: (id: unknown) => { oauthGetAccessToken?: (hash: string, now: number) => Promise<OAuthTokenRecord | null> | OAuthTokenRecord | null };
  };
  const coordinatorStub = coordinatorNamespace.get(coordinatorNamespace.idFromName('global'));

  const localMetaDb = (mergedEnv.META_TURSO_URL || tursoUrl)
    ? null
    : new NodeSqliteD1Database(
        join(dataDir, 'meta.sqlite'),
        opts.migrationsDir
          ? [
              join(resolve(opts.migrationsDir), 'meta', '0001_tracking.sql'),
              existsSync(join(resolve(opts.migrationsDir), 'meta', '0002_multiuser.sql'))
                ? join(resolve(opts.migrationsDir), 'meta', '0002_multiuser.sql')
                : { name: 'meta/0002_multiuser.sql', sql: metaMultiUserSql },
              existsSync(join(resolve(opts.migrationsDir), 'meta', '0003_round7_multiuser_hardening.sql'))
                ? join(resolve(opts.migrationsDir), 'meta', '0003_round7_multiuser_hardening.sql')
                : { name: 'meta/0003_round7_multiuser_hardening.sql', sql: metaRound7Sql },
              existsSync(join(resolve(opts.migrationsDir), 'meta', '0004_round9_founder_pinning.sql'))
                ? join(resolve(opts.migrationsDir), 'meta', '0004_round9_founder_pinning.sql')
                : { name: 'meta/0004_round9_founder_pinning.sql', sql: metaRound9Sql },
            ]
          : [
              { name: 'meta/0001_tracking.sql', sql: metaSchemaSql },
              { name: 'meta/0002_multiuser.sql', sql: metaMultiUserSql },
              { name: 'meta/0003_round7_multiuser_hardening.sql', sql: metaRound7Sql },
              { name: 'meta/0004_round9_founder_pinning.sql', sql: metaRound9Sql },
            ],
      );
  const localSearchDb = (mergedEnv.SEARCH_TURSO_URL || tursoUrl)
    ? null
    : new NodeSqliteD1Database(
        join(dataDir, 'search.sqlite'),
        opts.migrationsDir
          ? [join(resolve(opts.migrationsDir), 'search', '0001_fts.sql')]
          : [{ name: 'search/0001_fts.sql', sql: searchSchemaSql }],
      );

  const metaDb = localMetaDb
    ? localMetaDb
    : new TursoHttpD1Database({
        url: (mergedEnv.META_TURSO_URL ?? tursoUrl)!,
        authToken: mergedEnv.META_TURSO_AUTH_TOKEN ?? tursoToken,
      }).asD1Database();

  // Round 10 schema parity (`0005_round10_vault_and_oauth.sql`): idempotently apply `0005` statements and ensure
  // `secret_version INTEGER NOT NULL DEFAULT 1` exists on `mcp_servers` / `user_mcp_servers` across SQLite & D1.
  const round10MigrationCandidates = [
    ...(opts.migrationsDir ? [join(resolve(opts.migrationsDir), 'meta', '0005_round10_vault_and_oauth.sql')] : []),
    ...(() => {
      try {
        return [resolve(dirname(fileURLToPath(import.meta.url)), '../migrations/meta/0005_round10_vault_and_oauth.sql')];
      } catch {
        return [];
      }
    })(),
    resolve('migrations/meta/0005_round10_vault_and_oauth.sql'),
    resolve('hub/migrations/meta/0005_round10_vault_and_oauth.sql'),
  ];
  const round10MigrationFile = round10MigrationCandidates.find((p) => existsSync(p));
  const round10MigrationSql = round10MigrationFile ? readFileSync(round10MigrationFile, 'utf8') : metaRound10Sql;

  if (localMetaDb) {
    const migKey0005 = 'meta/0005_round10_vault_and_oauth.sql';
    const has0005 = localMetaDb.db.prepare('SELECT 1 FROM _ef_migrations WHERE name = ?').get(migKey0005);
    if (!has0005) {
      for (const rawStmt of round10MigrationSql.split(';')) {
        const stmt = rawStmt.trim();
        if (!stmt) continue;
        try {
          localMetaDb.db.exec(stmt);
        } catch {
          // Idempotent if target table/column already exists or is hosted in coordinator sqlite
        }
      }
      try {
        localMetaDb.db.prepare('INSERT OR IGNORE INTO _ef_migrations (name) VALUES (?)').run(migKey0005);
      } catch {
        // ignore
      }
    }
    try {
      localMetaDb.db.exec('ALTER TABLE mcp_servers ADD COLUMN secret_version INTEGER NOT NULL DEFAULT 1');
    } catch {
      // already exists or table absent
    }
    try {
      localMetaDb.db.exec('ALTER TABLE user_mcp_servers ADD COLUMN secret_version INTEGER NOT NULL DEFAULT 1');
    } catch {
      // already exists or table absent
    }
  }
  const coordRawDb = (coordinator as unknown as { db?: { exec: (sql: string) => void } }).db;
  if (coordRawDb && typeof coordRawDb.exec === 'function') {
    try {
      coordRawDb.exec('ALTER TABLE mcp_servers ADD COLUMN secret_version INTEGER NOT NULL DEFAULT 1');
    } catch {
      // already exists or table absent
    }
    try {
      coordRawDb.exec('ALTER TABLE user_mcp_servers ADD COLUMN secret_version INTEGER NOT NULL DEFAULT 1');
    } catch {
      // already exists or table absent
    }
  }
  void metaDb
    .prepare('ALTER TABLE mcp_servers ADD COLUMN secret_version INTEGER NOT NULL DEFAULT 1')
    .run()
    .catch(() => {});
  void metaDb
    .prepare('ALTER TABLE user_mcp_servers ADD COLUMN secret_version INTEGER NOT NULL DEFAULT 1')
    .run()
    .catch(() => {});
  const searchDb = localSearchDb
    ? localSearchDb
    : new TursoHttpD1Database({
        url: (mergedEnv.SEARCH_TURSO_URL ?? tursoUrl)!,
        authToken: mergedEnv.SEARCH_TURSO_AUTH_TOKEN ?? tursoToken,
      }).asD1Database();
  const artifactsBucket =
    mergedEnv.S3_ENDPOINT && mergedEnv.S3_BUCKET && mergedEnv.S3_ACCESS_KEY_ID && mergedEnv.S3_SECRET_ACCESS_KEY
      ? new S3ArtifactBucket({
          endpoint: mergedEnv.S3_ENDPOINT,
          bucket: mergedEnv.S3_BUCKET,
          accessKeyId: mergedEnv.S3_ACCESS_KEY_ID,
          secretAccessKey: mergedEnv.S3_SECRET_ACCESS_KEY,
          region: mergedEnv.S3_REGION ?? 'auto',
        }).asR2Bucket()
      : new NodeFsR2Bucket(join(dataDir, 'artifacts'));

  const safeFetch = createSafeOutboundFetch({
    ...(opts.dnsResolver ? { resolver: opts.dnsResolver } : {}),
    allowExplicitLoopbackUrls: true,
  });
  const safePublicFetch = createSafeOutboundFetch({
    ...(opts.dnsResolver ? { resolver: opts.dnsResolver } : {}),
    allowExplicitLoopbackUrls: false,
  });

  const callerTokenSecret =
    mergedEnv.CALLER_TOKEN ?? mergedEnv.EDGEFETCH_CALLER_TOKEN ?? mergedEnv.EDGEFETCH_SERVER_TOKEN;
  const mcpTokenSecret = mergedEnv.MCP_TOKEN;
  const agentTokenSecret = mergedEnv.AGENT_TOKEN ?? mergedEnv.EDGEFETCH_AGENT_TOKEN;
  const agentTokensMapRaw = mergedEnv.AGENT_TOKENS ?? mergedEnv.EDGEFETCH_AGENT_TOKENS;

  let boundPort = port;
  const explicitPublicOrigin = resolveConfiguredPublicOrigin(mergedEnv);
  const resolveCanonicalOrigin = (): string => {
    if (explicitPublicOrigin) return explicitPublicOrigin;
    const defaultHost = host === '0.0.0.0' || host === '::' ? 'hub.local' : host;
    return `http://${defaultHost}:${boundPort}`;
  };

  const workerEnv: Record<string, unknown> = {
    AGENT_HUB: coordinatorNamespace,
    META: metaDb,
    SEARCH: searchDb,
    ARTIFACTS: artifactsBucket,
    SAFE_FETCH: safeFetch,
    SAFE_PUBLIC_FETCH: safePublicFetch,
    CALLER_TOKEN: callerTokenSecret,
    SESSION_SECRET: mergedEnv.SESSION_SECRET ?? mergedEnv.EDGEFETCH_SESSION_SECRET,
    GITHUB_CLIENT_ID: mergedEnv.GITHUB_CLIENT_ID,
    GITHUB_CLIENT_SECRET: mergedEnv.GITHUB_CLIENT_SECRET,
    GITHUB_ALLOWED_USERS: mergedEnv.GITHUB_ALLOWED_USERS,
    GITHUB_OWNER_ID: mergedEnv.GITHUB_OWNER_ID,
    GITHUB_OWNER_LOGIN: mergedEnv.GITHUB_OWNER_LOGIN,
    SIGNUP_MODE: mergedEnv.SIGNUP_MODE,
    VAULT_MASTER_KEY: mergedEnv.VAULT_MASTER_KEY ?? mergedEnv.EDGEFETCH_VAULT_MASTER_KEY,
    MCP_TOKEN: mcpTokenSecret,
    AGENT_TOKEN: agentTokenSecret,
    AGENT_TOKENS: agentTokensMapRaw,
    USER_AGENT: mergedEnv.USER_AGENT ?? mergedEnv.EDGEFETCH_USER_AGENT,
    ROBOTS_BYPASS_HOSTS: mergedEnv.ROBOTS_BYPASS_HOSTS ?? mergedEnv.EDGEFETCH_ROBOTS_BYPASS_HOSTS,
    OAUTH_REDIRECT_ALLOWLIST: mergedEnv.OAUTH_REDIRECT_ALLOWLIST,
    SERPER_API_KEY: mergedEnv.SERPER_API_KEY,
    BRAVE_API_KEY: mergedEnv.BRAVE_API_KEY,
    TAVILY_API_KEY: mergedEnv.TAVILY_API_KEY,
    SEARXNG_URL: mergedEnv.SEARXNG_URL,
    WEBHOOK_SECRET: mergedEnv.WEBHOOK_SECRET,
    OTEL_EXPORTER_OTLP_ENDPOINT: mergedEnv.OTEL_EXPORTER_OTLP_ENDPOINT,
    OTEL_EXPORTER_OTLP_HEADERS: mergedEnv.OTEL_EXPORTER_OTLP_HEADERS,
    OTEL_SERVICE_NAME: mergedEnv.OTEL_SERVICE_NAME,
    BOT_SIGNING_PRIVATE_KEY: mergedEnv.BOT_SIGNING_PRIVATE_KEY ?? mergedEnv.EDGEFETCH_BOT_SIGNING_KEY,
    BOT_SIGNING_PUBLIC_KEY: mergedEnv.BOT_SIGNING_PUBLIC_KEY,
    BOT_CONTACT_URL: mergedEnv.BOT_CONTACT_URL,
    BOT_KEY_NBF: mergedEnv.BOT_KEY_NBF ?? mergedEnv.EDGEFETCH_BOT_KEY_NBF,
    BOT_KEY_EXP: mergedEnv.BOT_KEY_EXP ?? mergedEnv.EDGEFETCH_BOT_KEY_EXP,
    CRAWL4AI_API_URL: mergedEnv.CRAWL4AI_API_URL,
    CRAWL4AI_API_TOKEN: mergedEnv.CRAWL4AI_API_TOKEN,
    FIRECRAWL_API_URL: mergedEnv.FIRECRAWL_API_URL,
    FIRECRAWL_API_KEY: mergedEnv.FIRECRAWL_API_KEY,
    SPA_FALLBACK_ORDER: mergedEnv.SPA_FALLBACK_ORDER,
    EDGEFETCH_LLM_PROVIDER: mergedEnv.EDGEFETCH_LLM_PROVIDER,
    EDGEFETCH_LLM_BASE_URL: mergedEnv.EDGEFETCH_LLM_BASE_URL,
    EDGEFETCH_LLM_API_KEY: mergedEnv.EDGEFETCH_LLM_API_KEY,
    EDGEFETCH_LLM_MODEL: mergedEnv.EDGEFETCH_LLM_MODEL,
    EDGEFETCH_ALLOW_LOCAL_LLM_OVERRIDE: mergedEnv.EDGEFETCH_ALLOW_LOCAL_LLM_OVERRIDE,
    OLLAMA_HOST: mergedEnv.OLLAMA_HOST,
    OPENAI_API_KEY: mergedEnv.OPENAI_API_KEY,
    OPENROUTER_API_KEY: mergedEnv.OPENROUTER_API_KEY,
    ANTHROPIC_API_KEY: mergedEnv.ANTHROPIC_API_KEY,
    GEMINI_API_KEY: mergedEnv.GEMINI_API_KEY,
    EDGEFETCH_PUBLIC_ORIGIN: explicitPublicOrigin ?? mergedEnv.EDGEFETCH_PUBLIC_ORIGIN,
    EDGEFETCH_DISABLE_UPDATE_CHECK: mergedEnv.EDGEFETCH_DISABLE_UPDATE_CHECK,
    EDGEFETCH_DEV_TELEMETRY: mergedEnv.EDGEFETCH_DEV_TELEMETRY,
    EDGEFETCH_DEV_TELEMETRY_ENDPOINT: mergedEnv.EDGEFETCH_DEV_TELEMETRY_ENDPOINT,
    EDGEFETCH_DEV_TELEMETRY_URL: mergedEnv.EDGEFETCH_DEV_TELEMETRY_URL,
    DO_NOT_TRACK: mergedEnv.DO_NOT_TRACK,
  };

  const sessionSecret = resolveSessionSecret(workerEnv as {
    SESSION_SECRET?: string;
    CALLER_TOKEN?: string;
    GITHUB_CLIENT_ID?: string;
    GITHUB_CLIENT_SECRET?: string;
  });

  /**
   * Cryptographically verifies caller/agent/session/OAuth credentials BEFORE granting reserved authenticated
   * concurrency slots (`R7-M`), defeating `Authorization: Bearer bogus` slot starvation!
   */
  const hasVerifiedCallerCredentials = async (req: IncomingMessage, pathname: string): Promise<boolean> => {
    const authHdr = singleHeaderString(req.headers.authorization);
    const apiKeyHdr = singleHeaderString(req.headers['x-api-key']);
    const agentTokHdr = singleHeaderString(req.headers['x-agent-token']);
    const cookieHdr = singleHeaderString(req.headers.cookie);

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

    if (
      bearerTok &&
      bearerTok.startsWith('efa_') &&
      bearerTok.length >= 24 &&
      bearerTok.length <= 128 &&
      typeof coordinatorStub?.oauthGetAccessToken === 'function'
    ) {
      const tokenHash = createHash('sha256').update(bearerTok).digest('base64url');
      const rec = await coordinatorStub.oauthGetAccessToken(tokenHash, Date.now());
      if (rec) return true;
    }

    if ((agentTokHdr || bearerTok) && pathname.startsWith('/agent/')) {
      const probeHeaders = new Headers();
      if (authHdr) probeHeaders.set('authorization', authHdr);
      if (agentTokHdr) probeHeaders.set('x-agent-token', agentTokHdr);
      const siteHdr = singleHeaderString(req.headers['x-agent-site']);
      if (siteHdr) probeHeaders.set('x-agent-site', siteHdr);
      const probeReq = new Request(`http://hub.local${pathname}`, {
        method: (req.method ?? 'POST').toUpperCase(),
        headers: probeHeaders,
      });
      if (authorizeAgent(probeReq, { AGENT_TOKEN: agentTokenSecret, AGENT_TOKENS: agentTokensMapRaw }).ok) {
        return true;
      }
    }

    if (cookieHdr && cookieHdr.includes(`${ADMIN_COOKIE_NAME}=`) && sessionSecret) {
      const verifiedSession = await verifyAdminSessionCookie(cookieHdr, sessionSecret);
      if (verifiedSession.ok) return true;
    }

    return false;
  };

  const ctx = {
    waitUntil(promise: Promise<unknown>): void {
      promise.catch(() => undefined);
    },
    passThroughOnException(): void {
      // noop
    },
  } as unknown as ExecutionContext;

  const hasExplicitMaxInflightPerIp = typeof opts.maxInflightPerIp === 'number' && opts.maxInflightPerIp > 0;
  const maxInflightPerIp = hasExplicitMaxInflightPerIp ? Math.floor(opts.maxInflightPerIp!) : MAX_INFLIGHT_PER_IP;
  const maxInflightTotal =
    typeof opts.maxInflightTotal === 'number' && opts.maxInflightTotal > 0
      ? Math.floor(opts.maxInflightTotal)
      : MAX_INFLIGHT_TOTAL;
  const envMaxConnPerIp = Number(mergedEnv.EDGEFETCH_MAX_CONNECTIONS_PER_IP);
  const hasExplicitMaxConnPerIp =
    (typeof opts.maxConnectionsPerIp === 'number' && opts.maxConnectionsPerIp > 0) ||
    (Number.isFinite(envMaxConnPerIp) && envMaxConnPerIp > 0);
  const maxConnectionsPerIp =
    typeof opts.maxConnectionsPerIp === 'number' && opts.maxConnectionsPerIp > 0
      ? Math.floor(opts.maxConnectionsPerIp)
      : Number.isFinite(envMaxConnPerIp) && envMaxConnPerIp > 0
        ? Math.floor(envMaxConnPerIp)
        : MAX_CONNECTIONS_PER_IP;
  const envMaxConnTotal = Number(mergedEnv.EDGEFETCH_MAX_CONNECTIONS_TOTAL);
  const hasExplicitMaxConnTotal =
    (typeof opts.maxConnectionsTotal === 'number' && opts.maxConnectionsTotal > 0) ||
    (Number.isFinite(envMaxConnTotal) && envMaxConnTotal > 0);
  const maxConnectionsTotal =
    typeof opts.maxConnectionsTotal === 'number' && opts.maxConnectionsTotal > 0
      ? Math.floor(opts.maxConnectionsTotal)
      : Number.isFinite(envMaxConnTotal) && envMaxConnTotal > 0
        ? Math.floor(envMaxConnTotal)
        : MAX_CONNECTIONS_TOTAL;
  const envMaxPreHeaderPerIp = Number(mergedEnv.EDGEFETCH_MAX_PREHEADER_SOCKETS_PER_IP);
  const hasExplicitMaxPreHeaderPerIp =
    (typeof opts.maxPreHeaderSocketsPerIp === 'number' && opts.maxPreHeaderSocketsPerIp > 0) ||
    (Number.isFinite(envMaxPreHeaderPerIp) && envMaxPreHeaderPerIp > 0);
  const maxPreHeaderPerIp =
    typeof opts.maxPreHeaderSocketsPerIp === 'number' && opts.maxPreHeaderSocketsPerIp > 0
      ? Math.floor(opts.maxPreHeaderSocketsPerIp)
      : Number.isFinite(envMaxPreHeaderPerIp) && envMaxPreHeaderPerIp > 0
        ? Math.floor(envMaxPreHeaderPerIp)
        : MAX_PREHEADER_SOCKETS_PER_IP;
  const hasExplicitMaxGlobalPreHeader =
    typeof opts.maxGlobalPreHeaderSockets === 'number' && opts.maxGlobalPreHeaderSockets > 0;
  const envMaxTotalSockets = Number(mergedEnv.EDGEFETCH_MAX_TOTAL_SOCKETS);
  const maxTotalSockets =
    typeof opts.maxTotalSockets === 'number' && opts.maxTotalSockets > 0
      ? Math.floor(opts.maxTotalSockets)
      : Number.isFinite(envMaxTotalSockets) && envMaxTotalSockets > 0
        ? Math.floor(envMaxTotalSockets)
        : hasExplicitMaxConnTotal
          ? maxConnectionsTotal
          : hasExplicitMaxGlobalPreHeader
            ? Math.max(MAX_TOTAL_SOCKETS, Math.floor(opts.maxGlobalPreHeaderSockets!) + 32)
            : MAX_TOTAL_SOCKETS;
  const softGlobalSocketThreshold = Math.max(8, Math.floor(maxTotalSockets / 2));
  const socketPressureThreshold = Math.max(4, Math.floor(maxTotalSockets * 0.375));
  const envMaxEstablishedPerIp = Number(mergedEnv.EDGEFETCH_MAX_ESTABLISHED_SOCKETS_PER_IP);
  const hasExplicitMaxEstablishedPerIp =
    (typeof opts.maxEstablishedSocketsPerIp === 'number' && opts.maxEstablishedSocketsPerIp > 0) ||
    (Number.isFinite(envMaxEstablishedPerIp) && envMaxEstablishedPerIp > 0);
  const maxEstablishedSocketsPerIp =
    typeof opts.maxEstablishedSocketsPerIp === 'number' && opts.maxEstablishedSocketsPerIp > 0
      ? Math.floor(opts.maxEstablishedSocketsPerIp)
      : Number.isFinite(envMaxEstablishedPerIp) && envMaxEstablishedPerIp > 0
        ? Math.floor(envMaxEstablishedPerIp)
        : MAX_ESTABLISHED_SOCKETS_PER_IP;
  const maxRequestsPerConnection =
    typeof opts.maxRequestsPerConnection === 'number' && opts.maxRequestsPerConnection > 0
      ? Math.floor(opts.maxRequestsPerConnection)
      : MAX_REQUESTS_PER_CONNECTION;
  const keepAliveTimeoutMs =
    typeof opts.keepAliveTimeoutMs === 'number' && opts.keepAliveTimeoutMs > 0
      ? Math.floor(opts.keepAliveTimeoutMs)
      : KEEP_ALIVE_TIMEOUT_MS;
  const maxSocketWritableBytes =
    typeof opts.maxSocketWritableBytes === 'number' && opts.maxSocketWritableBytes > 0
      ? Math.floor(opts.maxSocketWritableBytes)
      : MAX_SOCKET_WRITABLE_BYTES;
  const socketDrainTimeoutMs =
    typeof opts.socketDrainTimeoutMs === 'number' && opts.socketDrainTimeoutMs > 0
      ? Math.floor(opts.socketDrainTimeoutMs)
      : SOCKET_DRAIN_TIMEOUT_MS;
  const maxGlobalPreHeaderSockets = hasExplicitMaxGlobalPreHeader
    ? Math.floor(opts.maxGlobalPreHeaderSockets!)
    : Math.max(16, Math.min(MAX_GLOBAL_PREHEADER_SOCKETS, maxTotalSockets));
  const headersTimeoutMs =
    typeof opts.headersTimeoutMs === 'number' && opts.headersTimeoutMs > 0
      ? Math.floor(opts.headersTimeoutMs)
      : PRE_HEADER_TIMEOUT_MS;

  const inflightByIp = new Map<string, number>();
  let totalInflight = 0;
  let unauthInflight = 0;
  let publicDiscoveryInflight = 0;
  const maxUnauthInflight =
    maxInflightTotal >= 8 ? maxInflightTotal - Math.min(32, Math.floor(maxInflightTotal / 4)) : maxInflightTotal;

  interface TrackedSocketRecord {
    socket: net.Socket;
    connSeq: number;
    isLoopback: boolean;
    activeBucket: string;
    establishedBucket: string | null;
    phase: 'preheader' | 'inflight' | 'idle_keepalive' | 'upgraded_ws' | 'closing';
    connectedAt: number;
    headerDeadlineAt: number;
    idleSince: number;
    bytesReadAtTurnStart: number;
    bytesReceivedOnCurrentRequest: number;
    sawRequestBytes: boolean;
    requestsReceived: number;
    requestsCompleted: number;
    activeResponses: number;
    pipelinedWaiting: number;
    pipelineTail: Promise<void>;
    finishPreHeader: () => void;
    releaseAccounting: () => void;
    markUpgradedWs: () => void;
  }

  // `R6-H4`, `R7-H8`, `R8-H1`, `R9-H7` & `R10-P1`:
  //  1. Strict loopback (`127.0.0.1`, `::1`, `::ffff:127.0.0.1`) has dedicated reserved socket & pre-header headroom,
  //     completely isolated from remote connection/pre-header/keep-alive pools so orchestrator `/health` & `/readyz` probes ALWAYS succeed.
  //  2. ALL live TCP sockets are tracked across `preheader`, `inflight`, `idle_keepalive`, and `upgraded_ws` states.
  //  3. Pre-header sockets that have already sent request bytes (`sawRequestBytes` / `bytesRead > bytesReadAtTurnStart`) and
  //     in-flight requests are NEVER evicted under connection pressure before `headersTimeout` / `requestTimeout` expires.
  //  4. `evictIdleSocketUnderPressure` ranks eligible victims in 3 strict tiers:
  //     - Tier 1: Zero-byte stalled pre-header sockets (`requestsCompleted === 0 && bytesRead === 0`), highest-churn/count IP or oldest stalled first.
  //     - Tier 2: Idle keep-alive sockets from over-represented IPs (`ipSocketCount > 2`), picking highest `ipSocketCount` and youngest / lowest-`requestsCompleted` socket first.
  //     - Tier 3 (1-socket-per-IP tie-break): Evicts newcomers (`requestsCompleted <= 1` and age < 5s) with FEWEST `requestsCompleted` and YOUNGEST `connectedAt` first while protecting established veteran persistent clients (`requestsCompleted >= 2` or age >= 5s with completed requests).
  const activeSocketsByIp = new Map<string, number>();
  const preHeaderSocketsByIp = new Map<string, number>();
  const establishedSocketsByIp = new Map<string, Set<net.Socket>>();
  const recentConnChurnByIp = new Map<string, { count: number; windowStart: number }>();
  const remotePreHeaderSockets = new Map<
    net.Socket,
    { bucket: string; connectedAt: number; record: TrackedSocketRecord }
  >();
  const idleKeepAliveSockets = new Map<net.Socket, TrackedSocketRecord>();
  const loopbackIdleKeepAliveSockets = new Map<net.Socket, TrackedSocketRecord>();
  const trackedSockets = new WeakMap<net.Socket, TrackedSocketRecord>();
  let remoteActiveSockets = 0;
  let loopbackActiveSockets = 0;
  let nextConnSeq = 0;

  const CHURN_WINDOW_MS = 5_000;
  const VETERAN_MIN_COMPLETED_REQUESTS = 2;
  const VETERAN_ESTABLISHED_AGE_MS = 5_000;
  const VETERAN_RESERVED_INFLIGHT = 32;

  const recordIpConnChurn = (bucket: string, nowMs: number): number => {
    if (recentConnChurnByIp.size > 4_096) {
      for (const [k, v] of recentConnChurnByIp) {
        if (nowMs - v.windowStart > CHURN_WINDOW_MS * 2) {
          recentConnChurnByIp.delete(k);
        }
      }
      if (recentConnChurnByIp.size > 4_096) recentConnChurnByIp.clear();
    }
    const existing = recentConnChurnByIp.get(bucket);
    if (!existing || nowMs - existing.windowStart >= CHURN_WINDOW_MS) {
      recentConnChurnByIp.set(bucket, { count: 1, windowStart: nowMs });
      return 1;
    }
    existing.count++;
    return existing.count;
  };

  const getRecentIpChurn = (bucket: string, nowMs: number): number => {
    const entry = recentConnChurnByIp.get(bucket);
    if (!entry || nowMs - entry.windowStart >= CHURN_WINDOW_MS) return 0;
    return entry.count;
  };

  const hasPartialRequestBytes = (rec: TrackedSocketRecord): boolean => {
    if (rec.sawRequestBytes || rec.bytesReceivedOnCurrentRequest > 0) return true;
    if ((rec.socket.readableLength ?? 0) > 0) return true;
    if (rec.socket.bytesRead > rec.bytesReadAtTurnStart) return true;
    return false;
  };

  const computeDynamicEstPerIpCap = (): number => {
    if (hasExplicitMaxEstablishedPerIp) {
      return maxEstablishedSocketsPerIp;
    }
    const headroomEstCap = Math.max(maxEstablishedSocketsPerIp, Math.min(maxConnectionsPerIp, 64, maxTotalSockets));
    if (trustProxy) {
      return headroomEstCap;
    }
    // Allow shared-address NAT users up to 64 persistent connections when global capacity has headroom;
    // tighten to maxEstablishedSocketsPerIp (16) under global socket pressure while evicting bloated single-IP hogs first.
    return remoteActiveSockets < socketPressureThreshold ? headroomEstCap : maxEstablishedSocketsPerIp;
  };

  const getIpTotalSocketCount = (rec: TrackedSocketRecord): number => {
    const bKey = rec.establishedBucket ?? rec.activeBucket;
    return Math.max(
      establishedSocketsByIp.get(bKey)?.size ?? 0,
      activeSocketsByIp.get(rec.activeBucket) ?? 1,
    );
  };

  const isVeteranKeepAliveSocket = (rec: TrackedSocketRecord, nowMs: number, ipCount: number): boolean => {
    if (rec.phase !== 'idle_keepalive' || ipCount > 2) return false;
    if (rec.requestsCompleted >= VETERAN_MIN_COMPLETED_REQUESTS) return true;
    if (rec.requestsCompleted >= 1 && nowMs - rec.connectedAt >= VETERAN_ESTABLISHED_AGE_MS) return true;
    return false;
  };

  const addSocketToEstablishedBucket = (rec: TrackedSocketRecord, targetBucket: string) => {
    if (rec.isLoopback || rec.phase === 'closing' || rec.phase === 'upgraded_ws') return;
    if (rec.establishedBucket === targetBucket) return;
    if (rec.establishedBucket !== null) {
      const prevSet = establishedSocketsByIp.get(rec.establishedBucket);
      if (prevSet) {
        prevSet.delete(rec.socket);
        if (prevSet.size === 0) establishedSocketsByIp.delete(rec.establishedBucket);
      }
    }
    let set = establishedSocketsByIp.get(targetBucket);
    if (!set) {
      set = new Set<net.Socket>();
      establishedSocketsByIp.set(targetBucket, set);
    }
    set.add(rec.socket);
    rec.establishedBucket = targetBucket;
  };

  const removeSocketFromEstablished = (rec: TrackedSocketRecord) => {
    idleKeepAliveSockets.delete(rec.socket);
    loopbackIdleKeepAliveSockets.delete(rec.socket);
    if (rec.establishedBucket !== null) {
      const set = establishedSocketsByIp.get(rec.establishedBucket);
      if (set) {
        set.delete(rec.socket);
        if (set.size === 0) establishedSocketsByIp.delete(rec.establishedBucket);
      }
      rec.establishedBucket = null;
    }
  };

  const rebucketActiveSocketIfNeeded = (rec: TrackedSocketRecord, nextBucket: string) => {
    if (rec.isLoopback || rec.phase === 'closing' || rec.activeBucket === nextBucket) return;
    const prevRem = activeSocketsByIp.get(rec.activeBucket) ?? 0;
    if (prevRem <= 1) activeSocketsByIp.delete(rec.activeBucket);
    else activeSocketsByIp.set(rec.activeBucket, prevRem - 1);
    activeSocketsByIp.set(nextBucket, (activeSocketsByIp.get(nextBucket) ?? 0) + 1);
    rec.activeBucket = nextBucket;
  };

  const evictSocketRecord = (rec: TrackedSocketRecord, nowMs = Date.now(), forceImmediateDestroy = false) => {
    const wasIdleKeepAlive = rec.phase === 'idle_keepalive';
    const idleAgeMs = nowMs - rec.idleSince;
    rec.releaseAccounting();
    if (rec.socket.destroyed) return;
    if (!forceImmediateDestroy && wasIdleKeepAlive && idleAgeMs < 50 && (rec.socket.writableLength ?? 0) === 0) {
      try {
        rec.socket.end();
      } catch {
        rec.socket.destroy();
        return;
      }
      const finFallback = setTimeout(() => {
        if (!rec.socket.destroyed) rec.socket.destroy();
      }, 100);
      finFallback.unref?.();
      return;
    }
    rec.socket.destroy();
  };

  const evictIdleKeepAliveForBucket = (bucket: string, nowMs = Date.now()): boolean => {
    let bestVictim: TrackedSocketRecord | null = null;
    for (const cand of idleKeepAliveSockets.values()) {
      if (cand.phase !== 'idle_keepalive' || cand.activeResponses > 0 || cand.pipelinedWaiting > 0) continue;
      if (hasPartialRequestBytes(cand)) continue;
      if (cand.establishedBucket === bucket || cand.activeBucket === bucket) {
        if (
          !bestVictim ||
          cand.requestsCompleted < bestVictim.requestsCompleted ||
          (cand.requestsCompleted === bestVictim.requestsCompleted &&
            (cand.connectedAt > bestVictim.connectedAt ||
              (cand.connectedAt === bestVictim.connectedAt && cand.connSeq > bestVictim.connSeq)))
        ) {
          bestVictim = cand;
        }
      }
    }
    if (!bestVictim) return false;
    evictSocketRecord(bestVictim, nowMs);
    return true;
  };

  const countZeroByteRemotePreHeaderSockets = (): number => {
    let zeroCount = 0;
    for (const candMeta of remotePreHeaderSockets.values()) {
      const cand = candMeta.record;
      if (cand.phase === 'preheader' && cand.requestsCompleted === 0 && !hasPartialRequestBytes(cand)) {
        zeroCount++;
      }
    }
    return zeroCount;
  };

  const selectZeroBytePreHeaderVictim = (
    nowMs: number,
    arrivingBucket?: string,
    allowFreshZeroByte = false,
  ): TrackedSocketRecord | null => {
    let bestVictim: TrackedSocketRecord | null = null;
    let bestScore = -1;
    for (const candMeta of remotePreHeaderSockets.values()) {
      const cand = candMeta.record;
      if (cand.phase !== 'preheader' || cand.requestsCompleted > 0 || cand.activeResponses > 0) continue;
      if (hasPartialRequestBytes(cand)) continue;
      const ageMs = nowMs - candMeta.connectedAt;
      const preCount = preHeaderSocketsByIp.get(candMeta.bucket) ?? 1;
      const actCount = activeSocketsByIp.get(candMeta.bucket) ?? preCount;
      const churn = getRecentIpChurn(candMeta.bucket, nowMs);
      const isAged = ageMs >= FRESH_PREHEADER_GRACE_MS;
      const isOtherMultiSocket = candMeta.bucket !== arrivingBucket && preCount >= 2;
      if (!isAged && !isOtherMultiSocket && !allowFreshZeroByte) {
        continue;
      }
      // Prefer aged stalled zero-byte sockets and high-count/high-churn IPs, breaking ties by oldest zero-byte socket
      const agedTierBoost = isAged ? 1_000_000 : 0;
      const score = agedTierBoost + Math.max(preCount, actCount) * 1_000 + Math.min(999, churn);
      if (
        !bestVictim ||
        score > bestScore ||
        (score === bestScore &&
          (cand.connectedAt < bestVictim.connectedAt ||
            (cand.connectedAt === bestVictim.connectedAt && cand.connSeq < bestVictim.connSeq)))
      ) {
        bestVictim = cand;
        bestScore = score;
      }
    }
    return bestVictim;
  };

  interface PressureEvictOptions {
    minIdleAgeMs?: number;
    arrivingBucket?: string;
    allowFreshZeroBytePreHeader?: boolean;
    allowTier3Newcomers?: boolean;
  }

  const evictIdleSocketUnderPressure = (nowMs = Date.now(), evictOpts: PressureEvictOptions = {}): boolean => {
    const minIdleAgeMs = evictOpts.minIdleAgeMs ?? 0;
    const allowFreshZeroByte = evictOpts.allowFreshZeroBytePreHeader ?? false;
    const allowTier3 = evictOpts.allowTier3Newcomers ?? true;

    // Tier 1: Zero-byte pre-header sockets (`requestsCompleted === 0 && bytesRead === 0`) — never evict partial-byte sockets!
    const tier1Victim = selectZeroBytePreHeaderVictim(nowMs, evictOpts.arrivingBucket, false);
    if (tier1Victim) {
      evictSocketRecord(tier1Victim, nowMs, true);
      return true;
    }

    // Tier 2: Idle keep-alive sockets from over-represented IPs (`ipSocketCount > 2`).
    // Pick the IP with the highest `ipSocketCount`, and within that IP evict its youngest / lowest-`requestsCompleted` idle socket first!
    let tier2Victim: TrackedSocketRecord | null = null;
    let tier2IpCount = 2;
    for (const cand of idleKeepAliveSockets.values()) {
      if (cand.phase !== 'idle_keepalive' || cand.activeResponses > 0 || cand.pipelinedWaiting > 0) continue;
      if (hasPartialRequestBytes(cand)) continue;
      if (minIdleAgeMs > 0 && nowMs - cand.idleSince < minIdleAgeMs) continue;
      const ipCount = getIpTotalSocketCount(cand);
      if (ipCount <= 2) continue;
      if (
        remoteActiveSockets < maxTotalSockets &&
        ipCount <= maxEstablishedSocketsPerIp &&
        cand.requestsCompleted >= VETERAN_MIN_COMPLETED_REQUESTS
      ) {
        continue;
      }
      if (
        !tier2Victim ||
        ipCount > tier2IpCount ||
        (ipCount === tier2IpCount &&
          (cand.requestsCompleted < tier2Victim.requestsCompleted ||
            (cand.requestsCompleted === tier2Victim.requestsCompleted &&
              (cand.connectedAt > tier2Victim.connectedAt ||
                (cand.connectedAt === tier2Victim.connectedAt && cand.connSeq > tier2Victim.connSeq)))))
      ) {
        tier2Victim = cand;
        tier2IpCount = ipCount;
      }
    }
    if (tier2Victim) {
      evictSocketRecord(tier2Victim, nowMs);
      return true;
    }

    // Tier 3 (1–2 socket-per-IP tie-break):
    // Protect veteran persistent keep-alive clients (`requestsCompleted >= 2` or age >= 5s with completed requests) up to
    // `maxProtectedVeterans` (`75%` of `maxTotalSockets`), and among newcomers (`requestsCompleted <= 1`) evict FEWEST
    // `requestsCompleted` first and YOUNGEST (`connectedAt` most recent) first!
    if (allowTier3) {
      const maxProtectedVeterans = Math.max(16, Math.floor(maxTotalSockets * 0.75));
      let veteranCount = 0;
      let newcomerVictim: TrackedSocketRecord | null = null;
      let excessVeteranVictim: TrackedSocketRecord | null = null;

      for (const cand of idleKeepAliveSockets.values()) {
        if (cand.phase !== 'idle_keepalive' || cand.activeResponses > 0 || cand.pipelinedWaiting > 0) continue;
        if (hasPartialRequestBytes(cand)) continue;
        const ipCount = getIpTotalSocketCount(cand);
        if (isVeteranKeepAliveSocket(cand, nowMs, ipCount)) {
          veteranCount++;
          if (
            !excessVeteranVictim ||
            cand.requestsCompleted < excessVeteranVictim.requestsCompleted ||
            (cand.requestsCompleted === excessVeteranVictim.requestsCompleted &&
              (cand.connectedAt > excessVeteranVictim.connectedAt ||
                (cand.connectedAt === excessVeteranVictim.connectedAt && cand.connSeq > excessVeteranVictim.connSeq)))
          ) {
            excessVeteranVictim = cand;
          }
          continue;
        }
        if (minIdleAgeMs > 0 && nowMs - cand.idleSince < minIdleAgeMs) continue;
        if (
          !newcomerVictim ||
          cand.requestsCompleted < newcomerVictim.requestsCompleted ||
          (cand.requestsCompleted === newcomerVictim.requestsCompleted &&
            (cand.connectedAt > newcomerVictim.connectedAt ||
              (cand.connectedAt === newcomerVictim.connectedAt && cand.connSeq > newcomerVictim.connSeq)))
        ) {
          newcomerVictim = cand;
        }
      }

      if (newcomerVictim) {
        evictSocketRecord(newcomerVictim, nowMs);
        return true;
      }

      if (veteranCount > maxProtectedVeterans && excessVeteranVictim) {
        evictSocketRecord(excessVeteranVictim, nowMs);
        return true;
      }
    }

    // Hard-cap fallback on fresh zero-byte pre-header churners (`bytesRead === 0` only, NEVER `bytesRead > 0`!)
    if (allowFreshZeroByte) {
      const freshZeroVictim = selectZeroBytePreHeaderVictim(nowMs, evictOpts.arrivingBucket, true);
      if (freshZeroVictim) {
        evictSocketRecord(freshZeroVictim, nowMs, true);
        return true;
      }
    }

    return false;
  };

  const sweepPressuredIdleSockets = () => {
    if (remoteActiveSockets < socketPressureThreshold) return;
    const nowMs = Date.now();
    while (remoteActiveSockets >= socketPressureThreshold) {
      if (
        !evictIdleSocketUnderPressure(nowMs, {
          minIdleAgeMs: PRESSURE_IDLE_EVICT_AGE_MS,
          allowTier3Newcomers: remoteActiveSockets >= softGlobalSocketThreshold,
        })
      ) {
        break;
      }
    }
  };

  const pressureSweepTimer = setInterval(sweepPressuredIdleSockets, 100);
  pressureSweepTimer.unref?.();

  const waitForSocketDrainBounded = (
    socket: net.Socket,
    rec: TrackedSocketRecord | undefined,
    timeoutMs: number,
  ): Promise<boolean> => {
    if (socket.destroyed || !socket.writable) return Promise.resolve(false);
    if ((socket.writableLength ?? 0) <= SOCKET_RESUME_HIGH_WATER_BYTES && !socket.writableNeedDrain) {
      return Promise.resolve(true);
    }
    return new Promise<boolean>((resolveDrain) => {
      let settled = false;
      const finish = (ok: boolean) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        socket.removeListener('drain', onDrain);
        socket.removeListener('close', onAbort);
        socket.removeListener('error', onAbort);
        resolveDrain(ok);
      };
      const onDrain = () => finish(!socket.destroyed && socket.writable);
      const onAbort = () => finish(false);
      const timer = setTimeout(() => {
        if (rec) evictSocketRecord(rec, Date.now(), true);
        else socket.destroy();
        finish(false);
      }, timeoutMs);
      timer.unref?.();
      socket.once('drain', onDrain);
      socket.once('close', onAbort);
      socket.once('error', onAbort);
    });
  };

  const armResponseDrainWatchdog = (socket: net.Socket, rec: TrackedSocketRecord | undefined, timeoutMs: number) => {
    if (socket.destroyed || (socket.writableLength ?? 0) === 0) return;
    let done = false;
    const cleanup = () => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      socket.removeListener('drain', cleanup);
      socket.removeListener('close', cleanup);
    };
    const timer = setTimeout(() => {
      if (done) return;
      done = true;
      socket.removeListener('drain', cleanup);
      socket.removeListener('close', cleanup);
      if (!socket.destroyed && (socket.writableLength ?? 0) > 0) {
        if (rec) evictSocketRecord(rec, Date.now(), true);
        else socket.destroy();
      }
    }, timeoutMs);
    timer.unref?.();
    socket.once('drain', cleanup);
    socket.once('close', cleanup);
  };

  const applyNodeSecurityHeaders = (res: import('node:http').ServerResponse, isHttps = false) => {
    for (const [k, v] of DEFAULT_SECURITY_HEADERS) {
      if (!res.hasHeader(k)) {
        res.setHeader(k, v);
      }
    }
    if (isHttps && !res.hasHeader('strict-transport-security')) {
      res.setHeader('strict-transport-security', 'max-age=31536000; includeSubDomains');
    }
  };

  const forceDestroyReqSocket = (req: IncomingMessage, res: import('node:http').ServerResponse) => {
    const sock = res.socket ?? req.socket;
    const rec = sock ? trackedSockets.get(sock) : undefined;
    if (rec) {
      rec.phase = 'closing';
      removeSocketFromEstablished(rec);
    }
    const tearDown = () => {
      const targetSock = res.socket ?? req.socket;
      const targetRec = targetSock ? trackedSockets.get(targetSock) : undefined;
      req.destroy();
      if (targetRec) evictSocketRecord(targetRec, Date.now(), true);
      else targetSock?.destroy();
    };
    res.once('finish', () => {
      setImmediate(tearDown);
    });
    const fallback = setTimeout(tearDown, 500);
    fallback.unref?.();
  };

  const getCombinedBufferedBytes = (
    socket: net.Socket | null | undefined,
    res: import('node:http').ServerResponse,
  ): number => {
    const sockPending = socket?.writableLength ?? 0;
    const resPending = res.writableLength ?? 0;
    const resOutSize = (res as unknown as { outputSize?: number }).outputSize ?? 0;
    return sockPending + Math.max(resPending, resOutSize);
  };

  const server = createServer(async (req, res) => {
    const reqSocket = req.socket;
    const sockRec = reqSocket ? trackedSockets.get(reqSocket) : undefined;
    sockRec?.finishPreHeader();
    req.on('error', () => undefined);
    res.on('error', () => undefined);

    if (!reqSocket || reqSocket.destroyed) {
      return;
    }

    if (sockRec) {
      sockRec.requestsReceived++;
      const curSocketPending = getCombinedBufferedBytes(reqSocket, res);
      if (
        sockRec.phase === 'closing' ||
        sockRec.requestsReceived > maxRequestsPerConnection ||
        curSocketPending > maxSocketWritableBytes ||
        sockRec.pipelinedWaiting >= MAX_PIPELINED_BACKLOG
      ) {
        evictSocketRecord(sockRec, Date.now(), true);
        return;
      }
    }

    let responseFinished = false;
    if (req.complete) {
      if (!reqSocket.destroyed) reqSocket.pause();
    } else {
      req.once('end', () => {
        if (!responseFinished && !reqSocket.destroyed) {
          reqSocket.pause();
        }
      });
    }

    let releasePipelineTurn: () => void = () => {};
    if (sockRec) {
      const prevPipeline = sockRec.pipelineTail;
      const currentTurnPromise = new Promise<void>((r) => {
        releasePipelineTurn = r;
      });
      sockRec.pipelineTail = currentTurnPromise;

      if (sockRec.activeResponses > 0 || sockRec.pipelinedWaiting > 0 || (reqSocket.writableLength ?? 0) > SOCKET_RESUME_HIGH_WATER_BYTES) {
        sockRec.pipelinedWaiting++;
        try {
          await prevPipeline;
          if (!reqSocket.destroyed && sockRec.phase !== 'closing' && (reqSocket.writableLength ?? 0) > SOCKET_RESUME_HIGH_WATER_BYTES) {
            const drainedBeforeExec = await waitForSocketDrainBounded(reqSocket, sockRec, socketDrainTimeoutMs);
            if (!drainedBeforeExec) {
              releasePipelineTurn();
              return;
            }
          }
        } finally {
          sockRec.pipelinedWaiting = Math.max(0, sockRec.pipelinedWaiting - 1);
        }
      }

      if (reqSocket.destroyed || sockRec.phase === 'closing') {
        releasePipelineTurn();
        return;
      }
    }

    const clientBucket = normalizeClientRateLimitIp(resolveTrustedClientIp(req, trustProxy, trustFlyClientIp));

    if (sockRec) {
      sockRec.activeResponses++;
      sockRec.phase = 'inflight';
      sockRec.bytesReceivedOnCurrentRequest = 0;
      sockRec.sawRequestBytes = false;
      sockRec.headerDeadlineAt = 0;
      idleKeepAliveSockets.delete(reqSocket);
      loopbackIdleKeepAliveSockets.delete(reqSocket);
      if (!sockRec.isLoopback) {
        if (trustProxy && clientBucket !== '127.0.0.1') {
          rebucketActiveSocketIfNeeded(sockRec, clientBucket);
        }
        addSocketToEstablishedBucket(sockRec, sockRec.activeBucket);
      }
    }

    let lifecycleFinalized = false;
    const finalizeSocketTurn = () => {
      if (lifecycleFinalized) return;
      lifecycleFinalized = true;
      responseFinished = true;
      if (sockRec) {
        sockRec.activeResponses = Math.max(0, sockRec.activeResponses - 1);
        sockRec.requestsCompleted++;
        const shouldCloseNow =
          reqSocket.destroyed ||
          !reqSocket.writable ||
          !res.shouldKeepAlive ||
          sockRec.phase === 'closing';
        if (shouldCloseNow) {
          sockRec.phase = 'closing';
          removeSocketFromEstablished(sockRec);
          if (!reqSocket.destroyed) {
            const lingerMs = remoteActiveSockets >= socketPressureThreshold ? 150 : 1_000;
            const closeLinger = setTimeout(() => {
              if (!reqSocket.destroyed) evictSocketRecord(sockRec, Date.now(), true);
            }, lingerMs);
            closeLinger.unref?.();
          }
        } else if (sockRec.activeResponses === 0) {
          sockRec.phase = 'idle_keepalive';
          sockRec.idleSince = Date.now();
          const bufferedNextBytes = reqSocket.readableLength ?? 0;
          sockRec.bytesReadAtTurnStart = reqSocket.bytesRead - bufferedNextBytes;
          sockRec.bytesReceivedOnCurrentRequest = bufferedNextBytes;
          sockRec.sawRequestBytes = bufferedNextBytes > 0;
          sockRec.headerDeadlineAt = bufferedNextBytes > 0 ? sockRec.idleSince + headersTimeoutMs : 0;
          if (sockRec.isLoopback) {
            loopbackIdleKeepAliveSockets.delete(reqSocket);
            loopbackIdleKeepAliveSockets.set(reqSocket, sockRec);
          } else {
            const estKey = sockRec.establishedBucket ?? sockRec.activeBucket;
            addSocketToEstablishedBucket(sockRec, estKey);
            idleKeepAliveSockets.delete(reqSocket);
            idleKeepAliveSockets.set(reqSocket, sockRec);
            const curEstCap = computeDynamicEstPerIpCap();
            while ((establishedSocketsByIp.get(estKey)?.size ?? 0) > curEstCap) {
              if (!evictIdleKeepAliveForBucket(estKey, sockRec.idleSince)) break;
            }
          }
          if (sockRec.pipelinedWaiting === 0 && !reqSocket.destroyed) {
            if ((reqSocket.writableLength ?? 0) <= SOCKET_RESUME_HIGH_WATER_BYTES) {
              reqSocket.resume();
            } else {
              reqSocket.once('drain', () => {
                if (!reqSocket.destroyed && sockRec.phase === 'idle_keepalive' && sockRec.pipelinedWaiting === 0) {
                  reqSocket.resume();
                }
              });
              armResponseDrainWatchdog(reqSocket, sockRec, socketDrainTimeoutMs);
            }
          }
        }
      }
      releasePipelineTurn();
    };
    res.once('finish', finalizeSocketTurn);
    res.once('close', finalizeSocketTurn);

    const applyKeepAlivePressurePolicy = () => {
      if (!sockRec || res.headersSent) return;
      let closeAfterRes = sockRec.requestsReceived >= maxRequestsPerConnection;
      if (!closeAfterRes && !sockRec.isLoopback) {
        const estKey = sockRec.establishedBucket ?? sockRec.activeBucket;
        const ipEstCount = Math.max(
          establishedSocketsByIp.get(estKey)?.size ?? 0,
          activeSocketsByIp.get(sockRec.activeBucket) ?? 1,
        );
        const curEstCap = computeDynamicEstPerIpCap();
        if (ipEstCount > curEstCap) {
          closeAfterRes = true;
        } else if (remoteActiveSockets >= socketPressureThreshold && ipEstCount > 2) {
          closeAfterRes = true;
        }
      }
      if (closeAfterRes) {
        res.shouldKeepAlive = false;
        res.setHeader('connection', 'close');
        sockRec.phase = 'closing';
      }
    };

    const writeChunkBounded = async (chunk: Uint8Array): Promise<boolean> => {
      if (reqSocket.destroyed || !reqSocket.writable || res.writableEnded) return false;
      if (getCombinedBufferedBytes(reqSocket, res) + chunk.byteLength > maxSocketWritableBytes) {
        if (sockRec) evictSocketRecord(sockRec, Date.now(), true);
        else reqSocket.destroy();
        return false;
      }
      const wroteClean = res.write(chunk);
      if (getCombinedBufferedBytes(reqSocket, res) > maxSocketWritableBytes) {
        if (sockRec) evictSocketRecord(sockRec, Date.now(), true);
        else reqSocket.destroy();
        return false;
      }
      if (!wroteClean || (reqSocket.writableLength ?? 0) > SOCKET_RESUME_HIGH_WATER_BYTES) {
        return await waitForSocketDrainBounded(reqSocket, sockRec, socketDrainTimeoutMs);
      }
      return true;
    };

    const endResponseBounded = (payload?: string) => {
      if (reqSocket.destroyed || res.writableEnded) return;
      const addLen = payload ? Buffer.byteLength(payload, 'utf8') : 0;
      if (getCombinedBufferedBytes(reqSocket, res) + addLen > maxSocketWritableBytes) {
        if (sockRec) evictSocketRecord(sockRec, Date.now(), true);
        else reqSocket.destroy();
        return;
      }
      if (payload !== undefined) res.end(payload);
      else res.end();
      if (getCombinedBufferedBytes(reqSocket, res) > maxSocketWritableBytes) {
        if (sockRec) evictSocketRecord(sockRec, Date.now(), true);
        else reqSocket.destroy();
        return;
      }
      armResponseDrainWatchdog(reqSocket, sockRec, socketDrainTimeoutMs);
    };

    const rawPathname = (req.url ?? '/').split('?')[0] ?? '/';
    const methodUpper = (req.method ?? 'GET').toUpperCase();
    const isHealthProbe =
      (methodUpper === 'GET' || methodUpper === 'HEAD') && (rawPathname === '/health' || rawPathname === '/readyz');
    const hasAuthAttemptHeader = Boolean(
      req.headers.authorization || req.headers['x-api-key'] || req.headers.cookie,
    );
    const hasCallerAuth = isHealthProbe ? false : await hasVerifiedCallerCredentials(req, rawPathname);
    if (reqSocket.destroyed) {
      finalizeSocketTurn();
      return;
    }
    const isPublicDiscoveryRoute =
      !isHealthProbe &&
      !hasAuthAttemptHeader &&
      (methodUpper === 'GET' || methodUpper === 'HEAD' || methodUpper === 'OPTIONS') &&
      (rawPathname === '/openapi.json' ||
        rawPathname.startsWith('/.well-known/') ||
        rawPathname === '/admin' ||
        rawPathname === '/admin/login' ||
        rawPathname === '/robots.txt');

    const curIpInflight = inflightByIp.get(clientBucket) ?? 0;
    const isEstablishedVeteranTurn = Boolean(
      sockRec &&
        !sockRec.isLoopback &&
        sockRec.requestsCompleted >= VETERAN_MIN_COMPLETED_REQUESTS &&
        getIpTotalSocketCount(sockRec) <= 2,
    );
    const effectiveInflightPerIp =
      !hasExplicitMaxInflightPerIp && (hasCallerAuth || isHealthProbe || isPublicDiscoveryRoute)
        ? Math.max(maxInflightPerIp, MAX_PREHEADER_SOCKETS_PER_IP)
        : maxInflightPerIp;
    const hitPerIpLimit = curIpInflight >= effectiveInflightPerIp;
    const hitGlobalLimit = isHealthProbe
      ? totalInflight >= maxInflightTotal + 64
      : isEstablishedVeteranTurn
        ? totalInflight >= maxInflightTotal + VETERAN_RESERVED_INFLIGHT
        : isPublicDiscoveryRoute
          ? totalInflight >= maxInflightTotal + PUBLIC_DISCOVERY_RESERVED_INFLIGHT ||
            (!hasCallerAuth &&
              unauthInflight >= maxUnauthInflight &&
              publicDiscoveryInflight >= PUBLIC_DISCOVERY_RESERVED_INFLIGHT)
          : totalInflight >= maxInflightTotal || (!hasCallerAuth && unauthInflight >= maxUnauthInflight);

    if (hitPerIpLimit || hitGlobalLimit) {
      res.statusCode = 429;
      res.setHeader('content-type', 'application/json');
      res.setHeader('cache-control', 'no-store');
      res.setHeader('retry-after', '1');
      applyNodeSecurityHeaders(res, explicitPublicOrigin?.startsWith('https://') ?? false);
      if (!isEstablishedVeteranTurn || !req.complete) {
        res.shouldKeepAlive = false;
        res.setHeader('connection', 'close');
        forceDestroyReqSocket(req, res);
      }
      endResponseBounded(JSON.stringify({ error: 'too_many_requests', message: 'Too many concurrent in-flight requests' }));
      return;
    }

    totalInflight++;
    const countedInPublicDiscovery = !hasCallerAuth && !isHealthProbe && isPublicDiscoveryRoute;
    const countedInUnauth = !hasCallerAuth && !isHealthProbe && !isPublicDiscoveryRoute;
    if (countedInPublicDiscovery) publicDiscoveryInflight++;
    if (countedInUnauth) unauthInflight++;
    inflightByIp.set(clientBucket, curIpInflight + 1);
    let slotReleased = false;
    const releaseInflightSlot = () => {
      if (slotReleased) return;
      slotReleased = true;
      totalInflight = Math.max(0, totalInflight - 1);
      if (countedInPublicDiscovery) publicDiscoveryInflight = Math.max(0, publicDiscoveryInflight - 1);
      if (countedInUnauth) unauthInflight = Math.max(0, unauthInflight - 1);
      const rem = inflightByIp.get(clientBucket) ?? 0;
      if (rem <= 1) inflightByIp.delete(clientBucket);
      else inflightByIp.set(clientBucket, rem - 1);
    };
    res.once('close', releaseInflightSlot);

    try {
      let webReq: Request;
      try {
        webReq = incomingToWebRequest(
          req,
          resolveCanonicalOrigin(),
          trustProxy,
          explicitPublicOrigin !== null,
          trustFlyClientIp,
          hasCallerAuth,
        );
      } catch {
        res.statusCode = 400;
        res.shouldKeepAlive = false;
        res.setHeader('content-type', 'application/json');
        res.setHeader('cache-control', 'no-store');
        res.setHeader('connection', 'close');
        applyNodeSecurityHeaders(res, explicitPublicOrigin?.startsWith('https://') ?? false);
        forceDestroyReqSocket(req, res);
        endResponseBounded(JSON.stringify({ error: 'bad_request', message: 'Malformed HTTP request or Host header' }));
        return;
      }

      const isHttpsReq = webReq.url.startsWith('https://');
      const ignoredBodyFraming =
        (methodUpper === 'GET' || methodUpper === 'HEAD' || methodUpper === 'OPTIONS') &&
        Boolean(req.headers['transfer-encoding'] || (req.headers['content-length'] && req.headers['content-length'] !== '0'));

      if (isHealthProbe) {
        res.statusCode = 200;
        res.setHeader('content-type', 'application/json; charset=utf-8');
        res.setHeader('cache-control', 'no-store');
        applyNodeSecurityHeaders(res, isHttpsReq);
        if (ignoredBodyFraming) {
          res.shouldKeepAlive = false;
          res.setHeader('connection', 'close');
          forceDestroyReqSocket(req, res);
        } else {
          applyKeepAlivePressurePolicy();
        }
        endResponseBounded(methodUpper === 'HEAD' ? undefined : '{"ok":true}');
        return;
      }

      try {
        const webRes = await (hubWorker as { fetch(r: Request, e: unknown, c?: ExecutionContext): Promise<Response> }).fetch(webReq, workerEnv, ctx);
        if (reqSocket.destroyed) return;
        res.statusCode = webRes.status;
        webRes.headers.forEach((val, key) => {
          if (key.toLowerCase() === 'set-cookie') {
            const getSetCookie = (webRes.headers as unknown as { getSetCookie?: () => string[] }).getSetCookie;
            if (typeof getSetCookie === 'function') {
              res.setHeader('set-cookie', getSetCookie.call(webRes.headers));
              return;
            }
          }
          res.setHeader(key, val);
        });
        applyNodeSecurityHeaders(res, isHttpsReq);
        // `R3-M1`: Whenever an unauthenticated / over-limit / error response (`>= 400`) finishes while the client is still
        // streaming an unread request body (`!req.complete`), OR when a `GET`/`HEAD`/`OPTIONS` request includes unexpected body framing,
        // send `Connection: close` and destroy the socket after flush!
        const shouldDestroyAfterFlush = (!req.complete && webRes.status >= 400) || ignoredBodyFraming;
        if (shouldDestroyAfterFlush) {
          res.shouldKeepAlive = false;
          res.setHeader('connection', 'close');
          forceDestroyReqSocket(req, res);
        } else {
          applyKeepAlivePressurePolicy();
        }
        if (!webRes.body) {
          endResponseBounded();
          return;
        }
        const reader = webRes.body.getReader();
        try {
          while (true) {
            const { done, value } = await reader.read();
            if (done) break;
            if (value && value.byteLength > 0) {
              const ok = await writeChunkBounded(value);
              if (!ok) {
                await reader.cancel('Slow client outbound buffer limit exceeded').catch(() => undefined);
                return;
              }
            }
          }
        } catch (streamErr) {
          await reader.cancel().catch(() => undefined);
          throw streamErr;
        }
        endResponseBounded();
      } catch (err) {
        if (reqSocket.destroyed || res.headersSent || res.writableEnded) {
          if (sockRec) evictSocketRecord(sockRec, Date.now(), true);
          else reqSocket.destroy();
          return;
        }
        res.statusCode = 500;
        res.shouldKeepAlive = false;
        res.setHeader('content-type', 'application/json');
        res.setHeader('cache-control', 'no-store');
        res.setHeader('connection', 'close');
        applyNodeSecurityHeaders(res, isHttpsReq);
        if (!req.complete) {
          forceDestroyReqSocket(req, res);
        }
        endResponseBounded(JSON.stringify({ error: 'internal_error', message: err instanceof Error ? err.message : String(err) }));
      }
    } finally {
      releaseInflightSlot();
    }
  });
  server.headersTimeout = headersTimeoutMs;
  server.requestTimeout = 30_000;
  server.keepAliveTimeout = keepAliveTimeoutMs;
  server.maxRequestsPerSocket = maxRequestsPerConnection;
  // Leave `server.maxConnections` unset so Node never drops incoming connections via `handle.close()` before
  // `server.on('connection')` runs our isolated loopback admission + synchronous keep-alive/pre-header eviction!

  server.on('connection', (socket) => {
    socket.on('error', () => undefined);
    const sockIp = normalizeSocketIp(socket.remoteAddress);
    const sockBucket = normalizeClientRateLimitIp(sockIp);
    const isStrictLoopbackProbe = sockBucket === '127.0.0.1';
    const effectiveRawPerIpCap =
      !trustProxy || hasExplicitMaxConnPerIp
        ? maxConnectionsPerIp
        : Math.max(maxConnectionsPerIp, maxInflightTotal + 32);
    const nowConnMs = Date.now();
    const connSeq = ++nextConnSeq;

    // Dedicated isolated loopback headroom (`127.0.0.1`, `::1`, `::ffff:127.0.0.1`): never competes with remote sockets!
    if (isStrictLoopbackProbe) {
      const loopbackCap = Math.max(effectiveRawPerIpCap, LOOPBACK_RESERVED_CONNECTIONS) + LOOPBACK_RESERVED_CONNECTIONS;
      while (loopbackActiveSockets >= loopbackCap && loopbackIdleKeepAliveSockets.size > 0) {
        const oldestLb = loopbackIdleKeepAliveSockets.values().next().value as TrackedSocketRecord | undefined;
        if (!oldestLb) break;
        evictSocketRecord(oldestLb, nowConnMs);
      }
      if (loopbackActiveSockets >= loopbackCap) {
        socket.destroy();
        return;
      }
      loopbackActiveSockets++;
      let lbHeaderDone = false;
      let lbAccountedClosed = false;
      let lbTimer: ReturnType<typeof setTimeout> | null = setTimeout(() => {
        evictSocketRecord(lbRecord, Date.now(), true);
      }, headersTimeoutMs);
      lbTimer.unref?.();
      const finishLbPreHeader = () => {
        if (lbHeaderDone) return;
        lbHeaderDone = true;
        if (lbTimer) {
          clearTimeout(lbTimer);
          lbTimer = null;
        }
      };
      const releaseLbAccounting = () => {
        finishLbPreHeader();
        loopbackIdleKeepAliveSockets.delete(socket);
        if (lbAccountedClosed) return;
        lbAccountedClosed = true;
        lbRecord.phase = 'closing';
        loopbackActiveSockets = Math.max(0, loopbackActiveSockets - 1);
      };
      const lbRecord: TrackedSocketRecord = {
        socket,
        connSeq,
        isLoopback: true,
        activeBucket: '127.0.0.1',
        establishedBucket: null,
        phase: 'preheader',
        connectedAt: nowConnMs,
        headerDeadlineAt: nowConnMs + headersTimeoutMs,
        idleSince: nowConnMs,
        bytesReadAtTurnStart: 0,
        bytesReceivedOnCurrentRequest: 0,
        sawRequestBytes: false,
        requestsReceived: 0,
        requestsCompleted: 0,
        activeResponses: 0,
        pipelinedWaiting: 0,
        pipelineTail: Promise.resolve(),
        finishPreHeader: finishLbPreHeader,
        releaseAccounting: releaseLbAccounting,
        markUpgradedWs: () => {
          finishLbPreHeader();
          loopbackIdleKeepAliveSockets.delete(socket);
          lbRecord.phase = 'upgraded_ws';
        },
      };
      trackedSockets.set(socket, lbRecord);
      socket.once('end', () => {
        if (!lbHeaderDone) evictSocketRecord(lbRecord, Date.now(), true);
      });
      socket.once('close', releaseLbAccounting);
      return;
    }

    recordIpConnChurn(sockBucket, nowConnMs);

    const effectivePreHeaderPerIpCap =
      !trustProxy || hasExplicitMaxPreHeaderPerIp
        ? maxPreHeaderPerIp
        : Math.max(maxPreHeaderPerIp, Math.min(128, maxGlobalPreHeaderSockets));

    // 1. Shared-NAT pre-header defense (`R8-M1` + `R10-P1`): if ZERO-BYTE stalled pre-header sockets on `sockBucket`
    //    have filled its per-IP pre-header cap, evict the oldest zero-byte stalled (`>= 50ms`) pre-header socket on
    //    `sockBucket`. NEVER evict any pre-header socket that has already sent request bytes (`bytesRead > 0`)!
    while ((preHeaderSocketsByIp.get(sockBucket) ?? 0) >= effectivePreHeaderPerIpCap) {
      let sameIpVictimRec: TrackedSocketRecord | null = null;
      for (const candMeta of remotePreHeaderSockets.values()) {
        const candRec = candMeta.record;
        if (
          candMeta.bucket === sockBucket &&
          candRec.requestsCompleted === 0 &&
          !hasPartialRequestBytes(candRec) &&
          nowConnMs - candMeta.connectedAt >= SHARED_NAT_PREHEADER_EVICT_AGE_MS
        ) {
          sameIpVictimRec = candRec;
          break;
        }
      }
      if (!sameIpVictimRec) {
        socket.destroy();
        return;
      }
      evictSocketRecord(sameIpVictimRec, nowConnMs, true);
    }

    // 2. Per-IP & Shared-NAT established keep-alive fairness (`R9-H7` + `R10-P1`):
    //    Allows up to 64 persistent connections per shared-NAT IP when global capacity has headroom (< socketPressureThreshold),
    //    tightening to 16 under global pressure while evicting youngest/lowest-request idle sockets on `sockBucket`.
    while (
      (establishedSocketsByIp.get(sockBucket)?.size ?? 0) >= computeDynamicEstPerIpCap() ||
      (activeSocketsByIp.get(sockBucket) ?? 0) >= effectiveRawPerIpCap
    ) {
      if (!evictIdleKeepAliveForBucket(sockBucket, nowConnMs)) {
        break;
      }
    }

    // 3. Soft global socket pressure (`>= softGlobalSocketThreshold`):
    //    1-for-1 eviction via strict 3-tier priority (zero-byte pre-header -> bloated IPs -> youngest newcomers; never veterans!).
    if (remoteActiveSockets >= softGlobalSocketThreshold && remoteActiveSockets < maxTotalSockets) {
      evictIdleSocketUnderPressure(nowConnMs, {
        arrivingBucket: sockBucket,
        allowFreshZeroBytePreHeader: false,
        allowTier3Newcomers: true,
      });
    }

    // 4. Hard global zero-byte pre-header / total socket caps (`R10-P1`):
    //    Pre-header sockets that have already sent request bytes (`bytesRead > 0`) are protected active requests
    //    counted against `maxTotalSockets` (never evicted before `headersTimeoutMs`), while zero-byte idle pre-header
    //    sockets are bounded by `maxGlobalPreHeaderSockets`.
    while (countZeroByteRemotePreHeaderSockets() >= maxGlobalPreHeaderSockets || remoteActiveSockets >= maxTotalSockets) {
      if (countZeroByteRemotePreHeaderSockets() >= maxGlobalPreHeaderSockets && remoteActiveSockets < maxTotalSockets) {
        const preVictim =
          selectZeroBytePreHeaderVictim(nowConnMs, sockBucket, false) ??
          selectZeroBytePreHeaderVictim(nowConnMs, sockBucket, true);
        if (!preVictim) {
          socket.destroy();
          return;
        }
        evictSocketRecord(preVictim, nowConnMs, true);
        continue;
      }

      const evicted = evictIdleSocketUnderPressure(nowConnMs, {
        arrivingBucket: sockBucket,
        allowFreshZeroBytePreHeader: true,
        allowTier3Newcomers: true,
      });
      if (!evicted) {
        socket.destroy();
        return;
      }
    }

    const curActiveForIp = activeSocketsByIp.get(sockBucket) ?? 0;
    if (remoteActiveSockets >= maxTotalSockets || curActiveForIp >= effectiveRawPerIpCap) {
      socket.destroy();
      return;
    }

    remoteActiveSockets++;
    activeSocketsByIp.set(sockBucket, curActiveForIp + 1);
    preHeaderSocketsByIp.set(sockBucket, (preHeaderSocketsByIp.get(sockBucket) ?? 0) + 1);

    let headerPhaseDone = false;
    let socketAccountedClosed = false;
    let idlePartialHeaderTimer: ReturnType<typeof setTimeout> | null = null;
    const clearIdlePartialHeaderTimer = () => {
      if (idlePartialHeaderTimer) {
        clearTimeout(idlePartialHeaderTimer);
        idlePartialHeaderTimer = null;
      }
    };

    const firstByteDeadlineMs = Math.min(headersTimeoutMs, FIRST_BYTE_PREHEADER_TIMEOUT_MS);
    let preHeaderTimer: ReturnType<typeof setTimeout> | null = setTimeout(() => {
      if (headerPhaseDone) return;
      if (!hasPartialRequestBytes(rec) || headersTimeoutMs <= FIRST_BYTE_PREHEADER_TIMEOUT_MS) {
        evictSocketRecord(rec, Date.now(), true);
        return;
      }
      const remainingMs = Math.max(1, rec.headerDeadlineAt - Date.now());
      preHeaderTimer = setTimeout(() => {
        if (!headerPhaseDone) {
          evictSocketRecord(rec, Date.now(), true);
        }
      }, remainingMs);
      preHeaderTimer.unref?.();
    }, firstByteDeadlineMs);
    preHeaderTimer.unref?.();

    const finishPreHeaderPhase = () => {
      clearIdlePartialHeaderTimer();
      if (headerPhaseDone) return;
      headerPhaseDone = true;
      if (preHeaderTimer) {
        clearTimeout(preHeaderTimer);
        preHeaderTimer = null;
      }
      remotePreHeaderSockets.delete(socket);
      const remPre = preHeaderSocketsByIp.get(sockBucket) ?? 0;
      if (remPre <= 1) preHeaderSocketsByIp.delete(sockBucket);
      else preHeaderSocketsByIp.set(sockBucket, remPre - 1);
    };

    const onRawSocketData = (chunk: Buffer | Uint8Array) => {
      if (chunk.byteLength <= 0 || rec.phase === 'closing' || rec.phase === 'upgraded_ws') return;
      if (rec.phase === 'preheader' || rec.phase === 'idle_keepalive') {
        rec.bytesReceivedOnCurrentRequest += chunk.byteLength;
        if (!rec.sawRequestBytes) {
          rec.sawRequestBytes = true;
          if (rec.phase === 'idle_keepalive') {
            const nowDataMs = Date.now();
            rec.headerDeadlineAt = nowDataMs + headersTimeoutMs;
            clearIdlePartialHeaderTimer();
            idlePartialHeaderTimer = setTimeout(() => {
              if (rec.phase === 'idle_keepalive' && rec.sawRequestBytes) {
                evictSocketRecord(rec, Date.now(), true);
              }
            }, headersTimeoutMs);
            idlePartialHeaderTimer.unref?.();
          }
        }
      }
    };

    const releaseRemoteAccounting = () => {
      clearIdlePartialHeaderTimer();
      socket.removeListener('data', onRawSocketData);
      finishPreHeaderPhase();
      removeSocketFromEstablished(rec);
      if (socketAccountedClosed) return;
      socketAccountedClosed = true;
      rec.phase = 'closing';
      remoteActiveSockets = Math.max(0, remoteActiveSockets - 1);
      const remSock = activeSocketsByIp.get(rec.activeBucket) ?? 0;
      if (remSock <= 1) activeSocketsByIp.delete(rec.activeBucket);
      else activeSocketsByIp.set(rec.activeBucket, remSock - 1);
    };

    const rec: TrackedSocketRecord = {
      socket,
      connSeq,
      isLoopback: false,
      activeBucket: sockBucket,
      establishedBucket: null,
      phase: 'preheader',
      connectedAt: nowConnMs,
      headerDeadlineAt: nowConnMs + headersTimeoutMs,
      idleSince: nowConnMs,
      bytesReadAtTurnStart: 0,
      bytesReceivedOnCurrentRequest: 0,
      sawRequestBytes: false,
      requestsReceived: 0,
      requestsCompleted: 0,
      activeResponses: 0,
      pipelinedWaiting: 0,
      pipelineTail: Promise.resolve(),
      finishPreHeader: finishPreHeaderPhase,
      releaseAccounting: releaseRemoteAccounting,
      markUpgradedWs: () => {
        clearIdlePartialHeaderTimer();
        socket.removeListener('data', onRawSocketData);
        finishPreHeaderPhase();
        removeSocketFromEstablished(rec);
        if (!socketAccountedClosed) {
          socketAccountedClosed = true;
          remoteActiveSockets = Math.max(0, remoteActiveSockets - 1);
          const remSock = activeSocketsByIp.get(rec.activeBucket) ?? 0;
          if (remSock <= 1) activeSocketsByIp.delete(rec.activeBucket);
          else activeSocketsByIp.set(rec.activeBucket, remSock - 1);
        }
        rec.phase = 'upgraded_ws';
      },
    };
    socket.on('data', onRawSocketData);
    trackedSockets.set(socket, rec);
    remotePreHeaderSockets.set(socket, {
      bucket: sockBucket,
      connectedAt: nowConnMs,
      record: rec,
    });

    socket.once('end', () => {
      if (!headerPhaseDone) {
        evictSocketRecord(rec, Date.now(), true);
      }
    });

    socket.once('close', releaseRemoteAccounting);
  });

  server.on('clientError', (_err, socket) => {
    socket.on('error', () => undefined);
    const rec = socket instanceof net.Socket ? trackedSockets.get(socket) : undefined;
    rec?.finishPreHeader();
    if (socket.writable && !socket.destroyed) {
      socket.end('HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n');
      const t = setTimeout(() => {
        if (rec) evictSocketRecord(rec, Date.now(), true);
        else socket.destroy();
      }, 250);
      t.unref?.();
    } else if (rec) {
      evictSocketRecord(rec, Date.now(), true);
    } else {
      socket.destroy();
    }
  });

  const wss = new WebSocketServer({
    noServer: true,
    maxPayload: 1_048_576,
    perMessageDeflate: false,
    handleProtocols: (protocols) => (protocols.has('edgefetch-agent') ? 'edgefetch-agent' : false),
  });
  const activeWsBySite = new Map<string, number>();

  server.on('upgrade', (req, socket, head) => {
    socket.on('error', () => undefined);
    const wsSockRec = socket instanceof net.Socket ? trackedSockets.get(socket) : undefined;
    wsSockRec?.finishPreHeader();
    const destroyUpgradeSock = () => {
      if (wsSockRec) evictSocketRecord(wsSockRec, Date.now(), true);
      else socket.destroy();
    };
    try {
      const pathname = (req.url ?? '/').split('?')[0];
      if (pathname !== '/agent/ws') {
        socket.write('HTTP/1.1 404 Not Found\r\nX-Content-Type-Options: nosniff\r\nConnection: close\r\nContent-Length: 0\r\n\r\n');
        destroyUpgradeSock();
        return;
      }
      let webReq: Request;
      try {
        webReq = incomingToWebRequest(
          req,
          resolveCanonicalOrigin(),
          trustProxy,
          explicitPublicOrigin !== null,
          trustFlyClientIp,
        );
      } catch {
        socket.write('HTTP/1.1 400 Bad Request\r\nX-Content-Type-Options: nosniff\r\nConnection: close\r\nContent-Length: 0\r\n\r\n');
        destroyUpgradeSock();
        return;
      }
      const auth = authorizeAgent(webReq, workerEnv as { AGENT_TOKEN?: string; AGENT_TOKENS?: string });
      const wsKey = req.headers['sec-websocket-key'];
      if (!auth.ok || typeof wsKey !== 'string' || !wsKey.trim()) {
        socket.write('HTTP/1.1 401 Unauthorized\r\nX-Content-Type-Options: nosniff\r\nConnection: close\r\nContent-Length: 0\r\n\r\n');
        destroyUpgradeSock();
        return;
      }
      const curSiteWs = activeWsBySite.get(auth.siteId) ?? 0;
      if (wss.clients.size >= MAX_AGENT_WS_CONNECTIONS || curSiteWs >= MAX_AGENT_WS_PER_SITE) {
        socket.write(
          'HTTP/1.1 429 Too Many Requests\r\nRetry-After: 5\r\nX-Content-Type-Options: nosniff\r\nConnection: close\r\nContent-Length: 0\r\n\r\n',
        );
        destroyUpgradeSock();
        return;
      }
      const pubIp = resolveTrustedClientIp(req, trustProxy, trustFlyClientIp);
      wss.handleUpgrade(req, socket, head, (wsClient) => {
        wsSockRec?.markUpgradedWs();
        activeWsBySite.set(auth.siteId, (activeWsBySite.get(auth.siteId) ?? 0) + 1);
        let wsCountReleased = false;
        wsClient.once('close', () => {
          if (wsCountReleased) return;
          wsCountReleased = true;
          const rem = activeWsBySite.get(auth.siteId) ?? 0;
          if (rem <= 1) activeWsBySite.delete(auth.siteId);
          else activeWsBySite.set(auth.siteId, rem - 1);
        });
        coordinator.acceptWebSocket({
          ws: wsClient,
          siteId: auth.siteId,
          arch: (req.headers['x-agent-arch'] as string | undefined) ?? null,
          version: (req.headers['x-agent-version'] as string | undefined) ?? null,
          browserVersion: (req.headers['x-agent-browser-version'] as string | undefined) ?? null,
          browserSandbox: (req.headers['x-agent-browser-sandbox'] as string | undefined) ?? null,
          capabilities: (req.headers['x-agent-capabilities'] as string | undefined) ?? null,
          publicIp: pubIp,
        });
      });
    } catch {
      try {
        socket.write('HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n');
      } catch {
        // ignore write failure
      }
      destroyUpgradeSock();
    }
  });

  return new Promise<{ server: typeof server; port: number; close: () => Promise<void> }>((resolveStart, rejectStart) => {
    server.once('error', rejectStart);
    server.listen(port, host, 2048, () => {
      const addr = server.address();
      boundPort = typeof addr === 'object' && addr ? addr.port : port;
      resolveStart({
        server,
        port: boundPort,
        close: () =>
          new Promise<void>((resClose) => {
            clearInterval(pressureSweepTimer);
            coordinator.close();
            for (const client of wss.clients) {
              try {
                client.terminate();
              } catch {
                // ignore
              }
            }
            wss.close();
            server.close(() => {
              localMetaDb?.close();
              localSearchDb?.close();
              resClose();
            });
            server.closeIdleConnections?.();
            server.closeAllConnections?.();
          }),
      });
    });
  });
}

// Run directly ONLY when executed as the standalone portable-server CLI script (never when imported inside bundled tests).
if (process.argv[1]?.replace(/\\/g, '/').endsWith('/portable-server.mjs') || process.argv[1] === 'portable-server.mjs') {
  startPortableHub()
    .then(({ port }) => {
      console.info(JSON.stringify({ event: 'portable_hub_listening', port, dataDir: process.env.EDGEFETCH_DATA_DIR ?? './.edgefetch-data' }));
    })
    .catch((err) => {
      console.error(err);
      process.exit(1);
    });
}
