/**
 * Portable Node.js 22.5+ / Docker / Fly.io / Railway / Render Hub entrypoint (`hub/dist/portable-server.mjs`).
 *
 * Runs the complete EdgeFetch Hub (`/admin` Control Center, OAuth 2.1, 15-tool `/mcp`, `.ipynb`/OpenAPI/Defuddle
 * extractors, `node:sqlite` FTS5 search, local `/data/artifacts` object store, `/agent/ws` Go worker fleet, and
 * vendor-agnostic OTLP trace export) with zero Cloudflare account, zero Postgres, and zero Redis!
 */
import { createServer, type IncomingMessage } from 'node:http';
import net from 'node:net';
import { join, resolve } from 'node:path';
import metaSchemaSql from '../migrations/meta/0001_tracking.sql';
import searchSchemaSql from '../migrations/search/0001_fts.sql';
import { authorizeAgent } from '../src/auth';
import hubWorker from '../src/index';
import { LocalAgentHubCoordinator, NodeFsR2Bucket, NodeSqliteD1Database } from './node-adapters';
import { S3ArtifactBucket } from './s3-bucket';
import { createSafeOutboundFetch, type LookupResolverFn } from './safe-fetch';
import { TursoHttpD1Database } from './turso-d1';

export interface PortableHubOptions {
  port?: number;
  host?: string;
  dataDir?: string;
  migrationsDir?: string;
  envOverrides?: Record<string, string | undefined>;
  dnsResolver?: LookupResolverFn;
}

function isTruthyFlag(val: string | undefined): boolean {
  const clean = (val ?? '').trim().toLowerCase();
  return clean === '1' || clean === 'true' || clean === 'yes' || clean === 'on';
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

function resolveTrustedClientIp(req: IncomingMessage, trustProxy: boolean): string {
  if (trustProxy) {
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
  let ctrl!: ReadableStreamDefaultController<Uint8Array>;

  const cleanup = () => {
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

  // M8: When `EDGEFETCH_PUBLIC_ORIGIN` is explicitly configured (or proxy headers are untrusted), strictly pin to `canonicalOrigin`.
  if (params.hasExplicitPublicOrigin || !params.trustProxy) {
    return { origin: baseOriginUrl.origin, trustedForwardedHost: null };
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

  // Strictly validate single-host syntax on both `Host` and `X-Forwarded-Host` (port <= 65535, no commas/spaces/`..`/IPv6),
  // and require `EDGEFETCH_PUBLIC_ORIGIN` to override `Host` behind a proxy — falling back only to validated `Host` so a
  // spoofed `X-Forwarded-Host` cannot forge OAuth issuer metadata or bypass `/mcp` `Origin` validation!
  const validHost = parseStrictSingleHost(params.hostHeader);
  const validFwdHost = parseStrictSingleHost(params.forwardedHostHeader);
  const authority = validHost ?? baseOriginUrl.host;
  const trustedForwardedHost = validFwdHost !== null && validHost !== null && validFwdHost === validHost ? validFwdHost : null;

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
    // H4: Never trust client-supplied `cf-connecting-ip`, and strip `x-forwarded-*` unless `EDGEFETCH_TRUST_PROXY=1`.
    if (lower === 'cf-connecting-ip') continue;
    if (!trustProxy && lower.startsWith('x-forwarded-')) continue;
    if (lower === 'x-forwarded-host' && trustedForwardedHost === null) continue;
    if (Array.isArray(v)) {
      for (const item of v) headers.append(k, item);
    } else if (typeof v === 'string') {
      headers.set(k, v);
    }
  }
  headers.set('cf-connecting-ip', resolveTrustedClientIp(req, trustProxy));

  const method = (req.method ?? 'GET').toUpperCase();
  const hasBody = method !== 'GET' && method !== 'HEAD' && method !== 'OPTIONS';
  return new Request(fullUrl, {
    method,
    headers,
    ...(hasBody ? { body: safeNodeReqToWebStream(req), duplex: 'half' } : {}),
  } as RequestInit);
}

export function startPortableHub(opts: PortableHubOptions = {}) {
  const port = opts.port ?? Number(process.env.PORT || 8787);
  const host = opts.host ?? process.env.HOST ?? '0.0.0.0';
  const dataDir = resolve(opts.dataDir ?? process.env.EDGEFETCH_DATA_DIR ?? './.edgefetch-data');

  const mergedEnv = { ...process.env, ...(opts.envOverrides ?? {}) };
  const trustProxy = isTruthyFlag(mergedEnv.EDGEFETCH_TRUST_PROXY);
  const tursoUrl = mergedEnv.TURSO_DATABASE_URL;
  const tursoToken = mergedEnv.TURSO_AUTH_TOKEN;

  const coordinator = new LocalAgentHubCoordinator(join(dataDir, 'hub.sqlite'));
  const localMetaDb = (mergedEnv.META_TURSO_URL || tursoUrl)
    ? null
    : new NodeSqliteD1Database(
        join(dataDir, 'meta.sqlite'),
        opts.migrationsDir
          ? [join(resolve(opts.migrationsDir), 'meta', '0001_tracking.sql')]
          : [{ name: 'meta/0001_tracking.sql', sql: metaSchemaSql }],
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

  const workerEnv: Record<string, unknown> = {
    AGENT_HUB: coordinator.asNamespace(),
    META: metaDb,
    SEARCH: searchDb,
    ARTIFACTS: artifactsBucket,
    SAFE_FETCH: safeFetch,
    SAFE_PUBLIC_FETCH: safePublicFetch,
    CALLER_TOKEN: mergedEnv.CALLER_TOKEN ?? mergedEnv.EDGEFETCH_CALLER_TOKEN ?? mergedEnv.EDGEFETCH_SERVER_TOKEN,
    MCP_TOKEN: mergedEnv.MCP_TOKEN,
    AGENT_TOKEN: mergedEnv.AGENT_TOKEN ?? mergedEnv.EDGEFETCH_AGENT_TOKEN,
    AGENT_TOKENS: mergedEnv.AGENT_TOKENS ?? mergedEnv.EDGEFETCH_AGENT_TOKENS,
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
  };

  let boundPort = port;
  let explicitPublicOrigin: string | null = null;
  if (mergedEnv.EDGEFETCH_PUBLIC_ORIGIN?.trim()) {
    try {
      explicitPublicOrigin = new URL(mergedEnv.EDGEFETCH_PUBLIC_ORIGIN.trim()).origin;
    } catch {
      explicitPublicOrigin = null;
    }
  }
  const resolveCanonicalOrigin = (): string => {
    if (explicitPublicOrigin) return explicitPublicOrigin;
    const defaultHost = host === '0.0.0.0' || host === '::' ? 'hub.local' : host;
    return `http://${defaultHost}:${boundPort}`;
  };

  const ctx = {
    waitUntil(promise: Promise<unknown>): void {
      promise.catch(() => undefined);
    },
    passThroughOnException(): void {
      // noop
    },
  } as unknown as ExecutionContext;

  const server = createServer(async (req, res) => {
    req.on('error', () => undefined);
    let webReq: Request;
    try {
      webReq = incomingToWebRequest(req, resolveCanonicalOrigin(), trustProxy, explicitPublicOrigin !== null);
    } catch {
      res.statusCode = 400;
      res.setHeader('content-type', 'application/json');
      res.setHeader('connection', 'close');
      res.once('finish', () => {
        setImmediate(() => req.destroy());
      });
      res.end(JSON.stringify({ error: 'bad_request', message: 'Malformed HTTP request or Host header' }));
      return;
    }
    try {
      const webRes = await (hubWorker as { fetch(r: Request, e: unknown, c?: ExecutionContext): Promise<Response> }).fetch(webReq, workerEnv, ctx);
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
      // `R3-M1`: Whenever an unauthenticated / over-limit / error response (`>= 400`) finishes while the client is still
      // streaming an unread request body (`!req.complete`), OR when a `GET`/`HEAD`/`OPTIONS` request includes unexpected body framing,
      // send `Connection: close` and destroy the socket after flush!
      const methodUpper = (req.method ?? 'GET').toUpperCase();
      const ignoredBodyFraming =
        (methodUpper === 'GET' || methodUpper === 'HEAD' || methodUpper === 'OPTIONS') &&
        Boolean(req.headers['transfer-encoding'] || (req.headers['content-length'] && req.headers['content-length'] !== '0'));
      const shouldDestroyAfterFlush = (!req.complete && webRes.status >= 400) || ignoredBodyFraming;
      if (shouldDestroyAfterFlush) {
        res.setHeader('connection', 'close');
        res.once('finish', () => {
          setImmediate(() => req.destroy());
        });
      }
      if (!webRes.body) {
        res.end();
        return;
      }
      const reader = webRes.body.getReader();
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        res.write(value);
      }
      res.end();
    } catch (err) {
      res.statusCode = 500;
      res.setHeader('content-type', 'application/json');
      res.setHeader('connection', 'close');
      if (!req.complete) {
        res.once('finish', () => {
          setImmediate(() => req.destroy());
        });
      }
      res.end(JSON.stringify({ error: 'internal_error', message: err instanceof Error ? err.message : String(err) }));
    }
  });
  server.headersTimeout = 15_000;
  server.requestTimeout = 30_000;
  server.keepAliveTimeout = 5_000;
  server.maxConnections = 512;

  server.on('upgrade', (req, socket, head) => {
    socket.on('error', () => undefined);
    try {
      const pathname = (req.url ?? '/').split('?')[0];
      if (pathname !== '/agent/ws') {
        socket.write('HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n');
        socket.destroy();
        return;
      }
      let webReq: Request;
      try {
        webReq = incomingToWebRequest(req, resolveCanonicalOrigin(), trustProxy, explicitPublicOrigin !== null);
      } catch {
        socket.write('HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n');
        socket.destroy();
        return;
      }
      const auth = authorizeAgent(webReq, workerEnv as { AGENT_TOKEN?: string; AGENT_TOKENS?: string });
      const wsKey = req.headers['sec-websocket-key'];
      if (!auth.ok || typeof wsKey !== 'string' || !wsKey.trim()) {
        socket.write('HTTP/1.1 401 Unauthorized\r\nConnection: close\r\n\r\n');
        socket.destroy();
        return;
      }
      const pubIp = resolveTrustedClientIp(req, trustProxy);
      const selectedProto = String(req.headers['sec-websocket-protocol'] ?? '')
        .split(',')
        .map((s) => s.trim())
        .find((s) => s === 'edgefetch-agent');
      coordinator.acceptNodeUpgrade({
        wsKey,
        socket,
        head,
        siteId: auth.siteId,
        arch: (req.headers['x-agent-arch'] as string | undefined) ?? null,
        version: (req.headers['x-agent-version'] as string | undefined) ?? null,
        browserVersion: (req.headers['x-agent-browser-version'] as string | undefined) ?? null,
        browserSandbox: (req.headers['x-agent-browser-sandbox'] as string | undefined) ?? null,
        capabilities: (req.headers['x-agent-capabilities'] as string | undefined) ?? null,
        publicIp: pubIp,
        subprotocol: selectedProto ?? null,
      });
    } catch {
      try {
        socket.write('HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n');
      } catch {
        // ignore write failure
      }
      socket.destroy();
    }
  });

  return new Promise<{ server: typeof server; port: number; close: () => Promise<void> }>((resolveStart, rejectStart) => {
    server.once('error', rejectStart);
    server.listen(port, host, () => {
      const addr = server.address();
      boundPort = typeof addr === 'object' && addr ? addr.port : port;
      resolveStart({
        server,
        port: boundPort,
        close: () =>
          new Promise<void>((resClose) => {
            coordinator.close();
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
