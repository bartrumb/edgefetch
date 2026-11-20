/**
 * Portable Node.js 22.5+ / Docker / Fly.io / Railway / Render Hub entrypoint (`hub/dist/portable-server.mjs`).
 *
 * Runs the complete EdgeFetch Hub (`/admin` Control Center, OAuth 2.1, 14-tool `/mcp`, `.ipynb`/OpenAPI/Defuddle
 * extractors, `node:sqlite` FTS5 search, local `/data/artifacts` object store, `/agent/ws` Go worker fleet, and
 * vendor-agnostic OTLP trace export) with zero Cloudflare account, zero Postgres, and zero Redis!
 */
import { createServer, type IncomingMessage } from 'node:http';
import { join, resolve } from 'node:path';
import { Readable } from 'node:stream';
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

function normalizeSocketIp(addr: string | undefined): string {
  const raw = (addr ?? '').trim();
  if (!raw) return '127.0.0.1';
  if (raw.startsWith('::ffff:')) {
    const v4 = raw.slice('::ffff:'.length);
    if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(v4)) return v4;
  }
  return raw;
}

function resolveTrustedClientIp(req: IncomingMessage, trustProxy: boolean): string {
  if (trustProxy) {
    const xff = (req.headers['x-forwarded-for'] as string | undefined)?.split(',')[0]?.trim();
    if (xff) return normalizeSocketIp(xff);
  }
  return normalizeSocketIp(req.socket?.remoteAddress);
}

function incomingToWebRequest(req: IncomingMessage, canonicalOrigin: string, trustProxy: boolean): Request {
  const baseOriginUrl = new URL(canonicalOrigin);
  let proto = baseOriginUrl.protocol.replace(/:$/, '');
  let authority = baseOriginUrl.host;

  if (trustProxy) {
    const fwdProto = (req.headers['x-forwarded-proto'] as string | undefined)?.split(',')[0]?.trim().toLowerCase();
    if (fwdProto === 'https' || fwdProto === 'http') {
      proto = fwdProto;
    }
    const fwdHost = (req.headers['x-forwarded-host'] as string | undefined)?.split(',')[0]?.trim();
    if (fwdHost && /^[A-Za-z0-9._-]+(?::\d{1,5})?$/.test(fwdHost)) {
      authority = fwdHost;
    }
  } else {
    // Reject malformed raw Host headers (`Host: [`) with 400 (H3), while keeping `selfHost` pinned to `canonicalOrigin` (H4)!
    const rawHost = req.headers.host;
    if (typeof rawHost === 'string' && rawHost.trim() !== '') {
      // Test URL constructability on rawHost so syntactically invalid Host headers fail closed as 400 Bad Request
      // without letting untrusted `Host: localhost` mutate `selfHost`.
      void new URL(`http://${rawHost.trim()}/`);
    }
  }

  const rawTarget = req.url ?? '/';
  if (!rawTarget.startsWith('/') && rawTarget !== '*') {
    throw new Error('Malformed request-target');
  }
  const fullUrl = new URL(rawTarget === '*' ? '/' : rawTarget, `${proto}://${authority}`).toString();

  const headers = new Headers();
  for (const [k, v] of Object.entries(req.headers)) {
    const lower = k.toLowerCase();
    // H4: Never trust client-supplied `cf-connecting-ip`, and strip `x-forwarded-*` unless `EDGEFETCH_TRUST_PROXY=1`.
    if (lower === 'cf-connecting-ip') continue;
    if (!trustProxy && lower.startsWith('x-forwarded-')) continue;
    if (Array.isArray(v)) {
      for (const item of v) headers.append(k, item);
    } else if (typeof v === 'string') {
      headers.set(k, v);
    }
  }
  headers.set('cf-connecting-ip', resolveTrustedClientIp(req, trustProxy));

  const hasBody = req.method !== 'GET' && req.method !== 'HEAD';
  return new Request(fullUrl, {
    method: req.method ?? 'GET',
    headers,
    ...(hasBody ? { body: Readable.toWeb(req) as unknown as ReadableStream<Uint8Array>, duplex: 'half' } : {}),
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
  const resolveCanonicalOrigin = (): string => {
    if (mergedEnv.EDGEFETCH_PUBLIC_ORIGIN?.trim()) {
      try {
        return new URL(mergedEnv.EDGEFETCH_PUBLIC_ORIGIN.trim()).origin;
      } catch {
        // fall through to bound origin
      }
    }
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
    let webReq: Request;
    try {
      webReq = incomingToWebRequest(req, resolveCanonicalOrigin(), trustProxy);
    } catch {
      res.statusCode = 400;
      res.setHeader('content-type', 'application/json');
      res.setHeader('connection', 'close');
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
      res.end(JSON.stringify({ error: 'internal_error', message: err instanceof Error ? err.message : String(err) }));
    }
  });

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
        webReq = incomingToWebRequest(req, resolveCanonicalOrigin(), trustProxy);
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
      coordinator.acceptNodeUpgrade({
        wsKey,
        socket,
        head,
        siteId: auth.siteId,
        arch: (req.headers['x-agent-arch'] as string | undefined) ?? null,
        version: (req.headers['x-agent-version'] as string | undefined) ?? null,
        capabilities: (req.headers['x-agent-capabilities'] as string | undefined) ?? null,
        publicIp: pubIp,
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
            server.close(() => {
              coordinator.close();
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
