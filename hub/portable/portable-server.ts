/**
 * Portable Node.js 22.5+ / Docker / Fly.io / Railway / Render Hub entrypoint (`hub/dist/portable-server.mjs`).
 *
 * Runs the complete EdgeFetch Hub (`/admin` Control Center, OAuth 2.1, 11-tool `/mcp`, `.ipynb`/OpenAPI/Defuddle
 * extractors, `node:sqlite` FTS5 search, local `/data/artifacts` object store, `/agent/ws` Go worker fleet, and
 * vendor-agnostic OTLP trace export) with zero Cloudflare account, zero Postgres, and zero Redis!
 */
import { createServer, type IncomingMessage } from 'node:http';
import { join, resolve } from 'node:path';
import { Readable } from 'node:stream';
import { fileURLToPath } from 'node:url';
import { authorizeAgent } from '../src/auth';
import hubWorker from '../src/index';
import { LocalAgentHubCoordinator, NodeFsR2Bucket, NodeSqliteD1Database } from './node-adapters';

const __dirname = fileURLToPath(new URL('.', import.meta.url));

export interface PortableHubOptions {
  port?: number;
  host?: string;
  dataDir?: string;
  migrationsDir?: string;
  envOverrides?: Record<string, string | undefined>;
}

function incomingToWebRequest(req: IncomingMessage, defaultOrigin: string): Request {
  const proto = (req.headers['x-forwarded-proto'] as string | undefined)?.split(',')[0]?.trim() || 'http';
  const host = (req.headers['x-forwarded-host'] as string | undefined)?.split(',')[0]?.trim() || req.headers.host || new URL(defaultOrigin).host;
  const fullUrl = `${proto}://${host}${req.url ?? '/'}`;
  const headers = new Headers();
  for (const [k, v] of Object.entries(req.headers)) {
    if (Array.isArray(v)) {
      for (const item of v) headers.append(k, item);
    } else if (typeof v === 'string') {
      headers.set(k, v);
    }
  }
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
  const migrationsDir = resolve(opts.migrationsDir ?? join(__dirname, '..', 'migrations'));

  const coordinator = new LocalAgentHubCoordinator(join(dataDir, 'hub.sqlite'));
  const metaDb = new NodeSqliteD1Database(join(dataDir, 'meta.sqlite'), [join(migrationsDir, 'meta', '0001_tracking.sql')]);
  const searchDb = new NodeSqliteD1Database(join(dataDir, 'search.sqlite'), [join(migrationsDir, 'search', '0001_fts.sql')]);
  const artifacts = new NodeFsR2Bucket(join(dataDir, 'artifacts'));

  const mergedEnv = { ...process.env, ...(opts.envOverrides ?? {}) };
  const workerEnv: Record<string, unknown> = {
    AGENT_HUB: coordinator.asNamespace(),
    META: metaDb,
    SEARCH: searchDb,
    ARTIFACTS: artifacts,
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
  };

  const defaultOrigin = `http://${host === '0.0.0.0' ? '127.0.0.1' : host}:${port}`;
  const ctx = {
    waitUntil(promise: Promise<unknown>): void {
      promise.catch(() => undefined);
    },
    passThroughOnException(): void {
      // noop
    },
  } as unknown as ExecutionContext;

  const server = createServer(async (req, res) => {
    try {
      const webReq = incomingToWebRequest(req, defaultOrigin);
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
    const pathname = (req.url ?? '/').split('?')[0];
    if (pathname !== '/agent/ws') {
      socket.write('HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n');
      socket.destroy();
      return;
    }
    const webReq = incomingToWebRequest(req, defaultOrigin);
    const auth = authorizeAgent(webReq, workerEnv as { AGENT_TOKEN?: string; AGENT_TOKENS?: string });
    const wsKey = req.headers['sec-websocket-key'];
    if (!auth.ok || typeof wsKey !== 'string' || !wsKey.trim()) {
      socket.write('HTTP/1.1 401 Unauthorized\r\nConnection: close\r\n\r\n');
      socket.destroy();
      return;
    }
    const pubIp =
      (req.headers['cf-connecting-ip'] as string | undefined) ??
      (req.headers['x-forwarded-for'] as string | undefined)?.split(',')[0]?.trim() ??
      req.socket.remoteAddress ??
      null;
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
  });

  return new Promise<{ server: typeof server; port: number; close: () => Promise<void> }>((resolveStart, rejectStart) => {
    server.once('error', rejectStart);
    server.listen(port, host, () => {
      const addr = server.address();
      const boundPort = typeof addr === 'object' && addr ? addr.port : port;
      resolveStart({
        server,
        port: boundPort,
        close: () =>
          new Promise<void>((resClose) => {
            server.close(() => {
              coordinator.close();
              metaDb.close();
              searchDb.close();
              resClose();
            });
          }),
      });
    });
  });
}

// Run directly when executed as main CLI script (`node dist/portable-server.mjs`).
if (import.meta.url === `file://${process.argv[1]?.replace(/\\/g, '/')}` || process.argv[1]?.endsWith('portable-server.mjs')) {
  startPortableHub()
    .then(({ port }) => {
      console.info(JSON.stringify({ event: 'portable_hub_listening', port, dataDir: process.env.EDGEFETCH_DATA_DIR ?? './.edgefetch-data' }));
    })
    .catch((err) => {
      console.error(err);
      process.exit(1);
    });
}
