import { createHash, randomBytes } from 'node:crypto';
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { gzipSync } from 'node:zlib';
import { build as esbuildBuild } from 'esbuild';
import { Miniflare, Response as MfResponse, convertV4MiniflareOptions } from 'miniflare';
import { createWorkerdWasmExternalPlugin } from '../../scripts/esbuild-wasm-plugin.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
export const HUB_ROOT = resolve(HERE, '../..');
export const REPO_ROOT = resolve(HUB_ROOT, '..');
export const DEFAULT_HUB_ORIGIN = 'https://hub.example.com';
export const MAX_WASM_INPUT_BYTES = 4 * 1024 * 1024;

let cachedBundleState = null;
let bundleInitPromise = null;
let tempBundleDir = null;

function cleanupTempBundleDir() {
  if (tempBundleDir) {
    try {
      rmSync(tempBundleDir, { recursive: true, force: true });
    } catch {
      // Ignore cleanup errors on exit
    }
    tempBundleDir = null;
  }
}

process.once('exit', cleanupTempBundleDir);

async function ensureWorkerdModules() {
  if (cachedBundleState) {
    return cachedBundleState;
  }
  if (bundleInitPromise) {
    return bundleInitPromise;
  }

  bundleInitPromise = (async () => {
    const envWasm = process.env.EDGEFETCH_WASM_PATH;
    const wasmPath = envWasm ? resolve(envWasm) : join(HUB_ROOT, 'src', 'edgefetch-core.wasm');
    if (!existsSync(wasmPath)) {
      throw new Error(`Missing edgefetch-core.wasm at ${wasmPath}; run node scripts/build-wasm.mjs first.`);
    }

    const compiledManifestsPath = join(REPO_ROOT, 'internal', 'extract', 'manifests', 'compiled.json');
    if (!existsSync(compiledManifestsPath)) {
      throw new Error(`Missing compiled.json at ${compiledManifestsPath}; run node scripts/compile-manifests.mjs first.`);
    }

    let workerCode;
    const envBundle = process.env.EDGEFETCH_WORKERD_BUNDLE;
    if (envBundle) {
      const bundlePath = resolve(envBundle);
      if (!existsSync(bundlePath)) {
        throw new Error(`Missing EDGEFETCH_WORKERD_BUNDLE at ${bundlePath}`);
      }
      workerCode = readFileSync(bundlePath, 'utf8');
    } else {
      tempBundleDir = mkdtempSync(join(tmpdir(), 'edgefetch-e2e-exp-'));
      const outfile = join(tempBundleDir, 'workerd-index.mjs');
      await esbuildBuild({
        entryPoints: [join(HUB_ROOT, 'src', 'index.ts')],
        bundle: true,
        platform: 'neutral',
        mainFields: ['module', 'main'],
        conditions: ['workerd', 'worker', 'browser'],
        format: 'esm',
        loader: { '.sql': 'text', '.yaml': 'text', '.yml': 'text' },
        plugins: [createWorkerdWasmExternalPlugin()],
        external: ['cloudflare:workers', 'node:*'],
        outfile,
      });
      workerCode = readFileSync(outfile, 'utf8');
      cleanupTempBundleDir();
    }

    const wasmBytes = readFileSync(wasmPath);
    cachedBundleState = {
      workerCode,
      wasmBytes,
    };
    return cachedBundleState;
  })();

  try {
    return await bundleInitPromise;
  } catch (err) {
    bundleInitPromise = null;
    throw err;
  }
}

function splitMigrationStatements(sql) {
  return sql
    .replace(/\r\n/g, '\n')
    .split(/\n\s*\n/)
    .map((s) => s.trim())
    .filter(Boolean);
}

async function applySqlDir(db, dirPath) {
  if (!existsSync(dirPath)) return;
  const files = readdirSync(dirPath)
    .filter((f) => f.endsWith('.sql'))
    .sort();
  for (const file of files) {
    const sql = readFileSync(join(dirPath, file), 'utf8');
    const stmts = splitMigrationStatements(sql);
    for (const stmt of stmts) {
      await db.prepare(stmt).run();
    }
  }
}

export async function applyD1Migrations(mf) {
  const metaDb = await mf.getD1Database('META');
  const searchDb = await mf.getD1Database('SEARCH');
  await applySqlDir(metaDb, join(HUB_ROOT, 'migrations', 'meta'));
  await applySqlDir(searchDb, join(HUB_ROOT, 'migrations', 'search'));
}

function normalizeHeadersRecord(headers) {
  const out = {};
  if (!headers) return out;
  if (typeof headers.forEach === 'function') {
    headers.forEach((value, key) => {
      out[String(key).toLowerCase()] = String(value);
    });
    return out;
  }
  for (const [k, v] of Object.entries(headers)) {
    out[String(k).toLowerCase()] = String(v);
  }
  return out;
}

function toMfResponse(resLike) {
  if (resLike instanceof MfResponse) {
    return resLike;
  }
  if (resLike && typeof resLike === 'object' && 'status' in resLike && 'body' in resLike) {
    const status = resLike.status ?? 200;
    const headers = resLike.headers ?? {};
    const body = status === 204 || status === 301 || status === 302 || status === 303 || status === 307 || status === 308
      ? null
      : resLike.body;
    return new MfResponse(body, { status, headers });
  }
  return new MfResponse(String(resLike ?? ''), { status: 200 });
}

function matchesRoute(matcher, urlObj, req) {
  const method = (req.method || 'GET').toUpperCase();
  if (typeof matcher === 'string') {
    if (matcher.includes('?')) {
      return req.url === matcher;
    }
    return `${urlObj.origin}${urlObj.pathname}` === matcher || req.url === matcher;
  }
  if (matcher instanceof RegExp) {
    return matcher.test(req.url);
  }
  if (typeof matcher === 'function') {
    return Boolean(matcher(urlObj, req));
  }
  if (matcher && typeof matcher === 'object') {
    if (matcher.method && matcher.method.toUpperCase() !== method) return false;
    if (matcher.host && urlObj.hostname.toLowerCase() !== matcher.host.toLowerCase()) return false;
    if (matcher.pathname !== undefined && urlObj.pathname !== matcher.pathname) return false;
    if (matcher.path !== undefined && `${urlObj.pathname}${urlObj.search}` !== matcher.path) return false;
    if (matcher.search !== undefined && urlObj.search !== matcher.search) return false;
    if (matcher.prefix && !urlObj.pathname.startsWith(matcher.prefix) && !req.url.startsWith(matcher.prefix)) return false;
    if (typeof matcher.match === 'function' && !matcher.match(urlObj, req)) return false;
    return true;
  }
  return false;
}

export function createOutboundRouter(options = {}) {
  const defaultRobotsBody = options.defaultRobots ?? 'User-agent: *\nAllow: /\n';
  const requestLog = [];
  const routes = [];
  const robotsByHost = new Map();
  const llmsByHost = new Map();

  function addRoute(matcher, handler) {
    routes.push({ matcher, handler });
    return router;
  }

  const router = {
    requestLog,

    setRobots(host, body, status = 200, headers = {}) {
      robotsByHost.set(host.toLowerCase(), {
        status,
        body,
        headers: { 'content-type': 'text/plain; charset=utf-8', ...headers },
      });
      return router;
    },

    setLlmsTxt(host, body, status = 200, headers = {}) {
      llmsByHost.set(host.toLowerCase(), {
        status,
        body,
        headers: { 'content-type': 'text/plain; charset=utf-8', ...headers },
      });
      return router;
    },

    route(matcher, handler) {
      return addRoute(matcher, handler);
    },

    html(matcher, body, init = {}) {
      return addRoute(matcher, () =>
        new MfResponse(body, {
          status: init.status ?? 200,
          headers: { 'content-type': 'text/html; charset=utf-8', ...(init.headers ?? {}) },
        }),
      );
    },

    json(matcher, data, init = {}) {
      const payload = typeof data === 'string' ? data : JSON.stringify(data);
      return addRoute(matcher, () =>
        new MfResponse(payload, {
          status: init.status ?? 200,
          headers: { 'content-type': 'application/json; charset=utf-8', ...(init.headers ?? {}) },
        }),
      );
    },

    xml(matcher, body, init = {}) {
      return addRoute(matcher, () =>
        new MfResponse(body, {
          status: init.status ?? 200,
          headers: { 'content-type': 'application/xml; charset=utf-8', ...(init.headers ?? {}) },
        }),
      );
    },

    text(matcher, body, init = {}) {
      return addRoute(matcher, () =>
        new MfResponse(body, {
          status: init.status ?? 200,
          headers: { 'content-type': 'text/plain; charset=utf-8', ...(init.headers ?? {}) },
        }),
      );
    },

    binary(matcher, bytes, contentType = 'application/pdf', init = {}) {
      return addRoute(matcher, () =>
        new MfResponse(bytes, {
          status: init.status ?? 200,
          headers: { 'content-type': contentType, ...(init.headers ?? {}) },
        }),
      );
    },

    redirect(matcher, location, status = 302, extraHeaders = {}) {
      return addRoute(matcher, () =>
        new MfResponse(null, {
          status,
          headers: { location, ...extraHeaders },
        }),
      );
    },

    status(matcher, statusCode, body = '', headers = {}) {
      return addRoute(matcher, () =>
        new MfResponse(statusCode === 204 ? null : body, {
          status: statusCode,
          headers,
        }),
      );
    },

    clearLog() {
      requestLog.length = 0;
    },

    countRequests(host, prefix) {
      const hostLower = host.toLowerCase();
      let count = 0;
      for (const entry of requestLog) {
        if (entry.host !== hostLower) continue;
        if (prefix === undefined) {
          count++;
        } else if (
          entry.pathname.startsWith(prefix) ||
          `${entry.pathname}${entry.search}`.startsWith(prefix) ||
          entry.url.startsWith(prefix)
        ) {
          count++;
        }
      }
      return count;
    },

    async handle(req) {
      const urlObj = new URL(req.url);
      const host = urlObj.hostname.toLowerCase();
      const method = (req.method || 'GET').toUpperCase();
      const headers = normalizeHeadersRecord(req.headers);

      requestLog.push({
        url: req.url,
        method,
        headers,
        host,
        pathname: urlObj.pathname,
        search: urlObj.search,
        timestamp: Date.now(),
      });

      // Check explicit routes in reverse order so later overrides win.
      for (let i = routes.length - 1; i >= 0; i--) {
        const entry = routes[i];
        if (matchesRoute(entry.matcher, urlObj, req)) {
          const res = typeof entry.handler === 'function' ? await entry.handler(urlObj, req, MfResponse) : entry.handler;
          return toMfResponse(res);
        }
      }

      if (urlObj.pathname === '/robots.txt') {
        const override = robotsByHost.get(host);
        if (override) {
          return new MfResponse(override.body, { status: override.status, headers: override.headers });
        }
        return new MfResponse(defaultRobotsBody, {
          status: 200,
          headers: { 'content-type': 'text/plain; charset=utf-8' },
        });
      }

      if (urlObj.pathname === '/llms.txt') {
        const override = llmsByHost.get(host);
        if (override) {
          return new MfResponse(override.body, { status: override.status, headers: override.headers });
        }
        return new MfResponse('not found', {
          status: 404,
          headers: { 'content-type': 'text/plain; charset=utf-8' },
        });
      }

      return new MfResponse(`Not Found: ${req.url}`, {
        status: 404,
        headers: { 'content-type': 'text/plain; charset=utf-8' },
      });
    },
  };

  return router;
}

async function parseDispatchResponse(res) {
  const text = await res.text();
  let body = text;
  try {
    body = text ? JSON.parse(text) : null;
  } catch {
    body = text;
  }
  return {
    status: res.status,
    headers: normalizeHeadersRecord(res.headers),
    body,
    rawText: text,
  };
}

export async function connectMockAgent(mf, options = {}) {
  const origin = options.origin ?? DEFAULT_HUB_ORIGIN;
  const site = options.site ?? 'site-1';
  const agentToken = options.agentToken;
  if (!agentToken) {
    throw new Error('connectMockAgent requires options.agentToken');
  }
  const capabilities = options.capabilities ?? 'artifacts-v1,browser-v1,pdf-v1';

  const res = await mf.dispatchFetch(`${origin}/agent/ws`, {
    headers: {
      upgrade: 'websocket',
      authorization: `Bearer ${agentToken}`,
      'x-agent-site': site,
      'x-agent-arch': options.arch ?? 'amd64',
      'x-agent-version': options.version ?? '1.1.0',
      'x-agent-capabilities': capabilities,
    },
  });
  if (res.status !== 101 || !res.webSocket) {
    throw new Error(`Failed to connect mock agent WebSocket: status=${res.status}`);
  }
  const ws = res.webSocket;
  ws.accept();

  const frames = [];
  let closed = false;

  const sha256Hex = (buf) => createHash('sha256').update(buf).digest('hex');

  ws.addEventListener('message', async (event) => {
    const raw = String(event.data);
    if (!raw.includes('"dispatch"')) return;
    const msg = JSON.parse(raw);
    const parsedCall = typeof msg.call === 'string' ? JSON.parse(msg.call) : (msg.call ?? {});
    frames.push({ msg, call: parsedCall, rawBytes: Buffer.byteLength(raw) });

    if (typeof options.onDispatch === 'function') {
      const helpers = {
        call: parsedCall,
        async uploadArtifact(rawData, artOpts = {}) {
          const rawBuf = typeof rawData === 'string' ? Buffer.from(rawData, 'utf8') : Buffer.from(rawData);
          const gz = gzipSync(rawBuf);
          const blobSha256 = sha256Hex(gz);
          const contentSha256 = sha256Hex(rawBuf);
          const retention = artOpts.retention ?? msg.artifacts?.retention ?? 'transient';
          const requestId = artOpts.requestId ?? parsedCall.requests?.[0]?.id ?? 'scrape-1';
          const upRes = await mf.dispatchFetch(`${origin}/agent/artifacts/${blobSha256}`, {
            method: 'PUT',
            headers: {
              authorization: `Bearer ${agentToken}`,
              'x-agent-site': site,
              'x-job-id': msg.jobId,
              'x-job-nonce': msg.jobNonce,
              'x-request-id': requestId,
              'x-content-sha256': contentSha256,
              'x-content-bytes': String(rawBuf.byteLength),
              'x-artifact-retention': retention,
              'content-type': 'application/gzip',
              'content-length': String(gz.byteLength),
            },
            body: gz,
          });
          if (upRes.status !== 200) {
            throw new Error(`Mock agent artifact upload failed: ${upRes.status} ${await upRes.text()}`);
          }
          return {
            blobSha256,
            contentSha256,
            contentBytes: rawBuf.byteLength,
            storedBytes: gz.byteLength,
            encoding: 'gzip',
            retention,
          };
        },
        async sendReply(replyPayload, replyOpts = {}) {
          const jsonStr = typeof replyPayload === 'string' ? replyPayload : JSON.stringify(replyPayload);
          const body = replyOpts.gzip ? gzipSync(jsonStr) : jsonStr;
          const headers = {
            authorization: `Bearer ${agentToken}`,
            'x-agent-site': site,
            'x-job-id': msg.jobId,
            'x-job-nonce': msg.jobNonce,
            'content-type': 'application/json',
            ...(replyOpts.gzip ? { 'content-encoding': 'gzip' } : {}),
            ...(replyOpts.headers ?? {}),
          };
          return await mf.dispatchFetch(`${origin}/agent/reply`, {
            method: 'POST',
            headers,
            body,
          });
        },
      };
      await options.onDispatch(msg, helpers);
    }
  });

  ws.addEventListener('close', () => {
    closed = true;
  });

  return {
    ws,
    frames,
    close(code = 1000, reason = 'done') {
      if (!closed) {
        closed = true;
        try {
          ws.close(code, reason);
        } catch {
          // Ignore close error if already closing/closed
        }
      }
    },
  };
}

let hubCounter = 0;

export async function createHubInstance(options = {}) {
  const router = options.router ?? createOutboundRouter();
  const withMigrations = options.withMigrations !== false;
  const callerToken = options.callerToken ?? randomBytes(24).toString('hex');
  const agentToken = options.agentToken ?? randomBytes(24).toString('hex');
  const origin = options.origin ?? DEFAULT_HUB_ORIGIN;

  const { workerCode, wasmBytes } = await ensureWorkerdModules();
  const workerName = options.name ?? `edgefetch-e2e-${++hubCounter}`;

  const mf = new Miniflare(
    convertV4MiniflareOptions({
      workers: [
        {
          name: workerName,
          modules: [
            { type: 'ESModule', path: 'entry.mjs', contents: workerCode },
            { type: 'CompiledWasm', path: 'edgefetch-core.wasm', contents: wasmBytes },
          ],
          compatibilityDate: '2026-10-01',
          durableObjects: {
            AGENT_HUB: { className: 'AgentHubDO', useSQLite: true },
          },
          r2Buckets: ['ARTIFACTS'],
          d1Databases: ['META', 'SEARCH'],
          bindings: {
            CALLER_TOKEN: callerToken,
            AGENT_TOKENS: JSON.stringify({ 'site-1': agentToken }),
            EDGEFETCH_DISABLE_UPDATE_CHECK: '1',
            ...(options.bindings ?? {}),
          },
          outboundService: (req) => router.handle(req),
        },
      ],
    }),
  );

  let disposed = false;
  const connectedAgents = [];

  try {
    if (withMigrations) {
      await applyD1Migrations(mf);
    }

    const authHeaders = (extra = {}) => ({
      authorization: `Bearer ${callerToken}`,
      'content-type': 'application/json',
      ...extra,
    });

    const dispatch = async (path, init = {}) => {
      return mf.dispatchFetch(`${origin}${path}`, { redirect: 'manual', ...init });
    };

    const postJson = async (path, payload, opts = {}) => {
      const res = await dispatch(path, {
        method: 'POST',
        headers: authHeaders(opts.headers),
        body: JSON.stringify(payload),
      });
      return parseDispatchResponse(res);
    };

    return {
      mf,
      callerToken,
      agentToken,
      origin,
      router,
      requestLog: router.requestLog,
      fetch: dispatch,
      scrape: (payload, opts) => postJson('/v1/scrape', payload, opts),
      extract: (payload, opts) => postJson('/v1/extract', payload, opts),
      jobs: (payload, opts) => postJson('/v1/jobs', payload, opts),
      crawl: (payload, opts) => postJson('/v1/crawl', payload, opts),
      getCrawl: async (id, opts = {}) => {
        const res = await dispatch(`/v1/crawl/${encodeURIComponent(id)}`, {
          method: 'GET',
          headers: authHeaders(opts.headers),
        });
        return parseDispatchResponse(res);
      },
      extractors: async (category, opts = {}) => {
        const qs = category ? `?category=${encodeURIComponent(category)}` : '';
        const res = await dispatch(`/v1/extractors${qs}`, {
          method: 'GET',
          headers: authHeaders(opts.headers),
        });
        return parseDispatchResponse(res);
      },
      connectMockAgent: async (agentOpts = {}) => {
        const agent = await connectMockAgent(mf, {
          origin,
          agentToken,
          ...agentOpts,
        });
        connectedAgents.push(agent);
        return agent;
      },
      dispose: async () => {
        if (disposed) return;
        disposed = true;
        for (const agent of connectedAgents) {
          agent.close();
        }
        await mf.dispose();
      },
    };
  } catch (err) {
    if (!disposed) {
      disposed = true;
      await mf.dispose().catch(() => undefined);
    }
    throw err;
  }
}

export async function withFreshHub(options, fn) {
  if (typeof options === 'function') {
    fn = options;
    options = {};
  }
  const hub = await createHubInstance(options);
  try {
    return await fn(hub);
  } finally {
    await hub.dispose();
  }
}
