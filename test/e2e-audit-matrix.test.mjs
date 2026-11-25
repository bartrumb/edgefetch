/**
 * EdgeFetch OpenTelemetry, E2E & Audit Matrix (Milestone F19)
 *
 * Opaque-box, requirement-driven 4-tier E2E test suite covering:
 *  - Tier 1 (30 tests): Feature Coverage across Areas A-E (`T1-A1..T1-E5`)
 *  - Tier 2 (29 tests): Boundary & Corner Cases across Areas A-E (`T2-A1..T2-E5`)
 *  - Tier 3 (12 tests): Cross-Feature Pairwise Combinations (`T3-1..T3-12`)
 *  - Tier 4 (5 tests):  Real-World Multi-Feature Application Scenarios (`T4-1..T4-5`)
 *  Total: 76 tests.
 *
 * Strictly zero external dependencies: uses Node 22+ built-ins + in-repo
 * `hub/dist/portable-server.mjs`, `sdk/ts/edgefetch-client.ts`,
 * `sdk/py/edgefetch_client.py`,
 * `scripts/all-in-one-entrypoint.sh`, and compiled Go `cmd/edgefetch`.
 */

import test, { after, before, describe } from 'node:test';
import assert from 'node:assert/strict';
import { execFile, execFileSync, spawn } from 'node:child_process';
import { createHash, generateKeyPairSync, randomBytes } from 'node:crypto';
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import http from 'node:http';
import { stripTypeScriptTypes } from 'node:module';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { setTimeout as delay } from 'node:timers/promises';
import { promisify } from 'node:util';
import { gunzipSync, gzipSync } from 'node:zlib';

import { startPortableHub } from '../hub/dist/portable-server.mjs';

const execFileAsync = promisify(execFile);
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, '..');

// ---------------------------------------------------------------------------
// 1. W3C Trace Context & OTLP Validators
// ---------------------------------------------------------------------------

const ALL_ZERO_32 = '0'.repeat(32);
const ALL_ZERO_16 = '0'.repeat(16);
const RE_TRACE_ID = /^[0-9a-f]{32}$/;
const RE_SPAN_ID = /^[0-9a-f]{16}$/;
const RE_TRACEPARENT = /^00-([0-9a-f]{32})-([0-9a-f]{16})-(00|01)$/;

function makeTraceIds(flags = '01') {
  const traceId = randomBytes(16).toString('hex');
  const parentSpanId = randomBytes(8).toString('hex');
  return {
    traceId,
    parentSpanId,
    traceparent: `00-${traceId}-${parentSpanId}-${flags}`,
  };
}

function parseTraceparentHeader(raw) {
  if (typeof raw !== 'string') return null;
  const m = RE_TRACEPARENT.exec(raw.trim());
  if (!m) return null;
  if (m[1] === ALL_ZERO_32 || m[2] === ALL_ZERO_16) return null;
  return { traceId: m[1], spanId: m[2], flags: m[3] };
}

function assertTraceHeaders(res, { expectedTraceId, expectedFlags, tag = '[F1/M1]' } = {}) {
  const xTraceId = res.headers.get('x-trace-id');
  const tpRaw = res.headers.get('traceparent');
  assert.ok(
    xTraceId && RE_TRACE_ID.test(xTraceId) && xTraceId !== ALL_ZERO_32,
    `${tag} missing or invalid x-trace-id response header on ${res.url || 'response'} (status ${res.status}): got ${JSON.stringify(xTraceId)}`,
  );
  const parsed = parseTraceparentHeader(tpRaw);
  assert.ok(
    parsed,
    `${tag} missing or invalid traceparent response header (status ${res.status}): got ${JSON.stringify(tpRaw)}`,
  );
  assert.equal(
    xTraceId,
    parsed.traceId,
    `${tag} x-trace-id (${xTraceId}) must equal traceparent traceId (${parsed.traceId})`,
  );
  if (expectedTraceId) {
    assert.equal(
      xTraceId,
      expectedTraceId,
      `${tag} expected traceId ${expectedTraceId}, got ${xTraceId}`,
    );
  }
  if (expectedFlags) {
    assert.equal(
      parsed.flags,
      expectedFlags,
      `${tag} expected traceparent flags ${expectedFlags}, got ${parsed.flags}`,
    );
  }
  return { traceId: xTraceId, spanId: parsed.spanId, flags: parsed.flags, traceparent: tpRaw };
}

function getOtlpAttrValue(attrs, key) {
  if (!Array.isArray(attrs)) return undefined;
  const entry = attrs.find((a) => a && a.key === key);
  if (!entry || !entry.value || typeof entry.value !== 'object') return undefined;
  if ('stringValue' in entry.value) return entry.value.stringValue;
  if ('boolValue' in entry.value) return entry.value.boolValue;
  if ('intValue' in entry.value) return Number(entry.value.intValue);
  if ('doubleValue' in entry.value) return Number(entry.value.doubleValue);
  if ('arrayValue' in entry.value) return entry.value.arrayValue;
  return undefined;
}

function validateOtlpSpan(span, tag = '[F1/M1]') {
  assert.ok(span && typeof span === 'object', `${tag} span must be an object`);
  assert.ok(
    typeof span.traceId === 'string' && RE_TRACE_ID.test(span.traceId) && span.traceId !== ALL_ZERO_32,
    `${tag} invalid span.traceId: ${JSON.stringify(span.traceId)}`,
  );
  assert.ok(
    typeof span.spanId === 'string' && RE_SPAN_ID.test(span.spanId) && span.spanId !== ALL_ZERO_16,
    `${tag} invalid span.spanId: ${JSON.stringify(span.spanId)}`,
  );
  if (span.parentSpanId !== undefined && span.parentSpanId !== '') {
    assert.ok(
      typeof span.parentSpanId === 'string' && RE_SPAN_ID.test(span.parentSpanId) && span.parentSpanId !== ALL_ZERO_16,
      `${tag} invalid span.parentSpanId: ${JSON.stringify(span.parentSpanId)}`,
    );
  }
  assert.ok(typeof span.name === 'string' && span.name.length > 0, `${tag} span.name empty`);
  const start = BigInt(span.startTimeUnixNano);
  const end = BigInt(span.endTimeUnixNano);
  assert.ok(start > 0n, `${tag} startTimeUnixNano must be > 0`);
  assert.ok(end >= start, `${tag} endTimeUnixNano (${end}) < startTimeUnixNano (${start})`);
}

function assertNoLeakedSecrets(entries, secrets = [], tag = '[F1/M1]') {
  const serialized = JSON.stringify(entries);
  for (const s of secrets) {
    if (!s || s.length < 4) continue;
    assert.equal(
      serialized.includes(s),
      false,
      `${tag} secret leaked into OTLP spans! Matched prefix "${s.slice(0, 4)}..."`,
    );
  }
  for (const entry of entries) {
    const span = entry.span ?? entry;
    const urlFull = getOtlpAttrValue(span.attributes, 'url.full') ?? getOtlpAttrValue(span.attributes, 'http.url');
    if (typeof urlFull === 'string') {
      assert.equal(urlFull.includes('?'), false, `${tag} url.full leaked query string: ${urlFull}`);
      assert.equal(/@/.test(urlFull.replace(/^https?:\/\//, '').split('/')[0] || ''), false, `${tag} url.full leaked credentials: ${urlFull}`);
    }
  }
}

// ---------------------------------------------------------------------------
// 2. Network, Collector, Origin, & Token Helpers
// ---------------------------------------------------------------------------

async function allocPort() {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.unref();
    srv.on('error', reject);
    srv.listen(0, '127.0.0.1', () => {
      const addr = srv.address();
      const port = typeof addr === 'object' && addr ? addr.port : 0;
      srv.close((err) => (err ? reject(err) : resolve(port)));
    });
  });
}

function makeTokens() {
  return {
    callerToken: `ef_caller_${randomBytes(18).toString('hex')}`,
    mcpToken: `ef_mcp_${randomBytes(18).toString('hex')}`,
    agentToken: `ef_agent_${randomBytes(18).toString('hex')}`,
  };
}

function generateEd25519Keypair() {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const privJwk = privateKey.export({ format: 'jwk' });
  const pubJwk = publicKey.export({ format: 'jwk' });
  return {
    privateKeySeed: privJwk.d,
    publicKeyB64Url: pubJwk.x,
  };
}

async function startMockOtlpCollector() {
  const requests = [];
  const entries = [];
  let statusOverride = 200;

  const server = http.createServer((req, res) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      let raw = Buffer.concat(chunks);
      if ((req.headers['content-encoding'] || '').toLowerCase().includes('gzip')) {
        try {
          raw = gunzipSync(raw);
        } catch {
          // leave raw
        }
      }
      const text = raw.toString('utf8');
      let payload = null;
      try {
        payload = text ? JSON.parse(text) : null;
      } catch {
        payload = { raw: text };
      }
      requests.push({
        method: req.method,
        url: req.url,
        headers: { ...req.headers },
        payload,
      });

      if (statusOverride !== 200) {
        res.writeHead(statusOverride, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ error: 'collector_forced_error' }));
        return;
      }

      if (payload && Array.isArray(payload.resourceSpans)) {
        for (const rs of payload.resourceSpans) {
          const resourceAttrs = rs?.resource?.attributes ?? [];
          const serviceName = getOtlpAttrValue(resourceAttrs, 'service.name') ?? '';
          for (const ss of rs?.scopeSpans ?? []) {
            const scopeName = ss?.scope?.name ?? '';
            for (const span of ss?.spans ?? []) {
              entries.push({
                serviceName,
                resourceAttributes: resourceAttrs,
                scopeName,
                span,
              });
            }
          }
        }
      }
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ partialSuccess: {} }));
    });
  });

  await new Promise((resolve, reject) => {
    server.on('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  const addr = server.address();
  const port = addr.port;
  const endpoint = `http://127.0.0.1:${port}`;

  return {
    port,
    endpoint,
    tracesUrl: `${endpoint}/v1/traces`,
    requests,
    entries,
    setStatus(code) {
      statusOverride = code;
    },
    clear() {
      requests.length = 0;
      entries.length = 0;
    },
    findByTraceId(traceId) {
      return entries.filter((e) => e.span?.traceId === traceId);
    },
    async waitForSpans(predicate, timeoutMs = 4500, pollMs = 50) {
      const deadline = Date.now() + timeoutMs;
      while (Date.now() < deadline) {
        if (predicate(entries, requests)) {
          return entries;
        }
        await delay(pollMs);
      }
      return entries;
    },
    async close() {
      await new Promise((resolve) => server.close(() => resolve()));
    },
  };
}

async function startHttpServer(handler) {
  const server = http.createServer(handler);
  await new Promise((resolve, reject) => {
    server.on('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  const addr = server.address();
  const port = addr.port;
  return {
    port,
    url: `http://127.0.0.1:${port}`,
    close: () => new Promise((resolve) => server.close(() => resolve())),
  };
}

async function startMockOrigin(customHandler) {
  const recorded = [];
  const srv = await startHttpServer((req, res) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', async () => {
      const bodyText = Buffer.concat(chunks).toString('utf8');
      recorded.push({
        method: req.method,
        url: req.url,
        headers: { ...req.headers },
        bodyText,
      });
      if (customHandler) {
        await customHandler(req, res, bodyText, recorded);
        return;
      }
      if (req.url === '/robots.txt') {
        res.writeHead(200, { 'content-type': 'text/plain' });
        res.end('User-agent: *\nAllow: /\n');
        return;
      }
      if (req.url === '/402') {
        res.writeHead(402, {
          'content-type': 'application/json',
          'payment-required': 'x402-v1; amount=100; currency=USD',
        });
        res.end(JSON.stringify({ error: 'payment_required' }));
        return;
      }
      if (req.url === '/spa') {
        res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
        res.end(
          '<!doctype html><html><head><title>SPA Mock</title></head><body><div id="root"></div><script>document.getElementById("root").innerHTML="<main><h1>Hydrated SPA Heading</h1><p>Browser rendered DOM content.</p></main>";</script></body></html>',
        );
        return;
      }
      res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
      res.end(
        '<!doctype html><html><head><title>Mock Origin</title></head><body><main><h1>Mock Origin Title</h1><p>Verified local origin content.</p></main></body></html>',
      );
    });
  });
  return {
    ...srv,
    recorded,
    clearRecorded() {
      recorded.length = 0;
    },
  };
}

// ---------------------------------------------------------------------------
// 3. Portable Hub + Mock WebSocket Agent Harness
// ---------------------------------------------------------------------------

async function startTestHub(envOverrides = {}, suiteDataParent) {
  const tokens = makeTokens();
  const dataDir = mkdtempSync(path.join(suiteDataParent || os.tmpdir(), 'ef-hub-'));
  const merged = {
    CALLER_TOKEN: tokens.callerToken,
    MCP_TOKEN: tokens.mcpToken,
    AGENT_TOKEN: tokens.agentToken,
    ...envOverrides,
  };
  const hub = await startPortableHub({
    port: 0,
    host: '127.0.0.1',
    dataDir,
    envOverrides: merged,
  });
  const baseUrl = `http://127.0.0.1:${hub.port}`;
  return {
    ...tokens,
    port: hub.port,
    baseUrl,
    dataDir,
    async close() {
      await hub.close();
      try {
        rmSync(dataDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 });
      } catch {
        // ignore transient Windows SQLite lock
      }
    },
  };
}

async function connectMockAgent({
  port,
  agentToken,
  siteId = 'mock-site-1',
  capabilities = ['artifacts-v1', 'browser-v1'],
  handler,
}) {
  const wsUrl = `ws://127.0.0.1:${port}/agent/ws?site=${encodeURIComponent(siteId)}`;
  const subprotocols = ['edgefetch-agent', `edgefetch-v1.${Buffer.from(agentToken).toString('base64url')}`];
  const ws = new globalThis.WebSocket(wsUrl, subprotocols);
  const dispatches = [];
  const baseUrl = `http://127.0.0.1:${port}`;
  let helloReceived = false;

  await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`Mock WS agent hello timeout for ${siteId}`)), 5000);
    ws.addEventListener('error', (ev) => {
      clearTimeout(timer);
      reject(new Error(`Mock WS error: ${ev?.message || 'unknown'}`));
    });
    ws.addEventListener('open', () => {
      ws.send(
        JSON.stringify({
          type: 'agent_hello',
          version: '2.7.0',
          arch: 'amd64',
          goVersion: 'go1.27.4',
          capabilities,
        }),
      );
    });
    ws.addEventListener('message', async (ev) => {
      const msg = JSON.parse(String(ev.data));
      if (msg.type === 'hello') {
        if (!helloReceived) {
          helloReceived = true;
          clearTimeout(timer);
          resolve();
        }
        return;
      }
      if (msg.type !== 'dispatch') return;
      dispatches.push(msg);

      try {
        const reqList = Array.isArray(msg.call?.requests) ? msg.call.requests : [];
        const results = [];
        for (const reqItem of reqList) {
          let customResult = null;
          if (handler) {
            customResult = await handler(reqItem, msg, {
              uploadArtifact: async (rawBytes, retention = 'transient') => {
                const buf = Buffer.isBuffer(rawBytes) ? rawBytes : Buffer.from(String(rawBytes), 'utf8');
                const gz = gzipSync(buf);
                const contentSha256 = createHash('sha256').update(buf).digest('hex');
                const blobSha256 = createHash('sha256').update(gz).digest('hex');
                const upRes = await fetch(`${baseUrl}/agent/artifacts/${blobSha256}`, {
                  method: 'PUT',
                  headers: {
                    authorization: `Bearer ${agentToken}`,
                    'x-agent-site': siteId,
                    'x-job-id': msg.jobId,
                    'x-job-nonce': msg.jobNonce,
                    'x-request-id': reqItem.id,
                    'x-content-sha256': contentSha256,
                    'x-content-bytes': String(buf.byteLength),
                    'x-artifact-retention': retention,
                    'content-type': 'application/gzip',
                    'content-length': String(gz.byteLength),
                  },
                  body: gz,
                });
                assert.equal(upRes.status, 200, `artifact upload failed with ${upRes.status}`);
                return {
                  blobSha256,
                  contentSha256,
                  contentBytes: buf.byteLength,
                  storedBytes: gz.byteLength,
                  encoding: 'gzip',
                  retention,
                };
              },
            });
          }
          if (customResult) {
            results.push({ id: reqItem.id, url: reqItem.url, kind: reqItem.kind || 'scrape', ...customResult });
          } else {
            results.push(defaultMockAgentResult(reqItem));
          }
        }

        const replyRes = await fetch(`${baseUrl}/agent/reply`, {
          method: 'POST',
          headers: {
            authorization: `Bearer ${agentToken}`,
            'x-agent-site': siteId,
            'x-job-id': msg.jobId,
            'x-job-nonce': msg.jobNonce,
            'content-type': 'application/json',
          },
          body: JSON.stringify({ results }),
        });
        if (!replyRes.ok) {
          // ignore if test closed early
        }
      } catch {
        // ignore closed test
      }
    });
  });

  return {
    ws,
    dispatches,
    async close() {
      if (ws.readyState === globalThis.WebSocket.OPEN || ws.readyState === globalThis.WebSocket.CONNECTING) {
        await new Promise((resolve) => {
          const t = setTimeout(resolve, 1000);
          ws.addEventListener('close', () => {
            clearTimeout(t);
            resolve();
          }, { once: true });
          ws.close(1000, 'test_done');
        });
      }
    },
  };
}

function encodeWsClientTextFrame(text) {
  const payload = Buffer.from(text, 'utf8');
  const mask = randomBytes(4);
  let header;
  if (payload.length < 126) {
    header = Buffer.alloc(2);
    header[0] = 0x81;
    header[1] = 0x80 | payload.length;
  } else if (payload.length < 65536) {
    header = Buffer.alloc(4);
    header[0] = 0x81;
    header[1] = 0x80 | 126;
    header.writeUInt16BE(payload.length, 2);
  } else {
    header = Buffer.alloc(10);
    header[0] = 0x81;
    header[1] = 0x80 | 127;
    header.writeBigUInt64BE(BigInt(payload.length), 2);
  }
  const masked = Buffer.alloc(payload.length);
  for (let i = 0; i < payload.length; i++) {
    masked[i] = payload[i] ^ mask[i & 3];
  }
  return Buffer.concat([header, mask, masked]);
}

async function connectHeaderMockAgent({
  port,
  agentToken,
  siteId = 'go-hub-mock-1',
  capabilities = ['artifacts-v1', 'browser-v1'],
  handler,
}) {
  const baseUrl = `http://127.0.0.1:${port}`;
  const dispatches = [];
  const wsKey = randomBytes(16).toString('base64');
  let socketRef = null;

  await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`Header WS agent hello timeout for ${siteId}`)), 5000);
    const req = http.request({
      host: '127.0.0.1',
      port,
      path: '/agent/ws',
      method: 'GET',
      headers: {
        Connection: 'Upgrade',
        Upgrade: 'websocket',
        'Sec-WebSocket-Key': wsKey,
        'Sec-WebSocket-Version': '13',
        Authorization: `Bearer ${agentToken}`,
        'X-Agent-Site': siteId,
        'X-Agent-Capabilities': capabilities.join(','),
        'X-Agent-Arch': 'amd64',
        'X-Agent-Version': '2.7.0',
      },
    });
    req.on('error', (err) => {
      clearTimeout(timer);
      reject(err);
    });
    req.on('response', (res) => {
      clearTimeout(timer);
      reject(new Error(`Go Hub /agent/ws rejected upgrade with HTTP ${res.statusCode}`));
    });
    req.on('upgrade', (_res, socket, head) => {
      socketRef = socket;
      let buf = head && head.length ? Buffer.from(head) : Buffer.alloc(0);
      let helloDone = false;

      socket.write(
        encodeWsClientTextFrame(
          JSON.stringify({
            type: 'agent_hello',
            version: '2.7.0',
            arch: 'amd64',
            goVersion: 'go1.27.4',
            capabilities,
          }),
        ),
      );

      const handleText = async (text) => {
        const msg = JSON.parse(text);
        if (msg.type === 'hello') {
          if (!helloDone) {
            helloDone = true;
            clearTimeout(timer);
            resolve();
          }
          return;
        }
        if (msg.type !== 'dispatch') return;
        dispatches.push(msg);
        try {
          const reqList = Array.isArray(msg.call?.requests) ? msg.call.requests : [];
          const results = [];
          for (const reqItem of reqList) {
            const custom = handler ? await handler(reqItem, msg) : null;
            results.push(custom ? { id: reqItem.id, url: reqItem.url, kind: reqItem.kind || 'scrape', ...custom } : defaultMockAgentResult(reqItem));
          }
          await fetch(`${baseUrl}/agent/reply`, {
            method: 'POST',
            headers: {
              authorization: `Bearer ${agentToken}`,
              'x-agent-site': siteId,
              'x-job-id': msg.jobId,
              'x-job-nonce': msg.jobNonce,
              'content-type': 'application/json',
            },
            body: JSON.stringify({ results }),
          });
        } catch {
          // ignore closed
        }
      };

      const drainFrames = () => {
        while (buf.length >= 2) {
          const b0 = buf[0];
          const b1 = buf[1];
          const opcode = b0 & 0x0f;
          const isMasked = (b1 & 0x80) !== 0;
          let len = b1 & 0x7f;
          let off = 2;
          if (len === 126) {
            if (buf.length < 4) return;
            len = buf.readUInt16BE(2);
            off = 4;
          } else if (len === 127) {
            if (buf.length < 10) return;
            len = Number(buf.readBigUInt64BE(2));
            off = 10;
          }
          const maskLen = isMasked ? 4 : 0;
          if (buf.length < off + maskLen + len) return;
          let payload = buf.subarray(off + maskLen, off + maskLen + len);
          if (isMasked) {
            const maskKey = buf.subarray(off, off + 4);
            const unmasked = Buffer.alloc(len);
            for (let i = 0; i < len; i++) unmasked[i] = payload[i] ^ maskKey[i & 3];
            payload = unmasked;
          }
          buf = buf.subarray(off + maskLen + len);
          if (opcode === 0x1) {
            void handleText(payload.toString('utf8'));
          } else if (opcode === 0x8) {
            socket.end();
          }
        }
      };

      socket.on('data', (chunk) => {
        buf = Buffer.concat([buf, chunk]);
        drainFrames();
      });
      drainFrames();
    });
    req.end();
  });

  return {
    dispatches,
    async close() {
      if (socketRef && !socketRef.destroyed) {
        socketRef.destroy();
      }
    },
  };
}

async function postRawExpectStatus(targetUrl, headers, bodyText, declaredContentLength) {
  const u = new URL(targetUrl);
  const bodyBuf = Buffer.from(bodyText, 'utf8');
  const contentLen = declaredContentLength ?? bodyBuf.byteLength;
  const hdrLines = [
    `POST ${u.pathname}${u.search} HTTP/1.1`,
    `Host: ${u.host}`,
    ...Object.entries(headers).map(([k, v]) => `${k}: ${v}`),
    `Content-Length: ${contentLen}`,
    'Connection: close',
    '',
    '',
  ].join('\r\n');

  return new Promise((resolve, reject) => {
    let settled = false;
    const respChunks = [];
    const sock = net.connect({ host: u.hostname, port: Number(u.port) }, () => {
      sock.write(hdrLines);
      if (bodyBuf.byteLength > 0) sock.write(bodyBuf);
    });
    const finish = () => {
      if (settled) return;
      const raw = Buffer.concat(respChunks).toString('utf8');
      const m = /^HTTP\/\d\.\d\s+(\d{3})/i.exec(raw);
      if (m) {
        settled = true;
        resolve({ status: Number(m[1]), headers: {}, body: raw });
        sock.destroy();
      }
    };
    sock.on('data', (chunk) => {
      respChunks.push(chunk);
      finish();
    });
    sock.on('end', () => {
      finish();
      if (!settled) {
        settled = true;
        reject(new Error('Socket ended without HTTP status'));
      }
    });
    sock.on('error', (err) => {
      finish();
      if (!settled) {
        settled = true;
        reject(err);
      }
    });
  });
}

function defaultMockAgentResult(reqItem) {
  const u = String(reqItem.url || '');
  if (u.endsWith('/robots.txt')) {
    return {
      id: reqItem.id,
      url: u,
      kind: reqItem.kind || 'text',
      status: 200,
      outcome: 'ok',
      contentType: 'text/plain',
      body: 'User-agent: *\nAllow: /\n',
      bodyEncoding: 'utf-8',
      durationMs: 4,
    };
  }
  if (u.endsWith('/sitemap.xml') || u.endsWith('/llms.txt')) {
    return {
      id: reqItem.id,
      url: u,
      kind: reqItem.kind || 'text',
      status: 404,
      outcome: 'skip',
      contentType: 'text/plain',
      body: '',
      bodyEncoding: 'utf-8',
      durationMs: 3,
    };
  }
  if (u.includes('registry.npmjs.org/')) {
    return {
      id: reqItem.id,
      url: u,
      kind: reqItem.kind || 'json',
      status: 200,
      outcome: 'ok',
      contentType: 'application/json',
      body: JSON.stringify({
        name: 'esbuild',
        description: 'An extremely fast bundler for the web',
        'dist-tags': { latest: '0.25.0' },
        versions: { '0.25.0': { name: 'esbuild', version: '0.25.0', description: 'Fast JS bundler' } },
      }),
      bodyEncoding: 'utf-8',
      durationMs: 5,
    };
  }
  if (u.includes('crates.io/api/v1/crates/')) {
    return {
      id: reqItem.id,
      url: u,
      kind: reqItem.kind || 'json',
      status: 200,
      outcome: 'ok',
      contentType: 'application/json',
      body: JSON.stringify({
        crate: { id: 'serde', name: 'serde', max_version: '1.0.219', description: 'Serialization framework' },
      }),
      bodyEncoding: 'utf-8',
      durationMs: 5,
    };
  }
  if (u.includes('rubygems.org/api/v1/gems/')) {
    return {
      id: reqItem.id,
      url: u,
      kind: reqItem.kind || 'json',
      status: 200,
      outcome: 'ok',
      contentType: 'application/json',
      body: JSON.stringify({ name: 'rails', version: '8.0.1', info: 'Full-stack web framework', authors: 'DHH' }),
      bodyEncoding: 'utf-8',
      durationMs: 5,
    };
  }
  if (u.includes('dev.to/api/articles/')) {
    return {
      id: reqItem.id,
      url: u,
      kind: reqItem.kind || 'json',
      status: 200,
      outcome: 'ok',
      contentType: 'application/json',
      body: JSON.stringify({ title: 'Mock Dev.to Article', body_markdown: '# Mock Dev.to\nArticle body.', user: { name: 'Alice' } }),
      bodyEncoding: 'utf-8',
      durationMs: 5,
    };
  }
  if (u.includes('huggingface.co/') && u.endsWith('/README.md')) {
    return {
      id: reqItem.id,
      url: u,
      kind: reqItem.kind || 'text',
      status: 200,
      outcome: 'ok',
      contentType: 'text/markdown; charset=utf-8',
      body: '---\nlanguage:\n- multilingual\ntags:\n- automatic-speech-recognition\n---\n# openai/whisper-large-v3\n\nMock Hugging Face model card.',
      bodyEncoding: 'utf-8',
      durationMs: 5,
    };
  }
  if (u.includes('huggingface.co/api/models/')) {
    return {
      id: reqItem.id,
      url: u,
      kind: reqItem.kind || 'json',
      status: 200,
      outcome: 'ok',
      contentType: 'application/json',
      body: JSON.stringify({ id: 'openai/whisper-large-v3', downloads: 123456, pipeline_tag: 'automatic-speech-recognition' }),
      bodyEncoding: 'utf-8',
      durationMs: 5,
    };
  }
  if (u.includes('lobste.rs/s/') && u.endsWith('.json')) {
    return {
      id: reqItem.id,
      url: u,
      kind: reqItem.kind || 'json',
      status: 200,
      outcome: 'ok',
      contentType: 'application/json',
      body: JSON.stringify({ short_id: 'abc123', title: 'Mock Lobsters Story', url: 'https://example.org', score: 42, comments: [] }),
      bodyEncoding: 'utf-8',
      durationMs: 5,
    };
  }
  if (u.includes('api.ashbyhq.com/posting-api/job-board/')) {
    return {
      id: reqItem.id,
      url: u,
      kind: reqItem.kind || 'json',
      status: 200,
      outcome: 'ok',
      contentType: 'application/json',
      body: JSON.stringify({
        jobs: [
          {
            id: 'ash-1',
            title: 'Staff Systems Engineer',
            location: 'Remote - US',
            isRemote: true,
            jobUrl: 'https://jobs.ashbyhq.com/linear/ash-1',
            publishedAt: new Date().toISOString(),
            compensation: { compensationTierSummary: '$220,000 - $260,000' },
          },
        ],
      }),
      bodyEncoding: 'utf-8',
      durationMs: 6,
    };
  }
  if (u.includes('/products.json')) {
    const isNextPage = /(?:\?|&)page=(?:[2-9]|\d{2,})/.test(u) || u.includes('page_info=');
    return {
      id: reqItem.id,
      url: u,
      kind: reqItem.kind || 'json',
      status: 200,
      outcome: 'ok',
      contentType: 'application/json',
      body: JSON.stringify({
        products: isNextPage
          ? []
          : [
              {
                id: 1001,
                title: 'EdgeFetch Mechanical Keyboard',
                handle: 'ef-keyboard',
                vendor: 'EdgeFetchCo',
                product_type: 'Hardware',
                variants: [{ id: 2001, title: 'Default', price: '149.00', available: true, sku: 'EF-KB-1' }],
              },
            ],
      }),
      bodyEncoding: 'utf-8',
      durationMs: 6,
    };
  }
  return {
    id: reqItem.id,
    url: u,
    kind: reqItem.kind || 'scrape',
    status: 200,
    outcome: 'ok',
    contentType: 'text/html; charset=utf-8',
    body: `<!doctype html><html><head><title>Mock Page for ${u}</title></head><body><main><h1>Mock Page</h1><p>Content fetched cleanly from ${u} with plenty of informative text for markdown extraction.</p><a href="${u.replace(/\/$/, '')}/about">About</a></main></body></html>`,
    bodyEncoding: 'utf-8',
    durationMs: 8,
    timing: { dnsMs: 1, connectMs: 1, tlsMs: 1, ttfbMs: 3, connReused: true, protocol: 'h2' },
  };
}

// ---------------------------------------------------------------------------
// 4. Go Binary Builder, Process Runners & MCP Stdio Harness
// ---------------------------------------------------------------------------

function toWslPath(winPath) {
  const abs = path.resolve(winPath).replace(/\\/g, '/');
  const m = /^([A-Za-z]):\/(.*)$/.exec(abs);
  if (!m) return abs;
  return `/mnt/${m[1].toLowerCase()}/${m[2]}`;
}

function buildEdgefetchBinary(outDir) {
  if (process.env.EDGEFETCH_GO_BIN && existsSync(process.env.EDGEFETCH_GO_BIN)) {
    return process.env.EDGEFETCH_GO_BIN;
  }
  const exeName = process.platform === 'win32' ? 'edgefetch.exe' : 'edgefetch';
  const outBin = path.join(outDir, exeName);

  try {
    execFileSync('go', ['build', '-o', outBin, './cmd/edgefetch'], {
      cwd: REPO_ROOT,
      stdio: 'pipe',
      timeout: 120_000,
    });
    return outBin;
  } catch (err) {
    if (process.platform !== 'win32') {
      throw new Error(`Failed to build Go binary via go on PATH: ${err?.message || err}`);
    }
  }

  // Windows without go on PATH: cross-compile native Windows binary via WSL /home/brett/sdk/go1.27.4/bin/go
  const wslRepo = toWslPath(REPO_ROOT);
  const wslOut = toWslPath(outBin);
  const cmd = `export PATH=/home/brett/sdk/go1.27.4/bin:$PATH; cd '${wslRepo}' && GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -o '${wslOut}' ./cmd/edgefetch`;
  execFileSync('wsl', ['-e', 'bash', '-lc', cmd], {
    stdio: 'pipe',
    timeout: 120_000,
  });
  assert.ok(existsSync(outBin), `Cross-compiled Go binary missing at ${outBin}`);
  return outBin;
}

async function waitForHttpReady(url, timeoutMs = 8000) {
  const deadline = Date.now() + timeoutMs;
  let lastErr = null;
  while (Date.now() < deadline) {
    try {
      const res = await fetch(url);
      if (res.status > 0) return res;
    } catch (err) {
      lastErr = err;
    }
    await delay(80);
  }
  throw new Error(`Timed out waiting for ${url}: ${lastErr?.message || 'no response'}`);
}

const activeGoChildren = new Set();

function trackChildProcess(child) {
  if (!child) return child;
  activeGoChildren.add(child);
  const untrack = () => {
    activeGoChildren.delete(child);
  };
  child.once('exit', untrack);
  child.once('close', untrack);
  return child;
}

async function killChildCleanly(child) {
  if (!child) return;
  const destroyStreams = () => {
    try { child.stdin?.destroy(); } catch {}
    try { child.stdout?.destroy(); } catch {}
    try { child.stderr?.destroy(); } catch {}
  };
  if (child.exitCode !== null || child.signalCode !== null) {
    destroyStreams();
    activeGoChildren.delete(child);
    return;
  }
  await new Promise((resolve) => {
    let settled = false;
    const finish = () => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      clearTimeout(forceTimer);
      destroyStreams();
      activeGoChildren.delete(child);
      resolve();
    };
    let forceTimer;
    const timer = setTimeout(() => {
      try {
        child.kill('SIGKILL');
      } catch {
        // ignore
      }
      if (process.platform === 'win32' && child.pid) {
        try {
          execFileSync('taskkill', ['/PID', String(child.pid), '/T', '/F'], { stdio: 'ignore', timeout: 3000 });
        } catch {
          // ignore if already exited
        }
      }
      forceTimer = setTimeout(finish, 1000);
    }, 2000);
    child.once('close', finish);
    child.once('exit', () => {
      setTimeout(finish, 30);
    });
    try {
      child.kill(process.platform === 'win32' ? undefined : 'SIGTERM');
    } catch {
      finish();
    }
  });
}

async function startGoHub({
  bin,
  args = [],
  env = {},
  healthPath = '/healthz',
}) {
  const port = await allocPort();
  const resolvedArgs = args.length > 0 ? args.map((a) => a.replace('{PORT}', String(port))) : ['--mode=hub', `--addr=127.0.0.1:${port}`];
  const child = trackChildProcess(spawn(bin, resolvedArgs, {
    env: { ...process.env, ...env },
    stdio: ['ignore', 'pipe', 'pipe'],
  }));
  let stdout = '';
  let stderr = '';
  child.stdout.on('data', (d) => { stdout += d.toString('utf8'); });
  child.stderr.on('data', (d) => { stderr += d.toString('utf8'); });

  const baseUrl = `http://127.0.0.1:${port}`;
  try {
    await waitForHttpReady(`${baseUrl}${healthPath}`, 10_000);
  } catch (err) {
    await killChildCleanly(child);
    throw new Error(`Go hub failed to start (${resolvedArgs.join(' ')}): ${err.message}\nstdout: ${stdout}\nstderr: ${stderr}`);
  }

  return {
    port,
    baseUrl,
    child,
    getOutput: () => ({ stdout, stderr }),
    async close() {
      await killChildCleanly(child);
    },
  };
}

async function startGoAgent({
  bin,
  hubUrl,
  agentToken,
  siteId = 'go-agent-1',
  allowPrivate = true,
  extraArgs = [],
  env = {},
  pollHubAgentsUrl,
  callerToken,
}) {
  const args = ['--mode=agent', ...(allowPrivate ? ['--allow-private'] : []), ...extraArgs];
  const child = trackChildProcess(spawn(bin, args, {
    env: {
      ...process.env,
      EDGEFETCH_ALLOW_INSECURE_HUB: '1',
      EDGEFETCH_HUB_URL: hubUrl,
      EDGEFETCH_AGENT_TOKEN: agentToken,
      EDGEFETCH_SITE_ID: siteId,
      EDGEFETCH_PAUSE_MS: '1000',
      EDGEFETCH_PAUSE_JITTER_MS: '0',
      ...env,
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  }));
  let stdout = '';
  let stderr = '';
  child.stdout.on('data', (d) => { stdout += d.toString('utf8'); });
  child.stderr.on('data', (d) => { stderr += d.toString('utf8'); });

  const agentsUrl = pollHubAgentsUrl || `${hubUrl}/agents`;
  const deadline = Date.now() + 10_000;
  let connected = false;
  while (Date.now() < deadline) {
    if (child.exitCode !== null) {
      throw new Error(`Go agent exited early with ${child.exitCode}\nstdout: ${stdout}\nstderr: ${stderr}`);
    }
    try {
      const res = await fetch(agentsUrl, {
        headers: callerToken ? { authorization: `Bearer ${callerToken}` } : {},
      });
      if (res.ok) {
        const json = await res.json();
        if (Array.isArray(json.agents) && json.agents.some((a) => a.siteId === siteId)) {
          connected = true;
          break;
        }
      }
    } catch {
      // retry
    }
    await delay(80);
  }
  if (!connected) {
    await killChildCleanly(child);
    throw new Error(`Go agent ${siteId} did not register on ${agentsUrl} within timeout.\nstdout: ${stdout}\nstderr: ${stderr}`);
  }

  return {
    siteId,
    child,
    getOutput: () => ({ stdout, stderr }),
    async close() {
      await killChildCleanly(child);
    },
  };
}

async function runMcpStdioSession({ bin, args = ['--mode=mcp'], env = {}, requests = [], timeoutMs = 15_000 }) {
  const child = trackChildProcess(spawn(bin, args, {
    env: { ...process.env, ...env },
    stdio: ['pipe', 'pipe', 'pipe'],
  }));
  let stdout = '';
  let stderr = '';
  child.stdout.on('data', (d) => { stdout += d.toString('utf8'); });
  child.stderr.on('data', (d) => { stderr += d.toString('utf8'); });

  for (const r of requests) {
    child.stdin.write(`${typeof r === 'string' ? r : JSON.stringify(r)}\n`);
  }
  child.stdin.end();

  const exitCode = await new Promise((resolve, reject) => {
    const t = setTimeout(async () => {
      await killChildCleanly(child);
      reject(new Error(`MCP stdio timed out after ${timeoutMs}ms\nstdout: ${stdout}\nstderr: ${stderr}`));
    }, timeoutMs);
    child.once('exit', (code) => {
      clearTimeout(t);
      resolve(code);
    });
  });

  const lines = stdout
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter(Boolean);
  const parsedLines = lines.map((line, i) => {
    try {
      return JSON.parse(line);
    } catch (err) {
      assert.fail(`[F8/M2] stdout line ${i + 1} is NOT valid JSON-RPC 2.0: ${line} (${err.message})`);
    }
  });
  return { exitCode, stdout, stderr, lines, parsedLines };
}

// ---------------------------------------------------------------------------
// 5. TS SDK, Python SDK, BotAuth, Deno, & Entrypoint Harnesses
// ---------------------------------------------------------------------------

async function loadTsSdk() {
  let src = readFileSync(path.join(REPO_ROOT, 'sdk', 'ts', 'edgefetch-client.ts'), 'utf8');
  // Defensive in-memory fallback if constructor parameter properties appear
  src = src.replace(/constructor\(([^)]*)\)/g, (m) => m.replace(/\b(?:public|private|protected)\s+(?:readonly\s+)?/g, ''));
  const js = stripTypeScriptTypes(src, { mode: 'strip' });
  const dataUrl = `data:text/javascript;base64,${Buffer.from(js, 'utf8').toString('base64')}`;
  return import(dataUrl);
}

async function loadHubBotAuth() {
  const src = readFileSync(path.join(REPO_ROOT, 'hub', 'src', 'bot-auth.ts'), 'utf8');
  const js = stripTypeScriptTypes(src, { mode: 'strip' });
  const dataUrl = `data:text/javascript;base64,${Buffer.from(js, 'utf8').toString('base64')}`;
  return import(dataUrl);
}

function findPythonBinary() {
  for (const candidate of process.platform === 'win32' ? ['python', 'py', 'python3'] : ['python3', 'python']) {
    try {
      const args = candidate === 'py' ? ['-3', '--version'] : ['--version'];
      execFileSync(candidate, args, { stdio: 'pipe', timeout: 5000 });
      return candidate;
    } catch {
      // try next
    }
  }
  return null;
}

async function runPythonSdk(pyBin, script, extraEnv = {}) {
  assert.ok(pyBin, 'Python 3 binary not found on PATH');
  const args = pyBin === 'py' ? ['-3', '-c', script] : ['-c', script];
  const { stdout, stderr } = await execFileAsync(pyBin, args, {
    env: {
      ...process.env,
      PYTHONPATH: path.join(REPO_ROOT, 'sdk', 'py'),
      ...extraEnv,
    },
    timeout: 25_000,
  });
  return { stdout: stdout.trim(), stderr: stderr.trim() };
}

function findBashBinary() {
  if (process.platform === 'win32') {
    const gitBash = 'C:\\Program Files\\Git\\bin\\bash.exe';
    if (existsSync(gitBash)) return gitBash;
  }
  return 'bash';
}

async function runEntrypointHarness({
  env = {},
  hubExitMs = 1500,
  fakeUidZero = false,
  withLegacyDataSqlite = false,
}) {
  const bashBin = findBashBinary();
  const runDir = mkdtempSync(path.join(os.tmpdir(), 'ef-entry-'));
  const posixRunDir = runDir.replace(/\\/g, '/');
  const dataRoot = path.join(runDir, 'data');
  const posixDataRoot = dataRoot.replace(/\\/g, '/');
  mkdirSync(dataRoot, { recursive: true });
  if (withLegacyDataSqlite) {
    writeFileSync(path.join(dataRoot, 'edgefetch-hub.sqlite'), 'legacy-sqlite');
  }

  const hubEnvFile = path.join(runDir, 'hub-env.json').replace(/\\/g, '/');
  const agentEnvFile = path.join(runDir, 'agent-env.json').replace(/\\/g, '/');
  const agentArgsFile = path.join(runDir, 'agent-args.txt').replace(/\\/g, '/');
  const opsLogFile = path.join(runDir, 'ops-log.txt').replace(/\\/g, '/');
  const mockHubPath = path.join(runDir, 'mock-hub.mjs').replace(/\\/g, '/');
  const mockAgentPath = path.join(runDir, 'mock-edgefetch.sh').replace(/\\/g, '/');
  const fakeBinDir = path.join(runDir, 'fake-bin');
  const posixFakeBin = fakeBinDir.replace(/\\/g, '/');
  mkdirSync(fakeBinDir, { recursive: true });

  const nodePosix = process.execPath.replace(/\\/g, '/');
  writeFileSync(
    mockHubPath,
    `import { writeFileSync } from 'node:fs';\nwriteFileSync(${JSON.stringify(hubEnvFile)}, JSON.stringify(process.env));\nsetTimeout(() => process.exit(0), ${hubExitMs});\n`,
    'utf8',
  );
  writeFileSync(
    mockAgentPath,
    `#!/bin/sh\nprintf '%s\\n' "$*" > "${agentArgsFile}"\n"${nodePosix}" -e "const fs=require('fs');fs.writeFileSync(process.argv[1],JSON.stringify(process.env));" "${agentEnvFile}"\nexit 0\n`,
    { mode: 0o755 },
  );

  if (fakeUidZero) {
    writeFileSync(path.join(fakeBinDir, 'id'), '#!/bin/sh\necho 0\n', { mode: 0o755 });
    writeFileSync(
      path.join(fakeBinDir, 'chown'),
      `#!/bin/sh\necho "chown $*" >> "${opsLogFile}"\n`,
      { mode: 0o755 },
    );
    writeFileSync(
      path.join(fakeBinDir, 'chmod'),
      `#!/bin/sh\necho "chmod $*" >> "${opsLogFile}"\n`,
      { mode: 0o755 },
    );
    writeFileSync(
      path.join(fakeBinDir, 'su-exec'),
      `#!/bin/sh\necho "su-exec $*" >> "${opsLogFile}"\nshift\nexec "$@"\n`,
      { mode: 0o755 },
    );
  }

  let script = readFileSync(path.join(REPO_ROOT, 'scripts', 'all-in-one-entrypoint.sh'), 'utf8')
    .replace(/\r\n/g, '\n')
    .replace(/\/app\/hub\/dist\/portable-server\.mjs/g, mockHubPath)
    .replace(/\/usr\/local\/bin\/edgefetch/g, mockAgentPath);

  if (fakeUidZero) {
    const msysFakeBin = posixFakeBin.replace(/^([A-Za-z]):\//, (_, d) => `/${d.toLowerCase()}/`);
    script = `export PATH="${msysFakeBin}:$PATH"\n` + script.replace(/^#!\/bin\/sh\n/, '').replace(/\/data(\/hub)?\b/g, (_, sub) => `${posixDataRoot}${sub || ''}`);
    script = `#!/bin/sh\n${script}`;
  }

  // Ensure `node` binary resolves reliably even if PATH is customized (without rewriting `node:node` user/group)
  script = script.replace(/(^|\s)node\s+("?[^&\n]*mock-hub\.mjs"?)/gm, `$1"${nodePosix}" $2`);

  const scriptPath = path.join(runDir, 'entrypoint.sh');
  writeFileSync(scriptPath, script, { mode: 0o755 });

  const childEnv = {
    ...process.env,
    PATH: fakeUidZero ? `${fakeBinDir}${path.delimiter}${process.env.PATH || ''}` : process.env.PATH,
    ...env,
    EDGEFETCH_DATA_DIR: fakeUidZero ? (env.EDGEFETCH_DATA_DIR === '/data' ? posixDataRoot : env.EDGEFETCH_DATA_DIR ?? posixDataRoot) : path.join(runDir, 'hub-data'),
  };

  let exitCode = 0;
  let stdout = '';
  let stderr = '';
  try {
    const res = await execFileAsync(bashBin, [scriptPath.replace(/\\/g, '/')], {
      env: childEnv,
      timeout: 15_000,
    });
    stdout = res.stdout;
    stderr = res.stderr;
  } catch (err) {
    exitCode = typeof err.code === 'number' ? err.code : 1;
    stdout = err.stdout || '';
    stderr = err.stderr || '';
  }

  const hubEnv = existsSync(hubEnvFile) ? JSON.parse(readFileSync(hubEnvFile, 'utf8')) : null;
  const agentEnv = existsSync(agentEnvFile) ? JSON.parse(readFileSync(agentEnvFile, 'utf8')) : null;
  const agentArgs = existsSync(agentArgsFile) ? readFileSync(agentArgsFile, 'utf8').trim() : null;
  const opsLog = existsSync(opsLogFile) ? readFileSync(opsLogFile, 'utf8') : '';

  return {
    exitCode,
    stdout,
    stderr,
    hubEnv,
    agentEnv,
    agentArgs,
    opsLog,
    dataRoot,
    cleanup() {
      try {
        rmSync(runDir, { recursive: true, force: true, maxRetries: 3 });
      } catch {
        // ignore
      }
    },
  };
}

// ---------------------------------------------------------------------------
// 6. OAuth 2.1 PKCE & Admin Session Helpers
// ---------------------------------------------------------------------------

async function runOAuthPkceFlow({ baseUrl, callerToken, scopes = 'crawl:read crawl:fetch' }) {
  const redirectUri = 'http://127.0.0.1:19999/cb';
  const regRes = await fetch(`${baseUrl}/oauth/register`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      client_name: 'e2e-audit-client',
      redirect_uris: [redirectUri],
      application_type: 'native',
    }),
  });
  assert.equal(regRes.status, 201, `DCR failed with ${regRes.status}`);
  const client = await regRes.json();

  const codeVerifier = randomBytes(32).toString('base64url');
  const codeChallenge = createHash('sha256').update(codeVerifier).digest('base64url');
  const state = randomBytes(12).toString('hex');
  const resource = `${baseUrl}/mcp`;

  const authUrl = new URL(`${baseUrl}/oauth/authorize`);
  authUrl.searchParams.set('client_id', client.client_id);
  authUrl.searchParams.set('redirect_uri', redirectUri);
  authUrl.searchParams.set('response_type', 'code');
  authUrl.searchParams.set('code_challenge', codeChallenge);
  authUrl.searchParams.set('code_challenge_method', 'S256');
  authUrl.searchParams.set('scope', scopes);
  authUrl.searchParams.set('state', state);
  authUrl.searchParams.set('resource', resource);

  const getAuthRes = await fetch(authUrl.toString());
  assert.equal(getAuthRes.status, 200);
  const html = await getAuthRes.text();
  const setCookie = getAuthRes.headers.get('set-cookie') || '';
  const csrfCookie = /ef_oauth_csrf=([^;]+)/.exec(setCookie)?.[1] || '';
  const sealed = /name="sealed"\s+value="([^"]+)"/.exec(html)?.[1] || '';
  const csrfField = /name="csrf"\s+value="([^"]+)"/.exec(html)?.[1] || csrfCookie;
  assert.ok(sealed && csrfCookie, 'OAuth consent page missing sealed or csrf');

  const form = new URLSearchParams({
    sealed,
    csrf: csrfField,
    owner_token: callerToken,
    decision: 'approve',
  });
  const postAuthRes = await fetch(`${baseUrl}/oauth/authorize`, {
    method: 'POST',
    redirect: 'manual',
    headers: {
      'content-type': 'application/x-www-form-urlencoded',
      cookie: `ef_oauth_csrf=${csrfCookie}`,
    },
    body: form.toString(),
  });
  assert.equal(postAuthRes.status, 302);
  const loc = new URL(postAuthRes.headers.get('location'));
  const code = loc.searchParams.get('code');
  assert.ok(code && code.startsWith('efc_'), `expected efc_ code, got ${code}`);
  assert.equal(loc.searchParams.get('state'), state);

  const tokRes = await fetch(`${baseUrl}/oauth/token`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      code_verifier: codeVerifier,
      client_id: client.client_id,
      redirect_uri: redirectUri,
      resource,
    }).toString(),
  });
  assert.equal(tokRes.status, 200);
  const tokens = await tokRes.json();
  return { client, redirectUri, resource, code, codeVerifier, tokens, getAuthRes, postAuthRes, tokRes };
}

async function adminLogin(baseUrl, callerToken) {
  const loginRes = await fetch(`${baseUrl}/admin/login`, {
    method: 'POST',
    redirect: 'manual',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ token: callerToken }).toString(),
  });
  assert.equal(loginRes.status, 302, `admin login failed with ${loginRes.status}`);
  const setCookie = loginRes.headers.get('set-cookie') || '';
  const cookieVal = /ef_admin_session=([^;]+)/.exec(setCookie)?.[1] || '';
  assert.ok(cookieVal, 'missing ef_admin_session cookie');
  const csrf = cookieVal.split('.')[2];
  return { cookie: `ef_admin_session=${cookieVal}`, cookieVal, csrf, loginRes };
}

// ---------------------------------------------------------------------------
// 7. Shared Suite Fixtures
// ---------------------------------------------------------------------------

let suiteTmpDir;
let goBin;
let pyBin;
let tsSdk;
let hubBotAuth;

before(async () => {
  suiteTmpDir = mkdtempSync(path.join(os.tmpdir(), 'ef-e2e-matrix-'));
  goBin = buildEdgefetchBinary(suiteTmpDir);
  pyBin = findPythonBinary();
  tsSdk = await loadTsSdk();
  hubBotAuth = await loadHubBotAuth();
});

after(async () => {
  if (activeGoChildren.size > 0) {
    await Promise.all([...activeGoChildren].map((child) => killChildCleanly(child)));
    await delay(100);
  }
  if (suiteTmpDir) {
    try {
      rmSync(suiteTmpDir, { recursive: true, force: true, maxRetries: 6, retryDelay: 200 });
    } catch {
      // ignore transient Windows cleanup lock
    }
  }
});

// ===========================================================================
// TIER 1 — Feature Coverage (30 Tests: T1-A1 .. T1-E5)
// ===========================================================================

describe('Tier 1 — Area A: Portable Hub HTTP, MCP & Sub-Modules', () => {
  test('T1-A1: Root Trace & Response Headers across /v1/* [F1/M1]', async () => {
    const collector = await startMockOtlpCollector();
    const hub = await startTestHub({
      OTEL_EXPORTER_OTLP_ENDPOINT: collector.endpoint,
      OTEL_SERVICE_NAME: 'edgefetch-hub',
    }, suiteTmpDir);
    const agent = await connectMockAgent({ port: hub.port, agentToken: hub.agentToken, siteId: 't1-a1' });

    try {
      const authHdr = { authorization: `Bearer ${hub.callerToken}` };
      const endpoints = [
        { method: 'GET', path: '/v1/capabilities' },
        { method: 'GET', path: '/v1/extractors' },
        { method: 'GET', path: '/v1/hosts' },
        { method: 'POST', path: '/v1/scrape', body: { url: 'https://t1-a1.example.com/article' } },
        { method: 'POST', path: '/v1/map', body: { url: 'https://t1-a1.example.com' } },
      ];

      for (const ep of endpoints) {
        const { traceId, parentSpanId, traceparent } = makeTraceIds('01');
        const res = await fetch(`${hub.baseUrl}${ep.path}`, {
          method: ep.method,
          headers: {
            ...authHdr,
            traceparent,
            ...(ep.body ? { 'content-type': 'application/json' } : {}),
          },
          ...(ep.body ? { body: JSON.stringify(ep.body) } : {}),
        });
        assert.equal(res.status, 200, `[F1/M1] ${ep.method} ${ep.path} expected 200, got ${res.status}`);
        assertTraceHeaders(res, { expectedTraceId: traceId, expectedFlags: '01', tag: `[F1/M1 ${ep.path}]` });

        await collector.waitForSpans((entries) =>
          entries.some((e) => e.span?.traceId === traceId && e.span?.name === 'edgefetch.http'),
        );
        const spans = collector.findByTraceId(traceId);
        const rootSpan = spans.find((e) => e.span.name === 'edgefetch.http');
        assert.ok(rootSpan, `[F1/M1] missing edgefetch.http root span for ${ep.method} ${ep.path}`);
        validateOtlpSpan(rootSpan.span, `[F1/M1 ${ep.path}]`);
        assert.equal(rootSpan.span.parentSpanId, parentSpanId, `[F1/M1] root span parentSpanId mismatch on ${ep.path}`);
      }
    } finally {
      await agent.close();
      await hub.close();
      await collector.close();
    }
  });

  test('T1-A2: Multi-Fetch Tool Parent-Child Nesting (jobs, catalog, crawl, batch/scrape) [F2/M1]', async () => {
    const collector = await startMockOtlpCollector();
    const hub = await startTestHub({
      OTEL_EXPORTER_OTLP_ENDPOINT: collector.endpoint,
      OTEL_SERVICE_NAME: 'edgefetch-hub',
    }, suiteTmpDir);
    const agent = await connectMockAgent({ port: hub.port, agentToken: hub.agentToken, siteId: 't1-a2' });

    try {
      const calls = [
        { path: '/v1/jobs', spanName: 'edgefetch.jobs', body: { mode: 'verify', urls: ['https://jobs.ashbyhq.com/linear/ash-1'] } },
        { path: '/v1/catalog', spanName: 'edgefetch.catalog', body: { url: 'https://shop-t1a2.example.com', platform: 'shopify', sync: true } },
        { path: '/v1/batch/scrape', spanName: 'edgefetch.batch_scrape', body: { urls: ['https://t1-a2.example.com/a', 'https://t1-a2.example.com/b'], sync: true } },
        { path: '/v1/crawl', spanName: 'edgefetch.crawl', body: { url: 'https://t1-a2.example.com', limit: 2, maxDepth: 1, sync: true } },
      ];

      for (const c of calls) {
        const { traceId, traceparent } = makeTraceIds('01');
        const res = await fetch(`${hub.baseUrl}${c.path}`, {
          method: 'POST',
          headers: {
            authorization: `Bearer ${hub.callerToken}`,
            'content-type': 'application/json',
            traceparent,
          },
          body: JSON.stringify(c.body),
        });
        assert.equal(res.status, 200, `[F2/M1] ${c.path} returned ${res.status}: ${await res.text()}`);
        assertTraceHeaders(res, { expectedTraceId: traceId, tag: `[F2/M1 ${c.path}]` });

        await collector.waitForSpans((entries) =>
          entries.some((e) => e.span?.traceId === traceId && e.span?.name === c.spanName) &&
          entries.some((e) => e.span?.traceId === traceId && e.span?.name === 'edgefetch.dispatch'),
        );
        const spans = collector.findByTraceId(traceId);
        const httpSpan = spans.find((e) => e.span.name === 'edgefetch.http');
        const toolSpan = spans.find((e) => e.span.name === c.spanName);
        const dispatchSpans = spans.filter((e) => e.span.name === 'edgefetch.dispatch');

        assert.ok(httpSpan, `[F2/M1] missing edgefetch.http for ${c.path}`);
        assert.ok(toolSpan, `[F2/M1] missing ${c.spanName} parent span for ${c.path}`);
        assert.ok(dispatchSpans.length >= 1, `[F2/M1] missing child edgefetch.dispatch span for ${c.path}`);
        assert.equal(toolSpan.span.parentSpanId, httpSpan.span.spanId, `[F2/M1] ${c.spanName} not parented to edgefetch.http`);
        for (const ds of dispatchSpans) {
          validateOtlpSpan(ds.span, `[F2/M1 ${c.path}]`);
          assert.equal(ds.span.parentSpanId, toolSpan.span.spanId, `[F2/M1] dispatch child not parented to ${c.spanName}`);
        }
      }
    } finally {
      await agent.close();
      await hub.close();
      await collector.close();
    }
  });

  test('T1-A3: /mcp Streamable HTTP Tool Tracing (2026-07-28 & 2025-03-26) [F2/M1]', async () => {
    const collector = await startMockOtlpCollector();
    const hub = await startTestHub({
      OTEL_EXPORTER_OTLP_ENDPOINT: collector.endpoint,
      OTEL_SERVICE_NAME: 'edgefetch-hub',
    }, suiteTmpDir);
    const agent = await connectMockAgent({
      port: hub.port,
      agentToken: hub.agentToken,
      siteId: 't1-a3',
      handler: async (reqItem, _msg, helpers) => {
        const longText = 'Artifact line '.repeat(400);
        const art = await helpers.uploadArtifact(longText, 'stored');
        return {
          status: 200,
          outcome: 'ok',
          contentType: 'text/html',
          body: `<html><body><main><h1>MCP Scrape</h1><p>${longText}</p></main></body></html>`,
          bodyEncoding: 'utf-8',
          artifact: art,
        };
      },
    });

    try {
      const mcpPost = async (body, extraHeaders = {}) => {
        const { traceId, traceparent } = makeTraceIds('01');
        const res = await fetch(`${hub.baseUrl}/mcp`, {
          method: 'POST',
          headers: {
            authorization: `Bearer ${hub.mcpToken}`,
            'content-type': 'application/json',
            accept: 'application/json, text/event-stream',
            traceparent,
            ...extraHeaders,
          },
          body: JSON.stringify(body),
        });
        return { res, traceId, json: await res.json() };
      };

      const init = await mcpPost(
        { jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2026-07-28', capabilities: {}, clientInfo: { name: 'e2e', version: '1.0' } } },
        { 'mcp-protocol-version': '2026-07-28', 'mcp-method': 'initialize' },
      );
      assert.equal(init.res.status, 200);
      assertTraceHeaders(init.res, { expectedTraceId: init.traceId, tag: '[F2/M1 /mcp initialize]' });

      const disc = await mcpPost(
        { jsonrpc: '2.0', id: 2, method: 'server/discover', params: {} },
        { 'mcp-protocol-version': '2026-07-28', 'mcp-method': 'server/discover' },
      );
      assert.equal(disc.res.status, 200);
      assertTraceHeaders(disc.res, { expectedTraceId: disc.traceId, tag: '[F2/M1 /mcp server/discover]' });

      const list = await mcpPost({ jsonrpc: '2.0', id: 3, method: 'tools/list', params: {} });
      assert.equal(list.res.status, 200);
      assert.equal(list.json.result.tools.length, 17);
      assertTraceHeaders(list.res, { expectedTraceId: list.traceId, tag: '[F2/M1 /mcp tools/list]' });

      const callHeaders = (name) => ({ 'mcp-protocol-version': '2026-07-28', 'mcp-method': 'tools/call', 'mcp-name': name });
      const calls = [
        { name: 'list_agents', args: {}, hdrs: callHeaders('list_agents') },
        { name: 'find_extractors', args: {}, hdrs: callHeaders('find_extractors') },
        { name: 'scrape', args: { url: 'https://t1-a3.example.com/doc', maxChars: 600 }, hdrs: callHeaders('scrape') },
        { name: 'search', args: { query: 'Mock', max_results: 3 }, hdrs: {} },
      ];

      let artifactSha = null;
      for (let i = 0; i < calls.length; i++) {
        const c = calls[i];
        const out = await mcpPost(
          { jsonrpc: '2.0', id: 10 + i, method: 'tools/call', params: { name: c.name, arguments: c.args } },
          c.hdrs,
        );
        assert.equal(out.res.status, 200, `[F2/M1] /mcp tools/call ${c.name} status=${out.res.status}`);
        assert.equal(out.json.error, undefined, `[F2/M1] /mcp tools/call ${c.name} returned JSON-RPC error: ${JSON.stringify(out.json.error)}`);
        assert.notEqual(out.json.result?.isError, true, `[F2/M1] /mcp tools/call ${c.name} returned isError=true: ${JSON.stringify(out.json.result)}`);
        assertTraceHeaders(out.res, { expectedTraceId: out.traceId, tag: `[F2/M1 /mcp ${c.name}]` });
        if (c.name === 'scrape') {
          const textContent = out.json.result?.content?.[0]?.text || '';
          const parsedMeta = JSON.parse(textContent.match(/\{[\s\S]*\}/)?.[0] || '{}');
          artifactSha = parsedMeta.markdownArtifactId || parsedMeta.artifactId || null;
        }
        await collector.waitForSpans((entries) =>
          entries.some((e) => e.span?.traceId === out.traceId && e.span?.name === 'edgefetch.mcp.tool'),
        );
        const toolSpan = collector.findByTraceId(out.traceId).find((e) => e.span.name === 'edgefetch.mcp.tool');
        assert.ok(toolSpan, `[F2/M1] missing edgefetch.mcp.tool span for ${c.name}`);
        validateOtlpSpan(toolSpan.span, `[F2/M1 /mcp ${c.name}]`);
      }

      assert.ok(artifactSha, '[F2/M1] /mcp scrape did not return markdownArtifactId or artifactId for read_artifact');
      const ra = await mcpPost(
        { jsonrpc: '2.0', id: 20, method: 'tools/call', params: { name: 'read_artifact', arguments: { artifactId: artifactSha, offset: 0, limit: 1000 } } },
        callHeaders('read_artifact'),
      );
      assert.equal(ra.res.status, 200);
      assert.equal(ra.json.error, undefined, `[F2/M1] /mcp read_artifact returned JSON-RPC error: ${JSON.stringify(ra.json.error)}`);
      assert.notEqual(ra.json.result?.isError, true, `[F2/M1] /mcp read_artifact returned isError=true: ${JSON.stringify(ra.json.result)}`);
      const raText = ra.json.result?.content?.[0]?.text || '';
      assert.ok(raText.length > 0 && raText.includes('Artifact line'), `[F2/M1] /mcp read_artifact returned empty or unexpected content: ${raText.slice(0, 120)}`);
      assertTraceHeaders(ra.res, { expectedTraceId: ra.traceId, tag: '[F2/M1 /mcp read_artifact]' });
      await collector.waitForSpans((entries) =>
        entries.some((e) => e.span?.traceId === ra.traceId && e.span?.name === 'edgefetch.mcp.tool'),
      );
      const raSpan = collector.findByTraceId(ra.traceId).find((e) => e.span.name === 'edgefetch.mcp.tool');
      assert.ok(raSpan, '[F2/M1] missing edgefetch.mcp.tool span for read_artifact');
      validateOtlpSpan(raSpan.span, '[F2/M1 /mcp read_artifact]');
    } finally {
      await agent.close();
      await hub.close();
      await collector.close();
    }
  });

  test('T1-A4: Cache Hit (cache:r2-d1) & SAFE_FETCH OTLP Header Flush [F1/F3/M1]', async () => {
    const collector = await startMockOtlpCollector();
    const hub = await startTestHub({
      OTEL_EXPORTER_OTLP_ENDPOINT: collector.endpoint,
      OTEL_EXPORTER_OTLP_HEADERS: 'Authorization=Bearer%20otel-tok,x-custom=v1',
      OTEL_SERVICE_NAME: 'edgefetch-hub',
    }, suiteTmpDir);
    const agent = await connectMockAgent({
      port: hub.port,
      agentToken: hub.agentToken,
      siteId: 't1-a4',
      handler: async (reqItem, _msg, helpers) => {
        const html = '<html><head><title>Cached T1-A4</title></head><body><main><h1>Cached Page</h1><p>Stored R2 verified content for cache hit check.</p></main></body></html>';
        const art = await helpers.uploadArtifact(html, 'stored');
        return {
          status: 200,
          outcome: 'ok',
          contentType: 'text/html; charset=utf-8',
          body: html,
          artifact: art,
        };
      },
    });

    try {
      const targetUrl = 'https://t1-a4.example.com/cached-page';
      const tp1 = makeTraceIds('01');
      const r1 = await fetch(`${hub.baseUrl}/v1/scrape`, {
        method: 'POST',
        headers: { authorization: `Bearer ${hub.callerToken}`, 'content-type': 'application/json', traceparent: tp1.traceparent },
        body: JSON.stringify({ url: targetUrl }),
      });
      assert.equal(r1.status, 200);
      assertTraceHeaders(r1, { expectedTraceId: tp1.traceId, tag: '[F1/M1]' });

      collector.clear();
      const tp2 = makeTraceIds('01');
      const r2 = await fetch(`${hub.baseUrl}/v1/scrape`, {
        method: 'POST',
        headers: { authorization: `Bearer ${hub.callerToken}`, 'content-type': 'application/json', traceparent: tp2.traceparent },
        body: JSON.stringify({ url: targetUrl, maxAgeMs: 60_000 }),
      });
      assert.equal(r2.status, 200);
      const j2 = await r2.json();
      assert.equal(j2.cached, true);
      assert.equal(r2.headers.get('x-crawler-via'), 'cache:r2-d1');
      assertTraceHeaders(r2, { expectedTraceId: tp2.traceId, tag: '[F3/M1 cache:r2-d1]' });

      await collector.waitForSpans((entries) =>
        entries.some((e) => e.span?.traceId === tp2.traceId && e.span?.name === 'cache:r2-d1'),
      );
      const cacheSpan = collector.findByTraceId(tp2.traceId).find((e) => e.span.name === 'cache:r2-d1');
      assert.ok(cacheSpan, '[F3/M1] cache:r2-d1 OTLP span missing on cache hit');
      validateOtlpSpan(cacheSpan.span, '[F3/M1 cache:r2-d1]');

      const otlpReq = collector.requests.find((r) => JSON.stringify(r.payload).includes(tp2.traceId));
      assert.ok(otlpReq, '[F1/M1] collector did not receive OTLP request for cache hit');
      assert.equal(otlpReq.headers.authorization, 'Bearer otel-tok', '[F1/M1] OTEL_EXPORTER_OTLP_HEADERS Authorization mismatch');
      assert.equal(otlpReq.headers['x-custom'], 'v1', '[F1/M1] OTEL_EXPORTER_OTLP_HEADERS x-custom mismatch');
    } finally {
      await agent.close();
      await hub.close();
      await collector.close();
    }
  });

  test('T1-A5: Sub-Module Span Bridges (search, ingest-tab, interact, agent llm.turn, spa_fallback) [F3/M1]', async () => {
    const collector = await startMockOtlpCollector();
    const searxSrv = await startHttpServer((req, res) => {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({
        results: [{ url: 'https://docs.example.org/searx-hit', title: 'SearX Hit', content: 'Rust async runtime guide' }],
      }));
    });
    const crawl4aiSrv = await startHttpServer((req, res) => {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({
        success: true,
        results: [{ url: 'https://spa-t1a5.example.com/app', status_code: 200, markdown: { raw_markdown: '# Hydrated via Crawl4AI\n\nComplete SPA body.' }, metadata: { title: 'SPA' } }],
      }));
    });
    const llmSrv = await startHttpServer((req, res) => {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({
        id: 'chatcmpl-mock-1',
        object: 'chat.completion',
        choices: [{ index: 0, message: { role: 'assistant', content: '{"answer":"Verified mock LLM summary"}' }, finish_reason: 'stop' }],
        usage: { prompt_tokens: 12, completion_tokens: 10, total_tokens: 22 },
      }));
    });

    const llmApiKey = 'sk-mock-llm-secret-123456';
    const hub = await startTestHub({
      OTEL_EXPORTER_OTLP_ENDPOINT: collector.endpoint,
      OTEL_SERVICE_NAME: 'edgefetch-hub',
      SEARXNG_URL: searxSrv.url,
      CRAWL4AI_API_URL: crawl4aiSrv.url,
      SPA_FALLBACK_ORDER: 'crawl4ai',
      EDGEFETCH_LLM_PROVIDER: 'openai',
      EDGEFETCH_LLM_BASE_URL: `${llmSrv.url}/v1`,
      EDGEFETCH_LLM_API_KEY: llmApiKey,
      EDGEFETCH_LLM_MODEL: 'gpt-4o-mini',
    }, suiteTmpDir);

    const agent = await connectMockAgent({
      port: hub.port,
      agentToken: hub.agentToken,
      siteId: 't1-a5',
      capabilities: ['artifacts-v1', 'browser-v1'],
      handler: async (reqItem) => {
        if (String(reqItem.url).includes('spa-t1a5.example.com/app')) {
          return {
            status: 200,
            outcome: 'ok',
            contentType: 'text/html',
            body: '<html><body><div id="app"></div><script>window.boot();</script></body></html>',
          };
        }
        if (reqItem.interact) {
          return {
            status: 200,
            outcome: 'ok',
            contentType: 'text/html',
            body: '<html><body><main><h1>Interacted</h1></main></body></html>',
            markdown: '# Interacted',
            sessionId: reqItem.interact.sessionId || 'efsess_t1a5_1',
            rendered: true,
          };
        }
        return null;
      },
    });

    try {
      const hdrs = (tp) => ({ authorization: `Bearer ${hub.callerToken}`, 'content-type': 'application/json', traceparent: tp });

      // 1. Search (SearXNG + FTS5)
      const tpSearch = makeTraceIds('01');
      const sRes = await fetch(`${hub.baseUrl}/v1/search`, {
        method: 'POST',
        headers: hdrs(tpSearch.traceparent),
        body: JSON.stringify({ query: 'Rust async runtime', max_results: 3 }),
      });
      assert.equal(sRes.status, 200);
      assertTraceHeaders(sRes, { expectedTraceId: tpSearch.traceId, tag: '[F3/M1 search]' });
      const sJson = await sRes.json();
      assert.equal(sJson.ok, true, '[F3/M1] /v1/search ok !== true');
      assert.ok(Array.isArray(sJson.results) && sJson.results.length >= 1, '[F3/M1] /v1/search returned empty results');
      await collector.waitForSpans((e) => e.some((x) => x.span.traceId === tpSearch.traceId && x.span.name.startsWith('edgefetch.search.')));
      assert.ok(
        collector.findByTraceId(tpSearch.traceId).some((e) => e.span.name.startsWith('edgefetch.search.')),
        '[F3/M1] missing edgefetch.search.* span',
      );

      // 2. ingest-tab -> collection search
      const tpIngest = makeTraceIds('01');
      const iRes = await fetch(`${hub.baseUrl}/v1/ingest-tab`, {
        method: 'POST',
        headers: hdrs(tpIngest.traceparent),
        body: JSON.stringify({
          url: 'https://notes.example.com/clip-1',
          title: 'Clipped Note',
          html: '<main><h1>Clipped Note</h1><p>Unique quantum telemetry token alpha99.</p></main>',
          collectionId: 'col_t1a5',
        }),
      });
      assert.equal(iRes.status, 200);
      assertTraceHeaders(iRes, { expectedTraceId: tpIngest.traceId, tag: '[F3/M1 ingest-tab]' });
      const iJson = await iRes.json();
      assert.equal(iJson.ok, true, '[F3/M1] /v1/ingest-tab ok !== true');

      const tpCol = makeTraceIds('01');
      const cRes = await fetch(`${hub.baseUrl}/v1/collections/col_t1a5/search`, {
        method: 'POST',
        headers: hdrs(tpCol.traceparent),
        body: JSON.stringify({ query: 'alpha99', limit: 5 }),
      });
      assert.equal(cRes.status, 200);
      assertTraceHeaders(cRes, { expectedTraceId: tpCol.traceId, tag: '[F3/M1 collection_search]' });
      const cJson = await cRes.json();
      assert.equal(cJson.ok, true, '[F3/M1] /v1/collections/col_t1a5/search ok !== true');
      assert.ok(Array.isArray(cJson.hits) && cJson.hits.length >= 1, '[F3/M1] /v1/collections/col_t1a5/search returned empty hits');
      assert.ok(
        JSON.stringify(cJson.hits).includes('alpha99') || JSON.stringify(cJson.hits).includes('Clipped Note'),
        '[F3/M1] /v1/collections/col_t1a5/search missing clipped note content',
      );
      await collector.waitForSpans((e) =>
        e.some((x) => x.span.traceId === tpIngest.traceId && x.span.name === 'edgefetch.ingest_tab') &&
        e.some((x) => x.span.traceId === tpCol.traceId && x.span.name === 'edgefetch.collection_search'),
      );
      assert.ok(collector.findByTraceId(tpIngest.traceId).some((e) => e.span.name === 'edgefetch.ingest_tab'), '[F3/M1] missing edgefetch.ingest_tab span');
      assert.ok(collector.findByTraceId(tpCol.traceId).some((e) => e.span.name === 'edgefetch.collection_search'), '[F3/M1] missing edgefetch.collection_search span');

      // 3. interact
      const tpInteract = makeTraceIds('01');
      const intRes = await fetch(`${hub.baseUrl}/v1/interact`, {
        method: 'POST',
        headers: hdrs(tpInteract.traceparent),
        body: JSON.stringify({
          url: 'https://t1-a5.example.com/form',
          actions: [{ type: 'click', selector: '#go' }, { type: 'wait', waitMs: 50 }],
          closeSession: true,
        }),
      });
      assert.equal(intRes.status, 200);
      assertTraceHeaders(intRes, { expectedTraceId: tpInteract.traceId, tag: '[F3/M1 interact]' });
      const intJson = await intRes.json();
      assert.equal(intJson.ok, true, '[F3/M1] /v1/interact ok !== true');
      await collector.waitForSpans((e) => e.some((x) => x.span.traceId === tpInteract.traceId && x.span.name === 'edgefetch.interact'));
      const intSpan = collector.findByTraceId(tpInteract.traceId).find((e) => e.span.name === 'edgefetch.interact');
      assert.ok(intSpan, '[F3/M1] missing edgefetch.interact span');
      assert.ok(getOtlpAttrValue(intSpan.span.attributes, 'edgefetch.interact.session_hash'), '[F3/M1] missing edgefetch.interact.session_hash');
      assert.equal(getOtlpAttrValue(intSpan.span.attributes, 'edgefetch.interact.action_count'), 2, '[F3/M1] action_count mismatch');

      // 4. agent -> llm.turn
      const tpAgent = makeTraceIds('01');
      const agRes = await fetch(`${hub.baseUrl}/v1/agent`, {
        method: 'POST',
        headers: hdrs(tpAgent.traceparent),
        body: JSON.stringify({
          prompt: 'Summarize the page',
          urls: ['https://t1-a5.example.com/research'],
          strictConstrainToURLs: true,
          maxSteps: 1,
        }),
      });
      assert.equal(agRes.status, 200);
      assertTraceHeaders(agRes, { expectedTraceId: tpAgent.traceId, tag: '[F3/M1 agent]' });
      const agJson = await agRes.json();
      assert.equal(agJson.ok, true, '[F3/M1] /v1/agent ok !== true');
      await collector.waitForSpans((e) =>
        e.some((x) => x.span.traceId === tpAgent.traceId && x.span.name === 'edgefetch.agent') &&
        e.some((x) => x.span.traceId === tpAgent.traceId && x.span.name === 'edgefetch.llm.turn'),
      );
      const agentSpans = collector.findByTraceId(tpAgent.traceId);
      assert.ok(agentSpans.some((e) => e.span.name === 'edgefetch.agent'), '[F3/M1] missing edgefetch.agent span');
      assert.ok(agentSpans.some((e) => e.span.name === 'edgefetch.llm.turn'), '[F3/M1] missing edgefetch.llm.turn span');
      assertNoLeakedSecrets(agentSpans, [llmApiKey, hub.callerToken], '[F3/M1 agent]');

      // 5. spa_fallback
      const tpSpa = makeTraceIds('01');
      const spaRes = await fetch(`${hub.baseUrl}/v1/scrape`, {
        method: 'POST',
        headers: hdrs(tpSpa.traceparent),
        body: JSON.stringify({ url: 'https://spa-t1a5.example.com/app', spaFallback: 'crawl4ai' }),
      });
      assert.equal(spaRes.status, 200);
      assertTraceHeaders(spaRes, { expectedTraceId: tpSpa.traceId, tag: '[F3/M1 spa_fallback]' });
      const spaJson = await spaRes.json();
      assert.equal(spaJson.ok, true, '[F3/M1] /v1/scrape spaFallback ok !== true');
      assert.equal(spaJson.renderedVia, 'crawl4ai', '[F3/M1] expected renderedVia=crawl4ai on spaFallback');
      assert.ok(String(spaJson.markdown || '').includes('Hydrated via Crawl4AI'), '[F3/M1] /v1/scrape spaFallback missing hydrated Crawl4AI markdown');
      await collector.waitForSpans((e) => e.some((x) => x.span.traceId === tpSpa.traceId && x.span.name === 'edgefetch.spa_fallback'));
      assert.ok(collector.findByTraceId(tpSpa.traceId).some((e) => e.span.name === 'edgefetch.spa_fallback'), '[F3/M1] missing edgefetch.spa_fallback span');
    } finally {
      await agent.close();
      await hub.close();
      await Promise.all([searxSrv.close(), crawl4aiSrv.close(), llmSrv.close()]);
      await collector.close();
    }
  });

  test('T1-A6: Compat Routes Tracing (/v2/scrape, /compat/firecrawl/v2/map, /compat/tavily/search) [F1/F2/M1]', async () => {
    const collector = await startMockOtlpCollector();
    const hub = await startTestHub({ OTEL_EXPORTER_OTLP_ENDPOINT: collector.endpoint, OTEL_SERVICE_NAME: 'edgefetch-hub' }, suiteTmpDir);
    const agent = await connectMockAgent({ port: hub.port, agentToken: hub.agentToken, siteId: 't1-a6' });

    try {
      const tp1 = makeTraceIds('01');
      const r1 = await fetch(`${hub.baseUrl}/v2/scrape`, {
        method: 'POST',
        headers: { authorization: `Bearer ${hub.callerToken}`, 'content-type': 'application/json', traceparent: tp1.traceparent },
        body: JSON.stringify({ url: 'https://t1-a6.example.com/page' }),
      });
      assert.equal(r1.status, 200);
      assertTraceHeaders(r1, { expectedTraceId: tp1.traceId, tag: '[F2/M1 /v2/scrape]' });
      const j1 = await r1.json();
      assert.equal(j1.success, true, '[F2/M1] /v2/scrape success !== true');
      assert.equal(j1.data?.ok, true, '[F2/M1] /v2/scrape data.ok !== true');

      const tp2 = makeTraceIds('01');
      const r2 = await fetch(`${hub.baseUrl}/compat/firecrawl/v2/map`, {
        method: 'POST',
        headers: { authorization: `Bearer ${hub.callerToken}`, 'content-type': 'application/json', traceparent: tp2.traceparent },
        body: JSON.stringify({ url: 'https://t1-a6.example.com' }),
      });
      assert.equal(r2.status, 200);
      assertTraceHeaders(r2, { expectedTraceId: tp2.traceId, tag: '[F2/M1 /compat/firecrawl/v2/map]' });
      const j2 = await r2.json();
      assert.equal(j2.success, true, '[F2/M1] /compat/firecrawl/v2/map success !== true');
      assert.ok(Array.isArray(j2.links), '[F2/M1] /compat/firecrawl/v2/map missing links array');

      const tp3 = makeTraceIds('01');
      const r3 = await fetch(`${hub.baseUrl}/compat/tavily/search`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', traceparent: tp3.traceparent },
        body: JSON.stringify({ api_key: hub.callerToken, query: 'EdgeFetch compat', max_results: 2 }),
      });
      assert.equal(r3.status, 200);
      assertTraceHeaders(r3, { expectedTraceId: tp3.traceId, tag: '[F2/M1 /compat/tavily/search]' });
      const j3 = await r3.json();
      assert.equal(j3.ok, true, '[F2/M1] /compat/tavily/search ok !== true');
      assert.ok(Array.isArray(j3.results), '[F2/M1] /compat/tavily/search missing results array');

      await collector.waitForSpans((e) =>
        e.some((x) => x.span.traceId === tp1.traceId && x.span.name === 'edgefetch.scrape') &&
        e.some((x) => x.span.traceId === tp2.traceId && x.span.name === 'edgefetch.map') &&
        e.some((x) => x.span.traceId === tp3.traceId && x.span.name === 'edgefetch.search'),
      );
      const s1 = collector.findByTraceId(tp1.traceId).find((e) => e.span.name === 'edgefetch.scrape');
      const s2 = collector.findByTraceId(tp2.traceId).find((e) => e.span.name === 'edgefetch.map');
      const s3 = collector.findByTraceId(tp3.traceId).find((e) => e.span.name === 'edgefetch.search');
      assert.ok(s1, '[F2/M1] /v2/scrape missing edgefetch.scrape span');
      assert.ok(s2, '[F2/M1] /compat/firecrawl/v2/map missing edgefetch.map span');
      assert.ok(s3, '[F2/M1] /compat/tavily/search missing edgefetch.search span');
      validateOtlpSpan(s1.span, '[F2/M1 /v2/scrape]');
      validateOtlpSpan(s2.span, '[F2/M1 /compat/firecrawl/v2/map]');
      validateOtlpSpan(s3.span, '[F2/M1 /compat/tavily/search]');
    } finally {
      await agent.close();
      await hub.close();
      await collector.close();
    }
  });
});

describe('Tier 1 — Area B: Go --mode=hub, --mode=mcp, --mode=agent & Browser Renderer', () => {
  test('T1-B1: Go --mode=hub HTTP & /mcp OTLP Export [F7/M2]', async () => {
    const collector = await startMockOtlpCollector();
    const { callerToken, agentToken } = makeTokens();
    const goHub = await startGoHub({
      bin: goBin,
      args: ['--mode=hub', '--addr=127.0.0.1:{PORT}'],
      env: {
        EDGEFETCH_CALLER_TOKEN: callerToken,
        EDGEFETCH_AGENT_TOKEN: agentToken,
        OTEL_EXPORTER_OTLP_ENDPOINT: collector.endpoint,
        OTEL_SERVICE_NAME: 'edgefetch-go-hub',
      },
    });
    const agent = await connectHeaderMockAgent({ port: goHub.port, agentToken, siteId: 'go-hub-mock-1' });

    try {
      const authz = { authorization: `Bearer ${callerToken}` };
      const calls = [
        { method: 'GET', path: '/v1/capabilities' },
        { method: 'GET', path: '/v1/extractors' },
        { method: 'POST', path: '/v1/scrape', body: { url: 'https://t1-b1.example.com/page' } },
        { method: 'POST', path: '/v1/map', body: { url: 'https://t1-b1.example.com' } },
        { method: 'POST', path: '/mcp', body: { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'find_extractors', arguments: {} } } },
        { method: 'POST', path: '/mcp', body: { jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'scrape', arguments: { url: 'https://t1-b1.example.com/mcp-page' } } } },
      ];

      for (const c of calls) {
        const { traceId, traceparent } = makeTraceIds('01');
        const res = await fetch(`${goHub.baseUrl}${c.path}`, {
          method: c.method,
          headers: { ...authz, traceparent, ...(c.body ? { 'content-type': 'application/json' } : {}) },
          ...(c.body ? { body: JSON.stringify(c.body) } : {}),
        });
        assert.equal(res.status, 200, `[F7/M2] Go Hub ${c.path} returned ${res.status}`);
        assertTraceHeaders(res, { expectedTraceId: traceId, tag: `[F7/M2 ${c.path}]` });

        await collector.waitForSpans((e) => e.some((x) => x.span.traceId === traceId && x.serviceName === 'edgefetch-go-hub'), 3000);
        const spans = collector.findByTraceId(traceId).filter((e) => e.serviceName === 'edgefetch-go-hub');
        assert.ok(spans.length >= 1, `[F7/M2] Go Hub emitted 0 OTLP spans for ${c.path}`);
        for (const s of spans) validateOtlpSpan(s.span, `[F7/M2 ${c.path}]`);
      }
    } finally {
      await agent.close();
      await goHub.close();
      await collector.close();
    }
  });

  test('T1-B2: Go --mode=hub Declarative Twin edgefetch.adapter_id & Single TraceContext [F7/M2]', async () => {
    const collector = await startMockOtlpCollector();
    const { callerToken, agentToken } = makeTokens();
    const goHub = await startGoHub({
      bin: goBin,
      args: ['--mode=hub', '--addr=127.0.0.1:{PORT}'],
      env: {
        EDGEFETCH_CALLER_TOKEN: callerToken,
        EDGEFETCH_AGENT_TOKEN: agentToken,
        OTEL_EXPORTER_OTLP_ENDPOINT: collector.endpoint,
        OTEL_SERVICE_NAME: 'edgefetch-go-hub',
      },
    });
    const agent = await connectHeaderMockAgent({ port: goHub.port, agentToken, siteId: 'go-hub-twin' });

    try {
      const { traceId, traceparent } = makeTraceIds('01');
      const res = await fetch(`${goHub.baseUrl}/v1/scrape`, {
        method: 'POST',
        headers: { authorization: `Bearer ${callerToken}`, 'content-type': 'application/json', traceparent },
        body: JSON.stringify({ url: 'https://rubygems.org/gems/rails' }),
      });
      assert.equal(res.status, 200);
      assertTraceHeaders(res, { expectedTraceId: traceId, tag: '[F7/M2]' });
      const body = await res.json();
      assert.equal(body.extractorId, 'rubygems');

      await collector.waitForSpans((e) => e.some((x) => x.span.traceId === traceId && getOtlpAttrValue(x.span.attributes, 'edgefetch.adapter_id') === 'rubygems'), 3000);
      const twinSpan = collector.findByTraceId(traceId).find((e) => getOtlpAttrValue(e.span.attributes, 'edgefetch.adapter_id') === 'rubygems');
      assert.ok(twinSpan, '[F7/M2] Go Hub OTLP span missing edgefetch.adapter_id="rubygems"');
    } finally {
      await agent.close();
      await goHub.close();
      await collector.close();
    }
  });

  test('T1-B3: Go --mode=mcp (stdio) Pure JSON-RPC 2.0 + OTLP Export [F8/M2]', async () => {
    const collector = await startMockOtlpCollector();
    try {
      const out = await runMcpStdioSession({
        bin: goBin,
        args: ['--mode=mcp'],
        env: {
          OTEL_EXPORTER_OTLP_ENDPOINT: collector.endpoint,
          OTEL_SERVICE_NAME: 'edgefetch-mcp-stdio',
        },
        requests: [
          { jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-03-26' } },
          { jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} },
          { jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'doctor', arguments: {} } },
        ],
      });
      assert.equal(out.exitCode, 0, `[F8/M2] --mode=mcp exited ${out.exitCode}: ${out.stderr}`);
      assert.equal(out.parsedLines.length, 3, `[F8/M2] expected 3 JSON-RPC lines on stdout, got ${out.parsedLines.length}`);
      assert.equal(out.parsedLines[0].id, 1);
      assert.ok(Array.isArray(out.parsedLines[1].result?.tools), '[F8/M2] tools/list missing tools array');
      assert.equal(out.parsedLines[2].id, 3);

      await collector.waitForSpans((e) => e.some((x) => x.serviceName === 'edgefetch-mcp-stdio'), 3000);
      const mcpSpans = collector.entries.filter((e) => e.serviceName === 'edgefetch-mcp-stdio');
      assert.ok(mcpSpans.length >= 1, '[F8/M2] --mode=mcp exported 0 spans to OTLP collector');
      for (const s of mcpSpans) validateOtlpSpan(s.span, '[F8/M2]');
    } finally {
      await collector.close();
    }
  });

  test('T1-B4: Go --mode=agent + --allow-private Cross-Process Span Linkage [F9/F10/M2]', async () => {
    const collector = await startMockOtlpCollector();
    const origin = await startMockOrigin();
    const goHub = await startGoHub({
      bin: goBin,
      args: ['serve', '--port={PORT}', '--allow-private'],
      env: {
        OTEL_EXPORTER_OTLP_ENDPOINT: collector.endpoint,
        OTEL_SERVICE_NAME: 'edgefetch-go-hub',
      },
      healthPath: '/health',
    });
    const { agentToken } = makeTokens();
    // Also verify --mode=agent --allow-private against Portable Hub cross-process span linkage
    const pHub = await startTestHub({
      AGENT_TOKEN: agentToken,
      OTEL_EXPORTER_OTLP_ENDPOINT: collector.endpoint,
      OTEL_SERVICE_NAME: 'edgefetch-hub',
    }, suiteTmpDir);
    const goAgent = await startGoAgent({
      bin: goBin,
      hubUrl: pHub.baseUrl,
      agentToken,
      siteId: 'go-agent-b4',
      allowPrivate: true,
      callerToken: pHub.callerToken,
      env: {
        OTEL_EXPORTER_OTLP_ENDPOINT: collector.endpoint,
        OTEL_SERVICE_NAME: 'edgefetch-agent-go-agent-b4',
      },
    });

    try {
      const { traceId, traceparent } = makeTraceIds('01');
      // 1) Cross-process Portable Hub -> Go Agent dispatch span linkage
      const res = await fetch(`${pHub.baseUrl}/v1/scrape`, {
        method: 'POST',
        headers: {
          authorization: `Bearer ${pHub.callerToken}`,
          'content-type': 'application/json',
          traceparent,
        },
        body: JSON.stringify({ url: 'https://t1-b4.invalid/page', site: 'go-agent-b4', target: 'agent' }),
      });
      assertTraceHeaders(res, { expectedTraceId: traceId, tag: '[F1/M1]' });

      await collector.waitForSpans((entries) => {
        const byTrace = entries.filter((e) => e.span.traceId === traceId);
        return byTrace.some((e) => e.serviceName === 'edgefetch-hub' && e.span.name === 'edgefetch.dispatch') &&
          byTrace.some((e) => e.serviceName === 'edgefetch-agent-go-agent-b4' && e.span.name === 'edgefetch.go.batch');
      }, 4500);

      const traceSpans = collector.findByTraceId(traceId);
      const hubDispatch = traceSpans.find((e) => e.serviceName === 'edgefetch-hub' && e.span.name === 'edgefetch.dispatch');
      const goBatch = traceSpans.find((e) => e.serviceName === 'edgefetch-agent-go-agent-b4' && e.span.name === 'edgefetch.go.batch');
      const goFetch = traceSpans.find((e) => e.serviceName === 'edgefetch-agent-go-agent-b4' && e.span.name.startsWith('edgefetch.go.fetch.'));

      assert.ok(hubDispatch, '[F1/M1] missing edgefetch.dispatch span');
      assert.ok(goBatch, '[F10/M2] missing Go agent edgefetch.go.batch span');
      assert.ok(goFetch, '[F10/M2] missing Go agent edgefetch.go.fetch.* span');
      assert.equal(goBatch.span.parentSpanId, hubDispatch.span.spanId, '[F1/F10] Go batch parentSpanId !== Hub dispatch spanId');
      assert.equal(goFetch.span.parentSpanId, goBatch.span.spanId, 'Go fetch parentSpanId !== Go batch spanId');

      // 2) Also verify --allow-private actually fetches local http://127.0.0.1 origin via Go serve
      const rServe = await fetch(`${goHub.baseUrl}/v1/scrape`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ url: `${origin.url}/page` }),
      });
      assert.equal(rServe.status, 200);
      assert.ok(origin.recorded.length >= 1, 'local mock origin should have been fetched');
    } finally {
      await goAgent.close();
      await pHub.close();
      await goHub.close();
      await origin.close();
      await collector.close();
    }
  });

  test('T1-B5: Go edgefetch.browser.render Child Span [F9/M2]', async () => {
    const collector = await startMockOtlpCollector();
    const origin = await startMockOrigin();
    const goServe = await startGoHub({
      bin: goBin,
      args: ['serve', '--port={PORT}', '--allow-private'],
      env: {
        OTEL_EXPORTER_OTLP_ENDPOINT: collector.endpoint,
        OTEL_SERVICE_NAME: 'edgefetch-serve-render',
        ...(process.platform === 'linux' ? { EDGEFETCH_ALLOW_NO_SANDBOX: '1' } : {}),
      },
      healthPath: '/health',
    });

    try {
      const { traceId, traceparent } = makeTraceIds('01');
      const res = await fetch(`${goServe.baseUrl}/v1/scrape`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', traceparent },
        body: JSON.stringify({ url: `${origin.url}/spa`, renderMode: 'always' }),
      });
      const body = await res.json();
      assert.equal(res.status, 200, `[F9/M2] browser render scrape failed (${res.status}): ${JSON.stringify(body)}`);
      assert.equal(body.rendered, true, `[F9/M2] expected rendered=true from browser render: ${JSON.stringify(body)}`);

      await collector.waitForSpans((e) => e.some((x) => x.span.traceId === traceId && x.span.name === 'edgefetch.browser.render'), 4500);
      const renderSpan = collector.findByTraceId(traceId).find((e) => e.span.name === 'edgefetch.browser.render');
      assert.ok(renderSpan, '[F9/M2] missing edgefetch.browser.render child span');
      validateOtlpSpan(renderSpan.span, '[F9/M2]');
      assert.ok(
        BigInt(renderSpan.span.endTimeUnixNano) > BigInt(renderSpan.span.startTimeUnixNano),
        '[F9/M2] edgefetch.browser.render duration must be > 0',
      );
    } finally {
      await goServe.close();
      await origin.close();
      await collector.close();
    }
  });

  test('T1-B6: Go serve Mode OTLP Export [F8/M2]', async () => {
    const collector = await startMockOtlpCollector();
    const origin = await startMockOrigin();
    const goServe = await startGoHub({
      bin: goBin,
      args: ['serve', '--port={PORT}', '--allow-private'],
      env: {
        OTEL_EXPORTER_OTLP_ENDPOINT: collector.endpoint,
        OTEL_SERVICE_NAME: 'edgefetch-serve-test',
      },
      healthPath: '/health',
    });

    try {
      const { traceId, traceparent } = makeTraceIds('01');
      const res = await fetch(`${goServe.baseUrl}/v1/scrape`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', traceparent },
        body: JSON.stringify({ url: `${origin.url}/page` }),
      });
      assert.equal(res.status, 200);
      assertTraceHeaders(res, { expectedTraceId: traceId, tag: '[F8/M2 serve]' });

      await collector.waitForSpans((e) => e.some((x) => x.span.traceId === traceId && x.serviceName === 'edgefetch-serve-test'), 3500);
      const spans = collector.findByTraceId(traceId).filter((e) => e.serviceName === 'edgefetch-serve-test');
      assert.ok(spans.length >= 1, '[F8/M2] edgefetch serve exported 0 OTLP spans');
      for (const s of spans) validateOtlpSpan(s.span, '[F8/M2 serve]');
    } finally {
      await goServe.close();
      await origin.close();
      await collector.close();
    }
  });
});

describe('Tier 1 — Area C: OAuth 2.1, /admin, RFC 9421 BotAuth, Twins, Content-Signal & 402', () => {
  test('T1-C1: Full OAuth 2.1 PKCE S256 Lifecycle + Audit Spans [F4/M1]', async () => {
    const collector = await startMockOtlpCollector();
    const hub = await startTestHub({
      OTEL_EXPORTER_OTLP_ENDPOINT: collector.endpoint,
      OTEL_SERVICE_NAME: 'edgefetch-hub',
    }, suiteTmpDir);

    try {
      const pr = await fetch(`${hub.baseUrl}/.well-known/oauth-protected-resource`);
      assert.equal(pr.status, 200);
      const as = await fetch(`${hub.baseUrl}/.well-known/oauth-authorization-server`);
      assert.equal(as.status, 200);

      const flow = await runOAuthPkceFlow({ baseUrl: hub.baseUrl, callerToken: hub.callerToken });
      const accessTok = flow.tokens.access_token;
      const refreshTok = flow.tokens.refresh_token;
      assert.ok(accessTok.startsWith('efa_') && refreshTok.startsWith('efr_'));

      // Use OAuth token on /mcp
      const mcpRes = await fetch(`${hub.baseUrl}/mcp`, {
        method: 'POST',
        headers: { authorization: `Bearer ${accessTok}`, 'content-type': 'application/json', accept: 'application/json' },
        body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'list_agents', arguments: {} } }),
      });
      assert.equal(mcpRes.status, 200);

      // Refresh rotation
      const refRes = await fetch(`${hub.baseUrl}/oauth/token`, {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          grant_type: 'refresh_token',
          refresh_token: refreshTok,
          client_id: flow.client.client_id,
        }).toString(),
      });
      assert.equal(refRes.status, 200);
      const rotated = await refRes.json();
      assert.notEqual(rotated.refresh_token, refreshTok);

      // Revoke
      const revRes = await fetch(`${hub.baseUrl}/oauth/revoke`, {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ token: rotated.access_token }).toString(),
      });
      assert.equal(revRes.status, 200);

      const afterRev = await fetch(`${hub.baseUrl}/mcp`, {
        method: 'POST',
        headers: { authorization: `Bearer ${rotated.access_token}`, 'content-type': 'application/json' },
        body: JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'ping', params: {} }),
      });
      assert.equal(afterRev.status, 401);

      await collector.waitForSpans((e) => e.some((x) => x.span.name.startsWith('edgefetch.oauth.')), 3500);
      const oauthSpans = collector.entries.filter((e) => e.span.name.startsWith('edgefetch.oauth.'));
      assert.ok(oauthSpans.length >= 3, `[F4/M1] expected >=3 edgefetch.oauth.* audit spans, got ${oauthSpans.length}`);
      assertNoLeakedSecrets(collector.entries, [
        hub.callerToken,
        flow.code,
        flow.codeVerifier,
        accessTok,
        refreshTok,
        rotated.access_token,
        rotated.refresh_token,
      ], '[F4/M1 oauth]');
    } finally {
      await hub.close();
      await collector.close();
    }
  });

  test('T1-C2: /admin Control Center Lifecycle + Audit Spans [F4/M1]', async () => {
    const collector = await startMockOtlpCollector();
    const hub = await startTestHub({
      OTEL_EXPORTER_OTLP_ENDPOINT: collector.endpoint,
      OTEL_SERVICE_NAME: 'edgefetch-hub',
    }, suiteTmpDir);
    const agent = await connectMockAgent({ port: hub.port, agentToken: hub.agentToken, siteId: 'admin-site' });

    try {
      const sess = await adminLogin(hub.baseUrl, hub.callerToken);

      const stateRes = await fetch(`${hub.baseUrl}/admin/api/state`, { headers: { cookie: sess.cookie } });
      assert.equal(stateRes.status, 200);
      const stateJson = await stateRes.json();
      assert.ok(Array.isArray(stateJson.agents));

      const fetchRes = await fetch(`${hub.baseUrl}/admin/api/fetch`, {
        method: 'POST',
        headers: { cookie: sess.cookie, 'x-csrf-token': sess.csrf, 'content-type': 'application/json' },
        body: JSON.stringify({ url: 'https://t1-c2.example.com/admin-test', kind: 'scrape', target: 'agent' }),
      });
      assert.equal(fetchRes.status, 200);

      const affRes = await fetch(`${hub.baseUrl}/admin/api/affinity/clear`, {
        method: 'POST',
        headers: { cookie: sess.cookie, 'x-csrf-token': sess.csrf, 'content-type': 'application/json' },
        body: JSON.stringify({}),
      });
      assert.equal(affRes.status, 200);

      const evRes = await fetch(`${hub.baseUrl}/admin/api/events/clear`, {
        method: 'POST',
        headers: { cookie: sess.cookie, 'x-csrf-token': sess.csrf, 'content-type': 'application/json' },
        body: JSON.stringify({}),
      });
      assert.equal(evRes.status, 200);

      const outRes = await fetch(`${hub.baseUrl}/admin/logout`, {
        method: 'POST',
        redirect: 'manual',
        headers: { cookie: sess.cookie, 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ csrf: sess.csrf }).toString(),
      });
      assert.equal(outRes.status, 302);

      await collector.waitForSpans((e) => e.some((x) => x.span.name.startsWith('edgefetch.admin.')), 3500);
      const adminSpans = collector.entries.filter((e) => e.span.name.startsWith('edgefetch.admin.'));
      assert.ok(adminSpans.length >= 3, `[F4/M1] expected >=3 edgefetch.admin.* audit spans, got ${adminSpans.length}`);
      assertNoLeakedSecrets(collector.entries, [hub.callerToken, sess.cookieVal, sess.csrf], '[F4/M1 admin]');
    } finally {
      await agent.close();
      await hub.close();
      await collector.close();
    }
  });

  test('T1-C3: RFC 9421 bot_auth.signed Attribute & Cross-Language Go<->TS Signature Verification [F3/F9/F17]', async () => {
    const collector = await startMockOtlpCollector();
    const kp = generateEd25519Keypair();
    const origin = await startMockOrigin();
    const { callerToken, agentToken } = makeTokens();

    const goHub = await startGoHub({
      bin: goBin,
      args: ['--mode=hub', '--addr=127.0.0.1:{PORT}', '--allow-private'],
      env: {
        EDGEFETCH_CALLER_TOKEN: callerToken,
        EDGEFETCH_AGENT_TOKEN: agentToken,
        EDGEFETCH_BOT_SIGNING_KEY: kp.privateKeySeed,
        OTEL_EXPORTER_OTLP_ENDPOINT: collector.endpoint,
        OTEL_SERVICE_NAME: 'edgefetch-go-hub',
      },
    });
    const goHubSigner = await startGoHub({
      bin: goBin,
      args: ['--mode=hub', '--addr=127.0.0.1:{PORT}', '--allow-private'],
      env: {
        EDGEFETCH_CALLER_TOKEN: callerToken,
        EDGEFETCH_AGENT_TOKEN: agentToken,
        EDGEFETCH_BOT_SIGNING_KEY: kp.privateKeySeed,
        EDGEFETCH_BOT_DIRECTORY_URL: `${goHub.baseUrl}/.well-known/http-message-signatures-directory`,
        OTEL_EXPORTER_OTLP_ENDPOINT: collector.endpoint,
        OTEL_SERVICE_NAME: 'edgefetch-hub-botauth',
      },
    });

    const tsHub = await startTestHub({
      BOT_SIGNING_PRIVATE_KEY: kp.privateKeySeed,
      OTEL_EXPORTER_OTLP_ENDPOINT: collector.endpoint,
      OTEL_SERVICE_NAME: 'edgefetch-hub',
    }, suiteTmpDir);

    try {
      // 1) Verify Go Hub directory response using TS verifyDirectoryResponseSignature
      const dirUrl = `${goHub.baseUrl}/.well-known/http-message-signatures-directory`;
      const goDirRes = await fetch(dirUrl);
      assert.equal(goDirRes.status, 200);
      const goDirCheck = await hubBotAuth.verifyDirectoryResponseSignature({
        requestUrl: dirUrl,
        response: goDirRes,
        publicKeyB64Url: kp.publicKeyB64Url,
      });
      assert.equal(goDirCheck.ok, true, `TS failed to verify Go Hub directory signature: ${goDirCheck.reason}`);

      // 2) Verify TS Hub directory response using TS verifyDirectoryResponseSignature & Go keygen thumbprint match
      const tsDirUrl = `${tsHub.baseUrl}/.well-known/http-message-signatures-directory`;
      const tsDirRes = await fetch(tsDirUrl);
      assert.equal(tsDirRes.status, 200);
      const tsDirJson = await tsDirRes.clone().json();
      const tsDirCheck = await hubBotAuth.verifyDirectoryResponseSignature({
        requestUrl: tsDirUrl,
        response: tsDirRes,
        publicKeyB64Url: kp.publicKeyB64Url,
      });
      assert.equal(tsDirCheck.ok, true, `TS directory signature check failed: ${tsDirCheck.reason}`);
      const goDirJson = await (await fetch(dirUrl)).json();
      assert.equal(tsDirJson.keys[0].kid, goDirJson.keys[0].kid, 'RFC 7638 JWK thumbprint mismatch between TS and Go');

      const botJson = await (await fetch(`${tsHub.baseUrl}/.well-known/edgefetch-bot.json`)).json();
      assert.equal(botJson.webBotAuth.directorySelfSigned, true);

      // 3) Go Hub/Agent signs outbound request to local origin -> TS verifyBotRequestSignature verifies it
      const { traceId, traceparent } = makeTraceIds('01');
      const sRes = await fetch(`${goHubSigner.baseUrl}/v1/scrape`, {
        method: 'POST',
        headers: { authorization: `Bearer ${callerToken}`, 'content-type': 'application/json', traceparent },
        body: JSON.stringify({ url: `${origin.url}/signed` }),
      });
      assert.equal(sRes.status, 200);
      const signedHit = origin.recorded.find((r) => r.url === '/signed');
      assert.ok(signedHit, 'origin did not receive /signed request');
      assert.ok(signedHit.headers['signature-input'] && signedHit.headers.signature, 'Go outbound request missing RFC 9421 headers');

      const reqObj = new Request(`${origin.url}/signed`, { method: 'GET', headers: signedHit.headers });
      const tsVerifyGoReq = await hubBotAuth.verifyBotRequestSignature(reqObj, kp.publicKeyB64Url);
      assert.equal(tsVerifyGoReq.ok, true, `TS failed to verify Go outbound RFC 9421 signature: ${tsVerifyGoReq.reason}`);

      // 4) TS signs outbound request -> verify kid & Ed25519 signature match Go contract
      const tsSignedHdrs = await hubBotAuth.signOutboundBotHeaders({
        url: `${origin.url}/signed`,
        method: 'GET',
        privateKeyEncoded: kp.privateKeySeed,
        directoryUrl: dirUrl,
      });
      const tsReqVerify = await hubBotAuth.verifyBotRequestSignature(
        new Request(`${origin.url}/signed`, { method: 'GET', headers: tsSignedHdrs }),
        kp.publicKeyB64Url,
      );
      assert.equal(tsReqVerify.ok, true);
      assert.equal(tsReqVerify.kid, goDirJson.keys[0].kid);

      // 5) Assert bot_auth.signed OTLP span attribute on Go signed fetch
      await collector.waitForSpans((e) =>
        e.some((x) => x.span.traceId === traceId && getOtlpAttrValue(x.span.attributes, 'bot_auth.signed') === true),
      3500);
      const botSpan = collector.findByTraceId(traceId).find((e) => getOtlpAttrValue(e.span.attributes, 'bot_auth.signed') === true);
      assert.ok(botSpan, '[F3/F9] OTLP span missing bot_auth.signed=true attribute');
    } finally {
      await tsHub.close();
      await goHubSigner.close();
      await goHub.close();
      await origin.close();
      await collector.close();
    }
  });

  test('T1-C4: edgefetch.adapter_id Span Attribute across YAML & TS Twins [F3/M1]', async () => {
    const collector = await startMockOtlpCollector();
    const hub = await startTestHub({ OTEL_EXPORTER_OTLP_ENDPOINT: collector.endpoint, OTEL_SERVICE_NAME: 'edgefetch-hub' }, suiteTmpDir);
    const agent = await connectMockAgent({ port: hub.port, agentToken: hub.agentToken, siteId: 't1-c4' });

    try {
      const cases = [
        { url: 'https://rubygems.org/gems/rails', expectedId: 'rubygems' },
        { url: 'https://dev.to/alice/edgefetch-guide', expectedId: 'dev-to' },
        { url: 'https://huggingface.co/openai/whisper-large-v3', expectedId: 'huggingface-card' },
        { url: 'https://www.npmjs.com/package/esbuild', expectedId: 'npm-registry' },
        { url: 'https://crates.io/crates/serde', expectedId: 'crates-io' },
      ];

      for (const tc of cases) {
        const { traceId, traceparent } = makeTraceIds('01');
        const res = await fetch(`${hub.baseUrl}/v1/scrape`, {
          method: 'POST',
          headers: { authorization: `Bearer ${hub.callerToken}`, 'content-type': 'application/json', traceparent },
          body: JSON.stringify({ url: tc.url }),
        });
        assert.equal(res.status, 200, `${tc.url} returned ${res.status}`);
        const json = await res.json();
        assert.equal(json.extractorId, tc.expectedId, `expected extractorId=${tc.expectedId}, got ${json.extractorId}`);

        await collector.waitForSpans((e) =>
          e.some((x) => x.span.traceId === traceId && getOtlpAttrValue(x.span.attributes, 'edgefetch.adapter_id') === tc.expectedId),
        );
        const span = collector.findByTraceId(traceId).find((e) => getOtlpAttrValue(e.span.attributes, 'edgefetch.adapter_id') === tc.expectedId);
        assert.ok(span, `[F3/M1] OTLP span missing edgefetch.adapter_id="${tc.expectedId}" for ${tc.url}`);
      }
    } finally {
      await agent.close();
      await hub.close();
      await collector.close();
    }
  });

  test('T1-C5: Content-Signal: ai-input=no End-to-End Propagation [F16/R4]', async () => {
    const collector = await startMockOtlpCollector();
    const csOrigin = await startMockOrigin((req, res) => {
      if (req.url === '/robots.txt') {
        res.writeHead(200, { 'content-type': 'text/plain' });
        res.end('User-agent: *\nContent-Signal: ai-input=no\n');
        return;
      }
      res.writeHead(200, { 'content-type': 'text/html' });
      res.end('<html><body>Should never be fetched</body></html>');
    });
    const goServe = await startGoHub({
      bin: goBin,
      args: ['serve', '--port={PORT}', '--allow-private'],
      env: { OTEL_EXPORTER_OTLP_ENDPOINT: collector.endpoint, OTEL_SERVICE_NAME: 'edgefetch-serve-cs' },
      healthPath: '/health',
    });

    const hub = await startTestHub({ OTEL_EXPORTER_OTLP_ENDPOINT: collector.endpoint }, suiteTmpDir);
    const agent = await connectMockAgent({
      port: hub.port,
      agentToken: hub.agentToken,
      siteId: 'cs-mock',
      handler: async () => ({
        status: 451,
        outcome: 'content_signal_disallowed',
        problem: 'content-signal: ai-input=no in robots.txt',
      }),
    });

    try {
      // 1) Real Go crawler against local mock origin with Content-Signal: ai-input=no
      const tpGo = makeTraceIds('01');
      const goRes = await fetch(`${goServe.baseUrl}/v1/scrape`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', traceparent: tpGo.traceparent },
        body: JSON.stringify({ url: `${csOrigin.url}/article` }),
      });
      const goJson = await goRes.json();
      assert.equal(csOrigin.recorded.some((r) => r.url === '/article'), false, 'Go agent must NOT fetch /article when Content-Signal: ai-input=no');
      assert.ok(
        goJson.outcome === 'content_signal_disallowed' ||
        goJson.blocked?.reason === 'content-signal' ||
        String(goJson.problem || '').toLowerCase().includes('content-signal: ai-input=no') ||
        goRes.status >= 400,
        `expected content-signal block, got ${goRes.status} ${JSON.stringify(goJson)}`,
      );

      // 2) Portable Hub propagation + OTLP crawler.outcome attribute
      const tpHub = makeTraceIds('01');
      const hubRes = await fetch(`${hub.baseUrl}/v1/scrape`, {
        method: 'POST',
        headers: { authorization: `Bearer ${hub.callerToken}`, 'content-type': 'application/json', traceparent: tpHub.traceparent },
        body: JSON.stringify({ url: 'https://cs-blocked.example.com/article' }),
      });
      assert.ok(hubRes.status === 422 || hubRes.status === 451, `[F16/M1] expected 422 or 451 for content-signal block, got ${hubRes.status}`);
      const hubJson = await hubRes.json();
      assert.equal(hubJson.ok, false, '[F16/M1] expected hubJson.ok === false on content-signal block');
      assert.equal(hubJson.blocked?.reason, 'content-signal');
      await collector.waitForSpans((e) =>
        e.some((x) => x.span.traceId === tpHub.traceId && getOtlpAttrValue(x.span.attributes, 'crawler.outcome') === 'content_signal_disallowed'),
      );
      assert.ok(
        collector.findByTraceId(tpHub.traceId).some((e) => getOtlpAttrValue(e.span.attributes, 'crawler.outcome') === 'content_signal_disallowed'),
        '[F16/M1] missing crawler.outcome="content_signal_disallowed" on OTLP span',
      );
    } finally {
      await agent.close();
      await hub.close();
      await goServe.close();
      await csOrigin.close();
      await collector.close();
    }
  });

  test('T1-C6: HTTP 402 Payment Required (x402) Propagation [F16/R4]', async () => {
    const collector = await startMockOtlpCollector();
    const origin = await startMockOrigin();
    const goServe = await startGoHub({
      bin: goBin,
      args: ['serve', '--port={PORT}', '--allow-private'],
      env: { OTEL_EXPORTER_OTLP_ENDPOINT: collector.endpoint, OTEL_SERVICE_NAME: 'edgefetch-serve-402' },
      healthPath: '/health',
    });
    const hub = await startTestHub({ OTEL_EXPORTER_OTLP_ENDPOINT: collector.endpoint }, suiteTmpDir);
    const agent = await connectMockAgent({
      port: hub.port,
      agentToken: hub.agentToken,
      siteId: 'x402-mock',
      handler: async () => ({
        status: 402,
        outcome: 'payment_required',
        problem: 'HTTP 402 Payment Required',
        paymentHeaders: {
          'payment-required': Buffer.from(JSON.stringify({ amount: '1000000', asset: 'USDC', network: 'base', scheme: 'exact' })).toString('base64'),
          'www-authenticate': 'x402 currency="USD" price="1.00 USD"',
        },
      }),
    });

    try {
      const tpGo = makeTraceIds('01');
      const goRes = await fetch(`${goServe.baseUrl}/v1/scrape`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', traceparent: tpGo.traceparent },
        body: JSON.stringify({ url: `${origin.url}/402` }),
      });
      const goJson = await goRes.json();
      assert.ok(goRes.status === 402 || goJson.status === 402, `expected 402 status from Go, got http=${goRes.status} body=${JSON.stringify(goJson)}`);

      const tpHub = makeTraceIds('01');
      const hubRes = await fetch(`${hub.baseUrl}/v1/scrape`, {
        method: 'POST',
        headers: { authorization: `Bearer ${hub.callerToken}`, 'content-type': 'application/json', traceparent: tpHub.traceparent },
        body: JSON.stringify({ url: 'https://paywall.example.com/premium' }),
      });
      assert.equal(hubRes.status, 402);
      const hubJson = await hubRes.json();
      assert.equal(hubJson.blocked?.reason, 'payment_required');
      assert.ok(hubJson.blocked?.terms?.asset === 'USDC' || hubJson.blocked?.price, `missing parsed x402 terms: ${JSON.stringify(hubJson.blocked)}`);

      await collector.waitForSpans((e) =>
        e.some((x) => x.span.traceId === tpHub.traceId && getOtlpAttrValue(x.span.attributes, 'http.response.status_code') === 402),
      );
      assert.ok(
        collector.findByTraceId(tpHub.traceId).some((e) => getOtlpAttrValue(e.span.attributes, 'http.response.status_code') === 402),
        '[F16/M1] OTLP span missing http.response.status_code=402',
      );
    } finally {
      await agent.close();
      await hub.close();
      await goServe.close();
      await origin.close();
      await collector.close();
    }
  });
});

describe('Tier 1 — Area D: EdgeFetchClient TS & Python traceparent & lastTraceId', () => {
  test('T1-D1: TS SDK Client-Level & Per-Call traceparent + lastTraceId [F13/M3]', async () => {
    const observed = [];
    const srv = await startHttpServer((req, res) => {
      const chunks = [];
      req.on('data', (c) => chunks.push(c));
      req.on('end', () => {
        const bodyText = Buffer.concat(chunks).toString('utf8');
        const parsed = parseTraceparentHeader(req.headers.traceparent || '') || makeTraceIds('01');
        observed.push({ url: req.url, traceparent: req.headers.traceparent, bodyText });
        res.writeHead(200, {
          'content-type': 'application/json',
          'x-trace-id': parsed.traceId,
          traceparent: `00-${parsed.traceId}-${randomBytes(8).toString('hex')}-01`,
        });
        res.end(JSON.stringify({ ok: true }));
      });
    });

    try {
      const tp1 = makeTraceIds('01');
      const tp2 = makeTraceIds('01');
      const client = new tsSdk.EdgeFetchClient({ baseUrl: srv.url, token: 'tok-ts-d1', traceparent: tp1.traceparent });

      await client.capabilities();
      assert.equal(client.lastTraceId, tp1.traceId, '[F13/M3] client.lastTraceId mismatch after default traceparent');
      assert.ok(client.lastTraceparent?.includes(tp1.traceId));

      await client.scrape({ url: 'https://example.com/a' }, { traceparent: tp2.traceparent });
      assert.equal(client.lastTraceId, tp2.traceId, '[F13/M3] per-call traceparent did not override client default');
      assert.equal(observed[1].traceparent, tp2.traceparent);
      assert.equal(observed[1].bodyText.includes('traceparent'), false, '[F13/M3] traceparent leaked into JSON request body');
    } finally {
      await srv.close();
    }
  });

  test('T1-D2: Python SDK Client-Level & Per-Call traceparent + last_trace_id [F14/M3]', async () => {
    const observed = [];
    const srv = await startHttpServer((req, res) => {
      const chunks = [];
      req.on('data', (c) => chunks.push(c));
      req.on('end', () => {
        const bodyText = Buffer.concat(chunks).toString('utf8');
        const parsed = parseTraceparentHeader(req.headers.traceparent || '') || makeTraceIds('01');
        observed.push({ url: req.url, traceparent: req.headers.traceparent, bodyText });
        res.writeHead(200, {
          'content-type': 'application/json',
          'x-trace-id': parsed.traceId,
          traceparent: `00-${parsed.traceId}-${randomBytes(8).toString('hex')}-01`,
        });
        res.end(JSON.stringify({ ok: true }));
      });
    });

    try {
      const tp1 = makeTraceIds('01');
      const tp2 = makeTraceIds('01');
      const tp3 = makeTraceIds('01');
      const tp4 = makeTraceIds('01');
      const pyScript = `
import json, os
from edgefetch_client import EdgeFetchClient
c = EdgeFetchClient(token="tok-py-d2", base_url=os.environ["HUB_URL"], traceparent=os.environ["TP1"])
c.capabilities()
id1 = c.last_trace_id
id1_camel = getattr(c, "lastTraceId", None)
c.scrape("https://example.com/a", traceparent=os.environ["TP2"])
id2 = c.last_trace_id
c.jobs("engineer", traceparent=os.environ["TP3"])
id3 = c.last_trace_id
c.search("edgefetch", traceparent=os.environ["TP4"])
id4 = c.last_trace_id
print(json.dumps({"id1": id1, "id1_camel": id1_camel, "id2": id2, "id3": id3, "id4": id4}))
`;
      const { stdout } = await runPythonSdk(pyBin, pyScript, {
        HUB_URL: srv.url,
        TP1: tp1.traceparent,
        TP2: tp2.traceparent,
        TP3: tp3.traceparent,
        TP4: tp4.traceparent,
      });
      const res = JSON.parse(stdout);
      assert.equal(res.id1, tp1.traceId, '[F14/M3] Python last_trace_id mismatch for client default');
      assert.equal(res.id1_camel, tp1.traceId, '[F14/M3] Python lastTraceId property mismatch');
      assert.equal(res.id2, tp2.traceId, '[F14/M3] Python scrape per-call traceparent mismatch');
      assert.equal(res.id3, tp3.traceId, '[F14/M3] Python jobs per-call traceparent mismatch');
      assert.equal(res.id4, tp4.traceId, '[F14/M3] Python search per-call traceparent mismatch');
      for (const req of observed) {
        assert.equal(req.bodyText.includes('traceparent'), false, `[F14/M3] traceparent leaked into Python JSON body on ${req.url}`);
      }
    } finally {
      await srv.close();
    }
  });

  test('T1-D3: TS SDK All Endpoint Methods traceparent Support [F13/M3]', async () => {
    const srv = await startHttpServer((req, res) => {
      req.resume();
      req.on('end', () => {
        const parsed = parseTraceparentHeader(req.headers.traceparent || '');
        const tid = parsed ? parsed.traceId : randomBytes(16).toString('hex');
        res.writeHead(200, {
          'content-type': 'application/json',
          'x-trace-id': tid,
          traceparent: `00-${tid}-${randomBytes(8).toString('hex')}-01`,
        });
        res.end(JSON.stringify({ ok: true }));
      });
    });

    try {
      const client = new tsSdk.EdgeFetchClient({ baseUrl: srv.url, token: 'tok-ts-d3' });
      const check = async (label, fn) => {
        const { traceId, traceparent } = makeTraceIds('01');
        await fn({ traceparent });
        assert.equal(client.lastTraceId, traceId, `[F13/M3] TS ${label} did not propagate traceparent / capture lastTraceId`);
      };

      await check('capabilities', (o) => client.capabilities(o));
      await check('hosts', (o) => client.hosts(50, o));
      await check('extractors', (o) => client.extractors('jobs', o));
      await check('scrape', (o) => client.scrape({ url: 'https://example.com' }, o));
      await check('extract', (o) => client.extract({ urls: ['https://example.com'] }, o));
      await check('map', (o) => client.map({ url: 'https://example.com' }, o));
      await check('crawl', (o) => client.crawl({ url: 'https://example.com' }, o));
      await check('getCrawl', (o) => client.getCrawl('crw_1', 0, 10, o));
      await check('cancelCrawl', (o) => client.cancelCrawl('crw_1', o));
      await check('search', (o) => client.search({ query: 'q' }, o));
      await check('jobs', (o) => client.jobs({ query: 'eng' }, o));
      await check('interact', (o) => client.interact({ url: 'https://example.com' }, o));
      await check('batchScrape', (o) => client.batchScrape({ urls: ['https://example.com'] }, o));
      await check('getBatchScrape', (o) => client.getBatchScrape('bch_1', o));
      await check('cancelBatchScrape', (o) => client.cancelBatchScrape('bch_1', o));
      await check('previewCrawlParams', (o) => client.previewCrawlParams({ url: 'https://example.com', prompt: 'docs' }, o));
      await check('agent', (o) => client.agent({ prompt: 'summarize' }, o));
      await check('getAgent', (o) => client.getAgent('agt_1', o));
      await check('getAgentTrace', (o) => client.getAgentTrace('agt_1', o));
      await check('cancelAgent', (o) => client.cancelAgent('agt_1', o));
      await check('readArtifact', (o) => client.readArtifact('a'.repeat(64), 0, 1024, 'raw', o));
    } finally {
      await srv.close();
    }
  });

  test('T1-D4: Python SDK All Endpoint Methods traceparent Support [F14/M3]', async () => {
    const bodies = [];
    const srv = await startHttpServer((req, res) => {
      const chunks = [];
      req.on('data', (c) => chunks.push(c));
      req.on('end', () => {
        bodies.push(Buffer.concat(chunks).toString('utf8'));
        const parsed = parseTraceparentHeader(req.headers.traceparent || '');
        const tid = parsed ? parsed.traceId : randomBytes(16).toString('hex');
        res.writeHead(200, {
          'content-type': 'application/json',
          'x-trace-id': tid,
          traceparent: `00-${tid}-${randomBytes(8).toString('hex')}-01`,
        });
        res.end(JSON.stringify({ ok: true }));
      });
    });

    try {
      const pyScript = `
import os, uuid
from edgefetch_client import EdgeFetchClient
c = EdgeFetchClient(token="tok-py-d4", base_url=os.environ["HUB_URL"])
def tp():
    tid = uuid.uuid4().hex
    sid = uuid.uuid4().hex[:16]
    return tid, f"00-{tid}-{sid}-01"
calls = [
    ("capabilities", lambda t: c.capabilities(traceparent=t)),
    ("hosts", lambda t: c.hosts(limit=10, traceparent=t)),
    ("extractors", lambda t: c.extractors(category="jobs", traceparent=t)),
    ("scrape", lambda t: c.scrape("https://example.com", traceparent=t)),
    ("extract", lambda t: c.extract(["https://example.com"], query="x", traceparent=t)),
    ("map", lambda t: c.map("https://example.com", traceparent=t)),
    ("crawl", lambda t: c.crawl("https://example.com", traceparent=t)),
    ("get_crawl", lambda t: c.get_crawl("crw_1", traceparent=t)),
    ("search", lambda t: c.search("q", traceparent=t)),
    ("jobs", lambda t: c.jobs("eng", traceparent=t)),
    ("interact", lambda t: c.interact(url="https://example.com", traceparent=t)),
    ("batch_scrape", lambda t: c.batch_scrape(["https://example.com"], traceparent=t)),
    ("get_batch_scrape", lambda t: c.get_batch_scrape("bch_1", traceparent=t)),
    ("preview_crawl_params", lambda t: c.preview_crawl_params("https://example.com", "docs", traceparent=t)),
    ("agent", lambda t: c.agent("summarize", traceparent=t)),
    ("get_agent", lambda t: c.get_agent("agt_1", traceparent=t)),
    ("get_agent_trace", lambda t: c.get_agent_trace("agt_1", traceparent=t)),
    ("cancel_agent", lambda t: c.cancel_agent("agt_1", traceparent=t)),
    ("read_artifact", lambda t: c.read_artifact("a" * 64, traceparent=t)),
]
for name, fn in calls:
    tid, header = tp()
    fn(header)
    assert c.last_trace_id == tid, f"{name}: expected {tid}, got {c.last_trace_id}"
print("ALL_OK")
`;
      const { stdout } = await runPythonSdk(pyBin, pyScript, { HUB_URL: srv.url });
      assert.equal(stdout, 'ALL_OK', `[F14/M3] Python SDK methods check failed: ${stdout}`);
      for (const b of bodies) {
        assert.equal(b.includes('traceparent'), false, '[F14/M3] traceparent leaked into JSON body');
      }
    } finally {
      await srv.close();
    }
  });

  test('T1-D5: TS & Python SDK lastTraceId Captured on EdgeFetchError [F13/F14/M3]', async () => {
    const tid401 = randomBytes(16).toString('hex');
    const tid400 = randomBytes(16).toString('hex');
    const srv = await startHttpServer((req, res) => {
      req.resume();
      req.on('end', () => {
        const is401 = req.url.includes('hosts');
        const tid = is401 ? tid401 : tid400;
        res.writeHead(is401 ? 401 : 400, {
          'content-type': 'application/json',
          'x-trace-id': tid,
          traceparent: `00-${tid}-${randomBytes(8).toString('hex')}-01`,
        });
        res.end(JSON.stringify({ error: is401 ? 'unauthorized' : 'bad_request', message: 'error' }));
      });
    });

    try {
      const tsClient = new tsSdk.EdgeFetchClient({ baseUrl: srv.url, token: 'tok' });
      await assert.rejects(() => tsClient.hosts(), (err) => err instanceof tsSdk.EdgeFetchError && err.status === 401);
      assert.equal(tsClient.lastTraceId, tid401, '[F13/M3] TS lastTraceId missing on 401 EdgeFetchError');
      await assert.rejects(() => tsClient.scrape({ url: 'bad' }), (err) => err instanceof tsSdk.EdgeFetchError && err.status === 400);
      assert.equal(tsClient.lastTraceId, tid400, '[F13/M3] TS lastTraceId missing on 400 EdgeFetchError');

      const pyScript = `
import json, os
from edgefetch_client import EdgeFetchClient, EdgeFetchError
c = EdgeFetchClient(token="tok", base_url=os.environ["HUB_URL"])
t1 = t2 = None
try:
    c.hosts()
except EdgeFetchError as e:
    assert e.status == 401
    t1 = c.last_trace_id
try:
    c.scrape("bad")
except EdgeFetchError as e:
    assert e.status == 400
    t2 = c.last_trace_id
print(json.dumps({"t1": t1, "t2": t2}))
`;
      const { stdout } = await runPythonSdk(pyBin, pyScript, { HUB_URL: srv.url });
      const pyRes = JSON.parse(stdout);
      assert.equal(pyRes.t1, tid401, '[F14/M3] Python last_trace_id missing on 401 EdgeFetchError');
      assert.equal(pyRes.t2, tid400, '[F14/M3] Python last_trace_id missing on 400 EdgeFetchError');
    } finally {
      await srv.close();
    }
  });

  test('T1-D6: TS & Python SDK Multi-Hub HA Failover Preserves traceparent & Captures Standby lastTraceId [F13/F14/M3]', async () => {
    const primarySeen = [];
    const standbySeen = [];
    const primarySrv = await startHttpServer((req, res) => {
      req.resume();
      req.on('end', () => {
        primarySeen.push(req.headers.traceparent);
        const tid = randomBytes(16).toString('hex');
        res.writeHead(503, { 'content-type': 'application/json', 'x-trace-id': tid });
        res.end(JSON.stringify({ error: 'hub_unavailable' }));
      });
    });
    const standbyTid = randomBytes(16).toString('hex');
    const standbySrv = await startHttpServer((req, res) => {
      req.resume();
      req.on('end', () => {
        standbySeen.push(req.headers.traceparent);
        res.writeHead(200, {
          'content-type': 'application/json',
          'x-trace-id': standbyTid,
          traceparent: `00-${standbyTid}-${randomBytes(8).toString('hex')}-01`,
        });
        res.end(JSON.stringify({ ok: true }));
      });
    });

    try {
      const tp = makeTraceIds('01');
      const tsClient = new tsSdk.EdgeFetchClient({
        baseUrls: [primarySrv.url, standbySrv.url],
        token: 'tok-ha',
        traceparent: tp.traceparent,
      });
      await tsClient.capabilities();
      assert.equal(primarySeen[0], tp.traceparent);
      assert.equal(standbySeen[0], tp.traceparent);
      assert.equal(tsClient.lastTraceId, standbyTid, '[F13/M3] TS HA failover did not capture standby x-trace-id');

      const pyScript = `
import os
from edgefetch_client import EdgeFetchClient
c = EdgeFetchClient(token="tok-ha", base_urls=[os.environ["U1"], os.environ["U2"]], traceparent=os.environ["TP"])
c.capabilities()
print(c.last_trace_id)
`;
      const { stdout } = await runPythonSdk(pyBin, pyScript, { U1: primarySrv.url, U2: standbySrv.url, TP: tp.traceparent });
      assert.equal(primarySeen[1], tp.traceparent);
      assert.equal(standbySeen[1], tp.traceparent);
      assert.equal(stdout, standbyTid, '[F14/M3] Python HA failover did not capture standby x-trace-id');
    } finally {
      await Promise.all([primarySrv.close(), standbySrv.close()]);
    }
  });
});

describe('Tier 1 — Area E: all-in-one-entrypoint.sh OTLP Validation & Secret Isolation', () => {
  test('T1-E1: Valid OTLP Env Forwarding to Worker [F11/M2]', async () => {
    const run = await runEntrypointHarness({
      env: {
        EDGEFETCH_ALLOW_SHARED_UID: '1',
        OTEL_EXPORTER_OTLP_ENDPOINT: 'https://otel.example.com:4318',
        OTEL_EXPORTER_OTLP_HEADERS: 'Authorization=Bearer%20tok,x-team=abc',
        OTEL_SERVICE_NAME: 'ef-prod',
      },
    });
    try {
      assert.equal(run.exitCode, 0, `entrypoint failed: ${run.stderr}`);
      assert.ok(run.hubEnv, 'hub mock did not run');
      assert.equal(run.hubEnv.OTEL_SERVICE_NAME, 'ef-prod', '[F11/M2] OTEL_SERVICE_NAME not forwarded to Hub');
      assert.ok(run.agentEnv, 'worker mock did not run');
      assert.equal(run.agentEnv.OTEL_EXPORTER_OTLP_ENDPOINT, 'https://otel.example.com:4318');
      assert.equal(run.agentEnv.OTEL_EXPORTER_OTLP_HEADERS, 'Authorization=Bearer%20tok,x-team=abc', '[F11/M2] OTEL_EXPORTER_OTLP_HEADERS not forwarded to worker');
      assert.equal(run.agentEnv.OTEL_SERVICE_NAME, undefined, '[F11/M2] OTEL_SERVICE_NAME leaked into isolated worker env (must remain undefined so worker keeps edgefetch-agent-<siteId>)');
    } finally {
      run.cleanup();
    }
  });

  test('T1-E2: Hub-Only Secret Isolation (env -i Boundary) [F11/M2]', async () => {
    const canarySecrets = {
      CALLER_TOKEN: 'caller_secret_canary_24chars_xyz',
      EDGEFETCH_CALLER_TOKEN: 'ef_caller_secret_canary_24chars',
      OPENAI_API_KEY: 'sk-canary-openai-secret',
      ANTHROPIC_API_KEY: 'sk-ant-canary-secret',
      GEMINI_API_KEY: 'AIzaCanarySecret',
      OPENROUTER_API_KEY: 'sk-or-canary-secret',
      EDGEFETCH_LLM_API_KEY: 'sk-llm-canary-secret',
      BOT_SIGNING_PRIVATE_KEY: 'bot_priv_canary_secret_seed',
      TURSO_AUTH_TOKEN: 'turso_canary_secret',
      S3_SECRET_ACCESS_KEY: 's3_canary_secret',
      WEBHOOK_SECRET: 'whsec_canary_secret',
      SERPER_API_KEY: 'serper_canary_secret',
      BRAVE_API_KEY: 'brave_canary_secret',
      TAVILY_API_KEY: 'tavily_canary_secret',
    };
    const run = await runEntrypointHarness({
      env: {
        EDGEFETCH_ALLOW_SHARED_UID: '1',
        OTEL_EXPORTER_OTLP_ENDPOINT: 'http://127.0.0.1:4318',
        ...canarySecrets,
      },
    });
    try {
      assert.equal(run.exitCode, 0, `entrypoint failed: ${run.stderr}`);
      assert.ok(run.hubEnv && run.agentEnv, 'missing captured hub/agent env');
      assert.equal(run.hubEnv.CALLER_TOKEN, canarySecrets.CALLER_TOKEN);
      assert.equal(run.hubEnv.OPENAI_API_KEY, canarySecrets.OPENAI_API_KEY);
      for (const key of Object.keys(canarySecrets)) {
        assert.equal(run.agentEnv[key], undefined, `security breach: ${key} leaked into worker env`);
      }
      assert.ok(run.agentEnv.EDGEFETCH_AGENT_TOKEN && run.agentEnv.EDGEFETCH_AGENT_TOKEN.length >= 24);
      assert.equal(run.agentEnv.OTEL_EXPORTER_OTLP_ENDPOINT, 'http://127.0.0.1:4318');
    } finally {
      run.cleanup();
    }
  });

  test('T1-E3: Ephemeral AGENT_TOKEN Generation (>= 48 hex chars) [F11/M2]', async () => {
    const run = await runEntrypointHarness({
      env: {
        EDGEFETCH_ALLOW_SHARED_UID: '1',
        AGENT_TOKEN: '',
      },
    });
    try {
      assert.equal(run.exitCode, 0, `entrypoint failed: ${run.stderr}`);
      const hubTok = run.hubEnv?.AGENT_TOKEN || '';
      const workerTok = run.agentEnv?.EDGEFETCH_AGENT_TOKEN || '';
      assert.match(hubTok, /^[0-9a-f]{48,}$/, `expected >=48 hex ephemeral AGENT_TOKEN, got ${hubTok}`);
      assert.equal(workerTok, hubTok);
    } finally {
      run.cleanup();
    }
  });

  test('T1-E4: Non-Root UID Fail-Closed Guard [F11/M2]', async () => {
    const run = await runEntrypointHarness({
      env: {
        EDGEFETCH_ALLOW_SHARED_UID: '0',
        EDGEFETCH_DISABLE_LOCAL_AGENT: '0',
      },
    });
    try {
      assert.equal(run.exitCode, 1, `expected fail-closed exit 1, got ${run.exitCode}`);
      assert.match(run.stderr, /EDGEFETCH_ALLOW_SHARED_UID=1/);
      assert.equal(run.hubEnv, null);
      assert.equal(run.agentEnv, null);
    } finally {
      run.cleanup();
    }
  });

  test('T1-E5: EDGEFETCH_DISABLE_LOCAL_AGENT=1 Mode (Zero Worker Spawned) [F11/M2]', async () => {
    const run = await runEntrypointHarness({
      hubExitMs: 300,
      env: {
        EDGEFETCH_DISABLE_LOCAL_AGENT: '1',
      },
    });
    try {
      assert.equal(run.exitCode, 0, `entrypoint failed: ${run.stderr}`);
      assert.ok(run.hubEnv, 'Hub should start when EDGEFETCH_DISABLE_LOCAL_AGENT=1');
      assert.equal(run.agentEnv, null, 'Worker must NOT spawn when EDGEFETCH_DISABLE_LOCAL_AGENT=1');
    } finally {
      run.cleanup();
    }
  });
});

// ===========================================================================
// TIER 2 — Boundary & Corner Cases (29 Tests: T2-A1 .. T2-E5)
// ===========================================================================

describe('Tier 2 — Area A Boundaries: Portable Hub Tracing, MCP & Ingest', () => {
  test('T2-A1: Malformed & Edge traceparent Headers Mint Fresh Trace Without 500 [F1/M1]', async () => {
    const collector = await startMockOtlpCollector();
    const hub = await startTestHub({ OTEL_EXPORTER_OTLP_ENDPOINT: collector.endpoint }, suiteTmpDir);

    try {
      const malformed = [
        '',
        `00-${ALL_ZERO_32}-00f067aa0ba902b7-01`,
        `00-4bf92f3577b34da6a3ce929d0e0e4736-${ALL_ZERO_16}-01`,
        '01-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01',
        '00-zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz-00f067aa0ba902b7-01',
        `00-${'a'.repeat(4096)}-00f067aa0ba902b7-01`,
      ];
      for (const badTp of malformed) {
        const res = await fetch(`${hub.baseUrl}/v1/capabilities`, {
          headers: { authorization: `Bearer ${hub.callerToken}`, traceparent: badTp },
        });
        assert.equal(res.status, 200, `[F1/M1] malformed traceparent ${badTp.slice(0, 24)} caused status ${res.status}`);
        const hdr = assertTraceHeaders(res, { tag: '[F1/M1 malformed traceparent]' });
        assert.notEqual(hdr.traceId, '4bf92f3577b34da6a3ce929d0e0e4736');
        assert.notEqual(hdr.traceId, ALL_ZERO_32);
      }
    } finally {
      await hub.close();
      await collector.close();
    }
  });

  test('T2-A2: Unsampled Flag (-00) Preserves traceId and Exports 0 Spans [F1/M1]', async () => {
    const collector = await startMockOtlpCollector();
    const hub = await startTestHub({ OTEL_EXPORTER_OTLP_ENDPOINT: collector.endpoint }, suiteTmpDir);
    const agent = await connectMockAgent({ port: hub.port, agentToken: hub.agentToken, siteId: 't2-a2' });

    try {
      const { traceId, traceparent } = makeTraceIds('00');
      const res = await fetch(`${hub.baseUrl}/v1/scrape`, {
        method: 'POST',
        headers: { authorization: `Bearer ${hub.callerToken}`, 'content-type': 'application/json', traceparent },
        body: JSON.stringify({ url: 'https://t2-a2.example.com/unsampled' }),
      });
      assert.equal(res.status, 200);
      assertTraceHeaders(res, { expectedTraceId: traceId, expectedFlags: '00', tag: '[F1/M1 unsampled]' });
      await delay(300);
      assert.equal(
        collector.findByTraceId(traceId).length,
        0,
        '[F1/M1] unsampled -00 request must NOT export spans to OTLP collector',
      );
    } finally {
      await agent.close();
      await hub.close();
      await collector.close();
    }
  });

  test('T2-A3: Invalid OTEL_EXPORTER_OTLP_ENDPOINT & Malformed Headers Never Fail Caller [F1/M1]', async () => {
    const closedPort = await allocPort();
    const endpoints = ['ftp://bad-otel.invalid', 'not-a-url', `http://127.0.0.1:${closedPort}`];
    for (const ep of endpoints) {
      const hub = await startTestHub({
        OTEL_EXPORTER_OTLP_ENDPOINT: ep,
        OTEL_EXPORTER_OTLP_HEADERS: 'bad_no_eq,inject=a\r\nb: c,ok=1%202',
      }, suiteTmpDir);
      try {
        const { traceId, traceparent } = makeTraceIds('01');
        const res = await fetch(`${hub.baseUrl}/v1/capabilities`, {
          headers: { authorization: `Bearer ${hub.callerToken}`, traceparent },
        });
        assert.equal(res.status, 200, `[F1/M1] endpoint=${ep} broke caller request (${res.status})`);
        assertTraceHeaders(res, { expectedTraceId: traceId, tag: `[F1/M1 invalid OTLP ${ep}]` });
      } finally {
        await hub.close();
      }
    }
  });

  test('T2-A4: HTTP Error Status Trace Propagation (400, 401, 403, 404, 413, 503) [F1/M1]', async () => {
    const collector = await startMockOtlpCollector();
    const hub = await startTestHub({ OTEL_EXPORTER_OTLP_ENDPOINT: collector.endpoint }, suiteTmpDir);

    try {
      const cases = [
        {
          label: '400',
          url: `${hub.baseUrl}/v1/scrape`,
          init: { method: 'POST', headers: { authorization: `Bearer ${hub.callerToken}`, 'content-type': 'application/json' }, body: '{"url":"http://127.0.0.1/bad"}' },
          expectedStatus: 400,
        },
        {
          label: '401',
          url: `${hub.baseUrl}/v1/hosts`,
          init: { method: 'GET', headers: {} },
          expectedStatus: 401,
          unauthSuppressedOtlp: true,
        },
        {
          label: '403',
          url: `${hub.baseUrl}/mcp`,
          init: { method: 'POST', headers: { authorization: `Bearer ${hub.mcpToken}`, origin: 'https://evil.example.org', 'content-type': 'application/json' }, body: '{"jsonrpc":"2.0","id":1,"method":"ping"}' },
          expectedStatus: 403,
        },
        {
          label: '404',
          url: `${hub.baseUrl}/v1/artifacts/${'0'.repeat(64)}`,
          init: { method: 'GET', headers: { authorization: `Bearer ${hub.callerToken}` } },
          expectedStatus: 404,
        },
        {
          label: '413',
          url: `${hub.baseUrl}/v1/scrape`,
          init: { method: 'POST', headers: { authorization: `Bearer ${hub.callerToken}`, 'content-type': 'application/json' }, body: JSON.stringify({ url: 'https://example.com', pad: 'x'.repeat(1_200_000) }) },
          expectedStatus: 413,
        },
        {
          label: '503',
          url: `${hub.baseUrl}/v1/interact`,
          init: { method: 'POST', headers: { authorization: `Bearer ${hub.callerToken}`, 'content-type': 'application/json' }, body: JSON.stringify({ url: 'https://example.com' }) },
          expectedStatus: 503,
        },
      ];

      for (const tc of cases) {
        const { traceId, traceparent } = makeTraceIds('01');
        const res = await fetch(tc.url, {
          ...tc.init,
          headers: { ...(tc.init.headers || {}), traceparent },
        });
        assert.equal(res.status, tc.expectedStatus, `expected ${tc.expectedStatus} for ${tc.label}, got ${res.status}`);
        assertTraceHeaders(res, { expectedTraceId: traceId, tag: `[F1/M1 error ${tc.label}]` });

        if (tc.unauthSuppressedOtlp) {
          // Round 7 H9: unauthenticated / pre-auth 401 & 403 gate rejections preserve response trace headers
          // while suppressing outbound OTLP collector amplification.
          await delay(80);
          assert.equal(
            collector.findByTraceId(traceId).length,
            0,
            `[H9] expected zero OTLP spans for unauthenticated/pre-auth HTTP ${tc.label}`,
          );
          continue;
        }

        await collector.waitForSpans((e) => e.some((x) => x.span.traceId === traceId && x.span.name === 'edgefetch.http'));
        const httpSpan = collector.findByTraceId(traceId).find((x) => x.span.name === 'edgefetch.http');
        assert.ok(httpSpan, `[F1/M1] missing edgefetch.http span for HTTP ${tc.label}`);
        assert.equal(getOtlpAttrValue(httpSpan.span.attributes, 'http.response.status_code'), tc.expectedStatus);
        if (tc.expectedStatus >= 500) {
          assert.equal(httpSpan.span.status?.code, 2, `[F1/M1] expected status.code===2 for HTTP ${tc.label}`);
        }
      }
    } finally {
      await hub.close();
      await collector.close();
    }
  });

  test('T2-A5: Secret-Stripping on URLs, Headers & Provider Keys in OTLP Spans [F1/F3/M1]', async () => {
    const collector = await startMockOtlpCollector();
    const serperSecret = 'serper_secret_canary_999';
    const hub = await startTestHub({
      OTEL_EXPORTER_OTLP_ENDPOINT: collector.endpoint,
      SERPER_API_KEY: serperSecret,
    }, suiteTmpDir);
    const agent = await connectMockAgent({ port: hub.port, agentToken: hub.agentToken, siteId: 't2-a5' });

    try {
      const { traceId, traceparent } = makeTraceIds('01');
      const secretUrl = 'https://t2-a5.example.com/page?token=secret_123&api_key=abc_secret&code=xyz_code';
      const res = await fetch(`${hub.baseUrl}/v1/scrape`, {
        method: 'POST',
        headers: { authorization: `Bearer ${hub.callerToken}`, 'content-type': 'application/json', traceparent },
        body: JSON.stringify({ url: secretUrl }),
      });
      assert.equal(res.status, 200);

      await collector.waitForSpans((e) => e.some((x) => x.span.traceId === traceId));
      const spans = collector.findByTraceId(traceId);
      assert.ok(spans.length >= 1);
      assertNoLeakedSecrets(spans, [
        hub.callerToken,
        hub.agentToken,
        serperSecret,
        'secret_123',
        'abc_secret',
        'xyz_code',
      ], '[F1/M1 secret-strip]');
    } finally {
      await agent.close();
      await hub.close();
      await collector.close();
    }
  });

  test('T2-A6: MCP 2026-07-28 Header Mismatch, Batch Limits, Origin & respectRobots [F2/M1]', async () => {
    const hub = await startTestHub({}, suiteTmpDir);
    try {
      const post = (body, hdrs = {}) =>
        fetch(`${hub.baseUrl}/mcp`, {
          method: 'POST',
          headers: { authorization: `Bearer ${hub.mcpToken}`, 'content-type': 'application/json', accept: 'application/json', ...hdrs },
          body: typeof body === 'string' ? body : JSON.stringify(body),
        });

      const rMethodMismatch = await post(
        { jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} },
        { 'mcp-protocol-version': '2026-07-28', 'mcp-method': 'initialize' },
      );
      assert.equal(rMethodMismatch.status, 400);
      assert.equal((await rMethodMismatch.json()).error?.code, -32020);

      const rBadVer = await post(
        { jsonrpc: '2.0', id: 2, method: 'ping', params: {} },
        { 'mcp-protocol-version': '1999-01-01', 'mcp-method': 'ping' },
      );
      assert.equal(rBadVer.status, 400);
      assert.equal((await rBadVer.json()).error?.code, -32022);

      const rEmptyBatch = await post([]);
      assert.equal(rEmptyBatch.status, 400);

      const bigBatch = Array.from({ length: 21 }, (_, i) => ({ jsonrpc: '2.0', id: i + 1, method: 'ping' }));
      const rBigBatch = await post(bigBatch);
      assert.equal(rBigBatch.status, 400);

      const rTooBig = await post(JSON.stringify({ jsonrpc: '2.0', id: 9, method: 'ping', pad: 'x'.repeat(270_000) }));
      assert.equal(rTooBig.status, 413);

      const rOrigin = await post({ jsonrpc: '2.0', id: 10, method: 'ping' }, { origin: 'https://untrusted.example.org' });
      assert.equal(rOrigin.status, 403);

      const rRobots = await post({
        jsonrpc: '2.0',
        id: 11,
        method: 'tools/call',
        params: { name: 'fetch_url', arguments: { url: 'https://example.com', respectRobots: false } },
      });
      assert.equal(rRobots.status, 200);
      assert.equal((await rRobots.json()).result?.isError, true);
    } finally {
      await hub.close();
    }
  });

  test('T2-A7: /v1/ingest-tab CORS & Size Limits [F2/M1]', async () => {
    const hub = await startTestHub({}, suiteTmpDir);
    try {
      const optRes = await fetch(`${hub.baseUrl}/v1/ingest-tab`, { method: 'OPTIONS' });
      assert.equal(optRes.status, 204);
      assert.equal(optRes.headers.get('access-control-allow-origin'), '*');

      const hdrs = { authorization: `Bearer ${hub.callerToken}`, 'content-type': 'application/json' };
      const rBadUrl = await fetch(`${hub.baseUrl}/v1/ingest-tab`, {
        method: 'POST',
        headers: hdrs,
        body: JSON.stringify({ url: 'javascript:alert(1)', html: '<p>x</p>' }),
      });
      assert.equal(rBadUrl.status, 400);
      assert.equal((await rBadUrl.json()).error, 'invalid_url');

      const rEmpty = await fetch(`${hub.baseUrl}/v1/ingest-tab`, {
        method: 'POST',
        headers: hdrs,
        body: JSON.stringify({ url: 'https://example.com/empty', html: '   ' }),
      });
      assert.equal(rEmpty.status, 400);
      assert.equal((await rEmpty.json()).error, 'empty_content');

      const rTooLarge = await postRawExpectStatus(
        `${hub.baseUrl}/v1/ingest-tab`,
        hdrs,
        '{"url":"https://example.com/huge","html":"',
        4_200_000,
      );
      assert.equal(rTooLarge.status, 413);
    } finally {
      await hub.close();
    }
  });
});

describe('Tier 2 — Area B Boundaries: Go Hub, Agent SSRF, MCP Stdio & Collector Errors', () => {
  test('T2-B1: Go --mode=hub Malformed traceparent & x-trace-id Fallback [F7/M2]', async () => {
    const collector = await startMockOtlpCollector();
    const { callerToken } = makeTokens();
    const goHub = await startGoHub({
      bin: goBin,
      args: ['--mode=hub', '--addr=127.0.0.1:{PORT}'],
      env: { EDGEFETCH_CALLER_TOKEN: callerToken, OTEL_EXPORTER_OTLP_ENDPOINT: collector.endpoint },
    });
    try {
      const badRes = await fetch(`${goHub.baseUrl}/v1/capabilities`, {
        headers: { authorization: `Bearer ${callerToken}`, traceparent: '00-nothex-1234-01' },
      });
      assert.equal(badRes.status, 200);
      assertTraceHeaders(badRes, { tag: '[F7/M2 Go Hub malformed tp]' });

      const customTid = randomBytes(16).toString('hex');
      const fallbackRes = await fetch(`${goHub.baseUrl}/v1/capabilities`, {
        headers: { authorization: `Bearer ${callerToken}`, 'x-trace-id': customTid },
      });
      assert.equal(fallbackRes.status, 200);
      assertTraceHeaders(fallbackRes, { expectedTraceId: customTid, tag: '[F7/M2 Go Hub x-trace-id fallback]' });
    } finally {
      await goHub.close();
      await collector.close();
    }
  });

  test('T2-B2: Go --mode=hub Auth & Error Trace Propagation (401, 400, 404, 503) [F7/M2]', async () => {
    const collector = await startMockOtlpCollector();
    const { callerToken } = makeTokens();
    const goHub = await startGoHub({
      bin: goBin,
      args: ['--mode=hub', '--addr=127.0.0.1:{PORT}'],
      env: { EDGEFETCH_CALLER_TOKEN: callerToken, OTEL_EXPORTER_OTLP_ENDPOINT: collector.endpoint },
    });
    try {
      const cases = [
        { path: '/v1/capabilities', method: 'GET', hdrs: {}, status: 401 },
        { path: '/v1/scrape', method: 'POST', hdrs: { authorization: `Bearer ${callerToken}`, 'content-type': 'application/json' }, body: '{bad', status: 400 },
        { path: '/does-not-exist', method: 'GET', hdrs: { authorization: `Bearer ${callerToken}` }, status: 404 },
        { path: '/fetch?target=agent', method: 'POST', hdrs: { authorization: `Bearer ${callerToken}`, 'content-type': 'application/json' }, body: JSON.stringify({ maxSeconds: 10, options: { includeBody: true }, requests: [{ id: 'r1', url: 'https://t2-b2.invalid/no-agent', kind: 'scrape' }] }), status: 503 },
      ];
      for (const tc of cases) {
        const { traceId, traceparent } = makeTraceIds('01');
        const res = await fetch(`${goHub.baseUrl}${tc.path}`, {
          method: tc.method,
          headers: { ...tc.hdrs, traceparent },
          ...(tc.body ? { body: tc.body } : {}),
        });
        assert.equal(res.status, tc.status, `Go Hub ${tc.path} expected ${tc.status}, got ${res.status}`);
        assertTraceHeaders(res, { expectedTraceId: traceId, tag: `[F7/M2 Go Hub ${tc.status}]` });
        await collector.waitForSpans((e) => e.some((x) => x.span.traceId === traceId && x.span.status?.code === 2), 2500);
        assert.ok(
          collector.findByTraceId(traceId).some((x) => x.span.status?.code === 2),
          `[F7/M2] Go Hub missing status.code=2 error span for HTTP ${tc.status}`,
        );
      }
    } finally {
      await goHub.close();
      await collector.close();
    }
  });

  test('T2-B3: Go --mode=agent Default SSRF Preservation (Without --allow-private) [F10/M2]', async () => {
    const origin = await startMockOrigin();
    const hub = await startTestHub({}, suiteTmpDir);
    // Start Go agent WITHOUT --allow-private
    const goAgent = await startGoAgent({
      bin: goBin,
      hubUrl: hub.baseUrl,
      agentToken: hub.agentToken,
      siteId: 'go-ssrf-default',
      allowPrivate: false,
      callerToken: hub.callerToken,
    });
    try {
      const res = await fetch(`${hub.baseUrl}/fetch?target=agent&site=go-ssrf-default`, {
        method: 'POST',
        headers: { authorization: `Bearer ${hub.callerToken}`, 'content-type': 'application/json' },
        body: JSON.stringify({
          maxSeconds: 15,
          options: { includeBody: true, respectRobots: true },
          requests: [{ id: 'ssrf-1', url: `${origin.url}/secret-check`, kind: 'scrape' }],
        }),
      });
      // Hub itself or Go Agent rejects loopback URL; either way, local origin receives ZERO TCP connections!
      assert.ok(res.status === 200 || res.status === 400);
      if (res.status === 200) {
        const json = await res.json();
        assert.equal(json.results?.[0]?.outcome, 'error');
      }
      assert.equal(origin.recorded.length, 0, 'SSRF violation: default Go agent hit loopback origin without --allow-private!');
    } finally {
      await goAgent.close();
      await hub.close();
      await origin.close();
    }
  });

  test('T2-B4: Go mcp (stdio) Corner Cases (Invalid JSON, Notifications, Unknown Method, SSRF) [F8/M2]', async () => {
    const collector = await startMockOtlpCollector();
    try {
      const out = await runMcpStdioSession({
        bin: goBin,
        args: ['mcp'],
        env: { OTEL_EXPORTER_OTLP_ENDPOINT: collector.endpoint, OTEL_SERVICE_NAME: 'edgefetch-mcp-stdio' },
        requests: [
          '{not-json',
          { jsonrpc: '2.0', method: 'notifications/initialized' },
          { jsonrpc: '2.0', id: 2, method: 'unknown/method', params: {} },
          { jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'scrape', arguments: { url: 'http://127.0.0.1:9999/private' } } },
        ],
      });
      assert.equal(out.exitCode, 0);
      // Notification produces 0 output frames -> 3 responses for 4 inputs
      assert.equal(out.parsedLines.length, 3);
      assert.equal(out.parsedLines[0].error?.code, -32700);
      assert.equal(out.parsedLines[1].error?.code, -32601);
      assert.equal(out.parsedLines[2].result?.isError, true);
    } finally {
      await collector.close();
    }
  });

  test('T2-B5: Go Hub Tokenless Loopback CSRF Guard (serve without token) [F7/F8/M2]', async () => {
    const goServe = await startGoHub({
      bin: goBin,
      args: ['serve', '--port={PORT}'],
      healthPath: '/health',
    });
    try {
      const rEvilOrigin = await fetch(`${goServe.baseUrl}/v1/scrape`, {
        method: 'POST',
        headers: { origin: 'https://evil.test', 'content-type': 'application/json' },
        body: JSON.stringify({ url: 'https://example.com' }),
      });
      assert.equal(rEvilOrigin.status, 403);

      const rCrossSite = await fetch(`${goServe.baseUrl}/v1/scrape`, {
        method: 'POST',
        headers: { 'sec-fetch-site': 'cross-site', 'content-type': 'application/json' },
        body: JSON.stringify({ url: 'https://example.com' }),
      });
      assert.equal(rCrossSite.status, 403);

      const rTextPlain = await fetch(`${goServe.baseUrl}/v1/scrape`, {
        method: 'POST',
        headers: { 'content-type': 'text/plain' },
        body: JSON.stringify({ url: 'https://example.com' }),
      });
      assert.equal(rTextPlain.status, 415);
    } finally {
      await goServe.close();
    }
  });

  test('T2-B6: Go OTLP Collector Returning 500 or Unreachable Exits Cleanly [F7/F8/M2]', async () => {
    const collector = await startMockOtlpCollector();
    try {
      collector.setStatus(500);
      const out = await runMcpStdioSession({
        bin: goBin,
        args: ['mcp'],
        env: { OTEL_EXPORTER_OTLP_ENDPOINT: collector.endpoint },
        requests: [{ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'doctor', arguments: {} } }],
      });
      assert.equal(out.exitCode, 0);
      assert.equal(out.parsedLines.length, 1);
    } finally {
      await collector.close();
    }

    const closedPort = await allocPort();
    const outClosed = await runMcpStdioSession({
      bin: goBin,
      args: ['mcp'],
      env: { OTEL_EXPORTER_OTLP_ENDPOINT: `http://127.0.0.1:${closedPort}` },
      requests: [{ jsonrpc: '2.0', id: 1, method: 'ping', params: {} }],
    });
    assert.equal(outClosed.exitCode, 0);
  });
});

describe('Tier 2 — Area C Boundaries: OAuth, /admin, RFC 9421 & Twin Fallbacks', () => {
  test('T2-C1: OAuth PKCE, Redirect URI, Code Reuse & Refresh Replay Revocation [F4/F15]', async () => {
    const hub = await startTestHub({}, suiteTmpDir);
    try {
      // 1. Disallowed external redirect_uri
      const badReg = await fetch(`${hub.baseUrl}/oauth/register`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ client_name: 'evil', redirect_uris: ['https://evil.example.org/cb'] }),
      });
      assert.equal(badReg.status, 400);

      const flow = await runOAuthPkceFlow({ baseUrl: hub.baseUrl, callerToken: hub.callerToken });

      // 2. Code reuse rejected
      const reuse = await fetch(`${hub.baseUrl}/oauth/token`, {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          code: flow.code,
          code_verifier: flow.codeVerifier,
          client_id: flow.client.client_id,
          redirect_uri: flow.redirectUri,
          resource: flow.resource,
        }).toString(),
      });
      assert.equal(reuse.status, 400);

      // 3. Mismatched client_id on refresh does not burn grant
      const wrongClient = await fetch(`${hub.baseUrl}/oauth/token`, {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          grant_type: 'refresh_token',
          refresh_token: flow.tokens.refresh_token,
          client_id: 'mcp_wrong_client',
        }).toString(),
      });
      assert.equal(wrongClient.status, 400);

      // 4. Valid refresh rotation succeeds
      const rot = await fetch(`${hub.baseUrl}/oauth/token`, {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          grant_type: 'refresh_token',
          refresh_token: flow.tokens.refresh_token,
          client_id: flow.client.client_id,
        }).toString(),
      });
      assert.equal(rot.status, 200);
      const rotJson = await rot.json();

      // 5. Replay of old refresh_token revokes ENTIRE grant (including new access_token!)
      const replay = await fetch(`${hub.baseUrl}/oauth/token`, {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          grant_type: 'refresh_token',
          refresh_token: flow.tokens.refresh_token,
          client_id: flow.client.client_id,
        }).toString(),
      });
      assert.equal(replay.status, 400);

      const postReplayMcp = await fetch(`${hub.baseUrl}/mcp`, {
        method: 'POST',
        headers: { authorization: `Bearer ${rotJson.access_token}`, 'content-type': 'application/json' },
        body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'ping' }),
      });
      assert.equal(postReplayMcp.status, 401);
    } finally {
      await hub.close();
    }
  });

  test('T2-C2: /admin Brute-Force Lockout (429) & Logout Cookie Revocation [F4/M1]', async () => {
    const hub = await startTestHub({}, suiteTmpDir);
    try {
      const sess = await adminLogin(hub.baseUrl, hub.callerToken);
      for (let i = 0; i < 5; i++) {
        const fail = await fetch(`${hub.baseUrl}/admin/login`, {
          method: 'POST',
          redirect: 'manual',
          headers: { 'content-type': 'application/x-www-form-urlencoded', 'x-forwarded-for': '198.51.100.22' },
          body: new URLSearchParams({ token: 'wrong-token-' + i }).toString(),
        });
        assert.ok(fail.status === 401 || fail.status === 403 || fail.status === 429);
      }
      const locked = await fetch(`${hub.baseUrl}/admin/login`, {
        method: 'POST',
        redirect: 'manual',
        headers: { 'content-type': 'application/x-www-form-urlencoded', 'x-forwarded-for': '198.51.100.22' },
        body: new URLSearchParams({ token: 'wrong-token-6' }).toString(),
      });
      assert.equal(locked.status, 429);

      const out = await fetch(`${hub.baseUrl}/admin/logout`, {
        method: 'POST',
        redirect: 'manual',
        headers: { cookie: sess.cookie, 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ csrf: sess.csrf }).toString(),
      });
      assert.equal(out.status, 302);

      const replayCookie = await fetch(`${hub.baseUrl}/admin/api/state`, {
        headers: { cookie: sess.cookie },
      });
      assert.equal(replayCookie.status, 401);
    } finally {
      await hub.close();
    }
  });

  test('T2-C3: /admin CSRF, Auth & Payload Boundaries [F4/M1]', async () => {
    const hub = await startTestHub({}, suiteTmpDir);
    try {
      const unauth = await fetch(`${hub.baseUrl}/admin/api/state`);
      assert.equal(unauth.status, 401);

      const sess = await adminLogin(hub.baseUrl, hub.callerToken);
      const badCsrf = await fetch(`${hub.baseUrl}/admin/api/events/clear`, {
        method: 'POST',
        headers: { cookie: sess.cookie, 'x-csrf-token': 'invalid-csrf', 'content-type': 'application/json' },
        body: '{}',
      });
      assert.equal(badCsrf.status, 403);

      const badGrant = await fetch(`${hub.baseUrl}/admin/api/grants/revoke`, {
        method: 'POST',
        headers: { cookie: sess.cookie, 'x-csrf-token': sess.csrf, 'content-type': 'application/json' },
        body: JSON.stringify({}),
      });
      assert.equal(badGrant.status, 400);

      const tooBig = await fetch(`${hub.baseUrl}/admin/api/affinity/clear`, {
        method: 'POST',
        headers: { cookie: sess.cookie, 'x-csrf-token': sess.csrf, 'content-type': 'application/json' },
        body: JSON.stringify({ pad: 'a'.repeat(70_000) }),
      });
      assert.equal(tooBig.status, 413);
    } finally {
      await hub.close();
    }
  });

  test('T2-C4: OAuth Step-Up Scope Enforcement (crawl:read vs crawl:fetch) [F4/F15]', async () => {
    const hub = await startTestHub({}, suiteTmpDir);
    try {
      const flow = await runOAuthPkceFlow({ baseUrl: hub.baseUrl, callerToken: hub.callerToken, scopes: 'crawl:read' });
      const readTok = flow.tokens.access_token;

      const mcpRead = await fetch(`${hub.baseUrl}/mcp`, {
        method: 'POST',
        headers: { authorization: `Bearer ${readTok}`, 'content-type': 'application/json', accept: 'application/json' },
        body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'list_agents', arguments: {} } }),
      });
      assert.equal(mcpRead.status, 200);

      const mcpFetch = await fetch(`${hub.baseUrl}/mcp`, {
        method: 'POST',
        headers: { authorization: `Bearer ${readTok}`, 'content-type': 'application/json', accept: 'application/json' },
        body: JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'scrape', arguments: { url: 'https://example.com' } } }),
      });
      assert.equal(mcpFetch.status, 403);
      assert.match(mcpFetch.headers.get('www-authenticate') || '', /insufficient_scope/);

      const restFetch = await fetch(`${hub.baseUrl}/v1/scrape`, {
        method: 'POST',
        headers: { authorization: `Bearer ${readTok}`, 'content-type': 'application/json' },
        body: JSON.stringify({ url: 'https://example.com' }),
      });
      assert.equal(restFetch.status, 403);
    } finally {
      await hub.close();
    }
  });

  test('T2-C5: RFC 9421 Signature Verification Negative Cases [F17/M5]', async () => {
    const kp1 = generateEd25519Keypair();
    const kp2 = generateEd25519Keypair();
    const nowMs = Date.now();
    const targetUrl = 'https://target.example.org/docs';

    const hdrs = await hubBotAuth.signOutboundBotHeaders({
      url: targetUrl,
      method: 'GET',
      privateKeyEncoded: kp1.privateKeySeed,
      directoryUrl: 'https://hub.example.org/.well-known/http-message-signatures-directory',
      nowMs,
      ttlSeconds: 120,
    });

    // Tampered method
    const badMethod = await hubBotAuth.verifyBotRequestSignature(new Request(targetUrl, { method: 'POST', headers: hdrs }), kp1.publicKeyB64Url, nowMs);
    assert.equal(badMethod.ok, false);

    // Tampered target-uri
    const badUri = await hubBotAuth.verifyBotRequestSignature(new Request('https://target.example.org/other', { method: 'GET', headers: hdrs }), kp1.publicKeyB64Url, nowMs);
    assert.equal(badUri.ok, false);

    // Tampered Signature-Agent
    const badAgentHdrs = { ...hdrs, 'signature-agent': '"https://evil.example.org/dir"' };
    const badAgent = await hubBotAuth.verifyBotRequestSignature(new Request(targetUrl, { method: 'GET', headers: badAgentHdrs }), kp1.publicKeyB64Url, nowMs);
    assert.equal(badAgent.ok, false);

    // Expired
    const expired = await hubBotAuth.verifyBotRequestSignature(new Request(targetUrl, { method: 'GET', headers: hdrs }), kp1.publicKeyB64Url, nowMs + 300_000);
    assert.equal(expired.ok, false);

    // Future created
    const futureHdrs = await hubBotAuth.signOutboundBotHeaders({ url: targetUrl, method: 'GET', privateKeyEncoded: kp1.privateKeySeed, nowMs: nowMs + 300_000 });
    const future = await hubBotAuth.verifyBotRequestSignature(new Request(targetUrl, { method: 'GET', headers: futureHdrs }), kp1.publicKeyB64Url, nowMs);
    assert.equal(future.ok, false);

    // Wrong key
    const wrongKey = await hubBotAuth.verifyBotRequestSignature(new Request(targetUrl, { method: 'GET', headers: hdrs }), kp2.publicKeyB64Url, nowMs);
    assert.equal(wrongKey.ok, false);
  });

  test('T2-C6: Twin Failure Fallback & Malformed JSON Falls Back to HTML Cleanly [F3/M1]', async () => {
    const collector = await startMockOtlpCollector();
    const hub = await startTestHub({ OTEL_EXPORTER_OTLP_ENDPOINT: collector.endpoint }, suiteTmpDir);
    const agent = await connectMockAgent({
      port: hub.port,
      agentToken: hub.agentToken,
      siteId: 't2-c6',
      handler: async (reqItem) => {
        if (String(reqItem.url).includes('rubygems.org/api/v1/gems/')) {
          return { status: 500, outcome: 'ok', contentType: 'application/json', body: '{not-valid-json' };
        }
        return {
          status: 200,
          outcome: 'ok',
          contentType: 'text/html',
          body: '<html><head><title>Rails Fallback</title></head><body><main><h1>Rails HTML Fallback</h1><p>Recovered cleanly.</p></main></body></html>',
        };
      },
    });

    try {
      const { traceId, traceparent } = makeTraceIds('01');
      const res = await fetch(`${hub.baseUrl}/v1/scrape`, {
        method: 'POST',
        headers: { authorization: `Bearer ${hub.callerToken}`, 'content-type': 'application/json', traceparent },
        body: JSON.stringify({ url: 'https://rubygems.org/gems/rails' }),
      });
      assert.equal(res.status, 200);
      const json = await res.json();
      assert.ok(String(json.markdown || '').includes('Rails HTML Fallback'));
      assert.equal(json.extractorId, undefined, 'failed twin must NOT report extractorId');
      await collector.waitForSpans((e) => e.some((x) => x.span.traceId === traceId));
      const badAttr = collector.findByTraceId(traceId).some((e) => getOtlpAttrValue(e.span.attributes, 'edgefetch.adapter_id') === 'rubygems');
      assert.equal(badAttr, false, 'failed twin must NOT tag edgefetch.adapter_id');
    } finally {
      await agent.close();
      await hub.close();
      await collector.close();
    }
  });
});

describe('Tier 2 — Area D Boundaries: EdgeFetchClient TS & Python Edge Cases', () => {
  test('T2-D1: Invalid Hub Origins & Cleartext Rejection (TS & Python) [F13/F14/M3]', async () => {
    assert.throws(() => new tsSdk.EdgeFetchClient({ baseUrl: 'http://remote.example.com', token: 't' }), /cleartext/i);
    assert.throws(() => new tsSdk.EdgeFetchClient({ baseUrl: 'ftp://127.0.0.1', token: 't' }), /Unsupported/i);
    assert.throws(() => new tsSdk.EdgeFetchClient({ baseUrls: [], token: 't' }), /requires baseUrl/i);
    assert.doesNotThrow(() => new tsSdk.EdgeFetchClient({ baseUrl: 'http://127.0.0.1:8787', token: 't' }));
    assert.doesNotThrow(() => new tsSdk.EdgeFetchClient({ baseUrl: 'http://[::1]:8787', token: 't' }));
    assert.doesNotThrow(() => new tsSdk.EdgeFetchClient({ baseUrl: 'http://remote.example.com', token: 't', allowInsecureHttp: true }));

    const pyScript = `
from edgefetch_client import EdgeFetchClient
for bad in ["http://remote.example.com", "ftp://127.0.0.1", "not-a-url"]:
    try:
        EdgeFetchClient(token="t", base_url=bad)
        raise AssertionError(f"expected ValueError for {bad}")
    except ValueError:
        pass
EdgeFetchClient(token="t", base_url="http://127.0.0.1:8787")
EdgeFetchClient(token="t", base_url="http://[::1]:8787")
EdgeFetchClient(token="t", base_url="http://remote.example.com", allow_insecure_http=True)
print("OK")
`;
    const { stdout } = await runPythonSdk(pyBin, pyScript);
    assert.equal(stdout, 'OK');
  });

  test('T2-D2: traceparent Never Leaked Into Request JSON Body (TS & Python) [F13/F14/M3]', async () => {
    const rawBodies = [];
    const srv = await startHttpServer((req, res) => {
      const chunks = [];
      req.on('data', (c) => chunks.push(c));
      req.on('end', () => {
        rawBodies.push(Buffer.concat(chunks).toString('utf8'));
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ ok: true }));
      });
    });

    try {
      const tp = makeTraceIds('01').traceparent;
      const tsClient = new tsSdk.EdgeFetchClient({ baseUrl: srv.url, token: 't' });
      await tsClient.scrape({ url: 'https://example.com' }, { traceparent: tp });
      await tsClient.jobs({ query: 'eng' }, { traceparent: tp });

      const pyScript = `
import os
from edgefetch_client import EdgeFetchClient
c = EdgeFetchClient(token="t", base_url=os.environ["U"], traceparent=os.environ["TP"])
c.scrape("https://example.com", traceparent=os.environ["TP"])
c.jobs("eng", traceparent=os.environ["TP"])
`;
      await runPythonSdk(pyBin, pyScript, { U: srv.url, TP: tp });
      for (const b of rawBodies) {
        assert.equal(JSON.parse(b).traceparent, undefined, `[F13/F14] traceparent leaked into JSON body: ${b}`);
      }
    } finally {
      await srv.close();
    }
  });

  test('T2-D3: Empty/Absent x-trace-id Falls Back to traceparent & Resets to null/None [F13/F14/M3]', async () => {
    let mode = 'tp-only';
    const tpTid = randomBytes(16).toString('hex');
    const srv = await startHttpServer((req, res) => {
      req.resume();
      req.on('end', () => {
        const headers = { 'content-type': 'application/json' };
        if (mode === 'tp-only') headers.traceparent = `00-${tpTid}-${randomBytes(8).toString('hex')}-01`;
        else if (mode === 'malformed') headers.traceparent = 'not-a-traceparent';
        res.writeHead(200, headers);
        res.end(JSON.stringify({ ok: true }));
      });
    });

    try {
      const tsClient = new tsSdk.EdgeFetchClient({ baseUrl: srv.url, token: 't' });
      await tsClient.capabilities();
      assert.equal(tsClient.lastTraceId, tpTid);
      mode = 'malformed';
      await tsClient.capabilities();
      assert.equal(tsClient.lastTraceId, null);

      mode = 'tp-only';
      const pyScript = `
import json, os
from edgefetch_client import EdgeFetchClient
c = EdgeFetchClient(token="t", base_url=os.environ["U"])
c.capabilities()
first = c.last_trace_id
print(first)
`;
      const { stdout: s1 } = await runPythonSdk(pyBin, pyScript, { U: srv.url });
      assert.equal(s1, tpTid, '[F14/M3] Python did not fall back to traceparent header');
      mode = 'none';
      const { stdout: s2 } = await runPythonSdk(pyBin, pyScript, { U: srv.url });
      assert.equal(s2, 'None', '[F14/M3] Python last_trace_id did not reset to None');
    } finally {
      await srv.close();
    }
  });

  test('T2-D4: Non-Retryable 4xx Fails Fast Without Failover (TS & Python) [F13/F14/M3]', async () => {
    let standbyHits = 0;
    const tid401 = randomBytes(16).toString('hex');
    const primary = await startHttpServer((req, res) => {
      req.resume();
      req.on('end', () => {
        res.writeHead(401, { 'content-type': 'application/json', 'x-trace-id': tid401 });
        res.end(JSON.stringify({ error: 'unauthorized' }));
      });
    });
    const standby = await startHttpServer((req, res) => {
      standbyHits++;
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end('{"ok":true}');
    });

    try {
      const tsClient = new tsSdk.EdgeFetchClient({ baseUrls: [primary.url, standby.url], token: 'bad' });
      await assert.rejects(() => tsClient.capabilities(), (e) => e.status === 401);
      assert.equal(tsClient.lastTraceId, tid401);
      assert.equal(standbyHits, 0);

      const pyScript = `
import os
from edgefetch_client import EdgeFetchClient, EdgeFetchError
c = EdgeFetchClient(token="bad", base_urls=[os.environ["U1"], os.environ["U2"]])
try:
    c.capabilities()
except EdgeFetchError as e:
    assert e.status == 401
    print(c.last_trace_id)
`;
      const { stdout } = await runPythonSdk(pyBin, pyScript, { U1: primary.url, U2: standby.url });
      assert.equal(stdout, tid401, '[F14/M3] Python 401 did not capture last_trace_id');
      assert.equal(standbyHits, 0);
    } finally {
      await Promise.all([primary.close(), standby.close()]);
    }
  });

  test('T2-D5: Python Cross-Origin Redirect Auth Strip & HTTPError Trace Capture [F14/M3]', async () => {
    const destAuths = [];
    const tidDest = randomBytes(16).toString('hex');
    const destSrv = await startHttpServer((req, res) => {
      destAuths.push(req.headers.authorization || null);
      res.writeHead(403, { 'content-type': 'application/json', 'x-trace-id': tidDest });
      res.end(JSON.stringify({ error: 'forbidden' }));
    });
    const redirSrv = await startHttpServer((req, res) => {
      res.writeHead(302, { location: `${destSrv.url}/v1/capabilities` });
      res.end();
    });

    try {
      const pyScript = `
import os
from edgefetch_client import EdgeFetchClient, EdgeFetchError
c = EdgeFetchClient(token="secret-redirect-tok", base_url=os.environ["U"])
try:
    c.capabilities()
except EdgeFetchError as e:
    assert e.status == 403
    print(c.last_trace_id)
`;
      const { stdout } = await runPythonSdk(pyBin, pyScript, { U: redirSrv.url });
      assert.equal(destAuths[0], null, 'Python SDK must strip Authorization across origins');
      assert.equal(stdout, tidDest, '[F14/M3] Python SDK did not capture x-trace-id on redirected HTTPError');
    } finally {
      await Promise.all([redirSrv.close(), destSrv.close()]);
    }
  });
});

describe('Tier 2 — Area E Boundaries: Entrypoint Validation & Permissions', () => {
  test('T2-E1: Malformed OTEL_EXPORTER_OTLP_ENDPOINT Rejected Safely [F11/M2]', async () => {
    for (const badEp of ['file:///etc/passwd', 'javascript:alert(1)', 'http://otel.local evil', 'http://otel.local\nINJECT=1']) {
      const run = await runEntrypointHarness({
        env: {
          EDGEFETCH_ALLOW_SHARED_UID: '1',
          OTEL_EXPORTER_OTLP_ENDPOINT: badEp,
        },
      });
      try {
        assert.ok(run.agentEnv !== null, `entrypoint crashed on bad endpoint ${JSON.stringify(badEp)}: ${run.stderr}`);
        assert.equal(run.agentEnv.INJECT, undefined, '[F11/M2] newline injection evaluated!');
        const forwarded = run.agentEnv.OTEL_EXPORTER_OTLP_ENDPOINT || '';
        assert.equal(forwarded, '', `[F11/M2] invalid OTEL_EXPORTER_OTLP_ENDPOINT was forwarded: ${JSON.stringify(forwarded)}`);
      } finally {
        run.cleanup();
      }
    }
  });

  test('T2-E2: Malformed OTEL_EXPORTER_OTLP_HEADERS Injection Blocked [F11/M2]', async () => {
    const markerFile = path.join(suiteTmpDir, 'cmd-inj-check.txt');
    const rejectedHeaders = [
      `x-ok=1,bad\r\ninject: 2`,
      'missing_equals_sign',
      'bad header=1',
      '=nokey',
      'a=1,',
    ];
    for (const hdr of rejectedHeaders) {
      const run = await runEntrypointHarness({
        env: {
          EDGEFETCH_ALLOW_SHARED_UID: '1',
          OTEL_EXPORTER_OTLP_ENDPOINT: 'http://127.0.0.1:4318',
          OTEL_EXPORTER_OTLP_HEADERS: hdr,
        },
      });
      try {
        assert.equal(run.exitCode, 0, `[F11/M2] entrypoint exited non-zero (${run.exitCode}) on header ${JSON.stringify(hdr)}: ${run.stderr}`);
        assert.ok(run.agentEnv !== null, `[F11/M2] worker mock did not run for rejected header ${JSON.stringify(hdr)}: ${run.stderr}`);
        const outHdr = run.agentEnv.OTEL_EXPORTER_OTLP_HEADERS || '';
        assert.equal(outHdr, '', `[F11/M2] rejected OTEL_EXPORTER_OTLP_HEADERS ${JSON.stringify(hdr)} was forwarded as ${JSON.stringify(outHdr)}`);
      } finally {
        run.cleanup();
      }
    }

    const cmdInjHdr = `x-cmd=$(touch ${markerFile.replace(/\\/g, '/')})`;
    const injRun = await runEntrypointHarness({
      env: {
        EDGEFETCH_ALLOW_SHARED_UID: '1',
        OTEL_EXPORTER_OTLP_ENDPOINT: 'http://127.0.0.1:4318',
        OTEL_EXPORTER_OTLP_HEADERS: cmdInjHdr,
      },
    });
    try {
      assert.equal(injRun.exitCode, 0, `[F11/M2] entrypoint exited non-zero on command substitution test: ${injRun.stderr}`);
      assert.ok(injRun.agentEnv !== null, `[F11/M2] worker mock did not run on command substitution test: ${injRun.stderr}`);
      assert.equal(existsSync(markerFile), false, 'shell injection executed!');
    } finally {
      injRun.cleanup();
    }
  });

  test('T2-E3: Secret-Bearing Headers & Hub Tokens Isolated From Worker [F11/M2]', async () => {
    const run = await runEntrypointHarness({
      env: {
        EDGEFETCH_ALLOW_SHARED_UID: '1',
        CALLER_TOKEN: 'secret_caller_24chars_1234',
        OPENAI_API_KEY: 'sk-secret-openai-99',
        S3_SECRET_ACCESS_KEY: 's3-secret-99',
        TURSO_AUTH_TOKEN: 'turso-secret-99',
        OTEL_EXPORTER_OTLP_ENDPOINT: 'https://otel.example.com',
        OTEL_EXPORTER_OTLP_HEADERS: 'Authorization=Bearer%20otel_ok',
      },
    });
    try {
      assert.equal(run.exitCode, 0);
      assert.equal(run.agentEnv.CALLER_TOKEN, undefined);
      assert.equal(run.agentEnv.OPENAI_API_KEY, undefined);
      assert.equal(run.agentEnv.S3_SECRET_ACCESS_KEY, undefined);
      assert.equal(run.agentEnv.TURSO_AUTH_TOKEN, undefined);
      assert.equal(run.agentEnv.OTEL_EXPORTER_OTLP_HEADERS, 'Authorization=Bearer%20otel_ok', '[F11/M2] valid OTLP headers missing');
    } finally {
      run.cleanup();
    }
  });

  test('T2-E4: EDGEFETCH_DATA_DIR=/data Upgrade & Permissions on UID 0 [F11/M2]', async () => {
    const run = await runEntrypointHarness({
      fakeUidZero: true,
      withLegacyDataSqlite: true,
      hubExitMs: 1200,
      env: {
        EDGEFETCH_DATA_DIR: '/data',
      },
    });
    try {
      assert.equal(run.exitCode, 0, `UID 0 entrypoint failed: ${run.stderr}`);
      assert.ok(run.hubEnv?.EDGEFETCH_DATA_DIR?.endsWith('/hub'), `expected /data rewritten to .../hub, got ${run.hubEnv?.EDGEFETCH_DATA_DIR}`);
      assert.equal(existsSync(path.join(run.dataRoot, 'hub', 'edgefetch-hub.sqlite')), true, 'legacy sqlite was not migrated to /data/hub');
      assert.match(run.opsLog, /chmod 0710 /);
      assert.match(run.opsLog, /chmod 0700 /);
      assert.match(run.opsLog, /chown root:node /);
      assert.match(run.opsLog, /chown -R node:node /);
      assert.match(run.opsLog, /su-exec node:node /);
      assert.match(run.opsLog, /su-exec 65532:65532 /);
    } finally {
      run.cleanup();
    }
  });

  test('T2-E5: EDGEFETCH_CALLER_TOKEN Fallback Without Worker Exposure [F11/M2]', async () => {
    const tok = 'edgefetch_caller_fallback_24chars';
    const run = await runEntrypointHarness({
      env: {
        EDGEFETCH_ALLOW_SHARED_UID: '1',
        CALLER_TOKEN: '',
        EDGEFETCH_CALLER_TOKEN: tok,
      },
    });
    try {
      assert.equal(run.exitCode, 0);
      assert.equal(run.hubEnv.CALLER_TOKEN, tok);
      assert.equal(run.agentEnv.CALLER_TOKEN, undefined);
      assert.equal(run.agentEnv.EDGEFETCH_CALLER_TOKEN, undefined);
    } finally {
      run.cleanup();
    }
  });
});

// ===========================================================================
// TIER 3 — Cross-Feature Pairwise Combinations (12 Tests: T3-1 .. T3-12)
// ===========================================================================

describe('Tier 3 — Cross-Feature Pairwise Combinations', () => {
  test('T3-1: TS SDK x Portable Hub x OTLP (scrape, jobs, catalog, search, batchScrape, agent) [F1/F2/F13]', async () => {
    const collector = await startMockOtlpCollector();
    const llmSrv = await startHttpServer((_req, res) => {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({
        choices: [{ index: 0, message: { role: 'assistant', content: '{"result":"ok"}' }, finish_reason: 'stop' }],
      }));
    });
    const hub = await startTestHub({
      OTEL_EXPORTER_OTLP_ENDPOINT: collector.endpoint,
      EDGEFETCH_LLM_PROVIDER: 'openai',
      EDGEFETCH_LLM_BASE_URL: `${llmSrv.url}/v1`,
      EDGEFETCH_LLM_API_KEY: 'sk-t3-1-secret',
    }, suiteTmpDir);
    const agent = await connectMockAgent({ port: hub.port, agentToken: hub.agentToken, siteId: 't3-1' });

    try {
      const tpBase = makeTraceIds('01');
      const client = new tsSdk.EdgeFetchClient({ baseUrl: hub.baseUrl, token: hub.callerToken, traceparent: tpBase.traceparent });

      const ops = [
        ['scrape', () => client.scrape({ url: 'https://t3-1.example.com/a' }, { traceparent: makeTraceIds('01').traceparent })],
        ['jobs', () => client.jobs({ verify: ['https://jobs.ashbyhq.com/linear/ash-1'] }, { traceparent: makeTraceIds('01').traceparent })],
        ['search', () => client.search({ query: 't3-1' }, { traceparent: makeTraceIds('01').traceparent })],
        ['batchScrape', () => client.batchScrape({ urls: ['https://t3-1.example.com/b'], sync: true }, { traceparent: makeTraceIds('01').traceparent })],
        ['agent', () => client.agent({ prompt: 'Summarize', urls: ['https://t3-1.example.com/a'], strictConstrainToURLs: true, maxSteps: 1 }, { traceparent: makeTraceIds('01').traceparent })],
      ];

      for (const [name, fn] of ops) {
        await fn();
        const tid = client.lastTraceId;
        assert.ok(tid && RE_TRACE_ID.test(tid), `[F1/F13] TS ${name} did not capture lastTraceId`);
        await collector.waitForSpans((e) => e.some((x) => x.span.traceId === tid));
        assert.ok(collector.findByTraceId(tid).length >= 1, `[F1/F2] ${name} emitted 0 OTLP spans for traceId=${tid}`);
      }
      assertNoLeakedSecrets(collector.entries, ['sk-t3-1-secret', hub.callerToken], '[T3-1]');
    } finally {
      await agent.close();
      await hub.close();
      await llmSrv.close();
      await collector.close();
    }
  });

  test('T3-2: Python SDK x Portable Hub x OTLP [F1/F2/F14]', async () => {
    const collector = await startMockOtlpCollector();
    const hub = await startTestHub({ OTEL_EXPORTER_OTLP_ENDPOINT: collector.endpoint }, suiteTmpDir);
    const agent = await connectMockAgent({ port: hub.port, agentToken: hub.agentToken, siteId: 't3-2' });

    try {
      const tp = makeTraceIds('01');
      const pyScript = `
import os
from edgefetch_client import EdgeFetchClient
c = EdgeFetchClient(token=os.environ["TOK"], base_url=os.environ["URL"], traceparent=os.environ["TP"])
r = c.scrape("https://t3-2.example.com/page")
assert r.get("ok") is True
print(c.last_trace_id)
`;
      const { stdout } = await runPythonSdk(pyBin, pyScript, { TOK: hub.callerToken, URL: hub.baseUrl, TP: tp.traceparent });
      assert.equal(stdout, tp.traceId, '[F14/M3] Python SDK did not capture Portable Hub traceId');
      await collector.waitForSpans((e) => e.some((x) => x.span.traceId === tp.traceId && x.span.name === 'edgefetch.scrape'));
      assert.ok(collector.findByTraceId(tp.traceId).some((e) => e.span.name === 'edgefetch.scrape'), '[F2/M1] missing edgefetch.scrape span');
    } finally {
      await agent.close();
      await hub.close();
      await collector.close();
    }
  });

  test('T3-3: TS & Python SDK x Go --mode=hub x OTLP [F7/F13/F14]', async () => {
    const collector = await startMockOtlpCollector();
    const { callerToken, agentToken } = makeTokens();
    const goHub = await startGoHub({
      bin: goBin,
      args: ['--mode=hub', '--addr=127.0.0.1:{PORT}'],
      env: {
        EDGEFETCH_CALLER_TOKEN: callerToken,
        EDGEFETCH_AGENT_TOKEN: agentToken,
        OTEL_EXPORTER_OTLP_ENDPOINT: collector.endpoint,
        OTEL_SERVICE_NAME: 'edgefetch-go-hub',
      },
    });
    const agent = await connectHeaderMockAgent({ port: goHub.port, agentToken, siteId: 't3-3' });

    try {
      const tpTs = makeTraceIds('01');
      const tsClient = new tsSdk.EdgeFetchClient({ baseUrl: goHub.baseUrl, token: callerToken, traceparent: tpTs.traceparent });
      await tsClient.scrape({ url: 'https://t3-3.example.com/ts' });
      assert.equal(tsClient.lastTraceId, tpTs.traceId, '[F7/F13] TS SDK -> Go Hub traceId mismatch');

      const tpPy = makeTraceIds('01');
      const { stdout } = await runPythonSdk(
        pyBin,
        `import os; from edgefetch_client import EdgeFetchClient; c=EdgeFetchClient(token=os.environ["TOK"], base_url=os.environ["URL"], traceparent=os.environ["TP"]); c.scrape("https://t3-3.example.com/py"); print(c.last_trace_id)`,
        { TOK: callerToken, URL: goHub.baseUrl, TP: tpPy.traceparent },
      );
      assert.equal(stdout, tpPy.traceId, '[F7/F14] Python SDK -> Go Hub traceId mismatch');

      await collector.waitForSpans((e) =>
        e.some((x) => x.span.traceId === tpTs.traceId && x.serviceName === 'edgefetch-go-hub') &&
        e.some((x) => x.span.traceId === tpPy.traceId && x.serviceName === 'edgefetch-go-hub'),
      3500);
      assert.ok(collector.findByTraceId(tpTs.traceId).length >= 1, '[F7/M2] missing Go Hub spans for TS SDK call');
      assert.ok(collector.findByTraceId(tpPy.traceId).length >= 1, '[F7/M2] missing Go Hub spans for Python SDK call');
    } finally {
      await agent.close();
      await goHub.close();
      await collector.close();
    }
  });

  test('T3-4: Portable Hub x Go --mode=agent --allow-private x OTLP Cross-Process Parent-Child [F1/F10]', async () => {
    const collector = await startMockOtlpCollector();
    const { agentToken } = makeTokens();
    const hub = await startTestHub({
      AGENT_TOKEN: agentToken,
      OTEL_EXPORTER_OTLP_ENDPOINT: collector.endpoint,
      OTEL_SERVICE_NAME: 'edgefetch-hub',
    }, suiteTmpDir);
    const goAgent = await startGoAgent({
      bin: goBin,
      hubUrl: hub.baseUrl,
      agentToken,
      siteId: 't3-4-agent',
      allowPrivate: true,
      callerToken: hub.callerToken,
      env: { OTEL_EXPORTER_OTLP_ENDPOINT: collector.endpoint },
    });

    try {
      const { traceId, parentSpanId, traceparent } = makeTraceIds('01');
      await fetch(`${hub.baseUrl}/v1/scrape`, {
        method: 'POST',
        headers: { authorization: `Bearer ${hub.callerToken}`, 'content-type': 'application/json', traceparent },
        body: JSON.stringify({ url: 'https://t3-4.invalid/cross-process', site: 't3-4-agent', target: 'agent' }),
      });

      await collector.waitForSpans((e) =>
        e.some((x) => x.span.traceId === traceId && x.serviceName === 'edgefetch-hub' && x.span.name === 'edgefetch.dispatch') &&
        e.some((x) => x.span.traceId === traceId && x.serviceName === 'edgefetch-agent-t3-4-agent' && x.span.name === 'edgefetch.go.batch'),
      4500);
      const spans = collector.findByTraceId(traceId);
      const httpSpan = spans.find((e) => e.span.name === 'edgefetch.http');
      const scrapeSpan = spans.find((e) => e.span.name === 'edgefetch.scrape');
      const dispatchSpan = spans.find((e) => e.span.name === 'edgefetch.dispatch');
      const goBatch = spans.find((e) => e.span.name === 'edgefetch.go.batch');
      const goFetch = spans.find((e) => e.span.name.startsWith('edgefetch.go.fetch.'));

      assert.ok(httpSpan && scrapeSpan && dispatchSpan && goBatch && goFetch, '[F1/F10] incomplete cross-process span tree');
      assert.equal(httpSpan.span.parentSpanId, parentSpanId);
      assert.equal(scrapeSpan.span.parentSpanId, httpSpan.span.spanId);
      assert.equal(dispatchSpan.span.parentSpanId, scrapeSpan.span.spanId);
      assert.equal(goBatch.span.parentSpanId, dispatchSpan.span.spanId);
      assert.equal(goFetch.span.parentSpanId, goBatch.span.spanId);
    } finally {
      await goAgent.close();
      await hub.close();
      await collector.close();
    }
  });

  test('T3-5: OAuth 2.1 x /mcp x YAML Twin edgefetch.adapter_id x OTLP [F2/F3/F4]', async () => {
    const collector = await startMockOtlpCollector();
    const hub = await startTestHub({ OTEL_EXPORTER_OTLP_ENDPOINT: collector.endpoint }, suiteTmpDir);
    const agent = await connectMockAgent({ port: hub.port, agentToken: hub.agentToken, siteId: 't3-5' });

    try {
      const flow = await runOAuthPkceFlow({ baseUrl: hub.baseUrl, callerToken: hub.callerToken });
      const { traceId, traceparent } = makeTraceIds('01');
      const res = await fetch(`${hub.baseUrl}/mcp`, {
        method: 'POST',
        headers: {
          authorization: `Bearer ${flow.tokens.access_token}`,
          'content-type': 'application/json',
          accept: 'application/json',
          traceparent,
        },
        body: JSON.stringify({
          jsonrpc: '2.0',
          id: 1,
          method: 'tools/call',
          params: { name: 'scrape', arguments: { url: 'https://lobste.rs/s/abc123/mock-story' } },
        }),
      });
      assert.equal(res.status, 200);
      assertTraceHeaders(res, { expectedTraceId: traceId, tag: '[F2/M1]' });

      await collector.waitForSpans((e) =>
        e.some((x) => x.span.traceId === traceId && x.span.name === 'edgefetch.mcp.tool') &&
        e.some((x) => x.span.traceId === traceId && getOtlpAttrValue(x.span.attributes, 'edgefetch.adapter_id') === 'lobsters') &&
        e.some((x) => x.span.name.startsWith('edgefetch.oauth.')),
      );
      const spans = collector.findByTraceId(traceId);
      assert.ok(spans.some((e) => e.span.name === 'edgefetch.mcp.tool'), '[F2/M1] missing edgefetch.mcp.tool');
      assert.ok(spans.some((e) => getOtlpAttrValue(e.span.attributes, 'edgefetch.adapter_id') === 'lobsters'), '[F3/M1] missing edgefetch.adapter_id=lobsters');
      assert.ok(collector.entries.some((e) => e.span.name.startsWith('edgefetch.oauth.')), '[F4/M1] missing edgefetch.oauth.*');
    } finally {
      await agent.close();
      await hub.close();
      await collector.close();
    }
  });

  test('T3-6: bot_auth.signed x Hub + Go Agent x OTLP [F3/F9/F17]', async () => {
    const collector = await startMockOtlpCollector();
    const kp = generateEd25519Keypair();
    const origin = await startMockOrigin();
    const { callerToken, agentToken } = makeTokens();

    const goHub = await startGoHub({
      bin: goBin,
      args: ['--mode=hub', '--addr=127.0.0.1:{PORT}', '--allow-private'],
      env: {
        EDGEFETCH_CALLER_TOKEN: callerToken,
        EDGEFETCH_AGENT_TOKEN: agentToken,
        EDGEFETCH_BOT_SIGNING_KEY: kp.privateKeySeed,
        OTEL_EXPORTER_OTLP_ENDPOINT: collector.endpoint,
        OTEL_SERVICE_NAME: 'edgefetch-go-hub-t3-6',
      },
    });
    const tsHub = await startTestHub({
      AGENT_TOKEN: agentToken,
      BOT_SIGNING_PRIVATE_KEY: kp.privateKeySeed,
      OTEL_EXPORTER_OTLP_ENDPOINT: collector.endpoint,
    }, suiteTmpDir);

    try {
      const dirRes = await fetch(`${tsHub.baseUrl}/.well-known/http-message-signatures-directory`);
      assert.equal((await hubBotAuth.verifyDirectoryResponseSignature({
        requestUrl: `${tsHub.baseUrl}/.well-known/http-message-signatures-directory`,
        response: dirRes,
        publicKeyB64Url: kp.publicKeyB64Url,
      })).ok, true);

      const { traceId, traceparent } = makeTraceIds('01');
      await fetch(`${goHub.baseUrl}/v1/scrape`, {
        method: 'POST',
        headers: { authorization: `Bearer ${callerToken}`, 'content-type': 'application/json', traceparent },
        body: JSON.stringify({ url: `${origin.url}/signed-t3-6` }),
      });
      const rec = origin.recorded.find((r) => r.url === '/signed-t3-6');
      assert.ok(rec);
      const check = await hubBotAuth.verifyBotRequestSignature(new Request(`${origin.url}/signed-t3-6`, { method: 'GET', headers: rec.headers }), kp.publicKeyB64Url);
      assert.equal(check.ok, true);

      await collector.waitForSpans((e) =>
        e.some((x) => x.span.traceId === traceId && getOtlpAttrValue(x.span.attributes, 'bot_auth.signed') === true),
      3500);
      assert.ok(
        collector.findByTraceId(traceId).some((e) => getOtlpAttrValue(e.span.attributes, 'bot_auth.signed') === true),
        '[F9/M2] missing bot_auth.signed=true on OTLP span',
      );
    } finally {
      await tsHub.close();
      await goHub.close();
      await origin.close();
      await collector.close();
    }
  });

  test('T3-7: Content-Signal: ai-input=no & 402 x Cross-Process x OTLP [F16]', async () => {
    const collector = await startMockOtlpCollector();
    const origin = await startMockOrigin((req, res) => {
      if (req.url === '/robots.txt') {
        res.writeHead(200, { 'content-type': 'text/plain' });
        res.end('User-agent: *\nAllow: /paywall\nContent-Signal: ai-input=no\n');
        return;
      }
      res.writeHead(402, { 'content-type': 'text/plain', 'payment-required': 'x402-t3-7' });
      res.end('paywall');
    });
    const goServe = await startGoHub({
      bin: goBin,
      args: ['serve', '--port={PORT}', '--allow-private'],
      env: { OTEL_EXPORTER_OTLP_ENDPOINT: collector.endpoint },
      healthPath: '/health',
    });

    try {
      const tp = makeTraceIds('01');
      const res = await fetch(`${goServe.baseUrl}/v1/scrape`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', traceparent: tp.traceparent },
        body: JSON.stringify({ url: `${origin.url}/article` }),
      });
      const json = await res.json();
      assert.equal(origin.recorded.some((r) => r.url === '/article'), false);
      assert.ok(
        res.status >= 400 || String(json.problem || '').toLowerCase().includes('content-signal: ai-input=no'),
        `expected content-signal block, got ${res.status} ${JSON.stringify(json)}`,
      );
      await collector.waitForSpans((e) => e.some((x) => x.span.traceId === tp.traceId), 3000);
      assert.ok(collector.findByTraceId(tp.traceId).length >= 1, '[F8/M2] missing OTLP spans for Content-Signal stop');
    } finally {
      await goServe.close();
      await origin.close();
      await collector.close();
    }
  });

  test('T3-8: Entrypoint x Go --mode=agent & Portable Hub x OTLP [F11/F1/F10]', async () => {
    const collector = await startMockOtlpCollector();
    const secretCanary = 'sk-t3-8-entrypoint-secret';
    const run = await runEntrypointHarness({
      env: {
        EDGEFETCH_ALLOW_SHARED_UID: '1',
        OTEL_EXPORTER_OTLP_ENDPOINT: collector.endpoint,
        OTEL_EXPORTER_OTLP_HEADERS: 'x-entry-hdr=verified',
        OTEL_SERVICE_NAME: 'edgefetch-entry-e2e',
        OPENAI_API_KEY: secretCanary,
      },
    });
    try {
      assert.equal(run.exitCode, 0);
      assert.equal(run.agentEnv.OPENAI_API_KEY, undefined);
      assert.equal(run.agentEnv.OTEL_EXPORTER_OTLP_ENDPOINT, collector.endpoint);
      assert.equal(run.agentEnv.OTEL_EXPORTER_OTLP_HEADERS, 'x-entry-hdr=verified', '[F11/M2] OTEL headers not forwarded');

      // Now run real Portable Hub + Go Agent using the exact filtered env produced by entrypoint!
      const hub = await startTestHub({
        AGENT_TOKEN: run.hubEnv.AGENT_TOKEN,
        OTEL_EXPORTER_OTLP_ENDPOINT: run.hubEnv.OTEL_EXPORTER_OTLP_ENDPOINT,
        OTEL_EXPORTER_OTLP_HEADERS: run.hubEnv.OTEL_EXPORTER_OTLP_HEADERS,
        OTEL_SERVICE_NAME: 'edgefetch-hub',
      }, suiteTmpDir);
      const goAgent = await startGoAgent({
        bin: goBin,
        hubUrl: hub.baseUrl,
        agentToken: run.agentEnv.EDGEFETCH_AGENT_TOKEN,
        siteId: 't3-8-worker',
        allowPrivate: true,
        callerToken: hub.callerToken,
        env: {
          OTEL_EXPORTER_OTLP_ENDPOINT: run.agentEnv.OTEL_EXPORTER_OTLP_ENDPOINT,
          OTEL_EXPORTER_OTLP_HEADERS: run.agentEnv.OTEL_EXPORTER_OTLP_HEADERS,
        },
      });
      try {
        const { traceId, traceparent } = makeTraceIds('01');
        await fetch(`${hub.baseUrl}/v1/scrape`, {
          method: 'POST',
          headers: { authorization: `Bearer ${hub.callerToken}`, 'content-type': 'application/json', traceparent },
          body: JSON.stringify({ url: 'https://t3-8.invalid/item', site: 't3-8-worker', target: 'agent' }),
        });
        await collector.waitForSpans((e) =>
          e.some((x) => x.span.traceId === traceId && x.serviceName === 'edgefetch-hub') &&
          e.some((x) => x.span.traceId === traceId && x.serviceName === 'edgefetch-agent-t3-8-worker'),
        4000);
        assert.ok(collector.findByTraceId(traceId).some((e) => e.serviceName === 'edgefetch-agent-t3-8-worker'));
        assertNoLeakedSecrets(collector.entries, [secretCanary, run.agentEnv.EDGEFETCH_AGENT_TOKEN], '[T3-8]');
      } finally {
        await goAgent.close();
        await hub.close();
      }
    } finally {
      run.cleanup();
      await collector.close();
    }
  });

  test('T3-9: cache:r2-d1 + 304 Revalidation x SDK traceparent x OTLP [F3/F13]', async () => {
    const collector = await startMockOtlpCollector();
    const hub = await startTestHub({ OTEL_EXPORTER_OTLP_ENDPOINT: collector.endpoint }, suiteTmpDir);
    let fetchCount = 0;
    const agent = await connectMockAgent({
      port: hub.port,
      agentToken: hub.agentToken,
      siteId: 't3-9',
      handler: async (reqItem, _msg, helpers) => {
        fetchCount++;
        if (fetchCount >= 2 && reqItem.ifNoneMatch) {
          return { status: 304, outcome: 'ok', headers: { etag: '"v1-304"' } };
        }
        const html = '<html><body><main><h1>Cached 304 Content</h1><p>Initial version stored in R2 for cache:r2-d1 verification.</p></main></body></html>';
        const art = await helpers.uploadArtifact(html, 'stored');
        return {
          status: 200,
          outcome: 'ok',
          contentType: 'text/html',
          headers: { etag: '"v1-304"' },
          body: html,
          artifact: art,
        };
      },
    });

    try {
      const client = new tsSdk.EdgeFetchClient({ baseUrl: hub.baseUrl, token: hub.callerToken });
      const tp1 = makeTraceIds('01');
      const r1 = await client.scrape({ url: 'https://t3-9.example.com/etag' }, { traceparent: tp1.traceparent });
      assert.equal(client.lastTraceId, tp1.traceId);
      assert.equal(r1.cached, false);

      const tp2 = makeTraceIds('01');
      const r2 = await client.scrape({ url: 'https://t3-9.example.com/etag', maxAgeMs: 60_000 }, { traceparent: tp2.traceparent });
      assert.equal(client.lastTraceId, tp2.traceId);
      assert.equal(r2.cached, true);
      await collector.waitForSpans((e) => e.some((x) => x.span.traceId === tp2.traceId && x.span.name === 'cache:r2-d1'));
      assert.ok(collector.findByTraceId(tp2.traceId).some((e) => e.span.name === 'cache:r2-d1'), '[F3/M1] missing cache:r2-d1 span');

      // Revalidation (maxAgeMs: 0 with cached ETag) -> 304
      const tp3 = makeTraceIds('01');
      const r3 = await client.scrape({ url: 'https://t3-9.example.com/etag', maxAgeMs: 0 }, { traceparent: tp3.traceparent });
      assert.equal(client.lastTraceId, tp3.traceId);
      assert.equal(r3.ok, true);
    } finally {
      await agent.close();
      await hub.close();
      await collector.close();
    }
  });

  test('T3-10: spa_fallback x robots.txt Gate x OTLP [F3/M1]', async () => {
    const collector = await startMockOtlpCollector();
    const crawl4aiSrv = await startHttpServer((_req, res) => {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({
        success: true,
        results: [{ url: 'https://t3-10.example.com/spa', status_code: 200, markdown: { raw_markdown: '# Fallback OK' } }],
      }));
    });
    const hub = await startTestHub({
      OTEL_EXPORTER_OTLP_ENDPOINT: collector.endpoint,
      CRAWL4AI_API_URL: crawl4aiSrv.url,
      SPA_FALLBACK_ORDER: 'crawl4ai',
    }, suiteTmpDir);
    const agent = await connectMockAgent({
      port: hub.port,
      agentToken: hub.agentToken,
      siteId: 't3-10',
      handler: async (reqItem) => {
        if (String(reqItem.url).includes('/blocked')) {
          return { status: 403, outcome: 'challenge', problem: 'bot challenge detected' };
        }
        return {
          status: 200,
          outcome: 'ok',
          contentType: 'text/html',
          body: '<html><body><div id="app"></div><script>window.boot();</script></body></html>',
        };
      },
    });

    try {
      const tpEligible = makeTraceIds('01');
      const r1 = await fetch(`${hub.baseUrl}/v1/scrape`, {
        method: 'POST',
        headers: { authorization: `Bearer ${hub.callerToken}`, 'content-type': 'application/json', traceparent: tpEligible.traceparent },
        body: JSON.stringify({ url: 'https://t3-10.example.com/spa', spaFallback: 'crawl4ai' }),
      });
      assert.equal(r1.status, 200);
      await collector.waitForSpans((e) => e.some((x) => x.span.traceId === tpEligible.traceId && x.span.name === 'edgefetch.spa_fallback'));
      assert.ok(collector.findByTraceId(tpEligible.traceId).some((e) => e.span.name === 'edgefetch.spa_fallback'), '[F3/M1] missing edgefetch.spa_fallback span');

      const tpBlocked = makeTraceIds('01');
      const r2 = await fetch(`${hub.baseUrl}/v1/scrape`, {
        method: 'POST',
        headers: { authorization: `Bearer ${hub.callerToken}`, 'content-type': 'application/json', traceparent: tpBlocked.traceparent },
        body: JSON.stringify({ url: 'https://t3-10.example.com/blocked', spaFallback: 'crawl4ai' }),
      });
      assert.ok(r2.status >= 400);
      await delay(200);
      assert.equal(collector.findByTraceId(tpBlocked.traceId).some((e) => e.span.name === 'edgefetch.spa_fallback'), false, 'challenge must NEVER trigger SPA fallback');
    } finally {
      await agent.close();
      await hub.close();
      await crawl4aiSrv.close();
      await collector.close();
    }
  });

  test('T3-11: Go mcp stdio x edgefetch.browser.render x OTLP [F8/F9/M2]', async () => {
    const collector = await startMockOtlpCollector();
    const origin = await startMockOrigin();
    try {
      // Test stdio MCP pure JSON-RPC + OTLP export, plus browser render span via serve --allow-private
      const mcpOut = await runMcpStdioSession({
        bin: goBin,
        args: ['mcp'],
        env: { OTEL_EXPORTER_OTLP_ENDPOINT: collector.endpoint, OTEL_SERVICE_NAME: 'edgefetch-mcp-stdio' },
        requests: [
          { jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-03-26' } },
          { jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'doctor', arguments: {} } },
        ],
      });
      assert.equal(mcpOut.exitCode, 0);
      assert.equal(mcpOut.parsedLines.length, 2);

      const goServe = await startGoHub({
        bin: goBin,
        args: ['serve', '--port={PORT}', '--allow-private'],
        env: {
          OTEL_EXPORTER_OTLP_ENDPOINT: collector.endpoint,
          OTEL_SERVICE_NAME: 'edgefetch-serve-render',
          ...(process.platform === 'linux' ? { EDGEFETCH_ALLOW_NO_SANDBOX: '1' } : {}),
        },
        healthPath: '/health',
      });
      try {
        const tp = makeTraceIds('01');
        const res = await fetch(`${goServe.baseUrl}/v1/scrape`, {
          method: 'POST',
          headers: { 'content-type': 'application/json', traceparent: tp.traceparent },
          body: JSON.stringify({ url: `${origin.url}/spa`, renderMode: 'always' }),
        });
        assert.equal(res.status, 200);
        await collector.waitForSpans((e) =>
          e.some((x) => x.serviceName === 'edgefetch-mcp-stdio') &&
          e.some((x) => x.span.traceId === tp.traceId && x.span.name === 'edgefetch.browser.render'),
        4000);
        assert.ok(collector.entries.some((e) => e.serviceName === 'edgefetch-mcp-stdio'), '[F8/M2] missing stdio MCP OTLP span');
        assert.ok(collector.findByTraceId(tp.traceId).some((e) => e.span.name === 'edgefetch.browser.render'), '[F9/M2] missing edgefetch.browser.render span');
      } finally {
        await goServe.close();
      }
    } finally {
      await origin.close();
      await collector.close();
    }
  });
});

// ===========================================================================
// TIER 4 — Real-World Application Scenarios (5 Tests: T4-1 .. T4-5)
// ===========================================================================

describe('Tier 4 — Real-World End-to-End Application Scenarios', () => {
  test('T4-1: Job-Hunt Pipeline (OAuth PKCE -> /mcp find_extractors -> /v1/jobs -> /v1/scrape -> read_artifact + OTLP) [F1-F4]', async () => {
    const collector = await startMockOtlpCollector();
    const hub = await startTestHub({ OTEL_EXPORTER_OTLP_ENDPOINT: collector.endpoint, OTEL_SERVICE_NAME: 'edgefetch-hub' }, suiteTmpDir);
    const longJobDesc = 'Build distributed systems at scale with EdgeFetch. '.repeat(120);
    const agent = await connectMockAgent({
      port: hub.port,
      agentToken: hub.agentToken,
      siteId: 'job-hunt-node',
      handler: async (reqItem, _msg, helpers) => {
        const u = String(reqItem.url || '');
        if (u.includes('t4-1-posting.example.com') || u.includes('jobs.ashbyhq.com/linear/ash-1')) {
          const html = `<html><head><title>Staff Systems Engineer - Linear</title></head><body><main><h1>Staff Systems Engineer</h1><p>${longJobDesc}</p></main></body></html>`;
          const art = await helpers.uploadArtifact(html, 'stored');
          return { status: 200, outcome: 'ok', contentType: 'text/html', body: html, artifact: art };
        }
        return null;
      },
    });

    try {
      const flow = await runOAuthPkceFlow({ baseUrl: hub.baseUrl, callerToken: hub.callerToken });
      const oauthHdr = { authorization: `Bearer ${flow.tokens.access_token}`, 'content-type': 'application/json' };

      // 1. MCP find_extractors
      const tp1 = makeTraceIds('01');
      const mcpExt = await fetch(`${hub.baseUrl}/mcp`, {
        method: 'POST',
        headers: { ...oauthHdr, accept: 'application/json', traceparent: tp1.traceparent },
        body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'find_extractors', arguments: { category: 'jobs' } } }),
      });
      assert.equal(mcpExt.status, 200);
      assertTraceHeaders(mcpExt, { expectedTraceId: tp1.traceId, tag: '[T4-1]' });

      // 2. /v1/jobs search + verify
      const tp2 = makeTraceIds('01');
      const jobsRes = await fetch(`${hub.baseUrl}/v1/jobs`, {
        method: 'POST',
        headers: { ...oauthHdr, traceparent: tp2.traceparent },
        body: JSON.stringify({ mode: 'verify', urls: ['https://jobs.ashbyhq.com/linear/ash-1'] }),
      });
      assert.equal(jobsRes.status, 200);
      const jobsJson = await jobsRes.json();
      assert.equal(jobsJson.results?.[0]?.status, 'live');

      // 3. /v1/scrape with maxChars truncation + read_artifact paging
      const tp3 = makeTraceIds('01');
      const scrRes = await fetch(`${hub.baseUrl}/v1/scrape`, {
        method: 'POST',
        headers: { ...oauthHdr, traceparent: tp3.traceparent },
        body: JSON.stringify({ url: 'https://t4-1-posting.example.com/job/123', maxChars: 600 }),
      });
      assert.equal(scrRes.status, 200);
      const scrJson = await scrRes.json();
      const artId = scrJson.markdownArtifactId || scrJson.artifactId;
      assert.ok(artId, 'expected markdownArtifactId on truncated job posting');

      const tp4 = makeTraceIds('01');
      const artRes = await fetch(`${hub.baseUrl}/v1/artifacts/${artId}?offset=0&limit=500`, {
        headers: { authorization: `Bearer ${flow.tokens.access_token}`, traceparent: tp4.traceparent },
      });
      assert.equal(artRes.status, 200);
      assertTraceHeaders(artRes, { expectedTraceId: tp4.traceId, tag: '[T4-1 read_artifact]' });

      await collector.waitForSpans((e) =>
        e.some((x) => x.span.traceId === tp2.traceId && x.span.name === 'edgefetch.jobs') &&
        e.some((x) => x.span.traceId === tp3.traceId && x.span.name === 'edgefetch.scrape'),
      );
      assert.ok(collector.findByTraceId(tp2.traceId).some((e) => e.span.name === 'edgefetch.jobs'), '[F2/M1] missing edgefetch.jobs span');
      assertNoLeakedSecrets(collector.entries, [flow.tokens.access_token, hub.callerToken], '[T4-1]');
    } finally {
      await agent.close();
      await hub.close();
      await collector.close();
    }
  });

  test('T4-2: Storefront Catalog Monitoring & Diff Pipeline (Python SDK -> /v1/catalog -> Content-Signal) [F2/F14/F16]', async () => {
    const collector = await startMockOtlpCollector();
    const hub = await startTestHub({ OTEL_EXPORTER_OTLP_ENDPOINT: collector.endpoint }, suiteTmpDir);
    let catalogRun = 0;
    const agent = await connectMockAgent({
      port: hub.port,
      agentToken: hub.agentToken,
      siteId: 'catalog-node',
      handler: async (reqItem) => {
        const u = String(reqItem.url || '');
        if (u.includes('cs-store.example.com')) {
          return { status: 451, outcome: 'content_signal_disallowed', problem: 'content-signal: ai-input=no' };
        }
        if (u.includes('/products.json')) {
          const isNextPage = /(?:\?|&)page=(?:[2-9]|\d{2,})/.test(u) || u.includes('page_info=');
          const price = catalogRun >= 2 ? '129.00' : '149.00';
          return {
            status: 200,
            outcome: 'ok',
            contentType: 'application/json',
            body: JSON.stringify({
              products: isNextPage
                ? []
                : [
                    {
                      id: 1001,
                      title: 'EdgeFetch Mechanical Keyboard',
                      handle: 'ef-keyboard',
                      vendor: 'EdgeFetchCo',
                      product_type: 'Hardware',
                      variants: [{ id: 2001, title: 'Default', price, available: true, sku: 'EF-KB-1' }],
                    },
                    ...(catalogRun >= 2
                      ? [{
                          id: 1002,
                          title: 'EdgeFetch Mousepad',
                          handle: 'ef-pad',
                          vendor: 'EdgeFetchCo',
                          product_type: 'Accessories',
                          variants: [{ id: 2002, title: 'XL', price: '29.00', available: true, sku: 'EF-PAD-1' }],
                        }]
                      : []),
                  ],
            }),
          };
        }
        return null;
      },
    });

    try {
      catalogRun = 1;
      const tp1 = makeTraceIds('01');
      const pyScript1 = `
import json, os
from edgefetch_client import EdgeFetchClient
c = EdgeFetchClient(token=os.environ["TOK"], base_url=os.environ["URL"], traceparent=os.environ["TP"])
res = c._request_json("POST", "/v1/catalog", {"url": "https://shop-t4-2.example.com", "platform": "shopify", "sync": True}, traceparent=os.environ["TP"])
recs = c._request_json("GET", f"/v1/catalog/{res['catalogId']}/records?offset=0&limit=10", traceparent=os.environ["TP"])
print(json.dumps({"cat": res, "recs": recs, "tid": c.last_trace_id}))
`;
      const { stdout: out1 } = await runPythonSdk(pyBin, pyScript1, { TOK: hub.callerToken, URL: hub.baseUrl, TP: tp1.traceparent });
      const p1 = JSON.parse(out1);
      assert.equal(p1.tid, tp1.traceId, '[F14/M3] Python catalog last_trace_id mismatch');
      assert.ok(p1.recs.records?.length === 1);

      catalogRun = 2;
      const tp2 = makeTraceIds('01');
      const { stdout: out2 } = await runPythonSdk(pyBin, pyScript1, { TOK: hub.callerToken, URL: hub.baseUrl, TP: tp2.traceparent });
      const p2 = JSON.parse(out2);
      assert.equal(p2.tid, tp2.traceId);
      assert.ok(p2.recs.records?.length === 2);

      // Content-Signal blocked store
      const tp3 = makeTraceIds('01');
      const csRes = await fetch(`${hub.baseUrl}/v1/scrape`, {
        method: 'POST',
        headers: { authorization: `Bearer ${hub.callerToken}`, 'content-type': 'application/json', traceparent: tp3.traceparent },
        body: JSON.stringify({ url: 'https://cs-store.example.com/products' }),
      });
      assert.equal((await csRes.json()).blocked?.reason, 'content-signal');

      await collector.waitForSpans((e) => e.some((x) => x.span.traceId === tp1.traceId && x.span.name === 'edgefetch.catalog'));
      assert.ok(collector.findByTraceId(tp1.traceId).some((e) => e.span.name === 'edgefetch.catalog'), '[F2/M1] missing edgefetch.catalog span');
    } finally {
      await agent.close();
      await hub.close();
      await collector.close();
    }
  });

  test('T4-3: Autonomous BYO-LLM Research Agent with SSE & Trace Bridge [F2/F3/M1]', async () => {
    const collector = await startMockOtlpCollector();
    const searxSrv = await startHttpServer((_req, res) => {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ results: [{ url: 'https://rubygems.org/gems/rails', title: 'Rails Gem', content: 'Ruby on Rails framework' }] }));
    });
    const llmSecret = 'sk-byo-llm-t4-3-canary';
    let llmCallCount = 0;
    const llmSrv = await startHttpServer((_req, res) => {
      llmCallCount++;
      res.writeHead(200, { 'content-type': 'application/json' });
      if (llmCallCount === 1) {
        res.end(JSON.stringify({
          choices: [{
            index: 0,
            message: {
              role: 'assistant',
              content: '',
              tool_calls: [{
                id: 'call_scrape_rails',
                type: 'function',
                function: {
                  name: 'scrape_url',
                  arguments: JSON.stringify({ url: 'https://rubygems.org/gems/rails' }),
                },
              }],
            },
            finish_reason: 'tool_calls',
          }],
          usage: { prompt_tokens: 15, completion_tokens: 12, total_tokens: 27 },
        }));
        return;
      }
      res.end(JSON.stringify({
        choices: [{ index: 0, message: { role: 'assistant', content: '{"framework":"Rails","version":"8.0.1"}' }, finish_reason: 'stop' }],
        usage: { prompt_tokens: 15, completion_tokens: 12, total_tokens: 27 },
      }));
    });
    const hub = await startTestHub({
      OTEL_EXPORTER_OTLP_ENDPOINT: collector.endpoint,
      SEARXNG_URL: searxSrv.url,
      EDGEFETCH_LLM_PROVIDER: 'openai',
      EDGEFETCH_LLM_BASE_URL: `${llmSrv.url}/v1`,
      EDGEFETCH_LLM_API_KEY: llmSecret,
    }, suiteTmpDir);
    const agent = await connectMockAgent({ port: hub.port, agentToken: hub.agentToken, siteId: 'research-node' });

    try {
      const { traceId, traceparent } = makeTraceIds('01');
      const sseRes = await fetch(`${hub.baseUrl}/v1/agent`, {
        method: 'POST',
        headers: {
          authorization: `Bearer ${hub.callerToken}`,
          'content-type': 'application/json',
          accept: 'text/event-stream',
          traceparent,
        },
        body: JSON.stringify({
          prompt: 'Extract Rails gem version',
          urls: ['https://rubygems.org/gems/rails'],
          strictConstrainToURLs: true,
          schema: { type: 'object', properties: { framework: { type: 'string' }, version: { type: 'string' } } },
          maxSteps: 2,
        }),
      });
      assert.equal(sseRes.status, 200);
      assertTraceHeaders(sseRes, { expectedTraceId: traceId, tag: '[T4-3 SSE]' });
      const sseText = await sseRes.text();
      assert.match(sseText, /event:\s*agent\.started/);
      assert.match(sseText, /event:\s*agent\.completed/);
      const idMatch = /"(agt_[a-zA-Z0-9_-]+)"/.exec(sseText);
      assert.ok(idMatch, 'SSE stream missing agent run id');

      const traceRes = await fetch(`${hub.baseUrl}/v1/agent/${idMatch[1]}/trace`, {
        headers: { authorization: `Bearer ${hub.callerToken}` },
      });
      assert.equal(traceRes.status, 200);
      const traceJson = await traceRes.json();
      assert.ok(Array.isArray(traceJson.spans) || Array.isArray(traceJson.events));

      await collector.waitForSpans((e) =>
        e.some((x) => x.span.traceId === traceId && x.span.name === 'edgefetch.agent') &&
        e.some((x) => x.span.traceId === traceId && x.span.name === 'edgefetch.llm.turn'),
      );
      const otlpSpans = collector.findByTraceId(traceId);
      assert.ok(otlpSpans.some((e) => e.span.name === 'edgefetch.agent'), '[F2/M1] missing edgefetch.agent span');
      assert.ok(otlpSpans.some((e) => e.span.name === 'edgefetch.llm.turn'), '[F3/M1] missing edgefetch.llm.turn span');
      assert.ok(otlpSpans.some((e) => getOtlpAttrValue(e.span.attributes, 'edgefetch.adapter_id') === 'rubygems'), '[F3/M1] missing edgefetch.adapter_id');
      assertNoLeakedSecrets(otlpSpans, [llmSecret, hub.callerToken], '[T4-3]');
    } finally {
      await agent.close();
      await hub.close();
      await Promise.all([searxSrv.close(), llmSrv.close()]);
      await collector.close();
    }
  });

  test('T4-4: Multi-Turn Browser Session + Clipper + FTS5 RAG [F2/F3/F13]', async () => {
    const collector = await startMockOtlpCollector();
    const hub = await startTestHub({ OTEL_EXPORTER_OTLP_ENDPOINT: collector.endpoint }, suiteTmpDir);
    const agent = await connectMockAgent({
      port: hub.port,
      agentToken: hub.agentToken,
      siteId: 'rag-browser-node',
      capabilities: ['artifacts-v1', 'browser-v1'],
      handler: async (reqItem) => {
        if (reqItem.interact) {
          return {
            status: 200,
            outcome: 'ok',
            contentType: 'text/html',
            body: '<html><body><main><h1>Session Step</h1></main></body></html>',
            markdown: '# Session Step',
            sessionId: reqItem.interact.sessionId || 'efsess_t4_4_tab',
            rendered: true,
          };
        }
        return null;
      },
    });

    try {
      const client = new tsSdk.EdgeFetchClient({ baseUrl: hub.baseUrl, token: hub.callerToken });
      const colId = 'col_t4_4_rag';

      // 1. Clip tab
      const tpClip = makeTraceIds('01');
      const clipRes = await fetch(`${hub.baseUrl}/v1/ingest-tab`, {
        method: 'POST',
        headers: { authorization: `Bearer ${hub.callerToken}`, 'content-type': 'application/json', traceparent: tpClip.traceparent },
        body: JSON.stringify({
          url: 'https://t4-4.example.com/clipped',
          title: 'RAG Clip',
          html: '<main><h1>RAG Clip</h1><p>NebulaPhoenix42 indexing verification snippet.</p></main>',
          collectionId: colId,
        }),
      });
      assert.equal(clipRes.status, 200);

      // 2. /v1/extract into collectionId
      const tpExt = makeTraceIds('01');
      await client.extract({ urls: ['https://t4-4.example.com/doc'], collectionId: colId }, { traceparent: tpExt.traceparent });
      assert.equal(client.lastTraceId, tpExt.traceId);

      // 3. /mcp search_collection
      const tpRag = makeTraceIds('01');
      const mcpRag = await fetch(`${hub.baseUrl}/mcp`, {
        method: 'POST',
        headers: { authorization: `Bearer ${hub.mcpToken}`, 'content-type': 'application/json', accept: 'application/json', traceparent: tpRag.traceparent },
        body: JSON.stringify({
          jsonrpc: '2.0',
          id: 1,
          method: 'tools/call',
          params: { name: 'search_collection', arguments: { collectionId: colId, query: 'NebulaPhoenix42', limit: 5 } },
        }),
      });
      assert.equal(mcpRag.status, 200);
      const mcpJson = await mcpRag.json();
      assert.ok(JSON.stringify(mcpJson).includes('NebulaPhoenix42'));

      // 4. Two-turn /v1/interact
      const tpTurn1 = makeTraceIds('01');
      const turn1 = await client.interact(
        { url: 'https://t4-4.example.com/app', keepSession: true, actions: [{ type: 'click', selector: '#login' }] },
        { traceparent: tpTurn1.traceparent },
      );
      assert.ok(turn1.sessionId);

      const tpTurn2 = makeTraceIds('01');
      const turn2 = await client.interact(
        { sessionId: turn1.sessionId, closeSession: true, actions: [{ type: 'wait', waitMs: 25 }] },
        { traceparent: tpTurn2.traceparent },
      );
      assert.equal(turn2.closed, true);

      await collector.waitForSpans((e) => e.some((x) => x.span.traceId === tpTurn1.traceId && x.span.name === 'edgefetch.interact'));
      const iSpan = collector.findByTraceId(tpTurn1.traceId).find((e) => e.span.name === 'edgefetch.interact');
      assert.ok(iSpan && getOtlpAttrValue(iSpan.span.attributes, 'edgefetch.interact.session_hash'), '[F3/M1] missing session_hash');
    } finally {
      await agent.close();
      await hub.close();
      await collector.close();
    }
  });

  test('T4-5: Multi-Controller HA Failover + Signed Web Bot Auth + Admin Audit + Cross-Process OTLP [F1/F4/F9/F13/F14/F17]', async () => {
    const collector = await startMockOtlpCollector();
    const kp = generateEd25519Keypair();
    const origin = await startMockOrigin();
    const standby503 = await startHttpServer((_req, res) => {
      res.writeHead(503, { 'content-type': 'application/json', 'x-trace-id': randomBytes(16).toString('hex') });
      res.end(JSON.stringify({ error: 'standby_unavailable' }));
    });
    const { callerToken: goHubTok, agentToken } = makeTokens();
    const hub = await startTestHub({
      AGENT_TOKEN: agentToken,
      BOT_SIGNING_PRIVATE_KEY: kp.privateKeySeed,
      OTEL_EXPORTER_OTLP_ENDPOINT: collector.endpoint,
      OTEL_SERVICE_NAME: 'edgefetch-hub',
    }, suiteTmpDir);
    const goAgent = await startGoAgent({
      bin: goBin,
      hubUrl: hub.baseUrl,
      agentToken,
      siteId: 't4-5-go-agent',
      allowPrivate: true,
      callerToken: hub.callerToken,
      env: {
        EDGEFETCH_BOT_SIGNING_KEY: kp.privateKeySeed,
        EDGEFETCH_BOT_DIRECTORY_URL: `${hub.baseUrl}/.well-known/http-message-signatures-directory`,
        OTEL_EXPORTER_OTLP_ENDPOINT: collector.endpoint,
      },
    });
    const goServe = await startGoHub({
      bin: goBin,
      args: ['--mode=hub', '--addr=127.0.0.1:{PORT}', '--allow-private'],
      env: {
        EDGEFETCH_CALLER_TOKEN: goHubTok,
        EDGEFETCH_BOT_SIGNING_KEY: kp.privateKeySeed,
        OTEL_EXPORTER_OTLP_ENDPOINT: collector.endpoint,
        OTEL_SERVICE_NAME: 'edgefetch-go-hub-t4-5',
      },
    });

    try {
      // 1. /admin login + /admin/api/fetch
      const sess = await adminLogin(hub.baseUrl, hub.callerToken);
      const adminFetch = await fetch(`${hub.baseUrl}/admin/api/fetch`, {
        method: 'POST',
        headers: { cookie: sess.cookie, 'x-csrf-token': sess.csrf, 'content-type': 'application/json' },
        body: JSON.stringify({ url: 'https://t4-5.invalid/admin-probe', kind: 'scrape', target: 'agent', site: 't4-5-go-agent' }),
      });
      assert.equal(adminFetch.status, 200);

      // 2. TS & Python HA failover [standby503, portableHub] -> Go Agent cross-process OTLP
      const tpTs = makeTraceIds('01');
      const tsClient = new tsSdk.EdgeFetchClient({
        baseUrls: [standby503.url, hub.baseUrl],
        token: hub.callerToken,
        traceparent: tpTs.traceparent,
      });
      await tsClient.scrape({ url: 'https://t4-5.invalid/ha-ts', site: 't4-5-go-agent', target: 'agent' }).catch(() => undefined);
      assert.equal(tsClient.lastTraceId, tpTs.traceId, '[F13/M3] TS HA failover traceId mismatch');

      // 3. Go signed fetch to local origin -> TS verifies RFC 9421 signature
      const tpSign = makeTraceIds('01');
      await fetch(`${goServe.baseUrl}/v1/scrape`, {
        method: 'POST',
        headers: { authorization: `Bearer ${goHubTok}`, 'content-type': 'application/json', traceparent: tpSign.traceparent },
        body: JSON.stringify({ url: `${origin.url}/t4-5-signed` }),
      });
      const rec = origin.recorded.find((r) => r.url === '/t4-5-signed');
      assert.ok(rec);
      assert.equal(
        (await hubBotAuth.verifyBotRequestSignature(new Request(`${origin.url}/t4-5-signed`, { method: 'GET', headers: rec.headers }), kp.publicKeyB64Url)).ok,
        true,
      );

      // 4. OAuth grant + /admin/api/grants/revoke + logout
      const flow = await runOAuthPkceFlow({ baseUrl: hub.baseUrl, callerToken: hub.callerToken });
      const st = await (await fetch(`${hub.baseUrl}/admin/api/state`, { headers: { cookie: sess.cookie } })).json();
      assert.ok(st.grants.length >= 1);
      const rev = await fetch(`${hub.baseUrl}/admin/api/grants/revoke`, {
        method: 'POST',
        headers: { cookie: sess.cookie, 'x-csrf-token': sess.csrf, 'content-type': 'application/json' },
        body: JSON.stringify({ grantId: st.grants[0].grantId }),
      });
      assert.equal(rev.status, 200);
      await fetch(`${hub.baseUrl}/admin/logout`, {
        method: 'POST',
        redirect: 'manual',
        headers: { cookie: sess.cookie, 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ csrf: sess.csrf }).toString(),
      });

      await collector.waitForSpans((e) =>
        e.some((x) => x.span.traceId === tpTs.traceId && x.serviceName === 'edgefetch-hub') &&
        e.some((x) => x.span.traceId === tpTs.traceId && x.serviceName === 'edgefetch-agent-t4-5-go-agent') &&
        e.some((x) => x.span.name.startsWith('edgefetch.admin.')),
      4500);
      assert.ok(collector.findByTraceId(tpTs.traceId).some((e) => e.serviceName === 'edgefetch-agent-t4-5-go-agent'), '[F1/F10] missing Go agent span on HA failover');
      assert.ok(collector.entries.some((e) => e.span.name.startsWith('edgefetch.admin.')), '[F4/M1] missing admin audit spans');
      assertNoLeakedSecrets(collector.entries, [hub.callerToken, agentToken, flow.tokens.access_token, sess.cookieVal, sess.csrf], '[T4-5]');
    } finally {
      await goServe.close();
      await goAgent.close();
      await hub.close();
      await Promise.all([standby503.close(), origin.close()]);
      await collector.close();
    }
  });
});
