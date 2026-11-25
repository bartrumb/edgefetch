/**
 * EdgeFetch Milestone M5 — Cross-Process Full-Stack OTLP E2E & Bidirectional
 * Go <-> TypeScript RFC 9421 Web Bot Auth Contract (`test/fullstack-otel.e2e.mjs`).
 *
 * Features verified end-to-end:
 *  - F16: Cross-Process Full-Stack OTLP E2E (`EdgeFetchClient` -> `startPortableHub`
 *         -> WebSocket `dispatch` -> compiled Go `edgefetch --mode=agent --allow-private`
 *         -> local HTTP mock origins -> local HTTP mock OTLP collector) across:
 *         1) `scrape` (with `?api_key=super-secret-do-not-leak` secret redaction check),
 *         2) `jobs` (Greenhouse ATS board discovery + JSON feed),
 *         3) `catalog` (Shopify `/products.json` pagination),
 *         4) `search` (FTS5 collection + mocked SearXNG JSON search),
 *         5) `Content-Signal: ai-input=no` policy enforcement,
 *         6) HTTP `402 Payment Required` (`x402`) handling.
 *  - F17: Bidirectional Go <-> TypeScript IETF RFC 9421 Web Bot Auth Contract:
 *         1) TypeScript sign (`signOutboundBotHeaders` + `signDirectoryResponse` +
 *            live Portable Hub directory) -> Go `internal/botauth` (`VerifyRequest` +
 *            `VerifyDirectoryResponse` + `ComputeJWKThumbprint`),
 *         2) Go sign (`edgefetch --mode=agent` outbound crawler + `edgefetch --mode=hub`
 *            directory self-signature) -> TypeScript `verifyBotRequestSignature` +
 *            `verifyDirectoryResponseSignature`.
 *
 * Cross-platform: runs seamlessly on both Ubuntu Linux CI (`go` on PATH) and Windows
 * hosts (native `GOOS=windows GOARCH=amd64` cross-compile via WSL Go fallback).
 */

import test, { after, before, describe } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync, spawn } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import {
  existsSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import http from 'node:http';
import { stripTypeScriptTypes } from 'node:module';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { gunzipSync } from 'node:zlib';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, '..');

const ALL_ZERO_32 = '0'.repeat(32);
const ALL_ZERO_16 = '0'.repeat(16);
const RE_TRACE_ID = /^[0-9a-f]{32}$/;
const RE_SPAN_ID = /^[0-9a-f]{16}$/;

function resolveRealTmpDir(prefix) {
  const raw = mkdtempSync(path.join(os.tmpdir(), prefix));
  try {
    return typeof realpathSync.native === 'function' ? realpathSync.native(raw) : realpathSync(raw);
  } catch {
    return raw;
  }
}

function toWslPath(winPath) {
  const abs = path.resolve(winPath).replace(/\\/g, '/');
  const m = /^([A-Za-z]):\/(.*)$/.exec(abs);
  if (!m) return abs;
  return `/mnt/${m[1].toLowerCase()}/${m[2]}`;
}

function makeTraceIds(flags = '01') {
  const traceId = randomBytes(16).toString('hex');
  const parentSpanId = randomBytes(8).toString('hex');
  return {
    traceId,
    parentSpanId,
    traceparent: `00-${traceId}-${parentSpanId}-${flags}`,
  };
}

function makeTokens() {
  return {
    callerToken: `ef_caller_${randomBytes(18).toString('hex')}`,
    mcpToken: `ef_mcp_${randomBytes(18).toString('hex')}`,
    agentToken: `ef_agent_${randomBytes(18).toString('hex')}`,
  };
}

function getOtlpAttrValue(attrs, key) {
  if (!Array.isArray(attrs)) return undefined;
  const entry = attrs.find((a) => a && a.key === key);
  if (!entry || !entry.value || typeof entry.value !== 'object') return undefined;
  if ('stringValue' in entry.value) return entry.value.stringValue;
  if ('boolValue' in entry.value) return entry.value.boolValue;
  if ('intValue' in entry.value) return Number(entry.value.intValue);
  if ('doubleValue' in entry.value) return Number(entry.value.doubleValue);
  return undefined;
}

function validateOtlpSpan(span, label = 'span') {
  assert.ok(span && typeof span === 'object', `${label}: span must be an object`);
  assert.ok(
    typeof span.traceId === 'string' && RE_TRACE_ID.test(span.traceId) && span.traceId !== ALL_ZERO_32,
    `${label}: invalid traceId ${JSON.stringify(span.traceId)}`,
  );
  assert.ok(
    typeof span.spanId === 'string' && RE_SPAN_ID.test(span.spanId) && span.spanId !== ALL_ZERO_16,
    `${label}: invalid spanId ${JSON.stringify(span.spanId)}`,
  );
  if (span.parentSpanId !== undefined && span.parentSpanId !== '') {
    assert.ok(
      typeof span.parentSpanId === 'string' && RE_SPAN_ID.test(span.parentSpanId) && span.parentSpanId !== ALL_ZERO_16,
      `${label}: invalid parentSpanId ${JSON.stringify(span.parentSpanId)}`,
    );
  }
  assert.ok(typeof span.name === 'string' && span.name.length > 0, `${label}: empty span name`);
  const start = BigInt(span.startTimeUnixNano);
  const end = BigInt(span.endTimeUnixNano);
  assert.ok(start > 0n, `${label}: startTimeUnixNano must be > 0`);
  assert.ok(end >= start, `${label}: endTimeUnixNano (${end}) < startTimeUnixNano (${start})`);
}

function assertNoSecretsInOtlp(requests, entries, secrets) {
  const serializedReqs = JSON.stringify(requests);
  const serializedEntries = JSON.stringify(entries);
  for (const secret of secrets) {
    if (!secret || secret.length < 4) continue;
    assert.equal(
      serializedReqs.includes(secret),
      false,
      `Secret leaked in raw OTLP collector request payload (prefix "${secret.slice(0, 4)}...")`,
    );
    assert.equal(
      serializedEntries.includes(secret),
      false,
      `Secret leaked in parsed OTLP span entries (prefix "${secret.slice(0, 4)}...")`,
    );
  }
  for (const entry of entries) {
    const urlFull = getOtlpAttrValue(entry.span?.attributes, 'url.full') ?? getOtlpAttrValue(entry.span?.attributes, 'http.url');
    if (typeof urlFull === 'string') {
      assert.equal(urlFull.includes('?'), false, `Span ${entry.span?.name} leaked query string in url.full: ${urlFull}`);
      assert.equal(
        /@/.test(urlFull.replace(/^https?:\/\//, '').split('/')[0] || ''),
        false,
        `Span ${entry.span?.name} leaked userinfo in url.full: ${urlFull}`,
      );
    }
  }
}

async function closeServerCleanly(server) {
  if (!server) return;
  await new Promise((resolve) => {
    server.close(() => resolve());
    server.closeIdleConnections?.();
    server.closeAllConnections?.();
  });
}

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

async function startHttpServer(handler, host = '127.0.0.1') {
  const server = http.createServer(handler);
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, host, resolve);
  });
  const addr = server.address();
  const port = typeof addr === 'object' && addr ? addr.port : 0;
  return {
    server,
    port,
    url: `http://${host}:${port}`,
    async close() {
      await closeServerCleanly(server);
    },
  };
}

async function startMockOtlpCollector() {
  const requests = [];
  const entries = [];
  const srv = await startHttpServer((req, res) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      let raw = Buffer.concat(chunks);
      if ((req.headers['content-encoding'] || '').toLowerCase().includes('gzip')) {
        try {
          raw = gunzipSync(raw);
        } catch {
          // keep raw bytes
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

  return {
    port: srv.port,
    endpoint: srv.url,
    tracesUrl: `${srv.url}/v1/traces`,
    requests,
    entries,
    findByTraceId(traceId) {
      return entries.filter((e) => e.span?.traceId === traceId);
    },
    async waitForSpans(predicate, timeoutMs = 6000, pollMs = 50) {
      const deadline = Date.now() + timeoutMs;
      while (Date.now() < deadline) {
        if (predicate(entries, requests)) return entries;
        await delay(pollMs);
      }
      return entries;
    },
    async close() {
      await srv.close();
    },
  };
}

function buildEdgefetchBinary(outDir) {
  if (process.env.EDGEFETCH_GO_BIN && existsSync(process.env.EDGEFETCH_GO_BIN)) {
    return { bin: process.env.EDGEFETCH_GO_BIN, useWslGo: process.platform === 'win32' };
  }
  const exeName = process.platform === 'win32' ? 'edgefetch.exe' : 'edgefetch';
  const outBin = path.join(outDir, exeName);

  try {
    execFileSync('go', ['build', '-o', outBin, './cmd/edgefetch'], {
      cwd: REPO_ROOT,
      stdio: 'pipe',
      timeout: 120_000,
    });
    return { bin: outBin, useWslGo: false };
  } catch (err) {
    if (process.platform !== 'win32') {
      throw new Error(`Failed to compile ./cmd/edgefetch via go on PATH: ${err?.message || err}`);
    }
  }

  const wslRepo = toWslPath(REPO_ROOT);
  const wslOut = toWslPath(outBin);
  const cmd = `export PATH=/home/brett/sdk/go1.27.4/bin:$PATH; cd '${wslRepo}' && GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -o '${wslOut}' ./cmd/edgefetch`;
  execFileSync('wsl', ['-e', 'bash', '-lc', cmd], {
    stdio: 'pipe',
    timeout: 120_000,
  });
  assert.ok(existsSync(outBin), `Expected compiled Windows Go binary at ${outBin}`);
  return { bin: outBin, useWslGo: true };
}

async function importStrippedTs(absPath) {
  let src = readFileSync(absPath, 'utf8');
  src = src.replace(/constructor\(([^)]*)\)/g, (m) => m.replace(/\b(?:public|private|protected)\s+(?:readonly\s+)?/g, ''));
  const js = stripTypeScriptTypes(src, { mode: 'strip' });
  const dataUrl = `data:text/javascript;base64,${Buffer.from(js, 'utf8').toString('base64')}`;
  return import(dataUrl);
}

async function bundleTypeScriptDeps() {
  const sdkMod = await importStrippedTs(path.join(REPO_ROOT, 'sdk', 'ts', 'edgefetch-client.ts'));
  const botAuthMod = await importStrippedTs(path.join(REPO_ROOT, 'hub', 'src', 'bot-auth.ts'));

  const startPortableHub = async ({ port = 0, host = '127.0.0.1', dataDir = '', envOverrides = {} } = {}) => {
    const chosenPort = port > 0 ? port : await allocPort();
    const child = trackChild(
      spawn(goBin, ['--mode=hub', `--addr=${host}:${chosenPort}`], {
        env: {
          ...process.env,
          EDGEFETCH_DATA_DIR: dataDir,
          EDGEFETCH_DISABLE_UPDATE_CHECK: '1',
          OTEL_BSP_SCHEDULE_DELAY: '50',
          ...envOverrides,
        },
        stdio: ['ignore', 'pipe', 'pipe'],
      }),
    );
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (d) => { stdout += d.toString('utf8'); });
    child.stderr.on('data', (d) => { stderr += d.toString('utf8'); });
    const deadline = Date.now() + 10_000;
    let ready = false;
    while (Date.now() < deadline) {
      if (child.exitCode !== null) {
        throw new Error(`Go hub exited early (${child.exitCode})\nstdout:\n${stdout}\nstderr:\n${stderr}`);
      }
      try {
        const r = await fetch(`http://${host}:${chosenPort}/healthz`);
        if (r.ok) {
          ready = true;
          break;
        }
      } catch {
        // retry
      }
      await delay(50);
    }
    if (!ready) {
      await killChildCleanly(child);
      throw new Error(`Go hub failed to become ready on ${host}:${chosenPort}\nstdout:\n${stdout}\nstderr:\n${stderr}`);
    }
    return {
      port: chosenPort,
      async close() {
        await delay(120);
        await killChildCleanly(child);
      },
    };
  };

  return {
    startPortableHub,
    EdgeFetchClient: sdkMod.EdgeFetchClient,
    EdgeFetchError: sdkMod.EdgeFetchError,
    computeEd25519JwkThumbprint: botAuthMod.computeEd25519JwkThumbprint,
    generateBotAuthKeyPair: botAuthMod.generateBotAuthKeyPair,
    signDirectoryResponse: botAuthMod.signDirectoryResponse,
    signOutboundBotHeaders: botAuthMod.signOutboundBotHeaders,
    verifyBotRequestSignature: botAuthMod.verifyBotRequestSignature,
    verifyDirectoryResponseSignature: botAuthMod.verifyDirectoryResponseSignature,
  };
}

const activeChildren = new Set();

function trackChild(child) {
  if (!child) return child;
  activeChildren.add(child);
  const cleanup = () => activeChildren.delete(child);
  child.once('exit', cleanup);
  child.once('close', cleanup);
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
    activeChildren.delete(child);
    return;
  }
  // Allow Go's 1s background OTLP batch ticker to flush any queued spans before termination on Windows
  await delay(1250);
  if (child.exitCode !== null || child.signalCode !== null) {
    destroyStreams();
    activeChildren.delete(child);
    return;
  }
  await new Promise((resolve) => {
    let settled = false;
    let forceTimer;
    const finish = () => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      clearTimeout(forceTimer);
      destroyStreams();
      activeChildren.delete(child);
      resolve();
    };
    const timer = setTimeout(() => {
      try { child.kill('SIGKILL'); } catch {}
      if (process.platform === 'win32' && child.pid) {
        try {
          execFileSync('taskkill', ['/PID', String(child.pid), '/T', '/F'], { stdio: 'ignore', timeout: 3000 });
        } catch {}
      }
      forceTimer = setTimeout(finish, 1000);
    }, 2000);
    child.once('close', finish);
    child.once('exit', () => setTimeout(finish, 30));
    try {
      child.kill(process.platform === 'win32' ? undefined : 'SIGTERM');
    } catch {
      finish();
    }
  });
}

/**
 * Transparent local HTTP + WebSocket bridge between the compiled Go `--mode=agent --allow-private`
 * worker and `startPortableHub`:
 *  - Preserves W3C `msg.trace` (`traceparent`, `x-trace-id`, `x-span-id`, `x-request-id`),
 *    `jobId`, `jobNonce`, and R2 gzipped artifact uploads untouched.
 *  - Maps public `https://<virtualHost>` URLs validated by the Hub onto local mock HTTP origins
 *    (`http://127.0.0.1:<mockPort>`) so the real Go `--mode=agent` binary executes live `robots.txt`,
 *    RFC 9421 signing, HTTP fetches, and OTLP exports against local ephemeral servers with zero external DNS.
 */
function encodeWsFrame(payloadBuf, opcode = 0x1, maskFrame = false) {
  const len = payloadBuf.length;
  const maskBit = maskFrame ? 0x80 : 0;
  let hdr;
  if (len < 126) {
    hdr = Buffer.from([0x80 | opcode, maskBit | len]);
  } else if (len < 65536) {
    hdr = Buffer.alloc(4);
    hdr[0] = 0x80 | opcode;
    hdr[1] = maskBit | 126;
    hdr.writeUInt16BE(len, 2);
  } else {
    hdr = Buffer.alloc(10);
    hdr[0] = 0x80 | opcode;
    hdr[1] = maskBit | 127;
    hdr.writeBigUInt64BE(BigInt(len), 2);
  }
  if (!maskFrame) return Buffer.concat([hdr, payloadBuf]);
  const mask = randomBytes(4);
  const masked = Buffer.alloc(len);
  for (let i = 0; i < len; i++) masked[i] = payloadBuf[i] ^ mask[i & 3];
  return Buffer.concat([hdr, mask, masked]);
}

function attachWsFrameDecoder(socket, initialHead, onFrame) {
  let buf = initialHead && initialHead.length ? Buffer.from(initialHead) : Buffer.alloc(0);
  const drain = () => {
    while (buf.length >= 2) {
      const opcode = buf[0] & 0x0f;
      const isMasked = (buf[1] & 0x80) !== 0;
      let len = buf[1] & 0x7f;
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
      onFrame(opcode, payload);
    }
  };
  socket.on('data', (chunk) => {
    buf = Buffer.concat([buf, chunk]);
    drain();
  });
  drain();
}

async function startAgentLocalOriginBridge({ hubPort, hostToLocalOrigin }) {
  const reverseUrlMap = new Map();

  function rewriteOutboundUrl(rawUrl) {
    if (typeof rawUrl !== 'string') return rawUrl;
    let parsed;
    try {
      parsed = new URL(rawUrl);
    } catch {
      return rawUrl;
    }
    const targetOrigin = hostToLocalOrigin[parsed.hostname.toLowerCase()];
    if (!targetOrigin) return rawUrl;
    const localBase = new URL(targetOrigin);
    const rewritten = `${localBase.origin}${parsed.pathname}${parsed.search}${parsed.hash}`;
    reverseUrlMap.set(`${localBase.origin}${parsed.pathname}${parsed.search}`, `${parsed.origin}${parsed.pathname}${parsed.search}`);
    reverseUrlMap.set(localBase.origin, parsed.origin);
    return rewritten;
  }

  function restoreInboundUrl(rawUrl) {
    if (typeof rawUrl !== 'string') return rawUrl;
    if (reverseUrlMap.has(rawUrl)) return reverseUrlMap.get(rawUrl);
    for (const [localPrefix, publicPrefix] of reverseUrlMap.entries()) {
      if (localPrefix.startsWith('http://127.') && rawUrl.startsWith(`${localPrefix}/`)) {
        return `${publicPrefix}${rawUrl.slice(localPrefix.length)}`;
      }
    }
    return rawUrl;
  }

  const openSockets = new Set();

  const server = http.createServer((req, res) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      let bodyBuf = Buffer.concat(chunks);
      if (req.method === 'POST' && (req.url || '').startsWith('/agent/reply')) {
        try {
          const isGz = (req.headers['content-encoding'] || '').toLowerCase().includes('gzip');
          const rawJsonBuf = isGz ? gunzipSync(bodyBuf) : bodyBuf;
          const parsed = JSON.parse(rawJsonBuf.toString('utf8'));
          if (Array.isArray(parsed?.results)) {
            for (const item of parsed.results) {
              if (item && typeof item === 'object') {
                if (typeof item.url === 'string') item.url = restoreInboundUrl(item.url);
                if (typeof item.finalUrl === 'string') item.finalUrl = restoreInboundUrl(item.finalUrl);
              }
            }
            bodyBuf = Buffer.from(JSON.stringify(parsed), 'utf8');
            delete req.headers['content-encoding'];
          }
        } catch {
          // forward raw bytes if non-JSON
        }
      }

      const fwdHeaders = { ...req.headers, host: `127.0.0.1:${hubPort}`, 'content-length': String(bodyBuf.byteLength) };
      const proxyReq = http.request(
        {
          host: '127.0.0.1',
          port: hubPort,
          method: req.method,
          path: req.url,
          headers: fwdHeaders,
        },
        (proxyRes) => {
          res.writeHead(proxyRes.statusCode || 502, proxyRes.headers);
          proxyRes.pipe(res);
        },
      );
      proxyReq.on('error', (err) => {
        res.writeHead(502, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ error: 'bridge_error', message: err.message }));
      });
      if (bodyBuf.byteLength > 0) proxyReq.write(bodyBuf);
      proxyReq.end();
    });
  });

  server.on('upgrade', (req, agentSock, agentHead) => {
    agentSock.on('error', () => undefined);
    const secKey = req.headers['sec-websocket-key'];
    if (!secKey) {
      agentSock.destroy();
      return;
    }
    const acceptVal = createHash('sha1')
      .update(`${secKey}258EAFA5-E914-47DA-95CA-C5AB0DC85B11`)
      .digest('base64');

    const upstreamHeaders = {
      Connection: 'Upgrade',
      Upgrade: 'websocket',
      'Sec-WebSocket-Key': randomBytes(16).toString('base64'),
      'Sec-WebSocket-Version': '13',
    };
    for (const [k, v] of Object.entries(req.headers)) {
      const lower = k.toLowerCase();
      if (lower === 'authorization' || lower.startsWith('x-agent-') || lower === 'user-agent' || lower === 'sec-websocket-protocol') {
        upstreamHeaders[k] = v;
      }
    }

    const upReq = http.request({
      host: '127.0.0.1',
      port: hubPort,
      path: req.url || '/agent/ws',
      method: 'GET',
      headers: upstreamHeaders,
    });
    upReq.on('error', () => agentSock.destroy());
    upReq.on('response', (res) => {
      agentSock.write(`HTTP/1.1 ${res.statusCode || 401} Unauthorized\r\nConnection: close\r\n\r\n`);
      agentSock.destroy();
    });
    upReq.on('upgrade', (upRes, hubSock, hubHead) => {
      hubSock.on('error', () => undefined);
      openSockets.add(agentSock);
      openSockets.add(hubSock);

      const subProto = upRes.headers['sec-websocket-protocol'];
      const respLines = [
        'HTTP/1.1 101 Switching Protocols',
        'Upgrade: websocket',
        'Connection: Upgrade',
        `Sec-WebSocket-Accept: ${acceptVal}`,
      ];
      if (subProto) respLines.push(`Sec-WebSocket-Protocol: ${subProto}`);
      respLines.push('', '');
      agentSock.write(respLines.join('\r\n'));

      const closeBoth = () => {
        openSockets.delete(agentSock);
        openSockets.delete(hubSock);
        agentSock.destroy();
        hubSock.destroy();
      };
      agentSock.on('close', closeBoth);
      hubSock.on('close', closeBoth);

      attachWsFrameDecoder(agentSock, agentHead, (opcode, payload) => {
        if (opcode === 0x8) {
          closeBoth();
          return;
        }
        if (opcode === 0x9) {
          agentSock.write(encodeWsFrame(payload, 0x0a, false));
          return;
        }
        hubSock.write(encodeWsFrame(payload, opcode, true));
      });

      attachWsFrameDecoder(hubSock, hubHead, (opcode, payload) => {
        if (opcode === 0x8) {
          closeBoth();
          return;
        }
        if (opcode === 0x9) {
          hubSock.write(encodeWsFrame(payload, 0x0a, true));
          return;
        }
        if (opcode === 0x1) {
          try {
            const msg = JSON.parse(payload.toString('utf8'));
            if (msg && msg.type === 'dispatch' && Array.isArray(msg.call?.requests)) {
              for (const r of msg.call.requests) {
                if (r && typeof r.url === 'string') r.url = rewriteOutboundUrl(r.url);
              }
              agentSock.write(encodeWsFrame(Buffer.from(JSON.stringify(msg), 'utf8'), 0x1, false));
              return;
            }
          } catch {
            // forward untouched
          }
        }
        agentSock.write(encodeWsFrame(payload, opcode, false));
      });
    });
    upReq.end();
  });

  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  const addr = server.address();
  const port = typeof addr === 'object' && addr ? addr.port : 0;

  return {
    port,
    url: `http://127.0.0.1:${port}`,
    async close() {
      for (const s of openSockets) {
        try { s.destroy(); } catch {}
      }
      openSockets.clear();
      await closeServerCleanly(server);
    },
  };
}

async function startRealGoAgent({
  bin,
  connectHubUrl,
  verifyHubBaseUrl,
  callerToken,
  agentToken,
  siteId,
  env = {},
}) {
  const child = trackChild(
    spawn(bin, ['--mode=agent', '--allow-private'], {
      env: {
        ...process.env,
        EDGEFETCH_ALLOW_INSECURE_HUB: '1',
        EDGEFETCH_HUB_URL: connectHubUrl,
        EDGEFETCH_AGENT_TOKEN: agentToken,
        EDGEFETCH_SITE_ID: siteId,
        EDGEFETCH_PAUSE_MS: '100',
        EDGEFETCH_PAUSE_JITTER_MS: '0',
        ...env,
      },
      stdio: ['ignore', 'pipe', 'pipe'],
    }),
  );

  let stdout = '';
  let stderr = '';
  child.stdout.on('data', (d) => { stdout += d.toString('utf8'); });
  child.stderr.on('data', (d) => { stderr += d.toString('utf8'); });

  const deadline = Date.now() + 12_000;
  let connected = false;
  while (Date.now() < deadline) {
    if (child.exitCode !== null) {
      throw new Error(`Go agent exited early (${child.exitCode})\nstdout:\n${stdout}\nstderr:\n${stderr}`);
    }
    try {
      const res = await fetch(`${verifyHubBaseUrl}/agents`, {
        headers: { authorization: `Bearer ${callerToken}` },
      });
      if (res.ok) {
        const json = await res.json();
        if (Array.isArray(json.agents) && json.agents.some((a) => a.siteId === siteId)) {
          connected = true;
          break;
        }
      }
    } catch {
      // retry until connected
    }
    await delay(80);
  }

  if (!connected) {
    await killChildCleanly(child);
    throw new Error(`Go agent ${siteId} failed to register on ${verifyHubBaseUrl}/agents\nstdout:\n${stdout}\nstderr:\n${stderr}`);
  }

  return {
    siteId,
    child,
    getLogs: () => ({ stdout, stderr }),
    async close() {
      await killChildCleanly(child);
    },
  };
}

/**
 * Runs Go `internal/botauth` (`VerifyRequest`, `VerifyDirectoryResponse`, `ComputeJWKThumbprint`,
 * `ParsePublicKey`) directly via `go test -overlay=<tmp>/overlay.json` without writing any file
 * into `REPO_ROOT`.
 */
function runGoBotAuthVerifyProbe({ tmpDir, useWslGo, fixture }) {
  const probeDir = resolveRealTmpDir('ef-go-botauth-probe-');
  try {
    const fixturePath = path.join(probeDir, 'ts-botauth-fixture.json');
    const virtualGoFile = path.join(REPO_ROOT, 'internal', 'botauth', 'zz_cross_lang_probe_test.go');
    const actualGoFile = path.join(probeDir, 'zz_cross_lang_probe_test.go');
    const overlayPath = path.join(probeDir, 'overlay.json');

    writeFileSync(fixturePath, JSON.stringify(fixture, null, 2), 'utf8');
    writeFileSync(
      actualGoFile,
      `package botauth

import (
	"encoding/json"
	"net/http"
	"os"
	"testing"
	"time"
)

type crossLangFixture struct {
	PublicKeyB64URL string            \`json:"publicKeyB64Url"\`
	ExpectedKid     string            \`json:"expectedKid"\`
	NowUnix         int64             \`json:"nowUnix"\`
	RequestMethod   string            \`json:"requestMethod"\`
	RequestURL      string            \`json:"requestUrl"\`
	RequestHeaders  map[string]string \`json:"requestHeaders"\`
	DirectoryURL    string            \`json:"directoryUrl"\`
	DirectoryBody   string            \`json:"directoryBody"\`
	DirectoryHdrs   map[string]string \`json:"directoryHeaders"\`
	LiveDirURL      string            \`json:"liveDirUrl"\`
	LiveDirBody     string            \`json:"liveDirBody"\`
	LiveDirHdrs     map[string]string \`json:"liveDirHeaders"\`
}

func TestCrossLangTSVerify(t *testing.T) {
	rawPath := os.Getenv("TS_BOTAUTH_FIXTURE_JSON")
	if rawPath == "" {
		t.Skip("TS_BOTAUTH_FIXTURE_JSON not set")
	}
	data, err := os.ReadFile(rawPath)
	if err != nil {
		t.Fatalf("ReadFile(%q): %v", rawPath, err)
	}
	var fx crossLangFixture
	if err := json.Unmarshal(data, &fx); err != nil {
		t.Fatalf("Unmarshal fixture: %v", err)
	}

	pub, err := ParsePublicKey(fx.PublicKeyB64URL)
	if err != nil {
		t.Fatalf("ParsePublicKey: %v", err)
	}
	gotKid, err := ComputeJWKThumbprint(pub)
	if err != nil {
		t.Fatalf("ComputeJWKThumbprint: %v", err)
	}
	if gotKid != fx.ExpectedKid {
		t.Fatalf("RFC 7638 thumbprint mismatch: Go=%q vs TS=%q", gotKid, fx.ExpectedKid)
	}

	now := time.Unix(fx.NowUnix, 0).UTC()

	// 1. Verify TS signOutboundBotHeaders request in Go VerifyRequest
	req, err := http.NewRequest(fx.RequestMethod, fx.RequestURL, nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	for k, v := range fx.RequestHeaders {
		req.Header.Set(k, v)
	}
	if err := VerifyRequest(req, pub, now.Add(15*time.Second)); err != nil {
		t.Fatalf("Go VerifyRequest rejected valid TS signature: %v", err)
	}

	// Negative checks: expired timestamp & tampered path must fail closed in Go
	if err := VerifyRequest(req, pub, now.Add(10*time.Minute)); err == nil {
		t.Fatal("expected expired TS request signature to fail Go VerifyRequest")
	}
	tamperedReq, _ := http.NewRequest(fx.RequestMethod, fx.RequestURL+"/tampered", nil)
	tamperedReq.Header = req.Header.Clone()
	if err := VerifyRequest(tamperedReq, pub, now); err == nil {
		t.Fatal("expected tampered @target-uri to fail Go VerifyRequest")
	}

	// 2. Verify TS signDirectoryResponse in Go VerifyDirectoryResponse
	dirReq, err := http.NewRequest(http.MethodGet, fx.DirectoryURL, nil)
	if err != nil {
		t.Fatalf("NewRequest(dir): %v", err)
	}
	dirHdr := make(http.Header)
	for k, v := range fx.DirectoryHdrs {
		dirHdr.Set(k, v)
	}
	if err := VerifyDirectoryResponse(dirReq, dirHdr, []byte(fx.DirectoryBody), pub, now.Add(15*time.Second)); err != nil {
		t.Fatalf("Go VerifyDirectoryResponse rejected valid TS directory signature: %v", err)
	}
	if err := VerifyDirectoryResponse(dirReq, dirHdr, []byte(fx.DirectoryBody+" "), pub, now); err == nil {
		t.Fatal("expected tampered directory body to fail Go VerifyDirectoryResponse")
	}

	// 3. Verify live Portable Hub /.well-known/http-message-signatures-directory response in Go
	liveReq, err := http.NewRequest(http.MethodGet, fx.LiveDirURL, nil)
	if err != nil {
		t.Fatalf("NewRequest(liveDir): %v", err)
	}
	liveHdr := make(http.Header)
	for k, v := range fx.LiveDirHdrs {
		liveHdr.Set(k, v)
	}
	if err := VerifyDirectoryResponse(liveReq, liveHdr, []byte(fx.LiveDirBody), pub, time.Now().UTC()); err != nil {
		t.Fatalf("Go VerifyDirectoryResponse rejected live Portable Hub directory response: %v", err)
	}
}
`,
      'utf8',
    );

    if (!useWslGo) {
      writeFileSync(overlayPath, JSON.stringify({ Replace: { [virtualGoFile]: actualGoFile } }), 'utf8');
      execFileSync(
        'go',
        ['test', `-overlay=${overlayPath}`, '-v', '-count=1', '-run', '^TestCrossLangTSVerify$', './internal/botauth'],
        {
          cwd: REPO_ROOT,
          env: { ...process.env, TS_BOTAUTH_FIXTURE_JSON: fixturePath },
          stdio: 'pipe',
          timeout: 60_000,
        },
      );
    } else {
      const wslRepo = toWslPath(REPO_ROOT);
      const wslVirtual = toWslPath(virtualGoFile);
      const wslActual = toWslPath(actualGoFile);
      const wslFixture = toWslPath(fixturePath);
      const wslOverlay = toWslPath(overlayPath);
      writeFileSync(overlayPath, JSON.stringify({ Replace: { [wslVirtual]: wslActual } }), 'utf8');
      const cmd = `export PATH=/home/brett/sdk/go1.27.4/bin:$PATH; cd '${wslRepo}' && TS_BOTAUTH_FIXTURE_JSON='${wslFixture}' go test -overlay='${wslOverlay}' -v -count=1 -run '^TestCrossLangTSVerify$' ./internal/botauth`;
      execFileSync('wsl', ['-e', 'bash', '-lc', cmd], {
        stdio: 'pipe',
        timeout: 60_000,
      });
    }
  } finally {
    rmSync(probeDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 });
  }
}

// ===========================================================================
// Suite Lifecycle & Shared Compiled Artifacts
// ===========================================================================

let suiteTmpDir = '';
let goBin = '';
let useWslGo = false;
let deps = null;

before(async () => {
  suiteTmpDir = resolveRealTmpDir('ef-fullstack-otel-');
  const built = buildEdgefetchBinary(suiteTmpDir);
  goBin = built.bin;
  useWslGo = built.useWslGo;
  deps = await bundleTypeScriptDeps(suiteTmpDir);
});

after(async () => {
  for (const child of [...activeChildren]) {
    await killChildCleanly(child);
  }
  if (suiteTmpDir) {
    try {
      rmSync(suiteTmpDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 });
    } catch {
      // ignore transient Windows SQLite WAL handle release lag
    }
  }
});

// ===========================================================================
// F16 — Cross-Process Full-Stack OTLP E2E
// ===========================================================================

describe('F16: Cross-Process Full-Stack OTLP E2E (EdgeFetchClient -> Portable Hub -> Go --mode=agent -> Collector)', () => {
  test('propagates W3C traceparent across scrape, jobs, catalog, search, Content-Signal: ai-input=no & 402 with exact parentSpanId linkage and zero secret leaks', async () => {
    const {
      startPortableHub,
      EdgeFetchClient,
      EdgeFetchError,
      generateBotAuthKeyPair,
      verifyBotRequestSignature,
      WebSocketServer,
      WsClient,
    } = deps;

    const collector = await startMockOtlpCollector();
    const botKey = await generateBotAuthKeyPair();
    const tokens = makeTokens();
    const querySecret = 'super-secret-do-not-leak';
    const originHits = [];
    const csOriginHits = [];

    // 1. Primary Mock Origin Server (HTML, robots.txt, Greenhouse ATS JSON, Shopify /products.json, HTTP 402 x402)
    const origin = await startHttpServer((req, res) => {
      req.resume();
      req.on('end', () => {
        const rawUrl = req.url || '/';
        const parsed = new URL(rawUrl, 'http://127.0.0.1');
        originHits.push({
          method: req.method || 'GET',
          url: rawUrl,
          pathname: parsed.pathname,
          headers: { ...req.headers },
        });

        if (parsed.pathname === '/robots.txt') {
          res.writeHead(200, { 'content-type': 'text/plain; charset=utf-8' });
          res.end('User-agent: *\nAllow: /\n');
          return;
        }
        if (parsed.pathname === '/llms.txt' || parsed.pathname === '/.well-known/llms.txt' || parsed.pathname === '/sitemap.xml') {
          res.writeHead(404, { 'content-type': 'text/plain' });
          res.end('not found');
          return;
        }
        if (parsed.pathname === '/articles/otel-guide') {
          res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
          res.end(
            '<!doctype html><html><head><title>Distributed OTLP Guide</title></head>' +
              '<body><main><h1>Distributed OTLP Guide</h1>' +
              '<p>End-to-end W3C traceparent correlation across EdgeFetch Hub and Go edge workers.</p>' +
              '</main></body></html>',
          );
          return;
        }
        if (parsed.pathname === '/' || parsed.pathname === '/careers' || parsed.pathname === '/jobs') {
          res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
          res.end(
            '<!doctype html><html><head><title>Acme Careers</title></head>' +
              '<body><main><h1>Join Acme Engineering</h1>' +
              '<p>Explore our open engineering positions:</p>' +
              '<a href="https://boards.greenhouse.io/acme">Open Roles on Greenhouse</a>' +
              '</main></body></html>',
          );
          return;
        }
        if (parsed.pathname === '/v1/boards/acme/jobs') {
          res.writeHead(200, { 'content-type': 'application/json; charset=utf-8' });
          res.end(
            JSON.stringify({
              jobs: [
                {
                  id: 90101,
                  title: 'Principal Distributed Systems Engineer',
                  absolute_url: 'https://boards.greenhouse.io/acme/jobs/90101',
                  updated_at: new Date().toISOString(),
                  location: { name: 'Remote - United States' },
                  content:
                    '&lt;p&gt;Build low-latency telemetry pipelines. Base salary range: $215,000 - $265,000 USD per year. 100% Remote.&lt;/p&gt;',
                },
              ],
            }),
          );
          return;
        }
        if (parsed.pathname === '/products.json') {
          const pageNum = Number(parsed.searchParams.get('page') || '1');
          const isFollowUp = pageNum > 1 || parsed.searchParams.has('page_info');
          res.writeHead(200, { 'content-type': 'application/json; charset=utf-8' });
          res.end(
            JSON.stringify({
              products: isFollowUp
                ? []
                : [
                    {
                      id: 5001,
                      title: 'EdgeFetch Telemetry Appliance',
                      handle: 'ef-telemetry-appliance',
                      vendor: 'EdgeFetch Labs',
                      product_type: 'Hardware',
                      variants: [
                        {
                          id: 6001,
                          title: 'Rackmount 1U',
                          price: '299.00',
                          available: true,
                          sku: 'EF-1U-OTLP',
                        },
                      ],
                    },
                  ],
            }),
          );
          return;
        }
        if (parsed.pathname === '/paywall/x402') {
          const termsB64 = Buffer.from(
            JSON.stringify({
              x402Version: 1,
              scheme: 'exact',
              amount: '1000000',
              asset: 'USDC',
              network: 'base',
              description: 'Premium research dossier',
            }),
            'utf8',
          ).toString('base64');
          res.writeHead(402, {
            'content-type': 'application/json; charset=utf-8',
            'payment-required': termsB64,
            'www-authenticate': 'x402 currency="USD" price="1.00 USD"',
          });
          res.end(JSON.stringify({ error: 'payment_required', message: 'x402 payment required' }));
          return;
        }

        res.writeHead(404, { 'content-type': 'text/plain' });
        res.end('not found');
      });
    });

    // 2. Dedicated Content-Signal: ai-input=no Mock Origin Server on 127.0.0.2 (isolated Go HostState robots.txt cache)
    const csOrigin = await startHttpServer((req, res) => {
      req.resume();
      req.on('end', () => {
        const rawUrl = req.url || '/';
        csOriginHits.push({ method: req.method || 'GET', url: rawUrl });
        if (rawUrl.startsWith('/robots.txt')) {
          res.writeHead(200, { 'content-type': 'text/plain; charset=utf-8' });
          res.end('User-agent: *\nContent-Signal: search=yes, ai-input=no, ai-train=no\nAllow: /\n');
          return;
        }
        res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
        res.end('<html><body>Should never be fetched when ai-input=no</body></html>');
      });
    }, '127.0.0.2');

    // 3. Mock SearXNG JSON Search Endpoint
    const searxMock = await startHttpServer((req, res) => {
      req.resume();
      req.on('end', () => {
        res.writeHead(200, { 'content-type': 'application/json; charset=utf-8' });
        res.end(
          JSON.stringify({
            results: [
              {
                url: 'https://origin.example.com/articles/otel-guide',
                title: 'Distributed OTLP Guide',
                content: 'QuantumTelemetry99 cross-process OpenTelemetry trace propagation reference.',
              },
            ],
          }),
        );
      });
    });

    const hubDataDir = path.join(suiteTmpDir, 'hub-f16-data');
    const hub = await startPortableHub({
      port: 0,
      host: '127.0.0.1',
      dataDir: hubDataDir,
      envOverrides: {
        CALLER_TOKEN: tokens.callerToken,
        MCP_TOKEN: tokens.mcpToken,
        AGENT_TOKEN: tokens.agentToken,
        BOT_SIGNING_PRIVATE_KEY: botKey.privateKeySeed,
        SEARXNG_URL: searxMock.url,
        OTEL_EXPORTER_OTLP_ENDPOINT: collector.endpoint,
        OTEL_SERVICE_NAME: 'edgefetch-hub',
      },
    });
    const hubBaseUrl = `http://127.0.0.1:${hub.port}`;

    const bridge = await startAgentLocalOriginBridge({
      hubPort: hub.port,
      hostToLocalOrigin: {
        'origin.example.com': origin.url,
        'acme.example.com': origin.url,
        'boards.greenhouse.io': origin.url,
        'job-boards.greenhouse.io': origin.url,
        'boards-api.greenhouse.io': origin.url,
        'shop.example.com': origin.url,
        'paywall.example.com': origin.url,
        'cs-blocked.example.com': csOrigin.url,
      },
    });

    const siteId = 'e2e-agent';
    const goAgent = await startRealGoAgent({
      bin: goBin,
      connectHubUrl: bridge.url,
      verifyHubBaseUrl: hubBaseUrl,
      callerToken: tokens.callerToken,
      agentToken: tokens.agentToken,
      siteId,
      env: {
        OTEL_EXPORTER_OTLP_ENDPOINT: collector.endpoint,
        OTEL_SERVICE_NAME: 'edgefetch-agent-e2e',
        EDGEFETCH_BOT_SIGNING_KEY: botKey.privateKeySeed,
        EDGEFETCH_BOT_DIRECTORY_URL: `${hubBaseUrl}/.well-known/http-message-signatures-directory`,
      },
    });

    try {
      const client = new EdgeFetchClient({
        baseUrl: hubBaseUrl,
        token: tokens.callerToken,
      });

      // -----------------------------------------------------------------------
      // 1) SCRAPE (dispatched over WebSocket to real Go --mode=agent -> mock origin, with ?api_key= secret)
      // -----------------------------------------------------------------------
      const tpScrape = makeTraceIds('01');
      const scrapeOut = await client.scrape(
        {
          url: `https://origin.example.com/articles/otel-guide?api_key=${querySecret}`,
          target: 'agent',
          site: siteId,
          noCache: true,
        },
        { traceparent: tpScrape.traceparent },
      );
      assert.equal(scrapeOut.ok, true);
      assert.match(String(scrapeOut.markdown || ''), /Distributed OTLP Guide/);
      assert.equal(client.lastTraceId, tpScrape.traceId, 'client.lastTraceId must match scrape traceparent traceId');
      assert.ok(
        originHits.some((h) => h.url === `/articles/otel-guide?api_key=${querySecret}`),
        'Real Go --mode=agent worker must fetch the target URL on the local mock origin',
      );

      // Verify Go agent signed the outbound request with RFC 9421 headers while fetching
      const signedArticleHit = originHits.find((h) => h.pathname === '/articles/otel-guide');
      assert.ok(signedArticleHit?.headers['signature-input'], 'Go agent must attach Signature-Input header');
      assert.ok(signedArticleHit?.headers.signature, 'Go agent must attach Signature header');
      assert.ok(signedArticleHit?.headers['signature-agent'], 'Go agent must attach Signature-Agent header');
      const verifyAgentSig = await verifyBotRequestSignature(
        new Request(`${origin.url}${signedArticleHit.url}`, {
          method: signedArticleHit.method,
          headers: signedArticleHit.headers,
        }),
        botKey.publicKey,
      );
      assert.equal(verifyAgentSig.ok, true, `TS verifyBotRequestSignature failed on Go agent request: ${verifyAgentSig.reason}`);

      await collector.waitForSpans((entries) => {
        const t = entries.filter((e) => e.span.traceId === tpScrape.traceId);
        return (
          t.some((e) => e.serviceName === 'edgefetch-hub' && e.span.name === 'edgefetch.http') &&
          t.some((e) => e.serviceName === 'edgefetch-hub' && e.span.name === 'edgefetch.scrape') &&
          t.some((e) => e.serviceName === 'edgefetch-hub' && e.span.name === 'edgefetch.dispatch') &&
          t.some((e) => e.serviceName === 'edgefetch-agent-e2e' && e.span.name === 'edgefetch.go.batch') &&
          t.some((e) => e.serviceName === 'edgefetch-agent-e2e' && e.span.name === 'edgefetch.go.fetch.scrape')
        );
      });

      const scrapeSpans = collector.findByTraceId(tpScrape.traceId);
      for (const s of scrapeSpans) validateOtlpSpan(s.span, 'scrape');

      const hubHttp = scrapeSpans.find((e) => e.serviceName === 'edgefetch-hub' && e.span.name === 'edgefetch.http');
      const hubScrape = scrapeSpans.find((e) => e.serviceName === 'edgefetch-hub' && e.span.name === 'edgefetch.scrape');
      const hubDispatch = scrapeSpans.find(
        (e) =>
          e.serviceName === 'edgefetch-hub' &&
          e.span.name === 'edgefetch.dispatch' &&
          scrapeSpans.some((g) => g.serviceName === 'edgefetch-agent-e2e' && g.span.name === 'edgefetch.go.batch' && g.span.parentSpanId === e.span.spanId),
      );
      const goBatch = scrapeSpans.find((e) => e.serviceName === 'edgefetch-agent-e2e' && e.span.name === 'edgefetch.go.batch');
      const goFetchScrape = scrapeSpans.find((e) => e.serviceName === 'edgefetch-agent-e2e' && e.span.name === 'edgefetch.go.fetch.scrape');

      assert.ok(hubHttp && hubScrape && hubDispatch && goBatch && goFetchScrape, 'Missing expected cross-process scrape spans');
      assert.equal(hubHttp.span.parentSpanId, tpScrape.parentSpanId, 'edgefetch.http.parentSpanId must equal inbound traceparent spanId');
      assert.equal(hubScrape.span.parentSpanId, hubHttp.span.spanId, 'edgefetch.scrape.parentSpanId must equal edgefetch.http.spanId');
      assert.equal(goBatch.span.parentSpanId, hubDispatch.span.spanId, 'edgefetch.go.batch.parentSpanId must equal edgefetch.dispatch.spanId');
      assert.equal(goFetchScrape.span.parentSpanId, goBatch.span.spanId, 'edgefetch.go.fetch.scrape.parentSpanId must equal edgefetch.go.batch.spanId');
      assert.equal(getOtlpAttrValue(goFetchScrape.span.attributes, 'bot_auth.signed'), true, 'Go fetch span must carry bot_auth.signed=true');

      // Also verify direct kind="page" batch dispatch (`edgefetch.go.fetch.page`) with ?api_key= secret redaction
      const tpPage = makeTraceIds('01');
      const pageOut = await client.requestJson(
        'POST',
        `/fetch?target=agent&site=${siteId}`,
        {
          maxSeconds: 20,
          options: { includeBody: false, respectRobots: true },
          requests: [{ id: 'page-1', url: `${origin.url}/articles/otel-guide?api_key=${querySecret}`, kind: 'page' }],
        },
        { traceparent: tpPage.traceparent },
      );
      assert.equal(pageOut.results?.[0]?.outcome, 'ok');
      assert.equal(client.lastTraceId, tpPage.traceId);

      await collector.waitForSpans((entries) => {
        const t = entries.filter((e) => e.span.traceId === tpPage.traceId);
        return (
          t.some((e) => e.serviceName === 'edgefetch-hub' && e.span.name === 'edgefetch.dispatch') &&
          t.some((e) => e.serviceName === 'edgefetch-agent-e2e' && e.span.name === 'edgefetch.go.batch') &&
          t.some((e) => e.serviceName === 'edgefetch-agent-e2e' && e.span.name === 'edgefetch.go.fetch.page')
        );
      });
      const pageSpans = collector.findByTraceId(tpPage.traceId);
      const goPageBatch = pageSpans.find((e) => e.serviceName === 'edgefetch-agent-e2e' && e.span.name === 'edgefetch.go.batch');
      const goFetchPage = pageSpans.find((e) => e.serviceName === 'edgefetch-agent-e2e' && e.span.name === 'edgefetch.go.fetch.page');
      assert.ok(goPageBatch && goFetchPage, 'Expected edgefetch.go.batch and edgefetch.go.fetch.page spans');
      assert.equal(goFetchPage.span.parentSpanId, goPageBatch.span.spanId);
      assert.ok(
        pageSpans.some((e) => e.serviceName === 'edgefetch-hub' && e.span.name === 'edgefetch.dispatch' && goPageBatch.span.parentSpanId === e.span.spanId),
        'Page Go batch must parent under Hub edgefetch.dispatch',
      );

      // -----------------------------------------------------------------------
      // 2) JOBS (Greenhouse ATS board discovery + JSON feed via real Go --mode=agent)
      // -----------------------------------------------------------------------
      const tpJobs = makeTraceIds('01');
      const jobsOut = await client.jobs(
        {
          domains: ['acme.example.com'],
          query: 'Distributed Systems',
          remote: true,
        },
        { traceparent: tpJobs.traceparent },
      );
      assert.equal(jobsOut.ok, true);
      assert.equal(client.lastTraceId, tpJobs.traceId, 'client.lastTraceId must match jobs traceparent traceId');
      assert.ok(
        Array.isArray(jobsOut.jobs) && jobsOut.jobs.some((j) => String(j.title).includes('Principal Distributed Systems Engineer')),
        `Expected Greenhouse job in jobsOut: ${JSON.stringify(jobsOut)}`,
      );

      await collector.waitForSpans((entries) => {
        const t = entries.filter((e) => e.span.traceId === tpJobs.traceId);
        return (
          t.some((e) => e.serviceName === 'edgefetch-hub' && e.span.name === 'edgefetch.http') &&
          t.some((e) => e.serviceName === 'edgefetch-hub' && e.span.name === 'edgefetch.jobs') &&
          t.some((e) => e.serviceName === 'edgefetch-agent-e2e' && e.span.name === 'edgefetch.go.batch') &&
          t.some((e) => e.serviceName === 'edgefetch-agent-e2e' && e.span.name === 'edgefetch.go.fetch.json')
        );
      });

      const jobsSpans = collector.findByTraceId(tpJobs.traceId);
      const hubJobs = jobsSpans.find((e) => e.serviceName === 'edgefetch-hub' && e.span.name === 'edgefetch.jobs');
      const goJobsBatch = jobsSpans.find((e) => e.serviceName === 'edgefetch-agent-e2e' && e.span.name === 'edgefetch.go.batch');
      assert.ok(hubJobs && goJobsBatch, 'Expected both edgefetch.jobs and edgefetch.go.batch spans on jobs traceId');
      assert.ok(
        jobsSpans.some(
          (e) =>
            e.serviceName === 'edgefetch-hub' &&
            e.span.name === 'edgefetch.dispatch' &&
            goJobsBatch.span.parentSpanId === e.span.spanId,
        ),
        'Jobs Go batch span must parent directly under a Hub edgefetch.dispatch span',
      );
      assert.ok(
        jobsSpans.some((e) => String(getOtlpAttrValue(e.span.attributes, 'edgefetch.adapter_id') || '').includes('greenhouse')),
        `Jobs OTLP trace must record greenhouse adapter_id; got attrs=${JSON.stringify(hubJobs.span.attributes)}`,
      );

      // -----------------------------------------------------------------------
      // 3) CATALOG (Shopify /products.json pagination via real Go --mode=agent)
      // -----------------------------------------------------------------------
      const tpCatalog = makeTraceIds('01');
      const catalogOut = await client.requestJson(
        'POST',
        '/v1/catalog',
        {
          url: 'https://shop.example.com',
          platform: 'shopify',
          sync: true,
          pauseMs: 10,
          target: 'agent',
          site: siteId,
        },
        { traceparent: tpCatalog.traceparent },
      );
      assert.equal(catalogOut.ok, true);
      assert.equal(catalogOut.status, 'complete');
      assert.equal(catalogOut.products, 1);
      assert.equal(client.lastTraceId, tpCatalog.traceId, 'client.lastTraceId must match catalog traceparent traceId');

      await collector.waitForSpans((entries) => {
        const t = entries.filter((e) => e.span.traceId === tpCatalog.traceId);
        return (
          t.some((e) => e.serviceName === 'edgefetch-hub' && e.span.name === 'edgefetch.catalog') &&
          t.some((e) => e.serviceName === 'edgefetch-agent-e2e' && e.span.name === 'edgefetch.go.batch') &&
          t.some((e) => e.serviceName === 'edgefetch-agent-e2e' && e.span.name === 'edgefetch.go.fetch.json')
        );
      });

      const catSpans = collector.findByTraceId(tpCatalog.traceId);
      const hubCat = catSpans.find((e) => e.serviceName === 'edgefetch-hub' && e.span.name === 'edgefetch.catalog');
      const goCatBatch = catSpans.find((e) => e.serviceName === 'edgefetch-agent-e2e' && e.span.name === 'edgefetch.go.batch');
      assert.ok(hubCat && goCatBatch, 'Expected both edgefetch.catalog and edgefetch.go.batch spans on catalog traceId');
      assert.ok(
        catSpans.some(
          (e) =>
            e.serviceName === 'edgefetch-hub' &&
            e.span.name === 'edgefetch.dispatch' &&
            goCatBatch.span.parentSpanId === e.span.spanId,
        ),
        'Catalog Go batch span must parent directly under a Hub edgefetch.dispatch span',
      );

      // -----------------------------------------------------------------------
      // 4) SEARCH (FTS5 collection + mocked SearXNG JSON search)
      // -----------------------------------------------------------------------
      const colId = 'col_fullstack_e2e';
      const ingestRes = await fetch(`${hubBaseUrl}/v1/ingest-tab`, {
        method: 'POST',
        headers: {
          authorization: `Bearer ${tokens.callerToken}`,
          'content-type': 'application/json',
        },
        body: JSON.stringify({
          url: 'https://origin.example.com/docs/fts5-entry',
          title: 'FTS5 Indexed Telemetry Doc',
          html: '<main><h1>FTS5 Indexed Telemetry Doc</h1><p>QuantumTelemetry99 local SQLite FTS5 corpus hit.</p></main>',
          collectionId: colId,
        }),
      });
      assert.equal(ingestRes.status, 200);

      const tpSearch = makeTraceIds('01');
      const searchOut = await client.search(
        {
          query: 'QuantumTelemetry99',
          collections: [colId],
          max_results: 5,
        },
        { traceparent: tpSearch.traceparent },
      );
      assert.equal(searchOut.ok, true);
      assert.ok(Array.isArray(searchOut.results) && searchOut.results.length >= 1, 'Expected search results from FTS5 / SearXNG');
      assert.equal(client.lastTraceId, tpSearch.traceId, 'client.lastTraceId must match search traceparent traceId');

      await collector.waitForSpans((entries) =>
        entries.some((e) => e.span.traceId === tpSearch.traceId && e.serviceName === 'edgefetch-hub' && e.span.name === 'edgefetch.search'),
      );
      const searchSpans = collector.findByTraceId(tpSearch.traceId);
      assert.ok(searchSpans.some((e) => e.span.name === 'edgefetch.http'), 'Missing edgefetch.http on search');
      assert.ok(searchSpans.some((e) => e.span.name === 'edgefetch.search'), 'Missing edgefetch.search on search');

      // -----------------------------------------------------------------------
      // 5) CONTENT-SIGNAL: ai-input=no POLICY ENFORCEMENT
      // -----------------------------------------------------------------------
      const tpCs = makeTraceIds('01');
      let csErr = null;
      try {
        await client.scrape(
          {
            url: 'https://cs-blocked.example.com/private-article',
            target: 'agent',
            site: siteId,
            noCache: true,
          },
          { traceparent: tpCs.traceparent },
        );
      } catch (err) {
        csErr = err;
      }
      assert.ok(csErr instanceof EdgeFetchError, `Expected EdgeFetchError on Content-Signal block, got ${csErr}`);
      assert.ok(csErr.status === 451 || csErr.status === 422, `Expected 451 or 422 status on Content-Signal block, got ${csErr.status}`);
      assert.equal(client.lastTraceId, tpCs.traceId, 'client.lastTraceId must be captured on Content-Signal EdgeFetchError');
      assert.equal(
        csOriginHits.some((h) => h.url.includes('/private-article')),
        false,
        'Go agent must strictly honor Content-Signal: ai-input=no without fetching /private-article',
      );

      await collector.waitForSpans((entries) => {
        const t = entries.filter((e) => e.span.traceId === tpCs.traceId);
        return (
          t.some((e) => e.serviceName === 'edgefetch-hub' && e.span.name === 'edgefetch.dispatch') &&
          t.some((e) => e.serviceName === 'edgefetch-agent-e2e' && e.span.name === 'edgefetch.go.batch') &&
          t.some((e) => e.serviceName === 'edgefetch-agent-e2e' && e.span.name === 'edgefetch.go.fetch.scrape')
        );
      });

      const csSpans = collector.findByTraceId(tpCs.traceId);
      const csDispatch = csSpans.find(
        (e) =>
          e.serviceName === 'edgefetch-hub' &&
          e.span.name === 'edgefetch.dispatch' &&
          csSpans.some((g) => g.serviceName === 'edgefetch-agent-e2e' && g.span.name === 'edgefetch.go.batch' && g.span.parentSpanId === e.span.spanId),
      );
      assert.ok(csDispatch, 'Content-Signal Go batch must parent under Hub edgefetch.dispatch');
      assert.ok(
        csSpans.some(
          (e) =>
            getOtlpAttrValue(e.span.attributes, 'crawler.outcome') === 'content_signal_disallowed' ||
            String(e.span?.status?.message || '').toLowerCase().includes('content-signal: ai-input=no'),
        ),
        'Expected Content-Signal disallow marker on OTLP spans',
      );

      // -----------------------------------------------------------------------
      // 6) HTTP 402 PAYMENT REQUIRED (x402) HANDLING
      // -----------------------------------------------------------------------
      const tp402 = makeTraceIds('01');
      let err402 = null;
      try {
        await client.scrape(
          {
            url: 'https://paywall.example.com/paywall/x402',
            target: 'agent',
            site: siteId,
            noCache: true,
          },
          { traceparent: tp402.traceparent },
        );
      } catch (err) {
        err402 = err;
      }
      assert.ok(err402 instanceof EdgeFetchError, `Expected EdgeFetchError on HTTP 402, got ${err402}`);
      assert.equal(err402.status, 402, `Expected HTTP 402 status, got ${err402.status}`);
      assert.equal(client.lastTraceId, tp402.traceId, 'client.lastTraceId must be captured on 402 EdgeFetchError');

      await collector.waitForSpans((entries) => {
        const t = entries.filter((e) => e.span.traceId === tp402.traceId);
        return (
          t.some((e) => e.serviceName === 'edgefetch-hub' && getOtlpAttrValue(e.span.attributes, 'http.response.status_code') === 402) &&
          t.some((e) => e.serviceName === 'edgefetch-agent-e2e' && e.span.name === 'edgefetch.go.batch') &&
          t.some((e) => e.serviceName === 'edgefetch-agent-e2e' && e.span.name === 'edgefetch.go.fetch.scrape')
        );
      });

      const spans402 = collector.findByTraceId(tp402.traceId);
      const goFetch402 = spans402.find((e) => e.serviceName === 'edgefetch-agent-e2e' && e.span.name === 'edgefetch.go.fetch.scrape');
      assert.ok(goFetch402, 'Expected Go edgefetch.go.fetch.page span on 402 response');
      assert.equal(getOtlpAttrValue(goFetch402.span.attributes, 'http.response.status_code'), 402);
      assert.equal(getOtlpAttrValue(goFetch402.span.attributes, 'crawler.outcome'), 'payment_required');
      assert.ok(
        spans402.some(
          (e) =>
            e.serviceName === 'edgefetch-hub' &&
            e.span.name === 'edgefetch.dispatch' &&
            spans402.some((g) => g.serviceName === 'edgefetch-agent-e2e' && g.span.name === 'edgefetch.go.batch' && g.span.parentSpanId === e.span.spanId),
        ),
        '402 Go batch span must parent directly under Hub edgefetch.dispatch',
      );

      // -----------------------------------------------------------------------
      // ZERO SECRET LEAKAGE INVARIANT ACROSS ALL SERIALIZED OTLP PAYLOADS
      // -----------------------------------------------------------------------
      assertNoSecretsInOtlp(collector.requests, collector.entries, [
        querySecret,
        tokens.callerToken,
        tokens.mcpToken,
        tokens.agentToken,
        botKey.privateKeySeed,
      ]);
    } finally {
      await goAgent.close();
      await bridge.close();
      await hub.close();
      await Promise.all([origin.close(), csOrigin.close(), searxMock.close()]);
      await collector.close();
    }
  });
});

// ===========================================================================
// F17 — Bidirectional Go <-> TypeScript RFC 9421 Web Bot Auth Contract
// ===========================================================================

describe('F17: Bidirectional Go <-> TypeScript RFC 9421 Web Bot Auth Contract', () => {
  test('Test 1 (TS Sign -> Go Verify): TypeScript request & directory signatures verify cleanly in Go internal/botauth', async () => {
    const {
      startPortableHub,
      computeEd25519JwkThumbprint,
      generateBotAuthKeyPair,
      signDirectoryResponse,
      signOutboundBotHeaders,
    } = deps;

    // Verify CLI keygen-bot-auth --json JWK thumbprint parity with TypeScript computeEd25519JwkThumbprint
    const cliOut = execFileSync(goBin, ['keygen-bot-auth', '--json'], { encoding: 'utf8', timeout: 15_000 });
    const goGenerated = JSON.parse(cliOut.trim());
    const pubBytes = Buffer.from(goGenerated.publicKey, 'base64url');
    const tsThumbprint = await computeEd25519JwkThumbprint(new Uint8Array(pubBytes));
    assert.equal(tsThumbprint, goGenerated.kid, 'RFC 7638 JWK thumbprint must match byte-for-byte between Go and TS');

    const kp = await generateBotAuthKeyPair();
    const tokens = makeTokens();
    const hub = await startPortableHub({
      port: 0,
      host: '127.0.0.1',
      dataDir: path.join(suiteTmpDir, 'hub-f17-ts-sign'),
      envOverrides: {
        CALLER_TOKEN: tokens.callerToken,
        AGENT_TOKEN: tokens.agentToken,
        BOT_SIGNING_PRIVATE_KEY: kp.privateKeySeed,
      },
    });

    try {
      const nowMs = 1_767_500_000_000;
      const nowUnix = Math.floor(nowMs / 1000);
      const directoryUrl = 'https://hub.example.com/.well-known/http-message-signatures-directory';
      const requestUrl = 'https://origin.example.com/research/paper?version=2';

      // 1. Sign outbound HTTP request in TypeScript
      const reqHeaders = await signOutboundBotHeaders({
        url: requestUrl,
        method: 'GET',
        privateKeyEncoded: kp.privateKeySeed,
        directoryUrl,
        nowMs,
        ttlSeconds: 300,
      });

      // 2. Sign directory response in TypeScript
      const directoryBody = JSON.stringify({ keys: [kp.jwk] }, null, 2);
      const dirHeaders = await signDirectoryResponse({
        authority: 'hub.example.com',
        body: directoryBody,
        privateKeyEncoded: kp.privateKeySeed,
        nowMs,
        ttlSeconds: 300,
      });

      // 3. Also capture live Portable Hub /.well-known/http-message-signatures-directory HTTP response
      const liveDirUrl = `http://127.0.0.1:${hub.port}/.well-known/http-message-signatures-directory`;
      const liveRes = await fetch(liveDirUrl);
      assert.equal(liveRes.status, 200);
      const liveBody = await liveRes.text();
      const liveDirHeaders = {};
      liveRes.headers.forEach((v, k) => {
        liveDirHeaders[k] = v;
      });

      // 4. Verify all TS-signed artifacts using Go internal/botauth (VerifyRequest + VerifyDirectoryResponse + ComputeJWKThumbprint)
      runGoBotAuthVerifyProbe({
        tmpDir: suiteTmpDir,
        useWslGo,
        fixture: {
          publicKeyB64Url: kp.publicKey,
          expectedKid: kp.kid,
          nowUnix,
          requestMethod: 'GET',
          requestUrl,
          requestHeaders: reqHeaders,
          directoryUrl,
          directoryBody,
          directoryHeaders: dirHeaders,
          liveDirUrl,
          liveDirBody: liveBody,
          liveDirHeaders,
        },
      });
    } finally {
      await hub.close();
    }
  });

  test('Test 2 (Go Sign -> TS Verify): Real Go crawler/hub outbound RFC 9421 & directory signatures verify cleanly in TypeScript', async () => {
    const {
      generateBotAuthKeyPair,
      verifyBotRequestSignature,
      verifyDirectoryResponseSignature,
    } = deps;

    const kp = await generateBotAuthKeyPair();
    const tokens = makeTokens();
    const capturedRequests = [];

    const origin = await startHttpServer((req, res) => {
      req.resume();
      req.on('end', () => {
        capturedRequests.push({
          method: req.method || 'GET',
          url: req.url || '/',
          headers: { ...req.headers },
        });
        if ((req.url || '').startsWith('/robots.txt')) {
          res.writeHead(200, { 'content-type': 'text/plain' });
          res.end('User-agent: *\nAllow: /\n');
          return;
        }
        res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
        res.end('<!doctype html><html><body><main><h1>Verified Bot Origin</h1></main></body></html>');
      });
    });

    const goHubPort = await allocPort();
    const goHubBaseUrl = `http://127.0.0.1:${goHubPort}`;
    const goDirUrl = `${goHubBaseUrl}/.well-known/http-message-signatures-directory`;

    const goHubChild = trackChild(
      spawn(goBin, ['--mode=hub', `--addr=127.0.0.1:${goHubPort}`, '--allow-private'], {
        env: {
          ...process.env,
          EDGEFETCH_CALLER_TOKEN: tokens.callerToken,
          EDGEFETCH_AGENT_TOKEN: tokens.agentToken,
          EDGEFETCH_BOT_SIGNING_KEY: kp.privateKeySeed,
          EDGEFETCH_BOT_DIRECTORY_URL: goDirUrl,
        },
        stdio: ['ignore', 'pipe', 'pipe'],
      }),
    );

    try {
      // Wait for Go Hub to listen
      const deadline = Date.now() + 10_000;
      let ready = false;
      while (Date.now() < deadline) {
        try {
          const r = await fetch(`${goHubBaseUrl}/healthz`);
          if (r.ok) {
            ready = true;
            break;
          }
        } catch {}
        await delay(60);
      }
      assert.equal(ready, true, 'Go --mode=hub failed to become ready');

      // 1. Verify Go-signed /.well-known/http-message-signatures-directory response in TypeScript
      const dirRes = await fetch(goDirUrl);
      assert.equal(dirRes.status, 200);
      const dirVerify = await verifyDirectoryResponseSignature({
        requestUrl: goDirUrl,
        response: dirRes,
        publicKeyB64Url: kp.publicKey,
      });
      assert.equal(dirVerify.ok, true, `TS verifyDirectoryResponseSignature rejected Go directory response: ${dirVerify.reason}`);
      assert.equal(dirVerify.kid, kp.kid);

      // 2. Trigger real Go crawler outbound signed HTTP request to mock origin & verify captured headers in TypeScript
      const targetPath = '/bot-verified/page?check=rfc9421';
      const scrapeRes = await fetch(`${goHubBaseUrl}/v1/scrape`, {
        method: 'POST',
        headers: {
          authorization: `Bearer ${tokens.callerToken}`,
          'content-type': 'application/json',
        },
        body: JSON.stringify({ url: `${origin.url}${targetPath}` }),
      });
      assert.equal(scrapeRes.status, 200);

      const hit = capturedRequests.find((r) => r.url === targetPath);
      assert.ok(hit, 'Mock origin did not receive signed request from Go crawler');
      assert.equal(hit.headers['signature-agent'], `"${goDirUrl}"`, 'Signature-Agent header mismatch');
      assert.match(String(hit.headers['signature-input'] || ''), /^sig1=\("@authority" "@method" "@target-uri" "signature-agent"\);.*tag="web-bot-auth"/);
      assert.match(String(hit.headers.signature || ''), /^sig1=:[A-Za-z0-9+/=]+:$/);

      const reqVerify = await verifyBotRequestSignature(
        new Request(`${origin.url}${hit.url}`, {
          method: hit.method,
          headers: hit.headers,
        }),
        kp.publicKey,
      );
      assert.equal(reqVerify.ok, true, `TS verifyBotRequestSignature rejected Go outbound request: ${reqVerify.reason}`);
      assert.equal(reqVerify.kid, kp.kid);

      // Negative check: tampering with public key or URL fails closed in TypeScript verifier
      const tamperedVerify = await verifyBotRequestSignature(
        new Request(`${origin.url}/tampered-path`, {
          method: hit.method,
          headers: hit.headers,
        }),
        kp.publicKey,
      );
      assert.equal(tamperedVerify.ok, false);
    } finally {
      await killChildCleanly(goHubChild);
      await origin.close();
    }
  });
});
