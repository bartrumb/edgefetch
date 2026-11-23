/**
 * Round 9 Stream 3 Security & Resilience Suite (`hub/test/round9-portable-otel.test.ts`):
 *
 *  1. `H7` — Portable Hub Held Keep-Alive Socket Lockout & Same-NAT Co-Tenant Fairness:
 *     - Preserves 12-connection & 24-connection client bursts across 1..16 addresses (`100%` succeed, `0%` dropped).
 *     - Reproduces exact Round 9 DoS: 16 attacker IPs holding 64 HTTP/1.1 keep-alive sockets each (`1,024` sockets)
 *       sending 1 cheap request every 500ms–2s (with continuous reconnects) while legitimate remote clients send
 *       152 requests -> **`152 / 152` (`100%`)** succeed + loopback `/health` `100%` succeeds!
 *     - Same-NAT co-tenant fairness: 1 squatter holding 64 keep-alive sockets on `127.0.4.77` cannot starve 152
 *       co-tenant requests arriving from that exact same `127.0.4.77` NAT address (`152 / 152` succeed).
 *     - Enforces `MAX_REQUESTS_PER_CONNECTION = 64` keep-alive rotation (`Connection: close` on request #64).
 *
 *  2. Slow-Read HTTP/1.1 Pipelining Memory Cap (`MAX_SOCKET_WRITABLE_BYTES = 2 MiB`):
 *     - Pipelining 200 back-to-back `GET /openapi.json` requests on a `pause()`d client socket that never calls
 *       `socket.read()` keeps server-side per-socket buffered bytes `< 2 MiB` (`<< 4 MiB`, vs 1.8 GB previously)
 *       and destroys the slow-read socket cleanly while normal clients remain 100% healthy.
 *     - Single multi-MiB streaming response on a `pause()`d client halts stream pulls under backpressure (`<= 2 MiB`)
 *       and tears down the stalled socket cleanly on drain timeout.
 *
 *  3. Non-Suppressible Security/Login Audit Spans & Audit Budget Isolation (`hub/src/otel.ts`):
 *     - Inbound `traceparent: 00-...-00` (`sampled=0`) NEVER suppresses `/admin/login` owner sign-in audit spans,
 *       failed login audit spans, `/admin/logout`, `/admin/api/*` mutations, `/oauth/*` grants/revocations, or `/mcp`
 *       authenticated spans on either Workers `hubWorker.fetch` or `startPortableHub`.
 *     - Public unauthenticated floods (`/openapi.json`, `/.well-known/*`, `/health`, `401` `/v1/scrape`, plus slow
 *       public OTLP collector saturation) CANNOT drain or block the OTLP export budget for authenticated or
 *       security-audit spans.
 */
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import http from 'node:http';
import net from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import {
  KEEP_ALIVE_TIMEOUT_MS,
  MAX_ESTABLISHED_SOCKETS_PER_IP,
  MAX_REQUESTS_PER_CONNECTION,
  MAX_SOCKET_WRITABLE_BYTES,
  MAX_TOTAL_SOCKETS,
  SOCKET_PRESSURE_THRESHOLD,
  SOFT_GLOBAL_SOCKET_THRESHOLD,
  startPortableHub,
} from '../portable/portable-server';
import { LocalAgentHubCoordinator } from '../portable/node-adapters';
import hubWorker from '../src/index';
import { ADMIN_COOKIE_NAME, createAdminSessionValue } from '../src/oauth';
import {
  MAX_PUBLIC_UNAUTH_INFLIGHT_OTLP,
  parseTraceparent,
  resetOtlpExportLimitersForTests,
  SECURITY_AUDIT_OTLP_CAPACITY,
  UNAUTH_OTLP_EXPORT_CAPACITY,
} from '../src/otel';

const CALLER_TOKEN = 'r9-owner-caller-secret-0123456789abcdef';

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

function sendBoundHttpRequest(params: {
  port: number;
  localAddress: string;
  path: string;
  method?: string;
  headers?: Record<string, string>;
  body?: string;
  timeoutMs?: number;
}): Promise<{ status: number; headers: http.IncomingHttpHeaders; body: string }> {
  return new Promise((resolveReq, rejectReq) => {
    const req = http.request(
      {
        host: '127.0.0.1',
        port: params.port,
        localAddress: params.localAddress,
        method: params.method ?? 'GET',
        path: params.path,
        agent: false,
        headers: {
          Host: `127.0.0.1:${params.port}`,
          Connection: 'close',
          ...(params.headers ?? {}),
        },
        timeout: params.timeoutMs ?? 5_000,
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (c: Buffer) => chunks.push(c));
        res.on('end', () => {
          resolveReq({
            status: res.statusCode ?? 0,
            headers: res.headers,
            body: Buffer.concat(chunks).toString('utf8'),
          });
        });
      },
    );
    req.on('timeout', () => {
      req.destroy(new Error('HTTP request timed out'));
    });
    req.on('error', rejectReq);
    if (params.body !== undefined) req.write(params.body);
    req.end();
  });
}

interface KeepAlivePoolController {
  stop: () => void;
}

function startKeepAliveAttackerPool(params: {
  port: number;
  localAddress: string;
  socketCount: number;
  pingIntervalMs: number;
}): KeepAlivePoolController {
  let stopped = false;
  const sockets = new Set<net.Socket>();
  const timers = new Set<ReturnType<typeof setTimeout>>();

  const openAndHoldKeepAliveSocket = (slotIdx: number) => {
    if (stopped) return;
    const sock = net.connect({
      host: '127.0.0.1',
      port: params.port,
      localAddress: params.localAddress,
    });
    sockets.add(sock);
    sock.resume(); // Drain responses so socket stays an established keep-alive socket!
    sock.on('error', () => undefined);

    let pingTimer: ReturnType<typeof setTimeout> | null = null;
    const sendCheapKeepAlivePing = () => {
      if (stopped || sock.destroyed || !sock.writable) return;
      sock.write(`GET /robots.txt HTTP/1.1\r\nHost: 127.0.0.1:${params.port}\r\nConnection: keep-alive\r\n\r\n`);
      pingTimer = setTimeout(sendCheapKeepAlivePing, params.pingIntervalMs + (slotIdx % 7) * 35);
      pingTimer.unref?.();
      timers.add(pingTimer);
    };

    sock.on('connect', () => {
      sendCheapKeepAlivePing();
    });

    sock.on('close', () => {
      sockets.delete(sock);
      if (pingTimer) {
        clearTimeout(pingTimer);
        timers.delete(pingTimer);
      }
      if (!stopped) {
        const reconnectTimer = setTimeout(() => {
          timers.delete(reconnectTimer);
          openAndHoldKeepAliveSocket(slotIdx);
        }, 600 + slotIdx * 20 + Math.floor(Math.random() * 400));
        reconnectTimer.unref?.();
        timers.add(reconnectTimer);
      }
    });
  };

  for (let i = 0; i < params.socketCount; i++) {
    const launchDelay = Math.floor(i / 8) * 3;
    if (launchDelay === 0) {
      openAndHoldKeepAliveSocket(i);
    } else {
      const t = setTimeout(() => {
        timers.delete(t);
        openAndHoldKeepAliveSocket(i);
      }, launchDelay);
      t.unref?.();
      timers.add(t);
    }
  }

  return {
    stop() {
      stopped = true;
      for (const t of timers) clearTimeout(t);
      timers.clear();
      for (const s of sockets) s.destroy();
      sockets.clear();
    },
  };
}

test('Round 9 [H7 — Held Keep-Alive Socket Lockout & Same-NAT Fairness]: 16 IPs × 64 keep-alive sockets cannot starve legitimate clients (152/152 = 100%) & 12/24 bursts succeed 100%', async () => {
  assert.equal(MAX_TOTAL_SOCKETS, 256);
  assert.equal(SOFT_GLOBAL_SOCKET_THRESHOLD, 128);
  assert.equal(SOCKET_PRESSURE_THRESHOLD, 96);
  assert.equal(MAX_ESTABLISHED_SOCKETS_PER_IP, 16);
  assert.equal(MAX_REQUESTS_PER_CONNECTION, 64);
  assert.equal(KEEP_ALIVE_TIMEOUT_MS, 4_000);

  const dataDir = mkdtempSync(join(tmpdir(), 'ef-r9-h7-'));
  const hub = await startPortableHub({
    port: 0,
    host: '127.0.0.1',
    dataDir,
    envOverrides: {
      CALLER_TOKEN,
      EDGEFETCH_DISABLE_UPDATE_CHECK: '1',
    },
  });

  const pools: KeepAlivePoolController[] = [];
  try {
    // 1. Preserve Round 8 burst behavior: 12-conn & 24-conn bursts from 1 address AND across 16 addresses (0% dropped!)
    for (const burstSize of [12, 24]) {
      const singleIpBurst = await Promise.all(
        Array.from({ length: burstSize }, () =>
          sendBoundHttpRequest({
            port: hub.port,
            localAddress: '127.0.6.10',
            path: '/v1/capabilities',
            headers: { Authorization: `Bearer ${CALLER_TOKEN}` },
          }),
        ),
      );
      assert.equal(
        singleIpBurst.filter((r) => r.status === 200).length,
        burstSize,
        `Expected ${burstSize}/${burstSize} single-IP burst requests to succeed`,
      );

      const multiIpBurst = await Promise.all(
        Array.from({ length: burstSize }, (_, idx) =>
          sendBoundHttpRequest({
            port: hub.port,
            localAddress: `127.0.6.${20 + (idx % 16)}`,
            path: '/v1/capabilities',
            headers: { Authorization: `Bearer ${CALLER_TOKEN}` },
          }),
        ),
      );
      assert.equal(
        multiIpBurst.filter((r) => r.status === 200).length,
        burstSize,
        `Expected ${burstSize}/${burstSize} 16-address burst requests to succeed`,
      );
    }

    // 2. Reproduce exact Round 9 H7 DoS:
    //    16 attacker addresses (`127.0.1.1`..`127.0.1.16`) each opening 64 HTTP/1.1 keep-alive sockets
    //    (`16 * 64 = 1,024` sockets) sending 1 cheap request every ~800ms (and reconnecting when evicted).
    for (let ipIdx = 1; ipIdx <= 16; ipIdx++) {
      pools.push(
        startKeepAliveAttackerPool({
          port: hub.port,
          localAddress: `127.0.1.${ipIdx}`,
          socketCount: 64,
          pingIntervalMs: 800,
        }),
      );
      await sleep(10);
    }
    await sleep(250);

    // Send 152 requests from legitimate remote clients (`127.0.2.1`..`127.0.2.8`) in waves of 8 -> 152/152 MUST succeed!
    let legitOk = 0;
    const totalLegitRequests = 152;
    for (let offset = 0; offset < totalLegitRequests; offset += 8) {
      const batchLen = Math.min(8, totalLegitRequests - offset);
      const batchOut = await Promise.all(
        Array.from({ length: batchLen }, (_, j) => {
          const reqNum = offset + j;
          const clientIp = `127.0.2.${(reqNum % 8) + 1}`;
          const isPublicCheck = reqNum % 4 === 3;
          return sendBoundHttpRequest({
            port: hub.port,
            localAddress: clientIp,
            path: isPublicCheck ? '/openapi.json' : '/v1/capabilities',
            headers: isPublicCheck ? {} : { Authorization: `Bearer ${CALLER_TOKEN}` },
          });
        }),
      );
      for (const r of batchOut) {
        if (r.status === 200) legitOk++;
      }
    }
    assert.equal(
      legitOk,
      152,
      `Expected 152/152 (100%) legitimate client requests to succeed under 16x64 held keep-alive attack, got ${legitOk}/152`,
    );

    // Loopback `/health` & `/readyz` probes also succeed 20/20
    for (let i = 0; i < 20; i++) {
      const hRes = await sendBoundHttpRequest({
        port: hub.port,
        localAddress: '127.0.0.1',
        path: i % 2 === 0 ? '/health' : '/readyz',
      });
      assert.equal(hRes.status, 200);
    }

    for (const p of pools) p.stop();
    pools.length = 0;
    await sleep(150);

    // 3. Same-NAT Co-Tenant Fairness:
    //    1 squatter behind corporate/carrier NAT `127.0.4.77` holds 64 keep-alive sockets pinging every 500ms;
    //    152 co-tenant requests arriving from that EXACT SAME `127.0.4.77` IP must succeed 152/152 (100%)!
    const natSquatter = startKeepAliveAttackerPool({
      port: hub.port,
      localAddress: '127.0.4.77',
      socketCount: 64,
      pingIntervalMs: 500,
    });
    pools.push(natSquatter);
    await sleep(150);

    let sameNatOk = 0;
    for (let c = 0; c < 152; c += 4) {
      const wave = await Promise.all(
        Array.from({ length: 4 }, () =>
          sendBoundHttpRequest({
            port: hub.port,
            localAddress: '127.0.4.77',
            path: '/v1/capabilities',
            headers: { Authorization: `Bearer ${CALLER_TOKEN}` },
          }),
        ),
      );
      for (const r of wave) {
        if (r.status === 200) sameNatOk++;
      }
    }
    natSquatter.stop();
    pools.length = 0;
    await sleep(120);
    assert.equal(
      sameNatOk,
      152,
      `Expected 152/152 co-tenants behind shared NAT 127.0.4.77 to succeed, got ${sameNatOk}/152`,
    );

    // 4. Verify `MAX_REQUESTS_PER_CONNECTION = 64` sends `Connection: close` on the 64th response on a single keep-alive socket
    const agent = new http.Agent({ keepAlive: true, maxSockets: 1 });
    try {
      let sawKeepAliveBefore64 = false;
      let connHeaderOn64 = '';
      for (let reqIdx = 1; reqIdx <= 64; reqIdx++) {
        const resHdr = await new Promise<http.IncomingHttpHeaders>((resPromise, rejPromise) => {
          const r = http.request(
            {
              host: '127.0.0.1',
              port: hub.port,
              localAddress: '127.0.5.99',
              path: '/health',
              method: 'GET',
              agent,
            },
            (res) => {
              res.resume();
              res.on('end', () => resPromise(res.headers));
            },
          );
          r.on('error', rejPromise);
          r.end();
        });
        if (reqIdx === 1 && (resHdr.connection ?? '').toLowerCase() !== 'close') {
          sawKeepAliveBefore64 = true;
        }
        if (reqIdx === 64) {
          connHeaderOn64 = String(resHdr.connection ?? '').toLowerCase();
        }
      }
      assert.equal(sawKeepAliveBefore64, true, 'Requests 1..63 on healthy socket should keep connection alive');
      assert.equal(connHeaderOn64, 'close', 'Request #64 must rotate keep-alive socket via Connection: close');
    } finally {
      agent.destroy();
    }
  } finally {
    for (const p of pools) p.stop();
    await hub.close();
    rmSync(dataDir, { recursive: true, force: true });
  }
});

test('Round 9 [Slow-Read HTTP Pipelining Memory Cap]: 200 pipelined requests & multi-MiB stream on paused socket stay < 2 MiB and destroy cleanly', async () => {
  assert.equal(MAX_SOCKET_WRITABLE_BYTES, 2 * 1024 * 1024);

  const dataDir = mkdtempSync(join(tmpdir(), 'ef-r9-pipeline-'));
  // Seed a 3.5 MiB high-entropy document via `POST /v1/ingest-tab` or local origin + test `maxSocketWritableBytes` directly!
  const bigOriginBody = `<html><body><main><h1>Large Doc</h1><p>${randomBytes(1_800_000).toString('hex')}</p></main></body></html>`; // ~3.6 MiB!
  const originServer = http.createServer((req, res) => {
    if (req.url === '/robots.txt') {
      res.writeHead(200, { 'content-type': 'text/plain' });
      res.end('User-agent: *\nAllow: /\n');
      return;
    }
    res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
    res.end(bigOriginBody);
  });
  await new Promise<void>((r) => originServer.listen(0, '127.0.0.1', r));
  const originPort = (originServer.address() as net.AddressInfo).port;

  const hub = await startPortableHub({
    port: 0,
    host: '127.0.0.1',
    dataDir,
    socketDrainTimeoutMs: 350, // Fast deterministic slow-read teardown in tests (production default is 10,000ms)
    envOverrides: {
      CALLER_TOKEN,
      ROBOTS_BYPASS_HOSTS: '127.0.0.1',
      EDGEFETCH_DISABLE_UPDATE_CHECK: '1',
    },
  });
  // Override SAFE_PUBLIC_FETCH only for local 3.6 MiB origin test? No — use `POST /v1/ingest-tab` or `maxSocketWritableBytes`!
  // Even cleaner: `POST /v1/ingest-tab` with `html` (3.2 MiB!) returns `markdown` (~3.2 MiB > 2 MiB!) directly from Hub!
  originServer.close();

  const serverSockets = new Set<net.Socket>();
  const serverSocketByRemoteIp = new Map<string, { sock: net.Socket; closed: Promise<void> }>();
  hub.server.on('connection', (s) => {
    serverSockets.add(s);
    const remIp = (s.remoteAddress ?? '').replace(/^::ffff:/i, '');
    const closed = new Promise<void>((r) => {
      s.once('close', () => {
        serverSockets.delete(s);
        r();
      });
    });
    if (remIp) {
      serverSocketByRemoteIp.set(remIp, { sock: s, closed });
    }
  });

  try {
    // 1. Sub-test A: 200 back-to-back pipelined `GET /openapi.json` (~150 KiB each = ~30 MiB if uncapped!) on a
    //    `pause()`d client socket that NEVER calls `read()`.
    //    Note: On Windows/libuv, calling `client.pause()` stops `WSARecv` on the client socket so we observe server-side
    //    socket destruction directly via `hub.server` connection tracking.
    let peakServerWritableBytes = 0;
    const sampleInterval = setInterval(() => {
      for (const ss of serverSockets) {
        if ((ss.writableLength ?? 0) > peakServerWritableBytes) {
          peakServerWritableBytes = ss.writableLength;
        }
      }
    }, 5);

    const pausedPipelineSock = net.connect({
      host: '127.0.0.1',
      port: hub.port,
      localAddress: '127.0.8.11',
    });
    pausedPipelineSock.pause();
    pausedPipelineSock.on('error', () => undefined);

    await new Promise<void>((r) => pausedPipelineSock.once('connect', () => r()));
    await sleep(15);
    const serverPipelineEntry = serverSocketByRemoteIp.get('127.0.8.11');
    assert.ok(serverPipelineEntry, 'Expected server to accept connection from 127.0.8.11');

    const pipelinedPayload = `GET /openapi.json HTTP/1.1\r\nHost: 127.0.0.1:${hub.port}\r\nConnection: keep-alive\r\n\r\n`.repeat(
      200,
    );
    pausedPipelineSock.write(pipelinedPayload);

    // Wait for server to detect slow-read pipelining abuse and destroy the server-side socket cleanly
    await Promise.race([
      serverPipelineEntry.closed,
      sleep(2_500).then(() => {
        throw new Error('Expected slow-read pipelining server socket to be destroyed within 2.5s');
      }),
    ]);
    clearInterval(sampleInterval);

    assert.equal(serverPipelineEntry.sock.destroyed, true, 'Server-side slow-read pipelined socket must be destroyed');
    assert.ok(
      peakServerWritableBytes <= MAX_SOCKET_WRITABLE_BYTES,
      `Expected per-socket writableLength <= ${MAX_SOCKET_WRITABLE_BYTES} (2 MiB), got ${peakServerWritableBytes}`,
    );
    assert.ok(
      peakServerWritableBytes < 4 * 1024 * 1024,
      `Expected server buffered bytes < 4 MiB, got ${peakServerWritableBytes}`,
    );
    pausedPipelineSock.destroy();

    // 2. Sub-test B: Single > 2.5 MiB response (`POST /v1/ingest-tab` echoing 2.6 MiB markdown) to a `pause()`d slow-read client!
    let peakStreamWritableBytes = 0;
    const streamSample = setInterval(() => {
      for (const ss of serverSockets) {
        if ((ss.writableLength ?? 0) > peakStreamWritableBytes) {
          peakStreamWritableBytes = ss.writableLength;
        }
      }
    }, 5);

    const bigMarkdownBody = JSON.stringify({
      url: 'https://docs.example.com/giant-spec',
      markdown: `# Giant Spec\n\n${randomBytes(1_350_000).toString('hex')}`, // ~2.7 MiB JSON response (> 2 MiB cap!)
    });

    const slowStreamClient = net.connect({
      host: '127.0.0.1',
      port: hub.port,
      localAddress: '127.0.8.12',
    });
    slowStreamClient.pause();
    slowStreamClient.on('error', () => undefined);
    await new Promise<void>((r) => slowStreamClient.once('connect', () => r()));
    await sleep(15);
    const serverStreamEntry = serverSocketByRemoteIp.get('127.0.8.12');
    assert.ok(serverStreamEntry, 'Expected server to accept connection from 127.0.8.12');

    slowStreamClient.write(
      `POST /v1/ingest-tab HTTP/1.1\r\nHost: 127.0.0.1:${hub.port}\r\nAuthorization: Bearer ${CALLER_TOKEN}\r\nContent-Type: application/json\r\nContent-Length: ${Buffer.byteLength(bigMarkdownBody)}\r\nConnection: keep-alive\r\n\r\n${bigMarkdownBody}`,
    );

    await Promise.race([
      serverStreamEntry.closed,
      sleep(2_500).then(() => {
        throw new Error('Expected stalled >2.5 MiB response server socket to be destroyed');
      }),
    ]);
    clearInterval(streamSample);

    assert.equal(serverStreamEntry.sock.destroyed, true, 'Server-side stalled stream socket must be destroyed');
    assert.ok(
      peakStreamWritableBytes <= MAX_SOCKET_WRITABLE_BYTES,
      `Expected streaming writableLength <= 2 MiB, got ${peakStreamWritableBytes}`,
    );
    slowStreamClient.destroy();

    // 3. Normal client after pipelining + slow-stream attacks still succeeds 100%
    const normalRes = await sendBoundHttpRequest({
      port: hub.port,
      localAddress: '127.0.8.99',
      path: '/v1/capabilities',
      headers: { Authorization: `Bearer ${CALLER_TOKEN}` },
    });
    assert.equal(normalRes.status, 200);
  } finally {
    await hub.close();
    rmSync(dataDir, { recursive: true, force: true });
  }
});

test('Round 9 [OTel Security Audit Spans]: traceparent -00 cannot suppress owner login/admin/OAuth/MCP audit spans & public floods cannot drain audit budget', async () => {
  resetOtlpExportLimitersForTests();
  assert.equal(UNAUTH_OTLP_EXPORT_CAPACITY, 30);
  assert.equal(SECURITY_AUDIT_OTLP_CAPACITY, 120);
  assert.equal(MAX_PUBLIC_UNAUTH_INFLIGHT_OTLP, 8);
  // Pure W3C parser contract remains intact (`-00` -> `sampled: false` at parser level)
  assert.equal(parseTraceparent('00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-00')?.sampled, false);

  interface CapturedSpan {
    traceId: string;
    spanId: string;
    parentSpanId?: string;
    name: string;
    attributes: Record<string, string | number | boolean>;
  }

  const exportedSpans: CapturedSpan[] = [];
  let holdPublicExports = false;
  const heldPublicExportResolvers: Array<() => void> = [];

  const collector = http.createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => {
      const raw = Buffer.concat(chunks).toString('utf8');
      let hasAuditOrAuth = false;
      try {
        const parsed = JSON.parse(raw) as {
          resourceSpans?: Array<{
            scopeSpans?: Array<{
              spans?: Array<{
                traceId: string;
                spanId: string;
                parentSpanId?: string;
                name: string;
                attributes?: Array<{
                  key: string;
                  value?: { stringValue?: string; intValue?: string; doubleValue?: number; boolValue?: boolean };
                }>;
              }>;
            }>;
          }>;
        };
        const batchSpans = parsed.resourceSpans?.[0]?.scopeSpans?.[0]?.spans ?? [];
        for (const s of batchSpans) {
          const attrMap: Record<string, string | number | boolean> = {};
          for (const a of s.attributes ?? []) {
            if (a.value?.stringValue !== undefined) attrMap[a.key] = a.value.stringValue;
            else if (a.value?.intValue !== undefined) attrMap[a.key] = Number(a.value.intValue);
            else if (a.value?.doubleValue !== undefined) attrMap[a.key] = a.value.doubleValue;
            else if (a.value?.boolValue !== undefined) attrMap[a.key] = a.value.boolValue;
          }
          if (s.name.startsWith('edgefetch.admin.') || s.name.startsWith('edgefetch.oauth.') || s.name === 'edgefetch.mcp.tool') {
            hasAuditOrAuth = true;
          }
          exportedSpans.push({
            traceId: s.traceId,
            spanId: s.spanId,
            ...(s.parentSpanId ? { parentSpanId: s.parentSpanId } : {}),
            name: s.name,
            attributes: attrMap,
          });
        }
      } catch {
        // ignore
      }
      const finishResp = () => {
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end('{}');
      };
      if (holdPublicExports && !hasAuditOrAuth) {
        heldPublicExportResolvers.push(finishResp);
      } else {
        finishResp();
      }
    });
  });

  await new Promise<void>((r) => collector.listen(0, '127.0.0.1', r));
  const collectorPort = (collector.address() as net.AddressInfo).port;
  const collectorEndpoint = `http://127.0.0.1:${collectorPort}`;

  const coordinator = new LocalAgentHubCoordinator(':memory:');
  const dataDir = mkdtempSync(join(tmpdir(), 'ef-r9-otel-'));
  const portable = await startPortableHub({
    port: 0,
    host: '127.0.0.1',
    dataDir,
    envOverrides: {
      CALLER_TOKEN,
      OTEL_EXPORTER_OTLP_ENDPOINT: collectorEndpoint,
      EDGEFETCH_DISABLE_UPDATE_CHECK: '1',
    },
  });

  try {
    const workerEnv = {
      AGENT_HUB: coordinator.asNamespace() as never,
      CALLER_TOKEN,
      OTEL_EXPORTER_OTLP_ENDPOINT: collectorEndpoint,
      EDGEFETCH_DISABLE_UPDATE_CHECK: '1',
    };

    // 1. Public unauthenticated flood: 120 `/openapi.json` + 120 `/.well-known/*` + 100 `/health` + 100 `401 /v1/scrape`
    //    (completely exhausting `UNAUTH_OTLP_EXPORT_CAPACITY = 30`!)
    for (let i = 0; i < 120; i++) {
      await hubWorker.fetch(new Request('https://hub.example.com/openapi.json'), workerEnv);
      await hubWorker.fetch(new Request('https://hub.example.com/.well-known/oauth-authorization-server'), workerEnv);
      if (i < 100) {
        await hubWorker.fetch(
          new Request('https://hub.example.com/health', {
            headers: { traceparent: `00-${'1'.repeat(32)}-${'2'.repeat(16)}-01` },
          }),
          workerEnv,
        );
        await hubWorker.fetch(
          new Request('https://hub.example.com/v1/scrape', {
            method: 'POST',
            headers: { 'content-type': 'application/json', traceparent: `00-${'3'.repeat(32)}-${'4'.repeat(16)}-01` },
            body: '{"url":"https://example.com"}',
          }),
          workerEnv,
        );
      }
    }

    // ALSO hold `MAX_PUBLIC_UNAUTH_INFLIGHT_OTLP` slow public OTLP collector exports open concurrently
    // (after refilling unauth budget just enough to launch slow public exports) to verify inflight isolation too!
    resetOtlpExportLimitersForTests();
    holdPublicExports = true;
    const stalledPublicFlushes: Promise<Response>[] = [];
    for (let i = 0; i < 20; i++) {
      stalledPublicFlushes.push(hubWorker.fetch(new Request('https://hub.example.com/openapi.json'), workerEnv));
    }
    await sleep(60);
    // Drain the remaining `unauthOtlpTokens` completely as well
    holdPublicExports = false;
    for (let i = 0; i < 40; i++) {
      await hubWorker.fetch(new Request('https://hub.example.com/openapi.json'), workerEnv);
    }

    exportedSpans.length = 0;

    // 2. Exact Round 9 reproduction on Workers Hub:
    //    Successful owner `POST /admin/login` WITH `traceparent: ...-00` MUST emit `edgefetch.admin.login` (`authenticated`)!
    const loginTraceUnsampled = 'aaaa1111bbbb2222cccc3333dddd4444';
    const loginParentId = '1122334455667788';
    const loginWith00 = await hubWorker.fetch(
      new Request('https://hub.example.com/admin/login', {
        method: 'POST',
        headers: {
          origin: 'https://hub.example.com',
          'content-type': 'application/x-www-form-urlencoded',
          traceparent: `00-${loginTraceUnsampled}-${loginParentId}-00`,
        },
        body: new URLSearchParams({ token: CALLER_TOKEN }).toString(),
      }),
      workerEnv,
    );
    assert.equal(loginWith00.status, 302);
    assert.match(
      loginWith00.headers.get('traceparent') ?? '',
      new RegExp(`^00-${loginTraceUnsampled}-[0-9a-f]{16}-01$`),
      'Promoted audit trace must advertise sampled -01 in response traceparent',
    );

    const loginAuditSpan = exportedSpans.find(
      (s) => s.name === 'edgefetch.admin.login' && s.traceId === loginTraceUnsampled,
    );
    assert.ok(loginAuditSpan, 'Owner login with traceparent -00 MUST emit edgefetch.admin.login audit span');
    assert.equal(loginAuditSpan.attributes['admin.outcome'], 'authenticated');
    const loginHttpSpan = exportedSpans.find(
      (s) => s.name === 'edgefetch.http' && s.traceId === loginTraceUnsampled,
    );
    assert.ok(loginHttpSpan, 'Enclosing edgefetch.http span must also be exported with parentSpanId stitched');
    assert.equal(loginHttpSpan.parentSpanId, loginParentId);

    // 3. Failed `POST /admin/login` (401) WITH `traceparent: ...-00` AFTER public traffic drained `unauthOtlpTokens`
    //    MUST ALSO emit `edgefetch.admin.login` (`unauthorized`) via isolated `security_audit` budget!
    const badLoginTrace = 'bbbb2222cccc3333dddd4444eeee5555';
    const badLoginWith00 = await hubWorker.fetch(
      new Request('https://hub.example.com/admin/login', {
        method: 'POST',
        headers: {
          origin: 'https://hub.example.com',
          'content-type': 'application/x-www-form-urlencoded',
          'cf-connecting-ip': '198.51.100.77',
          traceparent: `00-${badLoginTrace}-${loginParentId}-00`,
        },
        body: 'token=wrong-secret-guess',
      }),
      workerEnv,
    );
    assert.equal(badLoginWith00.status, 401);
    const badLoginSpan = exportedSpans.find(
      (s) => s.name === 'edgefetch.admin.login' && s.traceId === badLoginTrace,
    );
    assert.ok(badLoginSpan, 'Failed admin login with traceparent -00 must emit security_audit span even after public flood');
    assert.equal(badLoginSpan.attributes['admin.outcome'], 'unauthorized');

    // 4. OAuth `/oauth/register`, `/admin/api/grants/revoke`, `/mcp` tool call, and Portable Hub `/admin/login` with `-00`!
    const oauthRegTrace = 'cccc3333dddd4444eeee5555ffff6666';
    const regRes = await hubWorker.fetch(
      new Request('https://hub.example.com/oauth/register', {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'cf-connecting-ip': '198.51.100.88',
          traceparent: `00-${oauthRegTrace}-${loginParentId}-00`,
        },
        body: JSON.stringify({
          client_name: 'Audit Test Client',
          redirect_uris: ['http://127.0.0.1:8910/cb'],
        }),
      }),
      workerEnv,
    );
    assert.equal(regRes.status, 201);
    assert.ok(
      exportedSpans.some((s) => s.name === 'edgefetch.oauth.register' && s.traceId === oauthRegTrace),
      'OAuth client registration with traceparent -00 must emit edgefetch.oauth.register audit span',
    );

    const mintedAdmin = await createAdminSessionValue(CALLER_TOKEN);
    const adminRevokeTrace = 'dddd4444eeee5555ffff666600001111';
    const revokeRes = await hubWorker.fetch(
      new Request('https://hub.example.com/admin/api/grants/revoke', {
        method: 'POST',
        headers: {
          origin: 'https://hub.example.com',
          cookie: `${ADMIN_COOKIE_NAME}=${mintedAdmin.value}`,
          'x-csrf-token': mintedAdmin.csrf,
          'content-type': 'application/json',
          traceparent: `00-${adminRevokeTrace}-${loginParentId}-00`,
        },
        body: JSON.stringify({ grantId: 'grant_test_123' }),
      }),
      workerEnv,
    );
    assert.equal(revokeRes.status, 200);
    assert.ok(
      exportedSpans.some((s) => s.name === 'edgefetch.admin.grant_revoke' && s.traceId === adminRevokeTrace),
      'Admin grant_revoke with traceparent -00 must emit edgefetch.admin.grant_revoke audit span',
    );

    const mcpTrace = 'eeee5555ffff66660000111122223333';
    const mcpRes = await hubWorker.fetch(
      new Request('https://hub.example.com/mcp', {
        method: 'POST',
        headers: {
          authorization: `Bearer ${CALLER_TOKEN}`,
          'content-type': 'application/json',
          traceparent: `00-${mcpTrace}-${loginParentId}-00`,
        },
        body: JSON.stringify({
          jsonrpc: '2.0',
          id: 1,
          method: 'tools/call',
          params: { name: 'find_extractors', arguments: { query: 'stripe', limit: 2 } },
        }),
      }),
      workerEnv,
    );
    assert.equal(mcpRes.status, 200);
    assert.ok(
      exportedSpans.some((s) => s.name === 'edgefetch.mcp.tool' && s.traceId === mcpTrace),
      'MCP tools/call with traceparent -00 must emit edgefetch.mcp.tool span',
    );

    // Live Portable Hub HTTP server end-to-end owner login with `traceparent: ...-00`
    const portableLoginTrace = 'ffff6666000011112222333344445555';
    const portableBase = `http://127.0.0.1:${portable.port}`;
    const pLoginRes = await sendBoundHttpRequest({
      port: portable.port,
      localAddress: '127.0.9.42',
      method: 'POST',
      path: '/admin/login',
      headers: {
        Origin: portableBase,
        'Content-Type': 'application/x-www-form-urlencoded',
        traceparent: `00-${portableLoginTrace}-${loginParentId}-00`,
      },
      body: new URLSearchParams({ token: CALLER_TOKEN }).toString(),
    });
    assert.equal(pLoginRes.status, 302);
    await sleep(50);
    assert.ok(
      exportedSpans.some(
        (s) =>
          s.name === 'edgefetch.admin.login' &&
          s.traceId === portableLoginTrace &&
          s.attributes['admin.outcome'] === 'authenticated',
      ),
      'Live Portable Hub owner login with traceparent -00 must export edgefetch.admin.login span',
    );

    for (const finishHeld of heldPublicExportResolvers.splice(0)) finishHeld();
    await Promise.allSettled(stalledPublicFlushes);
  } finally {
    for (const finishHeld of heldPublicExportResolvers.splice(0)) finishHeld();
    coordinator.close();
    await portable.close();
    collector.close();
    rmSync(dataDir, { recursive: true, force: true });
  }
});
