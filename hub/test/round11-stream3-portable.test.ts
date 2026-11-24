/**
 * Round 11 Stream 3 Security & Load Resilience Suite (`hub/test/round11-stream3-portable.test.ts`):
 *
 *  `S5` — Portable Hub Partial-Header Slowloris & Keep-Alive Hold Defenses:
 *   1. Multi-IP partial-header slowloris flood past `maxTotalSockets` (`"GET /v1/scrape HTTP/1.1\r\nX-Slow: "`
 *      held open without `\r\n\r\n` + continuous reconnects): concurrent waves of new authenticated clients
 *      (`Authorization: Bearer ...`) succeed at 98–100% with fast latency + loopback `/health` 100%.
 *   2. Per-IP and global unproven pre-header accounting (`requestsCompleted === 0 && activeTurnCount === 0`,
 *      both 0-byte and partial-byte):
 *      - Highest-count address evicted first (0-byte before partial-byte, oldest `connectedAt` first).
 *      - Distributed 1-socket-per-IP partial-header botnet exceeding `maxTotalSockets` never blocks new clients.
 *      - Shared-NAT 100% partial-header squatters cannot block same-NAT co-tenants (`60/60` succeed).
 *      - Short `~1.25s` full-header deadline under socket pressure reaps stalled partial-header sockets without
 *        waiting 10s for `PRE_HEADER_TIMEOUT_MS`.
 *   3. Round 9 keep-alive hold + mixed 0-byte, partial-header, 1-req keep-alive, turn-2 partial-header, and
 *      veteran persistent keep-alive clients: new authenticated clients (`120/120` = 100%) AND established
 *      veteran persistent clients (`12/12` = 0 disconnects) both succeed reliably under heavy load.
 *   4. Loopback / local reverse-proxy (`127.0.0.1`) partial-header hold resilience (`40/40` succeed).
 */
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import http from 'node:http';
import net from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { startPortableHub } from '../portable/portable-server';

const CALLER_TOKEN = 'r11-s3-owner-caller-secret-0123456789abcdef';

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

function sendBoundHttpRequest(params: {
  port: number;
  localAddress?: string;
  path: string;
  method?: string;
  headers?: Record<string, string>;
  body?: string;
  timeoutMs?: number;
}): Promise<{ status: number; headers: http.IncomingHttpHeaders; body: string; latencyMs: number }> {
  const startedAt = Date.now();
  return new Promise((resolveReq, rejectReq) => {
    const req = http.request(
      {
        host: '127.0.0.1',
        port: params.port,
        ...(params.localAddress ? { localAddress: params.localAddress } : {}),
        method: params.method ?? 'GET',
        path: params.path,
        agent: false,
        headers: {
          Host: `127.0.0.1:${params.port}`,
          Connection: 'close',
          ...(params.headers ?? {}),
        },
        timeout: params.timeoutMs ?? 4_000,
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (c: Buffer) => chunks.push(c));
        res.on('end', () => {
          resolveReq({
            status: res.statusCode ?? 0,
            headers: res.headers,
            body: Buffer.concat(chunks).toString('utf8'),
            latencyMs: Date.now() - startedAt,
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

interface AttackerPoolHandle {
  stop: () => void;
  liveCount: () => number;
}

function startPartialHeaderSlowlorisPool(params: {
  port: number;
  localAddress?: string;
  socketCount: number;
  partialPayload?: string;
  reconnectDelayMs?: number;
}): AttackerPoolHandle {
  let stopped = false;
  const sockets = new Set<net.Socket>();
  const timers = new Set<ReturnType<typeof setTimeout>>();
  const payload =
    params.partialPayload ?? `GET /v1/scrape HTTP/1.1\r\nHost: 127.0.0.1:${params.port}\r\nX-Slow: `;

  const openOne = () => {
    if (stopped) return;
    const sock = net.connect({
      host: '127.0.0.1',
      port: params.port,
      ...(params.localAddress ? { localAddress: params.localAddress } : {}),
    });
    sockets.add(sock);
    sock.resume();
    sock.on('error', () => undefined);
    sock.on('connect', () => {
      if (!stopped && !sock.destroyed && payload.length > 0) {
        sock.write(payload);
      }
    });
    sock.on('close', () => {
      sockets.delete(sock);
      if (!stopped && params.reconnectDelayMs !== undefined && params.reconnectDelayMs >= 0) {
        const t = setTimeout(() => {
          timers.delete(t);
          openOne();
        }, params.reconnectDelayMs);
        t.unref?.();
        timers.add(t);
      }
    });
  };

  for (let i = 0; i < params.socketCount; i++) {
    openOne();
  }

  return {
    stop() {
      stopped = true;
      for (const t of timers) clearTimeout(t);
      timers.clear();
      for (const s of sockets) s.destroy();
      sockets.clear();
    },
    liveCount() {
      return sockets.size;
    },
  };
}

function startMixedKeepAliveHoldPool(params: {
  port: number;
  localAddress: string;
  socketCount: number;
  sendTurn2PartialBytes: boolean;
  pingIntervalMs: number;
}): AttackerPoolHandle {
  let stopped = false;
  const sockets = new Set<net.Socket>();
  const timers = new Set<ReturnType<typeof setTimeout>>();

  const openSlot = (slotIdx: number) => {
    if (stopped) return;
    const sock = net.connect({
      host: '127.0.0.1',
      port: params.port,
      localAddress: params.localAddress,
    });
    sockets.add(sock);
    sock.on('error', () => undefined);

    let turn1CompleteSeen = false;
    let buf = '';
    sock.on('data', (chunk: Buffer) => {
      if (turn1CompleteSeen) return;
      buf += chunk.toString('latin1');
      if (buf.includes('\r\n\r\n')) {
        turn1CompleteSeen = true;
        buf = '';
        if (params.sendTurn2PartialBytes && !stopped && !sock.destroyed) {
          // Hold partial headers on keep-alive turn #2 without `\r\n\r\n`!
          sock.write(`GET /v1/scrape HTTP/1.1\r\nHost: 127.0.0.1:${params.port}\r\nX-Turn2-Slow: `);
        }
      }
    });

    let pingTimer: ReturnType<typeof setTimeout> | null = null;
    const sendKeepAliveReq = () => {
      if (stopped || sock.destroyed || !sock.writable) return;
      sock.write(`GET /robots.txt HTTP/1.1\r\nHost: 127.0.0.1:${params.port}\r\nConnection: keep-alive\r\n\r\n`);
      if (!params.sendTurn2PartialBytes) {
        pingTimer = setTimeout(sendKeepAliveReq, params.pingIntervalMs + (slotIdx % 5) * 40);
        pingTimer.unref?.();
        timers.add(pingTimer);
      }
    };

    sock.on('connect', sendKeepAliveReq);
    sock.on('close', () => {
      sockets.delete(sock);
      if (pingTimer) {
        clearTimeout(pingTimer);
        timers.delete(pingTimer);
      }
      if (!stopped) {
        const rt = setTimeout(() => {
          timers.delete(rt);
          openSlot(slotIdx);
        }, 50 + (slotIdx % 8) * 15);
        rt.unref?.();
        timers.add(rt);
      }
    });
  };

  for (let i = 0; i < params.socketCount; i++) {
    openSlot(i);
  }

  return {
    stop() {
      stopped = true;
      for (const t of timers) clearTimeout(t);
      timers.clear();
      for (const s of sockets) s.destroy();
      sockets.clear();
    },
    liveCount() {
      return sockets.size;
    },
  };
}

interface PinnedVeteranClient {
  readonly ip: string;
  readonly closed: boolean;
  sendRequest(path: string, authToken?: string): Promise<{ status: number; body: string }>;
  destroy(): void;
}

async function openPinnedVeteranClient(port: number, ip: string): Promise<PinnedVeteranClient> {
  let pinnedSocket: net.Socket | null = null;
  let socketClosed = false;
  let createdConnections = 0;

  const agent = new http.Agent({
    keepAlive: true,
    maxSockets: 1,
    maxFreeSockets: 1,
    keepAliveMsecs: 15_000,
  });

  const origCreate = agent.createConnection.bind(agent);
  agent.createConnection = ((opts: net.TcpSocketConnectOpts, cb?: () => void) => {
    createdConnections++;
    if (createdConnections > 1) {
      throw new Error(`Pinned veteran socket ${ip} was evicted and attempted to reconnect!`);
    }
    const s = origCreate({ ...opts, localAddress: ip }, cb);
    pinnedSocket = s;
    s.on('error', () => undefined);
    s.once('close', () => {
      socketClosed = true;
    });
    return s;
  }) as typeof agent.createConnection;

  const sendRequest = (path: string, authToken = CALLER_TOKEN): Promise<{ status: number; body: string }> =>
    new Promise((resolveReq, rejectReq) => {
      if (pinnedSocket && (socketClosed || pinnedSocket.destroyed)) {
        rejectReq(new Error(`Pinned veteran socket ${ip} already closed`));
        return;
      }
      const req = http.request(
        {
          host: '127.0.0.1',
          port,
          path,
          method: 'GET',
          agent,
          headers: {
            Host: `127.0.0.1:${port}`,
            Connection: 'keep-alive',
            ...(authToken ? { Authorization: `Bearer ${authToken}` } : {}),
          },
          timeout: 4_000,
        },
        (res) => {
          const chunks: Buffer[] = [];
          res.on('data', (c: Buffer) => chunks.push(c));
          res.on('end', () => {
            resolveReq({ status: res.statusCode ?? 0, body: Buffer.concat(chunks).toString('utf8') });
          });
        },
      );
      req.on('timeout', () => req.destroy(new Error(`Timeout on veteran ${ip}`)));
      req.on('error', rejectReq);
      req.end();
    });

  // Complete 3 initial turns so `requestsCompleted === 3 >= VETERAN_MIN_COMPLETED_REQUESTS (2)`
  for (let i = 0; i < 3; i++) {
    const r = await sendRequest('/v1/capabilities', CALLER_TOKEN);
    assert.equal(r.status, 200);
  }

  return {
    ip,
    get closed() {
      return socketClosed || Boolean(pinnedSocket?.destroyed);
    },
    sendRequest,
    destroy() {
      socketClosed = true;
      pinnedSocket?.destroy();
      agent.destroy();
    },
  };
}

test('Round 11 [S5-1 — Partial-Header Slowloris Flood]: 16 attacker IPs × 20 partial-header sockets (320 > 256 maxTotalSockets) + reconnects cannot starve new authenticated clients (100% succeed, fast latency)', async () => {
  const dataDir = mkdtempSync(join(tmpdir(), 'ef-r11-s5-flood-'));
  const hub = await startPortableHub({
    port: 0,
    host: '127.0.0.1',
    dataDir,
    envOverrides: {
      CALLER_TOKEN,
      EDGEFETCH_DISABLE_UPDATE_CHECK: '1',
    },
  });

  const pools: AttackerPoolHandle[] = [];
  try {
    // 16 attacker IPs each hold 20 partial-header sockets (`16 * 20 = 320 > 256 = MAX_TOTAL_SOCKETS`),
    // sending `"GET /v1/scrape HTTP/1.1\r\nHost: ...\r\nX-Slow: "` (no `\r\n\r\n`) and reconnecting every 5ms on close!
    for (let ipIdx = 1; ipIdx <= 16; ipIdx++) {
      pools.push(
        startPartialHeaderSlowlorisPool({
          port: hub.port,
          localAddress: `127.0.50.${ipIdx}`,
          socketCount: 20,
          reconnectDelayMs: 5,
        }),
      );
    }
    await sleep(100);

    // Run 10 concurrent waves × 12 authenticated requests = 120 new authenticated client connections!
    let succeeded = 0;
    const latencies: number[] = [];
    const totalRequests = 120;

    for (let wave = 0; wave < 10; wave++) {
      const waveResults = await Promise.allSettled(
        Array.from({ length: 12 }, (_, idx) =>
          sendBoundHttpRequest({
            port: hub.port,
            localAddress: `127.0.60.${idx + 1}`,
            path: idx % 2 === 0 ? '/v1/capabilities' : '/v1/hosts',
            headers: { Authorization: `Bearer ${CALLER_TOKEN}` },
          }),
        ),
      );
      for (const res of waveResults) {
        if (res.status === 'fulfilled' && res.value.status === 200) {
          succeeded++;
          latencies.push(res.value.latencyMs);
        }
      }
    }

    assert.equal(
      succeeded,
      totalRequests,
      `Expected 120/120 (100%) authenticated client requests to succeed under 320-socket partial-header flood, got ${succeeded}/${totalRequests}`,
    );

    latencies.sort((a, b) => a - b);
    const p95LatencyMs = latencies[Math.floor(latencies.length * 0.95)] ?? 0;
    assert.ok(
      p95LatencyMs < 500,
      `Expected fast p95 authenticated latency (< 500ms, never waiting for 10s headersTimeout), got ${p95LatencyMs}ms`,
    );

    // Verify loopback `/health` and `/readyz` remain 100% responsive
    for (let i = 0; i < 20; i++) {
      const h = await sendBoundHttpRequest({
        port: hub.port,
        localAddress: '127.0.0.1',
        path: i % 2 === 0 ? '/health' : '/readyz',
      });
      assert.equal(h.status, 200);
    }
  } finally {
    for (const p of pools) p.stop();
    await hub.close();
    rmSync(dataDir, { recursive: true, force: true });
  }
});

test('Round 11 [S5-2 — Highest-Count-First Eviction, Distributed 1-Per-IP Botnet, Shared-NAT Partial Squatters & 1.25s Pressure Deadline]', async () => {
  const dataDir = mkdtempSync(join(tmpdir(), 'ef-r11-s5-evict-'));
  const hub = await startPortableHub({
    port: 0,
    host: '127.0.0.1',
    dataDir,
    maxTotalSockets: 32,
    maxGlobalPreHeaderSockets: 32,
    maxPreHeaderSocketsPerIp: 12,
    headersTimeoutMs: 10_000,
    envOverrides: {
      CALLER_TOKEN,
      EDGEFETCH_DISABLE_UPDATE_CHECK: '1',
    },
  });

  const openHeldPartialSocket = (ip: string, partial = 'GET /v1/scrape HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Slow: ') =>
    new Promise<{ sock: net.Socket; isClosed: () => boolean; closedAtPromise: Promise<number> }>((resolveOpen, rejectOpen) => {
      const t0 = Date.now();
      let closed = false;
      const s = net.connect({ host: '127.0.0.1', port: hub.port, localAddress: ip });
      s.resume();
      s.on('error', () => undefined);
      const closedAtPromise = new Promise<number>((r) => {
        s.once('close', () => {
          closed = true;
          r(Date.now() - t0);
        });
      });
      s.once('connect', () => {
        if (partial.length > 0 && !s.destroyed) s.write(partial);
        resolveOpen({ sock: s, isClosed: () => closed || s.destroyed, closedAtPromise });
      });
      s.once('error', rejectOpen);
    });

  const cleanupSockets: net.Socket[] = [];
  try {
    // 1. Sub-case A: Highest-count IP evicted first (oldest socket within that IP first), protecting 1-socket IPs!
    //    Fill `maxTotalSockets = 32` with:
    //    - `127.0.70.1`: 10 partial-header sockets
    //    - `127.0.70.2`: 6 partial-header sockets
    //    - `127.0.71.1`..`127.0.71.16`: 1 partial-header socket each (`10 + 6 + 16 = 32`)
    const hog10: Array<Awaited<ReturnType<typeof openHeldPartialSocket>>> = [];
    for (let i = 0; i < 10; i++) {
      const h = await openHeldPartialSocket('127.0.70.1');
      hog10.push(h);
      cleanupSockets.push(h.sock);
      await sleep(3);
    }
    const hog6: Array<Awaited<ReturnType<typeof openHeldPartialSocket>>> = [];
    for (let i = 0; i < 6; i++) {
      const h = await openHeldPartialSocket('127.0.70.2');
      hog6.push(h);
      cleanupSockets.push(h.sock);
    }
    const singles16: Array<Awaited<ReturnType<typeof openHeldPartialSocket>>> = [];
    for (let i = 1; i <= 16; i++) {
      const h = await openHeldPartialSocket(`127.0.71.${i}`);
      singles16.push(h);
      cleanupSockets.push(h.sock);
    }
    await sleep(30);

    // Send 3 sequential authenticated client requests -> 127.0.70.1 (count 10 -> 9 -> 8 -> 7) must absorb ALL evictions,
    // oldest sockets (`hog10[0..2]`) first, while ALL 16 single-socket IPs stay open!
    for (let k = 1; k <= 3; k++) {
      const r = await sendBoundHttpRequest({
        port: hub.port,
        localAddress: `127.0.72.${k}`,
        path: '/v1/capabilities',
        headers: { Authorization: `Bearer ${CALLER_TOKEN}` },
      });
      assert.equal(r.status, 200);
    }
    await sleep(30);

    const hog10ClosedCount = hog10.filter((h) => h.isClosed()).length;
    assert.ok(hog10ClosedCount >= 3, `Expected highest-count IP (127.0.70.1) to absorb >= 3 evictions, got ${hog10ClosedCount}`);
    assert.equal(hog10[0]!.isClosed(), true, 'Oldest socket on highest-count IP must be evicted first');
    assert.equal(
      singles16.filter((s) => s.isClosed()).length,
      0,
      'Single-socket partial-header IPs (< 1.25s old) must NOT be evicted while multi-socket hog IPs exist',
    );

    for (const s of cleanupSockets) s.destroy();
    cleanupSockets.length = 0;
    await sleep(60);

    // 2. Sub-case B: Distributed 1-socket-per-IP partial-header botnet (`40` distinct IPs > `maxTotalSockets = 32`)
    //    Immediately (< 100ms, BEFORE 1.25s timeout!) send 32 new authenticated requests -> 32/32 MUST succeed!
    const botnetPools: AttackerPoolHandle[] = [];
    for (let i = 1; i <= 40; i++) {
      botnetPools.push(
        startPartialHeaderSlowlorisPool({
          port: hub.port,
          localAddress: `127.0.73.${i}`,
          socketCount: 1,
          reconnectDelayMs: 10,
        }),
      );
    }
    await sleep(40);

    let botnetSurvived = 0;
    for (let wave = 0; wave < 4; wave++) {
      const out = await Promise.all(
        Array.from({ length: 8 }, (_, idx) =>
          sendBoundHttpRequest({
            port: hub.port,
            localAddress: `127.0.74.${idx + 1}`,
            path: '/v1/capabilities',
            headers: { Authorization: `Bearer ${CALLER_TOKEN}` },
          }),
        ),
      );
      for (const r of out) {
        if (r.status === 200) botnetSurvived++;
      }
    }
    for (const p of botnetPools) p.stop();
    await sleep(60);
    assert.equal(
      botnetSurvived,
      32,
      `Expected 32/32 authenticated requests to succeed against 40-IP 1-per-IP partial-header botnet, got ${botnetSurvived}/32`,
    );

    // 3. Sub-case C: Shared-NAT 100% partial-header squatters (`12/12` slots on `127.0.75.77` holding partial headers!)
    const natPool = startPartialHeaderSlowlorisPool({
      port: hub.port,
      localAddress: '127.0.75.77',
      socketCount: 12,
      reconnectDelayMs: 15,
    });
    await sleep(60);

    let sameNatOk = 0;
    for (let i = 0; i < 60; i++) {
      const r = await sendBoundHttpRequest({
        port: hub.port,
        localAddress: '127.0.75.77',
        path: '/v1/capabilities',
        headers: { Authorization: `Bearer ${CALLER_TOKEN}` },
      });
      if (r.status === 200) sameNatOk++;
    }
    natPool.stop();
    await sleep(60);
    assert.equal(
      sameNatOk,
      60,
      `Expected 60/60 shared-NAT peers on 127.0.75.77 to succeed despite 100% partial-header squatters, got ${sameNatOk}/60`,
    );

    // 4. Sub-case D: Short `~1.25s` full-header deadline under socket pressure (`headersTimeoutMs = 10_000`!)
    //    Open 20 partial-header sockets (`20 >= 50% of 32`, 1 per IP so only pressure deadline reaps them) and
    //    verify proactive timer sweep closes them near ~1.25s (<< 10s `headersTimeoutMs`)!
    const pressuredPartial = await Promise.all(
      Array.from({ length: 20 }, (_, idx) => openHeldPartialSocket(`127.0.76.${idx + 1}`)),
    );
    for (const p of pressuredPartial) cleanupSockets.push(p.sock);

    // Wait for at least half (until pressure drops below threshold) to be reaped by the ~1.25s pressure deadline
    const firstReapElapsed = await Promise.race(pressuredPartial.map((p) => p.closedAtPromise));
    await sleep(250);
    const reapedUnderPressure = pressuredPartial.filter((p) => p.isClosed()).length;
    assert.ok(
      firstReapElapsed >= 950 && firstReapElapsed < 2_600,
      `Expected pressured partial-header sockets to expire near ~1,250ms (not 10,000ms!), got ${firstReapElapsed}ms`,
    );
    assert.ok(
      reapedUnderPressure >= 8,
      `Expected proactive sweep to reap pressured partial-header sockets down below pressure threshold, reaped ${reapedUnderPressure}/20`,
    );
  } finally {
    for (const s of cleanupSockets) s.destroy();
    await hub.close();
    rmSync(dataDir, { recursive: true, force: true });
  }
});

test('Round 11 [S5-3 — Round 9 Keep-Alive Hold + Mixed Partial-Header / Turn-2 Partial / 0-Byte / Veteran Clients]: 120/120 new auth clients & 12/12 veterans succeed under 400-socket mixed hold', async () => {
  const dataDir = mkdtempSync(join(tmpdir(), 'ef-r11-s5-mixed-'));
  const hub = await startPortableHub({
    port: 0,
    host: '127.0.0.1',
    dataDir,
    keepAliveTimeoutMs: 12_000,
    envOverrides: {
      CALLER_TOKEN,
      EDGEFETCH_DISABLE_UPDATE_CHECK: '1',
    },
  });

  const veterans: PinnedVeteranClient[] = [];
  const attackerPools: AttackerPoolHandle[] = [];

  try {
    // 1. Establish 12 veteran persistent keep-alive clients (`127.0.80.1`..`127.0.80.12`, `requestsCompleted === 3`)
    for (let i = 1; i <= 12; i++) {
      veterans.push(await openPinnedVeteranClient(hub.port, `127.0.80.${i}`));
    }
    await sleep(280);

    // 2. Launch 400 concurrent held attacker sockets (> `MAX_TOTAL_SOCKETS = 256`) across 4 distinct hold modes:
    //    - 8 IPs × 20 partial-header slowloris sockets (`160` sockets)
    //    - 4 IPs × 20 Round-9 keep-alive idle hold sockets (`80` sockets)
    //    - 4 IPs × 20 keep-alive turn-2 partial-header hold sockets (`80` sockets)
    //    - 4 IPs × 20 zero-byte idle pre-header sockets (`80` sockets)
    for (let i = 1; i <= 8; i++) {
      attackerPools.push(
        startPartialHeaderSlowlorisPool({
          port: hub.port,
          localAddress: `127.0.81.${i}`,
          socketCount: 20,
          reconnectDelayMs: 10,
        }),
      );
    }
    for (let i = 1; i <= 4; i++) {
      attackerPools.push(
        startMixedKeepAliveHoldPool({
          port: hub.port,
          localAddress: `127.0.82.${i}`,
          socketCount: 20,
          sendTurn2PartialBytes: false,
          pingIntervalMs: 700,
        }),
      );
      attackerPools.push(
        startMixedKeepAliveHoldPool({
          port: hub.port,
          localAddress: `127.0.83.${i}`,
          socketCount: 20,
          sendTurn2PartialBytes: true,
          pingIntervalMs: 700,
        }),
      );
      attackerPools.push(
        startPartialHeaderSlowlorisPool({
          port: hub.port,
          localAddress: `127.0.84.${i}`,
          socketCount: 20,
          partialPayload: '',
          reconnectDelayMs: 15,
        }),
      );
    }
    await sleep(150);

    // 3. Send 12 waves × 10 = 120 new authenticated requests (`127.0.85.1`..`10`) interleaved with veteran keep-alive requests!
    let newAuthOk = 0;
    for (let wave = 0; wave < 12; wave++) {
      const waveOut = await Promise.allSettled(
        Array.from({ length: 10 }, (_, idx) =>
          sendBoundHttpRequest({
            port: hub.port,
            localAddress: `127.0.85.${idx + 1}`,
            path: idx % 3 === 0 ? '/openapi.json' : '/v1/capabilities',
            headers: idx % 3 === 0 ? {} : { Authorization: `Bearer ${CALLER_TOKEN}` },
          }),
        ),
      );
      for (const r of waveOut) {
        if (r.status === 'fulfilled' && r.value.status === 200) {
          newAuthOk++;
        }
      }

      if (wave % 3 === 2) {
        const vetResponses = await Promise.all(veterans.map((v) => v.sendRequest('/v1/capabilities', CALLER_TOKEN)));
        for (const vr of vetResponses) {
          assert.equal(vr.status, 200);
        }
      }
    }

    assert.equal(
      newAuthOk,
      120,
      `Expected 120/120 (100%) new client requests to succeed under 400-socket mixed keep-alive + partial-header hold, got ${newAuthOk}/120`,
    );

    for (const v of veterans) {
      assert.equal(v.closed, false, `Veteran persistent socket ${v.ip} must remain open with zero disconnects`);
    }
  } finally {
    for (const p of attackerPools) p.stop();
    for (const v of veterans) v.destroy();
    await hub.close();
    rmSync(dataDir, { recursive: true, force: true });
  }
});

test('Round 11 [S5-4 — Loopback / Reverse-Proxy Partial-Header Resilience]: 120 partial-header sockets on 127.0.0.1 never block /health or authenticated loopback requests', async () => {
  const dataDir = mkdtempSync(join(tmpdir(), 'ef-r11-s5-lb-'));
  const hub = await startPortableHub({
    port: 0,
    host: '127.0.0.1',
    dataDir,
    envOverrides: {
      CALLER_TOKEN,
      EDGEFETCH_DISABLE_UPDATE_CHECK: '1',
    },
  });

  const lbPool = startPartialHeaderSlowlorisPool({
    port: hub.port,
    localAddress: '127.0.0.1',
    socketCount: 120,
    reconnectDelayMs: 10,
  });

  try {
    await sleep(80);
    let okCount = 0;
    for (let i = 0; i < 40; i++) {
      const r = await sendBoundHttpRequest({
        port: hub.port,
        localAddress: '127.0.0.1',
        path: i % 2 === 0 ? '/health' : '/v1/capabilities',
        headers: i % 2 === 0 ? {} : { Authorization: `Bearer ${CALLER_TOKEN}` },
      });
      if (r.status === 200) okCount++;
    }
    assert.equal(okCount, 40, `Expected 40/40 loopback requests to survive 120-socket loopback partial-header hold, got ${okCount}/40`);
  } finally {
    lbPool.stop();
    await hub.close();
    rmSync(dataDir, { recursive: true, force: true });
  }
});
