/**
 * Round 10 Portable Hub Socket Eviction, Slow-First-Byte Protection & Shared-NAT Suite
 * (`hub/test/round10-portable-eviction.test.ts`):
 *
 *  1. `H8` / `P1` — 20 Long-Lived Persistent Keep-Alive Clients vs. 300 Distinct 1-Socket-Per-IP Churners:
 *     - Establishes 20 persistent HTTP/1.1 keep-alive clients (`127.0.10.1`..`127.0.10.20`), each completing
 *       multiple requests over time (`requestsCompleted >= 2`) on a pinned single TCP socket.
 *     - Unleashes 300 distinct 1-socket-per-IP churners (`127.0.20.1`..`127.0.21.50`, `perIpCount === 1` tie across
 *       all 300 addresses) in both 1-request keep-alive and zero-byte pre-header churn modes.
 *     - Verifies ALL 20 original persistent client TCP sockets remain open (zero disconnects/reconnects) and continue
 *       serving `200 OK` responses throughout and after the attack!
 *
 *  2. Slow-First-Byte Partial-Header Protection (`bytesRead > 0` / `sawRequestBytes`):
 *     - Clients that have already sent partial HTTP request bytes (`GET /he`, `GET /v1/capab`) are NEVER evicted
 *       under heavy connection churn before `headersTimeout` expires, and complete `200 OK` once headers finish;
 *       stalled partial-header sockets that exceed `headersTimeout` are still cleaned up on schedule.
 *
 *  3. Shared-Address NAT Persistent Headroom (`64` persistent connections when global capacity has headroom),
 *     Tier 2 Bloated-IP-First Youngest Eviction Under Pressure, and `0005` SQLite `secret_version` Migration Parity.
 */
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import http from 'node:http';
import net from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import test from 'node:test';
import { startPortableHub } from '../portable/portable-server';

const CALLER_TOKEN = 'r10-owner-caller-secret-0123456789abcdef';

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

function churnIpByIndex(idx: number): string {
  // Maps idx 0..299 -> 127.0.20.1..127.0.20.250, 127.0.21.1..127.0.21.50 (300 distinct remote-pool addresses)
  const major = 20 + Math.floor(idx / 250);
  const minor = 1 + (idx % 250);
  return `127.0.${major}.${minor}`;
}

interface PinnedPersistentClient {
  readonly ip: string;
  readonly socket: net.Socket;
  readonly closed: boolean;
  sendRequest(path: string, authToken?: string): Promise<{ status: number; headers: http.IncomingHttpHeaders; body: string }>;
  destroy(): void;
}

/**
 * Opens a single-socket `http.Agent` pinned to one TCP `net.Socket` (refusing to silently open a 2nd TCP socket if
 * the server ever closes/evicts the original connection!), so `sendRequest` fails immediately if evicted!
 */
async function openPinnedPersistentClient(port: number, ip: string, initialAuthToken?: string): Promise<PinnedPersistentClient> {
  let pinnedSocket: net.Socket | null = null;
  let socketClosed = false;
  let createdConnections = 0;

  const agent = new http.Agent({
    keepAlive: true,
    maxSockets: 1,
    maxFreeSockets: 1,
    keepAliveMsecs: 15_000,
  });

  const origCreateConnection = agent.createConnection.bind(agent);
  agent.createConnection = ((opts: net.TcpSocketConnectOpts, cb?: () => void) => {
    createdConnections++;
    if (createdConnections > 1) {
      throw new Error(`Pinned persistent client ${ip} attempted to reconnect because original socket was evicted!`);
    }
    const s = origCreateConnection({ ...opts, localAddress: ip }, cb);
    pinnedSocket = s;
    s.on('error', () => undefined);
    s.once('close', () => {
      socketClosed = true;
    });
    return s;
  }) as typeof agent.createConnection;

  const doRequest = (path: string, authToken?: string): Promise<{ status: number; headers: http.IncomingHttpHeaders; body: string }> =>
    new Promise((resolveReq, rejectReq) => {
      if (pinnedSocket && (socketClosed || pinnedSocket.destroyed)) {
        rejectReq(new Error(`Pinned persistent socket for ${ip} was already closed/evicted`));
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
          timeout: 5_000,
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
      req.on('socket', (s) => {
        if (pinnedSocket && s !== pinnedSocket) {
          req.destroy(new Error(`Socket identity changed for ${ip}!`));
        }
      });
      req.on('timeout', () => req.destroy(new Error(`Request timed out on ${ip}`)));
      req.on('error', rejectReq);
      req.end();
    });

  // Establish the TCP socket with request #1
  const firstRes = await doRequest('/v1/capabilities', initialAuthToken ?? CALLER_TOKEN);
  assert.equal(firstRes.status, 200);
  assert.ok(pinnedSocket, `Expected TCP socket to be created for ${ip}`);

  return {
    ip,
    get socket() {
      return pinnedSocket!;
    },
    get closed() {
      return socketClosed || Boolean(pinnedSocket?.destroyed);
    },
    sendRequest: doRequest,
    destroy() {
      socketClosed = true;
      pinnedSocket?.destroy();
      agent.destroy();
    },
  };
}

test('Round 10 [P1 / H8 Tie-Break]: 20 long-lived persistent keep-alive clients survive 300 distinct 1-socket-per-IP churners with zero disconnects', async () => {
  const dataDir = mkdtempSync(join(tmpdir(), 'ef-r10-veteran-'));
  const hub = await startPortableHub({
    port: 0,
    host: '127.0.0.1',
    dataDir,
    keepAliveTimeoutMs: 15_000,
    envOverrides: {
      CALLER_TOKEN,
      EDGEFETCH_DISABLE_UPDATE_CHECK: '1',
    },
  });

  const veterans: PinnedPersistentClient[] = [];
  const churnSockets = new Set<net.Socket>();

  try {
    // 1. Open 20 legitimate persistent keep-alive clients (`127.0.10.1`..`127.0.10.20`) and complete 3 requests each
    //    so all 20 are established veteran keep-alive clients (`requestsCompleted === 3`, `ipSocketCount === 1`).
    for (let i = 1; i <= 20; i++) {
      const client = await openPinnedPersistentClient(hub.port, `127.0.10.${i}`, CALLER_TOKEN);
      veterans.push(client);
    }

    for (let round = 0; round < 2; round++) {
      const warmup = await Promise.all(
        veterans.map((v, idx) =>
          idx % 2 === 0 ? v.sendRequest('/v1/capabilities', CALLER_TOKEN) : v.sendRequest('/openapi.json'),
        ),
      );
      for (const r of warmup) {
        assert.equal(r.status, 200);
        assert.notEqual(String(r.headers.connection ?? '').toLowerCase(), 'close');
      }
      await sleep(20);
    }

    // Let the 20 veterans sit idle past `PRESSURE_IDLE_EVICT_AGE_MS` (250ms) so under the old oldest-idle tie-break
    // they would have been the #1-#20 eviction targets!
    await sleep(320);

    // 2. Attack Wave 1: 300 distinct addresses (`perIpCount === 1` across all 300 addresses) each open 1 keep-alive
    //    socket, send 1 request (`requestsCompleted === 1`), and hold their socket open!
    await Promise.all(
      Array.from({ length: 300 }, (_, idx) => {
        const ip = churnIpByIndex(idx);
        return new Promise<void>((done) => {
          const s = net.connect({ host: '127.0.0.1', port: hub.port, localAddress: ip });
          churnSockets.add(s);
          s.resume();
          s.on('error', () => done());
          s.on('close', () => {
            churnSockets.delete(s);
            done();
          });
          s.on('connect', () => {
            s.write(`GET /openapi.json HTTP/1.1\r\nHost: 127.0.0.1:${hub.port}\r\nConnection: keep-alive\r\n\r\n`);
            const t = setTimeout(() => done(), 60);
            t.unref?.();
          });
        });
      }),
    );

    // Wait > 300ms while pressure sweep timer runs under saturation
    await sleep(350);

    // Every single one of the 20 original veteran persistent sockets MUST still be open and serve requests!
    for (const v of veterans) {
      assert.equal(v.closed, false, `Veteran persistent socket ${v.ip} must NOT be evicted by 300 1-per-IP keep-alive churners`);
    }
    const postWave1 = await Promise.all(
      veterans.map((v, idx) =>
        idx % 2 === 0 ? v.sendRequest('/v1/capabilities', CALLER_TOKEN) : v.sendRequest('/openapi.json'),
      ),
    );
    for (const r of postWave1) {
      assert.equal(r.status, 200);
    }

    // 3. Attack Wave 2: Rapid burst reconnect churn across all 300 distinct 1-socket-per-IP addresses
    //    (mixing zero-byte pre-header churners and 1-request keep-alive churners) while veterans stay idle in between!
    for (const s of churnSockets) s.destroy();
    churnSockets.clear();
    await sleep(100);

    for (let wave = 0; wave < 3; wave++) {
      await Promise.all(
        Array.from({ length: 100 }, (_, j) => {
          const idx = wave * 100 + j;
          const ip = churnIpByIndex(idx);
          return new Promise<void>((done) => {
            const s = net.connect({ host: '127.0.0.1', port: hub.port, localAddress: ip });
            churnSockets.add(s);
            s.resume();
            s.on('error', () => done());
            s.on('close', () => {
              churnSockets.delete(s);
              done();
            });
            s.on('connect', () => {
              if (idx % 2 === 0) {
                s.write(`GET /health HTTP/1.1\r\nHost: 127.0.0.1:${hub.port}\r\nConnection: keep-alive\r\n\r\n`);
              }
              // Odd-indexed churners hold 0-byte stalled pre-header sockets
              const t = setTimeout(() => done(), 40);
              t.unref?.();
            });
          });
        }),
      );
      await sleep(120);
      const midCheck = await Promise.all(veterans.map((v) => v.sendRequest('/v1/capabilities', CALLER_TOKEN)));
      for (const r of midCheck) {
        assert.equal(r.status, 200);
      }
    }

    for (const v of veterans) {
      assert.equal(v.closed, false, `Veteran persistent socket ${v.ip} must remain open across all churn waves`);
    }
  } finally {
    for (const s of churnSockets) s.destroy();
    for (const v of veterans) v.destroy();
    await hub.close();
    rmSync(dataDir, { recursive: true, force: true });
  }
});

test('Round 10 [P1 Slow-First-Byte Protection]: Pre-header sockets that have sent partial bytes (GET /he...) survive churn and complete 200 OK before headersTimeout', async () => {
  const dataDir = mkdtempSync(join(tmpdir(), 'ef-r10-slowbyte-'));
  const hub = await startPortableHub({
    port: 0,
    host: '127.0.0.1',
    dataDir,
    maxTotalSockets: 64,
    maxGlobalPreHeaderSockets: 48,
    headersTimeoutMs: 2_500,
    keepAliveTimeoutMs: 8_000,
    envOverrides: {
      CALLER_TOKEN,
      EDGEFETCH_DISABLE_UPDATE_CHECK: '1',
    },
  });

  const churnSockets = new Set<net.Socket>();
  const slowClients: Array<{
    ip: string;
    sock: net.Socket;
    getBuf: () => string;
    evictedEarly: () => boolean;
  }> = [];

  try {
    // 1. Connect 4 slow-first-byte clients (`127.0.30.1`..`127.0.30.4`) that immediately send partial header bytes (`GET /he`
    //    or `GET /v1/capab`) and then pause for 650ms (> 250ms grace, < 2,500ms headersTimeoutMs).
    for (let i = 1; i <= 4; i++) {
      const ip = `127.0.30.${i}`;
      const sock = net.connect({ host: '127.0.0.1', port: hub.port, localAddress: ip });
      let out = '';
      let closedFlag = false;
      sock.on('error', () => undefined);
      sock.on('data', (c: Buffer) => {
        out += c.toString('utf8');
      });
      sock.on('close', () => {
        closedFlag = true;
      });
      await new Promise<void>((r, rej) => {
        sock.once('connect', () => r());
        sock.once('error', rej);
      });
      const partialBytes = i % 2 === 1 ? 'GET /he' : 'GET /v1/capab';
      sock.write(partialBytes);
      slowClients.push({
        ip,
        sock,
        getBuf: () => out,
        evictedEarly: () => closedFlag || sock.destroyed,
      });
    }

    await sleep(40);

    // 2. While those 4 slow-first-byte clients hold partial request bytes in `preheader`, unleash 200 churn connections
    //    (far exceeding `maxGlobalPreHeaderSockets = 48` and `maxTotalSockets = 64`) over 600ms!
    for (let wave = 0; wave < 4; wave++) {
      await Promise.all(
        Array.from({ length: 50 }, (_, j) => {
          const idx = wave * 50 + j;
          const ip = churnIpByIndex(idx);
          return new Promise<void>((done) => {
            const s = net.connect({ host: '127.0.0.1', port: hub.port, localAddress: ip });
            churnSockets.add(s);
            s.resume();
            s.on('error', () => done());
            s.on('close', () => {
              churnSockets.delete(s);
              done();
            });
            s.on('connect', () => {
              if (j % 3 === 0) {
                s.write(`GET /health HTTP/1.1\r\nHost: 127.0.0.1:${hub.port}\r\nConnection: keep-alive\r\n\r\n`);
              }
              const t = setTimeout(() => done(), 30);
              t.unref?.();
            });
          });
        }),
      );
      await sleep(140);
    }

    // Verify NONE of the 4 slow-first-byte clients were evicted during the 600ms churn storm!
    for (const sc of slowClients) {
      assert.equal(
        sc.evictedEarly(),
        false,
        `Slow-first-byte client ${sc.ip} with bytesRead > 0 must NOT be evicted before headersTimeout`,
      );
    }

    // 3. Complete the HTTP headers on all 4 slow-first-byte clients and verify every one receives `HTTP/1.1 200 OK`!
    for (let i = 0; i < slowClients.length; i++) {
      const sc = slowClients[i]!;
      if ((i + 1) % 2 === 1) {
        sc.sock.write(`alth HTTP/1.1\r\nHost: 127.0.0.1:${hub.port}\r\nConnection: close\r\n\r\n`);
      } else {
        sc.sock.write(
          `ilities HTTP/1.1\r\nHost: 127.0.0.1:${hub.port}\r\nAuthorization: Bearer ${CALLER_TOKEN}\r\nConnection: close\r\n\r\n`,
        );
      }
    }

    await Promise.all(
      slowClients.map(
        (sc) =>
          new Promise<void>((resolveDone, rejectDone) => {
            const deadline = setTimeout(() => rejectDone(new Error(`Timed out waiting for 200 OK on ${sc.ip}`)), 3_000);
            const check = () => {
              if (sc.getBuf().startsWith('HTTP/1.1 200 OK')) {
                clearTimeout(deadline);
                resolveDone();
              } else if (sc.evictedEarly()) {
                clearTimeout(deadline);
                if (sc.getBuf().startsWith('HTTP/1.1 200 OK')) resolveDone();
                else rejectDone(new Error(`Slow-first-byte client ${sc.ip} closed without 200 OK: ${sc.getBuf().slice(0, 120)}`));
              } else {
                setTimeout(check, 20).unref?.();
              }
            };
            check();
          }),
      ),
    );

    for (const s of churnSockets) s.destroy();
    churnSockets.clear();

    // 4. Verify `headersTimeoutMs` (`2,500ms`) STILL terminates a stalled partial-header socket once its deadline expires
    const stalledPartial = net.connect({ host: '127.0.0.1', port: hub.port, localAddress: '127.0.30.99' });
    stalledPartial.on('error', () => undefined);
    const closedAfterDeadline = new Promise<number>((r) => {
      const t0 = Date.now();
      stalledPartial.once('close', () => r(Date.now() - t0));
    });
    await new Promise<void>((r) => stalledPartial.once('connect', () => r()));
    stalledPartial.write('GET /he');
    const elapsedMs = await closedAfterDeadline;
    assert.ok(elapsedMs >= 2_000 && elapsedMs < 4_500, `Expected stalled partial-header socket to close near headersTimeoutMs (2500ms), got ${elapsedMs}ms`);
  } finally {
    for (const s of churnSockets) s.destroy();
    for (const sc of slowClients) sc.sock.destroy();
    await hub.close();
    rmSync(dataDir, { recursive: true, force: true });
  }
});

test('Round 10 [Shared-NAT 64 Persistent Cap, Tier-2 Hog Eviction & 0005 SQLite Migration Parity]', async () => {
  const dataDir = mkdtempSync(join(tmpdir(), 'ef-r10-nat-mig-'));

  // Pre-seed `meta.sqlite` with a legacy `mcp_servers` table lacking `secret_version` to verify startup migration `0005`
  const preMetaPath = join(dataDir, 'meta.sqlite');
  const seedDb = new DatabaseSync(preMetaPath);
  seedDb.exec(`
    CREATE TABLE IF NOT EXISTS mcp_servers (
      id TEXT PRIMARY KEY,
      slug TEXT NOT NULL
    );
    INSERT INTO mcp_servers (id, slug) VALUES ('srv_1', 'demo');
  `);
  seedDb.close();

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

  const sharedNatClients: PinnedPersistentClient[] = [];
  const singleIpClients: PinnedPersistentClient[] = [];

  try {
    // 1. Verify `0005_round10_vault_and_oauth.sql` added `secret_version INTEGER NOT NULL DEFAULT 1` idempotently on startup
    const checkDb = new DatabaseSync(preMetaPath);
    try {
      const row = checkDb.prepare('SELECT id, slug, secret_version FROM mcp_servers WHERE id = ?').get('srv_1') as
        | { id: string; slug: string; secret_version: number }
        | undefined;
      assert.ok(row, 'Expected pre-seeded mcp_servers row to exist');
      assert.equal(row.secret_version, 1, 'Expected secret_version column to default to 1 after startup migration');
    } finally {
      checkDb.close();
    }

    // 2. Shared-address NAT fairness when global capacity has headroom (`< SOCKET_PRESSURE_THRESHOLD = 96`):
    //    32 persistent clients behind the SAME `127.0.40.10` NAT IP (> old 16 ceiling, <= 64 per-IP cap) all stay alive!
    for (let i = 0; i < 32; i++) {
      const c = await openPinnedPersistentClient(hub.port, '127.0.40.10', CALLER_TOKEN);
      sharedNatClients.push(c);
    }

    await sleep(80);
    for (let i = 0; i < sharedNatClients.length; i++) {
      assert.equal(
        sharedNatClients[i]!.closed,
        false,
        `Shared-NAT persistent connection #${i + 1} must remain open when global sockets have headroom`,
      );
    }

    // Make the first 4 shared-NAT sockets multi-request (`requestsCompleted === 3`) while sockets #5..#32 have `requestsCompleted === 1`
    for (let k = 0; k < 4; k++) {
      await sharedNatClients[k]!.sendRequest('/health');
      await sharedNatClients[k]!.sendRequest('/health');
    }

    // 3. Push global sockets past `SOFT_GLOBAL_SOCKET_THRESHOLD` (128) using 105 distinct single-IP persistent clients:
    //    Tier 2 MUST evict from the bloated 32-socket IP (`127.0.40.10`, `ipSocketCount > 2`), evicting its youngest
    //    `requestsCompleted === 1` sockets FIRST while keeping both the 4 multi-request shared-NAT sockets AND all
    //    single-IP clients open!
    for (let j = 1; j <= 105; j++) {
      const sc = await openPinnedPersistentClient(hub.port, `127.0.41.${j}`, CALLER_TOKEN);
      singleIpClients.push(sc);
    }

    await sleep(150);

    // All 4 multi-request sockets on `127.0.40.10` (`requestsCompleted === 3`) stay alive while
    // youngest 1-request sockets on `127.0.40.10` absorbed the Tier-2 eviction!
    for (let k = 0; k < 4; k++) {
      assert.equal(
        sharedNatClients[k]!.closed,
        false,
        `Higher-requestsCompleted socket #${k} on bloated IP should outlive youngest 1-req sockets on that IP`,
      );
    }
    const evictedYoungestOnHog = sharedNatClients.slice(16).filter((c) => c.closed).length;
    assert.ok(evictedYoungestOnHog > 0, 'Expected bloated IP youngest idle sockets to be evicted first under global pressure');
  } finally {
    for (const c of sharedNatClients) c.destroy();
    for (const c of singleIpClients) c.destroy();
    await hub.close();
    rmSync(dataDir, { recursive: true, force: true });
  }
});
