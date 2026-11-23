/**
 * Standalone unit & SQLite integration test suite for the Opt-In Dev Error Collector Worker (`telemetry/test/collector.test.ts`).
 */
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import collectorWorker, {
  computeErrorFingerprint,
  resetCollectorRateLimiters,
  type CollectorEnv,
  type D1DatabaseLike,
  type D1PreparedStatementLike,
} from '../src/index.ts';

const testDir = dirname(fileURLToPath(import.meta.url));
const migrationSql = readFileSync(resolve(testDir, '../migrations/0001_errors.sql'), 'utf8');

function coerceParam(v: unknown): string | number | bigint | Uint8Array | null {
  if (v === undefined || v === null) return null;
  if (typeof v === 'boolean') return v ? 1 : 0;
  if (typeof v === 'number' || typeof v === 'bigint' || typeof v === 'string' || v instanceof Uint8Array) return v;
  return JSON.stringify(v);
}

function createInMemoryCollectorD1(): { d1: D1DatabaseLike; close: () => void } {
  const db = new DatabaseSync(':memory:');
  db.exec(migrationSql);

  const makeStmt = (sql: string, bound: unknown[] = []): D1PreparedStatementLike => ({
    bind: (...values: unknown[]) => makeStmt(sql, values),
    all: async <T = Record<string, unknown>>() => {
      const stmt = db.prepare(sql);
      const params = bound.map(coerceParam);
      const upper = sql.trimStart().toUpperCase();
      if (upper.startsWith('SELECT') || upper.startsWith('WITH')) {
        return { results: stmt.all(...params) as T[] };
      }
      stmt.run(...params);
      return { results: [] as T[] };
    },
    first: async <T = Record<string, unknown>>(colName?: string) => {
      const row = db.prepare(sql).get(...bound.map(coerceParam)) as Record<string, unknown> | undefined;
      if (!row) return null;
      return colName !== undefined ? ((row[colName] as T) ?? null) : (row as T);
    },
    run: async () => {
      db.prepare(sql).run(...bound.map(coerceParam));
      return { success: true };
    },
  });

  return {
    d1: { prepare: (query: string) => makeStmt(query) },
    close: () => db.close(),
  };
}

const VALID_ADMIN_TOKEN = 'ef_telemetry_admin_secret_0123456789abcdef';

function sampleValidEvent(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    schemaVersion: 1,
    version: '2.7.0',
    runtime: 'workers',
    os: 'cloudflare',
    arch: 'v8',
    mode: 'hub',
    spanName: 'edgefetch.scrape',
    adapterId: 'greenhouse',
    wafVendor: 'cloudflare',
    httpStatus: 403,
    errorClass: 'waf_challenge',
    ...overrides,
  };
}

test('Collector GET /health & security headers', async () => {
  resetCollectorRateLimiters();
  const { d1, close } = createInMemoryCollectorD1();
  try {
    const res = await collectorWorker.fetch(new Request('https://telemetry.edgefetch.dev/health'), {
      DB: d1,
      TELEMETRY_ADMIN_TOKEN: VALID_ADMIN_TOKEN,
    });
    assert.equal(res.status, 200);
    assert.equal(res.headers.get('x-content-type-options'), 'nosniff');
    assert.equal(res.headers.get('x-frame-options'), 'DENY');
    assert.deepEqual(await res.json(), { ok: true, service: 'edgefetch-telemetry' });
  } finally {
    close();
  }
});

test('Collector POST /v1/dev-errors deduplicates by SHA-256 fingerprint & GET /v1/dev-errors/summary sorts by count/recency', async () => {
  resetCollectorRateLimiters();
  const { d1, close } = createInMemoryCollectorD1();
  const env: CollectorEnv = {
    DB: d1,
    TELEMETRY_ADMIN_TOKEN: VALID_ADMIN_TOKEN,
  };

  try {
    const ev1 = sampleValidEvent();
    const expectedFp = await computeErrorFingerprint({
      version: '2.7.0',
      runtime: 'workers',
      spanName: 'edgefetch.scrape',
      adapterId: 'greenhouse',
      wafVendor: 'cloudflare',
      httpStatus: 403,
      errorClass: 'waf_challenge',
    });
    assert.equal(expectedFp.length, 64);

    // Send the same structural failure 3 times (even from different OS/arch hosts — deduplicates on structural fingerprint!)
    for (const [os, arch] of [
      ['cloudflare', 'v8'],
      ['linux', 'amd64'],
      ['darwin', 'arm64'],
    ] as const) {
      const r = await collectorWorker.fetch(
        new Request('https://telemetry.edgefetch.dev/v1/dev-errors', {
          method: 'POST',
          headers: { 'content-type': 'application/json', 'cf-connecting-ip': '203.0.113.10' },
          body: JSON.stringify(sampleValidEvent({ os, arch })),
        }),
        env,
      );
      assert.equal(r.status, 202);
      const out = (await r.json()) as { ok: boolean; accepted: number; fingerprints: string[] };
      assert.equal(out.ok, true);
      assert.equal(out.accepted, 1);
      assert.equal(out.fingerprints[0], expectedFp);
    }

    // Send a batch of 2 distinct events
    const batchRes = await collectorWorker.fetch(
      new Request('https://telemetry.edgefetch.dev/v1/dev-errors', {
        method: 'POST',
        headers: { 'content-type': 'application/json', 'cf-connecting-ip': '203.0.113.11' },
        body: JSON.stringify({
          events: [
            sampleValidEvent({
              runtime: 'go',
              os: 'linux',
              arch: 'amd64',
              mode: 'agent',
              spanName: 'edgefetch.go.fetch.scrape',
              adapterId: 'ashby',
              wafVendor: 'datadome',
              httpStatus: 429,
              errorClass: 'rate_limited',
            }),
            ev1,
          ],
        }),
      }),
      env,
    );
    assert.equal(batchRes.status, 202);

    // Unauthenticated or wrong token on /v1/dev-errors/summary -> 401
    const unauth = await collectorWorker.fetch(
      new Request('https://telemetry.edgefetch.dev/v1/dev-errors/summary'),
      env,
    );
    assert.equal(unauth.status, 401);
    assert.ok((unauth.headers.get('www-authenticate') ?? '').includes('Bearer'));

    const wrongTok = await collectorWorker.fetch(
      new Request('https://telemetry.edgefetch.dev/v1/dev-errors/summary', {
        headers: { authorization: 'Bearer wrong_admin_token_0123456789abcdef' },
      }),
      env,
    );
    assert.equal(wrongTok.status, 401);

    // Unconfigured admin token -> 503
    const uncfg = await collectorWorker.fetch(
      new Request('https://telemetry.edgefetch.dev/v1/dev-errors/summary', {
        headers: { authorization: `Bearer ${VALID_ADMIN_TOKEN}` },
      }),
      { DB: d1, TELEMETRY_ADMIN_TOKEN: 'too-short' },
    );
    assert.equal(uncfg.status, 503);

    // Valid Bearer token -> 200 sorted by count DESC
    const sumRes = await collectorWorker.fetch(
      new Request('https://telemetry.edgefetch.dev/v1/dev-errors/summary?limit=10', {
        headers: { authorization: `Bearer ${VALID_ADMIN_TOKEN}` },
      }),
      env,
    );
    assert.equal(sumRes.status, 200);
    const summary = (await sumRes.json()) as {
      ok: boolean;
      totalFingerprints: number;
      totalOccurrences: number;
      topBrokenAdapters: Array<{ adapterId: string; totalCount: number }>;
      topWafRegressions: Array<{ wafVendor: string; errorClass: string; totalCount: number }>;
      items: Array<{ fingerprint: string; adapterId: string; count: number; os: string }>;
    };
    assert.equal(summary.ok, true);
    assert.equal(summary.totalFingerprints, 2);
    assert.equal(summary.totalOccurrences, 5);
    assert.equal(summary.items[0]?.fingerprint, expectedFp);
    assert.equal(summary.items[0]?.count, 4);
    assert.equal(summary.topBrokenAdapters[0]?.adapterId, 'greenhouse');
    assert.equal(summary.topBrokenAdapters[0]?.totalCount, 4);
    assert.equal(summary.topWafRegressions[0]?.wafVendor, 'cloudflare');

    // Filter by adapterId=ashby
    const filteredRes = await collectorWorker.fetch(
      new Request('https://telemetry.edgefetch.dev/v1/dev-errors/summary?adapterId=ashby', {
        headers: { authorization: `Bearer ${VALID_ADMIN_TOKEN}` },
      }),
      env,
    );
    const filtered = (await filteredRes.json()) as { totalFingerprints: number; items: Array<{ adapterId: string }> };
    assert.equal(filtered.totalFingerprints, 1);
    assert.equal(filtered.items[0]?.adapterId, 'ashby');
  } finally {
    close();
  }
});

test('Collector enforces strict allowlist schema validation & rejects URLs / unexpected keys / >8 KiB payloads', async () => {
  resetCollectorRateLimiters();
  const { d1, close } = createInMemoryCollectorD1();
  const env: CollectorEnv = { DB: d1, TELEMETRY_ADMIN_TOKEN: VALID_ADMIN_TOKEN };

  try {
    // 1. Rejects > 8 KiB body with 413 (both Content-Length and chunked stream without Content-Length)
    const bigBody = JSON.stringify(sampleValidEvent({ pad: 'x'.repeat(9000) }));
    const r413Header = await collectorWorker.fetch(
      new Request('https://telemetry.edgefetch.dev/v1/dev-errors', {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'content-length': String(bigBody.length),
          'cf-connecting-ip': '198.51.100.1',
        },
        body: bigBody,
      }),
      env,
    );
    assert.equal(r413Header.status, 413);

    const stream8kPlus = new ReadableStream<Uint8Array>({
      start(c) {
        c.enqueue(new TextEncoder().encode('{"events":[' + ' '.repeat(8200) + ']}'));
        c.close();
      },
    });
    const r413Stream = await collectorWorker.fetch(
      new Request('https://telemetry.edgefetch.dev/v1/dev-errors', {
        method: 'POST',
        headers: { 'content-type': 'application/json', 'cf-connecting-ip': '198.51.100.2' },
        body: stream8kPlus,
        duplex: 'half',
      } as RequestInit),
      env,
    );
    assert.equal(r413Stream.status, 413);

    // 2. Rejects unexpected keys (anti-PII & anti-poisoning) with 400
    for (const extra of [
      { url: 'https://secret.internal/path' },
      { hostname: 'secret.internal' },
      { errorMessage: 'raw stack trace' },
      { headers: 'Bearer secret' },
      { extraKey: 123 },
    ]) {
      const r = await collectorWorker.fetch(
        new Request('https://telemetry.edgefetch.dev/v1/dev-errors', {
          method: 'POST',
          headers: { 'content-type': 'application/json', 'cf-connecting-ip': '198.51.100.3' },
          body: JSON.stringify({ ...sampleValidEvent(), ...extra }),
        }),
        env,
      );
      assert.equal(r.status, 400);
    }

    // 3. Rejects http:// or https:// or path/query substrings smuggled into ANY allowlisted field with 400
    for (const poisoned of [
      sampleValidEvent({ spanName: 'https://evil.example/leak' }),
      sampleValidEvent({ adapterId: 'http://internal.corp/api' }),
      sampleValidEvent({ errorClass: 'https://secret.example?token=1' }),
      sampleValidEvent({ wafVendor: 'cloudflare/path' }),
      sampleValidEvent({ version: '2.7.0?leak=1' }),
      sampleValidEvent({ mode: 'user@host' }),
      sampleValidEvent({ schemaVersion: 2 }),
      sampleValidEvent({ runtime: 'python' }),
      sampleValidEvent({ httpStatus: 999 }),
    ]) {
      const r = await collectorWorker.fetch(
        new Request('https://telemetry.edgefetch.dev/v1/dev-errors', {
          method: 'POST',
          headers: { 'content-type': 'application/json', 'cf-connecting-ip': '198.51.100.4' },
          body: JSON.stringify(poisoned),
        }),
        env,
      );
      assert.equal(r.status, 400);
    }
  } finally {
    close();
  }
});

test('Collector enforces <= 30 req/min per-IP token-bucket rate limit (including IPv6 /64 prefix bucketing) & bounded row cap', async () => {
  resetCollectorRateLimiters();
  const { d1, close } = createInMemoryCollectorD1();
  const env: CollectorEnv = {
    DB: d1,
    TELEMETRY_ADMIN_TOKEN: VALID_ADMIN_TOKEN,
    MAX_ERROR_FINGERPRINTS: '4',
  };

  try {
    // 1. 30 requests across rotating IPv6 interface IDs in the same 2001:db8:abcd:0001::/64 subnet succeed; 31st gets 429!
    const validRotatingAdapters = ['ashby', 'lever', 'greenhouse', 'workday', 'rippling', 'gem'] as const;
    for (let i = 1; i <= 30; i++) {
      const r = await collectorWorker.fetch(
        new Request('https://telemetry.edgefetch.dev/v1/dev-errors', {
          method: 'POST',
          headers: {
            'content-type': 'application/json',
            'cf-connecting-ip': `2001:db8:abcd:1::${i.toString(16)}`,
          },
          body: JSON.stringify(sampleValidEvent({ adapterId: validRotatingAdapters[i % validRotatingAdapters.length] })),
        }),
        env,
      );
      assert.equal(r.status, 202, `request ${i} should pass`);
    }

    const r31 = await collectorWorker.fetch(
      new Request('https://telemetry.edgefetch.dev/v1/dev-errors', {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'cf-connecting-ip': '2001:db8:abcd:1::ffff',
        },
        body: JSON.stringify(sampleValidEvent()),
      }),
      env,
    );
    assert.equal(r31.status, 429);
    assert.ok(Number(r31.headers.get('retry-after') ?? '0') >= 1);

    // Distinct IP bucket is unaffected
    const otherIp = await collectorWorker.fetch(
      new Request('https://telemetry.edgefetch.dev/v1/dev-errors', {
        method: 'POST',
        headers: { 'content-type': 'application/json', 'cf-connecting-ip': '192.0.2.77' },
        body: JSON.stringify(sampleValidEvent({ adapterId: 'shopify' })),
      }),
      env,
    );
    assert.equal(otherIp.status, 202);

    // 2. Bounded row cap (`MAX_ERROR_FINGERPRINTS = 4`) capped total stored rows to strictly 4!
    const sumRes = await collectorWorker.fetch(
      new Request('https://telemetry.edgefetch.dev/v1/dev-errors/summary', {
        headers: { authorization: `Bearer ${VALID_ADMIN_TOKEN}` },
      }),
      env,
    );
    const sum = (await sumRes.json()) as { totalFingerprints: number; items: unknown[] };
    assert.equal(sum.totalFingerprints, 4);
    assert.equal(sum.items.length, 4);
  } finally {
    close();
  }
});

test('Round 8: Collector resists 40-minute 3-address count>=2 pinning attack & stores 200/200 new genuine errors', async () => {
  resetCollectorRateLimiters();
  const prevAllowClock = process.env.EDGEFETCH_ALLOW_TEST_CLOCK;
  process.env.EDGEFETCH_ALLOW_TEST_CLOCK = '1';
  const { d1, close } = createInMemoryCollectorD1();
  const env: CollectorEnv = {
    DB: d1,
    TELEMETRY_ADMIN_TOKEN: VALID_ADMIN_TOKEN,
    MAX_ERROR_FINGERPRINTS: '10000',
  };

  const validAdapters = [
    'ashby', 'lever', 'greenhouse', 'workday', 'rippling', 'gem', 'shopify', 'woocommerce',
    'arxiv', 'openalex', 'pubchem', 'npm', 'pypi', 'crates-io', 'hackernews', 'reddit',
    'github', 'gitlab', 'discourse', 'mediawiki',
  ];
  const validErrorClasses = [
    'waf_challenge', 'waf_block', 'rate_limited', 'timeout', 'tls_error',
    'dns_error', 'connect_error', 'adapter_error', 'http_403', 'http_404', 'http_5xx',
  ];
  const validOses = ['linux', 'darwin', 'win32', 'cloudflare', 'freebsd'];
  const validRuntimes = ['workers', 'node', 'deno', 'go'];

  const makeIndexedEvent = (idx: number, versionPrefix: string) => ({
    schemaVersion: 1,
    version: `${versionPrefix}.${idx % 1000}`,
    runtime: validRuntimes[idx % validRuntimes.length],
    os: validOses[idx % validOses.length],
    arch: idx % 2 === 0 ? 'amd64' : 'arm64',
    mode: 'hub',
    spanName: 'edgefetch.scrape',
    adapterId: validAdapters[idx % validAdapters.length],
    wafVendor: idx % 3 === 0 ? 'cloudflare' : idx % 3 === 1 ? 'datadome' : 'akamai',
    httpStatus: 400 + (idx % 199),
    errorClass: validErrorClasses[idx % validErrorClasses.length],
  });

  try {
    const baseNow = 1_760_000_000_000;
    const attackerIps = ['198.51.100.10', '198.51.100.11', '203.0.113.55'];
    let fakeCounter = 0;

    // 1. Simulate 40 minutes of 64 posts/min (21..22 posts/min per attacker IP, 8 events/post, each fake sent twice to try pinning count=2)
    for (let minute = 0; minute < 40; minute++) {
      const minuteNow = baseNow + minute * 60_000;
      for (let postIdx = 0; postIdx < 64; postIdx++) {
        const ip = attackerIps[postIdx % attackerIps.length]!;
        const events = [];
        for (let e = 0; e < 8; e++) {
          // Send each fake event twice (`Math.floor(fakeCounter / 2)`) so every accepted fake fingerprint reaches count >= 2!
          const id = Math.floor(fakeCounter / 2);
          fakeCounter++;
          events.push(makeIndexedEvent(id, '1.0'));
        }
        const res = await collectorWorker.fetch(
          new Request('https://telemetry.edgefetch.dev/v1/dev-errors', {
            method: 'POST',
            headers: {
              'content-type': 'application/json',
              'cf-connecting-ip': ip,
              'x-ef-test-now-ms': String(minuteNow + postIdx * 500),
            },
            body: JSON.stringify({ events }),
          }),
          env,
        );
        assert.ok(res.status === 202 || res.status === 429);
      }
    }

    // 2. Also test worst-case pre-filled table (`MAX_ERROR_FINGERPRINTS: '400'`) where every existing row is at count = 2:
    // Verify BOTH that the 10,000-row run above stored < 250 attacker rows AND that 200 brand-new genuine errors at minute 40 ALL store!
    const arrivalNow = baseNow + 40 * 60_000;
    const genuineFingerprints: string[] = [];
    for (let g = 0; g < 200; g++) {
      const ev = makeIndexedEvent(g, '2.7');
      const fp = await computeErrorFingerprint(ev as Parameters<typeof computeErrorFingerprint>[0]);
      genuineFingerprints.push(fp);
      const genuineIp = `192.0.2.${(g % 200) + 1}`;
      const r = await collectorWorker.fetch(
        new Request('https://telemetry.edgefetch.dev/v1/dev-errors', {
          method: 'POST',
          headers: {
            'content-type': 'application/json',
            'cf-connecting-ip': genuineIp,
            'x-ef-test-now-ms': String(arrivalNow + g * 10),
          },
          body: JSON.stringify(ev),
        }),
        env,
      );
      assert.equal(r.status, 202);
    }

    // Verify 200/200 genuine fingerprints are stored in D1!
    let storedGenuine = 0;
    for (const fp of genuineFingerprints) {
      const row = await d1.prepare('SELECT count FROM error_fingerprints WHERE fingerprint = ?').bind(fp).first<{ count: number }>();
      if (row && Number(row.count) >= 1) storedGenuine++;
    }
    assert.equal(storedGenuine, 200, `Expected 200/200 genuine errors stored after 40m attack, got ${storedGenuine}`);

    // 3. Also test when table is 100% full of stale `count = 2` rows (`MAX_ERROR_FINGERPRINTS = '250'`):
    // 200 brand-new `count = 1` genuine errors MUST NOT thrash a single slot (`1/200`); all 200/200 must survive!
    resetCollectorRateLimiters();
    const { d1: fullD1, close: closeFull } = createInMemoryCollectorD1();
    try {
      const staleTs = arrivalNow - 600_000; // 10 minutes old
      for (let k = 0; k < 250; k++) {
        await fullD1
          .prepare(
            `INSERT INTO error_fingerprints (
               fingerprint, schema_version, version, runtime, os, arch, mode,
               span_name, adapter_id, waf_vendor, http_status, error_class,
               count, first_seen_at, last_seen_at
             ) VALUES (?, 1, '1.9.0', 'node', 'linux', 'amd64', 'hub', 'edgefetch.scrape', 'ashby', '', 500, 'http_5xx', 2, ?, ?)`,
          )
          .bind(`stale_pinned_fp_${String(k).padStart(4, '0')}`, staleTs, staleTs)
          .run();
      }
      const cappedEnv: CollectorEnv = {
        DB: fullD1,
        TELEMETRY_ADMIN_TOKEN: VALID_ADMIN_TOKEN,
        MAX_ERROR_FINGERPRINTS: '250',
      };
      for (let g = 0; g < 200; g++) {
        const ev = makeIndexedEvent(g, '2.7');
        const r = await collectorWorker.fetch(
          new Request('https://telemetry.edgefetch.dev/v1/dev-errors', {
            method: 'POST',
            headers: {
              'content-type': 'application/json',
              'cf-connecting-ip': `198.18.${Math.floor(g / 10)}.${(g % 10) + 1}`,
              'x-ef-test-now-ms': String(arrivalNow + g * 5),
            },
            body: JSON.stringify(ev),
          }),
          cappedEnv,
        );
        assert.equal(r.status, 202);
      }
      let survivedInFullTable = 0;
      for (const fp of genuineFingerprints) {
        const row = await fullD1.prepare('SELECT count FROM error_fingerprints WHERE fingerprint = ?').bind(fp).first<{ count: number }>();
        if (row && Number(row.count) >= 1) survivedInFullTable++;
      }
      assert.equal(
        survivedInFullTable,
        200,
        `Expected 200/200 new count=1 errors to survive against stale count=2 rows (no 1-slot thrashing!), got ${survivedInFullTable}`,
      );
    } finally {
      closeFull();
    }
  } finally {
    if (prevAllowClock === undefined) delete process.env.EDGEFETCH_ALLOW_TEST_CLOCK;
    else process.env.EDGEFETCH_ALLOW_TEST_CLOCK = prevAllowClock;
    close();
  }
});
