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
    for (let i = 1; i <= 30; i++) {
      const r = await collectorWorker.fetch(
        new Request('https://telemetry.edgefetch.dev/v1/dev-errors', {
          method: 'POST',
          headers: {
            'content-type': 'application/json',
            'cf-connecting-ip': `2001:db8:abcd:1::${i.toString(16)}`,
          },
          body: JSON.stringify(sampleValidEvent({ adapterId: `adapter-${(i % 6) + 1}` })),
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
        body: JSON.stringify(sampleValidEvent({ adapterId: 'adapter-fresh' })),
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
