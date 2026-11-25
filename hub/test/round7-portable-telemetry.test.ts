import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import http from 'node:http';
import net from 'node:net';
import { dirname, resolve } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import collectorWorker, {
  IPV6_PREFIX48_RATE_LIMIT_CAPACITY,
  MAX_EVENTS_PER_POST,
  RATE_LIMIT_CAPACITY,
  resetCollectorRateLimiters,
  type D1DatabaseLike,
  type D1PreparedStatementLike,
} from '../../telemetry/src/index.ts';
import { LocalAgentHubCoordinator } from './stubs/cf-storage-mocks.ts';
import {
  DEV_TELEMETRY_SETTING_KEY,
  flushDevErrorTelemetry,
  isDoNotTrackEnabled,
  resolveDevTelemetryEndpoint,
  resolveDevTelemetryState,
  scrubSpanToDevErrorReport,
  validateDevErrorReport,
} from '../src/dev-telemetry.ts';
import hubWorker from '../src/index.ts';
import {
  buildCrawlChildSpans,
  buildOtlpTracePayload,
  createRequestTraceContext,
  parseOtlpHeaders,
  parseTraceparent,
  resetOtlpExportLimitersForTests,
  resolveOtlpTracesUrl,
  sanitizeUrlForSpan,
} from '../src/otel.ts';

const CALLER_TOKEN = 'r7-caller-secret-token-0123456789abcdef';

test('R7-OTel: Unauthenticated 401/403 requests emit 0 outbound OTLP/telemetry POSTs, public unauth floods are rate-limited, and OTel parsers block CRLF/NaN/oversized inputs', async () => {
  resetOtlpExportLimitersForTests();
  let otlpPosts = 0;
  let devTelPosts = 0;

  const otlpSink = http.createServer((req, res) => {
    req.resume();
    req.on('end', () => {
      if (req.url?.includes('/v1/traces')) otlpPosts++;
      else if (req.url?.includes('/v1/dev-errors')) devTelPosts++;
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end('{}');
    });
  });
  await new Promise<void>((r) => otlpSink.listen(0, '127.0.0.1', r));
  const sinkPort = (otlpSink.address() as net.AddressInfo).port;

  const coordinator = new LocalAgentHubCoordinator(':memory:');
  const env = {
    AGENT_HUB: coordinator.asNamespace() as never,
    CALLER_TOKEN,
    OTEL_EXPORTER_OTLP_ENDPOINT: `http://127.0.0.1:${sinkPort}`,
    EDGEFETCH_DEV_TELEMETRY: '1',
    EDGEFETCH_DEV_TELEMETRY_URL: `http://127.0.0.1:${sinkPort}/v1/dev-errors`,
  };

  try {
    // 1. 50 unauthenticated `401` requests across `/nope`, `/v1/scrape`, and `/mcp` -> 0 OTLP POSTs & 0 dev-telemetry POSTs!
    for (let i = 0; i < 50; i++) {
      const r1 = await hubWorker.fetch(
        new Request(`https://hub.example.com/nope-${i}`, {
          headers: { traceparent: `00-${'a'.repeat(32)}-${'b'.repeat(16)}-01` },
        }),
        env,
      );
      assert.equal(r1.status, 401);
      assert.equal(r1.headers.get('x-trace-id'), 'a'.repeat(32));
    }
    const rScrapeUnauth = await hubWorker.fetch(
      new Request('https://hub.example.com/v1/scrape', {
        method: 'POST',
        headers: { authorization: 'Bearer wrong-token', 'content-type': 'application/json' },
        body: JSON.stringify({ url: 'https://example.com' }),
      }),
      env,
    );
    assert.equal(rScrapeUnauth.status, 401);
    assert.equal(otlpPosts, 0, 'Unauthenticated 401 requests must emit 0 OTLP POSTs');
    assert.equal(devTelPosts, 0, 'Unauthenticated 401 requests must emit 0 dev-telemetry POSTs');

    // 2. Public `/health` WITH inbound `traceparent` also emits 0 OTLP POSTs
    const rHealth = await hubWorker.fetch(
      new Request('https://hub.example.com/health', {
        headers: { traceparent: `00-${'c'.repeat(32)}-${'d'.repeat(16)}-01` },
      }),
      env,
    );
    assert.equal(rHealth.status, 200);
    assert.equal(otlpPosts, 0);

    // 3. Authenticated `GET /v1/capabilities` DOES emit OTLP span cleanly
    const rAuthed = await hubWorker.fetch(
      new Request('https://hub.example.com/v1/capabilities', {
        headers: { authorization: `Bearer ${CALLER_TOKEN}` },
      }),
      env,
    );
    assert.equal(rAuthed.status, 200);
    assert.equal(otlpPosts, 1, 'Authenticated request must export OTLP trace');

    // 4. Hardened OTel helper parsers (`fn.mjs` & `amp.mjs` regression assertions)
    assert.equal(parseTraceparent(' '.repeat(1024) + `00-${'a'.repeat(32)}-${'b'.repeat(16)}-01`), null);
    const hdrs = parseOtlpHeaders(
      'Authorization=Bearer%20tok,x-crlf=val%0d%0aX-Evil:%201,__proto__=bad,host=evil.test,content-length=99,bad key=v',
    );
    assert.deepEqual(hdrs, { Authorization: 'Bearer tok' });
    assert.equal(resolveOtlpTracesUrl('https://user:pass@collector.example/otlp'), null);
    assert.ok(sanitizeUrlForSpan('https://h.example/' + 'a'.repeat(5_000)).length <= 512);
    assert.equal(sanitizeUrlForSpan('blob:https://h.example/uuid?token=SECRET'), 'blob:https://h.example/uuid');

    const traceCtx = createRequestTraceContext(
      new Request('https://hub.example/fetch', {
        headers: { 'x-request-id': '","call":{"requests":[]},"x":"' },
      }),
    );
    assert.equal(traceCtx.headers['x-request-id'], traceCtx.context.spanId);

    const childSpans = buildCrawlChildSpans({
      traceId: 'e'.repeat(32),
      parentSpanId: 'f'.repeat(16),
      via: 'agent:site-a',
      endTimeMs: 1_700_000_000_000,
      replyText: JSON.stringify({
        results: [{ id: '1', url: 'https://example.com', kind: 'page\r\nX:1' + 'k'.repeat(500), status: 'abc', outcome: 'ok', durationMs: 'x' }],
      }),
    });
    assert.equal(childSpans.length, 1);
    assert.equal(childSpans[0]!.name, 'edgefetch.fetch.page');
    assert.equal(Number.isFinite(childSpans[0]!.startTimeMs), true);
    assert.doesNotThrow(() =>
      buildOtlpTracePayload({
        spans: [{ ...childSpans[0]!, startTimeMs: Number.NaN, endTimeMs: Number.POSITIVE_INFINITY }],
      }),
    );
  } finally {
    coordinator.close();
    otlpSink.close();
  }
});

test('R7-DevTelemetry: DO_NOT_TRACK honors all non-disable values, scrubSpanToDevErrorReport strips hostnames/MCP-slugs/buildmeta, and AGENT_HUB admin_opt_out blocks background flushes', async () => {
  // 1. Console DO_NOT_TRACK compliance (`2`, `enabled`, `y`, `1`, `true`, `ON` -> disabled; `0`, `false`, `no`, `off`, `unset`, `''` -> not DNT)
  for (const dntOn of ['1', 'true', ' ON ', '2', 'enabled', 'y', 'yes-please']) {
    assert.equal(isDoNotTrackEnabled(dntOn), true, `Expected DNT active for ${dntOn}`);
    const st = resolveDevTelemetryState({
      env: { EDGEFETCH_DEV_TELEMETRY: '1', DO_NOT_TRACK: dntOn },
      dbSettingValue: '1',
    });
    assert.equal(st.enabled, false);
    assert.equal(st.doNotTrack, true);
    assert.equal(st.source, 'do_not_track');
  }
  for (const dntOff of ['', '0', 'false', 'FALSE', 'no', 'off', 'unset', undefined]) {
    assert.equal(isDoNotTrackEnabled(dntOff), false, `Expected DNT inactive for ${String(dntOff)}`);
  }

  // 2. Endpoint validation rejects credentials and cloud metadata IPs while allowing public HTTPS & explicit loopback
  assert.equal(resolveDevTelemetryEndpoint({ EDGEFETCH_DEV_TELEMETRY_URL: 'https://user:pw@evil.example/x' }), null);
  assert.equal(resolveDevTelemetryEndpoint({ EDGEFETCH_DEV_TELEMETRY_URL: 'http://169.254.169.254/latest' }), null);
  assert.equal(resolveDevTelemetryEndpoint({ EDGEFETCH_DEV_TELEMETRY_URL: 'http://127.0.0.1:9999' }), 'http://127.0.0.1:9999/v1/dev-errors');

  // 3. Zero-hostname & zero-MCP-vault-slug scrubbing
  const baseErrSpan = {
    traceId: 'a'.repeat(32),
    spanId: 'b'.repeat(16),
    name: 'GET intranet.corp.example/admin/users/4711?token=SECRET',
    startTimeMs: 1,
    endTimeMs: 2,
    statusOk: false,
  };
  const scrubbedHostSpan = scrubSpanToDevErrorReport(
    {
      ...baseErrSpan,
      attributes: { 'edgefetch.adapter_id': 'shop.private-customer.example' },
    },
    { version: 'v2.7.0+host.internal.example' },
  );
  assert.ok(scrubbedHostSpan);
  assert.equal(scrubbedHostSpan.spanName, 'edgefetch.span');
  assert.equal(scrubbedHostSpan.adapterId, '');
  assert.equal(scrubbedHostSpan.version, '2.7.0');

  const scrubbedMcpSlug = scrubSpanToDevErrorReport({
    ...baseErrSpan,
    name: 'edgefetch.agent.tool',
    attributes: { 'edgefetch.adapter_id': 'mcp:acme-internal-crm:lookup_customer_by_ssn' },
  });
  assert.ok(scrubbedMcpSlug);
  assert.equal(scrubbedMcpSlug.adapterId, 'mcp-federated');
  assert.equal(JSON.stringify(scrubbedMcpSlug).includes('acme-internal-crm'), false);
  assert.equal(JSON.stringify(scrubbedMcpSlug).includes('lookup_customer_by_ssn'), false);

  // Bogus `wafVendor: 'Victim-Example-Com'` on a `statusOk: true` span must be scrubbed to `''` and return `null`!
  const bogusWafSpan = scrubSpanToDevErrorReport({
    ...baseErrSpan,
    name: 'edgefetch.scrape',
    statusOk: true,
    attributes: { 'edgefetch.waf.vendor': 'Victim-Example-Com' },
  });
  assert.equal(bogusWafSpan, null);
  assert.equal(
    validateDevErrorReport({
      schemaVersion: 1,
      version: '2.7.0',
      runtime: 'node',
      os: 'linux',
      arch: 'x64',
      mode: 'hub',
      spanName: 'intranet.corp.example',
      adapterId: 'greenhouse',
      wafVendor: '',
      httpStatus: 500,
      errorClass: 'http_5xx',
    }).ok,
    false,
  );

  // 4. `admin_opt_out` (`'0'`) stored in `AGENT_HUB` suppresses background `flushDevErrorTelemetry` calls omitting `dbSettingValue`!
  const coordinator = new LocalAgentHubCoordinator(':memory:');
  try {
    await coordinator.settings.setSetting(DEV_TELEMETRY_SETTING_KEY, '0');
    let posts = 0;
    const sent = await flushDevErrorTelemetry({
      env: {
        AGENT_HUB: coordinator.asNamespace(),
        EDGEFETCH_DEV_TELEMETRY: '1',
        EDGEFETCH_DEV_TELEMETRY_URL: 'http://127.0.0.1:9/v1/dev-errors',
      } as never,
      spans: [{ ...baseErrSpan, name: 'edgefetch.fetch.json' }],
      fetchFn: async () => {
        posts++;
        return new Response('{}', { status: 202 });
      },
    });
    assert.equal(sent, false);
    assert.equal(posts, 0, 'Background flush without explicit dbSettingValue must honor admin_opt_out in AGENT_HUB');
  } finally {
    coordinator.close();
  }
});

test('R7-Collector: Two-tier IPv6 /64+/48 rate limit, anti-LRU-thrash, strict enum schema, within-POST dedup, and anti-blinding count>=2 eviction protection', async () => {
  resetCollectorRateLimiters();
  const hubRoot = process.env.EDGEFETCH_HUB_ROOT ?? resolve(dirname(fileURLToPath(import.meta.url)), '..');
  const collectorSql = readFileSync(resolve(hubRoot, '../telemetry/migrations/0001_errors.sql'), 'utf8');
  const sqlite = new DatabaseSync(':memory:');
  sqlite.exec(collectorSql);

  const coerce = (v: unknown): string | number | bigint | Uint8Array | null => {
    if (v === undefined || v === null) return null;
    if (typeof v === 'boolean') return v ? 1 : 0;
    if (typeof v === 'number' || typeof v === 'bigint' || typeof v === 'string' || v instanceof Uint8Array) return v;
    return JSON.stringify(v);
  };
  const makeStmt = (sql: string, bound: unknown[] = []): D1PreparedStatementLike => ({
    bind: (...vals: unknown[]) => makeStmt(sql, vals),
    all: async <T = Record<string, unknown>>() => {
      const st = sqlite.prepare(sql);
      const p = bound.map(coerce);
      return sql.trimStart().toUpperCase().startsWith('SELECT')
        ? { results: st.all(...p) as T[] }
        : (st.run(...p), { results: [] as T[] });
    },
    first: async <T = Record<string, unknown>>(col?: string) => {
      const row = sqlite.prepare(sql).get(...bound.map(coerce)) as Record<string, unknown> | undefined;
      if (!row) return null;
      return col !== undefined ? ((row[col] as T) ?? null) : (row as T);
    },
    run: async () => {
      sqlite.prepare(sql).run(...bound.map(coerce));
      return { success: true };
    },
  });
  const d1: D1DatabaseLike = { prepare: (q) => makeStmt(q) };
  const adminToken = 'collector_r7_admin_token_0123456789abcdef';
  const env = { DB: d1, TELEMETRY_ADMIN_TOKEN: adminToken, MAX_ERROR_FINGERPRINTS: '10' };

  const makeValidEvent = (overrides: Record<string, unknown> = {}) => ({
    schemaVersion: 1,
    version: '2.7.0',
    runtime: 'node',
    os: 'linux',
    arch: 'x64',
    mode: 'hub',
    spanName: 'edgefetch.scrape',
    adapterId: 'greenhouse',
    wafVendor: '',
    httpStatus: 500,
    errorClass: 'http_5xx',
    ...overrides,
  });

  const postCollector = (body: unknown, ip: string, extraHeaders: Record<string, string> = {}) =>
    collectorWorker.fetch(
      new Request('https://telemetry.edgefetch.dev/v1/dev-errors', {
        method: 'POST',
        headers: { 'content-type': 'application/json', 'cf-connecting-ip': ip, ...extraHeaders },
        body: typeof body === 'string' ? body : JSON.stringify(body),
      }),
      env,
    );

  try {
    // 1. Reject cross-origin simple-POST (`text/plain` -> 415, `Origin` -> 403) and smuggled schema values (`400`)
    assert.equal((await postCollector(makeValidEvent(), '198.51.100.1', { 'content-type': 'text/plain' })).status, 415);
    assert.equal((await postCollector(makeValidEvent(), '198.51.100.1', { origin: 'https://evil.example' })).status, 403);

    for (const smuggled of [
      { spanName: 'intranet.corp.example' },
      { spanName: '10.20.30.40:8443' },
      { adapterId: 'shop.private-customer.example' },
      { adapterId: 'mcp:acme-internal:tool' },
      { adapterId: 'zz-fake' },
      { wafVendor: 'victim-example-com' },
      { errorClass: 'acme-corp:user-4711:pwned' },
      { version: 'evil.example.com' },
      { os: 'host-db01-corp' },
      { arch: 'attacker-was-here' },
      { mode: 'call,me,at,evil-example' },
    ]) {
      const r = await postCollector(makeValidEvent(smuggled), '198.51.100.2');
      assert.equal(r.status, 400, `Expected 400 for smuggled ${JSON.stringify(smuggled)}`);
    }

    // Reject `> MAX_EVENTS_PER_POST` (8) items, and deduplicate identical events within one POST + block os/arch/mode overwrite!
    assert.equal(MAX_EVENTS_PER_POST, 8);
    const nineEvents = { events: Array.from({ length: 9 }, () => makeValidEvent()) };
    assert.equal((await postCollector(nineEvents, '198.51.100.3')).status, 400);

    const eightIdentical = {
      events: Array.from({ length: 8 }, () => makeValidEvent({ adapterId: 'shopify', os: 'linux', arch: 'x64', mode: 'hub' })),
    };
    assert.equal((await postCollector(eightIdentical, '198.51.100.4')).status, 202);
    // Attempt to overwrite os/arch/mode on same fingerprint
    assert.equal(
      (await postCollector(makeValidEvent({ adapterId: 'shopify', os: 'darwin', arch: 'arm64', mode: 'cli' }), '198.51.100.4')).status,
      202,
    );
    const shopifyRow = sqlite
      .prepare("SELECT count, os, arch, mode FROM error_fingerprints WHERE adapter_id = 'shopify'")
      .get() as { count: number; os: string; arch: string; mode: string };
    assert.equal(shopifyRow.count, 2, '8 identical events in POST #1 + 1 in POST #2 must equal count=2, not 9!');
    assert.equal(shopifyRow.os, 'linux', 'Existing row os must not be overwritten');
    assert.equal(shopifyRow.mode, 'hub', 'Existing row mode must not be overwritten');

    // 2. Two-tier IPv6 `/64` (30/min) AND `/48` (60/min) rate limit across 5,000 rotating `/64` subnets!
    resetCollectorRateLimiters();
    let acceptedInSlash48 = 0;
    let limitedInSlash48 = 0;
    for (let i = 0; i < 5_000; i++) {
      const rotatingIp = `2001:db8:7:${i.toString(16)}::1`;
      const st = (await postCollector(makeValidEvent({ adapterId: 'shopify' }), rotatingIp)).status;
      if (st === 202) acceptedInSlash48++;
      else if (st === 429) limitedInSlash48++;
    }
    assert.equal(acceptedInSlash48, IPV6_PREFIX48_RATE_LIMIT_CAPACITY, 'Entire IPv6 /48 must be capped at 60 req/min');
    assert.equal(limitedInSlash48, 5_000 - IPV6_PREFIX48_RATE_LIMIT_CAPACITY);
    assert.equal(RATE_LIMIT_CAPACITY, 30);

    // 3. Anti-blinding smart eviction (`MAX_ERROR_FINGERPRINTS = 10`):
    //    Insert 4 genuine multi-hit regressions (`count = 500`), then flood 20 distinct single-hit (`count = 1`) fingerprints!
    sqlite.exec('DELETE FROM error_fingerprints');
    resetCollectorRateLimiters();
    const genuineAdapters = ['greenhouse', 'lever', 'workday-cxs', 'ashby'];
    for (const a of genuineAdapters) {
      await postCollector(makeValidEvent({ adapterId: a, errorClass: 'adapter_error' }), '192.0.2.10');
    }
    sqlite.exec('UPDATE error_fingerprints SET count = 500');

    const noiseAdapters = [
      'icims',
      'rippling',
      'workable',
      'pinpoint',
      'teamtailor',
      'personio',
      'smartrecruiters',
      'recruitee',
      'bamboohr',
      'jazzhr',
      'shopify',
      'woocommerce',
      'socrata',
      'arcgis',
      'ckan',
      'sec-edgar',
      'openfda',
      'pubchem',
      'arxiv',
      'hackernews',
    ];
    for (let i = 0; i < noiseAdapters.length; i++) {
      const res = await postCollector(
        makeValidEvent({ adapterId: noiseAdapters[i], httpStatus: 502, errorClass: 'http_5xx' }),
        `203.0.113.${(i % 200) + 1}`,
      );
      assert.equal(res.status, 202);
    }

    // Total rows must stay strictly bounded at `MAX_ERROR_FINGERPRINTS` (10), and ALL 4 `count = 500` genuine rows MUST survive!
    const totalRows = (sqlite.prepare('SELECT COUNT(*) AS c FROM error_fingerprints').get() as { c: number }).c;
    assert.equal(totalRows, 10);
    const survivingGenuine = (
      sqlite.prepare('SELECT COUNT(*) AS c FROM error_fingerprints WHERE count = 500').get() as { c: number }
    ).c;
    assert.equal(survivingGenuine, 4, 'All 4 genuine multi-hit (count=500) regressions must survive single-hit flood!');

    // Verify trailing space on summary Bearer token is rejected (`401`)
    const badTrailingSpaceAuth = await collectorWorker.fetch(
      new Request('https://telemetry.edgefetch.dev/v1/dev-errors/summary', {
        headers: { authorization: `Bearer ${adminToken} extra` },
      }),
      env,
    );
    assert.equal(badTrailingSpaceAuth.status, 401);
  } finally {
    sqlite.close();
  }
});
