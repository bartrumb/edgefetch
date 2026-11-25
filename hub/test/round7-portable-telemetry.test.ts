import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import http from 'node:http';
import net from 'node:net';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { mkdtemp, rm } from 'node:fs/promises';
import collectorWorker, {
  IPV6_PREFIX48_RATE_LIMIT_CAPACITY,
  MAX_EVENTS_PER_POST,
  RATE_LIMIT_CAPACITY,
  resetCollectorRateLimiters,
  type D1DatabaseLike,
  type D1PreparedStatementLike,
} from '../../telemetry/src/index.ts';
import { LocalAgentHubCoordinator } from '../portable/node-adapters.ts';
import {
  FIRST_BYTE_PREHEADER_TIMEOUT_MS,
  MAX_PREHEADER_SOCKETS_PER_IP,
  PRE_HEADER_TIMEOUT_MS,
  resolveConfiguredPublicOrigin,
  startPortableHub,
} from '../portable/portable-server.ts';
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
import { ADMIN_COOKIE_NAME, createAdminSessionValue } from '../src/oauth.ts';
import {
  buildCrawlChildSpans,
  buildOtlpTracePayload,
  createRequestTraceContext,
  parseOtlpHeaders,
  parseTraceparent,
  RequestTracer,
  resetOtlpExportLimitersForTests,
  resolveOtlpTracesUrl,
  sanitizeUrlForSpan,
} from '../src/otel.ts';

const CALLER_TOKEN = 'r7-caller-secret-token-0123456789abcdef';
const MCP_TOKEN = 'r7-mcp-secret-token-0123456789abcdefXYZ';
const AGENT_TOKEN = 'r7-agent-secret-token-0123456789abcdef';

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

function rawTcpHttpRequest(
  port: number,
  payload: string,
  localAddress = '127.0.0.1',
  timeoutMs = 2_000,
): Promise<string> {
  return new Promise((res) => {
    const sock = net.connect({ port, host: '127.0.0.1', localAddress });
    let out = '';
    const timer = setTimeout(() => {
      sock.destroy();
      res(out || 'TIMEOUT');
    }, timeoutMs);
    sock.on('data', (chunk) => {
      out += chunk.toString('latin1');
    });
    sock.on('error', (err: NodeJS.ErrnoException) => {
      clearTimeout(timer);
      res(out || `SOCKERR:${err.code ?? err.message}`);
    });
    sock.on('close', () => {
      clearTimeout(timer);
      res(out || 'CLOSED');
    });
    sock.on('connect', () => {
      sock.write(payload);
    });
  });
}

test('R7-H8: Portable Hub exempts loopback /health & /readyz (100/100) under 132+ silent remote sockets, caps per-IP pre-header at 4, and FIFO-evicts global pre-header sockets with zero drift', async () => {
  assert.equal(MAX_PREHEADER_SOCKETS_PER_IP, 32);
  assert.equal(FIRST_BYTE_PREHEADER_TIMEOUT_MS, 5_000);
  assert.equal(PRE_HEADER_TIMEOUT_MS, 10_000);

  const dataDir = await mkdtemp(join(tmpdir(), 'ef-r7-h8-'));
  const hub = await startPortableHub({
    port: 0,
    host: '127.0.0.1',
    dataDir,
    maxGlobalPreHeaderSockets: 16,
    envOverrides: {
      CALLER_TOKEN,
      AGENT_TOKEN,
      EDGEFETCH_DISABLE_UPDATE_CHECK: '1',
    },
  });

  const silentKeepers: Array<{ stop: () => void }> = [];
  const startSilentKeeper = (fromIp: string, count: number) => {
    let stopped = false;
    const live = new Set<net.Socket>();
    const openOne = () => {
      if (stopped) return;
      const s = net.connect({ port: hub.port, host: '127.0.0.1', localAddress: fromIp });
      live.add(s);
      s.on('error', () => undefined);
      s.resume();
      s.on('close', () => {
        live.delete(s);
        if (!stopped) {
          const t = setTimeout(openOne, 25);
          t.unref?.();
        }
      });
    };
    for (let i = 0; i < count; i++) openOne();
    const keeper = {
      stop: () => {
        stopped = true;
        for (const s of live) s.destroy();
      },
    };
    silentKeepers.push(keeper);
    return keeper;
  };

  try {
    // 1. Reproduce `s7.mjs` `prehdr` + global saturation:
    //    6 remote IPs (`127.0.0.2`..`127.0.0.7`) opening 33 silent zero-byte sockets each (`198` silent sockets > `maxGlobalPreHeaderSockets=16`)!
    for (const n of [2, 3, 4, 5, 6, 7]) {
      startSilentKeeper(`127.0.0.${n}`, 33);
    }
    await sleep(150);

    // Verify 100/100 loopback `/health` & `/readyz` probes succeed AND remote `127.0.0.99` probes succeed via FIFO eviction!
    let loopbackOk = 0;
    let readyzOk = 0;
    let remoteOk = 0;
    for (let i = 0; i < 100; i++) {
      const h = await rawTcpHttpRequest(
        hub.port,
        'GET /health HTTP/1.1\r\nHost: hub.local\r\nConnection: close\r\n\r\n',
        '127.0.0.1',
      );
      if (h.startsWith('HTTP/1.1 200 OK')) loopbackOk++;

      if (i < 25) {
        const rz = await rawTcpHttpRequest(
          hub.port,
          'GET /readyz HTTP/1.1\r\nHost: hub.local\r\nConnection: close\r\n\r\n',
          '127.0.0.1',
        );
        if (rz.startsWith('HTTP/1.1 200 OK')) readyzOk++;

        const rem = await rawTcpHttpRequest(
          hub.port,
          `GET /v1/hosts HTTP/1.1\r\nHost: hub.local\r\nAuthorization: Bearer ${CALLER_TOKEN}\r\nConnection: close\r\n\r\n`,
          '127.0.0.99',
        );
        if (rem.startsWith('HTTP/1.1 200 OK')) remoteOk++;
      }
    }

    assert.equal(loopbackOk, 100, 'Loopback 127.0.0.1 /health must succeed 100/100 under silent pre-header flood');
    assert.equal(readyzOk, 25, 'Loopback 127.0.0.1 /readyz must succeed 25/25 under silent pre-header flood');
    assert.equal(remoteOk, 25, 'Legitimate remote client must evict silent pre-header sockets and succeed 25/25');

    for (const k of silentKeepers) k.stop();
    silentKeepers.length = 0;
    await sleep(150);

    // 2. Verify zero counter drift across rapid RST, half-open FIN, partial headers, clientError, and WS upgrade rejections (`127.0.0.12`)
    const quickExit = (data: string, halfOpen = false) =>
      new Promise<void>((res) => {
        const s = net.connect({ port: hub.port, host: '127.0.0.1', localAddress: '127.0.0.12', allowHalfOpen: true });
        s.on('error', () => res());
        s.on('close', () => res());
        s.on('connect', () => {
          if (data) s.write(data);
          if (halfOpen) {
            s.end();
            setTimeout(() => s.destroy(), 50).unref?.();
          } else {
            setTimeout(() => s.destroy(), 5).unref?.();
          }
        });
      });

    for (let i = 0; i < 40; i++) {
      await Promise.all([
        quickExit(''),
        quickExit('', true),
        quickExit('GET /health HTTP/1.1\r\nHo'),
        quickExit('NOT_HTTP\r\n\r\n'),
        quickExit('GET /agent/ws HTTP/1.1\r\nHost: a\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n'),
      ]);
    }
    await sleep(150);

    // All 10 fresh silent sockets from `127.0.0.12` (within `maxGlobalPreHeaderSockets = 16` and `MAX_PREHEADER_SOCKETS_PER_IP = 32`) should be admitted with zero counter drift
    const probeIdle: Array<net.Socket & { _closed?: boolean }> = await Promise.all(
      Array.from({ length: 10 }, () =>
        new Promise<net.Socket & { _closed?: boolean }>((r) => {
          const s: net.Socket & { _closed?: boolean } = net.connect({
            port: hub.port,
            host: '127.0.0.1',
            localAddress: '127.0.0.12',
          });
          s.on('error', () => undefined);
          s.on('close', () => {
            s._closed = true;
          });
          s.on('connect', () => r(s));
          setTimeout(() => r(s), 300).unref?.();
        }),
      ),
    );
    await sleep(150);
    const openIdleCount = probeIdle.filter((s) => !s._closed).length;
    for (const s of probeIdle) s.destroy();
    assert.equal(openIdleCount, Math.min(10, MAX_PREHEADER_SOCKETS_PER_IP, 16), 'Zero pre-header counter drift after rapid aborts');
  } finally {
    for (const k of silentKeepers) k.stop();
    await hub.close();
    await rm(dataDir, { recursive: true, force: true });
  }
});

test('R7-AuthSlots: Bogus Authorization/X-Api-Key/Cookie headers cannot claim reserved authenticated concurrency slots on Portable or Deno Hub', async () => {
  const dataDir = await mkdtemp(join(tmpdir(), 'ef-r7-slots-'));
  const hub = await startPortableHub({
    port: 0,
    host: '127.0.0.1',
    dataDir,
    maxInflightPerIp: 8,
    maxInflightTotal: 8, // maxUnauthInflight = 8 - 2 = 6; 2 slots strictly reserved for verified callers
    envOverrides: {
      CALLER_TOKEN,
      MCP_TOKEN,
      AGENT_TOKEN,
      EDGEFETCH_DISABLE_UPDATE_CHECK: '1',
    },
  });

  const stalledSockets: net.Socket[] = [];
  try {
    // Open 6 stalled POST requests carrying bogus `Authorization`, `X-Api-Key`, and `Cookie` headers across `127.0.0.2` & `127.0.0.3`
    for (let i = 0; i < 6; i++) {
      const fromIp = i < 3 ? '127.0.0.2' : '127.0.0.3';
      const s = await new Promise<net.Socket>((r) => {
        const sock = net.connect({ port: hub.port, host: '127.0.0.1', localAddress: fromIp });
        sock.on('error', () => undefined);
        sock.on('connect', () => {
          sock.write(
            `POST /oauth/token HTTP/1.1\r\nHost: hub.local\r\nAuthorization: Bearer bogus-token-${i}\r\nX-Api-Key: fake-key-${i}\r\nCookie: ${ADMIN_COOKIE_NAME}=bogus.cookie.val\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 500\r\n\r\n`,
          );
          r(sock);
        });
      });
      stalledSockets.push(s);
    }
    await sleep(100);

    // 7th bogus-auth request from a fresh IP (`127.0.0.4`) MUST be rejected with 429 (cannot eat reserved authenticated slots!)
    const bogus7 = await rawTcpHttpRequest(
      hub.port,
      'GET /openapi.json HTTP/1.1\r\nHost: hub.local\r\nAuthorization: Bearer completely-bogus-secret-token-value\r\nConnection: close\r\n\r\n',
      '127.0.0.4',
    );
    assert.match(bogus7, /^HTTP\/1\.1 429 /, 'Bogus Authorization header must hit unauthenticated slot ceiling (429)');

    // Genuine CALLER_TOKEN request from `127.0.0.5` MUST succeed (200) via reserved authenticated slot!
    const validCaller = await rawTcpHttpRequest(
      hub.port,
      `GET /v1/hosts HTTP/1.1\r\nHost: hub.local\r\nAuthorization: Bearer ${CALLER_TOKEN}\r\nConnection: close\r\n\r\n`,
      '127.0.0.5',
    );
    assert.match(validCaller, /^HTTP\/1\.1 200 /, 'Verified CALLER_TOKEN must succeed using reserved authenticated slot');

    // Genuine signed `ef_admin_session` cookie request MUST also succeed (200)!
    const mintedSession = await createAdminSessionValue(CALLER_TOKEN);
    const validAdmin = await rawTcpHttpRequest(
      hub.port,
      `GET /admin/api/state HTTP/1.1\r\nHost: hub.local\r\nCookie: ${ADMIN_COOKIE_NAME}=${mintedSession.value}\r\nConnection: close\r\n\r\n`,
      '127.0.0.6',
    );
    assert.match(validAdmin, /^HTTP\/1\.1 200 /, 'Verified signed admin cookie must succeed using reserved slot');
  } finally {
    for (const s of stalledSockets) s.destroy();
    await hub.close();
    await rm(dataDir, { recursive: true, force: true });
  }
});

test('R7-Origin: Fly.io, Render, and Railway 1-click deploy env vars resolve canonical HTTPS origin for /admin login CSRF & Secure cookies while blocking Host spoofing', async () => {
  assert.equal(resolveConfiguredPublicOrigin({ FLY_APP_NAME: 'myhub' }), 'https://myhub.fly.dev');
  assert.equal(resolveConfiguredPublicOrigin({ RENDER_EXTERNAL_URL: 'https://myhub.onrender.com/ignored' }), 'https://myhub.onrender.com');
  assert.equal(resolveConfiguredPublicOrigin({ RAILWAY_PUBLIC_DOMAIN: 'myhub.up.railway.app' }), 'https://myhub.up.railway.app');

  const dataDir = await mkdtemp(join(tmpdir(), 'ef-r7-fly-'));
  const hub = await startPortableHub({
    port: 0,
    host: '127.0.0.1',
    dataDir,
    envOverrides: {
      CALLER_TOKEN,
      EDGEFETCH_TRUST_PROXY: '1',
      FLY_APP_NAME: 'myhub',
      EDGEFETCH_PUBLIC_ORIGIN: undefined,
      EDGEFETCH_DISABLE_UPDATE_CHECK: '1',
    },
  });

  try {
    const body = `token=${CALLER_TOKEN}`;
    // 1. Legitimate Fly.io `/admin/login` succeeds (302) with `Secure` cookie + `HSTS`, even if `X-Forwarded-Proto: https, http` is sent!
    const okLogin = await rawTcpHttpRequest(
      hub.port,
      `POST /admin/login HTTP/1.1\r\nHost: myhub.fly.dev\r\nX-Forwarded-Proto: https, http\r\nX-Forwarded-For: 203.0.113.10\r\nOrigin: https://myhub.fly.dev\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: ${body.length}\r\nConnection: close\r\n\r\n${body}`,
    );
    assert.match(okLogin, /^HTTP\/1\.1 302 /);
    assert.match(okLogin, /set-cookie: (?:__Host-)?ef_admin_session=[^;]+;[^\r\n]*;\s*Secure/i);
    assert.match(okLogin, /strict-transport-security:/i);

    // 2. Spoofed `Host: evil.test` + `Origin: https://evil.test` is rejected with 403!
    const spoofedLogin = await rawTcpHttpRequest(
      hub.port,
      `POST /admin/login HTTP/1.1\r\nHost: evil.test\r\nX-Forwarded-Proto: https\r\nX-Forwarded-For: 203.0.113.11\r\nOrigin: https://evil.test\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: ${body.length}\r\nConnection: close\r\n\r\n${body}`,
    );
    assert.match(spoofedLogin, /^HTTP\/1\.1 403 /);

    // 3. OAuth metadata issuer stays pinned to `https://myhub.fly.dev` under `Host: evil.test`
    const oauthMeta = await rawTcpHttpRequest(
      hub.port,
      'GET /.well-known/oauth-authorization-server HTTP/1.1\r\nHost: evil.test\r\nX-Forwarded-Host: evil.test\r\nX-Forwarded-Proto: https\r\nConnection: close\r\n\r\n',
    );
    assert.ok(oauthMeta.includes('"issuer":"https://myhub.fly.dev"'));
  } finally {
    await hub.close();
    await rm(dataDir, { recursive: true, force: true });
  }
});

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
