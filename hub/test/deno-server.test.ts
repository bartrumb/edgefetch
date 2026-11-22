import assert from 'node:assert/strict';
import { createDenoHubHandler, createDenoSafeFetch, startDenoHub } from '../portable/deno-server.ts';

interface CapturedOtlpRequest {
  headers: Record<string, string>;
  body: {
    resourceSpans?: Array<{
      resource?: { attributes?: Array<{ key: string; value?: { stringValue?: string } }> };
      scopeSpans?: Array<{
        spans?: Array<{
          traceId: string;
          spanId: string;
          parentSpanId?: string;
          name: string;
          attributes?: Array<{ key: string; value?: Record<string, unknown> }>;
        }>;
      }>;
    }>;
  };
}

Deno.test('Deno Hub startDenoHub emits parent-linked OTLP spans via SAFE_FETCH and attaches trace headers', async () => {
  const captured: CapturedOtlpRequest[] = [];
  const collector = Deno.serve({ hostname: '127.0.0.1', port: 0 }, async (req) => {
    const url = new URL(req.url);
    if (req.method === 'POST' && url.pathname === '/v1/traces') {
      const headers = Object.fromEntries(req.headers.entries());
      const body = (await req.json()) as CapturedOtlpRequest['body'];
      captured.push({ headers, body });
      return Response.json({ partialSuccess: {} }, { status: 200 });
    }
    return new Response('not found', { status: 404 });
  });

  const collectorPort = (collector.addr as { port: number }).port;
  const callerToken = 'deno-smoke-caller-token-0123456789abcdef';
  const hub = startDenoHub({
    hostname: '127.0.0.1',
    port: 0,
    ephemeralStores: true,
    envOverrides: {
      CALLER_TOKEN: callerToken,
      OTEL_EXPORTER_OTLP_ENDPOINT: `http://127.0.0.1:${collectorPort}`,
      OTEL_EXPORTER_OTLP_HEADERS: 'Authorization=Bearer%20deno-otlp-tok,x-env=deno-ci',
      OTEL_SERVICE_NAME: 'edgefetch-deno-smoke',
    },
  });

  try {
    const baseUrl = `http://127.0.0.1:${hub.port}`;

    // 1. GET /health without traceparent: returns trace headers without emitting OTLP noise
    const healthRes = await fetch(`${baseUrl}/health`);
    assert.equal(healthRes.status, 200);
    await healthRes.body?.cancel();
    assert.match(healthRes.headers.get('x-trace-id') ?? '', /^[0-9a-f]{32}$/);
    assert.match(healthRes.headers.get('traceparent') ?? '', /^00-[0-9a-f]{32}-[0-9a-f]{16}-01$/);

    // 2. GET /v1/capabilities with inbound W3C traceparent preserves traceId
    const inboundTraceId = '4bf92f3577b34da6a3ce929d0e0e4736';
    const inboundParentId = '00f067aa0ba902b7';
    const capRes = await fetch(`${baseUrl}/v1/capabilities`, {
      headers: {
        authorization: `Bearer ${callerToken}`,
        traceparent: `00-${inboundTraceId}-${inboundParentId}-01`,
      },
    });
    assert.equal(capRes.status, 200);
    await capRes.body?.cancel();
    assert.equal(capRes.headers.get('x-trace-id'), inboundTraceId);
    assert.match(capRes.headers.get('traceparent') ?? '', new RegExp(`^00-${inboundTraceId}-[0-9a-f]{16}-01$`));

    // 3. POST /mcp tools/call:find_extractors creates nested edgefetch.http -> edgefetch.mcp.tool
    const mcpRes = await fetch(`${baseUrl}/mcp`, {
      method: 'POST',
      headers: {
        authorization: `Bearer ${callerToken}`,
        'content-type': 'application/json',
        traceparent: `00-${inboundTraceId}-${inboundParentId}-01`,
      },
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: 1,
        method: 'tools/call',
        params: {
          name: 'find_extractors',
          arguments: { query: 'greenhouse', limit: 3 },
        },
      }),
    });
    assert.equal(mcpRes.status, 200);
    await mcpRes.body?.cancel();
    assert.equal(mcpRes.headers.get('x-trace-id'), inboundTraceId);

    // 4. Unauthorized POST /v1/scrape still returns x-trace-id & traceparent
    const unauthRes = await fetch(`${baseUrl}/v1/scrape`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ url: 'https://example.com' }),
    });
    assert.equal(unauthRes.status, 401);
    await unauthRes.body?.cancel();
    assert.match(unauthRes.headers.get('x-trace-id') ?? '', /^[0-9a-f]{32}$/);
    assert.match(unauthRes.headers.get('traceparent') ?? '', /^00-[0-9a-f]{32}-[0-9a-f]{16}-01$/);

    await hub.flushPending();
    assert.ok(captured.length >= 2, `Expected OTLP batches captured, got ${captured.length}`);

    const first = captured[0]!;
    assert.equal(first.headers.authorization, 'Bearer deno-otlp-tok');
    assert.equal(first.headers['x-env'], 'deno-ci');

    const svcAttr = first.body.resourceSpans?.[0]?.resource?.attributes?.find((a) => a.key === 'service.name');
    assert.equal(svcAttr?.value?.stringValue, 'edgefetch-deno-smoke');

    const allSpans = captured.flatMap((c) => c.body.resourceSpans?.[0]?.scopeSpans?.[0]?.spans ?? []);
    const capSpan = allSpans.find((s) => s.name === 'edgefetch.capabilities' && s.traceId === inboundTraceId);
    assert.ok(capSpan, 'Expected edgefetch.capabilities span');

    const mcpToolSpan = allSpans.find((s) => s.name === 'edgefetch.mcp.tool' && s.traceId === inboundTraceId);
    assert.ok(mcpToolSpan, 'Expected edgefetch.mcp.tool span');
    assert.ok(
      allSpans.some((s) => s.name === 'edgefetch.http' && s.spanId === mcpToolSpan.parentSpanId && s.traceId === inboundTraceId),
      'edgefetch.mcp.tool must nest under edgefetch.http',
    );
  } finally {
    await hub.close();
    await collector.shutdown();
  }
});

Deno.test('Deno Hub createDenoHubHandler wires Deno.env fallback, envOverrides, and distinct SAFE_FETCH/SAFE_PUBLIC_FETCH', async () => {
  const prevEndpoint = Deno.env.get('OTEL_EXPORTER_OTLP_ENDPOINT');
  const prevService = Deno.env.get('OTEL_SERVICE_NAME');
  Deno.env.set('OTEL_EXPORTER_OTLP_ENDPOINT', 'http://127.0.0.1:4318');
  Deno.env.set('OTEL_SERVICE_NAME', 'from-deno-env');

  const h = createDenoHubHandler({
    port: 0,
    ephemeralStores: true,
    envOverrides: {
      CALLER_TOKEN: 'deno-env-caller-token-0123456789abcdef',
      OTEL_EXPORTER_OTLP_HEADERS: 'x-otel-override=yes',
      OTEL_SERVICE_NAME: 'from-override',
    },
  });

  try {
    assert.equal(h.workerEnv.OTEL_EXPORTER_OTLP_ENDPOINT, 'http://127.0.0.1:4318');
    assert.equal(h.workerEnv.OTEL_EXPORTER_OTLP_HEADERS, 'x-otel-override=yes');
    assert.equal(h.workerEnv.OTEL_SERVICE_NAME, 'from-override');
    assert.notEqual(h.workerEnv.SAFE_FETCH, h.workerEnv.SAFE_PUBLIC_FETCH);

    const res = await h.handler(new Request('http://127.0.0.1/health'));
    assert.equal(res.status, 200);
    await res.body?.cancel();
    assert.match(res.headers.get('x-trace-id') ?? '', /^[0-9a-f]{32}$/);
  } finally {
    await h.close();
    if (prevEndpoint === undefined) Deno.env.delete('OTEL_EXPORTER_OTLP_ENDPOINT');
    else Deno.env.set('OTEL_EXPORTER_OTLP_ENDPOINT', prevEndpoint);
    if (prevService === undefined) Deno.env.delete('OTEL_SERVICE_NAME');
    else Deno.env.set('OTEL_SERVICE_NAME', prevService);
  }
});

Deno.test('Deno createDenoSafeFetch permits hop-0 explicit loopback on SAFE_FETCH while blocking SSRF redirects & public loopback', async () => {
  const targetServer = Deno.serve({ hostname: '127.0.0.1', port: 0 }, async (req) => {
    const url = new URL(req.url);
    if (url.pathname === '/v1/traces') {
      await req.body?.cancel();
      return Response.json({ ok: true }, { status: 200 });
    }
    if (url.pathname === '/redirect-metadata') {
      return new Response(null, {
        status: 302,
        headers: { location: 'http://169.254.169.254/latest/meta-data/' },
      });
    }
    if (url.pathname === '/redirect-loopback-https') {
      return new Response(null, {
        status: 302,
        headers: { location: `https://127.0.0.1:${url.port}/admin` },
      });
    }
    return new Response('ok', { status: 200 });
  });

  try {
    const port = (targetServer.addr as { port: number }).port;
    const safeFetch = createDenoSafeFetch('hub.local', { allowExplicitLoopbackUrls: true });
    const safePublicFetch = createDenoSafeFetch('hub.local', { allowExplicitLoopbackUrls: false });

    const okRes = await safeFetch(`http://127.0.0.1:${port}/v1/traces`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: '{}',
    });
    assert.equal(okRes.status, 200);
    await okRes.body?.cancel();

    await assert.rejects(
      () => safePublicFetch(`http://127.0.0.1:${port}/v1/traces`, { method: 'POST', body: '{}' }),
      /SSRF blocked/,
    );
    await assert.rejects(
      () => safeFetch(`http://127.0.0.1:${port}/redirect-metadata`),
      /SSRF blocked/,
    );
    await assert.rejects(
      () => safeFetch(`http://127.0.0.1:${port}/redirect-loopback-https`),
      /SSRF blocked/,
    );
    await assert.rejects(
      () => safeFetch('http://169.254.169.254/latest/meta-data/'),
      /SSRF blocked/,
    );
  } finally {
    await targetServer.shutdown();
  }
});

Deno.test('Deno createDenoSafeFetch rejects obfuscated loopback URLs before fetchImpl while permitting canonical loopback', async () => {
  let fetchCalls = 0;
  const safeFetch = createDenoSafeFetch('hub.local', {
    allowExplicitLoopbackUrls: true,
    fetchImpl: async () => {
      fetchCalls++;
      return Response.json({ ok: true }, { status: 200 });
    },
    resolveDns: async () => ['93.184.216.34'],
  });

  for (const okUrl of [
    'http://127.0.0.1:4318/v1/traces',
    'http://localhost:4318/v1/traces',
    'http://[::1]:4318/v1/traces',
  ]) {
    const res = await safeFetch(okUrl, { method: 'POST', body: '{}' });
    assert.equal(res.status, 200);
  }
  assert.equal(fetchCalls, 3);

  fetchCalls = 0;
  for (const obfuscatedUrl of [
    'http://2130706433/',
    'http://0x7f000001/',
    'http://0177.0.0.1/',
    'http://127.1/',
    'http://[0:0:0:0:0:0:0:1]:4318/',
    'http://[::ffff:127.0.0.1]/',
    'http://localhost./v1/traces',
    'http://user@127.0.0.1:4318/',
    'http://127.0.0.1:0/v1/traces',
    'http://127.0.0.1:65536/v1/traces',
  ]) {
    await assert.rejects(() => safeFetch(obfuscatedUrl), /SSRF blocked/, `Expected block for ${obfuscatedUrl}`);
  }
  assert.equal(fetchCalls, 0);
});
