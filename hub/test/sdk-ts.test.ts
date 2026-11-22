import assert from 'node:assert/strict';
import test from 'node:test';
import {
  EdgeFetchClient,
  EdgeFetchError,
  type EdgeFetchRequestOptions,
} from '../../sdk/ts/edgefetch-client.ts';

interface CapturedCall {
  url: string;
  method: string;
  headers: Record<string, string>;
  body: string | undefined;
}

const TRACE_A = '00-0123456789abcdef0123456789abcdef-1111111111111111-01';
const TRACE_A_ID = '0123456789abcdef0123456789abcdef';
const TRACE_B = '00-FEDCBA9876543210FEDCBA9876543210-2222222222222222-00';
const TRACE_B_ID = 'fedcba9876543210fedcba9876543210';

function makeJsonResponse(
  status: number,
  body: unknown,
  headers?: Headers | Record<string, unknown> | null,
): Response {
  const res = {
    ok: status >= 200 && status < 300,
    status,
    headers: headers === undefined ? new Headers() : headers,
    json: async () => body,
  };
  return res as unknown as Response;
}

function makeRecorder(
  responder?: (call: CapturedCall, index: number) => Response | Promise<Response>,
): { calls: CapturedCall[]; fetchFn: typeof fetch } {
  const calls: CapturedCall[] = [];
  const fetchFn: typeof fetch = async (input, init) => {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url;
    const rawHeaders = (init?.headers ?? {}) as Record<string, string>;
    const call: CapturedCall = {
      url,
      method: init?.method ?? 'GET',
      headers: { ...rawHeaders },
      body: typeof init?.body === 'string' ? init.body : undefined,
    };
    calls.push(call);
    if (responder) {
      return responder(call, calls.length - 1);
    }
    return makeJsonResponse(200, { ok: true });
  };
  return { calls, fetchFn };
}

test('constructor validation, origin security, deduplication, and default global fetch', async () => {
  assert.throws(
    () => new EdgeFetchClient({ token: 'tok' }),
    /EdgeFetchClient requires baseUrl or non-empty baseUrls/,
  );
  assert.throws(
    () => new EdgeFetchClient({ token: 'tok', baseUrls: ['', '   '], baseUrl: '   ' }),
    /EdgeFetchClient requires baseUrl or non-empty baseUrls/,
  );
  assert.throws(
    () => new EdgeFetchClient({ token: 'tok', baseUrl: 'not-a-valid-url' }),
    /Invalid EdgeFetch Hub baseUrl/,
  );
  assert.throws(
    () => new EdgeFetchClient({ token: 'tok', baseUrl: 'ftp://hub.example.com' }),
    /Unsupported EdgeFetch Hub protocol/,
  );
  assert.throws(
    () => new EdgeFetchClient({ token: 'tok', baseUrl: 'http://remote.example.com:8787' }),
    /Refusing cleartext http:\/\/ Hub URL/,
  );
  assert.throws(
    () => new EdgeFetchClient({ token: 'tok', baseUrl: 'https://hub.example.com', traceparent: '00-abc\r\n' }),
    /Invalid traceparent header/,
  );
  assert.throws(
    () => new EdgeFetchClient({ token: 'tok', baseUrl: 'https://hub.example.com', traceparent: '00-abc\0' }),
    /Invalid traceparent header/,
  );

  for (const loopback of ['http://127.0.0.1:8787', 'http://localhost:8787', 'http://[::1]:8787']) {
    const { fetchFn } = makeRecorder();
    const client = new EdgeFetchClient({ token: 'tok', baseUrl: loopback, fetchFn });
    const res = await client.capabilities();
    assert.equal(res.ok, true);
  }

  const { calls, fetchFn } = makeRecorder();
  const dedupClient = new EdgeFetchClient({
    token: 'tok-dedup',
    baseUrls: [' https://primary.example.com/ ', ''],
    baseUrl: 'https://primary.example.com///',
    allowInsecureHttp: false,
    traceparent: '   ',
    fetchFn,
  });
  await dedupClient.capabilities();
  assert.equal(calls.length, 1);
  assert.equal(calls[0]!.url, 'https://primary.example.com/v1/capabilities');
  assert.equal(calls[0]!.headers.traceparent, undefined);

  const insecureClient = new EdgeFetchClient({
    token: 'tok-insecure',
    baseUrl: 'http://internal-hub.local:8787/',
    allowInsecureHttp: true,
    fetchFn,
  });
  await insecureClient.capabilities();
  assert.equal(calls[1]!.url, 'http://internal-hub.local:8787/v1/capabilities');

  const originalFetch = globalThis.fetch;
  let globalHit = false;
  globalThis.fetch = (async () => {
    globalHit = true;
    return makeJsonResponse(200, { ok: true, source: 'global' });
  }) as typeof fetch;
  try {
    const defaultFetchClient = new EdgeFetchClient({
      token: 'tok-global',
      baseUrl: 'https://global.example.com',
    });
    const out = await defaultFetchClient.capabilities();
    assert.equal(globalHit, true);
    assert.equal(out.source, 'global');
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('outbound traceparent forwarding, per-request override, suppression, probe passthrough, and body isolation', async () => {
  const { calls, fetchFn } = makeRecorder(() =>
    makeJsonResponse(
      200,
      { ok: true },
      new Headers({
        'X-Trace-Id': `  ${TRACE_A_ID}  `,
        Traceparent: `  ${TRACE_A}  `,
      }),
    ),
  );

  const client = new EdgeFetchClient({
    token: 'tok-trace',
    baseUrl: 'https://hub.example.com',
    traceparent: `  ${TRACE_A}  `,
    fetchFn,
  });
  assert.equal(client.lastTraceId, null);
  assert.equal(client.lastTraceparent, null);

  await client.scrape({ url: 'https://target.example.com' });
  assert.equal(calls[0]!.headers.traceparent, TRACE_A);
  assert.equal(calls[0]!.headers.authorization, 'Bearer tok-trace');
  assert.equal(calls[0]!.headers['content-type'], 'application/json');
  assert.deepEqual(JSON.parse(calls[0]!.body!), { url: 'https://target.example.com' });
  assert.equal(client.lastTraceId, TRACE_A_ID);
  assert.equal(client.lastTraceparent, TRACE_A);

  const overrideOpts: EdgeFetchRequestOptions = { traceparent: `  ${TRACE_B}  ` };
  await client.scrape({ url: 'https://target.example.com/2' }, overrideOpts);
  assert.equal(calls[1]!.headers.traceparent, TRACE_B);
  assert.equal('traceparent' in JSON.parse(calls[1]!.body!), false);

  await client.scrape({ url: 'https://target.example.com/3' }, { traceparent: '' });
  assert.equal(calls[2]!.headers.traceparent, undefined);

  await client.capabilities({ traceparent: '  non-w3c-probe-token  ' });
  assert.equal(calls[3]!.headers.traceparent, 'non-w3c-probe-token');
  assert.equal(calls[3]!.headers['content-type'], undefined);
  assert.equal(calls[3]!.body, undefined);

  await assert.rejects(
    () => client.capabilities({ traceparent: '00-bad\nheader' }),
    /Invalid traceparent header/,
  );
});

test('response header capture handles Headers, plain records, missing/invalid headers, and traceparent fallback', async () => {
  const responses: Array<Response> = [
    // 0: blank x-trace-id falls back to uppercase traceparent extraction
    makeJsonResponse(200, { ok: true }, new Headers({ 'x-trace-id': '   ', traceparent: ` ${TRACE_B} ` })),
    // 1: Headers without trace headers
    makeJsonResponse(200, { ok: true }, new Headers()),
    // 2: plain record object with mixed-case keys
    makeJsonResponse(200, { ok: true }, { 'Other-Header': 'x', 'X-Trace-Id': ` ${TRACE_A_ID} `, Traceparent: TRACE_A }),
    // 3: plain record with non-string value and whitespace value
    makeJsonResponse(200, { ok: true }, { 'X-Trace-Id': 123, Traceparent: '   ' }),
    // 4: missing headers (undefined/null)
    makeJsonResponse(200, { ok: true }, null),
    // 5: non-object headers stub
    makeJsonResponse(200, { ok: true }, 'invalid-headers' as unknown as Headers),
    // 6: custom Headers.get returning non-string / null
    makeJsonResponse(200, { ok: true }, { get: () => null } as unknown as Headers),
    // 7: malformed traceparent only
    makeJsonResponse(200, { ok: true }, new Headers({ traceparent: 'invalid-tp' })),
    // 8: all-zero traceId in traceparent
    makeJsonResponse(
      200,
      { ok: true },
      new Headers({ traceparent: '00-00000000000000000000000000000000-1111111111111111-01' }),
    ),
    // 9: all-zero spanId in traceparent
    makeJsonResponse(
      200,
      { ok: true },
      new Headers({ traceparent: `00-${TRACE_A_ID}-0000000000000000-01` }),
    ),
  ];

  let idx = 0;
  const client = new EdgeFetchClient({
    token: 'tok',
    baseUrl: 'https://hub.example.com',
    fetchFn: async () => responses[idx++]!,
  });

  await client.capabilities();
  assert.equal(client.lastTraceId, TRACE_B_ID);
  assert.equal(client.lastTraceparent, TRACE_B);

  await client.capabilities();
  assert.equal(client.lastTraceId, null);
  assert.equal(client.lastTraceparent, null);

  await client.capabilities();
  assert.equal(client.lastTraceId, TRACE_A_ID);
  assert.equal(client.lastTraceparent, TRACE_A);

  await client.capabilities();
  assert.equal(client.lastTraceId, null);
  assert.equal(client.lastTraceparent, null);

  await client.capabilities();
  assert.equal(client.lastTraceId, null);
  assert.equal(client.lastTraceparent, null);

  await client.capabilities();
  assert.equal(client.lastTraceId, null);
  assert.equal(client.lastTraceparent, null);

  await client.capabilities();
  assert.equal(client.lastTraceId, null);
  assert.equal(client.lastTraceparent, null);

  await client.capabilities();
  assert.equal(client.lastTraceId, null);
  assert.equal(client.lastTraceparent, 'invalid-tp');

  await client.capabilities();
  assert.equal(client.lastTraceId, null);

  await client.capabilities();
  assert.equal(client.lastTraceId, null);
});

test('error handling, failover across 502/503/504 and network errors, and per-attempt trace reset', async () => {
  // 1. 502 -> 504 -> 200 failover
  const { calls: calls1, fetchFn: fn1 } = makeRecorder((_call, i) => {
    if (i === 0) {
      return makeJsonResponse(
        502,
        { error: 'bad_gateway', message: 'primary 502' },
        new Headers({ 'x-trace-id': TRACE_A_ID, traceparent: TRACE_A }),
      );
    }
    if (i === 1) {
      return makeJsonResponse(504, { error: 'gateway_timeout', message: 'secondary 504' });
    }
    return makeJsonResponse(200, { ok: true }, new Headers({ traceparent: TRACE_B }));
  });
  const c1 = new EdgeFetchClient({
    token: 'tok',
    baseUrls: ['https://a.example.com', 'https://b.example.com', 'https://c.example.com'],
    fetchFn: fn1,
  });
  const res1 = await c1.capabilities();
  assert.equal(res1.ok, true);
  assert.equal(calls1.length, 3);
  assert.equal(c1.lastTraceId, TRACE_B_ID);
  assert.equal(c1.lastTraceparent, TRACE_B);

  // 2. 503 with trace-A on primary followed by 200 WITHOUT trace headers on standby -> resets to null
  const c2 = new EdgeFetchClient({
    token: 'tok',
    baseUrls: ['https://a.example.com', 'https://b.example.com'],
    fetchFn: makeRecorder((_call, i) =>
      i === 0
        ? makeJsonResponse(503, { error: 'unavailable' }, new Headers({ 'x-trace-id': TRACE_A_ID, traceparent: TRACE_A }))
        : makeJsonResponse(200, { ok: true }),
    ).fetchFn,
  });
  await c2.capabilities();
  assert.equal(c2.lastTraceId, null);
  assert.equal(c2.lastTraceparent, null);

  // 3. 503 exhaustion across all endpoints -> throws EdgeFetchError & preserves final endpoint trace headers
  const c3 = new EdgeFetchClient({
    token: 'tok',
    baseUrls: ['https://a.example.com', 'https://b.example.com'],
    fetchFn: makeRecorder((_call, i) =>
      makeJsonResponse(
        503,
        { error: 'evicting', message: `down-${i}` },
        new Headers({ 'x-trace-id': i === 0 ? TRACE_A_ID : TRACE_B_ID, traceparent: i === 0 ? TRACE_A : TRACE_B }),
      ),
    ).fetchFn,
  });
  await assert.rejects(
    () => c3.capabilities(),
    (err: unknown) => err instanceof EdgeFetchError && err.status === 503 && err.code === 'evicting' && err.message === 'down-1',
  );
  assert.equal(c3.lastTraceId, TRACE_B_ID);
  assert.equal(c3.lastTraceparent, TRACE_B);

  // 4. Non-gateway 401 with broken res.json() & missing error/message fields -> immediate throw, no failover, captures trace
  const { calls: calls4, fetchFn: fn4 } = makeRecorder(() => ({
    ok: false,
    status: 401,
    headers: new Headers({ 'x-trace-id': TRACE_A_ID, traceparent: TRACE_A }),
    json: async () => {
      throw new SyntaxError('Unexpected end of JSON');
    },
  }) as unknown as Response);
  const c4 = new EdgeFetchClient({
    token: 'tok',
    baseUrls: ['https://a.example.com', 'https://b.example.com'],
    fetchFn: fn4,
  });
  await assert.rejects(
    () => c4.capabilities(),
    (err: unknown) =>
      err instanceof EdgeFetchError &&
      err.status === 401 &&
      err.code === 'http_401' &&
      err.message === 'EdgeFetch HTTP 401',
  );
  assert.equal(calls4.length, 1);
  assert.equal(c4.lastTraceId, TRACE_A_ID);
  assert.equal(c4.lastTraceparent, TRACE_A);

  // 5. 503 with trace-A on primary followed by network Error on standby -> clears trace headers & throws network Error
  let attempt = 0;
  const c5 = new EdgeFetchClient({
    token: 'tok',
    baseUrls: ['https://a.example.com', 'https://b.example.com'],
    fetchFn: async () => {
      if (attempt++ === 0) {
        return makeJsonResponse(503, { error: 'busy' }, new Headers({ 'x-trace-id': TRACE_A_ID, traceparent: TRACE_A }));
      }
      throw new TypeError('connect ECONNREFUSED');
    },
  });
  await assert.rejects(() => c5.capabilities(), TypeError);
  assert.equal(c5.lastTraceId, null);
  assert.equal(c5.lastTraceparent, null);

  // 6. Non-Error thrown by fetchFn -> throws fallback Error('All EdgeFetch Hub endpoints failed')
  const c6 = new EdgeFetchClient({
    token: 'tok',
    baseUrl: 'https://a.example.com',
    fetchFn: async () => {
      throw 'raw-string-failure';
    },
  });
  await assert.rejects(() => c6.capabilities(), /All EdgeFetch Hub endpoints failed/);

  // 7. Non-object JSON error bodies (null, string, array) safely fall back without breaking 503 failover or EdgeFetchError
  const { calls: calls7, fetchFn: fn7 } = makeRecorder((_call, i) =>
    i === 0
      ? makeJsonResponse(503, null, new Headers({ 'x-trace-id': TRACE_A_ID }))
      : makeJsonResponse(200, { ok: true, recovered: true }, new Headers({ 'x-trace-id': TRACE_B_ID })),
  );
  const c7 = new EdgeFetchClient({
    token: 'tok',
    baseUrls: ['https://a.example.com', 'https://b.example.com'],
    fetchFn: fn7,
  });
  const res7 = await c7.capabilities();
  assert.equal(res7.recovered, true);
  assert.equal(calls7.length, 2);
  assert.equal(c7.lastTraceId, TRACE_B_ID);

  for (const nonObjectBody of [null, 'unauthorized-string', ['err']]) {
    const cNonObj = new EdgeFetchClient({
      token: 'tok',
      baseUrl: 'https://a.example.com',
      fetchFn: makeRecorder(() =>
        makeJsonResponse(401, nonObjectBody, new Headers({ 'x-trace-id': TRACE_A_ID, traceparent: TRACE_A })),
      ).fetchFn,
    });
    await assert.rejects(
      () => cNonObj.capabilities(),
      (err: unknown) =>
        err instanceof EdgeFetchError &&
        err.status === 401 &&
        err.code === 'http_401' &&
        err.message === 'EdgeFetch HTTP 401',
    );
    assert.equal(cNonObj.lastTraceId, TRACE_A_ID);
    assert.equal(cNonObj.lastTraceparent, TRACE_A);
  }
});

test('all 21 public SDK methods build expected routes, bodies, query params, and forward requestOptions', async () => {
  const { calls, fetchFn } = makeRecorder(() =>
    makeJsonResponse(200, { ok: true }, new Headers({ 'x-trace-id': TRACE_A_ID, traceparent: TRACE_A })),
  );
  const client = new EdgeFetchClient({
    token: 'tok-all',
    baseUrl: 'https://hub.example.com',
    fetchFn,
  });
  const opts: EdgeFetchRequestOptions = { traceparent: TRACE_B };

  await client.capabilities(opts);
  await client.hosts(undefined, opts);
  await client.hosts(0, opts);
  await client.hosts(999, opts);
  await client.extractors(undefined, opts);
  await client.extractors('jobs/ats', opts);
  await client.scrape({ url: 'https://example.com', formats: ['markdown'] }, opts);
  await client.extract({ urls: ['https://example.com'], query: 'extract title' }, opts);
  await client.map({ url: 'https://example.com', limit: 10 }, opts);
  await client.crawl({ url: 'https://example.com', limit: 5 }, opts);
  await client.getCrawl('crawl/1', undefined, undefined, opts);
  await client.getCrawl('crawl/2', 10, 50, opts);
  await client.cancelCrawl('crawl/1', opts);
  await client.search({ query: 'edgefetch' }, opts);
  await client.jobs({ query: 'engineer', remote: true }, opts);
  await client.interact({ url: 'https://example.com', actions: [{ type: 'click', selector: '#go' }] }, opts);
  await client.batchScrape({ urls: ['https://example.com/1'], sync: true }, opts);
  await client.getBatchScrape('batch/1', opts);
  await client.cancelBatchScrape('batch/1', opts);
  await client.previewCrawlParams({ url: 'https://example.com', prompt: 'docs' }, opts);
  await client.agent({ prompt: 'summarize' }, opts);
  await client.getAgent('agt/1', opts);
  await client.getAgentTrace('agt/1', opts);
  await client.cancelAgent('agt/1', opts);
  await client.readArtifact('sha/1', undefined, undefined, undefined, opts);
  await client.readArtifact('sha/1', 128, 256, 'markdown', opts);

  const expected: Array<[string, string]> = [
    ['GET', 'https://hub.example.com/v1/capabilities'],
    ['GET', 'https://hub.example.com/v1/hosts?limit=100'],
    ['GET', 'https://hub.example.com/v1/hosts?limit=1'],
    ['GET', 'https://hub.example.com/v1/hosts?limit=500'],
    ['GET', 'https://hub.example.com/v1/extractors'],
    ['GET', 'https://hub.example.com/v1/extractors?category=jobs%2Fats'],
    ['POST', 'https://hub.example.com/v1/scrape'],
    ['POST', 'https://hub.example.com/v1/extract'],
    ['POST', 'https://hub.example.com/v1/map'],
    ['POST', 'https://hub.example.com/v1/crawl'],
    ['GET', 'https://hub.example.com/v1/crawl/crawl%2F1?offset=0&limit=25'],
    ['GET', 'https://hub.example.com/v1/crawl/crawl%2F2?offset=10&limit=50'],
    ['DELETE', 'https://hub.example.com/v1/crawl/crawl%2F1'],
    ['POST', 'https://hub.example.com/v1/search'],
    ['POST', 'https://hub.example.com/v1/jobs'],
    ['POST', 'https://hub.example.com/v1/interact'],
    ['POST', 'https://hub.example.com/v1/batch/scrape'],
    ['GET', 'https://hub.example.com/v1/batch/scrape/batch%2F1'],
    ['DELETE', 'https://hub.example.com/v1/batch/scrape/batch%2F1'],
    ['POST', 'https://hub.example.com/v1/crawl/params-preview'],
    ['POST', 'https://hub.example.com/v1/agent'],
    ['GET', 'https://hub.example.com/v1/agent/agt%2F1'],
    ['GET', 'https://hub.example.com/v1/agent/agt%2F1/trace'],
    ['DELETE', 'https://hub.example.com/v1/agent/agt%2F1'],
    ['GET', 'https://hub.example.com/v1/artifacts/sha%2F1?format=json&offset=0&limit=65536'],
    ['GET', 'https://hub.example.com/v1/artifacts/sha%2F1?format=markdown&offset=128&limit=256'],
  ];

  assert.equal(calls.length, expected.length);
  for (let i = 0; i < expected.length; i++) {
    assert.equal(calls[i]!.method, expected[i]![0]);
    assert.equal(calls[i]!.url, expected[i]![1]);
    assert.equal(calls[i]!.headers.traceparent, TRACE_B);
    if (calls[i]!.body !== undefined) {
      assert.equal('traceparent' in JSON.parse(calls[i]!.body!), false);
    }
  }
});
