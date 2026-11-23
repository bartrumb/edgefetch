import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import test from 'node:test';
import { findRelevantAdapters } from '../src/agent-runner';
import { handleAdminRoute } from '../src/admin';
import { executeCatalogCall, resetCatalogStateForTests } from '../src/catalog';
import { executeCrawlJob, executeMapCall, getCrawlJobStatus } from '../src/map-crawl';
import { handleMcpRequest, truncateResultBodies, type McpServerDeps } from '../src/mcp';
import { createMemoryOAuthStore } from '../src/oauth';
import { validatePublicHttpsTargetUrl } from '../src/overflow';
import { collapseAnimatedCounterTickersLinear, executeScrapeCall, finalizeScrapedMarkdown } from '../src/scrape';
import { executeSearchCall } from '../src/web-search';

function createSqliteD1(sqlite: DatabaseSync): D1Database {
  const makeBound = (sql: string, boundValues: unknown[]) => ({
    bind(...vals: unknown[]) {
      return makeBound(sql, vals);
    },
    async run() {
      const stmt = sqlite.prepare(sql);
      const info = stmt.run(...(boundValues as never[]));
      return { success: true, meta: { changes: Number(info.changes ?? 0) } };
    },
    async first<T = Record<string, unknown>>(col?: string): Promise<T | null> {
      const stmt = sqlite.prepare(sql);
      const row = stmt.get(...(boundValues as never[])) as Record<string, unknown> | undefined;
      if (!row) return null;
      if (col) return (row[col] as T) ?? null;
      return row as T;
    },
    async all<T = Record<string, unknown>>(): Promise<{ results: T[]; success: boolean }> {
      const stmt = sqlite.prepare(sql);
      const rows = stmt.all(...(boundValues as never[])) as T[];
      return { results: rows, success: true };
    },
  });
  return {
    prepare(sql: string) {
      return makeBound(sql, []);
    },
    async batch(stmts: Array<{ run: () => Promise<unknown> }>) {
      const out = [];
      for (const s of stmts) out.push(await s.run());
      return out;
    },
    async exec(sql: string) {
      sqlite.exec(sql);
      return { count: 1, duration: 0 };
    },
  } as unknown as D1Database;
}

test('BugHunt #1, #5, #6, #7, #10, #13, #14: MCP fetch_url & fetch_batch structured policy rejections, per-item batch blocks, redirect classification, and effectivePauseMs', async () => {
  // #1, #13, #14: Decimal, octal, hex IPv4 and public IP literals classify cleanly with distinct reasons
  const decCheck = validatePublicHttpsTargetUrl('https://2130706433/');
  assert.equal(decCheck.ok, false);
  if (!decCheck.ok) assert.equal(decCheck.reason, 'ssrf');

  const octCheck = validatePublicHttpsTargetUrl('https://0177.0.0.1/');
  assert.equal(octCheck.ok, false);
  if (!octCheck.ok) assert.equal(octCheck.reason, 'ssrf');

  const pubIpCheck = validatePublicHttpsTargetUrl('https://8.8.8.8/');
  assert.equal(pubIpCheck.ok, false);
  if (!pubIpCheck.ok) {
    assert.equal(pubIpCheck.reason, 'ip_literal_not_allowed');
    assert.match(pubIpCheck.message, /IP address literals are not allowed/i);
  }

  const deps: McpServerDeps = {
    serverName: 'edgefetch',
    serverVersion: '2.7.4',
    ownerSecret: 'test-owner-secret-token-0123456789',
    oauthStore: createMemoryOAuthStore(),
    allowedTargets: ['auto', 'agent', 'container'],
    defaultTarget: 'auto',
    listFleet: async () => ({ connected: 0, agents: [], affinities: [] }),
    executeFetch: async ({ body }) => {
      const call = JSON.parse(body) as { requests: Array<{ id: string; url: string }> };
      const results = call.requests.map((r) => ({
        id: r.id,
        url: r.url,
        status: 200,
        outcome: 'ok',
        contentType: 'application/json',
        body: '{"ok":true}',
      }));
      return {
        status: 200,
        via: 'agent:site-x86',
        bodyText: JSON.stringify({ results, summary: { total: results.length, byOutcome: { ok: results.length } } }),
      };
    },
  };

  const callMcp = async (name: string, args: Record<string, unknown>) => {
    const resp = await handleMcpRequest(
      new Request('https://hub.example.com/mcp', {
        method: 'POST',
        headers: {
          authorization: 'Bearer test-owner-secret-token-0123456789',
          'content-type': 'application/json',
        },
        body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name, arguments: args } }),
      }),
      new URL('https://hub.example.com/mcp'),
      deps,
    );
    assert.equal(resp.status, 200);
    const rpc = (await resp.json()) as { result: { content: Array<{ text: string }>; isError?: boolean } };
    return {
      isError: Boolean(rpc.result.isError),
      parsed: JSON.parse(rpc.result.content[0]!.text) as Record<string, unknown>,
    };
  };

  // #1 & #13: fetch_url decimal/octal IPv4 returns structured JSON with retryable: false
  for (const badUrl of ['https://2130706433/', 'https://0177.0.0.1/', 'https://8.8.8.8/']) {
    const out = await callMcp('fetch_url', { url: badUrl });
    assert.equal(out.isError, true);
    assert.equal(out.parsed.ok, false);
    assert.equal(out.parsed.outcome, 'blocked');
    assert.equal(out.parsed.retryable, false);
    const blocked = out.parsed.blocked as { reason: string; retryable: boolean; message: string };
    assert.equal(blocked.retryable, false);
    if (badUrl.includes('8.8.8.8')) {
      assert.equal(blocked.reason, 'ip_literal_not_allowed');
    } else {
      assert.equal(blocked.reason, 'ssrf');
    }
  }

  // #7 & #10: fetch_batch with one invalid URL fails ONLY that item while succeeding on valid items, and echoes effectivePauseMs
  const batchOut = await callMcp('fetch_batch', {
    urls: ['https://example.com/a.json', 'https://169.254.169.254/latest/meta-data/', 'https://8.8.8.8/', 'https://example.com/b.json'],
    pauseMs: 0,
    pauseJitterMs: 0,
  });
  assert.equal(batchOut.isError, false);
  assert.equal(batchOut.parsed.effectivePauseMs, 2000);
  assert.equal(typeof batchOut.parsed.politenessFloorNote, 'string');
  const batchResults = batchOut.parsed.results as Array<Record<string, unknown>>;
  assert.equal(batchResults.length, 4);
  assert.equal(batchResults[0]?.outcome, 'ok');
  assert.equal(batchResults[1]?.outcome, 'blocked');
  assert.equal((batchResults[1]?.blocked as { reason: string }).reason, 'ssrf');
  assert.equal(batchResults[2]?.outcome, 'blocked');
  assert.equal((batchResults[2]?.blocked as { reason: string }).reason, 'ip_literal_not_allowed');
  assert.equal(batchResults[3]?.outcome, 'ok');

  // #5 & #6: Synthetic 403 "Forbidden redirect target:" -> blocked/ssrf with zero artifact; https->http redirect -> scheme_downgrade
  const normRedirects = truncateResultBodies({
    results: [
      {
        id: 'r-internal',
        url: 'https://httpbin.org/redirect-to?url=https%3A%2F%2F127.0.0.1%2F',
        status: 403,
        outcome: 'stop',
        problem: 'HTTP 403',
        body: 'Forbidden redirect target: redirect target is an internal address',
        artifact: { blobSha256: 'a'.repeat(64), retention: 'transient' },
      },
      {
        id: 'r-downgrade',
        url: 'https://httpbin.org/redirect-to?url=http%3A%2F%2Fexample.com%2F',
        status: 0,
        outcome: 'blocked_ssrf',
        blockedReason: 'scheme_downgrade',
        problem: 'HTTPS-to-HTTP redirect downgrade is not permitted',
      },
    ],
    summary: { total: 2, byOutcome: { stop: 1, blocked_ssrf: 1 } },
  });
  const nr = normRedirects.results as Array<Record<string, unknown>>;
  assert.equal(nr[0]?.outcome, 'blocked');
  assert.equal((nr[0]?.blocked as { reason: string }).reason, 'ssrf');
  assert.equal(nr[0]?.artifact, undefined);
  assert.equal(nr[0]?.artifactId, undefined);
  assert.equal(nr[0]?.body, undefined);

  assert.equal(nr[1]?.outcome, 'blocked');
  assert.equal((nr[1]?.blocked as { reason: string }).reason, 'scheme_downgrade');
});

test('BugHunt #2, #3, #4, #8, #9, #11, #12, #15 & Animated Counters: end-to-end verification', async () => {
  // #3: Owner crawl returns populated `data` even when IngestWorkflow hasn't populated `fetches`
  const sqlite = new DatabaseSync(':memory:');
  sqlite.exec(`
    CREATE TABLE crawls (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL DEFAULT 'owner',
      root_url TEXT NOT NULL,
      status TEXT NOT NULL,
      options_json TEXT NOT NULL,
      discovered_count INTEGER NOT NULL DEFAULT 0,
      fetched_count INTEGER NOT NULL DEFAULT 0,
      failed_count INTEGER NOT NULL DEFAULT 0,
      created_at INTEGER NOT NULL,
      updated_at INTEGER NOT NULL,
      finished_at INTEGER
    );
    CREATE TABLE pages (id TEXT PRIMARY KEY, url TEXT NOT NULL);
    CREATE TABLE documents (id TEXT PRIMARY KEY, content_sha256 TEXT, format TEXT, pipeline_version INTEGER, title TEXT, r2_key TEXT);
    CREATE TABLE fetches (id TEXT PRIMARY KEY, page_id TEXT, crawl_id TEXT, status INTEGER, outcome TEXT, content_sha256 TEXT, blob_sha256 TEXT, fetched_at INTEGER);
  `);
  const metaDb = createSqliteD1(sqlite);
  const now = Date.now();
  await metaDb
    .prepare(
      `INSERT INTO crawls (id, user_id, root_url, status, options_json, discovered_count, fetched_count, failed_count, created_at, updated_at)
       VALUES ('crw_test_owner', 'owner', 'https://edgefetch.dev/', 'queued', '{"limit":3,"maxDepth":1}', 0, 0, 0, ?, ?)`,
    )
    .bind(now, now)
    .run();

  await executeCrawlJob({
    crawlId: 'crw_test_owner',
    rootUrl: 'https://edgefetch.dev/',
    options: {
      limit: 3,
      maxDepth: 1,
      includePaths: [],
      excludePaths: [],
      allowSubdomains: false,
      allowExternalLinks: false,
      crawlEntireDomain: false,
      ignoreQueryParameters: true,
      deduplicateSimilarURLs: true,
      sitemap: 'skip',
      target: 'auto',
    },
    userId: 'owner',
    env: { META: metaDb },
    executeHubFetch: async (_target, body) => {
      const parsed = JSON.parse(body) as { requests: Array<{ id: string; url: string }> };
      const results = parsed.requests.map((r) => ({
        id: r.id,
        url: r.url,
        status: 200,
        outcome: 'ok',
        contentType: 'text/html',
        body:
          r.url === 'https://edgefetch.dev/'
            ? '<html><head><title>EdgeFetch Home</title></head><body><main><h1>EdgeFetch</h1><a href="/docs/">Docs</a><a href="/site-owners/">Site Owners</a></main></body></html>'
            : `<html><head><title>${r.url}</title></head><body><main><p>Content for ${r.url}</p></main></body></html>`,
      }));
      return { status: 200, via: 'cf', bodyText: JSON.stringify({ results }) };
    },
  });

  const pollOwnerCrawl = await getCrawlJobStatus({ crawlId: 'crw_test_owner', metaDb, userId: 'owner' });
  assert.equal(pollOwnerCrawl.ok, true);
  if (pollOwnerCrawl.ok) {
    assert.equal(pollOwnerCrawl.crawl.status, 'completed');
    assert.equal(pollOwnerCrawl.crawl.fetchedCount, 3);
    const crawlData = pollOwnerCrawl.crawl.data as Array<Record<string, unknown>>;
    assert.equal(crawlData.length, 3);
    assert.equal(crawlData[0]?.url, 'https://edgefetch.dev/');
    assert.equal(crawlData[0]?.title, 'EdgeFetch Home');
    assert.match(String(crawlData[0]?.markdown ?? ''), /EdgeFetch/);
  }

  // #4: `map` retries `container` when `auto` returns all `not_tried`, and returns 503 retryable if still all `not_tried`
  let mapAttempts = 0;
  const mapRecovered = await executeMapCall({
    payload: { url: 'https://edgefetch.dev/', limit: 20 },
    executeHubFetch: async (target, body) => {
      mapAttempts++;
      const parsed = JSON.parse(body) as { requests: Array<{ id: string; url: string }> };
      if (target === 'auto') {
        return {
          status: 200,
          via: 'agent:site-arm64',
          bodyText: JSON.stringify({ results: parsed.requests.map((r) => ({ id: r.id, url: r.url, status: 0, outcome: 'not_tried' })) }),
        };
      }
      return {
        status: 200,
        via: 'cf',
        bodyText: JSON.stringify({
          results: parsed.requests.map((r) => ({
            id: r.id,
            url: r.url,
            status: r.id === 'llms' ? 200 : 404,
            outcome: r.id === 'llms' ? 'ok' : 'not_found',
            body: r.id === 'llms' ? '# EdgeFetch\n- [Docs](https://edgefetch.dev/docs/)\n' : '',
          })),
        }),
      };
    },
  });
  assert.equal(mapAttempts, 2);
  assert.equal(mapRecovered.status, 200);
  assert.equal(mapRecovered.body.ok, true);
  assert.ok((mapRecovered.body.total as number) >= 2);

  const mapAllNotTried = await executeMapCall({
    payload: { url: 'https://edgefetch.dev/', limit: 20, target: 'agent' },
    executeHubFetch: async (_target, body) => {
      const parsed = JSON.parse(body) as { requests: Array<{ id: string; url: string }> };
      return {
        status: 200,
        via: 'agent:site-arm64',
        bodyText: JSON.stringify({ results: parsed.requests.map((r) => ({ id: r.id, url: r.url, status: 0, outcome: 'not_tried' })) }),
      };
    },
  });
  assert.equal(mapAllNotTried.status, 503);
  assert.equal(mapAllNotTried.body.ok, false);
  assert.equal(mapAllNotTried.body.retryable, true);

  // #8, #9, #12: `catalog` `fields:"lean"` strips tags/options/variants, backfills Shopify currency via `/cart.js`, and `maxPages` returns `ok: true, truncated: true`
  resetCatalogStateForTests();
  const catRun = await executeCatalogCall({
    payload: { url: 'https://shoes.example.com/', maxPages: 1, fields: 'lean' },
    env: {},
    sleepFn: async () => undefined,
    executeHubFetch: async (req) => {
      if (req.url.endsWith('/cart.js')) {
        return {
          status: 200,
          outcome: 'ok',
          headers: {},
          body: JSON.stringify({ token: 't', currency: 'USD', item_count: 0 }),
        };
      }
      if (req.url.endsWith('/robots.txt')) {
        return { status: 404, outcome: 'not_found', headers: {}, body: '' };
      }
      const items = Array.from({ length: 250 }, (_, idx) => ({
        id: 1000 + idx,
        title: idx === 0 ? 'Wool Runner' : `Shoe ${idx}`,
        handle: idx === 0 ? 'wool-runner' : `shoe-${idx}`,
        vendor: 'Allbirds',
        product_type: 'Shoes',
        tags: ['wool', 'sustainable'],
        options: [{ name: 'Size', values: ['8', '9', '10'] }],
        images: [{ src: 'https://cdn.shoes.example.com/wool.jpg' }],
        variants: [
          { id: 9000 + idx * 2, sku: `WR-${idx}-8`, title: '8', price: '110.00', available: true },
          { id: 9001 + idx * 2, sku: `WR-${idx}-9`, title: '9', price: '115.00', available: false },
        ],
      }));
      return { status: 200, outcome: 'ok', headers: {}, body: JSON.stringify({ products: items }) };
    },
  });
  assert.equal(catRun.status, 200);
  assert.equal(catRun.body.ok, true);
  assert.equal(catRun.body.truncated, true);
  assert.equal(catRun.body.reason, 'max_pages_reached');

  const pagedLean = await executeCatalogCall({
    payload: { catalogId: catRun.body.catalogId, query: 'wool runner', fields: 'lean' },
    env: {},
    executeHubFetch: async () => ({ status: 404, body: '' }),
  });
  assert.equal(pagedLean.status, 200);
  const leanRec = (pagedLean.body.records as Array<Record<string, unknown>>)[0]!;
  assert.equal(leanRec.title, 'Wool Runner');
  assert.equal(leanRec.currency, 'USD');
  assert.equal(leanRec.priceMin, 110);
  assert.equal(leanRec.priceMax, 115);
  assert.equal(leanRec.variantCount, 2);
  assert.equal('tags' in leanRec, false);
  assert.equal('options' in leanRec, false);
  assert.equal('variants' in leanRec, false);

  const pagedFull = await executeCatalogCall({
    payload: { catalogId: catRun.body.catalogId, query: 'wool runner', fields: 'full' },
    env: {},
    executeHubFetch: async () => ({ status: 404, body: '' }),
  });
  const fullRec = (pagedFull.body.records as Array<{ variants: Array<{ currency: string | null }> }>)[0]!;
  assert.equal(fullRec.variants[0]?.currency, 'USD');

  // #11: `find_extractors` query "CVE" does NOT pad unrelated developer adapters (Apple App Store / crates.io)
  const cveMatches = findRelevantAdapters({ query: 'CVE', limit: 10 });
  assert.ok(cveMatches.length >= 1);
  assert.ok(cveMatches[0]?.id === 'nist-nvd' || cveMatches[0]?.id === 'osv-cve');
  for (const m of cveMatches) {
    assert.notEqual(m.id, 'apple-app-store');
    assert.notEqual(m.id, 'crates-io');
  }

  // #15: `search` `via` does not claim `+serper+brave` when external providers contributed 0 site-filtered hits
  const searchOut = await executeSearchCall({
    payload: { query: 'site:edgefetch.dev docs', limit: 3 },
    env: { BRAVE_API_KEY: 'dummy-brave-key' },
    fetchFn: async () =>
      Response.json({
        web: {
          results: [{ title: 'Unrelated Domain', url: 'https://other.example.org/post', description: 'Unrelated' }],
        },
      }),
    executeHubFetch: async (_t, body) => {
      const parsed = JSON.parse(body) as { requests: Array<{ id: string; url: string }> };
      return {
        status: 200,
        via: 'cf',
        bodyText: JSON.stringify({
          results: parsed.requests.map((r) => ({
            id: r.id,
            url: r.url,
            status: r.id === 'llms' ? 200 : 404,
            outcome: r.id === 'llms' ? 'ok' : 'not_found',
            body: r.id === 'llms' ? '# EdgeFetch\n- [Docs](https://edgefetch.dev/docs/): Documentation\n' : '',
          })),
        }),
      };
    },
  });
  assert.equal(searchOut.status, 200);
  const viaStr = String(searchOut.via ?? searchOut.body.via ?? '');
  assert.ok(viaStr.includes('edge-map'), `expected edge-map in via, got ${viaStr}`);
  assert.equal(viaStr.includes('brave'), false, `unexpected +brave on 0-hit external result: ${viaStr}`);

  // Live `/admin/login` regression: privacy browsers/extensions that rewrite `Origin: null` on a genuine
  // `Sec-Fetch-Site: same-origin` form POST must succeed, while `Origin: null` with `cross-site`, `same-site`,
  // or missing `Sec-Fetch-Site` MUST still fail closed (`403 invalid_origin`), and `GET /admin/login` redirects to `/admin`.
  const adminOwnerTok = 'admin-owner-secret-0123456789abcdef';
  const adminOAuthStore = createMemoryOAuthStore();
  const adminDeps = {
    serviceName: 'EdgeFetch Hub',
    mcpSlug: 'edgefetch',
    ownerSecret: adminOwnerTok,
    oauthStore: adminOAuthStore,
    allowedTargets: ['auto' as const],
    defaultTarget: 'auto' as const,
    getState: async () => ({ connected: 0, agents: [], affinities: [], grants: [] }),
    clearAffinities: async () => undefined,
    revokeGrant: async () => false,
    executeFetch: async () => ({ status: 200, via: 'hub', bodyText: '{}' }),
  };
  const adminLoginUrl = new URL('https://hub.example.test/admin/login');
  const getLoginRes = await handleAdminRoute(new Request(adminLoginUrl, { method: 'GET' }), adminLoginUrl, adminDeps);
  assert.equal(getLoginRes?.status, 302);
  assert.equal(getLoginRes?.headers.get('location'), '/admin');

  for (const badHdrs of [
    { origin: 'null', 'sec-fetch-site': 'cross-site' },
    { origin: 'null', 'sec-fetch-site': 'same-site' },
    { origin: 'null' },
    { origin: 'https://evil.example', 'sec-fetch-site': 'same-origin' },
    { origin: 'https://sub.example.test', 'sec-fetch-site': 'same-site' },
  ]) {
    const blockedRes = await handleAdminRoute(
      new Request(adminLoginUrl, {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded', ...badHdrs },
        body: new URLSearchParams({ token: adminOwnerTok }).toString(),
      }),
      adminLoginUrl,
      adminDeps,
    );
    assert.equal(blockedRes?.status, 403, `Expected 403 for headers ${JSON.stringify(badHdrs)}`);
  }

  const sameOriginNullLogin = await handleAdminRoute(
    new Request(adminLoginUrl, {
      method: 'POST',
      headers: {
        'content-type': 'application/x-www-form-urlencoded',
        origin: 'null',
        'sec-fetch-site': 'same-origin',
        'sec-fetch-mode': 'navigate',
      },
      body: new URLSearchParams({ token: adminOwnerTok }).toString(),
    }),
    adminLoginUrl,
    adminDeps,
  );
  assert.equal(sameOriginNullLogin?.status, 302);
  assert.equal(sameOriginNullLogin?.headers.get('location'), '/admin');
  assert.match(sameOriginNullLogin?.headers.get('set-cookie') ?? '', /^__Host-ef_admin_session=/);

  // #2: `scrape` `renderMode: "auto"` surfaces actionable `warnings` when `browser-v1` is off (`fat_agent_required`) on a thin SPA
  const thinSpa = await executeScrapeCall({
    payload: { url: 'https://spa.example.com/', renderMode: 'auto', discoverLlmsTxt: false },
    env: {},
    executeHubFetch: async (target) => {
      if (target === 'agent') {
        return { status: 503, via: 'hub', bodyText: JSON.stringify({ error: 'fat_agent_required' }) };
      }
      return {
        status: 200,
        via: 'cf',
        bodyText: JSON.stringify({
          results: [
            {
              id: 's1',
              url: 'https://spa.example.com/',
              status: 200,
              outcome: 'ok',
              contentType: 'text/html',
              body: '<html><head><title>App</title><script src="/bundle.js"></script></head><body><div id="root"></div></body></html>',
            },
          ],
        }),
      };
    },
  });
  assert.equal(thinSpa.status, 200);
  const warnings = (thinSpa.body.warnings ?? []) as string[];
  assert.ok(warnings.some((w) => w.includes('allow_no_sandbox_browser')));

  // Minor animated counter dedup ("382,831,172 3 8 2, 8 3 1, 1 7 2" -> "382,831,172")
  assert.equal(
    collapseAnimatedCounterTickersLinear('Requests served: 382,831,172 3 8 2, 8 3 1, 1 7 2 today.'),
    'Requests served: 382,831,172 today.',
  );
  const finCounter = finalizeScrapedMarkdown('Total: 382,831,172 3 8 2, 8 3 1, 1 7 2 requests', {
    isPdf: false,
    includeImages: true,
  });
  assert.equal(finCounter.markdown, 'Total: 382,831,172 requests');
});
