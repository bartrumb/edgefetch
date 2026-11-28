import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import test from 'node:test';

import metaSql1 from '../migrations/meta/0001_tracking.sql';
import metaSql2 from '../migrations/meta/0002_multiuser.sql';
import metaSql3 from '../migrations/meta/0003_round7_multiuser_hardening.sql';
import searchSql1 from '../migrations/search/0001_fts.sql';

import hubWorker from '../src/index.ts';
import { LocalAgentHubCoordinator } from './stubs/cf-storage-mocks.ts';
import {
  buildCanonicalMcpToolSchemas,
  handleMcpRequest,
  MCP_TOOL_SCHEMAS,
  truncateResultBodies,
  type McpServerDeps,
} from '../src/mcp.ts';
import { createMemoryOAuthStore } from '../src/oauth.ts';
import {
  cloudflareOverflowFetch,
  DNS_NOT_FOUND_MESSAGE,
  isDnsNotFoundError,
  resetOverflowRobotsCacheForTests,
  scrubResolverIpFromError,
} from '../src/overflow.ts';
import {
  closeUnclosedCodeAfterSlice,
  executeInteractCall,
  executeScrapeCall,
  extractHtmlDocument,
  extractStructuredJsonFromPageWithDiagnostics,
} from '../src/scrape.ts';
import { D1FtsSearchIndex, executeExtractCall } from '../src/search-index.ts';
import { handleArtifactGetRequest, readArtifactPage, sanitizeFtsQuery } from '../src/storage.ts';
import { HUB_VERSION } from '../src/update-check.ts';

function createMemoryR2Bucket(): R2Bucket {
  const store = new Map<string, { bytes: Uint8Array; httpMetadata?: Record<string, string>; customMetadata?: Record<string, string>; uploaded: Date }>();
  return {
    async put(key: string, value: unknown, options?: { httpMetadata?: Record<string, string>; customMetadata?: Record<string, string> }) {
      let bytes: Uint8Array;
      if (typeof value === 'string') {
        bytes = new TextEncoder().encode(value);
      } else if (value instanceof Uint8Array) {
        bytes = new Uint8Array(value);
      } else if (value instanceof ArrayBuffer) {
        bytes = new Uint8Array(value);
      } else if (value && typeof (value as ReadableStream<Uint8Array>).getReader === 'function') {
        const reader = (value as ReadableStream<Uint8Array>).getReader();
        const chunks: Uint8Array[] = [];
        let total = 0;
        for (;;) {
          const { done, value: ch } = await reader.read();
          if (done) break;
          if (ch) {
            chunks.push(ch);
            total += ch.byteLength;
          }
        }
        bytes = new Uint8Array(total);
        let off = 0;
        for (const c of chunks) {
          bytes.set(c, off);
          off += c.byteLength;
        }
      } else {
        bytes = new Uint8Array(0);
      }
      const entry = {
        bytes,
        httpMetadata: options?.httpMetadata,
        customMetadata: options?.customMetadata,
        uploaded: new Date(),
      };
      store.set(key, entry);
      return { key, size: bytes.byteLength, uploaded: entry.uploaded } as unknown as R2Object;
    },
    async get(key: string) {
      const hit = store.get(key);
      if (!hit) return null;
      return {
        key,
        size: hit.bytes.byteLength,
        uploaded: hit.uploaded,
        httpMetadata: hit.httpMetadata,
        customMetadata: hit.customMetadata,
        body: new ReadableStream<Uint8Array>({
          start(ctrl) {
            ctrl.enqueue(hit.bytes);
            ctrl.close();
          },
        }),
        async text() {
          return new TextDecoder().decode(hit.bytes);
        },
        async json() {
          return JSON.parse(new TextDecoder().decode(hit.bytes));
        },
        async arrayBuffer() {
          return hit.bytes.buffer.slice(hit.bytes.byteOffset, hit.bytes.byteOffset + hit.bytes.byteLength);
        },
      } as unknown as R2ObjectBody;
    },
    async head(key: string) {
      const hit = store.get(key);
      if (!hit) return null;
      return {
        key,
        size: hit.bytes.byteLength,
        uploaded: hit.uploaded,
        httpMetadata: hit.httpMetadata,
        customMetadata: hit.customMetadata,
      } as unknown as R2Object;
    },
    async delete(keys: string | string[]) {
      for (const k of Array.isArray(keys) ? keys : [keys]) store.delete(k);
    },
  } as unknown as R2Bucket;
}

function createSqliteD1(schemaSql: string): D1Database {
  const sqlite = new DatabaseSync(':memory:');
  sqlite.exec(schemaSql);
  const makeStmt = (sql: string, bound: unknown[] = []): D1PreparedStatement => ({
    bind(...values: unknown[]) {
      return makeStmt(sql, values);
    },
    async first<T = Record<string, unknown>>(colName?: string): Promise<T | null> {
      const row = sqlite.prepare(sql).get(...(bound as never[])) as Record<string, unknown> | undefined;
      if (!row) return null;
      if (colName) return (row[colName] as T) ?? null;
      return row as T;
    },
    async all<T = Record<string, unknown>>() {
      const results = sqlite.prepare(sql).all(...(bound as never[])) as T[];
      return { success: true, meta: { rows_read: results.length, rows_written: 0, size_after: 4096 }, results } as unknown as D1Result<T>;
    },
    async run() {
      const info = sqlite.prepare(sql).run(...(bound as never[]));
      return {
        success: true,
        meta: { rows_read: 0, rows_written: Number(info.changes ?? 0), size_after: 4096 },
        results: [],
      } as unknown as D1Result;
    },
    async raw() {
      return [];
    },
  });
  return {
    prepare(sql: string) {
      return makeStmt(sql);
    },
    async batch<T = unknown>(statements: D1PreparedStatement[]) {
      const out: D1Result<T>[] = [];
      for (const st of statements) {
        out.push((await st.run()) as unknown as D1Result<T>);
      }
      return out;
    },
    async exec(sql: string) {
      sqlite.exec(sql);
      return { count: 1, duration: 0 };
    },
    async dump() {
      return new ArrayBuffer(0);
    },
  } as unknown as D1Database;
}

const META_SQL = `${metaSql1}\n${metaSql2}\n${metaSql3}`;
const SEARCH_SQL = searchSql1;

test('A.1: interact supports maxChars/offset paging (closing unclosed fences) and surfaces urlChanged/domChanged/no_effect warnings', async () => {
  const longCodeHtml =
    '<!doctype html><html><head><title>Interactive Guide</title></head><body><main>' +
    '<h1>Interactive Guide</h1><p>Introductory paragraph before code block.</p>' +
    '<pre><code class="language-ts">' +
    Array.from({ length: 30 }, (_, i) => `const step${i} = "line_${i}_value_abcdef";`).join('\n') +
    '</code></pre>' +
    '<p>Trailing conclusion paragraph after the fenced code block.</p>' +
    '</main></body></html>';

  const page1 = await executeInteractCall({
    payload: {
      url: 'https://docs.example.com/guide',
      maxChars: 220,
      offset: 0,
      actions: [{ type: 'click', selector: '#non-interactive-div' }],
    },
    env: {},
    executeHubFetch: async () => ({
      status: 200,
      via: 'agent:site-fat',
      bodyText: JSON.stringify({
        results: [
          {
            id: 'interact-1',
            url: 'https://docs.example.com/guide',
            finalUrl: 'https://docs.example.com/guide',
            status: 200,
            outcome: 'ok',
            contentType: 'text/html',
            body: longCodeHtml,
            actionResults: [{ index: 0, type: 'click', selector: '#non-interactive-div', urlChanged: false, domChanged: false }],
          },
        ],
      }),
    }),
  });

  assert.equal(page1.status, 200);
  assert.equal(page1.body.truncated, true);
  assert.equal(page1.body.offset, 0);
  assert.equal(typeof page1.body.totalChars, 'number');
  assert.ok((page1.body.remainingChars as number) > 0);
  assert.equal(typeof page1.body.nextOffset, 'number');

  const md1 = String(page1.body.markdown);
  const fenceMatches = md1.match(/^```/gm) ?? [];
  assert.equal(fenceMatches.length % 2, 0, 'Truncated fenced code block in interact must be cleanly closed');

  const actions = page1.body.actions as Array<Record<string, unknown>>;
  assert.equal(actions[0]?.urlChanged, false);
  assert.equal(actions[0]?.domChanged, false);
  assert.equal(actions[0]?.effect, 'no_effect');
  assert.ok(Array.isArray(page1.body.warnings) && (page1.body.warnings as string[]).length > 0);
  assert.match((page1.body.warnings as string[])[0]!, /no_effect|no URL or DOM change/i);

  // Page 2 using nextOffset
  const page2 = await executeInteractCall({
    payload: {
      url: 'https://docs.example.com/guide',
      offset: page1.body.nextOffset,
      maxChars: 5000,
    },
    env: {},
    executeHubFetch: async () => ({
      status: 200,
      via: 'agent:site-fat',
      bodyText: JSON.stringify({
        results: [
          {
            id: 'interact-1',
            url: 'https://docs.example.com/guide',
            finalUrl: 'https://docs.example.com/guide',
            status: 200,
            outcome: 'ok',
            contentType: 'text/html',
            body: longCodeHtml,
          },
        ],
      }),
    }),
  });
  assert.equal(page2.status, 200);
  assert.equal(page2.body.truncated, false);
  assert.equal(page2.body.remainingChars, 0);
  assert.equal(page2.body.nextOffset, null);
  assert.match(String(page2.body.markdown), /Trailing conclusion paragraph/);

  assert.equal(closeUnclosedCodeAfterSlice('Hello `inline_code'), 'Hello `inline_code`');
});

test('A.2: dns_not_found returns non-retryable NXDOMAIN error (never robots_unreachable) and redacts resolver IPs', async () => {
  resetOverflowRobotsCacheForTests();
  assert.equal(
    scrubResolverIpFromError('Get "https://dead.invalid/robots.txt": dial tcp: lookup dead.invalid on 127.0.0.11:53: no such host'),
    'Get "https://dead.invalid/robots.txt": dial tcp: lookup dead.invalid: no such host',
  );
  assert.equal(isDnsNotFoundError('stop', 'lookup dead.invalid on 127.0.0.11:53: no such host'), true);

  // 1) overflow.ts when /robots.txt lookup fails with ENOTFOUND / no such host
  const ovRes = await cloudflareOverflowFetch(
    JSON.stringify({
      maxSeconds: 15,
      options: { includeBody: true, respectRobots: true },
      requests: [{ id: 'nx-1', url: 'https://nonexistent-domain-xyz-98765.example/page', kind: 'page' }],
    }),
    'EdgeFetch/2.7.1',
    'hub.example.com',
    {
      useSharedRobotsCache: false,
      fetchFn: async () => {
        throw new Error('dial tcp: lookup nonexistent-domain-xyz-98765.example on 127.0.0.11:53: no such host');
      },
    },
  );
  assert.equal(ovRes.status, 200);
  const ovBody = (await ovRes.json()) as { results: Array<Record<string, unknown>>; summary: { byOutcome: Record<string, number> } };
  assert.equal(ovBody.results[0]?.outcome, 'dns_not_found');
  assert.equal(ovBody.results[0]?.retryable, false);
  assert.equal(ovBody.results[0]?.message, DNS_NOT_FOUND_MESSAGE);
  assert.equal(String(ovBody.results[0]?.problem).includes('127.0.0.11'), false);
  assert.equal(ovBody.summary.byOutcome.dns_not_found, 1);

  // 2) scrape.ts when Go returns stop/robots_unreachable wrapping a DNS NXDOMAIN lookup failure
  const scrapeNx = await executeScrapeCall({
    payload: { url: 'https://nxdomain-audit-check.example/docs' },
    env: {},
    executeHubFetch: async () => ({
      status: 200,
      via: 'agent:site-1',
      bodyText: JSON.stringify({
        results: [
          {
            id: 'scrape-1',
            url: 'https://nxdomain-audit-check.example/docs',
            status: 0,
            outcome: 'stop',
            problem: 'robots_unreachable: lookup nxdomain-audit-check.example on 127.0.0.11:53: no such host',
          },
        ],
      }),
    }),
  });
  assert.equal(scrapeNx.status, 502);
  assert.equal(scrapeNx.body.ok, false);
  assert.equal(scrapeNx.body.error, 'dns_not_found');
  assert.equal(scrapeNx.body.retryable, false);
  assert.equal(scrapeNx.body.message, DNS_NOT_FOUND_MESSAGE);
  assert.equal(scrapeNx.body.blocked, undefined);
  assert.equal(JSON.stringify(scrapeNx.body).includes('127.0.0.11'), false);

  // 3) mcp.ts truncateResultBodies normalizes Go's NXDOMAIN error and strips resolver IP
  const mcpTrunc = truncateResultBodies({
    results: [
      {
        id: 'm1',
        url: 'https://nxdomain-audit-check.example/',
        status: 0,
        outcome: 'stop',
        problem: 'robots_unreachable: dial tcp: lookup nxdomain-audit-check.example on 10.0.0.53:53: Name or service not known',
      },
    ],
    summary: { total: 1, byOutcome: { stop: 1 }, byStatus: { '0': 1 } },
  });
  const mcpItem = (mcpTrunc.results as Array<Record<string, unknown>>)[0]!;
  assert.equal(mcpItem.outcome, 'dns_not_found');
  assert.equal(mcpItem.error, 'dns_not_found');
  assert.equal(mcpItem.retryable, false);
  assert.equal(mcpItem.blocked, undefined);
  assert.equal(JSON.stringify(mcpTrunc).includes('10.0.0.53'), false);
  assert.equal((mcpTrunc.summary as { byOutcome: Record<string, number> }).byOutcome.dns_not_found, 1);
});

test('R14: cold public scrapes never issue a blind R2 GET on the options cache (index row gates it); warm ones still hit', async () => {
  const inner = createMemoryR2Bucket();
  const cacheGets: string[] = [];
  const bucket = new Proxy(inner, {
    get(target, prop, receiver) {
      if (prop === 'get') {
        return async (key: string, ...rest: unknown[]) => {
          if (String(key).includes('/scrape-cache/')) cacheGets.push(String(key));
          return (target as unknown as { get: (...a: unknown[]) => unknown }).get(key, ...rest);
        };
      }
      const v = Reflect.get(target, prop, receiver);
      return typeof v === 'function' ? v.bind(target) : v;
    },
  });
  const metaDb = createSqliteD1(META_SQL);
  let fetchCalls = 0;
  const hub = async () => {
    fetchCalls++;
    return {
      status: 200,
      via: 'agent:site-1',
      bodyText: JSON.stringify({
        results: [
          {
            id: 'scrape-1',
            url: 'https://r14.example.com/doc',
            finalUrl: 'https://r14.example.com/doc',
            status: 200,
            outcome: 'ok',
            contentType: 'text/html; charset=utf-8',
            body: '<!doctype html><html><head><title>R14</title></head><body><main><h1>R14</h1><p>Body text for the index test.</p></main></body></html>',
          },
        ],
      }),
    };
  };
  const env = { ARTIFACTS: bucket as unknown as R2Bucket, META: metaDb };

  const cold = await executeScrapeCall({ payload: { url: 'https://r14.example.com/doc', maxAgeMs: 60_000 }, env, executeHubFetch: hub });
  assert.equal(cold.status, 200);
  assert.equal(cold.body.cached, false);
  assert.deepEqual(cacheGets, [], 'a cold scrape must not GET a scrape-cache key that was never written');

  const warm = await executeScrapeCall({ payload: { url: 'https://r14.example.com/doc', maxAgeMs: 60_000 }, env, executeHubFetch: hub });
  assert.equal(warm.body.cached, true, 'the write upserted the index row, so the next lookup reads R2 and hits');
  assert.equal(fetchCalls, 1);
  assert.equal(cacheGets.length, 1);

  // A different, never-written option set is again gated without touching R2.
  cacheGets.length = 0;
  const otherOpts = await executeScrapeCall({
    payload: { url: 'https://r14.example.com/doc', onlyMainContent: false, maxAgeMs: 60_000 },
    env,
    executeHubFetch: hub,
  });
  assert.equal(otherOpts.body.cached, false);
  assert.deepEqual(cacheGets, []);
});

test('A.3: scrape cache key includes output-affecting options and preserves consistent response schema', async () => {
  const bucket = createMemoryR2Bucket();
  const metaDb = createSqliteD1(META_SQL);
  const pageHtml =
    '<!doctype html><html lang="en"><head><title>Cache Parity Doc</title><link rel="icon" href="/icon.png"></head>' +
    '<body><nav><a href="/nav-item">Site Navigation Chrome</a></nav>' +
    '<main><h1 id="intro">Main Heading</h1><p>Primary article body text with clear prose.</p>' +
    '<div id="extra-box"><p>Extra box details.</p></div></main>' +
    '<footer>Footer copyright notice</footer></body></html>';

  let fetchCalls = 0;
  const mockHubFetch = async () => {
    fetchCalls++;
    return {
      status: 200,
      via: 'agent:site-1',
      bodyText: JSON.stringify({
        results: [
          {
            id: 'scrape-1',
            url: 'https://cache-test.example.com/doc',
            finalUrl: 'https://cache-test.example.com/doc',
            status: 200,
            outcome: 'ok',
            contentType: 'text/html; charset=utf-8',
            body: pageHtml,
          },
        ],
      }),
    };
  };

  // 1) Fresh default scrape (onlyMainContent: true)
  const freshMain = await executeScrapeCall({
    payload: { url: 'https://cache-test.example.com/doc', maxAgeMs: 60_000 },
    env: { ARTIFACTS: bucket, META: metaDb },
    executeHubFetch: mockHubFetch,
  });
  assert.equal(freshMain.status, 200);
  assert.equal(freshMain.body.cached, false);
  assert.equal(fetchCalls, 1);
  assert.equal(String(freshMain.body.markdown).includes('Site Navigation Chrome'), false);

  // 2) Cached hit with identical options -> returns same schema fields as fresh scrape!
  const cachedMain = await executeScrapeCall({
    payload: { url: 'https://cache-test.example.com/doc', maxAgeMs: 60_000 },
    env: { ARTIFACTS: bucket, META: metaDb },
    executeHubFetch: mockHubFetch,
  });
  assert.equal(cachedMain.status, 200);
  assert.equal(cachedMain.body.cached, true);
  assert.equal(fetchCalls, 1, 'Identical options within maxAgeMs must hit cache');
  for (const key of ['finalUrl', 'title', 'rendered', 'wordCount', 'favicon', 'contentType', 'metadata']) {
    assert.deepEqual(
      cachedMain.body[key],
      key === 'metadata'
        ? { ...(freshMain.body.metadata as Record<string, unknown>), lastFetchedAt: (cachedMain.body.metadata as Record<string, unknown>).lastFetchedAt, canonicalUrl: 'https://cache-test.example.com/doc' }
        : freshMain.body[key],
      `Cached scrape field "${key}" must match fresh scrape`,
    );
  }

  // 3) Non-default `onlyMainContent: false` MUST NOT collide with `onlyMainContent: true` cache!
  const fullPageScrape = await executeScrapeCall({
    payload: { url: 'https://cache-test.example.com/doc', onlyMainContent: false, maxAgeMs: 60_000 },
    env: { ARTIFACTS: bucket, META: metaDb },
    executeHubFetch: mockHubFetch,
  });
  assert.equal(fullPageScrape.status, 200);
  assert.equal(fullPageScrape.body.cached, false);
  assert.equal(fetchCalls, 2, 'onlyMainContent: false must bypass onlyMainContent: true cache');
  assert.match(String(fullPageScrape.body.markdown), /Site Navigation Chrome/);

  // 4) Non-default `includeTags: ['#extra-box']` MUST NOT collide with prior caches!
  const includeTagScrape = await executeScrapeCall({
    payload: { url: 'https://cache-test.example.com/doc', includeTags: ['#extra-box'], maxAgeMs: 60_000 },
    env: { ARTIFACTS: bucket, META: metaDb },
    executeHubFetch: mockHubFetch,
  });
  assert.equal(fetchCalls, 3);
  assert.equal(String(includeTagScrape.body.markdown).trim(), 'Extra box details.');

  // 5) H4 + OptionsScrapeCache tenant & credential isolation:
  //    - Custom cookies/headers or non-owner userId MUST force visibility: 'private'
  //    - MUST NOT read the public OptionsScrapeCache populated above
  //    - MUST NOT poison public OptionsScrapeCache, and truncated cached markdownArtifactId stays tenant-scoped!
  const privCookieScrape = await executeScrapeCall({
    payload: {
      url: 'https://cache-test.example.com/doc',
      onlyMainContent: false,
      cookies: [{ name: 'session', value: 'secret-cookie' }],
      maxAgeMs: 60_000,
    },
    env: { ARTIFACTS: bucket, META: metaDb },
    executeHubFetch: async () => {
      fetchCalls++;
      return {
        status: 200,
        via: 'agent:site-1',
        bodyText: JSON.stringify({
          results: [
            {
              id: 'scrape-priv-1',
              url: 'https://cache-test.example.com/doc',
              finalUrl: 'https://cache-test.example.com/doc',
              status: 200,
              outcome: 'ok',
              contentType: 'text/html; charset=utf-8',
              body: '<!doctype html><html><body><main><p>' + 'Private authenticated secret paragraph. '.repeat(20) + '</p></main></body></html>',
            },
          ],
        }),
      };
    },
    userId: 'gh_42',
  });
  assert.equal(privCookieScrape.body.cached, false);
  assert.equal(privCookieScrape.body.visibility, 'private');
  assert.equal(fetchCalls, 4, 'Authenticated/tenant scrape must never read public OptionsScrapeCache');

  // Truncated private cache hit for gh_42 resolves readArtifactPage for gh_42 ONLY (404 for gh_99 and owner public):
  const privCachedTrunc = await executeScrapeCall({
    payload: {
      url: 'https://cache-test.example.com/doc',
      onlyMainContent: false,
      cookies: [{ name: 'session', value: 'secret-cookie' }],
      maxChars: 120,
      maxAgeMs: 60_000,
    },
    env: { ARTIFACTS: bucket, META: metaDb },
    executeHubFetch: mockHubFetch,
    userId: 'gh_42',
  });
  assert.equal(privCachedTrunc.body.cached, true);
  assert.equal(privCachedTrunc.body.visibility, 'private');
  assert.equal(privCachedTrunc.body.truncated, true);
  const privMdId = String(privCachedTrunc.body.markdownArtifactId);
  assert.match(privMdId, /^md:[0-9a-f]{64}$/);

  const gh42Art = await readArtifactPage({ bucket, blobSha256: privMdId, userId: 'gh_42' });
  assert.equal(gh42Art.ok, true);
  const gh99Art = await readArtifactPage({ bucket, blobSha256: privMdId, userId: 'gh_99' });
  assert.equal(gh99Art.ok, false);
  assert.equal(gh99Art.status, 404);
  const publicArt = await readArtifactPage({ bucket, blobSha256: privMdId, userId: 'owner' });
  assert.equal(publicArt.ok, false);
  assert.equal(publicArt.status, 404);
});

test('A.4: heuristic JSON-Schema extraction matches headerName + <dl> directives, never omits properties, and warns on unmatched fields', async () => {
  const mdnCacheControlHtml =
    '<!doctype html><html><head><title>Cache-Control - HTTP | MDN</title></head><body><main>' +
    '<h1>Cache-Control</h1>' +
    '<p>The Cache-Control HTTP header field holds directives for caching in both requests and responses.</p>' +
    '<h2>Request directives</h2>' +
    '<dl><dt><code>max-age</code></dt><dd>Maximum age in seconds.</dd><dt><code>no-cache</code></dt><dd>Validate before release.</dd></dl>' +
    '<h2>Response directives</h2>' +
    '<dl><dt><code>public</code></dt><dd>May be stored by any cache.</dd><dt><code>immutable</code></dt><dd>Response body will not change.</dd></dl>' +
    '<h2>Browser compatibility</h2>' +
    '<ul><li><a href="#compat">See full compatibility</a></li><li><a href="#more">Learn more</a></li></ul>' +
    '</main></body></html>';

  const doc = extractHtmlDocument(mdnCacheControlHtml, { baseUrl: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cache-Control', onlyMainContent: true });
  const diag = extractStructuredJsonFromPageWithDiagnostics(mdnCacheControlHtml, doc, {
    type: 'object',
    properties: {
      headerName: { type: 'string' },
      directives: { type: 'array', items: { type: 'string' } },
      rfcSectionSummary: { type: 'string' },
    },
  });

  assert.equal(diag.data.headerName, 'Cache-Control');
  assert.deepEqual(diag.data.directives, ['max-age', 'no-cache', 'public', 'immutable']);
  assert.equal('rfcSectionSummary' in diag.data, true, 'Declared schema properties must never be silently omitted');
  assert.equal(diag.data.rfcSectionSummary, null);
  assert.ok(diag.warnings.length > 0 && /agent/i.test(diag.warnings[0]!));

  // Verify scrape response surfaces jsonExtractionMode: 'heuristic' and warnings
  const scrapeJsonRes = await executeScrapeCall({
    payload: {
      url: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cache-Control',
      formats: [
        'markdown',
        {
          type: 'json',
          schema: {
            type: 'object',
            properties: {
              headerName: { type: 'string' },
              directives: { type: 'array', items: { type: 'string' } },
              nonExistentSemanticField: { type: 'string' },
            },
          },
        },
      ],
    },
    env: {},
    executeHubFetch: async () => ({
      status: 200,
      via: 'agent:site-1',
      bodyText: JSON.stringify({
        results: [
          {
            id: 'scrape-1',
            url: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cache-Control',
            status: 200,
            outcome: 'ok',
            contentType: 'text/html',
            body: mdnCacheControlHtml,
          },
        ],
      }),
    }),
  });
  assert.equal(scrapeJsonRes.status, 200);
  assert.equal(scrapeJsonRes.body.jsonExtractionMode, 'heuristic');
  const jsonOut = scrapeJsonRes.body.json as Record<string, unknown>;
  assert.equal(jsonOut.headerName, 'Cache-Control');
  assert.equal(jsonOut.nonExistentSemanticField, null);
  assert.equal((jsonOut.directives as string[]).includes('See full compatibility'), false);
  assert.ok(Array.isArray(scrapeJsonRes.body.warnings) && (scrapeJsonRes.body.warnings as string[]).length > 0);
});

test('A.5: wrangler.toml binds CRAWL CrawlWorkflow in production, and MCP crawl dispatches asynchronously to env.CRAWL without leaking principal/pollUrl', async () => {
  const wranglerToml = readFileSync(resolve('wrangler.toml'), 'utf8');
  assert.match(wranglerToml, /\[\[env\.production\.workflows\]\][\s\S]*?binding\s*=\s*"CRAWL"[\s\S]*?class_name\s*=\s*"CrawlWorkflow"/);

  const metaDb = createSqliteD1(META_SQL);
  const searchDb = createSqliteD1(SEARCH_SQL);
  const bucket = createMemoryR2Bucket();
  const coordinator = new LocalAgentHubCoordinator(':memory:');
  const workflowCreatedIds: string[] = [];

  const env = {
    AGENT_HUB: coordinator.asNamespace() as never,
    CALLER_TOKEN: 'owner-secret-token-for-crawl-audit-test-1234',
    META: metaDb,
    SEARCH: searchDb,
    ARTIFACTS: bucket,
    CRAWL: {
      async create(opts?: { id?: string }) {
        if (opts?.id) workflowCreatedIds.push(opts.id);
        return { id: opts?.id ?? 'wf_1' };
      },
    },
    SAFE_PUBLIC_FETCH: (async (u: RequestInfo | URL) => {
      const s = String(u);
      if (s.endsWith('/robots.txt')) return new Response('User-agent: *\nAllow: /\n', { status: 200 });
      if (s.endsWith('/sitemap.xml')) return new Response('not found', { status: 404 });
      return new Response('<html><head><title>IANA Example</title></head><body><h1>IANA Domains</h1><p>Reserved domains documentation.</p></body></html>', {
        status: 200,
        headers: { 'content-type': 'text/html; charset=utf-8' },
      });
    }) as typeof fetch,
  };

  for (const [idx, limit] of [2, 10].entries()) {
    const mcpReq = new Request('https://hub.example.com/mcp', {
      method: 'POST',
      headers: {
        authorization: `Bearer ${env.CALLER_TOKEN}`,
        'content-type': 'application/json',
      },
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: idx + 1,
        method: 'tools/call',
        params: {
          name: 'crawl',
          arguments: { url: 'https://iana.example.org/', limit, maxDepth: 1 },
        },
      }),
    });
    const mcpRes = await hubWorker.fetch(mcpReq, env as never, { waitUntil() {}, passThroughOnException() {} } as never);
    assert.equal(mcpRes.status, 200);
    const rpc = (await mcpRes.json()) as { result: { content: Array<{ text: string }> } };
    const crawlBody = JSON.parse(rpc.result.content[0]!.text) as Record<string, unknown>;
    assert.equal(crawlBody.status, 'queued');
    assert.equal(crawlBody.crawlId, workflowCreatedIds[idx]);
    assert.equal(crawlBody.principal, undefined);
    assert.equal(crawlBody.pollUrl, undefined);
    assert.match(String(crawlBody.pollHint), /crawlId/);
  }
});

test('B.1 & B.2: scriptless static HTML never triggers browser-auto, preserves primary <h1>, and strips Wikipedia edit chrome & RFC pilcrows', async () => {
  // B.1: example.com pure static HTML (zero <script> tags) + <header><h1>Example Domain</h1></header>
  const exampleHtml =
    '<!doctype html><html><head><title>Example Domain</title></head>' +
    '<body><header><h1>Example Domain</h1></header><div><p>This domain is for use in documentation examples without needing permission.</p>' +
    '<p><a href="https://iana.org/domains/example">Learn more</a></p></div></body></html>';

  const kindsCalled: string[] = [];
  const exRes = await executeScrapeCall({
    payload: { url: 'https://example.com/' },
    env: {},
    executeHubFetch: async (_target, rawBody) => {
      const req = (JSON.parse(rawBody) as { requests: Array<{ kind: string; renderMode?: string }> }).requests[0]!;
      kindsCalled.push(`${req.kind}:${req.renderMode ?? ''}`);
      return {
        status: 200,
        via: 'agent:site-fat',
        bodyText: JSON.stringify({
          results: [
            {
              id: 'scrape-1',
              url: 'https://example.com/',
              finalUrl: 'https://example.com/',
              status: 200,
              outcome: 'ok',
              // Even if an older Go node set rendered: true, Hub suppresses browser-auto on scriptless static HTML:
              rendered: true,
              contentType: 'text/html; charset=utf-8',
              body: exampleHtml,
            },
          ],
        }),
      };
    },
  });
  assert.deepEqual(kindsCalled, ['scrape:off'], 'Default auto renderMode must fetch static HTTP first and never trigger browser-auto on scriptless HTML');
  assert.equal(exRes.body.rendered, false);
  assert.equal(exRes.body.renderedVia, undefined);
  assert.match(String(exRes.body.markdown), /^# Example Domain\b/);

  // B.2: Wikipedia edit links (`veaction=edit`, `action=edit`, `.mw-editsection`) and RFC `¶` pilcrows
  const wikiAndRfcHtml =
    '<!doctype html><html><body><main>' +
    '<h2><span class="mw-headline" id="History">History</span>' +
    '<span class="mw-editsection"><span class="mw-editsection-bracket">[</span>' +
    '<a href="/w/index.php?title=HTTP&amp;veaction=edit&amp;section=12">edit</a>' +
    '<span class="mw-editsection-divider"> | </span>' +
    '<a href="/w/index.php?title=HTTP&amp;action=edit&amp;section=12">edit source</a>' +
    '<span class="mw-editsection-bracket">]</span></span></h2>' +
    '<p>RFC 9309 specifies that crawlers MUST obey Allow and Disallow rules.<a href="#section-2.2" class="pilcrow">¶</a></p>' +
    '<h3>Crawl-delay directive <a class="headerlink" href="#crawl-delay" title="Link to this heading">¶</a></h3>' +
    '<p>Trailing markdown pilcrow link test [¶](#p-2)</p>' +
    '</main></body></html>';
  const cleanedDoc = extractHtmlDocument(wikiAndRfcHtml, { baseUrl: 'https://en.wikipedia.org/wiki/HTTP', onlyMainContent: true });
  assert.equal(cleanedDoc.markdown.includes('veaction=edit'), false);
  assert.equal(cleanedDoc.markdown.includes('edit source'), false);
  assert.equal(cleanedDoc.markdown.includes('¶'), false);
  assert.match(cleanedDoc.markdown, /## History/);
  assert.match(cleanedDoc.markdown, /### Crawl-delay directive/);
});

test('B.3 & B.4: extract omits duplicate rawContent by default + flags 0-match queries; search_collection computes distinct BM25 scores, handles unbalanced syntax, and deduplicates snippet', async () => {
  // B.3: extract
  const tableOnlyHtml =
    '<!doctype html><html><head><title>Pricing Table</title></head><body><main>' +
    '<h1>Widget Pricing</h1><table><tr><th>Plan</th><th>Price</th></tr><tr><td>Starter</td><td>$10</td></tr></table>' +
    '</main></body></html>';
  const extZeroMatch = await executeExtractCall({
    payload: {
      urls: ['https://pricing.example.com/plans'],
      query: 'quantum chromodynamics gluon lattice',
    },
    env: {},
    executeHubFetch: async () => ({
      status: 200,
      via: 'agent:site-1',
      bodyText: JSON.stringify({
        results: [{ id: 'ext-1', url: 'https://pricing.example.com/plans', status: 200, outcome: 'ok', contentType: 'text/html', body: tableOnlyHtml }],
      }),
    }),
  });
  assert.equal(extZeroMatch.status, 200);
  const zeroItem = (extZeroMatch.body.results as Array<Record<string, unknown>>)[0]!;
  assert.equal('rawContent' in zeroItem, false, 'rawContent must be omitted unless includeRawContent is true');
  assert.equal(zeroItem.matchedQueryTerms, 0);
  assert.equal(zeroItem.noRelevantMatch, true);
  assert.equal(zeroItem.score, 0);
  assert.deepEqual(zeroItem.chunks, []);
  assert.equal(typeof zeroItem.note, 'string');

  const extMatchDefault = await executeExtractCall({
    payload: {
      urls: ['https://pricing.example.com/plans'],
      query: 'Starter Plan',
    },
    env: {},
    executeHubFetch: async () => ({
      status: 200,
      via: 'agent:site-1',
      bodyText: JSON.stringify({
        results: [{ id: 'ext-1', url: 'https://pricing.example.com/plans', status: 200, outcome: 'ok', contentType: 'text/html', body: tableOnlyHtml }],
      }),
    }),
  });
  const matchItem = (extMatchDefault.body.results as Array<Record<string, unknown>>)[0]!;
  assert.equal('rawContent' in matchItem, false);
  assert.ok((matchItem.chunks as unknown[]).length >= 1);

  // B.4: search_collection
  const searchDb = createSqliteD1(SEARCH_SQL);
  const idx = new D1FtsSearchIndex(searchDb);
  await idx.replacePageChunks({
    collectionId: 'audit-coll',
    documentId: 'doc_1',
    pageId: 'pg_1',
    url: 'https://docs.example.com/caching',
    title: 'HTTP Caching Architecture',
    markdown: '# HTTP Caching Architecture\n\nEdge caches store responses and validate stale entries with ETag and Cache-Control headers.',
    fetchedAt: Date.now(),
  });
  const longProse =
    '# Distributed Storage\n\n' +
    'Storage nodes replicate blocks across availability zones and verify checksums continuously. '.repeat(6) +
    'Cache-Control headers can also guide gateway proxies when serving static blobs to clients.';
  await idx.replacePageChunks({
    collectionId: 'audit-coll',
    documentId: 'doc_2',
    pageId: 'pg_2',
    url: 'https://docs.example.com/storage',
    title: 'Distributed Storage Guide',
    markdown: longProse,
    fetchedAt: Date.now(),
  });

  // Unbalanced query with `AND` where `unbalanced` matches 0 docs MUST return `[]`, NOT match `"and"` at score 0.5!
  const unbalancedHits = await idx.searchCollection({ collectionId: 'audit-coll', query: '"unbalanced AND (' });
  assert.deepEqual(unbalancedHits, []);

  // Multi-hit query produces distinct positive scores (not flat 1 or 0.5) and omits snippet on short text while compacting long text
  const cachingHits = await idx.searchCollection({ collectionId: 'audit-coll', query: 'HTTP Caching Cache-Control' });
  assert.equal(cachingHits.length, 2);
  assert.ok(cachingHits[0]!.score > cachingHits[1]!.score, `Expected distinct scores, got ${cachingHits[0]!.score} vs ${cachingHits[1]!.score}`);
  assert.notEqual(cachingHits[0]!.score, 1);
  assert.notEqual(cachingHits[0]!.score, 0.5);
  assert.equal(cachingHits[0]!.snippet, undefined, 'Short chunk (<=280 chars) must omit duplicate snippet');
  assert.ok(typeof cachingHits[1]!.snippet === 'string' && cachingHits[1]!.snippet!.length <= 200);
});

test('B.5 & B.6: fetch_batch maps 404->not_found vs 410->gone, normalizes SSRF redirects to blocked:{reason:"ssrf"}, and read_artifact returns consistent 404 artifact_not_found', async () => {
  // B.5: 404 vs 410 + SSRF redirect in cloudflareOverflowFetch & truncateResultBodies
  const ovBatch = await cloudflareOverflowFetch(
    JSON.stringify({
      maxSeconds: 20,
      options: { includeBody: true, respectRobots: true, pauseMs: 0 },
      requests: [
        { id: 'r404', url: 'https://public.example.com/missing', kind: 'page' },
        { id: 'r410', url: 'https://public.example.com/removed', kind: 'page' },
        { id: 'rssrf', url: 'https://public.example.com/redir-metadata', kind: 'page' },
      ],
    }),
    'EdgeFetch/2.7.1',
    'hub.example.com',
    {
      useSharedRobotsCache: false,
      sleepFn: async () => undefined,
      fetchFn: async (u) => {
        const s = String(u);
        if (s.endsWith('/robots.txt')) return new Response('User-agent: *\nAllow: /\n', { status: 200 });
        if (s.endsWith('/missing')) return new Response('Not Found', { status: 404 });
        if (s.endsWith('/removed')) return new Response('Gone', { status: 410 });
        if (s.endsWith('/redir-metadata')) {
          return new Response('', { status: 302, headers: { location: 'http://169.254.169.254/latest/meta-data/' } });
        }
        return new Response('ok', { status: 200 });
      },
    },
  );
  const ovParsed = (await ovBatch.json()) as Record<string, unknown>;
  const normalized = truncateResultBodies(ovParsed, 4096, true);
  const items = normalized.results as Array<Record<string, unknown>>;
  const byId = Object.fromEntries(items.map((it) => [String(it.id), it]));

  assert.equal(byId.r404?.outcome, 'not_found');
  assert.equal(byId.r410?.outcome, 'gone');
  assert.equal(byId.rssrf?.outcome, 'blocked');
  assert.deepEqual(byId.rssrf?.blocked, {
    reason: 'ssrf',
    retryable: false,
    message: 'Target or redirect resolved to a non-public/metadata IP address and was blocked.',
  });
  assert.equal(byId.rssrf?.body, undefined);

  // Also verify Go's `blocked_ssrf` outcome normalizes identically and drops raw error body
  const goSsrfNorm = truncateResultBodies({
    results: [
      {
        id: 'go-ssrf',
        url: 'https://redirect.example.com/aws',
        status: 403,
        outcome: 'blocked_ssrf',
        problem: 'dial tcp 169.254.169.254:80: non-public peer blocked',
        body: 'internal error trace',
      },
    ],
    summary: { total: 1, byOutcome: { blocked_ssrf: 1 }, byStatus: { '403': 1 } },
  });
  const goItem = (goSsrfNorm.results as Array<Record<string, unknown>>)[0]!;
  assert.equal(goItem.outcome, 'blocked');
  assert.equal((goItem.blocked as { reason: string }).reason, 'ssrf');
  assert.equal(goItem.body, undefined);

  // B.6: read_artifact consistent error shape across storage.ts, HTTP route, and MCP tool
  const bucket = createMemoryR2Bucket();
  const missingSha = 'a'.repeat(64);
  const storageMiss = await readArtifactPage({ bucket, blobSha256: missingSha });
  assert.deepEqual(storageMiss, {
    ok: false,
    status: 404,
    via: 'hub',
    error: 'artifact_not_found',
    message: 'Artifact was not found or has expired.',
  });

  const httpMiss = await handleArtifactGetRequest({
    request: new Request(`https://hub.example.com/v1/artifacts/${missingSha}`),
    url: new URL(`https://hub.example.com/v1/artifacts/${missingSha}`),
    blobSha256: missingSha,
    bucket,
  });
  assert.equal(httpMiss.status, 404);
  assert.deepEqual(await httpMiss.json(), {
    ok: false,
    status: 404,
    via: 'hub',
    error: 'artifact_not_found',
    message: 'Artifact was not found or has expired.',
  });

  const mcpDeps: McpServerDeps = {
    serverName: 'edgefetch-mcp',
    serverVersion: HUB_VERSION,
    ownerSecret: 'owner-secret-token-for-mcp-audit-test-9999',
    oauthStore: createMemoryOAuthStore(),
    allowedTargets: ['auto', 'agent', 'container'],
    defaultTarget: 'auto',
    listFleet: async () => ({ connected: 0, agents: [], affinities: [] }),
    executeFetch: async () => ({ status: 200, via: 'cf', bodyText: '{"results":[]}' }),
    readArtifact: async ({ blobSha256 }) => readArtifactPage({ bucket, blobSha256 }),
  };
  const mcpMissRes = await handleMcpRequest(
    new Request('https://hub.example.com/mcp', {
      method: 'POST',
      headers: {
        authorization: 'Bearer owner-secret-token-for-mcp-audit-test-9999',
        'content-type': 'application/json',
      },
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: 77,
        method: 'tools/call',
        params: { name: 'read_artifact', arguments: { artifactId: missingSha } },
      }),
    }),
    new URL('https://hub.example.com/mcp'),
    mcpDeps,
  );
  const mcpMissRpc = (await mcpMissRes.json()) as { result: { isError?: boolean; content: Array<{ text: string }> } };
  assert.equal(mcpMissRpc.result.isError, true);
  assert.deepEqual(JSON.parse(mcpMissRpc.result.content[0]!.text), {
    ok: false,
    status: 404,
    via: 'hub',
    error: 'artifact_not_found',
    message: 'Artifact was not found or has expired.',
  });
});

test('C.1, C.2 & C.3: MCP initialize/discover advertise listChanged: false + 2.8.20, subscriptions/listen ends gracefully, all 19 tool descriptions are jargon-free, and search inputSchema is deduplicated', async () => {
  assert.equal(HUB_VERSION, '2.8.20');
  const mcpDeps: McpServerDeps = {
    serverName: 'edgefetch-mcp',
    serverVersion: HUB_VERSION,
    ownerSecret: 'owner-secret-token-for-mcp-audit-test-9999',
    oauthStore: createMemoryOAuthStore(),
    allowedTargets: ['auto', 'agent', 'container'],
    defaultTarget: 'auto',
    listFleet: async () => ({ connected: 0, agents: [], affinities: [] }),
    executeFetch: async () => ({ status: 200, via: 'cf', bodyText: '{"results":[]}' }),
  };

  for (const method of ['initialize', 'server/discover'] as const) {
    const res = await handleMcpRequest(
      new Request('https://hub.example.com/mcp', {
        method: 'POST',
        headers: {
          authorization: 'Bearer owner-secret-token-for-mcp-audit-test-9999',
          'content-type': 'application/json',
        },
        body: JSON.stringify({
          jsonrpc: '2.0',
          id: method,
          method,
          params: method === 'initialize' ? { protocolVersion: '2025-03-26', clientInfo: { name: 'audit', version: '1.0' } } : {},
        }),
      }),
      new URL('https://hub.example.com/mcp'),
      mcpDeps,
    );
    const rpc = (await res.json()) as { result: Record<string, unknown> };
    // The tool list is fixed per deployed version, so the hub promises no tools/list_changed notifications.
    assert.deepEqual(rpc.result.capabilities, { tools: { listChanged: false } });
    const instructions = String(rpc.result.instructions ?? '');
    assert.equal(/\b(?:META D1|SEARCH D1|R2|HAOS|edgefetch_fat|Serper waterfall)\b/i.test(instructions), false);
  }

  // MCP 2026-07-28 `subscriptions/listen`: an SSE stream with `notifications/subscriptions/acknowledged` (no notification
  // types honored) and then a graceful `complete` result, both carrying the subscription ID (the request ID). Before,
  // this was "Method not found" (HTTP 404) and clients retried it with backoff on every connect.
  const listenRes = await handleMcpRequest(
    new Request('https://hub.example.com/mcp', {
      method: 'POST',
      headers: {
        authorization: 'Bearer owner-secret-token-for-mcp-audit-test-9999',
        'content-type': 'application/json',
        accept: 'application/json, text/event-stream',
        'mcp-protocol-version': '2026-07-28',
        'mcp-method': 'subscriptions/listen',
      },
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: 'listen-1',
        method: 'subscriptions/listen',
        params: {
          _meta: { 'io.modelcontextprotocol/protocolVersion': '2026-07-28' },
          notifications: { toolsListChanged: true },
        },
      }),
    }),
    new URL('https://hub.example.com/mcp'),
    mcpDeps,
  );
  assert.equal(listenRes.status, 200);
  assert.match(listenRes.headers.get('content-type') ?? '', /^text\/event-stream/);
  assert.equal(listenRes.headers.get('x-accel-buffering'), 'no');
  const listenMsgs = (await listenRes.text())
    .split('\n')
    .filter((line) => line.startsWith('data: '))
    .map((line) => JSON.parse(line.slice('data: '.length)) as Record<string, any>);
  assert.equal(listenMsgs.length, 2);
  assert.equal(listenMsgs[0]!.method, 'notifications/subscriptions/acknowledged');
  assert.equal(listenMsgs[0]!.params._meta['io.modelcontextprotocol/subscriptionId'], 'listen-1');
  assert.deepEqual(listenMsgs[0]!.params.notifications, {});
  assert.equal(listenMsgs[1]!.id, 'listen-1');
  assert.equal(listenMsgs[1]!.result.resultType, 'complete');
  assert.equal(listenMsgs[1]!.result._meta['io.modelcontextprotocol/subscriptionId'], 'listen-1');

  // Verify all 19 tool descriptions are plain English and free of internal infra jargon
  const tools = buildCanonicalMcpToolSchemas();
  assert.equal(tools.length, 19);
  const bannedJargonRe = /\b(?:META D1|SEARCH D1|D1 FTS5|R2|HAOS|Home Assistant OS|edgefetch_fat|Serper waterfall|edge-map)\b/i;
  for (const t of tools) {
    assert.equal(
      bannedJargonRe.test(t.description),
      false,
      `Tool "${t.name}" description still contains internal jargon: ${t.description}`,
    );
    const serializedProps = JSON.stringify(t.inputSchema.properties ?? {});
    assert.equal(
      bannedJargonRe.test(serializedProps),
      false,
      `Tool "${t.name}" parameter descriptions still contain internal jargon`,
    );
  }

  // Verify C.3: search inputSchema has exact clean camelCase set with zero duplicate snake_case aliases
  const searchSchema = MCP_TOOL_SCHEMAS.search!;
  assert.equal(searchSchema.additionalProperties, true);
  const searchPropKeys = Object.keys(searchSchema.properties);
  assert.deepEqual(searchPropKeys, [
    'query',
    'maxResults',
    'timeRange',
    'includeDomains',
    'excludeDomains',
    'includeRawContent',
    'chunksPerSource',
    'mode',
    'providers',
    'collectionId',
    'noCache',
    'visibility',
  ]);
  for (const legacyKey of [
    'max_results',
    'max_age_ms',
    'include_domains',
    'exclude_domains',
    'time_range',
    'include_raw_content',
    'chunks_per_source',
    'include_answer',
    'q',
    'limit',
  ]) {
    assert.equal(legacyKey in searchSchema.properties, false, `Legacy alias "${legacyKey}" must be removed from search inputSchema`);
  }
});
