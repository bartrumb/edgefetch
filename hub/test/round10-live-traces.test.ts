import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import test from 'node:test';
import { gzipSync } from 'node:zlib';
import { AgentHubEngine, createMemoryCooldownStore, routeFetchWithFailover, type HubSocketLike } from '../src/agent-hub.ts';
import { executeCatalogCall, getCatalogRecords, resetCatalogStateForTests } from '../src/catalog.ts';
import {
  discoverAtsBoardsFromHtml,
  executeJobsCall,
  extractJobPostingJsonLd,
  parsePayFromText,
  parseSmartRecruitersBoardScrape,
  resetJobsCacheForTests,
  resolveAtsPreFetchSpec,
} from '../src/jobs.ts';
import { executeCrawlJob } from '../src/map-crawl.ts';
import { sanitizeErrorMessageForSpan, sanitizeSpanAttributes } from '../src/otel.ts';
import { handleMcpRequest } from '../src/mcp.ts';
import { executeInteractCall, executeScrapeCall } from '../src/scrape.ts';
import { executeSearchCall, resetSearchProviderPacingForTests } from '../src/web-search.ts';
import { resetWikipediaStateForTests } from '../src/wikipedia.ts';
import {
  computeMarkdownSliceCheckpoints,
  sanitizeFullMarkdownDocumentForArtifact,
  sanitizeMarkdownPageSlice,
} from '../src/scrape-advanced.ts';
import { ensureD1ColumnIfMissing, executeExtractCall } from '../src/search-index.ts';
import { isEligibleForExternalSpaFallback } from '../src/spa-fallback.ts';
import { handleAgentArtifactUpload, resetRecentArtifactUploadsForTests } from '../src/storage.ts';

function createSqliteD1Tracker(sqlite: DatabaseSync) {
  const executedSql: string[] = [];
  const alterErrors: string[] = [];

  const wrapStmt = (sql: string, boundArgs: unknown[] = []) => ({
    bind: (...args: unknown[]) => wrapStmt(sql, args),
    run: async () => {
      executedSql.push(sql);
      try {
        const stmt = sqlite.prepare(sql);
        const res = stmt.run(...(boundArgs as never[]));
        return { success: true, meta: { rows_written: Number(res.changes ?? 0), size_after: 4096 } };
      } catch (err) {
        if (/^\s*ALTER\s+TABLE/i.test(sql)) {
          alterErrors.push(err instanceof Error ? err.message : String(err));
        }
        throw err;
      }
    },
    first: async <T = Record<string, unknown>>() => {
      executedSql.push(sql);
      const stmt = sqlite.prepare(sql);
      const row = stmt.get(...(boundArgs as never[]));
      return (row ?? null) as T | null;
    },
    all: async <T = Record<string, unknown>>() => {
      executedSql.push(sql);
      const stmt = sqlite.prepare(sql);
      const rows = stmt.all(...(boundArgs as never[]));
      return { success: true, results: rows as T[], meta: { size_after: 4096 } };
    },
  });

  const db = {
    prepare: (sql: string) => wrapStmt(sql),
    batch: async (stmts: Array<{ run: () => Promise<unknown> }>) => Promise.all(stmts.map((s) => s.run())),
  };

  return { db, executedSql, alterErrors };
}

test('R10-1: browser_worker_required & HAOS jargon retirement + legacy fat_agent_required compatibility', async () => {
  const emptyEngine = new AgentHubEngine({
    getSockets: () => [],
    cooldowns: createMemoryCooldownStore(),
  });

  // 1. Disconnected worker pool: no_agents uses clean worker-node phrasing (zero "HAOS" jargon)
  const noAgentsAll = await emptyEngine.dispatchFetch(
    JSON.stringify({ requests: [{ id: '1', url: 'https://example.com/', kind: 'page' }] }),
  );
  assert.equal(noAgentsAll.ok, false);
  if (!noAgentsAll.ok) {
    assert.equal(noAgentsAll.error, 'no_agents');
    assert.equal(noAgentsAll.message, 'No remote worker nodes are currently connected');
    assert.ok(!/HAOS/i.test(noAgentsAll.message));
  }

  const noAgentsSite = await emptyEngine.dispatchFetch(
    JSON.stringify({ requests: [{ id: '1', url: 'https://example.com/', kind: 'page' }] }),
    {},
    { preferredSite: 'site-1' },
  );
  assert.equal(noAgentsSite.ok, false);
  if (!noAgentsSite.ok) {
    assert.equal(noAgentsSite.error, 'no_agents');
    assert.equal(noAgentsSite.message, "Worker node 'site-1' is not connected");
  }

  // 2. Browser required with HTTP-only worker (no `browser-v1` capability): emits browser_worker_required with actionable guidance
  const httpOnlySocket: HubSocketLike = {
    readyState: 1,
    send() {},
    close() {},
    serializeAttachment() {},
    deserializeAttachment: () => ({
      siteId: 'site-1',
      arch: 'amd64',
      capabilities: ['fetch-v1'],
      connectedAt: 1000,
      lastJobAt: 0,
      jobsOk: 0,
      jobsErr: 0,
    }),
  };
  const httpOnlyEngine = new AgentHubEngine({
    getSockets: () => [httpOnlySocket],
    cooldowns: createMemoryCooldownStore(),
  });

  const noBrowserAll = await httpOnlyEngine.dispatchFetch(
    JSON.stringify({ requests: [{ id: '1', url: 'https://example.com/', kind: 'render' }] }),
  );
  assert.equal(noBrowserAll.ok, false);
  if (!noBrowserAll.ok) {
    assert.equal(noBrowserAll.status, 503);
    assert.equal(noBrowserAll.error, 'browser_worker_required');
    assert.equal(
      noBrowserAll.message,
      'Browser rendering is not enabled on any connected worker node. Enable allow_no_sandbox_browser in the Home Assistant add-on configuration, or connect a worker with Chromium enabled.',
    );
  }

  const noBrowserSite = await httpOnlyEngine.dispatchFetch(
    JSON.stringify({ requests: [{ id: '1', url: 'https://example.com/', kind: 'render' }] }),
    {},
    { preferredSite: 'site-1' },
  );
  assert.equal(noBrowserSite.ok, false);
  if (!noBrowserSite.ok) {
    assert.equal(noBrowserSite.status, 503);
    assert.equal(noBrowserAll.error, 'browser_worker_required');
    assert.equal(noBrowserSite.error, 'browser_worker_required');
    assert.equal(
      noBrowserSite.message,
      "Worker node 'site-1' is offline or does not have browser rendering enabled (enable allow_no_sandbox_browser in the Home Assistant add-on configuration, or connect a worker with Chromium enabled).",
    );
  }

  // 3. routeFetchWithFailover, isEligibleForExternalSpaFallback, and executeExtractCall accept BOTH browser_worker_required & legacy fat_agent_required
  for (const errCode of ['browser_worker_required', 'fat_agent_required'] as const) {
    assert.equal(isEligibleForExternalSpaFallback({ errorCode: errCode, status: 503 }), true);

    let containerCalled = false;
    const routed = await routeFetchWithFailover({
      target: 'auto',
      body: JSON.stringify({ requests: [{ id: '1', url: 'https://example.com/', kind: 'render' }] }),
      trace: {},
      callAgent: async () => ({ ok: false, status: 503, error: errCode, message: 'no chromium' }),
      callContainer: async () => {
        containerCalled = true;
        return new Response('{}', { status: 200 });
      },
    });
    assert.equal(routed.status, 503);
    assert.equal(containerCalled, false, `${errCode} must never fail over to non-browser container`);
    assert.equal(((await routed.json()) as { error: string }).error, errCode);

    const extractRes = await executeExtractCall({
      payload: { urls: ['https://spa.example.com/page'], renderMode: 'always', spaFallback: 'auto' },
      env: {
        CRAWL4AI_API_URL: 'https://crawl4ai.example.com',
        SAFE_FETCH: async (u) => {
          if (String(u).endsWith('/robots.txt')) return new Response('User-agent: *\nAllow: /\n', { status: 200 });
          return Response.json({
            success: true,
            status_code: 200,
            markdown: '# Rescued SPA Content\n\nRendered cleanly via external SPA fallback.',
          });
        },
      } as never,
      executeHubFetch: async () => ({
        status: 503,
        via: 'hub',
        bodyText: JSON.stringify({ error: errCode, message: 'no browser worker' }),
      }),
    });
    assert.equal(extractRes.status, 200);
    assert.equal((extractRes.body.results as Array<{ renderedVia?: string }>)[0]?.renderedVia, 'crawl4ai');
  }
});

test('R10-2: PRAGMA table_info guard eliminates duplicate column user_id SQLITE_ERROR on cold D1 isolates', async () => {
  resetCatalogStateForTests();

  // Case A: Cold isolate against an ALREADY-migrated D1 database -> ZERO ALTER TABLE statements, ZERO SQLITE_ERROR!
  const migratedSqlite = new DatabaseSync(':memory:');
  migratedSqlite.exec(`
    CREATE TABLE crawls (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL DEFAULT 'owner',
      root_url TEXT NOT NULL,
      status TEXT NOT NULL,
      options_json TEXT NOT NULL,
      pages_discovered INTEGER NOT NULL DEFAULT 0,
      pages_completed INTEGER NOT NULL DEFAULT 0,
      pages_failed INTEGER NOT NULL DEFAULT 0,
      created_at INTEGER NOT NULL,
      updated_at INTEGER NOT NULL
    );
    CREATE TABLE catalog_runs (
      catalog_id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL DEFAULT 'owner',
      origin TEXT NOT NULL,
      platform TEXT NOT NULL,
      collection TEXT NOT NULL DEFAULT '',
      status TEXT NOT NULL,
      products_count INTEGER NOT NULL DEFAULT 0,
      variants_count INTEGER NOT NULL DEFAULT 0,
      pages_read INTEGER NOT NULL DEFAULT 0,
      artifact_id TEXT,
      hashes_json TEXT,
      summary_json TEXT NOT NULL,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );
  `);
  const coldTracker = createSqliteD1Tracker(migratedSqlite);

  await executeCatalogCall({
    payload: { url: 'https://shop.example.com', maxPages: 1 },
    env: { META: coldTracker.db as unknown as D1Database },
    executeHubFetch: async () => ({
      status: 200,
      outcome: 'ok',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ products: [{ id: 1, title: 'Bike', handle: 'bike', variants: [{ id: 10, price: '999.00', available: true }] }] }),
    }),
  });

  await executeCrawlJob({
    crawlId: 'crawl_cold_1',
    rootUrl: 'https://docs.example.com/',
    options: { limit: 1, maxDepth: 0 },
    env: { META: coldTracker.db as unknown as D1Database },
    executeHubFetch: async () => ({
      status: 200,
      via: 'agent:site-1',
      bodyText: JSON.stringify({
        results: [{ id: '1', url: 'https://docs.example.com/', status: 200, outcome: 'ok', contentType: 'text/html', body: '<h1>Docs</h1>' }],
      }),
    }),
  });

  assert.equal(coldTracker.alterErrors.length, 0, `Expected zero duplicate-column errors, got: ${coldTracker.alterErrors.join('; ')}`);
  assert.equal(
    coldTracker.executedSql.filter((s) => /^\s*ALTER\s+TABLE/i.test(s)).length,
    0,
    'Cold isolate on migrated schema must NOT execute blind ALTER TABLE ADD COLUMN',
  );

  // Case B: Legacy pre-multiuser table missing `user_id` -> PRAGMA detects missing column and runs ALTER TABLE exactly once!
  const legacySqlite = new DatabaseSync(':memory:');
  legacySqlite.exec(`CREATE TABLE crawls (id TEXT PRIMARY KEY, created_at INTEGER NOT NULL);`);
  const legacyTracker = createSqliteD1Tracker(legacySqlite);
  const addedFirst = await ensureD1ColumnIfMissing({
    db: legacyTracker.db,
    table: 'crawls',
    column: 'user_id',
    alterSql: "ALTER TABLE crawls ADD COLUMN user_id TEXT NOT NULL DEFAULT 'owner'",
  });
  const addedSecond = await ensureD1ColumnIfMissing({
    db: legacyTracker.db,
    table: 'crawls',
    column: 'user_id',
    alterSql: "ALTER TABLE crawls ADD COLUMN user_id TEXT NOT NULL DEFAULT 'owner'",
  });
  assert.equal(addedFirst, true);
  assert.equal(addedSecond, false);
  assert.equal(legacyTracker.alterErrors.length, 0);
  assert.equal(legacyTracker.executedSql.filter((s) => /^\s*ALTER\s+TABLE/i.test(s)).length, 1);
});

test('R10-3: Ashby 1x board deduplication, Greenhouse 505-job pre-filter retention, fast /careers discovery & Workday/Rippling handling', async () => {
  resetJobsCacheForTests();
  const htmlToMd = (h: string) => ({ markdown: h.replace(/<[^>]+>/g, ' ').trim(), links: [] });

  // 1. Ashby: Serper returning 10 posting URLs from the same company downloads the Ashby board ONCE (not 10-11x)!
  let ashbyBoardDownloads = 0;
  let ashbySingleDownloads = 0;
  const ashbyOut = await executeJobsCall({
    payload: {
      query: 'Distributed Systems Engineer',
      remote: true,
      includeBuiltIn: false,
    },
    env: {},
    executeSearch: async ({ query: q }) => ({
      status: 200,
      body: {
        results: String(q).includes('ashbyhq')
          ? Array.from({ length: 10 }, (_, idx) => ({
              url: `https://jobs.ashbyhq.com/temporal/00000000-0000-0000-0000-${String(idx + 1).padStart(12, '0')}`,
            }))
          : [],
      },
    }),
    executeScrape: async (args) => {
      const u = String(args.url ?? '');
      if (u === 'https://jobs.ashbyhq.com/temporal') {
        ashbyBoardDownloads++;
        const spec = resolveAtsPreFetchSpec(u)!;
        const formatted = spec.format(
          JSON.stringify({
            organizationName: 'Temporal Technologies',
            jobs: Array.from({ length: 10 }, (_, idx) => ({
              id: `00000000-0000-0000-0000-${String(idx + 1).padStart(12, '0')}`,
              title: idx === 7 ? 'Senior Distributed Systems Engineer' : `Account Executive ${idx + 1}`,
              location: 'Remote - US',
              isRemote: true,
              publishedAt: new Date().toISOString(),
              compensation: {
                summaryComponents: [{ compensationType: 'Salary', currencyCode: 'USD', interval: 'year', minValue: 210_000, maxValue: 260_000 }],
              },
            })),
          }),
          u,
          htmlToMd,
        )!;
        return { status: 200, body: { ok: true, extractorId: spec.id, ...formatted } };
      }
      ashbySingleDownloads++;
      return { status: 404, body: { ok: false, status: 404 } };
    },
  });
  assert.equal(ashbyOut.status, 200);
  assert.equal(ashbyBoardDownloads, 1, 'Expected Ashby company board to be downloaded exactly ONCE');
  assert.equal(ashbySingleDownloads, 0, 'Expected zero redundant single-posting Ashby board re-downloads');
  assert.equal((ashbyOut.body.jobs as Array<{ title: string }>)[0]?.title, 'Senior Distributed Systems Engineer');
  assert.equal((ashbyOut.body.jobs as Array<{ pay?: { min: number } }>)[0]?.pay?.min, 210_000);

  // 2. Greenhouse 505-posting board (`cloudflare.com`): matches roles beyond index 120 + `/careers` stops immediately without probing `/jobs` or speculative slugs!
  const cloudflareProbedUrls: string[] = [];
  const ghSpec = resolveAtsPreFetchSpec('https://job-boards.greenhouse.io/cloudflare')!;
  const gh505Raw = JSON.stringify({
    meta: { total: 505 },
    jobs: Array.from({ length: 505 }, (_, i) => ({
      id: 7000000 + i,
      title: i === 450 ? 'Systems Engineer - Edge Runtime' : `Sales Role #${i + 1}`,
      absolute_url: `https://boards.greenhouse.io/cloudflare/jobs/${7000000 + i}`,
      location: { name: i === 450 ? 'Remote - US' : 'London, UK' },
      updated_at: new Date().toISOString(),
      content:
        i === 450
          ? '&lt;p&gt;Build Workers runtime. Annual salary range: &amp;dollar;185,000.00 &amp;ndash; &amp;dollar;245,000.00 USD.&lt;/p&gt;'
          : '&lt;p&gt;Sales role&lt;/p&gt;',
    })),
  });

  const cfDomainsRes = await executeJobsCall({
    payload: {
      domains: ['cloudflare.com'],
      query: 'Systems Engineer',
      remote: true,
    },
    env: {},
    executeSearch: async () => ({ status: 200, body: { results: [] } }),
    executeScrape: async (args) => {
      const u = String(args.url ?? '');
      cloudflareProbedUrls.push(u);
      if (u === 'https://cloudflare.com/careers') {
        assert.equal(args.discoverLlmsTxt, false);
        assert.equal(args.preferOriginMarkdown, false);
        assert.equal(args.renderMode, 'off');
        // JSON-escaped Next.js script payload
        return {
          status: 200,
          body: {
            ok: true,
            rawHtml: '<script id="__NEXT_DATA__">{"board":"https:\\/\\/boards.greenhouse.io\\/cloudflare"}</script>',
            links: [],
          },
        };
      }
      if (u === 'https://job-boards.greenhouse.io/cloudflare') {
        const fmt = ghSpec.format(gh505Raw, u, htmlToMd)!;
        return { status: 200, body: { ok: true, extractorId: ghSpec.id, ...fmt } };
      }
      return { status: 404, body: { ok: false, status: 404 } };
    },
  });
  assert.equal(cfDomainsRes.status, 200);
  assert.deepEqual(
    cloudflareProbedUrls,
    ['https://cloudflare.com/careers', 'https://job-boards.greenhouse.io/cloudflare'],
    'Confirmed /careers ATS link must skip /jobs, /about/careers, and all speculative slug probes',
  );
  const cfJobs = cfDomainsRes.body.jobs as Array<{ title: string; pay: { min: number; max: number } | null }>;
  assert.equal(cfJobs.length, 1, 'Expected posting #451 (beyond 120 cap) to survive pre-filter retention');
  assert.equal(cfJobs[0]?.title, 'Systems Engineer - Edge Runtime');
  assert.deepEqual(cfJobs[0]?.pay && { min: cfJobs[0].pay.min, max: cfJobs[0].pay.max }, { min: 185_000, max: 245_000 });

  // 3. Direct Workday CXS URL & Rippling single-job API + Rippling scheme-downgrade closed handling
  const wdCxsDirect = resolveAtsPreFetchSpec('https://novartis.wd5.myworkdayjobs.com/wday/cxs/novartis/Novartis_Careers/jobs')!;
  assert.ok(wdCxsDirect);
  assert.equal(wdCxsDirect.method, 'POST');
  assert.equal(wdCxsDirect.contentType, 'application/json');
  assert.deepEqual(JSON.parse(wdCxsDirect.requestBody!), { appliedFacets: {}, limit: 20, offset: 0, searchText: '' });
  assert.equal(
    discoverAtsBoardsFromHtml({
      sourceUrl: 'https://novartis.com/careers',
      rawHtml: '<script>fetch("https:\\/\\/novartis.wd5.myworkdayjobs.com\\/wday\\/cxs\\/novartis\\/Novartis_Careers\\/jobs")</script>',
    })[0]?.slug,
    'novartis/Novartis_Careers',
  );

  const ripJobSpec = resolveAtsPreFetchSpec('https://ats.rippling.com/en-US/acme-bio/jobs/9f8e7d6c-1234-5678-9abc-def012345678')!;
  assert.ok(ripJobSpec);
  assert.equal(ripJobSpec.id, 'rippling-job');
  assert.equal(ripJobSpec.fetchUrl, 'https://api.rippling.com/platform/api/ats/v1/board/acme-bio/jobs/9f8e7d6c-1234-5678-9abc-def012345678');
  const ripFmt = ripJobSpec.format(
    JSON.stringify({
      uuid: '9f8e7d6c-1234-5678-9abc-def012345678',
      name: 'Staff Platform Engineer',
      companyName: 'Acme Bio',
      workLocations: ['Remote (United States)'],
      createdOn: new Date().toISOString(),
      description: { role: '<p>Compensation: $195,000.00 - $240,000.00 USD</p>' },
    }),
    'https://ats.rippling.com/en-US/acme-bio/jobs/9f8e7d6c-1234-5678-9abc-def012345678',
    htmlToMd,
  )!;
  assert.equal(ripFmt.jobPosting?.title, 'Staff Platform Engineer');
  assert.equal(ripFmt.jobPosting?.pay?.min, 195_000);

  // Rippling redirect scheme downgrade on closed posting is treated cleanly as closed/unavailable
  const ripVerify = await executeJobsCall({
    payload: {
      verify: ['https://custom-careers.rippling.com/jobs/expired-1'],
    },
    env: {},
    executeSearch: async () => ({ status: 200, body: { results: [] } }),
    executeScrape: async () => ({
      status: 422,
      body: {
        ok: false,
        outcome: 'blocked',
        blockedReason: 'scheme_downgrade',
        problem: 'HTTPS-to-HTTP redirect downgrade is not permitted',
        blocked: { reason: 'scheme_downgrade', retryable: false },
      },
    }),
  });
  assert.equal(ripVerify.status, 200);
  assert.equal((ripVerify.body.results as Array<{ status: string }>)[0]?.status, 'closed');
});

test('R10-4: postedWithinDays <= 30 parity, 5-min LRU + 6-way parallel coalescing + 12s timeout guard, SmartRecruiters Visa & NYC salary extraction', async () => {
  resetJobsCacheForTests();
  const htmlToMd = (h: string) => ({ markdown: h.replace(/<[^>]+>/g, ' ').trim(), links: [] });

  // 1. postedWithinDays: 7, 30, and 60 NEVER pass `timeRange` to Serper ATS queries and all return fresh postings!
  const seenSearchArgs: Array<Record<string, unknown>> = [];
  const twoDaysAgoIso = new Date(Date.now() - 2 * 86_400_000).toISOString();
  const fortyFiveDaysAgoIso = new Date(Date.now() - 45 * 86_400_000).toISOString();

  for (const days of [7, 30, 60]) {
    const res = await executeJobsCall({
      payload: {
        query: 'Security Engineer',
        postedWithinDays: days,
        includeBuiltIn: false,
      },
      env: {},
      executeSearch: async (sArgs) => {
        seenSearchArgs.push(sArgs);
        return {
          status: 200,
          body: {
            results: String(sArgs.query).includes('ashbyhq') ? [{ url: 'https://jobs.ashbyhq.com/vanta' }] : [],
          },
        };
      },
      executeScrape: async () => ({
        status: 200,
        body: {
          ok: true,
          extractorId: 'ashby-board',
          jobs: [
            {
              title: 'Senior Security Engineer',
              company: 'Vanta',
              url: 'https://jobs.ashbyhq.com/vanta/fresh-1',
              applyUrl: 'https://jobs.ashbyhq.com/vanta/fresh-1/application',
              workplaceType: 'remote',
              locations: ['Remote - US'],
              pay: { min: 190_000, max: 230_000, currency: 'USD', period: 'year', basis: 'base' },
              postedAt: twoDaysAgoIso,
              source: 'ashby',
            },
            {
              title: 'Staff Security Engineer (45d old)',
              company: 'Vanta',
              url: 'https://jobs.ashbyhq.com/vanta/older-2',
              applyUrl: 'https://jobs.ashbyhq.com/vanta/older-2/application',
              workplaceType: 'remote',
              locations: ['Remote - US'],
              pay: { min: 210_000, max: 260_000, currency: 'USD', period: 'year', basis: 'base' },
              postedAt: fortyFiveDaysAgoIso,
              source: 'ashby',
            },
          ],
        },
      }),
    });
    assert.equal(res.status, 200);
    const titles = (res.body.jobs as Array<{ title: string }>).map((j) => j.title);
    assert.ok(titles.includes('Senior Security Engineer'), `postedWithinDays=${days} must return 2-day-old posting`);
    if (days <= 30) {
      assert.ok(!titles.includes('Staff Security Engineer (45d old)'), `postedWithinDays=${days} must filter 45-day-old posting via maxAgeCutoffMs`);
    } else {
      assert.ok(titles.includes('Staff Security Engineer (45d old)'), 'postedWithinDays=60 must include 45-day-old posting');
    }
  }
  assert.ok(
    seenSearchArgs.every((a) => a.timeRange === undefined),
    'ATS site: search queries must NEVER pass Serper timeRange (qdr:w / qdr:m)',
  );

  // 2. 6-way parallel `jobs` stampede coalesces onto 1 network fetch + 8 sequential filter tweaks hit 5-min cache in 0 network calls!
  resetJobsCacheForTests();
  const sharedProdEnv = { CALLER_TOKEN: 'prod-token', JOBS_SHARED_CACHE: true };
  let temporalNetworkFetches = 0;

  const slowTemporalScrape = async (args: Record<string, unknown>) => {
    const u = String(args.url ?? '');
    if (u.includes('jobs.ashbyhq.com/temporal')) {
      temporalNetworkFetches++;
      await new Promise((r) => setTimeout(r, 30));
      return {
        status: 200,
        body: {
          ok: true,
          extractorId: 'ashby-board',
          jobs: [
            {
              title: 'Principal Runtime Engineer',
              company: 'Temporal',
              url: 'https://jobs.ashbyhq.com/temporal/r1',
              applyUrl: 'https://jobs.ashbyhq.com/temporal/r1/application',
              workplaceType: 'remote',
              locations: ['Seattle, WA', 'Remote - US'],
              pay: { min: 230_000, max: 290_000, currency: 'USD', period: 'year', basis: 'base' },
              postedAt: twoDaysAgoIso,
              source: 'ashby',
            },
            {
              title: 'Cloud Infrastructure Engineer',
              company: 'Temporal',
              url: 'https://jobs.ashbyhq.com/temporal/r2',
              applyUrl: 'https://jobs.ashbyhq.com/temporal/r2/application',
              workplaceType: 'onsite',
              locations: ['Bellevue, WA'],
              pay: { min: 180_000, max: 220_000, currency: 'USD', period: 'year', basis: 'base' },
              postedAt: twoDaysAgoIso,
              source: 'ashby',
            },
          ],
        },
      };
    }
    if (u.includes('slow-broken-board')) {
      // Simulate hung board throwing / timing out; must NOT fail executeJobsCall!
      throw new Error('upstream socket hang up');
    }
    return { status: 404, body: { ok: false, status: 404 } };
  };

  // 6 parallel calls
  const parallelOuts = await Promise.all(
    Array.from({ length: 6 }, (_, idx) =>
      executeJobsCall({
        payload: {
          query: 'Engineer',
          remote: idx % 2 === 0 ? true : undefined,
          includeBuiltIn: false,
        },
        env: sharedProdEnv,
        executeSearch: async ({ query: q }) => ({
          status: 200,
          body: {
            results: String(q).includes('ashbyhq')
              ? [{ url: 'https://jobs.ashbyhq.com/temporal' }, { url: 'https://jobs.lever.co/slow-broken-board' }]
              : [],
          },
        }),
        executeScrape: slowTemporalScrape,
      }),
    ),
  );
  assert.ok(parallelOuts.every((o) => o.status === 200));
  assert.equal(temporalNetworkFetches, 1, '6 parallel jobs calls must coalesce onto 1 in-flight Temporal board fetch');

  // 8 sequential filter-tweaking calls -> 0 additional network downloads!
  for (let k = 0; k < 8; k++) {
    const seqOut = await executeJobsCall({
      payload: {
        query: 'Engineer',
        minBase: 170_000 + k * 5_000,
        postedWithinDays: k % 2 === 0 ? 7 : 30,
        locations: k % 3 === 0 ? ['United States'] : undefined,
        includeBuiltIn: false,
      },
      env: sharedProdEnv,
      executeSearch: async ({ query: q }) => ({
        status: 200,
        body: { results: String(q).includes('ashbyhq') ? [{ url: 'https://jobs.ashbyhq.com/temporal' }] : [] },
      }),
      executeScrape: slowTemporalScrape,
    });
    assert.equal(seqOut.status, 200);
    assert.ok((seqOut.body.jobs as unknown[]).length >= 1);
  }
  assert.equal(temporalNetworkFetches, 1, '8 sequential filter tweaks within 5 minutes must make ZERO repeat board fetches');

  // 3. SmartRecruiters Public HTML Board (`company: "Visa"`, zero `api.smartrecruiters.com` calls!) + JSON-LD enrichment
  const seenVisaUrls: string[] = [];
  const visaBoardMd = [
    '# Visa Careers',
    '- [Staff AI Platform Engineer](https://jobs.smartrecruiters.com/Visa/744000088811122-staff-ai-platform-engineer) — Austin, TX, US',
    '- [Senior Payment Systems Engineer](https://jobs.smartrecruiters.com/Visa/744000088811133-senior-payment-systems-engineer) — Foster City, CA, US',
  ].join('\n');
  assert.equal(parseSmartRecruitersBoardScrape('https://jobs.smartrecruiters.com/Visa', { markdown: visaBoardMd }).length, 2);

  const visaPostingHtml = `<!doctype html><html><head><script type="application/ld+json">${JSON.stringify({
    '@context': 'https://schema.org',
    '@type': 'JobPosting',
    title: 'Staff AI Platform Engineer',
    datePosted: twoDaysAgoIso,
    employmentType: 'FULL_TIME',
    hiringOrganization: { '@type': 'Organization', name: 'Visa' },
    jobLocationType: 'TELECOMMUTE',
    jobLocation: {
      '@type': 'Place',
      address: { '@type': 'PostalAddress', addressLocality: 'Austin', addressRegion: 'TX', addressCountry: 'US' },
    },
    baseSalary: {
      '@type': 'MonetaryAmount',
      currency: 'USD',
      value: '$185,400.00 - $252,800.00 USD',
      unitText: 'YEAR',
    },
  })}</script></head><body><h1>Staff AI Platform Engineer</h1></body></html>`;

  const visaRes = await executeJobsCall({
    payload: {
      company: 'Visa',
      query: 'AI Platform Engineer',
      postedWithinDays: 14,
      minBase: 180_000,
    },
    env: {},
    executeSearch: async () => ({ status: 200, body: { results: [] } }),
    executeScrape: async (args) => {
      const u = String(args.url ?? '');
      seenVisaUrls.push(u);
      assert.ok(!u.includes('api.smartrecruiters.com'), 'Must NEVER call robots-disallowed api.smartrecruiters.com');
      if (u === 'https://jobs.smartrecruiters.com/Visa') {
        return {
          status: 200,
          body: {
            ok: true,
            markdown: visaBoardMd,
            links: [
              'https://jobs.smartrecruiters.com/Visa/744000088811122-staff-ai-platform-engineer',
              'https://jobs.smartrecruiters.com/Visa/744000088811133-senior-payment-systems-engineer',
            ],
          },
        };
      }
      if (u === 'https://jobs.smartrecruiters.com/Visa/744000088811122-staff-ai-platform-engineer') {
        const jp = extractJobPostingJsonLd(visaPostingHtml, u)!;
        return {
          status: 200,
          body: { ok: true, jobPosting: jp, markdown: '# Staff AI Platform Engineer' },
        };
      }
      return { status: 404, body: { ok: false, status: 404 } };
    },
  });
  assert.equal(visaRes.status, 200);
  const visaJobs = visaRes.body.jobs as Array<{ title: string; company: string; pay: { min: number; max: number } | null; workplaceType: string }>;
  assert.equal(visaJobs.length, 1);
  assert.equal(visaJobs[0]?.title, 'Staff AI Platform Engineer');
  assert.equal(visaJobs[0]?.company, 'Visa');
  assert.equal(visaJobs[0]?.workplaceType, 'remote');
  assert.deepEqual(visaJobs[0]?.pay && { min: visaJobs[0].pay.min, max: visaJobs[0].pay.max }, { min: 185_400, max: 252_800 });

  // 4. Spotify / Lever NYC Pay-Transparency salary extraction (`lists` + `additionalPlain` + `.00` cents + em-dash)
  const leverBoardSpec = resolveAtsPreFetchSpec('https://jobs.lever.co/spotify')!;
  const spotifyBoardFmt = leverBoardSpec.format(
    JSON.stringify([
      {
        id: '11111111-2222-3333-4444-555555555555',
        text: 'Senior Backend Engineer, Personalization',
        hostedUrl: 'https://jobs.lever.co/spotify/11111111-2222-3333-4444-555555555555',
        workplaceType: 'hybrid',
        categories: { location: 'New York, NY', commitment: 'Full-time' },
        createdAt: Date.now() - 86_400_000,
        descriptionPlain: 'Build personalization services at scale.',
        lists: [
          {
            text: 'Where you will be',
            content: '<li>New York, NY. The United States base range for this position is $165,400.00 - $236,300.00 USD plus equity.</li>',
          },
        ],
        additionalPlain: '',
      },
    ]),
    'https://jobs.lever.co/spotify',
    htmlToMd,
  )!;
  assert.deepEqual(
    spotifyBoardFmt.jobs?.[0]?.pay && { min: spotifyBoardFmt.jobs[0].pay.min, max: spotifyBoardFmt.jobs[0].pay.max },
    { min: 165_400, max: 236_300 },
  );

  // Direct em-dash & direct MonetaryAmount minValue/maxValue
  assert.deepEqual(
    (() => {
      const p = parsePayFromText('NYC Pay Transparency Range: $180,000—$250,000');
      return p ? { min: p.min, max: p.max } : null;
    })(),
    { min: 180_000, max: 250_000 },
  );
  const directMonetaryJp = extractJobPostingJsonLd(
    `<script type="application/ld+json">${JSON.stringify({
      '@type': 'JobPosting',
      title: 'Principal ML Engineer',
      baseSalary: { '@type': 'MonetaryAmount', currency: 'USD', minValue: 215000, maxValue: 285000, unitText: 'YEAR' },
    })}</script>`,
    'https://careers.example.com/jobs/1',
  );
  assert.deepEqual(
    directMonetaryJp?.pay && { min: directMonetaryJp.pay.min, max: directMonetaryJp.pay.max },
    { min: 215_000, max: 285_000 },
  );

  // 5. Lever HTML `additional` pay when `lists` is non-empty & `additionalPlain === ""`, plus `company: "Spotify"` board probe when `ats_search` returns unrelated startups (`candidateUrls.size > 1`)
  const spotifyHtmlAdditionalFmt = leverBoardSpec.format(
    JSON.stringify([
      {
        id: 'b24fe5e5-dcb2-4238-a883-5fdb6bd404db',
        text: 'Accounting Analyst, Content Accounting',
        hostedUrl: 'https://jobs.lever.co/spotify/b24fe5e5-dcb2-4238-a883-5fdb6bd404db',
        workplaceType: 'hybrid',
        categories: { location: 'New York, NY', allLocations: ['New York, NY'] },
        createdAt: Date.now() - 86_400_000,
        descriptionPlain: '',
        description: '<div>Content accounting team.</div>',
        lists: [{ text: "What You'll Do", content: '<li>Close monthly accounting.</li>' }],
        additionalPlain: '',
        additional: '<div><p>The United States base range for this position is 75,645 - 94,556 USD plus equity.</p></div>',
      },
    ]),
    'https://jobs.lever.co/spotify',
    htmlToMd,
  )!;
  assert.deepEqual(
    spotifyHtmlAdditionalFmt.jobs?.[0]?.pay && {
      min: spotifyHtmlAdditionalFmt.jobs[0].pay.min,
      max: spotifyHtmlAdditionalFmt.jobs[0].pay.max,
    },
    { min: 75_645, max: 94_556 },
  );

  const spotifyCompanyRes = await executeJobsCall({
    payload: { company: 'Spotify', locations: ['New York'], limit: 5 },
    env: {},
    executeSearch: async () => ({
      status: 200,
      body: {
        // 5 unrelated startups mentioning "ex-Spotify" on Ashby/Greenhouse (`candidateUrls.size > 1`)
        results: [1, 2, 3, 4, 5].map((n) => ({ url: `https://jobs.ashbyhq.com/otherstartup${n}` })),
      },
    }),
    executeScrape: async (args) => {
      const u = String(args.url ?? '');
      if (u === 'https://jobs.lever.co/spotify') {
        return {
          status: 200,
          body: { ok: true, extractorId: 'lever-board', jobs: spotifyHtmlAdditionalFmt.jobs },
        };
      }
      return { status: 404, body: { ok: false, status: 404 } };
    },
  });
  assert.equal(spotifyCompanyRes.status, 200);
  const spotifyMatched = spotifyCompanyRes.body.jobs as Array<{ title: string; pay: { min: number; max: number } | null }>;
  assert.equal(spotifyMatched.length, 1);
  assert.deepEqual(
    spotifyMatched[0]?.pay && { min: spotifyMatched[0].pay.min, max: spotifyMatched[0].pay.max },
    { min: 75_645, max: 94_556 },
  );

  // 6. Workday relative `postedOn` ("Posted Today" vs "Posted 30+ Days Ago") & single-posting -> Workday board promotion
  const wdBoardSpec = resolveAtsPreFetchSpec('https://visa.wd5.myworkdayjobs.com/Visa?q=Engineer')!;
  const wdBoardFmt = wdBoardSpec.format(
    JSON.stringify({
      total: 2,
      jobPostings: [
        {
          title: 'Software Engineer, Agentic Developer',
          externalPath: '/job/US---Denver-CO/Software-Engineer--Agentic-Developer_REF090196W',
          locationsText: 'US - Denver, CO',
          postedOn: 'Posted Today',
        },
        {
          title: 'Legacy Systems Engineer',
          externalPath: '/job/US---Austin-TX/Legacy-Systems-Engineer_REF010000W',
          locationsText: 'US - Austin, TX',
          postedOn: 'Posted 30+ Days Ago',
        },
      ],
    }),
    'https://visa.wd5.myworkdayjobs.com/Visa?q=Engineer',
    htmlToMd,
  )!;
  assert.match(wdBoardFmt.jobs?.[0]?.postedAt ?? '', /^\d{4}-\d{2}-\d{2}$/);
  assert.match(wdBoardFmt.jobs?.[1]?.postedAt ?? '', /^\d{4}-\d{2}-\d{2}$/);

  const seenVisaSearchQueries: string[] = [];
  const visaBoardPromoRes = await executeJobsCall({
    payload: { company: 'Visa', query: 'Engineer', postedWithinDays: 14, limit: 10 },
    env: {},
    executeSearch: async ({ query: q }) => {
      const qs = String(q);
      seenVisaSearchQueries.push(qs);
      if (qs.includes('site:jobs.smartrecruiters.com/visa')) {
        return {
          status: 200,
          body: { results: [{ url: 'https://jobs.smartrecruiters.com/Visa/744000088811122-staff-ai-platform-engineer' }] },
        };
      }
      return {
        status: 200,
        body: { results: [{ url: 'https://visa.wd5.myworkdayjobs.com/en-US/Visa/job/SW-Engineer_REF089359W' }] },
      };
    },
    executeScrape: async (args) => {
      const u = String(args.url ?? '');
      if (u === 'https://visa.wd5.myworkdayjobs.com/Visa?q=Engineer') {
        return { status: 200, body: { ok: true, extractorId: 'workday-board', jobs: wdBoardFmt.jobs } };
      }
      if (u === 'https://jobs.smartrecruiters.com/Visa/744000088811122-staff-ai-platform-engineer') {
        const jp = extractJobPostingJsonLd(visaPostingHtml, u)!;
        return { status: 200, body: { ok: true, jobPosting: jp, markdown: '# Staff AI Platform Engineer' } };
      }
      return { status: 404, body: { ok: false, status: 404 } };
    },
  });
  assert.ok(seenVisaSearchQueries.some((q) => q.includes('site:jobs.smartrecruiters.com/visa')));
  const promoTitles = (visaBoardPromoRes.body.jobs as Array<{ title: string }>).map((j) => j.title);
  assert.ok(promoTitles.includes('Software Engineer, Agentic Developer'), 'Promoted Workday board must include Posted Today job');
  assert.ok(!promoTitles.includes('Legacy Systems Engineer'), 'postedWithinDays=14 must exclude Posted 30+ Days Ago Workday job');
  assert.ok(promoTitles.includes('Staff AI Platform Engineer'), 'Path-scoped SmartRecruiters search must include Visa SR job');

  // 7. J5 Word-Boundary Matching ("Engineer" matches "Software Engineer" / "Staff Engineers", NEVER "Engineering Manager" / "Engineering Director") + `minBaseMode: "overlap"`
  const wordBoundaryRes = await executeJobsCall({
    payload: {
      company: 'Temporal',
      query: 'Engineer',
      minBase: 240_000,
      minBaseMode: 'overlap',
      includeBuiltIn: false,
    },
    env: {},
    executeSearch: async () => ({ status: 200, body: { results: [] } }),
    executeScrape: async (args) => {
      if (String(args.url) === 'https://jobs.ashbyhq.com/temporal') {
        return {
          status: 200,
          body: {
            ok: true,
            extractorId: 'ashby-board',
            jobs: [
              {
                title: 'Engineering Manager, Core Runtime',
                company: 'Temporal',
                url: 'https://jobs.ashbyhq.com/temporal/em-1',
                applyUrl: 'https://jobs.ashbyhq.com/temporal/em-1/application',
                workplaceType: 'remote',
                locations: ['Remote - US'],
                pay: { min: 250_000, max: 310_000, currency: 'USD', period: 'year', basis: 'base' },
                postedAt: twoDaysAgoIso,
                source: 'ashby',
              },
              {
                title: 'Engineering Director, Cloud',
                company: 'Temporal',
                url: 'https://jobs.ashbyhq.com/temporal/ed-1',
                applyUrl: 'https://jobs.ashbyhq.com/temporal/ed-1/application',
                workplaceType: 'remote',
                locations: ['Remote - US'],
                pay: { min: 280_000, max: 350_000, currency: 'USD', period: 'year', basis: 'base' },
                postedAt: twoDaysAgoIso,
                source: 'ashby',
              },
              {
                title: 'Staff Software Engineer',
                company: 'Temporal',
                url: 'https://jobs.ashbyhq.com/temporal/swe-1',
                applyUrl: 'https://jobs.ashbyhq.com/temporal/swe-1/application',
                workplaceType: 'remote',
                locations: ['Remote - US'],
                pay: { min: 208_000, max: 341_000, currency: 'USD', period: 'year', basis: 'base' },
                postedAt: twoDaysAgoIso,
                source: 'ashby',
              },
            ],
          },
        };
      }
      return { status: 404, body: { ok: false, status: 404 } };
    },
  });
  assert.equal(wordBoundaryRes.status, 200);
  const wbTitles = (wordBoundaryRes.body.jobs as Array<{ title: string }>).map((j) => j.title);
  assert.deepEqual(wbTitles, ['Staff Software Engineer']);
});

test('Blind Audit Closure (EF-BLIND-02, EF-BLIND-04, EF-BLIND-05) & Catalog Stored-Snapshot Currency Backfill', async () => {
  // EF-BLIND-02: `handleAgentArtifactUpload` cryptographically verifies `x-content-sha256` + `x-content-bytes` against gunzipped payload
  // and deduplicates `'transient'` uploads after `META.artifacts` promotes `retention = 'stored'`.
  resetRecentArtifactUploadsForTests();
  const rawBytes = new TextEncoder().encode('verified payload for EF-BLIND-02');
  const gzBytes = gzipSync(rawBytes);
  const blobSha = createHash('sha256').update(gzBytes).digest('hex');
  const realContentSha = createHash('sha256').update(rawBytes).digest('hex');
  const poisonedSha = '0'.repeat(64);

  const sqlite = new DatabaseSync(':memory:');
  sqlite.exec(`CREATE TABLE artifacts (blob_sha256 TEXT PRIMARY KEY, retention TEXT, last_seen_at INTEGER);`);
  const { db: metaDb } = createSqliteD1Tracker(sqlite);

  let putCalls = 0;
  let headCalls = 0;
  const r2Map = new Map<string, { bytes: Uint8Array; customMetadata?: Record<string, string>; uploaded: Date }>();
  const mockBucket = {
    head: async (k: string) => {
      headCalls++;
      const found = r2Map.get(k);
      return found ? { key: k, size: found.bytes.byteLength, uploaded: found.uploaded, customMetadata: found.customMetadata } : null;
    },
    put: async (k: string, val: Uint8Array, opts?: { customMetadata?: Record<string, string> }) => {
      putCalls++;
      const rec = { bytes: new Uint8Array(val), customMetadata: opts?.customMetadata, uploaded: new Date() };
      r2Map.set(k, rec);
      return rec;
    },
  };

  // Poisoned `x-content-sha256` MUST be rejected with 400 BEFORE touching R2!
  const poisonedRes = await handleAgentArtifactUpload({
    request: new Request(`https://hub.example/agent/artifacts/${blobSha}`, {
      method: 'PUT',
      headers: {
        'content-length': String(gzBytes.byteLength),
        'x-content-sha256': poisonedSha,
        'x-content-bytes': String(rawBytes.byteLength),
        'x-artifact-retention': 'transient',
        'x-job-id': 'j_poison',
        'x-job-nonce': 'n_poison',
        'x-request-id': 'r_poison',
      },
      body: new Uint8Array(gzBytes),
    }),
    blobSha256: blobSha,
    siteId: 's1',
    bucket: mockBucket as unknown as R2Bucket,
    metaDb: metaDb as unknown as D1Database,
    authorizeJobUpload: async () => ({ ok: true }),
  });
  assert.equal(poisonedRes.status, 400);
  assert.equal(((await poisonedRes.json()) as { error: string }).error, 'content_sha256_mismatch');
  assert.equal(putCalls, 0);

  // Valid `'stored'` upload + `META.artifacts` `'stored'` row -> subsequent `'transient'` upload deduplicates cleanly (`putCalls === 1`)!
  const storedRes = await handleAgentArtifactUpload({
    request: new Request(`https://hub.example/agent/artifacts/${blobSha}`, {
      method: 'PUT',
      headers: {
        'content-length': String(gzBytes.byteLength),
        'x-content-sha256': realContentSha,
        'x-content-bytes': String(rawBytes.byteLength),
        'x-artifact-retention': 'stored',
        'x-job-id': 'j_ok',
        'x-job-nonce': 'n_ok',
        'x-request-id': 'r_ok',
      },
      body: new Uint8Array(gzBytes),
    }),
    blobSha256: blobSha,
    siteId: 's1',
    bucket: mockBucket as unknown as R2Bucket,
    metaDb: metaDb as unknown as D1Database,
    authorizeJobUpload: async () => ({ ok: true }),
  });
  assert.equal(storedRes.status, 200);
  assert.equal(putCalls, 1);
  sqlite.prepare(`INSERT INTO artifacts (blob_sha256, retention, last_seen_at) VALUES (?, 'stored', ?)`).run(blobSha, Date.now());
  resetRecentArtifactUploadsForTests();

  const transientAfterPromo = await handleAgentArtifactUpload({
    request: new Request(`https://hub.example/agent/artifacts/${blobSha}`, {
      method: 'PUT',
      headers: {
        'content-length': String(gzBytes.byteLength),
        'x-content-sha256': realContentSha,
        'x-content-bytes': String(rawBytes.byteLength),
        'x-artifact-retention': 'transient',
        'x-job-id': 'j_tr',
        'x-job-nonce': 'n_tr',
        'x-request-id': 'r_tr',
      },
      body: new Uint8Array(gzBytes),
    }),
    blobSha256: blobSha,
    siteId: 's1',
    bucket: mockBucket as unknown as R2Bucket,
    metaDb: metaDb as unknown as D1Database,
    authorizeJobUpload: async () => ({ ok: true }),
  });
  assert.equal(transientAfterPromo.status, 200);
  assert.equal(((await transientAfterPromo.json()) as { deduplicated: boolean }).deduplicated, true);
  assert.equal(putCalls, 1, 'Transient upload after stored promotion must deduplicate without re-PUTting');
  assert.equal(headCalls, 1);

  // EF-BLIND-04: `sanitizeErrorMessageForSpan` & `sanitizeSpanAttributes` scrub ws://, wss://, JSON-escaped https:\/\/, schemeless userinfo, colon tokens, and password=
  const secretSamples = [
    'WebSocket dial failed wss://agent:TEST_SECRET_123@hub.example.com/agent/ws?token=TEST_SECRET_456',
    'connect ws://user:TEST_SECRET_123@198.51.100.10:8080/ws?sig=TEST_SECRET_456 refused',
    'proxy connect user:TEST_SECRET_123@proxy.example.com:8080 failed',
    'upstream body: {"url":"https:\\/\\/user:TEST_SECRET_123@example.com\\/cb?code=TEST_SECRET_456"}',
    'auth header rejected: api_key: TEST_SECRET_123, access_token: "TEST_SECRET_456"',
    'login error password=TEST_SECRET_123',
  ];
  for (const sample of secretSamples) {
    const cleanErr = sanitizeErrorMessageForSpan(sample);
    const cleanAttrs = sanitizeSpanAttributes({ detail: sample });
    assert.ok(!cleanErr.includes('TEST_SECRET_'), `sanitizeErrorMessageForSpan leaked secret in: ${cleanErr}`);
    assert.ok(!String(cleanAttrs.detail).includes('TEST_SECRET_'), `sanitizeSpanAttributes leaked secret in: ${String(cleanAttrs.detail)}`);
  }

  // EF-BLIND-05: Nested-list dedent before fenced code block preserves fence state across `computeMarkdownSliceCheckpoints` & `sanitizeMarkdownPageSlice`
  const docC2 = [
    '1. first',
    '   - nested',
    `   prose in first ${'z'.repeat(80)}`,
    '     ```html',
    '   <b>RAW_HTML_MARKER</b>',
    '   ```',
    '',
    'Normal prose outside code block.',
  ].join('\n');
  const cleanFull = sanitizeFullMarkdownDocumentForArtifact(docC2);
  const cps = computeMarkdownSliceCheckpoints(cleanFull, 32);
  const markerIdx = cleanFull.indexOf('   <b>RAW_HTML_MARKER</b>');
  assert.ok(markerIdx > 0);
  const slicedMd = sanitizeMarkdownPageSlice(cleanFull, markerIdx, cleanFull.slice(markerIdx), false, cps);
  assert.ok(slicedMd.includes('<b>RAW_HTML_MARKER</b>'), `Literal code inside reopened fence should not be escaped: ${slicedMd}`);
  const afterProse = slicedMd.slice(slicedMd.indexOf('Normal prose outside code block.'));
  assert.ok(!afterProse.includes('```'), `Trailing prose outside code block must NOT be wrapped in an inverted fence: ${slicedMd}`);

  // Stored Shopify catalog snapshot with `currency: null` backfills currency via `/meta.json` on `getCatalogRecords`
  resetCatalogStateForTests();
  const catCreate = await executeCatalogCall({
    payload: { url: 'https://www.allbirds.example.com/', maxPages: 1, fields: 'lean' },
    executeHubFetch: async ({ url: u }) => {
      if (u.includes('/products.json')) {
        return {
          status: 200,
          body: JSON.stringify({
            products: [
              {
                id: 101,
                title: 'Wool Runner',
                handle: 'wool-runner',
                vendor: 'Allbirds',
                product_type: 'Shoes',
                tags: ['wool'],
                variants: [{ id: 201, title: '10', price: '98.00', available: true }],
              },
            ],
          }),
        };
      }
      // Simulate initial run when /meta.json temporarily failed so stored snapshot has `currency: null`
      return { status: 503, body: '' };
    },
  });
  const catId = String(catCreate.body.catalogId);
  const pagedBackfill = await getCatalogRecords({
    catalogId: catId,
    fields: 'lean',
    executeHubFetch: async ({ url: u }) => {
      assert.ok(!u.endsWith('/cart.js'), 'Should hit /meta.json first without needing /cart.js');
      if (u.endsWith('/meta.json')) {
        return { status: 200, body: JSON.stringify({ currency: 'USD' }) };
      }
      return { status: 404, body: '' };
    },
  });
  assert.equal(pagedBackfill.status, 200);
  const leanRecs = pagedBackfill.body.records as Array<{ currency: string | null }>;
  assert.equal(leanRecs[0]?.currency, 'USD');

  // B1: `interact` stores PNG screenshots in R2 (`private/<userId>/...`) returning `screenshotArtifactId`,
  // and MCP `tools/call` `interact` strips inline 188K `screenshotBase64` from text output while REST preserves `screenshotBase64`.
  const bigPngBytes = Buffer.alloc(140_000, 0x89);
  const bigPngB64 = bigPngBytes.toString('base64');
  assert.ok(bigPngB64.length > 180_000);
  const interactRes = await executeInteractCall({
    payload: {
      url: 'https://news.ycombinator.com/',
      formats: ['markdown', 'screenshot'],
    },
    env: { ARTIFACTS: mockBucket as unknown as R2Bucket },
    userId: 'user_alice',
    executeHubFetch: async () => ({
      status: 200,
      via: 'agent:site-win-vm',
      bodyText: JSON.stringify({
        results: [
          {
            id: 'interact-1',
            url: 'https://news.ycombinator.com/',
            finalUrl: 'https://news.ycombinator.com/',
            status: 200,
            outcome: 'ok',
            contentType: 'text/html',
            body: '<html><head><title>Hacker News</title></head><body><main><h1>Hacker News</h1></main></body></html>',
            screenshotBase64: bigPngB64,
          },
        ],
      }),
    }),
  });
  assert.equal(interactRes.status, 200);
  const shotArtId = String(interactRes.body.screenshotArtifactId ?? '');
  assert.match(shotArtId, /^[0-9a-f]{64}$/);
  assert.equal(interactRes.body.screenshotBytes, bigPngBytes.byteLength);
  assert.equal(interactRes.body.screenshotMimeType, 'image/png');
  assert.equal(interactRes.body.screenshotBase64, bigPngB64, 'REST /v1/interact retains screenshotBase64 for SDK compatibility');
  assert.ok(
    [...r2Map.keys()].some((k) => k.startsWith('private/user_alice/tmp/sha256/') && k.includes(shotArtId)),
    'Interact screenshot artifact must be stored under private/<userId>/tmp/sha256/',
  );

  const mcpResp = await handleMcpRequest(
    new Request('https://hub.example/mcp', {
      method: 'POST',
      headers: {
        authorization: 'Bearer test-caller-secret-0123456789abcdef',
        'content-type': 'application/json',
        accept: 'application/json, text/event-stream',
        'mcp-protocol-version': '2025-03-26',
      },
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: 77,
        method: 'tools/call',
        params: {
          name: 'interact',
          arguments: { url: 'https://news.ycombinator.com/', formats: ['markdown', 'screenshot'] },
        },
      }),
    }),
    new URL('https://hub.example/mcp'),
    {
      ownerSecret: 'test-caller-secret-0123456789abcdef',
      allowedTargets: ['auto', 'agent', 'container'],
      defaultTarget: 'auto',
      executeFetch: async () => ({ status: 200, via: 'hub', bodyText: '{}' }),
      executeInteract: async () => interactRes,
    },
  );
  assert.equal(mcpResp.status, 200);
  const mcpJson = (await mcpResp.json()) as { result: { content: Array<{ type: string; text: string }> } };
  const mcpText = mcpJson.result.content[0]!.text;
  assert.ok(mcpText.length < 2_000, `Expected compact MCP interact JSON (< 2 KB), got ${mcpText.length} chars`);
  const parsedMcpInteract = JSON.parse(mcpText) as Record<string, unknown>;
  assert.equal(parsedMcpInteract.screenshotArtifactId, shotArtId);
  assert.equal(parsedMcpInteract.screenshotBase64, undefined, 'MCP interact text must omit 188K inline screenshotBase64');
});

test('Wikipedia Spec Acceptance Suite (#1..#7): mediawiki cleanup, detected.adapter, redirects, de.wikipedia, Tier 2 resolver, robots suggestion, 24h cache & 201st use_bulk_channel', async () => {
  resetWikipediaStateForTests();
  resetSearchProviderPacingForTests();

  const wikiR2Map = new Map<string, { bytes: Uint8Array; customMetadata?: Record<string, string>; uploaded: Date }>();
  const wikiBucket = {
    get: async (k: string) => {
      const found = wikiR2Map.get(k);
      if (!found) return null;
      return {
        key: k,
        size: found.bytes.byteLength,
        uploaded: found.uploaded,
        customMetadata: found.customMetadata,
        body: new Blob([found.bytes]).stream(),
        arrayBuffer: async () => found.bytes.slice().buffer,
        text: async () => new TextDecoder().decode(found.bytes),
        json: async () => JSON.parse(new TextDecoder().decode(found.bytes)),
      };
    },
    head: async (k: string) => {
      const found = wikiR2Map.get(k);
      return found ? { key: k, size: found.bytes.byteLength, uploaded: found.uploaded, customMetadata: found.customMetadata } : null;
    },
    put: async (k: string, val: string | Uint8Array, opts?: { customMetadata?: Record<string, string> }) => {
      const bytes = typeof val === 'string' ? new TextEncoder().encode(val) : new Uint8Array(val);
      const rec = { bytes, customMetadata: opts?.customMetadata, uploaded: new Date() };
      wikiR2Map.set(k, rec);
      return rec;
    },
    delete: async (k: string) => {
      wikiR2Map.delete(k);
    },
  };

  let outboundFetches = 0;
  const http2WikiHtml = `<!doctype html>
<html lang="en">
<head>
  <meta name="generator" content="MediaWiki 1.48.0-wmf.5">
  <link rel="canonical" href="https://en.wikipedia.org/wiki/HTTP/2">
  <title>HTTP/2 - Wikipedia</title>
</head>
<body>
  <main>
    <p>[Jump to content](#bodyContent)</p>
    <p>[ ] Toggle the table of contents</p>
    <h1>HTTP/2</h1>
    <p>38 languages</p>
    <p><a href="https://www.wikidata.org/wiki/Special:EntityPage/Q18691915#sitelinks-wikipedia">Edit links</a></p>
    <p>From Wikipedia, the free encyclopedia</p>
    <table class="infobox">
      <tr><th>Communication protocol</th><td>HTTP/2</td></tr>
      <tr><th>RFC</th><td>RFC 9113</td></tr>
    </table>
    <p><b>HTTP/2</b> is a major revision of the HTTP network protocol<sup class="reference"><a href="#cite_note-1">[1]</a></sup><sup class="reference"><a href="#cite_note-2">[2]</a></sup>.</p>
    <h2>History <span class="mw-editsection"><a href="/w/index.php?title=HTTP/2&amp;action=edit&amp;section=1">[edit]</a></span></h2>
    <p>Standardized in May 2015 [ ] with multiplexing support [3].</p>
    <h2>Navigation menu</h2>
    <p>Personal tools</p>
  </main>
</body>
</html>`;

  // #1 & #6: Scrape `/wiki/HTTP/2` -> clean Markdown (no `[ ]`, no `Edit links`, no `[1]`/`[2]`, infobox table kept, `detected.adapter == "mediawiki"`),
  // AND immediate re-scrape hits default 24h cache (`cached: true`, 0 new outbound requests)!
  const t1 = await executeScrapeCall({
    payload: { url: 'https://en.wikipedia.org/wiki/HTTP/2' },
    env: { ARTIFACTS: wikiBucket as unknown as R2Bucket },
    executeHubFetch: async () => {
      outboundFetches++;
      return {
        status: 200,
        via: 'agent:site-x86',
        bodyText: JSON.stringify({
          results: [
            {
              id: 'scrape-1',
              url: 'https://en.wikipedia.org/wiki/HTTP/2',
              finalUrl: 'https://en.wikipedia.org/wiki/HTTP/2',
              status: 200,
              outcome: 'ok',
              contentType: 'text/html; charset=utf-8',
              headers: { etag: 'W/"wiki-http2-v1"' },
              body: http2WikiHtml,
            },
          ],
        }),
      };
    },
  });
  assert.equal(t1.status, 200);
  assert.equal(outboundFetches, 1);
  const md1 = String(t1.body.markdown ?? '');
  assert.ok(!md1.includes('[ ]'), `Expected no stray [ ] in: ${md1}`);
  assert.ok(!md1.includes('Edit links'), `Expected no Edit links in: ${md1}`);
  assert.ok(!/\[\d+\]/.test(md1), `Expected no [n] citation markers in: ${md1}`);
  assert.ok(!md1.includes('[edit]'), `Expected no [edit] in: ${md1}`);
  assert.ok(md1.includes('RFC 9113'), `Expected infobox table preserved in: ${md1}`);
  assert.equal((t1.body.detected as { adapter?: string })?.adapter, 'mediawiki');

  // #6: Re-scrape within default 24h maxAgeMs -> `cached: true`, ZERO outbound fetches!
  const t6 = await executeScrapeCall({
    payload: { url: 'https://en.wikipedia.org/wiki/HTTP/2' },
    env: { ARTIFACTS: wikiBucket as unknown as R2Bucket },
    executeHubFetch: async () => {
      outboundFetches++;
      throw new Error('Should NOT make an outbound fetch on cached Wikipedia re-scrape!');
    },
  });
  assert.equal(t6.status, 200);
  assert.equal(t6.body.cached, true);
  assert.equal(outboundFetches, 1);
  assert.equal((t6.body.detected as { adapter?: string })?.adapter, 'mediawiki');

  // #2: Internal MediaWiki HTTP-200 `#REDIRECT [[HTTP/2]]` (`/wiki/HTTP2` -> `<link rel="canonical" href=".../wiki/HTTP/2">`)
  // promotes `finalUrl` to `"https://en.wikipedia.org/wiki/HTTP/2"`
  const t2 = await executeScrapeCall({
    payload: { url: 'https://en.wikipedia.org/wiki/HTTP2' },
    env: {},
    executeHubFetch: async () => ({
      status: 200,
      via: 'agent:site-arm64',
      bodyText: JSON.stringify({
        results: [
          {
            id: 'scrape-1',
            url: 'https://en.wikipedia.org/wiki/HTTP2',
            finalUrl: 'https://en.wikipedia.org/wiki/HTTP2',
            status: 200,
            outcome: 'ok',
            contentType: 'text/html; charset=utf-8',
            body: http2WikiHtml,
          },
        ],
      }),
    }),
  });
  assert.equal(t2.status, 200);
  assert.equal(t2.body.finalUrl, 'https://en.wikipedia.org/wiki/HTTP/2');

  // Conditional GET (`If-None-Match`) on Wikipedia refresh (`maxAgeMs: 0`) sends `ifNoneMatch` and handles `304 Not Modified`
  const tReval = await executeScrapeCall({
    payload: { url: 'https://en.wikipedia.org/wiki/HTTP/2', maxAgeMs: 0 },
    env: { ARTIFACTS: wikiBucket as unknown as R2Bucket },
    executeHubFetch: async (_target, rawBody) => {
      const reqObj = JSON.parse(rawBody) as { requests: Array<{ ifNoneMatch?: string }> };
      assert.equal(reqObj.requests[0]?.ifNoneMatch, 'W/"wiki-http2-v1"');
      return {
        status: 200,
        via: 'agent:site-x86',
        bodyText: JSON.stringify({
          results: [{ id: 'scrape-1', url: 'https://en.wikipedia.org/wiki/HTTP/2', status: 304, outcome: 'ok' }],
        }),
      };
    },
  });
  assert.equal(tReval.status, 200);
  assert.equal(tReval.body.cached, true);
  assert.equal(tReval.body.revalidated, true);
  assert.equal((tReval.body.detected as { adapter?: string })?.adapter, 'mediawiki');

  // #3: Non-English wiki (`de.wikipedia.org`) strips German `Links bearbeiten` & `[Bearbeiten]`
  const t3 = await executeScrapeCall({
    payload: { url: 'https://de.wikipedia.org/wiki/Hypertext%20Transfer%20Protocol' },
    env: {},
    executeHubFetch: async (_target, rawBody) => {
      const parsedReq = JSON.parse(rawBody) as { requests: Array<{ url: string }> };
      assert.equal(parsedReq.requests[0]?.url, 'https://de.wikipedia.org/wiki/Hypertext_Transfer_Protocol');
      return {
        status: 200,
        via: 'agent:site-win-vm',
        bodyText: JSON.stringify({
          results: [
            {
              id: 'scrape-1',
              url: 'https://de.wikipedia.org/wiki/Hypertext_Transfer_Protocol',
              finalUrl: 'https://de.wikipedia.org/wiki/Hypertext_Transfer_Protocol',
              status: 200,
              outcome: 'ok',
              contentType: 'text/html; charset=utf-8',
              body: `<!doctype html><html lang="de"><head><meta name="generator" content="MediaWiki 1.48.0"></head><body><main><h1>Hypertext Transfer Protocol</h1><p><a href="https://www.wikidata.org/wiki/Special:EntityPage/Q8777#sitelinks-wikipedia">Links bearbeiten</a></p><p>Das HTTP Protokoll<a href="#cite_note-1">[1]</a>.</p><h2>Geschichte <a href="/w/index.php?title=HTTP&amp;action=edit">[Bearbeiten | Quelltext bearbeiten]</a></h2></main></body></html>`,
            },
          ],
        }),
      };
    },
  });
  assert.equal(t3.status, 200);
  assert.equal((t3.body.detected as { adapter?: string })?.adapter, 'mediawiki');
  assert.ok(!String(t3.body.markdown).includes('Links bearbeiten'));
  assert.ok(!String(t3.body.markdown).includes('Bearbeiten'));

  // #4: Tier 2 resolver (`wikipedia: true`) returns `/wiki/Robots.txt` in top 3, drops Special:/Talk:/w/:/api/, and makes ZERO origin/map requests!
  let hubFetchDuringWikiSearch = 0;
  const t4 = await executeSearchCall({
    payload: { query: 'polite web crawler robots.txt', wikipedia: true, lang: 'en', maxResults: 5 },
    env: { SERPER_API_KEY: 'serper-test-key' },
    executeHubFetch: async () => {
      hubFetchDuringWikiSearch++;
      return { status: 200, via: 'agent', bodyText: '{"results":[]}' };
    },
    providerFetchFn: async (_url, init) => {
      const reqBody = JSON.parse(String(init?.body ?? '{}')) as { q: string };
      assert.match(reqBody.q, /^site:en\.wikipedia\.org\b/);
      return new Response(
        JSON.stringify({
          organic: [
            { title: 'Search results - Wikipedia', link: 'https://en.wikipedia.org/wiki/Special:Search?search=robots.txt', snippet: 'Special search' },
            { title: 'Robots.txt - Wikipedia', link: 'https://en.wikipedia.org/wiki/Robots.txt#Examples', snippet: 'Robots Exclusion Protocol standard' },
            { title: 'Talk:Robots.txt - Wikipedia', link: 'https://en.wikipedia.org/wiki/Talk:Robots.txt', snippet: 'Talk page' },
            { title: 'API - Wikipedia', link: 'https://en.wikipedia.org/w/api.php?action=query', snippet: 'Action API' },
            { title: 'Web crawler - Wikipedia', link: 'https://en.wikipedia.org/wiki/Web%20crawler', snippet: 'Internet bot that systematically browses' },
          ],
        }),
        { status: 200, headers: { 'content-type': 'application/json' } },
      );
    },
  });
  assert.equal(t4.status, 200);
  assert.equal(hubFetchDuringWikiSearch, 0, 'Tier 2 search with SERP hits must make 0 requests to Wikipedia');
  const t4Urls = (t4.body.results as Array<{ url: string; canonicalTitle?: string }>).map((r) => r.url);
  assert.deepEqual(t4Urls, ['https://en.wikipedia.org/wiki/Robots.txt', 'https://en.wikipedia.org/wiki/Web_crawler']);

  // #5: `fetch_url https://en.wikipedia.org/w/api.php?action=query&titles=HTTP/2` -> `blocked.reason == "robots"` with Wikipedia suggestion
  const t5Resp = await handleMcpRequest(
    new Request('https://hub.example/mcp', {
      method: 'POST',
      headers: {
        authorization: 'Bearer test-caller-secret-0123456789abcdef',
        'content-type': 'application/json',
        accept: 'application/json, text/event-stream',
        'mcp-protocol-version': '2025-03-26',
      },
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: 88,
        method: 'tools/call',
        params: {
          name: 'fetch_url',
          arguments: { url: 'https://en.wikipedia.org/w/api.php?action=query&titles=HTTP/2' },
        },
      }),
    }),
    new URL('https://hub.example/mcp'),
    {
      ownerSecret: 'test-caller-secret-0123456789abcdef',
      allowedTargets: ['auto', 'agent', 'container'],
      defaultTarget: 'auto',
      executeFetch: async () => ({
        status: 200,
        via: 'agent:site-x86',
        bodyText: JSON.stringify({
          results: [
            {
              id: 'mcp-1',
              url: 'https://en.wikipedia.org/w/api.php?action=query&titles=HTTP/2',
              status: 0,
              outcome: 'skip',
              problem: 'disallowed by robots.txt',
            },
          ],
          summary: { total: 1, byOutcome: { skip: 1 } },
        }),
      }),
    },
  );
  const t5Json = JSON.parse(((await t5Resp.json()) as { result: { content: Array<{ text: string }> } }).result.content[0]!.text) as {
    blocked?: { reason: string; suggestion: string };
  };
  assert.equal(t5Json.blocked?.reason, 'robots');
  assert.match(t5Json.blocked?.suggestion ?? '', /Wikipedia search and API paths are robots-disallowed/);
  assert.match(t5Json.blocked?.suggestion ?? '', /site:en\.wikipedia\.org/);

  // #7: 201st live article request in an hour from one caller -> `outcome: "use_bulk_channel"`
  resetWikipediaStateForTests();
  for (let i = 1; i <= 200; i++) {
    const okRes = await executeScrapeCall({
      payload: { url: `https://en.wikipedia.org/wiki/Topic_${i}`, noCache: true },
      env: {},
      userId: 'caller_bulk_test',
      executeHubFetch: async () => ({
        status: 200,
        via: 'agent:site-x86',
        bodyText: JSON.stringify({
          results: [
            {
              id: 'scrape-1',
              url: `https://en.wikipedia.org/wiki/Topic_${i}`,
              finalUrl: `https://en.wikipedia.org/wiki/Topic_${i}`,
              status: 200,
              outcome: 'ok',
              contentType: 'text/html',
              body: '<html><body><main><h1>Topic</h1><p>Body</p></main></body></html>',
            },
          ],
        }),
      }),
    });
    assert.equal(okRes.status, 200);
  }
  const bulkBlocked = await executeScrapeCall({
    payload: { url: 'https://en.wikipedia.org/wiki/Topic_201', noCache: true },
    env: {},
    userId: 'caller_bulk_test',
    executeHubFetch: async () => {
      throw new Error('201st request must NOT hit origin!');
    },
  });
  assert.equal(bulkBlocked.status, 429);
  assert.equal(bulkBlocked.body.outcome, 'use_bulk_channel');
  assert.ok(String((bulkBlocked.body.bulkChannels as { wikimediaEnterprise: string })?.wikimediaEnterprise).includes('enterprise.wikimedia.com'));
  resetWikipediaStateForTests();
});

test('Live Trace Remediation Suite: ATS 404 fast-return, closed ?error=true Chromium suppression, IC vs Manager role matching, & list_agents browserConfinement', async () => {
  resetJobsCacheForTests();

  // 1. Non-existent hosted ATS board (`boards.greenhouse.io/nonexistent`) makes 1 fetch (not 3) and returns 404 immediately
  let ghBoardFetches = 0;
  const gh404Board = await executeScrapeCall({
    payload: { url: 'https://boards.greenhouse.io/nonexistent' },
    env: {},
    executeHubFetch: async (_target, rawBody) => {
      ghBoardFetches++;
      const parsed = JSON.parse(rawBody) as { requests: Array<{ id: string; url: string }> };
      assert.equal(parsed.requests[0]?.id, 'ats-greenhouse-board');
      return {
        status: 200,
        via: 'agent:site-x86',
        bodyText: JSON.stringify({
          results: [{ id: 'ats-greenhouse-board', url: parsed.requests[0]!.url, status: 404, outcome: 'error', problem: 'HTTP 404' }],
        }),
      };
    },
  });
  assert.equal(gh404Board.status, 404);
  assert.equal(gh404Board.body.outcome, 'not_found');
  assert.equal(ghBoardFetches, 1, 'Authoritative Greenhouse 404 must NOT fall through to twin-greenhouse-board or HTML scrape-1');

  // 2. Closed Greenhouse job (`job-boards.greenhouse.io/devrev/jobs/6174459004`) returning 404 on boards-api returns `closed_posting` in 1 fetch (0 Chromium renders!)
  let ghJobFetches = 0;
  const ghClosedJob = await executeScrapeCall({
    payload: { url: 'https://job-boards.greenhouse.io/devrev/jobs/6174459004' },
    env: {},
    executeHubFetch: async (_target, rawBody) => {
      ghJobFetches++;
      const parsed = JSON.parse(rawBody) as { requests: Array<{ id: string; url: string; kind?: string }> };
      assert.notEqual(parsed.requests[0]?.kind, 'render', 'Closed Greenhouse job must NEVER launch headless Chromium!');
      return {
        status: 200,
        via: 'agent:site-x86',
        bodyText: JSON.stringify({
          results: [{ id: 'ats-greenhouse-job', url: parsed.requests[0]!.url, status: 404, outcome: 'error', problem: 'HTTP 404' }],
        }),
      };
    },
  });
  assert.equal(ghClosedJob.status, 404);
  assert.equal(ghClosedJob.body.contentState, 'closed_posting');
  assert.equal(ghJobFetches, 1);

  // 3. Direct thin SPA redirect to `?error=true` skips `auto-render-1` Chromium
  let errRedirectCalls = 0;
  const directErrRedirect = await executeScrapeCall({
    payload: { url: 'https://job-boards.greenhouse.io/devrev?error=true' },
    env: {},
    executeHubFetch: async (_target, rawBody) => {
      errRedirectCalls++;
      const parsed = JSON.parse(rawBody) as { requests: Array<{ id: string; kind?: string }> };
      assert.notEqual(parsed.requests[0]?.id, 'auto-render-1', 'Must not trigger auto-render-1 on ?error=true closed_posting');
      return {
        status: 200,
        via: 'agent:site-x86',
        bodyText: JSON.stringify({
          results: [
            {
              id: 'scrape-1',
              url: 'https://job-boards.greenhouse.io/devrev?error=true',
              finalUrl: 'https://job-boards.greenhouse.io/devrev?error=true',
              status: 200,
              outcome: 'ok',
              contentType: 'text/html; charset=utf-8',
              body: '<!doctype html><html><head><script src="/app.js"></script></head><body><div id="root">Current Openings</div></body></html>',
            },
          ],
        }),
      };
    },
  });
  assert.equal(directErrRedirect.status, 200);
  assert.equal(directErrRedirect.body.contentState, 'closed_posting');
  assert.equal(errRedirectCalls, 1);

  // 4. IC role query ("Security Engineer") does NOT match "Security Engineering Manager" via snippet fallback
  const icFilterRes = await executeJobsCall({
    payload: { query: 'Security Engineer', includeBuiltIn: false },
    env: { SERPER_API_KEY: 'serper-test' },
    executeSearch: async (sArgs) => {
      assert.equal(sArgs.mode, 'serper', 'Speculative ATS queries must pass mode=serper when SERPER_API_KEY is set');
      return { status: 200, body: { results: [{ url: 'https://jobs.ashbyhq.com/acme' }] } };
    },
    executeScrape: async () => ({
      status: 200,
      body: {
        ok: true,
        extractorId: 'ashby-board',
        jobs: [
          {
            title: 'Security Engineering Manager',
            company: 'Acme',
            url: 'https://jobs.ashbyhq.com/acme/mgr-1',
            applyUrl: 'https://jobs.ashbyhq.com/acme/mgr-1/application',
            workplaceType: 'remote',
            locations: ['Remote - US'],
            pay: null,
            postedAt: new Date().toISOString(),
            source: 'ashby',
            snippet: 'Lead a distributed team of Security Engineers building cloud infrastructure.',
          },
          {
            title: 'Senior Security Engineer',
            company: 'Acme',
            url: 'https://jobs.ashbyhq.com/acme/ic-1',
            applyUrl: 'https://jobs.ashbyhq.com/acme/ic-1/application',
            workplaceType: 'remote',
            locations: ['Remote - US'],
            pay: null,
            postedAt: new Date().toISOString(),
            source: 'ashby',
            snippet: 'Hands-on security engineering role.',
          },
        ],
      },
    }),
  });
  const icTitles = (icFilterRes.body.jobs as Array<{ title: string }>).map((j) => j.title);
  assert.deepEqual(icTitles, ['Senior Security Engineer']);

  // 5. `list_agents` surfaces `browserConfinement: "container-mac+loopback-proxy"` when `browser-v1` + `browserSandbox: "off"`
  const listAgentsResp = await handleMcpRequest(
    new Request('https://hub.example/mcp', {
      method: 'POST',
      headers: {
        authorization: 'Bearer test-caller-secret-0123456789abcdef',
        'content-type': 'application/json',
        accept: 'application/json, text/event-stream',
        'mcp-protocol-version': '2025-03-26',
      },
      body: JSON.stringify({ jsonrpc: '2.0', id: 99, method: 'tools/call', params: { name: 'list_agents', arguments: {} } }),
    }),
    new URL('https://hub.example/mcp'),
    {
      ownerSecret: 'test-caller-secret-0123456789abcdef',
      allowedTargets: ['auto', 'agent', 'container'],
      defaultTarget: 'auto',
      executeFetch: async () => ({ status: 200, via: 'hub', bodyText: '{}' }),
      listFleet: async () => ({
        connected: 1,
        agents: [
          {
            siteId: 'site-x86',
            arch: 'amd64',
            version: '2.7.7',
            browserSandbox: 'off',
            capabilities: ['artifacts-v1', 'browser-v1', 'pdf-v1'],
            connectedAt: 1000,
            jobsOk: 10,
            jobsErr: 0,
          },
        ],
        affinities: [],
      }),
    },
  );
  const fleetOut = JSON.parse(((await listAgentsResp.json()) as { result: { content: Array<{ text: string }> } }).result.content[0]!.text) as {
    agents: Array<{ browserSandbox?: string; browserConfinement?: string }>;
  };
  assert.equal(fleetOut.agents[0]?.browserSandbox, 'off');
  assert.equal(fleetOut.agents[0]?.browserConfinement, 'container-mac+loopback-proxy');
});
