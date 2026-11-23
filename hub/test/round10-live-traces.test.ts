import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import test from 'node:test';
import { AgentHubEngine, createMemoryCooldownStore, routeFetchWithFailover, type HubSocketLike } from '../src/agent-hub.ts';
import { executeCatalogCall, resetCatalogStateForTests } from '../src/catalog.ts';
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
import { ensureD1ColumnIfMissing, executeExtractCall } from '../src/search-index.ts';
import { isEligibleForExternalSpaFallback } from '../src/spa-fallback.ts';

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
});
