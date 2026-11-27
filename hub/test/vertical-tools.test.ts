import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import test from 'node:test';

import { executeCompanyCall } from '../src/company';
import { executeJobsCall, resetJobsCacheForTests } from '../src/jobs';
import { executeSalariesCall, recordSalaryObservations } from '../src/salaries';
import { NodeSqliteD1Database } from './stubs/cf-storage-mocks';

const wdStr = (value: string) => ({ mainsnak: { snaktype: 'value', datavalue: { type: 'string', value } }, rank: 'normal' });
const wdEntity = (id: string, label: string, description: string, claims: Record<string, unknown[]>) => ({
  id,
  type: 'item',
  labels: { en: { language: 'en', value: label } },
  descriptions: { en: { language: 'en', value: description } },
  claims,
});
const decoy = wdEntity('Q900001', 'Acme Widgets', 'fictional band', { P856: [wdStr('https://acmewidgets.net/')] });
const real = wdEntity('Q900002', 'Acme Widgets', 'American widget manufacturing company', {
  P856: [wdStr('https://www.acmewidgets.com/')],
  P5531: [wdStr('0000123456')],
});

test('VERT-1: company profile merges homepage JSON-LD, domain-corroborated Wikidata, SEC, hiring, and Google Maps', async () => {
  const fetched: string[] = [];
  const fetchFn = (async (input: RequestInfo | URL) => {
    const u = String(input);
    fetched.push(u);
    if (u.includes('wbsearchentities')) {
      return Response.json({
        search: [
          { id: 'Q900001', label: 'Acme Widgets', description: 'fictional band' },
          { id: 'Q900002', label: 'Acme Widgets', description: 'American widget manufacturing company' },
        ],
      });
    }
    if (u.includes('wbgetentities') && /props=labels(?:&|$)/.test(decodeURIComponent(u))) return Response.json({ entities: {} });
    if (u.includes('wbgetentities') || u.includes('Special:EntityData')) {
      return Response.json({ entities: { Q900001: decoy, Q900002: real } });
    }
    if (u.includes('data.sec.gov/submissions/CIK0000123456.json')) {
      return Response.json({
        cik: '123456',
        name: 'ACME WIDGETS INC',
        sic: '3569',
        sicDescription: 'General Industrial Machinery',
        tickers: ['ACMW'],
        exchanges: ['Nasdaq'],
        addresses: { business: { city: 'SPRINGFIELD', stateOrCountry: 'IL' } },
      });
    }
    if (u.includes('companyfacts')) return Response.json({ cik: 123456, facts: {} });
    return new Response('not found', { status: 404 });
  }) as unknown as typeof fetch;
  const homepageHtml =
    '<html><head><title>Acme Widgets</title><script type="application/ld+json">' +
    JSON.stringify({
      '@context': 'https://schema.org',
      '@type': 'Organization',
      name: 'Acme Widgets',
      url: 'https://www.acmewidgets.com/',
      description: 'We build widgets.',
      sameAs: ['https://www.linkedin.com/company/acme-widgets/', 'javascript:alert(1)'],
    }) +
    '</script></head><body><h1>Acme</h1></body></html>';
  const mapsQueries: string[] = [];

  const res = await executeCompanyCall({
    payload: { name: 'Acme Widgets', domain: 'acmewidgets.com' },
    deps: {
      scrapePage: async (pageUrl) =>
        pageUrl.endsWith('/about')
          ? { status: 404, body: { ok: false } }
          : { status: 200, body: { ok: true, finalUrl: pageUrl, title: 'Acme Widgets', rawHtml: homepageHtml, metadata: { description: 'We build widgets.' } } },
      fetchFn,
      runJobs: async () => ({
        status: 200,
        body: {
          ok: true,
          count: 2,
          jobs: [
            { title: 'Widget Engineer', url: 'https://boards.greenhouse.io/acmewidgets/jobs/1', source: 'greenhouse', locations: ['Remote'] },
            { title: 'Sales Lead', url: 'https://boards.greenhouse.io/acmewidgets/jobs/2', source: 'greenhouse', locations: ['Springfield, IL'] },
          ],
        },
      }),
      callMapsPlaces: async (query) => {
        mapsQueries.push(query);
        return JSON.stringify({
          places: [
            { displayName: { text: 'Acme Widgets HQ' }, formattedAddress: '1 Widget Way, Springfield, IL', websiteUri: 'https://www.acmewidgets.com/', googleMapsUri: 'https://maps.google.com/?cid=1', rating: 4.4, userRatingCount: 120 },
            { displayName: { text: 'Acme Widgets (other)' }, formattedAddress: 'Elsewhere', websiteUri: 'https://acmewidgets.net/' },
          ],
        });
      },
    },
  });
  assert.equal(res.status, 200, JSON.stringify(res.body).slice(0, 500));
  const p = res.body as Record<string, any>;
  assert.equal(p.wikidataId, 'Q900002', 'domain-corroborated entity wins over the same-name decoy');
  assert.equal(p.cik, '0000123456');
  assert.equal(p.ticker, 'ACMW');
  assert.ok(String(p.legalName ?? '').toUpperCase().includes('ACME WIDGETS'));
  assert.equal(p.hiring?.openRoles, 2);
  assert.equal(p.place?.name, 'Acme Widgets HQ', 'Maps place matched by website domain, not the decoy');
  assert.equal(p.googleMaps, 'used');
  assert.ok(mapsQueries[0]?.toLowerCase().includes('acme widgets'));
  assert.ok(p.fieldSources && typeof p.fieldSources === 'object' && Object.keys(p.fieldSources).length > 3);
  assert.ok(!JSON.stringify(p).includes('javascript:'), 'unsafe sameAs links are dropped');
  assert.equal(typeof p.markdown, 'string');

  // No Maps MCP connected -> reported as not_connected, profile still built.
  const noMaps = await executeCompanyCall({
    payload: { domain: 'acmewidgets.com', includeHiring: false },
    deps: { scrapePage: async () => ({ status: 404, body: { ok: false } }), fetchFn },
  });
  assert.equal(noMaps.status, 200);
  assert.equal((noMaps.body as Record<string, unknown>).googleMaps, 'not_connected');

  // Input validation.
  const bad = await executeCompanyCall({ payload: {}, deps: { scrapePage: async () => ({ status: 404, body: {} }), fetchFn } });
  assert.equal(bad.status, 400);
});

test('VERT-2: jobs searches record employer-posted pay; salaries aggregates them and tops up when data is thin', async () => {
  const workDir = mkdtempSync(join(tmpdir(), 'ef-salaries-'));
  const metaDb = new NodeSqliteD1Database(join(workDir, 'meta.sqlite'), [resolve('migrations/meta/0001_tracking.sql')]);
  try {
    const pay = (min: number, max: number) => ({ min, max, currency: 'USD', period: 'year', basis: 'base', raw: `$${min}-$${max}` });
    const jobs = [
      { title: 'Senior Software Engineer', company: 'alpha', url: 'https://boards.greenhouse.io/alpha/jobs/1', source: 'greenhouse', locations: ['Remote - US'], workplaceType: 'remote', pay: pay(180_000, 220_000) },
      { title: 'Sr. Software Engineer, Backend', company: 'beta', url: 'https://jobs.lever.co/beta/2', source: 'lever', locations: ['New York, NY'], workplaceType: 'hybrid', pay: pay(170_000, 210_000) },
      { title: 'Senior Software Engineer', company: 'gamma', url: 'https://jobs.ashbyhq.com/gamma/3', source: 'ashby', locations: ['San Francisco, CA'], workplaceType: 'onsite', pay: pay(190_000, 240_000) },
      { title: 'Office Manager', company: 'gamma', url: 'https://jobs.ashbyhq.com/gamma/4', source: 'ashby', locations: ['Austin, TX'], workplaceType: 'onsite', pay: pay(60_000, 70_000) },
      { title: 'Senior Software Engineer', company: 'delta', url: 'https://boards.greenhouse.io/delta/jobs/5', source: 'greenhouse', locations: ['Remote'], workplaceType: 'remote' },
    ];
    const recorded = await recordSalaryObservations(metaDb as unknown as D1Database, jobs as never, Date.UTC(2026, 10, 20));
    assert.equal(recorded, 4, 'postings without pay are not recorded');

    let topUps = 0;
    const res = await executeSalariesCall({
      payload: { title: 'Senior Software Engineer' },
      env: { META: metaDb as unknown as D1Database },
      runJobsSearch: async () => {
        topUps++;
      },
      now: Date.UTC(2026, 10, 27),
    });
    assert.equal(res.status, 200, JSON.stringify(res.body).slice(0, 400));
    const body = res.body as Record<string, any>;
    assert.equal(body.matched, 3, 'three senior SWE ranges; the office manager is a different family');
    assert.equal(body.currency, 'USD');
    assert.ok(body.midpoint.median >= 195_000 && body.midpoint.median <= 215_000, `median ${body.midpoint.median}`);
    assert.equal(topUps, 1, 'fewer than 5 observations triggers one live top-up search');
    assert.equal(body.refreshed, true);

    const missing = await executeSalariesCall({ payload: {}, env: { META: metaDb as unknown as D1Database } });
    assert.equal(missing.status, 400);
  } finally {
    metaDb.close();
    rmSync(workDir, { recursive: true, force: true });
  }
});

test('VERT-3: executeJobsCall records pay observations for salaries', async () => {
  resetJobsCacheForTests();
  const workDir = mkdtempSync(join(tmpdir(), 'ef-salaries-jobs-'));
  const metaDb = new NodeSqliteD1Database(join(workDir, 'meta.sqlite'), [resolve('migrations/meta/0001_tracking.sql')]);
  try {
    const board = 'https://boards.greenhouse.io/payco';
    await executeJobsCall({
      payload: { query: 'Platform Engineer', company: 'payco', includeBuiltIn: false, limit: 5 },
      env: { META: metaDb } as never,
      executeSearch: async () => ({ status: 200, body: { ok: true, results: [] } }),
      executeScrape: async (args) =>
        String(args.url).startsWith(board)
          ? {
              status: 200,
              body: {
                ok: true,
                extractorId: 'greenhouse-board',
                total: 1,
                jobs: [
                  {
                    title: 'Platform Engineer',
                    company: 'payco',
                    url: `${board}/jobs/9`,
                    source: 'greenhouse',
                    locations: ['Remote'],
                    pay: { min: 150_000, max: 190_000, currency: 'USD', period: 'year', basis: 'base', raw: '$150k-$190k' },
                  },
                ],
              },
            }
          : { status: 404, body: { ok: false } },
    });
    const rows = (await metaDb.prepare('SELECT url, title_family FROM jobs_salary_observations').all<Record<string, string>>()).results;
    assert.equal(rows.length, 1);
    assert.equal(rows[0]!.url, `${board}/jobs/9`);
  } finally {
    metaDb.close();
    rmSync(workDir, { recursive: true, force: true });
  }
});
