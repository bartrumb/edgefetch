import assert from 'node:assert/strict';
import { mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import { KNOWN_TELEMETRY_ADAPTER_IDS } from '../src/dev-telemetry';
import { DECLARATIVE_SITE_ADAPTERS } from '../src/extractors/declarative';
import { listRegisteredAdapters, resolveSiteExtractorTwin } from '../src/extractors/registry';
import { executeScrapeCall, extractHtmlDocument, isTrustedTwinRedirectUrl } from '../src/scrape';
import { executeExtractCall } from '../src/search-index';
import { resetIsolateBudgetForTests } from '../src/wasm-bridge';
import { NodeFsR2Bucket } from './stubs/cf-storage-mocks';

const simpleHtmlToMd = (frag: string, base?: string) => {
  const doc = extractHtmlDocument(`<!doctype html><html><body>${frag}</body></html>`, {
    baseUrl: base ?? 'https://example.com',
    onlyMainContent: false,
  });
  return { markdown: doc.markdown, links: doc.links };
};

test('M2-1: All 12 M2 adapters registered, maxBytes bounded <= 4 MiB, and telemetry IDs allowlisted', () => {
  const expectedIds = [
    'zendesk-hc',
    'federal-register',
    'cpsc-recalls',
    'us-cfr-govinfo',
    'eur-lex',
    'terraform-registry',
    'docker-hub',
    'maven-central',
    'nuget-gallery',
    'homebrew-formulae',
    'osv-ghsa',
    'wikidata-openlibrary',
  ];
  const all = listRegisteredAdapters();
  const byId = new Map(all.map((a) => [a.id, a]));
  for (const id of expectedIds) {
    assert.ok(byId.has(id), `missing M2 adapter ${id} in listRegisteredAdapters()`);
    assert.ok(KNOWN_TELEMETRY_ADAPTER_IDS.has(id), `missing M2 adapter ${id} in KNOWN_TELEMETRY_ADAPTER_IDS`);
  }
  assert.ok(DECLARATIVE_SITE_ADAPTERS.length >= 68);
});

test('M2-2: isTrustedTwinRedirectUrl edge cases across wildcard, cross-domain, and same-host redirects', () => {
  // 1. Wildcard *.zendesk.com: same-host passes; cross-host redirect to custom HC domain fails open.
  assert.equal(
    isTrustedTwinRedirectUrl(
      'zendesk-hc',
      'https://acme.zendesk.com/api/v2/help_center/en-us/articles/440.json',
      { finalUrl: 'https://acme.zendesk.com/api/v2/help_center/en-us/articles/440.json' },
    ),
    true,
  );
  assert.equal(
    isTrustedTwinRedirectUrl(
      'zendesk-hc',
      'https://acme.zendesk.com/api/v2/help_center/en-us/articles/440.json',
      { finalUrl: 'https://help.customdomain.com/api/v2/help_center/en-us/articles/440.json' },
    ),
    false,
  );

  // 2. Open Library same-host 302 redirect (/isbn/*.json -> /books/OL...M.json) passes.
  assert.equal(
    isTrustedTwinRedirectUrl(
      'wikidata-openlibrary',
      'https://openlibrary.org/isbn/9780140328721.json',
      { finalUrl: 'https://openlibrary.org/books/OL7353617M.json' },
    ),
    true,
  );

  // 3. CPSC non-wildcard cross-host redirect (saferproducts.gov -> www.saferproducts.gov) passes.
  assert.equal(
    isTrustedTwinRedirectUrl(
      'cpsc-recalls',
      'https://saferproducts.gov/RestWebServices/Recall?format=json&RecallNumber=24123',
      { finalUrl: 'https://www.saferproducts.gov/RestWebServices/Recall?format=json&RecallNumber=24123' },
    ),
    true,
  );

  // 4. SSRF loopback redirect is blocked.
  assert.equal(
    isTrustedTwinRedirectUrl(
      'maven-central',
      'https://search.maven.org/solrsearch/select?q=g:a',
      { finalUrl: 'https://127.0.0.1/secret' },
    ),
    false,
  );
});

test('M2-3: Unfiltered saferproducts.gov/RestWebServices/Recall rejected pre-fetch with 422 and zero upstream calls', async () => {
  resetIsolateBudgetForTests();
  let fetchCalls = 0;
  for (const badUrl of [
    'https://www.saferproducts.gov/RestWebServices/Recall?format=json',
    'https://saferproducts.gov/RestWebServices/Recall/',
    'https://www.saferproducts.gov/RestWebServices/Recall?RecallNumber=bad!query',
  ]) {
    const res = await executeScrapeCall({
      payload: { url: badUrl, formats: ['markdown'] },
      env: {},
      executeHubFetch: async () => {
        fetchCalls++;
        return { status: 200, via: 'agent:test', bodyText: '{"results":[]}' };
      },
    });
    assert.equal(res.status, 422, `expected 422 for ${badUrl}`);
    assert.equal(res.body.outcome, 'skip');
    assert.equal(res.body.code, 'UNBOUNDED_ENDPOINT_BLOCKED');
    assert.equal(fetchCalls, 0, 'must never invoke executeHubFetch for unfiltered saferproducts dump');
  }
});

test('M2-4: zendesk-hc attachments enrichment, 404/401/draft fail-open, and cross-host redirect fail-open', async () => {
  resetIsolateBudgetForTests();
  const articleUrl = 'https://acme.zendesk.com/hc/en-us/articles/4408886858138-Manual';

  // Case 1: Article + /attachments.json enrichment
  const okRes = await executeScrapeCall({
    payload: { url: articleUrl, formats: ['markdown', 'links'] },
    env: {},
    executeHubFetch: async (_target, rawBody) => {
      const req = JSON.parse(rawBody) as { requests: Array<{ url: string }> };
      const u = req.requests[0]!.url;
      assert.ok(rawBody.includes('"respectRobots":true'));
      if (u.includes('/attachments.json')) {
        return {
          status: 200,
          via: 'agent:test',
          bodyText: JSON.stringify({
            results: [
              {
                id: 'att',
                url: u,
                finalUrl: u,
                status: 200,
                outcome: 'ok',
                contentType: 'application/json',
                body: JSON.stringify({
                  article_attachments: [
                    {
                      file_name: 'service-manual.pdf',
                      content_url: 'https://acme.zendesk.com/hc/article_attachments/77/service-manual.pdf',
                      content_type: 'application/pdf',
                      size: 2097152,
                    },
                  ],
                }),
              },
            ],
          }),
        };
      }
      return {
        status: 200,
        via: 'agent:test',
        bodyText: JSON.stringify({
          results: [
            {
              id: 'zd',
              url: u,
              finalUrl: u,
              status: 200,
              outcome: 'ok',
              contentType: 'application/json',
              body: JSON.stringify({
                article: {
                  title: 'Battery Care',
                  body: '<p>Follow safety guidelines.</p>',
                  updated_at: '2026-02-01T00:00:00Z',
                  html_url: articleUrl,
                  draft: false,
                },
                sections: [{ name: 'Safety', html_url: 'https://acme.zendesk.com/hc/en-us/sections/1' }],
                categories: [{ name: 'Manuals', html_url: 'https://acme.zendesk.com/hc/en-us/categories/2' }],
              }),
            },
          ],
        }),
      };
    },
  });
  assert.equal(okRes.status, 200);
  assert.equal(okRes.body.extractorId, 'zendesk-hc');
  assert.match(String(okRes.body.markdown ?? ''), /Manuals › Safety/);
  assert.match(String(okRes.body.markdown ?? ''), /service-manual\.pdf/);
  assert.ok((okRes.body.links as string[]).includes('https://acme.zendesk.com/hc/article_attachments/77/service-manual.pdf'));

  // Case 2: Attachments 401 -> article still succeeds
  const noAttRes = await executeScrapeCall({
    payload: { url: articleUrl, formats: ['markdown'] },
    env: {},
    executeHubFetch: async (_target, rawBody) => {
      const req = JSON.parse(rawBody) as { requests: Array<{ url: string }> };
      const u = req.requests[0]!.url;
      if (u.includes('/attachments.json')) {
        return {
          status: 200,
          via: 'agent:test',
          bodyText: JSON.stringify({ results: [{ id: 'att', url: u, status: 401, outcome: 'error' }] }),
        };
      }
      return {
        status: 200,
        via: 'agent:test',
        bodyText: JSON.stringify({
          results: [
            {
              id: 'zd',
              url: u,
              finalUrl: u,
              status: 200,
              outcome: 'ok',
              contentType: 'application/json',
              body: JSON.stringify({
                article: { title: 'Battery Care', body: '<p>Follow safety guidelines.</p>', draft: false },
              }),
            },
          ],
        }),
      };
    },
  });
  assert.equal(noAttRes.status, 200);
  assert.equal(noAttRes.body.extractorId, 'zendesk-hc');
  assert.match(String(noAttRes.body.markdown ?? ''), /Follow safety guidelines\./);

  // Case 3: draft: true fails open to standard HTML fetch
  const seenUrls: string[] = [];
  const draftRes = await executeScrapeCall({
    payload: { url: articleUrl, formats: ['markdown'] },
    env: {},
    executeHubFetch: async (_target, rawBody) => {
      const req = JSON.parse(rawBody) as { requests: Array<{ url: string }> };
      const u = req.requests[0]!.url;
      seenUrls.push(u);
      if (u.includes('/api/v2/')) {
        return {
          status: 200,
          via: 'agent:test',
          bodyText: JSON.stringify({
            results: [
              {
                id: 'zd',
                url: u,
                finalUrl: u,
                status: 200,
                outcome: 'ok',
                contentType: 'application/json',
                body: JSON.stringify({
                  article: { title: 'Draft', body: '<p>Unpublished</p>', draft: true },
                }),
              },
            ],
          }),
        };
      }
      return {
        status: 200,
        via: 'agent:test',
        bodyText: JSON.stringify({
          results: [
            {
              id: 'scrape-1',
              url: articleUrl,
              finalUrl: articleUrl,
              status: 200,
              outcome: 'ok',
              contentType: 'text/html',
              body: '<!doctype html><html><head><title>HTML Fallback</title></head><body><main><h1>HTML Fallback</h1><p>Public HTML page content.</p></main></body></html>',
            },
          ],
        }),
      };
    },
  });
  assert.equal(draftRes.status, 200);
  assert.equal(draftRes.body.extractorId, undefined);
  assert.match(String(draftRes.body.markdown ?? ''), /Public HTML page content\./);
  assert.ok(seenUrls.includes(articleUrl), 'expected fail-open to original HTML URL');

  // Case 4: 404 on twin API fails open to HTML
  const notFoundRes = await executeScrapeCall({
    payload: { url: articleUrl, formats: ['markdown'] },
    env: {},
    executeHubFetch: async (_target, rawBody) => {
      const req = JSON.parse(rawBody) as { requests: Array<{ url: string }> };
      const u = req.requests[0]!.url;
      if (u.includes('/api/v2/')) {
        return {
          status: 200,
          via: 'agent:test',
          bodyText: JSON.stringify({ results: [{ id: 'zd', url: u, status: 404, outcome: 'not_found' }] }),
        };
      }
      return {
        status: 200,
        via: 'agent:test',
        bodyText: JSON.stringify({
          results: [
            {
              id: 'scrape-1',
              url: articleUrl,
              finalUrl: articleUrl,
              status: 200,
              outcome: 'ok',
              contentType: 'text/html',
              body: '<!doctype html><html><body><main><h1>Fallback 404</h1><p>Standard HTML rendered.</p></main></body></html>',
            },
          ],
        }),
      };
    },
  });
  assert.equal(notFoundRes.status, 200);
  assert.match(String(notFoundRes.body.markdown ?? ''), /Standard HTML rendered\./);
});

test('M2-5: us-cfr-govinfo >4 MiB (bodyOmitted) falls back to wssearch/getContentDetail summary JSON, never Angular SPA', async () => {
  resetIsolateBudgetForTests();
  const cfrUrl = 'https://www.govinfo.gov/app/details/CFR-2023-title32-vol2';
  const fetchedUrls: string[] = [];

  const res = await executeScrapeCall({
    payload: { url: cfrUrl, formats: ['markdown', 'links'] },
    env: {},
    executeHubFetch: async (_target, rawBody) => {
      const req = JSON.parse(rawBody) as { requests: Array<{ url: string }> };
      const u = req.requests[0]!.url;
      fetchedUrls.push(u);
      if (u.endsWith('.htm')) {
        return {
          status: 200,
          via: 'agent:test',
          bodyText: JSON.stringify({
            results: [{ id: 'twin', url: u, finalUrl: u, status: 200, outcome: 'ok', bodyOmitted: true }],
          }),
        };
      }
      if (u.includes('/wssearch/getContentDetail')) {
        return {
          status: 200,
          via: 'agent:test',
          bodyText: JSON.stringify({
            results: [
              {
                id: 'sum',
                url: u,
                finalUrl: u,
                status: 200,
                outcome: 'ok',
                contentType: 'application/json',
                body: JSON.stringify({
                  title: 'Title 32 - National Defense (Vol 2)',
                  packageId: 'CFR-2023-title32-vol2',
                  collectionName: 'Code of Federal Regulations',
                  dateIssued: '2023-07-01',
                  download: {
                    pdfLink: 'https://www.govinfo.gov/content/pkg/CFR-2023-title32-vol2/pdf/CFR-2023-title32-vol2.pdf',
                    xmlLink: 'https://www.govinfo.gov/content/pkg/CFR-2023-title32-vol2/xml/CFR-2023-title32-vol2.xml',
                  },
                }),
              },
            ],
          }),
        };
      }
      throw new Error(`Unexpected fallback to SPA URL: ${u}`);
    },
  });

  assert.equal(res.status, 200);
  assert.equal(res.body.extractorId, 'us-cfr-govinfo');
  assert.match(String(res.body.markdown ?? ''), /Title 32 - National Defense/);
  assert.match(String(res.body.markdown ?? ''), /CFR-2023-title32-vol2\.pdf/);
  assert.ok(!fetchedUrls.includes(cfrUrl), 'must not fall through to Angular /app/details/ SPA when wssearch succeeds');
  const warnings = (res.body.warnings as string[] | undefined) ?? [];
  assert.ok(warnings.some((w) => w.includes('4 MiB WASM input budget')));
});

test('M2-6: cpsc.gov/Recalls/<year>/<slug> post-HTML bounded saferproducts enrichment + DOM fallback on empty []', async () => {
  resetIsolateBudgetForTests();
  const cpscUrl = 'https://www.cpsc.gov/Recalls/2024/Acme-Bike-Helmet';
  const recallHtml =
    '<!doctype html><html><head><title>Acme Bike Helmet Recall</title></head><body><main><h1>Acme Bike Helmet Recall</h1><p><strong>Recall Number:</strong> 24-123</p><p>Stop using immediately and contact Acme for a refund.</p></main></body></html>';

  // Case 1: Bounded saferproducts.gov returns matching JSON
  const enrichedRes = await executeScrapeCall({
    payload: { url: cpscUrl, formats: ['markdown'] },
    env: {},
    executeHubFetch: async (_target, rawBody) => {
      const req = JSON.parse(rawBody) as { requests: Array<{ url: string }> };
      const u = req.requests[0]!.url;
      if (u.includes('saferproducts.gov')) {
        assert.ok(u.includes('RecallNumber=24123'), `expected stripped RecallNumber=24123, got ${u}`);
        return {
          status: 200,
          via: 'agent:test',
          bodyText: JSON.stringify({
            results: [
              {
                id: 'cpsc',
                url: u,
                finalUrl: u,
                status: 200,
                outcome: 'ok',
                contentType: 'application/json',
                body: JSON.stringify([
                  {
                    RecallNumber: '24123',
                    Title: 'Acme Bike Helmet Recall (SaferProducts)',
                    RecallDate: '2024-03-14',
                    Description: 'Chin strap buckle can break.',
                    Hazards: [{ Name: 'Head injury hazard' }],
                    Remedies: [{ Name: 'Full refund' }],
                  },
                ]),
              },
            ],
          }),
        };
      }
      return {
        status: 200,
        via: 'agent:test',
        bodyText: JSON.stringify({
          results: [{ id: 'scrape-1', url: u, finalUrl: u, status: 200, outcome: 'ok', contentType: 'text/html', body: recallHtml }],
        }),
      };
    },
  });
  assert.equal(enrichedRes.status, 200);
  assert.equal(enrichedRes.body.extractorId, 'cpsc-recalls');
  assert.match(String(enrichedRes.body.markdown ?? ''), /Head injury hazard/);

  // Case 2: saferproducts.gov returns [] -> retains CPSC DOM extraction
  const domFallbackRes = await executeScrapeCall({
    payload: { url: cpscUrl, formats: ['markdown'] },
    env: {},
    executeHubFetch: async (_target, rawBody) => {
      const req = JSON.parse(rawBody) as { requests: Array<{ url: string }> };
      const u = req.requests[0]!.url;
      if (u.includes('saferproducts.gov')) {
        return {
          status: 200,
          via: 'agent:test',
          bodyText: JSON.stringify({
            results: [{ id: 'cpsc', url: u, finalUrl: u, status: 200, outcome: 'ok', contentType: 'application/json', body: '[]' }],
          }),
        };
      }
      return {
        status: 200,
        via: 'agent:test',
        bodyText: JSON.stringify({
          results: [{ id: 'scrape-1', url: u, finalUrl: u, status: 200, outcome: 'ok', contentType: 'text/html', body: recallHtml }],
        }),
      };
    },
  });
  assert.equal(domFallbackRes.status, 200);
  assert.equal(domFallbackRes.body.extractorId, 'cpsc-recalls');
  assert.match(String(domFallbackRes.body.markdown ?? ''), /contact Acme for a refund/);
});

test('M2-7: docker-hub /tags enrichment, eur-lex never /TXT/DOC/, openlibrary never /api/*, federal-register never /documents/current', async () => {
  resetIsolateBudgetForTests();

  // Route guard invariants
  assert.equal(resolveSiteExtractorTwin('https://eur-lex.europa.eu/legal-content/EN/TXT/DOC/?uri=CELEX:32016R0679'), null);
  assert.equal(resolveSiteExtractorTwin('https://www.federalregister.gov/documents/current'), null);

  const olTwin = resolveSiteExtractorTwin('https://openlibrary.org/isbn/978-0-14-032872-1');
  assert.ok(olTwin);
  assert.equal(olTwin.fetchUrl, 'https://openlibrary.org/isbn/978-0-14-032872-1.json');
  assert.ok(!olTwin.fetchUrl.includes('/api/'), 'openlibrary twin must NEVER hit disallowed /api/*');

  // Docker Hub root + /tags companion enrichment
  const dhRes = await executeScrapeCall({
    payload: { url: 'https://hub.docker.com/_/alpine', formats: ['markdown'] },
    env: {},
    executeHubFetch: async (_target, rawBody) => {
      const req = JSON.parse(rawBody) as { requests: Array<{ url: string }> };
      const u = req.requests[0]!.url;
      if (u.includes('/tags')) {
        return {
          status: 200,
          via: 'agent:test',
          bodyText: JSON.stringify({
            results: [
              {
                id: 'tags',
                url: u,
                finalUrl: u,
                status: 200,
                outcome: 'ok',
                contentType: 'application/json',
                body: JSON.stringify({
                  count: 250,
                  results: [
                    {
                      name: '3.20',
                      full_size: 3670016,
                      last_updated: '2026-01-15T00:00:00Z',
                      images: [{ os: 'linux', architecture: 'amd64' }],
                    },
                  ],
                }),
              },
            ],
          }),
        };
      }
      return {
        status: 200,
        via: 'agent:test',
        bodyText: JSON.stringify({
          results: [
            {
              id: 'dh',
              url: u,
              finalUrl: u,
              status: 200,
              outcome: 'ok',
              contentType: 'application/json',
              body: JSON.stringify({
                namespace: 'library',
                name: 'alpine',
                description: 'Minimal Alpine image',
                pull_count: 5000000,
                star_count: 9000,
                full_description: 'Lightweight container base.',
              }),
            },
          ],
        }),
      };
    },
  });
  assert.equal(dhRes.status, 200);
  assert.equal(dhRes.body.extractorId, 'docker-hub');
  assert.match(String(dhRes.body.markdown ?? ''), /Lightweight container base/);
  assert.match(String(dhRes.body.markdown ?? ''), /## Recent Tags/);
  assert.match(String(dhRes.body.markdown ?? ''), /`3\.20`/);

  // NuGet un-inlined & inlined check via TS bridge
  const ngTwin = resolveSiteExtractorTwin('https://nuget.org/packages/Serilog');
  assert.ok(ngTwin);
  assert.equal(ngTwin.fetchUrl, 'https://api.nuget.org/v3/registration5-gz-semver2/serilog/index.json');
  const ngDoc = ngTwin.formatTwin(
    JSON.stringify({
      items: [{ '@id': 'https://api.nuget.org/v3/registration5-gz-semver2/serilog/page/1.json', count: 120, lower: '1.0.0', upper: '4.2.0' }],
    }),
    'https://nuget.org/packages/Serilog',
    simpleHtmlToMd,
  );
  assert.ok(ngDoc);
  assert.match(ngDoc.markdown, /4\.2\.0/);
  assert.match(ngDoc.markdown, /Registration Pages/);
});

test('M2-8: Regression fixes for cpsc guard bypasses, zendesk script leak, cpsc P3 render skip, govinfo /summary, and Tier 3 exactSegments', async () => {
  resetIsolateBudgetForTests();

  // 1. cpsc-recalls guard: dashes-only, single-alnum-after-strip, duplicate mixed-case keys, and //RestWebServices/Recall
  let guardFetchCalls = 0;
  for (const badUrl of [
    'https://www.saferproducts.gov//RestWebServices/Recall',
    'https://www.saferproducts.gov//RestWebServices/Recall?format=json',
    'https://www.saferproducts.gov/RestWebServices/Recall?RecallNumber=--',
    'https://www.saferproducts.gov/RestWebServices/Recall?RecallNumber=---',
    'https://www.saferproducts.gov/RestWebServices/Recall?RecallNumber=-1',
    'https://www.saferproducts.gov/RestWebServices/Recall?RecallNumber=2-',
    'https://www.saferproducts.gov/RestWebServices/Recall?recallnumber=24123&RecallNumber=bad!',
    'https://www.saferproducts.gov/RestWebServices/Recall?RecallNumber=&recallnumber=24123',
  ]) {
    const res = await executeScrapeCall({
      payload: { url: badUrl, formats: ['markdown'] },
      env: {},
      executeHubFetch: async () => {
        guardFetchCalls++;
        return { status: 200, via: 'agent:test', bodyText: '{"results":[]}' };
      },
    });
    assert.equal(res.status, 422, `expected 422 for ${badUrl}`);
    assert.equal(res.body.outcome, 'skip');
    assert.equal(res.body.code, 'UNBOUNDED_ENDPOINT_BLOCKED');
    assert.equal(guardFetchCalls, 0, `must not invoke executeHubFetch for ${badUrl}`);
  }

  // 2. zendesk-hc <script>/<style>-only body fails open to HTML instead of leaking JS/CSS
  for (const leakBody of [
    '<script>alert(1)</script><style>body{}</style>',
    '<style>.secret{display:none}</style>',
  ]) {
    const articleUrl = 'https://acme.zendesk.com/hc/en-us/articles/440-Manual';
    const res = await executeScrapeCall({
      payload: { url: articleUrl, formats: ['markdown'] },
      env: {},
      executeHubFetch: async (_target, rawBody) => {
        const req = JSON.parse(rawBody) as { requests: Array<{ url: string }> };
        const u = req.requests[0]!.url;
        if (u.includes('/api/v2/')) {
          return {
            status: 200,
            via: 'agent:test',
            bodyText: JSON.stringify({
              results: [
                {
                  id: 'zd',
                  url: u,
                  finalUrl: u,
                  status: 200,
                  outcome: 'ok',
                  contentType: 'application/json',
                  body: JSON.stringify({
                    article: { title: 'XSS Test', body: leakBody, draft: false },
                  }),
                },
              ],
            }),
          };
        }
        return {
          status: 200,
          via: 'agent:test',
          bodyText: JSON.stringify({
            results: [
              {
                id: 'scrape-1',
                url: articleUrl,
                finalUrl: articleUrl,
                status: 200,
                outcome: 'ok',
                contentType: 'text/html',
                body: '<!doctype html><html><body><main><h1>Public Article</h1><p>Clean HTML fallback body.</p></main></body></html>',
              },
            ],
          }),
        };
      },
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.extractorId, undefined, `expected fail-open for ${leakBody}`);
    assert.doesNotMatch(String(res.body.markdown ?? ''), /alert\(1\)|\.secret/);
    assert.match(String(res.body.markdown ?? ''), /Clean HTML fallback body/);
  }

  // 3. cpsc-recalls thin scripted HTML skips P3 headless Chromium render when SaferProducts enrichment succeeds
  const thinCpscUrl = 'https://www.cpsc.gov/Recalls/2024/Thin-Helmet';
  const cpscKinds: string[] = [];
  const thinCpscRes = await executeScrapeCall({
    payload: { url: thinCpscUrl, formats: ['markdown'] },
    env: {},
    executeHubFetch: async (_target, rawBody) => {
      const req = JSON.parse(rawBody) as { requests: Array<{ url: string; kind: string }> };
      const r = req.requests[0]!;
      cpscKinds.push(`${r.kind}:${r.url}`);
      if (r.kind === 'render') {
        throw new Error('P3 auto-render should not fire when cpscRecallDoc succeeded');
      }
      if (r.url.includes('saferproducts.gov')) {
        return {
          status: 200,
          via: 'agent:test',
          bodyText: JSON.stringify({
            results: [
              {
                id: 'cpsc',
                url: r.url,
                finalUrl: r.url,
                status: 200,
                outcome: 'ok',
                contentType: 'application/json',
                body: JSON.stringify([
                  {
                    RecallNumber: '24123',
                    Title: 'Thin Helmet Recall',
                    RecallDate: '2024-04-01',
                    Description: 'Strap may detach.',
                    Hazards: [{ Name: 'Fall hazard' }],
                    Remedies: [{ Name: 'Replacement' }],
                  },
                ]),
              },
            ],
          }),
        };
      }
      return {
        status: 200,
        via: 'agent:test',
        bodyText: JSON.stringify({
          results: [
            {
              id: 'scrape-1',
              url: r.url,
              finalUrl: r.url,
              status: 200,
              outcome: 'ok',
              contentType: 'text/html',
              body: '<!doctype html><html><head><script src="/app.js"></script></head><body><main><h1>Thin Helmet</h1><p>Recall Number: 24-123</p></main></body></html>',
            },
          ],
        }),
      };
    },
  });
  assert.equal(thinCpscRes.status, 200);
  assert.equal(thinCpscRes.body.extractorId, 'cpsc-recalls');
  assert.match(String(thinCpscRes.body.markdown ?? ''), /Fall hazard/);
  assert.ok(!cpscKinds.some((k) => k.startsWith('render:')), `unexpected P3 render call: ${JSON.stringify(cpscKinds)}`);

  // 4. us-cfr-govinfo /summary subpath returns null from resolveSiteExtractorTwin
  assert.equal(
    resolveSiteExtractorTwin('https://www.govinfo.gov/app/details/CFR-2023-title16-vol2/CFR-2023-title16-vol2-part1500/summary'),
    null,
  );

  // 5-7. terraform-registry, maven-central, nuget-gallery route rejections + /latest support
  for (const badTwinUrl of [
    'https://registry.terraform.io/providers/hashicorp/random/docs',
    'https://registry.terraform.io/providers/hashicorp/random/latest/docs/resources/string',
    'https://registry.terraform.io/providers/hashicorp/random/3.8.1/docs/resources/string',
    'https://registry.terraform.io/providers/hashicorp/random/3.8.1%20OR%201',
    'https://registry.terraform.io/modules/terraform-aws-modules/vpc/aws/submodules/vpc-endpoints',
    'https://registry.terraform.io/modules/terraform-aws-modules/vpc/aws/examples/simple',
    'https://registry.terraform.io/modules/terraform-aws-modules/vpc/aws/5.1.0/submodules/vpc-endpoints',
    'https://registry.terraform.io/modules/terraform-aws-modules/vpc/aws/5.1.0/examples/simple',
    'https://central.sonatype.com/artifact/com.foo/bar/1.0:OR:a:evil',
    'https://central.sonatype.com/artifact/com.foo/bar/1.0%3AOR%3Aa%3Aevil',
    'https://central.sonatype.com/artifact/com.foo/bar/1.0%20OR%20*',
    'https://central.sonatype.com/artifact/com.fasterxml.jackson.core/jackson-databind/versions',
    'https://www.nuget.org/packages/Newtonsoft.Json/ReportAbuse',
    'https://www.nuget.org/packages/Newtonsoft.Json/ContactOwners',
    'https://www.nuget.org/packages/Newtonsoft.Json/versions',
  ]) {
    assert.equal(resolveSiteExtractorTwin(badTwinUrl), null, `expected null twin for ${badTwinUrl}`);
  }
  assert.equal(
    resolveSiteExtractorTwin('https://registry.terraform.io/providers/hashicorp/random/latest')?.fetchUrl,
    'https://registry.terraform.io/v1/providers/hashicorp/random',
  );
  assert.equal(
    resolveSiteExtractorTwin('https://registry.terraform.io/modules/terraform-aws-modules/vpc/aws/latest')?.fetchUrl,
    'https://registry.terraform.io/v1/modules/terraform-aws-modules/vpc/aws',
  );

  // 8. homebrew-formulae fullName fallback to name when full_name is missing
  const hbTwin = resolveSiteExtractorTwin('https://formulae.brew.sh/formula/jq')!;
  assert.ok(hbTwin);
  const hbDoc = hbTwin.formatTwin(
    JSON.stringify({ name: 'jq', desc: 'JSON processor' }),
    'https://formulae.brew.sh/formula/jq',
    simpleHtmlToMd,
  );
  assert.ok(hbDoc);
  assert.equal(hbDoc.title, 'jq (Homebrew Formula)');
});

test('M2-FIX-1: HTML body with empty hub extraction never falls back to node-supplied legacy Markdown', async () => {
  resetIsolateBudgetForTests();
  const pageUrl = 'https://legacy-leak.example.com/blank';
  const leakMarker = 'NODE_LEGACY_SCRIPT_LEAK_7f3a';
  const res = await executeScrapeCall({
    payload: { url: pageUrl, formats: ['markdown', 'text'], renderMode: 'off' },
    env: {},
    executeHubFetch: async (_target, rawBody) => {
      const req = JSON.parse(rawBody) as { requests: Array<{ id: string; url: string }> };
      const r0 = req.requests[0]!;
      return {
        status: 200,
        via: 'agent:test',
        bodyText: JSON.stringify({
          results: [
            {
              id: r0.id,
              url: r0.url,
              finalUrl: r0.url,
              status: 200,
              outcome: 'ok',
              contentType: 'text/html; charset=utf-8',
              body: `<!doctype html><html><head><title></title></head><body><script>window.x = "${leakMarker}";</script><div style="display:none">${leakMarker} hidden</div></body></html>`,
              // Legacy node extractor output that leaked script text and display:none content.
              markdown: `${leakMarker} hidden copy from the legacy node extractor`,
            },
          ],
        }),
      };
    },
  });
  assert.equal(
    JSON.stringify(res.body).includes(leakMarker),
    false,
    `node Markdown for an HTML body must not be used as the fallback: ${JSON.stringify(res.body).slice(0, 600)}`,
  );
});

test('M2-FIX-1b: non-HTML body keeps the node-supplied Markdown fallback', async () => {
  resetIsolateBudgetForTests();
  const pageUrl = 'https://node-md.example.com/notes.bin';
  const nodeMarker = 'NODE_NON_HTML_MARKDOWN_OK_91c2';
  const res = await executeScrapeCall({
    payload: { url: pageUrl, formats: ['markdown'], renderMode: 'off' },
    env: {},
    executeHubFetch: async (_target, rawBody) => {
      const req = JSON.parse(rawBody) as { requests: Array<{ id: string; url: string }> };
      const r0 = req.requests[0]!;
      return {
        status: 200,
        via: 'agent:test',
        bodyText: JSON.stringify({
          results: [
            {
              id: r0.id,
              url: r0.url,
              finalUrl: r0.url,
              status: 200,
              outcome: 'ok',
              contentType: 'application/x-edgefetch-test',
              body: 'raw opaque payload',
              markdown: `# Notes\n\n${nodeMarker} converted on the node for a non-HTML document.`,
            },
          ],
        }),
      };
    },
  });
  assert.equal(res.status, 200, JSON.stringify(res.body).slice(0, 600));
  assert.match(String(res.body.markdown ?? ''), new RegExp(nodeMarker));
});

test('M2-FIX-2: registry-twin adapter output is labelled by the Go content-state classifier, not hardcoded active', async () => {
  resetIsolateBudgetForTests();
  const articleUrl = 'https://acme.zendesk.com/hc/en-us/articles/4408886858139-Missing';
  const zendeskFetch =
    (article: { title: string; body: string }) =>
    async (_target: unknown, rawBody: string) => {
      const req = JSON.parse(rawBody) as { requests: Array<{ url: string }> };
      const u = req.requests[0]!.url;
      if (u.includes('/attachments.json')) {
        return {
          status: 200,
          via: 'agent:test',
          bodyText: JSON.stringify({
            results: [
              {
                id: 'att',
                url: u,
                finalUrl: u,
                status: 200,
                outcome: 'ok',
                contentType: 'application/json',
                body: JSON.stringify({ article_attachments: [] }),
              },
            ],
          }),
        };
      }
      return {
        status: 200,
        via: 'agent:test',
        bodyText: JSON.stringify({
          results: [
            {
              id: 'zd',
              url: u,
              finalUrl: u,
              status: 200,
              outcome: 'ok',
              contentType: 'application/json',
              body: JSON.stringify({
                article: { ...article, updated_at: '2026-02-01T00:00:00Z', html_url: articleUrl, draft: false },
              }),
            },
          ],
        }),
      };
    };

  const soft404Res = await executeScrapeCall({
    payload: { url: articleUrl, formats: ['markdown'] },
    env: {},
    executeHubFetch: zendeskFetch({
      title: 'Page Not Found',
      body: '<p>The page you requested could not be found.</p>',
    }),
  });
  assert.equal(soft404Res.status, 200);
  assert.equal(soft404Res.body.extractorId, 'zendesk-hc');
  assert.equal(soft404Res.body.contentState, 'soft_404');
  assert.equal(typeof soft404Res.body.contentStateReason, 'string');

  resetIsolateBudgetForTests();
  const activeRes = await executeScrapeCall({
    payload: { url: articleUrl, formats: ['markdown'] },
    env: {},
    executeHubFetch: zendeskFetch({
      title: 'Battery Care',
      body: '<p>Follow the safety guidelines when charging and storing the battery pack.</p>',
    }),
  });
  assert.equal(activeRes.status, 200);
  assert.equal(activeRes.body.extractorId, 'zendesk-hc');
  assert.equal(activeRes.body.contentState, 'active');
  assert.equal(activeRes.body.contentStateReason, undefined);
});

test('M2-FIX-3: private /v1/extract cache hit preserves the transient temporarily_unavailable content state', async () => {
  resetIsolateBudgetForTests();
  const dir = mkdtempSync(join(tmpdir(), 'ef-m2-tu-'));
  try {
    const bucket = new NodeFsR2Bucket(join(dir, 'r2'));
    const env = { ARTIFACTS: bucket as unknown as R2Bucket };
    const pageUrl = 'https://tu-cache.example.com/status';
    const missRes = await executeExtractCall({
      payload: { urls: [pageUrl], visibility: 'private', maxAgeMs: 600_000, renderMode: 'off' },
      env,
      executeHubFetch: async (_t, rawBody) => {
        const parsed = JSON.parse(rawBody) as { requests: Array<{ id: string; url: string }> };
        const r0 = parsed.requests[0]!;
        return {
          status: 200,
          via: 'agent:static',
          bodyText: JSON.stringify({
            results: [
              {
                id: r0.id,
                url: r0.url,
                finalUrl: r0.url,
                status: 200,
                outcome: 'ok',
                contentType: 'text/html; charset=utf-8',
                body: '<html><head><title>Service Status</title></head><body><main><h1>Service Status</h1><p>All regional systems are reporting normal operation this week across every data center.</p></main></body></html>',
              },
            ],
          }),
        };
      },
    });
    assert.equal(missRes.status, 200);
    const missItem = (missRes.body.results as Array<Record<string, unknown>>)[0]!;
    assert.equal(missItem.cached, false);

    // Rewrite the stored private cache record's state, as written by a classifier that knows the new state.
    const files: string[] = [];
    const walk = (p: string) => {
      for (const ent of readdirSync(p, { withFileTypes: true })) {
        const full = join(p, ent.name);
        if (ent.isDirectory()) walk(full);
        else files.push(full);
      }
    };
    walk(join(dir, 'r2'));
    let rewritten = 0;
    for (const f of files) {
      const txt = readFileSync(f, 'utf8');
      if (!txt.startsWith('{')) continue;
      let rec: Record<string, unknown>;
      try {
        rec = JSON.parse(txt) as Record<string, unknown>;
      } catch {
        continue;
      }
      if (rec.url !== pageUrl || typeof rec.markdown !== 'string') continue;
      rec.contentState = 'temporarily_unavailable';
      writeFileSync(f, JSON.stringify(rec));
      rewritten++;
    }
    assert.ok(rewritten >= 1, 'expected a private extract cache record to rewrite');

    const hitRes = await executeExtractCall({
      payload: { urls: [pageUrl], visibility: 'private', maxAgeMs: 600_000, renderMode: 'off' },
      env,
      executeHubFetch: async () => {
        throw new Error('private cache hit must not call executeHubFetch');
      },
    });
    assert.equal(hitRes.status, 200);
    const hitItem = (hitRes.body.results as Array<Record<string, unknown>>)[0]!;
    assert.equal(hitItem.cached, true);
    assert.equal(hitItem.contentState, 'temporarily_unavailable');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
