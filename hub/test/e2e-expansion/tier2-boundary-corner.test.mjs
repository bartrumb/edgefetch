import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { after, before, describe, test } from 'node:test';
import {
  createHubInstance,
  createOutboundRouter,
  MAX_WASM_INPUT_BYTES,
  withFreshHub,
} from './harness.mjs';
import {
  F01_ZENDESK,
  F02_SHOPIFY,
  F03_WOOCOMMERCE,
  F04_FEDERAL_REGISTER,
  F05_CPSC_RECALLS,
  F06_GOVINFO,
  F07_EURLEX,
  F08_XENFORO,
  F09_SQUARESPACE,
  F10_BIGCOMMERCE,
  F11_SFCC,
  F12_SHOPWARE_MAGENTO,
  F13_SRAM_BOSCH_HELP,
  F14_MICRODATA_SPEC,
  F15_TERRAFORM,
  F16_DOCKER_HUB,
  F17_MAVEN_CENTRAL,
  F18_NUGET,
  F19_HOMEBREW,
  F20_OSV,
  F21_WORKDAY_ICIMS,
  F22_UKG_PAYLOCITY_DOVER,
  F23_NHTSA_FCC,
  F24_WIKIDATA_OPENLIBRARY,
  F25_JSONFILTER_RECORDS,
  F30_NFPA,
  F31_GIANT_LIV,
  F32_BUMM,
  F33_BICYCLE_RETAILER,
  F34_YOUTUBE,
  F35_D1_HIGH_ROI,
} from './fixtures.mjs';

const INLINE_HYDRATION_BUDGET_BYTES = 18 * 1024 * 1024;
const MAX_ARTIFACT_CONTENT_BYTES = 16 * 1024 * 1024;

const over4Mib = (unit) => unit.repeat(Math.ceil((MAX_WASM_INPUT_BYTES + 64 * 1024) / unit.length));

function exactBytesHtml(targetBytes, titleMarker, bodySnippet = '') {
  const prefix = `<!doctype html><html><head><title>${titleMarker}</title></head><body><main><h1>${titleMarker}</h1>${bodySnippet}<p>`;
  const suffix = '</p></main></body></html>';
  const overhead = Buffer.byteLength(prefix, 'utf8') + Buffer.byteLength(suffix, 'utf8');
  if (targetBytes < overhead) {
    throw new Error(`targetBytes ${targetBytes} < overhead ${overhead}`);
  }
  return `${prefix}${'a'.repeat(targetBytes - overhead)}${suffix}`;
}

function exactBytesJson(baseObj, padKey, targetBytes) {
  const probe = JSON.stringify({ ...baseObj, [padKey]: '' });
  const overhead = Buffer.byteLength(probe, 'utf8');
  if (targetBytes < overhead) {
    throw new Error(`targetBytes ${targetBytes} < json overhead ${overhead}`);
  }
  return JSON.stringify({ ...baseObj, [padKey]: 'x'.repeat(targetBytes - overhead) });
}

async function postHubJson(hub, path, payload) {
  const res = await hub.fetch(path, {
    method: 'POST',
    headers: {
      authorization: `Bearer ${hub.callerToken}`,
      'content-type': 'application/json',
    },
    body: JSON.stringify(payload),
  });
  const rawText = await res.text();
  let body = rawText;
  try {
    body = rawText ? JSON.parse(rawText) : null;
  } catch {
    body = rawText;
  }
  return { status: res.status, body, rawText };
}

function hasSkuInRecords(records, sku) {
  return (records ?? []).some((r) => r.sku === sku || r.variants?.some((v) => v.sku === sku));
}

function hasPriceInRecords(records, price) {
  return (records ?? []).some(
    (r) => Number(r.price ?? r.variants?.[0]?.price) === price || r.variants?.some((v) => Number(v.price) === price),
  );
}

// ============================================================================
// Group A: Tier 1 Public Records, Docs & Forum Adapters (F01, F04–F08 — 30 tests)
// ============================================================================
describe('Tier 2 Group A — Boundary & Error Cases: Public Records, Docs & Forums (F01, F04–F08)', () => {
  let router;
  let hub;

  before(async () => {
    router = createOutboundRouter();

    // F01 Zendesk Help Center boundary routes
    router.status(
      'https://zd-t2-1.zendesk.com/api/v2/help_center/en-us/articles/101.json',
      401,
      JSON.stringify({ error: "Couldn't authenticate you" }),
      { 'content-type': 'application/json' },
    );
    router.html(
      'https://zd-t2-1.zendesk.com/hc/en-us/articles/101-private',
      '<!doctype html><html><head><title>Public Mirror</title></head><body><main><h1>Public Mirror</h1><p>Fallback HTML body text.</p></main></body></html>',
    );

    router.json('https://zd-t2-2.zendesk.com/api/v2/help_center/en-us/articles/102.json', {
      article: {
        ...F01_ZENDESK.articleJson.article,
        id: 102,
        title: 'Draft Article Should Not Leak',
        draft: true,
        body: '',
      },
    });
    router.html(
      'https://zd-t2-2.zendesk.com/hc/en-us/articles/102-draft',
      '<!doctype html><html><head><title>Live Page</title></head><body><main><h1>Live Page</h1><p>Active content.</p></main></body></html>',
    );

    router.text(
      'https://zd-t2-3.zendesk.com/api/v2/help_center/en-us/articles/103.json',
      '{"article":{"id":103,',
      { headers: { 'content-type': 'application/json; charset=utf-8' } },
    );
    router.html(
      'https://zd-t2-3.zendesk.com/hc/en-us/articles/103-malformed',
      '<!doctype html><html><head><title>HTML Recovery</title></head><body><main><h1>HTML Recovery</h1><p>Recovered cleanly.</p></main></body></html>',
    );

    router.text(
      'https://zd-t2-4.zendesk.com/api/v2/help_center/en-us/articles/104.json',
      exactBytesJson(
        { article: { ...F01_ZENDESK.articleJson.article, id: 104, title: 'Huge Twin' } },
        'padding',
        MAX_WASM_INPUT_BYTES + 1,
      ),
      { headers: { 'content-type': 'application/json; charset=utf-8' } },
    );
    router.html(
      'https://zd-t2-4.zendesk.com/hc/en-us/articles/104-huge',
      '<!doctype html><html><head><title>Huge Article Fallback</title></head><body><main><h1>Huge Article Fallback</h1><p>Safe size.</p></main></body></html>',
    );

    router.redirect(
      'https://zd-t2-5.zendesk.com/api/v2/help_center/en-us/articles/105.json',
      'https://custom-help.example.org/api/v2/help_center/en-us/articles/105.json',
      302,
    );
    router.json('https://custom-help.example.org/api/v2/help_center/en-us/articles/105.json', {
      article: { id: 105, title: 'UNTRUSTED_ZD_MARKER', body: '<p>Cross-host</p>', draft: false },
    });
    router.html(
      'https://zd-t2-5.zendesk.com/hc/en-us/articles/105-crosshost',
      '<!doctype html><html><head><title>Origin Fallback</title></head><body><main><h1>Origin Fallback</h1><p>Trusted origin HTML.</p></main></body></html>',
    );

    // F04 Federal Register (default Allow: / in shared Group A router; F04.T2.1 uses withFreshHub)
    router.status('https://www.federalregister.gov/api/v1/documents/2024-99999.json', 404, '{"error":"not found"}', {
      'content-type': 'application/json',
    });
    router.status(
      'https://www.federalregister.gov/documents/2024/01/02/2024-99999/missing',
      404,
      '<html><body><h1>Not Found</h1></body></html>',
      { 'content-type': 'text/html' },
    );
    router.json('https://www.federalregister.gov/api/v1/documents/2024-00002.json', {});
    router.html(
      'https://www.federalregister.gov/documents/2024/01/02/2024-00002/empty-json',
      '<!doctype html><html><head><title>FR HTML Fallback</title></head><body><main><h1>FR HTML Fallback</h1><p>Rule text.</p></main></body></html>',
    );
    router.json('https://www.federalregister.gov/api/v1/documents/2024-00003.json', {
      document_number: '2024-00003',
      title: 'Minimal Notice',
      agencies: [],
      cfr_references: [],
      docket_ids: [],
      effective_on: null,
      pdf_url: 'javascript:alert(1)',
    });
    router.text(
      'https://www.federalregister.gov/api/v1/documents/2024-00004.json',
      exactBytesJson({ ...F04_FEDERAL_REGISTER.doc2024_00001, document_number: '2024-00004' }, 'abstract', MAX_WASM_INPUT_BYTES + 1),
      { headers: { 'content-type': 'application/json; charset=utf-8' } },
    );
    router.html(
      'https://www.federalregister.gov/documents/2024/01/02/2024-00004/over-4mb',
      '<!doctype html><html><head><title>Oversized FR Fallback</title></head><body><main><h1>Oversized FR Fallback</h1><p>Safe fallback.</p></main></body></html>',
    );

    // F05 CPSC & SaferProducts
    router.json(
      (u) => u.hostname === 'www.saferproducts.gov' && u.pathname === '/RestWebServices/Recall' && u.searchParams.get('RecallNumber') === '99999',
      [],
    );
    router.json(
      (u) => u.hostname === 'www.saferproducts.gov' && u.pathname === '/RestWebServices/Recall' && !u.searchParams.get('RecallNumber'),
      [{ RecallID: 1, RecallNumber: '00001', Title: 'UNBOUNDED_DUMP_MARKER' }],
    );
    router.status(
      (u) =>
        u.hostname === 'www.saferproducts.gov' &&
        u.pathname === '/RestWebServices/Recall' &&
        (u.searchParams.get('RecallNumber') === '24777' || u.searchParams.get('RecallNumber') === '24-777'),
      500,
      'Internal Server Error',
    );
    router.html(
      'https://www.cpsc.gov/Recalls/2024/No-Recall-Number-Page',
      '<!doctype html><html><head><title>Safety Notice</title></head><body><main><h1>Safety Notice</h1><p>General consumer advisory without recall ID.</p></main></body></html>',
    );
    router.html(
      'https://www.cpsc.gov/Recalls/2024/Cpsc-Lookup-500',
      F05_CPSC_RECALLS.cpscHtmlRecall.replaceAll('24-123', '24-777'),
    );

    // F06 US CFR GovInfo
    router.html(
      'https://www.govinfo.gov/content/pkg/CFR-2023-title16-vol9/html/CFR-2023-title16-vol9.htm',
      exactBytesHtml(MAX_WASM_INPUT_BYTES + 1, '16 CFR Vol 9 Huge'),
    );
    router.json(
      (u) => u.hostname === 'www.govinfo.gov' && u.pathname === '/wssearch/getContentDetail' && u.searchParams.get('packageId') === 'CFR-2023-title16-vol9',
      { ...F06_GOVINFO.wssearchContentDetail, packageId: 'CFR-2023-title16-vol9', title: 'Title 16 Volume 9 Summary' },
    );
    router.html('https://www.govinfo.gov/app/details/CFR-2023-title16-vol9', F06_GOVINFO.angularSpaShell);

    router.html(
      'https://www.govinfo.gov/content/pkg/CFR-2023-title16-vol8/html/CFR-2023-title16-vol8.htm',
      exactBytesHtml(MAX_WASM_INPUT_BYTES, '16 CFR Part 1512', '<p>Bicycle safety standard exact 4 MiB body.</p>'),
    );
    router.html('https://www.govinfo.gov/app/details/CFR-2023-title16-vol8', F06_GOVINFO.angularSpaShell);

    router.status('https://www.govinfo.gov/content/pkg/CFR-2023-title49-404/html/CFR-2023-title49-404.htm', 404, 'Not Found');
    router.status(
      (u) => u.hostname === 'www.govinfo.gov' && u.pathname === '/wssearch/getContentDetail' && u.searchParams.get('packageId') === 'CFR-2023-title49-404',
      404,
      'Not Found',
    );
    router.html('https://www.govinfo.gov/app/details/CFR-2023-title49-404', F06_GOVINFO.angularSpaShell);

    router.status('https://www.govinfo.gov/content/pkg/CFR-2023-title16-vol7/html/CFR-2023-title16-vol7.htm', 404, 'Not Found');
    router.text(
      (u) => u.hostname === 'www.govinfo.gov' && u.pathname === '/wssearch/getContentDetail' && u.searchParams.get('packageId') === 'CFR-2023-title16-vol7',
      '{"title":',
      { headers: { 'content-type': 'application/json; charset=utf-8' } },
    );
    router.html(
      'https://www.govinfo.gov/app/details/CFR-2023-title16-vol7',
      '<!doctype html><html><head><title>Details Shell</title></head><body><main><h1>Details Shell</h1><p>GovInfo fallback shell.</p></main></body></html>',
    );

    router.status(
      'https://www.govinfo.gov/content/pkg/CFR-2023-title16-vol6/html/CFR-2023-title16-vol6-sec1.htm',
      404,
      'Not Found',
    );
    router.json(
      (u) => u.hostname === 'www.govinfo.gov' && u.pathname === '/wssearch/getContentDetail' && u.searchParams.get('packageId') === 'CFR-2023-title16-vol6',
      {
        ...F06_GOVINFO.wssearchContentDetail,
        packageId: 'CFR-2023-title16-vol6',
        granuleId: 'CFR-2023-title16-vol6-sec1',
        title: 'Granule Section 1',
      },
    );
    router.html('https://www.govinfo.gov/app/details/CFR-2023-title16-vol6/CFR-2023-title16-vol6-sec1', F06_GOVINFO.angularSpaShell);

    // F07 EUR-Lex (F07.T2.2–F07.T2.4 in shared Group A router; F07.T2.1 & F07.T2.5 in withFreshHub)
    router.html(
      (u) => u.hostname === 'eur-lex.europa.eu' && u.pathname === '/legal-content/EN/TXT/HTML/' && u.searchParams.get('uri') === 'CELEX:32023R1542',
      exactBytesHtml(MAX_WASM_INPUT_BYTES + 1, 'EUR-Lex Over 4MiB'),
    );
    router.html(
      (u) => u.hostname === 'eur-lex.europa.eu' && u.pathname === '/legal-content/EN/TXT/' && u.searchParams.get('uri') === 'CELEX:32023R1542',
      '<!doctype html><html><head><title>EU Regulation Overview</title></head><body><main><h1>EU Regulation Overview</h1><p>Fallback summary.</p></main></body></html>',
    );
    router.status(
      (u) => u.hostname === 'eur-lex.europa.eu' && u.pathname === '/legal-content/FR/TXT/HTML/' && u.searchParams.get('uri') === 'CELEX:32016R0679',
      500,
      'Internal Server Error',
    );
    router.html(
      (u) => u.hostname === 'eur-lex.europa.eu' && u.pathname === '/legal-content/FR/TXT/' && u.searchParams.get('uri') === 'CELEX:32016R0679',
      '<!doctype html><html><head><title>GDPR Portal Fallback</title></head><body><main><h1>GDPR Portal Fallback</h1><p>French regulation fallback.</p></main></body></html>',
    );
    router.html(
      (u) => u.hostname === 'eur-lex.europa.eu' && u.pathname === '/legal-content/EN/TXT/HTML/' && u.searchParams.get('uri') === 'CELEX:EMPTY',
      '<html><body></body></html>',
    );
    router.html(
      (u) => u.hostname === 'eur-lex.europa.eu' && u.pathname === '/legal-content/EN/TXT/' && u.searchParams.get('uri') === 'CELEX:EMPTY',
      '<!doctype html><html><head><title>Empty HTML Fallback</title></head><body><main><h1>Empty HTML Fallback</h1><p>EUR-Lex portal fallback.</p></main></body></html>',
    );

    // F08 XenForo 2
    router.html(
      'https://forums.electricbikereview.com/threads/empty-thread.100/',
      `<!doctype html><html><head><title>Empty Thread</title></head><body>
        <div class="p-title"><h1 class="p-title-value">Empty Thread</h1></div>
        <article class="message message--post" data-author="bob" id="post-1">
          <div class="message-content"><div class="bbWrapper">   </div><aside class="message-signature">Signed: Bob</aside></div>
        </article>
      </body></html>`,
    );
    router.html(
      'https://forums.electricbikereview.com/threads/nested-quotes.101/',
      `<!doctype html><html><head><title>Nested Quotes</title></head><body>
        <div class="p-body-sidebar"><div>SIDEBAR_PROMO</div></div>
        <div class="p-body-main">
          <div class="p-title"><h1 class="p-title-value">Nested Quotes Thread</h1></div>
          <article class="message message--post" data-author="alice" id="post-1">
            <div class="message-userDetails"><h4 class="message-name">alice</h4></div>
            <header class="message-attribution"><time class="u-dt" datetime="2026-10-01T10:00:00Z">Oct 1, 2026</time><a href="#post-1">#1</a></header>
            <div class="message-content"><div class="bbWrapper">Initial motor torque measurement is 85 Nm.</div></div>
          </article>
          <article class="message message--post" data-author="charlie" id="post-2">
            <div class="message-userDetails"><h4 class="message-name">charlie</h4></div>
            <header class="message-attribution"><time class="u-dt" datetime="2026-10-01T11:00:00Z">Oct 1, 2026</time><a href="#post-2">#2</a></header>
            <div class="message-content"><div class="bbWrapper">
              <blockquote class="bbCodeBlock bbCodeBlock--quote"><div class="bbCodeBlock-content">
                <blockquote class="bbCodeBlock bbCodeBlock--quote"><div class="bbCodeBlock-content">
                  <blockquote class="bbCodeBlock bbCodeBlock--quote"><div class="bbCodeBlock-content">Deep level 3 quote</div></blockquote>
                  Level 2 quote
                </div></blockquote>
                Initial motor torque measurement is 85 Nm.
              </div></blockquote>
              Confirmed with calibrated wrench.
            </div></div>
          </article>
        </div>
      </body></html>`,
    );
    router.html(
      'https://forums.electricbikereview.com/threads/huge-thread.102/',
      `<!doctype html><html><head><title>Huge Thread</title></head><body><main>${over4Mib(
        '<article class="message message--post" data-author="spam"><div class="bbWrapper">Post payload row</div></article>',
      )}</main></body></html>`,
    );

    hub = await createHubInstance({ router });
  });

  after(async () => {
    await hub?.dispose();
  });

  // --- F01: zendesk-hc (5 tests) ---
  test('F01.T2.1: zendesk-hc private article (401 JSON) falls back cleanly to HTML', async () => {
    const res = await hub.scrape({ url: 'https://zd-t2-1.zendesk.com/hc/en-us/articles/101-private', discoverLlmsTxt: false });
    assert.equal(res.status, 200);
    assert.equal(res.body.ok, true);
    assert.notEqual(res.body.extractorId, 'zendesk-hc');
    assert.match(res.body.markdown, /Public Mirror/);
    assert.match(res.body.markdown, /Fallback HTML body text/);
    assert.ok(router.countRequests('zd-t2-1.zendesk.com', '/hc/en-us/articles/101-private') >= 1);
  });

  test('F01.T2.2: zendesk-hc draft article with empty body falls back to live HTML', async () => {
    const res = await hub.scrape({ url: 'https://zd-t2-2.zendesk.com/hc/en-us/articles/102-draft', discoverLlmsTxt: false });
    assert.equal(res.status, 200);
    assert.notEqual(res.body.extractorId, 'zendesk-hc');
    assert.match(res.body.markdown, /Live Page/);
    assert.equal(res.body.markdown.includes('Draft Article Should Not Leak'), false);
  });

  test('F01.T2.3: zendesk-hc malformed/truncated JSON twin falls back to HTML without 5xx', async () => {
    const res = await hub.scrape({ url: 'https://zd-t2-3.zendesk.com/hc/en-us/articles/103-malformed', discoverLlmsTxt: false });
    assert.equal(res.status, 200);
    assert.equal(res.body.ok, true);
    assert.notEqual(res.body.extractorId, 'zendesk-hc');
    assert.match(res.body.markdown, /HTML Recovery/);
  });

  test('F01.T2.4: zendesk-hc >4 MiB (4,194,305 B) JSON twin exceeds WASM bound and falls back to HTML', async () => {
    const res = await hub.scrape({ url: 'https://zd-t2-4.zendesk.com/hc/en-us/articles/104-huge', discoverLlmsTxt: false });
    assert.equal(res.status, 200);
    assert.notEqual(res.body.extractorId, 'zendesk-hc');
    assert.match(res.body.markdown, /Huge Article Fallback/);
  });

  test('F01.T2.5: zendesk-hc wildcard *.zendesk.com rejects cross-host twin redirect via isTrustedTwinRedirectUrl', async () => {
    const res = await hub.scrape({ url: 'https://zd-t2-5.zendesk.com/hc/en-us/articles/105-crosshost', discoverLlmsTxt: false });
    assert.equal(res.status, 200);
    assert.notEqual(res.body.extractorId, 'zendesk-hc');
    assert.equal(res.body.markdown.includes('UNTRUSTED_ZD_MARKER'), false);
    assert.match(res.body.markdown, /Origin Fallback/);
  });

  // --- F04: federal-register (5 tests) ---
  test('F04.T2.1: federal-register respects robots.txt Disallow: /documents/current', async () => {
    const r = createOutboundRouter();
    r.setRobots('www.federalregister.gov', 'User-agent: *\nDisallow: /documents/current\nAllow: /api/v1/\nAllow: /documents/2024/\n');
    r.html('https://www.federalregister.gov/documents/current', '<html><body><h1>Current</h1></body></html>');
    await withFreshHub({ router: r }, async (h) => {
      const res = await h.scrape({ url: 'https://www.federalregister.gov/documents/current', discoverLlmsTxt: false });
      assert.equal(res.status, 422);
      assert.equal(res.body.ok, false);
      assert.match(String(res.body.problem ?? ''), /robots\.txt/i);
      assert.equal(r.countRequests('www.federalregister.gov', '/documents/current'), 0);
      assert.equal(r.countRequests('www.federalregister.gov', '/api/v1/'), 0);
    });
  });

  test('F04.T2.2: federal-register 404 on both twin and HTML returns 422 not_found', async () => {
    const res = await hub.scrape({
      url: 'https://www.federalregister.gov/documents/2024/01/02/2024-99999/missing',
      discoverLlmsTxt: false,
    });
    assert.equal(res.status, 422);
    assert.equal(res.body.ok, false);
    assert.equal(res.body.outcome, 'not_found');
    assert.equal(res.body.status, 404);
  });

  test('F04.T2.3: federal-register empty {} JSON twin falls back to HTML', async () => {
    const res = await hub.scrape({
      url: 'https://www.federalregister.gov/documents/2024/01/02/2024-00002/empty-json',
      discoverLlmsTxt: false,
    });
    assert.equal(res.status, 200);
    assert.notEqual(res.body.extractorId, 'federal-register');
    assert.match(res.body.markdown, /FR HTML Fallback/);
  });

  test('F04.T2.4: federal-register handles null/empty fields and strips javascript: pdf_url', async () => {
    const res = await hub.scrape({
      url: 'https://www.federalregister.gov/documents/2024/01/02/2024-00003/null-fields',
      discoverLlmsTxt: false,
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.extractorId, 'federal-register');
    assert.match(res.body.markdown, /Minimal Notice/);
    assert.equal(res.body.markdown.includes('javascript:'), false);
  });

  test('F04.T2.5: federal-register >4 MiB (4,194,305 B) JSON twin falls back cleanly to HTML', async () => {
    const res = await hub.scrape({
      url: 'https://www.federalregister.gov/documents/2024/01/02/2024-00004/over-4mb',
      discoverLlmsTxt: false,
    });
    assert.equal(res.status, 200);
    assert.notEqual(res.body.extractorId, 'federal-register');
    assert.match(res.body.markdown, /Oversized FR Fallback/);
  });

  // --- F05: cpsc-recalls (5 tests) ---
  test('F05.T2.1: saferproducts.gov unfiltered /RestWebServices/Recall?format=json blocked pre-fetch (422)', async () => {
    router.clearLog();
    const res = await hub.scrape({
      url: 'https://www.saferproducts.gov/RestWebServices/Recall?format=json',
      discoverLlmsTxt: false,
    });
    assert.equal(res.status, 422);
    assert.equal(res.body.ok, false);
    assert.equal(res.body.error, 'unbounded_endpoint_blocked');
    assert.equal(res.body.code, 'UNBOUNDED_ENDPOINT_BLOCKED');
    assert.equal(router.countRequests('www.saferproducts.gov', '/RestWebServices/Recall'), 0);
  });

  test('F05.T2.2: saferproducts.gov empty RecallNumber= parameter is blocked pre-fetch', async () => {
    router.clearLog();
    const res = await hub.scrape({
      url: 'https://www.saferproducts.gov/RestWebServices/Recall?format=json&RecallNumber=',
      discoverLlmsTxt: false,
    });
    assert.equal(res.status, 422);
    assert.equal(res.body.error, 'unbounded_endpoint_blocked');
    assert.equal(router.countRequests('www.saferproducts.gov'), 0);
  });

  test('F05.T2.3: saferproducts.gov unknown RecallNumber returning [] produces zero recall records without crash', async () => {
    router.clearLog();
    const res = await hub.scrape({
      url: 'https://www.saferproducts.gov/RestWebServices/Recall?format=json&RecallNumber=99999',
      discoverLlmsTxt: false,
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.ok, true);
    assert.ok(router.countRequests('www.saferproducts.gov', '/RestWebServices/Recall') >= 1);
    assert.notEqual(res.body.extractorId, 'cpsc-recalls');
    assert.equal(res.body.records?.length ?? 0, 0);
  });

  test('F05.T2.4: cpsc.gov HTML without Recall Number does not probe saferproducts.gov', async () => {
    router.clearLog();
    const res = await hub.scrape({
      url: 'https://www.cpsc.gov/Recalls/2024/No-Recall-Number-Page',
      discoverLlmsTxt: false,
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.ok, true);
    assert.match(res.body.markdown, /Safety Notice/);
    assert.equal(router.countRequests('www.saferproducts.gov'), 0);
  });

  test('F05.T2.5: cpsc.gov retains HTML content when saferproducts.gov lookup returns HTTP 500', async () => {
    router.clearLog();
    const res = await hub.scrape({
      url: 'https://www.cpsc.gov/Recalls/2024/Cpsc-Lookup-500',
      discoverLlmsTxt: false,
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.ok, true);
    assert.match(res.body.markdown, /24-777/);
    assert.ok(router.countRequests('www.saferproducts.gov', '/RestWebServices/Recall') >= 1);
  });

  // --- F06: us-cfr-govinfo (5 tests) ---
  test('F06.T2.1: us-cfr-govinfo >4 MiB .htm triggers wssearch/getContentDetail summary fallback with warning', async () => {
    const res = await hub.scrape({
      url: 'https://www.govinfo.gov/app/details/CFR-2023-title16-vol9',
      discoverLlmsTxt: false,
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.ok, true);
    assert.equal(res.body.extractorId, 'us-cfr-govinfo');
    assert.match(res.body.markdown, /Title 16 Volume 9 Summary/);
    assert.ok((res.body.warnings ?? []).some((w) => /4 MiB/i.test(w)));
  });

  test('F06.T2.2: us-cfr-govinfo exact 4,194,304 B (= MAX_WASM_INPUT_BYTES) .htm succeeds inside WASM budget', async () => {
    const res = await hub.scrape({
      url: 'https://www.govinfo.gov/app/details/CFR-2023-title16-vol8',
      discoverLlmsTxt: false,
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.ok, true);
    assert.equal(res.body.extractorId, 'us-cfr-govinfo');
    assert.match(res.body.markdown, /16 CFR Part 1512/);
    assert.equal(res.body.edgeBudgetExceeded, undefined);
  });

  test('F06.T2.3: us-cfr-govinfo 404 on both .htm and wssearch falls back to origin SPA HTML', async () => {
    router.clearLog();
    const res = await hub.scrape({
      url: 'https://www.govinfo.gov/app/details/CFR-2023-title49-404',
      discoverLlmsTxt: false,
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.ok, true);
    assert.notEqual(res.body.extractorId, 'us-cfr-govinfo');
    assert.ok(router.countRequests('www.govinfo.gov', '/wssearch/getContentDetail') >= 1);
  });

  test('F06.T2.4: us-cfr-govinfo malformed wssearch JSON falls back cleanly to HTML', async () => {
    const res = await hub.scrape({
      url: 'https://www.govinfo.gov/app/details/CFR-2023-title16-vol7',
      discoverLlmsTxt: false,
    });
    assert.equal(res.status, 200);
    assert.notEqual(res.body.extractorId, 'us-cfr-govinfo');
    assert.match(res.body.markdown, /Details Shell/);
  });

  test('F06.T2.5: us-cfr-govinfo granule URL missing .htm passes granuleId to wssearch summary fallback', async () => {
    router.clearLog();
    const res = await hub.scrape({
      url: 'https://www.govinfo.gov/app/details/CFR-2023-title16-vol6/CFR-2023-title16-vol6-sec1',
      discoverLlmsTxt: false,
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.extractorId, 'us-cfr-govinfo');
    assert.match(res.body.markdown, /Granule Section 1/);
    assert.ok(router.requestLog.some((r) => r.url.includes('granuleId=CFR-2023-title16-vol6-sec1')));
  });

  // --- F07: eur-lex (5 tests) ---
  test('F07.T2.1: eur-lex respects robots.txt Disallow: /legal-content/*/TXT/DOC/', async () => {
    const r = createOutboundRouter();
    r.setRobots('eur-lex.europa.eu', 'User-agent: *\nCrawl-delay: 10\nDisallow: /legal-content/*/TXT/DOC/\nAllow: /\n');
    r.html('https://eur-lex.europa.eu/legal-content/EN/TXT/DOC/?uri=CELEX:32023R1542', '<html><body>Doc</body></html>');
    await withFreshHub({ router: r }, async (h) => {
      const res = await h.scrape({
        url: 'https://eur-lex.europa.eu/legal-content/EN/TXT/DOC/?uri=CELEX:32023R1542',
        discoverLlmsTxt: false,
      });
      assert.equal(res.status, 422);
      assert.equal(res.body.ok, false);
      assert.match(String(res.body.problem ?? ''), /robots\.txt/i);
      assert.equal(r.countRequests('eur-lex.europa.eu', '/legal-content/EN/TXT/DOC/'), 0);
    });
  });

  test('F07.T2.2: eur-lex >4 MiB (4,194,305 B) /TXT/HTML/ twin falls back to /TXT/ overview HTML', async () => {
    const res = await hub.scrape({
      url: 'https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32023R1542',
      discoverLlmsTxt: false,
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.ok, true);
    assert.notEqual(res.body.extractorId, 'eur-lex');
    assert.match(res.body.markdown, /EU Regulation Overview/);
  });

  test('F07.T2.3: eur-lex 500 on /TXT/HTML/ falls back to /TXT/ portal HTML', async () => {
    const res = await hub.scrape({
      url: 'https://eur-lex.europa.eu/legal-content/FR/TXT/?uri=CELEX:32016R0679',
      discoverLlmsTxt: false,
    });
    assert.equal(res.status, 200);
    assert.notEqual(res.body.extractorId, 'eur-lex');
    assert.match(res.body.markdown, /GDPR Portal Fallback/);
  });

  test('F07.T2.4: eur-lex empty /TXT/HTML/ body falls back to /TXT/ HTML', async () => {
    const res = await hub.scrape({
      url: 'https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:EMPTY',
      discoverLlmsTxt: false,
    });
    assert.equal(res.status, 200);
    assert.notEqual(res.body.extractorId, 'eur-lex');
    assert.match(res.body.markdown, /Empty HTML Fallback/);
  });

  test('F07.T2.5: eur-lex Crawl-delay in robots.txt paces sequential /fetch/batch twin requests', async () => {
    const r = createOutboundRouter();
    r.setRobots('eur-lex.europa.eu', 'User-agent: *\nCrawl-delay: 1.2\nDisallow: /legal-content/*/TXT/DOC/\nAllow: /\n');
    r.html(
      (u) => u.hostname === 'eur-lex.europa.eu' && u.pathname === '/legal-content/EN/TXT/HTML/' && u.searchParams.get('uri') === 'CELEX:1',
      F07_EURLEX.enBatteryRegulationHtml,
    );
    r.html(
      (u) => u.hostname === 'eur-lex.europa.eu' && u.pathname === '/legal-content/EN/TXT/HTML/' && u.searchParams.get('uri') === 'CELEX:2',
      F07_EURLEX.enBatteryRegulationHtml,
    );
    await withFreshHub({ router: r }, async (h) => {
      const res = await postHubJson(h, '/fetch/batch', {
        urls: [
          'https://eur-lex.europa.eu/legal-content/EN/TXT/HTML/?uri=CELEX:1',
          'https://eur-lex.europa.eu/legal-content/EN/TXT/HTML/?uri=CELEX:2',
        ],
        maxSeconds: 10,
        options: { includeBody: true, respectRobots: true, pauseMs: 100 },
      });
      assert.equal(res.status, 200);
      assert.equal(res.body.results?.length, 2);
      assert.equal(res.body.results[0].outcome, 'ok');
      assert.equal(res.body.results[1].outcome, 'ok');
      const hits = r.requestLog.filter((e) => e.host === 'eur-lex.europa.eu' && e.pathname === '/legal-content/EN/TXT/HTML/');
      assert.equal(hits.length, 2);
      assert.ok(hits[1].timestamp - hits[0].timestamp >= 1100, `Expected Crawl-delay >=1100ms, got ${hits[1].timestamp - hits[0].timestamp}ms`);
    });
  });

  // --- F08: xenforo-thread (5 tests) ---
  test('F08.T2.1: endless-sphere.com Disallow: /forums/ blocks forum index via robots.txt', async () => {
    const r = createOutboundRouter();
    r.setRobots('endless-sphere.com', 'User-agent: *\nDisallow: /forums/\nDisallow: /sphere/search/\nAllow: /sphere/threads/\n');
    r.html('https://endless-sphere.com/forums/general-discussion.1/', '<html><body>Blocked</body></html>');
    await withFreshHub({ router: r }, async (h) => {
      const res = await h.scrape({ url: 'https://endless-sphere.com/forums/general-discussion.1/', discoverLlmsTxt: false });
      assert.equal(res.status, 422);
      assert.equal(res.body.ok, false);
      assert.match(String(res.body.problem ?? ''), /robots\.txt/i);
      assert.equal(r.countRequests('endless-sphere.com', '/forums/'), 0);
    });
  });

  test('F08.T2.2: endless-sphere.com Disallow: /sphere/search/ blocks search queries via robots.txt', async () => {
    const r = createOutboundRouter();
    r.setRobots('endless-sphere.com', 'User-agent: *\nDisallow: /forums/\nDisallow: /sphere/search/\nAllow: /sphere/threads/\n');
    r.html('https://endless-sphere.com/sphere/search/?q=battery', '<html><body>Search</body></html>');
    await withFreshHub({ router: r }, async (h) => {
      const res = await h.scrape({ url: 'https://endless-sphere.com/sphere/search/?q=battery', discoverLlmsTxt: false });
      assert.equal(res.status, 422);
      assert.equal(res.body.ok, false);
      assert.match(String(res.body?.problem ?? ''), /robots/i);
      assert.equal(r.countRequests('endless-sphere.com', '/sphere/search/'), 0);
    });
  });

  test('F08.T2.3: xenforo-thread strips .message-signature even when .bbWrapper is whitespace-only', async () => {
    const res = await hub.scrape({
      url: 'https://forums.electricbikereview.com/threads/empty-thread.100/',
      discoverLlmsTxt: false,
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.ok, true);
    assert.equal(res.body.markdown.includes('Signed: Bob'), false);
  });

  test('F08.T2.4: xenforo-thread handles 3-level nested blockquotes and strips .p-body-sidebar chrome', async () => {
    const res = await hub.scrape({
      url: 'https://forums.electricbikereview.com/threads/nested-quotes.101/',
      discoverLlmsTxt: false,
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.extractorId, 'xenforo-thread');
    assert.equal(res.body.markdown.includes('SIDEBAR_PROMO'), false);
    assert.match(res.body.markdown, /alice/i);
    assert.match(res.body.markdown, /Confirmed with calibrated wrench/);
  });

  test('F08.T2.5: xenforo-thread >4 MiB HTML on container returns edgeBudgetExceeded: true', async () => {
    const res = await hub.scrape({
      url: 'https://forums.electricbikereview.com/threads/huge-thread.102/',
      target: 'container',
      discoverLlmsTxt: false,
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.edgeBudgetExceeded, true);
    assert.equal(res.body.markdown, '');
    assert.ok((res.body.warnings ?? []).some((w) => w.includes('4 MiB WASM input budget')));
  });
});

// ============================================================================
// Group B: Tier 1 & Tier 2 Commerce, Docs & Product Core (F02, F03, F09–F14 — 40 tests)
// ============================================================================
describe('Tier 2 Group B — Boundary & Error Cases: Commerce, Docs & Product Core (F02, F03, F09–F14)', () => {
  let router;
  let hub;

  before(async () => {
    router = createOutboundRouter();

    // F02 Shopify (F02.T2.1 uses withFreshHub)
    router.json('https://sh-t2-2.myshopify.com/collections/empty-col/products.json', { products: [] });
    router.html(
      'https://sh-t2-2.myshopify.com/collections/empty-col',
      '<!doctype html><html><head><title>Empty Collection HTML</title></head><body><main><h1>Empty Collection HTML</h1><p>No items in stock.</p></main></body></html>',
    );
    router.status(
      'https://sh-t2-3.myshopify.com/collections/password-col/products.json',
      401,
      JSON.stringify({ errors: 'Password required' }),
      { 'content-type': 'application/json' },
    );
    router.html(
      'https://sh-t2-3.myshopify.com/collections/password-col',
      '<!doctype html><html><head><title>Storefront Password</title></head><body><main><h1>Storefront Password</h1><p>Enter password.</p></main></body></html>',
    );
    router.html('https://custom-sh-t2.example.com/collections/ebikes', F02_SHOPIFY.collectionHtml('custom-sh-t2.myshopify.com'));
    router.text(
      (u) => u.hostname === 'custom-sh-t2.example.com' && u.pathname === '/collections/ebikes/products.json',
      '{"products":[{"id":1',
      { headers: { 'content-type': 'application/json; charset=utf-8' } },
    );
    router.text(
      'https://sh-t2-5.myshopify.com/collections/huge/products.json',
      exactBytesJson({ products: F02_SHOPIFY.collectionProductsJson.products }, 'padding', MAX_WASM_INPUT_BYTES + 1),
      { headers: { 'content-type': 'application/json; charset=utf-8' } },
    );
    router.html(
      'https://sh-t2-5.myshopify.com/collections/huge',
      '<!doctype html><html><head><title>Huge Shopify Fallback</title></head><body><main><h1>Huge Shopify Fallback</h1><p>Fallback page.</p></main></body></html>',
    );

    // F03 WooCommerce (F03.T2.1 uses withFreshHub)
    router.html('https://woo-t2-2.example.com/product-category/ebikes/', F03_WOOCOMMERCE.categoryHtml('E-Bikes Category'));
    router.status(
      (u) => u.hostname === 'woo-t2-2.example.com' && u.pathname === '/wp-json/wc/store/v1/products',
      404,
      JSON.stringify({ code: 'rest_no_route' }),
      { 'content-type': 'application/json' },
    );
    router.html(
      'https://woo-t2-3.example.com/shop/',
      '<!doctype html><html><head><title>Shop Catalog</title><meta name="generator" content="WooCommerce 9.3.1"></head><body class="woocommerce"><h1>Shop Catalog</h1><p>Coming soon.</p></body></html>',
    );
    router.json(
      (u) => u.hostname === 'woo-t2-3.example.com' && u.pathname === '/wp-json/wc/store/v1/products',
      [],
    );
    router.html('https://woo-t2-4.example.com/product-category/accessories/', F03_WOOCOMMERCE.categoryHtml('Accessories'));
    router.json(
      (u) => u.hostname === 'woo-t2-4.example.com' && u.pathname === '/wp-json/wc/store/v1/products',
      [
        {
          id: 601,
          name: 'Tokyo Bell',
          slug: 'tokyo-bell',
          permalink: 'https://woo-t2-4.example.com/product/tokyo-bell/',
          sku: 'JPY-BELL-1',
          is_in_stock: true,
          prices: { price: '15000', regular_price: '15000', currency_code: 'JPY', currency_minor_unit: 0 },
        },
        {
          id: 602,
          name: 'US Mirror',
          slug: 'us-mirror',
          permalink: 'https://woo-t2-4.example.com/product/us-mirror/',
          sku: 'USD-MIR-2',
          is_in_stock: true,
          prices: { price: '2999', regular_price: '2999', currency_code: 'USD', currency_minor_unit: 2 },
        },
      ],
    );
    router.html('https://woo-t2-5.example.com/product-category/helmets/', F03_WOOCOMMERCE.categoryHtml('Helmets Fallback'));
    router.text(
      (u) => u.hostname === 'woo-t2-5.example.com' && u.pathname === '/wp-json/wc/store/v1/products',
      '[{"id":1',
      { headers: { 'content-type': 'application/json; charset=utf-8' } },
    );

    // F09 Squarespace Commerce
    router.html(
      (u) => u.hostname === 'sq-t2-1.example.com' && u.pathname === '/shop' && !u.searchParams.has('format'),
      F09_SQUARESPACE.shopHtml.replace(
        'Static = { SQUARESPACE_CONTEXT: { website: { id: "sq-site-1" } } };',
        'Static = {}; Static.SQUARESPACE_CONTEXT = { website: { id: "sq-site-1" } };',
      ),
    );
    router.status(
      (u) => u.hostname === 'sq-t2-1.example.com' && u.pathname === '/shop' && u.searchParams.get('format') === 'json-pretty',
      403,
      'Forbidden',
    );

    router.html(
      (u) => u.hostname === 'sq-t2-2.example.com' && u.pathname === '/about' && !u.searchParams.has('format'),
      '<!doctype html><html><head><title>About Us</title><script>Static={};Static.SQUARESPACE_CONTEXT={website:{id:"sq2"}};</script></head><body><main><h1>About Our Workshop</h1><p>Founded in 2018.</p></main></body></html>',
    );
    router.json(
      (u) => u.hostname === 'sq-t2-2.example.com' && u.pathname === '/about' && u.searchParams.get('format') === 'json-pretty',
      { collection: { title: 'About' } },
    );

    router.html(
      (u) => u.hostname === 'sq-t2-3.example.com' && u.pathname === '/shop/p/helmet' && !u.searchParams.has('format'),
      '<!doctype html><html><head><title>Helmet</title><script>Static={};Static.SQUARESPACE_CONTEXT={website:{id:"sq3"}};</script></head><body><main data-controller="ProductList"><h1>Commuter Helmet</h1><p>HTML fallback.</p></main></body></html>',
    );
    router.text(
      (u) => u.hostname === 'sq-t2-3.example.com' && u.pathname === '/shop/p/helmet' && u.searchParams.get('format') === 'json-pretty',
      '{bad',
      { headers: { 'content-type': 'application/json; charset=utf-8' } },
    );

    router.html(
      (u) => u.hostname === 'sq-t2-4.example.com' && u.pathname === '/shop/p/zero-price' && !u.searchParams.has('format'),
      '<!doctype html><html><head><title>Free Manual</title><script>Static={};Static.SQUARESPACE_CONTEXT={website:{id:"sq4"}};</script></head><body><main data-controller="ProductList"><h1>Free Manual</h1></main></body></html>',
    );
    router.json(
      (u) => u.hostname === 'sq-t2-4.example.com' && u.pathname === '/shop/p/zero-price' && u.searchParams.get('format') === 'json-pretty',
      {
        item: {
          id: 'sq-free-0',
          title: 'Free Manual',
          fullUrl: '/shop/p/zero-price',
          structuredContent: {
            variants: [{ sku: 'MAN-0', priceMoney: { value: '0.00', currency: 'USD' }, stock: { unlimited: true } }],
          },
        },
      },
    );

    router.html(
      (u) => u.hostname === 'sq-t2-5.example.com' && u.pathname === '/shop' && !u.searchParams.has('format'),
      '<!doctype html><html><head><title>SQ Shop Fallback</title><script>Static={};Static.SQUARESPACE_CONTEXT={website:{id:"sq5"}};</script></head><body><main data-controller="ProductList"><h1>SQ Shop Fallback</h1><p>Recovered HTML.</p></main></body></html>',
    );
    router.text(
      (u) => u.hostname === 'sq-t2-5.example.com' && u.pathname === '/shop' && u.searchParams.get('format') === 'json-pretty',
      exactBytesJson({ ...F09_SQUARESPACE.shopJsonPretty }, 'padding', MAX_WASM_INPUT_BYTES + 1),
      { headers: { 'content-type': 'application/json; charset=utf-8' } },
    );

    // F10 BigCommerce
    router.html(
      'https://bc-t2-1.example.com/bikes/commuter/',
      '<!doctype html><html><head><title>Commuter Bike</title><link rel="preconnect" href="https://cdn11.bigcommerce.com"><script>window.BCData = {bad_json;</script></head><body><main><h1>Commuter Bike</h1><p>Belt-drive urban bike.</p></main></body></html>',
    );
    router.html(
      'https://bc-t2-2.example.com/bikes/road/',
      '<!doctype html><html><head><title>Road Frame</title><link rel="preconnect" href="https://cdn11.bigcommerce.com"><script>window.BCData = {"store_settings":{"currency":"USD"}};</script></head><body><main class="productView"><h1 class="productView-title">Road Frame</h1><p>Carbon monocoque frameset.</p></main></body></html>',
    );
    router.xml(
      'https://bc-t2-3.example.com/xmlsitemap.php',
      '<?xml version="1.0" encoding="UTF-8"?><sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><sitemap><loc>https://bc-t2-3.example.com/xmlsitemap.php?type=products&amp;page=1</loc></sitemap></sitemapindex>',
    );
    router.xml(
      (u) => u.hostname === 'bc-t2-4.example.com' && u.pathname === '/xmlsitemap.php',
      '<urlset><url><loc>https://bc-t2-4.example.com/p1',
    );
    router.html(
      'https://bc-t2-5.example.com/bikes/cargo/',
      `<!doctype html><html><head><title>Cargo Bike</title><link rel="preconnect" href="https://cdn11.bigcommerce.com">
      <script>window.BCData = {"product_attributes":{"sku":"BC-99","price":{"without_tax":{"value":1899,"currency":"USD"}},"instock":true}};</script>
      <script type="application/ld+json">{"@context":"https://schema.org","@type":"Product","name":"Cargo Bike","url":"/bikes/cargo/?v=2","offers":{"@type":"Offer","price":"1899.00","priceCurrency":"USD"}}</script>
      </head><body><main class="productView"><h1 class="productView-title">Cargo Bike</h1></main></body></html>`,
    );

    // F11 SFCC Demandware
    router.html('https://sfcc-t2-1.example.com/p/trek-domane', F11_SFCC.productHtml('sfcc-t2-1.example.com'));
    router.status(
      (u) => u.hostname === 'sfcc-t2-1.example.com' && u.pathname.includes('Product-Variation'),
      403,
      'WAF Blocked',
    );
    router.html(
      'https://sfcc-t2-2.example.com/p/trek-fx',
      `<!doctype html><html><head><title>Trek FX</title><script src="https://sfcc-t2-2.example.com/on/demandware.static/js/main.js"></script></head><body><main><h1>Trek FX</h1><a href="/on/demandware.store/Sites-TrekUS-Site/en_US/Product-Variation?pid=999">M</a><table><tr><th>Size</th><th>Reach</th></tr><tr><td>M</td><td>385</td></tr></table></main></body></html>`,
    );
    router.status(
      (u) => u.hostname === 'sfcc-t2-2.example.com' && u.pathname.includes('Product-Variation'),
      404,
      'Not Found',
    );
    router.html('https://sfcc-t2-3.example.com/p/malformed', F11_SFCC.productHtml('sfcc-t2-3.example.com'));
    router.json(
      (u) => u.hostname === 'sfcc-t2-3.example.com' && u.pathname.includes('Product-Variation'),
      { product: null },
    );
    router.html('https://sfcc-t2-4.example.com/p/out-of-stock', F11_SFCC.productHtml('sfcc-t2-4.example.com'));
    router.json(
      (u) => u.hostname === 'sfcc-t2-4.example.com' && u.pathname.includes('Product-Variation'),
      {
        product: {
          id: 'SF-0',
          productName: 'Domane SL',
          price: { sales: { value: 3499.99, currency: 'USD' } },
          availability: { inStock: false, ats: 0 },
        },
      },
    );
    router.html(
      'https://not-sfcc-cannondale.example.com/en-us/bikes',
      '<!doctype html><html><head><title>Cannondale Bikes</title><link rel="stylesheet" href="/sitecore/content/theme.css"></head><body><main><h1>Cannondale Lineup</h1><p>Sitecore CMS page.</p></main></body></html>',
    );

    // F12 Shopware & Magento
    router.html(
      'https://mg-t2-1.example.com/brakes/mt7',
      '<!doctype html><html><head><title>MT7 Pro</title></head><body><main><h1>MT7 Pro</h1><p>Four-piston hydraulic brake.</p><div data-role="swatch-options"></div><script type="text/x-magento-init">{ "[data-role=swatch-options]": {</script></main></body></html>',
    );
    router.html('https://mg-t2-2.example.com/brakes/mt5', F12_SHOPWARE_MAGENTO.magentoSwatchHtml.replaceAll('MT7', 'MT5').replaceAll('MAG-MT7', 'MAG-MT5'));
    router.status((u) => u.hostname === 'mg-t2-2.example.com' && u.pathname.startsWith('/rest/V1/'), 401, 'Unauthorized');
    router.html(
      'https://sw-t2-3.example.com/lights/m99',
      F12_SHOPWARE_MAGENTO.shopware6Html.replace(
        /<tbody>[\s\S]*?<\/tbody>/,
        '<tbody></tbody>',
      ),
    );
    router.html(
      'https://shopify-supernova.example.com/products/m99-mini',
      '<!doctype html><html><head><title>M99 Mini</title><script>window.Shopify={shop:"supernova.myshopify.com"};</script></head><body><main><h1>M99 Mini</h1><p>Shopify storefront.</p></main></body></html>',
    );
    router.html(
      'https://mg-t2-5.example.com/p/huge-swatches',
      `<!doctype html><html><head><title>Huge Magento</title></head><body><main><div data-role="swatch-options"></div>${over4Mib('<p>swatch row</p>')}</main></body></html>`,
    );

    // F13 SRAM Docs & Bosch eBike Help (F13.T2.1 & F13.T2.2 use withFreshHub)
    router.html('https://docs.sram.com/en-US/publications/pub123/eagle-manual', F13_SRAM_BOSCH_HELP.sramDocsHtml);
    router.status('https://docs.sram.com/api/khub/maps', 404, 'Not Found');
    router.status('https://docs.sram.com/en-US/publications/pub404/missing', 404, '<html><body><h1>404 Not Found</h1></body></html>', {
      'content-type': 'text/html',
    });
    router.html(
      'https://docs.sram.com/en-US/publications/pub-huge/manual',
      `<!doctype html><html><head><title>Huge SRAM Manual</title></head><body><main class="ft-topic-content">${over4Mib('<p>torque spec row</p>')}</main></body></html>`,
    );

    // F14 Microdata & Spec-Table Fallback (M1)
    router.html('https://f14-t2-1.example.com/catalogue/a-light-in-the-attic_1000/index.html', F14_MICRODATA_SPEC.booksToScrapeHtml);
    router.html(
      'https://f14-t2-2.example.com/parts/bafang-g020',
      `<!doctype html><html><head><title>Bafang G020 Hub Motor</title></head><body><main><h1>Bafang G020 Hub Motor</h1>
        <dl class="specs"><dt>SKU</dt><dd>BAF-G020</dd><dt>Voltage</dt><dd>48V</dd><dt>Power</dt><dd>500W</dd></dl>
        <table class="woocommerce-product-attributes"><tr><th>SKU</th><td>BAF-G020</td></tr><tr><th>Voltage</th><td>48V</td></tr><tr><th>Power</th><td>500W</td></tr></table>
      </main></body></html>`,
    );
    router.html(
      'https://f14-t2-3.example.com/blog/article',
      `<!doctype html><html><head><title>Commuting Tips</title></head><body><article><h1>Winter Commuting Tips</h1>
        <p>Layering keeps your ride comfortable in cold mornings.</p>
        <table><tr><th>Layer</th><th>Material</th></tr><tr><td>Base</td><td>Merino wool</td></tr><tr><td>Shell</td><td>Ripstop nylon</td></tr></table>
      </article></body></html>`,
    );
    router.html(
      'https://f14-t2-4.example.com/microdata-xss',
      `<!doctype html><html><head><title>XSS Microdata Test</title></head><body><main itemscope itemtype="https://schema.org/Product">
        <h1 itemprop="name">Secure Lock</h1>
        <link itemprop="url" href="javascript:alert(1)" />
        <img itemprop="image" src="data:text/html,xss" alt="bad" />
        <div itemprop="offers" itemscope itemtype="https://schema.org/Offer">
          <meta itemprop="price" content="99.00" />
          <meta itemprop="priceCurrency" content="USD" />
        </div>
      </main></body></html>`,
    );
    router.html(
      'https://f14-t2-5.example.com/microdata-euro',
      `<!doctype html><html><head><title>Euro Microdata Test</title></head><body><main itemscope itemtype="https://schema.org/Product">
        <h1 itemprop="name">Euro Touring Bike</h1>
        <span itemprop="sku">EU-TOUR-1</span>
        <div itemprop="offers" itemscope itemtype="https://schema.org/Offer">
          <meta itemprop="price" content="1.299,50" />
          <meta itemprop="priceCurrency" content="EUR" />
          <link itemprop="availability" href="https://schema.org/OutOfStock" />
        </div>
      </main></body></html>`,
    );

    hub = await createHubInstance({ router });
  });

  after(async () => {
    await hub?.dispose();
  });

  // --- F02: shopify (5 tests) ---
  test('F02.T2.1: shopify respects robots.txt Disallow: /collections/all', async () => {
    const r = createOutboundRouter();
    r.setRobots('sh-t2-1.myshopify.com', 'User-agent: *\nDisallow: /collections/all\nAllow: /products/\n');
    r.html('https://sh-t2-1.myshopify.com/collections/all', '<html><body>All</body></html>');
    await withFreshHub({ router: r }, async (h) => {
      const res = await h.scrape({ url: 'https://sh-t2-1.myshopify.com/collections/all', discoverLlmsTxt: false });
      assert.equal(res.status, 422);
      assert.equal(res.body.ok, false);
      assert.match(String(res.body.problem ?? ''), /robots\.txt/i);
      assert.equal(r.countRequests('sh-t2-1.myshopify.com', '/collections/all'), 0);
    });
  });

  test('F02.T2.2: shopify empty products: [] falls back to collection HTML with 0 records', async () => {
    const res = await hub.scrape({ url: 'https://sh-t2-2.myshopify.com/collections/empty-col', discoverLlmsTxt: false });
    assert.equal(res.status, 200);
    assert.equal(res.body.ok, true);
    assert.equal(res.body.records?.length ?? 0, 0);
    assert.match(res.body.markdown, /Empty Collection HTML/);
  });

  test('F02.T2.3: shopify password-protected 401 products.json falls back to HTML', async () => {
    const res = await hub.scrape({ url: 'https://sh-t2-3.myshopify.com/collections/password-col', discoverLlmsTxt: false });
    assert.equal(res.status, 200);
    assert.notEqual(res.body.extractorId, 'shopify');
    assert.match(res.body.markdown, /Storefront Password/);
  });

  test('F02.T2.4: shopify custom-domain truncated JSON falls back cleanly to HTML', async () => {
    const res = await hub.scrape({ url: 'https://custom-sh-t2.example.com/collections/ebikes', discoverLlmsTxt: false });
    assert.equal(res.status, 200);
    assert.equal(res.body.ok, true);
    assert.match(res.body.markdown, /Electric Bikes/);
  });

  test('F02.T2.5: shopify >4 MiB (4,194,305 B) products.json falls back cleanly to HTML', async () => {
    const res = await hub.scrape({ url: 'https://sh-t2-5.myshopify.com/collections/huge', discoverLlmsTxt: false });
    assert.equal(res.status, 200);
    assert.notEqual(res.body.extractorId, 'shopify');
    assert.match(res.body.markdown, /Huge Shopify Fallback/);
  });

  // --- F03: woocommerce (5 tests) ---
  test('F03.T2.1: woocommerce respects robots.txt Disallow: /product-category/other/', async () => {
    const r = createOutboundRouter();
    r.setRobots('woo-t2-1.example.com', 'User-agent: *\nCrawl-Delay: 20\nDisallow: /product-category/other/\nAllow: /\n');
    r.html('https://woo-t2-1.example.com/product-category/other/', '<html><body>Blocked</body></html>');
    await withFreshHub({ router: r }, async (h) => {
      const res = await h.scrape({ url: 'https://woo-t2-1.example.com/product-category/other/', discoverLlmsTxt: false });
      assert.equal(res.status, 422);
      assert.equal(res.body.ok, false);
      assert.match(String(res.body.problem ?? ''), /robots\.txt/i);
      assert.equal(r.countRequests('woo-t2-1.example.com', '/product-category/other/'), 0);
    });
  });

  test('F03.T2.2: woocommerce disabled Store API (404 rest_no_route) falls back to HTML', async () => {
    const res = await hub.scrape({ url: 'https://woo-t2-2.example.com/product-category/ebikes/', discoverLlmsTxt: false });
    assert.equal(res.status, 200);
    assert.equal(res.body.ok, true);
    assert.notEqual(res.body.extractorId, 'woocommerce');
    assert.match(res.body.markdown, /E-Bikes Category/);
  });

  test('F03.T2.3: woocommerce /shop/ empty [] Store API response retains HTML with 0 records', async () => {
    const res = await hub.scrape({ url: 'https://woo-t2-3.example.com/shop/', discoverLlmsTxt: false });
    assert.equal(res.status, 200);
    assert.equal(res.body.records?.length ?? 0, 0);
    assert.match(res.body.markdown, /Shop Catalog/);
  });

  test('F03.T2.4: woocommerce currency_minor_unit: 0 (JPY 15000) vs 2 (USD 29.99) scales prices accurately', async () => {
    const res = await hub.scrape({ url: 'https://woo-t2-4.example.com/product-category/accessories/', discoverLlmsTxt: false });
    assert.equal(res.status, 200);
    assert.equal(res.body.extractorId, 'woocommerce');
    assert.ok(hasPriceInRecords(res.body.records, 15000), 'Expected JPY price 15000 (minor_unit=0)');
    assert.ok(hasPriceInRecords(res.body.records, 29.99), 'Expected USD price 29.99 (minor_unit=2)');
  });

  test('F03.T2.5: woocommerce malformed Store API JSON falls back cleanly to HTML', async () => {
    const res = await hub.scrape({ url: 'https://woo-t2-5.example.com/product-category/helmets/', discoverLlmsTxt: false });
    assert.equal(res.status, 200);
    assert.equal(res.body.ok, true);
    assert.notEqual(res.body.extractorId, 'woocommerce');
    assert.match(res.body.markdown, /Helmets Fallback/);
  });

  // --- F09: squarespace-commerce (5 tests) ---
  test('F09.T2.1: squarespace-commerce 403 on ?format=json-pretty falls back cleanly to HTML', async () => {
    router.clearLog();
    const res = await hub.scrape({ url: 'https://sq-t2-1.example.com/shop', discoverLlmsTxt: false });
    assert.equal(res.status, 200);
    assert.equal(res.body.ok, true);
    assert.ok(
      router.requestLog.some((r) => r.host === 'sq-t2-1.example.com' && r.search.includes('format=json-pretty')),
      'Expected ?format=json-pretty twin probe for sq-t2-1',
    );
    assert.notEqual(res.body.extractorId, 'squarespace-commerce');
    assert.match(res.body.markdown, /Urban Cycle Shop/);
  });

  test('F09.T2.2: squarespace-commerce non-commerce /about page without items[] falls back to HTML', async () => {
    router.clearLog();
    const res = await hub.scrape({ url: 'https://sq-t2-2.example.com/about', discoverLlmsTxt: false });
    assert.equal(res.status, 200);
    assert.equal(res.body.ok, true);
    assert.ok(router.countRequests('sq-t2-2.example.com', '/about') >= 1);
    assert.equal(res.body.records?.length ?? 0, 0);
    assert.match(res.body.markdown, /About Our Workshop/);
  });

  test('F09.T2.3: squarespace-commerce malformed ?format=json-pretty falls back cleanly to HTML', async () => {
    router.clearLog();
    const res = await hub.scrape({ url: 'https://sq-t2-3.example.com/shop/p/helmet', discoverLlmsTxt: false });
    assert.equal(res.status, 200);
    assert.equal(res.body.ok, true);
    assert.ok(
      router.requestLog.some((r) => r.host === 'sq-t2-3.example.com' && r.search.includes('format=json-pretty')),
      'Expected ?format=json-pretty twin probe for sq-t2-3',
    );
    assert.notEqual(res.body.extractorId, 'squarespace-commerce');
    assert.match(res.body.markdown, /Commuter Helmet/);
  });

  test('F09.T2.4: squarespace-commerce zero-price unlimited stock variant normalizes price=0 & available=true', async () => {
    const res = await hub.scrape({ url: 'https://sq-t2-4.example.com/shop/p/zero-price', discoverLlmsTxt: false });
    assert.equal(res.status, 200);
    assert.equal(res.body.extractorId, 'squarespace-commerce');
    assert.ok(hasSkuInRecords(res.body.records, 'MAN-0'));
    const v0 = res.body.records?.[0]?.variants?.[0] ?? res.body.records?.[0];
    assert.equal(Number(v0?.price), 0);
    assert.equal(v0?.available, true);
  });

  test('F09.T2.5: squarespace-commerce >4 MiB ?format=json-pretty falls back cleanly to HTML', async () => {
    router.clearLog();
    const res = await hub.scrape({ url: 'https://sq-t2-5.example.com/shop', discoverLlmsTxt: false });
    assert.equal(res.status, 200);
    assert.ok(
      router.requestLog.some((r) => r.host === 'sq-t2-5.example.com' && r.search.includes('format=json-pretty')),
      'Expected ?format=json-pretty twin probe for sq-t2-5',
    );
    assert.notEqual(res.body.extractorId, 'squarespace-commerce');
    assert.match(res.body.markdown, /SQ Shop Fallback/);
  });

  // --- F10: bigcommerce-store (5 tests) ---
  test('F10.T2.1: bigcommerce-store malformed BCData JSON falls back cleanly to HTML body', async () => {
    const res = await hub.scrape({ url: 'https://bc-t2-1.example.com/bikes/commuter/', discoverLlmsTxt: false });
    assert.equal(res.status, 200);
    assert.equal(res.body.ok, true);
    assert.match(res.body.markdown, /Commuter Bike/);
  });

  test('F10.T2.2: bigcommerce-store BCData missing product_attributes handles page cleanly', async () => {
    const res = await hub.scrape({ url: 'https://bc-t2-2.example.com/bikes/road/', discoverLlmsTxt: false });
    assert.equal(res.status, 200);
    assert.equal(res.body.ok, true);
    assert.match(res.body.markdown, /Road Frame/);
  });

  test('F10.T2.3: bigcommerce-store /xmlsitemap.php sitemapindex surfaces child sitemap URL', async () => {
    const res = await hub.scrape({ url: 'https://bc-t2-3.example.com/xmlsitemap.php', discoverLlmsTxt: false });
    assert.equal(res.status, 200);
    assert.equal(res.body.ok, true);
    assert.ok(res.body.markdown.includes('xmlsitemap.php?type=products&page=1'));
  });

  test('F10.T2.4: bigcommerce-store truncated/malformed XML sitemap does not crash Worker', async () => {
    router.clearLog();
    const res = await hub.scrape({ url: 'https://bc-t2-4.example.com/xmlsitemap.php?type=products&page=1', discoverLlmsTxt: false });
    assert.ok(router.countRequests('bc-t2-4.example.com', '/xmlsitemap.php') >= 1);
    assert.ok(res.status === 200 || res.status === 422);
    if (res.status === 200) {
      assert.equal(res.body.ok, true);
    }
  });

  test('F10.T2.5: bigcommerce-store BCData backfills product.sku and resolves relative product.url', async () => {
    const res = await hub.scrape({
      url: 'https://bc-t2-5.example.com/bikes/cargo/',
      formats: ['markdown', 'product'],
      discoverLlmsTxt: false,
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.product?.sku, 'BC-99');
    assert.equal(res.body.product?.url, 'https://bc-t2-5.example.com/bikes/cargo/?v=2');
  });

  // --- F11: sfcc-demandware (5 tests) ---
  test('F11.T2.1: sfcc-demandware 403 WAF on Product-Variation retains HTML geometry table', async () => {
    const res = await hub.scrape({ url: 'https://sfcc-t2-1.example.com/p/trek-domane', discoverLlmsTxt: false });
    assert.equal(res.status, 200);
    assert.equal(res.body.ok, true);
    assert.match(res.body.markdown, /Stack/);
    assert.match(res.body.markdown, /Reach/);
  });

  test('F11.T2.2: sfcc-demandware 404 on Product-Variation retains HTML geometry table', async () => {
    const res = await hub.scrape({ url: 'https://sfcc-t2-2.example.com/p/trek-fx', discoverLlmsTxt: false });
    assert.equal(res.status, 200);
    assert.match(res.body.markdown, /Trek FX/);
    assert.match(res.body.markdown, /385/);
  });

  test('F11.T2.3: sfcc-demandware malformed { product: null } falls back to HTML without empty markdown', async () => {
    const res = await hub.scrape({ url: 'https://sfcc-t2-3.example.com/p/malformed', discoverLlmsTxt: false });
    assert.equal(res.status, 200);
    assert.equal(res.body.ok, true);
    assert.match(res.body.markdown, /Domane SL 6 Gen 4/);
  });

  test('F11.T2.4: sfcc-demandware out-of-stock variation sets available: false in CatalogRecord', async () => {
    const res = await hub.scrape({ url: 'https://sfcc-t2-4.example.com/p/out-of-stock', discoverLlmsTxt: false });
    assert.equal(res.status, 200);
    assert.equal(res.body.extractorId, 'sfcc-demandware');
    const v0 = res.body.records?.[0]?.variants?.[0] ?? res.body.records?.[0];
    assert.equal(v0?.available, false);
  });

  test('F11.T2.5: sfcc-demandware fingerprint detection does not fire on Sitecore HTML', async () => {
    router.clearLog();
    const res = await hub.scrape({ url: 'https://not-sfcc-cannondale.example.com/en-us/bikes', discoverLlmsTxt: false });
    assert.equal(res.status, 200);
    assert.notEqual(res.body.extractorId, 'sfcc-demandware');
    assert.equal(router.countRequests('not-sfcc-cannondale.example.com', '/on/demandware.store'), 0);
  });

  // --- F12: shopware-magento (5 tests) ---
  test('F12.T2.1: shopware-magento malformed text/x-magento-init JSON falls back to HTML', async () => {
    const res = await hub.scrape({ url: 'https://mg-t2-1.example.com/brakes/mt7', discoverLlmsTxt: false });
    assert.equal(res.status, 200);
    assert.equal(res.body.ok, true);
    assert.match(res.body.markdown, /MT7 Pro/);
  });

  test('F12.T2.2: shopware-magento extracts inline swatch SKUs even when /rest/V1/ returns 401', async () => {
    const res = await hub.scrape({ url: 'https://mg-t2-2.example.com/brakes/mt5', discoverLlmsTxt: false });
    assert.equal(res.status, 200);
    assert.equal(res.body.ok, true);
    assert.match(res.body.markdown, /MAG-MT5-180/);
  });

  test('F12.T2.3: shopware-magento Shopware 6 empty properties tbody still extracts JSON-LD/HTML title', async () => {
    const res = await hub.scrape({ url: 'https://sw-t2-3.example.com/lights/m99', discoverLlmsTxt: false });
    assert.equal(res.status, 200);
    assert.equal(res.body.ok, true);
    assert.match(res.body.markdown, /Supernova M99 Mini Pro-25/);
  });

  test('F12.T2.4: shopware-magento fingerprint detection does not fire on Shopify storefronts', async () => {
    router.clearLog();
    const res = await hub.scrape({ url: 'https://shopify-supernova.example.com/products/m99-mini', discoverLlmsTxt: false });
    assert.equal(res.status, 200);
    assert.notEqual(res.body.extractorId, 'shopware-magento');
    assert.equal(router.countRequests('shopify-supernova.example.com', '/rest/V1/'), 0);
  });

  test('F12.T2.5: shopware-magento >4 MiB Magento HTML on container returns edgeBudgetExceeded: true', async () => {
    const res = await hub.scrape({
      url: 'https://mg-t2-5.example.com/p/huge-swatches',
      target: 'container',
      discoverLlmsTxt: false,
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.edgeBudgetExceeded, true);
    assert.equal(res.body.markdown, '');
  });

  // --- F13: sram-docs & bosch-ebike-help (5 tests) ---
  test('F13.T2.1: help.bosch-ebike.com /api/* is blocked by robots.txt with 0 outbound fetches', async () => {
    const r = createOutboundRouter();
    r.setRobots('help.bosch-ebike.com', 'User-agent: *\nDisallow: /api/*\nAllow: /\n');
    r.json('https://help.bosch-ebike.com/api/v2/articles/123', { ok: true });
    await withFreshHub({ router: r }, async (h) => {
      const res = await h.scrape({ url: 'https://help.bosch-ebike.com/api/v2/articles/123', discoverLlmsTxt: false });
      assert.equal(res.status, 422);
      assert.equal(res.body.ok, false);
      assert.match(String(res.body.problem ?? ''), /robots\.txt/i);
      assert.equal(r.countRequests('help.bosch-ebike.com', '/api/'), 0);
    });
  });

  test('F13.T2.2: help.bosch-ebike.com HTML strips 50 KB data:image/webp;base64 & aria-hidden error without calling /api/', async () => {
    const r = createOutboundRouter();
    r.setRobots('help.bosch-ebike.com', 'User-agent: *\nDisallow: /api/*\nAllow: /\n');
    const hugeBase64 = 'A'.repeat(50 * 1024);
    r.html(
      'https://help.bosch-ebike.com/en/help-center/smart-system',
      `<!doctype html><html><head><title>Smart System Guide</title></head><body>
        <div class="dodo-service-include__error" aria-hidden="true">Service Error</div>
        <main><h1>Smart System Guide</h1>
        <img src="data:image/webp;base64,${hugeBase64}" alt="blob"/>
        <p>Battery care instructions.</p></main>
      </body></html>`,
    );
    await withFreshHub({ router: r }, async (h) => {
      const res = await h.scrape({
        url: 'https://help.bosch-ebike.com/en/help-center/smart-system',
        discoverLlmsTxt: false,
      });
      assert.equal(res.status, 200);
      assert.equal(res.body.ok, true);
      assert.ok(r.countRequests('help.bosch-ebike.com', '/en/help-center/smart-system') >= 1);
      assert.equal(r.countRequests('help.bosch-ebike.com', '/api/'), 0);
      assert.equal(res.body.markdown.includes('data:image/webp;base64'), false);
      assert.equal(res.body.markdown.includes('Service Error'), false);
      assert.match(res.body.markdown, /Battery care instructions/);
    });
  });

  test('F13.T2.3: docs.sram.com Fluid Topics HTML extracts publication body without hitting /api/khub/maps', async () => {
    router.clearLog();
    const res = await hub.scrape({
      url: 'https://docs.sram.com/en-US/publications/pub123/eagle-manual',
      discoverLlmsTxt: false,
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.ok, true);
    assert.equal(router.countRequests('docs.sram.com', '/api/khub/maps'), 0);
    assert.match(res.body.markdown, /Full Mount derailleur knurled bolt/);
  });

  test('F13.T2.4: docs.sram.com 404 returns 422 not_found', async () => {
    const res = await hub.scrape({
      url: 'https://docs.sram.com/en-US/publications/pub404/missing',
      discoverLlmsTxt: false,
    });
    assert.equal(res.status, 422);
    assert.equal(res.body.ok, false);
    assert.equal(res.body.outcome, 'not_found');
    assert.equal(res.body.status, 404);
  });

  test('F13.T2.5: docs.sram.com >4 MiB HTML on container returns edgeBudgetExceeded: true', async () => {
    const res = await hub.scrape({
      url: 'https://docs.sram.com/en-US/publications/pub-huge/manual',
      target: 'container',
      discoverLlmsTxt: false,
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.edgeBudgetExceeded, true);
    assert.equal(res.body.markdown, '');
  });

  // --- F14: Microdata / Spec-table Product Fallback (5 tests — M1) ---
  test('F14.T2.1: spec-table product fallback extracts books.toscrape GBP price, UPC/gtin & availability', async () => {
    const res = await hub.scrape({
      url: 'https://f14-t2-1.example.com/catalogue/a-light-in-the-attic_1000/index.html',
      formats: ['product'],
      discoverLlmsTxt: false,
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.product?.title, 'A Light in the Attic');
    assert.equal(res.body.product?.price, 51.77);
    assert.equal(res.body.product?.currency, 'GBP');
    assert.equal(res.body.product?.gtin, undefined, 'hex store UPC must not be reported as a GS1 gtin');
    assert.equal(res.body.product?.specs?.upc, 'a897fe39b1053632');
    assert.equal(res.body.product?.availability, 'InStock');
  });

  test('F14.T2.2: spec-table & <dl> fallback populates product.sku & json schema fields without JSON-LD', async () => {
    const res = await hub.scrape({
      url: 'https://f14-t2-2.example.com/parts/bafang-g020',
      formats: [
        'product',
        {
          type: 'json',
          schema: {
            type: 'object',
            properties: { voltage: { type: 'string' }, power: { type: 'string' }, sku: { type: 'string' } },
          },
        },
      ],
      discoverLlmsTxt: false,
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.product?.sku, 'BAF-G020');
    assert.ok(res.body.json && (res.body.json.sku === 'BAF-G020' || res.body.json.voltage === '48V'));
  });

  test('F14.T2.3: non-product blog table does NOT hallucinate a product object', async () => {
    const res = await hub.scrape({
      url: 'https://f14-t2-3.example.com/blog/article',
      formats: ['product'],
      discoverLlmsTxt: false,
    });
    assert.equal(res.status, 200);
    assert.ok(res.body.product === undefined || res.body.product === null, `Expected no product on blog table, got ${JSON.stringify(res.body.product)}`);
  });

  test('F14.T2.4: microdata product blocks javascript: url & data: image XSS', async () => {
    const res = await hub.scrape({
      url: 'https://f14-t2-4.example.com/microdata-xss',
      formats: ['product'],
      discoverLlmsTxt: false,
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.product?.url, 'https://f14-t2-4.example.com/microdata-xss');
    assert.equal((res.body.product?.images ?? []).some((u) => u.startsWith('data:')), false);
  });

  test('F14.T2.5: microdata product parses European comma-decimal price & OutOfStock', async () => {
    const res = await hub.scrape({
      url: 'https://f14-t2-5.example.com/microdata-euro',
      formats: ['product'],
      discoverLlmsTxt: false,
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.product?.currency, 'EUR');
    assert.equal(res.body.product?.availability, 'OutOfStock');
    assert.equal(res.body.product?.price, 1299.5);
  });
});

// ============================================================================
// Group C: Tier 3 Developer, Package & Security Registries (F15–F20 — 30 tests)
// ============================================================================
describe('Tier 2 Group C — Boundary & Error Cases: Package & Security Registries (F15–F20)', () => {
  let router;
  let hub;

  before(async () => {
    router = createOutboundRouter();

    // F15 Terraform Registry
    router.status('https://registry.terraform.io/v1/providers/hashicorp/nonexistent', 404, JSON.stringify({ errors: ['Not Found'] }), {
      'content-type': 'application/json',
    });
    router.status('https://registry.terraform.io/providers/hashicorp/nonexistent', 404, '<html><body>Not Found</body></html>', {
      'content-type': 'text/html',
    });
    router.text(
      'https://registry.terraform.io/v1/modules/terraform-aws-modules/vpc/aws',
      exactBytesJson(F15_TERRAFORM.moduleJson, 'description', MAX_WASM_INPUT_BYTES),
      { headers: { 'content-type': 'application/json; charset=utf-8' } },
    );
    router.text(
      'https://registry.terraform.io/v1/modules/terraform-aws-modules/huge/aws',
      exactBytesJson(F15_TERRAFORM.moduleJson, 'description', MAX_WASM_INPUT_BYTES + 1),
      { headers: { 'content-type': 'application/json; charset=utf-8' } },
    );
    router.html(
      'https://registry.terraform.io/modules/terraform-aws-modules/huge/aws',
      '<!doctype html><html><head><title>Huge Module HTML</title></head><body><main><h1>Huge Module HTML</h1><p>Fallback module docs.</p></main></body></html>',
    );
    router.text(
      (u) => u.hostname === 'registry.terraform.io' && u.pathname.startsWith('/v1/providers/hashicorp/aws'),
      '{broken',
      { headers: { 'content-type': 'application/json; charset=utf-8' } },
    );
    router.html(
      'https://registry.terraform.io/providers/hashicorp/aws/5.40.0/docs/resources/s3_bucket',
      '<!doctype html><html><head><title>aws_s3_bucket</title></head><body><main><h1>aws_s3_bucket</h1><p>Resource docs.</p></main></body></html>',
    );
    router.redirect(
      'https://registry.terraform.io/v1/providers/hashicorp/random',
      'https://evil-tf.example.com/provider.json',
      302,
    );
    router.json('https://evil-tf.example.com/provider.json', {
      id: 'hashicorp/random/9.9.9',
      namespace: 'hashicorp',
      name: 'random',
      version: '9.9.9',
      description: 'EVIL_TF',
    });
    router.html(
      'https://registry.terraform.io/providers/hashicorp/random',
      '<!doctype html><html><head><title>Random Provider HTML</title></head><body><main><h1>Random Provider HTML</h1><p>Trusted origin.</p></main></body></html>',
    );

    // F16 Docker Hub
    router.status('https://hub.docker.com/v2/repositories/privateorg/secretrepo/', 401, JSON.stringify({ message: 'object not found' }), {
      'content-type': 'application/json',
    });
    router.html(
      'https://hub.docker.com/r/privateorg/secretrepo',
      '<!doctype html><html><head><title>Sign in</title></head><body><main><h1>Sign in</h1><p>Private repository.</p></main></body></html>',
    );
    router.json('https://hub.docker.com/v2/repositories/library/alpine/', F16_DOCKER_HUB.alpineRepoJson);
    router.status(
      (u) => u.hostname === 'hub.docker.com' && u.pathname === '/v2/repositories/library/alpine/tags',
      429,
      'Too Many Requests',
    );
    router.json('https://hub.docker.com/v2/repositories/myorg/emptytags/', {
      user: 'myorg',
      name: 'emptytags',
      namespace: 'myorg',
      description: 'Repo with no tags',
      star_count: 1,
      pull_count: 10,
      full_description: null,
    });
    router.json(
      (u) => u.hostname === 'hub.docker.com' && u.pathname === '/v2/repositories/myorg/emptytags/tags',
      { count: 0, results: [] },
    );
    router.text('https://hub.docker.com/v2/repositories/myorg/badjson/', '{"name":', {
      headers: { 'content-type': 'application/json; charset=utf-8' },
    });
    router.html(
      'https://hub.docker.com/r/myorg/badjson',
      '<!doctype html><html><head><title>Docker HTML Fallback</title></head><body><main><h1>Docker HTML Fallback</h1><p>Fallback page.</p></main></body></html>',
    );
    router.text(
      'https://hub.docker.com/v2/repositories/myorg/over4mb/',
      exactBytesJson({ ...F16_DOCKER_HUB.alpineRepoJson, name: 'over4mb', namespace: 'myorg' }, 'full_description', MAX_WASM_INPUT_BYTES + 1),
      { headers: { 'content-type': 'application/json; charset=utf-8' } },
    );
    router.html(
      'https://hub.docker.com/r/myorg/over4mb',
      '<!doctype html><html><head><title>Docker Over Budget</title></head><body><main><h1>Docker Over Budget</h1><p>Over 4 MiB fallback.</p></main></body></html>',
    );

    // F17 Maven Central
    router.json(
      (u) => u.hostname === 'search.maven.org' && u.pathname === '/solrsearch/select' && (u.searchParams.get('q') ?? '').includes('missing-lib'),
      { responseHeader: { status: 0 }, response: { numFound: 0, docs: [] } },
    );
    router.html(
      'https://central.sonatype.com/artifact/com.example/missing-lib',
      '<!doctype html><html><head><title>Artifact Not Found</title></head><body><main><h1>Artifact Not Found</h1><p>No such artifact.</p></main></body></html>',
    );
    router.status(
      (u) => u.hostname === 'search.maven.org' && u.pathname === '/solrsearch/select' && (u.searchParams.get('q') ?? '').includes('solr-500'),
      500,
      'Internal Server Error',
    );
    router.html(
      'https://central.sonatype.com/artifact/com.example/solr-500',
      '<!doctype html><html><head><title>Sonatype HTML</title></head><body><main><h1>Sonatype HTML</h1><p>HTML fallback.</p></main></body></html>',
    );
    router.html(
      (u) => u.hostname === 'central.sonatype.com' && u.pathname.startsWith('/artifact/com.example/inject'),
      '<!doctype html><html><head><title>Invalid Artifact</title></head><body><main><h1>Invalid Artifact</h1></main></body></html>',
    );
    router.redirect(
      (u) => u.hostname === 'search.maven.org' && u.pathname === '/solrsearch/select' && (u.searchParams.get('q') ?? '').includes('cross-redir'),
      'https://evil-maven.example.com/solr.json',
      302,
    );
    router.json('https://evil-maven.example.com/solr.json', {
      response: { numFound: 1, docs: [{ id: 'EVIL_MAVEN', g: 'com.example', a: 'EVIL_MAVEN', latestVersion: '9.9.9' }] },
    });
    router.html(
      'https://central.sonatype.com/artifact/com.example/cross-redir',
      '<!doctype html><html><head><title>Safe Sonatype</title></head><body><main><h1>Safe Sonatype</h1><p>Safe fallback.</p></main></body></html>',
    );
    router.route(
      (u) => u.hostname === 'search.maven.org' && u.pathname === '/solrsearch/select' && (u.searchParams.get('q') ?? '').includes('over4mb'),
      (_u, _req, MfRes) =>
        new MfRes(exactBytesJson(F17_MAVEN_CENTRAL.guavaSolrJson, 'padding', MAX_WASM_INPUT_BYTES + 1), {
          status: 200,
          headers: { 'content-type': 'application/json; charset=utf-8' },
        }),
    );
    router.html(
      'https://central.sonatype.com/artifact/com.example/over4mb',
      '<!doctype html><html><head><title>Maven Fallback</title></head><body><main><h1>Maven Fallback</h1><p>Over 4 MiB fallback.</p></main></body></html>',
    );

    // F18 NuGet Gallery
    router.json(
      'https://api.nuget.org/v3/registration5-gz-semver2/mixedcase.package.name/index.json',
      {
        ...F18_NUGET.newtonsoftIndexJson,
        items: [
          {
            ...F18_NUGET.newtonsoftIndexJson.items[0],
            items: [
              {
                catalogEntry: {
                  ...F18_NUGET.newtonsoftIndexJson.items[0].items[0].catalogEntry,
                  id: 'MixedCase.Package.Name',
                },
              },
            ],
          },
        ],
      },
    );
    router.json('https://api.nuget.org/v3/registration5-gz-semver2/huge.uninlined.pkg/index.json', {
      count: 1,
      items: [
        {
          '@id': 'https://api.nuget.org/v3/registration5-gz-semver2/huge.uninlined.pkg/page/1.0.0/2.0.0.json',
          lower: '1.0.0',
          upper: '2.0.0',
          count: 64,
        },
      ],
    });
    router.status('https://api.nuget.org/v3/registration5-gz-semver2/missing.pkg/index.json', 404, 'Not Found');
    router.status('https://www.nuget.org/packages/Missing.Pkg', 404, '<html><body>Not Found</body></html>', {
      'content-type': 'text/html',
    });
    router.text('https://api.nuget.org/v3/registration5-gz-semver2/badjson.pkg/index.json', '{"count":', {
      headers: { 'content-type': 'application/json; charset=utf-8' },
    });
    router.html(
      'https://www.nuget.org/packages/BadJson.Pkg',
      '<!doctype html><html><head><title>NuGet HTML Fallback</title></head><body><main><h1>NuGet HTML Fallback</h1></main></body></html>',
    );
    router.text(
      'https://api.nuget.org/v3/registration5-gz-semver2/over4mb.pkg/index.json',
      exactBytesJson(F18_NUGET.unInlinedStubIndexJson, 'padding', MAX_WASM_INPUT_BYTES + 1),
      { headers: { 'content-type': 'application/json; charset=utf-8' } },
    );
    router.html(
      'https://www.nuget.org/packages/Over4Mb.Pkg',
      '<!doctype html><html><head><title>NuGet Over Budget</title></head><body><main><h1>NuGet Over Budget</h1></main></body></html>',
    );

    // F19 Homebrew Formulae
    router.json(
      (u) =>
        u.hostname === 'formulae.brew.sh' &&
        (u.pathname === '/api/formula/python@3.8.json' || u.pathname === '/api/formula/python%403.8.json'),
      F19_HOMEBREW.deprecatedFormulaJson,
    );
    router.json('https://formulae.brew.sh/api/cask/disabled-app.json', {
      ...F19_HOMEBREW.iterm2CaskJson,
      token: 'disabled-app',
      full_token: 'disabled-app',
      name: ['Disabled App'],
      disabled: true,
      disable_date: '2025-01-01',
      disable_reason: 'unmaintained',
    });
    router.status('https://formulae.brew.sh/api/formula/does-not-exist.json', 404, 'Not Found');
    router.status('https://formulae.brew.sh/formula/does-not-exist', 404, '<html><body>Not Found</body></html>', {
      'content-type': 'text/html',
    });
    router.text('https://formulae.brew.sh/api/formula/bad-json.json', '{"name":', {
      headers: { 'content-type': 'application/json; charset=utf-8' },
    });
    router.html(
      'https://formulae.brew.sh/formula/bad-json',
      '<!doctype html><html><head><title>Homebrew HTML</title></head><body><main><h1>Homebrew HTML</h1></main></body></html>',
    );
    router.text(
      'https://formulae.brew.sh/api/formula/over4mb.json',
      exactBytesJson({ ...F19_HOMEBREW.jqFormulaJson, name: 'over4mb' }, 'desc', MAX_WASM_INPUT_BYTES + 1),
      { headers: { 'content-type': 'application/json; charset=utf-8' } },
    );
    router.html(
      'https://formulae.brew.sh/formula/over4mb',
      '<!doctype html><html><head><title>Brew Over Budget</title></head><body><main><h1>Brew Over Budget</h1></main></body></html>',
    );

    // F20 OSV / GHSA
    router.status('https://api.osv.dev/v1/vulns/GHSA-0000-0000-0000', 404, JSON.stringify({ code: 5, message: 'Bug not found.' }), {
      'content-type': 'application/json',
    });
    router.status('https://osv.dev/vulnerability/GHSA-0000-0000-0000', 404, '<html><body>Not Found</body></html>', {
      'content-type': 'text/html',
    });
    router.json('https://api.osv.dev/v1/vulns/GHSA-huge-vers-1111', {
      ...F20_OSV.ghsaVulnJson(500),
      id: 'GHSA-huge-vers-1111',
    });
    router.text('https://api.osv.dev/v1/vulns/GHSA-bad1-json-2222', '{"id":', {
      headers: { 'content-type': 'application/json; charset=utf-8' },
    });
    router.html(
      'https://github.com/advisories/GHSA-bad1-json-2222',
      '<!doctype html><html><head><title>GHSA Advisory HTML</title></head><body><main><h1>GHSA Advisory HTML</h1></main></body></html>',
    );
    router.redirect('https://api.osv.dev/v1/vulns/GHSA-evil-redr-3333', 'https://evil-osv.example.com/v1/vulns/x', 302);
    router.json('https://evil-osv.example.com/v1/vulns/x', { id: 'EVIL_OSV', summary: 'EVIL_OSV' });
    router.html(
      'https://github.com/advisories/GHSA-evil-redr-3333',
      '<!doctype html><html><head><title>GitHub Advisory Fallback</title></head><body><main><h1>GitHub Advisory Fallback</h1></main></body></html>',
    );
    router.text(
      'https://api.osv.dev/v1/vulns/PYSEC-2024-999',
      exactBytesJson({ ...F20_OSV.pysecVulnJson, id: 'PYSEC-2024-999' }, 'details', MAX_WASM_INPUT_BYTES + 1),
      { headers: { 'content-type': 'application/json; charset=utf-8' } },
    );
    router.html(
      'https://osv.dev/vulnerability/PYSEC-2024-999',
      '<!doctype html><html><head><title>OSV Over Budget</title></head><body><main><h1>OSV Over Budget</h1></main></body></html>',
    );

    hub = await createHubInstance({ router });
  });

  after(async () => {
    await hub?.dispose();
  });

  // --- F15: terraform-registry (5 tests) ---
  test('F15.T2.1: terraform-registry 404 on both API and HTML returns 422 not_found', async () => {
    const res = await hub.scrape({
      url: 'https://registry.terraform.io/providers/hashicorp/nonexistent',
      discoverLlmsTxt: false,
    });
    assert.equal(res.status, 422);
    assert.equal(res.body.ok, false);
    assert.equal(res.body.outcome, 'not_found');
    assert.equal(res.body.status, 404);
  });

  test('F15.T2.2: terraform-registry module JSON exact 4,194,304 B (= MAX_WASM_INPUT_BYTES) succeeds', async () => {
    const res = await hub.scrape({
      url: 'https://registry.terraform.io/modules/terraform-aws-modules/vpc/aws',
      discoverLlmsTxt: false,
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.ok, true);
    assert.equal(res.body.extractorId, 'terraform-registry');
    assert.equal(res.body.edgeBudgetExceeded, undefined);
  });

  test('F15.T2.3: terraform-registry module JSON 4,194,305 B (> MAX_WASM_INPUT_BYTES) falls back to HTML', async () => {
    const res = await hub.scrape({
      url: 'https://registry.terraform.io/modules/terraform-aws-modules/huge/aws',
      discoverLlmsTxt: false,
    });
    assert.equal(res.status, 200);
    assert.notEqual(res.body.extractorId, 'terraform-registry');
    assert.match(res.body.markdown, /Huge Module HTML/);
  });

  test('F15.T2.4: terraform-registry malformed twin JSON on versioned docs URL falls back cleanly to HTML', async () => {
    const res = await hub.scrape({
      url: 'https://registry.terraform.io/providers/hashicorp/aws/5.40.0/docs/resources/s3_bucket',
      discoverLlmsTxt: false,
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.ok, true);
    assert.match(res.body.markdown, /aws_s3_bucket/);
  });

  test('F15.T2.5: terraform-registry rejects untrusted cross-host twin redirect', async () => {
    const res = await hub.scrape({
      url: 'https://registry.terraform.io/providers/hashicorp/random',
      discoverLlmsTxt: false,
    });
    assert.equal(res.status, 200);
    assert.notEqual(res.body.extractorId, 'terraform-registry');
    assert.equal(res.body.markdown.includes('EVIL_TF'), false);
    assert.match(res.body.markdown, /Random Provider HTML/);
  });

  // --- F16: docker-hub (5 tests) ---
  test('F16.T2.1: docker-hub 401 private repo API falls back to HTML', async () => {
    const res = await hub.scrape({ url: 'https://hub.docker.com/r/privateorg/secretrepo', discoverLlmsTxt: false });
    assert.equal(res.status, 200);
    assert.notEqual(res.body.extractorId, 'docker-hub');
    assert.match(res.body.markdown, /Sign in/);
  });

  test('F16.T2.2: docker-hub retains repo metadata when /tags returns 429', async () => {
    const res = await hub.scrape({ url: 'https://hub.docker.com/_/alpine', discoverLlmsTxt: false });
    assert.equal(res.status, 200);
    assert.equal(res.body.ok, true);
    assert.equal(res.body.extractorId, 'docker-hub');
    assert.match(res.body.markdown, /Alpine Linux/i);
  });

  test('F16.T2.3: docker-hub handles full_description: null and empty tags without crashing', async () => {
    const res = await hub.scrape({ url: 'https://hub.docker.com/r/myorg/emptytags', discoverLlmsTxt: false });
    assert.equal(res.status, 200);
    assert.equal(res.body.extractorId, 'docker-hub');
    assert.match(res.body.markdown, /myorg\/emptytags/i);
  });

  test('F16.T2.4: docker-hub truncated repo JSON falls back cleanly to HTML', async () => {
    const res = await hub.scrape({ url: 'https://hub.docker.com/r/myorg/badjson', discoverLlmsTxt: false });
    assert.equal(res.status, 200);
    assert.notEqual(res.body.extractorId, 'docker-hub');
    assert.match(res.body.markdown, /Docker HTML Fallback/);
  });

  test('F16.T2.5: docker-hub >4 MiB repo JSON falls back cleanly to HTML', async () => {
    const res = await hub.scrape({ url: 'https://hub.docker.com/r/myorg/over4mb', discoverLlmsTxt: false });
    assert.equal(res.status, 200);
    assert.notEqual(res.body.extractorId, 'docker-hub');
    assert.match(res.body.markdown, /Docker Over Budget/);
  });

  // --- F17: maven-central (5 tests) ---
  test('F17.T2.1: maven-central numFound: 0 falls back to Sonatype HTML', async () => {
    const res = await hub.scrape({
      url: 'https://central.sonatype.com/artifact/com.example/missing-lib',
      discoverLlmsTxt: false,
    });
    assert.equal(res.status, 200);
    assert.notEqual(res.body.extractorId, 'maven-central');
    assert.match(res.body.markdown, /Artifact Not Found/);
  });

  test('F17.T2.2: maven-central Solr 500 falls back cleanly to Sonatype HTML', async () => {
    const res = await hub.scrape({
      url: 'https://central.sonatype.com/artifact/com.example/solr-500',
      discoverLlmsTxt: false,
    });
    assert.equal(res.status, 200);
    assert.notEqual(res.body.extractorId, 'maven-central');
    assert.match(res.body.markdown, /Sonatype HTML/);
  });

  test('F17.T2.3: maven-central rejects/sanitizes Solr operator injection in artifact path', async () => {
    router.clearLog();
    const res = await hub.scrape({
      url: 'https://central.sonatype.com/artifact/com.example/inject%20OR%20*%3A*/bad',
      discoverLlmsTxt: false,
    });
    assert.ok(res.status === 200 || res.status === 400 || res.status === 422);
    assert.equal(
      router.countRequests('search.maven.org'),
      0,
      'Must never forward raw Solr operators to search.maven.org',
    );
  });

  test('F17.T2.4: maven-central rejects untrusted cross-host redirect from search.maven.org', async () => {
    const res = await hub.scrape({
      url: 'https://central.sonatype.com/artifact/com.example/cross-redir',
      discoverLlmsTxt: false,
    });
    assert.equal(res.status, 200);
    assert.notEqual(res.body.extractorId, 'maven-central');
    assert.equal(res.body.markdown.includes('EVIL_MAVEN'), false);
  });

  test('F17.T2.5: maven-central >4 MiB Solr JSON falls back cleanly to HTML', async () => {
    const res = await hub.scrape({
      url: 'https://central.sonatype.com/artifact/com.example/over4mb',
      discoverLlmsTxt: false,
    });
    assert.equal(res.status, 200);
    assert.notEqual(res.body.extractorId, 'maven-central');
    assert.match(res.body.markdown, /Maven Fallback/);
  });

  // --- F18: nuget-gallery (5 tests) ---
  test('F18.T2.1: nuget-gallery lowercases mixed-case package ID in registration API request', async () => {
    router.clearLog();
    const res = await hub.scrape({ url: 'https://www.nuget.org/packages/MixedCase.Package.Name', discoverLlmsTxt: false });
    assert.equal(res.status, 200);
    assert.equal(res.body.extractorId, 'nuget-gallery');
    assert.ok(router.countRequests('api.nuget.org', '/v3/registration5-gz-semver2/mixedcase.package.name/index.json') >= 1);
  });

  test('F18.T2.2: nuget-gallery handles un-inlined page stubs without inline items[]', async () => {
    const res = await hub.scrape({ url: 'https://www.nuget.org/packages/Huge.Uninlined.Pkg', discoverLlmsTxt: false });
    assert.equal(res.status, 200);
    assert.equal(res.body.extractorId, 'nuget-gallery');
    assert.match(res.body.markdown, /1\.0\.0/);
    assert.match(res.body.markdown, /2\.0\.0/);
    assert.match(res.body.markdown, /64/);
  });

  test('F18.T2.3: nuget-gallery 404 on both API and HTML returns 422 not_found', async () => {
    const res = await hub.scrape({ url: 'https://www.nuget.org/packages/Missing.Pkg', discoverLlmsTxt: false });
    assert.equal(res.status, 422);
    assert.equal(res.body.ok, false);
    assert.equal(res.body.outcome, 'not_found');
    assert.equal(res.body.status, 404);
  });

  test('F18.T2.4: nuget-gallery malformed index JSON falls back cleanly to HTML', async () => {
    const res = await hub.scrape({ url: 'https://www.nuget.org/packages/BadJson.Pkg', discoverLlmsTxt: false });
    assert.equal(res.status, 200);
    assert.notEqual(res.body.extractorId, 'nuget-gallery');
    assert.match(res.body.markdown, /NuGet HTML Fallback/);
  });

  test('F18.T2.5: nuget-gallery >4 MiB index JSON falls back cleanly to HTML', async () => {
    const res = await hub.scrape({ url: 'https://www.nuget.org/packages/Over4Mb.Pkg', discoverLlmsTxt: false });
    assert.equal(res.status, 200);
    assert.notEqual(res.body.extractorId, 'nuget-gallery');
    assert.match(res.body.markdown, /NuGet Over Budget/);
  });

  // --- F19: homebrew-formulae (5 tests) ---
  test('F19.T2.1: homebrew-formulae handles @ in formula ID and surfaces deprecated metadata', async () => {
    const res = await hub.scrape({ url: 'https://formulae.brew.sh/formula/python@3.8', discoverLlmsTxt: false });
    assert.equal(res.status, 200);
    assert.equal(res.body.extractorId, 'homebrew-formulae');
    assert.match(res.body.markdown, /deprecated/i);
    assert.match(res.body.markdown, /python@3\.8/);
  });

  test('F19.T2.2: homebrew-formulae surfaces disabled cask status and reason', async () => {
    const res = await hub.scrape({ url: 'https://formulae.brew.sh/cask/disabled-app', discoverLlmsTxt: false });
    assert.equal(res.status, 200);
    assert.equal(res.body.extractorId, 'homebrew-formulae');
    assert.match(res.body.markdown, /disabled/i);
    assert.match(res.body.markdown, /unmaintained/i);
  });

  test('F19.T2.3: homebrew-formulae 404 on both API and HTML returns 422 not_found', async () => {
    const res = await hub.scrape({ url: 'https://formulae.brew.sh/formula/does-not-exist', discoverLlmsTxt: false });
    assert.equal(res.status, 422);
    assert.equal(res.body.ok, false);
    assert.equal(res.body.outcome, 'not_found');
    assert.equal(res.body.status, 404);
  });

  test('F19.T2.4: homebrew-formulae malformed JSON falls back cleanly to HTML', async () => {
    const res = await hub.scrape({ url: 'https://formulae.brew.sh/formula/bad-json', discoverLlmsTxt: false });
    assert.equal(res.status, 200);
    assert.notEqual(res.body.extractorId, 'homebrew-formulae');
    assert.match(res.body.markdown, /Homebrew HTML/);
  });

  test('F19.T2.5: homebrew-formulae >4 MiB JSON falls back cleanly to HTML', async () => {
    const res = await hub.scrape({ url: 'https://formulae.brew.sh/formula/over4mb', discoverLlmsTxt: false });
    assert.equal(res.status, 200);
    assert.notEqual(res.body.extractorId, 'homebrew-formulae');
    assert.match(res.body.markdown, /Brew Over Budget/);
  });

  // --- F20: osv-ghsa (5 tests) ---
  test('F20.T2.1: osv-ghsa 404 on both api.osv.dev and osv.dev returns 422 not_found', async () => {
    const res = await hub.scrape({ url: 'https://osv.dev/vulnerability/GHSA-0000-0000-0000', discoverLlmsTxt: false });
    assert.equal(res.status, 422);
    assert.equal(res.body.ok, false);
    assert.equal(res.body.outcome, 'not_found');
    assert.equal(res.body.status, 404);
  });

  test('F20.T2.2: osv-ghsa bounds huge 500-entry versions[] array in formatted Markdown', async () => {
    const res = await hub.scrape({ url: 'https://github.com/advisories/GHSA-huge-vers-1111', discoverLlmsTxt: false });
    assert.equal(res.status, 200);
    assert.equal(res.body.extractorId, 'osv-ghsa');
    assert.match(res.body.markdown, /GHSA-huge-vers-1111/);
    assert.ok(res.body.markdown.length < 50_000, `Expected bounded markdown < 50000, got ${res.body.markdown.length}`);
  });

  test('F20.T2.3: osv-ghsa malformed JSON falls back cleanly to GitHub advisory HTML', async () => {
    const res = await hub.scrape({ url: 'https://github.com/advisories/GHSA-bad1-json-2222', discoverLlmsTxt: false });
    assert.equal(res.status, 200);
    assert.notEqual(res.body.extractorId, 'osv-ghsa');
    assert.match(res.body.markdown, /GHSA Advisory HTML/);
  });

  test('F20.T2.4: osv-ghsa rejects untrusted cross-host redirect from api.osv.dev', async () => {
    const res = await hub.scrape({ url: 'https://github.com/advisories/GHSA-evil-redr-3333', discoverLlmsTxt: false });
    assert.equal(res.status, 200);
    assert.notEqual(res.body.extractorId, 'osv-ghsa');
    assert.equal(res.body.markdown.includes('EVIL_OSV'), false);
  });

  test('F20.T2.5: osv-ghsa >4 MiB OSV JSON falls back cleanly to HTML', async () => {
    const res = await hub.scrape({ url: 'https://osv.dev/vulnerability/PYSEC-2024-999', discoverLlmsTxt: false });
    assert.equal(res.status, 200);
    assert.notEqual(res.body.extractorId, 'osv-ghsa');
    assert.match(res.body.markdown, /OSV Over Budget/);
  });
});

// ============================================================================
// Group D: Tier 4 ATS Hardening, Public APIs & Knowledge Twins (F21–F24 — 20 tests)
// ============================================================================
describe('Tier 2 Group D — Boundary & Error Cases: ATS Hardening, Public APIs & Knowledge Twins (F21–F24)', () => {
  let router;
  let hub;

  before(async () => {
    router = createOutboundRouter();

    // F21 Workday & iCIMS
    router.status(
      (u) => u.hostname === 'glean-t2.wd5.myworkdayjobs.com' && u.pathname.includes('/wday/cxs/'),
      422,
      JSON.stringify({ errorCode: 'S123', errorCaseId: 'case-1', httpStatus: 422, message: 'Invalid tenant or site' }),
      { 'content-type': 'application/json' },
    );
    router.html('https://glean-t2.wd5.myworkdayjobs.com/en-US/Glean', '<main>Error</main>');

    router.status(
      (u) => u.hostname === 'temporal-t2.wd1.myworkdayjobs.com' && u.pathname.includes('/wday/cxs/'),
      500,
      JSON.stringify({ errorCode: 'S500', errorCaseId: 'case-2', httpStatus: 500, message: 'Internal server error' }),
      { 'content-type': 'application/json' },
    );
    router.html('https://temporal-t2.wd1.myworkdayjobs.com/en-US/Temporal', '<main>Error</main>');

    router.status(
      (u) => u.hostname === 'waf-wd-t2.wd1.myworkdayjobs.com' && u.pathname.includes('/wday/cxs/'),
      422,
      '<!doctype html><html><head><title>Just a moment...</title></head><body><h1>Just a moment...</h1><p>Enable JavaScript and cookies to continue</p></body></html>',
      { 'content-type': 'text/html', 'cf-mitigated': 'challenge' },
    );
    router.status(
      'https://waf-wd-t2.wd1.myworkdayjobs.com/en-US/Careers',
      422,
      '<!doctype html><html><head><title>Just a moment...</title></head><body><h1>Just a moment...</h1></body></html>',
      { 'content-type': 'text/html', 'cf-mitigated': 'challenge' },
    );

    // F21.T2.4 /v1/jobs Phase 1 Greenhouse succeeds without Workday wd1/wd5 probes
    router.json(
      (u) => u.hostname === 'boards-api.greenhouse.io' && u.pathname === '/v1/boards/glean-t2-dom/jobs',
      {
        jobs: [
          {
            id: 7001,
            title: 'Staff Search Engineer',
            absolute_url: 'https://boards.greenhouse.io/glean-t2-dom/jobs/7001',
            location: { name: 'Palo Alto, CA' },
            updated_at: '2026-10-20T12:00:00Z',
            content: '<p>Build enterprise search infrastructure.</p>',
          },
        ],
      },
    );
    router.status(
      (u) => (u.hostname === 'glean-t2-dom.wd1.myworkdayjobs.com' || u.hostname === 'glean-t2-dom.wd5.myworkdayjobs.com'),
      422,
      JSON.stringify({ errorCode: 'S123', errorCaseId: 'case-3', httpStatus: 422 }),
      { 'content-type': 'application/json' },
    );

    router.html(
      'https://careers-t2.icims.com/jobs/search?ss=1&in_iframe=1',
      '<!doctype html><html><head><title>Careers Search</title></head><body><div class="iCIMS_MainWrapper"><p>No jobs match your search criteria.</p></div></body></html>',
    );

    // F22 Paylocity fallback (UKG & Dover robots tests use withFreshHub)
    router.status('https://recruiting.paylocity.com/recruiting/api/feed/jobs/guid-empty', 404, 'Not Found');
    router.html(
      'https://recruiting.paylocity.com/recruiting/jobs/All/guid-empty/Acme',
      '<!doctype html><html><head><title>Acme Careers</title></head><body><main><h1>Acme Careers</h1><p>Fallback job page.</p><script>window.pageData = {bad;</script></main></body></html>',
    );

    // F23 NHTSA vPIC & FCC ID (api.nhtsa.gov 403 & fccid.io robots use withFreshHub)
    router.json('https://vpic.nhtsa.dot.gov/api/vehicles/decodevinvalues/INVALIDVIN000?format=json', {
      Count: 1,
      Results: [{ VIN: 'INVALIDVIN000', ErrorCode: '6', ErrorText: 'Incomplete VIN' }],
    });
    router.status('https://fccid.io/ABC-123/missing-device', 404, '<html><body><h1>404 Not Found</h1></body></html>', {
      'content-type': 'text/html',
    });
    router.html(
      'https://fccid.io/ABC-123/empty-table',
      '<!doctype html><html><head><title>FCC ID ABC-123</title></head><body><main><h1>FCC ID ABC-123</h1><table><tbody></tbody></table></main></body></html>',
    );

    // F24 Wikidata & OpenLibrary (openlibrary robots tests use withFreshHub)
    router.text(
      'https://openlibrary.org/isbn/9780140328722.json',
      'redirect',
    );
    router.redirect('https://openlibrary.org/isbn/9780140328722.json', 'https://evil-books.example.com/OL1.json', 302);
    router.json('https://evil-books.example.com/OL1.json', { title: 'EVIL_OL', isbn_13: ['9780140328722'] });
    router.html(
      'https://openlibrary.org/isbn/9780140328722',
      '<!doctype html><html><head><title>Book HTML Fallback</title></head><body><main><h1>Book HTML Fallback</h1></main></body></html>',
    );

    router.text(
      'https://www.wikidata.org/wiki/Special:EntityData/Q30.json',
      exactBytesJson(F24_WIKIDATA_OPENLIBRARY.wikidataQ42Json, 'padding', MAX_WASM_INPUT_BYTES + 1),
      { headers: { 'content-type': 'application/json; charset=utf-8' } },
    );
    router.html(
      'https://www.wikidata.org/wiki/Q30',
      '<!doctype html><html><head><title>United States (Q30)</title></head><body><main><h1>United States (Q30)</h1><p>HTML fallback.</p></main></body></html>',
    );
    router.status('https://www.wikidata.org/wiki/Special:EntityData/Q999999999.json', 404, 'Not Found');
    router.status('https://www.wikidata.org/wiki/Q999999999', 404, '<html><body>Not Found</body></html>', {
      'content-type': 'text/html',
    });

    hub = await createHubInstance({ router });
  });

  after(async () => {
    await hub?.dispose();
  });

  // --- F21: Workday & iCIMS (5 tests) ---
  test('F21.T2.1: Workday CXS 422 fast-exits even with ?q=engineer&offset=20 without HTML fetch', async () => {
    router.clearLog();
    const res = await hub.scrape({
      url: 'https://glean-t2.wd5.myworkdayjobs.com/en-US/Glean?q=engineer&offset=20',
      discoverLlmsTxt: false,
    });
    assert.equal(res.status, 404);
    assert.equal(res.body.ok, false);
    assert.equal(res.body.outcome, 'not_found');
    assert.equal(res.body.upstreamStatus, 422);
    assert.equal(res.body.extractorId, 'workday-board');
    assert.equal(router.countRequests('glean-t2.wd5.myworkdayjobs.com', '/en-US/Glean'), 0);
  });

  test('F21.T2.2: Workday CXS structured 500 JSON fast-exits to 404 not_found without HTML fetch', async () => {
    router.clearLog();
    const res = await hub.scrape({
      url: 'https://temporal-t2.wd1.myworkdayjobs.com/en-US/Temporal',
      discoverLlmsTxt: false,
    });
    assert.equal(res.status, 404);
    assert.equal(res.body.ok, false);
    assert.equal(res.body.outcome, 'not_found');
    assert.equal(res.body.upstreamStatus, 500);
    assert.equal(router.countRequests('temporal-t2.wd1.myworkdayjobs.com', '/en-US/Temporal'), 0);
  });

  test('F21.T2.3: Workday CXS 422 Cloudflare HTML challenge is classified as 403 challenge (not 404 not_found)', async () => {
    const res = await hub.scrape({
      url: 'https://waf-wd-t2.wd1.myworkdayjobs.com/en-US/Careers',
      discoverLlmsTxt: false,
    });
    assert.equal(res.status, 403);
    assert.equal(res.body.ok, false);
    assert.equal(res.body.outcome, 'challenge');
  });

  test('F21.T2.4: /v1/jobs skips Workday wd1/wd5 probes when Phase 1 Greenhouse board succeeds', async () => {
    router.clearLog();
    const res = await hub.jobs({ domains: ['glean-t2-dom.com'], company: 'glean-t2-dom' });
    assert.equal(res.status, 200);
    assert.equal(res.body.ok, true);
    assert.ok(router.countRequests('boards-api.greenhouse.io', '/v1/boards/glean-t2-dom/jobs') >= 1);
    assert.ok((res.body.jobs?.length ?? 0) >= 1, `Expected >= 1 job, got ${res.body.jobs?.length ?? 0}`);
    assert.equal(
      router.countRequests('glean-t2-dom.wd1.myworkdayjobs.com') +
        router.countRequests('glean-t2-dom.wd5.myworkdayjobs.com'),
      0,
    );
  });

  test('F21.T2.5: iCIMS ?in_iframe=1 empty-state returns 0 job records cleanly', async () => {
    const res = await hub.scrape({
      url: 'https://careers-t2.icims.com/jobs/search?ss=1&in_iframe=1',
      discoverLlmsTxt: false,
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.ok, true);
    assert.equal(res.body.records?.length ?? 0, 0);
    assert.match(res.body.markdown, /No jobs match your search criteria/);
  });

  // --- F22: ukg-paylocity-dover (5 tests) ---
  test('F22.T2.1: UKG Pro */JobBoardView is blocked by robots.txt with 0 outbound requests', async () => {
    const r = createOutboundRouter();
    r.setRobots('recruiting.ultipro.com', F22_UKG_PAYLOCITY_DOVER.ukgRobotsTxt);
    await withFreshHub({ router: r }, async (h) => {
      const res = await h.scrape({
        url: 'https://recruiting.ultipro.com/ACME1001/JobBoardView/1234',
        discoverLlmsTxt: false,
      });
      assert.equal(res.status, 422);
      assert.equal(res.body.ok, false);
      assert.match(String(res.body.problem ?? ''), /robots\.txt/i);
      assert.equal(r.countRequests('recruiting.ultipro.com', '/ACME1001/JobBoardView'), 0);
    });
  });

  test('F22.T2.2: UKG Pro tenant root /ACME1001/ outside */JobBoard/ is blocked by robots.txt', async () => {
    const r = createOutboundRouter();
    r.setRobots('recruiting.ultipro.com', F22_UKG_PAYLOCITY_DOVER.ukgRobotsTxt);
    r.html('https://recruiting.ultipro.com/ACME1001/', '<html><body>Tenant Root</body></html>');
    await withFreshHub({ router: r }, async (h) => {
      const res = await h.scrape({ url: 'https://recruiting.ultipro.com/ACME1001/', discoverLlmsTxt: false });
      assert.equal(res.status, 422);
      assert.equal(res.body.ok, false);
      assert.match(String(res.body?.problem ?? ''), /robots/i);
      assert.equal(r.countRequests('recruiting.ultipro.com', '/ACME1001/'), 0);
    });
  });

  test('F22.T2.3: Dover extracts SSR jobs HTML cleanly without calling disallowed /api/', async () => {
    const r = createOutboundRouter();
    r.setRobots('app.dover.com', F22_UKG_PAYLOCITY_DOVER.doverRobotsTxt);
    r.html(
      'https://app.dover.com/jobs/acme-t2',
      F22_UKG_PAYLOCITY_DOVER.doverHtml.replace('Founding Robotics Engineer', 'Staff Rust Engineer'),
    );
    await withFreshHub({ router: r }, async (h) => {
      const res = await h.scrape({ url: 'https://app.dover.com/jobs/acme-t2', discoverLlmsTxt: false });
      assert.equal(res.status, 200);
      assert.equal(res.body.ok, true);
      assert.ok(r.countRequests('app.dover.com', '/jobs/acme-t2') >= 1);
      assert.equal(r.countRequests('app.dover.com', '/api/'), 0);
      assert.match(res.body.markdown, /Staff Rust Engineer/);
    });
  });

  test('F22.T2.4: Dover direct /api/ URL is blocked by robots.txt with 0 outbound requests', async () => {
    const r = createOutboundRouter();
    r.setRobots('jobs.dover.com', F22_UKG_PAYLOCITY_DOVER.doverRobotsTxt);
    await withFreshHub({ router: r }, async (h) => {
      const res = await h.scrape({
        url: 'https://jobs.dover.com/api/v1/job-board/jobs/acme-t2',
        discoverLlmsTxt: false,
      });
      assert.equal(res.status, 422);
      assert.equal(res.body.ok, false);
      assert.match(String(res.body.problem ?? ''), /robots\.txt/i);
      assert.equal(r.countRequests('jobs.dover.com', '/api/'), 0);
    });
  });

  test('F22.T2.5: Paylocity 404 feed + malformed window.pageData falls back cleanly to HTML', async () => {
    const res = await hub.scrape({
      url: 'https://recruiting.paylocity.com/recruiting/jobs/All/guid-empty/Acme',
      discoverLlmsTxt: false,
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.ok, true);
    assert.match(res.body.markdown, /Acme Careers/);
  });

  // --- F23: nhtsa-vpic & fcc-id (5 tests) ---
  test('F23.T2.1: NHTSA vPIC invalid VIN surfaces ErrorCode and Incomplete VIN cleanly', async () => {
    const res = await hub.scrape({
      url: 'https://vpic.nhtsa.dot.gov/api/vehicles/decodevinvalues/INVALIDVIN000?format=json',
      discoverLlmsTxt: false,
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.ok, true);
    assert.match(res.body.markdown, /Incomplete VIN/);
  });

  test('F23.T2.2: api.nhtsa.gov 403 on robots.txt or endpoint fails closed without 403 bypass', async () => {
    const r = createOutboundRouter();
    r.setRobots('api.nhtsa.gov', 'Forbidden', 403);
    r.status('https://api.nhtsa.gov/recalls/recallsByVehicle?make=trek&model=domane&modelYear=2024', 403, 'Forbidden');
    await withFreshHub({ router: r }, async (h) => {
      const res = await h.scrape({
        url: 'https://api.nhtsa.gov/recalls/recallsByVehicle?make=trek&model=domane&modelYear=2024',
        discoverLlmsTxt: false,
      });
      assert.ok(res.status === 403 || res.status === 422);
      assert.equal(res.body.ok, false);
      assert.equal(res.body.status, 403);
      assert.ok(r.countRequests('api.nhtsa.gov', '/robots.txt') >= 1);
      assert.ok(r.countRequests('api.nhtsa.gov', '/recalls/') <= 1);
    });
  });

  test('F23.T2.3: fccid.io disallowed /ViewExhibitReport.cfm is blocked by robots.txt', async () => {
    const r = createOutboundRouter();
    r.setRobots('fccid.io', F23_NHTSA_FCC.fccRobotsTxt);
    await withFreshHub({ router: r }, async (h) => {
      const res = await h.scrape({ url: 'https://fccid.io/ViewExhibitReport.cfm?id=123', discoverLlmsTxt: false });
      assert.equal(res.status, 422);
      assert.equal(res.body.ok, false);
      assert.match(String(res.body.problem ?? ''), /robots\.txt/i);
      assert.equal(r.countRequests('fccid.io', '/ViewExhibitReport.cfm'), 0);
    });
  });

  test('F23.T2.4: fccid.io 404 returns 422 not_found', async () => {
    const res = await hub.scrape({ url: 'https://fccid.io/ABC-123/missing-device', discoverLlmsTxt: false });
    assert.equal(res.status, 422);
    assert.equal(res.body.ok, false);
    assert.equal(res.body.outcome, 'not_found');
    assert.equal(res.body.status, 404);
  });

  test('F23.T2.5: fccid.io empty exhibit table retains heading cleanly', async () => {
    const res = await hub.scrape({ url: 'https://fccid.io/ABC-123/empty-table', discoverLlmsTxt: false });
    assert.equal(res.status, 200);
    assert.equal(res.body.ok, true);
    assert.match(res.body.markdown, /FCC ID ABC-123/);
  });

  // --- F24: wikidata-openlibrary (5 tests) ---
  test('F24.T2.1: openlibrary.org Disallow: /api blocks /api/books with 0 outbound requests', async () => {
    const r = createOutboundRouter();
    r.setRobots('openlibrary.org', F24_WIKIDATA_OPENLIBRARY.openLibraryRobotsTxt);
    await withFreshHub({ router: r }, async (h) => {
      const res = await h.scrape({
        url: 'https://openlibrary.org/api/books?bibkeys=ISBN:9780140328721',
        discoverLlmsTxt: false,
      });
      assert.equal(res.status, 422);
      assert.equal(res.body.ok, false);
      assert.match(String(res.body.problem ?? ''), /robots\.txt/i);
      assert.equal(r.countRequests('openlibrary.org', '/api/books'), 0);
    });
  });

  test('F24.T2.2: openlibrary.org /isbn/*.json same-host 302 to /books/OL*.json passes isTrustedTwinRedirectUrl without touching /api', async () => {
    const r = createOutboundRouter();
    r.setRobots('openlibrary.org', F24_WIKIDATA_OPENLIBRARY.openLibraryRobotsTxt);
    r.redirect('https://openlibrary.org/isbn/9780140328721.json', 'https://openlibrary.org/books/OL7353617M.json', 302);
    r.json('https://openlibrary.org/books/OL7353617M.json', F24_WIKIDATA_OPENLIBRARY.openLibraryBookJson());
    await withFreshHub({ router: r }, async (h) => {
      const res = await h.scrape({ url: 'https://openlibrary.org/isbn/9780140328721', discoverLlmsTxt: false });
      assert.equal(res.status, 200);
      assert.equal(res.body.extractorId, 'wikidata-openlibrary');
      assert.ok(r.countRequests('openlibrary.org', '/books/OL7353617M.json') >= 1);
      assert.equal(r.countRequests('openlibrary.org', '/api'), 0);
    });
  });

  test('F24.T2.3: openlibrary.org rejects cross-host redirect from /isbn/*.json to evil domain', async () => {
    const res = await hub.scrape({ url: 'https://openlibrary.org/isbn/9780140328722', discoverLlmsTxt: false });
    assert.equal(res.status, 200);
    assert.notEqual(res.body.extractorId, 'wikidata-openlibrary');
    assert.equal(res.body.markdown.includes('EVIL_OL'), false);
    assert.match(res.body.markdown, /Book HTML Fallback/);
  });

  test('F24.T2.4: wikidata.org >4 MiB EntityData JSON falls back cleanly to HTML', async () => {
    const res = await hub.scrape({ url: 'https://www.wikidata.org/wiki/Q30', discoverLlmsTxt: false });
    assert.equal(res.status, 200);
    assert.notEqual(res.body.extractorId, 'wikidata-openlibrary');
    assert.match(res.body.markdown, /United States/);
  });

  test('F24.T2.5: wikidata.org 404 entity returns 422 not_found', async () => {
    const res = await hub.scrape({ url: 'https://www.wikidata.org/wiki/Q999999999', discoverLlmsTxt: false });
    assert.equal(res.status, 422);
    assert.equal(res.body.ok, false);
    assert.equal(res.body.outcome, 'not_found');
    assert.equal(res.body.status, 404);
  });
});

// ============================================================================
// Group E: L-01–L-05 Audit Follow-Ups (F25–F29 — 25 tests)
// ============================================================================
describe('Tier 2 Group E — M1 Audit Follow-Ups L-01..L-05 (F25–F29)', () => {
  // --- F25: L-01 jsonFilter cache key & bypass isolation (5 tests) ---
  test('F25.T2.1: L-01 distinct jsonFilter values isolate cache entries (both cached: false)', async () => {
    const r = createOutboundRouter();
    r.json('https://l01-t2-1.example.com/items.json', [
      { name: 'Lock', price: 45 },
      { name: 'Motor', price: 450 },
    ]);
    await withFreshHub({ router: r }, async (h) => {
      const r1 = await h.scrape({
        url: 'https://l01-t2-1.example.com/items.json',
        jsonFilter: 'price=45',
        maxAgeMs: 60_000,
        discoverLlmsTxt: false,
      });
      const r2 = await h.scrape({
        url: 'https://l01-t2-1.example.com/items.json',
        jsonFilter: 'price!=45',
        maxAgeMs: 60_000,
        discoverLlmsTxt: false,
      });
      assert.equal(r1.status, 200);
      assert.equal(r1.body.cached, false);
      assert.match(r1.body.markdown, /Lock/);
      assert.equal(r1.body.markdown.includes('Motor'), false);
      assert.equal(r2.status, 200);
      assert.equal(r2.body.cached, false);
      assert.match(r2.body.markdown, /Motor/);
      assert.equal(r2.body.markdown.includes('Lock'), false);
      assert.equal(r.countRequests('l01-t2-1.example.com', '/items.json'), 2);
    });
  });

  test('F25.T2.2: L-01 whitespace-only jsonFilter shares unfiltered cache key (cached: true)', async () => {
    const r = createOutboundRouter();
    r.json('https://l01-t2-2.example.com/items.json', [{ name: 'Lock', price: 45 }]);
    await withFreshHub({ router: r }, async (h) => {
      const r1 = await h.scrape({
        url: 'https://l01-t2-2.example.com/items.json',
        maxAgeMs: 60_000,
        discoverLlmsTxt: false,
      });
      const r2 = await h.scrape({
        url: 'https://l01-t2-2.example.com/items.json',
        jsonFilter: '   ',
        maxAgeMs: 60_000,
        discoverLlmsTxt: false,
      });
      assert.equal(r1.status, 200);
      assert.equal(r1.body.cached, false);
      assert.equal(r2.status, 200);
      assert.equal(r2.body.cached, true);
      assert.equal(r.countRequests('l01-t2-2.example.com', '/items.json'), 1);
    });
  });

  test('F25.T2.3: L-01 unfiltered scrape does not bleed into subsequent jsonFilter request', async () => {
    const r = createOutboundRouter();
    r.json('https://l01-t2-3.example.com/items.json', [
      { name: 'Lock', price: 45 },
      { name: 'Motor', price: 450 },
    ]);
    await withFreshHub({ router: r }, async (h) => {
      const r1 = await h.scrape({
        url: 'https://l01-t2-3.example.com/items.json',
        maxAgeMs: 60_000,
        discoverLlmsTxt: false,
      });
      const r2 = await h.scrape({
        url: 'https://l01-t2-3.example.com/items.json',
        jsonFilter: 'price=45',
        maxAgeMs: 60_000,
        discoverLlmsTxt: false,
      });
      assert.equal(r1.status, 200);
      assert.equal(r2.status, 200);
      assert.equal(r2.body.cached, false);
      assert.equal(r2.body.markdown.includes('Motor'), false);
    });
  });

  test('F25.T2.4: L-01 noCache: true with jsonFilter bypasses cache and fetches fresh payload', async () => {
    const r = createOutboundRouter();
    let hit = 0;
    r.route('https://l01-t2-4.example.com/items.json', (_u, _req, MfRes) => {
      hit++;
      return new MfRes(JSON.stringify([{ name: hit === 1 ? 'Lock V1' : 'Lock V2', price: 45 }]), {
        status: 200,
        headers: { 'content-type': 'application/json; charset=utf-8' },
      });
    });
    await withFreshHub({ router: r }, async (h) => {
      const r1 = await h.scrape({
        url: 'https://l01-t2-4.example.com/items.json',
        jsonFilter: 'price=45',
        maxAgeMs: 60_000,
        discoverLlmsTxt: false,
      });
      const r2 = await h.scrape({
        url: 'https://l01-t2-4.example.com/items.json',
        jsonFilter: 'price=45',
        maxAgeMs: 60_000,
        noCache: true,
        discoverLlmsTxt: false,
      });
      assert.equal(r1.status, 200);
      assert.equal(r2.status, 200);
      assert.equal(r2.body.cached, false);
      assert.match(r2.body.markdown, /Lock V2/);
      assert.equal(r.countRequests('l01-t2-4.example.com', '/items.json'), 2);
    });
  });

  test('F25.T2.5: L-01 jsonFilter + redactPii produces isolated redacted cache entry', async () => {
    const r = createOutboundRouter();
    r.json('https://l01-t2-5.example.com/items.json', [{ name: 'Lock', price: 45, email: 'bob@example.com' }]);
    await withFreshHub({ router: r }, async (h) => {
      const r1 = await h.scrape({
        url: 'https://l01-t2-5.example.com/items.json',
        jsonFilter: 'price=45',
        maxAgeMs: 60_000,
        discoverLlmsTxt: false,
      });
      const r2 = await h.scrape({
        url: 'https://l01-t2-5.example.com/items.json',
        jsonFilter: 'price=45',
        maxAgeMs: 60_000,
        redactPii: true,
        discoverLlmsTxt: false,
      });
      assert.equal(r1.status, 200);
      assert.equal(r2.status, 200);
      assert.equal(r2.body.cached, false);
      assert.equal(r2.body.markdown.includes('bob@example.com'), false);
    });
  });

  // --- F26: L-02 edgeBudgetExceeded boundaries (5 tests) ---
  test('F26.T2.1: L-02 exact 4,194,304 B (= MAX_WASM_INPUT_BYTES) artifact inline succeeds without edgeBudgetExceeded', async () => {
    const exact4MHtml = exactBytesHtml(MAX_WASM_INPUT_BYTES, 'Exact 4MiB');
    await withFreshHub(async (h) => {
      await h.connectMockAgent({
        onDispatch: async (_msg, helpers) => {
          const req0 = helpers.call.requests?.[0] ?? {};
          await helpers.sendReply({
            results: [
              {
                id: req0.id,
                url: req0.url,
                finalUrl: req0.url,
                status: 200,
                outcome: 'ok',
                contentType: 'text/html',
                body: exact4MHtml,
                bodyEncoding: 'utf-8',
              },
            ],
          });
        },
      });
      const res = await h.scrape({
        url: 'https://l02-t2-1.example.com/exact-4mb.html',
        target: 'agent',
        discoverLlmsTxt: false,
      });
      assert.equal(res.status, 200);
      assert.equal(res.body.edgeBudgetExceeded, undefined);
      assert.match(res.body.markdown, /Exact 4MiB/);
    });
  });

  test('F26.T2.2: L-02 4,194,305 B artifact with bodyOmitted: true & extractedOnNode: false sets edgeBudgetExceeded: true', async () => {
    const overHtml = exactBytesHtml(MAX_WASM_INPUT_BYTES + 1, 'Over 4MiB');
    await withFreshHub(async (h) => {
      let expectedSha;
      await h.connectMockAgent({
        onDispatch: async (_msg, helpers) => {
          const req0 = helpers.call.requests?.[0] ?? {};
          const art = await helpers.uploadArtifact(overHtml, { requestId: req0.id });
          expectedSha = art.blobSha256;
          await helpers.sendReply({
            results: [
              {
                id: req0.id,
                url: req0.url,
                finalUrl: req0.url,
                status: 200,
                outcome: 'ok',
                contentType: 'text/html',
                bodyOmitted: true,
                extractedOnNode: false,
                artifact: art,
              },
            ],
          });
        },
      });
      const res = await h.scrape({
        url: 'https://l02-t2-2.example.com/over-4mb.html',
        target: 'agent',
        discoverLlmsTxt: false,
      });
      assert.equal(res.status, 200);
      assert.equal(res.body.edgeBudgetExceeded, true);
      assert.equal(res.body.markdown, '');
      assert.equal(res.body.artifactId, expectedSha);
      assert.ok((res.body.warnings ?? []).some((w) => w.includes('4 MiB WASM input budget')));
    });
  });

  test('F26.T2.3: L-02 >4 MiB origin text/markdown truncates cleanly with contentSource: origin-markdown (not edgeBudgetExceeded)', async () => {
    const r = createOutboundRouter();
    const mdPrefix = '# Huge Origin Markdown\n\n';
    const hugeMd = `${mdPrefix}${'m'.repeat(MAX_WASM_INPUT_BYTES + 1 - Buffer.byteLength(mdPrefix, 'utf8'))}`;
    r.text('https://l02-t2-3.example.com/over-4mb.md', hugeMd, {
      headers: { 'content-type': 'text/markdown; charset=utf-8' },
    });
    await withFreshHub({ router: r }, async (h) => {
      const res = await h.scrape({
        url: 'https://l02-t2-3.example.com/over-4mb.md',
        target: 'container',
        discoverLlmsTxt: false,
      });
      assert.equal(res.status, 200);
      assert.equal(res.body.edgeBudgetExceeded, undefined);
      assert.equal(res.body.contentSource, 'origin-markdown');
      assert.equal(res.body.sourceTruncated, true);
      assert.match(res.body.markdown, /Huge Origin Markdown/);
    });
  });

  test('F26.T2.4: L-02 includeTags request rejects unscoped node markdown (no contentScopingApplied)', async () => {
    await withFreshHub(async (h) => {
      await h.connectMockAgent({
        onDispatch: async (_msg, helpers) => {
          const req0 = helpers.call.requests?.[0] ?? {};
          await helpers.sendReply({
            results: [
              {
                id: req0.id,
                url: req0.url,
                finalUrl: req0.url,
                status: 200,
                outcome: 'ok',
                contentType: 'text/html',
                bodyOmitted: true,
                extractedOnNode: true,
                markdown: '# Scoped',
              },
            ],
          });
        },
      });
      const res = await h.scrape({
        url: 'https://l02-t2-4.example.com/tag-scoped.html',
        target: 'agent',
        includeTags: ['main'],
        discoverLlmsTxt: false,
      });
      assert.equal(res.status, 200);
      assert.equal(res.body.edgeBudgetExceeded, true);
      assert.equal(res.body.markdown, '');
    });
  });

  test('F26.T2.5: L-02 extractedOnNode: true with markdownOverBudget: true returns edgeBudgetExceeded: true', async () => {
    await withFreshHub(async (h) => {
      await h.connectMockAgent({
        onDispatch: async (_msg, helpers) => {
          const req0 = helpers.call.requests?.[0] ?? {};
          await helpers.sendReply({
            results: [
              {
                id: req0.id,
                url: req0.url,
                finalUrl: req0.url,
                status: 200,
                outcome: 'ok',
                contentType: 'text/html',
                bodyOmitted: true,
                extractedOnNode: true,
                markdownOverBudget: true,
                markdown: '',
              },
            ],
          });
        },
      });
      const res = await h.scrape({
        url: 'https://l02-t2-5.example.com/huge-node-md.html',
        target: 'agent',
        discoverLlmsTxt: false,
      });
      assert.equal(res.status, 200);
      assert.equal(res.body.edgeBudgetExceeded, true);
      assert.equal(res.body.markdown, '');
    });
  });

  // --- F27: L-03 rawBase64 / parsers: [] > 4 MiB up to 18 MiB wire budget (5 tests) ---
  test('F27.T2.1: L-03 rawBase64 hydrates exact 4,194,305 B HTML artifact inline', async () => {
    const html4MPlus1 = exactBytesHtml(MAX_WASM_INPUT_BYTES + 1, 'RawBase64 4MiB+1');
    await withFreshHub(async (h) => {
      await h.connectMockAgent({
        onDispatch: async (_msg, helpers) => {
          const req0 = helpers.call.requests?.[0] ?? {};
          const art = await helpers.uploadArtifact(html4MPlus1, { requestId: req0.id });
          await helpers.sendReply({
            results: [
              {
                id: req0.id,
                url: req0.url,
                finalUrl: req0.url,
                status: 200,
                outcome: 'ok',
                contentType: 'text/html',
                bodyOmitted: true,
                artifact: art,
              },
            ],
          });
        },
      });
      const res = await h.scrape({
        url: 'https://l03-t2-1.example.com/4mb-plus-1.html',
        target: 'agent',
        formats: ['rawBase64'],
        discoverLlmsTxt: false,
      });
      assert.equal(res.status, 200);
      assert.equal(typeof res.body.rawBase64, 'string');
      assert.equal(Buffer.from(res.body.rawBase64, 'base64').byteLength, MAX_WASM_INPUT_BYTES + 1);
    });
  });

  test('F27.T2.2: L-03 rawBase64 + parsers: [] hydrates 16 MiB ASCII PDF within 18 MiB wire budget', async () => {
    const header = '%PDF-1.7\n';
    const footer = '\n%%EOF\n';
    const pdf16Mib = Buffer.concat([
      Buffer.from(header, 'ascii'),
      Buffer.alloc(MAX_ARTIFACT_CONTENT_BYTES - header.length - footer.length, 0x20),
      Buffer.from(footer, 'ascii'),
    ]);
    await withFreshHub(async (h) => {
      await h.connectMockAgent({
        onDispatch: async (_msg, helpers) => {
          const req0 = helpers.call.requests?.[0] ?? {};
          const art = await helpers.uploadArtifact(pdf16Mib, { requestId: req0.id });
          await helpers.sendReply({
            results: [
              {
                id: req0.id,
                url: req0.url,
                finalUrl: req0.url,
                status: 200,
                outcome: 'ok',
                contentType: 'application/pdf',
                bodyOmitted: true,
                artifact: art,
              },
            ],
          });
        },
      });
      const res = await h.scrape({
        url: 'https://l03-t2-2.example.com/16mb-pdf.pdf',
        target: 'agent',
        formats: ['rawBase64'],
        parsers: [],
        discoverLlmsTxt: false,
      });
      assert.equal(res.status, 200);
      assert.equal(typeof res.body.rawBase64, 'string');
      assert.equal(Buffer.from(res.body.rawBase64, 'base64').byteLength, MAX_ARTIFACT_CONTENT_BYTES);
    });
  });

  test('F27.T2.3: L-03 14 MiB binary (0xff) base64 (~18.67 MiB > 18 MiB wire budget) returns artifactId + warning', async () => {
    const bin14Mib = Buffer.alloc(14 * 1024 * 1024, 0xff);
    await withFreshHub(async (h) => {
      let expectedSha;
      await h.connectMockAgent({
        onDispatch: async (_msg, helpers) => {
          const req0 = helpers.call.requests?.[0] ?? {};
          const art = await helpers.uploadArtifact(bin14Mib, { requestId: req0.id });
          expectedSha = art.blobSha256;
          await helpers.sendReply({
            results: [
              {
                id: req0.id,
                url: req0.url,
                finalUrl: req0.url,
                status: 200,
                outcome: 'ok',
                contentType: 'application/pdf',
                bodyOmitted: true,
                artifact: art,
              },
            ],
          });
        },
      });
      const res = await h.scrape({
        url: 'https://l03-t2-3.example.com/14mb-bin.pdf',
        target: 'agent',
        formats: ['rawBase64'],
        parsers: [],
        discoverLlmsTxt: false,
      });
      assert.equal(res.status, 200);
      assert.equal(res.body.rawBase64, undefined);
      assert.equal(res.body.artifactId, expectedSha);
      assert.ok((res.body.warnings ?? []).some((w) => w.includes('artifactId')));
    });
  });

  test('F27.T2.4: L-03 rawBase64 dispatches maxInlineBodyBytes === INLINE_HYDRATION_BUDGET_BYTES (18 MiB)', async () => {
    const html5Mib = exactBytesHtml(5 * 1024 * 1024, 'RawBase64 5MiB');
    await withFreshHub(async (h) => {
      let seenMaxInline;
      await h.connectMockAgent({
        onDispatch: async (_msg, helpers) => {
          const req0 = helpers.call.requests?.[0] ?? {};
          seenMaxInline = helpers.call.options?.maxInlineBodyBytes;
          const art = await helpers.uploadArtifact(html5Mib, { requestId: req0.id });
          await helpers.sendReply({
            results: [
              {
                id: req0.id,
                url: req0.url,
                finalUrl: req0.url,
                status: 200,
                outcome: 'ok',
                contentType: 'text/html',
                bodyOmitted: true,
                artifact: art,
              },
            ],
          });
        },
      });
      const res = await h.scrape({
        url: 'https://l03-t2-4.example.com/5mb-raw-only.html',
        target: 'agent',
        formats: ['rawBase64'],
        discoverLlmsTxt: false,
      });
      assert.equal(seenMaxInline, INLINE_HYDRATION_BUDGET_BYTES);
      assert.equal(res.status, 200);
      assert.equal(typeof res.body.rawBase64, 'string');
    });
  });

  test('F27.T2.5: L-03 parsers: [] with >4 MiB PDF binary hydrates rawBase64 without edgeBudgetExceeded', async () => {
    const pdf5Mib = Buffer.concat([
      Buffer.from('%PDF-1.7\n', 'ascii'),
      Buffer.alloc(5 * 1024 * 1024 - 16, 0x20),
      Buffer.from('\n%%EOF\n', 'ascii'),
    ]);
    await withFreshHub(async (h) => {
      await h.connectMockAgent({
        onDispatch: async (_msg, helpers) => {
          const req0 = helpers.call.requests?.[0] ?? {};
          const art = await helpers.uploadArtifact(pdf5Mib, { requestId: req0.id });
          await helpers.sendReply({
            results: [
              {
                id: req0.id,
                url: req0.url,
                finalUrl: req0.url,
                status: 200,
                outcome: 'ok',
                contentType: 'application/pdf',
                bodyOmitted: true,
                artifact: art,
              },
            ],
          });
        },
      });
      const res = await h.scrape({
        url: 'https://l03-t2-5.example.com/5mb-parsers-empty.pdf',
        target: 'agent',
        parsers: [],
        formats: ['markdown'],
        discoverLlmsTxt: false,
      });
      assert.equal(res.status, 200);
      assert.equal(typeof res.body.rawBase64, 'string');
      assert.equal(res.body.edgeBudgetExceeded, undefined);
    });
  });

  // --- F28: L-04 relative product.url + backfillProductFromRecord (5 tests) ---
  test('F28.T2.1: L-04 JSON-LD Product relative ../bikes/gravel#frame resolves against finalUrl', async () => {
    const r = createOutboundRouter();
    r.html(
      'https://l04-t2-1.example.com/cat/sub/page.html',
      '<!doctype html><html><head><script type="application/ld+json">{"@type":"Product","name":"Gravel Pro","url":"../bikes/gravel#frame","offers":{"price":"2100.00","priceCurrency":"USD"}}</script></head><body><h1>Gravel Pro</h1></body></html>',
    );
    await withFreshHub({ router: r }, async (h) => {
      const res = await h.scrape({
        url: 'https://l04-t2-1.example.com/cat/sub/page.html',
        formats: ['product'],
        discoverLlmsTxt: false,
      });
      assert.equal(res.status, 200);
      assert.equal(res.body.product?.url, 'https://l04-t2-1.example.com/cat/bikes/gravel#frame');
    });
  });

  test('F28.T2.2: L-04 JSON-LD Product protocol-relative //host/path resolves to https://', async () => {
    const r = createOutboundRouter();
    r.html(
      'https://l04-t2-2.example.com/shop/item',
      '<!doctype html><html><head><script type="application/ld+json">{"@type":"Product","name":"Hub Motor","url":"//l04-t2-2.example.com/p/123","offers":{"price":"399.00","priceCurrency":"USD"}}</script></head><body><h1>Hub Motor</h1></body></html>',
    );
    await withFreshHub({ router: r }, async (h) => {
      const res = await h.scrape({
        url: 'https://l04-t2-2.example.com/shop/item',
        formats: ['product'],
        discoverLlmsTxt: false,
      });
      assert.equal(res.status, 200);
      assert.equal(res.body.product?.url, 'https://l04-t2-2.example.com/p/123');
    });
  });

  test('F28.T2.3: L-04 JSON-LD Product SSRF https://127.0.0.1/internal falls back to finalUrl', async () => {
    const r = createOutboundRouter();
    r.html(
      'https://l04-t2-3.example.com/shop/ssrf-url',
      '<!doctype html><html><head><script type="application/ld+json">{"@type":"Product","name":"Safe Lock","url":"https://127.0.0.1/internal","offers":{"price":"49.00","priceCurrency":"USD"}}</script></head><body><h1>Safe Lock</h1></body></html>',
    );
    await withFreshHub({ router: r }, async (h) => {
      const res = await h.scrape({
        url: 'https://l04-t2-3.example.com/shop/ssrf-url',
        formats: ['product'],
        discoverLlmsTxt: false,
      });
      assert.equal(res.status, 200);
      assert.equal(res.body.product?.url, 'https://l04-t2-3.example.com/shop/ssrf-url');
    });
  });

  test('F28.T2.4: L-04 backfillProductFromRecord fills missing brand & availability without overwriting explicit JSON-LD sku/price', async () => {
    const r = createOutboundRouter();
    r.html(
      'https://l04-t2-4.example.com/products/ebike',
      `<!doctype html><html><head><title>City E-Bike</title>
      <script>window.Shopify = { shop: "l04-t2-4.myshopify.com" };</script>
      <script type="application/ld+json">{"@type":"Product","name":"City E-Bike","sku":"EXPLICIT-SKU","offers":{"@type":"Offer","price":"1999.00","priceCurrency":"USD"}}</script>
      </head><body><main><h1>City E-Bike</h1></main></body></html>`,
    );
    r.json('https://l04-t2-4.example.com/products/ebike.json', {
      product: {
        id: 5001,
        title: 'City E-Bike',
        handle: 'ebike',
        vendor: 'AcmeCycles',
        body_html: '<p>Urban commuter.</p>',
        variants: [{ id: 1, title: 'Default', sku: 'TWIN-SKU', price: '2499.00', available: true }],
      },
    });
    await withFreshHub({ router: r }, async (h) => {
      const res = await h.scrape({
        url: 'https://l04-t2-4.example.com/products/ebike',
        formats: ['product'],
        discoverLlmsTxt: false,
      });
      assert.equal(res.status, 200);
      assert.equal(res.body.product?.sku, 'EXPLICIT-SKU');
      assert.equal(res.body.product?.price, 1999);
      assert.equal(res.body.product?.brand, 'AcmeCycles');
      assert.equal(res.body.product?.availability, 'InStock');
    });
  });

  test('F28.T2.5: L-04 custom-domain WooCommerce without JSON-LD backfills product & json from Store API', async () => {
    const r = createOutboundRouter();
    r.html(
      'https://l04-t2-5.example.com/product/no-ld/',
      '<!doctype html><html><head><title>Woo Product</title><meta name="generator" content="WooCommerce 9.3.1"></head><body class="woocommerce single-product"><main><h1>Woo Product</h1></main></body></html>',
    );
    r.json(
      (u) => u.hostname === 'l04-t2-5.example.com' && u.pathname.startsWith('/wp-json/wc/store/v1/products'),
      {
        id: 77,
        name: 'Woo Product',
        slug: 'no-ld',
        permalink: 'https://l04-t2-5.example.com/product/no-ld/',
        sku: 'WC-55',
        brands: [{ name: 'WooBrand' }],
        is_in_stock: true,
        prices: { price: '49900', currency_code: 'USD', currency_minor_unit: 2 },
      },
    );
    await withFreshHub({ router: r }, async (h) => {
      const res = await h.scrape({
        url: 'https://l04-t2-5.example.com/product/no-ld/',
        formats: [
          'product',
          { type: 'json', schema: { type: 'object', properties: { sku: { type: 'string' }, brand: { type: 'string' } } } },
        ],
        discoverLlmsTxt: false,
      });
      assert.equal(res.status, 200);
      assert.equal(res.body.product?.sku, 'WC-55');
      assert.equal(res.body.product?.price, 499);
      assert.equal(res.body.json?.sku, 'WC-55');
    });
  });

  // --- F29: L-05 maxInlineBodyBytes on auto-render-1 & wd-stub-render-1 (5 tests) ---
  test('F29.T2.1: L-05 auto-render-1 exact 4,194,304 B (= MAX_WASM_INPUT_BYTES) hydrated HTML succeeds', async () => {
    const rendered4M = exactBytesHtml(MAX_WASM_INPUT_BYTES, 'Rendered Exact 4MiB', `<p>${'word '.repeat(60)}</p>`);
    await withFreshHub(async (h) => {
      let seenMaxInline;
      await h.connectMockAgent({
        onDispatch: async (_msg, helpers) => {
          const req0 = helpers.call.requests?.[0] ?? {};
          if (req0.id === 'auto-render-1') {
            seenMaxInline = helpers.call.options?.maxInlineBodyBytes;
            await helpers.sendReply({
              results: [
                {
                  id: req0.id,
                  url: req0.url,
                  finalUrl: req0.url,
                  status: 200,
                  outcome: 'ok',
                  contentType: 'text/html',
                  body: rendered4M,
                  bodyEncoding: 'utf-8',
                },
              ],
            });
            return;
          }
          await helpers.sendReply({
            results: [
              {
                id: req0.id,
                url: req0.url,
                finalUrl: req0.url,
                status: 200,
                outcome: 'ok',
                contentType: 'text/html',
                body: '<html><body><div id="root"></div><script src="/a.js"></script></body></html>',
                bodyEncoding: 'utf-8',
              },
            ],
          });
        },
      });
      const res = await h.scrape({ url: 'https://l05-t2-1.example.com/spa', discoverLlmsTxt: false });
      assert.equal(seenMaxInline, MAX_WASM_INPUT_BYTES);
      assert.equal(res.status, 200);
      assert.equal(res.body.rendered, true);
      assert.equal(res.body.renderedVia, 'browser-auto');
    });
  });

  test('F29.T2.2: L-05 auto-render-1 503 browser_worker_required degrades cleanly to rendered: false + warning', async () => {
    await withFreshHub(async (h) => {
      await h.connectMockAgent({
        capabilities: 'artifacts-v1',
        onDispatch: async (_msg, helpers) => {
          const req0 = helpers.call.requests?.[0] ?? {};
          await helpers.sendReply({
            results: [
              {
                id: req0.id,
                url: req0.url,
                finalUrl: req0.url,
                status: 200,
                outcome: 'ok',
                contentType: 'text/html',
                body: '<html><body><div id="root"></div><script src="/a.js"></script></body></html>',
                bodyEncoding: 'utf-8',
              },
            ],
          });
        },
      });
      const res = await h.scrape({ url: 'https://l05-t2-2.example.com/spa-503', discoverLlmsTxt: false });
      assert.equal(res.status, 200);
      assert.equal(res.body.ok, true);
      assert.equal(res.body.rendered, false);
      assert.ok((res.body.warnings ?? []).some((w) => w.includes('browser-v1')));
    });
  });

  test('F29.T2.3: L-05 auto-render-1 returning fewer words than static HTML keeps rendered: false', async () => {
    await withFreshHub(async (h) => {
      await h.connectMockAgent({
        onDispatch: async (_msg, helpers) => {
          const req0 = helpers.call.requests?.[0] ?? {};
          const isRender = req0.id === 'auto-render-1';
          await helpers.sendReply({
            results: [
              {
                id: req0.id,
                url: req0.url,
                finalUrl: req0.url,
                status: 200,
                outcome: 'ok',
                contentType: 'text/html',
                body: isRender
                  ? '<html><body><main><p>Empty</p></main></body></html>'
                  : '<html><body><main><h1>Initial Static Heading</h1><p>Initial words one two three four five six seven eight nine ten eleven twelve.</p></main><script src="/a.js"></script></body></html>',
                bodyEncoding: 'utf-8',
              },
            ],
          });
        },
      });
      const res = await h.scrape({ url: 'https://l05-t2-3.example.com/spa-same', discoverLlmsTxt: false });
      assert.equal(res.status, 200);
      assert.equal(res.body.rendered, false);
      assert.match(res.body.markdown, /Initial Static Heading/);
    });
  });

  test('F29.T2.4: L-05 wd-stub-render-1 enforces maxInlineBodyBytes: MAX_WASM_INPUT_BYTES on >4 MiB artifact', async () => {
    const bigWdHtml = exactBytesHtml(MAX_WASM_INPUT_BYTES + 1, 'Huge Workday');
    await withFreshHub(async (h) => {
      let wdStubMaxInline;
      await h.connectMockAgent({
        onDispatch: async (_msg, helpers) => {
          const req0 = helpers.call.requests?.[0] ?? {};
          if (req0.id === 'wd-stub-render-1') {
            wdStubMaxInline = helpers.call.options?.maxInlineBodyBytes;
            const art = await helpers.uploadArtifact(bigWdHtml, { requestId: req0.id });
            await helpers.sendReply({
              results: [
                {
                  id: req0.id,
                  url: req0.url,
                  finalUrl: req0.url,
                  status: 200,
                  outcome: 'ok',
                  contentType: 'text/html',
                  bodyOmitted: true,
                  artifact: art,
                },
              ],
            });
            return;
          }
          if (req0.id === 'scrape-1') {
            await helpers.sendReply({
              results: [
                {
                  id: req0.id,
                  url: req0.url,
                  finalUrl: req0.url,
                  status: 200,
                  outcome: 'ok',
                  contentType: 'application/json',
                  body: '{"widget":"redirect","url":"https://l05t2.wd1.myworkdayjobs.com/en-US/Careers","externalSpa":true}',
                  bodyEncoding: 'utf-8',
                },
              ],
            });
            return;
          }
          await helpers.sendReply({
            results: [{ id: req0.id, url: req0.url, status: 500, outcome: 'error', problem: 'HTTP 500' }],
          });
        },
      });
      const res = await h.scrape({
        url: 'https://l05t2.wd1.myworkdayjobs.com/en-US/Careers',
        discoverLlmsTxt: false,
      });
      assert.equal(wdStubMaxInline, MAX_WASM_INPUT_BYTES);
      assert.equal(res.status, 200);
      assert.equal(res.body.ok, true);
    });
  });

  test('F29.T2.5: L-05 thin external iframe SPA triggers auto-render-1 with maxInlineBodyBytes: MAX_WASM_INPUT_BYTES', async () => {
    await withFreshHub(async (h) => {
      let seenMaxInline;
      await h.connectMockAgent({
        onDispatch: async (_msg, helpers) => {
          const req0 = helpers.call.requests?.[0] ?? {};
          const isRender = req0.id === 'auto-render-1';
          if (isRender) seenMaxInline = helpers.call.options?.maxInlineBodyBytes;
          await helpers.sendReply({
            results: [
              {
                id: req0.id,
                url: req0.url,
                finalUrl: req0.url,
                status: 200,
                outcome: 'ok',
                contentType: 'text/html',
                body: isRender
                  ? `<html><body><main><h1>Hydrated Iframe</h1><p>${'job '.repeat(60)}</p></main></body></html>`
                  : '<html><body><iframe src="https://widget.example.com/board"></iframe></body></html>',
                bodyEncoding: 'utf-8',
              },
            ],
          });
        },
      });
      const res = await h.scrape({ url: 'https://l05-t2-5.example.com/iframe-spa', discoverLlmsTxt: false });
      assert.equal(seenMaxInline, MAX_WASM_INPUT_BYTES);
      assert.equal(res.status, 200);
      assert.equal(res.body.rendered, true);
    });
  });
});

// ============================================================================
// Group F: Production Log-Mined Ethical Adapters (F30–F35 — 30 tests)
// ============================================================================
describe('Tier 2 Group F — Boundary & Error Cases: Log-Mined Adapters (F30–F35)', () => {
  let router;
  let hub;

  before(async () => {
    router = createOutboundRouter();

    // F30 NFPA (robots tests use withFreshHub)
    router.html(
      'https://www.nfpa.org/codes-and-standards/nfpa-855-bad-json',
      '<!doctype html><html><head><title>NFPA 855</title></head><body><script id="__NEXT_DATA__" type="application/json">{malformed</script><main><h1>NFPA 855 Fallback</h1><p>Energy storage standard.</p></main></body></html>',
    );
    router.html(
      'https://www.nfpa.org/codes-and-standards/nfpa-855-empty-ph',
      `<!doctype html><html><head><title>NFPA Main DOM</title></head><body>
        <main><h1>NFPA Main DOM</h1><p>DOM fallback content when placeholders empty.</p></main>
        <script id="__NEXT_DATA__" type="application/json">${JSON.stringify({ props: { pageProps: { layoutData: { sitecore: { route: { placeholders: { 'storefront-main': [] } } } } } } })}</script>
      </body></html>`,
    );
    router.html(
      'https://link.nfpa.org/publications/855',
      '<!doctype html><html><head><title>NFPA LiNK</title></head><body><div id="root">Subscribe to NFPA LiNK to view codes.</div><script src="/app.js"></script></body></html>',
    );

    // F31 Giant & Liv (robots tests use withFreshHub)
    router.html(
      'https://www.giant-bicycles.com/us/trance-x-29',
      '<!doctype html><html><head><title>Trance X 29</title></head><body><main><h1>Trance X 29</h1><section id="specifications"><ul></ul></section><p>Trail bike overview.</p></main></body></html>',
    );
    router.html(
      'https://www.giant-bicycles.com/us/defy-advanced',
      `${F31_GIANT_LIV.bikeHtml('Giant', 'Defy Advanced').replace('Defy_Manual_2026.pdf', 'Defy_Manual.pdf').replace('</main>', '<a href="/us/shop/defy">Buy</a></main>')}`,
    );
    router.html(
      'https://www.giant-bicycles.com/us/huge-spec',
      `<!doctype html><html><head><title>Huge Giant</title></head><body><main>${over4Mib('<p>spec row</p>')}</main></body></html>`,
    );

    // F32 bumm.de (robots test uses withFreshHub)
    router.html(
      'https://bumm.de/en/products/detail/iq-x-bad-ld',
      '<!doctype html><html><head><title>IQ-X</title><script type="application/ld+json">{bad</script></head><body><main><h1>IQ-X</h1><table class="attributes-table"><tr><th>Lux</th><td>100 Lux</td></tr></table></main></body></html>',
    );
    router.html(
      'https://bumm.de/en/products/detail/iq-x-no-pdf',
      F32_BUMM.productHtml('en').replace(/<a href="[^"]+\.pdf">[^<]+<\/a>/, ''),
    );
    router.status('https://bumm.de/en/products/detail/iq-x-404', 404, '<html><body>Not Found</body></html>', {
      'content-type': 'text/html',
    });
    router.html(
      'https://bumm.de/en/products/detail/iq-x-huge',
      `<!doctype html><html><head><title>Huge Bumm</title></head><body><main>${over4Mib('<p>beam row</p>')}</main></body></html>`,
    );

    // F33 Bicycle Retailer (robots test uses withFreshHub)
    router.xml('https://www.bicycleretailer.com/rss.xml', '<rss><channel><item><title>Broken');
    router.html(
      'https://www.bicycleretailer.com/industry-news/empty-body',
      '<!doctype html><html><head><title>News Title</title></head><body><aside class="region-sidebar-second"><div>SIDEBAR_AD</div></aside><main><article class="node-article"><h1>News Title</h1><div class="field-name-body"></div></article></main></body></html>',
    );
    router.status('https://www.bicycleretailer.com/industry-news/404-article', 404, '<html><body>Not Found</body></html>', {
      'content-type': 'text/html',
    });
    router.html(
      'https://www.bicycleretailer.com/industry-news/huge',
      `<!doctype html><html><head><title>Huge BRAIN</title></head><body><main>${over4Mib('<p>news paragraph</p>')}</main></body></html>`,
    );

    // F35 D1 High-ROI
    router.html(
      'https://productinfo.shimano.com/en/product/DU-EP801-BAD',
      '<!doctype html><html><head><title>DU-EP801</title></head><body><script>self.__next_f=self.__next_f||[];self.__next_f.push([1,"{broken"])</script><main><h1>DU-EP801</h1><p>Drive unit overview.</p></main></body></html>',
    );
    router.html(
      'https://productinfo.shimano.com/en/product/DU-EP801',
      F35_D1_HIGH_ROI.shimanoProductInfoRscHtml('DU-EP801'),
    );
    router.status('https://si.shimano.com/en/pdfs/dm/123', 403, 'Forbidden');
    router.status('https://bike.shimano.com/en-EU/home.html', 403, 'Forbidden');
    router.html(
      'https://www.law.cornell.edu/cfr/text/16/1512.18',
      F35_D1_HIGH_ROI.cornellCfrHtml.replace('Cornell Donate Sidebar Noise', 'CORNELL_SIDEBAR_DONATE'),
    );
    router.html(
      'https://www.sram.com/en/sram/models/rd-gx-e-b1',
      '<!doctype html><html><head><title>GX Eagle</title><script type="application/ld+json">{bad</script></head><body><main class="product-detail"><h1>GX Eagle Derailleur</h1><table><tr><th>Weight</th><td>290g</td></tr></table></main></body></html>',
    );
    router.status('https://www.tq-ebike.com/en/help-support/hpr50-404', 404, '<html><body>Not Found</body></html>', {
      'content-type': 'text/html',
    });

    hub = await createHubInstance({ router });
  });

  after(async () => {
    await hub?.dispose();
  });

  // --- F30: www.nfpa.org (5 tests) ---
  test('F30.T2.1: www.nfpa.org Disallow: /en/ blocks localized paths via robots.txt', async () => {
    const r = createOutboundRouter();
    r.setRobots('www.nfpa.org', F30_NFPA.robotsTxt);
    await withFreshHub({ router: r }, async (h) => {
      const res = await h.scrape({ url: 'https://www.nfpa.org/en/codes-and-standards/nfpa-855', discoverLlmsTxt: false });
      assert.equal(res.status, 422);
      assert.equal(res.body.ok, false);
      assert.match(String(res.body.problem ?? ''), /robots\.txt/i);
      assert.equal(r.countRequests('www.nfpa.org', '/en/'), 0);
    });
  });

  test('F30.T2.2: www.nfpa.org Disallow: /-/media/ blocks media PDFs via robots.txt', async () => {
    const r = createOutboundRouter();
    r.setRobots('www.nfpa.org', F30_NFPA.robotsTxt);
    r.html('https://www.nfpa.org/-/media/files/standard.pdf', '<html><body>Media PDF</body></html>');
    await withFreshHub({ router: r }, async (h) => {
      const res = await h.scrape({ url: 'https://www.nfpa.org/-/media/files/standard.pdf', discoverLlmsTxt: false });
      assert.equal(res.status, 422);
      assert.equal(res.body.ok, false);
      assert.match(String(res.body?.problem ?? ''), /robots/i);
      assert.equal(r.countRequests('www.nfpa.org', '/-/media/'), 0);
    });
  });

  test('F30.T2.3: www.nfpa.org malformed __NEXT_DATA__ JSON falls back cleanly to HTML', async () => {
    const res = await hub.scrape({ url: 'https://www.nfpa.org/codes-and-standards/nfpa-855-bad-json', discoverLlmsTxt: false });
    assert.equal(res.status, 200);
    assert.equal(res.body.ok, true);
    assert.match(res.body.markdown, /NFPA 855 Fallback/);
  });

  test('F30.T2.4: www.nfpa.org empty storefront-main placeholder falls back to DOM content', async () => {
    const res = await hub.scrape({ url: 'https://www.nfpa.org/codes-and-standards/nfpa-855-empty-ph', discoverLlmsTxt: false });
    assert.equal(res.status, 200);
    assert.equal(res.body.ok, true);
    assert.match(res.body.markdown, /NFPA Main DOM/);
  });

  test('F30.T2.5: link.nfpa.org paywall SPA shell does not trigger www.nfpa.org Sitecore extractor', async () => {
    router.clearLog();
    const res = await hub.scrape({ url: 'https://link.nfpa.org/publications/855', discoverLlmsTxt: false });
    assert.ok(res.status === 200 || res.status === 402);
    assert.ok(router.countRequests('link.nfpa.org', '/publications/855') >= 1);
    assert.notEqual(res.body.extractorId, 'nfpa');
  });

  // --- F31: giant-liv-bikes (5 tests) ---
  test('F31.T2.1: giant-bicycles.com Disallow: /*shop* blocks checkout URL via robots.txt', async () => {
    const r = createOutboundRouter();
    r.setRobots('www.giant-bicycles.com', F31_GIANT_LIV.robotsTxt);
    await withFreshHub({ router: r }, async (h) => {
      const res = await h.scrape({ url: 'https://www.giant-bicycles.com/us/shop/checkout', discoverLlmsTxt: false });
      assert.equal(res.status, 422);
      assert.equal(res.body.ok, false);
      assert.match(String(res.body.problem ?? ''), /robots\.txt/i);
      assert.equal(r.countRequests('www.giant-bicycles.com', '/us/shop/'), 0);
    });
  });

  test('F31.T2.2: liv-cycling.com Disallow: /*comparison* blocks comparison URL via robots.txt', async () => {
    const r = createOutboundRouter();
    r.setRobots('www.liv-cycling.com', F31_GIANT_LIV.robotsTxt);
    r.html('https://www.liv-cycling.com/us/bikes-comparison', '<html><body>Comparison</body></html>');
    await withFreshHub({ router: r }, async (h) => {
      const res = await h.scrape({ url: 'https://www.liv-cycling.com/us/bikes-comparison', discoverLlmsTxt: false });
      assert.equal(res.status, 422);
      assert.equal(res.body.ok, false);
      assert.match(String(res.body?.problem ?? ''), /robots/i);
      assert.equal(r.countRequests('www.liv-cycling.com', '/us/bikes-comparison'), 0);
    });
  });

  test('F31.T2.3: giant-bicycles.com empty #specifications & missing geometry retains overview without /apiproxy/ or /shop/', async () => {
    router.clearLog();
    const res = await hub.scrape({ url: 'https://www.giant-bicycles.com/us/trance-x-29', discoverLlmsTxt: false });
    assert.equal(res.status, 200);
    assert.equal(res.body.ok, true);
    assert.match(res.body.markdown, /Trance X 29/);
    assert.match(res.body.markdown, /Trail bike overview/);
    assert.equal(router.countRequests('www.giant-bicycles.com', '/apiproxy/'), 0);
    assert.equal(router.countRequests('www.giant-bicycles.com', '/us/shop/'), 0);
  });

  test('F31.T2.4: giant-bicycles.com extracts specs, geometry, and manual PDF without following /us/shop/ links', async () => {
    router.clearLog();
    const res = await hub.scrape({
      url: 'https://www.giant-bicycles.com/us/defy-advanced',
      formats: ['markdown', 'links'],
      discoverLlmsTxt: false,
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.extractorId, 'giant-liv-bikes');
    assert.ok(res.body.markdown.includes('Defy_Manual.pdf') || (res.body.links ?? []).some((l) => l.includes('Defy_Manual.pdf')));
    assert.equal(router.countRequests('www.giant-bicycles.com', '/us/shop/'), 0);
  });

  test('F31.T2.5: giant-bicycles.com >4 MiB HTML on container returns edgeBudgetExceeded: true', async () => {
    const res = await hub.scrape({
      url: 'https://www.giant-bicycles.com/us/huge-spec',
      target: 'container',
      discoverLlmsTxt: false,
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.edgeBudgetExceeded, true);
    assert.equal(res.body.markdown, '');
  });

  // --- F32: bumm-de (5 tests) ---
  test('F32.T2.1: bumm.de Disallow: /typo3/ blocks TYPO3 backend via robots.txt', async () => {
    const r = createOutboundRouter();
    r.setRobots('bumm.de', F32_BUMM.robotsTxt);
    r.html('https://bumm.de/typo3/index.php', '<html><body>TYPO3 Backend</body></html>');
    await withFreshHub({ router: r }, async (h) => {
      const res = await h.scrape({ url: 'https://bumm.de/typo3/index.php', discoverLlmsTxt: false });
      assert.equal(res.status, 422);
      assert.equal(res.body.ok, false);
      assert.match(String(res.body?.problem ?? ''), /robots/i);
      assert.equal(r.countRequests('bumm.de', '/typo3/'), 0);
    });
  });

  test('F32.T2.2: bumm.de malformed JSON-LD retains table.attributes-table specs', async () => {
    const res = await hub.scrape({ url: 'https://bumm.de/en/products/detail/iq-x-bad-ld', discoverLlmsTxt: false });
    assert.equal(res.status, 200);
    assert.equal(res.body.ok, true);
    assert.match(res.body.markdown, /100 Lux/);
  });

  test('F32.T2.3: bumm.de handles product page with zero PDF manual links cleanly', async () => {
    const res = await hub.scrape({ url: 'https://bumm.de/en/products/detail/iq-x-no-pdf', discoverLlmsTxt: false });
    assert.equal(res.status, 200);
    assert.equal(res.body.extractorId, 'bumm-de');
    assert.match(res.body.markdown, /100 Lux/);
  });

  test('F32.T2.4: bumm.de 404 returns 422 not_found', async () => {
    const res = await hub.scrape({ url: 'https://bumm.de/en/products/detail/iq-x-404', discoverLlmsTxt: false });
    assert.equal(res.status, 422);
    assert.equal(res.body.ok, false);
    assert.equal(res.body.outcome, 'not_found');
    assert.equal(res.body.status, 404);
  });

  test('F32.T2.5: bumm.de >4 MiB HTML on container returns edgeBudgetExceeded: true', async () => {
    const res = await hub.scrape({
      url: 'https://bumm.de/en/products/detail/iq-x-huge',
      target: 'container',
      discoverLlmsTxt: false,
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.edgeBudgetExceeded, true);
    assert.equal(res.body.markdown, '');
  });

  // --- F33: bicycleretailer (5 tests) ---
  test('F33.T2.1: bicycleretailer.com Disallow: /admin/ blocks admin path via robots.txt', async () => {
    const r = createOutboundRouter();
    r.setRobots('www.bicycleretailer.com', F33_BICYCLE_RETAILER.robotsTxt);
    r.html('https://www.bicycleretailer.com/admin/config', '<html><body>Admin Config</body></html>');
    await withFreshHub({ router: r }, async (h) => {
      const res = await h.scrape({ url: 'https://www.bicycleretailer.com/admin/config', discoverLlmsTxt: false });
      assert.equal(res.status, 422);
      assert.equal(res.body.ok, false);
      assert.match(String(res.body?.problem ?? ''), /robots/i);
      assert.equal(r.countRequests('www.bicycleretailer.com', '/admin/'), 0);
    });
  });

  test('F33.T2.2: bicycleretailer.com malformed RSS XML handles cleanly without Worker 500', async () => {
    router.clearLog();
    const res = await hub.scrape({ url: 'https://www.bicycleretailer.com/rss.xml', discoverLlmsTxt: false });
    assert.ok(router.countRequests('www.bicycleretailer.com', '/rss.xml') >= 1);
    assert.ok(
      (res.status === 200 && res.body.ok === true && res.body.extractorId !== 'bicycleretailer') ||
        (res.status === 422 && res.body.ok === false && res.body.outcome === 'error'),
      `Unexpected malformed RSS outcome: status=${res.status}, body=${JSON.stringify(res.body)}`,
    );
  });

  test('F33.T2.3: bicycleretailer.com empty .field-name-body strips sidebar ads and retains heading', async () => {
    const res = await hub.scrape({ url: 'https://www.bicycleretailer.com/industry-news/empty-body', discoverLlmsTxt: false });
    assert.equal(res.status, 200);
    assert.equal(res.body.ok, true);
    assert.equal(res.body.markdown.includes('SIDEBAR_AD'), false);
    assert.match(res.body.markdown, /News Title/);
  });

  test('F33.T2.4: bicycleretailer.com 404 returns 422 not_found', async () => {
    const res = await hub.scrape({ url: 'https://www.bicycleretailer.com/industry-news/404-article', discoverLlmsTxt: false });
    assert.equal(res.status, 422);
    assert.equal(res.body.ok, false);
    assert.equal(res.body.outcome, 'not_found');
    assert.equal(res.body.status, 404);
  });

  test('F33.T2.5: bicycleretailer.com >4 MiB HTML on container returns edgeBudgetExceeded: true', async () => {
    const res = await hub.scrape({
      url: 'https://www.bicycleretailer.com/industry-news/huge',
      target: 'container',
      discoverLlmsTxt: false,
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.edgeBudgetExceeded, true);
    assert.equal(res.body.markdown, '');
  });

  // --- F34: youtube (5 tests — each isolated in withFreshHub for robots & mock agent) ---
  test('F34.T2.1: youtube.com Disallow: /api/ blocks /api/timedtext with 0 outbound requests', async () => {
    const r = createOutboundRouter();
    r.setRobots('www.youtube.com', F34_YOUTUBE.robotsTxt);
    await withFreshHub({ router: r }, async (h) => {
      const res = await h.scrape({
        url: 'https://www.youtube.com/api/timedtext?v=abc123&lang=en',
        discoverLlmsTxt: false,
      });
      assert.equal(res.status, 422);
      assert.equal(res.body.ok, false);
      assert.match(String(res.body.problem ?? ''), /robots\.txt/i);
      assert.equal(r.countRequests('www.youtube.com', '/api/timedtext'), 0);
    });
  });

  test('F34.T2.2: youtube.com /watch static fast-path extracts videoDetails and skips auto-render-1 & /api/timedtext', async () => {
    const r = createOutboundRouter();
    r.setRobots('www.youtube.com', F34_YOUTUBE.robotsTxt);
    const padWatchHtml = `${F34_YOUTUBE.watchHtml('E-Bike Motor Teardown', 'BikeTech')}<!-- ${'p'.repeat(700 * 1024)} -->`;
    await withFreshHub({ router: r }, async (h) => {
      const agent = await h.connectMockAgent({
        onDispatch: async (_msg, helpers) => {
          const req0 = helpers.call.requests?.[0] ?? {};
          await helpers.sendReply({
            results: [
              {
                id: req0.id,
                url: req0.url,
                finalUrl: req0.url,
                status: 200,
                outcome: 'ok',
                contentType: 'text/html',
                body: padWatchHtml,
                bodyEncoding: 'utf-8',
              },
            ],
          });
        },
      });
      const res = await h.scrape({ url: 'https://www.youtube.com/watch?v=good123', discoverLlmsTxt: false });
      assert.equal(res.status, 200);
      assert.equal(res.body.ok, true);
      assert.equal(res.body.rendered, false);
      assert.match(res.body.markdown, /E-Bike Motor Teardown/);
      assert.equal(agent.frames.filter((f) => f.call.requests?.[0]?.id === 'auto-render-1').length, 0);
      assert.equal(r.countRequests('www.youtube.com', '/api/timedtext'), 0);
    });
  });

  test('F34.T2.3: youtube.com /watch with malformed videoDetails JSON falls back cleanly without /api/timedtext', async () => {
    const r = createOutboundRouter();
    r.setRobots('www.youtube.com', F34_YOUTUBE.robotsTxt);
    r.html(
      'https://www.youtube.com/watch?v=brokenjson',
      '<!doctype html><html><head><title>Watch Fallback</title></head><body><main><h1>Watch Fallback</h1><p>Video overview fallback text.</p></main><script>var ytInitialPlayerResponse={"videoDetails":{bad_json;</script></body></html>',
    );
    await withFreshHub({ router: r }, async (h) => {
      const res = await h.scrape({ url: 'https://www.youtube.com/watch?v=brokenjson', discoverLlmsTxt: false });
      assert.equal(res.status, 200);
      assert.equal(res.body.ok, true);
      assert.ok(r.countRequests('www.youtube.com', '/watch') >= 1);
      assert.match(res.body.markdown, /Watch Fallback/);
      assert.equal(r.countRequests('www.youtube.com', '/api/timedtext'), 0);
    });
  });

  test('F34.T2.4: youtube.com /watch 403/429 bot-check interstitial does not bypass or call /api/timedtext', async () => {
    const r = createOutboundRouter();
    r.setRobots('www.youtube.com', F34_YOUTUBE.robotsTxt);
    r.status(
      'https://www.youtube.com/watch?v=loginwall',
      403,
      "<html><body><h1>Sign in to confirm you're not a bot</h1></body></html>",
      { 'content-type': 'text/html' },
    );
    await withFreshHub({ router: r }, async (h) => {
      const res = await h.scrape({ url: 'https://www.youtube.com/watch?v=loginwall', discoverLlmsTxt: false });
      assert.ok(res.status === 403 || res.status === 422);
      assert.equal(res.body.ok, false);
      assert.equal(res.body.status, 403);
      const watchHits = r.countRequests('www.youtube.com', '/watch');
      assert.ok(watchHits >= 1 && watchHits <= 2, `Expected 1..2 /watch hits, got ${watchHits}`);
      assert.equal(r.countRequests('www.youtube.com', '/api/timedtext'), 0);
    });
  });

  test('F34.T2.5: youtube.com >4 MiB /watch HTML on container returns edgeBudgetExceeded: true without /api/timedtext', async () => {
    const r = createOutboundRouter();
    r.setRobots('www.youtube.com', F34_YOUTUBE.robotsTxt);
    r.html(
      'https://www.youtube.com/watch?v=huge4mb',
      exactBytesHtml(MAX_WASM_INPUT_BYTES + 1, 'Huge YouTube'),
    );
    await withFreshHub({ router: r }, async (h) => {
      const res = await h.scrape({
        url: 'https://www.youtube.com/watch?v=huge4mb',
        target: 'container',
        discoverLlmsTxt: false,
      });
      assert.equal(res.status, 200);
      assert.equal(res.body.edgeBudgetExceeded, true);
      assert.equal(res.body.markdown, '');
      assert.equal(r.countRequests('www.youtube.com', '/api/timedtext'), 0);
    });
  });

  // --- F35: D1 high-ROI (5 tests) ---
  test('F35.T2.1: productinfo.shimano.com malformed __next_f RSC falls back to HTML cleanly', async () => {
    const res = await hub.scrape({ url: 'https://productinfo.shimano.com/en/product/DU-EP801-BAD', discoverLlmsTxt: false });
    assert.equal(res.status, 200);
    assert.equal(res.body.ok, true);
    assert.match(res.body.markdown, /DU-EP801/);
    assert.match(res.body.markdown, /Drive unit overview/);
  });

  test('F35.T2.2: scraping productinfo.shimano.com never probes 403-blocked si.shimano.com or bike.shimano.com', async () => {
    router.clearLog();
    const res = await hub.scrape({ url: 'https://productinfo.shimano.com/en/product/DU-EP801', discoverLlmsTxt: false });
    assert.equal(res.status, 200);
    assert.equal(res.body.ok, true);
    assert.ok(router.countRequests('productinfo.shimano.com', '/en/product/DU-EP801') >= 1);
    assert.match(res.body.markdown, /DU-EP801|85 Nm/);
    assert.equal(router.countRequests('si.shimano.com'), 0);
    assert.equal(router.countRequests('bike.shimano.com'), 0);
  });

  test('F35.T2.3: law.cornell.edu cornell-lii strips #sidebar-first donate chrome', async () => {
    const res = await hub.scrape({ url: 'https://www.law.cornell.edu/cfr/text/16/1512.18', discoverLlmsTxt: false });
    assert.equal(res.status, 200);
    assert.equal(res.body.extractorId, 'cornell-lii');
    assert.equal(res.body.markdown.includes('CORNELL_SIDEBAR_DONATE'), false);
  });

  test('F35.T2.4: www.sram.com malformed JSON-LD retains .product-detail HTML specs', async () => {
    const res = await hub.scrape({ url: 'https://www.sram.com/en/sram/models/rd-gx-e-b1', discoverLlmsTxt: false });
    assert.equal(res.status, 200);
    assert.equal(res.body.ok, true);
    assert.match(res.body.markdown, /290g/);
  });

  test('F35.T2.5: www.tq-ebike.com 404 returns 422 not_found', async () => {
    const res = await hub.scrape({ url: 'https://www.tq-ebike.com/en/help-support/hpr50-404', discoverLlmsTxt: false });
    assert.equal(res.status, 422);
    assert.equal(res.body.ok, false);
    assert.equal(res.body.outcome, 'not_found');
    assert.equal(res.body.status, 404);
  });
});

// ============================================================================
// Group G: Security, Politeness, Redirect & Budget Guards (F36 — 10 tests, R5 — MUST PASS)
// ============================================================================
describe('Tier 2 Group G — R5 Security, Politeness, Redirect & Budget Guards (F36)', () => {
  test('F36.T2.1: Content-Signal: ai-input=no in robots.txt blocks scrape with content_signal_disallowed', async () => {
    const router = createOutboundRouter();
    router.setRobots('cs-no.example.com', 'User-agent: *\nAllow: /\nContent-Signal: search=yes, ai-input=no, ai-train=no\n');
    router.html('https://cs-no.example.com/docs/guide', '<html><body>Should not fetch</body></html>');
    await withFreshHub({ router }, async (hub) => {
      const res = await hub.scrape({ url: 'https://cs-no.example.com/docs/guide', discoverLlmsTxt: false });
      assert.equal(res.status, 422);
      assert.equal(res.body.ok, false);
      assert.equal(res.body.outcome, 'content_signal_disallowed');
      assert.match(String(res.body.problem ?? ''), /ai-input=no/i);
      assert.equal(router.countRequests('cs-no.example.com', '/docs/guide'), 0);
    });
  });

  test('F36.T2.2: Crawl-delay in robots.txt spaces sequential /v1/crawl wave fetches & enforces maxSeconds budget guard', async () => {
    const router = createOutboundRouter();
    router.setRobots('cd-t2.example.com', 'User-agent: *\nCrawl-delay: 1.5\nAllow: /\n');
    router.html(
      'https://cd-t2.example.com/',
      '<!doctype html><html><head><title>Root</title></head><body><main><a href="/p1">P1</a><a href="/p2">P2</a></main></body></html>',
    );
    router.html('https://cd-t2.example.com/p1', '<html><body><main><h1>Page 1</h1></main></body></html>');
    router.html('https://cd-t2.example.com/p2', '<html><body><main><h1>Page 2</h1></main></body></html>');

    router.setRobots('cd-t2-budget.example.com', 'User-agent: *\nCrawl-delay: 25\nAllow: /\n');
    router.html('https://cd-t2-budget.example.com/a', '<html><body>A</body></html>');
    router.html('https://cd-t2-budget.example.com/b', '<html><body>B</body></html>');

    await withFreshHub({ router }, async (hub) => {
      const crawlRes = await hub.crawl({
        url: 'https://cd-t2.example.com/',
        sync: true,
        maxDepth: 1,
        limit: 4,
        sitemap: 'skip',
        delay: 0.1,
      });
      assert.equal(crawlRes.status, 200);
      assert.equal(crawlRes.body.ok, true);
      const p1Hit = router.requestLog.find((e) => e.host === 'cd-t2.example.com' && e.pathname === '/p1');
      const p2Hit = router.requestLog.find((e) => e.host === 'cd-t2.example.com' && e.pathname === '/p2');
      assert.ok(p1Hit && p2Hit, 'Expected both /p1 and /p2 to be fetched');
      const delta = Math.abs(p2Hit.timestamp - p1Hit.timestamp);
      assert.ok(delta >= 1400, `Expected Crawl-delay >=1400ms between /p1 and /p2, got ${delta}ms`);

      const budgetRes = await postHubJson(hub, '/fetch/batch', {
        urls: ['https://cd-t2-budget.example.com/a', 'https://cd-t2-budget.example.com/b'],
        maxSeconds: 1,
        options: { includeBody: true, respectRobots: true, pauseMs: 0 },
      });
      assert.equal(budgetRes.status, 200);
      assert.equal(budgetRes.body.results?.[0]?.outcome, 'ok');
      assert.equal(budgetRes.body.results?.[1]?.outcome, 'not_tried');
      assert.match(String(budgetRes.body.results?.[1]?.problem ?? ''), /budget exhausted/i);
    });
  });

  test('F36.T2.3: robots.txt blocks up.codes, standards.iteh.ai /api/, ecfr.gov /api/, and fails closed on 429 robots.txt', async () => {
    const router = createOutboundRouter();
    router.setRobots('up.codes', 'User-agent: *\nDisallow: /\n');
    router.setRobots('standards.iteh.ai', 'User-agent: *\nDisallow: /api/\nAllow: /\n');
    router.setRobots('www.ecfr.gov', 'User-agent: *\nDisallow: /api/\nAllow: /\n');
    router.setRobots('kalkhoff-t2.example.com', 'Too Many Requests', 429);

    const targets = [
      'https://up.codes/codes/ny',
      'https://standards.iteh.ai/api/standards/iso-4210',
      'https://www.ecfr.gov/api/versioner/v1/full/2024-01-01/title-16.xml',
      'https://kalkhoff-t2.example.com/de/bikes',
    ];
    for (const u of targets) {
      router.html(u, '<html><body>Blocked Target</body></html>');
    }

    await withFreshHub({ router }, async (hub) => {
      for (const u of targets) {
        const res = await hub.scrape({ url: u, discoverLlmsTxt: false });
        assert.equal(res.status, 422, `Expected 422 for ${u}, got ${res.status}`);
        assert.equal(res.body.ok, false);
        assert.match(String(res.body?.problem ?? ''), /robots/i);
      }
      assert.equal(router.countRequests('up.codes', '/codes'), 0);
      assert.equal(router.countRequests('standards.iteh.ai', '/api/'), 0);
      assert.equal(router.countRequests('www.ecfr.gov', '/api/'), 0);
      assert.equal(router.countRequests('kalkhoff-t2.example.com', '/de/'), 0);
    });
  });

  test('F36.T2.4: isTrustedTwinRedirectUrl rejects cross-host redirects on both exact-domain and wildcard adapters', async () => {
    const router = createOutboundRouter();
    // Exact-domain twin (`pypi`) redirecting to untrusted host
    router.redirect('https://pypi.org/pypi/requests/json', 'https://evil-pypi.example.com/requests.json', 302);
    router.json('https://evil-pypi.example.com/requests.json', {
      info: { name: 'EVIL_REDIR_PAYLOAD', summary: 'EVIL_REDIR_PAYLOAD' },
    });
    router.html(
      'https://pypi.org/project/requests/',
      '<!doctype html><html><head><title>Safe Origin HTML</title></head><body><main><h1>Safe Origin HTML</h1></main></body></html>',
    );
    // Wildcard twin (`*.zendesk.com` or `*.readthedocs.io`) redirecting cross-host
    router.redirect(
      'https://acme-t2-w.zendesk.com/api/v2/help_center/en-us/articles/777.json',
      'https://other.zendesk.com/api/v2/help_center/en-us/articles/777.json',
      302,
    );
    router.json('https://other.zendesk.com/api/v2/help_center/en-us/articles/777.json', {
      article: { id: 777, title: 'EVIL_REDIR_PAYLOAD', body: '<p>EVIL_REDIR_PAYLOAD</p>', draft: false },
    });
    router.html(
      'https://acme-t2-w.zendesk.com/hc/en-us/articles/777',
      '<!doctype html><html><head><title>Safe Origin HTML</title></head><body><main><h1>Safe Origin HTML</h1></main></body></html>',
    );

    await withFreshHub({ router }, async (hub) => {
      const r1 = await hub.scrape({ url: 'https://pypi.org/project/requests/', discoverLlmsTxt: false });
      assert.equal(r1.status, 200);
      assert.notEqual(r1.body.extractorId, 'pypi');
      assert.equal(r1.body.markdown.includes('EVIL_REDIR_PAYLOAD'), false);
      assert.match(r1.body.markdown, /Safe Origin HTML/);

      const r2 = await hub.scrape({ url: 'https://acme-t2-w.zendesk.com/hc/en-us/articles/777', discoverLlmsTxt: false });
      assert.equal(r2.status, 200);
      assert.notEqual(r2.body.extractorId, 'zendesk-hc');
      assert.equal(r2.body.markdown.includes('EVIL_REDIR_PAYLOAD'), false);
      assert.match(r2.body.markdown, /Safe Origin HTML/);
    });
  });

  test('F36.T2.5: validatePublicHttpsTargetUrl rejects SSRF schemes, IPv4/IPv6 literals, .local/.internal/.nip.io, ports & creds pre-flight', async () => {
    const router = createOutboundRouter();
    const badUrls = [
      'http://plain.example.com/',
      'https://127.0.0.1/a',
      'https://[::1]/a',
      'https://[::ffff:127.0.0.1]/a',
      'https://8.8.8.8/a',
      'https://169.254.169.254/latest/meta-data/',
      'https://svc.local/',
      'https://meta.internal/',
      'https://10.0.0.1.nip.io/',
      'https://example.com:8443/',
      'https://user:pass@example.com/',
    ];
    await withFreshHub({ router }, async (hub) => {
      for (const badUrl of badUrls) {
        const res = await hub.scrape({ url: badUrl, discoverLlmsTxt: false });
        assert.equal(res.status, 400, `Expected 400 for ${badUrl}, got ${res.status}`);
        assert.equal(res.body.ok, false);
        assert.equal(res.body.error, 'invalid_url');
      }
      assert.equal(router.requestLog.length, 0);
    });
  });

  test('F36.T2.6: redirect-hop scheme downgrade, IPv6 loopback, IMDS, and credentials are blocked', async () => {
    const router = createOutboundRouter();
    router.redirect('https://hop-t2-a.example.com/go', 'http://downgrade.example.com/x', 302);
    router.redirect('https://hop-t2-b.example.com/go', 'https://[::1]/secret', 302);
    router.redirect('https://hop-t2-c.example.com/go', 'https://169.254.169.254/latest', 302);
    router.redirect('https://hop-t2-d.example.com/go', 'https://admin:pw@redir.example.com/', 302);

    await withFreshHub({ router }, async (hub) => {
      const expected = [
        { host: 'hop-t2-a.example.com', status: 422, outcome: 'error' },
        { host: 'hop-t2-b.example.com', status: 403, outcome: 'blocked' },
        { host: 'hop-t2-c.example.com', status: 403, outcome: 'blocked' },
        { host: 'hop-t2-d.example.com', status: 403, outcome: 'blocked' },
      ];
      for (const { host, status, outcome } of expected) {
        const res = await hub.scrape({ url: `https://${host}/go`, discoverLlmsTxt: false });
        assert.ok(router.countRequests(host, '/go') >= 1, `Expected /go hit for ${host}`);
        assert.equal(res.status, status, `Expected ${status} for ${host}, got ${res.status}`);
        assert.equal(res.body.ok, false);
        assert.equal(res.body.outcome, outcome, `Expected outcome ${outcome} for ${host}, got ${res.body.outcome}`);
      }
      assert.equal(router.countRequests('downgrade.example.com'), 0);
      assert.equal(router.countRequests('[::1]'), 0);
      assert.equal(router.countRequests('169.254.169.254'), 0);
      assert.equal(router.countRequests('redir.example.com'), 0);
    });
  });

  test('F36.T2.7: MAX_WASM_INPUT_BYTES exact boundary 4,194,304 succeeds vs 4,194,305 triggers edgeBudgetExceeded', async () => {
    const router = createOutboundRouter();
    router.html('https://exact-4m.example.com/doc.html', exactBytesHtml(MAX_WASM_INPUT_BYTES, 'Boundary Marker'));
    router.html('https://over-4m.example.com/doc.html', exactBytesHtml(MAX_WASM_INPUT_BYTES + 1, 'Boundary Marker'));
    await withFreshHub({ router }, async (hub) => {
      const okRes = await hScrape(hub, 'https://exact-4m.example.com/doc.html');
      assert.equal(okRes.status, 200);
      assert.equal(okRes.body.edgeBudgetExceeded, undefined);
      assert.match(okRes.body.markdown, /Boundary Marker/);

      const overRes = await hScrape(hub, 'https://over-4m.example.com/doc.html');
      assert.equal(overRes.status, 200);
      assert.equal(overRes.body.edgeBudgetExceeded, true);
      assert.equal(overRes.body.markdown, '');
      assert.ok((overRes.body.warnings ?? []).some((w) => w.includes('4 MiB WASM input budget')));
    });

    async function hScrape(hub, url) {
      return hub.scrape({ url, target: 'container', discoverLlmsTxt: false });
    }
  });

  test('F36.T2.8: saferproducts.gov unfiltered / malformed / duplicate RecallNumber queries are blocked pre-fetch', async () => {
    const router = createOutboundRouter();
    router.json(
      (u) => u.hostname === 'www.saferproducts.gov',
      [{ RecallID: 1, RecallNumber: '00001', Title: 'EVIL_DUMP' }],
    );
    const badQueries = [
      'https://www.saferproducts.gov/RestWebServices/Recall',
      'https://www.saferproducts.gov/RestWebServices/Recall?format=json&RecallNumber=1',
      'https://www.saferproducts.gov/RestWebServices/Recall?format=json&RecallNumber=24123&RecallNumber=24124',
      'https://www.saferproducts.gov/RestWebServices/Recall?format=json&RecallNumber=24123/../all',
    ];
    await withFreshHub({ router }, async (hub) => {
      for (const u of badQueries) {
        const res = await hub.scrape({ url: u, discoverLlmsTxt: false });
        assert.equal(res.status, 422, `Expected 422 for ${u}, got ${res.status}`);
        assert.equal(res.body.ok, false);
        assert.equal(res.body.error, 'unbounded_endpoint_blocked');
      }
      assert.equal(router.countRequests('www.saferproducts.gov'), 0);
    });
  });

  test('F36.T2.9: respectRobots: false rejected (400 robots_required), 403 WAF & 402 paywall never bypassed', async () => {
    const router = createOutboundRouter();
    router.setRobots('strict-robots.example.com', 'User-agent: *\nDisallow: /\n');
    router.html('https://strict-robots.example.com/secret', '<html><body>Secret</body></html>');
    router.status('https://si.shimano.com/en/pdfs/dm/123', 403, 'Just a moment...', {
      'cf-mitigated': 'challenge',
      server: 'cloudflare',
    });
    router.status('https://paywall.example.com/doc', 402, 'Payment Required', {
      'payment-required': 'true',
    });
    await withFreshHub({ router }, async (hub) => {
      const robRes = await postHubJson(hub, '/fetch', {
        requests: [{ id: 'r1', url: 'https://strict-robots.example.com/secret' }],
        options: { respectRobots: false },
      });
      assert.equal(robRes.status, 400);
      assert.equal(robRes.body.error, 'robots_required');
      assert.equal(router.countRequests('strict-robots.example.com'), 0);

      const wafRes = await hub.scrape({ url: 'https://si.shimano.com/en/pdfs/dm/123', discoverLlmsTxt: false });
      assert.equal(wafRes.status, 403);
      assert.equal(wafRes.body.ok, false);
      assert.equal(wafRes.body.outcome, 'challenge');

      const payRes = await hub.scrape({ url: 'https://paywall.example.com/doc', discoverLlmsTxt: false });
      assert.equal(payRes.status, 402);
      assert.equal(payRes.body.ok, false);
      assert.equal(payRes.body.outcome, 'payment_required');
    });
  });

  test('F36.T2.10: POST /v1/batch/scrape enforces robots.txt disallows across 5 adapter hosts with 0 disallowed fetches', async () => {
    const router = createOutboundRouter();
    router.setRobots('openlibrary.org', F24_WIKIDATA_OPENLIBRARY.openLibraryRobotsTxt);
    router.setRobots('help.bosch-ebike.com', 'User-agent: *\nDisallow: /api/*\nAllow: /\n');
    router.setRobots('app.dover.com', F22_UKG_PAYLOCITY_DOVER.doverRobotsTxt);
    router.setRobots('recruiting.ultipro.com', F22_UKG_PAYLOCITY_DOVER.ukgRobotsTxt);
    router.setRobots('www.youtube.com', F34_YOUTUBE.robotsTxt);

    const disallowedUrls = [
      'https://openlibrary.org/api/books?bibkeys=ISBN:9780140328721',
      'https://help.bosch-ebike.com/api/v1/articles',
      'https://app.dover.com/api/v1/job-board/jobs/acme',
      'https://recruiting.ultipro.com/ACME/JobBoardView/123',
      'https://www.youtube.com/api/timedtext?v=abc123&lang=en',
    ];
    await withFreshHub({ router }, async (hub) => {
      const batchRes = await postHubJson(hub, '/v1/batch/scrape', {
        urls: disallowedUrls,
        sync: true,
        maxConcurrency: 1,
        discoverLlmsTxt: false,
      });
      assert.equal(batchRes.status, 200);
      assert.equal(batchRes.body.ok, true);
      assert.equal(batchRes.body.total, 5);
      assert.equal(batchRes.body.completed, 0);
      assert.equal(batchRes.body.failed, 5);
      assert.equal(batchRes.body.errors?.length, 5);
      for (const err of batchRes.body.errors) {
        assert.match(String(err.error ?? ''), /robots\.txt/i);
      }
      assert.equal(router.countRequests('openlibrary.org', '/api/'), 0);
      assert.equal(router.countRequests('help.bosch-ebike.com', '/api/'), 0);
      assert.equal(router.countRequests('app.dover.com', '/api/'), 0);
      assert.equal(router.countRequests('recruiting.ultipro.com', '/ACME/JobBoardView'), 0);
      assert.equal(router.countRequests('www.youtube.com', '/api/timedtext'), 0);
    });
  });
});

// Keep createHash / hasSkuInRecords referenced so no unused-import lint issues arise
void createHash;
void hasSkuInRecords;
