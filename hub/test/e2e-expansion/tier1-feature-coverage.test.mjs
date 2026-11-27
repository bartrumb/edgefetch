import assert from 'node:assert/strict';
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

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const over4Mib = (unit) => unit.repeat(Math.ceil((MAX_WASM_INPUT_BYTES + 64 * 1024) / unit.length));

// ============================================================================
// Group A: Tier 1 Public Records, Docs & Forum Adapters (F01, F04–F08)
// ============================================================================
describe('Tier 1 — Public Records, Docs & Forum Adapters (F01, F04–F08)', () => {
  let router;
  let hub;

  before(async () => {
    router = createOutboundRouter();

    // F01 Zendesk Help Center (distinct subdomains avoid 2s DO host-window delay)
    router.json('https://acme1.zendesk.com/api/v2/help_center/en-us/articles/4408886858138.json', F01_ZENDESK.articleJson);
    router.json('https://acme2.zendesk.com/api/v2/help_center/en-us/articles/4408886858138.json', F01_ZENDESK.articleJson);
    router.json('https://acme2.zendesk.com/api/v2/help_center/en-us/articles/4408886858138/attachments.json', F01_ZENDESK.attachmentsJson);
    router.json('https://acme3.zendesk.com/api/v2/help_center/en-us/sections/360001234567/articles.json', F01_ZENDESK.sectionArticlesJson);
    router.json('https://acme3.zendesk.com/api/v2/help_center/en-us/sections/360001234567/articles.json?per_page=50', F01_ZENDESK.sectionArticlesJson);
    router.json('https://acme4.zendesk.com/api/v2/help_center/en-us/categories/200123456/sections.json', F01_ZENDESK.categorySectionsJson);
    router.json('https://acme4.zendesk.com/api/v2/help_center/en-us/categories/200123456/sections.json?per_page=50', F01_ZENDESK.categorySectionsJson);
    router.json('https://acme5.zendesk.com/api/v2/help_center/fr-fr/articles/4408886858139.json', F01_ZENDESK.frArticleJson);

    // F04 Federal Register
    router.json('https://www.federalregister.gov/api/v1/documents/2024-00001.json', F04_FEDERAL_REGISTER.doc2024_00001);

    // F05 CPSC & SaferProducts
    router.json(
      (u) => u.hostname === 'www.saferproducts.gov' && u.pathname === '/RestWebServices/Recall' && u.searchParams.get('RecallNumber') === '24123',
      F05_CPSC_RECALLS.saferProductsRecall24123,
    );
    router.json(
      (u) => u.hostname === 'www.saferproducts.gov' && u.pathname === '/RestWebServices/Recall' && u.searchParams.get('RecallNumber') === '24456',
      F05_CPSC_RECALLS.saferProductsRecall24123.map((r) => ({ ...r, RecallNumber: '24456' })),
    );
    router.html('https://www.cpsc.gov/Recalls/2024/VoltPeak-Recalls-E-Bike-Lithium-Ion-Batteries', F05_CPSC_RECALLS.cpscHtmlRecall);

    // F06 US CFR GovInfo
    router.html('https://www.govinfo.gov/content/pkg/CFR-2023-title16-vol2/html/CFR-2023-title16-vol2.htm', F06_GOVINFO.cfrHtm);
    router.html('https://www.govinfo.gov/content/pkg/CFR-2023-title16-vol2/html/CFR-2023-title16-vol2-part1512.htm', F06_GOVINFO.cfrHtm);
    router.html('https://www.govinfo.gov/app/details/CFR-2023-title16-vol2', F06_GOVINFO.angularSpaShell);
    router.html('https://www.govinfo.gov/app/details/CFR-2023-title16-vol2/CFR-2023-title16-vol2-part1512', F06_GOVINFO.angularSpaShell);
    router.status('https://www.govinfo.gov/content/pkg/CFR-2024-title49-vol9/html/CFR-2024-title49-vol9.htm', 404, 'Not found');
    router.json(
      (u) => u.hostname === 'www.govinfo.gov' && u.pathname === '/wssearch/getContentDetail',
      F06_GOVINFO.wssearchContentDetail,
    );
    router.html('https://www.govinfo.gov/app/details/CFR-2024-title49-vol9', F06_GOVINFO.angularSpaShell);

    // F07 EUR-Lex
    router.setRobots('eur-lex.europa.eu', 'User-agent: *\nDisallow: /legal-content/*/TXT/DOC/\nAllow: /\n');
    router.html(
      (u) => u.hostname === 'eur-lex.europa.eu' && u.pathname === '/legal-content/EN/TXT/HTML/' && u.searchParams.get('uri') === 'CELEX:32023R1542',
      F07_EURLEX.enBatteryRegulationHtml,
    );
    router.html(
      (u) => u.hostname === 'eur-lex.europa.eu' && u.pathname === '/legal-content/DE/TXT/HTML/' && u.searchParams.get('uri') === 'CELEX:32006L0042',
      F07_EURLEX.deMachineryHtml,
    );
    router.html(
      (u) => u.hostname === 'eur-lex.europa.eu' && u.pathname === '/legal-content/EN/TXT/HTML/' && u.searchParams.get('uri') === 'OJ:L_202302854',
      F07_EURLEX.enBatteryRegulationHtml,
    );
    router.html(
      (u) => u.hostname === 'eur-lex.europa.eu' && u.pathname.endsWith('/TXT/'),
      F07_EURLEX.jsShellHtml,
    );

    // F08 XenForo 2
    router.setRobots('endless-sphere.com', 'User-agent: *\nDisallow: /forums/\nDisallow: /sphere/search/\nAllow: /sphere/threads/\n');
    router.html('https://forums.electricbikereview.com/threads/bosch-cx-gen4-torque-specs.54321/', F08_XENFORO.threadHtml());
    router.html('https://endless-sphere.com/sphere/threads/72v-controller-tuning.12345/', F08_XENFORO.threadHtml('72V Controller Tuning Guide'));
    router.html('https://www.mtbr.com/threads/suspension-fork-service.98765/', F08_XENFORO.threadHtml('Suspension Fork Service Intervals'));

    hub = await createHubInstance({ router });
  });

  after(async () => {
    await hub?.dispose();
  });

  // --- F01: zendesk-hc (5 tests) ---
  test('F01.1: zendesk-hc article URL resolves to Help Center JSON twin with clean Markdown & updated_at', async () => {
    const res = await hub.scrape({ url: 'https://acme1.zendesk.com/hc/en-us/articles/4408886858138-getting-started', discoverLlmsTxt: false });
    assert.equal(res.status, 200);
    assert.equal(res.body.ok, true);
    assert.equal(res.body.extractorId, 'zendesk-hc');
    assert.match(res.body.markdown, /Getting Started with Acme Fleet Telemetry/);
    assert.match(res.body.markdown, /firmware.*v4\.2/i);
    assert.equal(res.body.markdown.includes('<strong>'), false);
    assert.ok(router.countRequests('acme1.zendesk.com', '/api/v2/help_center/en-us/articles/4408886858138.json') >= 1);
  });

  test('F01.2: zendesk-hc article surfaces PDF manual attachment links', async () => {
    const res = await hub.scrape({
      url: 'https://acme2.zendesk.com/hc/en-us/articles/4408886858138-getting-started',
      formats: ['markdown', 'links'],
      discoverLlmsTxt: false,
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.extractorId, 'zendesk-hc');
    const links = res.body.links ?? [];
    assert.ok(
      links.some((l) => l.includes('Fleet_Manual_v4.pdf')) || res.body.markdown.includes('Fleet_Manual_v4.pdf'),
      'Expected Fleet_Manual_v4.pdf link in response',
    );
  });

  test('F01.3: zendesk-hc section URL resolves to section articles list & records[]', async () => {
    const res = await hub.scrape({ url: 'https://acme3.zendesk.com/hc/en-us/sections/360001234567-manuals', discoverLlmsTxt: false });
    assert.equal(res.status, 200);
    assert.equal(res.body.extractorId, 'zendesk-hc');
    assert.match(res.body.markdown, /Diagnostic Error Codes Reference/);
    assert.ok(Array.isArray(res.body.records) && res.body.records.length >= 2);
  });

  test('F01.4: zendesk-hc category URL resolves to category sections list & records[]', async () => {
    const res = await hub.scrape({ url: 'https://acme4.zendesk.com/hc/en-us/categories/200123456-support', discoverLlmsTxt: false });
    assert.equal(res.status, 200);
    assert.equal(res.body.extractorId, 'zendesk-hc');
    assert.match(res.body.markdown, /Hardware Manuals/);
    assert.match(res.body.markdown, /Troubleshooting & Faults/);
    assert.ok(Array.isArray(res.body.records) && res.body.records.length >= 2);
  });

  test('F01.5: zendesk-hc preserves non-US locale (fr-fr) in twin request & labels', async () => {
    const res = await hub.scrape({ url: 'https://acme5.zendesk.com/hc/fr-fr/articles/4408886858139-demarrage', discoverLlmsTxt: false });
    assert.equal(res.status, 200);
    assert.equal(res.body.extractorId, 'zendesk-hc');
    assert.match(res.body.markdown, /Guide de demarrage rapide/);
    assert.ok(router.countRequests('acme5.zendesk.com', '/api/v2/help_center/fr-fr/articles/4408886858139.json') >= 1);
  });

  // --- F04: federal-register (5 tests) ---
  test('F04.1: federal-register dated document URL resolves to /api/v1/documents/<doc>.json', async () => {
    const res = await hub.scrape({
      url: 'https://www.federalregister.gov/documents/2024/01/02/2024-00001/safety-standard-for-lithium-ion-ebike-batteries',
      discoverLlmsTxt: false,
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.extractorId, 'federal-register');
    assert.match(res.body.markdown, /Safety Standard for Lithium-Ion E-Bike Batteries/);
    assert.match(res.body.markdown, /89 FR 1042/);
    assert.ok(router.countRequests('www.federalregister.gov', '/api/v1/documents/2024-00001.json') >= 1);
  });

  test('F04.2: federal-register extracts CFR references & agency names', async () => {
    const res = await hub.scrape({
      url: 'https://www.federalregister.gov/documents/2024/01/02/2024-00001/safety-standard',
      discoverLlmsTxt: false,
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.extractorId, 'federal-register');
    assert.match(res.body.markdown, /Consumer Product Safety Commission/i);
    assert.match(res.body.markdown, /16.*1512/);
  });

  test('F04.3: federal-register preserves PDF & docket references', async () => {
    const res = await hub.scrape({
      url: 'https://www.federalregister.gov/documents/2024/01/02/2024-00001/safety-standard',
      formats: ['markdown', 'links'],
      discoverLlmsTxt: false,
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.extractorId, 'federal-register');
    assert.match(res.body.markdown, /CPSC-2023-0042/);
    assert.ok((res.body.links ?? []).some((l) => l.includes('2024-00001.pdf')) || res.body.markdown.includes('2024-00001.pdf'));
  });

  test('F04.4: federal-register includes publication_date, effective_on, and rule type', async () => {
    const res = await hub.scrape({
      url: 'https://www.federalregister.gov/documents/2024/01/02/2024-00001/safety-standard',
      discoverLlmsTxt: false,
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.extractorId, 'federal-register');
    assert.match(res.body.markdown, /2024-01-02/);
    assert.match(res.body.markdown, /2024-03-04/);
    assert.match(res.body.markdown, /Rule/);
  });

  test('F04.5: federal-register supports json format extraction for document_number & citation', async () => {
    const res = await hub.scrape({
      url: 'https://www.federalregister.gov/documents/2024/01/02/2024-00001/safety-standard',
      formats: ['markdown', { type: 'json', schema: { type: 'object', properties: { document_number: { type: 'string' }, citation: { type: 'string' } } } }],
      discoverLlmsTxt: false,
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.extractorId, 'federal-register');
    assert.equal(res.body.json?.document_number, '2024-00001');
    assert.equal(res.body.json?.citation, '89 FR 1042');
  });

  // --- F05: cpsc-recalls (5 tests) ---
  test('F05.1: saferproducts.gov bounded RecallNumber JSON returns formatted recall Markdown & records[]', async () => {
    const res = await hub.scrape({
      url: 'https://www.saferproducts.gov/RestWebServices/Recall?format=json&RecallNumber=24123',
      discoverLlmsTxt: false,
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.extractorId, 'cpsc-recalls');
    assert.match(res.body.markdown, /VoltPeak Recalls E-Bike Lithium-Ion Batteries/);
    assert.match(res.body.markdown, /overheat and ignite/);
    assert.ok(Array.isArray(res.body.records) && res.body.records.length >= 1);
  });

  test('F05.2: saferproducts.gov URL with RecallNumber normalizes format=json without unfiltered dump', async () => {
    const res = await hub.scrape({
      url: 'https://www.saferproducts.gov/RestWebServices/Recall?RecallNumber=24456',
      discoverLlmsTxt: false,
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.extractorId, 'cpsc-recalls');
    assert.match(res.body.markdown, /24456/);
  });

  test('F05.3: cpsc.gov/Recalls HTML extracts structured recall hazard, remedy, units, and recall number', async () => {
    const res = await hub.scrape({
      url: 'https://www.cpsc.gov/Recalls/2024/VoltPeak-Recalls-E-Bike-Lithium-Ion-Batteries',
      discoverLlmsTxt: false,
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.extractorId, 'cpsc-recalls');
    assert.match(res.body.markdown, /24-123|24123/);
    assert.match(res.body.markdown, /overheat and ignite/);
    assert.match(res.body.markdown, /UL-2271 certified replacement|replacement battery pack/i);
    assert.match(res.body.markdown, /12,400/);
  });

  test('F05.4: cpsc-recalls renders product units, manufacturer, and consumer contact', async () => {
    const res = await hub.scrape({
      url: 'https://www.saferproducts.gov/RestWebServices/Recall?format=json&RecallNumber=24123',
      discoverLlmsTxt: false,
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.extractorId, 'cpsc-recalls');
    assert.match(res.body.markdown, /VoltPeak Mobility Inc\./);
    assert.match(res.body.markdown, /12,400/);
    assert.match(res.body.markdown, /800-555-0199/);
  });

  test('F05.5: cpsc-recalls preserves CPSC recall URL in links format', async () => {
    const res = await hub.scrape({
      url: 'https://www.saferproducts.gov/RestWebServices/Recall?format=json&RecallNumber=24123',
      formats: ['markdown', 'links'],
      discoverLlmsTxt: false,
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.extractorId, 'cpsc-recalls');
    assert.ok((res.body.links ?? []).some((l) => l.includes('cpsc.gov/Recalls/2024/VoltPeak')));
  });

  // --- F06: us-cfr-govinfo (5 tests) ---
  test('F06.1: govinfo /app/details/<PKGID> bypasses Angular SPA via static .htm twin', async () => {
    const res = await hub.scrape({
      url: 'https://www.govinfo.gov/app/details/CFR-2023-title16-vol2',
      discoverLlmsTxt: false,
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.extractorId, 'us-cfr-govinfo');
    assert.match(res.body.markdown, /PART 1512 - REQUIREMENTS FOR BICYCLES/);
    assert.match(res.body.markdown, /15 feet from 15 mph/);
    assert.ok(router.countRequests('www.govinfo.gov', '/content/pkg/CFR-2023-title16-vol2/html/CFR-2023-title16-vol2.htm') >= 1);
  });

  test('F06.2: govinfo granule /app/details/<PKGID>/<GRANULE> resolves granule .htm twin', async () => {
    const res = await hub.scrape({
      url: 'https://www.govinfo.gov/app/details/CFR-2023-title16-vol2/CFR-2023-title16-vol2-part1512',
      discoverLlmsTxt: false,
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.extractorId, 'us-cfr-govinfo');
    assert.match(res.body.markdown, /§ 1512\.1 Scope/);
  });

  test('F06.3: govinfo falls back to wssearch/getContentDetail summary when .htm is unavailable', async () => {
    const res = await hub.scrape({
      url: 'https://www.govinfo.gov/app/details/CFR-2024-title49-vol9',
      discoverLlmsTxt: false,
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.extractorId, 'us-cfr-govinfo');
    assert.match(res.body.markdown, /Code of Federal Regulations|Consumer Product Safety Commission/i);
  });

  test('F06.4: govinfo summary includes download links (PDF/XML)', async () => {
    const res = await hub.scrape({
      url: 'https://www.govinfo.gov/app/details/CFR-2024-title49-vol9',
      formats: ['markdown', 'links'],
      discoverLlmsTxt: false,
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.extractorId, 'us-cfr-govinfo');
    assert.ok(
      res.body.markdown.includes('.pdf') || (res.body.links ?? []).some((l) => l.includes('.pdf')),
      'Expected PDF download link from wssearch summary',
    );
  });

  test('F06.5: govinfo output excludes Angular <app-root> shell', async () => {
    const res = await hub.scrape({
      url: 'https://www.govinfo.gov/app/details/CFR-2023-title16-vol2',
      discoverLlmsTxt: false,
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.extractorId, 'us-cfr-govinfo');
    assert.equal(res.body.markdown.includes('app-root'), false);
  });

  // --- F07: eur-lex (5 tests) ---
  test('F07.1: eur-lex EN /TXT/?uri=CELEX:... upgrades to /TXT/HTML/ static twin', async () => {
    const res = await hub.scrape({
      url: 'https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32023R1542',
      discoverLlmsTxt: false,
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.extractorId, 'eur-lex');
    assert.match(res.body.markdown, /REGULATION \(EU\) 2023\/1542/);
    assert.match(res.body.markdown, /light means of transport/i);
    assert.ok(router.countRequests('eur-lex.europa.eu', '/legal-content/EN/TXT/HTML/') >= 1);
  });

  test('F07.2: eur-lex preserves non-English language segment (DE)', async () => {
    const res = await hub.scrape({
      url: 'https://eur-lex.europa.eu/legal-content/DE/TXT/?uri=CELEX:32006L0042',
      discoverLlmsTxt: false,
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.extractorId, 'eur-lex');
    assert.match(res.body.markdown, /RICHTLINIE 2006\/42\/EG/);
    assert.ok(router.countRequests('eur-lex.europa.eu', '/legal-content/DE/TXT/HTML/') >= 1);
  });

  test('F07.3: eur-lex supports OJ: URI scheme', async () => {
    const res = await hub.scrape({
      url: 'https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=OJ:L_202302854',
      discoverLlmsTxt: false,
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.extractorId, 'eur-lex');
    assert.match(res.body.markdown, /Article 1/);
  });

  test('F07.4: eur-lex never fetches disallowed /TXT/DOC/ path', async () => {
    router.clearLog();
    const res = await hub.scrape({
      url: 'https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32023R1542',
      discoverLlmsTxt: false,
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.ok, true);
    assert.equal(res.body.extractorId, 'eur-lex');
    assert.ok(router.countRequests('eur-lex.europa.eu', '/legal-content/EN/TXT/HTML/') >= 1);
    assert.equal(router.countRequests('eur-lex.europa.eu', '/legal-content/EN/TXT/DOC/'), 0);
  });

  test('F07.5: eur-lex preserves legislation tables in Markdown', async () => {
    const res = await hub.scrape({
      url: 'https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32023R1542',
      discoverLlmsTxt: false,
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.extractorId, 'eur-lex');
    assert.match(res.body.markdown, /LMT Battery/);
    assert.match(res.body.markdown, /Carbon Footprint Threshold/);
  });

  // --- F08: xenforo-thread (5 tests) ---
  test('F08.1: xenforo-thread extracts posts, authors, and timestamps on electricbikereview.com', async () => {
    const res = await hub.scrape({
      url: 'https://forums.electricbikereview.com/threads/bosch-cx-gen4-torque-specs.54321/',
      discoverLlmsTxt: false,
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.extractorId, 'xenforo-thread');
    assert.match(res.body.markdown, /wrench_pro/);
    assert.match(res.body.markdown, /22 Nm/);
    assert.match(res.body.markdown, /ebike_tech/);
  });

  test('F08.2: xenforo-thread strips .message-signature and .p-body-sidebar chrome on endless-sphere', async () => {
    const res = await hub.scrape({
      url: 'https://endless-sphere.com/sphere/threads/72v-controller-tuning.12345/',
      discoverLlmsTxt: false,
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.extractorId, 'xenforo-thread');
    assert.equal(res.body.markdown.includes('Signature Promo Spam'), false);
    assert.equal(res.body.markdown.includes('Latest Threads Sidebar Noise'), false);
  });

  test('F08.3: xenforo-thread preserves bbCodeBlock quotes cleanly', async () => {
    const res = await hub.scrape({
      url: 'https://forums.electricbikereview.com/threads/bosch-cx-gen4-torque-specs.54321/',
      discoverLlmsTxt: false,
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.extractorId, 'xenforo-thread');
    assert.match(res.body.markdown, /wrench_pro said|>.*22 Nm/);
  });

  test('F08.4: xenforo-thread populates structured records[] for mtbr.com posts', async () => {
    const res = await hub.scrape({
      url: 'https://www.mtbr.com/threads/suspension-fork-service.98765/',
      discoverLlmsTxt: false,
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.extractorId, 'xenforo-thread');
    assert.ok(Array.isArray(res.body.records) && res.body.records.length >= 2);
    assert.equal(res.body.records[0]?.author, 'wrench_pro');
  });

  test('F08.5: xenforo-thread preserves inline technical code specs inside .bbWrapper', async () => {
    const res = await hub.scrape({
      url: 'https://forums.electricbikereview.com/threads/bosch-cx-gen4-torque-specs.54321/',
      discoverLlmsTxt: false,
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.extractorId, 'xenforo-thread');
    assert.match(res.body.markdown, /25 Nm/);
  });
});

// ============================================================================
// Group B: Tier 1 & Tier 2 Commerce, Docs & M1 Product Core (F02, F03, F09–F14)
// ============================================================================
describe('Tier 1 & Tier 2 — Commerce, Tech Docs & M1 Product Core (F02, F03, F09–F14)', () => {
  let router;
  let hub;

  before(async () => {
    router = createOutboundRouter();

    // F02 Shopify collections
    for (const h of ['voltride1.myshopify.com', 'voltride2.myshopify.com', 'voltride3.myshopify.com', 'voltride4.myshopify.com']) {
      router.html(`https://${h}/collections/ebikes`, F02_SHOPIFY.collectionHtml(h));
      router.json(`https://${h}/collections/ebikes/products.json?limit=50`, F02_SHOPIFY.collectionProductsJson);
      router.json(`https://${h}/collections/ebikes/products.json`, F02_SHOPIFY.collectionProductsJson);
    }
    router.html('https://www.voltridebikes.com/collections/commuter-bikes', F02_SHOPIFY.collectionHtml('voltride1.myshopify.com'));
    router.json('https://www.voltridebikes.com/collections/commuter-bikes/products.json?limit=50', F02_SHOPIFY.collectionProductsJson);
    router.json('https://www.voltridebikes.com/collections/commuter-bikes/products.json', F02_SHOPIFY.collectionProductsJson);

    // F03 WooCommerce
    for (const h of ['rideshop1.example.com', 'rideshop2.example.com', 'rideshop3.example.com', 'rideshop4.example.com']) {
      router.html(`https://${h}/product-category/electric-bikes/`, F03_WOOCOMMERCE.categoryHtml('Electric Bikes'));
      router.html(`https://${h}/shop/`, F03_WOOCOMMERCE.categoryHtml('Shop'));
      router.json(`https://${h}/wp-json/wc/store/v1/products?category=electric-bikes&per_page=50`, F03_WOOCOMMERCE.storeProductsUsd);
      router.json(`https://${h}/wp-json/wc/store/v1/products?per_page=50`, F03_WOOCOMMERCE.storeProductsUsd);
    }
    router.html('https://euroride.example.de/product-category/trekking/', F03_WOOCOMMERCE.categoryHtml('Trekking E-Bikes'));
    router.json('https://euroride.example.de/wp-json/wc/store/v1/products?category=trekking&per_page=50', F03_WOOCOMMERCE.storeProductsEur);

    // F09 Squarespace Commerce
    router.html('https://urbancycle1.example.com/shop', F09_SQUARESPACE.shopHtml);
    router.json('https://urbancycle1.example.com/shop?format=json-pretty', F09_SQUARESPACE.shopJsonPretty);
    router.html('https://urbancycle2.example.com/shop/p/porteur-front-rack', F09_SQUARESPACE.shopHtml);
    router.json('https://urbancycle2.example.com/shop/p/porteur-front-rack?format=json-pretty', F09_SQUARESPACE.productJsonPretty);
    router.html('https://urbancycle3.example.com/shop/p/porteur-front-rack', F09_SQUARESPACE.shopHtml);
    router.json('https://urbancycle3.example.com/shop/p/porteur-front-rack?format=json-pretty', F09_SQUARESPACE.productJsonPretty);
    router.html('https://urbancycle4.example.com/shop?category=bags', F09_SQUARESPACE.shopHtml);
    router.json('https://urbancycle4.example.com/shop?category=bags&format=json-pretty', F09_SQUARESPACE.shopJsonPretty);
    router.html('https://urbancycle-fallback.example.com/about', F09_SQUARESPACE.shopHtml);
    router.status('https://urbancycle-fallback.example.com/about?format=json-pretty', 404, 'Not found');

    // F10 BigCommerce
    for (const h of ['peakbikes1.example.com', 'peakbikes2.example.com', 'peakbikes3.example.com']) {
      router.html(`https://${h}/trailblazer-hydraulic-brake-kit/`, F10_BIGCOMMERCE.productHtml(true));
    }
    router.route('https://peakbikes4.example.com/header-only-bc/', () => ({
      status: 200,
      headers: { 'content-type': 'text/html; charset=utf-8', 'x-bc-storefront': 'stencil-1' },
      body: F10_BIGCOMMERCE.productHtml(false),
    }));
    router.xml('https://peakbikes5.example.com/xmlsitemap.php', F10_BIGCOMMERCE.xmlSitemap);

    // F11 SFCC Demandware
    router.html('https://www.trekbikes.com/us/en_US/bikes/domane-sl-6-gen-4/p/44751/', F11_SFCC.productHtml('www.trekbikes.com'));
    router.json(
      (u) => u.hostname === 'www.trekbikes.com' && u.pathname.includes('Product-Variation'),
      F11_SFCC.productVariationJson,
    );
    for (const h of ['bikes1.example.com', 'bikes2.example.com', 'bikes3.example.com', 'bikes4.example.com']) {
      router.html(`https://${h}/us/en_US/bikes/domane-sl-6-gen-4/p/44751/`, F11_SFCC.productHtml(h));
      router.json(
        (u) => u.hostname === h && u.pathname.includes('Product-Variation'),
        F11_SFCC.productVariationJson,
      );
    }

    // F12 Shopware 6 & Magento 2
    for (const h of ['parts1.example.com', 'parts2.example.com']) {
      router.html(`https://${h}/magura-mt7-pro.html`, F12_SHOPWARE_MAGENTO.magentoSwatchHtml);
      router.json(
        (u) => u.hostname === h && u.pathname.startsWith('/rest/V1/products-render-info'),
        F12_SHOPWARE_MAGENTO.magentoRestRenderInfo,
      );
    }
    for (const h of ['oem1.example.de', 'oem2.example.de', 'oem3.example.de']) {
      router.html(`https://${h}/supernova-m99-mini.html`, F12_SHOPWARE_MAGENTO.shopware6Html);
    }

    // F13 SRAM Docs & Bosch eBike Help
    router.setRobots('help.bosch-ebike.com', 'User-agent: *\nDisallow: /api/*\nAllow: /\n');
    router.html('https://docs.sram.com/en-US/publications/1zPBXB1BWfF7E1mLreIuVi/eagle-axs-manual', F13_SRAM_BOSCH_HELP.sramDocsHtml);
    router.html('https://docs.sram.com/en-US/publications/2aBC3dEF/rockshox-service?models=sid-sl', F13_SRAM_BOSCH_HELP.sramDocsHtml);
    router.html('https://help.bosch-ebike.com/en/help-center/ebike-battery-charging', F13_SRAM_BOSCH_HELP.boschHelpHtml);

    // F14 Microdata & Spec-Table Product Fallback (M1)
    router.html('https://books.toscrape.com/catalogue/a-light-in-the-attic_1000/index.html', F14_MICRODATA_SPEC.booksToScrapeHtml);
    router.html('https://www.bikeschematics.com/parts/shimano-ep801', F14_MICRODATA_SPEC.bikeschematicsHtml);
    router.html('https://www.bafang-e.com/en/oem-area/components/component/motor/mm-g510-1000', F14_MICRODATA_SPEC.bafangDlHtml);
    router.html('https://med.example.com/products/powertube-750', F14_MICRODATA_SPEC.microdataProductHtml);
    router.html('https://eurocargo.example.de/kits/cargo-frame', F14_MICRODATA_SPEC.euroSpecTableHtml);

    hub = await createHubInstance({ router });
  });

  after(async () => {
    await hub?.dispose();
  });

  // --- F02: shopify collection upgrade (5 tests) ---
  test('F02.1: *.myshopify.com/collections/<handle> upgrades to products.json & GFM table + records[]', async () => {
    const res = await hub.scrape({ url: 'https://voltride1.myshopify.com/collections/ebikes', discoverLlmsTxt: false });
    assert.equal(res.status, 200);
    assert.equal(res.body.extractorId, 'shopify');
    assert.match(res.body.markdown, /Apex Commuter 500/);
    assert.match(res.body.markdown, /VR-APX-BLK/);
    assert.ok(Array.isArray(res.body.records) && res.body.records.length >= 2);
  });

  test('F02.2: custom-domain Shopify /collections/<handle> enriches via /collections/<handle>/products.json', async () => {
    const res = await hub.scrape({ url: 'https://www.voltridebikes.com/collections/commuter-bikes', discoverLlmsTxt: false });
    assert.equal(res.status, 200);
    assert.match(res.body.markdown, /Hauler Cargo Pro/);
    assert.ok(
      Array.isArray(res.body.records) &&
        res.body.records.some((r) => r.sku === 'VR-HLR-750' || r.variants?.some((v) => v.sku === 'VR-HLR-750')),
    );
  });

  test('F02.3: shopify collection includes multi-variant SKUs & pricing', async () => {
    const res = await hub.scrape({ url: 'https://voltride2.myshopify.com/collections/ebikes', discoverLlmsTxt: false });
    assert.equal(res.status, 200);
    assert.match(res.body.markdown, /1599|1,599/);
    assert.match(res.body.markdown, /VR-APX-WHT/);
  });

  test('F02.4: shopify collection with formats: ["markdown", "product"] backfills product from records[0]', async () => {
    const res = await hub.scrape({
      url: 'https://voltride3.myshopify.com/collections/ebikes',
      formats: ['markdown', 'product'],
      discoverLlmsTxt: false,
    });
    assert.equal(res.status, 200);
    assert.ok(res.body.product, 'Expected product backfilled from Shopify collection records[0]');
    assert.equal(res.body.product.brand, 'VoltRide');
    assert.equal(res.body.product.sku, 'VR-APX-BLK');
  });

  test('F02.5: shopify collection supports jsonFilter over collection records', async () => {
    const res = await hub.scrape({
      url: 'https://voltride4.myshopify.com/collections/ebikes',
      jsonFilter: 'title~Hauler',
      discoverLlmsTxt: false,
    });
    assert.equal(res.status, 200);
    assert.match(res.body.markdown, /Hauler Cargo Pro/);
  });

  // --- F03: woocommerce category & custom-domain upgrade (5 tests) ---
  test('F03.1: custom-domain WooCommerce /product-category/<slug>/ upgrades via Store API', async () => {
    const res = await hub.scrape({
      url: 'https://rideshop1.example.com/product-category/electric-bikes/',
      discoverLlmsTxt: false,
    });
    assert.equal(res.status, 200);
    assert.match(res.body.markdown, /City Cruiser ST/);
    assert.match(res.body.markdown, /WC-CITY-ST/);
    assert.ok(Array.isArray(res.body.records) && res.body.records.length >= 2);
  });

  test('F03.2: custom-domain WooCommerce /shop/ upgrades via /wp-json/wc/store/v1/products', async () => {
    const res = await hub.scrape({ url: 'https://rideshop2.example.com/shop/', discoverLlmsTxt: false });
    assert.equal(res.status, 200);
    assert.match(res.body.markdown, /Gravel Explorer XR/);
    assert.ok(
      Array.isArray(res.body.records) &&
        res.body.records.some(
          (r) => Number(r.price ?? r.variants?.[0]?.price) === 1499 || r.variants?.some((v) => Number(v.price) === 1499),
        ),
    );
  });

  test('F03.3: woocommerce category preserves SKU and in-stock/out-of-stock status', async () => {
    const res = await hub.scrape({
      url: 'https://rideshop3.example.com/product-category/electric-bikes/',
      discoverLlmsTxt: false,
    });
    assert.equal(res.status, 200);
    assert.ok(Array.isArray(res.body.records) && res.body.records.length >= 2);
    const outItem = res.body.records.find(
      (r) => r.sku === 'WC-GRVL-XR' || r.variants?.some((v) => v.sku === 'WC-GRVL-XR'),
    );
    assert.ok(outItem, 'Expected WC-GRVL-XR record');
  });

  test('F03.4: woocommerce category handles non-USD currency (EUR) & minor-unit scaling', async () => {
    const res = await hub.scrape({
      url: 'https://euroride.example.de/product-category/trekking/',
      discoverLlmsTxt: false,
    });
    assert.equal(res.status, 200);
    assert.match(res.body.markdown, /Alpen Tourer E8/);
    assert.match(res.body.markdown, /3299\.5|3,299\.50/);
    assert.ok(
      res.body.records?.some(
        (r) => (r.currency ?? r.variants?.[0]?.currency) === 'EUR' || r.variants?.some((v) => v.currency === 'EUR'),
      ),
    );
  });

  test('F03.5: woocommerce category preserves product permalinks in links format', async () => {
    const res = await hub.scrape({
      url: 'https://rideshop4.example.com/product-category/electric-bikes/',
      formats: ['markdown', 'links'],
      discoverLlmsTxt: false,
    });
    assert.equal(res.status, 200);
    assert.ok((res.body.links ?? []).some((l) => l.includes('city-cruiser-st')));
  });

  // --- F09: squarespace-commerce (5 tests) ---
  test('F09.1: squarespace /shop upgrades via ?format=json-pretty with items[] table & records[]', async () => {
    const res = await hub.scrape({ url: 'https://urbancycle1.example.com/shop', discoverLlmsTxt: false });
    assert.equal(res.status, 200);
    assert.match(res.body.markdown, /Porteur Front Rack/);
    assert.match(res.body.markdown, /Canvas Pannier Pair/);
    assert.ok(Array.isArray(res.body.records) && res.body.records.length >= 2);
  });

  test('F09.2: squarespace product detail extracts variants[], SKUs, and salePriceMoney', async () => {
    const res = await hub.scrape({ url: 'https://urbancycle2.example.com/shop/p/porteur-front-rack', discoverLlmsTxt: false });
    assert.equal(res.status, 200);
    assert.match(res.body.markdown, /SQ-RACK-BLK/);
    assert.match(res.body.markdown, /SQ-RACK-SLV/);
    assert.ok(Array.isArray(res.body.records) && res.body.records.some((r) => JSON.stringify(r).includes('SQ-RACK-BLK')));
  });

  test('F09.3: squarespace product populates product format with SKU & price', async () => {
    const res = await hub.scrape({
      url: 'https://urbancycle3.example.com/shop/p/porteur-front-rack',
      formats: ['markdown', 'product'],
      discoverLlmsTxt: false,
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.product?.sku, 'SQ-RACK-BLK');
  });

  test('F09.4: squarespace URL with existing query string preserves params + format=json-pretty', async () => {
    const res = await hub.scrape({ url: 'https://urbancycle4.example.com/shop?category=bags', discoverLlmsTxt: false });
    assert.equal(res.status, 200);
    assert.match(res.body.markdown, /Canvas Pannier Pair/);
    assert.ok(router.countRequests('urbancycle4.example.com', '/shop?category=bags&format=json-pretty') >= 1);
  });

  test('F09.5: squarespace non-commerce page gracefully falls back to HTML when ?format=json-pretty 404s', async () => {
    const res = await hub.scrape({ url: 'https://urbancycle-fallback.example.com/about', discoverLlmsTxt: false });
    assert.equal(res.status, 200);
    assert.match(res.body.markdown, /Urban Cycle Shop/);
  });

  // --- F10: bigcommerce-store (5 tests) ---
  test('F10.1: bigcommerce Stencil BCData extracts SKU, UPC, price, and stock into records[]', async () => {
    const res = await hub.scrape({ url: 'https://peakbikes1.example.com/trailblazer-hydraulic-brake-kit/', discoverLlmsTxt: false });
    assert.equal(res.status, 200);
    assert.match(res.body.markdown, /TrailBlazer Hydraulic Brake Kit/);
    assert.ok(
      Array.isArray(res.body.records) &&
        res.body.records.some((r) => r.sku === 'BC-BRK-400' || r.variants?.some((v) => v.sku === 'BC-BRK-400')),
    );
  });

  test('F10.2: bigcommerce Stencil extracts form[data-cart-item-add] product options', async () => {
    const res = await hub.scrape({ url: 'https://peakbikes2.example.com/trailblazer-hydraulic-brake-kit/', discoverLlmsTxt: false });
    assert.equal(res.status, 200);
    assert.match(res.body.markdown, /180mm/);
    assert.match(res.body.markdown, /203mm/);
  });

  test('F10.3: bigcommerce /xmlsitemap.php parses product sitemap URLs', async () => {
    const res = await hub.scrape({ url: 'https://peakbikes5.example.com/xmlsitemap.php', discoverLlmsTxt: false });
    assert.equal(res.status, 200);
    assert.match(res.body.markdown, /trailblazer-hydraulic-brake-kit/);
    assert.match(res.body.markdown, /carbon-bar-35mm/);
  });

  test('F10.4: bigcommerce product populates product format (sku, price, availability)', async () => {
    const res = await hub.scrape({
      url: 'https://peakbikes3.example.com/trailblazer-hydraulic-brake-kit/',
      formats: ['markdown', 'product'],
      discoverLlmsTxt: false,
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.product?.sku, 'BC-BRK-400');
    assert.equal(res.body.product?.price, 249.95);
    assert.equal(res.body.product?.availability, 'InStock');
  });

  test('F10.5: bigcommerce detects x-bc-* headers even without cdn11.bigcommerce.com link', async () => {
    const res = await hub.scrape({ url: 'https://peakbikes4.example.com/header-only-bc/', discoverLlmsTxt: false });
    assert.equal(res.status, 200);
    assert.ok(
      Array.isArray(res.body.records) &&
        res.body.records.some((r) => r.sku === 'BC-BRK-400' || r.variants?.some((v) => v.sku === 'BC-BRK-400')),
    );
  });

  // --- F11: sfcc-demandware (5 tests) ---
  test('F11.1: sfcc-demandware Product-Variation twin extracts SKU, sales/list price, availability', async () => {
    const res = await hub.scrape({ url: 'https://www.trekbikes.com/us/en_US/bikes/domane-sl-6-gen-4/p/44751/', discoverLlmsTxt: false });
    assert.equal(res.status, 200);
    assert.match(res.body.markdown, /44751-54-BLK/);
    assert.match(res.body.markdown, /4699\.99|4,699\.99/);
    assert.ok(
      Array.isArray(res.body.records) &&
        res.body.records.some((r) => r.sku === '44751-54-BLK' || r.variants?.some((v) => v.sku === '44751-54-BLK')),
    );
  });

  test('F11.2: sfcc-demandware preserves HTML geometry table in Markdown', async () => {
    const res = await hub.scrape({ url: 'https://bikes1.example.com/us/en_US/bikes/domane-sl-6-gen-4/p/44751/', discoverLlmsTxt: false });
    assert.equal(res.status, 200);
    assert.match(res.body.markdown, /Reach \(mm\)/);
    assert.match(res.body.markdown, /575/);
  });

  test('F11.3: sfcc-demandware surfaces variationAttributes (size, color)', async () => {
    const res = await hub.scrape({ url: 'https://bikes2.example.com/us/en_US/bikes/domane-sl-6-gen-4/p/44751/', discoverLlmsTxt: false });
    assert.equal(res.status, 200);
    assert.match(res.body.markdown, /Hex Blue/);
    assert.match(res.body.markdown, /56cm/);
  });

  test('F11.4: sfcc-demandware populates product format (sku, price, brand, availability)', async () => {
    const res = await hub.scrape({
      url: 'https://bikes3.example.com/us/en_US/bikes/domane-sl-6-gen-4/p/44751/',
      formats: ['markdown', 'product'],
      discoverLlmsTxt: false,
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.product?.sku, '44751-54-BLK');
    assert.equal(res.body.product?.price, 4699.99);
    assert.equal(res.body.product?.availability, 'InStock');
  });

  test('F11.5: sfcc-demandware detects SFCC via DOM/static fingerprints on arbitrary domain', async () => {
    const res = await hub.scrape({ url: 'https://bikes4.example.com/us/en_US/bikes/domane-sl-6-gen-4/p/44751/', discoverLlmsTxt: false });
    assert.equal(res.status, 200);
    assert.ok(
      Array.isArray(res.body.records) &&
        res.body.records.some((r) => r.sku === '44751-54-BLK' || r.variants?.some((v) => v.sku === '44751-54-BLK')),
    );
  });

  // --- F12: shopware-magento (5 tests) ---
  test('F12.1: magento 2 extracts text/x-magento-init swatch-renderer variant SKUs & prices offline', async () => {
    const res = await hub.scrape({ url: 'https://parts1.example.com/magura-mt7-pro.html', discoverLlmsTxt: false });
    assert.equal(res.status, 200);
    assert.match(res.body.markdown, /MAG-MT7-180/);
    assert.match(res.body.markdown, /MAG-MT7-203/);
    assert.ok(
      Array.isArray(res.body.records) &&
        res.body.records.some((r) => r.sku === 'MAG-MT7-180' || r.variants?.some((v) => v.sku === 'MAG-MT7-180')),
    );
  });

  test('F12.2: magento 2 populates product format from swatch JSON', async () => {
    const res = await hub.scrape({
      url: 'https://parts2.example.com/magura-mt7-pro.html',
      formats: ['markdown', 'product'],
      discoverLlmsTxt: false,
    });
    assert.equal(res.status, 200);
    assert.ok(res.body.product?.sku === 'MAG-MT7-180' || res.body.product?.variants?.length >= 2);
  });

  test('F12.3: shopware 6 extracts sw-product-detail property table + JSON-LD Product', async () => {
    const res = await hub.scrape({
      url: 'https://oem1.example.de/supernova-m99-mini.html',
      formats: ['markdown', 'product'],
      discoverLlmsTxt: false,
    });
    assert.equal(res.status, 200);
    assert.match(res.body.markdown, /1,150 lm/);
    assert.equal(res.body.product?.sku, 'SN-M99-MINI25');
    assert.equal(res.body.product?.price, 299);
    assert.equal(res.body.product?.currency, 'EUR');
  });

  test('F12.4: shopware 6 exposes property specs in records[] or product.specs', async () => {
    const res = await hub.scrape({
      url: 'https://oem2.example.de/supernova-m99-mini.html',
      formats: ['markdown', 'product'],
      discoverLlmsTxt: false,
    });
    assert.equal(res.status, 200);
    assert.match(res.body.markdown, /12V DC/);
    assert.ok(
      Array.isArray(res.body.records) &&
        res.body.records.some((r) => r.sku === 'SN-M99-MINI25' || r.variants?.some((v) => v.sku === 'SN-M99-MINI25')),
    );
  });

  test('F12.5: shopware-magento detects platform by HTML fingerprint on arbitrary OEM domain', async () => {
    const res = await hub.scrape({ url: 'https://oem3.example.de/supernova-m99-mini.html', discoverLlmsTxt: false });
    assert.equal(res.status, 200);
    assert.ok(
      res.body.extractorId === 'shopware-magento' || res.body.detected?.platform === 'shopware',
      `Expected shopware-magento / shopware detection, got extractorId=${res.body.extractorId}, platform=${res.body.detected?.platform}`,
    );
  });

  // --- F13: sram-docs & bosch-ebike-help (5 tests) ---
  test('F13.1: docs.sram.com Fluid Topics page extracts clean Markdown & PDF manual link', async () => {
    const res = await hub.scrape({
      url: 'https://docs.sram.com/en-US/publications/1zPBXB1BWfF7E1mLreIuVi/eagle-axs-manual',
      formats: ['markdown', 'links'],
      discoverLlmsTxt: false,
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.extractorId, 'sram-docs');
    assert.match(res.body.markdown, /Eagle AXS Transmission Installation/);
    assert.match(res.body.markdown, /35 Nm/);
    assert.ok((res.body.links ?? []).some((l) => l.includes('eagle-axs.pdf')));
  });

  test('F13.2: docs.sram.com preserves ?models= query URL and extracts cleanly', async () => {
    const res = await hub.scrape({
      url: 'https://docs.sram.com/en-US/publications/2aBC3dEF/rockshox-service?models=sid-sl',
      discoverLlmsTxt: false,
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.extractorId, 'sram-docs');
    assert.match(res.body.markdown, /35 Nm/);
  });

  test('F13.3: help.bosch-ebike.com strips base64 image blobs & aria-hidden Suspense error fallback', async () => {
    const res = await hub.scrape({
      url: 'https://help.bosch-ebike.com/en/help-center/ebike-battery-charging',
      discoverLlmsTxt: false,
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.extractorId, 'bosch-ebike-help');
    assert.match(res.body.markdown, /PowerTube 750/);
    assert.equal(res.body.markdown.includes('data:image/webp;base64'), false);
    assert.equal(res.body.markdown.includes('Service temporarily unavailable'), false);
  });

  test('F13.4: help.bosch-ebike.com NEVER requests /api/* (politeness invariant)', async () => {
    router.clearLog();
    const res = await hub.scrape({
      url: 'https://help.bosch-ebike.com/en/help-center/ebike-battery-charging',
      discoverLlmsTxt: false,
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.ok, true);
    assert.equal(res.body.extractorId, 'bosch-ebike-help');
    assert.ok(router.countRequests('help.bosch-ebike.com', '/en/help-center/ebike-battery-charging') >= 1);
    assert.equal(router.countRequests('help.bosch-ebike.com', '/api'), 0);
  });

  test('F13.5: help.bosch-ebike.com recovers React streaming #S:0 content without $RC script noise', async () => {
    const res = await hub.scrape({
      url: 'https://help.bosch-ebike.com/en/help-center/ebike-battery-charging',
      discoverLlmsTxt: false,
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.extractorId, 'bosch-ebike-help');
    assert.match(res.body.markdown, /ambient temperatures between 0°C and 40°C/);
    assert.equal(res.body.markdown.includes('$RC('), false);
  });

  // --- F14: Microdata / Spec-Table Product Fallback (M1 — MUST PASS) ---
  test('F14.1: books.toscrape.com HTML spec table populates both product and json formats', async () => {
    const res = await hub.scrape({
      url: 'https://books.toscrape.com/catalogue/a-light-in-the-attic_1000/index.html',
      formats: [
        'markdown',
        'product',
        { type: 'json', schema: { type: 'object', properties: { price: { type: 'number' }, currency: { type: 'string' }, upc: { type: 'string' }, inStock: { type: 'boolean' } } } },
      ],
      discoverLlmsTxt: false,
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.product?.title, 'A Light in the Attic');
    assert.equal(res.body.product?.price, 51.77);
    assert.equal(res.body.product?.currency, 'GBP');
    assert.equal(res.body.product?.gtin, undefined, 'hex store UPC must not be reported as a GS1 gtin');
    assert.equal(res.body.product?.specs?.upc, 'a897fe39b1053632');
    assert.equal(res.body.product?.availability, 'InStock');
    assert.equal(res.body.json?.price, 51.77);
    assert.equal(res.body.json?.currency, 'GBP');
    assert.equal(res.body.json?.upc, 'a897fe39b1053632');
    assert.equal(res.body.json?.inStock, true);
  });

  test('F14.2: bikeschematics.com 2-column hardware spec table extracts sku, mpn, brand, price, and specs', async () => {
    const res = await hub.scrape({
      url: 'https://www.bikeschematics.com/parts/shimano-ep801',
      formats: ['markdown', 'product'],
      discoverLlmsTxt: false,
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.product?.sku, 'SH-EP801-01');
    assert.equal(res.body.product?.mpn, 'SH-EP801-01');
    assert.equal(res.body.product?.brand, 'Shimano');
    assert.equal(res.body.product?.price, 899);
    assert.equal(res.body.product?.availability, 'InStock');
    assert.equal(res.body.product?.specs?.voltage, '36V');
    assert.equal(res.body.product?.specs?.maxTorque, '85 Nm');
  });

  test('F14.3: bafang-e.com <dl> hardware spec list activates without price (hardwareSpecCount >= 3)', async () => {
    const res = await hub.scrape({
      url: 'https://www.bafang-e.com/en/oem-area/components/component/motor/mm-g510-1000',
      formats: ['markdown', 'product'],
      discoverLlmsTxt: false,
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.product?.sku, 'MM G510.1000');
    assert.equal(res.body.product?.mpn, 'MM G510.1000');
    assert.equal(res.body.product?.specs?.ratedVoltage, '48V');
    assert.equal(res.body.product?.specs?.ratedPower, '1000W');
    assert.equal(res.body.product?.specs?.maxTorque, '160 Nm');
  });

  test('F14.4: Schema.org Microdata Product extracts nested Brand, Offer, SKU, and relative image URL', async () => {
    const res = await hub.scrape({
      url: 'https://med.example.com/products/powertube-750',
      formats: ['markdown', 'product'],
      discoverLlmsTxt: false,
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.product?.title, 'Bosch PowerTube 750 Horizontal');
    assert.equal(res.body.product?.brand, 'Bosch');
    assert.equal(res.body.product?.sku, 'BCH-POWERTUBE-750');
    assert.equal(res.body.product?.price, 649.5);
    assert.equal(res.body.product?.currency, 'EUR');
    assert.equal(res.body.product?.availability, 'InStock');
    assert.deepEqual(res.body.product?.images, ['https://med.example.com/images/powertube-750.jpg']);
  });

  test('F14.5: European comma-decimal price in spec table parses numeric EUR price & OutOfStock', async () => {
    const res = await hub.scrape({
      url: 'https://eurocargo.example.de/kits/cargo-frame',
      formats: ['markdown', 'product'],
      discoverLlmsTxt: false,
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.product?.sku, 'EU-CARGO-1');
    assert.equal(res.body.product?.brand, 'EuroCargo');
    assert.equal(res.body.product?.price, 1299);
    assert.equal(res.body.product?.currency, 'EUR');
    assert.equal(res.body.product?.availability, 'OutOfStock');
  });
});

// ============================================================================
// Group C: Tier 3 Keyless Package & Security Registries + Wikidata/OL (F15–F20, F24)
// ============================================================================
describe('Tier 3 & Tier 4 — Keyless JSON Twins (F15–F20, F24)', () => {
  let router;
  let hub;

  before(async () => {
    router = createOutboundRouter();

    // F15 Terraform Registry
    router.json('https://registry.terraform.io/v1/providers/hashicorp/random', F15_TERRAFORM.providerJson);
    router.json('https://registry.terraform.io/v1/providers/hashicorp/aws/5.40.0', { ...F15_TERRAFORM.providerJson, id: 'hashicorp/aws/5.40.0', name: 'aws', version: '5.40.0' });
    router.json('https://registry.terraform.io/v1/modules/terraform-aws-modules/vpc/aws', F15_TERRAFORM.moduleJson);
    router.json('https://registry.terraform.io/v1/modules/terraform-aws-modules/eks/aws/20.0.0', { ...F15_TERRAFORM.moduleJson, id: 'terraform-aws-modules/eks/aws/20.0.0', name: 'eks', version: '20.0.0' });

    // F16 Docker Hub
    router.json('https://hub.docker.com/v2/repositories/library/alpine/', F16_DOCKER_HUB.alpineRepoJson);
    router.json('https://hub.docker.com/v2/repositories/library/alpine/tags?page_size=25', F16_DOCKER_HUB.tagsJson);
    router.json('https://hub.docker.com/v2/repositories/grafana/grafana/', F16_DOCKER_HUB.grafanaRepoJson);
    router.json('https://hub.docker.com/v2/repositories/grafana/grafana/tags?page_size=25', F16_DOCKER_HUB.tagsJson);
    router.json('https://hub.docker.com/v2/repositories/library/postgres/', { ...F16_DOCKER_HUB.alpineRepoJson, name: 'postgres' });
    router.json('https://hub.docker.com/v2/repositories/library/postgres/tags?page_size=25', F16_DOCKER_HUB.tagsJson);

    // F17 Maven Central
    router.json(
      (u) => u.hostname === 'search.maven.org' && u.pathname === '/solrsearch/select' && u.search.includes('guava'),
      F17_MAVEN_CENTRAL.guavaSolrJson,
    );
    // The versioned (GAV) route moved to central.sonatype.com's live Solr endpoint in v2.8.15; unversioned stays on
    // search.maven.org.
    router.json(
      (u) => u.hostname === 'central.sonatype.com' && u.pathname === '/solrsearch/select' && u.search.includes('commons-lang3'),
      F17_MAVEN_CENTRAL.commonsLangGavJson,
    );

    // F18 NuGet Gallery
    router.json('https://api.nuget.org/v3/registration5-gz-semver2/newtonsoft.json/index.json', F18_NUGET.newtonsoftIndexJson);
    router.json('https://api.nuget.org/v3/registration5-gz-semver2/serilog/index.json', F18_NUGET.unInlinedStubIndexJson);

    // F19 Homebrew Formulae
    router.json('https://formulae.brew.sh/api/formula/jq.json', F19_HOMEBREW.jqFormulaJson);
    router.json('https://formulae.brew.sh/api/formula/python@3.8.json', F19_HOMEBREW.deprecatedFormulaJson);
    router.json('https://formulae.brew.sh/api/formula/old-tool.json', F19_HOMEBREW.disabledFormulaJson);
    router.json('https://formulae.brew.sh/api/cask/iterm2.json', F19_HOMEBREW.iterm2CaskJson);

    // F20 OSV & GHSA
    router.json('https://api.osv.dev/v1/vulns/GHSA-jfh8-c2jp-5v3q', F20_OSV.ghsaVulnJson(3));
    router.json('https://api.osv.dev/v1/vulns/GHSA-bigv-1111-2222', F20_OSV.ghsaVulnJson(500));
    router.json('https://api.osv.dev/v1/vulns/PYSEC-2023-123', F20_OSV.pysecVulnJson);

    // F24 Wikidata & Open Library
    router.setRobots('openlibrary.org', F24_WIKIDATA_OPENLIBRARY.openLibraryRobotsTxt);
    router.json('https://www.wikidata.org/wiki/Special:EntityData/Q42.json', F24_WIKIDATA_OPENLIBRARY.wikidataQ42Json);
    router.json('https://www.wikidata.org/wiki/Special:EntityData/Q937.json', F24_WIKIDATA_OPENLIBRARY.wikidataQ937Json);
    router.redirect('https://openlibrary.org/isbn/9780140328721.json', 'https://openlibrary.org/books/OL7353617M.json', 302);
    router.json('https://openlibrary.org/books/OL7353617M.json', F24_WIKIDATA_OPENLIBRARY.openLibraryBookJson('9780140328721', 'Fantastic Mr. Fox'));
    router.json('https://openlibrary.org/isbn/0140328726.json', F24_WIKIDATA_OPENLIBRARY.openLibraryBookJson('9780140328721', 'Fantastic Mr. Fox'));

    hub = await createHubInstance({ router });
  });

  after(async () => {
    await hub?.dispose();
  });

  // --- F15: terraform-registry (5 tests) ---
  test('F15.1: terraform-registry provider resolves to /v1/providers/<ns>/<name>', async () => {
    const res = await hub.scrape({ url: 'https://registry.terraform.io/providers/hashicorp/random', discoverLlmsTxt: false });
    assert.equal(res.status, 200);
    assert.equal(res.body.extractorId, 'terraform-registry');
    assert.match(res.body.markdown, /hashicorp\/random/);
    assert.match(res.body.markdown, /3\.6\.2/);
  });

  test('F15.2: terraform-registry versioned provider URL resolves cleanly', async () => {
    const res = await hub.scrape({ url: 'https://registry.terraform.io/providers/hashicorp/aws/5.40.0', discoverLlmsTxt: false });
    assert.equal(res.status, 200);
    assert.equal(res.body.extractorId, 'terraform-registry');
    assert.match(res.body.markdown, /5\.40\.0/);
  });

  test('F15.3: terraform-registry module resolves root inputs/outputs & readme', async () => {
    const res = await hub.scrape({ url: 'https://registry.terraform.io/modules/terraform-aws-modules/vpc/aws', discoverLlmsTxt: false });
    assert.equal(res.status, 200);
    assert.equal(res.body.extractorId, 'terraform-registry');
    assert.match(res.body.markdown, /AWS VPC Terraform module/);
    assert.match(res.body.markdown, /cidr/);
  });

  test('F15.4: terraform-registry versioned module URL resolves cleanly', async () => {
    const res = await hub.scrape({ url: 'https://registry.terraform.io/modules/terraform-aws-modules/eks/aws/20.0.0', discoverLlmsTxt: false });
    assert.equal(res.status, 200);
    assert.equal(res.body.extractorId, 'terraform-registry');
    assert.match(res.body.markdown, /20\.0\.0/);
  });

  test('F15.5: terraform-registry preserves source repository link', async () => {
    const res = await hub.scrape({
      url: 'https://registry.terraform.io/providers/hashicorp/random',
      formats: ['markdown', 'links'],
      discoverLlmsTxt: false,
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.extractorId, 'terraform-registry');
    assert.ok((res.body.links ?? []).some((l) => l.includes('terraform-provider-random')) || res.body.markdown.includes('terraform-provider-random'));
  });

  // --- F16: docker-hub (5 tests) ---
  test('F16.1: docker-hub official _/<repo> resolves /v2/repositories/library/<repo>/', async () => {
    const res = await hub.scrape({ url: 'https://hub.docker.com/_/alpine', discoverLlmsTxt: false });
    assert.equal(res.status, 200);
    assert.equal(res.body.extractorId, 'docker-hub');
    assert.match(res.body.markdown, /Alpine Linux/);
    assert.match(res.body.markdown, /10,?842/);
  });

  test('F16.2: docker-hub namespaced r/<ns>/<repo> resolves /v2/repositories/<ns>/<repo>/', async () => {
    const res = await hub.scrape({ url: 'https://hub.docker.com/r/grafana/grafana', discoverLlmsTxt: false });
    assert.equal(res.status, 200);
    assert.equal(res.body.extractorId, 'docker-hub');
    assert.match(res.body.markdown, /Grafana/);
    assert.match(res.body.markdown, /observability/);
  });

  test('F16.3: docker-hub fetches /tags & renders tag metadata when available', async () => {
    const res = await hub.scrape({ url: 'https://hub.docker.com/_/alpine/tags', discoverLlmsTxt: false });
    assert.equal(res.status, 200);
    assert.equal(res.body.extractorId, 'docker-hub');
    assert.match(res.body.markdown, /3\.20\.3/);
  });

  test('F16.4: docker-hub official postgres tags URL resolves cleanly', async () => {
    const res = await hub.scrape({ url: 'https://hub.docker.com/_/postgres/tags', discoverLlmsTxt: false });
    assert.equal(res.status, 200);
    assert.equal(res.body.extractorId, 'docker-hub');
    assert.match(res.body.markdown, /postgres/i);
    assert.match(res.body.markdown, /3\.20\.3|latest/);
  });

  test('F16.5: docker-hub populates structured repository metadata', async () => {
    const res = await hub.scrape({ url: 'https://hub.docker.com/r/grafana/grafana', discoverLlmsTxt: false });
    assert.equal(res.status, 200);
    assert.equal(res.body.extractorId, 'docker-hub');
    assert.match(res.body.markdown, /6,?420|1,?400/);
  });

  // --- F17: maven-central (5 tests) ---
  test('F17.1: maven-central artifact resolves search.maven.org solrsearch JSON', async () => {
    const res = await hub.scrape({ url: 'https://central.sonatype.com/artifact/com.google.guava/guava', discoverLlmsTxt: false });
    assert.equal(res.status, 200);
    assert.equal(res.body.extractorId, 'maven-central');
    assert.match(res.body.markdown, /com\.google\.guava/);
    assert.match(res.body.markdown, /33\.3\.1-jre/);
  });

  test('F17.2: maven-central versioned artifact resolves GAV coordinates', async () => {
    const res = await hub.scrape({ url: 'https://central.sonatype.com/artifact/org.apache.commons/commons-lang3/3.14.0', discoverLlmsTxt: false });
    assert.equal(res.status, 200);
    assert.equal(res.body.extractorId, 'maven-central');
    assert.match(res.body.markdown, /commons-lang3/);
    assert.match(res.body.markdown, /3\.14\.0/);
  });

  test('F17.3: maven-central routes cross-domain to search.maven.org without HTML fallback', async () => {
    router.clearLog();
    const res = await hub.scrape({ url: 'https://central.sonatype.com/artifact/com.google.guava/guava', discoverLlmsTxt: false });
    assert.equal(res.status, 200);
    assert.ok(router.countRequests('search.maven.org', '/solrsearch/select') >= 1);
    assert.equal(router.countRequests('central.sonatype.com', '/artifact'), 0);
  });

  test('F17.4: maven-central surfaces packaging & classifier artifacts', async () => {
    const res = await hub.scrape({ url: 'https://central.sonatype.com/artifact/com.google.guava/guava', discoverLlmsTxt: false });
    assert.equal(res.status, 200);
    assert.equal(res.body.extractorId, 'maven-central');
    assert.match(res.body.markdown, /bundle|jar/i);
  });

  test('F17.5: maven-central supports json format extraction', async () => {
    const res = await hub.scrape({
      url: 'https://central.sonatype.com/artifact/com.google.guava/guava',
      formats: ['markdown', { type: 'json', schema: { type: 'object', properties: { latestVersion: { type: 'string' }, g: { type: 'string' }, a: { type: 'string' } } } }],
      discoverLlmsTxt: false,
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.extractorId, 'maven-central');
    assert.equal(res.body.json?.latestVersion, '33.3.1-jre');
  });

  // --- F18: nuget-gallery (5 tests) ---
  test('F18.1: nuget-gallery lowercases package ID for v3 registration5-gz-semver2 JSON', async () => {
    const res = await hub.scrape({ url: 'https://www.nuget.org/packages/Newtonsoft.Json', discoverLlmsTxt: false });
    assert.equal(res.status, 200);
    assert.equal(res.body.extractorId, 'nuget-gallery');
    assert.match(res.body.markdown, /Newtonsoft\.Json/);
    assert.match(res.body.markdown, /13\.0\.3/);
    assert.match(res.body.markdown, /MIT/);
  });

  test('F18.2: nuget-gallery versioned URL resolves cleanly', async () => {
    const res = await hub.scrape({ url: 'https://www.nuget.org/packages/Serilog/3.1.1', discoverLlmsTxt: false });
    assert.equal(res.status, 200);
    assert.equal(res.body.extractorId, 'nuget-gallery');
    assert.match(res.body.markdown, /3\.1\.1/);
  });

  test('F18.3: nuget-gallery handles un-inlined page stubs cleanly without empty output', async () => {
    const res = await hub.scrape({ url: 'https://www.nuget.org/packages/Serilog', discoverLlmsTxt: false });
    assert.equal(res.status, 200);
    assert.equal(res.body.extractorId, 'nuget-gallery');
    assert.match(res.body.markdown, /1\.0\.0|3\.1\.1/);
  });

  test('F18.4: nuget-gallery renders dependencyGroups & target frameworks', async () => {
    const res = await hub.scrape({ url: 'https://www.nuget.org/packages/Newtonsoft.Json', discoverLlmsTxt: false });
    assert.equal(res.status, 200);
    assert.equal(res.body.extractorId, 'nuget-gallery');
    assert.match(res.body.markdown, /Microsoft\.CSharp/);
    assert.match(res.body.markdown, /NETStandard2\.0/i);
  });

  test('F18.5: nuget-gallery requests lowercased registration URL on api.nuget.org', async () => {
    router.clearLog();
    await hub.scrape({ url: 'https://www.nuget.org/packages/Newtonsoft.Json', discoverLlmsTxt: false });
    assert.equal(router.countRequests('api.nuget.org', '/v3/registration5-gz-semver2/newtonsoft.json/index.json'), 1);
  });

  // --- F19: homebrew-formulae (5 tests) ---
  test('F19.1: homebrew-formulae formula URL resolves /api/formula/<id>.json', async () => {
    const res = await hub.scrape({ url: 'https://formulae.brew.sh/formula/jq', discoverLlmsTxt: false });
    assert.equal(res.status, 200);
    assert.equal(res.body.extractorId, 'homebrew-formulae');
    assert.match(res.body.markdown, /jq/);
    assert.match(res.body.markdown, /1\.7\.1/);
    assert.match(res.body.markdown, /oniguruma/);
  });

  test('F19.2: homebrew-formulae cask URL resolves /api/cask/<id>.json', async () => {
    const res = await hub.scrape({ url: 'https://formulae.brew.sh/cask/iterm2', discoverLlmsTxt: false });
    assert.equal(res.status, 200);
    assert.equal(res.body.extractorId, 'homebrew-formulae');
    assert.match(res.body.markdown, /iTerm2/);
    assert.match(res.body.markdown, /3\.5\.5/);
  });

  test('F19.3: homebrew-formulae highlights deprecated formula status', async () => {
    const res = await hub.scrape({ url: 'https://formulae.brew.sh/formula/python@3.8', discoverLlmsTxt: false });
    assert.equal(res.status, 200);
    assert.equal(res.body.extractorId, 'homebrew-formulae');
    assert.match(res.body.markdown, /deprecated/i);
  });

  test('F19.4: homebrew-formulae highlights disabled formula status', async () => {
    const res = await hub.scrape({ url: 'https://formulae.brew.sh/formula/old-tool', discoverLlmsTxt: false });
    assert.equal(res.status, 200);
    assert.equal(res.body.extractorId, 'homebrew-formulae');
    assert.match(res.body.markdown, /disabled/i);
  });

  test('F19.5: homebrew-formulae renders analytics & build_dependencies', async () => {
    const res = await hub.scrape({ url: 'https://formulae.brew.sh/formula/jq', discoverLlmsTxt: false });
    assert.equal(res.status, 200);
    assert.equal(res.body.extractorId, 'homebrew-formulae');
    assert.match(res.body.markdown, /MIT/);
    assert.match(res.body.markdown, /autoconf|185,?420/);
  });

  // --- F20: osv-ghsa (5 tests) ---
  test('F20.1: osv.dev/vulnerability/<id> resolves api.osv.dev/v1/vulns/<id>', async () => {
    const res = await hub.scrape({ url: 'https://osv.dev/vulnerability/GHSA-jfh8-c2jp-5v3q', discoverLlmsTxt: false });
    assert.equal(res.status, 200);
    assert.equal(res.body.extractorId, 'osv-ghsa');
    assert.match(res.body.markdown, /Log4Shell/);
    assert.match(res.body.markdown, /CVE-2021-44228/);
  });

  test('F20.2: github.com/advisories/GHSA-* cross-domain twin resolves api.osv.dev/v1/vulns/<id>', async () => {
    const res = await hub.scrape({ url: 'https://github.com/advisories/GHSA-jfh8-c2jp-5v3q', discoverLlmsTxt: false });
    assert.equal(res.status, 200);
    assert.equal(res.body.extractorId, 'osv-ghsa');
    assert.match(res.body.markdown, /org\.apache\.logging\.log4j:log4j-core/);
    assert.match(res.body.markdown, /2\.15\.0/);
  });

  test('F20.3: osv.dev supports non-GHSA ecosystem IDs (PYSEC)', async () => {
    const res = await hub.scrape({ url: 'https://osv.dev/vulnerability/PYSEC-2023-123', discoverLlmsTxt: false });
    assert.equal(res.status, 200);
    assert.equal(res.body.extractorId, 'osv-ghsa');
    assert.match(res.body.markdown, /sample-pkg/);
  });

  test('F20.4: osv-ghsa bounds huge affected[].versions arrays cleanly', async () => {
    const res = await hub.scrape({ url: 'https://osv.dev/vulnerability/GHSA-bigv-1111-2222', discoverLlmsTxt: false });
    assert.equal(res.status, 200);
    assert.equal(res.body.extractorId, 'osv-ghsa');
    assert.ok(res.body.markdown.length < 100_000, 'Expected bounded Markdown for 500 versions');
  });

  test('F20.5: osv-ghsa preserves advisory & fix references in links', async () => {
    const res = await hub.scrape({
      url: 'https://osv.dev/vulnerability/GHSA-jfh8-c2jp-5v3q',
      formats: ['markdown', 'links'],
      discoverLlmsTxt: false,
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.extractorId, 'osv-ghsa');
    assert.ok((res.body.links ?? []).some((l) => l.includes('CVE-2021-44228')));
  });

  // --- F24: wikidata-openlibrary (5 tests) ---
  test('F24.1: wikidata.org/wiki/Q42 resolves Special:EntityData/Q42.json', async () => {
    const res = await hub.scrape({ url: 'https://www.wikidata.org/wiki/Q42', discoverLlmsTxt: false });
    assert.equal(res.status, 200);
    assert.equal(res.body.extractorId, 'wikidata-openlibrary');
    assert.match(res.body.markdown, /Douglas Adams/);
    assert.match(res.body.markdown, /science fiction writer/i);
  });

  test('F24.2: wikidata.org/wiki/Q937 extracts aliases & sitelinks', async () => {
    const res = await hub.scrape({ url: 'https://www.wikidata.org/wiki/Q937', discoverLlmsTxt: false });
    assert.equal(res.status, 200);
    assert.equal(res.body.extractorId, 'wikidata-openlibrary');
    assert.match(res.body.markdown, /Albert Einstein/);
    assert.match(res.body.markdown, /theoretical physicist/i);
  });

  test('F24.3: openlibrary.org/isbn/<isbn13> follows same-host 302 from /isbn/*.json to /books/*.json', async () => {
    const res = await hub.scrape({ url: 'https://openlibrary.org/isbn/9780140328721', discoverLlmsTxt: false });
    assert.equal(res.status, 200);
    assert.equal(res.body.extractorId, 'wikidata-openlibrary');
    assert.match(res.body.markdown, /Fantastic Mr\. Fox/);
    assert.match(res.body.markdown, /Puffin Books/);
  });

  test('F24.4: openlibrary.org NEVER requests disallowed /api/* (politeness invariant)', async () => {
    router.clearLog();
    const res = await hub.scrape({ url: 'https://openlibrary.org/isbn/9780140328721', discoverLlmsTxt: false });
    assert.equal(res.status, 200);
    assert.equal(res.body.ok, true);
    assert.equal(res.body.extractorId, 'wikidata-openlibrary');
    assert.ok(router.countRequests('openlibrary.org', '/isbn/9780140328721.json') >= 1);
    assert.equal(router.countRequests('openlibrary.org', '/api'), 0);
  });

  test('F24.5: openlibrary.org supports 10-digit ISBN URLs', async () => {
    const res = await hub.scrape({ url: 'https://openlibrary.org/isbn/0140328726', discoverLlmsTxt: false });
    assert.equal(res.status, 200);
    assert.equal(res.body.extractorId, 'wikidata-openlibrary');
    assert.match(res.body.markdown, /Fantastic Mr\. Fox/);
  });
});

// ============================================================================
// Group D: Tier 4 ATS, Public APIs & Log-Mined Adapters (F21–F23, F30–F35)
// ============================================================================
describe('Tier 4 — ATS Hardening, Public APIs & Log-Mined Adapters (F21–F23, F30–F35)', () => {
  let router;
  let hub;

  before(async () => {
    router = createOutboundRouter();

    // F21 Workday & iCIMS
    router.status(
      (u) => u.hostname === 'glean.wd5.myworkdayjobs.com' && u.pathname.includes('/wday/cxs/'),
      422,
      JSON.stringify(F21_WORKDAY_ICIMS.workdayCxs422),
      { 'content-type': 'application/json' },
    );
    router.status(
      (u) => u.hostname === 'temporal.wd1.myworkdayjobs.com' && u.pathname.includes('/wday/cxs/'),
      500,
      JSON.stringify(F21_WORKDAY_ICIMS.workdayCxs500),
      { 'content-type': 'application/json' },
    );
    router.json(
      (u) => u.hostname === 'temporal.wd5.myworkdayjobs.com' && u.pathname.includes('/wday/cxs/'),
      F21_WORKDAY_ICIMS.workdayCxsJobsOk,
    );
    router.html('https://careers-acme.icims.com/jobs/search?ss=1&in_iframe=1', F21_WORKDAY_ICIMS.icimsSearchIframeHtml);
    router.html('https://careers-acme.icims.com/jobs/4123/firmware-engineer/job?in_iframe=1', F21_WORKDAY_ICIMS.icimsJobIframeHtml);

    // F22 UKG, Paylocity, Dover
    router.setRobots('recruiting.ultipro.com', F22_UKG_PAYLOCITY_DOVER.ukgRobotsTxt);
    router.html(
      'https://recruiting.ultipro.com/ACM1001/JobBoard/11111111-2222-3333-4444-555555555555/',
      F22_UKG_PAYLOCITY_DOVER.ukgJobBoardHtml,
    );
    router.json(
      'https://recruiting.paylocity.com/recruiting/api/feed/jobs/aaaa-bbbb-cccc',
      F22_UKG_PAYLOCITY_DOVER.paylocityFeedJson,
    );
    router.html('https://recruiting.paylocity.com/Recruiting/Jobs/All/aaaa-bbbb-cccc', F22_UKG_PAYLOCITY_DOVER.paylocityHtml);
    router.setRobots('app.dover.com', F22_UKG_PAYLOCITY_DOVER.doverRobotsTxt);
    router.setRobots('jobs.dover.com', F22_UKG_PAYLOCITY_DOVER.doverRobotsTxt);
    router.html('https://app.dover.com/jobs/acme', F22_UKG_PAYLOCITY_DOVER.doverHtml);
    router.html('https://jobs.dover.com/acme', F22_UKG_PAYLOCITY_DOVER.doverHtml);

    // F23 NHTSA vPIC & FCC ID
    router.json(
      'https://vpic.nhtsa.dot.gov/api/vehicles/decodevinvalues/1HGCM82633A004352?format=json',
      F23_NHTSA_FCC.vpicVinJson,
    );
    router.json(
      'https://api.nhtsa.gov/recalls/recallsByVehicle?make=honda&model=accord&modelYear=2020',
      F23_NHTSA_FCC.nhtsaRecallsJson,
    );
    router.status('https://api.nhtsa.gov/recalls/recallsByVehicle?make=blocked&model=test&modelYear=2024', 403, 'Forbidden');
    router.setRobots('fccid.io', F23_NHTSA_FCC.fccRobotsTxt);
    router.html('https://fccid.io/BCG-E3542A', F23_NHTSA_FCC.fccHtml);

    // F30 NFPA Sitecore JSS __NEXT_DATA__
    router.setRobots('www.nfpa.org', F30_NFPA.robotsTxt);
    router.html('https://www.nfpa.org/codes-and-standards/nfpa-70-standard-development/70', F30_NFPA.nextDataHtml());
    router.html('https://www.nfpa.org/education-and-research/electrical/nfpa-70', F30_NFPA.nextDataHtml('NFPA 70 Electrical Safety'));

    // F31 Giant & Liv Bikes
    router.setRobots('www.giant-bicycles.com', F31_GIANT_LIV.robotsTxt);
    router.setRobots('www.liv-cycling.com', F31_GIANT_LIV.robotsTxt);
    router.html('https://www.giant-bicycles.com/us/defy-advanced-pro-0', F31_GIANT_LIV.bikeHtml('Giant', 'Defy Advanced Pro 0'));
    router.html('https://www.liv-cycling.com/us/avail-advanced-pro-0', F31_GIANT_LIV.bikeHtml('Liv', 'Avail Advanced Pro 0'));
    router.html('https://www.giant-bicycles.com/us/manuals', F31_GIANT_LIV.manualsHtml);

    // F32 bumm.de
    router.setRobots('bumm.de', F32_BUMM.robotsTxt);
    router.html('https://bumm.de/en/product-detail/iq-x.html', F32_BUMM.productHtml('en'));
    router.html('https://bumm.de/de/product-detail/iq-x.html', F32_BUMM.productHtml('de'));

    // F33 Bicycle Retailer
    router.setRobots('www.bicycleretailer.com', F33_BICYCLE_RETAILER.robotsTxt);
    router.html('https://www.bicycleretailer.com/industry-news/2026/11/01/ebike-battery-rules', F33_BICYCLE_RETAILER.articleHtml);
    router.html('https://www.bicycleretailer.com/industry-news', F33_BICYCLE_RETAILER.listingHtml);
    router.xml('https://www.bicycleretailer.com/rss.xml', F33_BICYCLE_RETAILER.rssXml);

    // F34 YouTube
    router.setRobots('www.youtube.com', F34_YOUTUBE.robotsTxt);
    router.html('https://www.youtube.com/watch?v=dQw4w9WgXcQ', F34_YOUTUBE.watchHtml());
    router.html(
      'https://www.youtube.com/watch?v=unicode123',
      F34_YOUTUBE.watchHtml('München E-Bike Test — 85 Nm 🚴', 'RadLab DE'),
    );

    // F35 D1 High-ROI
    router.html('https://productinfo.shimano.com/en/product/DU-EP801', F35_D1_HIGH_ROI.shimanoProductInfoRscHtml('DU-EP801'));
    router.html('https://productinfo.shimano.com/en/spec/mtb-drivetrain', F35_D1_HIGH_ROI.shimanoProductInfoRscHtml('RD-M8100-SGS'));
    router.html('https://www.law.cornell.edu/cfr/text/16/part-1512', F35_D1_HIGH_ROI.cornellCfrHtml);
    router.html('https://www.sram.com/en/sram/models/rd-xx-e-b1', F35_D1_HIGH_ROI.sramModelHtml);
    router.html('https://www.tq-ebike.com/en/products/hpr50', F35_D1_HIGH_ROI.tqEbikeHtml);

    hub = await createHubInstance({ router });
  });

  after(async () => {
    await hub?.dispose();
  });

  // --- F21: Workday CXS & iCIMS hardening (5 tests) ---
  test('F21.1: Workday CXS 422 with query/offset fast-exits cleanly without HTML/browser fallback', async () => {
    router.clearLog();
    const res = await hub.scrape({
      url: 'https://glean.wd5.myworkdayjobs.com/en-US/Glean?q=engineer&offset=20',
      discoverLlmsTxt: false,
    });
    assert.equal(res.status, 404);
    assert.equal(res.body.outcome, 'not_found');
    assert.equal(router.countRequests('glean.wd5.myworkdayjobs.com', '/en-US/Glean'), 0);
  });

  test('F21.2: Workday CXS 500 JSON error fast-exits cleanly without hanging or retrying', async () => {
    const res = await hub.scrape({
      url: 'https://temporal.wd1.myworkdayjobs.com/en-US/Temporal',
      discoverLlmsTxt: false,
    });
    assert.equal(res.status, 404);
    assert.equal(res.body.outcome, 'not_found');
  });

  test('F21.3: Workday /v1/jobs search on temporal.wd5 returns jobs cleanly without wd1 500 probes', async () => {
    router.clearLog();
    const res = await hub.jobs({
      domains: ['temporal.wd5.myworkdayjobs.com'],
      query: 'Engineer',
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.ok, true);
    assert.ok(Array.isArray(res.body.jobs) && res.body.jobs.length >= 1);
    assert.equal(router.countRequests('temporal.wd1.myworkdayjobs.com'), 0);
  });

  test('F21.4: iCIMS ?in_iframe=1 job board search table extracts job listings cleanly', async () => {
    const res = await hub.scrape({
      url: 'https://careers-acme.icims.com/jobs/search?ss=1&in_iframe=1',
      discoverLlmsTxt: false,
    });
    assert.equal(res.status, 200);
    assert.match(res.body.markdown, /Firmware Engineer/);
    assert.match(res.body.markdown, /Battery Test Lead/);
  });

  test('F21.5: iCIMS ?in_iframe=1 single job extracts JobPosting & description', async () => {
    const res = await hub.scrape({
      url: 'https://careers-acme.icims.com/jobs/4123/firmware-engineer/job?in_iframe=1',
      discoverLlmsTxt: false,
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.jobPosting?.title, 'Firmware Engineer');
    assert.match(res.body.markdown, /CAN-bus firmware/);
  });

  // --- F22: ukg-paylocity-dover (5 tests) ---
  test('F22.1: UKG Pro */JobBoard/* extracts structured opportunities cleanly', async () => {
    const res = await hub.scrape({
      url: 'https://recruiting.ultipro.com/ACM1001/JobBoard/11111111-2222-3333-4444-555555555555/',
      discoverLlmsTxt: false,
    });
    assert.equal(res.status, 200);
    assert.match(res.body.markdown, /Embedded Systems Engineer/);
    assert.ok((Array.isArray(res.body.jobs) && res.body.jobs.length >= 2) || (Array.isArray(res.body.records) && res.body.records.length >= 2));
  });

  test('F22.2: UKG Pro NEVER requests root / or */JobBoardView (robots.txt politeness)', async () => {
    router.clearLog();
    const res = await hub.scrape({
      url: 'https://recruiting.ultipro.com/ACM1001/JobBoard/11111111-2222-3333-4444-555555555555/',
      discoverLlmsTxt: false,
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.ok, true);
    assert.ok(
      router.countRequests('recruiting.ultipro.com', '/ACM1001/JobBoard/11111111-2222-3333-4444-555555555555/') >= 1,
    );
    assert.match(res.body.markdown, /Embedded Systems Engineer/);
    assert.equal(router.countRequests('recruiting.ultipro.com', '/JobBoardView'), 0);
    assert.equal(
      router.requestLog.filter((r) => r.host === 'recruiting.ultipro.com' && r.pathname === '/').length,
      0,
    );
  });

  test('F22.3: Paylocity job board extracts structured jobs via feed/HTML', async () => {
    const res = await hub.scrape({
      url: 'https://recruiting.paylocity.com/Recruiting/Jobs/All/aaaa-bbbb-cccc',
      discoverLlmsTxt: false,
    });
    assert.equal(res.status, 200);
    assert.match(res.body.markdown, /Product Safety Engineer/);
    assert.ok((Array.isArray(res.body.jobs) && res.body.jobs.length >= 1) || (Array.isArray(res.body.records) && res.body.records.length >= 1));
  });

  test('F22.4: Dover job board extracts __NEXT_DATA__ roles via HTML/SSR', async () => {
    const res = await hub.scrape({ url: 'https://app.dover.com/jobs/acme', discoverLlmsTxt: false });
    assert.equal(res.status, 200);
    assert.match(res.body.markdown, /Founding Robotics Engineer/);
    assert.ok((Array.isArray(res.body.jobs) && res.body.jobs.length >= 2) || (Array.isArray(res.body.records) && res.body.records.length >= 2));
  });

  test('F22.5: Dover NEVER requests disallowed /api/* on app.dover.com or jobs.dover.com', async () => {
    router.clearLog();
    const res1 = await hub.scrape({ url: 'https://app.dover.com/jobs/acme', discoverLlmsTxt: false });
    const res2 = await hub.scrape({ url: 'https://jobs.dover.com/acme', discoverLlmsTxt: false });
    assert.equal(res1.status, 200);
    assert.equal(res1.body.ok, true);
    assert.equal(res2.status, 200);
    assert.equal(res2.body.ok, true);
    assert.ok(router.countRequests('app.dover.com', '/jobs/acme') >= 1);
    assert.ok(router.countRequests('jobs.dover.com', '/acme') >= 1);
    assert.match(res1.body.markdown, /Founding Robotics Engineer/);
    assert.match(res2.body.markdown, /Founding Robotics Engineer/);
    assert.equal(router.countRequests('app.dover.com', '/api'), 0);
    assert.equal(router.countRequests('jobs.dover.com', '/api'), 0);
  });

  // --- F23: nhtsa-vpic-recalls & fcc-id (5 tests) ---
  test('F23.1: NHTSA vPIC VIN decode formats vehicle fields cleanly', async () => {
    const res = await hub.scrape({
      url: 'https://vpic.nhtsa.dot.gov/api/vehicles/decodevinvalues/1HGCM82633A004352?format=json',
      discoverLlmsTxt: false,
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.extractorId, 'nhtsa-vpic-recalls');
    assert.match(res.body.markdown, /HONDA/);
    assert.match(res.body.markdown, /Accord/);
    assert.match(res.body.markdown, /2003/);
  });

  test('F23.2: NHTSA recalls API formats campaign number, component, and remedy', async () => {
    const res = await hub.scrape({
      url: 'https://api.nhtsa.gov/recalls/recallsByVehicle?make=honda&model=accord&modelYear=2020',
      discoverLlmsTxt: false,
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.extractorId, 'nhtsa-vpic-recalls');
    assert.match(res.body.markdown, /23V858000/);
    assert.match(res.body.markdown, /fuel pump/i);
  });

  test('F23.3: NHTSA 403 Forbidden fails cleanly without WAF bypass', async () => {
    const res = await hub.scrape({
      url: 'https://api.nhtsa.gov/recalls/recallsByVehicle?make=blocked&model=test&modelYear=2024',
      discoverLlmsTxt: false,
    });
    assert.ok(res.status === 403 || res.status === 422);
    assert.equal(res.body.ok, false);
  });

  test('F23.4: fccid.io extracts grant metadata, frequency/power table & PDF exhibit link', async () => {
    const res = await hub.scrape({
      url: 'https://fccid.io/BCG-E3542A',
      formats: ['markdown', 'links'],
      discoverLlmsTxt: false,
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.extractorId, 'fcc-id');
    assert.match(res.body.markdown, /BCG-E3542A/);
    assert.match(res.body.markdown, /2402 - 2480 MHz/);
    assert.ok((res.body.links ?? []).some((l) => l.includes('User-Manual-654321.pdf')));
  });

  test('F23.5: fccid.io respects robots.txt disallows (/ViewExhibitReport.cfm, /subscribe.php)', async () => {
    router.clearLog();
    const res = await hub.scrape({
      url: 'https://fccid.io/ViewExhibitReport.cfm?id=123',
      discoverLlmsTxt: false,
    });
    assert.equal(res.status, 422);
    assert.equal(router.countRequests('fccid.io', '/ViewExhibitReport.cfm'), 0);
  });

  // --- F30: www.nfpa.org Sitecore JSS __NEXT_DATA__ (5 tests) ---
  test('F30.1: www.nfpa.org unpacks __NEXT_DATA__ PageTitle & ContentBlock without browser', async () => {
    const res = await hub.scrape({
      url: 'https://www.nfpa.org/codes-and-standards/nfpa-70-standard-development/70',
      discoverLlmsTxt: false,
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.rendered, false);
    assert.match(res.body.markdown, /NFPA 70 National Electrical Code/);
    assert.match(res.body.markdown, /overcurrent protection/i);
  });

  test('F30.2: www.nfpa.org extracts Accordion items & SplitScreenCalloutComponent', async () => {
    const res = await hub.scrape({
      url: 'https://www.nfpa.org/education-and-research/electrical/nfpa-70',
      discoverLlmsTxt: false,
    });
    assert.equal(res.status, 200);
    assert.match(res.body.markdown, /Article 625 Electric Vehicle Power Transfer/);
    assert.match(res.body.markdown, /Article 706 Energy Storage Systems/);
    assert.match(res.body.markdown, /Code Adoption Highlights/);
  });

  test('F30.3: www.nfpa.org preserves TwoColumnVideo & CTA links', async () => {
    const res = await hub.scrape({
      url: 'https://www.nfpa.org/codes-and-standards/nfpa-70-standard-development/70',
      formats: ['markdown', 'links'],
      discoverLlmsTxt: false,
    });
    assert.equal(res.status, 200);
    assert.match(res.body.markdown, /NFPA 70 Overview Video/);
    const links = res.body.links ?? [];
    assert.ok(
      links.some((l) => l.includes('nfpa-70-standard-development/70') || l.includes('nfpa-70-overview')),
      `Expected NFPA CTA/video link in res.body.links, got ${JSON.stringify(links)}`,
    );
  });

  test('F30.4: www.nfpa.org never hits disallowed /-/media/ or /en/ paths', async () => {
    router.clearLog();
    const res = await hub.scrape({
      url: 'https://www.nfpa.org/codes-and-standards/nfpa-70-standard-development/70',
      discoverLlmsTxt: false,
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.ok, true);
    assert.ok(router.countRequests('www.nfpa.org', '/codes-and-standards/nfpa-70-standard-development/70') >= 1);
    assert.match(res.body.markdown, /NFPA 70 National Electrical Code/);
    assert.equal(router.countRequests('www.nfpa.org', '/-/media/'), 0);
    assert.equal(router.countRequests('www.nfpa.org', '/en/'), 0);
  });

  test('F30.5: www.nfpa.org yields rich wordCount (>= 30 words) from Sitecore JSS payload', async () => {
    const res = await hub.scrape({
      url: 'https://www.nfpa.org/education-and-research/electrical/nfpa-70',
      discoverLlmsTxt: false,
    });
    assert.equal(res.status, 200);
    assert.ok((res.body.wordCount ?? 0) >= 30, `Expected rich wordCount, got ${res.body.wordCount}`);
  });

  // --- F31: giant-liv-bikes (5 tests) ---
  test('F31.1: www.giant-bicycles.com extracts specifications datarows & geometry table', async () => {
    const res = await hub.scrape({
      url: 'https://www.giant-bicycles.com/us/defy-advanced-pro-0',
      discoverLlmsTxt: false,
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.extractorId, 'giant-liv-bikes');
    assert.match(res.body.markdown, /Defy Advanced Pro 0/);
    assert.match(res.body.markdown, /Shimano Ultegra Di2/);
    assert.match(res.body.markdown, /562/);
  });

  test('F31.2: www.liv-cycling.com shares giant-liv-bikes extraction cleanly', async () => {
    const res = await hub.scrape({
      url: 'https://www.liv-cycling.com/us/avail-advanced-pro-0',
      discoverLlmsTxt: false,
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.extractorId, 'giant-liv-bikes');
    assert.match(res.body.markdown, /Avail Advanced Pro 0/);
    assert.match(res.body.markdown, /384/);
  });

  test('F31.3: www.giant-bicycles.com/us/manuals surfaces PDF manual links', async () => {
    const res = await hub.scrape({
      url: 'https://www.giant-bicycles.com/us/manuals',
      formats: ['markdown', 'links'],
      discoverLlmsTxt: false,
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.extractorId, 'giant-liv-bikes');
    assert.ok((res.body.links ?? []).some((l) => l.includes('SyncDrive_Pro2_Manual.pdf')));
  });

  test('F31.4: giant-liv-bikes NEVER hits disallowed /shop* or /apiproxy/* paths', async () => {
    router.clearLog();
    const res1 = await hub.scrape({ url: 'https://www.giant-bicycles.com/us/defy-advanced-pro-0', discoverLlmsTxt: false });
    const res2 = await hub.scrape({ url: 'https://www.liv-cycling.com/us/avail-advanced-pro-0', discoverLlmsTxt: false });
    assert.equal(res1.status, 200);
    assert.equal(res1.body.ok, true);
    assert.equal(res1.body.extractorId, 'giant-liv-bikes');
    assert.equal(res2.status, 200);
    assert.equal(res2.body.ok, true);
    assert.equal(res2.body.extractorId, 'giant-liv-bikes');
    assert.ok(router.countRequests('www.giant-bicycles.com', '/us/defy-advanced-pro-0') >= 1);
    assert.ok(router.countRequests('www.liv-cycling.com', '/us/avail-advanced-pro-0') >= 1);
    assert.equal(router.countRequests('www.giant-bicycles.com', '/shop'), 0);
    assert.equal(router.countRequests('www.giant-bicycles.com', '/apiproxy'), 0);
    assert.equal(router.countRequests('www.liv-cycling.com', '/shop'), 0);
  });

  test('F31.5: giant-liv-bikes preserves manual PDF links alongside bike specs', async () => {
    const res = await hub.scrape({
      url: 'https://www.giant-bicycles.com/us/defy-advanced-pro-0',
      formats: ['markdown', 'links'],
      discoverLlmsTxt: false,
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.extractorId, 'giant-liv-bikes');
    assert.ok((res.body.links ?? []).some((l) => l.includes('Defy_Manual_2026.pdf')));
  });

  // --- F32: bumm.de (5 tests) ---
  test('F32.1: bumm.de extracts TYPO3 JSON-LD Product & table.attributes-table specs', async () => {
    const res = await hub.scrape({
      url: 'https://bumm.de/en/product-detail/iq-x.html',
      discoverLlmsTxt: false,
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.extractorId, 'bumm-de');
    assert.match(res.body.markdown, /100 Lux/);
    assert.match(res.body.markdown, /CNC Aluminum/);
  });

  test('F32.2: bumm.de surfaces PDF mounting instruction manual links', async () => {
    const res = await hub.scrape({
      url: 'https://bumm.de/en/product-detail/iq-x.html',
      formats: ['markdown', 'links'],
      discoverLlmsTxt: false,
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.extractorId, 'bumm-de');
    assert.ok((res.body.links ?? []).some((l) => l.includes('Anleitung_IQ-X.pdf')));
  });

  test('F32.3: bumm.de populates product format (sku, brand, price, currency)', async () => {
    const res = await hub.scrape({
      url: 'https://bumm.de/en/product-detail/iq-x.html',
      formats: ['markdown', 'product'],
      discoverLlmsTxt: false,
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.extractorId, 'bumm-de');
    assert.equal(res.body.product?.sku, '164RTSNDI-01');
    assert.equal(res.body.product?.brand, 'Busch & Müller');
    assert.equal(res.body.product?.currency, 'EUR');
  });

  test('F32.4: bumm.de handles German umlauts and comma-decimal EUR price cleanly', async () => {
    const res = await hub.scrape({
      url: 'https://bumm.de/de/product-detail/iq-x.html',
      formats: ['markdown', 'product'],
      discoverLlmsTxt: false,
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.extractorId, 'bumm-de');
    assert.match(res.body.markdown, /Scheinwerfer für E-Bikes/);
    assert.equal(res.body.product?.price, 149.9);
  });

  test('F32.5: bumm.de never requests disallowed /typo3/ path', async () => {
    router.clearLog();
    const res = await hub.scrape({ url: 'https://bumm.de/en/product-detail/iq-x.html', discoverLlmsTxt: false });
    assert.equal(res.status, 200);
    assert.equal(res.body.ok, true);
    assert.equal(res.body.extractorId, 'bumm-de');
    assert.ok(router.countRequests('bumm.de', '/en/product-detail/iq-x.html') >= 1);
    assert.equal(router.countRequests('bumm.de', '/typo3/'), 0);
  });

  // --- F33: www.bicycleretailer.com (5 tests) ---
  test('F33.1: bicycleretailer.com extracts Drupal .node-article & .field-name-body without sidebar ads', async () => {
    const res = await hub.scrape({
      url: 'https://www.bicycleretailer.com/industry-news/2026/11/01/ebike-battery-rules',
      discoverLlmsTxt: false,
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.extractorId, 'bicycleretailer');
    assert.match(res.body.markdown, /UL 2849 and UL 2271/);
    assert.equal(res.body.markdown.includes('Sidebar Ads Noise'), false);
  });

  test('F33.2: bicycleretailer.com listing extracts .view-content article links & summaries', async () => {
    const res = await hub.scrape({
      url: 'https://www.bicycleretailer.com/industry-news',
      formats: ['markdown', 'links'],
      discoverLlmsTxt: false,
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.extractorId, 'bicycleretailer');
    assert.match(res.body.markdown, /Shimano Reports Q3/);
    assert.ok((res.body.links ?? []).some((l) => l.includes('shimano-q3-results')));
  });

  test('F33.3: bicycleretailer.com /rss.xml parses RSS entries into clean Markdown', async () => {
    const res = await hub.scrape({ url: 'https://www.bicycleretailer.com/rss.xml', discoverLlmsTxt: false });
    assert.equal(res.status, 200);
    assert.match(res.body.markdown, /CPSC Finalizes E-Bike Battery Safety Guidance/);
    assert.match(res.body.markdown, /ebike-battery-rules/);
  });

  test('F33.4: bicycleretailer.com preserves author & publishedTime metadata', async () => {
    const res = await hub.scrape({
      url: 'https://www.bicycleretailer.com/industry-news/2026/11/01/ebike-battery-rules',
      discoverLlmsTxt: false,
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.extractorId, 'bicycleretailer');
    assert.equal(res.body.metadata?.author, 'Marc Sani');
  });

  test('F33.5: bicycleretailer.com never requests disallowed /admin/ path', async () => {
    router.clearLog();
    const res = await hub.scrape({
      url: 'https://www.bicycleretailer.com/industry-news/2026/11/01/ebike-battery-rules',
      discoverLlmsTxt: false,
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.ok, true);
    assert.equal(res.body.extractorId, 'bicycleretailer');
    assert.ok(router.countRequests('www.bicycleretailer.com', '/industry-news/2026/11/01/ebike-battery-rules') >= 1);
    assert.equal(router.countRequests('www.bicycleretailer.com', '/admin/'), 0);
  });

  // --- F34: www.youtube.com watch fast-path (5 tests) ---
  test('F34.1: youtube.com/watch extracts title, author & description from static videoDetails', async () => {
    const res = await hub.scrape({
      url: 'https://www.youtube.com/watch?v=dQw4w9WgXcQ',
      discoverLlmsTxt: false,
    });
    assert.equal(res.status, 200);
    assert.match(res.body.markdown, /Bosch Performance Line CX Gen5 Review/);
    assert.match(res.body.markdown, /ElectricBikeLab/);
    assert.match(res.body.markdown, /85 Nm torque/);
  });

  test('F34.2: youtube.com/watch skips CDP auto-render even when browser agent is connected', async () => {
    await withFreshHub({ router }, async (ytHub) => {
      const agent = await ytHub.connectMockAgent({
        onDispatch: async (msg, helpers) => {
          const req0 = helpers.call.requests?.[0] ?? {};
          await helpers.sendReply({
            results: [
              {
                id: req0.id,
                url: req0.url,
                finalUrl: req0.url,
                status: 200,
                outcome: 'ok',
                contentType: 'text/html; charset=utf-8',
                body: F34_YOUTUBE.watchHtml(),
                bodyEncoding: 'utf-8',
              },
            ],
          });
        },
      });
      const res = await ytHub.scrape({
        url: 'https://www.youtube.com/watch?v=dQw4w9WgXcQ',
        discoverLlmsTxt: false,
      });
      assert.equal(res.status, 200);
      assert.equal(res.body.rendered, false);
      const renderFrames = agent.frames.filter((f) => f.call.requests?.[0]?.id === 'auto-render-1');
      assert.equal(renderFrames.length, 0, 'YouTube /watch must never trigger auto-render-1 when static videoDetails present');
    });
  });

  test('F34.3: youtube.com NEVER fetches disallowed /api/timedtext or /youtubei/*', async () => {
    router.clearLog();
    const res = await hub.scrape({ url: 'https://www.youtube.com/watch?v=dQw4w9WgXcQ', discoverLlmsTxt: false });
    assert.equal(res.status, 200);
    assert.equal(res.body.ok, true);
    assert.ok(router.countRequests('www.youtube.com', '/watch?v=dQw4w9WgXcQ') >= 1);
    assert.match(res.body.markdown, /Bosch Performance Line CX Gen5 Review/);
    assert.equal(router.countRequests('www.youtube.com', '/api/timedtext'), 0);
    assert.equal(router.countRequests('www.youtube.com', '/youtubei'), 0);
  });

  test('F34.4: youtube.com extracts metadata cleanly despite captionTracks URLs in HTML', async () => {
    const res = await hub.scrape({
      url: 'https://www.youtube.com/watch?v=dQw4w9WgXcQ',
      discoverLlmsTxt: false,
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.metadata?.title, 'Bosch Performance Line CX Gen5 Review');
    assert.equal(router.countRequests('www.youtube.com', '/api/timedtext'), 0);
  });

  test('F34.5: youtube.com preserves Unicode titles & channel names cleanly', async () => {
    const res = await hub.scrape({
      url: 'https://www.youtube.com/watch?v=unicode123',
      discoverLlmsTxt: false,
    });
    assert.equal(res.status, 200);
    assert.match(res.body.markdown, /München E-Bike Test/);
    assert.match(res.body.markdown, /RadLab DE/);
  });

  // --- F35: D1 high-ROI discoveries (5 tests) ---
  test('F35.1: productinfo.shimano.com Next.js RSC TableSpecContents unpacks full spec table', async () => {
    const res = await hub.scrape({
      url: 'https://productinfo.shimano.com/en/product/DU-EP801',
      discoverLlmsTxt: false,
    });
    assert.equal(res.status, 200);
    assert.match(res.body.markdown, /DU-EP801/);
    assert.match(res.body.markdown, /85 Nm/);
    assert.match(res.body.markdown, /BT-EN806/);
  });

  test('F35.2: productinfo.shimano.com /spec/ RSC payload extracts drivetrain specs cleanly', async () => {
    const res = await hub.scrape({
      url: 'https://productinfo.shimano.com/en/spec/mtb-drivetrain',
      discoverLlmsTxt: false,
    });
    assert.equal(res.status, 200);
    assert.match(res.body.markdown, /RD-M8100-SGS/);
  });

  test('F35.3: www.law.cornell.edu CFR HTML extracts #content without navbar/sidebar chrome', async () => {
    const res = await hub.scrape({
      url: 'https://www.law.cornell.edu/cfr/text/16/part-1512',
      discoverLlmsTxt: false,
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.extractorId, 'cornell-lii');
    assert.match(res.body.markdown, /16 CFR Part 1512/);
    assert.equal(res.body.markdown.includes('Cornell Donate Sidebar Noise'), false);
  });

  test('F35.4: www.sram.com product detail extracts JSON-LD + specs table', async () => {
    const res = await hub.scrape({
      url: 'https://www.sram.com/en/sram/models/rd-xx-e-b1',
      formats: ['markdown', 'product'],
      discoverLlmsTxt: false,
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.extractorId, 'sram-models');
    assert.match(res.body.markdown, /XX SL Eagle AXS Rear Derailleur/);
    assert.equal(res.body.product?.sku, '00.7518.161.000');
  });

  test('F35.5: www.tq-ebike.com TYPO3 product page extracts JSON-LD + specs cleanly', async () => {
    const res = await hub.scrape({
      url: 'https://www.tq-ebike.com/en/products/hpr50',
      formats: ['markdown', 'product'],
      discoverLlmsTxt: false,
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.extractorId, 'tq-ebike');
    assert.match(res.body.markdown, /Harmonic Pin-Ring/);
    assert.equal(res.body.product?.sku, 'TQ-HPR50-SYS');
  });
});

// ============================================================================
// Group E: M1 Audit Follow-Ups L-01..L-05 (F25–F29 — MUST PASS)
// ============================================================================
describe('M1 — Audit Follow-Ups L-01..L-05 (F25–F29)', () => {
  // --- F25: L-01 jsonFilter in cache key & bypass check (5 tests) ---
  test('F25.1: L-01 cached unfiltered scrape is NOT served to a jsonFilter request', async () => {
    const router = createOutboundRouter();
    router.json('https://l01-a.example.com/roles.json', F25_JSONFILTER_RECORDS);
    await withFreshHub({ router }, async (hub) => {
      const plain = await hub.scrape({
        url: 'https://l01-a.example.com/roles.json',
        maxAgeMs: 600_000,
        discoverLlmsTxt: false,
      });
      assert.equal(plain.status, 200);
      assert.match(plain.body.markdown, /Sales Role Bravo/);

      const filtered = await hub.scrape({
        url: 'https://l01-a.example.com/roles.json',
        maxAgeMs: 600_000,
        jsonFilter: 'team=Platform',
        discoverLlmsTxt: false,
      });
      assert.equal(filtered.status, 200);
      assert.equal(filtered.body.cached, false);
      assert.match(filtered.body.markdown, /Platform Role Alpha/);
      assert.equal(filtered.body.markdown.includes('Sales Role Bravo'), false);
    });
  });

  test('F25.2: L-01 identical jsonFilter hits its own filtered cache & preserves filtering', async () => {
    const router = createOutboundRouter();
    router.json('https://l01-b.example.com/roles.json', F25_JSONFILTER_RECORDS);
    await withFreshHub({ router }, async (hub) => {
      const first = await hub.scrape({
        url: 'https://l01-b.example.com/roles.json',
        maxAgeMs: 600_000,
        jsonFilter: 'team=Platform',
        discoverLlmsTxt: false,
      });
      assert.equal(first.status, 200);
      assert.equal(first.body.cached, false);

      const second = await hub.scrape({
        url: 'https://l01-b.example.com/roles.json',
        maxAgeMs: 600_000,
        jsonFilter: 'team=Platform',
        discoverLlmsTxt: false,
      });
      assert.equal(second.status, 200);
      assert.equal(second.body.cached, true);
      assert.match(second.body.markdown, /Platform Role Alpha/);
      assert.equal(second.body.markdown.includes('Sales Role Bravo'), false);
    });
  });

  test('F25.3: L-01 different jsonFilter values never collide in cache', async () => {
    const router = createOutboundRouter();
    router.json('https://l01-c.example.com/roles.json', F25_JSONFILTER_RECORDS);
    await withFreshHub({ router }, async (hub) => {
      const plat = await hub.scrape({
        url: 'https://l01-c.example.com/roles.json',
        maxAgeMs: 600_000,
        jsonFilter: 'team=Platform',
        discoverLlmsTxt: false,
      });
      assert.equal(plat.status, 200);
      assert.equal(plat.body.markdown.includes('Sales Role Bravo'), false);

      const sales = await hub.scrape({
        url: 'https://l01-c.example.com/roles.json',
        maxAgeMs: 600_000,
        jsonFilter: 'team=Sales',
        discoverLlmsTxt: false,
      });
      assert.equal(sales.status, 200);
      assert.equal(sales.body.cached, false);
      assert.match(sales.body.markdown, /Sales Role Bravo/);
      assert.equal(sales.body.markdown.includes('Platform Role Alpha'), false);
    });
  });

  test('F25.4: L-01 filtered scrape first never poisons subsequent unfiltered scrape', async () => {
    const router = createOutboundRouter();
    router.json('https://l01-d.example.com/roles.json', F25_JSONFILTER_RECORDS);
    await withFreshHub({ router }, async (hub) => {
      const filtered = await hub.scrape({
        url: 'https://l01-d.example.com/roles.json',
        maxAgeMs: 600_000,
        jsonFilter: 'team=Platform',
        discoverLlmsTxt: false,
      });
      assert.equal(filtered.status, 200);
      assert.equal(filtered.body.markdown.includes('Sales Role Bravo'), false);

      const plain = await hub.scrape({
        url: 'https://l01-d.example.com/roles.json',
        maxAgeMs: 600_000,
        discoverLlmsTxt: false,
      });
      assert.equal(plain.status, 200);
      assert.match(plain.body.markdown, /Platform Role Alpha/);
      assert.match(plain.body.markdown, /Sales Role Bravo/);
    });
  });

  test('F25.5: L-01 blank whitespace jsonFilter behaves identically to unfiltered scrape', async () => {
    const router = createOutboundRouter();
    router.json('https://l01-e.example.com/roles.json', F25_JSONFILTER_RECORDS);
    await withFreshHub({ router }, async (hub) => {
      const plain = await hub.scrape({
        url: 'https://l01-e.example.com/roles.json',
        maxAgeMs: 600_000,
        discoverLlmsTxt: false,
      });
      assert.equal(plain.status, 200);

      const blankFilter = await hub.scrape({
        url: 'https://l01-e.example.com/roles.json',
        maxAgeMs: 600_000,
        jsonFilter: '   ',
        discoverLlmsTxt: false,
      });
      assert.equal(blankFilter.status, 200);
      assert.equal(blankFilter.body.cached, true);
      assert.match(blankFilter.body.markdown, /Sales Role Bravo/);
    });
  });

  // --- F26: L-02 edgeBudgetExceeded (5 tests) ---
  test('F26.1: L-02 primary agent bodyOmitted without extractedOnNode returns edgeBudgetExceeded: true & artifactId', async () => {
    const router = createOutboundRouter();
    const xml5Mib = `<sitemap>${over4Mib('<url><loc>https://l02.example.com/p</loc></url>')}</sitemap>`;
    await withFreshHub({ router }, async (hub) => {
      let expectedBlobSha = '';
      await hub.connectMockAgent({
        onDispatch: async (_msg, helpers) => {
          const req0 = helpers.call.requests?.[0] ?? {};
          const art = await helpers.uploadArtifact(xml5Mib, { requestId: req0.id });
          expectedBlobSha = art.blobSha256;
          await helpers.sendReply({
            results: [
              {
                id: req0.id,
                url: req0.url,
                finalUrl: req0.url,
                status: 200,
                outcome: 'ok',
                contentType: 'application/xml',
                bodyOmitted: true,
                artifact: art,
              },
            ],
          });
        },
      });
      const res = await hub.scrape({
        url: 'https://l02.example.com/sitemap.xml',
        target: 'agent',
        discoverLlmsTxt: false,
      });
      assert.equal(res.status, 200);
      assert.equal(res.body.edgeBudgetExceeded, true);
      assert.equal(res.body.artifactId, expectedBlobSha);
      assert.equal(res.body.markdown, '');
      assert.ok((res.body.warnings ?? []).some((w) => w.includes('4 MiB WASM input budget')));
    });
  });

  test('F26.2: L-02 primary agent bodyOmitted with extractedOnNode: false returns edgeBudgetExceeded: true', async () => {
    const router = createOutboundRouter();
    const html5Mib = `<html><body>${over4Mib('<p>chunk</p>')}</body></html>`;
    await withFreshHub({ router }, async (hub) => {
      await hub.connectMockAgent({
        onDispatch: async (_msg, helpers) => {
          const req0 = helpers.call.requests?.[0] ?? {};
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
                extractedOnNode: false,
                artifact: art,
              },
            ],
          });
        },
      });
      const res = await hub.scrape({
        url: 'https://l02-false.example.com/big.html',
        target: 'agent',
        discoverLlmsTxt: false,
      });
      assert.equal(res.status, 200);
      assert.equal(res.body.edgeBudgetExceeded, true);
    });
  });

  test('F26.3: L-02 regression: extractedOnNode: true with valid markdown succeeds without edgeBudgetExceeded', async () => {
    const router = createOutboundRouter();
    await withFreshHub({ router }, async (hub) => {
      await hub.connectMockAgent({
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
                markdown: '# Big Document\n\nExtracted natively on Go node.',
              },
            ],
          });
        },
      });
      const res = await hub.scrape({
        url: 'https://l02-node.example.com/big.html',
        target: 'agent',
        discoverLlmsTxt: false,
      });
      assert.equal(res.status, 200);
      assert.equal(res.body.edgeBudgetExceeded, undefined);
      assert.equal(res.body.extractedOnNode, true);
      assert.match(res.body.markdown, /Extracted natively on Go node/);
    });
  });

  test('F26.4: L-02 regression: node-parsed PDF with bodyOmitted: true preserves markdown without edgeBudgetExceeded', async () => {
    const router = createOutboundRouter();
    await withFreshHub({ router }, async (hub) => {
      await hub.connectMockAgent({
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
                contentType: 'application/pdf',
                pdfEngine: 'poppler-pdftotext',
                bodyOmitted: true,
                markdown: '# PDF Manual\n\nTorque specification 25 Nm.',
              },
            ],
          });
        },
      });
      const res = await hub.scrape({
        url: 'https://l02-pdf.example.com/manual.pdf',
        target: 'agent',
        discoverLlmsTxt: false,
      });
      assert.equal(res.status, 200);
      assert.equal(res.body.edgeBudgetExceeded, undefined);
      assert.match(res.body.markdown, /Torque specification 25 Nm/);
    });
  });

  test('F26.5: L-02 primary agent extractedOnNode: true with empty markdown returns edgeBudgetExceeded: true', async () => {
    const router = createOutboundRouter();
    await withFreshHub({ router }, async (hub) => {
      await hub.connectMockAgent({
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
                contentType: 'application/xml',
                bodyOmitted: true,
                extractedOnNode: true,
                markdown: '',
              },
            ],
          });
        },
      });
      const res = await hub.scrape({
        url: 'https://l02-empty.example.com/empty.xml',
        target: 'agent',
        discoverLlmsTxt: false,
      });
      assert.equal(res.status, 200);
      assert.equal(res.body.edgeBudgetExceeded, true);
    });
  });

  // --- F27: L-03 rawBase64 / parsers: [] > 4 MiB inline hydration (5 tests) ---
  test('F27.1: L-03 formats: ["rawBase64"] hydrates 5 MiB HTML artifact from R2 into rawBase64', async () => {
    const router = createOutboundRouter();
    const bigHtml5Mib = `<!doctype html><html><body><p>${'B'.repeat(5 * 1024 * 1024)}</p></body></html>`;
    await withFreshHub({ router }, async (hub) => {
      await hub.connectMockAgent({
        onDispatch: async (_msg, helpers) => {
          const req0 = helpers.call.requests?.[0] ?? {};
          assert.ok(req0.formats?.includes('rawBase64'));
          const art = await helpers.uploadArtifact(bigHtml5Mib, { requestId: req0.id });
          await helpers.sendReply({
            results: [
              {
                id: req0.id,
                url: req0.url,
                finalUrl: req0.url,
                status: 200,
                outcome: 'ok',
                contentType: 'text/html; charset=utf-8',
                bodyOmitted: true,
                artifact: art,
              },
            ],
          });
        },
      });
      const res = await hub.scrape({
        url: 'https://l03-html.example.com/5mb.html',
        target: 'agent',
        formats: ['rawBase64'],
        discoverLlmsTxt: false,
      });
      assert.equal(res.status, 200);
      assert.equal(typeof res.body.rawBase64, 'string');
      assert.equal(Buffer.from(res.body.rawBase64, 'base64').toString('utf8'), bigHtml5Mib);
    });
  });

  test('F27.2: L-03 formats: ["rawBase64"], parsers: [] hydrates 5 MiB PDF artifact from R2', async () => {
    const router = createOutboundRouter();
    const pdf5Mib = Buffer.concat([
      Buffer.from('%PDF-1.7\n%EOF\n', 'utf8'),
      Buffer.alloc(5 * 1024 * 1024, 0x20),
    ]);
    await withFreshHub({ router }, async (hub) => {
      await hub.connectMockAgent({
        onDispatch: async (_msg, helpers) => {
          const req0 = helpers.call.requests?.[0] ?? {};
          const art = await helpers.uploadArtifact(pdf5Mib, { requestId: req0.id });
          await helpers.sendReply({
            results: [
              {
                id: req0.id,
                kind: 'binary',
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
      const res = await hub.scrape({
        url: 'https://l03-pdf.example.com/5mb.pdf',
        target: 'agent',
        formats: ['rawBase64'],
        parsers: [],
        discoverLlmsTxt: false,
      });
      assert.equal(res.status, 200);
      assert.equal(typeof res.body.rawBase64, 'string');
      const decoded = Buffer.from(res.body.rawBase64, 'base64');
      assert.equal(decoded.byteLength, pdf5Mib.byteLength);
      assert.equal(decoded.subarray(0, 8).toString('utf8'), '%PDF-1.7');
    });
  });

  test('F27.3: L-03 formats: ["markdown", "rawBase64"] on 5 MiB HTML returns rawBase64 + WASM budget warning', async () => {
    const router = createOutboundRouter();
    const bigHtml5Mib = `<!doctype html><html><body><p>${'C'.repeat(5 * 1024 * 1024)}</p></body></html>`;
    await withFreshHub({ router }, async (hub) => {
      await hub.connectMockAgent({
        onDispatch: async (_msg, helpers) => {
          const req0 = helpers.call.requests?.[0] ?? {};
          const art = await helpers.uploadArtifact(bigHtml5Mib, { requestId: req0.id });
          await helpers.sendReply({
            results: [
              {
                id: req0.id,
                url: req0.url,
                finalUrl: req0.url,
                status: 200,
                outcome: 'ok',
                contentType: 'text/html; charset=utf-8',
                bodyOmitted: true,
                artifact: art,
              },
            ],
          });
        },
      });
      const res = await hub.scrape({
        url: 'https://l03-mixed.example.com/5mb.html',
        target: 'agent',
        formats: ['markdown', 'rawBase64'],
        discoverLlmsTxt: false,
      });
      assert.equal(res.status, 200);
      assert.equal(typeof res.body.rawBase64, 'string');
      assert.ok((res.body.warnings ?? []).some((w) => w.includes('4 MiB edge budget') && w.includes('rawBase64')));
    });
  });

  test('F27.4: L-03 contrast control: normal 5 MiB HTML without rawBase64 stays capped at 4 MiB on R2 hydration', async () => {
    const router = createOutboundRouter();
    const bigHtml5Mib = `<!doctype html><html><body><p>${'D'.repeat(5 * 1024 * 1024)}</p></body></html>`;
    await withFreshHub({ router }, async (hub) => {
      await hub.connectMockAgent({
        onDispatch: async (_msg, helpers) => {
          const req0 = helpers.call.requests?.[0] ?? {};
          assert.equal(helpers.call.options?.maxInlineBodyBytes, MAX_WASM_INPUT_BYTES);
          const art = await helpers.uploadArtifact(bigHtml5Mib, { requestId: req0.id });
          await helpers.sendReply({
            results: [
              {
                id: req0.id,
                url: req0.url,
                finalUrl: req0.url,
                status: 200,
                outcome: 'ok',
                contentType: 'text/html; charset=utf-8',
                bodyOmitted: true,
                artifact: art,
              },
            ],
          });
        },
      });
      const res = await hub.scrape({
        url: 'https://l03-ctrl.example.com/5mb.html',
        target: 'agent',
        formats: ['markdown'],
        discoverLlmsTxt: false,
      });
      assert.equal(res.status, 200);
      assert.equal(res.body.edgeBudgetExceeded, true);
      assert.equal(res.body.rawBase64, undefined);
    });
  });

  test('F27.5: L-03 > 18 MiB wire-budget binary with parsers: [] omits rawBase64 cleanly & returns artifactId', async () => {
    const router = createOutboundRouter();
    // Use non-UTF-8 bytes (0xff) so encodeBodyForWire base64-encodes (15 MiB -> 20 MiB > 18 MiB wire budget).
    const big15Mib = Buffer.alloc(15 * 1024 * 1024, 0xff);
    await withFreshHub({ router }, async (hub) => {
      let expectedBlobSha = '';
      await hub.connectMockAgent({
        onDispatch: async (_msg, helpers) => {
          const req0 = helpers.call.requests?.[0] ?? {};
          const art = await helpers.uploadArtifact(big15Mib, { requestId: req0.id });
          expectedBlobSha = art.blobSha256;
          await helpers.sendReply({
            results: [
              {
                id: req0.id,
                kind: 'binary',
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
      const res = await hub.scrape({
        url: 'https://l03-15mb.example.com/huge.pdf',
        target: 'agent',
        formats: ['rawBase64'],
        parsers: [],
        discoverLlmsTxt: false,
      });
      assert.equal(res.status, 200);
      assert.equal(res.body.rawBase64, undefined);
      assert.equal(res.body.artifactId, expectedBlobSha);
      assert.ok((res.body.warnings ?? []).some((w) => w.includes('artifactId')));
    });
  });

  // --- F28: L-04 (R3-04) relative product.url resolution + recordsForJson[0] backfill (5 tests) ---
  test('F28.1: L-04 JSON-LD Product relative url resolves against finalUrl', async () => {
    const router = createOutboundRouter();
    router.html(
      'https://l04-shop.example.com/cat/index.html',
      `<!doctype html><html><head><script type="application/ld+json">{"@type":"Product","name":"Aero Helmet","url":"/products/aero-helmet?color=red","offers":{"price":"129.00","priceCurrency":"USD"}}</script></head><body><h1>Aero Helmet</h1></body></html>`,
    );
    await withFreshHub({ router }, async (hub) => {
      const res = await hub.scrape({
        url: 'https://l04-shop.example.com/cat/index.html',
        formats: ['product'],
        discoverLlmsTxt: false,
      });
      assert.equal(res.status, 200);
      assert.equal(res.body.product?.url, 'https://l04-shop.example.com/products/aero-helmet?color=red');
    });
  });

  test('F28.2: L-04 JSON-LD Product unsafe javascript: url is blocked and falls back to finalUrl', async () => {
    const router = createOutboundRouter();
    router.html(
      'https://l04-xss.example.com/item',
      `<!doctype html><html><head><script type="application/ld+json">{"@type":"Product","name":"Safe Lock","url":"javascript:alert(1)","offers":{"price":"49.00","priceCurrency":"USD"}}</script></head><body><h1>Safe Lock</h1></body></html>`,
    );
    await withFreshHub({ router }, async (hub) => {
      const res = await hub.scrape({
        url: 'https://l04-xss.example.com/item',
        formats: ['product'],
        discoverLlmsTxt: false,
      });
      assert.equal(res.status, 200);
      assert.equal(res.body.product?.url, 'https://l04-xss.example.com/item');
    });
  });

  test('F28.3: L-04 OpenGraph relative og:url resolves against finalUrl', async () => {
    const router = createOutboundRouter();
    router.html(
      'https://l04-og.example.com/browse',
      `<!doctype html><html><head><meta property="og:title" content="Trail Light"/><meta property="og:url" content="/items/trail-light"/><meta property="product:price:amount" content="79.50"/><meta property="product:price:currency" content="USD"/></head><body><h1>Trail Light</h1></body></html>`,
    );
    await withFreshHub({ router }, async (hub) => {
      const res = await hub.scrape({
        url: 'https://l04-og.example.com/browse',
        formats: ['product'],
        discoverLlmsTxt: false,
      });
      assert.equal(res.status, 200);
      assert.equal(res.body.product?.url, 'https://l04-og.example.com/items/trail-light');
      assert.equal(res.body.product?.price, 79.5);
    });
  });

  test('F28.4: L-04 custom-domain Shopify HTML backfills product.{sku,price,brand,availability} & json from recordsForJson[0]', async () => {
    const router = createOutboundRouter();
    router.html(
      'https://boutique.example.com/products/canvas-pack',
      `<!doctype html><html><head><title>Canvas Pack</title><script>window.Shopify = { shop: "boutique.myshopify.com" };</script></head><body><main><h1>Canvas Pack</h1><p>Durable waxed canvas pack.</p></main></body></html>`,
    );
    router.json('https://boutique.example.com/products/canvas-pack.json', {
      product: {
        id: 9001,
        title: 'Canvas Pack',
        handle: 'canvas-pack',
        vendor: 'Boutique',
        body_html: '<p>Durable waxed canvas pack.</p>',
        images: [{ src: 'https://cdn.example.com/canvas-pack.jpg' }],
        variants: [{ id: 101, title: 'Default', sku: 'CP-1', price: '149.00', available: true }],
      },
    });
    await withFreshHub({ router }, async (hub) => {
      const res = await hub.scrape({
        url: 'https://boutique.example.com/products/canvas-pack',
        formats: [
          'markdown',
          'product',
          { type: 'json', schema: { type: 'object', properties: { sku: { type: 'string' }, price: { type: 'number' } } } },
        ],
        discoverLlmsTxt: false,
      });
      assert.equal(res.status, 200);
      assert.equal(res.body.product?.sku, 'CP-1');
      assert.equal(res.body.product?.price, 149);
      assert.equal(res.body.product?.brand, 'Boutique');
      assert.equal(res.body.product?.availability, 'InStock');
      assert.equal(res.body.json?.sku, 'CP-1');
    });
  });

  test('F28.5: L-04 Shopify twin path (*.myshopify.com/products/...) populates product from formatted.records[0]', async () => {
    const router = createOutboundRouter();
    router.json('https://boutique.myshopify.com/products/canvas-pack.json', {
      product: {
        id: 9001,
        title: 'Canvas Pack',
        handle: 'canvas-pack',
        vendor: 'Boutique',
        body_html: '<p>Durable waxed canvas pack.</p>',
        images: [{ src: 'https://cdn.example.com/canvas-pack.jpg' }],
        variants: [{ id: 101, title: 'Default', sku: 'CP-1', price: '149.00', available: true }],
      },
    });
    await withFreshHub({ router }, async (hub) => {
      const res = await hub.scrape({
        url: 'https://boutique.myshopify.com/products/canvas-pack',
        formats: ['product'],
        discoverLlmsTxt: false,
      });
      assert.equal(res.status, 200);
      assert.equal(res.body.product?.sku, 'CP-1');
      assert.equal(res.body.product?.brand, 'Boutique');
      assert.equal(res.body.product?.price, 149);
    });
  });

  // --- F29: L-05 maxInlineBodyBytes on auto-render-1 & wd-stub-render-1 (5 tests) ---
  test('F29.1: L-05 auto-render-1 sends maxInlineBodyBytes: MAX_WASM_INPUT_BYTES', async () => {
    const router = createOutboundRouter();
    await withFreshHub({ router }, async (hub) => {
      let autoRenderMaxInline;
      await hub.connectMockAgent({
        onDispatch: async (_msg, helpers) => {
          const req0 = helpers.call.requests?.[0] ?? {};
          if (req0.id === 'auto-render-1') {
            autoRenderMaxInline = helpers.call.options?.maxInlineBodyBytes;
            await helpers.sendReply({
              results: [
                {
                  id: req0.id,
                  url: req0.url,
                  finalUrl: req0.url,
                  status: 200,
                  outcome: 'ok',
                  contentType: 'text/html',
                  body: `<html><body><main><h1>Rendered SPA</h1><p>${'word '.repeat(80)}</p></main></body></html>`,
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
                body: '<html><body><div id="root"></div><script src="/app.js"></script></body></html>',
                bodyEncoding: 'utf-8',
              },
            ],
          });
        },
      });
      const res = await hub.scrape({
        url: 'https://l05-spa.example.com/app',
        discoverLlmsTxt: false,
      });
      assert.equal(res.status, 200);
      assert.equal(autoRenderMaxInline, MAX_WASM_INPUT_BYTES);
    });
  });

  test('F29.2: L-05 wd-stub-render-1 sends maxInlineBodyBytes: MAX_WASM_INPUT_BYTES', async () => {
    const router = createOutboundRouter();
    await withFreshHub({ router }, async (hub) => {
      let wdStubMaxInline;
      await hub.connectMockAgent({
        onDispatch: async (_msg, helpers) => {
          const req0 = helpers.call.requests?.[0] ?? {};
          if (req0.id === 'wd-stub-render-1') {
            wdStubMaxInline = helpers.call.options?.maxInlineBodyBytes;
            await helpers.sendReply({
              results: [
                {
                  id: req0.id,
                  url: req0.url,
                  finalUrl: req0.url,
                  status: 200,
                  outcome: 'ok',
                  contentType: 'text/html',
                  body: '<html><body><main><h1>Workday Careers</h1><p>Senior Engineer role open now.</p></main></body></html>',
                  bodyEncoding: 'utf-8',
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
                  body: '{"widget":"redirect","url":"https://l05acme.wd1.myworkdayjobs.com/en-US/Careers","externalSpa":true}',
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
      const res = await hub.scrape({
        url: 'https://l05acme.wd1.myworkdayjobs.com/en-US/Careers',
        discoverLlmsTxt: false,
      });
      assert.equal(res.status, 200);
      assert.equal(wdStubMaxInline, MAX_WASM_INPUT_BYTES);
    });
  });

  test('F29.3: L-05 auto-render-1 with in-budget rendered HTML returns rendered: true & renderedVia: browser-auto', async () => {
    const router = createOutboundRouter();
    await withFreshHub({ router }, async (hub) => {
      await hub.connectMockAgent({
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
                  ? `<html><body><main><h1>Hydrated Content</h1><p>${'detail '.repeat(60)}</p></main></body></html>`
                  : '<html><body><div id="root"></div><script src="/bundle.js"></script></body></html>',
                bodyEncoding: 'utf-8',
              },
            ],
          });
        },
      });
      const res = await hub.scrape({
        url: 'https://l05-render.example.com/page',
        discoverLlmsTxt: false,
      });
      assert.equal(res.status, 200);
      assert.equal(res.body.rendered, true);
      assert.equal(res.body.renderedVia, 'browser-auto');
      assert.match(res.body.markdown, /Hydrated Content/);
    });
  });

  test('F29.4: L-05 auto-render-1 with >4 MiB rendered R2 artifact respects maxInlineBodyBytes cap', async () => {
    const router = createOutboundRouter();
    const bigRendered5Mib = `<html><body><main>${over4Mib('<p>rendered item</p>')}</main></body></html>`;
    await withFreshHub({ router }, async (hub) => {
      await hub.connectMockAgent({
        onDispatch: async (_msg, helpers) => {
          const req0 = helpers.call.requests?.[0] ?? {};
          if (req0.id === 'auto-render-1') {
            assert.equal(helpers.call.options?.maxInlineBodyBytes, MAX_WASM_INPUT_BYTES);
            const art = await helpers.uploadArtifact(bigRendered5Mib, { requestId: req0.id });
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
          await helpers.sendReply({
            results: [
              {
                id: req0.id,
                url: req0.url,
                finalUrl: req0.url,
                status: 200,
                outcome: 'ok',
                contentType: 'text/html',
                body: '<html><body><div id="root"></div><script src="/bundle.js"></script></body></html>',
                bodyEncoding: 'utf-8',
              },
            ],
          });
        },
      });
      const res = await hub.scrape({
        url: 'https://l05-over.example.com/huge-spa',
        discoverLlmsTxt: false,
      });
      // Since auto-render-1 returned bodyOmitted: true without body, scrape keeps thin SPA fallback without crashing WASM.
      assert.equal(res.status, 200);
      assert.equal(res.body.ok, true);
    });
  });

  test('F29.5: L-05 renderMode: "off" on thin SPA never dispatches auto-render-1', async () => {
    const router = createOutboundRouter();
    await withFreshHub({ router }, async (hub) => {
      const agent = await hub.connectMockAgent({
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
                body: '<html><body><div id="root"></div><script src="/bundle.js"></script></body></html>',
                bodyEncoding: 'utf-8',
              },
            ],
          });
        },
      });
      const res = await hub.scrape({
        url: 'https://l05-off.example.com/spa',
        renderMode: 'off',
        discoverLlmsTxt: false,
      });
      assert.equal(res.status, 200);
      assert.equal(agent.frames.filter((f) => f.call.requests?.[0]?.id === 'auto-render-1').length, 0);
    });
  });
});

// ============================================================================
// Group F: Security & Politeness Guards (F36 — 9 tests)
// ============================================================================
describe('R5 — Security & Politeness Guards (F36)', () => {
  test('F36.1: robots.txt Disallow: /private/ blocks /v1/scrape (422) and never fetches target path', async () => {
    const router = createOutboundRouter();
    router.setRobots('robots-priv.example.com', 'User-agent: *\nDisallow: /private/\nAllow: /\n');
    router.html('https://robots-priv.example.com/private/secret', '<html><body>Secret</body></html>');
    await withFreshHub({ router }, async (hub) => {
      const res = await hub.scrape({ url: 'https://robots-priv.example.com/private/secret', discoverLlmsTxt: false });
      assert.equal(res.status, 422);
      assert.equal(res.body.ok, false);
      assert.match(String(res.body.problem ?? ''), /robots\.txt/i);
      assert.equal(router.countRequests('robots-priv.example.com', '/private'), 0);
    });
  });

  test('F36.2: robots.txt Disallow: / (e.g. up.codes) blocks /v1/scrape and never fetches content', async () => {
    const router = createOutboundRouter();
    router.setRobots('up.codes', 'User-agent: *\nDisallow: /\n');
    router.html('https://up.codes/codes/california', '<html><body>Blocked</body></html>');
    await withFreshHub({ router }, async (hub) => {
      const res = await hub.scrape({ url: 'https://up.codes/codes/california', discoverLlmsTxt: false });
      assert.equal(res.status, 422);
      assert.equal(res.body.ok, false);
      assert.equal(router.countRequests('up.codes', '/codes'), 0);
    });
  });

  test('F36.3: robots.txt is enforced on every redirect hop', async () => {
    const router = createOutboundRouter();
    router.setRobots('hop-src.example.com', 'User-agent: *\nAllow: /\n');
    router.setRobots('hop-dst.example.com', 'User-agent: *\nDisallow: /blocked\n');
    router.redirect('https://hop-src.example.com/go', 'https://hop-dst.example.com/blocked', 302);
    router.html('https://hop-dst.example.com/blocked', '<html><body>Should never fetch</body></html>');
    await withFreshHub({ router }, async (hub) => {
      const res = await hub.scrape({ url: 'https://hop-src.example.com/go', discoverLlmsTxt: false });
      assert.equal(res.status, 422);
      assert.equal(res.body.ok, false);
      assert.ok(router.countRequests('hop-dst.example.com', '/robots.txt') >= 1);
      assert.equal(router.countRequests('hop-dst.example.com', '/blocked'), 0);
    });
  });

  test('F36.4: validatePublicHttpsTargetUrl SSRF rejects http://, loopback, IMDS, .local, credentials & rebinding', async () => {
    const router = createOutboundRouter();
    await withFreshHub({ router }, async (hub) => {
      const badUrls = [
        'http://example.com/page',
        'https://127.0.0.1/admin',
        'https://169.254.169.254/latest/meta-data/',
        'https://metadata.google.internal/computeMetadata/v1/',
        'https://secret:pass@example.com/private',
        'https://10.0.0.1.nip.io/ssrf',
        'https://printer.local/status',
      ];
      for (const badUrl of badUrls) {
        const res = await hub.scrape({ url: badUrl, discoverLlmsTxt: false });
        assert.equal(res.status, 400, `Expected 400 for SSRF URL ${badUrl}, got ${res.status}`);
        assert.equal(res.body.error, 'invalid_url');
      }
      assert.equal(router.requestLog.length, 0, 'SSRF URLs must make zero outbound requests');
    });
  });

  test('F36.5: redirect-hop SSRF / scheme downgrade to http://127.0.0.1 or 10.0.0.1 is blocked', async () => {
    const router = createOutboundRouter();
    router.redirect('https://ssrf-redir.example.com/hop1', 'http://127.0.0.1/internal', 302);
    router.redirect('https://ssrf-redir2.example.com/hop2', 'https://10.0.0.1/secret', 302);
    await withFreshHub({ router }, async (hub) => {
      const r1 = await hub.scrape({ url: 'https://ssrf-redir.example.com/hop1', discoverLlmsTxt: false });
      assert.equal(r1.status, 403);
      assert.equal(r1.body.ok, false);
      assert.equal(r1.body.outcome, 'blocked');
      const r2 = await hub.scrape({ url: 'https://ssrf-redir2.example.com/hop2', discoverLlmsTxt: false });
      assert.equal(r2.status, 403);
      assert.equal(r2.body.ok, false);
      assert.equal(r2.body.outcome, 'blocked');
      assert.equal(router.countRequests('127.0.0.1'), 0);
      assert.equal(router.countRequests('10.0.0.1'), 0);
    });
  });

  test('F36.6: isTrustedTwinRedirectUrl rejects cross-host twin redirect to untrusted domain', async () => {
    const router = createOutboundRouter();
    router.redirect('https://rubygems.org/api/v1/gems/rack.json', 'https://evil-cdn.example.com/rack.json', 302);
    router.json('https://evil-cdn.example.com/rack.json', {
      name: 'EVIL_TWIN_MARKER',
      version: '9.9.9',
      info: 'Injected cross-host twin body that must be rejected by isTrustedTwinRedirectUrl',
    });
    router.html('https://rubygems.org/gems/rack', '<html><head><title>rack | RubyGems</title></head><body><main><h1>rack</h1><p>HTML fallback page.</p></main></body></html>');
    await withFreshHub({ router }, async (hub) => {
      const res = await hub.scrape({ url: 'https://rubygems.org/gems/rack', discoverLlmsTxt: false });
      assert.equal(res.status, 200);
      assert.notEqual(res.body.extractorId, 'rubygems');
      assert.equal(String(res.body.markdown ?? '').includes('EVIL_TWIN_MARKER'), false);
    });
  });

  test('F36.7: MAX_WASM_INPUT_BYTES (4 MiB) prevents >4 MiB Cloudflare overflow body from entering WASM', async () => {
    const router = createOutboundRouter();
    const bigHtml = `<!doctype html><html><head><title>Huge</title></head><body><main>${over4Mib('<p>large payload row</p>')}</main></body></html>`;
    router.html('https://huge-cf.example.com/big.html', bigHtml);
    await withFreshHub({ router }, async (hub) => {
      const res = await hub.scrape({
        url: 'https://huge-cf.example.com/big.html',
        target: 'container',
        discoverLlmsTxt: false,
      });
      assert.equal(res.status, 200);
      assert.equal(res.body.edgeBudgetExceeded, true);
      assert.equal(res.body.markdown, '');
      assert.ok((res.body.warnings ?? []).some((w) => w.includes('4 MiB WASM input budget')));
    });
  });

  test('F36.8: unfiltered saferproducts.gov dump without RecallNumber is rejected (never processes 25 MiB dump)', async () => {
    const router = createOutboundRouter();
    router.json('https://www.saferproducts.gov/RestWebServices/Recall?format=json', [
      { RecallID: 1, RecallNumber: '00001', Title: 'UNFILTERED_DUMP_SHOULD_NOT_PASS' },
    ]);
    await withFreshHub({ router }, async (hub) => {
      const res = await hub.scrape({
        url: 'https://www.saferproducts.gov/RestWebServices/Recall?format=json',
        discoverLlmsTxt: false,
      });
      assert.ok(
        res.status >= 400 || res.body.ok === false || (res.body.extractorId !== 'cpsc-recalls' && !String(res.body.markdown ?? '').includes('UNFILTERED_DUMP_SHOULD_NOT_PASS')),
        `Unfiltered saferproducts.gov dump must be rejected, got status=${res.status} body=${JSON.stringify(res.body).slice(0, 200)}`,
      );
      assert.notEqual(res.body.extractorId, 'cpsc-recalls');
    });
  });

  test('F36.9: HTTP 403 WAF block (www.osha.gov / si.shimano.com) returns 403 without bypass', async () => {
    const router = createOutboundRouter();
    router.status('https://www.osha.gov/laws-regs/standardinterpretations/2023-01-01', 403, 'Just a moment...', {
      'cf-mitigated': 'challenge',
      server: 'cloudflare',
    });
    await withFreshHub({ router }, async (hub) => {
      const res = await hub.scrape({
        url: 'https://www.osha.gov/laws-regs/standardinterpretations/2023-01-01',
        discoverLlmsTxt: false,
      });
      assert.equal(res.status, 403);
      assert.equal(res.body.ok, false);
      assert.equal(res.body.outcome, 'challenge');
    });
  });
});
