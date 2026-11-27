import assert from 'node:assert/strict';
import { describe, test } from 'node:test';
import {
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

const over4Mib = (unit) => unit.repeat(Math.ceil((MAX_WASM_INPUT_BYTES + 64 * 1024) / unit.length));

describe('Tier 4 — Real-World Multi-Step Application Workloads', () => {
  // Scenario 1: E-Bike Fleet Catalog & Spec Intelligence Sweep
  test('T4.01: Scenario 1 — E-Bike Fleet Catalog & Spec Intelligence Sweep (F02, F03, F11, F14, F25, F28, F31, F32, F35, F36)', async () => {
    const router = createOutboundRouter();

    // F02 + F28: Shopify collection & custom-domain product
    router.html('https://voltride.example.com/collections/commuter', F02_SHOPIFY.collectionHtml('voltride.myshopify.com'));
    router.json('https://voltride.example.com/collections/commuter/products.json?limit=50', F02_SHOPIFY.collectionProductsJson);
    router.html(
      'https://voltride.example.com/products/apex-commuter-500',
      `<!doctype html><html><head><title>Apex Commuter 500</title><script>window.Shopify = { shop: "voltride.myshopify.com", currency: { active: "USD" } };</script></head><body><main><h1>Apex Commuter 500</h1><p>Commuter e-bike.</p></main></body></html>`,
    );
    router.json('https://voltride.example.com/products/apex-commuter-500.json', {
      product: { ...F02_SHOPIFY.collectionProductsJson.products[0] },
    });

    // F03 + F36: WooCommerce category + robots disallow
    router.setRobots('rideshop.example.com', 'User-agent: *\nDisallow: /product-category/other/\nAllow: /\n');
    router.html('https://rideshop.example.com/product-category/ebikes/', F03_WOOCOMMERCE.categoryHtml('Electric Bikes'));
    router.html('https://rideshop.example.com/product-category/other/', F03_WOOCOMMERCE.categoryHtml('Other'));
    router.json('https://rideshop.example.com/wp-json/wc/store/v1/products?category=ebikes&per_page=50', F03_WOOCOMMERCE.storeProductsUsd);

    // F11: SFCC Demandware
    router.html('https://trekbikes-t4.example.com/us/en_US/fx-3/p/44751/', F11_SFCC.productHtml('trekbikes-t4.example.com'));
    router.json(
      (u) => u.hostname === 'trekbikes-t4.example.com' && u.pathname.includes('Product-Variation'),
      F11_SFCC.productVariationJson,
    );

    // F35: Shimano RSC + F31: Giant + F32: Bumm + F14/F28: Bikeschematics
    router.html('https://productinfo.shimano.com/en/product/DU-EP801', F35_D1_HIGH_ROI.shimanoProductInfoRscHtml('DU-EP801'));
    router.setRobots('www.giant-bicycles.com', F31_GIANT_LIV.robotsTxt);
    router.html('https://www.giant-bicycles.com/us/defy-advanced-1', F31_GIANT_LIV.bikeHtml('Giant', 'Defy Advanced 1'));
    router.setRobots('bumm.de', F32_BUMM.robotsTxt);
    router.html(
      'https://bumm.de/en/product-detail/iq-x.html',
      F32_BUMM.productHtml('en').replace('"sku": "164RTSNDI-01",', '"url": "/en/product-detail/iq-x.html",\n    "sku": "164RTSNDI-01",'),
    );
    router.html(
      'https://bikeschematics.example.com/specs/bafang-m600',
      `<!doctype html><html><head><title>Bafang M600 Drive Unit</title></head><body><main itemscope itemtype="https://schema.org/Product"><h1 itemprop="name">Bafang M600 Drive Unit</h1><a itemprop="url" href="/parts/bafang-m600">Spec Sheet</a><table class="spec-table"><tr><th>SKU</th><td>BF-M600-85</td></tr><tr><th>Brand</th><td>Bafang</td></tr><tr><th>Price</th><td>$899.00</td></tr><tr><th>Availability</th><td>In Stock</td></tr></table></main></body></html>`,
    );

    // F25: Fleet inventory JSON for jsonFilter cache isolation
    router.json('https://fleet-inventory.example.com/catalog.json', [
      { id: 'f1', title: 'Commuter 85', team: '85Nm' },
      { id: 'f2', title: 'City Lite 50', team: '50Nm' },
    ]);

    await withFreshHub({ router }, async (hub) => {
      // 1. Verify commerce extractors registered
      const catRes = await hub.extractors('commerce-social');
      assert.equal(catRes.status, 200);
      const catIds = new Set((catRes.body.extractors ?? []).map((e) => e.id));
      for (const expectedId of ['shopify', 'woocommerce', 'sfcc-demandware']) {
        assert.ok(catIds.has(expectedId), `Expected commerce-social extractor "${expectedId}"`);
      }
      const allExRes = await hub.extractors();
      assert.equal(allExRes.status, 200);
      const allIds = new Set((allExRes.body.extractors ?? []).map((e) => e.id));
      for (const expectedId of ['giant-liv-bikes', 'bumm-de']) {
        assert.ok(allIds.has(expectedId), `Expected extractor "${expectedId}" in GET /v1/extractors`);
      }

      // 2. Shopify collection + product backfill
      const shopColl = await hub.scrape({
        url: 'https://voltride.example.com/collections/commuter',
        formats: ['markdown', 'product'],
        discoverLlmsTxt: false,
      });
      assert.equal(shopColl.status, 200);
      assert.ok(Array.isArray(shopColl.body.records) && shopColl.body.records.length >= 2);

      const shopProd = await hub.scrape({
        url: 'https://voltride.example.com/products/apex-commuter-500',
        formats: [
          'markdown',
          'product',
          { type: 'json', schema: { type: 'object', properties: { sku: { type: 'string' }, price: { type: 'number' } } } },
        ],
        discoverLlmsTxt: false,
      });
      assert.equal(shopProd.status, 200);
      assert.equal(shopProd.body.product?.sku, 'VR-APX-BLK');
      assert.equal(shopProd.body.json?.sku, 'VR-APX-BLK');

      // 3. WooCommerce allowed vs disallowed
      const wooOk = await hub.scrape({
        url: 'https://rideshop.example.com/product-category/ebikes/',
        discoverLlmsTxt: false,
      });
      assert.equal(wooOk.status, 200);
      assert.ok(Array.isArray(wooOk.body.records) && wooOk.body.records.length >= 2);

      const wooBlocked = await hub.scrape({
        url: 'https://rideshop.example.com/product-category/other/',
        discoverLlmsTxt: false,
      });
      assert.equal(wooBlocked.status, 422);
      assert.equal(router.countRequests('rideshop.example.com', '/product-category/other/'), 0);

      // 4. SFCC, Shimano, Giant, Bumm, Bikeschematics
      const sfccRes = await hub.scrape({
        url: 'https://trekbikes-t4.example.com/us/en_US/fx-3/p/44751/',
        formats: ['markdown', 'product'],
        discoverLlmsTxt: false,
      });
      assert.equal(sfccRes.status, 200);
      assert.equal(sfccRes.body.product?.sku, '44751-54-BLK');

      const shimanoRes = await hub.scrape({
        url: 'https://productinfo.shimano.com/en/product/DU-EP801',
        discoverLlmsTxt: false,
      });
      assert.equal(shimanoRes.status, 200);
      assert.match(shimanoRes.body.markdown, /85 Nm/);

      const giantRes = await hub.scrape({
        url: 'https://www.giant-bicycles.com/us/defy-advanced-1',
        formats: ['markdown', 'links'],
        discoverLlmsTxt: false,
      });
      assert.equal(giantRes.status, 200);
      assert.equal(giantRes.body.extractorId, 'giant-liv-bikes');
      assert.equal(router.countRequests('www.giant-bicycles.com', '/us/shop'), 0);

      const bummRes = await hub.scrape({
        url: 'https://bumm.de/en/product-detail/iq-x.html',
        formats: ['markdown', 'product', 'links'],
        discoverLlmsTxt: false,
      });
      assert.equal(bummRes.status, 200);
      assert.equal(bummRes.body.product?.url, 'https://bumm.de/en/product-detail/iq-x.html');
      assert.equal(bummRes.body.product?.sku, '164RTSNDI-01');

      const specRes = await hub.scrape({
        url: 'https://bikeschematics.example.com/specs/bafang-m600',
        formats: ['markdown', 'product', { type: 'json', schema: { type: 'object', properties: { sku: { type: 'string' }, price: { type: 'number' } } } }],
        discoverLlmsTxt: false,
      });
      assert.equal(specRes.status, 200);
      assert.equal(specRes.body.product?.url, 'https://bikeschematics.example.com/parts/bafang-m600');
      assert.equal(specRes.body.product?.sku, 'BF-M600-85');
      assert.equal(specRes.body.json?.sku, 'BF-M600-85');

      // 5. jsonFilter cache isolation
      const invPlain = await hub.scrape({
        url: 'https://fleet-inventory.example.com/catalog.json',
        maxAgeMs: 600_000,
        discoverLlmsTxt: false,
      });
      assert.equal(invPlain.status, 200);
      assert.match(invPlain.body.markdown, /City Lite 50/);

      const invFiltered = await hub.scrape({
        url: 'https://fleet-inventory.example.com/catalog.json',
        maxAgeMs: 600_000,
        jsonFilter: 'team=85Nm',
        discoverLlmsTxt: false,
      });
      assert.equal(invFiltered.status, 200);
      assert.equal(invFiltered.body.cached, false);
      assert.match(invFiltered.body.markdown, /Commuter 85/);
      assert.equal(invFiltered.body.markdown.includes('City Lite 50'), false);

      const invPlainReplay = await hub.scrape({
        url: 'https://fleet-inventory.example.com/catalog.json',
        maxAgeMs: 600_000,
        discoverLlmsTxt: false,
      });
      assert.equal(invPlainReplay.status, 200);
      assert.equal(invPlainReplay.body.cached, true);
      assert.match(invPlainReplay.body.markdown, /City Lite 50/);
    });
  });

  // Scenario 2: Product Compliance & Regulatory Safety Audit
  test('T4.02: Scenario 2 — Product Compliance & Regulatory Safety Audit (F04, F05, F06, F07, F23, F30, F35, F36)', async () => {
    const router = createOutboundRouter();

    router.json('https://www.federalregister.gov/api/v1/documents/2024-00001.json', F04_FEDERAL_REGISTER.doc2024_00001);
    router.json(
      (u) => u.hostname === 'www.saferproducts.gov' && u.pathname === '/RestWebServices/Recall' && u.searchParams.get('RecallNumber') === '24123',
      F05_CPSC_RECALLS.saferProductsRecall24123,
    );
    router.json('https://www.saferproducts.gov/RestWebServices/Recall?format=json', [
      { RecallID: 1, RecallNumber: '00001', Title: 'UNFILTERED_DUMP' },
    ]);
    router.html('https://www.govinfo.gov/content/pkg/CFR-2023-title16-vol2/html/CFR-2023-title16-vol2.htm', F06_GOVINFO.cfrHtm);
    router.html('https://www.govinfo.gov/app/details/CFR-2023-title16-vol2', F06_GOVINFO.angularSpaShell);
    router.setRobots('eur-lex.europa.eu', 'User-agent: *\nDisallow: /legal-content/*/TXT/DOC/\nAllow: /\n');
    router.html(
      (u) => u.hostname === 'eur-lex.europa.eu' && u.pathname === '/legal-content/EN/TXT/HTML/' && u.searchParams.get('uri') === 'CELEX:32023R1542',
      F07_EURLEX.enBatteryRegulationHtml,
    );
    router.setRobots('www.nfpa.org', F30_NFPA.robotsTxt);
    router.html('https://www.nfpa.org/codes-and-standards/nfpa-70-standard-development/70', F30_NFPA.nextDataHtml('NFPA 855 Energy Storage'));
    router.html('https://www.law.cornell.edu/cfr/text/16/part-1512', F35_D1_HIGH_ROI.cornellCfrHtml);
    router.json('https://vpic.nhtsa.dot.gov/api/vehicles/decodevinvalues/1HGCM82633A004352?format=json', F23_NHTSA_FCC.vpicVinJson);
    router.status('https://api.nhtsa.gov/robots.txt', 403, 'Forbidden');
    router.setRobots('fccid.io', F23_NHTSA_FCC.fccRobotsTxt);
    router.html('https://fccid.io/BCG-E3542A', F23_NHTSA_FCC.fccHtml);

    // Blocked regulatory targets
    router.setRobots('up.codes', 'User-agent: *\nDisallow: /\n');
    router.html('https://up.codes/codes/ca', '<html><body>Blocked</body></html>');
    router.setRobots('www.ecfr.gov', 'User-agent: *\nDisallow: /api/\nAllow: /\n');
    router.json('https://www.ecfr.gov/api/versioner/v1/full/2026-01-01/title-16.xml', { blocked: true });
    router.status('https://www.osha.gov/laws-regs/standardinterpretations/2023-01-01', 403, 'Just a moment...', {
      'cf-mitigated': 'challenge',
      server: 'cloudflare',
    });

    await withFreshHub({ router }, async (hub) => {
      // 1. Batch extract compliant US regulatory sources
      const extRes = await hub.extract({
        urls: [
          'https://www.federalregister.gov/documents/2024/01/02/2024-00001/safety-standard-for-lithium-ion-ebike-batteries',
          'https://www.govinfo.gov/app/details/CFR-2023-title16-vol2',
          'https://www.law.cornell.edu/cfr/text/16/part-1512',
          'https://www.nfpa.org/codes-and-standards/nfpa-70-standard-development/70',
        ],
        query: 'lithium battery 16 CFR bicycles',
        chunksPerSource: 2,
      });
      assert.equal(extRes.status, 200);
      assert.equal(extRes.body.results.length, 4);
      assert.equal(extRes.body.failedResults.length, 0);

      // 2. Scrape CPSC recall, EUR-Lex, vPIC VIN, FCC ID
      const cpscRes = await hub.scrape({
        url: 'https://www.saferproducts.gov/RestWebServices/Recall?RecallNumber=24123&format=json',
        discoverLlmsTxt: false,
      });
      assert.equal(cpscRes.status, 200);
      assert.equal(cpscRes.body.extractorId, 'cpsc-recalls');
      assert.match(cpscRes.body.markdown, /UL-2271/);

      const eurRes = await hub.scrape({
        url: 'https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32023R1542',
        discoverLlmsTxt: false,
      });
      assert.equal(eurRes.status, 200);
      assert.equal(eurRes.body.extractorId, 'eur-lex');
      assert.equal(router.countRequests('eur-lex.europa.eu', '/legal-content/EN/TXT/DOC/'), 0);

      const vinRes = await hub.scrape({
        url: 'https://vpic.nhtsa.dot.gov/api/vehicles/decodevinvalues/1HGCM82633A004352?format=json',
        discoverLlmsTxt: false,
      });
      assert.equal(vinRes.status, 200);
      assert.match(vinRes.body.markdown, /HONDA/);

      const fccRes = await hub.scrape({
        url: 'https://fccid.io/BCG-E3542A',
        discoverLlmsTxt: false,
      });
      assert.equal(fccRes.status, 200);
      assert.equal(fccRes.body.extractorId, 'fcc-id');

      // 3. Negative guard sweeps
      const unfilteredCpsc = await hub.scrape({
        url: 'https://www.saferproducts.gov/RestWebServices/Recall?format=json',
        discoverLlmsTxt: false,
      });
      assert.notEqual(unfilteredCpsc.body.extractorId, 'cpsc-recalls');

      const upRes = await hub.scrape({ url: 'https://up.codes/codes/ca', discoverLlmsTxt: false });
      assert.equal(upRes.status, 422);
      assert.equal(router.countRequests('up.codes', '/codes'), 0);

      const ecfrRes = await hub.scrape({ url: 'https://www.ecfr.gov/api/versioner/v1/full/2026-01-01/title-16.xml', discoverLlmsTxt: false });
      assert.equal(ecfrRes.status, 422);
      assert.equal(router.countRequests('www.ecfr.gov', '/api/'), 0);

      const nfpaDisallowed = await hub.scrape({ url: 'https://www.nfpa.org/en/codes', discoverLlmsTxt: false });
      assert.equal(nfpaDisallowed.status, 422);
      assert.equal(router.countRequests('www.nfpa.org', '/en/'), 0);

      const fccDisallowed = await hub.scrape({ url: 'https://fccid.io/ViewExhibitReport.cfm?id=1', discoverLlmsTxt: false });
      assert.equal(fccDisallowed.status, 422);
      assert.equal(router.countRequests('fccid.io', '/ViewExhibitReport.cfm'), 0);

      const oshaRes = await hub.scrape({ url: 'https://www.osha.gov/laws-regs/standardinterpretations/2023-01-01', discoverLlmsTxt: false });
      assert.equal(oshaRes.status, 403);

      const nhtsaApiRes = await hub.scrape({ url: 'https://api.nhtsa.gov/recalls/recallsByVehicle?make=honda&model=accord&modelYear=2020', discoverLlmsTxt: false });
      assert.ok(nhtsaApiRes.status === 403 || nhtsaApiRes.status === 422);
    });
  });

  // Scenario 3: Open-Source Vulnerability & Package Supply-Chain Triage
  test('T4.03: Scenario 3 — Open-Source Vulnerability & Package Supply-Chain Triage (F15, F16, F17, F18, F19, F20, F36)', async () => {
    const router = createOutboundRouter();

    router.json('https://api.osv.dev/v1/vulns/GHSA-jfh8-c2jp-5v3q', F20_OSV.ghsaVulnJson(3));
    router.json('https://registry.terraform.io/v1/providers/hashicorp/aws', {
      ...F15_TERRAFORM.providerJson,
      id: 'hashicorp/aws/5.40.0',
      name: 'aws',
      version: '5.40.0',
    });
    router.json('https://registry.terraform.io/v1/modules/terraform-aws-modules/vpc/aws', F15_TERRAFORM.moduleJson);
    router.json('https://hub.docker.com/v2/repositories/library/alpine/', F16_DOCKER_HUB.alpineRepoJson);
    router.json('https://hub.docker.com/v2/repositories/library/alpine/tags?page_size=25', F16_DOCKER_HUB.tagsJson);
    router.json(
      (u) => u.hostname === 'search.maven.org' && u.pathname === '/solrsearch/select' && u.search.includes('log4j-core'),
      {
        ...F17_MAVEN_CENTRAL.guavaSolrJson,
        response: {
          numFound: 1,
          docs: [{ id: 'org.apache.logging.log4j:log4j-core', g: 'org.apache.logging.log4j', a: 'log4j-core', latestVersion: '2.23.1', p: 'jar', versionCount: 80 }],
        },
      },
    );
    router.json('https://api.nuget.org/v3/registration5-gz-semver2/newtonsoft.json/index.json', F18_NUGET.newtonsoftIndexJson);
    router.json('https://formulae.brew.sh/api/formula/jq.json', F19_HOMEBREW.jqFormulaJson);
    router.json('https://formulae.brew.sh/api/cask/iterm2.json', F19_HOMEBREW.iterm2CaskJson);

    // Poisoned cross-host redirect
    router.redirect('https://hub.docker.com/v2/repositories/evil/app/', 'https://evil-cdn.example.com/app.json', 302);
    router.json('https://evil-cdn.example.com/app.json', { name: 'EVIL_APP_MARKER' });
    router.html('https://hub.docker.com/r/evil/app', '<html><body><main><h1>evil/app</h1><p>Fallback HTML.</p></main></body></html>');

    await withFreshHub({ router }, async (hub) => {
      // 1. Batch /v1/extract across 6 ecosystems
      const extRes = await hub.extract({
        urls: [
          'https://osv.dev/vulnerability/GHSA-jfh8-c2jp-5v3q',
          'https://registry.terraform.io/providers/hashicorp/aws',
          'https://hub.docker.com/_/alpine',
          'https://central.sonatype.com/artifact/org.apache.logging.log4j/log4j-core',
          'https://www.nuget.org/packages/Newtonsoft.Json',
          'https://formulae.brew.sh/formula/jq',
        ],
        query: 'version fixed 2.15.0 3.20.3',
        chunksPerSource: 3,
      });
      assert.equal(extRes.status, 200);
      assert.equal(extRes.body.results.length, 6);

      // 2. Individual scrapes for /tags, module, cask, NuGet lowercasing
      const tagsRes = await hub.scrape({ url: 'https://hub.docker.com/_/alpine/tags', discoverLlmsTxt: false });
      assert.equal(tagsRes.status, 200);
      assert.equal(tagsRes.body.extractorId, 'docker-hub');
      assert.match(tagsRes.body.markdown, /3\.20\.3/);

      const modRes = await hub.scrape({ url: 'https://registry.terraform.io/modules/terraform-aws-modules/vpc/aws', discoverLlmsTxt: false });
      assert.equal(modRes.status, 200);
      assert.equal(modRes.body.extractorId, 'terraform-registry');
      assert.match(modRes.body.markdown, /cidr/);

      const caskRes = await hub.scrape({ url: 'https://formulae.brew.sh/cask/iterm2', discoverLlmsTxt: false });
      assert.equal(caskRes.status, 200);
      assert.equal(caskRes.body.extractorId, 'homebrew-formulae');
      assert.match(caskRes.body.markdown, /iTerm2/);

      const nugetRes = await hub.scrape({ url: 'https://www.nuget.org/packages/Newtonsoft.Json', discoverLlmsTxt: false });
      assert.equal(nugetRes.status, 200);
      assert.equal(nugetRes.body.extractorId, 'nuget-gallery');
      assert.ok(router.countRequests('api.nuget.org', '/v3/registration5-gz-semver2/newtonsoft.json/index.json') >= 1);

      // 3. Cross-host poisoned redirect + IMDS SSRF guard
      const poisonRes = await hub.scrape({ url: 'https://hub.docker.com/r/evil/app', discoverLlmsTxt: false });
      assert.equal(poisonRes.status, 200);
      assert.equal(poisonRes.body.markdown.includes('EVIL_APP_MARKER'), false);

      const ssrfRes = await hub.scrape({ url: 'https://169.254.169.254/latest/meta-data/', discoverLlmsTxt: false });
      assert.equal(ssrfRes.status, 400);
      assert.equal(ssrfRes.body.error, 'invalid_url');
      assert.equal(router.countRequests('169.254.169.254'), 0);
    });
  });

  // Scenario 4: Multi-Source Technical Support & Community Knowledge Graph
  test('T4.04: Scenario 4 — Multi-Source Technical Support & Community Knowledge Graph (F01, F08, F13, F24, F34, F35, F36)', async () => {
    const router = createOutboundRouter();

    router.json('https://acme.zendesk.com/api/v2/help_center/en-us/articles/4408886858138.json', F01_ZENDESK.articleJson);
    router.json('https://acme.zendesk.com/api/v2/help_center/en-us/articles/4408886858138/attachments.json', F01_ZENDESK.attachmentsJson);

    router.setRobots('endless-sphere.com', 'User-agent: *\nDisallow: /forums/\nAllow: /sphere/threads/\n');
    router.html('https://endless-sphere.com/sphere/threads/mid-drive-thermal.12045/', F08_XENFORO.threadHtml('Mid-Drive Thermal Cutout'));
    router.html('https://endless-sphere.com/forums/index', '<html><body>Disallowed</body></html>');

    router.html('https://docs.sram.com/en-US/publications/1zPBXB1BWfF7E1mLreIuVi/eagle-axs-manual', F13_SRAM_BOSCH_HELP.sramDocsHtml);
    router.setRobots('help.bosch-ebike.com', 'User-agent: *\nDisallow: /api/*\nAllow: /\n');
    router.html('https://help.bosch-ebike.com/en/help-center/smart-system-error-503', F13_SRAM_BOSCH_HELP.boschHelpHtml);

    router.html('https://www.tq-ebike.com/en/help-support/hpr50', F35_D1_HIGH_ROI.tqEbikeHtml);
    router.html('https://www.sram.com/en/sram/models/fc-red-e1', F35_D1_HIGH_ROI.sramModelHtml);

    router.setRobots('www.youtube.com', F34_YOUTUBE.robotsTxt);
    router.html('https://www.youtube.com/watch?v=dQw4w9WgXcQ', F34_YOUTUBE.watchHtml());

    router.json('https://www.wikidata.org/wiki/Special:EntityData/Q42.json', F24_WIKIDATA_OPENLIBRARY.wikidataQ42Json);
    router.setRobots('openlibrary.org', F24_WIKIDATA_OPENLIBRARY.openLibraryRobotsTxt);
    router.redirect('https://openlibrary.org/isbn/9780140328721.json', 'https://openlibrary.org/books/OL7353617M.json', 302);
    router.json('https://openlibrary.org/books/OL7353617M.json', F24_WIKIDATA_OPENLIBRARY.openLibraryBookJson());

    await withFreshHub({ router }, async (hub) => {
      const zdRes = await hub.scrape({
        url: 'https://acme.zendesk.com/hc/en-us/articles/4408886858138-getting-started',
        formats: ['markdown', 'links'],
        discoverLlmsTxt: false,
      });
      assert.equal(zdRes.status, 200);
      assert.equal(zdRes.body.extractorId, 'zendesk-hc');
      assert.ok((zdRes.body.links ?? []).some((l) => l.includes('Fleet_Manual_v4.pdf')));

      const xfRes = await hub.scrape({
        url: 'https://endless-sphere.com/sphere/threads/mid-drive-thermal.12045/',
        discoverLlmsTxt: false,
      });
      assert.equal(xfRes.status, 200);
      assert.equal(xfRes.body.extractorId, 'xenforo-thread');
      assert.equal(xfRes.body.markdown.includes('Signature Promo Spam'), false);

      const sramDocsRes = await hub.scrape({
        url: 'https://docs.sram.com/en-US/publications/1zPBXB1BWfF7E1mLreIuVi/eagle-axs-manual',
        discoverLlmsTxt: false,
      });
      assert.equal(sramDocsRes.status, 200);
      assert.equal(sramDocsRes.body.extractorId, 'sram-docs');

      const boschRes = await hub.scrape({
        url: 'https://help.bosch-ebike.com/en/help-center/smart-system-error-503',
        discoverLlmsTxt: false,
      });
      assert.equal(boschRes.status, 200);
      assert.equal(boschRes.body.extractorId, 'bosch-ebike-help');
      assert.equal(boschRes.body.markdown.includes('data:image/webp;base64'), false);
      assert.equal(router.countRequests('help.bosch-ebike.com', '/api'), 0);

      const wdRes = await hub.scrape({ url: 'https://www.wikidata.org/wiki/Q42', discoverLlmsTxt: false });
      assert.equal(wdRes.status, 200);
      assert.equal(wdRes.body.extractorId, 'wikidata-openlibrary');

      const olRes = await hub.scrape({ url: 'https://openlibrary.org/isbn/9780140328721', discoverLlmsTxt: false });
      assert.equal(olRes.status, 200);
      assert.equal(olRes.body.extractorId, 'wikidata-openlibrary');
      assert.equal(router.countRequests('openlibrary.org', '/api'), 0);

      // Batch extract across support & community graph
      const extRes = await hub.extract({
        urls: [
          'https://acme.zendesk.com/hc/en-us/articles/4408886858138-getting-started',
          'https://endless-sphere.com/sphere/threads/mid-drive-thermal.12045/',
          'https://help.bosch-ebike.com/en/help-center/smart-system-error-503',
          'https://www.tq-ebike.com/en/help-support/hpr50',
        ],
        query: 'firmware torque PowerTube',
      });
      assert.equal(extRes.status, 200);
      assert.equal(extRes.body.results.length, 4);

      // Negative disallowed paths
      assert.equal((await hub.scrape({ url: 'https://endless-sphere.com/forums/index', discoverLlmsTxt: false })).status, 422);
      assert.equal((await hub.scrape({ url: 'https://openlibrary.org/api/books', discoverLlmsTxt: false })).status, 422);
      assert.equal((await hub.scrape({ url: 'https://help.bosch-ebike.com/api/v1/search', discoverLlmsTxt: false })).status, 422);
      assert.equal(router.countRequests('endless-sphere.com', '/forums/'), 0);
      assert.equal(router.countRequests('openlibrary.org', '/api'), 0);
      assert.equal(router.countRequests('help.bosch-ebike.com', '/api'), 0);

      // Connect Mock Agent last to verify YouTube /watch skips auto-render-1
      const agent = await hub.connectMockAgent({
        onDispatch: async (_msg, helpers) => {
          const req0 = helpers.call.requests?.[0] ?? {};
          await helpers.sendReply({
            results: [{ id: req0.id, url: req0.url, finalUrl: req0.url, status: 200, outcome: 'ok', contentType: 'text/html', body: F34_YOUTUBE.watchHtml(), bodyEncoding: 'utf-8' }],
          });
        },
      });
      const ytRes = await hub.scrape({
        url: 'https://www.youtube.com/watch?v=dQw4w9WgXcQ',
        discoverLlmsTxt: false,
      });
      assert.equal(ytRes.status, 200);
      assert.equal(ytRes.body.rendered, false);
      assert.equal(agent.frames.filter((f) => f.call.requests?.[0]?.id === 'auto-render-1').length, 0);
      assert.equal(router.countRequests('www.youtube.com', '/api/timedtext'), 0);
    });
  });

  // Scenario 5: Multi-ATS Talent & Job-Board Pipeline
  test('T4.05: Scenario 5 — Multi-ATS Talent & Job-Board Pipeline (F21, F22, F36)', async () => {
    const router = createOutboundRouter();

    router.status(
      (u) => u.hostname === 'glean.wd5.myworkdayjobs.com' && u.pathname.includes('/wday/cxs/'),
      422,
      JSON.stringify(F21_WORKDAY_ICIMS.workdayCxs422),
      { 'content-type': 'application/json' },
    );
    router.html(
      'https://temporal.com/careers',
      '<html><body><a href="https://temporal.wd5.myworkdayjobs.com/en-US/External">Careers</a></body></html>',
    );
    router.json(
      (u) => u.hostname === 'temporal.wd5.myworkdayjobs.com' && u.pathname.includes('/wday/cxs/'),
      F21_WORKDAY_ICIMS.workdayCxsJobsOk,
    );
    router.html('https://careers-trail.icims.com/jobs/search?ss=1&in_iframe=1', F21_WORKDAY_ICIMS.icimsSearchIframeHtml.replaceAll('careers-acme.icims.com', 'careers-trail.icims.com'));
    router.html('https://careers-trail.icims.com/jobs/4123/firmware-engineer/job?in_iframe=1', F21_WORKDAY_ICIMS.icimsJobIframeHtml);

    router.setRobots('recruiting.ultipro.com', F22_UKG_PAYLOCITY_DOVER.ukgRobotsTxt);
    router.html('https://recruiting.ultipro.com/ACM1001/JobBoard/11111111-2222-3333-4444-555555555555/', F22_UKG_PAYLOCITY_DOVER.ukgJobBoardHtml);
    router.html('https://recruiting.ultipro.com/ACM1001/JobBoardView/1', '<html><body>Disallowed</body></html>');

    router.json('https://recruiting.paylocity.com/recruiting/api/feed/jobs/aaaa-bbbb-cccc', F22_UKG_PAYLOCITY_DOVER.paylocityFeedJson);
    router.html('https://recruiting.paylocity.com/Recruiting/Jobs/All/aaaa-bbbb-cccc', F22_UKG_PAYLOCITY_DOVER.paylocityHtml);

    router.setRobots('app.dover.com', F22_UKG_PAYLOCITY_DOVER.doverRobotsTxt);
    router.html('https://app.dover.com/jobs/voltcycle', F22_UKG_PAYLOCITY_DOVER.doverHtml);

    await withFreshHub({ router }, async (hub) => {
      // 1. Glean wd5 fast-exit
      const gleanRes = await hub.scrape({
        url: 'https://glean.wd5.myworkdayjobs.com/en-US/Glean?q=engineer&offset=20',
        discoverLlmsTxt: false,
      });
      assert.equal(gleanRes.status, 404);
      assert.equal(gleanRes.body.outcome, 'not_found');

      // 2. Scrape iCIMS, UKG, Paylocity, Dover boards
      const icimsRes = await hub.scrape({ url: 'https://careers-trail.icims.com/jobs/search?ss=1&in_iframe=1', discoverLlmsTxt: false });
      assert.equal(icimsRes.status, 200);
      assert.match(icimsRes.body.markdown, /Firmware Engineer/);

      const ukgRes = await hub.scrape({
        url: 'https://recruiting.ultipro.com/ACM1001/JobBoard/11111111-2222-3333-4444-555555555555/',
        discoverLlmsTxt: false,
      });
      assert.equal(ukgRes.status, 200);
      assert.ok((ukgRes.body.jobs ?? ukgRes.body.records ?? []).length >= 2);

      const payRes = await hub.scrape({
        url: 'https://recruiting.paylocity.com/Recruiting/Jobs/All/aaaa-bbbb-cccc',
        discoverLlmsTxt: false,
      });
      assert.equal(payRes.status, 200);
      assert.match(payRes.body.markdown, /Product Safety Engineer/);

      const doverRes = await hub.scrape({
        url: 'https://app.dover.com/jobs/voltcycle',
        discoverLlmsTxt: false,
      });
      assert.equal(doverRes.status, 200);
      assert.match(doverRes.body.markdown, /Founding Robotics Engineer/);

      // 3. POST /v1/jobs search + verify mode
      const jobsSearch = await hub.jobs({
        domains: ['temporal.com'],
        query: 'Engineer',
      });
      assert.equal(jobsSearch.status, 200);
      assert.ok(Array.isArray(jobsSearch.body.jobs) && jobsSearch.body.jobs.length >= 1);

      const verifyRes = await hub.jobs({
        mode: 'verify',
        urls: [
          'https://careers-trail.icims.com/jobs/4123/firmware-engineer/job?in_iframe=1',
          'https://glean.wd5.myworkdayjobs.com/en-US/Glean/job/Remote/Role_JR1',
        ],
      });
      assert.equal(verifyRes.status, 200);
      assert.equal(verifyRes.body.checked, 2);

      // 4. Negative robots.txt enforcement
      assert.equal((await hub.scrape({ url: 'https://recruiting.ultipro.com/ACM1001/JobBoardView/1', discoverLlmsTxt: false })).status, 422);
      assert.equal((await hub.scrape({ url: 'https://app.dover.com/api/v1/job-board/jobs/voltcycle', discoverLlmsTxt: false })).status, 422);
      assert.equal(router.countRequests('recruiting.ultipro.com', '/JobBoardView'), 0);
      assert.equal(router.countRequests('app.dover.com', '/api'), 0);
    });
  });

  // Scenario 6: Commerce Long-Tail & Large-Payload Edge Resilience
  test('T4.06: Scenario 6 — Commerce Long-Tail & Large-Payload Edge Resilience (F09, F10, F12, F26, F27, F29, F33, F36)', async () => {
    const router = createOutboundRouter();

    router.html('https://studio-velo.example.com/shop', F09_SQUARESPACE.shopHtml);
    router.json('https://studio-velo.example.com/shop?format=json-pretty', F09_SQUARESPACE.shopJsonPretty);
    router.html('https://pedal-gear.example.com/trailblazer-hydraulic-brake-kit/', F10_BIGCOMMERCE.productHtml(true));
    router.xml('https://pedal-gear.example.com/xmlsitemap.php', F10_BIGCOMMERCE.xmlSitemap);
    router.html(
      'https://euro-oem.example.de/magura-mt7-pro.html',
      F12_SHOPWARE_MAGENTO.magentoSwatchHtml.replace(
        '"currencyFormat": "$%s"',
        '"index": { "2001": { "93": "10" }, "2002": { "93": "11" } },\n            "currencyFormat": "$%s"',
      ),
    );
    router.html('https://euro-oem.example.de/supernova-m99-mini.html', F12_SHOPWARE_MAGENTO.shopware6Html);
    router.setRobots('www.bicycleretailer.com', F33_BICYCLE_RETAILER.robotsTxt);
    router.html('https://www.bicycleretailer.com/industry-news/2026/11/01/ebike-battery-rules', F33_BICYCLE_RETAILER.articleHtml);
    router.html('https://www.bicycleretailer.com/admin/settings', '<html><body>Admin</body></html>');
    router.xml('https://www.bicycleretailer.com/rss.xml', F33_BICYCLE_RETAILER.rssXml);

    const xml5Mib = `<urlset>${over4Mib('<url><loc>https://big-sitemap.example.com/p</loc></url>')}</urlset>`;
    const pdf5Mib = Buffer.concat([Buffer.from('%PDF-1.7\n%EOF\n', 'utf8'), Buffer.alloc(5 * 1024 * 1024, 0x20)]);
    // Use 0xff non-UTF-8 bytes so base64 expansion exceeds 18 MiB wire budget.
    const pdf15Mib = Buffer.alloc(15 * 1024 * 1024, 0xff);

    await withFreshHub({ router }, async (hub) => {
      // 1. Long-tail commerce & news scrapes
      const sqRes = await hub.scrape({ url: 'https://studio-velo.example.com/shop', discoverLlmsTxt: false });
      assert.equal(sqRes.status, 200);
      assert.equal(sqRes.body.extractorId, 'squarespace-commerce');

      const bcRes = await hub.scrape({ url: 'https://pedal-gear.example.com/trailblazer-hydraulic-brake-kit/', discoverLlmsTxt: false });
      assert.equal(bcRes.status, 200);
      assert.equal(bcRes.body.extractorId, 'bigcommerce-store');

      const mgRes = await hub.scrape({ url: 'https://euro-oem.example.de/magura-mt7-pro.html', discoverLlmsTxt: false });
      assert.equal(mgRes.status, 200);
      assert.equal(mgRes.body.extractorId, 'shopware-magento');
      assert.ok(Array.isArray(mgRes.body.records) && mgRes.body.records.length >= 1);

      const swRes = await hub.scrape({ url: 'https://euro-oem.example.de/supernova-m99-mini.html', formats: ['markdown', 'product'], discoverLlmsTxt: false });
      assert.equal(swRes.status, 200);
      assert.equal(swRes.body.product?.sku, 'SN-M99-MINI25');

      const brRes = await hub.scrape({ url: 'https://www.bicycleretailer.com/rss.xml', discoverLlmsTxt: false });
      assert.equal(brRes.status, 200);
      assert.match(brRes.body.markdown, /CPSC Finalizes E-Bike Battery Safety Guidance/);

      const brBlocked = await hub.scrape({ url: 'https://www.bicycleretailer.com/admin/settings', discoverLlmsTxt: false });
      assert.equal(brBlocked.status, 422);
      assert.equal(brBlocked.body.ok, false);
      assert.match(String(brBlocked.body.error ?? brBlocked.body.problem ?? ''), /robots/i);
      assert.equal(router.countRequests('www.bicycleretailer.com', '/admin/'), 0);

      // 2. Large-payload Mock Agent tests (L-02, L-03, L-05)
      let bigXmlSha = '';
      let hugePdfSha = '';
      let autoRenderCap;
      await hub.connectMockAgent({
        onDispatch: async (_msg, helpers) => {
          const req0 = helpers.call.requests?.[0] ?? {};
          const u = String(req0.url ?? '');
          if (req0.id === 'auto-render-1') {
            autoRenderCap = helpers.call.options?.maxInlineBodyBytes;
            await helpers.sendReply({
              results: [
                {
                  id: req0.id,
                  url: u,
                  finalUrl: u,
                  status: 200,
                  outcome: 'ok',
                  contentType: 'text/html',
                  body: `<html><body><main><h1>Bike Configurator</h1><p>${'spec '.repeat(60)}</p></main></body></html>`,
                  bodyEncoding: 'utf-8',
                },
              ],
            });
            return;
          }
          if (u.includes('big-sitemap.example.com')) {
            const art = await helpers.uploadArtifact(xml5Mib, { requestId: req0.id });
            bigXmlSha = art.blobSha256;
            await helpers.sendReply({
              results: [{ id: req0.id, url: u, finalUrl: u, status: 200, outcome: 'ok', contentType: 'application/xml', bodyOmitted: true, artifact: art }],
            });
            return;
          }
          if (u.includes('manual-pdf.example.com')) {
            const art = await helpers.uploadArtifact(pdf5Mib, { requestId: req0.id });
            await helpers.sendReply({
              results: [{ id: req0.id, kind: 'binary', url: u, finalUrl: u, status: 200, outcome: 'ok', contentType: 'application/pdf', bodyOmitted: true, artifact: art }],
            });
            return;
          }
          if (u.includes('huge-pdf.example.com')) {
            const art = await helpers.uploadArtifact(pdf15Mib, { requestId: req0.id });
            hugePdfSha = art.blobSha256;
            await helpers.sendReply({
              results: [{ id: req0.id, kind: 'binary', url: u, finalUrl: u, status: 200, outcome: 'ok', contentType: 'application/pdf', bodyOmitted: true, artifact: art }],
            });
            return;
          }
          await helpers.sendReply({
            results: [{ id: req0.id, url: u, finalUrl: u, status: 200, outcome: 'ok', contentType: 'text/html', body: '<html><body><div id="root"></div><script src="/app.js"></script></body></html>', bodyEncoding: 'utf-8' }],
          });
        },
      });

      const l02Res = await hub.scrape({ url: 'https://big-sitemap.example.com/sitemap.xml', target: 'agent', discoverLlmsTxt: false });
      assert.equal(l02Res.status, 200);
      assert.equal(l02Res.body.edgeBudgetExceeded, true);
      assert.equal(l02Res.body.artifactId, bigXmlSha);

      const l03Ok = await hub.scrape({ url: 'https://manual-pdf.example.com/service-guide.pdf', target: 'agent', formats: ['rawBase64'], parsers: [], discoverLlmsTxt: false });
      assert.equal(l03Ok.status, 200);
      assert.equal(Buffer.from(l03Ok.body.rawBase64, 'base64').byteLength, pdf5Mib.byteLength);

      const l03Huge = await hub.scrape({ url: 'https://huge-pdf.example.com/full-catalog.pdf', target: 'agent', formats: ['rawBase64'], parsers: [], discoverLlmsTxt: false });
      assert.equal(l03Huge.status, 200);
      assert.equal(l03Huge.body.rawBase64, undefined);
      assert.equal(l03Huge.body.artifactId, hugePdfSha);

      const l05Res = await hub.scrape({ url: 'https://spa-store.example.com/configurator', discoverLlmsTxt: false });
      assert.equal(l05Res.status, 200);
      assert.equal(l05Res.body.rendered, true);
      assert.equal(l05Res.body.renderedVia, 'browser-auto');
      assert.equal(autoRenderCap, MAX_WASM_INPUT_BYTES);
    });
  });

  // Scenario 7: Multi-URL /v1/extract & /v1/crawl Mixed-Origin Batch with Politeness Enforcement
  test('T4.07: Scenario 7 — Multi-URL /v1/extract & /v1/crawl Mixed-Origin Batch with Politeness Enforcement (F01, F04, F15, F25, F31, F33, F36)', async () => {
    const router = createOutboundRouter();

    router.json('https://acme.zendesk.com/api/v2/help_center/en-us/articles/4408886858138.json', F01_ZENDESK.articleJson);
    router.json('https://www.federalregister.gov/api/v1/documents/2024-00001.json', F04_FEDERAL_REGISTER.doc2024_00001);
    router.json('https://registry.terraform.io/v1/providers/hashicorp/aws', { ...F15_TERRAFORM.providerJson, name: 'aws', version: '5.40.0' });
    router.json('https://mixed-feed.example.com/alerts.json', [
      { id: 'a1', severity: 'high', title: 'Firmware Safety Alert' },
      { id: 'a2', severity: 'low', title: 'Routine Firmware Notice' },
    ]);

    router.setRobots('up.codes', 'User-agent: *\nDisallow: /\n');
    router.html('https://up.codes/codes/ca', '<html><body>Blocked</body></html>');
    router.status('https://www.osha.gov/regs', 403, 'Just a moment...', { 'cf-mitigated': 'challenge', server: 'cloudflare' });

    router.setRobots('www.giant-bicycles.com', F31_GIANT_LIV.robotsTxt);
    const giantSeed = F31_GIANT_LIV.bikeHtml('Giant', 'Defy Advanced 1').replace(
      '</main>',
      '<a href="https://www.giant-bicycles.com/us/shop/checkout">Shop</a><a href="https://www.giant-bicycles.com/us/manuals">Manuals</a></main>',
    );
    router.html('https://www.giant-bicycles.com/us/defy-advanced-1', giantSeed);
    router.html('https://www.giant-bicycles.com/us/manuals', F31_GIANT_LIV.manualsHtml);
    router.html('https://www.giant-bicycles.com/us/shop/checkout', '<html><body>Disallowed Shop</body></html>');

    router.setRobots('www.bicycleretailer.com', 'User-agent: *\nCrawl-delay: 1\nDisallow: /private-drafts/\nAllow: /\n');
    const brSeed = F33_BICYCLE_RETAILER.listingHtml.replace(
      '</main>',
      '<a href="https://www.bicycleretailer.com/private-drafts/embargoed">Draft</a></main>',
    );
    router.html('https://www.bicycleretailer.com/industry-news', brSeed);
    router.html('https://www.bicycleretailer.com/industry-news/2026/11/01/ebike-battery-rules', F33_BICYCLE_RETAILER.articleHtml);
    router.html('https://www.bicycleretailer.com/private-drafts/embargoed', '<html><body>Embargoed</body></html>');

    await withFreshHub({ router }, async (hub) => {
      // 1. Mixed-origin /v1/extract with allowed twins, jsonFilter, robots disallow & 403 challenge
      const extRes = await hub.extract({
        urls: [
          'https://acme.zendesk.com/hc/en-us/articles/4408886858138-getting-started',
          'https://www.federalregister.gov/documents/2024/01/02/2024-00001/safety-standard-for-lithium-ion-ebike-batteries',
          'https://registry.terraform.io/providers/hashicorp/aws',
          'https://mixed-feed.example.com/alerts.json',
          'https://up.codes/codes/ca',
          'https://www.osha.gov/regs',
        ],
        query: 'safety firmware',
        jsonFilter: 'severity=high',
      });
      assert.equal(extRes.status, 200);
      assert.equal(extRes.body.results.length, 4);
      assert.equal(extRes.body.failedResults.length, 2);
      const alertsResult = extRes.body.results.find((r) => r.url.includes('alerts.json'));
      assert.ok(alertsResult, 'Expected alerts.json in results[]');
      assert.match(JSON.stringify(alertsResult), /Firmware Safety Alert/);
      assert.equal(JSON.stringify(alertsResult).includes('Routine Firmware Notice'), false);
      assert.equal(router.countRequests('up.codes', '/codes'), 0);

      // 2. SSRF rejection in /v1/extract
      const ssrfBatch = await hub.extract({
        urls: ['https://127.0.0.1/admin'],
        query: 'admin',
      });
      assert.equal(ssrfBatch.status, 400);
      assert.equal(ssrfBatch.body.error, 'invalid_urls');
      assert.equal(router.countRequests('127.0.0.1'), 0);

      // 3. Crawl Giant skipping /us/shop/*
      const giantCrawl = await hub.crawl({
        url: 'https://www.giant-bicycles.com/us/defy-advanced-1',
        sync: true,
        limit: 4,
        maxDepth: 1,
        delay: 0,
        sitemap: 'skip',
      });
      assert.equal(giantCrawl.status, 200);
      assert.equal(giantCrawl.body.status, 'completed');
      const giantStatus = await hub.getCrawl(giantCrawl.body.id);
      assert.equal(giantStatus.status, 200);
      assert.ok(giantStatus.body.fetchedCount >= 1);
      assert.equal(router.countRequests('www.giant-bicycles.com', '/us/shop'), 0);

      // 4. Crawl BicycleRetailer skipping /private-drafts/
      const brCrawl = await hub.crawl({
        url: 'https://www.bicycleretailer.com/industry-news',
        sync: true,
        limit: 4,
        maxDepth: 1,
        delay: 0,
        sitemap: 'skip',
      });
      assert.equal(brCrawl.status, 200);
      assert.equal(brCrawl.body.status, 'completed');
      const brStatus = await hub.getCrawl(brCrawl.body.id);
      assert.equal(brStatus.status, 200);
      assert.ok(brStatus.body.fetchedCount >= 1);
      assert.equal(router.countRequests('www.bicycleretailer.com', '/private-drafts/'), 0);
    });
  });
});
