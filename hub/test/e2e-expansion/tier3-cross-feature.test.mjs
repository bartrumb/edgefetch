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

const over4Mib = (unit) => unit.repeat(Math.ceil((MAX_WASM_INPUT_BYTES + 64 * 1024) / unit.length));

async function getCrawlWithQuery(hub, crawlId, qs) {
  const res = await hub.fetch(`/v1/crawl/${encodeURIComponent(crawlId)}?${qs}`, {
    method: 'GET',
    headers: { authorization: `Bearer ${hub.callerToken}` },
  });
  const text = await res.text();
  return { status: res.status, body: text ? JSON.parse(text) : null };
}

// ============================================================================
// Suite 1: Commerce, Product Backfill (L-04) & Options-Cache (L-01) (T3.01–T3.11)
// ============================================================================
describe('Tier 3 — Commerce, Product Backfill (L-04) & Options-Cache (L-01)', () => {
  let router;
  let hub;

  before(async () => {
    router = createOutboundRouter();

    // T3.01: Shopify custom-domain product HTML + .json twin
    router.html(
      'https://voltride-t3.example.com/products/apex-commuter-500',
      `<!doctype html><html><head><title>Apex Commuter 500</title><script>window.Shopify = { shop: "voltride-t3.myshopify.com", currency: { active: "USD" } };</script></head><body><main><h1>Apex Commuter 500</h1><p>500W hub motor commuter e-bike.</p></main></body></html>`,
    );
    router.json('https://voltride-t3.example.com/products/apex-commuter-500.json', {
      product: {
        ...F02_SHOPIFY.collectionProductsJson.products[0],
      },
    });

    // T3.02: WooCommerce custom-domain product HTML + Store API with PII
    const wcProdWithPii = {
      ...F03_WOOCOMMERCE.storeProductsUsd[0],
      permalink: 'https://rideshop-t3.example.com/product/city-cruiser-st/',
      short_description: '<p>Lightweight urban step-through e-bike. Support: support@rideshop.example.com or 555-867-5309.</p>',
    };
    router.html(
      'https://rideshop-t3.example.com/product/city-cruiser-st/',
      `<!doctype html><html><head><title>City Cruiser ST - RideShop</title><meta name="generator" content="WooCommerce 9.3.1"></head><body class="single-product woocommerce"><main><h1>City Cruiser ST</h1><p>Urban commuter bike. Email support@rideshop.example.com or call 555-867-5309.</p></main></body></html>`,
    );
    router.json(
      (u) => u.hostname === 'rideshop-t3.example.com' && u.pathname === '/wp-json/wc/store/v1/products',
      [wcProdWithPii],
    );

    // T3.04: Microdata / Spec-table with relative itemprop="url"
    router.html(
      'https://bikeschematics-t3.example.com/specs/hub-m600',
      `<!doctype html><html><head><title>Bafang M600 Drive Unit</title></head><body><main itemscope itemtype="https://schema.org/Product"><h1 itemprop="name">Bafang M600 Drive Unit</h1><a itemprop="url" href="/parts/m600">Canonical Part</a><span itemprop="brand">Bafang</span><span itemprop="sku">BF-M600</span><div itemprop="offers" itemscope itemtype="https://schema.org/Offer"><meta itemprop="price" content="849.00" /><meta itemprop="priceCurrency" content="USD" /><link itemprop="availability" href="https://schema.org/InStock" /></div><table class="spec-table"><tr><th>SKU</th><td>BF-M600</td></tr><tr><th>Brand</th><td>Bafang</td></tr><tr><th>Price</th><td>$849.00</td></tr><tr><th>Availability</th><td>In Stock</td></tr></table></main></body></html>`,
    );

    // T3.05: Squarespace product with PII + ?format=json-pretty
    const sqProdWithPii = {
      item: {
        ...F09_SQUARESPACE.productJsonPretty.item,
        body: '<p>Chromoly steel front cargo rack. Call 555-234-5678 or email orders@urbancycle-t3.example.com.</p>',
      },
    };
    router.html('https://urbancycle-t3.example.com/shop/p/porteur-front-rack', F09_SQUARESPACE.shopHtml);
    router.json('https://urbancycle-t3.example.com/shop/p/porteur-front-rack?format=json-pretty', sqProdWithPii);

    // T3.06: BigCommerce Stencil BCData + links
    router.html('https://peakbikes-t3.example.com/trailblazer-hydraulic-brake-kit/', F10_BIGCOMMERCE.productHtml(true));

    // T3.07: SFCC Demandware + Product-Variation + geometry table
    router.html(
      'https://bikes-t3.example.com/us/en_US/bikes/domane-sl-6-gen-4/p/44751/',
      F11_SFCC.productHtml('bikes-t3.example.com'),
    );
    router.json(
      (u) => u.hostname === 'bikes-t3.example.com' && u.pathname.includes('Product-Variation'),
      F11_SFCC.productVariationJson,
    );

    // T3.08: Shopware 6 & Magento 2 with PII
    const shopwareWithPii = F12_SHOPWARE_MAGENTO.shopware6Html.replace(
      '</tbody>',
      '<tr><th>Support</th><td>service@oem-t3.example.de</td></tr></tbody>',
    );
    const magentoWithPii = F12_SHOPWARE_MAGENTO.magentoSwatchHtml
      .replace(
        '<h1>Magura MT7 Pro Disc Brake</h1>',
        '<h1>Magura MT7 Pro Disc Brake</h1><p>Tech desk: tech@parts-t3.example.com</p>',
      )
      .replace(
        '"currencyFormat": "$%s"',
        '"index": { "2001": { "93": "10" }, "2002": { "93": "11" } },\n            "currencyFormat": "$%s"',
      );
    router.html('https://oem-t3.example.de/supernova-m99-mini.html', shopwareWithPii);
    router.html('https://parts-t3.example.com/magura-mt7-pro.html', magentoWithPii);

    hub = await createHubInstance({ router });
  });

  after(async () => {
    await hub?.dispose();
  });

  test('T3.01: F02 + F28 (L-04) custom-domain Shopify HTML + .json backfills product & json schema', async () => {
    const res = await hub.scrape({
      url: 'https://voltride-t3.example.com/products/apex-commuter-500',
      formats: [
        'markdown',
        'product',
        { type: 'json', schema: { type: 'object', properties: { sku: { type: 'string' }, price: { type: 'number' }, brand: { type: 'string' } } } },
      ],
      discoverLlmsTxt: false,
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.extractorId, 'shopify');
    assert.ok(Array.isArray(res.body.records) && res.body.records.length >= 1);
    assert.equal(res.body.product?.sku, 'VR-APX-BLK');
    assert.equal(res.body.product?.price, 1599);
    assert.equal(res.body.product?.brand, 'VoltRide');
    assert.equal(res.body.product?.availability, 'InStock');
    assert.equal(res.body.product?.url, 'https://voltride-t3.example.com/products/apex-commuter-500');
    assert.equal(res.body.json?.sku, 'VR-APX-BLK');
    assert.equal(res.body.json?.price, 1599);
  });

  test('T3.02: F03 + F28 (L-04) + redactPii redacts WooCommerce Store API PII while keeping product SKU & price', async () => {
    const res = await hub.scrape({
      url: 'https://rideshop-t3.example.com/product/city-cruiser-st/',
      redactPii: true,
      formats: [
        'markdown',
        'product',
        { type: 'json', schema: { type: 'object', properties: { sku: { type: 'string' }, price: { type: 'number' }, description: { type: 'string' } } } },
      ],
      discoverLlmsTxt: false,
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.extractorId, 'woocommerce');
    assert.equal(res.body.markdown.includes('support@rideshop.example.com'), false);
    assert.equal(res.body.markdown.includes('555-867-5309'), false);
    assert.equal(JSON.stringify(res.body.records ?? []).includes('support@rideshop.example.com'), false);
    assert.equal(String(res.body.product?.description ?? '').includes('support@rideshop.example.com'), false);
    assert.equal(JSON.stringify(res.body.json ?? {}).includes('support@rideshop.example.com'), false);
    assert.equal(res.body.product?.sku, 'WC-CITY-ST');
    assert.equal(res.body.product?.price, 1499);
  });

  test('T3.03: F03 + F25 (L-01) + F36 WooCommerce robots.txt disallow blocks /other/ while jsonFilter isolates /roles.json cache', async () => {
    const localRouter = createOutboundRouter();
    localRouter.setRobots('ride1up-cat.example.com', 'User-agent: *\nDisallow: /product-category/other/\nAllow: /\n');
    localRouter.html('https://ride1up-cat.example.com/product-category/other/', F03_WOOCOMMERCE.categoryHtml('Other'));
    localRouter.html('https://ride1up-cat.example.com/product-category/ebikes/', F03_WOOCOMMERCE.categoryHtml('Electric Bikes'));
    localRouter.json(
      'https://ride1up-cat.example.com/wp-json/wc/store/v1/products?category=ebikes&per_page=50',
      F03_WOOCOMMERCE.storeProductsUsd,
    );
    localRouter.json('https://ride1up-cat.example.com/roles.json', F25_JSONFILTER_RECORDS);
    await withFreshHub({ router: localRouter }, async (localHub) => {
      const blocked = await localHub.scrape({
        url: 'https://ride1up-cat.example.com/product-category/other/',
        discoverLlmsTxt: false,
      });
      assert.equal(blocked.status, 422);
      assert.equal(localRouter.countRequests('ride1up-cat.example.com', '/product-category/other/'), 0);

      const wooOk = await localHub.scrape({
        url: 'https://ride1up-cat.example.com/product-category/ebikes/',
        discoverLlmsTxt: false,
      });
      assert.equal(wooOk.status, 200);
      assert.match(wooOk.body.markdown, /City Cruiser ST/);

      const plain = await localHub.scrape({
        url: 'https://ride1up-cat.example.com/roles.json',
        maxAgeMs: 600_000,
        discoverLlmsTxt: false,
      });
      assert.equal(plain.status, 200);
      assert.match(plain.body.markdown, /Sales Role Bravo/);

      const filtered = await localHub.scrape({
        url: 'https://ride1up-cat.example.com/roles.json',
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

  test('T3.04: F14 + F28 (L-04) non-JSON-LD microdata/spec-table resolves relative itemprop="url" & populates product + json', async () => {
    const res = await hub.scrape({
      url: 'https://bikeschematics-t3.example.com/specs/hub-m600',
      formats: [
        'markdown',
        'product',
        { type: 'json', schema: { type: 'object', properties: { sku: { type: 'string' }, price: { type: 'number' }, brand: { type: 'string' } } } },
      ],
      discoverLlmsTxt: false,
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.product?.url, 'https://bikeschematics-t3.example.com/parts/m600');
    assert.equal(res.body.product?.sku, 'BF-M600');
    assert.equal(res.body.product?.price, 849);
    assert.equal(res.body.product?.brand, 'Bafang');
    assert.equal(res.body.json?.sku, 'BF-M600');
    assert.equal(res.body.json?.price, 849);
  });

  test('T3.05: F09 + F28 (L-04) + redactPii Squarespace ?format=json-pretty redacts PII & populates product + json', async () => {
    const res = await hub.scrape({
      url: 'https://urbancycle-t3.example.com/shop/p/porteur-front-rack',
      redactPii: true,
      formats: [
        'markdown',
        'product',
        { type: 'json', schema: { type: 'object', properties: { sku: { type: 'string' }, price: { type: 'number' } } } },
      ],
      discoverLlmsTxt: false,
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.extractorId, 'squarespace-commerce');
    assert.ok(Array.isArray(res.body.records) && res.body.records.length >= 1);
    assert.equal(res.body.product?.sku, 'SQ-RACK-BLK');
    assert.equal(res.body.json?.sku, 'SQ-RACK-BLK');
    assert.equal(res.body.markdown.includes('555-234-5678'), false);
    assert.equal(res.body.markdown.includes('orders@urbancycle-t3.example.com'), false);
    assert.equal(JSON.stringify(res.body.records ?? []).includes('555-234-5678'), false);
  });

  test('T3.06: F10 + F28 (L-04) BigCommerce BCData populates records[], product & links', async () => {
    const res = await hub.scrape({
      url: 'https://peakbikes-t3.example.com/trailblazer-hydraulic-brake-kit/',
      formats: ['markdown', 'product', 'links'],
      discoverLlmsTxt: false,
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.extractorId, 'bigcommerce-store');
    assert.ok(
      Array.isArray(res.body.records) &&
        res.body.records.some((r) => r.sku === 'BC-BRK-400' || r.variants?.some((v) => v.sku === 'BC-BRK-400')),
    );
    assert.equal(res.body.product?.sku, 'BC-BRK-400');
    assert.equal(res.body.product?.price, 249.95);
    assert.equal(res.body.product?.availability, 'InStock');
  });

  test('T3.07: F11 + F28 (L-04) + query SFCC Product-Variation ranks geometry chunks & populates product + json', async () => {
    const res = await hub.scrape({
      url: 'https://bikes-t3.example.com/us/en_US/bikes/domane-sl-6-gen-4/p/44751/',
      query: 'Stack Reach 575',
      formats: [
        'markdown',
        'product',
        { type: 'json', schema: { type: 'object', properties: { sku: { type: 'string' }, price: { type: 'number' } } } },
      ],
      discoverLlmsTxt: false,
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.extractorId, 'sfcc-demandware');
    assert.equal(res.body.queryFiltered, true);
    assert.ok(Array.isArray(res.body.chunks) && res.body.chunks.some((c) => /575|Reach/i.test(c.text)));
    assert.equal(res.body.product?.sku, '44751-54-BLK');
    assert.equal(res.body.json?.sku, '44751-54-BLK');
  });

  test('T3.08: F12 + F28 (L-04) + redactPii Shopware 6 & Magento 2 redact inline contact PII while keeping SKUs', async () => {
    const swRes = await hub.scrape({
      url: 'https://oem-t3.example.de/supernova-m99-mini.html',
      redactPii: true,
      formats: ['markdown', 'product'],
      discoverLlmsTxt: false,
    });
    assert.equal(swRes.status, 200);
    assert.ok(swRes.body.extractorId === 'shopware-magento' || swRes.body.detected?.platform === 'shopware');
    assert.equal(swRes.body.markdown.includes('service@oem-t3.example.de'), false);
    assert.equal(JSON.stringify(swRes.body.records ?? []).includes('service@oem-t3.example.de'), false);
    assert.equal(swRes.body.product?.sku, 'SN-M99-MINI25');

    const mgRes = await hub.scrape({
      url: 'https://parts-t3.example.com/magura-mt7-pro.html',
      redactPii: true,
      formats: ['markdown', 'product'],
      discoverLlmsTxt: false,
    });
    assert.equal(mgRes.status, 200);
    assert.equal(mgRes.body.extractorId, 'shopware-magento');
    assert.equal(mgRes.body.markdown.includes('tech@parts-t3.example.com'), false);
    assert.ok(
      mgRes.body.product?.sku === 'MAG-MT7-180' ||
        mgRes.body.records?.some((r) => r.sku === 'MAG-MT7-180' || r.variants?.some((v) => v.sku === 'MAG-MT7-180')),
    );
  });

  test('T3.09: F25 (L-01) + redactPii + maxAgeMs isolates redacted vs raw cache entries and hits identical replay', async () => {
    const localRouter = createOutboundRouter();
    const contacts = [
      { id: 'c1', team: 'Eng', title: 'Alice Eng', description: 'Email alice@eng.example.com or call 555-111-2222.' },
      { id: 'c2', team: 'Sales', title: 'Bob Sales', description: 'Email bob@sales.example.com or call 555-333-4444.' },
    ];
    localRouter.json('https://l01-pii.example.com/contacts.json', contacts);
    await withFreshHub({ router: localRouter }, async (localHub) => {
      const first = await localHub.scrape({
        url: 'https://l01-pii.example.com/contacts.json',
        jsonFilter: 'team=Eng',
        redactPii: true,
        maxAgeMs: 600_000,
        discoverLlmsTxt: false,
      });
      assert.equal(first.status, 200);
      assert.equal(first.body.cached, false);
      assert.equal(first.body.markdown.includes('alice@eng.example.com'), false);
      assert.equal(first.body.markdown.includes('bob@sales.example.com'), false);

      const unredacted = await localHub.scrape({
        url: 'https://l01-pii.example.com/contacts.json',
        jsonFilter: 'team=Eng',
        redactPii: false,
        maxAgeMs: 600_000,
        discoverLlmsTxt: false,
      });
      assert.equal(unredacted.status, 200);
      assert.equal(unredacted.body.cached, false);
      assert.match(unredacted.body.markdown, /alice@eng\.example\.com/);

      const replay = await localHub.scrape({
        url: 'https://l01-pii.example.com/contacts.json',
        jsonFilter: 'team=Eng',
        redactPii: true,
        maxAgeMs: 600_000,
        discoverLlmsTxt: false,
      });
      assert.equal(replay.status, 200);
      assert.equal(replay.body.cached, true);
      assert.equal(replay.body.markdown.includes('alice@eng.example.com'), false);
      assert.equal(localRouter.countRequests('l01-pii.example.com', '/contacts.json'), 2);
    });
  });

  test('T3.10: F25 (L-01) + formats + onlyMainContent + maxAgeMs differentiates scrapeOptionsHash keys', async () => {
    const localRouter = createOutboundRouter();
    localRouter.json('https://l01-opts.example.com/catalog.json', [
      { id: 'p1', cat: 'ebike', name: 'Commuter 500', url: 'https://l01-opts.example.com/p1' },
      { id: 'p2', cat: 'helmet', name: 'Urban Lid', url: 'https://l01-opts.example.com/p2' },
    ]);
    await withFreshHub({ router: localRouter }, async (localHub) => {
      const r1 = await localHub.scrape({
        url: 'https://l01-opts.example.com/catalog.json',
        jsonFilter: 'cat=ebike',
        formats: ['markdown'],
        maxAgeMs: 600_000,
        discoverLlmsTxt: false,
      });
      assert.equal(r1.status, 200);
      assert.equal(r1.body.cached, false);

      const r2 = await localHub.scrape({
        url: 'https://l01-opts.example.com/catalog.json',
        jsonFilter: 'cat=ebike',
        formats: ['markdown', 'links'],
        maxAgeMs: 600_000,
        discoverLlmsTxt: false,
      });
      assert.equal(r2.status, 200);
      assert.equal(r2.body.cached, false);

      const r3 = await localHub.scrape({
        url: 'https://l01-opts.example.com/catalog.json',
        jsonFilter: 'cat=ebike',
        onlyMainContent: false,
        maxAgeMs: 600_000,
        discoverLlmsTxt: false,
      });
      assert.equal(r3.status, 200);
      assert.equal(r3.body.cached, false);

      const r1Replay = await localHub.scrape({
        url: 'https://l01-opts.example.com/catalog.json',
        jsonFilter: 'cat=ebike',
        formats: ['markdown'],
        maxAgeMs: 600_000,
        discoverLlmsTxt: false,
      });
      assert.equal(r1Replay.status, 200);
      assert.equal(r1Replay.body.cached, true);
    });
  });

  test('T3.11: F25 (L-01) + includeTags/excludeTags + maxAgeMs isolates options cache cleanly', async () => {
    const localRouter = createOutboundRouter();
    localRouter.html(
      'https://l01-tags.example.com/items.html',
      `<!doctype html><html><body><aside>Sidebar Noise</aside><article><h1>Main Article</h1><p>Battery cell thermal management guide.</p></article></body></html>`,
    );
    await withFreshHub({ router: localRouter }, async (localHub) => {
      const inc1 = await localHub.scrape({
        url: 'https://l01-tags.example.com/items.html',
        includeTags: ['article'],
        jsonFilter: 'team=Platform',
        maxAgeMs: 600_000,
        discoverLlmsTxt: false,
      });
      assert.equal(inc1.status, 200);
      assert.equal(inc1.body.cached, false);
      assert.match(inc1.body.markdown, /Main Article/);
      assert.equal(inc1.body.markdown.includes('Sidebar Noise'), false);

      const exc1 = await localHub.scrape({
        url: 'https://l01-tags.example.com/items.html',
        excludeTags: ['aside'],
        jsonFilter: 'team=Platform',
        maxAgeMs: 600_000,
        discoverLlmsTxt: false,
      });
      assert.equal(exc1.status, 200);
      assert.equal(exc1.body.cached, false);

      const incReplay = await localHub.scrape({
        url: 'https://l01-tags.example.com/items.html',
        includeTags: ['article'],
        jsonFilter: 'team=Platform',
        maxAgeMs: 600_000,
        discoverLlmsTxt: false,
      });
      assert.equal(incReplay.status, 200);
      assert.equal(incReplay.body.cached, true);
    });
  });
});

// ============================================================================
// Suite 2: Public Records, Forums, Tech Docs & Registry Twins (T3.12–T3.23)
// ============================================================================
describe('Tier 3 — Public Records, Forums, Tech Docs & Registry Twins', () => {
  let router;
  let hub;

  before(async () => {
    router = createOutboundRouter();

    // T3.13: Zendesk article with PII
    const zdPiiArticle = {
      article: {
        ...F01_ZENDESK.articleJson.article,
        body: '<h2>Firmware Pairing</h2><p>Ensure firmware <strong>v4.2</strong> is paired. Contact ops@acme-t3.example.com for fleet keys.</p>',
      },
    };
    router.json('https://acme-t3.zendesk.com/api/v2/help_center/en-us/articles/4408886858138.json', zdPiiArticle);
    router.json('https://acme-t3.zendesk.com/api/v2/help_center/en-us/articles/4408886858138/attachments.json', F01_ZENDESK.attachmentsJson);

    // T3.14: Federal Register
    router.json('https://www.federalregister.gov/api/v1/documents/2024-00001.json', F04_FEDERAL_REGISTER.doc2024_00001);

    // T3.18: XenForo 2 with inline PII
    const xfWithPii = F08_XENFORO.threadHtml('Bosch CX Gen4 BMS Cutoff Voltage').replace(
      'blue Loctite 243.',
      'blue Loctite 243. Email tech@rider-t3.example.org for BMS calibration sheets.',
    );
    router.html('https://forums.electricbikereview.com/threads/bms-cutoff-voltage.99123/', xfWithPii);

    // T3.20: Terraform Registry
    router.json('https://registry.terraform.io/v1/providers/hashicorp/random', F15_TERRAFORM.providerJson);
    router.json('https://registry.terraform.io/v1/modules/terraform-aws-modules/vpc/aws', F15_TERRAFORM.moduleJson);

    // T3.22: Maven Central + OSV/GHSA
    router.json(
      (u) => u.hostname === 'search.maven.org' && u.pathname === '/solrsearch/select' && u.search.includes('guava'),
      F17_MAVEN_CENTRAL.guavaSolrJson,
    );
    router.json('https://api.osv.dev/v1/vulns/GHSA-jfh8-c2jp-5v3q', F20_OSV.ghsaVulnJson(3));

    // T3.23: NuGet (with maintainer email PII) + Homebrew deprecated formula
    const nugetPii = structuredClone(F18_NUGET.newtonsoftIndexJson);
    nugetPii.items[0].items[0].catalogEntry.authors = 'James Newton-King (maint@nuget-t3.example.com)';
    router.json('https://api.nuget.org/v3/registration5-gz-semver2/newtonsoft.json/index.json', nugetPii);
    router.json(
      (u) =>
        u.hostname === 'formulae.brew.sh' &&
        (u.pathname === '/api/formula/python%403.8.json' || u.pathname === '/api/formula/python@3.8.json'),
      F19_HOMEBREW.deprecatedFormulaJson,
    );

    hub = await createHubInstance({ router });
  });

  after(async () => {
    await hub?.dispose();
  });

  test('T3.12: F01 + F27 (L-03) Zendesk HC surfaces PDF attachment URL -> Mock Agent rawBase64 + parsers: [] hydrates 5 MiB PDF', async () => {
    const localRouter = createOutboundRouter();
    localRouter.json('https://acme.zendesk.com/api/v2/help_center/en-us/articles/4408886858138.json', F01_ZENDESK.articleJson);
    localRouter.json('https://acme.zendesk.com/api/v2/help_center/en-us/articles/4408886858138/attachments.json', F01_ZENDESK.attachmentsJson);
    const pdf5Mib = Buffer.concat([Buffer.from('%PDF-1.7\n%EOF\n', 'utf8'), Buffer.alloc(5 * 1024 * 1024, 0x20)]);

    await withFreshHub({ router: localRouter }, async (localHub) => {
      const zdRes = await localHub.scrape({
        url: 'https://acme.zendesk.com/hc/en-us/articles/4408886858138-getting-started',
        formats: ['markdown', 'links'],
        discoverLlmsTxt: false,
      });
      assert.equal(zdRes.status, 200);
      assert.equal(zdRes.body.extractorId, 'zendesk-hc');
      const pdfUrl = (zdRes.body.links ?? []).find((l) => l.includes('Fleet_Manual_v4.pdf'));
      assert.ok(pdfUrl, 'Expected Fleet_Manual_v4.pdf URL in Zendesk links[]');

      await localHub.connectMockAgent({
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

      const pdfRes = await localHub.scrape({
        url: pdfUrl,
        target: 'agent',
        formats: ['rawBase64'],
        parsers: [],
        discoverLlmsTxt: false,
      });
      assert.equal(pdfRes.status, 200);
      assert.equal(typeof pdfRes.body.rawBase64, 'string');
      const decoded = Buffer.from(pdfRes.body.rawBase64, 'base64');
      assert.equal(decoded.byteLength, pdf5Mib.byteLength);
      assert.equal(decoded.subarray(0, 8).toString('utf8'), '%PDF-1.7');
    });
  });

  test('T3.13: F01 + redactPii + query Zendesk HC redacts email in markdown & chunks while preserving attachment links', async () => {
    const res = await hub.scrape({
      url: 'https://acme-t3.zendesk.com/hc/en-us/articles/4408886858138-getting-started',
      redactPii: true,
      query: 'firmware pairing',
      formats: ['markdown', 'links'],
      discoverLlmsTxt: false,
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.extractorId, 'zendesk-hc');
    assert.equal(res.body.queryFiltered, true);
    assert.equal(res.body.markdown.includes('ops@acme-t3.example.com'), false);
    assert.equal(JSON.stringify(res.body.chunks ?? []).includes('ops@acme-t3.example.com'), false);
    assert.ok((res.body.links ?? []).some((l) => l.includes('Fleet_Manual_v4.pdf')));
  });

  test('T3.14: F04 + POST /v1/extract Federal Register ranks chunks & populates rawContent', async () => {
    const res = await hub.extract({
      urls: ['https://www.federalregister.gov/documents/2024/01/02/2024-00001/safety-standard-for-lithium-ion-ebike-batteries'],
      query: 'thermal runaway lithium-ion',
      chunksPerSource: 2,
      includeRawContent: true,
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.ok, true);
    assert.equal(res.body.results.length, 1);
    const r0 = res.body.results[0];
    assert.ok(r0.chunks.length >= 1 && r0.chunks.length <= 2);
    assert.ok((r0.matchedQueryTerms ?? 0) >= 1);
    assert.ok((r0.score ?? 0) > 0);
    assert.match(String(r0.rawContent ?? ''), /89 FR 1042/);
  });

  test('T3.15: F05 + F36 + redactPii bounded CPSC recall redacts ConsumerContact while unfiltered saferproducts dump is rejected', async () => {
    const localRouter = createOutboundRouter();
    const boundedRecall = F05_CPSC_RECALLS.saferProductsRecall24123.map((r) => ({
      ...r,
      RecallNumber: '26142',
      ConsumerContact: 'VoltPeak toll-free at 800-555-0199 or support@voltpeak-t3.example.com.',
    }));
    localRouter.json(
      (u) => u.hostname === 'www.saferproducts.gov' && u.pathname === '/RestWebServices/Recall' && u.searchParams.get('RecallNumber') === '26142',
      boundedRecall,
    );
    localRouter.json('https://www.saferproducts.gov/RestWebServices/Recall?format=json', [
      { RecallID: 1, RecallNumber: '00001', Title: 'UNFILTERED_DUMP_SHOULD_NOT_PASS' },
    ]);
    await withFreshHub({ router: localRouter }, async (localHub) => {
      const pos = await localHub.scrape({
        url: 'https://www.saferproducts.gov/RestWebServices/Recall?RecallNumber=26142&format=json',
        redactPii: true,
        discoverLlmsTxt: false,
      });
      assert.equal(pos.status, 200);
      assert.equal(pos.body.extractorId, 'cpsc-recalls');
      assert.equal(pos.body.markdown.includes('support@voltpeak-t3.example.com'), false);
      assert.equal(pos.body.markdown.includes('800-555-0199'), false);

      const neg = await localHub.scrape({
        url: 'https://www.saferproducts.gov/RestWebServices/Recall?format=json',
        discoverLlmsTxt: false,
      });
      assert.ok(neg.status >= 400 || neg.body.ok === false || neg.body.extractorId !== 'cpsc-recalls');
      assert.notEqual(neg.body.extractorId, 'cpsc-recalls');
    });
  });

  test('T3.16: F06 + F26 (L-02) GovInfo >4 MiB .htm falls back to wssearch summary + query, while raw >4 MiB agent HTML sets edgeBudgetExceeded', async () => {
    const localRouter = createOutboundRouter();
    const bigCfr = `<!doctype html><html><body>${over4Mib('<p>16 CFR Part 1512 bicycle brake rules</p>')}</body></html>`;
    localRouter.html('https://www.govinfo.gov/content/pkg/CFR-2025-title16-vol2/html/CFR-2025-title16-vol2.htm', bigCfr);
    localRouter.json(
      (u) => u.hostname === 'www.govinfo.gov' && u.pathname === '/wssearch/getContentDetail',
      { ...F06_GOVINFO.wssearchContentDetail, packageId: 'CFR-2025-title16-vol2' },
    );
    localRouter.html('https://www.govinfo.gov/app/details/CFR-2025-title16-vol2', F06_GOVINFO.angularSpaShell);

    await withFreshHub({ router: localRouter }, async (localHub) => {
      const govRes = await localHub.scrape({
        url: 'https://www.govinfo.gov/app/details/CFR-2025-title16-vol2',
        target: 'container',
        query: 'Bicycles CFR',
        discoverLlmsTxt: false,
      });
      assert.equal(govRes.status, 200);
      assert.equal(govRes.body.extractorId, 'us-cfr-govinfo');
      assert.equal(govRes.body.queryFiltered, true);
      assert.match(govRes.body.markdown, /16 CFR Part 1512 - Requirements for Bicycles/);

      const bigHtml5Mib = `<html><body>${over4Mib('<p>large section</p>')}</body></html>`;
      let expectedBlob = '';
      await localHub.connectMockAgent({
        onDispatch: async (_msg, helpers) => {
          const req0 = helpers.call.requests?.[0] ?? {};
          const art = await helpers.uploadArtifact(bigHtml5Mib, { requestId: req0.id });
          expectedBlob = art.blobSha256;
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
      const agentRes = await localHub.scrape({
        url: 'https://big-raw.example.com/cfr-huge.html',
        target: 'agent',
        discoverLlmsTxt: false,
      });
      assert.equal(agentRes.status, 200);
      assert.equal(agentRes.body.edgeBudgetExceeded, true);
      assert.equal(agentRes.body.artifactId, expectedBlob);
    });
  });

  test('T3.17: F07 + POST /v1/crawl + F36 EUR-Lex crawl stores static regulation & never fetches disallowed /TXT/DOC/', async () => {
    const localRouter = createOutboundRouter();
    localRouter.setRobots('eur-lex.europa.eu', 'User-agent: *\nDisallow: /legal-content/*/TXT/DOC/\nAllow: /\n');
    const enWithLinks = F07_EURLEX.enBatteryRegulationHtml.replace(
      '</main>',
      '<p><a href="https://eur-lex.europa.eu/legal-content/EN/TXT/DOC/?uri=CELEX:32023R1542">Word DOC</a> | <a href="https://eur-lex.europa.eu/legal-content/EN/TXT/HTML/?uri=CELEX:32006L0042">Machinery Directive</a></p></main>',
    );
    localRouter.html(
      (u) => u.hostname === 'eur-lex.europa.eu' && u.pathname === '/legal-content/EN/TXT/HTML/' && u.searchParams.get('uri') === 'CELEX:32023R1542',
      enWithLinks,
    );
    localRouter.html(
      (u) => u.hostname === 'eur-lex.europa.eu' && u.pathname === '/legal-content/EN/TXT/HTML/' && u.searchParams.get('uri') === 'CELEX:32006L0042',
      F07_EURLEX.deMachineryHtml,
    );
    localRouter.html(
      (u) => u.hostname === 'eur-lex.europa.eu' && u.pathname === '/legal-content/EN/TXT/DOC/',
      '<html><body>DOC DISALLOWED</body></html>',
    );

    await withFreshHub({ router: localRouter }, async (localHub) => {
      const start = await localHub.crawl({
        url: 'https://eur-lex.europa.eu/legal-content/EN/TXT/HTML/?uri=CELEX:32023R1542',
        collectionId: 'eurlex-t3',
        sync: true,
        limit: 4,
        maxDepth: 1,
        delay: 0,
        sitemap: 'skip',
      });
      assert.equal(start.status, 200);
      assert.equal(start.body.status, 'completed');

      const statusRes = await localHub.getCrawl(start.body.id);
      assert.equal(statusRes.status, 200);
      assert.equal(statusRes.body.status, 'completed');
      assert.ok(statusRes.body.fetchedCount >= 1);
      assert.ok(statusRes.body.data.some((d) => d.url.includes('CELEX:32023R1542')));
      const searchRes = await localHub.fetch('/v1/collections/eurlex-t3/search', {
        method: 'POST',
        headers: { authorization: `Bearer ${localHub.callerToken}`, 'content-type': 'application/json' },
        body: JSON.stringify({ query: 'light means of transport' }),
      });
      assert.equal(searchRes.status, 200);
      const searchBody = await searchRes.json();
      assert.ok((searchBody.hits ?? []).some((r) => /2023\/1542|light means of transport/i.test(JSON.stringify(r))));
      assert.equal(localRouter.countRequests('eur-lex.europa.eu', '/legal-content/EN/TXT/DOC/'), 0);
    });
  });

  test('T3.18: F08 + redactPii + query XenForo 2 strips signatures/sidebar, redacts email & ranks BMS post', async () => {
    const res = await hub.scrape({
      url: 'https://forums.electricbikereview.com/threads/bms-cutoff-voltage.99123/',
      redactPii: true,
      query: '22 Nm Loctite',
      formats: ['markdown', 'links'],
      discoverLlmsTxt: false,
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.extractorId, 'xenforo-thread');
    assert.equal(res.body.queryFiltered, true);
    assert.equal(res.body.markdown.includes('Signature Promo Spam'), false);
    assert.equal(res.body.markdown.includes('Latest Threads Sidebar Noise'), false);
    assert.equal(res.body.markdown.includes('tech@rider-t3.example.org'), false);
    assert.ok(Array.isArray(res.body.chunks) && res.body.chunks.some((c) => /22 Nm|Loctite/i.test(c.text)));
  });

  test('T3.19: F13 + F36 + F29 (L-05) Bosch eBike Help cleans SSR HTML without /api/* while thin SPA sets maxInlineBodyBytes on auto-render-1', async () => {
    const localRouter = createOutboundRouter();
    localRouter.setRobots('help.bosch-ebike.com', 'User-agent: *\nDisallow: /api/*\nAllow: /\n');
    localRouter.html('https://help.bosch-ebike.com/en/help-center/ebike-battery-charging', F13_SRAM_BOSCH_HELP.boschHelpHtml);

    await withFreshHub({ router: localRouter }, async (localHub) => {
      const ssrRes = await localHub.scrape({
        url: 'https://help.bosch-ebike.com/en/help-center/ebike-battery-charging',
        discoverLlmsTxt: false,
      });
      assert.equal(ssrRes.status, 200);
      assert.equal(ssrRes.body.extractorId, 'bosch-ebike-help');
      assert.equal(ssrRes.body.markdown.includes('data:image/webp;base64'), false);
      assert.equal(ssrRes.body.markdown.includes('Service temporarily unavailable'), false);
      assert.equal(localRouter.countRequests('help.bosch-ebike.com', '/api'), 0);

      let autoRenderMaxInline;
      await localHub.connectMockAgent({
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
                  body: `<html><body><main><h1>Bosch Help Rendered</h1><p>${'charging '.repeat(60)}</p></main></body></html>`,
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
                body: '<html><body><div id="app"></div><script src="/app.js"></script></body></html>',
                bodyEncoding: 'utf-8',
              },
            ],
          });
        },
      });
      const spaRes = await localHub.scrape({
        url: 'https://spa-bosch-t3.example.com/app',
        discoverLlmsTxt: false,
      });
      assert.equal(spaRes.status, 200);
      assert.equal(autoRenderMaxInline, MAX_WASM_INPUT_BYTES);
    });
  });

  test('T3.20: F15 + POST /v1/extract Terraform provider + module ranks VPC module inputs with rawContent', async () => {
    const res = await hub.extract({
      urls: [
        'https://registry.terraform.io/providers/hashicorp/random',
        'https://registry.terraform.io/modules/terraform-aws-modules/vpc/aws',
      ],
      query: 'cidr availability zones',
      chunksPerSource: 3,
      includeRawContent: true,
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.results.length, 2);
    const modRes = res.body.results[1];
    assert.ok(modRes.chunks.length >= 1);
    assert.ok((modRes.score ?? 0) > 0);
    assert.match(String(modRes.rawContent ?? ''), /cidr/i);
  });

  test('T3.21: F16 + json + F36 Docker Hub extracts repo/tag json while untrusted cross-host 302 redirect is rejected', async () => {
    const localRouter = createOutboundRouter();
    localRouter.json('https://hub.docker.com/v2/repositories/library/alpine/', F16_DOCKER_HUB.alpineRepoJson);
    localRouter.json('https://hub.docker.com/v2/repositories/library/alpine/tags?page_size=25', F16_DOCKER_HUB.tagsJson);
    localRouter.redirect('https://hub.docker.com/v2/repositories/library/evil/', 'https://evil-cdn.example.com/alpine.json', 302);
    localRouter.json('https://evil-cdn.example.com/alpine.json', { name: 'EVIL_DOCKER_MARKER', description: 'Must be blocked' });
    localRouter.html('https://hub.docker.com/_/evil', '<html><body><main><h1>evil</h1><p>HTML fallback page.</p></main></body></html>');

    await withFreshHub({ router: localRouter }, async (localHub) => {
      const okRes = await localHub.scrape({
        url: 'https://hub.docker.com/_/alpine',
        formats: ['markdown', { type: 'json', schema: { type: 'object', properties: { name: { type: 'string' }, description: { type: 'string' } } } }],
        discoverLlmsTxt: false,
      });
      assert.equal(okRes.status, 200);
      assert.equal(okRes.body.extractorId, 'docker-hub');
      assert.match(okRes.body.markdown, /Alpine Linux/);
      assert.match(String(okRes.body.json?.name ?? ''), /library\/alpine/i);
      assert.match(String(okRes.body.json?.description ?? ''), /Alpine Linux/i);

      const tagsRes = await localHub.scrape({
        url: 'https://hub.docker.com/_/alpine/tags',
        discoverLlmsTxt: false,
      });
      assert.equal(tagsRes.status, 200);
      assert.equal(tagsRes.body.extractorId, 'docker-hub');
      assert.match(tagsRes.body.markdown, /3\.20\.3/);

      const evilRes = await localHub.scrape({
        url: 'https://hub.docker.com/_/evil',
        discoverLlmsTxt: false,
      });
      assert.equal(evilRes.status, 200);
      assert.notEqual(evilRes.body.extractorId, 'docker-hub');
      assert.equal(evilRes.body.markdown.includes('EVIL_DOCKER_MARKER'), false);
    });
  });

  test('T3.22: F17 + F20 + POST /v1/extract Maven Central + GHSA OSV advisory ranks fixed version 2.15.0', async () => {
    const res = await hub.extract({
      urls: [
        'https://central.sonatype.com/artifact/com.google.guava/guava',
        'https://github.com/advisories/GHSA-jfh8-c2jp-5v3q',
      ],
      query: '2.15.0 fixed Log4j2',
      chunksPerSource: 3,
      includeRawContent: true,
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.results.length, 2);
    const osvRes = res.body.results[1];
    assert.ok(osvRes.chunks.length >= 1);
    assert.ok((osvRes.score ?? 0) > 0);
    assert.match(JSON.stringify(osvRes), /2\.15\.0/);
  });

  test('T3.23: F18 + F19 + POST /v1/extract + redactPii lowercases NuGet, redacts maintainer email & surfaces Homebrew deprecation', async () => {
    const res = await hub.extract({
      urls: [
        'https://www.nuget.org/packages/Newtonsoft.Json',
        'https://formulae.brew.sh/formula/python@3.8',
      ],
      redactPii: true,
      query: 'Newtonsoft deprecated',
      chunksPerSource: 3,
      includeRawContent: true,
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.results.length, 2);
    assert.equal(router.countRequests('api.nuget.org', '/v3/registration5-gz-semver2/newtonsoft.json/index.json') >= 1, true);
    assert.equal(JSON.stringify(res.body.results[0]).includes('maint@nuget-t3.example.com'), false);
    assert.match(JSON.stringify(res.body.results[1]), /deprecated/i);
  });
});

// ============================================================================
// Suite 3: ATS, Public APIs, L-02/L-03/L-05 & Log-Mined Adapters (T3.24–T3.37)
// ============================================================================
describe('Tier 3 — ATS, Public APIs, L-02/L-03/L-05 & Log-Mined Adapters', () => {
  let router;
  let hub;

  before(async () => {
    router = createOutboundRouter();

    // T3.34: bumm.de with relative JSON-LD Product.url
    const bummRelativeUrl = F32_BUMM.productHtml('en').replace(
      '"sku": "164RTSNDI-01",',
      '"url": "/en/product-detail/iq-x.html",\n    "sku": "164RTSNDI-01",',
    );
    router.setRobots('bumm.de', F32_BUMM.robotsTxt);
    router.html('https://bumm.de/en/product-detail/iq-x.html', bummRelativeUrl);

    // T3.37: D1 high-ROI (Shimano RSC, SRAM, TQ eBike)
    router.html('https://productinfo.shimano.com/en/product/DU-EP801', F35_D1_HIGH_ROI.shimanoProductInfoRscHtml('DU-EP801'));
    router.html('https://www.sram.com/en/sram/models/rd-xx-e-b1', F35_D1_HIGH_ROI.sramModelHtml);
    router.html('https://www.tq-ebike.com/en/products/hpr50', F35_D1_HIGH_ROI.tqEbikeHtml);

    hub = await createHubInstance({ router });
  });

  after(async () => {
    await hub?.dispose();
  });

  test('T3.24: F21 + F29 (L-05) Workday 422 fast-exits without render while redirect stub dispatches wd-stub-render-1 with 4 MiB cap', async () => {
    const localRouter = createOutboundRouter();
    localRouter.status(
      (u) => u.hostname === 'glean.wd5.myworkdayjobs.com' && u.pathname.includes('/wday/cxs/'),
      422,
      JSON.stringify(F21_WORKDAY_ICIMS.workdayCxs422),
      { 'content-type': 'application/json' },
    );
    await withFreshHub({ router: localRouter }, async (localHub) => {
      let wdStubMaxInline;
      const agent = await localHub.connectMockAgent({
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
                  body: '<html><body><main><h1>Acme Careers</h1><p>Senior Firmware Engineer open role.</p></main></body></html>',
                  bodyEncoding: 'utf-8',
                },
              ],
            });
            return;
          }
          if (req0.id === 'scrape-1' && String(req0.url).includes('l05acme.wd1.myworkdayjobs.com')) {
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
          if (String(req0.url).includes('glean.wd5.myworkdayjobs.com') && String(req0.url).includes('/wday/cxs/')) {
            await helpers.sendReply({
              results: [
                {
                  id: req0.id,
                  url: req0.url,
                  finalUrl: req0.url,
                  status: 422,
                  outcome: 'http_error',
                  contentType: 'application/json',
                  body: JSON.stringify(F21_WORKDAY_ICIMS.workdayCxs422),
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

      const fastExitRes = await localHub.scrape({
        url: 'https://glean.wd5.myworkdayjobs.com/en-US/Glean?q=engineer&offset=20',
        discoverLlmsTxt: false,
      });
      assert.equal(fastExitRes.status, 404);
      assert.equal(fastExitRes.body.outcome, 'not_found');
      assert.equal(agent.frames.filter((f) => f.call.requests?.[0]?.id === 'auto-render-1').length, 0);

      const stubRes = await localHub.scrape({
        url: 'https://l05acme.wd1.myworkdayjobs.com/en-US/Careers',
        discoverLlmsTxt: false,
      });
      assert.equal(stubRes.status, 200);
      assert.equal(stubRes.body.renderedVia, 'browser-auto');
      assert.equal(wdStubMaxInline, MAX_WASM_INPUT_BYTES);
    });
  });

  test('T3.25: F21 + F22 + POST /v1/jobs discovers iCIMS, UKG, Paylocity & Dover boards via domains and filters remote + minBase', async () => {
    const localRouter = createOutboundRouter();
    localRouter.html(
      'https://icims-co.example.com/careers',
      '<html><body><a href="https://careers-icimsco.icims.com/jobs/search?ss=1&in_iframe=1">Open Roles</a></body></html>',
    );
    localRouter.html(
      'https://careers-icimsco.icims.com/jobs/search?ss=1&in_iframe=1',
      `<!doctype html><html><body><div class="iCIMS_JobsTable">
        <div class="row"><div class="title"><a class="iCIMS_Anchor" href="https://careers-icimsco.icims.com/jobs/101/staff-firmware-engineer/job?in_iframe=1"><span>Staff Firmware Engineer</span></a></div><div class="additionalFields"><dl><dt>Location</dt><dd>Remote, US</dd><dt>Salary</dt><dd>$160,000 - $185,000</dd></dl></div></div>
        <div class="row"><div class="title"><a class="iCIMS_Anchor" href="https://careers-icimsco.icims.com/jobs/102/onsite-tech/job?in_iframe=1"><span>Onsite Technician</span></a></div><div class="additionalFields"><dl><dt>Location</dt><dd>Boulder, CO</dd><dt>Salary</dt><dd>$70,000</dd></dl></div></div>
      </div></body></html>`,
    );
    localRouter.html(
      'https://careers-icimsco.icims.com/jobs/101/staff-firmware-engineer/job?in_iframe=1',
      F21_WORKDAY_ICIMS.icimsJobIframeHtml.replace('San Jose', 'Remote'),
    );

    localRouter.setRobots('recruiting.ultipro.com', F22_UKG_PAYLOCITY_DOVER.ukgRobotsTxt);
    localRouter.html(
      'https://ukg-co.example.com/careers',
      '<html><body><a href="https://recruiting.ultipro.com/UKG1001/JobBoard/11111111-2222-3333-4444-555555555555/">UKG Board</a></body></html>',
    );
    localRouter.html(
      'https://recruiting.ultipro.com/UKG1001/JobBoard/11111111-2222-3333-4444-555555555555/',
      `<!doctype html><html><body><script>window.__PRELOADED_STATE__ = { opportunities: [
        { Id: "ukg-1", Title: "Principal Firmware Engineer", Location: "Remote", Compensation: "$170,000 - $195,000", PostedDate: "2026-10-12", ApplyUrl: "https://recruiting.ultipro.com/UKG1001/JobBoard/11111111-2222-3333-4444-555555555555/OpportunityDetail?opportunityId=ukg-1" }
      ] };</script></body></html>`,
    );

    localRouter.html(
      'https://paylocity-co.example.com/careers',
      '<html><body><a href="https://recruiting.paylocity.com/Recruiting/Jobs/All/1111-2222-3333">Paylocity Board</a></body></html>',
    );
    localRouter.json('https://recruiting.paylocity.com/recruiting/api/feed/jobs/1111-2222-3333', {
      jobs: [
        {
          jobId: 'plc-1',
          title: 'Lead Firmware Engineer',
          locationName: 'Remote',
          publishedDate: '2026-10-15',
          jobUrl: 'https://recruiting.paylocity.com/Recruiting/Jobs/Details/1',
          description: 'Remote US role. Base salary $155,000 - $175,000.',
        },
      ],
    });
    localRouter.html('https://recruiting.paylocity.com/Recruiting/Jobs/All/1111-2222-3333', F22_UKG_PAYLOCITY_DOVER.paylocityHtml);

    localRouter.setRobots('app.dover.com', F22_UKG_PAYLOCITY_DOVER.doverRobotsTxt);
    localRouter.html(
      'https://dover-co.example.com/careers',
      '<html><body><a href="https://app.dover.com/jobs/doverco">Dover Board</a></body></html>',
    );
    localRouter.html(
      'https://app.dover.com/jobs/doverco',
      F22_UKG_PAYLOCITY_DOVER.doverHtml.replace('Founding Robotics Engineer', 'Remote Firmware Engineer ($165,000)'),
    );

    await withFreshHub({ router: localRouter }, async (localHub) => {
      const res = await localHub.jobs({
        domains: ['icims-co.example.com', 'ukg-co.example.com', 'paylocity-co.example.com', 'dover-co.example.com'],
        query: 'Firmware Engineer',
        remote: true,
        minBase: 140000,
        strictPay: true,
      });
      assert.equal(res.status, 200);
      assert.equal(res.body.ok, true);
      const foundBoards = (res.body.discoveredBoards ?? []).filter(
        (b) => b.boardStatus !== 'not_found' && b.platform !== 'unknown' && Boolean(b.boardUrl),
      );
      assert.ok(foundBoards.length >= 3, `Expected >= 3 discovered boards, got ${foundBoards.length}`);
      assert.ok(Array.isArray(res.body.jobs) && res.body.jobs.length >= 1);
      for (const job of res.body.jobs) {
        assert.ok(job.workplaceType === 'remote' || job.locations?.some((l) => /remote/i.test(l)));
        assert.ok((job.pay?.min ?? job.pay?.max ?? 0) >= 140000);
      }
      assert.equal(localRouter.countRequests('app.dover.com', '/api'), 0);
    });
  });

  test('T3.26: F22 + redactPii + F36 Dover & UKG redact recruiter PII on allowed paths and block disallowed /api/ & /JobBoardView', async () => {
    const localRouter = createOutboundRouter();
    localRouter.setRobots('app.dover.com', F22_UKG_PAYLOCITY_DOVER.doverRobotsTxt);
    localRouter.setRobots('recruiting.ultipro.com', F22_UKG_PAYLOCITY_DOVER.ukgRobotsTxt);

    const doverWithPii = F22_UKG_PAYLOCITY_DOVER.doverHtml.replace(
      'Acme Robotics Open Roles',
      'Acme Robotics Open Roles — Recruiter: talent@dover-t3.example.com / 555-901-2233',
    );
    const ukgWithPii = F22_UKG_PAYLOCITY_DOVER.ukgJobBoardHtml.replace(
      'Boulder, CO',
      'Boulder, CO (recruiter@ukg-t3.example.com)',
    );
    localRouter.html('https://app.dover.com/jobs/acme', doverWithPii);
    localRouter.json('https://app.dover.com/api/v1/job-board/jobs/acme', { jobs: [] });
    localRouter.html('https://recruiting.ultipro.com/ACM1001/JobBoard/11111111-2222-3333-4444-555555555555/', ukgWithPii);
    localRouter.html('https://recruiting.ultipro.com/ACM1001/JobBoardView/123', '<html><body>Disallowed</body></html>');

    await withFreshHub({ router: localRouter }, async (localHub) => {
      const doverRes = await localHub.scrape({
        url: 'https://app.dover.com/jobs/acme',
        redactPii: true,
        discoverLlmsTxt: false,
      });
      assert.equal(doverRes.status, 200);
      assert.equal(doverRes.body.extractorId, 'ukg-paylocity-dover');
      assert.match(doverRes.body.markdown, /Founding Robotics Engineer/);
      assert.ok((doverRes.body.jobs ?? doverRes.body.records ?? []).length >= 2);
      assert.equal(doverRes.body.markdown.includes('talent@dover-t3.example.com'), false);
      assert.equal(doverRes.body.markdown.includes('555-901-2233'), false);

      const ukgRes = await localHub.scrape({
        url: 'https://recruiting.ultipro.com/ACM1001/JobBoard/11111111-2222-3333-4444-555555555555/',
        redactPii: true,
        discoverLlmsTxt: false,
      });
      assert.equal(ukgRes.status, 200);
      assert.equal(ukgRes.body.extractorId, 'ukg-paylocity-dover');
      assert.ok((ukgRes.body.jobs ?? ukgRes.body.records ?? []).length >= 2);
      assert.equal(ukgRes.body.markdown.includes('recruiter@ukg-t3.example.com'), false);
      assert.equal(JSON.stringify(ukgRes.body.jobs ?? ukgRes.body.records ?? []).includes('recruiter@ukg-t3.example.com'), false);

      const doverApi = await localHub.scrape({
        url: 'https://app.dover.com/api/v1/job-board/jobs/acme',
        discoverLlmsTxt: false,
      });
      assert.equal(doverApi.status, 422);
      assert.equal(localRouter.countRequests('app.dover.com', '/api'), 0);

      const ukgView = await localHub.scrape({
        url: 'https://recruiting.ultipro.com/ACM1001/JobBoardView/123',
        discoverLlmsTxt: false,
      });
      assert.equal(ukgView.status, 422);
      assert.equal(localRouter.countRequests('recruiting.ultipro.com', '/JobBoardView'), 0);
    });
  });

  test('T3.27: F23 + F36 + json vPIC & fccid.io populate json schema while api.nhtsa.gov 403 & disallowed FCC path are blocked', async () => {
    const localRouter = createOutboundRouter();
    localRouter.json('https://vpic.nhtsa.dot.gov/api/vehicles/decodevinvalues/1HGCM82633A004352?format=json', F23_NHTSA_FCC.vpicVinJson);
    localRouter.status('https://api.nhtsa.gov/robots.txt', 403, 'Forbidden');
    localRouter.setRobots('fccid.io', F23_NHTSA_FCC.fccRobotsTxt);
    localRouter.html('https://fccid.io/BCG-E3542A', F23_NHTSA_FCC.fccHtml);
    localRouter.html('https://fccid.io/ViewExhibitReport.cfm?id=999', '<html><body>Disallowed</body></html>');

    await withFreshHub({ router: localRouter }, async (localHub) => {
      const vinRes = await localHub.scrape({
        url: 'https://vpic.nhtsa.dot.gov/api/vehicles/decodevinvalues/1HGCM82633A004352?format=json',
        formats: ['markdown', { type: 'json', schema: { type: 'object', properties: { Make: { type: 'string' }, ModelYear: { type: 'string' } } } }],
        discoverLlmsTxt: false,
      });
      assert.equal(vinRes.status, 200);
      assert.equal(vinRes.body.extractorId, 'nhtsa-vpic-recalls');
      assert.equal(vinRes.body.json?.Make, 'HONDA');
      assert.equal(vinRes.body.json?.ModelYear, '2003');

      const fccRes = await localHub.scrape({
        url: 'https://fccid.io/BCG-E3542A',
        formats: ['markdown', { type: 'json', schema: { type: 'object', properties: { title: { type: 'string' } } } }],
        discoverLlmsTxt: false,
      });
      assert.equal(fccRes.status, 200);
      assert.equal(fccRes.body.extractorId, 'fcc-id');
      assert.match(String(fccRes.body.json?.title ?? fccRes.body.markdown), /BCG-E3542A/);

      const nhtsaBlocked = await localHub.scrape({
        url: 'https://api.nhtsa.gov/recalls/recallsByVehicle?make=honda&model=accord&modelYear=2020',
        discoverLlmsTxt: false,
      });
      assert.ok(nhtsaBlocked.status === 403 || nhtsaBlocked.status === 422);
      assert.equal(nhtsaBlocked.body.ok, false);

      const fccBlocked = await localHub.scrape({
        url: 'https://fccid.io/ViewExhibitReport.cfm?id=999',
        discoverLlmsTxt: false,
      });
      assert.equal(fccBlocked.status, 422);
      assert.equal(localRouter.countRequests('fccid.io', '/ViewExhibitReport.cfm'), 0);
    });
  });

  test('T3.28: F24 + F36 + json Open Library same-host 302 + Wikidata Q42 populate json while /api/books is blocked', async () => {
    const localRouter = createOutboundRouter();
    localRouter.setRobots('openlibrary.org', F24_WIKIDATA_OPENLIBRARY.openLibraryRobotsTxt);
    localRouter.redirect('https://openlibrary.org/isbn/9780140328721.json', 'https://openlibrary.org/books/OL7353617M.json', 302);
    localRouter.json('https://openlibrary.org/books/OL7353617M.json', F24_WIKIDATA_OPENLIBRARY.openLibraryBookJson());
    localRouter.json('https://www.wikidata.org/wiki/Special:EntityData/Q42.json', F24_WIKIDATA_OPENLIBRARY.wikidataQ42Json);

    await withFreshHub({ router: localRouter }, async (localHub) => {
      const olRes = await localHub.scrape({
        url: 'https://openlibrary.org/isbn/9780140328721',
        formats: ['markdown', { type: 'json', schema: { type: 'object', properties: { title: { type: 'string' }, publish_date: { type: 'string' } } } }],
        discoverLlmsTxt: false,
      });
      assert.equal(olRes.status, 200);
      assert.equal(olRes.body.extractorId, 'wikidata-openlibrary');
      assert.equal(olRes.body.json?.title, 'Fantastic Mr. Fox');
      assert.equal(localRouter.countRequests('openlibrary.org', '/api'), 0);

      const olBlocked = await localHub.scrape({
        url: 'https://openlibrary.org/api/books?bibkeys=ISBN:9780140328721',
        discoverLlmsTxt: false,
      });
      assert.equal(olBlocked.status, 422);
      assert.equal(localRouter.countRequests('openlibrary.org', '/api'), 0);

      const wdRes = await localHub.scrape({
        url: 'https://www.wikidata.org/wiki/Q42',
        formats: ['markdown', { type: 'json', schema: { type: 'object', properties: { label: { type: 'string' } } } }],
        discoverLlmsTxt: false,
      });
      assert.equal(wdRes.status, 200);
      assert.equal(wdRes.body.extractorId, 'wikidata-openlibrary');
      assert.match(wdRes.body.markdown, /Douglas Adams/);
    });
  });

  test('T3.29: F26 (L-02) + F29 (L-05) auto-render-1 >4 MiB artifact stays safe without WASM crash while primary scrape-1 flags edgeBudgetExceeded', async () => {
    const localRouter = createOutboundRouter();
    const bigHtml5Mib = `<html><body><main>${over4Mib('<p>rendered element</p>')}</main></body></html>`;
    await withFreshHub({ router: localRouter }, async (localHub) => {
      let autoRenderCap;
      let expectedBlob = '';
      await localHub.connectMockAgent({
        onDispatch: async (_msg, helpers) => {
          const req0 = helpers.call.requests?.[0] ?? {};
          if (req0.id === 'auto-render-1') {
            autoRenderCap = helpers.call.options?.maxInlineBodyBytes;
            const art = await helpers.uploadArtifact(bigHtml5Mib, { requestId: req0.id });
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
          if (String(req0.url).includes('primary-big.example.com')) {
            const art = await helpers.uploadArtifact(bigHtml5Mib, { requestId: req0.id });
            expectedBlob = art.blobSha256;
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
                body: '<html><body><div id="root"></div><script src="/app.js"></script></body></html>',
                bodyEncoding: 'utf-8',
              },
            ],
          });
        },
      });

      const spaRes = await localHub.scrape({
        url: 'https://spa-over.example.com/app',
        discoverLlmsTxt: false,
      });
      assert.equal(spaRes.status, 200);
      assert.equal(spaRes.body.ok, true);
      assert.equal(autoRenderCap, MAX_WASM_INPUT_BYTES);

      const primaryRes = await localHub.scrape({
        url: 'https://primary-big.example.com/huge',
        target: 'agent',
        discoverLlmsTxt: false,
      });
      assert.equal(primaryRes.status, 200);
      assert.equal(primaryRes.body.edgeBudgetExceeded, true);
      assert.equal(primaryRes.body.artifactId, expectedBlob);
    });
  });

  test('T3.30: F26 (L-02) + F27 (L-03) same 5 MiB HTML artifact yields edgeBudgetExceeded on [markdown] vs full rawBase64 on [markdown, rawBase64]', async () => {
    const localRouter = createOutboundRouter();
    const bigHtml5Mib = `<!doctype html><html><body><p>${'M'.repeat(5 * 1024 * 1024)}</p></body></html>`;
    await withFreshHub({ router: localRouter }, async (localHub) => {
      await localHub.connectMockAgent({
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

      const mdOnly = await localHub.scrape({
        url: 'https://l02-l03.example.com/5mb-a.html',
        target: 'agent',
        formats: ['markdown'],
        discoverLlmsTxt: false,
      });
      assert.equal(mdOnly.status, 200);
      assert.equal(mdOnly.body.edgeBudgetExceeded, true);
      assert.equal(mdOnly.body.markdown, '');
      assert.equal(mdOnly.body.rawBase64, undefined);

      const withRaw = await localHub.scrape({
        url: 'https://l02-l03.example.com/5mb-b.html',
        target: 'agent',
        formats: ['markdown', 'rawBase64'],
        discoverLlmsTxt: false,
      });
      assert.equal(withRaw.status, 200);
      assert.equal(withRaw.body.edgeBudgetExceeded, undefined);
      assert.equal(Buffer.from(withRaw.body.rawBase64, 'base64').toString('utf8'), bigHtml5Mib);
      assert.ok((withRaw.body.warnings ?? []).some((w) => w.includes('4 MiB edge budget') && w.includes('rawBase64')));
    });
  });

  test('T3.31: F27 (L-03) + F32 + F36 bumm.de PDF manual hydrates 5 MiB rawBase64 while 15 MiB 0xff (>18 MiB wire) omits rawBase64 + returns artifactId', async () => {
    const localRouter = createOutboundRouter();
    localRouter.setRobots('bumm.de', F32_BUMM.robotsTxt);
    localRouter.html('https://bumm.de/en/product-detail/iq-x.html', F32_BUMM.productHtml('en'));

    const pdf5Mib = Buffer.concat([Buffer.from('%PDF-1.7\n%EOF\n', 'utf8'), Buffer.alloc(5 * 1024 * 1024, 0x20)]);
    // Use 0xff non-UTF-8 bytes so base64 expansion (20 MiB) exceeds the 18 MiB wire budget.
    const pdf15Mib = Buffer.alloc(15 * 1024 * 1024, 0xff);

    await withFreshHub({ router: localRouter }, async (localHub) => {
      const bummRes = await localHub.scrape({
        url: 'https://bumm.de/en/product-detail/iq-x.html',
        formats: ['markdown', 'links'],
        discoverLlmsTxt: false,
      });
      assert.equal(bummRes.status, 200);
      assert.equal(bummRes.body.extractorId, 'bumm-de');
      const pdfUrl = (bummRes.body.links ?? []).find((l) => l.includes('Anleitung_IQ-X.pdf'));
      assert.ok(pdfUrl, 'Expected Anleitung_IQ-X.pdf in bumm.de links');

      let expectedHugeSha = '';
      await localHub.connectMockAgent({
        onDispatch: async (_msg, helpers) => {
          const req0 = helpers.call.requests?.[0] ?? {};
          const isHuge = String(req0.url).includes('huge=1');
          const art = await helpers.uploadArtifact(isHuge ? pdf15Mib : pdf5Mib, { requestId: req0.id });
          if (isHuge) expectedHugeSha = art.blobSha256;
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

      const okPdf = await localHub.scrape({
        url: pdfUrl,
        target: 'agent',
        formats: ['rawBase64'],
        parsers: [],
        discoverLlmsTxt: false,
      });
      assert.equal(okPdf.status, 200);
      const dec5 = Buffer.from(okPdf.body.rawBase64, 'base64');
      assert.equal(dec5.byteLength, pdf5Mib.byteLength);
      assert.equal(dec5.subarray(0, 8).toString('utf8'), '%PDF-1.7');

      const hugePdf = await localHub.scrape({
        url: `${pdfUrl}?huge=1`,
        target: 'agent',
        formats: ['rawBase64'],
        parsers: [],
        discoverLlmsTxt: false,
      });
      assert.equal(hugePdf.status, 200);
      assert.equal(hugePdf.body.rawBase64, undefined);
      assert.equal(hugePdf.body.artifactId, expectedHugeSha);
      assert.ok((hugePdf.body.warnings ?? []).some((w) => w.includes('artifactId')));
    });
  });

  test('T3.32: F30 + F29 (L-05) + F36 NFPA __NEXT_DATA__ skips auto-render-1 while /en/ & /-/media/ are blocked by robots.txt', async () => {
    const localRouter = createOutboundRouter();
    localRouter.setRobots('www.nfpa.org', F30_NFPA.robotsTxt);
    localRouter.html('https://www.nfpa.org/codes-and-standards/nfpa-70-standard-development/70', F30_NFPA.nextDataHtml());
    localRouter.html('https://www.nfpa.org/en/blocked', '<html><body>Blocked</body></html>');
    localRouter.html('https://www.nfpa.org/-/media/blocked.pdf', 'Blocked');

    await withFreshHub({ router: localRouter }, async (localHub) => {
      const enRes = await localHub.scrape({ url: 'https://www.nfpa.org/en/blocked', discoverLlmsTxt: false });
      assert.equal(enRes.status, 422);
      const mediaRes = await localHub.scrape({ url: 'https://www.nfpa.org/-/media/blocked.pdf', discoverLlmsTxt: false });
      assert.equal(mediaRes.status, 422);
      assert.equal(localRouter.countRequests('www.nfpa.org', '/en/'), 0);
      assert.equal(localRouter.countRequests('www.nfpa.org', '/-/media/'), 0);

      // Connect Mock Agent last to verify NFPA __NEXT_DATA__ skips auto-render-1
      const agent = await localHub.connectMockAgent({
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
                body: F30_NFPA.nextDataHtml(),
                bodyEncoding: 'utf-8',
              },
            ],
          });
        },
      });

      const okRes = await localHub.scrape({
        url: 'https://www.nfpa.org/codes-and-standards/nfpa-70-standard-development/70',
        discoverLlmsTxt: false,
      });
      assert.equal(okRes.status, 200);
      assert.equal(okRes.body.rendered, false);
      assert.match(okRes.body.markdown, /NFPA 70 National Electrical Code/);
      assert.equal(agent.frames.filter((f) => f.call.requests?.[0]?.id === 'auto-render-1').length, 0);
    });
  });

  test('T3.33: F31 + F14 + F28 + POST /v1/crawl + F36 Giant crawl skips /shop* & scrape populates specs + product/json', async () => {
    const localRouter = createOutboundRouter();
    localRouter.setRobots('www.giant-bicycles.com', F31_GIANT_LIV.robotsTxt);
    const bikeHtmlWithShopLink = F31_GIANT_LIV.bikeHtml('Giant', 'Defy Advanced Pro 0').replace(
      '</main>',
      '<a href="https://www.giant-bicycles.com/us/shop/checkout">Shop</a><a href="https://www.giant-bicycles.com/us/manuals">Manuals</a></main>',
    );
    localRouter.html('https://www.giant-bicycles.com/us/defy-advanced-pro-0', bikeHtmlWithShopLink);
    localRouter.html('https://www.giant-bicycles.com/us/manuals', F31_GIANT_LIV.manualsHtml);
    localRouter.html('https://www.giant-bicycles.com/us/shop/checkout', '<html><body>Disallowed Shop</body></html>');

    await withFreshHub({ router: localRouter }, async (localHub) => {
      const crawlRes = await localHub.crawl({
        url: 'https://www.giant-bicycles.com/us/defy-advanced-pro-0',
        collectionId: 'giant-t3',
        sync: true,
        limit: 3,
        maxDepth: 1,
        delay: 0,
        sitemap: 'skip',
      });
      assert.equal(crawlRes.status, 200);
      assert.equal(crawlRes.body.status, 'completed');
      const statusRes = await localHub.getCrawl(crawlRes.body.id);
      assert.equal(statusRes.status, 200);
      assert.ok(statusRes.body.data.some((d) => d.url.includes('/us/defy-advanced-pro-0')));
      const searchRes = await localHub.fetch('/v1/collections/giant-t3/search', {
        method: 'POST',
        headers: { authorization: `Bearer ${localHub.callerToken}`, 'content-type': 'application/json' },
        body: JSON.stringify({ query: 'Defy Advanced Pro 0' }),
      });
      assert.equal(searchRes.status, 200);
      const searchBody = await searchRes.json();
      assert.ok((searchBody.hits ?? []).some((r) => /Defy Advanced Pro 0/i.test(JSON.stringify(r))));
      assert.equal(localRouter.countRequests('www.giant-bicycles.com', '/us/shop'), 0);

      const scrapeRes = await localHub.scrape({
        url: 'https://www.giant-bicycles.com/us/defy-advanced-pro-0',
        formats: ['markdown', 'product', { type: 'json', schema: { type: 'object', properties: { title: { type: 'string' } } } }],
        discoverLlmsTxt: false,
      });
      assert.equal(scrapeRes.status, 200);
      assert.equal(scrapeRes.body.extractorId, 'giant-liv-bikes');
      assert.match(scrapeRes.body.markdown, /562/);
      assert.ok(scrapeRes.body.product || scrapeRes.body.json);
    });
  });

  test('T3.34: F32 + F14 + F28 (L-04) bumm.de resolves relative JSON-LD Product.url & populates product, json, and PDF links', async () => {
    const res = await hub.scrape({
      url: 'https://bumm.de/en/product-detail/iq-x.html',
      formats: [
        'markdown',
        'product',
        'links',
        { type: 'json', schema: { type: 'object', properties: { sku: { type: 'string' }, price: { type: 'number' } } } },
      ],
      discoverLlmsTxt: false,
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.extractorId, 'bumm-de');
    assert.equal(res.body.product?.url, 'https://bumm.de/en/product-detail/iq-x.html');
    assert.equal(res.body.product?.sku, '164RTSNDI-01');
    assert.equal(res.body.json?.sku, '164RTSNDI-01');
    assert.ok((res.body.links ?? []).some((l) => l.includes('Anleitung_IQ-X.pdf')));
  });

  test('T3.35: F33 + POST /v1/crawl + GET /v1/crawl/:id pagination + redactPii on BicycleRetailer', async () => {
    const localRouter = createOutboundRouter();
    localRouter.setRobots('www.bicycleretailer.com', 'User-agent: *\nCrawl-delay: 1\nDisallow: /admin/\nAllow: /\n');
    localRouter.html('https://www.bicycleretailer.com/industry-news', F33_BICYCLE_RETAILER.listingHtml);
    const articleWithEmail = F33_BICYCLE_RETAILER.articleHtml.replace(
      'retail bicycle dealers.</p>',
      'retail bicycle dealers. Contact marc@bicycleretailer-t3.example.com.</p>',
    );
    localRouter.html('https://www.bicycleretailer.com/industry-news/2026/11/01/ebike-battery-rules', articleWithEmail);
    localRouter.html(
      'https://www.bicycleretailer.com/industry-news/2026/10/28/shimano-q3-results',
      F33_BICYCLE_RETAILER.articleHtml.replace('CPSC Finalizes E-Bike Battery Safety Guidance', 'Shimano Reports Q3 Results'),
    );

    await withFreshHub({ router: localRouter }, async (localHub) => {
      const crawlRes = await localHub.crawl({
        url: 'https://www.bicycleretailer.com/industry-news',
        sync: true,
        limit: 4,
        maxDepth: 1,
        delay: 0,
        sitemap: 'skip',
      });
      assert.equal(crawlRes.status, 200);
      assert.equal(crawlRes.body.status, 'completed');

      const page1 = await getCrawlWithQuery(localHub, crawlRes.body.id, 'offset=0&limit=2');
      assert.equal(page1.status, 200);
      assert.equal(page1.body.data.length, 2);
      assert.equal(page1.body.hasMore, true);
      assert.equal(page1.body.nextOffset, 2);

      const scrapeRes = await localHub.scrape({
        url: 'https://www.bicycleretailer.com/industry-news/2026/11/01/ebike-battery-rules',
        redactPii: true,
        discoverLlmsTxt: false,
      });
      assert.equal(scrapeRes.status, 200);
      assert.equal(scrapeRes.body.extractorId, 'bicycleretailer');
      assert.equal(scrapeRes.body.markdown.includes('marc@bicycleretailer-t3.example.com'), false);
    });
  });

  test('T3.36: F34 + F29 (L-05) + F36 + query YouTube /watch skips auto-render-1, blocks /api/timedtext & filters by query', async () => {
    const localRouter = createOutboundRouter();
    localRouter.setRobots('www.youtube.com', F34_YOUTUBE.robotsTxt);
    localRouter.html('https://www.youtube.com/watch?v=dQw4w9WgXcQ', F34_YOUTUBE.watchHtml());
    await withFreshHub({ router: localRouter }, async (localHub) => {
      const agent = await localHub.connectMockAgent({
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
                body: F34_YOUTUBE.watchHtml(),
                bodyEncoding: 'utf-8',
              },
            ],
          });
        },
      });
      const res = await localHub.scrape({
        url: 'https://www.youtube.com/watch?v=dQw4w9WgXcQ',
        query: 'Bosch CX Gen5 85 Nm',
        discoverLlmsTxt: false,
      });
      assert.equal(res.status, 200);
      assert.equal(res.body.rendered, false);
      assert.equal(res.body.queryFiltered, true);
      assert.equal(agent.frames.filter((f) => f.call.requests?.[0]?.id === 'auto-render-1').length, 0);
      assert.equal(localRouter.countRequests('www.youtube.com', '/api/timedtext'), 0);
    });
  });

  test('T3.37: F35 + F28 (L-04) + json Shimano RSC, SRAM & TQ eBike extract specs and product + json fields', async () => {
    const shimanoRes = await hub.scrape({
      url: 'https://productinfo.shimano.com/en/product/DU-EP801',
      discoverLlmsTxt: false,
    });
    assert.equal(shimanoRes.status, 200);
    assert.match(shimanoRes.body.markdown, /85 Nm/);

    const sramRes = await hub.scrape({
      url: 'https://www.sram.com/en/sram/models/rd-xx-e-b1',
      formats: ['markdown', 'product', { type: 'json', schema: { type: 'object', properties: { sku: { type: 'string' }, price: { type: 'number' } } } }],
      discoverLlmsTxt: false,
    });
    assert.equal(sramRes.status, 200);
    assert.equal(sramRes.body.extractorId, 'sram-models');
    assert.equal(sramRes.body.product?.sku, '00.7518.161.000');
    assert.equal(sramRes.body.json?.sku, '00.7518.161.000');

    const tqRes = await hub.scrape({
      url: 'https://www.tq-ebike.com/en/products/hpr50',
      formats: ['markdown', 'product', { type: 'json', schema: { type: 'object', properties: { sku: { type: 'string' } } } }],
      discoverLlmsTxt: false,
    });
    assert.equal(tqRes.status, 200);
    assert.equal(tqRes.body.extractorId, 'tq-ebike');
    assert.equal(tqRes.body.product?.sku, 'TQ-HPR50-SYS');
    assert.equal(tqRes.body.json?.sku, 'TQ-HPR50-SYS');
  });
});

// ============================================================================
// Suite 4: GET /v1/extractors & Multi-Source /v1/extract Combinations (T3.38–T3.40)
// ============================================================================
describe('Tier 3 — GET /v1/extractors & Multi-Source /v1/extract Combinations', () => {
  test('T3.38: GET /v1/extractors & ?category= expose all registered F01–F35 adapters with valid schemas', async () => {
    await withFreshHub(async (hub) => {
      const allRes = await hub.extractors();
      assert.equal(allRes.status, 200);
      assert.equal(allRes.body.ok, true);
      assert.ok(allRes.body.total >= 80, `Expected >= 80 extractors, got ${allRes.body.total}`);
      const catSum = Object.values(allRes.body.categories ?? {}).reduce((a, b) => a + b, 0);
      assert.equal(catSum, allRes.body.total);

      const ids = new Set((allRes.body.extractors ?? []).map((e) => e.id));
      const requiredIds = [
        'zendesk-hc',
        'shopify',
        'woocommerce',
        'federal-register',
        'cpsc-recalls',
        'us-cfr-govinfo',
        'eur-lex',
        'xenforo-thread',
        'squarespace-commerce',
        'bigcommerce-store',
        'sfcc-demandware',
        'shopware-magento',
        'sram-docs',
        'bosch-ebike-help',
        'terraform-registry',
        'docker-hub',
        'maven-central',
        'nuget-gallery',
        'homebrew-formulae',
        'osv-ghsa',
        'ukg-paylocity-dover',
        'nhtsa-vpic-recalls',
        'fcc-id',
        'wikidata-openlibrary',
        'giant-liv-bikes',
        'bumm-de',
        'bicycleretailer',
        'cornell-lii',
      ];
      for (const reqId of requiredIds) {
        assert.ok(ids.has(reqId), `Expected GET /v1/extractors to include "${reqId}"`);
      }

      const devRes = await hub.extractors('developer');
      assert.equal(devRes.status, 200);
      assert.ok(devRes.body.extractors.every((e) => e.category === 'developer'));
    });
  });

  test('T3.39: POST /v1/extract + F25 (L-01) + F15 + F20 bypasses unfiltered cache when jsonFilter is supplied', async () => {
    const router = createOutboundRouter();
    router.json('https://extract-l01.example.com/roles.json', F25_JSONFILTER_RECORDS);
    router.json('https://api.osv.dev/v1/vulns/GHSA-jfh8-c2jp-5v3q', F20_OSV.ghsaVulnJson(3));
    router.json('https://registry.terraform.io/v1/providers/hashicorp/random', F15_TERRAFORM.providerJson);

    await withFreshHub({ router }, async (hub) => {
      const first = await hub.extract({
        urls: [
          'https://extract-l01.example.com/roles.json',
          'https://osv.dev/vulnerability/GHSA-jfh8-c2jp-5v3q',
          'https://registry.terraform.io/providers/hashicorp/random',
        ],
        maxAgeMs: 600_000,
      });
      assert.equal(first.status, 200);
      assert.equal(first.body.results.length, 3);

      const filtered = await hub.extract({
        urls: [
          'https://extract-l01.example.com/roles.json',
          'https://osv.dev/vulnerability/GHSA-jfh8-c2jp-5v3q',
          'https://registry.terraform.io/providers/hashicorp/random',
        ],
        jsonFilter: 'team=Platform',
        maxAgeMs: 600_000,
      });
      assert.equal(filtered.status, 200);
      const rolesItem = filtered.body.results.find((r) => r.url.includes('roles.json'));
      assert.ok(rolesItem, 'Expected roles.json result');
      assert.equal(rolesItem.cached, false);
      assert.match(JSON.stringify(rolesItem.chunks), /Platform Role Alpha/);
      assert.equal(JSON.stringify(rolesItem.chunks).includes('Sales Role Bravo'), false);
    });
  });

  test('T3.40: F35 (law.cornell.edu) + F06 (govinfo.gov) + POST /v1/extract + redactPii ranks 16 CFR chunks & strips chrome', async () => {
    const router = createOutboundRouter();
    const cornellWithPii = F35_D1_HIGH_ROI.cornellCfrHtml.replace(
      'stopping distance test procedures.',
      'stopping distance test procedures. Inquiries: clerk@cornell-t3.example.edu.',
    );
    router.html('https://www.law.cornell.edu/cfr/text/16/part-1512', cornellWithPii);
    router.html('https://www.govinfo.gov/content/pkg/CFR-2023-title16-vol2/html/CFR-2023-title16-vol2.htm', F06_GOVINFO.cfrHtm);
    router.html('https://www.govinfo.gov/app/details/CFR-2023-title16-vol2', F06_GOVINFO.angularSpaShell);

    await withFreshHub({ router }, async (hub) => {
      const res = await hub.extract({
        urls: [
          'https://www.law.cornell.edu/cfr/text/16/part-1512',
          'https://www.govinfo.gov/app/details/CFR-2023-title16-vol2',
        ],
        query: '16 CFR bicycles brakes',
        redactPii: true,
        chunksPerSource: 2,
        includeRawContent: true,
      });
      assert.equal(res.status, 200);
      assert.equal(res.body.results.length, 2);
      for (const item of res.body.results) {
        assert.ok(item.chunks.length >= 1 && item.chunks.length <= 2);
        assert.ok((item.score ?? 0) > 0);
      }
      const cornellItem = res.body.results[0];
      assert.equal(JSON.stringify(cornellItem).includes('Cornell Donate Sidebar Noise'), false);
      assert.equal(JSON.stringify(cornellItem).includes('clerk@cornell-t3.example.edu'), false);
    });
  });
});
