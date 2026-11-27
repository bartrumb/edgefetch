import assert from 'node:assert/strict';
import { existsSync } from 'node:fs';
import { resolve } from 'node:path';
import test from 'node:test';

import { KNOWN_TELEMETRY_ADAPTER_IDS } from '../src/dev-telemetry';
import { DECLARATIVE_SITE_ADAPTERS } from '../src/extractors/declarative';
import { listRegisteredAdapters, resolveSiteExtractorTwin } from '../src/extractors/registry';
import {
  backfillProductFromRecord,
  executeScrapeCall,
  extractHtmlDocument,
  isTrustedTwinRedirectUrl,
} from '../src/scrape';
import { MAX_WASM_INPUT_BYTES, resetIsolateBudgetForTests } from '../src/wasm-bridge';

function okFetchReply(url: string, contentType: string, body: string, finalUrl = url) {
  return {
    status: 200,
    via: 'agent:test',
    bodyText: JSON.stringify({
      results: [
        {
          id: 'r1',
          url,
          finalUrl,
          status: 200,
          outcome: 'ok',
          contentType,
          body,
        },
      ],
    }),
  };
}

function failFetchReply(url: string, status: number, outcome: 'http_error' | 'skip' = 'http_error') {
  return {
    status: 200,
    via: 'agent:test',
    bodyText: JSON.stringify({
      results: [
        {
          id: 'r1',
          url,
          finalUrl: url,
          status,
          outcome,
          body: '',
        },
      ],
    }),
  };
}

test('M3-1: All M3 adapters registered, maxBytes bounded <= 4 MiB, telemetry allowlisted, and stray hub/{}) deleted', () => {
  const expectedIds = [
    'shopify',
    'woocommerce',
    'xenforo-thread',
    'squarespace-commerce',
    'bigcommerce-store',
    'sfcc-demandware',
    'shopware-magento',
    'sram-docs',
    'bosch-ebike-help',
  ];
  const all = listRegisteredAdapters();
  const byId = new Map(all.map((a) => [a.id, a]));
  for (const id of expectedIds) {
    assert.ok(byId.has(id), `missing M3 adapter ${id} in listRegisteredAdapters()`);
    assert.ok(KNOWN_TELEMETRY_ADAPTER_IDS.has(id), `missing M3 adapter ${id} in KNOWN_TELEMETRY_ADAPTER_IDS`);
  }
  assert.ok(DECLARATIVE_SITE_ADAPTERS.length >= 75);
  assert.equal(existsSync(resolve(process.cwd(), '{})')), false, 'stray 0-byte hub/{}) must be deleted');
});

test('M3-2 (Item #1): Shopify *.myshopify.com and custom-domain /collections/<handle> + SKU table + multi-handle', async () => {
  resetIsolateBudgetForTests();

  // 1. *.myshopify.com collection twin resolves to /collections/<handle>/products.json?limit=50
  const colTwin = resolveSiteExtractorTwin('https://acme.myshopify.com/collections/electric-bikes');
  assert.ok(colTwin);
  assert.equal(colTwin.fetchUrl, 'https://acme.myshopify.com/collections/electric-bikes/products.json?limit=50');
  assert.ok((colTwin.maxBytes ?? 0) <= MAX_WASM_INPUT_BYTES);

  // 2. *.myshopify.com/collections/<col>/products/<handle> MUST still resolve to single-product twin (not collection!)
  const prodInColTwin = resolveSiteExtractorTwin('https://acme.myshopify.com/collections/electric-bikes/products/roadster-1');
  assert.ok(prodInColTwin);
  assert.equal(prodInColTwin.fetchUrl, 'https://acme.myshopify.com/products/roadster-1.json');

  // 3. Cross-host redirect on *.myshopify.com fails open to HTML, then custom-domain collection enrichment runs on finalUrl!
  const fetchedUrls: string[] = [];
  const res = await executeScrapeCall({
    payload: { url: 'https://acme.myshopify.com/collections/electric-bikes', formats: ['markdown', 'records', 'product'] },
    env: {},
    executeHubFetch: async (_target, rawBody) => {
      const req = JSON.parse(rawBody) as {
        options: { respectRobots?: boolean; maxBytes?: number; maxInlineBodyBytes?: number };
        requests: Array<{ url: string }>;
      };
      const u = req.requests[0]!.url;
      fetchedUrls.push(u);
      assert.equal(req.options.respectRobots, true);
      assert.equal(req.options.maxInlineBodyBytes, MAX_WASM_INPUT_BYTES);
      if (u === 'https://acme.myshopify.com/collections/electric-bikes/products.json?limit=50') {
        // Cross-host redirect to custom domain -> rejected by isTrustedTwinRedirectUrl -> fails open to HTML!
        return okFetchReply(u, 'application/json', '{}', 'https://custombikes.example/collections/electric-bikes');
      }
      if (u === 'https://acme.myshopify.com/collections/electric-bikes') {
        return okFetchReply(
          u,
          'text/html',
          '<html><head><script>Shopify.shop="acme.myshopify.com";Shopify.currency={"active":"CAD"};</script></head><body><h1>Electric Bikes</h1></body></html>',
          'https://custombikes.example/collections/electric-bikes',
        );
      }
      if (u === 'https://custombikes.example/collections/electric-bikes/products.json?limit=50') {
        assert.equal(req.options.maxBytes, MAX_WASM_INPUT_BYTES);
        return okFetchReply(
          u,
          'application/json',
          JSON.stringify({
            products: [
              {
                id: 901,
                title: 'Roadster E-Bike',
                handle: 'roadster-ebike',
                vendor: 'CustomBikes',
                product_type: 'E-Bikes',
                variants: [{ id: 9001, sku: 'CB-RD-500', price: '1899.00', available: true }],
              },
            ],
          }),
        );
      }
      return failFetchReply(u, 404);
    },
  });

  assert.equal(res.status, 200);
  assert.ok(fetchedUrls.includes('https://custombikes.example/collections/electric-bikes/products.json?limit=50'));
  assert.equal(res.body.detected?.adapter, 'shopify');
  const md = String(res.body.markdown ?? '');
  assert.ok(md.includes('| Product | Vendor | Type | SKU | Variants | Price | Stock | Updated |'));
  assert.ok(md.includes('CB-RD-500'));
  assert.ok(md.includes('CAD 1899.00'));
  assert.equal((res.body.records as Array<Record<string, unknown>>)?.[0]?.platform, 'shopify');
});

test('M3-3 (Item #2): WooCommerce custom-domain /product-category/<slug> and /shop/ twins + fail-open HTML fallback', async () => {
  resetIsolateBudgetForTests();

  const seenRequests: Array<{ url: string; maxBytes?: number; respectRobots?: boolean }> = [];
  const wooHtml = `<html><body class="woocommerce-page tax-product_cat">
    <h1 class="woocommerce-products-header__title">Gravel Bikes</h1>
    <ul class="products"><li class="product">
      <a href="/product/gravel-pro/"><h2 class="woocommerce-loop-product__title">Gravel Pro</h2></a>
      <span class="price"><span class="amount">$1,450.00</span></span>
      <a class="add_to_cart_button" data-product_id="55" data-product_sku="GP-55">Add</a>
    </li></ul>
  </body></html>`;

  // Case A: Store API succeeds with per_page=50
  const okRes = await executeScrapeCall({
    payload: { url: 'https://ridestore.example/product-category/bikes/ebikes/', formats: ['markdown', 'records'] },
    env: {},
    executeHubFetch: async (_target, rawBody) => {
      const req = JSON.parse(rawBody) as {
        options: { respectRobots?: boolean; maxBytes?: number; maxInlineBodyBytes?: number };
        requests: Array<{ url: string }>;
      };
      const u = req.requests[0]!.url;
      seenRequests.push({ url: u, maxBytes: req.options.maxBytes, respectRobots: req.options.respectRobots });
      if (u === 'https://ridestore.example/product-category/bikes/ebikes/') {
        return okFetchReply(u, 'text/html', wooHtml);
      }
      if (u === 'https://ridestore.example/wp-json/wc/store/v1/products?category=ebikes&per_page=50') {
        assert.equal(req.options.respectRobots, true);
        assert.equal(req.options.maxBytes, MAX_WASM_INPUT_BYTES);
        return okFetchReply(
          u,
          'application/json',
          JSON.stringify([
            {
              id: 701,
              slug: 'commuter-500',
              name: 'Commuter 500',
              sku: 'WOO-500',
              is_in_stock: true,
              prices: { price: '129900', currency_code: 'USD', currency_minor_unit: 2 },
            },
          ]),
        );
      }
      return failFetchReply(u, 404);
    },
  });
  assert.equal(okRes.status, 200);
  assert.ok(seenRequests.some((r) => r.url === 'https://ridestore.example/wp-json/wc/store/v1/products?category=ebikes&per_page=50'));
  assert.ok(String(okRes.body.markdown ?? '').includes('WOO-500'));
  assert.equal((okRes.body.records as Array<Record<string, unknown>>)?.[0]?.platform, 'woocommerce');

  // Case B: Store API disallowed by robots.txt (`outcome: 'skip'`) -> fails open cleanly to HTML catalog extraction!
  const fallbackRes = await executeScrapeCall({
    payload: { url: 'https://ridestore.example/shop/', formats: ['markdown', 'records'] },
    env: {},
    executeHubFetch: async (_target, rawBody) => {
      const req = JSON.parse(rawBody) as { requests: Array<{ url: string }> };
      const u = req.requests[0]!.url;
      if (u === 'https://ridestore.example/shop/') {
        return okFetchReply(u, 'text/html', wooHtml);
      }
      return failFetchReply(u, 403, 'skip');
    },
  });
  assert.equal(fallbackRes.status, 200);
  assert.ok(String(fallbackRes.body.markdown ?? '').includes('Gravel Pro'));
  assert.ok(String(fallbackRes.body.markdown ?? '').includes('GP-55'));
});

test('M3-4 (Item #3): xenforo-thread extracts posts/authors/timestamps/quotes without signatures or sidebars', async () => {
  resetIsolateBudgetForTests();
  let fetchCalls = 0;
  const xfHtml = `<!doctype html><html><body>
    <h1 class="p-title-value">Bafang M620 Firmware Thread</h1>
    <div class="p-body-main">
      <article class="message message--post" data-author="TorqueRider">
        <time class="u-dt" datetime="2026-05-01T10:00:00Z">May 1, 2026</time>
        <div class="bbWrapper"><p>UART programming cable pinout details.</p></div>
        <aside class="message-signature">Hidden signature footer</aside>
      </article>
      <article class="message message--post" data-author="VoltTech">
        <time class="u-dt" datetime="2026-05-02T11:30:00Z">May 2, 2026</time>
        <div class="bbWrapper">
          <blockquote class="bbCodeBlock bbCodeBlock--quote">
            <div class="bbCodeBlock-title">TorqueRider said:</div>
            <div class="bbCodeBlock-content">
              <div class="bbCodeBlock-expandContent"><p>UART programming cable pinout details.</p></div>
              <div class="bbCodeBlock-expandLink">Click to expand...</div>
            </div>
          </blockquote>
          <p>Use 1200 baud for readback.</p>
        </div>
      </article>
    </div>
    <aside class="p-body-sidebar">Sidebar Ads</aside>
  </body></html>`;

  const res = await executeScrapeCall({
    payload: { url: 'https://endless-sphere.com/sphere/threads/bafang-m620.88123/', formats: ['markdown', 'records'] },
    env: {},
    executeHubFetch: async (_target, rawBody) => {
      fetchCalls++;
      const req = JSON.parse(rawBody) as { requests: Array<{ url: string }> };
      return okFetchReply(req.requests[0]!.url, 'text/html', xfHtml);
    },
  });

  assert.equal(res.status, 200);
  assert.equal(fetchCalls, 1, 'xenforo-thread must not issue extra twin fetches');
  assert.equal(res.body.detected?.adapter, 'xenforo-thread');
  const md = String(res.body.markdown ?? '');
  assert.ok(md.includes('Original Post — TorqueRider'));
  assert.ok(md.includes('> **TorqueRider said:**'));
  assert.equal(md.includes('Click to expand...'), false);
  assert.equal(md.includes('Hidden signature footer'), false);
  assert.equal(md.includes('Sidebar Ads'), false);
  assert.equal((res.body.records as Array<unknown>)?.length, 2);
});

test('M3-5 (Item #4): squarespace-commerce ?format=json-pretty twin, strict same-host redirect, non-commerce skip', async () => {
  resetIsolateBudgetForTests();

  // Case A: Commerce store fetches ?format=json-pretty with bounded guards
  const sqHtml = `<html><head><script>Static={};Static.SQUARESPACE_CONTEXT={"productType":1};</script></head><body><div class="ProductList"></div></body></html>`;
  const res = await executeScrapeCall({
    payload: { url: 'https://studio.example.com/shop', formats: ['markdown', 'records'] },
    env: {},
    executeHubFetch: async (_target, rawBody) => {
      const req = JSON.parse(rawBody) as {
        options: { respectRobots?: boolean; maxBytes?: number; maxInlineBodyBytes?: number };
        requests: Array<{ url: string }>;
      };
      const u = req.requests[0]!.url;
      if (u === 'https://studio.example.com/shop') {
        return okFetchReply(u, 'text/html', sqHtml);
      }
      if (u === 'https://studio.example.com/shop?format=json-pretty') {
        assert.equal(req.options.respectRobots, true);
        assert.equal(req.options.maxBytes, MAX_WASM_INPUT_BYTES);
        assert.equal(req.options.maxInlineBodyBytes, MAX_WASM_INPUT_BYTES);
        return okFetchReply(
          u,
          'application/json',
          JSON.stringify({
            collection: { title: 'Studio Gear' },
            items: [
              {
                id: 'item-1',
                urlId: 'canvas-pack',
                fullUrl: '/shop/p/canvas-pack',
                title: 'Canvas Frame Bag',
                structuredContent: {
                  variants: [
                    { id: 'v1', sku: 'SQ-BAG-01', priceMoney: { value: '85.00', currency: 'USD' }, stock: { unlimited: true } },
                  ],
                },
              },
            ],
          }),
        );
      }
      return failFetchReply(u, 404);
    },
  });
  assert.equal(res.status, 200);
  assert.equal(res.body.detected?.adapter, 'squarespace-commerce');
  assert.ok(String(res.body.markdown ?? '').includes('SQ-BAG-01'));
  assert.equal((res.body.records as Array<Record<string, unknown>>)?.[0]?.platform, 'squarespace');

  // Case B: Non-commerce Squarespace blog MUST NOT trigger ?format=json-pretty fetch
  let twinAttempted = false;
  await executeScrapeCall({
    payload: { url: 'https://blog.example.com/posts/hello', formats: ['markdown'] },
    env: {},
    executeHubFetch: async (_target, rawBody) => {
      const req = JSON.parse(rawBody) as { requests: Array<{ url: string }> };
      const u = req.requests[0]!.url;
      if (u.includes('format=json-pretty')) twinAttempted = true;
      return okFetchReply(
        u,
        'text/html',
        '<html><head><script>Static={};Static.SQUARESPACE_CONTEXT={};</script></head><body><article><h1>Hello Blog</h1><p>Not a store.</p></article></body></html>',
      );
    },
  });
  assert.equal(twinAttempted, false, 'non-commerce Squarespace blog must not fetch ?format=json-pretty');

  // Case C: Cross-host redirect for undefined trustAdapterId fails closed without throwing
  assert.equal(
    isTrustedTwinRedirectUrl(undefined, 'https://studio.example.com/shop?format=json-pretty', {
      finalUrl: 'https://other-host.example/shop?format=json-pretty',
    }),
    false,
  );
});

test('M3-6 (Item #5): bigcommerce-store Stencil BCData + /xmlsitemap.php twin + non-XML fail-open', async () => {
  resetIsolateBudgetForTests();

  // 1. Pre-fetch /xmlsitemap.php twin
  const smTwin = resolveSiteExtractorTwin('https://demo.mybigcommerce.com/xmlsitemap.php');
  assert.ok(smTwin);
  assert.ok((smTwin.maxBytes ?? 0) <= MAX_WASM_INPUT_BYTES);
  const nonXmlDoc = smTwin.formatTwin('<html><body>Not a sitemap</body></html>', 'https://example.com/xmlsitemap.php', () => ({
    markdown: '',
    links: [],
  }));
  assert.equal(nonXmlDoc, null, 'non-XML /xmlsitemap.php must fail open cleanly');

  const smRes = await executeScrapeCall({
    payload: { url: 'https://demo.mybigcommerce.com/xmlsitemap.php', formats: ['markdown', 'records'] },
    env: {},
    executeHubFetch: async (_target, rawBody) => {
      const req = JSON.parse(rawBody) as { requests: Array<{ url: string }> };
      return okFetchReply(
        req.requests[0]!.url,
        'application/xml',
        `<?xml version="1.0"?><urlset><url><loc>https://demo.mybigcommerce.com/helmet-1/</loc><lastmod>2026-05-01</lastmod></url></urlset>`,
      );
    },
  });
  assert.equal(smRes.status, 200);
  assert.ok(String(smRes.body.markdown ?? '').includes('https://demo.mybigcommerce.com/helmet-1/'));

  // 2. HTML Stencil BCData + options + <dl class="productView-info">
  const bcHtml = `<!doctype html><html><head>
    <script src="https://cdn11.bigcommerce.com/s-abc/stencil.js"></script>
    <script>window.BCData = {"product_attributes":{"sku":"BC-900","instock":true,"price":{"without_tax":{"value":499,"currency":"USD"}}}};</script>
  </head><body>
    <h1 class="productView-title">Carbon Seatpost</h1>
    <dl class="productView-info"><dt class="productView-info-name">Diameter:</dt><dd class="productView-info-value">27.2 mm</dd></dl>
    <form data-cart-item-add><input type="hidden" name="product_id" value="900" /><div class="form-field"><label class="form-label">Offset:</label><select name="attribute[1]"><option value="1">20mm</option></select></div></form>
  </body></html>`;
  const htmlRes = await executeScrapeCall({
    payload: { url: 'https://custom-bc.example/carbon-seatpost/', formats: ['markdown', 'records'] },
    env: {},
    executeHubFetch: async (_target, rawBody) => {
      const req = JSON.parse(rawBody) as { requests: Array<{ url: string }> };
      return okFetchReply(req.requests[0]!.url, 'text/html', bcHtml);
    },
  });
  assert.equal(htmlRes.status, 200);
  assert.equal(htmlRes.body.detected?.adapter, 'bigcommerce-store');
  assert.ok(String(htmlRes.body.markdown ?? '').includes('BC-900'));
  assert.ok(String(htmlRes.body.markdown ?? '').includes('27.2 mm'));
  assert.equal((htmlRes.body.records as Array<Record<string, unknown>>)?.[0]?.platform, 'bigcommerce');
});

test('M3-7 (Item #6): sfcc-demandware structural detection, Product-Variation twin, and 403 fail-open to geometry HTML', async () => {
  resetIsolateBudgetForTests();

  const sfccHtml = `<!doctype html><html><head>
    <link rel="stylesheet" href="/on/demandware.static/Sites-Generic-Site/-/en_US/v1/style.css" />
  </head><body>
    <h1 class="product-name" data-pid="TRAIL-9">Trail 9 Bike</h1>
    <div data-url="/on/demandware.store/Sites-Generic-Site/en_US/Product-Variation?pid=TRAIL-9"></div>
    <table class="geometry-table"><tr><th>Size</th><th>Reach (mm)</th></tr><tr><td>M</td><td>445</td></tr></table>
  </body></html>`;

  // Case A: Variation JSON succeeds on arbitrary non-hardcoded host
  const okRes = await executeScrapeCall({
    payload: { url: 'https://bikes.arbitrary.example/p/trail-9', formats: ['markdown', 'records'] },
    env: {},
    executeHubFetch: async (_target, rawBody) => {
      const req = JSON.parse(rawBody) as { requests: Array<{ url: string }> };
      const u = req.requests[0]!.url;
      if (u === 'https://bikes.arbitrary.example/p/trail-9') {
        return okFetchReply(u, 'text/html', sfccHtml);
      }
      if (u.includes('Product-Variation?pid=TRAIL-9')) {
        return okFetchReply(
          u,
          'application/json',
          JSON.stringify({
            product: {
              id: 'TRAIL-9',
              productName: 'Trail 9 Bike',
              brand: 'Arbitrary',
              available: true,
              price: { sales: { value: 2499.0, currency: 'USD' } },
            },
          }),
        );
      }
      return failFetchReply(u, 404);
    },
  });
  assert.equal(okRes.status, 200);
  assert.equal(okRes.body.detected?.adapter, 'sfcc-demandware');
  assert.ok(String(okRes.body.markdown ?? '').includes('2499.00'));
  assert.ok(String(okRes.body.markdown ?? '').includes('| M | 445 |'));

  // Case B: Product-Variation returns 403 -> fails open cleanly to sfcc_html geometry table
  const fbRes = await executeScrapeCall({
    payload: { url: 'https://bikes.arbitrary.example/p/trail-9', formats: ['markdown', 'records'] },
    env: {},
    executeHubFetch: async (_target, rawBody) => {
      const req = JSON.parse(rawBody) as { requests: Array<{ url: string }> };
      const u = req.requests[0]!.url;
      if (u === 'https://bikes.arbitrary.example/p/trail-9') {
        return okFetchReply(u, 'text/html', sfccHtml);
      }
      return failFetchReply(u, 403);
    },
  });
  assert.equal(fbRes.status, 200);
  assert.equal(fbRes.body.detected?.adapter, 'sfcc-demandware');
  assert.ok(String(fbRes.body.markdown ?? '').includes('| M | 445 |'));
});

test('M3-8 (Item #7): shopware-magento (Magento 2 swatches + bounded REST fail-open, Shopware 6 specs)', async () => {
  resetIsolateBudgetForTests();

  // 1. Magento 2 with data-product-id but no inline jsonConfig -> tries bounded /rest/V1/products-render-info, fails open on 401
  const magFallbackHtml = `<!doctype html><html><body>
    <h1 class="page-title"><span>Brakes Set</span></h1>
    <div data-role="swatch-options" data-product-id="881"></div>
    <script type="text/x-magento-init">{"*":{"Magento_Catalog/js/product":{}}}</script>
    <table id="product-attribute-specs-table"><tr><th>Rotor</th><td>203 mm</td></tr></table>
  </body></html>`;
  let restUrlSeen = '';
  const magOk = await executeScrapeCall({
    payload: { url: 'https://parts.arbitrary.example/brakes-set', formats: ['markdown', 'records'] },
    env: {},
    executeHubFetch: async (_target, rawBody) => {
      const req = JSON.parse(rawBody) as { requests: Array<{ url: string }> };
      const u = req.requests[0]!.url;
      if (u === 'https://parts.arbitrary.example/brakes-set') {
        return okFetchReply(u, 'text/html', magFallbackHtml);
      }
      if (u.includes('/rest/V1/products-render-info')) {
        restUrlSeen = u;
        return okFetchReply(
          u,
          'application/json',
          JSON.stringify({
            items: [{ id: 881, name: 'Brakes Set', sku: 'MAG-881', currency_code: 'USD', is_salable: '1', price_info: { final_price: 199.95 } }],
          }),
        );
      }
      return failFetchReply(u, 404);
    },
  });
  assert.equal(magOk.status, 200);
  assert.ok(restUrlSeen.includes('pageSize]=1'));
  assert.ok(String(magOk.body.markdown ?? '').includes('MAG-881'));
  assert.ok(String(magOk.body.markdown ?? '').includes('203 mm'));

  // 2. Shopware 6 structural HTML extraction
  const swHtml = `<!doctype html><html><body><div class="sw-product-detail">
    <h1 class="product-detail-name">M99 Headlight</h1>
    <span class="product-detail-ordernumber">SW-M99</span>
    <span class="product-detail-price">€249,00</span>
    <table class="product-detail-properties-table"><tr><th>Output</th><td>1600 lm</td></tr></table>
  </div></body></html>`;
  const swRes = await executeScrapeCall({
    payload: { url: 'https://lights.arbitrary.example/m99', formats: ['markdown', 'records'] },
    env: {},
    executeHubFetch: async (_target, rawBody) => {
      const req = JSON.parse(rawBody) as { requests: Array<{ url: string }> };
      return okFetchReply(req.requests[0]!.url, 'text/html', swHtml);
    },
  });
  assert.equal(swRes.status, 200);
  assert.equal(swRes.body.detected?.adapter, 'shopware-magento');
  assert.ok(String(swRes.body.markdown ?? '').includes('1600 lm'));
  assert.equal((swRes.body.records as Array<Record<string, unknown>>)?.[0]?.platform, 'shopware6');
});

test('M3-9 (Item #8): sram-docs & bosch-ebike-help strip data:image/dodo-error, zero /api/* calls on help.bosch-ebike.com', async () => {
  resetIsolateBudgetForTests();
  const boschFetched: string[] = [];
  const boschBodyFiller =
    'Verify the rear wheel spoke magnet alignment with the sensor housing mark on the chainstay. ' +
    'Ensure the gap between magnet and sensor is between 5 mm and 17 mm, inspect the cable routing for kinks or pinches, ' +
    'and restart the drive unit after tightening the magnet screw to specification. If error code 503 persists after cleaning ' +
    'both contact surfaces and verifying battery charge state, consult your authorized dealer diagnostic report for wheel circumference calibration.';
  const boschHtml = `<!doctype html><html><body>
    <nav aria-label="breadcrumb"><a href="/us/help-center">Help Center</a><span>Error Codes</span></nav>
    <img src="data:image/png;base64,${'B'.repeat(4096)}" alt="inline" />
    <div class="dodo-service-include__error" aria-hidden="true">Broken include banner</div>
    <template id="B:0">Spinner</template>
    <div hidden id="S:0"><h1>Error 503</h1><p>Check speed sensor magnet. ${boschBodyFiller}</p><a href="https://help.bosch-ebike.com/files/guide.pdf">Guide</a></div>
    <script>$RC("B:0","S:0");</script>
  </body></html>`;

  const boschRes = await executeScrapeCall({
    payload: { url: 'https://help.bosch-ebike.com/us/help-center/ebw-error-codes?models=bdu37yy', formats: ['markdown', 'links'] },
    env: {},
    executeHubFetch: async (_target, rawBody) => {
      const req = JSON.parse(rawBody) as { requests: Array<{ url: string }> };
      const u = req.requests[0]!.url;
      boschFetched.push(u);
      return okFetchReply(u, 'text/html', boschHtml);
    },
  });
  assert.equal(boschRes.status, 200);
  assert.deepEqual(boschFetched, ['https://help.bosch-ebike.com/us/help-center/ebw-error-codes?models=bdu37yy']);
  assert.equal(boschFetched.some((u) => u.includes('/api/')), false, 'must NEVER call /api/* on help.bosch-ebike.com');
  assert.equal(boschRes.body.detected?.adapter, 'bosch-ebike-help');
  const bmd = String(boschRes.body.markdown ?? '');
  assert.ok(bmd.includes('Check speed sensor magnet.'));
  assert.ok(bmd.includes('bdu37yy'));
  assert.ok(bmd.includes('https://help.bosch-ebike.com/files/guide.pdf'));
  assert.equal(bmd.includes('data:image/'), false);
  assert.equal(bmd.includes('Broken include banner'), false);

  // www.bosch-ebike.com must NOT match bosch-ebike-help
  const wwwRes = await executeScrapeCall({
    payload: { url: 'https://www.bosch-ebike.com/us/products', formats: ['markdown'] },
    env: {},
    executeHubFetch: async (_target, rawBody) => {
      const req = JSON.parse(rawBody) as { requests: Array<{ url: string }> };
      return okFetchReply(req.requests[0]!.url, 'text/html', '<html><body><main><h1>Products</h1><p>Overview.</p></main></body></html>');
    },
  });
  assert.notEqual(wwwRes.body.detected?.adapter, 'bosch-ebike-help');

  // React 18 streaming Suspense ($RC) inside <main> (>= 20 chars shell) + out-of-band <div hidden id="S:0"> + .dodo-service-include__error
  const suspenseInMainHtml = `<!doctype html><html><body>
    <main><h1>Bosch Help</h1><p>Please wait while loading article details...</p><!--$?--><template id="B:0"></template><!--/$--></main>
    <div class="dodo-service-include__error">Error loading</div>
    <div hidden id="S:0"><h2>Error 503 Guide</h2><p>${boschBodyFiller}</p></div>
    <script>$RC("B:0","S:0")</script>
  </body></html>`;
  const suspenseRes = await executeScrapeCall({
    payload: { url: 'https://help.bosch-ebike.com/us/help-center/ebw-suspense', formats: ['markdown'] },
    env: {},
    executeHubFetch: async (_target, rawBody) => {
      const req = JSON.parse(rawBody) as { requests: Array<{ url: string }> };
      return okFetchReply(req.requests[0]!.url, 'text/html', suspenseInMainHtml);
    },
  });
  assert.equal(suspenseRes.status, 200);
  assert.equal(suspenseRes.body.detected?.adapter, 'bosch-ebike-help');
  const smd = String(suspenseRes.body.markdown ?? '');
  assert.ok(smd.includes('Error 503 Guide'));
  assert.ok(smd.includes('Verify the rear wheel spoke magnet alignment'));
  assert.equal(smd.includes('Error loading'), false);
});

test('M3-10 (Item #9): backfillProductFromRecord normalizes "Not in stock" to OutOfStock before InStock & resolves ctx.finalUrl', () => {
  const out = backfillProductFromRecord(
    { url: 'https://shop.example/p/1', title: 'Widget' },
    {
      variants: [{ sku: 'W-1', price: 29.99, currency: 'USD', availability: 'Not in stock' }],
    },
    { finalUrl: 'https://shop.example/p/1' },
  );
  assert.ok(out);
  assert.equal(out.availability, 'OutOfStock');

  const outSpaces = backfillProductFromRecord(
    { url: 'https://shop.example/p/2', title: 'Widget 2' },
    {
      availability: '  not   in   stock  ',
    },
    { finalUrl: 'https://shop.example/p/2' },
  );
  assert.ok(outSpaces);
  assert.equal(outSpaces.availability, 'OutOfStock');

  const inStock = backfillProductFromRecord(
    { url: 'https://shop.example/p/3', title: 'Widget 3' },
    {
      availability: 'In stock',
    },
    { finalUrl: 'https://shop.example/p/3' },
  );
  assert.ok(inStock);
  assert.equal(inStock.availability, 'InStock');

  // Null productOut resolves url from ctx.finalUrl, and existing unnormalized out.availability is normalized.
  const fromNull = backfillProductFromRecord(
    null,
    { title: 'Widget 4', sku: 'W-4', availability: 'Not in stock' },
    { finalUrl: 'https://shop.example/p/4' },
  );
  assert.ok(fromNull);
  assert.equal(fromNull.url, 'https://shop.example/p/4');
  assert.equal(fromNull.availability, 'OutOfStock');

  const existingOut = backfillProductFromRecord(
    { url: 'https://shop.example/p/5', title: 'Widget 5', availability: 'Not in stock' },
    { sku: 'W-5', availability: 'In stock' },
    { finalUrl: 'https://shop.example/p/5' },
  );
  assert.ok(existingOut);
  assert.equal(existingOut.availability, 'OutOfStock');
});

test('M3-11: Markdown link injection prevention across BigCommerce XML sitemap and Squarespace JSON via executeScrapeCall', async () => {
  resetIsolateBudgetForTests();

  const bcXml = `<?xml version="1.0" encoding="UTF-8"?>
  <urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9" xmlns:image="http://www.google.com/schemas/sitemap-image/1.1">
    <url>
      <loc>https://demo.mybigcommerce.com/a)[xss](https://evil.com)</loc>
      <lastmod>2026-04-01</lastmod>
      <image:image><image:loc>https://cdn.example.com/a[imgxss](https://evil.com)</image:loc></image:image>
    </url>
  </urlset>`;
  const bcRes = await executeScrapeCall({
    payload: { url: 'https://demo.mybigcommerce.com/xmlsitemap.php', formats: ['markdown'] },
    env: {},
    executeHubFetch: async (_target, rawBody) => {
      const req = JSON.parse(rawBody) as { requests: Array<{ url: string }> };
      return okFetchReply(req.requests[0]!.url, 'application/xml', bcXml);
    },
  });
  assert.equal(bcRes.status, 200);
  const bcMd = String(bcRes.body.markdown ?? '');
  assert.equal(bcMd.includes('](https://evil.com)'), false);
  assert.equal(bcMd.includes('https://evil.com)'), false);
  assert.ok(bcMd.includes('%29%5Bxss%5D%28'));

  const sqJson = JSON.stringify({
    items: [
      {
        id: 'sq-xss',
        title: 'Safe Product',
        fullUrl: 'https://sq.arbitrary.example/shop/p/a)[xss](https://evil.com)',
        structuredContent: {
          variants: [{ id: 'v1', sku: 'SQ-1', priceMoney: { value: '49.00', currency: 'USD' } }],
        },
      },
    ],
  });
  const sqRes = await executeScrapeCall({
    payload: { url: 'https://sq.arbitrary.example/shop', formats: ['markdown'] },
    env: {},
    executeHubFetch: async (_target, rawBody) => {
      const req = JSON.parse(rawBody) as { requests: Array<{ url: string }> };
      const u = req.requests[0]!.url;
      if (u.includes('format=json-pretty')) {
        return okFetchReply(u, 'application/json', sqJson);
      }
      return okFetchReply(
        u,
        'text/html',
        '<html><head><script>Static = {}; Static.SQUARESPACE_CONTEXT = {"productType":1};</script></head><body><div class="ProductList"></div></body></html>',
      );
    },
  });
  assert.equal(sqRes.status, 200);
  const sqMd = String(sqRes.body.markdown ?? '');
  assert.equal(sqMd.includes('](https://evil.com)'), false);
  assert.equal(sqMd.includes('https://evil.com)'), false);
  assert.ok(sqMd.includes('%29%5Bxss%5D%28'));
});

test('M3-12: BigCommerce BCData stub shadowing and Schema.org Microdata product extraction via executeScrapeCall', async () => {
  resetIsolateBudgetForTests();

  const bcEmptyFirstHtml = `<!doctype html><html><head>
    <script src="https://cdn11.bigcommerce.com/s-demo123/stencil.js"></script>
    <script>window.BCData = window.BCData || {};</script>
    <script>BCData = {"product_attributes":{"sku":"REAL-SKU","instock":true,"price":{"without_tax":{"value":50,"currency":"USD"}}}};</script>
  </head><body><h1 class="productView-title">Bike</h1></body></html>`;
  const r1 = await executeScrapeCall({
    payload: { url: 'https://demo.mybigcommerce.com/bike/', formats: ['markdown', 'records'] },
    env: {},
    executeHubFetch: async (_target, rawBody) => {
      const req = JSON.parse(rawBody) as { requests: Array<{ url: string }> };
      return okFetchReply(req.requests[0]!.url, 'text/html', bcEmptyFirstHtml);
    },
  });
  assert.equal(r1.status, 200);
  assert.equal(r1.body.detected?.adapter, 'bigcommerce-store');
  assert.ok(String(r1.body.markdown ?? '').includes('REAL-SKU'));
  assert.equal((r1.body.records as Array<Record<string, unknown>>)?.[0]?.variants?.[0]?.sku, 'REAL-SKU');

  const bcMicrodataHtml = `<!doctype html><html><head>
    <script src="https://cdn11.bigcommerce.com/s-abc/stencil.js"></script>
  </head><body>
    <div itemscope itemtype="https://schema.org/Product">
      <h1 itemprop="name">Microdata Helmet</h1>
      <span itemprop="sku">MD-99</span>
      <div itemprop="offers" itemscope itemtype="https://schema.org/Offer">
        <meta itemprop="price" content="79.95"/>
        <meta itemprop="priceCurrency" content="USD"/>
        <link itemprop="availability" href="https://schema.org/OutOfStock"/>
      </div>
      <form data-cart-item-add>
        <div class="form-field"><label class="form-label">Size:</label><select><option value="1">M</option></select></div>
      </form>
    </div>
  </body></html>`;
  const r2 = await executeScrapeCall({
    payload: { url: 'https://bc-custom.arbitrary.example/helmet/', formats: ['markdown', 'records'] },
    env: {},
    executeHubFetch: async (_target, rawBody) => {
      const req = JSON.parse(rawBody) as { requests: Array<{ url: string }> };
      return okFetchReply(req.requests[0]!.url, 'text/html', bcMicrodataHtml);
    },
  });
  assert.equal(r2.status, 200);
  assert.equal(r2.body.detected?.adapter, 'bigcommerce-store');
  assert.ok(String(r2.body.markdown ?? '').includes('MD-99'));
  const rec2 = (r2.body.records as Array<Record<string, unknown>>)?.[0] as Record<string, unknown>;
  assert.equal((rec2?.variants as Array<Record<string, unknown>>)?.[0]?.price, 79.95);
  assert.equal((rec2?.options as Array<Record<string, unknown>>)?.[0]?.name, 'Size');
});

test('M3-13: ExtractStructuredProduct normalizes JSON-LD & OpenGraph "Not in stock" to OutOfStock in product format', async () => {
  resetIsolateBudgetForTests();

  const ldHtml = `<!doctype html><html><head><script type="application/ld+json">{"@type":"Product","name":"Lock","offers":{"@type":"Offer","price":"39.00","priceCurrency":"USD","availability":"Not in stock"}}</script></head><body><h1>Lock</h1></body></html>`;
  const ldRes = await executeScrapeCall({
    payload: { url: 'https://shop.arbitrary.example/p/lock', formats: ['product'] },
    env: {},
    executeHubFetch: async (_target, rawBody) => {
      const req = JSON.parse(rawBody) as { requests: Array<{ url: string }> };
      return okFetchReply(req.requests[0]!.url, 'text/html', ldHtml);
    },
  });
  assert.equal(ldRes.status, 200);
  assert.equal((ldRes.body.product as Record<string, unknown>)?.availability, 'OutOfStock');

  const ogHtml = `<!doctype html><html><head><meta property="og:title" content="Rack"/><meta property="product:price:amount" content="89.00"/><meta property="product:availability" content="Not in stock"/></head><body><h1>Rack</h1></body></html>`;
  const ogRes = await executeScrapeCall({
    payload: { url: 'https://shop.arbitrary.example/p/rack', formats: ['product'] },
    env: {},
    executeHubFetch: async (_target, rawBody) => {
      const req = JSON.parse(rawBody) as { requests: Array<{ url: string }> };
      return okFetchReply(req.requests[0]!.url, 'text/html', ogHtml);
    },
  });
  assert.equal(ogRes.status, 200);
  assert.equal((ogRes.body.product as Record<string, unknown>)?.availability, 'OutOfStock');
});

test('M3-14: Declarative twinFetchUrl forwarding & custom-domain WooCommerce redirect fail-closed guard', async () => {
  resetIsolateBudgetForTests();

  const noopHtmlToMd = (frag: string) => ({ markdown: frag, links: [] });

  // 1. *.myshopify.com/collections/ebikes forwards resolved.fetchUrl (?limit=50) into formatCommerceTwinDoc
  const shopColUrl = 'https://acme.myshopify.com/collections/ebikes';
  const twin = resolveSiteExtractorTwin(shopColUrl);
  assert.ok(twin);
  const makeProducts = (n: number) =>
    JSON.stringify({
      products: Array.from({ length: n }, (_, i) => ({
        id: i + 1,
        title: `Bike ${i + 1}`,
        handle: `bike-${i + 1}`,
        variants: [{ id: i + 100, sku: `BK-${i + 1}`, price: '999.00', available: true }],
      })),
    });
  const doc35 = twin.formatTwin(makeProducts(35), shopColUrl, noopHtmlToMd) as {
    pagination?: { limit?: number; hasMore?: boolean; nextUrl?: string };
  };
  assert.equal(doc35?.pagination?.limit, 50);
  assert.equal(doc35?.pagination?.hasMore, false);

  const doc50 = twin.formatTwin(makeProducts(50), shopColUrl, noopHtmlToMd) as {
    pagination?: { limit?: number; hasMore?: boolean; nextUrl?: string };
  };
  assert.equal(doc50?.pagination?.limit, 50);
  assert.equal(doc50?.pagination?.hasMore, true);
  assert.equal(doc50?.pagination?.nextUrl, 'https://acme.myshopify.com/collections/ebikes/products.json?limit=50&page=2');

  // 2. woocommerce.yaml Route 1 (/wp-json/wc/store/v1/products) with [] still returns empty table message
  const wooDirectUrl = 'https://woo.example.com/wp-json/wc/store/v1/products';
  const wooTwin = resolveSiteExtractorTwin(wooDirectUrl);
  assert.ok(wooTwin);
  const wooEmptyDoc = wooTwin.formatTwin('[]', wooDirectUrl, noopHtmlToMd);
  assert.ok(wooEmptyDoc);
  assert.ok(String(wooEmptyDoc.markdown ?? '').includes('No products returned on this page.'));

  // 3. Custom-domain WooCommerce Store API redirect to https://woocommerce.com/... fails closed (undefined trustAdapterId)
  assert.equal(
    isTrustedTwinRedirectUrl(
      undefined,
      'https://ridestore.example/wp-json/wc/store/v1/products?category=ebikes&per_page=50',
      { finalUrl: 'https://woocommerce.com/wp-json/wc/store/v1/products' },
      'edgefetch.example',
    ),
    false,
  );
  const wooHtml = `<html><body class="woocommerce-page tax-product_cat">
    <h1 class="woocommerce-products-header__title">Gravel Bikes</h1>
    <ul class="products"><li class="product">
      <a href="/product/gravel-pro/"><h2 class="woocommerce-loop-product__title">Gravel Pro</h2></a>
      <span class="price"><span class="amount">$1,450.00</span></span>
      <a class="add_to_cart_button" data-product_id="55" data-product_sku="GP-55">Add</a>
    </li></ul>
  </body></html>`;
  const redirRes = await executeScrapeCall({
    payload: { url: 'https://ridestore.example/product-category/ebikes/', formats: ['markdown', 'records'] },
    env: {},
    executeHubFetch: async (_target, rawBody) => {
      const req = JSON.parse(rawBody) as { requests: Array<{ url: string }> };
      const u = req.requests[0]!.url;
      if (u === 'https://ridestore.example/product-category/ebikes/') {
        return okFetchReply(u, 'text/html', wooHtml);
      }
      if (u.includes('/wp-json/wc/store/v1/products')) {
        return okFetchReply(
          u,
          'application/json',
          JSON.stringify([{ id: 999, slug: 'evil', name: 'Poisoned', sku: 'EVIL-1', prices: { price: '100', currency_code: 'USD', currency_minor_unit: 2 } }]),
          'https://woocommerce.com/wp-json/wc/store/v1/products',
        );
      }
      return failFetchReply(u, 404);
    },
  });
  assert.equal(redirRes.status, 200);
  const rmd = String(redirRes.body.markdown ?? '');
  assert.equal(rmd.includes('EVIL-1'), false, 'cross-host redirect to woocommerce.com must be rejected');
  assert.ok(rmd.includes('GP-55'), 'should fall back to WooCommerce HTML catalog');
});

test('M3-15: Body Markdown link injection prevention (sram-docs, bosch-ebike-help, xenforo-thread, general) & balanced parens', async () => {
  resetIsolateBudgetForTests();

  const unescapedInjectedRe = /(?:^|[^\\])(?:\[xss\]|\])\s*\(\s*https?:\/\/evil\.com/;
  const sramHtml = `<!doctype html><html><body><main><h1>Tech Doc</h1><p>Inspect the speed sensor magnet on the rear wheel spoke and ensure the gap is between 5 mm and 17 mm. Check cable routing along the chainstay for pinches or kinks, then restart the Bosch drive unit after tightening.</p><p><a href="https://docs.sram.com/a)[xss](https://evil.com/doc.pdf">Manual PDF</a></p><p><a href="https://docs.sram.com/doc">Label ](https://evil.com/doc.pdf)</a></p></main></body></html>`;
  const sramDirect = extractHtmlDocument(sramHtml, {
    baseUrl: 'https://docs.sram.com/en-US/publications/7E6x3h',
    onlyMainContent: true,
  });
  assert.equal(unescapedInjectedRe.test(sramDirect.markdown), false);
  assert.ok(sramDirect.markdown.includes('%29%5Bxss%5D%28'));

  const sramScrape = await executeScrapeCall({
    payload: { url: 'https://docs.sram.com/en-US/publications/7E6x3h', formats: ['markdown', 'links'] },
    env: {},
    executeHubFetch: async (_target, rawBody) => {
      const req = JSON.parse(rawBody) as { requests: Array<{ url: string }> };
      return okFetchReply(req.requests[0]!.url, 'text/html', sramHtml);
    },
  });
  assert.equal(sramScrape.status, 200);
  const sramMd = String(sramScrape.body.markdown ?? '');
  assert.equal(unescapedInjectedRe.test(sramMd), false);
  for (const l of (sramScrape.body.links as string[]) ?? []) {
    assert.equal(l.includes(')[xss]('), false);
    assert.notEqual(new URL(l).hostname, 'evil.com');
  }

  const boschHtml = `<!doctype html><html><body><main><h1>Tech Doc</h1><p>Inspect the speed sensor magnet on the rear wheel spoke and ensure the gap is between 5 mm and 17 mm. Check cable routing along the chainstay for pinches or kinks, then restart the Bosch drive unit after tightening.</p><p><a href="https://help.bosch-ebike.com/a)[xss](https://evil.com/doc.pdf">Manual PDF</a></p></main></body></html>`;
  const boschScrape = await executeScrapeCall({
    payload: { url: 'https://help.bosch-ebike.com/us/help-center/ebw-error-codes', formats: ['markdown', 'links'] },
    env: {},
    executeHubFetch: async (_target, rawBody) => {
      const req = JSON.parse(rawBody) as { requests: Array<{ url: string }> };
      return okFetchReply(req.requests[0]!.url, 'text/html', boschHtml);
    },
  });
  assert.equal(boschScrape.status, 200);
  const boschMd = String(boschScrape.body.markdown ?? '');
  assert.equal(unescapedInjectedRe.test(boschMd), false);
  assert.ok(boschMd.includes('%29%5Bxss%5D%28'));

  const wikiHtml = `<!doctype html><html><body><main><h1>Balanced</h1><p><a href="https://en.wikipedia.org/wiki/Foo_(bar)">Foo</a> and <a href="https://example.com/a)[xss](https://evil.com/x)">Click</a></p></main></body></html>`;
  const wikiDirect = extractHtmlDocument(wikiHtml, {
    baseUrl: 'https://example.com/post',
    onlyMainContent: true,
  });
  assert.ok(wikiDirect.markdown.includes('[Foo](https://en.wikipedia.org/wiki/Foo_(bar))'));
  assert.equal(unescapedInjectedRe.test(wikiDirect.markdown), false);
  assert.ok(wikiDirect.links.includes('https://en.wikipedia.org/wiki/Foo_(bar)'));
});

test('M3-16: Bosch Help missing B:0 orphan S:0 with nested S:2 emits S:2 strictly once', async () => {
  resetIsolateBudgetForTests();

  const orphanNestedWithMain = `<!doctype html><html><body>
    <main><h1>Missing Template Nested</h1><p>Main shell text over twenty characters.</p></main>
    <div hidden id="S:0"><p>OrphanOuter</p><template id="B:2"></template><p>OrphanAfter</p></div>
    <div hidden id="S:2"><p>OrphanInnerS2 Inspect the speed sensor magnet on the rear wheel spoke and ensure the gap is between 5 mm and 17 mm. Check cable routing along the chainstay for pinches or kinks, then restart the Bosch drive unit after tightening.</p></div>
    <script>$RC("B:0","S:0");$RC("B:2","S:2")</script>
  </body></html>`;

  const directWithMain = extractHtmlDocument(orphanNestedWithMain, {
    baseUrl: 'https://help.bosch-ebike.com/us/help-center/ebw-error-codes',
    onlyMainContent: true,
  });
  assert.equal(directWithMain.markdown.split('OrphanInnerS2').length - 1, 1);

  const scrapeWithMain = await executeScrapeCall({
    payload: { url: 'https://help.bosch-ebike.com/us/help-center/ebw-error-codes', formats: ['markdown'] },
    env: {},
    executeHubFetch: async (_target, rawBody) => {
      const req = JSON.parse(rawBody) as { requests: Array<{ url: string }> };
      return okFetchReply(req.requests[0]!.url, 'text/html', orphanNestedWithMain);
    },
  });
  assert.equal(scrapeWithMain.status, 200);
  assert.equal(scrapeWithMain.body.detected?.adapter, 'bosch-ebike-help');
  assert.equal(String(scrapeWithMain.body.markdown ?? '').split('OrphanInnerS2').length - 1, 1);

  const orphanNestedNoMain = `<!doctype html><html><body>
    <div hidden id="S:0"><p>A</p><template id="B:2"></template></div>
    <div hidden id="S:2"><p>OrphanInnerS2</p></div>
    <script>$RC("B:0","S:0");$RC("B:2","S:2")</script>
  </body></html>`;
  const directNoMain = extractHtmlDocument(orphanNestedNoMain, {
    baseUrl: 'https://help.bosch-ebike.com/us/help-center/ebw-error-codes',
    onlyMainContent: true,
  });
  assert.equal(directNoMain.markdown.split('OrphanInnerS2').length - 1, 1);
});

test('M3-17: Multi-pass entity Markdown link injection (Bypasses #1 & #2) across tech docs, forums, badges, and general HTML', async () => {
  resetIsolateBudgetForTests();

  const unescapedInjectedRe = /(?:^|[^\\])(?:\[xss\]|\])\s*\(\s*https?:\/\/evil\.com/;

  // 1. Bypass #1 + #2 on sram-docs
  const sramHtml = `<!doctype html><html><body><main><h1>Tech Doc</h1>
    <p>Inspect the speed sensor magnet on the rear wheel spoke and ensure the gap is between 5 mm and 17 mm.</p>
    <p><a href="https://docs.sram.com/ok">Manual &amp;#93;(https://evil.com/doc.pdf)</a></p>
    <p><a href="https://docs.sram.com/ok2">Named &amp;rsqb;(https://evil.com/doc.pdf)</a></p>
    <p><a href="https://docs.sram.com/a&amp;rpar;&amp;lsqb;xss&amp;rsqb;&amp;lpar;https://evil.com/doc.pdf">Manual PDF</a></p>
    <p><a href="https://docs.sram.com/ok"><img src="https://img.shields.io/a.svg" alt="ok"> Docs &amp;#93;(https://evil.com)</a></p>
    <p><a href="https://docs.sram.com/ok">![fake](https://evil.com/x.png)</a></p>
  </main></body></html>`;
  const sramScrape = await executeScrapeCall({
    payload: { url: 'https://docs.sram.com/en-US/publications/7E6x3h', formats: ['markdown', 'links', 'images'] },
    env: {},
    executeHubFetch: async (_target, rawBody) => {
      const req = JSON.parse(rawBody) as { requests: Array<{ url: string }> };
      return okFetchReply(req.requests[0]!.url, 'text/html', sramHtml);
    },
  });
  assert.equal(sramScrape.status, 200);
  const sramMd = String(sramScrape.body.markdown ?? '');
  assert.equal(unescapedInjectedRe.test(sramMd), false);
  assert.equal(sramMd.includes('## PDF Manuals'), false);
  assert.ok(sramMd.includes('%29%5Bxss%5D%28'));
  for (const l of (sramScrape.body.links as string[]) ?? []) {
    assert.equal(l.includes('&rpar;'), false);
    assert.notEqual(new URL(l).hostname, 'evil.com');
  }
  const sramImgs = (sramScrape.body.images as Array<Record<string, unknown>>) ?? [];
  assert.deepEqual(sramImgs, [{ url: 'https://img.shields.io/a.svg', alt: 'ok' }]);

  // 2. Bypass #1 + #2 on bosch-ebike-help
  const boschHtml = `<!doctype html><html><body><main><h1>Bosch Doc</h1>
    <p>Inspect the speed sensor magnet on the rear wheel spoke and ensure the gap is between 5 mm and 17 mm.</p>
    <p><a href="https://help.bosch-ebike.com/a&amp;rpar;&amp;lsqb;xss&amp;rsqb;&amp;lpar;https://evil.com/doc.pdf">Manual PDF</a></p>
    <p><a href="https://help.bosch-ebike.com/ok">Triple &amp;amp;#93;(https://evil.com/doc.pdf)</a></p>
  </main></body></html>`;
  const boschScrape = await executeScrapeCall({
    payload: { url: 'https://help.bosch-ebike.com/us/help-center/ebw-error-codes', formats: ['markdown', 'links'] },
    env: {},
    executeHubFetch: async (_target, rawBody) => {
      const req = JSON.parse(rawBody) as { requests: Array<{ url: string }> };
      return okFetchReply(req.requests[0]!.url, 'text/html', boschHtml);
    },
  });
  assert.equal(boschScrape.status, 200);
  const boschMd = String(boschScrape.body.markdown ?? '');
  assert.equal(unescapedInjectedRe.test(boschMd), false);
  assert.equal(boschMd.includes('## PDF Manuals'), false);

  // 3. XenForo + general HTML + Wikipedia Foo_(bar) + semicolonless query
  const genHtml = `<!doctype html><html><body><main><h1>Compat</h1>
    <p><a href="https://en.wikipedia.org/wiki/Foo_(bar)">Foo</a></p>
    <p><a href="https://example.com/watch?v=1&amp;currentTime=45&section=2&region=us">Video</a></p>
    <p><a href="https://example.com/ok">Entity &amp;#x5D;(https://evil.com/x)</a></p>
  </main></body></html>`;
  const genDoc = extractHtmlDocument(genHtml, {
    baseUrl: 'https://example.com/post',
    onlyMainContent: true,
  });
  assert.equal(unescapedInjectedRe.test(genDoc.markdown), false);
  assert.ok(genDoc.markdown.includes('[Foo](https://en.wikipedia.org/wiki/Foo_(bar))'));
  assert.ok(genDoc.markdown.includes('https://example.com/watch?v=1&currentTime=45&section=2&region=us'));
});

test('M3-18: E2E contracts F02.T2.2, F10.2, F11.4/T2.4, and F12.1/12.2/12.T2.2', async () => {
  resetIsolateBudgetForTests();

  // 1. F02.T2.2: Shopify empty collection products: [] fails open to collection HTML, while direct .json keeps empty message
  const noopHtmlToMd = (frag: string) => ({ markdown: frag, links: [] });
  const shColTwin = resolveSiteExtractorTwin('https://sh-t2-2.myshopify.com/collections/empty-col');
  assert.ok(shColTwin);
  assert.equal(shColTwin.formatTwin('{"products":[]}', 'https://sh-t2-2.myshopify.com/collections/empty-col', noopHtmlToMd), null);

  const shDirectTwin = resolveSiteExtractorTwin('https://store.example.com/products.json');
  assert.ok(shDirectTwin);
  const shDirectEmpty = shDirectTwin.formatTwin('{"products":[]}', 'https://store.example.com/products.json', noopHtmlToMd);
  assert.ok(shDirectEmpty && String(shDirectEmpty.markdown ?? '').includes('No products returned on this page.'));

  const f02Res = await executeScrapeCall({
    payload: { url: 'https://sh-t2-2.myshopify.com/collections/empty-col', formats: ['markdown', 'records'] },
    env: {},
    executeHubFetch: async (_target, rawBody) => {
      const req = JSON.parse(rawBody) as { requests: Array<{ url: string }> };
      const u = req.requests[0]!.url;
      if (u.endsWith('/products.json?limit=50')) {
        return okFetchReply(u, 'application/json', '{"products":[]}');
      }
      return okFetchReply(u, 'text/html', '<!doctype html><html><head><title>Empty Collection HTML</title></head><body><main><h1>Empty Collection HTML</h1><p>No items in stock.</p></main></body></html>');
    },
  });
  assert.equal(f02Res.status, 200);
  assert.ok(String(f02Res.body.markdown ?? '').includes('Empty Collection HTML'));

  // 2. F10.2: BigCommerce [data-product-option-change] with plain <label>
  const bcRes = await executeScrapeCall({
    payload: { url: 'https://peakbikes2.example.com/trailblazer-hydraulic-brake-kit/', formats: ['markdown', 'records'] },
    env: {},
    executeHubFetch: async (_target, rawBody) => {
      const req = JSON.parse(rawBody) as { requests: Array<{ url: string }> };
      return okFetchReply(
        req.requests[0]!.url,
        'text/html',
        `<!doctype html><html><head><script>window.BCData = {"product_attributes":{"sku":"BC-1","price":{"without_tax":{"value":149.00,"currency":"USD"}}}};</script></head><body>
          <h1 class="productView-title">Trailblazer Brake Kit</h1>
          <form data-cart-item-add>
            <div data-product-option-change>
              <label>Rotor Size</label>
              <select name="attribute[101]">
                <option value="1">180mm</option>
                <option value="2">203mm</option>
              </select>
            </div>
          </form>
        </body></html>`,
      );
    },
  });
  assert.equal(bcRes.status, 200);
  const bcMd = String(bcRes.body.markdown ?? '');
  assert.ok(bcMd.includes('180mm') && bcMd.includes('203mm'));

  // 3. F11.4 & F11.T2.4: SFCC availability.inStock -> product.availability & variants[0].available
  const sfccHtml = `<!doctype html><html><head><script src="https://bikes3.example.com/on/demandware.static/Sites-Bike-Site/-/en_US/v1/main.js"></script></head><body><div class="product-detail" data-pid="44751-54-BLK"><h1>Domane SL 6 Gen 4</h1><a href="/on/demandware.store/Sites-Bike-Site/en_US/Product-Variation?pid=44751-54-BLK">54</a></div></body></html>`;
  const sfccTrue = await executeScrapeCall({
    payload: { url: 'https://bikes3.example.com/us/en_US/bikes/domane-sl-6-gen-4/p/44751/', formats: ['markdown', 'product'] },
    env: {},
    executeHubFetch: async (_target, rawBody) => {
      const req = JSON.parse(rawBody) as { requests: Array<{ url: string }> };
      const u = req.requests[0]!.url;
      if (u.includes('Product-Variation')) {
        return okFetchReply(
          u,
          'application/json',
          JSON.stringify({
            product: {
              id: '44751-54-BLK',
              productName: 'Domane SL 6 Gen 4',
              price: { sales: { value: 4699.99, currency: 'USD' } },
              availability: { inStock: true, ats: 7, messages: ['In Stock'] },
            },
          }),
        );
      }
      return okFetchReply(u, 'text/html', sfccHtml);
    },
  });
  assert.equal(sfccTrue.status, 200);
  assert.equal((sfccTrue.body.product as Record<string, unknown>)?.availability, 'InStock');

  const sfccFalse = await executeScrapeCall({
    payload: { url: 'https://bikes3.example.com/us/en_US/bikes/domane-sl/p/SF-0/', formats: ['markdown', 'records'] },
    env: {},
    executeHubFetch: async (_target, rawBody) => {
      const req = JSON.parse(rawBody) as { requests: Array<{ url: string }> };
      const u = req.requests[0]!.url;
      if (u.includes('Product-Variation')) {
        return okFetchReply(
          u,
          'application/json',
          JSON.stringify({
            product: {
              id: 'SF-0',
              productName: 'Domane SL',
              price: { sales: { value: 3499.99, currency: 'USD' } },
              availability: { inStock: false, ats: 0 },
            },
          }),
        );
      }
      return okFetchReply(
        u,
        'text/html',
        `<!doctype html><html><head><script src="https://bikes3.example.com/on/demandware.static/Sites-Bike-Site/-/en_US/v1/main.js"></script></head><body><div class="product-detail" data-pid="SF-0"><h1>Domane SL</h1><a href="/on/demandware.store/Sites-Bike-Site/en_US/Product-Variation?pid=SF-0">54</a></div></body></html>`,
      );
    },
  });
  assert.equal(sfccFalse.status, 200);
  const v0 = ((sfccFalse.body.records as Array<Record<string, unknown>>)?.[0]?.variants as Array<Record<string, unknown>>)?.[0];
  assert.equal(v0?.available, false);

  // 4. F12.1, F12.2, F12.T2.2: Magento 2 index-less swatch-renderer offline + 401 /rest/V1/
  const magHtml = `<!doctype html><html><body>
    <h1>Magura MT7 Pro Disc Brake</h1>
    <div data-role="swatch-options"></div>
    <script type="text/x-magento-init">
    {
      "[data-role=swatch-options]": {
        "Magento_Swatches/js/swatch-renderer": {
          "jsonConfig": {
            "attributes": {
              "93": {
                "id": "93",
                "code": "rotor_size",
                "label": "Rotor Size",
                "options": [
                  {"id": "10", "label": "180mm", "products": ["2001"]},
                  {"id": "11", "label": "203mm", "products": ["2002"]}
                ]
              }
            },
            "sku": {"2001": "MAG-MT7-180", "2002": "MAG-MT7-203"},
            "optionPrices": {
              "2001": {"finalPrice": {"amount": 269}},
              "2002": {"finalPrice": {"amount": 289}}
            },
            "currencyFormat": "$%s"
          }
        }
      }
    }
    </script>
  </body></html>`;
  const magRes = await executeScrapeCall({
    payload: { url: 'https://parts1.example.com/magura-mt7-pro.html', formats: ['markdown', 'records', 'product'] },
    env: {},
    executeHubFetch: async (_target, rawBody) => {
      const req = JSON.parse(rawBody) as { requests: Array<{ url: string }> };
      const u = req.requests[0]!.url;
      if (u.includes('/rest/V1/')) {
        return failFetchReply(u, 401);
      }
      return okFetchReply(u, 'text/html', magHtml);
    },
  });
  assert.equal(magRes.status, 200);
  const magMd = String(magRes.body.markdown ?? '');
  assert.ok(magMd.includes('MAG-MT7-180') && magMd.includes('MAG-MT7-203'));
  assert.equal((magRes.body.product as Record<string, unknown>)?.sku, 'MAG-MT7-180');
});

test('M3-19: BigCommerce <fieldset><legend> options & live companion twin availability over stale JSON-LD', async () => {
  resetIsolateBudgetForTests();

  // 1. BigCommerce <fieldset><legend>Mount Type</legend> with unclassed <label for="m1">
  const bcLegendRes = await executeScrapeCall({
    payload: { url: 'https://peakbikes3.example.com/disc-adapter/', formats: ['markdown', 'records'] },
    env: {},
    executeHubFetch: async (_target, rawBody) => {
      const req = JSON.parse(rawBody) as { requests: Array<{ url: string }> };
      return okFetchReply(
        req.requests[0]!.url,
        'text/html',
        `<!doctype html><html><head><script src="https://cdn11.bigcommerce.com/s-abc/stencil.js"></script></head><body>
          <h1 class="productView-title">Disc Brake Adapter</h1>
          <form data-cart-item-add>
            <fieldset class="form-field" data-product-attribute="set-radio">
              <legend>Mount Type</legend>
              <input type="radio" id="m1" name="attribute[200]" value="1" />
              <label for="m1">Direct Mount</label>
              <input type="radio" id="m2" name="attribute[200]" value="2" />
              <label for="m2">Post Mount</label>
            </fieldset>
          </form>
        </body></html>`,
      );
    },
  });
  assert.equal(bcLegendRes.status, 200);
  const bcRec0 = (bcLegendRes.body.records as Array<Record<string, unknown>>)?.[0];
  const bcOpts = bcRec0?.options as Array<{ name: string; values: string[] }> | undefined;
  assert.equal(bcOpts?.[0]?.name, 'Mount Type');
  assert.deepEqual(bcOpts?.[0]?.values, ['Direct Mount', 'Post Mount']);

  // 2. SFCC stale JSON-LD InStock + live Product-Variation inStock: false -> product.availability === 'OutOfStock'
  const sfccStaleHtml = `<!doctype html><html><head>
    <script src="https://bikes4.example.com/on/demandware.static/Sites-Bike-Site/-/en_US/v1/main.js"></script>
    <script type="application/ld+json">${JSON.stringify({
      '@context': 'https://schema.org',
      '@type': 'Product',
      name: 'Domane SL 6',
      sku: '44751-54-BLK',
      offers: { '@type': 'Offer', price: '4699.99', priceCurrency: 'USD', availability: 'https://schema.org/InStock' },
    })}</script>
  </head><body><div class="product-detail" data-pid="44751-54-BLK"><h1>Domane SL 6</h1><a href="/on/demandware.store/Sites-Bike-Site/en_US/Product-Variation?pid=44751-54-BLK">54</a></div></body></html>`;
  const sfccRes = await executeScrapeCall({
    payload: { url: 'https://bikes4.example.com/us/en_US/bikes/domane-sl-6/p/44751/', formats: ['markdown', 'product', 'records'] },
    env: {},
    executeHubFetch: async (_target, rawBody) => {
      const req = JSON.parse(rawBody) as { requests: Array<{ url: string }> };
      const u = req.requests[0]!.url;
      if (u.includes('Product-Variation')) {
        return okFetchReply(
          u,
          'application/json',
          JSON.stringify({
            product: {
              id: '44751-54-BLK',
              productName: 'Domane SL 6',
              price: { sales: { value: 4699.99, currency: 'USD' } },
              availability: { inStock: false, ats: 0 },
            },
          }),
        );
      }
      return okFetchReply(u, 'text/html', sfccStaleHtml);
    },
  });
  assert.equal(sfccRes.status, 200);
  const sfccProd = sfccRes.body.product as Record<string, unknown>;
  assert.equal(sfccProd?.availability, 'OutOfStock');

  // 3. Multi-variant Shopify live twin ([{ available: false }, { available: true }]) -> 'InStock'
  const shopMultiHtml = `<!doctype html><html><head>
    <script src="https://cdn.shopify.com/s/files/1/shop.js"></script>
    <script type="application/ld+json">${JSON.stringify({
      '@context': 'https://schema.org',
      '@type': 'Product',
      name: 'Trail Bike',
      offers: { '@type': 'Offer', price: '1999.00', priceCurrency: 'USD', availability: 'https://schema.org/OutOfStock' },
    })}</script>
  </head><body><h1>Trail Bike</h1></body></html>`;
  const shopMultiRes = await executeScrapeCall({
    payload: { url: 'https://customshop2.example.com/products/trail-bike', formats: ['markdown', 'product'] },
    env: {},
    executeHubFetch: async (_target, rawBody) => {
      const req = JSON.parse(rawBody) as { requests: Array<{ url: string }> };
      const u = req.requests[0]!.url;
      if (u.endsWith('/products/trail-bike.json')) {
        return okFetchReply(
          u,
          'application/json',
          JSON.stringify({
            product: {
              id: 501,
              title: 'Trail Bike',
              vendor: 'Peak',
              variants: [
                { id: 1, title: 'S', sku: 'TB-S', price: '1999.00', available: false },
                { id: 2, title: 'M', sku: 'TB-M', price: '1999.00', available: true },
              ],
            },
          }),
        );
      }
      return okFetchReply(u, 'text/html', shopMultiHtml);
    },
  });
  assert.equal(shopMultiRes.status, 200);
  assert.equal((shopMultiRes.body.product as Record<string, unknown>)?.availability, 'InStock');

  // 4. M3-10 3-arg backfillProductFromRecord still preserves existing out.availability
  const preserved = backfillProductFromRecord(
    { url: 'https://shop.example/p/5', title: 'Widget 5', availability: 'Not in stock' },
    { sku: 'W-5', availability: 'In stock' },
    { finalUrl: 'https://shop.example/p/5' },
  );
  assert.equal(preserved?.availability, 'OutOfStock');
});

test('M3-20: WooCommerce HTML JSON-LD + live Store API availability, { type: "json", schema } live twin, & BigCommerce/Shopware6 raw descriptions', async () => {
  resetIsolateBudgetForTests();

  // 1. WooCommerce single-product HTML JSON-LD (InStock) + live Store API (is_in_stock: false)
  const wooHtml = `<!doctype html><html><head>
    <link rel="stylesheet" href="https://woo-live.example.com/wp-content/plugins/woocommerce/assets/css/woocommerce.css" />
    <script type="application/ld+json">${JSON.stringify({
      '@context': 'https://schema.org',
      '@type': 'Product',
      name: 'Trail Fork 140',
      sku: 'FORK-HTML-140',
      offers: { '@type': 'Offer', price: '699.00', priceCurrency: 'USD', availability: 'https://schema.org/InStock' },
    })}</script>
  </head><body class="woocommerce-page single-product"><h1>Trail Fork 140</h1></body></html>`;
  const wooRes = await executeScrapeCall({
    payload: {
      url: 'https://woo-live.example.com/product/trail-fork-140/',
      formats: [
        'markdown',
        'product',
        {
          type: 'json',
          schema: {
            type: 'object',
            properties: {
              sku: { type: 'string' },
              price: { type: 'number' },
              availability: { type: 'string' },
              inStock: { type: 'boolean' },
            },
          },
        },
      ],
    },
    env: {},
    executeHubFetch: async (_target, rawBody) => {
      const req = JSON.parse(rawBody) as { requests: Array<{ url: string }> };
      const u = req.requests[0]!.url;
      if (u.includes('/wp-json/wc/store/v1/products')) {
        return okFetchReply(
          u,
          'application/json',
          JSON.stringify([
            {
              id: 88,
              name: 'Trail Fork 140',
              slug: 'trail-fork-140',
              sku: 'FORK-TWIN-140',
              is_in_stock: false,
              prices: { price: '64900', currency_code: 'USD', currency_minor_unit: 2 },
            },
          ]),
        );
      }
      return okFetchReply(u, 'text/html', wooHtml);
    },
  });
  assert.equal(wooRes.status, 200);
  assert.equal((wooRes.body.product as Record<string, unknown>)?.availability, 'OutOfStock');
  assert.equal((wooRes.body.product as Record<string, unknown>)?.sku, 'FORK-HTML-140');
  assert.equal((wooRes.body.product as Record<string, unknown>)?.price, 699);
  const wooJson = wooRes.body.json as Record<string, unknown>;
  assert.equal(wooJson?.availability, 'OutOfStock');
  assert.equal(wooJson?.inStock, false);
  assert.equal(wooJson?.sku, 'FORK-HTML-140');
  assert.equal(wooJson?.price, 699);

  // 2. SFCC stale JSON-LD InStock + live Product-Variation inStock: false with { type: 'json', schema }
  const sfccHtml = `<!doctype html><html><head>
    <script src="https://bikes5.example.com/on/demandware.static/Sites-Bike-Site/-/en_US/v1/main.js"></script>
    <script type="application/ld+json">${JSON.stringify({
      '@context': 'https://schema.org',
      '@type': 'Product',
      name: 'Domane SL 6',
      sku: '44751-54-BLK',
      offers: { '@type': 'Offer', price: '2999.00', priceCurrency: 'USD', availability: 'https://schema.org/InStock' },
    })}</script>
  </head><body><div class="product-detail" data-pid="44751-54-BLK"><h1>Domane SL 6</h1><a href="/on/demandware.store/Sites-Bike-Site/en_US/Product-Variation?pid=44751-54-BLK">54</a></div></body></html>`;
  const sfccJsonRes = await executeScrapeCall({
    payload: {
      url: 'https://bikes5.example.com/us/en_US/bikes/domane-sl-6/p/44751/',
      formats: [
        'product',
        {
          type: 'json',
          schema: {
            type: 'object',
            properties: {
              sku: { type: 'string' },
              price: { type: 'number' },
              availability: { type: 'string' },
              inStock: { type: 'boolean' },
            },
          },
        },
      ],
    },
    env: {},
    executeHubFetch: async (_target, rawBody) => {
      const req = JSON.parse(rawBody) as { requests: Array<{ url: string }> };
      const u = req.requests[0]!.url;
      if (u.includes('Product-Variation')) {
        return okFetchReply(
          u,
          'application/json',
          JSON.stringify({
            product: {
              id: '44751-54-BLK',
              productName: 'Domane SL 6',
              price: { sales: { value: 2499, currency: 'USD' } },
              availability: { inStock: false, ats: 0 },
            },
          }),
        );
      }
      return okFetchReply(u, 'text/html', sfccHtml);
    },
  });
  assert.equal(sfccJsonRes.status, 200);
  assert.equal((sfccJsonRes.body.product as Record<string, unknown>)?.availability, 'OutOfStock');
  assert.equal((sfccJsonRes.body.json as Record<string, unknown>)?.availability, 'OutOfStock');
  assert.equal((sfccJsonRes.body.json as Record<string, unknown>)?.inStock, false);

  // 3. BigCommerce & Shopware 6 end-to-end Hub scrape: entity-encoded link neutralization + &section=2 + plain <fieldset>
  const bcHubRes = await executeScrapeCall({
    payload: { url: 'https://bc-raw.example.com/rotor/', formats: ['markdown', 'records'] },
    env: {},
    executeHubFetch: async (_target, rawBody) => {
      const req = JSON.parse(rawBody) as { requests: Array<{ url: string }> };
      return okFetchReply(
        req.requests[0]!.url,
        'text/html',
        `<!doctype html><html><head><script src="https://cdn11.bigcommerce.com/s-abc/stencil.js"></script></head><body>
          <h1 class="productView-title">E-Bike Rotor</h1>
          <form data-cart-item-add>
            <fieldset><legend>Mount Type</legend>
              <input type="radio" id="m1" name="m"><label for="m1">Direct Mount</label>
              <input type="radio" id="m2" name="m"><label for="m2">Post Mount</label>
            </fieldset>
          </form>
          <div id="tab-description">
            <p>Part &#91;xss&#93;(https://evil.com)</p>
            <p><a href="https://example.com/watch?v=1&currentTime=45&section=2&region=us">Video</a></p>
          </div>
        </body></html>`,
      );
    },
  });
  assert.equal(bcHubRes.status, 200);
  const bcMd = String(bcHubRes.body.markdown ?? '');
  assert.ok(!/(?:^|[^\\])\[xss\]\(https?:\/\/evil\.com/.test(bcMd), `BigCommerce markdown injected link:\n${bcMd}`);
  assert.ok(bcMd.includes('https://example.com/watch?v=1&currentTime=45&section=2&region=us'));
  const bcOpts = ((bcHubRes.body.records as Array<Record<string, unknown>>)?.[0]?.options as Array<{ name: string; values: string[] }>) ?? [];
  assert.equal(bcOpts[0]?.name, 'Mount Type');
  assert.deepEqual(bcOpts[0]?.values, ['Direct Mount', 'Post Mount']);
});
