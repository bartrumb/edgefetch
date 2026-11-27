// Realistic opaque-box fixtures for Tier 1–4 E2E expansion tests (F01–F36).
// Kept strictly under hub/test/e2e-expansion/ (never inside hub/test/fixtures/adapters/).

export const F01_ZENDESK = {
  articleJson: {
    article: {
      id: 4408886858138,
      url: 'https://acme.zendesk.com/api/v2/help_center/en-us/articles/4408886858138.json',
      html_url: 'https://acme.zendesk.com/hc/en-us/articles/4408886858138-getting-started',
      author_id: 901234,
      section_id: 360001234567,
      title: 'Getting Started with Acme Fleet Telemetry',
      body: '<h2>Prerequisites</h2><p>Ensure firmware <strong>v4.2</strong> is installed before pairing.</p><ul><li>Download the <a href="https://acme.zendesk.com/hc/article_attachments/991122/Fleet_Manual_v4.pdf">Fleet Manual PDF</a></li><li>Configure webhook secret</li></ul>',
      locale: 'en-us',
      label_names: ['telemetry', 'firmware', 'onboarding'],
      created_at: '2025-02-10T10:00:00Z',
      updated_at: '2026-10-14T15:30:00Z',
      edited_at: '2026-10-14T15:30:00Z',
      draft: false,
    },
  },
  attachmentsJson: {
    article_attachments: [
      {
        id: 991122,
        file_name: 'Fleet_Manual_v4.pdf',
        content_url: 'https://acme.zendesk.com/hc/article_attachments/991122/Fleet_Manual_v4.pdf',
        content_type: 'application/pdf',
        size: 245760,
      },
    ],
  },
  sectionArticlesJson: {
    articles: [
      {
        id: 4408886858138,
        html_url: 'https://acme.zendesk.com/hc/en-us/articles/4408886858138-getting-started',
        title: 'Getting Started with Acme Fleet Telemetry',
        updated_at: '2026-10-14T15:30:00Z',
        snippet: 'Ensure firmware v4.2 is installed before pairing.',
      },
      {
        id: 4408886999001,
        html_url: 'https://acme.zendesk.com/hc/en-us/articles/4408886999001-diagnostic-codes',
        title: 'Diagnostic Error Codes Reference',
        updated_at: '2026-10-01T08:00:00Z',
        snippet: 'Lookup table for E10 through E99 controller faults.',
      },
    ],
    count: 2,
  },
  categorySectionsJson: {
    sections: [
      {
        id: 360001234567,
        html_url: 'https://acme.zendesk.com/hc/en-us/sections/360001234567-manuals',
        name: 'Hardware Manuals',
        description: 'Official PDF manuals and wiring guides.',
        updated_at: '2026-09-20T12:00:00Z',
      },
      {
        id: 360001234999,
        html_url: 'https://acme.zendesk.com/hc/en-us/sections/360001234999-troubleshooting',
        name: 'Troubleshooting & Faults',
        description: 'Battery and motor controller diagnostics.',
        updated_at: '2026-09-25T09:00:00Z',
      },
    ],
    count: 2,
  },
  frArticleJson: {
    article: {
      id: 4408886858139,
      html_url: 'https://acme.zendesk.com/hc/fr-fr/articles/4408886858139-demarrage',
      section_id: 360001234567,
      title: 'Guide de demarrage rapide',
      body: '<p>Verifiez la version du micrologiciel avant la mise en service.</p>',
      locale: 'fr-fr',
      label_names: ['demarrage', 'manuel'],
      updated_at: '2026-10-10T11:00:00Z',
      draft: false,
    },
  },
};

export const F02_SHOPIFY = {
  collectionHtml: (shopDomain) => `<!doctype html>
<html>
<head>
  <title>Electric Bikes Collection</title>
  <script>window.Shopify = { shop: "${shopDomain}", currency: { active: "USD" } };</script>
</head>
<body>
  <main>
    <h1>Electric Bikes</h1>
    <p>Browse our commuter and cargo electric bicycles.</p>
  </main>
</body>
</html>`,
  collectionProductsJson: {
    products: [
      {
        id: 881001,
        title: 'Apex Commuter 500',
        handle: 'apex-commuter-500',
        vendor: 'VoltRide',
        product_type: 'Electric Bike',
        body_html: '<p>500W hub motor commuter e-bike with hydraulic disc brakes.</p>',
        images: [{ src: 'https://cdn.shopify.com/s/files/1/apex-500.jpg' }],
        variants: [
          { id: 99101, title: 'Step-Over / Matte Black', sku: 'VR-APX-BLK', price: '1599.00', available: true },
          { id: 99102, title: 'Step-Thru / Pearl White', sku: 'VR-APX-WHT', price: '1649.00', available: false },
        ],
      },
      {
        id: 881002,
        title: 'Hauler Cargo Pro',
        handle: 'hauler-cargo-pro',
        vendor: 'VoltRide',
        product_type: 'Cargo Bike',
        body_html: '<p>Long-tail utility cargo e-bike rated to 400 lbs.</p>',
        images: [{ src: 'https://cdn.shopify.com/s/files/1/hauler-pro.jpg' }],
        variants: [
          { id: 99201, title: 'Standard 750Wh', sku: 'VR-HLR-750', price: '2299.00', available: true },
        ],
      },
    ],
  },
};

export const F03_WOOCOMMERCE = {
  categoryHtml: (title = 'Electric Bikes') => `<!doctype html>
<html>
<head>
  <title>${title} - RideShop</title>
  <meta name="generator" content="WooCommerce 9.3.1">
  <link rel="stylesheet" href="/wp-content/plugins/woocommerce/assets/css/woocommerce.css">
</head>
<body class="archive tax-product_cat woocommerce woocommerce-page">
  <main>
    <h1>${title}</h1>
    <ul class="products">
      <li class="product"><a href="/product/city-cruiser-st/">City Cruiser ST</a></li>
    </ul>
  </main>
</body>
</html>`,
  storeProductsUsd: [
    {
      id: 401,
      name: 'City Cruiser ST',
      slug: 'city-cruiser-st',
      permalink: 'https://rideshop.example.com/product/city-cruiser-st/',
      sku: 'WC-CITY-ST',
      short_description: '<p>Lightweight urban step-through e-bike.</p>',
      is_in_stock: true,
      prices: {
        price: '149900',
        regular_price: '169900',
        sale_price: '149900',
        currency_code: 'USD',
        currency_minor_unit: 2,
      },
      images: [{ src: 'https://rideshop.example.com/wp-content/uploads/city-cruiser.jpg' }],
    },
    {
      id: 402,
      name: 'Gravel Explorer XR',
      slug: 'gravel-explorer-xr',
      permalink: 'https://rideshop.example.com/product/gravel-explorer-xr/',
      sku: 'WC-GRVL-XR',
      short_description: '<p>All-road electric gravel bike.</p>',
      is_in_stock: false,
      prices: {
        price: '219900',
        regular_price: '219900',
        sale_price: '219900',
        currency_code: 'USD',
        currency_minor_unit: 2,
      },
      images: [{ src: 'https://rideshop.example.com/wp-content/uploads/gravel-xr.jpg' }],
    },
  ],
  storeProductsEur: [
    {
      id: 501,
      name: 'Alpen Tourer E8',
      slug: 'alpen-tourer-e8',
      permalink: 'https://euroride.example.de/product/alpen-tourer-e8/',
      sku: 'EU-ALP-E8',
      short_description: '<p>Trekking E-Bike mit Bosch Performance CX.</p>',
      is_in_stock: true,
      prices: {
        price: '329950',
        regular_price: '349950',
        sale_price: '329950',
        currency_code: 'EUR',
        currency_minor_unit: 2,
      },
      images: [{ src: 'https://euroride.example.de/wp-content/uploads/alpen-e8.jpg' }],
    },
  ],
};

export const F04_FEDERAL_REGISTER = {
  doc2024_00001: {
    document_number: '2024-00001',
    title: 'Safety Standard for Lithium-Ion E-Bike Batteries and Chargers',
    type: 'Rule',
    citation: '89 FR 1042',
    publication_date: '2024-01-02',
    effective_on: '2024-03-04',
    abstract: 'The Consumer Product Safety Commission issues a final rule establishing thermal runaway test criteria for micromobility lithium-ion battery packs.',
    agencies: [{ name: 'Consumer Product Safety Commission', raw_name: 'CONSUMER PRODUCT SAFETY COMMISSION', slug: 'consumer-product-safety-commission' }],
    cfr_references: [{ title: 16, part: 1512 }, { title: 16, part: 1299 }],
    docket_ids: ['CPSC-2023-0042'],
    html_url: 'https://www.federalregister.gov/documents/2024/01/02/2024-00001/safety-standard-for-lithium-ion-ebike-batteries',
    body_html_url: 'https://www.federalregister.gov/documents/full_text/html/2024/01/02/2024-00001.html',
    pdf_url: 'https://www.govinfo.gov/content/pkg/FR-2024-01-02/pdf/2024-00001.pdf',
    full_text_xml_url: 'https://www.federalregister.gov/documents/full_text/xml/2024/01/02/2024-00001.xml',
  },
};

export const F05_CPSC_RECALLS = {
  saferProductsRecall24123: [
    {
      RecallID: 98123,
      RecallNumber: '24123',
      RecallDate: '2024-05-16T00:00:00',
      Title: 'VoltPeak Recalls E-Bike Lithium-Ion Batteries Due to Fire and Burn Hazards',
      Description: 'This recall involves VoltPeak 48V 14Ah lithium-ion battery packs sold with commuter e-bikes.',
      URL: 'https://www.cpsc.gov/Recalls/2024/VoltPeak-Recalls-E-Bike-Lithium-Ion-Batteries',
      ConsumerContact: 'VoltPeak toll-free at 800-555-0199 from 9 a.m. to 5 p.m. ET.',
      Products: [{ Name: 'VoltPeak 48V 14Ah E-Bike Battery Pack', NumberOfUnits: 'About 12,400', Type: 'Batteries' }],
      Hazards: [{ Name: 'The lithium-ion battery can overheat and ignite, posing fire and burn hazards to consumers.' }],
      Remedies: [{ Name: 'Consumers should immediately stop using the recalled batteries and contact VoltPeak for a free UL-2271 certified replacement.' }],
      Manufacturers: [{ Name: 'VoltPeak Mobility Inc.' }],
      Retailers: [{ Name: 'VoltPeak online and authorized bicycle dealers nationwide.' }],
      Images: [{ URL: 'https://www.cpsc.gov/s3fs-public/voltpeak-battery.jpg' }],
    },
  ],
  cpscHtmlRecall: `<!doctype html>
<html>
<head><title>VoltPeak Recalls E-Bike Lithium-Ion Batteries | CPSC.gov</title></head>
<body>
  <main class="node--type-recall">
    <h1>VoltPeak Recalls E-Bike Lithium-Ion Batteries Due to Fire and Burn Hazards</h1>
    <div class="recall-product__field"><span class="field__label">Recall Number:</span> <span class="field__item">24-123</span></div>
    <div class="recall-product__field"><span class="field__label">Recall Date:</span> <span class="field__item">May 16, 2024</span></div>
    <div class="recall-product__field"><span class="field__label">Hazard:</span> <span class="field__item">The lithium-ion battery can overheat and ignite, posing fire and burn hazards.</span></div>
    <div class="recall-product__field"><span class="field__label">Remedy:</span> <span class="field__item">Contact VoltPeak for a free replacement battery pack.</span></div>
    <div class="recall-product__field"><span class="field__label">Units:</span> <span class="field__item">About 12,400</span></div>
    <div class="recall-product__field"><span class="field__label">Consumer Contact:</span> <span class="field__item">800-555-0199</span></div>
  </main>
</body>
</html>`,
};

export const F06_GOVINFO = {
  cfrHtm: `<!doctype html>
<html>
<head><title>16 CFR Part 1512 - Requirements for Bicycles</title></head>
<body>
  <h1>Title 16: Commercial Practices</h1>
  <h2>PART 1512 - REQUIREMENTS FOR BICYCLES</h2>
  <h3>§ 1512.1 Scope</h3>
  <p>This part sets forth the requirements for a bicycle as defined in § 1512.2(a) that is not a sidewalk bicycle.</p>
  <h3>§ 1512.5 Requirements for braking system</h3>
  <p>Bicycles shall be equipped with front- and rear-wheel brakes or rear-wheel brakes only capable of stopping within 15 feet from 15 mph.</p>
</body>
</html>`,
  wssearchContentDetail: {
    packageId: 'CFR-2023-title16-vol2',
    title: '16 CFR Part 1512 - Requirements for Bicycles',
    collection: 'Code of Federal Regulations',
    collectionCode: 'CFR',
    dateIssued: '2023-01-01',
    download: {
      pdfLink: 'https://www.govinfo.gov/content/pkg/CFR-2023-title16-vol2/pdf/CFR-2023-title16-vol2.pdf',
      xmlLink: 'https://www.govinfo.gov/content/pkg/CFR-2023-title16-vol2/xml/CFR-2023-title16-vol2.xml',
      htmLink: 'https://www.govinfo.gov/content/pkg/CFR-2023-title16-vol2/html/CFR-2023-title16-vol2.htm',
    },
    metadata: {
      agency: 'Consumer Product Safety Commission',
      titleNumber: '16',
      volumeNumber: '2',
    },
  },
  angularSpaShell: `<!doctype html><html><head><title>govinfo</title></head><body><app-root></app-root><script src="/main.js"></script></body></html>`,
};

export const F07_EURLEX = {
  enBatteryRegulationHtml: `<!doctype html>
<html lang="en">
<head><title>Regulation (EU) 2023/1542 - Batteries and waste batteries</title></head>
<body>
  <main id="document1">
    <h1>REGULATION (EU) 2023/1542 OF THE EUROPEAN PARLIAMENT AND OF THE COUNCIL</h1>
    <p class="oj-doc-ti">concerning batteries and waste batteries (CELEX:32023R1542)</p>
    <h2>Article 1 - Subject matter and scope</h2>
    <p>This Regulation lays down requirements on sustainability, safety, labelling, marking and information for light means of transport (LMT) batteries.</p>
    <table>
      <tr><th>Category</th><th>Carbon Footprint Threshold</th><th>Removability</th></tr>
      <tr><td>LMT Battery</td><td>Mandatory declaration</td><td>Replaceable by independent professional</td></tr>
    </table>
  </main>
</body>
</html>`,
  deMachineryHtml: `<!doctype html>
<html lang="de">
<head><title>Richtlinie 2006/42/EG - Maschinenrichtlinie</title></head>
<body>
  <main id="document1">
    <h1>RICHTLINIE 2006/42/EG DES EUROPÄISCHEN PARLAMENTS</h1>
    <h2>Artikel 1 - Anwendungsbereich</h2>
    <p>Diese Richtlinie gilt für Maschinen, auswechselbare Ausrüstungen und Sicherheitsbauteile.</p>
  </main>
</body>
</html>`,
  jsShellHtml: `<!doctype html><html><head><title>EUR-Lex</title></head><body><div id="loading">Loading EUR-Lex viewer...</div></body></html>`,
};

export const F08_XENFORO = {
  threadHtml: (title = 'Bosch CX Gen4 Torque Specs & Motor Mount Bolts', withQuotes = true) => `<!doctype html>
<html>
<head><title>${title}</title></head>
<body>
  <div class="p-body-sidebar"><div>Latest Threads Sidebar Noise</div></div>
  <div class="p-body-main">
    <div class="p-title"><h1 class="p-title-value">${title}</h1></div>
    <article class="message message--post" data-author="wrench_pro" data-content="post-1001" id="post-1001">
      <div class="message-inner">
        <div class="message-userDetails"><h4 class="message-name">wrench_pro</h4></div>
        <header class="message-attribution">
          <time class="u-dt" datetime="2026-09-12T14:22:00+0000" data-time="1789222920">Sep 12, 2026</time>
          <a href="#post-1001">#1</a>
        </header>
        <div class="message-content">
          <div class="bbWrapper">For the Gen4 Performance Line CX motor frame bolts, torque the three M8 mounting bolts to <strong>22 Nm</strong> with blue Loctite 243.</div>
          <aside class="message-signature">Sent from my trail bike | Signature Promo Spam</aside>
        </div>
      </div>
    </article>
    <article class="message message--post" data-author="ebike_tech" data-content="post-1002" id="post-1002">
      <div class="message-inner">
        <div class="message-userDetails"><h4 class="message-name">ebike_tech</h4></div>
        <header class="message-attribution">
          <time class="u-dt" datetime="2026-09-12T16:05:00+0000" data-time="1789229100">Sep 12, 2026</time>
          <a href="#post-1002">#2</a>
        </header>
        <div class="message-content">
          <div class="bbWrapper">
            ${withQuotes ? '<blockquote class="bbCodeBlock bbCodeBlock--quote" data-quote="wrench_pro"><div class="bbCodeBlock-title">wrench_pro said:</div><div class="bbCodeBlock-content">torque the three M8 mounting bolts to 22 Nm</div></blockquote>' : ''}
            Confirmed: spider lockring is <code>25 Nm</code> left-hand thread!
          </div>
          <aside class="message-signature">Check out my affiliate store signature</aside>
        </div>
      </div>
    </article>
  </div>
</body>
</html>`,
};

export const F09_SQUARESPACE = {
  shopHtml: `<!doctype html>
<html>
<head>
  <title>Shop | Urban Cycle Co</title>
  <script>Static = {}; Static.SQUARESPACE_CONTEXT = { website: { id: "sq-site-1" } };</script>
</head>
<body>
  <main data-controller="ProductList"><h1>Urban Cycle Shop</h1><p>Explore racks and panniers.</p></main>
</body>
</html>`,
  shopJsonPretty: {
    collection: { title: 'Shop', fullUrl: '/shop' },
    items: [
      {
        id: 'sq-item-1',
        title: 'Porteur Front Rack',
        fullUrl: '/shop/p/porteur-front-rack',
        assetUrl: 'https://images.squarespace-cdn.com/content/v1/porteur-rack.jpg',
        structuredContent: {
          productType: 1,
          variants: [
            {
              sku: 'SQ-RACK-BLK',
              priceMoney: { value: '125.00', currency: 'USD' },
              salePriceMoney: { value: '99.00', currency: 'USD' },
              onSale: true,
              qtyInStock: 14,
              attributes: { Finish: 'Matte Black' },
            },
          ],
        },
      },
      {
        id: 'sq-item-2',
        title: 'Canvas Pannier Pair',
        fullUrl: '/shop/p/canvas-pannier-pair',
        assetUrl: 'https://images.squarespace-cdn.com/content/v1/pannier.jpg',
        structuredContent: {
          productType: 1,
          variants: [
            {
              sku: 'SQ-PAN-OLV',
              priceMoney: { value: '185.00', currency: 'USD' },
              qtyInStock: 6,
              attributes: { Color: 'Olive' },
            },
          ],
        },
      },
    ],
  },
  productJsonPretty: {
    item: {
      id: 'sq-item-1',
      title: 'Porteur Front Rack',
      fullUrl: '/shop/p/porteur-front-rack',
      body: '<p>Chromoly steel front cargo rack rated for 15 kg.</p>',
      assetUrl: 'https://images.squarespace-cdn.com/content/v1/porteur-rack.jpg',
      structuredContent: {
        sku: 'SQ-RACK-BLK',
        priceMoney: { value: '125.00', currency: 'USD' },
        variants: [
          {
            sku: 'SQ-RACK-BLK',
            priceMoney: { value: '125.00', currency: 'USD' },
            salePriceMoney: { value: '99.00', currency: 'USD' },
            onSale: true,
            qtyInStock: 14,
            attributes: { Finish: 'Matte Black' },
          },
          {
            sku: 'SQ-RACK-SLV',
            priceMoney: { value: '125.00', currency: 'USD' },
            qtyInStock: 0,
            attributes: { Finish: 'Polished Silver' },
          },
        ],
      },
    },
  },
};

export const F10_BIGCOMMERCE = {
  productHtml: (withCdn = true) => `<!doctype html>
<html>
<head>
  <title>TrailBlazer Hydraulic Brake Kit - PeakBikes</title>
  ${withCdn ? '<link rel="preconnect" href="https://cdn11.bigcommerce.com">' : ''}
  <script>
    window.BCData = {
      "product_attributes": {
        "sku": "BC-BRK-400",
        "upc": "810012345678",
        "price": { "without_tax": { "value": 249.95, "currency": "USD" } },
        "instock": true,
        "stock": 18,
        "weight": { "value": 0.48 }
      }
    };
  </script>
</head>
<body>
  <main class="productView">
    <h1 class="productView-title">TrailBlazer Hydraulic Brake Kit</h1>
    <span class="productView-brand">PeakBikes</span>
    <form data-cart-item-add>
      <div data-product-option-change>
        <label>Rotor Size</label>
        <select name="attribute[101]">
          <option value="1">180mm</option>
          <option value="2">203mm</option>
        </select>
      </div>
    </form>
  </main>
</body>
</html>`,
  xmlSitemap: `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>https://peakbikes.example.com/trailblazer-hydraulic-brake-kit/</loc><lastmod>2026-10-01</lastmod></url>
  <url><loc>https://peakbikes.example.com/carbon-bar-35mm/</loc><lastmod>2026-10-05</lastmod></url>
</urlset>`,
};

export const F11_SFCC = {
  productHtml: (host = 'www.trekbikes.com') => `<!doctype html>
<html>
<head>
  <title>Domane SL 6 Gen 4 | Trek</title>
  <script src="https://${host}/on/demandware.static/Sites-TrekUS-Site/-/en_US/v1700/js/main.js"></script>
</head>
<body>
  <main class="product-detail" data-pid="44751">
    <h1>Domane SL 6 Gen 4</h1>
    <div class="variation-links">
      <a href="/on/demandware.store/Sites-TrekUS-Site/en_US/Product-Variation?pid=44751&dwvar_44751_size=54">54cm</a>
    </div>
    <table class="geometry-table">
      <thead><tr><th>Frame Size</th><th>Reach (mm)</th><th>Stack (mm)</th></tr></thead>
      <tbody>
        <tr><td>54cm</td><td>374</td><td>575</td></tr>
        <tr><td>56cm</td><td>377</td><td>591</td></tr>
      </tbody>
    </table>
  </main>
</body>
</html>`,
  productVariationJson: {
    action: 'Product-Variation',
    product: {
      id: '44751-54-BLK',
      masterProductID: '44751',
      productName: 'Domane SL 6 Gen 4',
      brand: 'Trek',
      price: {
        sales: { value: 4699.99, currency: 'USD', formatted: '$4,699.99' },
        list: { value: 4999.99, currency: 'USD', formatted: '$4,999.99' },
      },
      availability: {
        inStock: true,
        ats: 7,
        messages: ['In Stock'],
      },
      variationAttributes: [
        { attributeId: 'size', displayName: 'Size', values: [{ displayValue: '54cm', selected: true }, { displayValue: '56cm', selected: false }] },
        { attributeId: 'color', displayName: 'Color', values: [{ displayValue: 'Hex Blue', selected: true }] },
      ],
    },
  },
};

export const F12_SHOPWARE_MAGENTO = {
  magentoSwatchHtml: `<!doctype html>
<html>
<head><title>Magura MT7 Pro Disc Brake</title></head>
<body>
  <main class="product-info-main">
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
                  { "id": "10", "label": "180mm", "products": ["2001"] },
                  { "id": "11", "label": "203mm", "products": ["2002"] }
                ]
              }
            },
            "sku": {
              "2001": "MAG-MT7-180",
              "2002": "MAG-MT7-203"
            },
            "optionPrices": {
              "2001": { "finalPrice": { "amount": 269.00 } },
              "2002": { "finalPrice": { "amount": 289.00 } }
            },
            "currencyFormat": "$%s"
          }
        }
      }
    }
    </script>
  </main>
</body>
</html>`,
  magentoRestRenderInfo: {
    items: [
      {
        id: 2001,
        name: 'Magura MT7 Pro 180mm',
        sku: 'MAG-MT7-180',
        price_info: { final_price: 269.0, regular_price: 299.0, currency_code: 'USD' },
        is_salable: '1',
      },
      {
        id: 2002,
        name: 'Magura MT7 Pro 203mm',
        sku: 'MAG-MT7-203',
        price_info: { final_price: 289.0, regular_price: 319.0, currency_code: 'USD' },
        is_salable: '1',
      },
    ],
  },
  shopware6Html: `<!doctype html>
<html>
<head>
  <title>Supernova M99 Mini Pro-25</title>
  <script type="application/ld+json">
  {
    "@context": "https://schema.org",
    "@type": "Product",
    "name": "Supernova M99 Mini Pro-25",
    "sku": "SN-M99-MINI25",
    "brand": { "@type": "Brand", "name": "Supernova" },
    "offers": { "@type": "Offer", "price": "299.00", "priceCurrency": "EUR", "availability": "https://schema.org/InStock" }
  }
  </script>
</head>
<body>
  <main class="sw-product-detail">
    <h1>Supernova M99 Mini Pro-25</h1>
    <table class="product-detail-properties-table">
      <tbody>
        <tr><th>High Beam</th><td>1,150 lm / 260 lx</td></tr>
        <tr><th>Low Beam</th><td>450 lm / 150 lx</td></tr>
        <tr><th>Voltage</th><td>12V DC</td></tr>
      </tbody>
    </table>
  </main>
</body>
</html>`,
};

export const F13_SRAM_BOSCH_HELP = {
  sramDocsHtml: `<!doctype html>
<html>
<head><title>Eagle AXS Transmission User Manual | SRAM Docs</title></head>
<body>
  <div class="ft-breadcrumbs"><a href="/en-US">Docs</a> / <span>Eagle AXS</span></div>
  <main class="ft-topic-content">
    <h1>Eagle AXS Transmission Installation</h1>
    <p>Tighten the Full Mount derailleur knurled bolt to <strong>35 Nm</strong> using a calibrated torque wrench.</p>
    <a href="https://docs.sram.com/en-US/publications/1zPBXB1BWfF7E1mLreIuVi/eagle-axs.pdf">Download PDF Manual</a>
  </main>
</body>
</html>`,
  boschHelpHtml: `<!doctype html>
<html>
<head><title>Charging your eBike battery | Bosch eBike Help</title></head>
<body>
  <div class="dodo-service-include__error" aria-hidden="true">Service temporarily unavailable</div>
  <main>
    <nav class="breadcrumb">Help Center / Batteries</nav>
    <h1>Charging your Bosch eBike Battery</h1>
    <img src="data:image/webp;base64,UklGRh4AAABXRUJQVlA4TBEAAAAvAAAAAAfQ//73v/+BiOh/AAA=" alt="inline-blob">
    <div id="S:0">
      <p>Use only original Bosch eBike chargers at ambient temperatures between 0°C and 40°C.</p>
      <ul><li>Standard Charger 4A: 50% charge in 1.7 hours for PowerTube 750.</li></ul>
    </div>
    <script>$RC("B:0","S:0");</script>
  </main>
</body>
</html>`,
};

export const F14_MICRODATA_SPEC = {
  booksToScrapeHtml: `<!doctype html>
<html>
<head><title>A Light in the Attic | Books to Scrape</title></head>
<body>
  <article class="product_page">
    <h1>A Light in the Attic</h1>
    <p class="price_color">£51.77</p>
    <p class="instock availability">In stock (22 available)</p>
    <div id="product_description"></div><p>It's hard to imagine a world without A Light in the Attic.</p>
    <table class="table table-striped">
      <tr><th>UPC</th><td>a897fe39b1053632</td></tr>
      <tr><th>Product Type</th><td>Books</td></tr>
      <tr><th>Price (excl. tax)</th><td>£51.77</td></tr>
      <tr><th>Availability</th><td>In stock (22 available)</td></tr>
    </table>
  </article>
</body>
</html>`,
  bikeschematicsHtml: `<!doctype html>
<html>
<head><title>Shimano EP801 Drive Unit | BikeSchematics</title></head>
<body>
  <main>
    <h1>Shimano EP801 Drive Unit</h1>
    <span class="price">$899.00</span>
    <span class="instock">In Stock</span>
    <table class="spec-table">
      <tr><th>Part Number</th><td>SH-EP801-01</td></tr>
      <tr><th>Brand</th><td>Shimano</td></tr>
      <tr><th>Voltage</th><td>36V</td></tr>
      <tr><th>Max Torque</th><td>85 Nm</td></tr>
      <tr><th>Weight</th><td>2.7 kg</td></tr>
    </table>
  </main>
</body>
</html>`,
  bafangDlHtml: `<!doctype html>
<html>
<head><title>Bafang M620 Ultra Motor | Bafang</title></head>
<body>
  <main>
    <h1>Bafang M620 Ultra Mid-Drive Motor</h1>
    <dl class="specs">
      <dt>Model</dt><dd>MM G510.1000</dd>
      <dt>Rated Voltage</dt><dd>48V</dd>
      <dt>Rated Power</dt><dd>1000W</dd>
      <dt>Max Torque</dt><dd>160 Nm</dd>
    </dl>
  </main>
</body>
</html>`,
  microdataProductHtml: `<!doctype html>
<html>
<head><title>Bosch PowerTube 750</title></head>
<body>
  <main itemscope itemtype="https://schema.org/Product">
    <h1 itemprop="name">Bosch PowerTube 750 Horizontal</h1>
    <span itemprop="brand" itemscope itemtype="https://schema.org/Brand"><span itemprop="name">Bosch</span></span>
    <span itemprop="sku">BCH-POWERTUBE-750</span>
    <div itemprop="offers" itemscope itemtype="https://schema.org/Offer">
      <meta itemprop="price" content="649.50" />
      <meta itemprop="priceCurrency" content="EUR" />
      <link itemprop="availability" href="https://schema.org/InStock" />
    </div>
    <img itemprop="image" src="/images/powertube-750.jpg" alt="PowerTube 750" />
  </main>
</body>
</html>`,
  euroSpecTableHtml: `<!doctype html>
<html>
<head><title>Cargo E-Bike Frame Kit</title></head>
<body>
  <main>
    <h1>Cargo E-Bike Frame Kit</h1>
    <table>
      <tr><th>SKU</th><td>EU-CARGO-1</td></tr>
      <tr><th>Brand</th><td>EuroCargo</td></tr>
      <tr><th>Price</th><td>€1.299,00</td></tr>
      <tr><th>Stock</th><td>Out of stock</td></tr>
    </table>
  </main>
</body>
</html>`,
};

export const F15_TERRAFORM = {
  providerJson: {
    id: 'hashicorp/random/3.6.2',
    namespace: 'hashicorp',
    name: 'random',
    version: '3.6.2',
    tier: 'official',
    downloads: 980432100,
    published_at: '2026-06-01T12:00:00Z',
    source: 'https://github.com/hashicorp/terraform-provider-random',
    description: 'Provides randomness for Terraform configurations.',
    versions: ['3.6.2', '3.6.1', '3.6.0'],
  },
  moduleJson: {
    id: 'terraform-aws-modules/vpc/aws/5.8.1',
    namespace: 'terraform-aws-modules',
    name: 'vpc',
    provider: 'aws',
    version: '5.8.1',
    verified: true,
    downloads: 112500000,
    source: 'https://github.com/terraform-aws-modules/terraform-aws-modules-vpc',
    description: 'Terraform module which creates VPC resources on AWS.',
    root: {
      inputs: [
        { name: 'cidr', type: 'string', description: 'The CIDR block for the VPC', default: '10.0.0.0/16', required: false },
        { name: 'azs', type: 'list(string)', description: 'A list of availability zones', required: true },
      ],
      outputs: [{ name: 'vpc_id', description: 'The ID of the VPC' }],
      dependencies: [],
      readme: '# AWS VPC Terraform module\n\nCreates subnets, route tables, and NAT gateways.',
    },
    submodules: [{ name: 'vpc-endpoints', path: 'modules/vpc-endpoints' }],
  },
};

export const F16_DOCKER_HUB = {
  alpineRepoJson: {
    user: 'library',
    name: 'alpine',
    namespace: 'library',
    description: 'A minimal Docker image based on Alpine Linux with a complete package index and only 5 MB in size!',
    star_count: 10842,
    pull_count: 9500000000,
    last_updated: '2026-10-18T02:11:00Z',
    full_description: '# Alpine Linux\n\nMinimal Linux container image using musl libc and busybox.',
  },
  grafanaRepoJson: {
    user: 'grafana',
    name: 'grafana',
    namespace: 'grafana',
    description: 'The open and composable observability and data visualization platform.',
    star_count: 6420,
    pull_count: 1400000000,
    last_updated: '2026-10-20T14:00:00Z',
    full_description: '# Grafana\n\nQuery, visualize, and alert on metrics and logs.',
  },
  tagsJson: {
    count: 2,
    results: [
      {
        name: '3.20.3',
        full_size: 3624960,
        last_updated: '2026-10-18T02:11:00Z',
        images: [{ architecture: 'amd64', os: 'linux', digest: 'sha256:aaaa1111' }, { architecture: 'arm64', os: 'linux', digest: 'sha256:bbbb2222' }],
      },
      {
        name: 'latest',
        full_size: 3624960,
        last_updated: '2026-10-18T02:11:00Z',
        images: [{ architecture: 'amd64', os: 'linux', digest: 'sha256:aaaa1111' }],
      },
    ],
  },
};

export const F17_MAVEN_CENTRAL = {
  guavaSolrJson: {
    responseHeader: { status: 0 },
    response: {
      numFound: 1,
      docs: [
        {
          id: 'com.google.guava:guava',
          g: 'com.google.guava',
          a: 'guava',
          latestVersion: '33.3.1-jre',
          p: 'bundle',
          timestamp: 1726704000000,
          versionCount: 94,
          ec: ['-sources.jar', '-javadoc.jar', '.jar'],
        },
      ],
    },
  },
  commonsLangGavJson: {
    responseHeader: { status: 0 },
    response: {
      numFound: 1,
      docs: [
        {
          id: 'org.apache.commons:commons-lang3:3.14.0',
          g: 'org.apache.commons',
          a: 'commons-lang3',
          v: '3.14.0',
          latestVersion: '3.14.0',
          p: 'jar',
          timestamp: 1700000000000,
          ec: ['-sources.jar', '-javadoc.jar', '.jar'],
        },
      ],
    },
  },
};

export const F18_NUGET = {
  newtonsoftIndexJson: {
    count: 1,
    items: [
      {
        '@id': 'https://api.nuget.org/v3/registration5-gz-semver2/newtonsoft.json/page/12.0.1/13.0.3.json',
        count: 2,
        lower: '12.0.1',
        upper: '13.0.3',
        items: [
          {
            catalogEntry: {
              id: 'Newtonsoft.Json',
              version: '13.0.3',
              authors: 'James Newton-King',
              description: 'Json.NET is a popular high-performance JSON framework for .NET',
              licenseExpression: 'MIT',
              projectUrl: 'https://www.newtonsoft.com/json',
              published: '2023-03-08T07:42:00Z',
              listed: true,
              dependencyGroups: [
                {
                  targetFramework: '.NETStandard2.0',
                  dependencies: [{ id: 'Microsoft.CSharp', range: '[4.7.0, )' }],
                },
              ],
            },
          },
        ],
      },
    ],
  },
  unInlinedStubIndexJson: {
    count: 2,
    items: [
      { '@id': 'https://api.nuget.org/v3/registration5-gz-semver2/serilog/page/1.0.0/2.12.0.json', count: 50, lower: '1.0.0', upper: '2.12.0' },
      { '@id': 'https://api.nuget.org/v3/registration5-gz-semver2/serilog/page/3.0.0/3.1.1.json', count: 12, lower: '3.0.0', upper: '3.1.1' },
    ],
  },
};

export const F19_HOMEBREW = {
  jqFormulaJson: {
    name: 'jq',
    full_name: 'jq',
    desc: 'Lightweight and flexible command-line JSON processor',
    license: 'MIT',
    homepage: 'https://jqlang.github.io/jq/',
    versions: { stable: '1.7.1', head: 'HEAD', bottle: true },
    dependencies: ['oniguruma'],
    build_dependencies: ['autoconf', 'automake'],
    deprecated: false,
    disabled: false,
    analytics: { install: { '30d': { jq: 185420 } } },
  },
  deprecatedFormulaJson: {
    name: 'python@3.8',
    full_name: 'python@3.8',
    desc: 'Interpreted, interactive, object-oriented programming language',
    license: 'Python-2.0',
    homepage: 'https://www.python.org/',
    versions: { stable: '3.8.20' },
    dependencies: ['openssl@3'],
    deprecated: true,
    deprecation_date: '2024-10-14',
    deprecation_reason: 'upstream_eol',
    disabled: false,
  },
  disabledFormulaJson: {
    name: 'old-tool',
    full_name: 'old-tool',
    desc: 'Retired CLI utility',
    license: 'MIT',
    homepage: 'https://example.org/old-tool',
    versions: { stable: '1.0.0' },
    dependencies: [],
    deprecated: false,
    disabled: true,
    disable_date: '2025-01-01',
    disable_reason: 'unmaintained',
  },
  iterm2CaskJson: {
    token: 'iterm2',
    full_token: 'iterm2',
    name: ['iTerm2'],
    desc: 'Terminal emulator as alternative to Apple\'s Terminal app',
    homepage: 'https://iterm2.com/',
    url: 'https://iterm2.com/downloads/stable/iTerm2-3_5_5.zip',
    version: '3.5.5',
    sha256: 'abc123def456',
    auto_updates: true,
    depends_on: { macos: { '>=': ['10.15'] } },
  },
};

export const F20_OSV = {
  ghsaVulnJson: (versionCount = 3) => ({
    id: 'GHSA-jfh8-c2jp-5v3q',
    summary: 'Apache Log4j2 Remote Code Execution (Log4Shell)',
    details: 'Apache Log4j2 JNDI features used in configuration and log messages do not protect against attacker controlled LDAP endpoints.',
    aliases: ['CVE-2021-44228'],
    severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H' }],
    published: '2021-12-10T00:00:00Z',
    modified: '2024-05-01T12:00:00Z',
    affected: [
      {
        package: { ecosystem: 'Maven', name: 'org.apache.logging.log4j:log4j-core' },
        ranges: [{ type: 'ECOSYSTEM', events: [{ introduced: '2.0-beta9' }, { fixed: '2.15.0' }] }],
        versions: Array.from({ length: versionCount }, (_, i) => `2.${i}.0`),
      },
    ],
    references: [
      { type: 'ADVISORY', url: 'https://nvd.nist.gov/vuln/detail/CVE-2021-44228' },
      { type: 'FIX', url: 'https://github.com/apache/logging-log4j2/pull/608' },
    ],
  }),
  pysecVulnJson: {
    id: 'PYSEC-2023-123',
    summary: 'Sample Python security advisory',
    details: 'Improper input validation in sample package.',
    aliases: ['CVE-2023-99999'],
    published: '2023-08-01T00:00:00Z',
    affected: [{ package: { ecosystem: 'PyPI', name: 'sample-pkg' }, versions: ['1.0.0', '1.0.1'] }],
    references: [{ type: 'ADVISORY', url: 'https://osv.dev/vulnerability/PYSEC-2023-123' }],
  },
};

export const F21_WORKDAY_ICIMS = {
  workdayCxs422: { errorCode: 'S22', errorCaseId: 'case-wd-422', httpStatus: 422, message: 'Invalid tenant or cluster' },
  workdayCxs500: { errorCode: 'INTERNAL_SERVER_ERROR', message: 'Tenant site not found on wd1 cluster' },
  workdayCxsJobsOk: {
    total: 2,
    jobPostings: [
      {
        title: 'Senior Distributed Systems Engineer',
        externalPath: '/job/San-Francisco-CA/Senior-Distributed-Systems-Engineer_JR1042',
        locationsText: 'San Francisco, CA',
        postedOn: 'Posted 2 Days Ago',
      },
      {
        title: 'Staff Infrastructure Engineer',
        externalPath: '/job/Remote/Staff-Infrastructure-Engineer_JR1043',
        locationsText: 'Remote, US',
        postedOn: 'Posted 5 Days Ago',
      },
    ],
  },
  icimsSearchIframeHtml: `<!doctype html>
<html>
<head><title>Careers Search | Acme</title></head>
<body>
  <div class="iCIMS_JobsTable">
    <div class="row">
      <div class="title"><a class="iCIMS_Anchor" href="https://careers-acme.icims.com/jobs/4123/firmware-engineer/job?in_iframe=1"><span>Firmware Engineer</span></a></div>
      <div class="additionalFields"><dl><dt>Location</dt><dd>US-CA-San Jose</dd></dl></div>
    </div>
    <div class="row">
      <div class="title"><a class="iCIMS_Anchor" href="https://careers-acme.icims.com/jobs/4124/battery-test-lead/job?in_iframe=1"><span>Battery Test Lead</span></a></div>
      <div class="additionalFields"><dl><dt>Location</dt><dd>US-CO-Boulder</dd></dl></div>
    </div>
  </div>
</body>
</html>`,
  icimsJobIframeHtml: `<!doctype html>
<html>
<head>
  <title>Firmware Engineer - Acme</title>
  <script type="application/ld+json">
  {
    "@context": "https://schema.org",
    "@type": "JobPosting",
    "title": "Firmware Engineer",
    "hiringOrganization": { "@type": "Organization", "name": "Acme Mobility" },
    "jobLocation": { "@type": "Place", "address": { "@type": "PostalAddress", "addressLocality": "San Jose", "addressRegion": "CA", "addressCountry": "US" } },
    "employmentType": "FULL_TIME",
    "datePosted": "2026-10-15",
    "description": "Develop embedded CAN-bus firmware for e-bike motor controllers."
  }
  </script>
</head>
<body>
  <div class="iCIMS_MainWrapper">
    <h1 class="iCIMS_Header">Firmware Engineer</h1>
    <div class="iCIMS_JobContent"><p>Develop embedded CAN-bus firmware for e-bike motor controllers.</p></div>
  </div>
</body>
</html>`,
};

export const F22_UKG_PAYLOCITY_DOVER = {
  ukgRobotsTxt: 'User-agent: *\nDisallow: /\nAllow: */JobBoard/\nDisallow: */JobBoardView\n',
  ukgJobBoardHtml: `<!doctype html>
<html>
<head><title>Acme Mobility Careers | UKG Pro</title></head>
<body>
  <main>
    <h1>Acme Mobility Open Opportunities</h1>
    <script>
      window.__PRELOADED_STATE__ = {
        opportunities: [
          { Id: "opp-101", Title: "Embedded Systems Engineer", Location: "Boulder, CO", PostedDate: "2026-10-12", ApplyUrl: "https://recruiting.ultipro.com/ACM1001/JobBoard/11111111-2222-3333-4444-555555555555/OpportunityDetail?opportunityId=opp-101" },
          { Id: "opp-102", Title: "Supply Chain Planner", Location: "Remote", PostedDate: "2026-10-15", ApplyUrl: "https://recruiting.ultipro.com/ACM1001/JobBoard/11111111-2222-3333-4444-555555555555/OpportunityDetail?opportunityId=opp-102" }
        ]
      };
    </script>
  </main>
</body>
</html>`,
  paylocityFeedJson: {
    jobs: [
      {
        jobId: 'plc-901',
        title: 'Product Safety Engineer',
        department: 'Engineering',
        locationName: 'Austin, TX',
        publishedDate: '2026-10-10',
        jobUrl: 'https://recruiting.paylocity.com/Recruiting/Jobs/Details/901',
        description: 'Lead UL 2849 battery and drivetrain compliance.',
      },
      {
        jobId: 'plc-902',
        title: 'Field Service Specialist',
        department: 'Operations',
        locationName: 'Denver, CO',
        publishedDate: '2026-10-14',
        jobUrl: 'https://recruiting.paylocity.com/Recruiting/Jobs/Details/902',
      },
    ],
  },
  paylocityHtml: `<!doctype html>
<html>
<head><title>Paylocity Jobs</title></head>
<body>
  <script>window.pageData = { Jobs: [{ JobId: "plc-901", Title: "Product Safety Engineer", LocationName: "Austin, TX" }] };</script>
</body>
</html>`,
  doverRobotsTxt: 'User-agent: *\nDisallow: /api/\nAllow: /\n',
  doverHtml: `<!doctype html>
<html>
<head><title>Careers at Acme Robotics | Dover</title></head>
<body>
  <main>
    <h1>Acme Robotics Open Roles</h1>
    <div id="__next"></div>
    <script id="__NEXT_DATA__" type="application/json">
    {
      "props": {
        "pageProps": {
          "company": { "name": "Acme Robotics" },
          "jobs": [
            { "id": "dov-1", "title": "Founding Robotics Engineer", "location": "San Francisco, CA", "url": "https://app.dover.com/apply/acme/dov-1" },
            { "id": "dov-2", "title": "Mechanical Design Lead", "location": "Remote", "url": "https://app.dover.com/apply/acme/dov-2" }
          ]
        }
      }
    }
    </script>
  </main>
</body>
</html>`,
};

export const F23_NHTSA_FCC = {
  vpicVinJson: {
    Count: 1,
    Message: 'Results returned successfully.',
    SearchCriteria: 'VIN:1HGCM82633A004352',
    Results: [
      {
        VIN: '1HGCM82633A004352',
        Make: 'HONDA',
        Model: 'Accord',
        ModelYear: '2003',
        VehicleType: 'PASSENGER CAR',
        BodyClass: 'Sedan/Saloon',
        PlantCountry: 'UNITED STATES (USA)',
        EngineCylinders: '6',
        DisplacementL: '3.0',
        ErrorCode: '0',
      },
    ],
  },
  nhtsaRecallsJson: {
    Count: 1,
    Message: 'Results returned successfully',
    results: [
      {
        NHTSACampaignNumber: '23V858000',
        Component: 'FUEL SYSTEM, GASOLINE:DELIVERY:FUEL PUMP',
        Summary: 'The low-pressure fuel pump impeller may deform and cause the fuel pump to fail.',
        Consequence: 'A failed fuel pump can cause an engine stall while driving, increasing the risk of a crash.',
        Remedy: 'Dealers will replace the fuel pump module, free of charge.',
        ReportReceivedDate: '19/12/2023',
      },
    ],
  },
  fccRobotsTxt: 'User-agent: *\nDisallow: /ViewExhibitReport.cfm\nDisallow: /subscribe.php\nDisallow: /frequency?\nAllow: /\n',
  fccHtml: `<!doctype html>
<html>
<head><title>FCC ID BCG-E3542A Wireless Device by Apple Inc.</title></head>
<body>
  <main>
    <h1>FCC ID BCG-E3542A</h1>
    <p>Grantee: Apple Inc. | Application Purpose: Original Grant</p>
    <table>
      <tr><th>Frequency Range</th><td>2402 - 2480 MHz</td></tr>
      <tr><th>Max Output Power</th><td>0.019 W</td></tr>
      <tr><th>Grant Date</th><td>2024-09-10</td></tr>
    </table>
    <a href="https://fccid.io/BCG-E3542A/User-Manual/User-Manual-654321.pdf">User Manual PDF</a>
  </main>
</body>
</html>`,
};

export const F24_WIKIDATA_OPENLIBRARY = {
  wikidataQ42Json: {
    entities: {
      Q42: {
        type: 'item',
        id: 'Q42',
        labels: { en: { language: 'en', value: 'Douglas Adams' } },
        descriptions: { en: { language: 'en', value: 'English science fiction writer and humourist (1952–2001)' } },
        aliases: { en: [{ language: 'en', value: 'Douglas Noel Adams' }] },
        sitelinks: { enwiki: { site: 'enwiki', title: 'Douglas Adams', url: 'https://en.wikipedia.org/wiki/Douglas_Adams' } },
        claims: { P31: [{ mainsnak: { datavalue: { value: { id: 'Q5' } } } }] },
      },
    },
  },
  wikidataQ937Json: {
    entities: {
      Q937: {
        type: 'item',
        id: 'Q937',
        labels: { en: { language: 'en', value: 'Albert Einstein' } },
        descriptions: { en: { language: 'en', value: 'German-born theoretical physicist (1879–1955)' } },
        aliases: { en: [{ language: 'en', value: 'Einstein' }] },
        sitelinks: { enwiki: { site: 'enwiki', title: 'Albert Einstein' } },
      },
    },
  },
  openLibraryRobotsTxt: 'User-agent: *\nDisallow: /api\nAllow: /\n',
  openLibraryBookJson: (isbn13 = '9780140328721', title = 'Fantastic Mr. Fox') => ({
    title,
    subtitle: 'Special Edition',
    publishers: ['Puffin Books'],
    publish_date: '1988',
    number_of_pages: 96,
    isbn_10: ['0140328726'],
    isbn_13: [isbn13],
    authors: [{ key: '/authors/OL34184A' }],
    works: [{ key: '/works/OL45804W' }],
    covers: [8739161],
    key: '/books/OL7353617M',
  }),
};

export const F25_JSONFILTER_RECORDS = [
  { id: 'r1', title: 'Platform Role Alpha', team: 'Platform' },
  { id: 'r2', title: 'Sales Role Bravo', team: 'Sales' },
  { id: 'r3', title: 'Platform Role Charlie', team: 'Platform' },
  { id: 'r4', title: 'Sales Role Delta', team: 'Sales' },
];

export const F30_NFPA = {
  robotsTxt: 'User-agent: *\nDisallow: /-/media/\nDisallow: /ar/\nDisallow: /en/\nDisallow: /data/\nAllow: /\n',
  nextDataHtml: (title = 'NFPA 70 National Electrical Code') => {
    const nextData = {
      props: {
        pageProps: {
          layoutData: {
            sitecore: {
              route: {
                name: 'nfpa-70',
                placeholders: {
                  'storefront-main': [
                    { componentName: 'PageTitle', fields: { title: { value: title }, subtitle: { value: 'Standard for safe electrical installation.' } } },
                    { componentName: 'ContentBlock', fields: { content: { value: '<p>NFPA 70 provides comprehensive requirements for electrical wiring, overcurrent protection, and e-bike charging circuits.</p>' } } },
                    {
                      componentName: 'SplitScreenCalloutComponent',
                      fields: {
                        heading: { value: 'Code Adoption Highlights' },
                        body: { value: '<p>Adopted across all 50 US states for residential and commercial electrical systems.</p>' },
                        ctaLink: { value: { href: 'https://www.nfpa.org/codes-and-standards/nfpa-70-standard-development/70', text: 'View Standard Development' } },
                      },
                    },
                    {
                      componentName: 'Accordion',
                      fields: {
                        items: [
                          { heading: { value: 'Article 625 Electric Vehicle Power Transfer' }, body: { value: '<p>Covers EVSE and micromobility charging branch circuits.</p>' } },
                          { heading: { value: 'Article 706 Energy Storage Systems' }, body: { value: '<p>Covers stationary lithium-ion battery storage safety.</p>' } },
                        ],
                      },
                    },
                    {
                      componentName: 'TwoColumnVideo',
                      fields: {
                        title: { value: 'NFPA 70 Overview Video' },
                        videoUrl: { value: { href: 'https://www.nfpa.org/videos/nfpa-70-overview', text: 'Watch Overview' } },
                      },
                    },
                  ],
                },
              },
            },
          },
        },
      },
    };
    return `<!doctype html>
<html>
<head><title>${title}</title></head>
<body>
  <div id="__next"><div>Loading...</div></div>
  <script id="__NEXT_DATA__" type="application/json">${JSON.stringify(nextData)}</script>
</body>
</html>`;
  },
};

export const F31_GIANT_LIV = {
  robotsTxt: 'User-agent: *\nCrawl-delay: 2\nDisallow: /*shop*\nDisallow: /*comparison*\nDisallow: /*account*\nAllow: /\n',
  bikeHtml: (brand, model) => `<!doctype html>
<html>
<head><title>${model} | ${brand}</title></head>
<body>
  <main>
    <h1>${model}</h1>
    <section id="specifications">
      <h2>Specifications</h2>
      <ul class="specifications">
        <li class="datarow"><span class="label">Frame</span><span class="value">Advanced-grade composite</span></li>
        <li class="datarow"><span class="label">Drivetrain</span><span class="value">Shimano Ultegra Di2 12-speed</span></li>
        <li class="datarow"><span class="label">Brakes</span><span class="value">Shimano Ultegra Di2 hydraulic, 160mm rotors</span></li>
      </ul>
    </section>
    <section id="geometry">
      <h2>Geometry</h2>
      <table class="geometry geometry-global">
        <thead><tr><th>Size</th><th>Stack (mm)</th><th>Reach (mm)</th></tr></thead>
        <tbody>
          <tr><td>M</td><td>562</td><td>377</td></tr>
          <tr><td>ML</td><td>581</td><td>384</td></tr>
        </tbody>
      </table>
    </section>
    <a href="https://static.giant-bicycles.com/Manuals/Defy_Manual_2026.pdf">Owner Manual PDF</a>
  </main>
</body>
</html>`,
  manualsHtml: `<!doctype html>
<html>
<head><title>Owner Manuals | Giant Bicycles</title></head>
<body>
  <main>
    <h1>Owner Manuals</h1>
    <ul>
      <li><a href="https://static.giant-bicycles.com/Manuals/SyncDrive_Pro2_Manual.pdf">SyncDrive Pro 2 Manual (PDF)</a></li>
      <li><a href="https://static.giant-bicycles.com/Manuals/EnergyPak_Smart_800.pdf">EnergyPak Smart 800 Manual (PDF)</a></li>
    </ul>
  </main>
</body>
</html>`,
};

export const F32_BUMM = {
  robotsTxt: 'User-agent: *\nDisallow: /typo3/\nAllow: /\n',
  productHtml: (lang = 'en') => `<!doctype html>
<html lang="${lang}">
<head>
  <title>${lang === 'de' ? 'IQ-X Scheinwerfer' : 'IQ-X Dynamo Headlight'} | Busch &amp; Müller</title>
  <script type="application/ld+json">
  {
    "@context": "https://schema.org",
    "@type": "Product",
    "name": "${lang === 'de' ? 'IQ-X Dynamo Scheinwerfer für E-Bikes' : 'IQ-X Dynamo Headlight'}",
    "sku": "164RTSNDI-01",
    "brand": { "@type": "Brand", "name": "Busch & Müller" },
    "offers": { "@type": "Offer", "price": "${lang === 'de' ? '149,90' : '149.90'}", "priceCurrency": "EUR", "availability": "https://schema.org/InStock" }
  }
  </script>
</head>
<body>
  <main>
    <h1>${lang === 'de' ? 'IQ-X Scheinwerfer für E-Bikes' : 'IQ-X Dynamo Headlight'}</h1>
    <table class="attributes-table">
      <tr><th>Illuminance</th><td>100 Lux</td></tr>
      <tr><th>Daytime Running Light</th><td>Yes</td></tr>
      <tr><th>Housing</th><td>CNC Aluminum</td></tr>
    </table>
    <a href="https://bumm.de/fileadmin/user_upload/Anleitung_IQ-X.pdf">Anleitung_IQ-X.pdf</a>
  </main>
</body>
</html>`,
};

export const F33_BICYCLE_RETAILER = {
  robotsTxt: 'User-agent: *\nCrawl-delay: 10\nDisallow: /admin/\nAllow: /\n',
  articleHtml: `<!doctype html>
<html>
<head>
  <title>CPSC Finalizes E-Bike Battery Safety Guidance | Bicycle Retailer</title>
  <meta name="author" content="Marc Sani">
  <meta property="article:published_time" content="2026-11-01T10:00:00Z">
</head>
<body>
  <aside class="region-sidebar-second"><div>Sidebar Ads Noise</div></aside>
  <main>
    <article class="node-article">
      <h1>CPSC Finalizes E-Bike Battery Safety Guidance</h1>
      <div class="submitted">By Marc Sani — Nov 1, 2026</div>
      <div class="field-name-body">
        <p>The Consumer Product Safety Commission published updated certification guidance referencing UL 2849 and UL 2271 for retail bicycle dealers.</p>
      </div>
    </article>
  </main>
</body>
</html>`,
  listingHtml: `<!doctype html>
<html>
<head><title>Industry News | Bicycle Retailer</title></head>
<body>
  <main>
    <h1>Industry News</h1>
    <div class="view-content">
      <div class="views-row">
        <h3><a href="/industry-news/2026/11/01/ebike-battery-rules">CPSC Finalizes E-Bike Battery Safety Guidance</a></h3>
        <p>Updated certification guidance for US retailers.</p>
      </div>
      <div class="views-row">
        <h3><a href="/industry-news/2026/10/28/shimano-q3-results">Shimano Reports Q3 Bicycle Component Shipments</a></h3>
        <p>European and North American inventory levels stabilize.</p>
      </div>
    </div>
  </main>
</body>
</html>`,
  rssXml: `<?xml version="1.0" encoding="utf-8"?>
<rss version="2.0">
  <channel>
    <title>Bicycle Retailer and Industry News</title>
    <link>https://www.bicycleretailer.com/</link>
    <item>
      <title>CPSC Finalizes E-Bike Battery Safety Guidance</title>
      <link>https://www.bicycleretailer.com/industry-news/2026/11/01/ebike-battery-rules</link>
      <pubDate>Sun, 01 Nov 2026 10:00:00 GMT</pubDate>
      <description>Updated certification guidance for US retailers.</description>
    </item>
  </channel>
</rss>`,
};

export const F34_YOUTUBE = {
  robotsTxt: 'User-agent: *\nDisallow: /api/\nDisallow: /youtubei/\nDisallow: /feeds/videos.xml\nAllow: /watch\n',
  watchHtml: (title = 'Bosch Performance Line CX Gen5 Review', author = 'ElectricBikeLab') => {
    const playerResponse = {
      videoDetails: {
        videoId: 'dQw4w9WgXcQ',
        title,
        author,
        lengthSeconds: '842',
        channelId: 'UCtest1234',
        shortDescription: 'Full bench dyno and hill-climb test of the Bosch CX Gen5 motor with 85 Nm torque.',
        keywords: ['ebike', 'bosch', 'motor'],
      },
      captions: {
        playerCaptionsTracklistRenderer: {
          captionTracks: [
            { baseUrl: 'https://www.youtube.com/api/timedtext?v=dQw4w9WgXcQ&lang=en', languageCode: 'en', name: { simpleText: 'English' } },
          ],
        },
      },
    };
    return `<!doctype html>
<html>
<head><title>${title} - YouTube</title></head>
<body>
  <ytd-app></ytd-app>
  <script>var ytInitialPlayerResponse = ${JSON.stringify(playerResponse)};</script>
</body>
</html>`;
  },
};

export const F35_D1_HIGH_ROI = {
  shimanoProductInfoRscHtml: (model = 'DU-EP801') => {
    const specData = {
      TableSpecContents: [
        {
          categoryName: 'Drive Unit Specifications',
          specs: [
            { specName: 'Model No', specValue: model },
            { specName: 'Rated Continuous Power', specValue: '250 W' },
            { specName: 'Maximum Torque', specValue: '85 Nm' },
            { specName: 'Compatible Battery', specValue: 'BT-EN806 / BT-EN808' },
          ],
        },
      ],
    };
    const escaped = JSON.stringify(specData).replace(/\\/g, '\\\\').replace(/"/g, '\\"');
    return `<!doctype html>
<html>
<head><title>${model} | SHIMANO PRODUCT INFO</title></head>
<body>
  <div id="__next"><div>Loading...</div></div>
  <script>self.__next_f=self.__next_f||[];self.__next_f.push([1,"5:[\\"$\\",\\"div\\",null,{\\"spec\\":\\"${escaped}\\"}]\\n"])</script>
</body>
</html>`;
  },
  cornellCfrHtml: `<!doctype html>
<html>
<head><title>16 CFR Part 1512 - REQUIREMENTS FOR BICYCLES | LII</title></head>
<body>
  <header class="navbar">Cornell LII Top Nav Noise</header>
  <aside class="sidebar">Cornell Donate Sidebar Noise</aside>
  <main id="content">
    <h1>16 CFR Part 1512 - REQUIREMENTS FOR BICYCLES</h1>
    <div class="tab-pane active">
      <p><strong>§ 1512.1 Scope.</strong> This part sets forth the requirements for a bicycle that is not a sidewalk bicycle.</p>
      <p><strong>§ 1512.18 Tests and test procedures.</strong> Reflector and brake stopping distance test procedures.</p>
    </div>
  </main>
</body>
</html>`,
  sramModelHtml: `<!doctype html>
<html>
<head>
  <title>XX SL Eagle AXS Rear Derailleur | SRAM</title>
  <script type="application/ld+json">
  {
    "@context": "https://schema.org",
    "@type": "Product",
    "name": "XX SL Eagle AXS Rear Derailleur",
    "sku": "00.7518.161.000",
    "brand": { "@type": "Brand", "name": "SRAM" },
    "offers": { "@type": "Offer", "price": "700.00", "priceCurrency": "USD", "availability": "https://schema.org/InStock" }
  }
  </script>
</head>
<body>
  <main class="product-detail">
    <h1>XX SL Eagle AXS Rear Derailleur</h1>
    <table class="specs-table">
      <tr><th>Speeds</th><td>12</td></tr>
      <tr><th>Max Tooth</th><td>52T</td></tr>
      <tr><th>Cage Material</th><td>Carbon</td></tr>
    </table>
  </main>
</body>
</html>`,
  tqEbikeHtml: `<!doctype html>
<html>
<head>
  <title>TQ HPR50 Drive System | TQ e-Mobility</title>
  <script type="application/ld+json">
  {
    "@context": "https://schema.org",
    "@type": "Product",
    "name": "TQ HPR50 Drive System",
    "sku": "TQ-HPR50-SYS",
    "brand": { "@type": "Brand", "name": "TQ" }
  }
  </script>
</head>
<body>
  <main>
    <h1>TQ HPR50 Drive System</h1>
    <p>Harmonic Pin-Ring transmission delivering 50 Nm torque at just 1,850 g motor weight.</p>
    <table class="tx-specs">
      <tr><th>Torque</th><td>50 Nm</td></tr>
      <tr><th>System Weight</th><td>3,900 g (with 360 Wh battery)</td></tr>
    </table>
  </main>
</body>
</html>`,
};
