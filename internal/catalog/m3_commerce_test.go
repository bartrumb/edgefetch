package catalog

import (
	"strings"
	"testing"
)

func TestM3ShopifyCollectionAndSKUColumn(t *testing.T) {
	colTwin := ResolveCustomDomainShopifyCollectionTwinURL("https://shop.example.com/en-us/collections/electric-bikes/")
	if colTwin == nil || colTwin.Handle != "electric-bikes" || colTwin.JSONURL != "https://shop.example.com/collections/electric-bikes/products.json?limit=50" {
		t.Fatalf("unexpected Shopify collection twin: %+v", colTwin)
	}
	if ResolveCustomDomainShopifyCollectionTwinURL("https://shop.example.com/collections/electric-bikes/products/commuter-1") != nil {
		t.Fatal("expected /collections/<col>/products/<prod> to NOT resolve as collection twin")
	}

	feed := FormatShopifyProductsFeedTwin(
		`{"products":[{"id":1,"title":"Commuter E-Bike","handle":"commuter-e-bike","vendor":"Peak","product_type":"Bikes","variants":[{"id":11,"sku":"PK-100","price":"1499.00","available":true},{"id":12,"sku":"PK-101","price":"1599.00","available":false}]}]}`,
		"https://shop.example.com/collections/electric-bikes",
		ShopifyFeedFormatOptions{
			TwinURL:  "https://shop.example.com/collections/electric-bikes/products.json?limit=1&page=1",
			Currency: "CAD",
		},
	)
	if feed == nil || len(feed.Records) != 1 {
		t.Fatalf("expected Shopify collection feed doc, got %+v", feed)
	}
	if !strings.Contains(feed.Markdown, "| Product | Vendor | Type | SKU | Variants | Price | Stock | Updated |") {
		t.Fatalf("expected SKU column in GFM header:\n%s", feed.Markdown)
	}
	if !strings.Contains(feed.Markdown, "`PK-100`, `PK-101`") || !strings.Contains(feed.Markdown, "CAD") {
		t.Fatalf("expected SKUs and CAD currency in markdown:\n%s", feed.Markdown)
	}
	if feed.Pagination == nil || feed.Pagination.Limit != 1 || !feed.Pagination.HasMore || !strings.Contains(feed.Pagination.NextURL, "products.json") {
		t.Fatalf("unexpected collection pagination: %+v", feed.Pagination)
	}
}

func TestM3WooCommerceCategoryAndShopTwins(t *testing.T) {
	catTwin := ResolveCustomDomainWooCommerceCatalogTwinURL("https://bikes.example.com/product-category/bikes/electric-bikes/")
	if catTwin == nil || catTwin.Kind != "category" || catTwin.Slug != "electric-bikes" ||
		catTwin.StoreAPIURL != "https://bikes.example.com/wp-json/wc/store/v1/products?category=electric-bikes&per_page=50" {
		t.Fatalf("unexpected Woo category twin: %+v", catTwin)
	}
	shopTwin := ResolveCustomDomainWooCommerceCatalogTwinURL("https://bikes.example.com/en/shop/page/2/")
	if shopTwin == nil || shopTwin.Kind != "shop" ||
		shopTwin.StoreAPIURL != "https://bikes.example.com/wp-json/wc/store/v1/products?per_page=50&page=2" {
		t.Fatalf("unexpected Woo shop twin: %+v", shopTwin)
	}

	// Error JSON and empty array with twinURL must fail open (return nil).
	if FormatWCStoreAPIListTwinWithOptions(`{"code":"rest_invalid_param","message":"bad"}`, "https://bikes.example.com/shop/", shopTwin.StoreAPIURL) != nil {
		t.Fatal("expected error JSON to return nil")
	}
	if FormatWCStoreAPIListTwinWithOptions(`[]`, "https://bikes.example.com/product-category/ebikes/", catTwin.StoreAPIURL) != nil {
		t.Fatal("expected empty [] on custom-domain twin to fail open (nil)")
	}

	// HTML fallback for /product-category/
	catHTML := `<html><body class="woocommerce-page tax-product_cat">
		<h1 class="woocommerce-products-header__title">Electric Bikes</h1>
		<ul class="products">
			<li class="product">
				<a href="/product/roadster-v2/"><h2 class="woocommerce-loop-product__title">Roadster V2</h2></a>
				<span class="price"><span class="amount">$1,295.00</span></span>
				<a class="add_to_cart_button" data-product_id="401" data-product_sku="RD-V2">Add</a>
			</li>
		</ul>
	</body></html>`
	htmlRes := ExtractWooCommerceCatalogHTML("https://bikes.example.com/product-category/ebikes/", catHTML, "", "woocommerce")
	if htmlRes == nil || len(htmlRes.Records) != 1 || *htmlRes.Records[0].Variants[0].SKU != "RD-V2" {
		t.Fatalf("unexpected WooCommerce catalog HTML fallback: %+v", htmlRes)
	}
}

func TestM3SquarespaceCommerce(t *testing.T) {
	sqBlog := `<html><head><script>Static = {}; Static.SQUARESPACE_CONTEXT = {"website":{}};</script></head><body><article class="blog-item">Hello world</article></body></html>`
	if IsSquarespaceCommerceHTMLOrHeaders(sqBlog, nil) {
		t.Fatal("non-commerce Squarespace blog must NOT match commerce fingerprint")
	}
	sqStore := `<html><head><script>Static = {}; Static.SQUARESPACE_CONTEXT = {"productType":1};</script></head><body><div class="ProductList"></div></body></html>`
	if !IsSquarespaceCommerceHTMLOrHeaders(sqStore, nil) {
		t.Fatal("expected Squarespace commerce fingerprint match")
	}

	twinURL := ResolveSquarespaceCommerceTwinURL("https://studio.example.com/shop?category=posters")
	if twinURL != "https://studio.example.com/shop?category=posters&format=json-pretty" {
		t.Fatalf("unexpected Squarespace twin URL: %q", twinURL)
	}
	if ResolveSquarespaceCommerceTwinURL("https://studio.example.com/shop?format=json-pretty") != "" {
		t.Fatal("expected already-formatted Squarespace URL to return empty twin")
	}

	singleJSON := `{
		"item": {
			"id": "sq-1",
			"urlId": "trail-helmet",
			"fullUrl": "/shop/p/trail-helmet",
			"title": "Trail Helmet",
			"body": "<p>MIPS protection.</p>",
			"assetUrl": "http://127.0.0.1/evil.jpg",
			"structuredContent": {
				"variants": [
					{
						"id": "v1",
						"sku": "TH-BLK-M",
						"priceMoney": {"value": "129.95", "currency": "USD"},
						"onSale": true,
						"salePriceMoney": {"value": "99.95", "currency": "USD"},
						"attributes": {"Size": "M", "Color": "Black"},
						"stock": {"unlimited": false, "quantity": 5},
						"mainImage": {"assetUrl": "https://images.squarespace-cdn.com/helmet.jpg"}
					}
				]
			}
		}
	}`
	doc := FormatSquarespaceCommerceJSON(singleJSON, "https://studio.example.com/shop/p/trail-helmet")
	if doc == nil || len(doc.Records) != 1 || len(doc.Records[0].Variants) != 1 {
		t.Fatalf("unexpected Squarespace single-item format: %+v", doc)
	}
	v0 := doc.Records[0].Variants[0]
	if *v0.SKU != "TH-BLK-M" || *v0.Price != 99.95 || *v0.CompareAt != 129.95 || !*v0.Available {
		t.Fatalf("unexpected Squarespace variant values: %+v", v0)
	}
	if strings.Contains(doc.Markdown, "127.0.0.1") || !strings.Contains(doc.Markdown, "TH-BLK-M") {
		t.Fatalf("SSRF image leaked or SKU missing:\n%s", doc.Markdown)
	}
}

func TestM3BigCommerceHTMLAndSitemap(t *testing.T) {
	bcHTML := `<!doctype html><html><head>
		<script src="https://cdn11.bigcommerce.com/s-demo123/stencil.js"></script>
		<script>window.BCData = {"product_attributes":{"sku":"BC-FRAME-1","upc":"123456789012","instock":true,"stock":12,"price":{"without_tax":{"value":899.5,"currency":"USD"}}}};</script>
	</head><body>
		<h1 class="productView-title">Gravel Frameset</h1>
		<div class="productView-brand"><a>Apex Cycles</a></div>
		<dl class="productView-info"><dt class="productView-info-name">Weight:</dt><dd class="productView-info-value">1,450 g</dd></dl>
		<form data-cart-item-add>
			<input type="hidden" name="product_id" value="778" />
			<div class="form-field" data-product-attribute="set-select">
				<label class="form-label">Frame Size:</label>
				<select name="attribute[1]"><option value="">Choose</option><option value="10">54cm</option><option value="11">56cm</option></select>
			</div>
		</form>
		<div id="tab-description"><p>Carbon fork included.</p></div>
	</body></html>`
	res := ExtractBigCommerceHTML("https://demo.mybigcommerce.com/gravel-frameset/", bcHTML, "", "bigcommerce-store")
	if res == nil || len(res.Records) != 1 {
		t.Fatalf("expected BigCommerce HTML extraction, got %+v", res)
	}
	r0 := res.Records[0]
	if *r0.Variants[0].SKU != "BC-FRAME-1" || *r0.Variants[0].Price != 899.5 || len(r0.Options) != 1 || len(r0.Options[0].Values) != 2 {
		t.Fatalf("unexpected BigCommerce record: %+v", r0)
	}
	if !strings.Contains(res.Markdown, "1,450 g") || !strings.Contains(res.Markdown, "54cm, 56cm") {
		t.Fatalf("missing BigCommerce specs/options in markdown:\n%s", res.Markdown)
	}

	sitemapXML := `<?xml version="1.0" encoding="UTF-8"?>
	<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9" xmlns:image="http://www.google.com/schemas/sitemap-image/1.1">
		<url><loc>https://demo.mybigcommerce.com/gravel-frameset/</loc><lastmod>2026-04-01</lastmod><image:image><image:loc>https://cdn11.bigcommerce.com/s-demo123/frame.jpg</image:loc></image:image></url>
		<url><loc>http://127.0.0.1/ssrf</loc><lastmod>2026-04-01</lastmod></url>
	</urlset>`
	smDoc := FormatBigCommerceXMLSitemap(sitemapXML, "https://demo.mybigcommerce.com/xmlsitemap.php")
	if smDoc == nil || len(smDoc.Records) != 1 || strings.Contains(smDoc.Markdown, "127.0.0.1") {
		t.Fatalf("unexpected BigCommerce sitemap result: %+v", smDoc)
	}
	if FormatBigCommerceXMLSitemap("<html><body>Not XML</body></html>", "https://example.com/xmlsitemap.php") != nil {
		t.Fatal("expected non-XML to fail open (nil)")
	}

	// Empty BCData stub before real BCData assignment must NOT shadow product_attributes.
	bcEmptyFirstHTML := `<!doctype html><html><head>
		<script src="https://cdn11.bigcommerce.com/s-demo123/stencil.js"></script>
		<script>window.BCData = window.BCData || {};</script>
		<script>BCData = {"product_attributes":{"sku":"REAL-SKU","instock":true,"price":{"without_tax":{"value":50,"currency":"USD"}}}};</script>
	</head><body><h1 class="productView-title">Bike</h1></body></html>`
	emptyFirstRes := ExtractBigCommerceHTML("https://demo.mybigcommerce.com/bike/", bcEmptyFirstHTML, "", "bigcommerce-store")
	if emptyFirstRes == nil || len(emptyFirstRes.Records) != 1 {
		t.Fatalf("expected BigCommerce extraction after empty stub, got %+v", emptyFirstRes)
	}
	vStub := emptyFirstRes.Records[0].Variants[0]
	if vStub.SKU == nil || *vStub.SKU != "REAL-SKU" || vStub.Price == nil || *vStub.Price != 50 || vStub.Currency == nil || *vStub.Currency != "USD" || vStub.Available == nil || !*vStub.Available {
		t.Fatalf("unexpected BigCommerce values after empty stub: %+v", vStub)
	}

	// Schema.org Microdata product page without JSON-LD or BCData.
	bcMicrodataHTML := `<!doctype html><html><head><script src="https://cdn11.bigcommerce.com/s-abc/stencil.js"></script></head><body>
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
	</body></html>`
	mdRes := ExtractBigCommerceHTML("https://demo.mybigcommerce.com/helmet/", bcMicrodataHTML, "", "bigcommerce-store")
	if mdRes == nil || len(mdRes.Records) != 1 || mdRes.Records[0].Title != "Microdata Helmet" {
		t.Fatalf("expected BigCommerce microdata extraction, got %+v", mdRes)
	}
	vMD := mdRes.Records[0].Variants[0]
	if vMD.SKU == nil || *vMD.SKU != "MD-99" || vMD.Price == nil || *vMD.Price != 79.95 || vMD.Currency == nil || *vMD.Currency != "USD" || vMD.Available == nil || *vMD.Available {
		t.Fatalf("unexpected BigCommerce microdata variant: %+v", vMD)
	}
	if len(mdRes.Records[0].Options) != 1 || mdRes.Records[0].Options[0].Name != "Size" || len(mdRes.Records[0].Options[0].Values) != 1 || mdRes.Records[0].Options[0].Values[0] != "M" {
		t.Fatalf("unexpected BigCommerce microdata options: %+v", mdRes.Records[0].Options)
	}

	// Category .productGrid with Microdata cards and no form[data-cart-item-add]/.productView still takes Category Grid Path.
	bcGridWithMicroHTML := `<!doctype html><html><head><script src="https://cdn11.bigcommerce.com/s-abc/stencil.js"></script></head><body>
		<h1 class="page-heading">Helmets</h1>
		<ul class="productGrid">
			<li class="product" data-entity-id="1" data-sku="G-1" itemscope itemtype="https://schema.org/Product"><h4 class="card-title"><a itemprop="name" href="/h1">Helmet One</a></h4><span class="price">$59.00</span></li>
			<li class="product" data-entity-id="2" data-sku="G-2" itemscope itemtype="https://schema.org/Product"><h4 class="card-title"><a itemprop="name" href="/h2">Helmet Two</a></h4><span class="price">$69.00</span></li>
		</ul>
	</body></html>`
	gridRes := ExtractBigCommerceHTML("https://demo.mybigcommerce.com/helmets/", bcGridWithMicroHTML, "", "bigcommerce-store")
	if gridRes == nil || len(gridRes.Records) != 2 {
		t.Fatalf("expected BigCommerce category grid path with 2 records, got %+v", gridRes)
	}

	// <fieldset><legend>Mount Type</legend> with unclassed <label for="m1"> radio options and Cornerstone <label class="form-label" for="m1">
	bcLegendHTML := `<!doctype html><html><head><script src="https://cdn11.bigcommerce.com/s-abc/stencil.js"></script></head><body>
		<h1 class="productView-title">Disc Brake Adapter</h1>
		<form data-cart-item-add>
			<fieldset class="form-field" data-product-attribute="set-radio">
				<legend>Mount Type</legend>
				<input type="radio" id="m1" name="attribute[200]" value="1" />
				<label for="m1">Direct Mount</label>
				<input type="radio" id="m2" name="attribute[200]" value="2" />
				<label for="m2">Post Mount</label>
			</fieldset>
			<fieldset class="form-field" data-product-attribute="set-radio">
				<legend>Caliper Offset</legend>
				<input type="radio" id="o1" name="attribute[201]" value="1" />
				<label class="form-label" for="o1">0mm</label>
				<input type="radio" id="o2" name="attribute[201]" value="2" />
				<label class="form-label" for="o2">20mm</label>
			</fieldset>
			<div data-product-option-change>
				<label>Rotor Size</label>
				<select name="attribute[101]"><option value="1">180mm</option><option value="2">203mm</option></select>
			</div>
		</form>
	</body></html>`
	legRes := ExtractBigCommerceHTML("https://demo.mybigcommerce.com/adapter/", bcLegendHTML, "", "bigcommerce-store")
	if legRes == nil || len(legRes.Records) != 1 || len(legRes.Records[0].Options) != 3 {
		t.Fatalf("expected 3 BigCommerce options from legend/label, got %+v", legRes)
	}
	opts := legRes.Records[0].Options
	if opts[0].Name != "Mount Type" || len(opts[0].Values) != 2 || opts[0].Values[0] != "Direct Mount" || opts[0].Values[1] != "Post Mount" {
		t.Fatalf("unexpected Mount Type option: %+v", opts[0])
	}
	if opts[1].Name != "Caliper Offset" || len(opts[1].Values) != 2 || opts[1].Values[0] != "0mm" || opts[1].Values[1] != "20mm" {
		t.Fatalf("unexpected Cornerstone Caliper Offset option: %+v", opts[1])
	}
	if opts[2].Name != "Rotor Size" || len(opts[2].Values) != 2 || opts[2].Values[0] != "180mm" || opts[2].Values[1] != "203mm" {
		t.Fatalf("unexpected Rotor Size option: %+v", opts[2])
	}
}

func TestM3SFCCDemandwareStructuralAndFailOpen(t *testing.T) {
	sfccHTML := `<!doctype html><html><head>
		<link rel="stylesheet" href="/on/demandware.static/Sites-BikesUS-Site/-/en_US/v1/css/global.css" />
	</head><body>
		<h1 class="product-name" data-pid="FX-3-DISC">FX 3 Disc</h1>
		<div data-url="/on/demandware.store/Sites-BikesUS-Site/en_US/Product-Variation?pid=FX-3-DISC"></div>
		<table class="geometry-table">
			<tr><th>Size</th><th>Stack (mm)</th><th>Reach (mm)</th></tr>
			<tr><td>M</td><td>568</td><td>394</td></tr>
			<tr><td>L</td><td>589</td><td>402</td></tr>
		</table>
	</body></html>`
	// Works on arbitrary host (zero hardcoded brand list!).
	if !IsSFCCDemandwareHTMLOrHeaders(sfccHTML, nil) {
		t.Fatal("expected structural SFCC detection")
	}
	twin := ResolveSFCCProductVariationTwinURL("https://arbitrary-store.example/p/fx-3", sfccHTML)
	if twin == nil || twin.PID != "FX-3-DISC" || twin.VariationURL != "https://arbitrary-store.example/on/demandware.store/Sites-BikesUS-Site/en_US/Product-Variation?pid=FX-3-DISC" {
		t.Fatalf("unexpected SFCC twin: %+v", twin)
	}
	// Cross-origin Product-Variation URL in HTML MUST be rejected (even when data-pid is present).
	evilHTML := `<div data-url="https://evil.example/on/demandware.store/Sites-BikesUS-Site/en_US/Product-Variation?pid=X"></div>`
	if ResolveSFCCProductVariationTwinURL("https://arbitrary-store.example/p/fx-3", evilHTML) != nil {
		t.Fatal("expected cross-origin Product-Variation URL to be rejected")
	}
	evilWithPidHTML := `<div data-pid="FX3" data-url="https://evil.org/on/demandware.store/Sites-Ex-Site/en_US/Product-Variation?pid=FX3"></div>`
	if ResolveSFCCProductVariationTwinURL("https://arbitrary-store.example/p/fx-3", evilWithPidHTML) != nil {
		t.Fatal("expected cross-origin https://evil.org path with data-pid to be rejected")
	}
	httpEvilWithPidHTML := `<div data-pid="FX3" data-url="http://evil.org/on/demandware.store/Sites-Ex-Site/en_US/Product-Variation?pid=FX3"></div>`
	if ResolveSFCCProductVariationTwinURL("https://arbitrary-store.example/p/fx-3", httpEvilWithPidHTML) != nil {
		t.Fatal("expected cross-origin http://evil.org path with data-pid to be rejected")
	}
	mixedHTML := `<div data-url="https://evil.org/on/demandware.store/Sites-Bad-Site/en_US/Product-Variation?pid=BAD"></div><div data-url="/on/demandware.store/Sites-Good-Site/en_US/Product-Variation?pid=GOOD"></div>`
	mixedTwin := ResolveSFCCProductVariationTwinURL("https://arbitrary-store.example/p/fx-3", mixedHTML)
	if mixedTwin == nil || mixedTwin.VariationURL != "https://arbitrary-store.example/on/demandware.store/Sites-Good-Site/en_US/Product-Variation?pid=GOOD" {
		t.Fatalf("expected mixed HTML to skip cross-origin and pick relative same-origin twin, got %+v", mixedTwin)
	}

	varJSON := `{"product":{"id":"FX-3-DISC","productName":"FX 3 Disc","brand":"TrailCo","available":true,"price":{"sales":{"value":999.99,"currency":"USD"}},"variationAttributes":[{"displayName":"Size","values":[{"displayValue":"M","selected":true},{"displayValue":"L","selected":false}]}]}}`
	doc := FormatSFCCProductVariationJSON(varJSON, "https://arbitrary-store.example/p/fx-3", sfccHTML, "")
	if doc == nil || len(doc.Records) != 1 || *doc.Records[0].Variants[0].Price != 999.99 {
		t.Fatalf("unexpected SFCC variation doc: %+v", doc)
	}
	if !strings.Contains(doc.Markdown, "## Geometry") || !strings.Contains(doc.Markdown, "| M | 568 | 394 |") {
		t.Fatalf("expected merged HTML geometry table in markdown:\n%s", doc.Markdown)
	}

	// HTML fail-open when Product-Variation returns 403/404.
	htmlRes := ExtractSFCCProductHTML("https://arbitrary-store.example/p/fx-3", sfccHTML, "", "sfcc-demandware")
	if htmlRes == nil || !strings.Contains(htmlRes.Markdown, "568") {
		t.Fatalf("expected SFCC HTML fallback with geometry table, got %+v", htmlRes)
	}
}

func TestM3Magento2AndShopware6Structural(t *testing.T) {
	magHTML := `<!doctype html><html><body>
		<h1 class="page-title"><span>Magura MT7 Pro</span></h1>
		<div data-role="swatch-options" data-product-id="4242"></div>
		<script type="text/x-magento-init">
		{
			"[data-role=swatch-options]": {
				"Magento_Swatches/js/swatch-renderer": {
					"jsonConfig": {
						"attributes": {
							"93": {"id":"93","code":"color","label":"Color","options":[{"id":"50","label":"Neon Yellow"},{"id":"51","label":"Black"}]}
						},
						"index": {
							"4243": {"93":"50"},
							"4244": {"93":"51"}
						},
						"optionPrices": {
							"4243": {"finalPrice":{"amount":249.00}},
							"4244": {"finalPrice":{"amount":239.00}}
						},
						"sku": {
							"4243": "MT7-NEON",
							"4244": "MT7-BLK"
						}
					}
				}
			}
		}
		</script>
		<table id="product-attribute-specs-table">
			<tr><th>Piston Count</th><td>4 Pistons</td></tr>
			<tr><th>Weight</th><td>255 g</td></tr>
		</table>
	</body></html>`
	magRes := ExtractMagento2ProductHTML("https://oem-shop.example/mt7-pro", magHTML, "", "shopware-magento")
	if magRes == nil || len(magRes.Records) != 1 || len(magRes.Records[0].Variants) != 2 {
		t.Fatalf("expected Magento 2 extraction with 2 variants, got %+v", magRes)
	}
	if *magRes.Records[0].Variants[0].SKU != "MT7-NEON" || *magRes.Records[0].Variants[0].Price != 249.00 {
		t.Fatalf("unexpected Magento 2 variant 0: %+v", magRes.Records[0].Variants[0])
	}
	if !strings.Contains(magRes.Markdown, "4 Pistons") {
		t.Fatalf("missing Magento specs table:\n%s", magRes.Markdown)
	}

	magTwin := ResolveMagento2RenderInfoTwinURL("https://oem-shop.example/mt7-pro", magHTML)
	if !strings.Contains(magTwin, "/rest/V1/products-render-info?") || !strings.Contains(magTwin, "4242") {
		t.Fatalf("unexpected Magento render-info twin URL: %q", magTwin)
	}
	if FormatMagento2RenderInfoJSON(`{"message":"Consumer is not authorized"}`, magTwin, "") != nil {
		t.Fatal("expected 401 Magento error JSON to fail open (nil)")
	}

	swHTML := `<!doctype html><html><body>
		<div class="sw-product-detail">
			<h1 class="product-detail-name">M99 Mini Pro-25</h1>
			<span class="product-detail-ordernumber">SW-M99-25</span>
			<span class="product-detail-price">€299,00</span>
			<div class="product-detail-configurator-group">
				<div class="product-detail-configurator-group-title">Mount</div>
				<label class="product-detail-configurator-option-label">Handlebar 31.8mm</label>
			</div>
			<table class="product-detail-properties-table">
				<tr><th>High Beam</th><td>1150 lm</td></tr>
			</table>
		</div>
	</body></html>`
	swRes := ExtractShopware6ProductHTML("https://eu-oem.example/m99-mini", swHTML, "", "shopware-magento")
	if swRes == nil || len(swRes.Records) != 1 || *swRes.Records[0].Variants[0].SKU != "SW-M99-25" || *swRes.Records[0].Variants[0].Price != 299.00 {
		t.Fatalf("unexpected Shopware 6 extraction: %+v", swRes)
	}
	if !strings.Contains(swRes.Markdown, "1150 lm") {
		t.Fatalf("missing Shopware 6 properties table:\n%s", swRes.Markdown)
	}
}

func TestM3MarkdownLinkInjectionPrevention(t *testing.T) {
	// 1. FormatMarkdownLinkCommerce label escaping (backslashes, brackets, angle brackets) & idempotency.
	l1 := FormatMarkdownLinkCommerce(`Foo\\]`, "https://ex.com/a)[xss](https://evil.com)")
	if strings.Contains(l1, "](https://evil.com)") || l1 != `[Foo\\\]](https://ex.com/a%29%5Bxss%5D%28https://evil.com%29)` {
		t.Fatalf("unexpected FormatMarkdownLinkCommerce output for double backslash: %q", l1)
	}
	l2 := FormatMarkdownLinkCommerce(`Foo\`, "https://ex.com/item")
	if l2 != `[Foo\\](https://ex.com/item)` {
		t.Fatalf("unexpected trailing backslash handling: %q", l2)
	}
	// Idempotency on already-sanitized SanitizeCommerceField output.
	sanitized := SanitizeCommerceField(`Bar [1] \\] <tag>`, 200)
	if got := FormatMarkdownLinkCommerce(sanitized, "https://ex.com/b(1)"); strings.Contains(got, "(1)") {
		t.Fatalf("destination parens not encoded: %q", got)
	}

	// 2. BigCommerce /xmlsitemap.php (<urlset> & <sitemapindex>).
	bcURLSet := `<?xml version="1.0" encoding="UTF-8"?>
	<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9" xmlns:image="http://www.google.com/schemas/sitemap-image/1.1">
		<url>
			<loc>https://bc.example/a)[xss](https://evil.com)</loc>
			<lastmod>2026-04-01</lastmod>
			<image:image><image:loc>https://cdn.example.com/a[imgxss](https://evil.com)</image:loc></image:image>
		</url>
	</urlset>`
	bcSM := FormatBigCommerceXMLSitemap(bcURLSet, "https://bc.example/xmlsitemap.php")
	if bcSM == nil {
		t.Fatal("expected BigCommerce urlset doc")
	}
	if strings.Contains(bcSM.Markdown, "](https://evil.com)") ||
		strings.Contains(bcSM.Markdown, "https://evil.com)") ||
		!strings.Contains(bcSM.Markdown, "%29%5Bxss%5D%28") ||
		!strings.Contains(bcSM.Markdown, "https://cdn.example.com/a%5Bimgxss%5D%28https://evil.com%29") {
		t.Fatalf("BigCommerce urlset link/image injection not neutralized:\n%s", bcSM.Markdown)
	}

	bcIndex := `<?xml version="1.0" encoding="UTF-8"?>
	<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
		<sitemap><loc>https://bc.example/sub)[xss](https://evil.com)</loc><lastmod>2026-04-01</lastmod></sitemap>
	</sitemapindex>`
	bcIdxDoc := FormatBigCommerceXMLSitemap(bcIndex, "https://bc.example/xmlsitemap.php")
	if bcIdxDoc == nil || strings.Contains(bcIdxDoc.Markdown, "](https://evil.com)") || !strings.Contains(bcIdxDoc.Markdown, "%29%5Bxss%5D%28") {
		t.Fatalf("BigCommerce sitemapindex link injection not neutralized: %+v", bcIdxDoc)
	}

	// 3. Squarespace ?format=json-pretty & HTML card.
	sqJSON := `{"items":[{"id":"1","title":"Item","fullUrl":"https://sq.example/shop/p/a)[xss](https://evil.com)","structuredContent":{"variants":[{"id":"v1","sku":"S1","priceMoney":{"value":"10.00","currency":"USD"}}]}}]}`
	sqDoc := FormatSquarespaceCommerceJSON(sqJSON, "https://sq.example/shop")
	if sqDoc == nil || strings.Contains(sqDoc.Markdown, "](https://evil.com)") || !strings.Contains(sqDoc.Markdown, "%29%5Bxss%5D%28") {
		t.Fatalf("Squarespace JSON link injection not neutralized: %+v", sqDoc)
	}
	sqHTML := `<html><head><script>Static.SQUARESPACE_CONTEXT={"productType":1};</script></head><body><div class="ProductList-item"><a href="/p/a)[xss](https://evil.com)"><span class="ProductList-title">Card</span></a><span class="product-price">$10.00</span></div></body></html>`
	sqHTMLRes := ExtractSquarespaceCommerceHTML("https://sq.example/shop", sqHTML, "", "squarespace-commerce")
	if sqHTMLRes == nil || strings.Contains(sqHTMLRes.Markdown, "](https://evil.com)") || !strings.Contains(sqHTMLRes.Markdown, "%29%5Bxss%5D%28") {
		t.Fatalf("Squarespace HTML link injection not neutralized: %+v", sqHTMLRes)
	}

	// 4. WooCommerce Store API list & HTML catalog.
	wooJSON := `[{"id":1,"name":"Woo Bike","slug":"woo","permalink":"https://woo.example/p/a)[xss](https://evil.com)","sku":"W1","prices":{"price":"1000","currency_code":"USD","currency_minor_unit":2},"is_in_stock":true}]`
	wooDoc := FormatWCStoreAPIListTwinWithOptions(wooJSON, "https://woo.example/shop/", "")
	if wooDoc == nil || strings.Contains(wooDoc.Markdown, "](https://evil.com)") || !strings.Contains(wooDoc.Markdown, "%29%5Bxss%5D%28") {
		t.Fatalf("WooCommerce JSON link injection not neutralized: %+v", wooDoc)
	}
	wooHTML := `<html><body class="woocommerce-page"><ul class="products"><li class="product"><a href="/p/a)[xss](https://evil.com)"><h2 class="woocommerce-loop-product__title">Woo Card</h2></a><span class="price">$50.00</span></li></ul></body></html>`
	wooHTMLRes := ExtractWooCommerceCatalogHTML("https://woo.example/shop/", wooHTML, "", "woocommerce")
	if wooHTMLRes == nil || strings.Contains(wooHTMLRes.Markdown, "](https://evil.com)") || !strings.Contains(wooHTMLRes.Markdown, "%29%5Bxss%5D%28") {
		t.Fatalf("WooCommerce HTML link injection not neutralized: %+v", wooHTMLRes)
	}

	// 5. Shopify feed & pagination nextURL.
	shopJSON := `{"products":[{"id":1,"title":"Shop Bike","handle":"a)[xss](https://evil.com)","variants":[{"id":10,"sku":"SH1","price":"10.00","available":true}]}]}`
	shopDoc := FormatShopifyProductsFeedTwin(shopJSON, "https://shop.example/collections/a)[xss](https://evil.com)", ShopifyFeedFormatOptions{
		TwinURL: "https://shop.example/collections/a)[xss](https://evil.com)/products.json?limit=1&page=1",
	})
	if shopDoc == nil || strings.Contains(shopDoc.Markdown, "](https://evil.com)") || !strings.Contains(shopDoc.Markdown, "%29%5Bxss%5D%28") {
		t.Fatalf("Shopify feed/pagination link injection not neutralized: %+v", shopDoc)
	}

	// 6. Magento 2 /rest/V1/products-render-info.
	magJSON := `{"items":[{"id":1,"name":"Mag Item","url":"https://mag.example/a)[xss](https://evil.com)","sku":"M1","currency_code":"USD","price_info":{"final_price":25}}]}`
	magDoc := FormatMagento2RenderInfoJSON(magJSON, "https://mag.example/rest/V1/products-render-info?searchCriteria[pageSize]=1", "")
	if magDoc == nil || strings.Contains(magDoc.Markdown, "](https://evil.com)") || !strings.Contains(magDoc.Markdown, "%29%5Bxss%5D%28") {
		t.Fatalf("Magento 2 render-info link injection not neutralized: %+v", magDoc)
	}
}

func TestM3Iteration4CommerceContracts(t *testing.T) {
	// 1. F02.T2.2: Shopify empty products: [] pre-fetch twin fails open, while direct .json returns empty message.
	emptyTwin := FormatShopifyProductsFeedTwin(
		`{"products":[]}`,
		"https://sh-t2-2.myshopify.com/collections/empty-col",
		ShopifyFeedFormatOptions{TwinURL: "https://sh-t2-2.myshopify.com/collections/empty-col/products.json?limit=50"},
	)
	if emptyTwin != nil {
		t.Fatalf("expected nil (fail-open) for empty collection pre-fetch twin, got %+v", emptyTwin)
	}
	directEmpty := FormatShopifyProductsFeedTwin(
		`{"products":[]}`,
		"https://store.example.com/products.json",
	)
	if directEmpty == nil || !strings.Contains(directEmpty.Markdown, "No products returned on this page.") {
		t.Fatalf("expected direct .json feed to emit empty-page message, got %+v", directEmpty)
	}

	// 2. F10.2: BigCommerce Stencil [data-product-option-change] with plain <label> + Cornerstone nested guard + swatches
	bcOptChangeHTML := `<html><head><script>window.BCData = {"product_attributes":{"sku":"BC-101","price":{"without_tax":{"value":49.99,"currency":"USD"}}}};</script></head><body>
		<h1 class="productView-title">Trailblazer Kit</h1>
		<form data-cart-item-add>
			<div data-product-option-change>
				<label>Rotor Size</label>
				<select name="attribute[101]">
					<option value="1">180mm</option>
					<option value="2">203mm</option>
				</select>
			</div>
		</form>
	</body></html>`
	bcRes := ExtractBigCommerceHTML("https://peakbikes2.example.com/trailblazer/", bcOptChangeHTML, "", "bigcommerce-store")
	if bcRes == nil || len(bcRes.Records) != 1 || len(bcRes.Records[0].Options) != 1 {
		t.Fatalf("expected 1 option from [data-product-option-change], got %+v", bcRes)
	}
	if bcRes.Records[0].Options[0].Name != "Rotor Size" || len(bcRes.Records[0].Options[0].Values) != 2 {
		t.Fatalf("unexpected Rotor Size option: %+v", bcRes.Records[0].Options[0])
	}

	bcNestedCornerstoneHTML := `<html><head><script>window.BCData = {"product_attributes":{"sku":"BC-202","price":{"without_tax":{"value":99.00,"currency":"USD"}}}};</script></head><body>
		<h1 class="productView-title">Cornerstone Bike</h1>
		<form data-cart-item-add>
			<div data-product-option-change>
				<div class="form-field" data-product-attribute="set-select">
					<label class="form-label">Size:</label>
					<select name="attribute[1]"><option value="">Choose</option><option value="10">54cm</option><option value="11">56cm</option></select>
				</div>
				<div class="form-field" data-product-attribute="swatch">
					<label class="form-label">Color:</label>
					<label class="form-option" title="Matte Black"><span></span></label>
					<label class="form-option" title="Signal Red"><span></span></label>
				</div>
			</div>
		</form>
	</body></html>`
	bcNestedRes := ExtractBigCommerceHTML("https://cornerstone.example.com/bike/", bcNestedCornerstoneHTML, "", "bigcommerce-store")
	if bcNestedRes == nil || len(bcNestedRes.Records) != 1 || len(bcNestedRes.Records[0].Options) != 2 {
		t.Fatalf("expected 2 distinct options (no outer wrapper merge), got %+v", bcNestedRes)
	}
	if bcNestedRes.Records[0].Options[0].Name != "Size" || bcNestedRes.Records[0].Options[1].Name != "Color" {
		t.Fatalf("unexpected Cornerstone options: %+v", bcNestedRes.Records[0].Options)
	}
	if len(bcNestedRes.Records[0].Options[1].Values) != 2 || bcNestedRes.Records[0].Options[1].Values[0] != "Matte Black" {
		t.Fatalf("expected swatch title fallback, got %+v", bcNestedRes.Records[0].Options[1].Values)
	}

	// 3. F11.4 & F11.T2.4: SFCC availability.inStock / ats / messages
	sfccInStock := FormatSFCCProductVariationJSON(
		`{"product":{"id":"44751-54-BLK","productName":"Domane SL 6","price":{"sales":{"value":4699.99,"currency":"USD"}},"availability":{"inStock":true,"ats":7,"messages":["In Stock"]}}}`,
		"https://bikes3.example.com/on/demandware.store/Sites-Bike-Site/en_US/Product-Variation?pid=44751-54-BLK",
		"",
		"",
	)
	if sfccInStock == nil || len(sfccInStock.Records) != 1 || sfccInStock.Records[0].Variants[0].Available == nil || !*sfccInStock.Records[0].Variants[0].Available {
		t.Fatalf("expected SFCC inStock=true, got %+v", sfccInStock)
	}
	sfccOOS := FormatSFCCProductVariationJSON(
		`{"product":{"id":"SF-0","productName":"Domane SL","price":{"sales":{"value":3499.99,"currency":"USD"}},"availability":{"inStock":false,"ats":0}}}`,
		"https://bikes3.example.com/on/demandware.store/Sites-Bike-Site/en_US/Product-Variation?pid=SF-0",
		"",
		"",
	)
	if sfccOOS == nil || len(sfccOOS.Records) != 1 || sfccOOS.Records[0].Variants[0].Available == nil || *sfccOOS.Records[0].Variants[0].Available {
		t.Fatalf("expected SFCC inStock=false, got %+v", sfccOOS)
	}
	sfccMsgNeg := FormatSFCCProductVariationJSON(
		`{"product":{"id":"SF-1","productName":"Domane AL","price":{"sales":{"value":1999.99,"currency":"USD"}},"availability":{"messages":["Not in stock"]}}}`,
		"https://bikes3.example.com/on/demandware.store/Sites-Bike-Site/en_US/Product-Variation?pid=SF-1",
		"",
		"",
	)
	if sfccMsgNeg == nil || sfccMsgNeg.Records[0].Variants[0].Available == nil || *sfccMsgNeg.Records[0].Variants[0].Available {
		t.Fatalf("expected SFCC 'Not in stock' message -> false, got %+v", sfccMsgNeg)
	}

	// 4. F12.1, F12.2, F12.T2.2: Magento 2 index-less options[].products[] + currencyFormat + ResolveMagento2RenderInfoTwinURL fallback
	magIndexlessHTML := `<html><body>
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
							"2001": {"finalPrice": {"amount": 269.00}},
							"2002": {"finalPrice": {"amount": 289.00}}
						},
						"currencyFormat": "$%s"
					}
				}
			}
		}
		</script>
	</body></html>`
	magRes := ExtractMagento2ProductHTML("https://parts1.example.com/magura-mt7-pro.html", magIndexlessHTML, "", "shopware-magento")
	if magRes == nil || len(magRes.Records) != 1 || len(magRes.Records[0].Variants) != 2 {
		t.Fatalf("expected 2 synthesized variants from index-less jsonConfig, got %+v", magRes)
	}
	v0, v1 := magRes.Records[0].Variants[0], magRes.Records[0].Variants[1]
	if v0.SKU == nil || *v0.SKU != "MAG-MT7-180" || v0.Price == nil || *v0.Price != 269.0 || v0.Currency == nil || *v0.Currency != "USD" {
		t.Fatalf("unexpected variant 0: %+v", v0)
	}
	if v1.SKU == nil || *v1.SKU != "MAG-MT7-203" || v1.Price == nil || *v1.Price != 289.0 {
		t.Fatalf("unexpected variant 1: %+v", v1)
	}
	if !strings.Contains(magRes.Markdown, "MAG-MT7-180") || !strings.Contains(magRes.Markdown, "MAG-MT7-203") {
		t.Fatalf("expected variant SKUs in markdown:\n%s", magRes.Markdown)
	}
	twinURL := ResolveMagento2RenderInfoTwinURL("https://parts1.example.com/magura-mt7-pro.html", magIndexlessHTML)
	if !strings.Contains(twinURL, "value]=2001") {
		t.Fatalf("expected ResolveMagento2RenderInfoTwinURL fallback to child ID 2001, got %q", twinURL)
	}
}

func TestM3Iteration6BigCommerceAndShopwareHardening(t *testing.T) {
	// 1. BigCommerce & Shopware 6 raw description slicing: neutralize entity-encoded [xss](evil.com)
	// and preserve semicolonless query parameters (&currentTime=45&section=2&region=us).
	bcRawHTML := `<!doctype html><html><head><script src="https://cdn11.bigcommerce.com/s-abc/stencil.js"></script></head><body>
		<h1 class="productView-title">E-Bike Rotor</h1>
		<form data-cart-item-add><input type="hidden" name="product_id" value="77" /></form>
		<div id="tab-description">
			<p>Part &#91;xss&#93;(https://evil.com)</p>
			<!-- </div> fake close inside comment -->
			<h3>&lsqb;xss&rsqb;&lpar;https://evil.com&rpar;</h3>
			<table><tr><th>Spec</th></tr><tr><td>&#91;xss&#93;(https://evil.com)</td></tr></table>
			<p><a href="https://example.com/watch?v=1&currentTime=45&section=2&region=us">Video</a></p>
		</div>
	</body></html>`
	bcRes := ExtractBigCommerceHTML("https://shop.example.com/rotor/", bcRawHTML, "", "bigcommerce-store")
	if bcRes == nil {
		t.Fatal("expected BigCommerce result")
	}
	if strings.Contains(bcRes.Markdown, "[xss](https://evil.com)") || !strings.Contains(bcRes.Markdown, `\[xss\](https://evil.com)`) {
		t.Fatalf("BigCommerce description failed to neutralize entity-encoded link:\n%s", bcRes.Markdown)
	}
	if !strings.Contains(bcRes.Markdown, "https://example.com/watch?v=1&currentTime=45&section=2&region=us") {
		t.Fatalf("BigCommerce corrupted semicolonless query params:\n%s", bcRes.Markdown)
	}

	swRawHTML := `<!doctype html><html><body>
		<div class="sw-product-detail">
			<h1 class="product-detail-name">MT7 Brake</h1>
			<span class="product-detail-price">€269.00</span>
			<div class="product-detail-description-text">
				<p>Part &#91;xss&#93;(https://evil.com)</p>
				<p><a href="https://example.com/watch?v=1&currentTime=45&section=2&region=us">Video</a></p>
			</div>
		</div>
	</body></html>`
	swRes := ExtractShopware6ProductHTML("https://sw.example.com/mt7", swRawHTML, "", "shopware-magento")
	if swRes == nil {
		t.Fatal("expected Shopware 6 result")
	}
	if strings.Contains(swRes.Markdown, "[xss](https://evil.com)") || !strings.Contains(swRes.Markdown, `\[xss\](https://evil.com)`) {
		t.Fatalf("Shopware 6 description failed to neutralize entity-encoded link:\n%s", swRes.Markdown)
	}
	if !strings.Contains(swRes.Markdown, "https://example.com/watch?v=1&currentTime=45&section=2&region=us") {
		t.Fatalf("Shopware 6 corrupted semicolonless query params:\n%s", swRes.Markdown)
	}

	// 2. BigCommerce <fieldset><legend> edge cases:
	// (a) plain <fieldset> without .form-field / data-product-attribute
	bcPlainFS := `<html><head><script src="https://cdn11.bigcommerce.com/s-abc/stencil.js"></script></head><body>
		<h1 class="productView-title">Adapter</h1>
		<form data-cart-item-add>
			<fieldset><legend>Mount Type</legend>
				<input type="radio" id="m1" name="m"><label for="m1">Direct Mount</label>
				<input type="radio" id="m2" name="m"><label for="m2">Post Mount</label>
			</fieldset>
		</form>
	</body></html>`
	rPlain := ExtractBigCommerceHTML("https://bc.example.com/adapter", bcPlainFS, "", "bigcommerce-store")
	if rPlain == nil || len(rPlain.Records[0].Options) != 1 || rPlain.Records[0].Options[0].Name != "Mount Type" || len(rPlain.Records[0].Options[0].Values) != 2 {
		t.Fatalf("plain <fieldset> options failed: %+v", rPlain)
	}

	// (b) two <fieldset>s inside [data-product-option-change] without .form-field
	bcTwoFS := `<html><head><script src="https://cdn11.bigcommerce.com/s-abc/stencil.js"></script></head><body>
		<h1 class="productView-title">Adapter</h1>
		<form data-cart-item-add>
			<div data-product-option-change>
				<fieldset><legend>Mount Type</legend>
					<input type="radio" id="m1" name="m"><label for="m1">Direct Mount</label>
					<input type="radio" id="m2" name="m"><label for="m2">Post Mount</label>
				</fieldset>
				<fieldset><legend>Finish</legend>
					<input type="radio" id="f1" name="f"><label for="f1">Matte Black</label>
					<input type="radio" id="f2" name="f"><label for="f2">Silver</label>
				</fieldset>
			</div>
		</form>
	</body></html>`
	rTwo := ExtractBigCommerceHTML("https://bc.example.com/adapter2", bcTwoFS, "", "bigcommerce-store")
	if rTwo == nil || len(rTwo.Records[0].Options) != 2 || rTwo.Records[0].Options[0].Name != "Mount Type" || rTwo.Records[0].Options[1].Name != "Finish" {
		t.Fatalf("two <fieldset>s under [data-product-option-change] failed: %+v", rTwo)
	}

	// (c) radio without id + <label class="form-label"> without for inside <fieldset><legend>
	bcNoIDRadio := `<html><head><script src="https://cdn11.bigcommerce.com/s-abc/stencil.js"></script></head><body>
		<h1 class="productView-title">Adapter</h1>
		<form data-cart-item-add>
			<fieldset class="form-field"><legend>Finish</legend>
				<input type="radio" name="f" data-label="Matte Black"><label class="form-label">Matte Black</label>
				<input type="radio" name="f" data-label="Silver"><label class="form-label">Silver</label>
			</fieldset>
		</form>
	</body></html>`
	rNoID := ExtractBigCommerceHTML("https://bc.example.com/adapter3", bcNoIDRadio, "", "bigcommerce-store")
	if rNoID == nil || len(rNoID.Records[0].Options) != 1 || rNoID.Records[0].Options[0].Name != "Finish" || len(rNoID.Records[0].Options[0].Values) != 2 {
		t.Fatalf("id-less radio with form-label failed: %+v", rNoID)
	}
}

func TestM3Iteration8UnbalancedContainersAndRadioPromptLabel(t *testing.T) {
	// 1. BigCommerce unbalanced inner <div> inside #tab-description and .productView-description:
	// must NOT fall back to x/net/html dNode.HTML() (which decodes &#91;/&lsqb; and &currentTime/&section/&region).
	bcUnbalTab := `<!doctype html><html><head><script src="https://cdn11.bigcommerce.com/s-abc/stencil.js"></script></head><body>
		<h1 class="productView-title">Unbalanced Div Test</h1>
		<form data-cart-item-add><input type="hidden" name="product_id" value="101" /></form>
		<div id="tab-description"><p>Safe text &#91;xss&#93;&#40;https://evil.com&#41; and &lsqb;xss2&rsqb;&lpar;https://evil.com&rpar;</p><div><span>Unbalanced inner div<p><a href="https://videos.example/watch?v=1&currentTime=45&section=2&region=us">WatchVideo</a></p></div>
		<footer>BigCommerce Site Footer</footer>
	</body></html>`
	bcRes := ExtractBigCommerceHTML("https://bc.example.com/unbalanced", bcUnbalTab, "", "bigcommerce-store")
	if bcRes == nil || len(bcRes.Records) != 1 || bcRes.Records[0].DescriptionText == nil {
		t.Fatalf("expected BigCommerce extraction on unbalanced #tab-description, got %+v", bcRes)
	}
	bcDesc := *bcRes.Records[0].DescriptionText
	for _, label := range []struct {
		name string
		text string
	}{{"markdown", bcRes.Markdown}, {"records[0].descriptionText", bcDesc}} {
		if strings.Contains(label.text, "[xss](https://evil.com)") || strings.Contains(label.text, "[xss2](https://evil.com)") {
			t.Fatalf("BigCommerce %s emitted active evil.com link:\n%s", label.name, label.text)
		}
		if !strings.Contains(label.text, "https://videos.example/watch?v=1&currentTime=45&section=2&region=us") {
			t.Fatalf("BigCommerce %s corrupted semicolonless query params:\n%s", label.name, label.text)
		}
		if strings.Contains(label.text, "BigCommerce Site Footer") {
			t.Fatalf("BigCommerce %s leaked past <footer> boundary:\n%s", label.name, label.text)
		}
	}

	// Also verify .productView-description unbalanced fallback.
	bcUnbalView := `<!doctype html><html><head><script src="https://cdn11.bigcommerce.com/s-abc/stencil.js"></script></head><body>
		<div class="productView">
			<h1 class="productView-title">Unbalanced View Test</h1>
			<div class="productView-description"><p>Safe &#91;xss&#93;&#40;https://evil.com&#41; and &lsqb;xss2&rsqb;&lpar;https://evil.com&rpar;</p><div><span>Unbalanced<a href="https://videos.example/watch?v=1&currentTime=45&section=2&region=us">Watch</a></div>
		</div>
	</body></html>`
	bcViewRes := ExtractBigCommerceHTML("https://bc.example.com/unbalanced-view", bcUnbalView, "", "bigcommerce-store")
	if bcViewRes == nil || len(bcViewRes.Records) != 1 || bcViewRes.Records[0].DescriptionText == nil {
		t.Fatalf("expected BigCommerce extraction on unbalanced .productView-description, got %+v", bcViewRes)
	}
	if strings.Contains(bcViewRes.Markdown, "[xss](https://evil.com)") || strings.Contains(*bcViewRes.Records[0].DescriptionText, "[xss2](https://evil.com)") ||
		!strings.Contains(*bcViewRes.Records[0].DescriptionText, "&currentTime=45&section=2&region=us") {
		t.Fatalf("BigCommerce .productView-description unbalanced fallback failed:\nmd=%s\ndesc=%s", bcViewRes.Markdown, *bcViewRes.Records[0].DescriptionText)
	}

	// 2. Shopware 6 unbalanced inner <div> inside .product-detail-description-text:
	swUnbal := `<!doctype html><html><body>
		<main class="sw-product-detail">
			<h1 class="product-detail-name">SW6 Real Unbalanced</h1>
			<span class="product-detail-price">€199.00</span>
			<div class="product-detail-description-text"><p>Safe text &#91;xss&#93;&#40;https://evil.com&#41; and &lsqb;xss2&rsqb;&lpar;https://evil.com&rpar;</p><div><span>Unbalanced inner div<p><a href="https://videos.example/watch?v=1&currentTime=45&section=2&region=us">WatchVideo</a></p></div>
		</main>
		<footer>SW6 Footer Chrome</footer>
	</body></html>`
	swRes := ExtractShopware6ProductHTML("https://sw.example.com/unbalanced", swUnbal, "", "shopware-magento")
	if swRes == nil || len(swRes.Records) != 1 || swRes.Records[0].DescriptionText == nil {
		t.Fatalf("expected Shopware 6 extraction on unbalanced container, got %+v", swRes)
	}
	swDesc := *swRes.Records[0].DescriptionText
	for _, label := range []struct {
		name string
		text string
	}{{"markdown", swRes.Markdown}, {"records[0].descriptionText", swDesc}} {
		if strings.Contains(label.text, "[xss](https://evil.com)") || strings.Contains(label.text, "[xss2](https://evil.com)") {
			t.Fatalf("Shopware 6 %s emitted active evil.com link:\n%s", label.name, label.text)
		}
		if !strings.Contains(label.text, "https://videos.example/watch?v=1&currentTime=45&section=2&region=us") {
			t.Fatalf("Shopware 6 %s corrupted semicolonless query params:\n%s", label.name, label.text)
		}
		if strings.Contains(label.text, "SW6 Footer Chrome") {
			t.Fatalf("Shopware 6 %s leaked past </main> boundary:\n%s", label.name, label.text)
		}
	}

	// 3. BigCommerce id-less radio <fieldset><legend> with leading prompt <label class="form-label">Select finish:</label>
	// plus preservation of Cornerstone swatches, <label>-wrapped radios, for/id, data-label, and <select>.
	bcPromptRadio := `<!doctype html><html><head><script src="https://cdn11.bigcommerce.com/s-abc/stencil.js"></script></head><body>
		<h1 class="productView-title">Stem</h1>
		<form data-cart-item-add>
			<fieldset class="form-field">
				<legend>Finish</legend>
				<label class="form-label">Select finish:</label>
				<input type="radio" name="attr[2]" value="10"><label class="form-label">Matte Black</label>
				<input type="radio" name="attr[2]" value="11"><label class="form-label">Raw Silver</label>
			</fieldset>
			<fieldset class="form-field">
				<legend>Clamp</legend>
				<label class="form-label">Choose clamp:</label>
				<label><input type="radio" name="attr[3]" value="20"> 31.8mm</label>
				<label><input type="radio" name="attr[3]" value="21"> 35.0mm</label>
			</fieldset>
			<div class="form-field" data-product-attribute="swatch">
				<label class="form-label">Bolt Color:</label>
				<label class="form-option"><span title="Titanium"></span></label>
				<label class="form-option"><span title="Black"></span></label>
			</div>
		</form>
	</body></html>`
	promptRes := ExtractBigCommerceHTML("https://bc.example.com/stem", bcPromptRadio, "", "bigcommerce-store")
	if promptRes == nil || len(promptRes.Records) != 1 || len(promptRes.Records[0].Options) != 3 {
		t.Fatalf("expected 3 BigCommerce options, got %+v", promptRes)
	}
	o0 := promptRes.Records[0].Options[0]
	if o0.Name != "Finish" || len(o0.Values) != 2 || o0.Values[0] != "Matte Black" || o0.Values[1] != "Raw Silver" {
		t.Fatalf("id-less radio leaked prompt label or dropped options: %+v", o0)
	}
	o1 := promptRes.Records[0].Options[1]
	if o1.Name != "Clamp" || len(o1.Values) != 2 || o1.Values[0] != "31.8mm" || o1.Values[1] != "35.0mm" {
		t.Fatalf("<label>-wrapped radio failed: %+v", o1)
	}
	o2 := promptRes.Records[0].Options[2]
	if o2.Name != "Bolt Color" || len(o2.Values) != 2 || o2.Values[0] != "Titanium" || o2.Values[1] != "Black" {
		t.Fatalf("Cornerstone label.form-option > span[title] failed: %+v", o2)
	}
}

func TestM3Iteration9BigCommerceMixedForAndIDLessRadios(t *testing.T) {
	// Probe 4.1f: mixed for-linked + id-less radio inside the same <fieldset><legend>
	// with leading prompt <label class="form-label">Select finish:</label>.
	bcMixedHTML := `<!doctype html><html><head><script src="https://cdn11.bigcommerce.com/s-abc/stencil.js"></script></head><body>
		<h1 class="productView-title">Mixed Radio Stem</h1>
		<form data-cart-item-add>
			<fieldset class="form-field">
				<legend>Finish</legend>
				<label class="form-label">Select finish:</label>
				<input type="radio" id="fin-1" name="attr[2]" value="10"><label class="form-label" for="fin-1">Matte Black</label>
				<input type="radio" name="attr[2]" value="11"><label class="form-label">Raw Silver</label>
				<label class="form-label">Trailing Note</label>
			</fieldset>
			<fieldset class="form-field">
				<legend>Size</legend>
				<label class="form-label">Select size:</label>
				<input type="radio" name="attr[3]" value="20"><label class="form-label">90mm</label>
				<input type="radio" id="sz-2" name="attr[3]" value="21"><label class="form-label" for="sz-2">100mm</label>
			</fieldset>
		</form>
	</body></html>`
	res := ExtractBigCommerceHTML("https://bc.example.com/mixed-stem", bcMixedHTML, "", "bigcommerce-store")
	if res == nil || len(res.Records) != 1 || len(res.Records[0].Options) != 2 {
		t.Fatalf("expected 2 BigCommerce options for mixed radios, got %+v", res)
	}
	oFinish := res.Records[0].Options[0]
	if oFinish.Name != "Finish" || len(oFinish.Values) != 2 || oFinish.Values[0] != "Matte Black" || oFinish.Values[1] != "Raw Silver" {
		t.Fatalf("mixed for-linked + id-less Finish failed: %+v", oFinish)
	}
	oSize := res.Records[0].Options[1]
	if oSize.Name != "Size" || len(oSize.Values) != 2 {
		t.Fatalf("mixed id-less + for-linked Size failed: %+v", oSize)
	}
	has90 := false
	has100 := false
	for _, v := range oSize.Values {
		if v == "90mm" {
			has90 = true
		}
		if v == "100mm" {
			has100 = true
		}
	}
	if !has90 || !has100 {
		t.Fatalf("mixed id-less + for-linked Size missing values: %+v", oSize)
	}
}

func TestM3Iteration10BigCommerceNodeKeyMixedRadios(t *testing.T) {
	assertExactValues := func(t *testing.T, label string, got []string, want []string) {
		t.Helper()
		if len(got) != len(want) {
			t.Fatalf("%s: expected %v (len %d), got %v (len %d)", label, want, len(want), got, len(got))
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("%s: index %d expected %q, got %q (full=%v)", label, i, want[i], got[i], got)
			}
		}
	}

	// BC-1 / 4.1f-2: id-less first + for-linked second + leading prompt + trailing note
	bc1HTML := `<!doctype html><html><head><script src="https://cdn11.bigcommerce.com/s-abc/stencil.js"></script></head><body>
		<h1 class="productView-title">BC-1 Stem</h1>
		<form data-cart-item-add>
			<fieldset class="form-field">
				<legend>Size</legend>
				<label class="form-label">Select size:</label>
				<input type="radio" name="attr[3]" value="20"><label class="form-label">90mm</label>
				<input type="radio" id="sz-2" name="attr[3]" value="21"><label class="form-label" for="sz-2">100mm</label>
				<label class="form-label">Trailing Note</label>
			</fieldset>
		</form>
	</body></html>`
	res1 := ExtractBigCommerceHTML("https://bc.example.com/bc1", bc1HTML, "", "bigcommerce-store")
	if res1 == nil || len(res1.Records) != 1 || len(res1.Records[0].Options) != 1 {
		t.Fatalf("BC-1: expected 1 option, got %+v", res1)
	}
	assertExactValues(t, "BC-1", res1.Records[0].Options[0].Values, []string{"100mm", "90mm"})

	// BC-2 / 4.1f-3: <label>-wrapped + Helper Note + for-linked + id-less + data-label + Trailing Note
	bc2HTML := `<!doctype html><html><head><script src="https://cdn11.bigcommerce.com/s-abc/stencil.js"></script></head><body>
		<h1 class="productView-title">BC-2 Stem</h1>
		<form data-cart-item-add>
			<fieldset class="form-field">
				<legend>Finish</legend>
				<label class="form-label">Select finish:</label>
				<label class="form-label"><input type="radio" name="attr[2]" value="1">Wrapped Gold</label>
				<label class="form-label">Helper Note</label>
				<input type="radio" id="fin-1" name="attr[2]" value="2"><label class="form-label" for="fin-1">Matte Black</label>
				<input type="radio" name="attr[2]" value="3"><label class="form-label">Raw Silver</label>
				<input type="radio" name="attr[2]" value="4" data-label="Anodized Blue">
				<label class="form-label">Trailing Note</label>
			</fieldset>
		</form>
	</body></html>`
	res2 := ExtractBigCommerceHTML("https://bc.example.com/bc2", bc2HTML, "", "bigcommerce-store")
	if res2 == nil || len(res2.Records) != 1 || len(res2.Records[0].Options) != 1 {
		t.Fatalf("BC-2: expected 1 option, got %+v", res2)
	}
	assertExactValues(t, "BC-2", res2.Records[0].Options[0].Values, []string{"Wrapped Gold", "Matte Black", "Anodized Blue", "Raw Silver"})

	// BC-3 / 4.1f-4: (a) id-less + data-label + trailing note; (b) id-less + <label>-wrapped + trailing note
	bc3HTML := `<!doctype html><html><head><script src="https://cdn11.bigcommerce.com/s-abc/stencil.js"></script></head><body>
		<h1 class="productView-title">BC-3 Stem</h1>
		<form data-cart-item-add>
			<fieldset class="form-field">
				<legend>Finish</legend>
				<label class="form-label">Select finish:</label>
				<input type="radio" name="attr[2]" value="11"><label class="form-label">Matte Black</label>
				<input type="radio" name="attr[2]" value="12" data-label="Raw Silver">
				<label class="form-label">Trailing Note</label>
			</fieldset>
			<fieldset class="form-field">
				<legend>Edition</legend>
				<label class="form-label">Select edition:</label>
				<input type="radio" name="attr[4]" value="31"><label class="form-label">Raw Silver</label>
				<label class="form-label"><input type="radio" name="attr[4]" value="32">Wrapped Gold</label>
				<label class="form-label">Trailing Note</label>
			</fieldset>
		</form>
	</body></html>`
	res3 := ExtractBigCommerceHTML("https://bc.example.com/bc3", bc3HTML, "", "bigcommerce-store")
	if res3 == nil || len(res3.Records) != 1 || len(res3.Records[0].Options) != 2 {
		t.Fatalf("BC-3: expected 2 options, got %+v", res3)
	}
	assertExactValues(t, "BC-3a", res3.Records[0].Options[0].Values, []string{"Raw Silver", "Matte Black"})
	assertExactValues(t, "BC-3b", res3.Records[0].Options[1].Values, []string{"Wrapped Gold", "Raw Silver"})

	// Unlabeled id-less radio followed by <label>-wrapped radio (wrapping label must not be stolen,
	// even if a subsequent empty-text wrapped label or non-empty wrapped label follows).
	bcUnlabeledBeforeWrapped := `<!doctype html><html><head><script src="https://cdn11.bigcommerce.com/s-abc/stencil.js"></script></head><body>
		<h1 class="productView-title">Unlabeled First</h1>
		<form data-cart-item-add>
			<fieldset class="form-field">
				<legend>Clamp</legend>
				<input type="radio" name="attr[5]" value="1">
				<label class="form-label"><input type="radio" name="attr[5]" value="2">Wrapped 31.8mm</label>
				<label class="form-label"><input type="radio" name="attr[5]" value="3"></label>
				<label class="form-label">Trailing Note</label>
			</fieldset>
		</form>
	</body></html>`
	res4 := ExtractBigCommerceHTML("https://bc.example.com/bc4", bcUnlabeledBeforeWrapped, "", "bigcommerce-store")
	if res4 == nil || len(res4.Records) != 1 || len(res4.Records[0].Options) != 1 {
		t.Fatalf("BC-unlabeled-before-wrapped: expected 1 option, got %+v", res4)
	}
	assertExactValues(t, "BC-unlabeled-before-wrapped", res4.Records[0].Options[0].Values, []string{"Wrapped 31.8mm"})
}
