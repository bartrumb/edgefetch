package extract

import (
	"fmt"
	"testing"
)

// Shopify-style JSON-LD publishes `sku` only on the Offer; ExtractStructuredProduct must fall back to it.
func TestExtractStructuredProductSkuFallsBackToPrimaryOffer(t *testing.T) {
	html := `<!doctype html><html><head><script type="application/ld+json">{
		"@context": "https://schema.org",
		"@type": "Product",
		"name": "Summit Hat",
		"offers": [
			{"@type": "Offer", "sku": "TCM1234-TIMBER", "price": "38.00", "priceCurrency": "USD", "availability": "https://schema.org/InStock"},
			{"@type": "Offer", "sku": "TCM1234-OTHER", "price": "40.00", "priceCurrency": "USD"}
		]
	}</script></head><body><h1>Summit Hat</h1></body></html>`
	product := ExtractStructuredProduct(html, "https://shop.example.com/products/summit-hat", "", "")
	if product == nil {
		t.Fatal("expected a structured product from Product JSON-LD")
	}
	if got, _ := product["sku"].(string); got != "TCM1234-TIMBER" {
		t.Fatalf("expected sku from the primary offer, got %#v", product["sku"])
	}

	// A Product-level sku still wins over the offer sku.
	htmlProductSku := `<script type="application/ld+json">{"@type":"Product","name":"Cap","sku":"PRODUCT-SKU",` +
		`"offers":{"@type":"Offer","sku":"OFFER-SKU","price":"10.00","priceCurrency":"USD"}}</script>`
	product = ExtractStructuredProduct(htmlProductSku, "https://shop.example.com/products/cap", "", "")
	if product == nil {
		t.Fatal("expected a structured product")
	}
	if got, _ := product["sku"].(string); got != "PRODUCT-SKU" {
		t.Fatalf("expected Product-level sku to take precedence, got %#v", product["sku"])
	}
}

func TestExtractStructuredProductRelativeURLAndSafety(t *testing.T) {
	finalURL := "https://shop.example.com/cat/index.html"
	cases := []struct {
		name     string
		ldURL    string
		finalURL string
		want     string
	}{
		{name: "root relative path", ldURL: "/products/summit-hat", finalURL: finalURL, want: "https://shop.example.com/products/summit-hat"},
		{name: "dot relative with query", ldURL: "./hat?v=2", finalURL: finalURL, want: "https://shop.example.com/cat/hat?v=2"},
		{name: "fragment", ldURL: "#specs", finalURL: finalURL, want: "https://shop.example.com/cat/index.html#specs"},
		{name: "sibling file", ldURL: "hat.html", finalURL: finalURL, want: "https://shop.example.com/cat/hat.html"},
		{name: "protocol-relative public", ldURL: "//cdn.example.com/p/1", finalURL: finalURL, want: "https://cdn.example.com/p/1"},
		{name: "protocol-relative triple slash rejected", ldURL: "///evil", finalURL: finalURL, want: finalURL},
		{name: "protocol-relative loopback rejected", ldURL: "//127.0.0.1/pwn", finalURL: finalURL, want: finalURL},
		{name: "javascript rejected", ldURL: "javascript:alert(1)", finalURL: finalURL, want: finalURL},
		{name: "obfuscated javascript rejected", ldURL: "java&#x09;script:alert(1)", finalURL: finalURL, want: finalURL},
		{name: "data rejected", ldURL: "data:text/html,<script>", finalURL: finalURL, want: finalURL},
		{name: "vbscript rejected", ldURL: "vbscript:msgbox(1)", finalURL: finalURL, want: finalURL},
		{name: "file rejected", ldURL: "file:///etc/passwd", finalURL: finalURL, want: finalURL},
		{name: "mailto rejected", ldURL: "mailto:a@b.com", finalURL: finalURL, want: finalURL},
		{name: "loopback rejected", ldURL: "http://127.0.0.1/pwn", finalURL: finalURL, want: finalURL},
		{name: "localhost rejected", ldURL: "http://localhost/pwn", finalURL: finalURL, want: finalURL},
		{name: "blank rejected", ldURL: "   ", finalURL: finalURL, want: finalURL},
		{name: "empty finalURL with relative", ldURL: "/p/1", finalURL: "", want: ""},
		{name: "empty finalURL with absolute", ldURL: "https://shop.example.com/p/1", finalURL: "", want: "https://shop.example.com/p/1"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			html := `<script type="application/ld+json">{"@type":"Product","name":"Item","url":` +
				`"` + tc.ldURL + `","offers":{"@type":"Offer","price":"10.00","priceCurrency":"USD"}}</script>`
			prod := ExtractStructuredProduct(html, tc.finalURL, "", "")
			if prod == nil {
				t.Fatalf("expected product for case %q", tc.name)
			}
			if got, _ := prod["url"].(string); got != tc.want {
				t.Fatalf("url mismatch: got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestExtractStructuredProductEuropeanPricesAndGtinMpn(t *testing.T) {
	html := `<script type="application/ld+json">{
		"@type":"Product",
		"name":"Supernova M99",
		"mpn":"M99-PRO-2",
		"gtin12":"012345678905",
		"offers":[
			{"@type":"Offer","price":"1.299,00 €","availability":"InStock"},
			{"@type":"Offer","price":"€199,99","priceCurrency":"EUR"}
		]
	}</script>`
	prod := ExtractStructuredProduct(html, "https://shop.example.eu/m99", "", "")
	if prod == nil {
		t.Fatal("expected product")
	}
	if prod["price"] != float64(1299) {
		t.Fatalf("expected 1299, got %#v", prod["price"])
	}
	if prod["currency"] != "EUR" {
		t.Fatalf("expected EUR inferred from €, got %#v", prod["currency"])
	}
	if prod["gtin"] != "012345678905" {
		t.Fatalf("expected gtin12, got %#v", prod["gtin"])
	}
	if prod["mpn"] != "M99-PRO-2" {
		t.Fatalf("expected mpn, got %#v", prod["mpn"])
	}
	variants, _ := prod["variants"].([]map[string]any)
	if len(variants) != 2 || variants[1]["price"] != 199.99 {
		t.Fatalf("expected second variant price 199.99, got %#v", prod["variants"])
	}
}

func TestExtractStructuredProductMicrodataAndScopeIsolation(t *testing.T) {
	html := `<!doctype html><html><body>
	<div itemscope itemtype="https://schema.org/Product">
		<a itemprop="url" href="/items/g510">Link</a>
		<h1 itemprop="name">Bafang M620 Drive</h1>
		<a itemprop="brand" href="/brands/bafang">Bafang</a>
		<div itemprop="manufacturer" itemscope itemtype="https://schema.org/Organization">
			<span itemprop="name">DoNotOverwriteProductName</span>
		</div>
		<span itemprop="sku">BF-M620</span>
		<img itemprop="image" src="/img/m620.jpg" />
		<div itemprop="aggregateRating" itemscope itemtype="https://schema.org/AggregateRating">
			<span itemprop="ratingValue">4.8</span>
			<span itemprop="reviewCount">19</span>
		</div>
		<div itemprop="offers" itemscope itemtype="https://schema.org/Offer">
			<meta itemprop="name" content="48V Version" />
			<span itemprop="sku">BF-M620-48</span>
			<meta itemprop="price" content="649.50" />
			<meta itemprop="priceCurrency" content="USD" />
			<link itemprop="availability" href="https://schema.org/InStock" />
		</div>
		<div itemprop="offers" itemscope itemtype="https://schema.org/Offer">
			<meta itemprop="name" content="52V Version" />
			<span itemprop="sku">BF-M620-52</span>
			<span>$699.00</span>
			<meta itemprop="price" content="699.00" />
			<meta itemprop="priceCurrency" content="USD" />
		</div>
	</div>
	</body></html>`
	prod := ExtractStructuredProduct(html, "https://oem.example.com/catalog/m620", "", "")
	if prod == nil {
		t.Fatal("expected microdata product")
	}
	if prod["title"] != "Bafang M620 Drive" {
		t.Fatalf("title polluted or missing: %#v", prod["title"])
	}
	if prod["url"] != "https://oem.example.com/items/g510" {
		t.Fatalf("expected resolved microdata url, got %#v", prod["url"])
	}
	if prod["brand"] != "Bafang" {
		t.Fatalf("expected text-over-href brand 'Bafang', got %#v", prod["brand"])
	}
	if prod["sku"] != "BF-M620" {
		t.Fatalf("expected sku BF-M620, got %#v", prod["sku"])
	}
	if prod["price"] != 649.5 {
		t.Fatalf("expected price 649.5, got %#v", prod["price"])
	}
	if prod["currency"] != "USD" {
		t.Fatalf("expected USD, got %#v", prod["currency"])
	}
	if prod["availability"] != "InStock" {
		t.Fatalf("expected InStock, got %#v", prod["availability"])
	}
	if prod["rating"] != 4.8 || prod["reviewCount"] != float64(19) {
		t.Fatalf("unexpected rating/reviewCount: %#v / %#v", prod["rating"], prod["reviewCount"])
	}
	imgs, _ := prod["images"].([]string)
	if len(imgs) != 1 || imgs[0] != "https://oem.example.com/img/m620.jpg" {
		t.Fatalf("unexpected images: %#v", prod["images"])
	}
	variants, _ := prod["variants"].([]map[string]any)
	if len(variants) != 2 || variants[1]["sku"] != "BF-M620-52" {
		t.Fatalf("unexpected variants: %#v", prod["variants"])
	}

	// Standalone <meta itemprop="price"> without enclosing itemscope must fall through to OG fallback.
	ogOnly := `<meta name="price" content=""><meta itemprop="price" content="Contact"><meta property="og:image" content="https://img.example/a.jpg">`
	ogProd := ExtractStructuredProduct(ogOnly, "https://shop.example.com/p/3", "OG Item", "OG Desc")
	if ogProd == nil || ogProd["price"] != "Contact" {
		t.Fatalf("expected standalone meta itemprop=price to fall back to OG, got %#v", ogProd)
	}
}

func TestExtractStructuredProductSpecTablesAndJsonDiagnostics(t *testing.T) {
	// 1. books.toscrape.com fixture
	booksHTML := `<!doctype html><html><body>
	<article class="product_page">
		<div id="product_gallery"><div class="item active"><img src="../../media/cache/a.jpg" alt="Light" /></div></div>
		<div class="product_main">
			<h1>A Light in the Attic</h1>
			<p class="price_color">£51.77</p>
			<p class="instock availability"><i class="icon-ok"></i> In stock (22 available)</p>
		</div>
		<div id="product_description"><h2>Product Description</h2></div>
		<p>It's hard to imagine a world without A Light in the Attic.</p>
		<table class="table table-striped">
			<tr><th>UPC</th><td>a897fe39b1053632</td></tr>
			<tr><th>Product Type</th><td>Books</td></tr>
			<tr><th>Price (excl. tax)</th><td>£51.77</td></tr>
			<tr><th>Price (incl. tax)</th><td>£51.77</td></tr>
			<tr><th>Tax</th><td>£0.00</td></tr>
			<tr><th>Availability</th><td>In stock (22 available)</td></tr>
			<tr><th>Number of reviews</th><td>0</td></tr>
		</table>
	</article></body></html>`
	bookURL := "https://books.toscrape.com/catalogue/a-light-in-the-attic_1000/index.html"
	bookProd := ExtractStructuredProduct(booksHTML, bookURL, "", "")
	if bookProd == nil {
		t.Fatal("expected books.toscrape product")
	}
	if bookProd["title"] != "A Light in the Attic" || bookProd["price"] != 51.77 || bookProd["currency"] != "GBP" {
		t.Fatalf("unexpected book product core fields: %#v", bookProd)
	}
	// The book's "UPC" row is a 16-char hex store ID, not a GS1 GTIN: never report it as gtin, keep it in specs.
	if _, hasGTIN := bookProd["gtin"]; hasGTIN || bookProd["availability"] != "InStock" {
		t.Fatalf("unexpected book gtin/availability (hex UPC must not become gtin): %#v", bookProd)
	}
	if fmt.Sprint(specValueGo(bookProd["specs"], "upc")) != "a897fe39b1053632" {
		t.Fatalf("raw UPC must stay in specs.upc, got specs %#v", bookProd["specs"])
	}
	bookImgs, _ := bookProd["images"].([]string)
	if len(bookImgs) != 1 || bookImgs[0] != "https://books.toscrape.com/media/cache/a.jpg" {
		t.Fatalf("unexpected book images: %#v", bookProd["images"])
	}
	bookSchema := map[string]any{
		"type": "object",
		"properties": map[string]any{
			"price":           map[string]any{"type": "number"},
			"currency":        map[string]any{"type": "string"},
			"upc":             map[string]any{"type": "string"},
			"inStock":         map[string]any{"type": "boolean"},
			"productType":     map[string]any{"type": "string"},
			"numberOfReviews": map[string]any{"type": "string"},
		},
	}
	bookDoc := ExtractedDocumentFull{CanonicalURL: bookURL, Title: "A Light in the Attic"}
	bookJson, _, _ := ExtractStructuredJSONFromPageWithDiagnostics(booksHTML, bookDoc, bookSchema, "")
	if bookJson["price"] != 51.77 || bookJson["currency"] != "GBP" || bookJson["upc"] != "a897fe39b1053632" ||
		bookJson["inStock"] != true || bookJson["productType"] != "Books" || bookJson["numberOfReviews"] != "0" {
		t.Fatalf("unexpected book json extraction: %#v", bookJson)
	}

	// 2. bikeschematics.com fixture (<dl> + MSRP/Part Number)
	bikeHTML := `<!doctype html><html><body><main>
		<h1>Shimano Deore XT RD-M8100</h1>
		<dl>
			<dt>Part Number</dt><dd>IRDM8100SGS</dd>
			<dt>Manufacturer</dt><dd>Shimano</dd>
			<dt>MSRP</dt><dd>$119.99</dd>
			<dt>Availability</dt><dd>In Stock</dd>
		</dl>
	</main></body></html>`
	bikeProd := ExtractStructuredProduct(bikeHTML, "https://bikeschematics.com/parts/rd-m8100", "", "")
	if bikeProd == nil || bikeProd["mpn"] != "IRDM8100SGS" || bikeProd["brand"] != "Shimano" || bikeProd["price"] != 119.99 {
		t.Fatalf("unexpected bikeschematics product: %#v", bikeProd)
	}

	// 3. bafang-e.com OEM fixture (no price; Code + hardware specs)
	bafangHTML := `<!doctype html><html><body><main>
		<h1>M620</h1>
		<table>
			<tr><th>Code</th><td>MM G510.750.C</td></tr>
			<tr><th>Rated Voltage (DCV)</th><td>48</td></tr>
			<tr><th>Rated Power (W)</th><td>750</td></tr>
			<tr><th>Max Torque (N.m)</th><td>160</td></tr>
			<tr><th>Weight (kg)</th><td>5.3</td></tr>
		</table>
	</main></body></html>`
	bafangProd := ExtractStructuredProduct(bafangHTML, "https://www.bafang-e.com/en/oem-area/components/component/motor/mm-g5107501000c", "", "")
	if bafangProd == nil || bafangProd["sku"] != "MM G510.750.C" {
		t.Fatalf("unexpected bafang product: %#v", bafangProd)
	}
	bafangSchema := map[string]any{
		"type": "object",
		"properties": map[string]any{
			"sku":          map[string]any{"type": "string"},
			"ratedVoltage": map[string]any{"type": "string"},
			"ratedPower":   map[string]any{"type": "string"},
			"maxTorque":    map[string]any{"type": "string"},
		},
	}
	bafangJson, _, _ := ExtractStructuredJSONFromPageWithDiagnostics(bafangHTML, ExtractedDocumentFull{CanonicalURL: "https://www.bafang-e.com/m620"}, bafangSchema, "")
	if bafangJson["sku"] != "MM G510.750.C" || bafangJson["ratedVoltage"] != "48" || bafangJson["ratedPower"] != "750" || bafangJson["maxTorque"] != "160" {
		t.Fatalf("unexpected bafang json extraction: %#v", bafangJson)
	}
}

func TestExtractStructuredProductSpecTableNegativeVetoes(t *testing.T) {
	negatives := []struct {
		name string
		html string
	}{
		{
			name: "wikipedia infobox",
			html: `<html><body><div class="mw-parser-output"><h1>Bicycle</h1><table class="infobox"><tr><th>Type</th><td>Vehicle</td></tr><tr><th>Price</th><td>$500</td></tr></table></div></body></html>`,
		},
		{
			name: "TechArticle API parameter table",
			html: `<html><head><script type="application/ld+json">{"@type":"TechArticle","headline":"API Docs"}</script></head><body><h1>API</h1><table><tr><th>Code</th><td>200</td></tr><tr><th>Weight</th><td>10</td></tr><tr><th>Price</th><td>$10</td></tr></table></body></html>`,
		},
		{
			name: "JobPosting table with salary",
			html: `<html><body><h1>Senior Engineer</h1><table><tr><th>Title</th><td>Engineer</td></tr><tr><th>Salary</th><td>$150,000</td></tr><tr><th>SKU</th><td>JOB-1</td></tr></table></body></html>`,
		},
		{
			name: "og:type article comparison table",
			html: `<html><head><meta property="og:type" content="article"></head><body><h1>Best Bikes</h1><table><tr><th>Price</th><td>$999</td></tr><tr><th>Brand</th><td>Acme</td></tr></table></body></html>`,
		},
		{
			name: "table inside nav",
			html: `<html><body><h1>Store</h1><nav><table><tr><th>Price</th><td>$10</td></tr><tr><th>SKU</th><td>N1</td></tr></table></nav></body></html>`,
		},
		{
			name: "plain html",
			html: `<html><body>plain</body></html>`,
		},
	}

	for _, tc := range negatives {
		t.Run(tc.name, func(t *testing.T) {
			if got := ExtractStructuredProduct(tc.html, "https://example.com/page", "Page", ""); got != nil {
				t.Fatalf("expected nil for veto case %q, got %#v", tc.name, got)
			}
		})
	}
}

func TestNormalizeAvailabilityNotInStockOrdering(t *testing.T) {
	cases := []struct {
		raw  string
		want string
	}{
		{"Not in stock", "OutOfStock"},
		{"not  in  stock", "OutOfStock"},
		{"Not-in-stock", "OutOfStock"},
		{"not instock", "OutOfStock"},
		{"Not available", "OutOfStock"},
		{"No longer available", "OutOfStock"},
		{"Unavailable", "OutOfStock"},
		{"Out of stock", "OutOfStock"},
		{"In stock", "InStock"},
		{"InStock", "InStock"},
		{"https://schema.org/InStock", "InStock"},
		{"https://schema.org/OutOfStock", "OutOfStock"},
		{"Available", "InStock"},
	}
	for _, tc := range cases {
		if got := normalizeAvailabilitySliceGo(tc.raw); got != tc.want {
			t.Fatalf("normalizeAvailabilitySliceGo(%q) = %q, want %q", tc.raw, got, tc.want)
		}
	}

	// Verify ExtractStructuredProduct end-to-end across all 4 extraction paths (Microdata, JSON-LD primary,
	// JSON-LD multi-offer variants[], and OpenGraph).
	microHTML := `<div itemscope itemtype="https://schema.org/Product"><span itemprop="name">Brake Pad</span><div itemprop="offers" itemscope itemtype="https://schema.org/Offer"><span itemprop="price">$19.99</span><span itemprop="availability">Not in stock</span></div></div>`
	prod := ExtractStructuredProduct(microHTML, "https://shop.example.com/p/pad", "", "")
	if prod == nil || prod["availability"] != "OutOfStock" {
		t.Fatalf("expected OutOfStock from Microdata ExtractStructuredProduct, got %#v", prod)
	}

	availMatrix := []struct {
		raw  string
		want string
	}{
		{"Not in stock", "OutOfStock"},
		{"not  in  stock", "OutOfStock"},
		{"Not-in-stock", "OutOfStock"},
		{"Out of stock", "OutOfStock"},
		{"Unavailable", "OutOfStock"},
		{"In stock", "InStock"},
	}
	for _, tc := range availMatrix {
		ldSingle := `<script type="application/ld+json">{"@type":"Product","name":"Rotor","offers":{"@type":"Offer","price":"29.00","priceCurrency":"USD","availability":"` + tc.raw + `"}}</script>`
		p1 := ExtractStructuredProduct(ldSingle, "https://shop.example.com/p/rotor", "", "")
		if p1 == nil || p1["availability"] != tc.want {
			t.Fatalf("JSON-LD primary offer availability(%q) = %#v, want %q", tc.raw, p1["availability"], tc.want)
		}

		ldMulti := `<script type="application/ld+json">{"@type":"Product","name":"Rotor","offers":[{"@type":"Offer","price":"29.00","priceCurrency":"USD","availability":"In stock"},{"@type":"Offer","price":"35.00","priceCurrency":"USD","availability":"` + tc.raw + `"}]}</script>`
		p2 := ExtractStructuredProduct(ldMulti, "https://shop.example.com/p/rotor", "", "")
		vars, _ := p2["variants"].([]map[string]any)
		if len(vars) != 2 || vars[1]["availability"] != tc.want {
			t.Fatalf("JSON-LD multi-offer variant availability(%q) = %#v, want %q", tc.raw, p2["variants"], tc.want)
		}

		ogHTML := `<meta property="og:title" content="Rotor"><meta property="product:price:amount" content="29.00"><meta property="product:availability" content="` + tc.raw + `">`
		p3 := ExtractStructuredProduct(ogHTML, "https://shop.example.com/p/rotor", "", "")
		if p3 == nil || p3["availability"] != tc.want {
			t.Fatalf("OpenGraph availability(%q) = %#v, want %q", tc.raw, p3["availability"], tc.want)
		}
	}

	// PreferRecordAvailability: live companion twin availability overrides stale HTML JSON-LD
	// in ExtractStructuredJSONFromPageWithDiagnostics without overwriting explicit JSON-LD sku/price.
	staleHTML := `<!doctype html><html><head>
		<script type="application/ld+json">{"@type":"Product","name":"Domane SL 6","sku":"HTML-SKU","offers":{"@type":"Offer","price":"2999.00","priceCurrency":"USD","availability":"https://schema.org/InStock"}}</script>
	</head><body><h1>Domane SL 6</h1></body></html>`
	schema := map[string]any{
		"type": "object",
		"properties": map[string]any{
			"sku":          map[string]any{"type": "string"},
			"price":        map[string]any{"type": "number"},
			"availability": map[string]any{"type": "string"},
			"inStock":      map[string]any{"type": "boolean"},
		},
	}
	liveDoc := ExtractedDocumentFull{
		CanonicalURL:             "https://bikes.example.com/p/domane",
		Title:                    "Domane SL 6",
		PreferRecordAvailability: true,
		Records: []map[string]any{
			{
				"sku": "TWIN-SKU",
				"variants": []any{
					map[string]any{"sku": "TWIN-SKU", "price": 2499.0, "available": false},
				},
			},
		},
	}
	liveRes, _, _ := ExtractStructuredJSONFromPageWithDiagnostics(staleHTML, liveDoc, schema, "")
	if liveRes["availability"] != "OutOfStock" || liveRes["inStock"] != false {
		t.Fatalf("expected live twin OutOfStock / inStock=false, got %#v", liveRes)
	}
	if liveRes["sku"] != "HTML-SKU" || liveRes["price"] != 2999.0 {
		t.Fatalf("expected explicit HTML JSON-LD sku/price preserved, got %#v", liveRes)
	}

	// Non-live-twin record availability must still be normalized when HTML has no availability.
	noAvailHTML := `<!doctype html><html><head>
		<script type="application/ld+json">{"@type":"Product","name":"Domane SL 6","sku":"HTML-SKU","offers":{"@type":"Offer","price":"2999.00","priceCurrency":"USD"}}</script>
	</head><body><h1>Domane SL 6</h1></body></html>`
	nonLiveDoc := ExtractedDocumentFull{
		CanonicalURL:             "https://bikes.example.com/p/domane",
		Title:                    "Domane SL 6",
		PreferRecordAvailability: false,
		Records: []map[string]any{
			{
				"sku":          "TWIN-SKU",
				"availability": "in stock",
			},
		},
	}
	nonLiveRes, _, _ := ExtractStructuredJSONFromPageWithDiagnostics(noAvailHTML, nonLiveDoc, schema, "")
	if nonLiveRes["availability"] != "InStock" || nonLiveRes["inStock"] != true {
		t.Fatalf("expected normalized InStock / inStock=true from non-live-twin record, got %#v", nonLiveRes)
	}
	if nonLiveRes["sku"] != "HTML-SKU" || nonLiveRes["price"] != 2999.0 {
		t.Fatalf("expected explicit HTML JSON-LD sku/price preserved on non-live-twin, got %#v", nonLiveRes)
	}

	// Parity assertions for normalizeRecordAvailabilityFmtGo (including negative phrases before "instock").
	fmtAvailCases := []struct {
		raw       string
		wantAvail string
		wantStock bool
	}{
		{"not-in-stock", "OutOfStock", false},
		{"not instock", "OutOfStock", false},
		{"not available", "OutOfStock", false},
		{"no longer available", "OutOfStock", false},
		{"not  in  stock", "OutOfStock", false},
		{"Currently Not-in-Stock", "OutOfStock", false},
		{"InStock", "InStock", true},
		{"in stock", "InStock", true},
	}
	for _, tc := range fmtAvailCases {
		if got := normalizeRecordAvailabilityFmtGo(tc.raw); got != tc.wantAvail {
			t.Fatalf("normalizeRecordAvailabilityFmtGo(%q) = %q, want %q", tc.raw, got, tc.wantAvail)
		}
		doc := ExtractedDocumentFull{
			CanonicalURL: "https://bikes.example.com/p/domane",
			Title:        "Domane SL 6",
			Records:      []map[string]any{{"sku": "TWIN-SKU", "availability": tc.raw}},
		}
		res, _, _ := ExtractStructuredJSONFromPageWithDiagnostics(noAvailHTML, doc, schema, "")
		if res["availability"] != tc.wantAvail || res["inStock"] != tc.wantStock {
			t.Fatalf("ExtractStructuredJSONFromPageWithDiagnostics(%q) got availability=%#v inStock=%#v, want %q / %v",
				tc.raw, res["availability"], res["inStock"], tc.wantAvail, tc.wantStock)
		}
	}
}

func TestStructuredProductJSONLDUrlObjectAndCurrencySpecGO6(t *testing.T) {
	t.Parallel()

	// JSON-LD `"url": {"@id": "/products/hub"}` must resolve into product["url"]
	htmlURLObj := `<!doctype html><html><head><script type="application/ld+json">{
		"@context": "https://schema.org",
		"@type": "Product",
		"name": "Trail Hub",
		"url": {"@id": "/products/hub"},
		"offers": {"@type": "Offer", "price": "199.00", "priceCurrency": "USD"}
	}</script></head><body><h1>Trail Hub</h1></body></html>`
	prodURLObj := ExtractStructuredProduct(htmlURLObj, "https://shop.example.com/p/trail-hub", "", "")
	if prodURLObj == nil {
		t.Fatal("expected structured product from JSON-LD url.@id")
	}
	if got, _ := prodURLObj["url"].(string); got != "https://shop.example.com/products/hub" {
		t.Fatalf("expected resolved JSON-LD url object @id, got %#v", prodURLObj["url"])
	}

	// Non-table, non-<dl> currency-prefixed spec without literal "price" keyword
	htmlCurrencyOnly := `<!doctype html><html><head><title>Brake Pad Set</title></head><body>
		<main>
			<h1>Brake Pad Set</h1>
			<p class="amount">$49.99</p>
			<ul><li>SKU: BP-490</li><li>Brand: TrailStop</li></ul>
			<div class="summary">Organic compound for wet trails.</div>
		</main>
	</body></html>`
	prodCurr := ExtractStructuredProduct(htmlCurrencyOnly, "https://shop.example.com/products/brake-pad-set", "Brake Pad Set", "")
	if prodCurr == nil {
		t.Fatal("expected structured product from currency-prefixed non-table/non-dl price spec")
	}
	if gotPrice, _ := prodCurr["price"].(float64); gotPrice != 49.99 {
		t.Fatalf("expected price 49.99 without literal 'price' label, got %#v (%+v)", prodCurr["price"], prodCurr)
	}

	// Explicit GBP symbol outside table/dl/price-word should also resolve price + GBP currency.
	htmlGBP := `<!doctype html><html><head><title>Brake Rotor</title></head><body>
		<main>
			<h1>Brake Rotor</h1>
			<span class="amount">£39.50</span>
			<ul><li>SKU: BR-180</li><li>Brand: TrailStop</li></ul>
		</main>
	</body></html>`
	prodGBP := ExtractStructuredProduct(htmlGBP, "https://shop.example.com/products/brake-rotor", "Brake Rotor", "")
	if prodGBP == nil || prodGBP["price"] != 39.5 || prodGBP["currency"] != "GBP" {
		t.Fatalf("expected GBP price 39.50 without literal 'price' label, got %#v", prodGBP)
	}
}

func specValueGo(specs any, key string) any {
	switch m := specs.(type) {
	case map[string]string:
		return m[key]
	case map[string]any:
		return m[key]
	}
	return nil
}

func TestPlausibleGTINGo(t *testing.T) {
	cases := map[string]string{
		"012345678905":      "012345678905",  // UPC-A / GTIN-12
		"4006381333931":     "4006381333931", // EAN-13
		"978-0-14-032872-1": "9780140328721", // ISBN-13 with hyphens
		"9650 1234":         "96501234",      // GTIN-8 with a space
		"10012345678902":    "10012345678902", // GTIN-14
		"a897fe39b1053632":  "",              // hex store ID
		"0140328726":        "",              // ISBN-10 is not a GTIN
		"12345":             "",
		"":                  "",
		"SKU-123456789012":  "",
	}
	for in, want := range cases {
		if got := plausibleGTINGo(in); got != want {
			t.Errorf("plausibleGTINGo(%q) = %q, want %q", in, got, want)
		}
	}
	if got := firstPlausibleGTINGo("", "a897fe39b1053632", "4006381333931"); got != "4006381333931" {
		t.Errorf("firstPlausibleGTINGo skipped to the wrong candidate: %q", got)
	}
}

