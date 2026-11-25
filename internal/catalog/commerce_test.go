package catalog

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestSanitizeCommerceFieldsAndImageURLs(t *testing.T) {
	blockedURLs := []string{
		"http://localhost/img.png",
		"http://cdn.shopify.com/s/files/1/cleartext.jpg",
		"https://cdn.shopify.com:8443/s/files/1/port.jpg",
		"https://localhost/img.png",
		"https://api.localhost/img.png",
		"https://nas.local/img.png",
		"https://metadata.internal/img.png",
		"http://127.0.0.1/img.png",
		"https://127.0.0.1/img.png",
		"http://169.254.169.254/latest/meta-data/",
		"http://10.0.0.1/img.png",
		"http://172.16.5.4/img.png",
		"http://192.168.1.10/img.png",
		"http://2130706433/img.png",
		"https://2130706433/img.png",
		"https://0177.0.0.1/img.png",
		"https://0x7f000001/img.png",
		"https://[::1]/img.png",
		"https://[::ffff:127.0.0.1]/img.png",
		"//localhost/img.png",
		"//169.254.169.254/img.png",
		"///cdn.shopify.com/img.png",
		"https://user:pass@cdn.shopify.com/img.png",
		"https://co.uk/img.png",
		"javascript:alert(1)",
		"data:image/svg+xml,<svg onload=1>",
		"file:///etc/passwd",
		"ftp://cdn.shopify.com/img.png",
	}
	for _, bad := range blockedURLs {
		if got := NormalizePublicCommerceImageURL(bad); got != "" {
			t.Fatalf("expected non-public/unsafe URL %q rejected, got %q", bad, got)
		}
	}
	if got := NormalizePublicCommerceImageURL("https://cdn.shopify.com/s/files/1/product.jpg"); got != "https://cdn.shopify.com/s/files/1/product.jpg" {
		t.Fatalf("unexpected public URL: %q", got)
	}
	if got := NormalizePublicCommerceImageURL("//cdn.shopify.com/s/files/1/product.png"); got != "https://cdn.shopify.com/s/files/1/product.png" {
		t.Fatalf("unexpected protocol-relative URL: %q", got)
	}

	if got := SanitizeCommerceField("Adapter <USB-C>", 400); got != "Adapter &lt;USB-C&gt;" {
		t.Fatalf("unexpected SanitizeCommerceField: %q", got)
	}
	ts := SanitizeCommerceTimestamp("2026-01-01 <x> & (y)", 96)
	if ts == nil || *ts != `2026-01-01 &lt;x&gt; &amp; \(y\)` {
		t.Fatalf("unexpected SanitizeCommerceTimestamp: %v", ts)
	}
	phish := SanitizeCommerceField("# Fake Top Heading\n<script>alert(1)</script> Hoodie [Buy Free](https://evil.example/phish) [XSS](javascript:alert(1)) \U000E0069", 400)
	if strings.Contains(phish, "<") || strings.HasPrefix(phish, "#") || strings.Contains(phish, "javascript:") || strings.Contains(phish, "\U000E0069") {
		t.Fatalf("unsafe characters survived SanitizeCommerceField: %q", phish)
	}
	if strings.Contains(phish, "](https://evil.example") {
		t.Fatalf("phishing link survived SanitizeCommerceField: %q", phish)
	}
}

func TestShopifyNormalizationEnrichmentFeedAndHTML(t *testing.T) {
	if !IsShopifyHTMLOrHeaders("", map[string]string{"X-ShopId": "42"}) {
		t.Fatal("expected X-ShopId header to detect Shopify")
	}
	if !IsShopifyHTMLOrHeaders(`<script>Shopify.shop = "acme.myshopify.com"; Shopify.currency = {"active":"CAD"};</script>`, nil) {
		t.Fatal("expected Shopify.shop HTML to detect Shopify")
	}
	if cur := ExtractShopifyCurrencyFromHTML(`<script>Shopify.currency = {"active":"CAD","rate":"1.0"};</script>`); cur != "CAD" {
		t.Fatalf("expected CAD currency, got %q", cur)
	}
	if twin := ResolveCustomDomainShopifyProductTwinURL("https://shop.example.com/products/%E0%A4%A"); twin != nil {
		t.Fatalf("expected invalid UTF-8 handle rejected, got %+v", twin)
	}
	if twin := ResolveCustomDomainShopifyProductTwinURL("https://shop.example.com/products/%E0%A4"); twin != nil {
		t.Fatalf("expected truncated UTF-8 handle rejected, got %+v", twin)
	}
	twinOK := ResolveCustomDomainShopifyProductTwinURL("https://store.example.com/products/trail-runner.json")
	if twinOK == nil || twinOK.JSONURL != "https://store.example.com/products/trail-runner.json" || twinOK.JSURL != "https://store.example.com/products/trail-runner.js" {
		t.Fatalf("unexpected Shopify twin URLs: %+v", twinOK)
	}

	rawJSON := `{
		"product": {
			"id": 9001,
			"handle": "usb-c-dock",
			"title": "Thunderbolt Dock <USB-C> [Gen 2] *Pro* _Edition_ #1 & Hub",
			"vendor": "Acme <Hardware> & Co [Official](javascript:alert(1))",
			"published_at": "2026-11-20T10:00:00Z\r\n<script>alert(1)</script> & [x](javascript:alert(1))",
			"updated_at": "2026-11-21T12:00:00Z\n<img src=x onerror=1> | [y](https://evil.example)",
			"images": [
				{"id": 1, "src": "http://169.254.169.254/latest/meta-data/iam"},
				{"id": 4, "src": "https://cdn.shopify.com/s/files/1/dock.jpg"}
			],
			"body_html": "<p>Includes cable. <img src=\"http://127.0.0.1/pixel.png\" alt=\"ssrf\"> <img src=\"https://cdn.shopify.com/s/files/1/diagram.png\" alt=\"diagram\"></p>",
			"variants": [
				{
					"id": 501,
					"title": "100W <PD> [US] *Fast*",
					"sku": "SKU<USB-C>[v2]*pro*_1#A` + "`" + `B|C",
					"price": "129.00",
					"compare_at_price": "159.00",
					"featured_image": {"src": "http://10.0.0.5/internal.png"}
				}
			]
		}
	}`
	ajaxBody := `{"variants":[{"id":501,"available":true,"barcode":"0012345678905","inventory_policy":"deny"}]}`
	enriched := EnrichShopifyProductFromJSON(ShopifyEnrichParams{
		RawJSON:    rawJSON,
		ProductURL: "https://store.example.com/products/usb-c-dock",
		Currency:   "CAD",
		AjaxJSBody: ajaxBody,
	})
	if enriched == nil {
		t.Fatal("expected EnrichShopifyProductFromJSON to succeed")
	}
	if strings.Contains(enriched.Markdown, "127.0.0.1") {
		t.Fatalf("SSRF image survived in enriched Markdown: %s", enriched.Markdown)
	}
	if !strings.Contains(enriched.Markdown, "https://cdn.shopify.com/s/files/1/diagram.png") {
		t.Fatalf("expected public diagram image in Markdown, got:\n%s", enriched.Markdown)
	}
	if !strings.Contains(enriched.Markdown, "CAD 129.00") {
		t.Fatalf("expected CAD 129.00 in Markdown, got:\n%s", enriched.Markdown)
	}
	rec := enriched.Records[0]
	if rec.Variants[0].Available == nil || !*rec.Variants[0].Available {
		t.Fatal("expected AjaxJS available=true merged")
	}
	if rec.Variants[0].Barcode == nil || *rec.Variants[0].Barcode != "0012345678905" {
		t.Fatal("expected AjaxJS barcode merged")
	}
	if rec.Variants[0].SKU == nil || !strings.Contains(*rec.Variants[0].SKU, "|C") || !strings.Contains(*rec.Variants[0].SKU, "&lt;USB-C&gt;") {
		t.Fatalf("expected non-destructive SKU escaping, got %v", rec.Variants[0].SKU)
	}

	feed := FormatShopifyProductsFeedTwin(`{"products":[{"id":1,"title":"Shoe A","handle":"shoe-a","vendor":"Peak","variants":[{"id":11,"price":"99.00","available":true}]},{"id":2,"title":"Shoe B","handle":"shoe-b","vendor":"Peak","variants":[{"id":22,"price":"129.00","available":false}]}]}`, "https://store.example.com/products.json?limit=2&page=1")
	if feed == nil || feed.Pagination == nil || !feed.Pagination.HasMore || len(feed.Records) != 2 {
		t.Fatalf("unexpected Shopify feed twin: %+v", feed)
	}

	htmlRes := ExtractShopifyProductHTML(
		"https://www.allbirds.com/products/usb-cable",
		`<html><head><script>Shopify.shop="allbirds.myshopify.com";</script><script type="application/ld+json">{"@type":"Product","name":"Cable <USB-C>","sku":"SKU<1>|A","offers":[{"price":"15.00","priceCurrency":"USD","image":"http://127.0.0.1/bad.png"}]}</script></head><body></body></html>`,
		"",
		"shopify",
	)
	if htmlRes == nil || !strings.Contains(htmlRes.Title, "&lt;USB-C&gt;") || strings.Contains(htmlRes.Markdown, "127.0.0.1") {
		t.Fatalf("unexpected ExtractShopifyProductHTML: %+v", htmlRes)
	}
}

func TestWooCommerceNormalizationTwinsAndDeclarativeSpec(t *testing.T) {
	if !IsWooCommerceHTMLOrHeaders("", map[string]string{"Link": `<https://shop.example.org/wp-json/wc/store/v1/>; rel="https://api.w.org/"`}) {
		t.Fatal("expected WooCommerce Link header match")
	}
	wooTwin := ResolveCustomDomainWooCommerceProductTwinURL("https://shop.example.org/en-us/product/espresso-grinder/")
	if wooTwin == nil || wooTwin.Slug != "espresso-grinder" || wooTwin.StoreAPIURL != "https://shop.example.org/wp-json/wc/store/v1/products?slug=espresso-grinder" {
		t.Fatalf("unexpected Woo twin: %+v", wooTwin)
	}

	wooRaw := `{
		"id": 303,
		"slug": "cable-usb-c",
		"name": "Braided Cable <USB-C> *2m* [Black] #Pro",
		"sku": "WC<USB-C>*2M*|BLK",
		"permalink": "http://127.0.0.1/pwn",
		"date_created": "2026-10-01T00:00:00Z <svg onload=1> (tz)",
		"is_in_stock": true,
		"prices": {"price": "1999", "regular_price": "2499", "currency_code": "USD", "currency_minor_unit": 2},
		"images": [{"src": "http://2130706433/ssrf.png"}, {"src": "https://shop.example.org/wp-content/uploads/cable.jpg"}]
	}`
	prodDoc := FormatWCStoreAPIProductTwin(wooRaw, "https://shop.example.org/wp-json/wc/store/v1/products/303")
	if prodDoc == nil || len(prodDoc.Records) != 1 {
		t.Fatalf("expected FormatWCStoreAPIProductTwin success, got %+v", prodDoc)
	}
	r0 := prodDoc.Records[0]
	if r0.URL != "https://shop.example.org/product/cable-usb-c/" {
		t.Fatalf("expected unsafe permalink rejected with canonical fallback, got %q", r0.URL)
	}
	if r0.Variants[0].Price == nil || *r0.Variants[0].Price != 19.99 || r0.Variants[0].CompareAt == nil || *r0.Variants[0].CompareAt != 24.99 {
		t.Fatalf("unexpected scaled Woo prices: %+v", r0.Variants[0])
	}

	listDoc := FormatWCStoreAPIListTwin("["+wooRaw+"]", "https://shop.example.org/wp-json/wc/store/v1/products?per_page=1&page=1")
	if listDoc == nil || listDoc.Pagination == nil || !listDoc.Pagination.HasMore {
		t.Fatalf("unexpected FormatWCStoreAPIListTwin: %+v", listDoc)
	}
	enrichDoc := EnrichWooCommerceProductFromStoreAPI(WooEnrichParams{
		RawJSON:        "[" + wooRaw + "]",
		ProductURL:     "https://shop.example.org/product/cable-usb-c/",
		Slug:           "cable-usb-c",
		FallbackBodyMD: "# Ignored H1\n\nFallback braided nylon cable details.",
	})
	if enrichDoc == nil || !strings.Contains(enrichDoc.Markdown, "Fallback braided nylon cable details.") {
		t.Fatalf("unexpected EnrichWooCommerceProductFromStoreAPI: %+v", enrichDoc)
	}

	wooHTML := ExtractWooCommerceProductHTML(
		"https://woo.example.com/product/usb-cable/",
		`<html><body class="woocommerce-page single-product"><script type="application/ld+json">{"@type":"Product","name":"Woo <USB-C>","sku":"WOO<1>|B","image":"http://localhost/bad.png","offers":{"price":"25.00","priceCurrency":"USD"}}</script></body></html>`,
		"",
		"woocommerce",
	)
	if wooHTML == nil || wooHTML.Records[0].Images == nil || len(*wooHTML.Records[0].Images) != 0 {
		t.Fatalf("expected empty non-nil images slice on Woo HTML record, got %+v", wooHTML)
	}
	rawRecJSON, err := json.Marshal(wooHTML.Records[0])
	if err != nil || !strings.Contains(string(rawRecJSON), `"images":[]`) {
		t.Fatalf("expected full mode record JSON to include \"images\":[], got %s", string(rawRecJSON))
	}

	if _, err := ValidateDeclarativeCatalogConfig(DeclarativeCatalogConfig{Platform: "magento"}); err == nil {
		t.Fatal("expected unsupported platform magento to fail")
	}
	shopCfg := DeclarativeCatalogConfig{Platform: "shopify", PauseMs: 2000, PageCap: 10}
	fp, err := CatalogSpecFirstPage(shopCfg, "https://shop.example.com/collections/gear", "")
	if err != nil || fp != "https://shop.example.com/collections/gear/products.json?limit=250&page=1" {
		t.Fatalf("unexpected shopify firstPage: %q (%v)", fp, err)
	}
}
