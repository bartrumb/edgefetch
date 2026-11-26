package extract

import "testing"

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
