package extract

import (
	"encoding/json"
	"regexp"
	"strings"
	"testing"
)

func TestR10P3ManifestFetchURLStrictHostAndOriginBinding(t *testing.T) {
	buildManifestJSON := func(domains []string, fetchURL string) ([]byte, DeclarativeManifest) {
		rawMap := map[string]any{
			"id":          "r10-binding-check",
			"name":        "R10 Binding Check",
			"category":    "developer",
			"description": "Tests strict {host} and {origin} authority boundary binding in fetchUrl.",
			"domains":     domains,
			"exampleUrls": []string{"https://docs.example.org/items/42"},
			"routes": []any{
				map[string]any{
					"match": map[string]any{
						"pathSegments": []any{"items", map[string]any{"param": "id"}},
					},
					"twin": map[string]any{
						"id":       "r10-binding-twin",
						"fetchUrl": fetchURL,
						"kind":     "json",
						"accept":   "application/json",
					},
					"extract": map[string]any{
						"titleTemplate": "Item",
					},
				},
			},
		}
		raw, err := json.Marshal(rawMap)
		if err != nil {
			t.Fatalf("json.Marshal manifest: %v", err)
		}
		m := DeclarativeManifest{
			ID:          "r10-binding-check",
			Name:        "R10 Binding Check",
			Category:    "developer",
			Description: "Tests strict {host} and {origin} authority boundary binding in fetchUrl.",
			Domains:     domains,
			ExampleURLs: []string{"https://docs.example.org/items/42"},
			Routes: []DeclarativeRouteSpec{{
				Match: DeclarativeMatchSpec{
					PathSegments: []DeclarativeSegmentSpec{
						{IsLiteral: true, Literal: "items"},
						{ParamSpec: DeclarativeParamSegment{Param: "id"}},
					},
				},
				Twin: DeclarativeTwinSpec{
					ID:       "r10-binding-twin",
					FetchURL: fetchURL,
					Kind:     "json",
					Accept:   "application/json",
				},
				Extract: DeclarativeExtractSpec{
					TitleTemplate: "Item",
				},
			}},
		}
		return raw, m
	}

	// Attack vectors MUST fail on BOTH non-wildcard static-domain adapters AND wildcard adapters!
	domainSets := [][]string{
		{"docs.example.org"}, // non-wildcard adapter (previously bypassed hasWildcard guard!)
		{"*.wikipedia.org"},  // approved wildcard adapter
	}
	badFetchURLs := []string{
		"https://{host}.evil.example/items/{id}",
		"{origin}.evil.example/items/{id}",
		"https://{host}@evil.example/items/{id}",
		"{origin}@evil.example/items/{id}",
		"https://{host}:8443/items/{id}",
		"{origin}:8443/items/{id}",
		"https://{host}//evil.example/items/{id}",
		"{origin}//evil.example/items/{id}",
		"https://{host}",
		"{origin}",
		"https://collector.evil.example/steal?h={host}",
		"https://collector.evil.example/steal?o={origin}",
		"{origin}/api/items/{id}?redirect={origin}",
		"https://{host}/api/items/{id}?redirect={origin}",
	}

	for _, doms := range domainSets {
		for _, badFU := range badFetchURLs {
			raw, m := buildManifestJSON(doms, badFU)
			if _, err := ParseDeclarativeManifest(raw); err == nil {
				t.Fatalf("SECURITY (P3): ParseDeclarativeManifest accepted %q on domains %v", badFU, doms)
			}
			if err := ValidateDeclarativeManifests([]DeclarativeManifest{m}); err == nil {
				t.Fatalf("SECURITY (P3): ValidateDeclarativeManifests accepted %q on domains %v", badFU, doms)
			}
		}
	}

	// Legitimate same-origin `{host}/` and `{origin}/` bindings MUST continue to pass!
	goodFetchURLs := []string{
		"https://{host}/api/v1/items/{id}",
		"{origin}/api/v1/items/{id}",
		"{requestUrl}",
	}
	for _, doms := range domainSets {
		for _, goodFU := range goodFetchURLs {
			raw, m := buildManifestJSON(doms, goodFU)
			if _, err := ParseDeclarativeManifest(raw); err != nil {
				t.Fatalf("expected valid fetchUrl %q on domains %v to pass ParseDeclarativeManifest, got: %v", goodFU, doms, err)
			}
			if err := ValidateDeclarativeManifests([]DeclarativeManifest{m}); err != nil {
				t.Fatalf("expected valid fetchUrl %q on domains %v to pass ValidateDeclarativeManifests, got: %v", goodFU, doms, err)
			}
		}
	}
}

func hasUnescapedClickableEvilLinkR10(s string) bool {
	// Match `[label](https://evil.example...)` ONLY when neither `[` nor `]` is backslash-escaped (`\[` / `\]`).
	reUnescapedLink := regexp.MustCompile(`(?:^|[^\\])\[[^\]\\\n]*\](?:\\)*\(\s*https?://evil\.example`)
	return reUnescapedLink.MatchString(s)
}

func TestR10P3GoCommerceEscapesWithoutStrippingSKUsOrTitlesAndBlocksInjectedHeadingsLinksImages(t *testing.T) {
	reInjectedHeading := regexp.MustCompile(`(?m)^#{1,6}[ \t]+.*(?:Injected|Pwned|EvilHeading)`)

	const trickySKU = "SKU-`PRO`|v2[A]<1>#9"
	const trickyTitle = "Widget #1 [Deluxe] `Gen2` | <Fast> & # Injected"

	shopifyPayload, err := json.Marshal(map[string]any{
		"product": map[string]any{
			"title":        trickyTitle,
			"vendor":       "Acme [Vendor](https://evil.example/vendor) <script>alert(1)</script>",
			"product_type": "Hardware\n# EvilHeading",
			"tags":         "winter, [Promo](https://evil.example/tag), # InjectedTag, <svg onload=1>",
			"published_at": "2026-03-15T10:00:00Z\n# Pwned\n[click](https://evil.example/date) <img src=x onerror=1>",
			"updated_at":   "2026-03-16T12:00:00Z [upd](https://evil.example/upd)",
			"options": []any{
				map[string]any{
					"name":   "Size [Chart](https://evil.example/opt)",
					"values": []any{"Small | Medium", "`Large` <XL>"},
				},
			},
			// Put non-public URLs FIRST so safeImgs[0] proves all 5 unsafe URLs were dropped and // was upgraded to https://!
			"images": []any{
				map[string]any{"src": "http://cdn.shopify.com/s/files/1/insecure-http.jpg"},
				map[string]any{"src": "https://127.0.0.1/loopback.jpg"},
				map[string]any{"src": "https://169.254.169.254/latest/meta-data/iam"},
				map[string]any{"src": "https://localhost/internal.jpg"},
				map[string]any{"src": "javascript:alert(1)"},
				map[string]any{"src": "//cdn.shopify.com/s/files/1/protocol-rel.jpg"},
			},
			"variants": []any{
				map[string]any{
					"title":     "Blue | [Link](https://evil.example/var) <b onload=1>",
					"sku":       trickySKU,
					"price":     "29.99",
					"available": true,
				},
			},
			"body_html": `<h1>EvilHeading</h1><p>Great jacket. <a href="https://evil.example/phish">Claim Prize</a></p>` +
				"\n# Injected Markdown Heading\n[Markdown Phish](https://evil.example/md)\n<script>stealCookies()</script>",
		},
	})
	if err != nil {
		t.Fatalf("marshal shopifyPayload: %v", err)
	}

	doc, ok := formatCommerceTwinGo(shopifyPayload, "shopify_product", "https://shop.example.com/products/widget")
	if !ok || doc == nil {
		t.Fatal("expected formatCommerceTwinGo(shopify_product) to succeed")
	}

	for _, checkMD := range []string{doc.Markdown, SanitizeScrapedMarkdown(doc.Markdown)} {
		if strings.IndexByte(checkMD, '<') >= 0 {
			t.Fatalf("SECURITY (P3): raw `<` survived in Go commerce Markdown:\n%s", checkMD)
		}
		// Check every line AFTER line 0 (line 0 is the legitimate `# <Product Title>` H1) for injected ATX headings!
		mdLines := strings.Split(checkMD, "\n")
		if len(mdLines) > 1 && reInjectedHeading.MatchString(strings.Join(mdLines[1:], "\n")) {
			t.Fatalf("SECURITY (P3): injected ATX heading survived in Go commerce Markdown:\n%s", checkMD)
		}
		if hasUnescapedClickableEvilLinkR10(checkMD) {
			t.Fatalf("SECURITY (P3): injected clickable Markdown link survived in Go commerce Markdown:\n%s", checkMD)
		}
		// Verify SKU and title characters were ESCAPED (in multi-backtick code span / prose), NOT stripped!
		for _, mustKeepToken := range []string{"SKU-", "`PRO`", `\|v2`, `\[A\]`, "&lt;1>", "#9", `Widget \#1`, `\# Injected`} {
			if !strings.Contains(checkMD, mustKeepToken) {
				t.Fatalf("expected commerce output to preserve escaped token %q without stripping characters, got:\n%s", mustKeepToken, checkMD)
			}
		}
		// Verify all 5 non-public image URLs were skipped and //cdn.shopify.com/... was upgraded to https:// as Primary Image!
		if !strings.Contains(checkMD, "https://cdn.shopify.com/s/files/1/protocol-rel.jpg") {
			t.Fatalf("expected valid protocol-relative public image upgraded to HTTPS in commerce output:\n%s", checkMD)
		}
		for _, forbiddenImg := range []string{"insecure-http.jpg", "127.0.0.1", "169.254.169.254", "localhost", "javascript:"} {
			if strings.Contains(checkMD, forbiddenImg) {
				t.Fatalf("SECURITY (P3): non-public image URL %q leaked into commerce output:\n%s", forbiddenImg, checkMD)
			}
		}
	}

	// Also verify WooCommerce single product & catalog modes escape titles, SKUs, dates, and descriptions identically.
	wooCatalogPayload, _ := json.Marshal([]any{
		map[string]any{
			"name":              "Woo #1 [Item](https://evil.example/woo) `X` | <Y>",
			"sku":               trickySKU,
			"date_created":      "2026-04-01\n# Injected Date Heading",
			"on_sale":           true,
			"is_in_stock":       true,
			"prices":            map[string]any{"price": "1999", "currency_minor_unit": 2, "currency_symbol": "$"},
			"categories":        []any{map[string]any{"name": "[Cat](https://evil.example/cat) <svg>"}},
			"short_description": "<h2>EvilHeading</h2><a href=\"https://evil.example/woo-desc\">Click</a>\n# Injected\n[bad](https://evil.example/woo2)",
		},
	})
	wooDoc, ok := formatCommerceTwinGo(wooCatalogPayload, "woocommerce_catalog_page", "https://woo.example.com/shop")
	if !ok || wooDoc == nil {
		t.Fatal("expected formatCommerceTwinGo(woocommerce_catalog_page) to succeed")
	}
	if strings.IndexByte(wooDoc.Markdown, '<') >= 0 ||
		reInjectedHeading.MatchString(wooDoc.Markdown) ||
		hasUnescapedClickableEvilLinkR10(wooDoc.Markdown) ||
		!strings.Contains(wooDoc.Markdown, "`PRO`") ||
		!strings.Contains(wooDoc.Markdown, `Woo \#1`) {
		t.Fatalf("unexpected WooCommerce catalog output:\n%s", wooDoc.Markdown)
	}
}
