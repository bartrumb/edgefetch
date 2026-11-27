package extract

import (
	"strings"
	"testing"
)

func TestDecodeHTMLEntitiesHTML5NamedFallback(t *testing.T) {
	cases := map[string]string{
		"&Eacute;monda":               "Émonda",
		"caf&eacute; cr&egrave;me":    "café crème",
		"Fa&ccedil;ade &Uuml;ber":     "Façade Über",
		"&#201;monda &#xC9;monda":     "Émonda Émonda",
		"&Eacute;&mdash;&ntilde;":     "É—ñ",
		"&lt;b&gt;":                   "<b>",
		"&notanentity; &Eacutex;":     "&notanentity; &Eacutex;",
		"&lowbar;&ast;&lbrack;&nvlt;": "&lowbar;&ast;&lbrack;&nvlt;",
	}
	for in, want := range cases {
		if got := DecodeHTMLEntities(in); got != want {
			t.Errorf("DecodeHTMLEntities(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSanitizeScrapedMetaHTML5NamedEntities(t *testing.T) {
	if got := SanitizeScrapedMeta("&Eacute;monda ALR"); got != "Émonda ALR" {
		t.Fatalf("named entity: got %q", got)
	}
	if got := SanitizeScrapedMeta("&#201;monda ALR"); got != "Émonda ALR" {
		t.Fatalf("numeric entity: got %q", got)
	}
	got := SanitizeScrapedMeta("&lt;script&gt;alert(1)&lt;/script&gt; &Eacute;")
	if strings.Contains(got, "<") {
		t.Fatalf("escaped markup became live: %q", got)
	}
	if !strings.HasSuffix(got, "É") {
		t.Fatalf("expected trailing É: %q", got)
	}
}

func TestExtractHTMLDocumentFullDecodesMetadataEntities(t *testing.T) {
	rawHTML := `<!doctype html><html lang="en"><head>
<title>&Eacute;monda ALR Disc Frameset - Trek Bikes</title>
<meta name="description" content="Discover your next great ride with &Eacute;monda ALR Disc Frameset &#8212; caf&eacute;." />
<meta property="og:title" content="&amp;Eacute;monda ALR Disc Frameset - Trek Bikes"/>
</head><body><main><h1>&Eacute;monda ALR Disc Frameset</h1>
<p>The &Eacute;monda ALR is a lightweight aluminium race frameset built for climbing and long rides.</p>
</main></body></html>`
	doc := ExtractHTMLDocumentFull(rawHTML, FullExtractOptions{BaseURL: "https://shop.example.com/p/1"})
	if doc.Title != "Émonda ALR Disc Frameset - Trek Bikes" {
		t.Fatalf("title = %q", doc.Title)
	}
	if doc.Description != "Discover your next great ride with Émonda ALR Disc Frameset — café." {
		t.Fatalf("description = %q", doc.Description)
	}
	if strings.Contains(doc.Markdown, "&Eacute;") || !strings.Contains(doc.Markdown, "Émonda") {
		t.Fatalf("markdown kept raw entity: %q", doc.Markdown)
	}
}

func TestExtractHTMLDocumentFullDoubleEncodedOGTitle(t *testing.T) {
	// og:title is the only title source; the site double-encoded `&Eacute;` as `&amp;Eacute;`.
	rawHTML := `<!doctype html><html><head>
<meta property="og:title" content="&amp;Eacute;monda ALR Disc Frameset"/>
<meta property="og:description" content="&amp;Eacute;monda &amp;mdash; light"/>
</head><body><main><p>Body text for the double encoded metadata regression case.</p></main></body></html>`
	doc := ExtractHTMLDocumentFull(rawHTML, FullExtractOptions{BaseURL: "https://shop.example.com/p/2"})
	if doc.Title != "Émonda ALR Disc Frameset" {
		t.Fatalf("title = %q", doc.Title)
	}
	if doc.Description != "Émonda — light" {
		t.Fatalf("description = %q", doc.Description)
	}
}

func TestExtractHTMLDocumentFullEscapedScriptTitleStaysInert(t *testing.T) {
	rawHTML := `<!doctype html><html><head>
<title>&lt;script&gt;alert(1)&lt;/script&gt; &Eacute;dition</title>
<meta property="og:title" content="&amp;lt;img src=x onerror=alert(1)&amp;gt;"/>
<meta name="description" content="&lt;script&gt;alert(2)&lt;/script&gt; r&eacute;sum&eacute;"/>
</head><body><main><h1>&lt;script&gt;alert(3)&lt;/script&gt; &Eacute;dition</h1>
<p>Paragraph body for the escaped script metadata regression case.</p></main></body></html>`
	doc := ExtractHTMLDocumentFull(rawHTML, FullExtractOptions{BaseURL: "https://shop.example.com/p/3"})
	for name, v := range map[string]string{"title": doc.Title, "description": doc.Description, "markdown": doc.Markdown} {
		low := strings.ToLower(v)
		if strings.Contains(low, "<script") || strings.Contains(low, "<img") || strings.Contains(low, "</script") {
			t.Fatalf("%s contains live markup: %q", name, v)
		}
	}
	if !strings.Contains(doc.Title, "Édition") {
		t.Fatalf("title lost decoded accent: %q", doc.Title)
	}
	if !strings.Contains(doc.Description, "résumé") {
		t.Fatalf("description lost decoded accent: %q", doc.Description)
	}
}

func TestExtractHTMLDocumentFullFaviconSkipsOriginRootAppleTouchIcons(t *testing.T) {
	head := `<link rel="shortcut icon" type="image/x-icon" href="//trekcdnprod.azureedge.net/hybris/faviconTrek.ico"/>
<link rel="apple-touch-icon" href="/"/>
<link rel="apple-touch-icon" sizes="76x76" href="/"/>
<link rel="apple-touch-icon" sizes="120x120" href="/"/>`
	base := "https://www.trekbikes.com/us/en_US/p/37299/"
	rawHTML := `<!doctype html><html><head><title>Frameset</title>` + head + `</head><body><main><p>Body text for the favicon regression case.</p></main></body></html>`
	doc := ExtractHTMLDocumentFull(rawHTML, FullExtractOptions{BaseURL: base})
	if doc.Favicon != "https://trekcdnprod.azureedge.net/hybris/faviconTrek.ico" {
		t.Fatalf("favicon = %q", doc.Favicon)
	}

	// apple-touch-icon listed first still loses to an explicit icon; root-only candidates fall back to /favicon.ico.
	reordered := `<!doctype html><html><head><link rel="apple-touch-icon" href="/apple-180.png"/><link rel="icon" href="/fav.png"/></head><body><p>x</p></body></html>`
	if got := ExtractHTMLDocumentFull(reordered, FullExtractOptions{BaseURL: base}).Favicon; got != "https://www.trekbikes.com/fav.png" {
		t.Fatalf("explicit icon should win, got %q", got)
	}
	rootOnly := `<!doctype html><html><head><link rel="apple-touch-icon" href="/"/><link rel="icon" href="https://www.trekbikes.com"/></head><body><p>x</p></body></html>`
	if got := ExtractHTMLDocumentFull(rootOnly, FullExtractOptions{BaseURL: base}).Favicon; got != "https://www.trekbikes.com/favicon.ico" {
		t.Fatalf("root-only candidates should fall back to /favicon.ico, got %q", got)
	}
	appleOnly := `<!doctype html><html><head><link rel="apple-touch-icon" href="/"/><link rel="apple-touch-icon" href="/touch.png"/></head><body><p>x</p></body></html>`
	if got := ExtractHTMLDocumentFull(appleOnly, FullExtractOptions{BaseURL: base}).Favicon; got != "https://www.trekbikes.com/touch.png" {
		t.Fatalf("next non-root candidate should be used, got %q", got)
	}
}
