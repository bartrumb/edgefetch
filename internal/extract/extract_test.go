package extract

import (
	"bytes"
	"compress/zlib"
	"context"
	"fmt"
	"net/url"
	"strings"
	"testing"
)

func TestExtractHTMLMarkdownBrandingAndRerank(t *testing.T) {
	raw := `<!DOCTYPE html>
<html>
<head>
  <title>EdgeFetch Documentation</title>
  <meta name="description" content="Distributed outbound HTTP/2 & browser fetcher">
  <meta name="theme-color" content="#0f172a">
  <link rel="canonical" href="https://example.com/docs/intro">
  <link rel="icon" href="/assets/favicon.svg">
  <style>
    body { font-family: "Inter", sans-serif; color: #1e293b; background: #38bdf8; }
  </style>
</head>
<body>
  <nav><a href="/login">Nav Login</a></nav>
  <main>
    <img src="/assets/logo.png" alt="EdgeFetch Logo">
    <h1>Getting Started</h1>
    <p>EdgeFetch connects outbound from <strong>Home Assistant OS</strong> to Cloudflare Durable Objects. Contact support@example.com or (512) 555-0199 for help.</p>
    <table>
      <tr><th>Variant</th><th>Footprint</th></tr>
      <tr><td>Lite</td><td>9 MB distroless</td></tr>
      <tr><td>Fat</td><td>Chromium + Poppler PDF</td></tr>
    </table>
    <h2>Torque Specifications</h2>
    <p>Tighten the rear axle nut to 35 Nm and verify rotor clearance before riding.</p>
    <pre><code>go test -race ./...</code></pre>
    <a href="/docs/security">Security Model</a>
  </main>
  <footer>Copyright 2026</footer>
</body>
</html>`

	got := ExtractHTML(raw, ExtractOptions{
		BaseURL:         "https://example.com/docs/intro",
		OnlyMainContent: true,
		IncludeLinks:    true,
		IncludeImages:   true,
		IncludeBranding: true,
		RedactPII:       true,
	})

	if strings.Contains(got.Markdown, "Nav Login") || strings.Contains(got.Markdown, "Copyright 2026") {
		t.Fatalf("OnlyMainContent failed to strip nav/footer: %s", got.Markdown)
	}
	if !strings.Contains(got.Markdown, "| Variant | Footprint |") || !strings.Contains(got.Markdown, "| Fat | Chromium + Poppler PDF |") {
		t.Fatalf("expected GFM table in markdown, got:\n%s", got.Markdown)
	}
	if !strings.Contains(got.Markdown, "[REDACTED_EMAIL]") || !strings.Contains(got.Markdown, "[REDACTED_PHONE]") {
		t.Fatalf("expected PII redaction in markdown, got:\n%s", got.Markdown)
	}
	if got.Branding == nil || got.Branding.ThemeColor != "#0f172a" || got.Branding.Logo != "https://example.com/assets/logo.png" {
		t.Fatalf("unexpected branding profile: %+v", got.Branding)
	}
	if len(got.Links) != 1 || got.Links[0] != "https://example.com/docs/security" {
		t.Fatalf("unexpected extracted links: %+v", got.Links)
	}

	reranked := RerankPassages(got.Markdown, "rear axle torque Nm", 220)
	if !strings.Contains(reranked, "35 Nm") {
		t.Fatalf("expected BM25 passage reranker to surface torque section, got:\n%s", reranked)
	}
}

func TestParseLlmsTxtAndCompanionMarkdown(t *testing.T) {
	llmsRaw := `# Cloudflare Developers
> Build serverless apps, Durable Objects, and AI agents at the edge.

## Workers
- [Overview](https://developers.cloudflare.com/workers/): Core runtime concepts
- [Wrangler CLI](/workers/wrangler.md): Local dev and deployments
- [Full Documentation](/llms-full.txt): Complete single-file reference
`
	doc, ok := ParseLlmsTxt(llmsRaw, "https://developers.cloudflare.com/llms.txt")
	if !ok {
		t.Fatal("expected valid llms.txt parse")
	}
	if doc.Title != "Cloudflare Developers" || doc.FullTxtURL != "https://developers.cloudflare.com/llms-full.txt" {
		t.Fatalf("unexpected doc metadata: %+v", doc)
	}
	matched, companion, related := doc.MatchPage("https://developers.cloudflare.com/workers/wrangler")
	if matched == nil || companion != "https://developers.cloudflare.com/workers/wrangler.md" {
		t.Fatalf("expected companion .md match, got matched=%+v companion=%q", matched, companion)
	}
	if len(related) == 0 {
		t.Fatal("expected related section links")
	}
	if _, ok := ParseLlmsTxt("<!DOCTYPE html><html><body>404 Not Found</body></html>", "https://example.com/llms.txt"); ok {
		t.Fatal("HTML soft-404 must be rejected by ParseLlmsTxt")
	}
	if got := CandidateCompanionMarkdownURL("https://docs.example.com/guide/install/"); got != "https://docs.example.com/guide/install.md" {
		t.Fatalf("unexpected candidate companion URL: %q", got)
	}
}

func TestNeedsBrowserRenderAndChallengeDetection(t *testing.T) {
	spa := `<!doctype html><html><head><title>App</title><script type="module" src="/assets/index.js"></script></head><body><div id="root"></div></body></html>`
	if !NeedsBrowserRender(spa) {
		t.Fatal("expected SPA shell to trigger NeedsBrowserRender")
	}
	challenge := `<!doctype html><html><head><title>Just a moment...</title></head><body><div class="cf-turnstile"></div></body></html>`
	if why := DetectRenderedChallenge(challenge); why == "" {
		t.Fatal("expected anti-bot challenge detection")
	}
}

func TestPureGoCompressedPDFExtraction(t *testing.T) {
	var zbuf bytes.Buffer
	zw := zlib.NewWriter(&zbuf)
	_, _ = zw.Write([]byte("BT /F1 12 Tf 72 712 Td (Shimano EP801 Torque Table: 50 Nm) Tj ET"))
	_ = zw.Close()

	var pdf bytes.Buffer
	pdf.WriteString("%PDF-1.7\n1 0 obj << /Length 100 /Filter /FlateDecode >>\nstream\n")
	pdf.Write(zbuf.Bytes())
	pdf.WriteString("\nendstream\nendobj\n%%EOF")

	text, _, err := ExtractPDFText(context.Background(), pdf.Bytes(), 10)
	if err != nil {
		t.Fatalf("ExtractPDFText failed: %v", err)
	}
	if !strings.Contains(text, "Shimano EP801 Torque Table: 50 Nm") {
		t.Fatalf("unexpected PDF extracted text: %q", text)
	}
}

func TestCodeStashPreservesGenericsHeadersAndMultiBackticks(t *testing.T) {
	raw := `<html><body><main>
		<h1>Type Signatures</h1>
		<p>Async hook returns <code>Promise&lt;Array&lt;string&gt;&gt;</code> and supports <code>use ` + "`" + `tick` + "`" + ` literals</code>.</p>
		<pre><code class="language-c">#include &lt;stdio.h&gt;
int main(void) { return 0; }</code></pre>
	</main></body></html>`
	got := ExtractHTML(raw, ExtractOptions{OnlyMainContent: true})
	if !strings.Contains(got.Markdown, "`Promise<Array<string>>`") {
		t.Fatalf("generic angle brackets stripped from inline code: %s", got.Markdown)
	}
	if !strings.Contains(got.Markdown, "``use `tick` literals``") {
		t.Fatalf("multi-backtick inline code span broken: %s", got.Markdown)
	}
	if !strings.Contains(got.Markdown, "```c\n#include <stdio.h>") {
		t.Fatalf("language-tagged C include stripped from fenced block: %s", got.Markdown)
	}

	// Pages without <main>/<article> (like https://example.com) must never leak <head><title> into body Markdown!
	noMain := `<!doctype html><html><head><title>Example Domain</title></head><body><div><h1>Example Domain</h1><p>This domain is for use in documentation examples.</p></div></body></html>`
	gotNoMain := ExtractHTML(noMain, ExtractOptions{OnlyMainContent: true})
	if strings.Contains(gotNoMain.Markdown, "Example DomainThis") || strings.Count(gotNoMain.Markdown, "Example Domain") != 1 {
		t.Fatalf("unexpected <head><title> duplication in <main>-less page:\n%s", gotNoMain.Markdown)
	}
}

func TestResolveHrefPreservesSemicolonlessQueryParams(t *testing.T) {
	raw := `<html><body><main><a href="https://example.com/watch?v=1&amp;currentTime=45&section=2&region=us">Video</a></main></body></html>`
	got := ExtractHTML(raw, ExtractOptions{BaseURL: "https://example.com", OnlyMainContent: true, IncludeLinks: true})
	want := "https://example.com/watch?v=1&currentTime=45&section=2&region=us"
	if len(got.Links) != 1 || got.Links[0] != want {
		t.Fatalf("expected link %q, got %v", want, got.Links)
	}
	if !strings.Contains(got.Markdown, want) {
		t.Fatalf("expected Markdown to preserve %q, got: %s", want, got.Markdown)
	}

	// Invisible Unicode Tag ASCII smuggling (U+E0000..U+E007F) and Bidi overrides must be stripped.
	smuggled := "<html><body><main><p>Clean\U000E0049\U000E0047\u202E text</p></main></body></html>"
	gotClean := ExtractHTML(smuggled, ExtractOptions{OnlyMainContent: true})
	if gotClean.Markdown != "Clean text" {
		t.Fatalf("expected invisible smuggling codepoints stripped, got %q", gotClean.Markdown)
	}

	// Print-stylesheet duplicate URLs immediately following links (`[label](url)(url)`) must collapse to `[label](url)`.
	printDup := `<html><body><main><p>Read our <a href="https://clinicaltrials.gov/about-site/disclaimer">disclaimer</a>(https://clinicaltrials.gov/about-site/disclaimer) before continuing.</p></main></body></html>`
	gotDup := ExtractHTML(printDup, ExtractOptions{OnlyMainContent: true})
	if strings.Contains(gotDup.Markdown, ")(https://clinicaltrials.gov/about-site/disclaimer)") {
		t.Fatalf("expected duplicate print-stylesheet URL collapsed, got: %s", gotDup.Markdown)
	}
}

func TestNeedsBrowserRenderAndExtractHTMLBranches(t *testing.T) {
	// NeedsBrowserRender branches
	if NeedsBrowserRender("") || NeedsBrowserRender("   \n\t ") {
		t.Fatal("empty HTML must not need browser render")
	}
	longBody := "<html><body><p>" + strings.Repeat("content ", 50) + "</p><script>x()</script></body></html>"
	if NeedsBrowserRender(longBody) {
		t.Fatal(">=240 char plain text must not need browser render")
	}
	if NeedsBrowserRender(`<html><body><div id="root"></div></body></html>`) {
		t.Fatal("HTML without <script must not need browser render")
	}
	if !NeedsBrowserRender(`<html><head><script type="module" src="/app.js"></script></head><body><div id="mount"></div></body></html>`) {
		t.Fatal("type=module with <80 chars text should trigger NeedsBrowserRender")
	}
	if NeedsBrowserRender(`<html><head><script type="module" src="/app.js"></script></head><body>` + strings.Repeat("word ", 20) + `</body></html>`) {
		t.Fatal(">=80 chars text without #root shell should not trigger NeedsBrowserRender")
	}
	if !NeedsBrowserRender(`<html><head><script src="/_next/static/app.js"></script></head><body></body></html>`) {
		t.Fatal("/_next/static/ with empty body should trigger NeedsBrowserRender")
	}
	if !NeedsBrowserRender(`<html><head><script src="/@vite/client"></script></head><body></body></html>`) {
		t.Fatal("vite with empty body should trigger NeedsBrowserRender")
	}

	// <article> fallback, Query with MaxChars==0 (16_000 limit), and MaxChars truncation
	artHTML := `<html><head><title>Article Title</title><meta property="og:description" content="OG Desc"><meta name="twitter:image" content="/img/og.png"></head>` +
		`<body><nav><a href="/x">X</a></nav><article><p>This article contains more than thirty-two characters of real body text.</p></article></body></html>`
	artOut := ExtractHTML(artHTML, ExtractOptions{
		BaseURL:         "https://example.com/post",
		OnlyMainContent: true,
		IncludeBranding: true,
		Query:           "article body",
		MaxChars:        0,
	})
	if !strings.Contains(artOut.Markdown, "thirty-two characters") || artOut.Description != "OG Desc" || artOut.Branding.OGImage != "https://example.com/img/og.png" {
		t.Fatalf("unexpected article extraction: %+v", artOut)
	}
	truncOut := ExtractHTML(artHTML, ExtractOptions{OnlyMainContent: true, MaxChars: 12})
	if len(truncOut.Markdown) != 12 || len(truncOut.Text) != 12 {
		t.Fatalf("expected MaxChars=12 truncation, got md=%d txt=%d", len(truncOut.Markdown), len(truncOut.Text))
	}

	// HTML -> Markdown edge cases: ec-line, nested fence, empty code, backtick-edge inline code,
	// empty/jagged tables, data: img, empty/javascript/# links, empty h2, <b>/<em>/<i>/<blockquote>/<li>/<hr>/<br>,
	// unequal reDupLink & reDupInLink.
	richHTML := `<html><head>
		<meta property="og:title" content="OG Fallback Title">
		<meta name="description" content="">
		<link rel="icon" href="">
		<style>
			body { color: #ffffff; background: #000000; border-color: #111111; outline-color: #222222; }
			.c { color: #333333; background: #444444; fill: #555555; stroke: #666666; }
			.d { color: #777777; background: #888888; border-color: #999999; }
			.f { font-family: "VeryLongFontNameThatExceedsFortyEightCharactersInLengthLimit", 'Roboto Mono', sans-serif; }
		</style>
		<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400">
	</head><body><main>
		<pre><code><div class="ec-line">lineA</div><div class="ec-line">lineB</div></code></pre>
		<pre><code>` + "```" + `nested` + "```" + `</code></pre>
		<p>Empty code: <code>   </code> and padded: <code>` + "`x`" + `</code>.</p>
		<table><p>no rows</p></table>
		<table><tr></tr></table>
		<table><tr><th>A</th><th>B</th></tr><tr><td>only1</td></tr></table>
		<img src="data:image/png;base64,AAAA" alt="inline">
		<a href="https://example.com/empty"><span></span></a>
		<a href="javascript:void(0)">JS Link</a>
		<a href="#sec">Anchor Link</a>
		<h2><span></span></h2>
		<p><b>Bold</b><b> </b> <em>Em</em> <i>Italic</i><i> </i></p>
		<blockquote>Quoted line</blockquote>
		<blockquote>   </blockquote>
		<ul><li>Item 1</li><li>   </li></ul>
		<hr><br>
		<p><a href="https://a.com">Different</a>(https://b.com)</p>
		<p><a href="https://a.com">Same (https://a.com)</a> and <a href="https://b.com">Other (https://a.com)</a></p>
		<div data-single='one' data-unquoted=two></div>
	</main></body></html>`
	richOut := ExtractHTML(richHTML, ExtractOptions{
		BaseURL:         "https://example.com",
		OnlyMainContent: true,
		IncludeBranding: true,
	})
	for _, want := range []string{
		"# OG Fallback Title",
		"lineA\nlineB",
		"````\n```nested```\n````",
		"`` `x` ``",
		"| only1 |  |",
		"**Bold**",
		"*Em* *Italic*",
		"> Quoted line",
		"- Item 1",
		"---",
		"[Different](https://a.com)(https://b.com)",
		"[Same](https://a.com)",
		"[Other (https://a.com)](https://b.com)",
	} {
		if !strings.Contains(richOut.Markdown, want) {
			t.Fatalf("expected Markdown to contain %q, got:\n%s", want, richOut.Markdown)
		}
	}
	if len(richOut.Branding.Colors) != 8 {
		t.Fatalf("expected 8 capped non-bw colors, got %v", richOut.Branding.Colors)
	}
	if len(richOut.Branding.Fonts) != 2 || richOut.Branding.Fonts[0] != "Space Grotesk" || richOut.Branding.Fonts[1] != "Roboto Mono" {
		t.Fatalf("unexpected fonts: %v", richOut.Branding.Fonts)
	}

	// Single-quoted & unquoted attributes + missing firstAttr + resolveHref/resolveHTTPSLink edge cases
	attrs := parseAttrs(`<div a='sq' b=uq>`)
	if attrs["a"] != "sq" || attrs["b"] != "uq" || firstAttr(attrs, "missing", "nope") != "" {
		t.Fatalf("unexpected parseAttrs/firstAttr result: %+v", attrs)
	}
	base, _ := url.Parse("https://example.com/dir/")
	if resolveHref("", base) != "" || resolveHref("://bad", base) != "" {
		t.Fatal("resolveHref should reject empty and malformed URLs")
	}
	if resolveHTTPSLink("", base) != "" || resolveHTTPSLink("ftp://files.example.com/a", base) != "" {
		t.Fatal("resolveHTTPSLink should reject empty and ftp URLs")
	}

	// Link (250) and Image (60) extraction caps
	var bigHTML strings.Builder
	bigHTML.WriteString("<html><body><main>")
	for i := 0; i < 260; i++ {
		fmt.Fprintf(&bigHTML, `<a href="https://example.com/l/%d">L%d</a>`, i, i)
	}
	bigHTML.WriteString(`<img src="https://example.com/i/0.png" alt="dup">`)
	for i := 0; i < 65; i++ {
		fmt.Fprintf(&bigHTML, `<img src="https://example.com/i/%d.png" alt="I%d">`, i, i)
	}
	bigHTML.WriteString("</main></body></html>")
	cappedOut := ExtractHTML(bigHTML.String(), ExtractOptions{
		BaseURL:       "https://example.com",
		IncludeLinks:  true,
		IncludeImages: true,
	})
	if len(cappedOut.Links) != 250 || len(cappedOut.Images) != 60 {
		t.Fatalf("expected 250 links & 60 images, got links=%d images=%d", len(cappedOut.Links), len(cappedOut.Images))
	}
}

func TestRerankPassagesAndRedactPIIBranches(t *testing.T) {
	if RerankPassages("", "query", 100) != "" || RerankPassages("hello", "   ", 100) != "hello" {
		t.Fatal("RerankPassages empty query/doc failed")
	}
	if RerankPassages("hello world", "the and for", 5) != "hello" {
		t.Fatal("stopword-only query with maxChars=5 should truncate to 5")
	}
	if RerankPassages("hello", "the and for", 20) != "hello" {
		t.Fatal("stopword-only query within maxChars should return doc")
	}
	if RerankPassages("single block text", "block", 6) != "single" || RerankPassages("single", "single", 0) != "single" {
		t.Fatal("single-chunk RerankPassages branches failed")
	}

	// Multi-chunk: blank blocks, out-of-order higher-scored chunk sorted back, skipping oversized chunk to fit smaller one, exact budget break
	doc := "Alpha intro paragraph.\n\n\n\n" +
		"Unrelated filler block " + strings.Repeat("filler ", 15) + "\n\n" +
		"## Target\n\nTarget torque spec 42 Nm here.\n\n" +
		"Small target note."
	got := RerankPassages(doc, "target", 60)
	if !strings.Contains(got, "## Target") {
		t.Fatalf("expected target chunk selected, got %q", got)
	}

	// Reading-order preservation across >= 2 selected chunks where later chunk scores higher
	doc2 := "alpha mention\n\n\n\nalpha alpha alpha exact match\n\nomega unrelated"
	got2 := RerankPassages(doc2, "alpha", 200)
	idxFirst := strings.Index(got2, "alpha mention")
	idxSecond := strings.Index(got2, "alpha alpha alpha")
	if idxFirst < 0 || idxSecond < 0 || idxFirst > idxSecond {
		t.Fatalf("expected reading order preserved across selected chunks, got %q", got2)
	}
	// Exact budget break: first chunk len 13 + 2 = 15 >= maxChars 15
	got3 := RerankPassages("alpha chunk01\n\nalpha chunk02", "alpha", 15)
	if got3 != "alpha chunk01" {
		t.Fatalf("expected budget break after first chunk, got %q", got3)
	}

	// RedactPII Luhn-valid (including >9 doubled digits) vs Luhn-invalid & isLuhnCard bounds
	redacted := RedactPII("Valid: 5555-5555-5555-4444 Invalid: 4111-1111-1111-1112")
	if !strings.Contains(redacted, "Valid: [REDACTED_CARD]") || !strings.Contains(redacted, "Invalid: 4111-1111-1111-1112") {
		t.Fatalf("unexpected RedactPII card handling: %q", redacted)
	}
	if isLuhnCard("123") || isLuhnCard("12345678901234567890") {
		t.Fatal("isLuhnCard length bounds failed")
	}
}

func TestJsrTrailingEmptyCodeAndProductHeuristicSchema(t *testing.T) {
	// 1. JSR `<pre class="highlight"><code>...</code><button class="copyButton" data-copy="...">...</button><code></code></pre>`
	jsrHTML := `<!doctype html><html><head><title>@std/path - JSR</title></head><body><main>
<h1>@std/path</h1>
<h2>Path Properties</h2>
<pre class="highlight"><code><span class="pl-k">import</span> * <span class="pl-k">as</span> path <span class="pl-k">from</span> <span class="pl-s">"@std/path"</span>;
path.isAbsolute("/home/user");
</code><button class="copyButton" data-copy="import * as path from &quot;@std/path&quot;;"><svg><path d="M0 0"></path></svg></button><code></code></pre>
</main></body></html>`
	jsrDoc := ExtractHTMLDocumentFull(jsrHTML, FullExtractOptions{
		BaseURL:         "https://jsr.io/@std/path",
		OnlyMainContent: true,
	})
	if !strings.Contains(jsrDoc.Markdown, `import * as path from "@std/path";`) || strings.Contains(jsrDoc.Markdown, "```\n\n```") {
		t.Fatalf("expected JSR code block preserved without empty fence, got:\n%s", jsrDoc.Markdown)
	}

	// 2. Schema.org `Product` `offers` + nested `brand` object + fenced JSON scalar extraction in `ExtractStructuredJSONFromPageWithDiagnostics`
	shopHTML := `<!doctype html><html><head><title>Wool Runner NZ</title>
<script type="application/ld+json">{"@context":"https://schema.org","@type":"Product","name":"Wool Runner NZ","brand":{"@type":"Brand","name":"Allbirds"},"sku":"WR-NZ-10","offers":[{"@type":"Offer","price":"112.00","priceCurrency":"USD","availability":"https://schema.org/InStock"}]}</script>
</head><body><main><h1>Wool Runner NZ</h1><p>Waterproof merino sneaker.</p></main></body></html>`
	shopDoc := ExtractHTMLDocumentFull(shopHTML, FullExtractOptions{
		BaseURL:         "https://www.allbirds.com/products/wool-runner-nz",
		OnlyMainContent: true,
	})
	schema := map[string]any{
		"type": "object",
		"properties": map[string]any{
			"title":    map[string]any{"type": "string"},
			"brand":    map[string]any{"type": "string"},
			"price":    map[string]any{"type": "number"},
			"currency": map[string]any{"type": "string"},
			"inStock":  map[string]any{"type": "boolean"},
		},
	}
	res, _, unfilled := ExtractStructuredJSONFromPageWithDiagnostics(shopHTML, shopDoc, schema, "")
	if len(unfilled) != 0 {
		t.Fatalf("expected 0 unfilled product schema fields, got %v (res=%+v)", unfilled, res)
	}
	if res["price"] != float64(112) || res["currency"] != "USD" || res["brand"] != "Allbirds" || res["inStock"] != true {
		t.Fatalf("unexpected extracted product schema JSON: %+v", res)
	}

	// 3. Fenced JSON scalar fallback (e.g. `agent` heuristic extraction over npm JSON markdown)
	npmDoc := ExtractedDocumentFull{
		Title:    "zod@4.6.7",
		Markdown: "# zod@4.6.7\n\n```json\n{\n  \"name\": \"zod\",\n  \"version\": \"4.6.7\",\n  \"license\": \"MIT\"\n}\n```",
	}
	npmSchema := map[string]any{
		"type": "object",
		"properties": map[string]any{
			"version": map[string]any{"type": "string"},
			"license": map[string]any{"type": "string"},
		},
	}
	npmRes, _, npmUnfilled := ExtractStructuredJSONFromPageWithDiagnostics("", npmDoc, npmSchema, "")
	if len(npmUnfilled) != 0 || npmRes["version"] != "4.6.7" || npmRes["license"] != "MIT" {
		t.Fatalf("expected fenced JSON scalar extraction for version & license, got res=%+v unfilled=%v", npmRes, npmUnfilled)
	}
}
