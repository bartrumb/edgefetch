package extract

import (
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
