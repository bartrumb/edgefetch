package classify

import (
	"net/http"
	"strings"
	"testing"
)

func TestWAFSignatureCatalogAndAntiFalsePositiveGuardrails(t *testing.T) {
	t.Run("detects all 7 WAF vendors accurately", func(t *testing.T) {
		vendors := []struct {
			name       string
			status     int
			headers    map[string]string
			body       string
			wantVendor string
		}{
			{
				name:       "cloudflare header",
				status:     403,
				headers:    map[string]string{"cf-mitigated": "challenge"},
				body:       "<html><body>Just a moment...</body></html>",
				wantVendor: "cloudflare",
			},
			{
				name:       "akamai reference 18",
				status:     403,
				headers:    map[string]string{"server": "AkamaiGHost"},
				body:       "<html><head><title>Access Denied</title></head><body><h1>Access Denied</h1>Reference #18.4f2a1002.1763599000.abcdef</body></html>",
				wantVendor: "akamai",
			},
			{
				name:       "datadome interstitial",
				status:     403,
				headers:    map[string]string{"x-datadome": "protected"},
				body:       `<html><body><iframe src="https://geo.captcha-delivery.com/captcha/?initialCid=123"></iframe></body></html>`,
				wantVendor: "datadome",
			},
			{
				name:       "perimeterx human challenge",
				status:     403,
				headers:    map[string]string{"set-cookie": "_pxhd=abc123; Path=/"},
				body:       `<html><body><div id="px-captcha"></div><script>window._pxAppId='PX12345';</script></body></html>`,
				wantVendor: "perimeterx",
			},
			{
				name:       "aws waf captcha",
				status:     202,
				headers:    map[string]string{"x-amzn-waf-action": "captcha"},
				body:       `<html><body><div id="awswaf-captcha"></div></body></html>`,
				wantVendor: "aws-waf",
			},
			{
				name:       "imperva incapsula",
				status:     200,
				headers:    map[string]string{"set-cookie": "visid_incap_999=xyz"},
				body:       `<html><body><iframe src="/_Incapsula_Resource?SWJIYLWA=719d34d31c8e3a6e6fffd425f7e032f3"></iframe></body></html>`,
				wantVendor: "imperva",
			},
			{
				name:       "vercel firewall",
				status:     403,
				headers:    map[string]string{"x-vercel-mitigated": "challenge"},
				body:       `<html><body>Security Checkpoint</body></html>`,
				wantVendor: "vercel",
			},
		}

		for _, tc := range vendors {
			h := http.Header{}
			for k, v := range tc.headers {
				h.Set(k, v)
			}
			m := ClassifyWAF(tc.status, h, []byte(tc.body))
			if m == nil {
				t.Fatalf("%s: expected WAFMatch, got nil", tc.name)
			}
			if m.Vendor != tc.wantVendor {
				t.Fatalf("%s: got vendor %q, want %q", tc.name, m.Vendor, tc.wantVendor)
			}
			out, _ := Classify(KindScrape, tc.status, h, []byte(tc.body))
			if out != OutcomeChallenge {
				t.Fatalf("%s: expected OutcomeChallenge from Classify, got %q", tc.name, out)
			}
		}
	})

	t.Run("anti-false-positive guardrails never trigger on Turnstile docs, footer CAPTCHA blogs, or Schema.org articles", func(t *testing.T) {
		// 1. Documentation page quoting Turnstile / _cf_chl_opt / Verify you are human inside <pre><code> + >250 words
		turnstileDocs := `<!doctype html><html><head><title>Cloudflare Turnstile Integration Guide</title></head><body>` +
			`<main><h1>Turnstile Server-Side Validation</h1>` +
			`<p>` + strings.Repeat("Turnstile replaces intrusive CAPTCHAs with cryptographic proof and privacy-preserving widget tokens. ", 25) + `</p>` +
			`<pre><code>&lt;div class="cf-turnstile" data-sitekey="1x00000000000000000000AA"&gt;&lt;/div&gt;
&lt;script src="https://challenges.cloudflare.com/turnstile/v0/api.js"&gt;&lt;/script&gt;
window._cf_chl_opt = { chlPageData: "demo" }; // Verify you are human</code></pre>` +
			`</main></body></html>`
		if got := ClassifyWAF(200, http.Header{"Content-Type": []string{"text/html"}}, []byte(turnstileDocs)); got != nil {
			t.Fatalf("Turnstile documentation page must NOT false-positive as a challenge, got: %+v", got)
		}

		// 2. Short job posting (<150 words) with valid Schema.org JobPosting JSON-LD AND a footer g-recaptcha newsletter form!
		jobWithFooterCaptcha := `<!doctype html><html><head><title>Staff Engineer</title>` +
			`<script type="application/ld+json">{"@context":"https://schema.org","@type":"JobPosting","title":"Staff Engineer"}</script>` +
			`</head><body><main><h1>Staff Engineer</h1><p>Build distributed consensus systems in Go.</p></main>` +
			`<footer><form><div class="g-recaptcha" data-sitekey="abc"></div></form></footer></body></html>`
		if got := ClassifyWAF(200, http.Header{"Content-Type": []string{"text/html"}}, []byte(jobWithFooterCaptcha)); got != nil {
			t.Fatalf("JobPosting JSON-LD page with footer reCAPTCHA must NOT false-positive, got: %+v", got)
		}

		// 3. Site page with rich <nav> (>=4 links) + >=120 words and h-captcha contact widget
		navSite := `<!doctype html><html><head><title>Contact Support</title></head><body>` +
			`<nav><a href="/docs">Docs</a><a href="/pricing">Pricing</a><a href="/blog">Blog</a><a href="/careers">Careers</a></nav>` +
			`<main><h1>Contact Support</h1><p>` + strings.Repeat("Reach out to our platform engineering support team for architecture reviews. ", 15) + `</p>` +
			`<div class="h-captcha"></div></main></body></html>`
		if got := ClassifyWAF(200, http.Header{"Content-Type": []string{"text/html"}}, []byte(navSite)); got != nil {
			t.Fatalf("Page with rich <nav> and >=120 words must NOT false-positive, got: %+v", got)
		}
	})
}
