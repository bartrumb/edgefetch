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

func TestClassifyWAFLayer1HeadersAndBodyCaps(t *testing.T) {
	t.Run("layer 1 header variants and negative cases", func(t *testing.T) {
		cases := []struct {
			name     string
			status   int
			headers  http.Header
			body     string
			wantNil  bool
			wantVend string
			wantCat  string
		}{
			{
				name:     "cf-mitigated whitespace defaults to challenge",
				status:   403,
				headers:  http.Header{"Cf-Mitigated": []string{"   "}},
				wantVend: "cloudflare",
				wantCat:  "challenge",
			},
			{
				name:     "cf-mitigated block",
				status:   403,
				headers:  http.Header{"Cf-Mitigated": []string{"block"}},
				wantVend: "cloudflare",
				wantCat:  "waf_block",
			},
			{
				name:     "aws-waf challenge",
				status:   403,
				headers:  http.Header{"X-Amzn-Waf-Action": []string{"challenge"}},
				wantVend: "aws-waf",
				wantCat:  "challenge",
			},
			{
				name:     "aws-waf block",
				status:   403,
				headers:  http.Header{"X-Amzn-Waf-Action": []string{"block"}},
				wantVend: "aws-waf",
				wantCat:  "waf_block",
			},
			{
				name:    "aws-waf allow does not match",
				status:  200,
				headers: http.Header{"X-Amzn-Waf-Action": []string{"allow"}},
				wantNil: true,
			},
			{
				name:     "vercel deny",
				status:   403,
				headers:  http.Header{"X-Vercel-Mitigated": []string{"deny"}},
				wantVend: "vercel",
				wantCat:  "waf_block",
			},
			{
				name:     "vercel block",
				status:   403,
				headers:  http.Header{"X-Vercel-Mitigated": []string{"block"}},
				wantVend: "vercel",
				wantCat:  "waf_block",
			},
			{
				name:     "datadome x-dd-b on 401",
				status:   401,
				headers:  http.Header{"X-Dd-B": []string{"1"}},
				wantVend: "datadome",
				wantCat:  "challenge",
			},
			{
				name:    "datadome header ignored on 200",
				status:  200,
				headers: http.Header{"X-Datadome": []string{"protected"}},
				wantNil: true,
			},
			{
				name:     "kasada 429",
				status:   429,
				headers:  http.Header{"X-Kpsdk-Ct": []string{"token-abc"}},
				wantVend: "kasada",
				wantCat:  "challenge",
			},
			{
				name:     "kasada 403",
				status:   403,
				headers:  http.Header{"X-Kpsdk-Ct": []string{"token-abc"}},
				wantVend: "kasada",
				wantCat:  "challenge",
			},
			{
				name:    "kasada ignored on 200",
				status:  200,
				headers: http.Header{"X-Kpsdk-Ct": []string{"token-abc"}},
				wantNil: true,
			},
			{
				name:     "perimeterx x-px-blocked",
				status:   403,
				headers:  http.Header{"X-Px-Blocked": []string{"1"}},
				wantVend: "perimeterx",
				wantCat:  "challenge",
			},
			{
				name:    "nil headers and empty body",
				status:  403,
				headers: nil,
				body:    "",
				wantNil: true,
			},
		}

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				got := ClassifyWAF(tc.status, tc.headers, []byte(tc.body))
				if tc.wantNil {
					if got != nil {
						t.Fatalf("expected nil, got %+v", got)
					}
					return
				}
				if got == nil || got.Vendor != tc.wantVend || got.Category != tc.wantCat {
					t.Fatalf("got %+v, want vendor=%q category=%q", got, tc.wantVend, tc.wantCat)
				}
			})
		}
	})

	t.Run("body length caps and structural content vetos", func(t *testing.T) {
		// 200 OK > 49,152 bytes exits before Layer 3 scan
		big200 := "<title>Just a moment...</title>" + strings.Repeat("a", 50_000)
		if got := ClassifyWAF(200, http.Header{}, []byte(big200)); got != nil {
			t.Fatalf("expected 200 >48KiB body to skip WAF DOM scan, got %+v", got)
		}

		// Non-2xx > 98,304 bytes caps sample at 98,304 bytes
		cleanPrefix := strings.Repeat("word ", 19_800) // 99,000 bytes
		if got := ClassifyWAF(403, http.Header{}, []byte(cleanPrefix+"<title>Just a moment...</title>")); got != nil {
			t.Fatalf("expected signature past 96KiB cap to be ignored, got %+v", got)
		}
		if got := ClassifyWAF(403, http.Header{}, []byte("<title>Just a moment...</title>"+cleanPrefix)); got == nil || got.Vendor != "cloudflare" {
			t.Fatalf("expected signature within first 96KiB of large 403 to match cloudflare, got %+v", got)
		}

		// >= 250 plain words without <main>/<article>/<h2>/<nav>/JSON-LD triggers hasStructuralContentVeto line 73
		prose250 := "<html><head><title>Verify you are human</title></head><body><p>" +
			strings.Repeat("documentation ", 255) +
			`</p><div class="cf-turnstile"></div></body></html>`
		if got := ClassifyWAF(200, http.Header{}, []byte(prose250)); got != nil {
			t.Fatalf("expected >=250 visibleWords veto on 200 OK, got %+v", got)
		}

		// >= 2 <h2>/<h3> subheadings and >= 100 visible words (< 250) triggers veto line 76
		subheadingsVeto := "<html><head><title>Verify you are human</title></head><body>" +
			"<h2>Overview</h2><h3>Details</h3><p>" + strings.Repeat("guide ", 105) +
			`</p><div class="cf-turnstile"></div></body></html>`
		if got := ClassifyWAF(200, http.Header{}, []byte(subheadingsVeto)); got != nil {
			t.Fatalf("expected >=2 subheadings + >=100 words veto on 200 OK, got %+v", got)
		}

		// 120..249 plain words on 200 OK without structural vetos triggers visibleWords >= 120 guard line 184
		words130 := "<html><head><title>Verify you are human</title></head><body><p>" +
			strings.Repeat("article ", 130) +
			`</p><div class="cf-turnstile"></div></body></html>`
		if got := ClassifyWAF(200, http.Header{}, []byte(words130)); got != nil {
			t.Fatalf("expected >=120 visibleWords on 200 OK to suppress WAF match, got %+v", got)
		}
	})
}

func TestClassifyWAFLayer3DOMDetectors(t *testing.T) {
	cases := []struct {
		name     string
		status   int
		headers  http.Header
		body     string
		wantNil  bool
		wantVend string
		wantCat  string
	}{
		{
			name:     "cloudflare title just a moment",
			status:   403,
			body:     `<html><head><title>Just a moment...</title></head><body>Loading</body></html>`,
			wantVend: "cloudflare",
			wantCat:  "challenge",
		},
		{
			name:     "cloudflare _cf_chl_opt + challenge-platform",
			status:   403,
			body:     `<html><body><script>window._cf_chl_opt={};</script><script src="/cdn-cgi/challenge-platform/h/b/orchestrate/chl_page/v1"></script></body></html>`,
			wantVend: "cloudflare",
			wantCat:  "challenge",
		},
		{
			name:     "cloudflare generic title + turnstile",
			status:   403,
			body:     `<html><head><title>Verify you are human</title></head><body><script src="https://challenges.cloudflare.com/turnstile/v0/api.js"></script></body></html>`,
			wantVend: "cloudflare",
			wantCat:  "challenge",
		},
		{
			name:     "datadome geo.captcha-delivery.com without header",
			status:   403,
			body:     `<html><body><iframe src="https://geo.captcha-delivery.com/captcha/"></iframe></body></html>`,
			wantVend: "datadome",
			wantCat:  "challenge",
		},
		{
			name:     "datadome ct.captcha-delivery.com without header",
			status:   200,
			body:     `<html><body><script src="https://ct.captcha-delivery.com/c.js"></script></body></html>`,
			wantVend: "datadome",
			wantCat:  "challenge",
		},
		{
			name:     "perimeterx appId + blockScript",
			status:   403,
			body:     `<html><body><script>window.px={"appId":"PX12345","blockScript":"/abc/captcha.js"};</script></body></html>`,
			wantVend: "perimeterx",
			wantCat:  "challenge",
		},
		{
			name:     "akamai _abck cookie + 403 + edgesuite.net",
			status:   403,
			headers:  http.Header{"Set-Cookie": []string{"_abck=xyz; Path=/"}},
			body:     `<html><body>Access Denied via a123.edgesuite.net</body></html>`,
			wantVend: "akamai",
			wantCat:  "waf_block",
		},
		{
			name:     "aws-waf awswafintegration DOM without header",
			status:   202,
			body:     `<html><body><script>AwsWafIntegration.forceRefreshToken()</script></body></html>`,
			wantVend: "aws-waf",
			wantCat:  "challenge",
		},
		{
			name:     "aws-waf aws-waf-token DOM without header",
			status:   405,
			body:     `<html><body><div data-token="aws-waf-token"></div></body></html>`,
			wantVend: "aws-waf",
			wantCat:  "challenge",
		},
		{
			name:     "imperva visid_incap + incident id",
			status:   200,
			headers:  http.Header{"Set-Cookie": []string{"visid_incap_1=abc"}},
			body:     `<html><body>Incapsula incident ID: 12345-67890</body></html>`,
			wantVend: "imperva",
			wantCat:  "challenge",
		},
		{
			name:     "fastly 403 block page with server fastly",
			status:   403,
			headers:  http.Header{"Server": []string{"fastly"}},
			body:     `<html><body>Request blocked by edge policy.</body></html>`,
			wantVend: "fastly",
			wantCat:  "waf_block",
		},
		{
			name:     "fastly 403 block page with x-served-by",
			status:   403,
			headers:  http.Header{"X-Served-By": []string{"cache-iad-kiad70001"}},
			body:     `<html><body>Request blocked.</body></html>`,
			wantVend: "fastly",
			wantCat:  "waf_block",
		},
		{
			name:    "fastly unknown domain is not WAF block",
			status:  403,
			headers: http.Header{"Server": []string{"fastly"}},
			body:    `<html><body>Fastly error: unknown domain example.com. Request blocked.</body></html>`,
			wantNil: true,
		},
		{
			name:    "fastly 200 is not fastly 403 block",
			status:  200,
			headers: http.Header{"Server": []string{"fastly"}},
			body:    `<html><body>Request blocked.</body></html>`,
			wantNil: true,
		},
		{
			name:     "generic title + g-recaptcha",
			status:   403,
			body:     `<html><head><title>Verify you are human</title></head><body><div class="g-recaptcha"></div></body></html>`,
			wantVend: "generic",
			wantCat:  "challenge",
		},
		{
			name:     "generic title + h-captcha",
			status:   200,
			body:     `<html><head><title>Human Verification</title></head><body><div class="h-captcha"></div></body></html>`,
			wantVend: "generic",
			wantCat:  "challenge",
		},
		{
			name:     "generic title + cf-turnstile",
			status:   403,
			body:     `<html><head><title>Security Check</title></head><body><div class="cf-turnstile"></div></body></html>`,
			wantVend: "generic",
			wantCat:  "challenge",
		},
		{
			name:    "generic title + captcha >= 80 words suppressed",
			status:  403,
			body:    `<html><head><title>Security Check</title></head><body><p>` + strings.Repeat("word ", 85) + `</p><div class="g-recaptcha"></div></body></html>`,
			wantNil: true,
		},
		{
			name:     "generic js check checking your browser before accessing",
			status:   200,
			body:     `<html><body>Checking your browser before accessing example.com</body></html>`,
			wantVend: "generic",
			wantCat:  "challenge",
		},
		{
			name:     "generic js check please wait while we check your browser",
			status:   200,
			body:     `<html><body>Please wait while we check your browser...</body></html>`,
			wantVend: "generic",
			wantCat:  "challenge",
		},
		{
			name:     "generic anubis pow interstitial",
			status:   200,
			body:     `<html><body>Making sure you're not a bot! Powered by Anubis.</body></html>`,
			wantVend: "generic",
			wantCat:  "challenge",
		},
		{
			name:    "anubis mention alone does not trigger",
			status:  200,
			body:    `<html><body>Anubis documentation page</body></html>`,
			wantNil: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ClassifyWAF(tc.status, tc.headers, []byte(tc.body))
			if tc.wantNil {
				if got != nil {
					t.Fatalf("expected nil, got %+v", got)
				}
				return
			}
			if got == nil || got.Vendor != tc.wantVend || got.Category != tc.wantCat {
				t.Fatalf("got %+v, want vendor=%q category=%q", got, tc.wantVend, tc.wantCat)
			}
		})
	}
}
