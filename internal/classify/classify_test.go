package classify

import (
	"net/http"
	"strings"
	"testing"
)

func TestClassifyOutcomes(t *testing.T) {
	// Table-driven testing (`[]struct{...}` + `t.Run`) is the standard Go idiom for exhaustive edge-case coverage.
	cases := []struct {
		name        string
		kind        Kind
		status      int
		contentType string
		cfMitigated string
		body        string
		want        Outcome
		wantProblem string
	}{
		{"feed valid products array", KindFeed, 200, "application/json", "", `{"products":[{"id":1}]}`, OutcomeOK, ""},
		{"feed empty products array", KindFeed, 200, "application/json", "", `{"products":[]}`, OutcomeOK, ""},
		{"feed challenge header wins over 200", KindFeed, 200, "text/html", "challenge", "<html></html>", OutcomeChallenge, "Cloudflare challenge (cf-mitigated)"},
		{"feed soft-block HTML 200", KindFeed, 200, "text/html", "", "<html>blocked</html>", OutcomeError, "not JSON (text/html)"},
		{"feed invalid json no content-type", KindFeed, 200, "", "", "not-json", OutcomeError, "not JSON (null)"},
		{"feed JSON null", KindFeed, 200, "application/json", "", "null", OutcomeError, "feed is JSON null"},
		{"feed JSON array root", KindFeed, 200, "application/json", "", `[1,2]`, OutcomeError, "no products array"},
		{"feed missing products key", KindFeed, 200, "application/json", "", `{"items":[]}`, OutcomeError, "no products array"},
		{"feed 500 error", KindFeed, 500, "application/json", "", `{}`, OutcomeError, "HTTP 500"},
		{"generic json valid", KindJSON, 200, "application/json", "", `[1,2,3]`, OutcomeOK, ""},
		{"generic json invalid", KindJSON, 200, "text/plain", "", `nope`, OutcomeError, "not JSON (text/plain)"},
		{"generic json 404", KindJSON, 404, "application/json", "", `{}`, OutcomeError, "HTTP 404"},
		{"page 200 html", KindPage, 200, "text/html; charset=utf-8", "", "<html>ok</html>", OutcomeOK, ""},
		{"page 200 markdown for agents", KindPage, 200, "text/markdown; charset=utf-8", "", "# Origin Markdown\n", OutcomeOK, ""},
		{"page 200 x-markdown", KindPage, 200, "text/x-markdown", "", "# Origin Markdown\n", OutcomeOK, ""},
		{"page 200 non-html skipped", KindPage, 200, "image/png", "", "\x89PNG", OutcomeSkip, ""},
		{"page 402 payment required", KindPage, 402, "application/json", "", `{"x402Version":1}`, OutcomePaymentRequired, "http 402 payment required"},
		{"page 404 not_found", KindPage, 404, "text/html", "", "not found", OutcomeNotFound, ""},
		{"page 410 gone", KindPage, 410, "text/html", "", "gone", OutcomeGone, ""},
		{"page 429 stops host", KindPage, 429, "text/plain", "", "slow down", OutcomeStop, "HTTP 429"},
		{"page 500 skipped", KindPage, 500, "text/html", "", "oops", OutcomeSkip, ""},
		{"text 200 xml", KindText, 200, "application/xml", "", "<urlset/>", OutcomeOK, ""},
		{"text 404 skipped", KindText, 404, "text/plain", "", "missing", OutcomeSkip, ""},
		{"text 403 stops host", KindText, 403, "text/plain", "", "denied", OutcomeStop, "HTTP 403"},
		{"catalog 200 ok", KindCatalog, 200, "text/html", "", "<html></html>", OutcomeOK, ""},
		{"catalog 503 errors", KindCatalog, 503, "text/html", "", "down", OutcomeError, "HTTP 503"},
		{"scrape 200 ok", KindScrape, 200, "text/html", "", "<main>hi</main>", OutcomeOK, ""},
		{"scrape 402 x402 payment required", KindScrape, 402, "application/json", "", `{"accepts":[{"maxAmountRequired":"2000"}]}`, OutcomePaymentRequired, "http 402 payment required"},
		{"scrape 429 stop", KindScrape, 429, "text/plain", "", "rate limited", OutcomeStop, "HTTP 429"},
		{"scrape 404 not_found", KindScrape, 404, "text/html", "", "missing", OutcomeNotFound, "HTTP 404"},
		{"scrape 500 error", KindScrape, 500, "text/html", "", "err", OutcomeError, "HTTP 500"},
		{"render 200 ok", KindRender, 200, "text/html", "", "<html></html>", OutcomeOK, ""},
		{"render 404 not_found", KindRender, 404, "text/html", "", "missing", OutcomeNotFound, "HTTP 404"},
		{"pdf 200 content-type pdf", KindPDF, 200, "application/pdf", "", "binary", OutcomeOK, ""},
		{"pdf 200 magic bytes octet-stream", KindPDF, 200, "application/octet-stream", "", "%PDF-1.7 ...", OutcomeOK, ""},
		{"pdf 200 html soft-404 error", KindPDF, 200, "text/html", "", "<html>login</html>", OutcomeError, "not a PDF (text/html)"},
		{"pdf 403 stop", KindPDF, 403, "text/plain", "", "denied", OutcomeStop, "HTTP 403"},
		{"pdf 410 gone", KindPDF, 410, "text/plain", "", "gone", OutcomeGone, "HTTP 410"},
		{"pdf 502 error", KindPDF, 502, "text/plain", "", "bad gateway", OutcomeError, "HTTP 502"},
		{"binary 200 ok", KindBinary, 200, "application/octet-stream", "", "\x00\x01\x02", OutcomeOK, ""},
		{"binary 429 stop", KindBinary, 429, "text/plain", "", "slow", OutcomeStop, "HTTP 429"},
		{"binary 404 not_found", KindBinary, 404, "text/plain", "", "missing", OutcomeNotFound, "HTTP 404"},
		{"binary 410 gone", KindBinary, 410, "text/plain", "", "gone", OutcomeGone, "HTTP 410"},
		{"binary 403 stop", KindBinary, 403, "text/plain", "", "denied", OutcomeStop, "HTTP 403"},
		{"binary 503 stop", KindBinary, 503, "text/plain", "", "busy", OutcomeStop, "HTTP 503"},
		{"binary 500 error", KindBinary, 500, "text/plain", "", "boom", OutcomeError, "HTTP 500"},
		{"text 429 stop", KindText, 429, "text/plain", "", "slow", OutcomeStop, "HTTP 429"},
		{"text 503 stop", KindText, 503, "text/plain", "", "busy", OutcomeStop, "HTTP 503"},
		{"page 403 stop", KindPage, 403, "text/html", "", "denied", OutcomeStop, "HTTP 403"},
		{"page 503 stop", KindPage, 503, "text/html", "", "busy", OutcomeStop, "HTTP 503"},
		{"page 199 skip", KindPage, 199, "text/html", "", "", OutcomeSkip, ""},
		{"page 300 skip", KindPage, 300, "text/html", "", "", OutcomeSkip, ""},
		{"page 204 html ok", KindPage, 204, "text/html", "", "", OutcomeOK, ""},
		{"json empty body error", KindJSON, 200, "application/json", "", "", OutcomeError, "not JSON (application/json)"},
		{"scrape 403 stop", KindScrape, 403, "text/html", "", "denied", OutcomeStop, "HTTP 403"},
		{"scrape 503 stop", KindScrape, 503, "text/html", "", "busy", OutcomeStop, "HTTP 503"},
		{"scrape 410 gone", KindScrape, 410, "text/html", "", "gone", OutcomeGone, "HTTP 410"},
		{"render 403 stop", KindRender, 403, "text/html", "", "denied", OutcomeStop, "HTTP 403"},
		{"render 503 stop", KindRender, 503, "text/html", "", "busy", OutcomeStop, "HTTP 503"},
		{"render 410 gone", KindRender, 410, "text/html", "", "gone", OutcomeGone, "HTTP 410"},
		{"pdf 429 stop", KindPDF, 429, "text/plain", "", "slow", OutcomeStop, "HTTP 429"},
		{"pdf 503 stop", KindPDF, 503, "text/plain", "", "busy", OutcomeStop, "HTTP 503"},
		{"pdf 404 not_found", KindPDF, 404, "text/plain", "", "missing", OutcomeNotFound, "HTTP 404"},
		{"pdf 200 >1024 prefix match ok", KindPDF, 200, "application/octet-stream", "", "%PDF-1.7 " + strings.Repeat("x", 2040), OutcomeOK, ""},
		{"pdf 200 >1024 magic past cap error", KindPDF, 200, "application/octet-stream", "", strings.Repeat("x", 1100) + "%PDF-1.7", OutcomeError, "not a PDF (application/octet-stream)"},
		{"feed products non-array string", KindFeed, 200, "application/json", "", `{"products":"bad"}`, OutcomeError, "no products array"},
		{"feed products null", KindFeed, 200, "application/json", "", `{"products":null}`, OutcomeError, "no products array"},
		{"unknown kind defaults to feed", Kind("custom"), 200, "application/json", "", `{"products":[{"id":1}]}`, OutcomeOK, ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := http.Header{}
			if tc.contentType != "" {
				h.Set("content-type", tc.contentType)
			}
			if tc.cfMitigated != "" {
				h.Set("cf-mitigated", tc.cfMitigated)
			}
			got, prob := Classify(tc.kind, tc.status, h, []byte(tc.body))
			if got != tc.want {
				t.Fatalf("Classify() outcome = %q, want %q (problem=%q)", got, tc.want, prob)
			}
			if tc.wantProblem != "" && prob != tc.wantProblem {
				t.Fatalf("Classify() problem = %q, want %q", prob, tc.wantProblem)
			}
		})
	}
}

func TestAcceptForAndStopsHost(t *testing.T) {
	acceptCases := []struct {
		kind    Kind
		req     string
		want    string
		wantErr bool
	}{
		{KindFeed, "", "application/json", false},
		{KindJSON, "", "application/json", false},
		{KindPage, "", DefaultAgentPageAccept, false},
		{KindCatalog, "", "text/html", false},
		{KindRender, "", "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8", false},
		{KindScrape, "", DefaultAgentPageAccept, false},
		{KindScrape, "text/markdown", "text/markdown", false},
		{KindPDF, "", "application/pdf,*/*;q=0.8", false},
		{KindBinary, "", "*/*", false},
		{KindBinary, "image/webp", "image/webp", false},
		{KindText, "text/html", "text/html", false},
		{KindText, "text/markdown", "text/markdown", false},
		{KindText, "text/x-markdown", "text/x-markdown", false},
		{KindText, "application/xml", "application/xml", false},
		{KindText, "text/xml", "text/xml", false},
		{KindText, "application/rss+xml", "application/rss+xml", false},
		{KindText, "application/atom+xml", "application/atom+xml", false},
		{KindText, "application/json", "application/json", false},
		{KindText, "text/calendar", "text/calendar", false},
		{KindText, "text/plain", "text/plain", false},
		{KindText, "", "", true},
		{KindText, "*/*", "", true},
		{"", "", "", true},
		{Kind("bogus"), "", "", true},
	}
	for _, tc := range acceptCases {
		got, err := AcceptFor(tc.kind, tc.req)
		if tc.wantErr {
			if err == nil {
				t.Fatalf("AcceptFor(%q, %q) expected error, got %q", tc.kind, tc.req, got)
			}
			continue
		}
		if err != nil || got != tc.want {
			t.Fatalf("AcceptFor(%q, %q) = (%q, %v), want (%q, nil)", tc.kind, tc.req, got, err, tc.want)
		}
	}

	if !StopsHost(KindScrape, OutcomeChallenge) || !StopsHost(KindScrape, OutcomeStop) || !StopsHost(KindPage, OutcomeRateLimited) || !StopsHost(KindPage, OutcomePaymentRequired) {
		t.Fatal("Challenge, Stop, RateLimited, and PaymentRequired must always stop host")
	}
	if !StopsHost(KindFeed, OutcomeError) || !StopsHost(KindJSON, OutcomeError) || !StopsHost(KindCatalog, OutcomeError) {
		t.Fatal("OutcomeError on Feed/JSON/Catalog must stop host")
	}
	if StopsHost(KindPage, OutcomeError) || StopsHost(KindScrape, OutcomeGone) || StopsHost(KindScrape, OutcomeNotFound) || StopsHost(KindScrape, OutcomeDNSNotFound) || StopsHost(KindScrape, OutcomeBlockedSSRF) {
		t.Fatal("OutcomeError on Page or NotFound/Gone/DNSNotFound/BlockedSSRF on Scrape must not stop host")
	}

	autoOKTypes := []string{
		"application/json; charset=utf-8",
		"application/ld+json",
		"application/problem+json",
		"application/rss+xml",
		"application/atom+xml",
		"application/xml",
		"text/xml; charset=utf-8",
		"text/plain; charset=utf-8",
		"text/markdown",
	}
	for _, ct := range autoOKTypes {
		h := http.Header{"Content-Type": []string{ct}}
		if got, _ := ClassifyAuto(KindPage, true, 200, h, []byte("{}")); got != OutcomeOK {
			t.Fatalf("ClassifyAuto(KindPage, true, 200, %q) = %q, want %q", ct, got, OutcomeOK)
		}
		if got, _ := ClassifyAuto("", false, 200, h, []byte("{}")); got != OutcomeOK {
			t.Fatalf("ClassifyAuto(\"\", false, 200, %q) = %q, want %q", ct, got, OutcomeOK)
		}
	}
	imgH := http.Header{"Content-Type": []string{"image/png"}}
	if got, _ := ClassifyAuto(KindPage, true, 200, imgH, []byte("\x89PNG")); got != OutcomeSkip {
		t.Fatalf("ClassifyAuto(KindPage, true, 200, image/png) = %q, want %q", got, OutcomeSkip)
	}
	jsonH := http.Header{"Content-Type": []string{"application/json"}}
	if got, _ := ClassifyAuto(KindPage, false, 200, jsonH, []byte("{}")); got != OutcomeSkip {
		t.Fatalf("ClassifyAuto(KindPage, false, 200, json) = %q, want %q", got, OutcomeSkip)
	}
	if got, _ := ClassifyAuto(KindPage, true, 500, jsonH, []byte("{}")); got != OutcomeSkip {
		t.Fatalf("ClassifyAuto(KindPage, true, 500, json) = %q, want %q", got, OutcomeSkip)
	}
	if got, _ := ClassifyAuto(KindFeed, true, 200, jsonH, []byte("{}")); got != OutcomeError {
		t.Fatalf("ClassifyAuto(KindFeed, true, 200, json) = %q, want %q", got, OutcomeError)
	}
	for _, nonAuto := range []string{"", "image/png", "application/octet-stream", "text/plain+json"} {
		if IsAutoPageContentType(nonAuto) {
			t.Fatalf("expected IsAutoPageContentType(%q) == false", nonAuto)
		}
	}
}

func BenchmarkClassifyFeedJSON(b *testing.B) {
	h := http.Header{"Content-Type": []string{"application/json"}}
	payload := []byte(`{"products":[{"id":101,"title":"Roadster"},{"id":102,"title":"Commuter"}]}`)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = Classify(KindFeed, 200, h, payload)
	}
}
