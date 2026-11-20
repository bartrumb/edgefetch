package classify

import (
	"net/http"
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
		{"page 200 non-html skipped", KindPage, 200, "image/png", "", "\x89PNG", OutcomeSkip, ""},
		{"page 404 gone", KindPage, 404, "text/html", "", "not found", OutcomeGone, ""},
		{"page 410 gone", KindPage, 410, "text/html", "", "gone", OutcomeGone, ""},
		{"page 429 stops host", KindPage, 429, "text/plain", "", "slow down", OutcomeStop, "HTTP 429"},
		{"page 500 skipped", KindPage, 500, "text/html", "", "oops", OutcomeSkip, ""},
		{"text 200 xml", KindText, 200, "application/xml", "", "<urlset/>", OutcomeOK, ""},
		{"text 404 skipped", KindText, 404, "text/plain", "", "missing", OutcomeSkip, ""},
		{"text 403 stops host", KindText, 403, "text/plain", "", "denied", OutcomeStop, "HTTP 403"},
		{"catalog 200 ok", KindCatalog, 200, "text/html", "", "<html></html>", OutcomeOK, ""},
		{"catalog 503 errors", KindCatalog, 503, "text/html", "", "down", OutcomeError, "HTTP 503"},
		{"scrape 200 ok", KindScrape, 200, "text/html", "", "<main>hi</main>", OutcomeOK, ""},
		{"scrape 429 stop", KindScrape, 429, "text/plain", "", "rate limited", OutcomeStop, "HTTP 429"},
		{"scrape 404 gone", KindScrape, 404, "text/html", "", "missing", OutcomeGone, "HTTP 404"},
		{"scrape 500 error", KindScrape, 500, "text/html", "", "err", OutcomeError, "HTTP 500"},
		{"render 200 ok", KindRender, 200, "text/html", "", "<html></html>", OutcomeOK, ""},
		{"pdf 200 content-type pdf", KindPDF, 200, "application/pdf", "", "binary", OutcomeOK, ""},
		{"pdf 200 magic bytes octet-stream", KindPDF, 200, "application/octet-stream", "", "%PDF-1.7 ...", OutcomeOK, ""},
		{"pdf 200 html soft-404 error", KindPDF, 200, "text/html", "", "<html>login</html>", OutcomeError, "not a PDF (text/html)"},
		{"pdf 403 stop", KindPDF, 403, "text/plain", "", "denied", OutcomeStop, "HTTP 403"},
		{"pdf 410 gone", KindPDF, 410, "text/plain", "", "gone", OutcomeGone, "HTTP 410"},
		{"pdf 502 error", KindPDF, 502, "text/plain", "", "bad gateway", OutcomeError, "HTTP 502"},
		{"binary 200 ok", KindBinary, 200, "application/octet-stream", "", "\x00\x01\x02", OutcomeOK, ""},
		{"binary 429 stop", KindBinary, 429, "text/plain", "", "slow", OutcomeStop, "HTTP 429"},
		{"binary 404 gone", KindBinary, 404, "text/plain", "", "missing", OutcomeGone, "HTTP 404"},
		{"binary 500 error", KindBinary, 500, "text/plain", "", "boom", OutcomeError, "HTTP 500"},
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
		{KindPage, "", "text/html", false},
		{KindCatalog, "", "text/html", false},
		{KindRender, "", "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8", false},
		{KindScrape, "", "text/markdown,text/html;q=0.95,application/xhtml+xml;q=0.9,application/pdf;q=0.85,application/json;q=0.8,*/*;q=0.7", false},
		{KindScrape, "text/markdown", "text/markdown", false},
		{KindPDF, "", "application/pdf,*/*;q=0.8", false},
		{KindBinary, "", "*/*", false},
		{KindBinary, "image/webp", "image/webp", false},
		{KindText, "application/xml", "application/xml", false},
		{KindText, "text/plain", "text/plain", false},
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

	if !StopsHost(KindScrape, OutcomeChallenge) || !StopsHost(KindScrape, OutcomeStop) {
		t.Fatal("Challenge and Stop must always stop host")
	}
	if !StopsHost(KindFeed, OutcomeError) || !StopsHost(KindJSON, OutcomeError) || !StopsHost(KindCatalog, OutcomeError) {
		t.Fatal("OutcomeError on Feed/JSON/Catalog must stop host")
	}
	if StopsHost(KindPage, OutcomeError) || StopsHost(KindScrape, OutcomeGone) {
		t.Fatal("OutcomeError on Page or OutcomeGone on Scrape must not stop host")
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
