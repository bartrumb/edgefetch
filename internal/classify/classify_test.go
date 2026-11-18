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
		{"feed JSON null", KindFeed, 200, "application/json", "", "null", OutcomeError, "feed is JSON null"},
		{"feed missing products key", KindFeed, 200, "application/json", "", `{"items":[]}`, OutcomeError, "no products array"},
		{"generic json valid", KindJSON, 200, "application/json", "", `[1,2,3]`, OutcomeOK, ""},
		{"page 200 html", KindPage, 200, "text/html; charset=utf-8", "", "<html>ok</html>", OutcomeOK, ""},
		{"page 404 gone", KindPage, 404, "text/html", "", "not found", OutcomeGone, ""},
		{"page 410 gone", KindPage, 410, "text/html", "", "gone", OutcomeGone, ""},
		{"page 429 stops host", KindPage, 429, "text/plain", "", "slow down", OutcomeStop, "HTTP 429"},
		{"page 500 skipped", KindPage, 500, "text/html", "", "oops", OutcomeSkip, ""},
		{"text 200 xml", KindText, 200, "application/xml", "", "<urlset/>", OutcomeOK, ""},
		{"text 403 stops host", KindText, 403, "text/plain", "", "denied", OutcomeStop, "HTTP 403"},
		{"catalog 503 errors", KindCatalog, 503, "text/html", "", "down", OutcomeError, "HTTP 503"},
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
	if got, err := AcceptFor(KindText, "application/xml"); err != nil || got != "application/xml" {
		t.Fatalf("AcceptFor(text, xml) = %q, %v", got, err)
	}
	if _, err := AcceptFor(KindText, "*/*"); err == nil {
		t.Fatal("expected wildcard Accept rejected for KindText")
	}
	if !StopsHost(KindFeed, OutcomeError) || StopsHost(KindPage, OutcomeError) {
		t.Fatal("StopsHost mismatch on OutcomeError")
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
