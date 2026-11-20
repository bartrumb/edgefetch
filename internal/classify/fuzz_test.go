package classify

import (
	"net/http"
	"testing"
)

func FuzzClassify(f *testing.F) {
	f.Add("scrape", 200, "text/html; charset=utf-8", "", []byte("<main><h1>Hello</h1></main>"))
	f.Add("feed", 200, "application/json", "", []byte(`{"products":[{"id":1}]}`))
	f.Add("pdf", 200, "application/pdf", "", []byte("%PDF-1.7\n"))
	f.Add("json", 429, "application/json", "challenge", []byte(`{}`))

	f.Fuzz(func(t *testing.T, kindStr string, status int, ct, cfMitigated string, body []byte) {
		if len(body) > 64<<10 {
			return
		}
		h := http.Header{}
		if ct != "" {
			h.Set("content-type", ct)
		}
		if cfMitigated != "" {
			h.Set("cf-mitigated", cfMitigated)
		}
		out, _ := Classify(Kind(kindStr), status, h, body)
		if cfMitigated != "" && out != OutcomeChallenge {
			t.Fatalf("cf-mitigated header must always produce OutcomeChallenge, got %q", out)
		}
		_ = StopsHost(Kind(kindStr), out)
	})
}
