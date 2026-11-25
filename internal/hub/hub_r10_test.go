package hub

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/bartrumb/edgefetch/v2/internal/crawl"
)

func TestR10P4HubTwinRedirectEnforcesValidateRedirectTarget(t *testing.T) {
	// Static guard: verify `isSameTwinOriginDomain` has been deleted and `ValidateRedirectTarget` is wired.
	hubSrc, err := os.ReadFile("hub.go")
	if err != nil {
		t.Fatalf("ReadFile(hub.go): %v", err)
	}
	routesScrapeSrc, err := os.ReadFile("routes_scrape.go")
	if err != nil {
		t.Fatalf("ReadFile(routes_scrape.go): %v", err)
	}
	combinedSrc := string(hubSrc) + "\n" + string(routesScrapeSrc)
	if strings.Contains(combinedSrc, "isSameTwinOriginDomain") {
		t.Fatal("isSameTwinOriginDomain must be completely removed from internal/hub")
	}
	if !strings.Contains(combinedSrc, "ValidateRedirectTarget(") {
		t.Fatal("expected twin.ValidateRedirectTarget(...) to be wired in internal/hub")
	}

	// Spin up a mock multi-host TLS origin serving both declarative JSON twins (with controlled 302 redirects)
	// and fallback HTML pages so we verify end-to-end Hub `/v1/scrape` and `/v2/scrape` behavior!
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := strings.ToLower(r.Host)
		if h, _, splitErr := net.SplitHostPort(host); splitErr == nil {
			host = h
		}
		if r.URL.Path == "/robots.txt" || r.URL.Path == "/llms.txt" {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		switch {
		// 1) Sibling subdomain attack on rubygems.org -> unclaimed.rubygems.org (previously accepted by isSameTwinOriginDomain!)
		case host == "rubygems.org" && r.URL.Path == "/api/v1/gems/sibling-hijack.json":
			http.Redirect(w, r, "https://unclaimed.rubygems.org/api/v1/gems/sibling-hijack.json", http.StatusFound)
			return
		case host == "unclaimed.rubygems.org" && r.URL.Path == "/api/v1/gems/sibling-hijack.json":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"name":"POISONED_SIBLING_TWIN","version":"9.9.9","info":"Hijacked from unclaimed sibling subdomain"}`))
			return
		case host == "rubygems.org" && r.URL.Path == "/gems/sibling-hijack":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write([]byte(`<!doctype html><html><body><main><h1>Safe HTML Fallback Sibling</h1><p>Canonical HTML body.</p></main></body></html>`))
			return

		// 2) Parent domain redirect attack on en.wikipedia.org -> wikipedia.org
		case host == "en.wikipedia.org" && r.URL.Path == "/api/rest_v1/page/summary/ParentHijack":
			http.Redirect(w, r, "https://wikipedia.org/poison-parent.json", http.StatusFound)
			return
		case host == "wikipedia.org" && r.URL.Path == "/poison-parent.json":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"title":"POISONED_PARENT_TWIN","extract":"Hijacked from parent domain"}`))
			return
		case host == "en.wikipedia.org" && r.URL.Path == "/wiki/ParentHijack":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write([]byte(`<!doctype html><html><body><main><h1>Safe HTML Fallback Parent</h1><p>Canonical Wiki HTML.</p></main></body></html>`))
			return

		// 3) Cross-wildcard redirect on *.wikipedia.org: en.wikipedia.org -> evil.wikipedia.org
		case host == "en.wikipedia.org" && r.URL.Path == "/api/rest_v1/page/summary/WildcardLateral":
			http.Redirect(w, r, "https://evil.wikipedia.org/api/rest_v1/page/summary/WildcardLateral", http.StatusFound)
			return
		case host == "evil.wikipedia.org":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"title":"POISONED_WILDCARD_TWIN","extract":"Lateral wildcard hop"}`))
			return
		case host == "en.wikipedia.org" && r.URL.Path == "/wiki/WildcardLateral":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write([]byte(`<!doctype html><html><body><main><h1>Safe HTML Fallback Wildcard</h1><p>Canonical Wiki HTML.</p></main></body></html>`))
			return

		// 4) Legitimate declared non-wildcard domain redirect: rubygems.org -> www.rubygems.org (both declared in rubygems.yaml!)
		case host == "rubygems.org" && r.URL.Path == "/api/v1/gems/legit-declared.json":
			http.Redirect(w, r, "https://www.rubygems.org/api/v1/gems/legit-declared.json", http.StatusFound)
			return
		case host == "www.rubygems.org" && r.URL.Path == "/api/v1/gems/legit-declared.json":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"name":"legit-declared","version":"2.4.0","info":"Trusted declared twin redirect succeeded.","downloads":12345}`))
			return

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer origin.Close()

	originAddr := origin.Listener.Addr().String()
	tlsCfg := origin.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	tlsCfg.InsecureSkipVerify = true
	originTr := &http.Transport{
		TLSClientConfig: tlsCfg,
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, originAddr)
		},
	}
	allowHTTPS := func(u *url.URL) error {
		if u.Scheme != "https" {
			return io.ErrUnexpectedEOF
		}
		return nil
	}
	silentLog := slog.New(slog.NewJSONHandler(io.Discard, nil))
	crawler := crawl.NewCrawler(originTr, allowHTTPS, crawl.DefaultUserAgent, silentLog)
	crawler.Sleep = func(context.Context, time.Duration) error { return nil }
	defer crawler.Close()

	const callerTok = "r10-caller-secret-token-0123456789"
	hubSrv := NewServer(Config{
		CallerToken:     callerTok,
		AgentToken:      "r10-agent-secret-token-0123456789",
		FallbackCrawler: crawler,
		Allow:           allowHTTPS,
		Logger:          silentLog,
	})
	defer hubSrv.Close()
	ts := httptest.NewServer(hubSrv)
	defer ts.Close()

	callScrape := func(endpoint, targetURL string) map[string]any {
		t.Helper()
		body, _ := json.Marshal(map[string]any{"url": targetURL})
		req, _ := http.NewRequest(http.MethodPost, ts.URL+endpoint, strings.NewReader(string(body)))
		req.Header.Set("Authorization", "Bearer "+callerTok)
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("POST %s(%s): %v", endpoint, targetURL, err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			t.Fatalf("POST %s(%s) status=%d body=%s", endpoint, targetURL, resp.StatusCode, string(raw))
		}
		var out map[string]any
		if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
			t.Fatalf("decode response: %v", err)
		}
		return out
	}

	// Verify all 3 hostile twin redirects are REJECTED and fall back cleanly to HTML!
	blockedCases := []struct {
		name         string
		url          string
		poisonMarker string
		wantFallback string
	}{
		{
			name:         "sibling_subdomain_redirect",
			url:          "https://rubygems.org/gems/sibling-hijack",
			poisonMarker: "POISONED_SIBLING_TWIN",
			wantFallback: "Safe HTML Fallback Sibling",
		},
		{
			name:         "parent_domain_redirect",
			url:          "https://en.wikipedia.org/wiki/ParentHijack",
			poisonMarker: "POISONED_PARENT_TWIN",
			wantFallback: "Safe HTML Fallback Parent",
		},
		{
			name:         "wildcard_lateral_redirect",
			url:          "https://en.wikipedia.org/wiki/WildcardLateral",
			poisonMarker: "POISONED_WILDCARD_TWIN",
			wantFallback: "Safe HTML Fallback Wildcard",
		},
	}

	for _, tc := range blockedCases {
		resV1 := callScrape("/v1/scrape", tc.url)
		mdV1, _ := resV1["markdown"].(string)
		if strings.Contains(mdV1, tc.poisonMarker) {
			t.Fatalf("SECURITY (P4) [%s]: poisoned twin redirect accepted on /v1/scrape!\nmd=%s", tc.name, mdV1)
		}
		if !strings.Contains(mdV1, tc.wantFallback) {
			t.Fatalf("[%s] expected clean HTML fallback containing %q, got md=%q", tc.name, tc.wantFallback, mdV1)
		}

		resV2 := callScrape("/v2/scrape", tc.url)
		dataV2, _ := resV2["data"].(map[string]any)
		mdV2, _ := dataV2["markdown"].(string)
		if strings.Contains(mdV2, tc.poisonMarker) || !strings.Contains(mdV2, tc.wantFallback) {
			t.Fatalf("SECURITY (P4) [%s]: unexpected /v2/scrape result: %+v", tc.name, resV2)
		}
	}

	// Verify legitimate redirect to explicitly declared non-wildcard domain (`www.rubygems.org`) SUCCEEDS!
	legit := callScrape("/v1/scrape", "https://rubygems.org/gems/legit-declared")
	legitMD, _ := legit["markdown"].(string)
	if !strings.Contains(legitMD, "Trusted declared twin redirect succeeded.") || !strings.Contains(legitMD, "2.4.0") {
		t.Fatalf("expected declared non-wildcard domain twin redirect (rubygems.org -> www.rubygems.org) to succeed, got: %+v", legit)
	}
}
