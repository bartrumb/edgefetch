package crawl

import (
	"bytes"
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
	"sync"
	"testing"
	"time"

	"github.com/bartrumb/edgefetch/internal/classify"
)

type recordedSleeps struct {
	mu  sync.Mutex
	all []time.Duration
}

func (s *recordedSleeps) record(_ context.Context, d time.Duration) error {
	s.mu.Lock()
	s.all = append(s.all, d)
	s.mu.Unlock()
	return nil
}

func newTestCrawler(t *testing.T, h http.Handler) (*Crawler, *recordedSleeps) {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	addr := srv.Listener.Addr().String()
	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		},
	}
	c := NewCrawler(tr, func(*url.URL) error { return nil }, DefaultUserAgent, slog.New(slog.NewJSONHandler(io.Discard, nil)))
	s := &recordedSleeps{}
	c.Sleep = s.record
	c.Jitter = func(d time.Duration) time.Duration { return d / 2 }
	return c, s
}

func TestCrawlerPacingJitterConditionalGETAndTruncation(t *testing.T) {
	c, sleeps := newTestCrawler(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/etag":
			if r.Header.Get("If-None-Match") == `"v1"` {
				w.WriteHeader(http.StatusNotModified)
				return
			}
			w.Header().Set("content-type", "text/html")
			w.Header().Set("etag", `"v1"`)
			_, _ = w.Write([]byte("<html>fresh</html>"))
		case "/huge":
			w.Header().Set("content-type", "text/html")
			_, _ = w.Write([]byte(strings.Repeat("x", 2048)))
		}
	}))

	res := c.Run(context.Background(), []Request{
		{ID: "demo", URL: "http://store.test/etag", Kind: classify.KindPage},
		{ID: "demo", URL: "http://store.test/etag", Kind: classify.KindPage, IfNoneMatch: `"v1"`},
		{ID: "demo", URL: "http://store.test/huge", Kind: classify.KindPage},
	}, Options{PauseMs: 2000, PauseJitterMs: 1000, MaxBytes: 512, IncludeBody: true})

	if res[0].Outcome != classify.OutcomeOK || res[0].ETag != `"v1"` {
		t.Fatalf("res[0] = %+v", res[0])
	}
	if res[1].Outcome != classify.OutcomeOK || res[1].Status != http.StatusNotModified {
		t.Fatalf("res[1] expected 304 ok, got %+v", res[1])
	}
	if !res[2].Truncated || res[2].Outcome != classify.OutcomeError {
		t.Fatalf("res[2] expected truncated error, got %+v", res[2])
	}
	// PauseMs=2000 + Jitter(1000)=500 -> 2500ms between sequential requests on the same host.
	if len(sleeps.all) != 2 || sleeps.all[0] != 2500*time.Millisecond {
		t.Fatalf("unexpected sleeps: %v", sleeps.all)
	}
}

func TestURLGuardsAndUserAgentValidation(t *testing.T) {
	rule := WithBlockedHost(WithAllowedHosts(PublicHTTPS, []string{"catalog.example.com", "hub.example.com"}), "hub.example.com")

	okURL, _ := url.Parse("https://sub.catalog.example.com/products.json")
	if err := rule(okURL); err != nil {
		t.Fatalf("expected catalog URL allowed: %v", err)
	}

	hubURL, _ := url.Parse("https://hub.example.com/fetch")
	if err := rule(hubURL); err == nil {
		t.Fatal("expected recursive hub URL rejected")
	}

	trailingDotHub, _ := url.Parse("https://hub.example.com./fetch")
	if err := rule(trailingDotHub); err == nil {
		t.Fatal("SECURITY: expected trailing-dot hub.example.com. URL rejected")
	}

	trailingDotCatalog, _ := url.Parse("https://sub.catalog.example.com./products.json")
	if err := rule(trailingDotCatalog); err != nil {
		t.Fatalf("expected trailing-dot allowed subdomain accepted: %v", err)
	}

	if err := ValidateUserAgent("EdgeFetch/1.0\r\nX-Injected: bad"); err == nil {
		t.Fatal("SECURITY: expected CRLF in User-Agent to be rejected")
	}
	if err := ValidateUserAgent(DefaultUserAgent); err != nil {
		t.Fatalf("DefaultUserAgent rejected: %v", err)
	}
}

func TestHTTPHandlerValidation(t *testing.T) {
	c, _ := newTestCrawler(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("content-type", "application/json")
		_, _ = w.Write([]byte(`{"products":[]}`))
	}))
	h := NewHandler(c, PublicHTTPS)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/fetch", bytes.NewBufferString(`{"requests":[{"id":"a","url":"http://127.0.0.1/x","kind":"feed"}]}`))
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 on loopback URL, got %d", rec.Code)
	}
	var errBody map[string]string
	_ = json.Unmarshal(rec.Body.Bytes(), &errBody)
	if errBody["error"] != "bad_url" {
		t.Fatalf("unexpected error body: %v", errBody)
	}
}

func TestAuthenticatedHandlerBearerProtection(t *testing.T) {
	c, _ := newTestCrawler(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("content-type", "application/json")
		_, _ = w.Write([]byte(`{"products":[]}`))
	}))
	const secret = "server-secret-token-0123456789abcdef"
	h := NewAuthenticatedHandler(c, func(*url.URL) error { return nil }, secret)

	// /healthz remains unauthenticated for container probes.
	healthRec := httptest.NewRecorder()
	h.ServeHTTP(healthRec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if healthRec.Code != http.StatusOK {
		t.Fatalf("/healthz status = %d, want 200", healthRec.Code)
	}

	// Missing Bearer -> 401.
	unauthRec := httptest.NewRecorder()
	h.ServeHTTP(unauthRec, httptest.NewRequest(http.MethodPost, "/fetch", bytes.NewBufferString(`{"requests":[{"id":"1","url":"http://store.test/products.json","kind":"feed"}]}`)))
	if unauthRec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated /fetch = %d, want 401", unauthRec.Code)
	}

	// Wrong Bearer -> 401.
	badRec := httptest.NewRecorder()
	badReq := httptest.NewRequest(http.MethodPost, "/fetch", bytes.NewBufferString(`{"requests":[{"id":"1","url":"http://store.test/products.json","kind":"feed"}]}`))
	badReq.Header.Set("Authorization", "Bearer wrong-token-0123456789abcdef")
	h.ServeHTTP(badRec, badReq)
	if badRec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong bearer /fetch = %d, want 401", badRec.Code)
	}

	// Valid Bearer -> 200.
	okRec := httptest.NewRecorder()
	okReq := httptest.NewRequest(http.MethodPost, "/fetch", bytes.NewBufferString(`{"requests":[{"id":"1","url":"http://store.test/products.json","kind":"feed"}]}`))
	okReq.Header.Set("Authorization", "Bearer "+secret)
	h.ServeHTTP(okRec, okReq)
	if okRec.Code != http.StatusOK {
		t.Fatalf("authorized /fetch = %d, want 200 (%s)", okRec.Code, okRec.Body.String())
	}
}

func TestRobotsRFC9309Unreachable4295xxAnd404(t *testing.T) {
	// 1. robots.txt returning 429 must assume disallow (OutcomeStop), never fetch target page.
	hitPage := false
	c429, _ := newTestCrawler(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/robots.txt" {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		hitPage = true
		w.Header().Set("content-type", "text/html")
		_, _ = w.Write([]byte("<html>should not be fetched</html>"))
	}))
	res429 := c429.Run(context.Background(), []Request{
		{ID: "r1", URL: "http://rate-limited.test/secret", Kind: classify.KindPage},
	}, Options{}) // Default Options{} now enables RespectRobots automatically!
	if hitPage || res429[0].Outcome != classify.OutcomeStop {
		t.Fatalf("RFC 9309: 429 on /robots.txt must disallow crawl by default (hitPage=%v, res=%+v)", hitPage, res429[0])
	}

	// 2. robots.txt failing with a transport error must assume disallow (OutcomeStop).
	deadTr := &http.Transport{
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			return nil, io.ErrUnexpectedEOF
		},
	}
	cDead := NewCrawler(deadTr, func(*url.URL) error { return nil }, DefaultUserAgent, slog.New(slog.NewJSONHandler(io.Discard, nil)))
	cDead.Sleep = func(context.Context, time.Duration) error { return nil }
	resDead := cDead.Run(context.Background(), []Request{
		{ID: "r2", URL: "https://unreachable.test/page", Kind: classify.KindPage},
	}, Options{RespectRobots: Bool(true)})
	if resDead[0].Outcome != classify.OutcomeStop || !strings.Contains(resDead[0].Problem, "robots.txt unreachable") {
		t.Fatalf("RFC 9309: unreachable /robots.txt must stop host, got %+v", resDead[0])
	}

	// 3. robots.txt returning 404 means unavailable -> allow crawl (OutcomeOK).
	c404, _ := newTestCrawler(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/robots.txt" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("content-type", "text/html")
		_, _ = w.Write([]byte("<html>ok</html>"))
	}))
	res404 := c404.Run(context.Background(), []Request{
		{ID: "r3", URL: "http://no-robots.test/public", Kind: classify.KindPage},
	}, Options{Robots: Bool(true)}) // Also exercises legacy `Robots` alias -> RespectRobots!
	if res404[0].Outcome != classify.OutcomeOK {
		t.Fatalf("404 /robots.txt should allow crawl, got %+v", res404[0])
	}

	// 4. Redirect to a robots-disallowed path (/public -> /private) MUST be blocked on the redirect hop (A3)!
	hitPrivate := false
	cRedir, redirSleeps := newTestCrawler(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/robots.txt":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("User-agent: *\nDisallow: /private\nCrawl-delay: 3\n"))
		case "/public":
			http.Redirect(w, r, "/private", http.StatusFound)
		case "/private":
			hitPrivate = true
			w.Header().Set("content-type", "text/html")
			_, _ = w.Write([]byte("<html>secret</html>"))
		}
	}))
	resRedir := cRedir.Run(context.Background(), []Request{
		{ID: "redir", URL: "http://redir.test/public", Kind: classify.KindPage},
	}, Options{PauseMs: 1000})
	if hitPrivate || resRedir[0].Outcome == classify.OutcomeOK {
		t.Fatalf("A3 BUG: redirect from /public to /private bypassed robots.txt (hitPrivate=%v, res=%+v)", hitPrivate, resRedir[0])
	}
	if len(redirSleeps.all) == 0 || redirSleeps.all[0] < 3*time.Second {
		t.Fatalf("A3 BUG: redirect hop skipped per-host Crawl-delay pacing (sleeps=%v)", redirSleeps.all)
	}

	// 5. Caller-supplied RespectRobots=false MUST be rejected unless host is in owner RobotsBypassHosts allowlist (A5)!
	cNoBypass, _ := newTestCrawler(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "text/html")
		_, _ = w.Write([]byte("<html>ok</html>"))
	}))
	if code, _, ok := ValidateCallWithCrawler(cNoBypass, FetchCall{
		Requests: []Request{{ID: "r4", URL: "https://example.com/public", Kind: classify.KindPage}},
		Options:  Options{RespectRobots: Bool(false)},
	}, PublicHTTPS); ok || code != "robots_required" {
		t.Fatalf("A5 BUG: expected RespectRobots=false rejected for unallowlisted host, got ok=%v code=%q", ok, code)
	}
	cNoBypass.SetRobotsBypassHosts([]string{"example.com"})
	if _, _, ok := ValidateCallWithCrawler(cNoBypass, FetchCall{
		Requests: []Request{{ID: "r4", URL: "https://sub.example.com/public", Kind: classify.KindPage}},
		Options:  Options{RespectRobots: Bool(false)},
	}, PublicHTTPS); !ok {
		t.Fatal("expected owner-allowlisted host to pass ValidateCallWithCrawler")
	}

	// 6. 78 KiB /robots.txt with Disallow rule at the end MUST still be parsed and enforced per RFC 9309 §2.5 (A4)!
	hitSecret78K := false
	c78k, _ := newTestCrawler(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/robots.txt" {
			_, _ = w.Write([]byte("User-agent: *\n" + strings.Repeat("# pad pad pad pad pad pad\n", 3200) + "Disallow: /secret\n"))
			return
		}
		hitSecret78K = true
		w.Header().Set("content-type", "text/html")
		_, _ = w.Write([]byte("<html>secret</html>"))
	}))
	res78k := c78k.Run(context.Background(), []Request{
		{ID: "r78k", URL: "http://large-robots.test/secret", Kind: classify.KindPage},
	}, Options{})
	if hitSecret78K || res78k[0].Outcome != classify.OutcomeSkip {
		t.Fatalf("expected 78 KiB /robots.txt trailing rule enforced (hit=%v, res=%+v)", hitSecret78K, res78k[0])
	}
}

func TestSharedWireContractFixture(t *testing.T) {
	raw, err := os.ReadFile("../../testdata/wire-contract.json")
	if err != nil {
		t.Fatalf("read wire-contract.json: %v", err)
	}
	var fixtures map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fixtures); err != nil {
		t.Fatalf("parse fixture map: %v", err)
	}
	for name, payload := range fixtures {
		dec := json.NewDecoder(bytes.NewReader(payload))
		dec.DisallowUnknownFields()
		var call FetchCall
		if err := dec.Decode(&call); err != nil {
			t.Fatalf("fixture %s rejected by strict Go decoder: %v", name, err)
		}
		norm := call.Options.Normalize()
		if !norm.RobotsEnabled() {
			t.Fatalf("fixture %s expected Normalize().RobotsEnabled() == true, got %+v", name, norm)
		}
	}
}
