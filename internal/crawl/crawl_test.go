package crawl

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bartrumb/edgefetch/internal/browser"
	"github.com/bartrumb/edgefetch/internal/classify"
	"github.com/bartrumb/edgefetch/internal/politeness"
	"github.com/coder/websocket"
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
		if strings.HasSuffix(name, "Reply") {
			var reply FetchReply
			if err := dec.Decode(&reply); err != nil {
				t.Fatalf("reply fixture %s rejected by strict Go decoder: %v", name, err)
			}
			if len(reply.Results) < 2 {
				t.Fatalf("reply fixture %s expected >= 2 results", name)
			}
			rawLatin1, err := reply.Results[1].DecodeBody()
			if err != nil || !bytes.Equal(rawLatin1, []byte("caf\xe9")) {
				t.Fatalf("reply fixture %s base64 DecodeBody mismatch: got %x err=%v", name, rawLatin1, err)
			}
			continue
		}
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

func TestNonUTF8BodyPreservesExactBytesAcrossJSONWire(t *testing.T) {
	rawLatin1 := []byte("<html>caf\xe9</html>")
	c, _ := newTestCrawler(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/robots.txt" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("content-type", "text/html; charset=iso-8859-1")
		_, _ = w.Write(rawLatin1)
	}))

	res := c.Run(context.Background(), []Request{
		{ID: "latin1", URL: "http://latin1.test/menu", Kind: classify.KindPage},
	}, Options{IncludeBody: true})
	if len(res) != 1 || res[0].Outcome != classify.OutcomeOK {
		t.Fatalf("expected ok result, got %+v", res)
	}

	wireJSON, err := json.Marshal(res[0])
	if err != nil {
		t.Fatalf("marshal result: %v", err)
	}
	var wireMap map[string]any
	if err := json.Unmarshal(wireJSON, &wireMap); err != nil {
		t.Fatalf("unmarshal map: %v", err)
	}
	enc, _ := wireMap["bodyEncoding"].(string)
	bodyStr, _ := wireMap["body"].(string)
	var gotBytes []byte
	if enc == "base64" {
		gotBytes, err = base64.StdEncoding.DecodeString(bodyStr)
		if err != nil {
			t.Fatalf("decode base64 body: %v", err)
		}
	} else {
		gotBytes = []byte(bodyStr)
	}
	if !bytes.Equal(gotBytes, rawLatin1) {
		t.Fatalf("A6 BUG: non-UTF-8 body corrupted across JSON wire: want %x, got %x (bodyEncoding=%q)", rawLatin1, gotBytes, enc)
	}
}

func TestBatchTotalBodyBudgetAndServerConcurrencyLimit(t *testing.T) {
	// Three 7 MiB pages = 21 MiB total > 20 MiB Hub reply cap unless bounded by total batch body budget (A9 / H2)!
	sevenMiB := "<html>" + strings.Repeat("A", (7<<20)-13) + "</html>"
	c, _ := newTestCrawler(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/robots.txt" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("content-type", "text/html")
		_, _ = w.Write([]byte(sevenMiB))
	}))

	res := c.Run(context.Background(), []Request{
		{ID: "p1", URL: "http://a.budget.test/1", Kind: classify.KindPage},
		{ID: "p2", URL: "http://b.budget.test/2", Kind: classify.KindPage},
		{ID: "p3", URL: "http://c.budget.test/3", Kind: classify.KindPage},
	}, Options{IncludeBody: true, MaxBytes: 8 << 20, Concurrency: 1})

	totalRetained := len(res[0].Body) + len(res[1].Body) + len(res[2].Body)
	if totalRetained > 18<<20 {
		t.Fatalf("A9 BUG: batch retained %d bytes in memory (> 18 MiB budget), risking OOM and Hub 413", totalRetained)
	}
	if !res[2].Truncated || !res[2].BodyOmitted || res[2].Body != "" {
		t.Fatalf("expected 3rd 7 MiB page marked Truncated+BodyOmitted with empty Body, got truncated=%v omitted=%v len=%d",
			res[2].Truncated, res[2].BodyOmitted, len(res[2].Body))
	}

	// Verify HTTP server caps concurrent /fetch calls at MaxConcurrentServerCalls (503 server_busy on overflow).
	gate := make(chan struct{})
	var entered atomic.Int32
	allEntered := make(chan struct{})
	originSlow := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/robots.txt" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if entered.Add(1) == MaxConcurrentServerCalls {
			close(allEntered)
		}
		<-gate
		w.Header().Set("content-type", "text/html")
		_, _ = w.Write([]byte("<html>ok</html>"))
	}))
	defer originSlow.Close()
	slowAddr := originSlow.Listener.Addr().String()
	slowTLS := originSlow.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	slowTLS.InsecureSkipVerify = true
	slowTr := &http.Transport{
		TLSClientConfig: slowTLS,
		DialContext: func(ctx context.Context, n, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, n, slowAddr)
		},
	}
	slowCrawler := NewCrawler(slowTr, PublicHTTPS, DefaultUserAgent, slog.New(slog.NewTextHandler(io.Discard, nil)))
	slowCrawler.Sleep = func(context.Context, time.Duration) error { return nil }
	apiSrv := httptest.NewServer(NewAuthenticatedHandler(slowCrawler, PublicHTTPS, ""))
	defer apiSrv.Close()

	var wg sync.WaitGroup
	for i := 0; i < MaxConcurrentServerCalls; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			payload := fmt.Sprintf(`{"requests":[{"id":"%d","url":"https://s%d.example.com/","kind":"page"}]}`, n, n)
			resp, err := http.Post(apiSrv.URL+"/fetch", "application/json", strings.NewReader(payload))
			if err == nil {
				_ = resp.Body.Close()
			}
		}(i)
	}
	<-allEntered

	overflowResp, err := http.Post(apiSrv.URL+"/fetch", "application/json", strings.NewReader(`{"requests":[{"id":"over","url":"https://over.example.com/","kind":"page"}]}`))
	if err != nil {
		t.Fatalf("overflow POST /fetch: %v", err)
	}
	_ = overflowResp.Body.Close()
	close(gate)
	wg.Wait()

	if overflowResp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("expected HTTP 503 server_busy when >%d concurrent /fetch calls arrive, got %d", MaxConcurrentServerCalls, overflowResp.StatusCode)
	}
}

func TestPermanentSSRFErrorNotRetriedAndBackoffHasQuarterFloor(t *testing.T) {
	var dials atomic.Int32
	tr := &http.Transport{
		DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
			dials.Add(1)
			return nil, politeness.CheckPublicPeerAddress("127.0.0.1:443")
		},
	}
	c := NewCrawler(tr, PublicHTTPS, DefaultUserAgent, slog.New(slog.NewTextHandler(io.Discard, nil)))
	c.Sleep = func(context.Context, time.Duration) error { return nil }
	c.SetRobotsBypassHosts([]string{"rebind.example.com"})
	res := c.Run(context.Background(), []Request{
		{ID: "ssrf", URL: "https://rebind.example.com/", Kind: classify.KindPage},
	}, Options{Retries: 3, RespectRobots: Bool(false)})
	if dials.Load() != 1 || res[0].Attempts != 1 {
		t.Fatalf("A11 BUG: permanent SSRF refusal was retried %d times (attempts=%d), want 1", dials.Load(), res[0].Attempts)
	}

	// Verify backoff has a >= 25% floor even when Jitter returns 0.
	c502, sleeps := newTestCrawler(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/robots.txt" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusBadGateway)
	}))
	c502.Jitter = func(time.Duration) time.Duration { return 0 }
	_ = c502.Run(context.Background(), []Request{
		{ID: "b1", URL: "http://backoff.test/", Kind: classify.KindPage},
	}, Options{Retries: 1})
	if len(sleeps.all) == 0 || sleeps.all[0] < 250*time.Millisecond {
		t.Fatalf("A11 BUG: zero-jitter retry backoff slept %v, want >= 250ms floor", sleeps.all)
	}
}

func TestScrapeLlmsTxtCompanionMarkdownAndRobotsGuard(t *testing.T) {
	c, _ := newTestCrawler(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/robots.txt":
			w.Header().Set("Content-Type", "text/plain")
			if r.Host == "blocked-llms.test" {
				_, _ = w.Write([]byte("User-agent: *\nDisallow: /llms.txt\nDisallow: /.well-known/llms.txt\n"))
				return
			}
			w.WriteHeader(http.StatusNotFound)
		case "/llms.txt":
			w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
			_, _ = w.Write([]byte("# Docs Portal\n> Fast technical reference.\n\n## Guides\n- [Install Guide](/guide/install.md): CLI setup\n- [Full Reference](/llms-full.txt): Everything\n"))
		case "/guide/install.md":
			w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
			_, _ = w.Write([]byte("# Install Guide\n\nRun `edgefetch --version` to verify the static Go binary.\n"))
		case "/guide/install":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write([]byte("<html><head><title>Install</title></head><body><nav>noisy chrome</nav><main><h1>HTML Fallback</h1><p>Browser copy.</p></main></body></html>"))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))

	results := c.Run(context.Background(), []Request{
		{
			ID:      "s1",
			URL:     "http://docs.test/guide/install",
			Kind:    classify.KindScrape,
			Formats: []string{"markdown", "links"},
		},
		{
			ID:      "s2",
			URL:     "http://blocked-llms.test/guide/install",
			Kind:    classify.KindScrape,
			Formats: []string{"markdown"},
		},
		{
			ID:      "bad-hdr",
			URL:     "http://docs.test/guide/install",
			Kind:    classify.KindScrape,
			Headers: map[string]string{"Cookie": "session=secret"},
		},
	}, Options{PauseMs: 5})

	if results[0].Outcome != classify.OutcomeOK || results[0].Llms == nil || !results[0].Llms.Found || !results[0].Llms.UsedCompanionMd {
		t.Fatalf("expected llms.txt discovery + companion .md upgrade, got: %+v (llms=%+v)", results[0], results[0].Llms)
	}
	if !strings.Contains(results[0].Markdown, "edgefetch --version") {
		t.Fatalf("expected companion markdown content, got: %q", results[0].Markdown)
	}
	if results[1].Outcome != classify.OutcomeOK || results[1].Llms == nil || results[1].Llms.Found {
		t.Fatalf("robots.txt Disallow:/llms.txt must block llms.txt fetch cleanly while still scraping allowed HTML page: %+v", results[1].Llms)
	}
	if !strings.Contains(results[1].Markdown, "HTML Fallback") || strings.Contains(results[1].Markdown, "noisy chrome") {
		t.Fatalf("expected clean main-content HTML->Markdown fallback when llms.txt is disallowed, got: %q", results[1].Markdown)
	}
	if results[2].Outcome != classify.OutcomeError || !strings.Contains(results[2].Problem, "not permitted") {
		t.Fatalf("expected forbidden Cookie header to be rejected, got: %+v", results[2])
	}
}

func TestRenderModeAutoPreChecksRobotsAndPDFExtraction(t *testing.T) {
	var cdpNavigations atomic.Int32
	cdpSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer conn.CloseNow()
		for {
			_, raw, err := conn.Read(r.Context())
			if err != nil {
				return
			}
			var req struct {
				ID        int64           `json:"id"`
				SessionID string          `json:"sessionId"`
				Method    string          `json:"method"`
				Params    json.RawMessage `json:"params"`
			}
			if json.Unmarshal(raw, &req) != nil {
				continue
			}
			send := func(v any) {
				b, _ := json.Marshal(v)
				_ = conn.Write(r.Context(), websocket.MessageText, b)
			}
			switch req.Method {
			case "Target.createBrowserContext":
				send(map[string]any{"id": req.ID, "result": map[string]any{"browserContextId": "bc-1"}})
			case "Target.createTarget":
				send(map[string]any{"id": req.ID, "result": map[string]any{"targetId": "tgt-1"}})
			case "Target.attachToTarget":
				send(map[string]any{"id": req.ID, "result": map[string]any{"sessionId": "s-1"}})
			case "Page.navigate":
				cdpNavigations.Add(1)
				send(map[string]any{"id": req.ID, "sessionId": req.SessionID, "result": map[string]any{"frameId": "f-1"}})
				send(map[string]any{"sessionId": req.SessionID, "method": "Page.loadEventFired", "params": map[string]any{}})
			case "Runtime.evaluate":
				docJSON, _ := json.Marshal(map[string]string{
					"url":  "http://spa.test/app",
					"html": "<html><head><title>Hydrated SPA</title></head><body><main><h1>Client Rendered Inventory</h1></main></body></html>",
				})
				send(map[string]any{"id": req.ID, "sessionId": req.SessionID, "result": map[string]any{"result": map[string]any{"type": "string", "value": string(docJSON)}}})
			default:
				send(map[string]any{"id": req.ID, "sessionId": req.SessionID, "result": map[string]any{}})
			}
		}
	}))
	defer cdpSrv.Close()

	c, _ := newTestCrawler(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/robots.txt":
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte("User-agent: *\nDisallow: /blocked-render\n"))
		case "/app":
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`<!doctype html><html><head><script type="module" src="/main.js"></script></head><body><div id="root"></div></body></html>`))
		case "/manual.pdf":
			w.Header().Set("Content-Type", "application/pdf")
			_, _ = w.Write([]byte("%PDF-1.7\n1 0 obj << /Length 48 >>\nstream\nBT /F1 12 Tf 72 712 Td (Battery Spec 720Wh) Tj ET\nendstream\nendobj\n%%EOF"))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	mockR := browser.NewMockRenderer("ws://"+strings.TrimPrefix(cdpSrv.URL, "http://"), nil, DefaultUserAgent)
	c.SetRenderer(mockR)
	defer c.Close()

	out := c.Run(context.Background(), []Request{
		{ID: "blocked", URL: "http://spa.test/blocked-render", Kind: classify.KindRender, WaitForMs: 10},
		{ID: "spa", URL: "http://spa.test/app", Kind: classify.KindScrape, RenderMode: "auto", WaitForMs: 10, DiscoverLlms: Bool(false)},
		{ID: "pdf", URL: "http://spa.test/manual.pdf", Kind: classify.KindPDF},
	}, Options{PauseMs: 5})

	if out[0].Outcome != classify.OutcomeError || !strings.Contains(out[0].Problem, "robots.txt disallowed") {
		t.Fatalf("expected robots.txt to block KindRender before launching browser, got: %+v", out[0])
	}
	if !out[1].Rendered || !strings.Contains(out[1].Markdown, "Client Rendered Inventory") {
		t.Fatalf("expected RenderMode=auto to upgrade SPA shell to hydrated Markdown, got: %+v", out[1])
	}
	if cdpNavigations.Load() != 1 {
		t.Fatalf("expected exactly 1 CDP navigation (blocked-render must never reach CDP), got %d", cdpNavigations.Load())
	}
	if out[2].Outcome != classify.OutcomeOK || !strings.Contains(out[2].Markdown, "Battery Spec 720Wh") {
		t.Fatalf("expected PDF extraction in KindPDF, got: %+v", out[2])
	}
}

func TestRobotsFollowsMultiHopRedirectsAndBlocksSSRFRedirect(t *testing.T) {
	c, _ := newTestCrawler(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Host {
		case "aventon.test":
			if r.URL.Path == "/robots.txt" {
				w.Header().Set("Location", "http://www.aventon.test/robots.txt")
				w.WriteHeader(http.StatusMovedPermanently)
				return
			}
			if r.URL.Path == "/products.json" {
				w.Header().Set("Location", "http://www.aventon.test/products.json")
				w.WriteHeader(http.StatusMovedPermanently)
				return
			}
		case "www.aventon.test":
			if r.URL.Path == "/robots.txt" {
				w.Header().Set("Content-Type", "text/plain")
				_, _ = w.Write([]byte("User-agent: *\nDisallow: /checkout\n"))
				return
			}
			if r.URL.Path == "/products.json" {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"products":[{"id":1,"title":"Aventure.2"}]}`))
				return
			}
		case "ssrf-robots.test":
			if r.URL.Path == "/robots.txt" {
				w.Header().Set("Location", "http://127.0.0.1/robots.txt")
				w.WriteHeader(http.StatusFound)
				return
			}
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	c.allow = func(u *url.URL) error {
		if u.Hostname() == "127.0.0.1" {
			return fmt.Errorf("refusing connection to non-public IP 127.0.0.1")
		}
		return nil
	}

	out := c.Run(context.Background(), []Request{
		{ID: "aventon", URL: "http://aventon.test/products.json", Kind: classify.KindFeed},
		{ID: "blocked-path", URL: "http://aventon.test/checkout", Kind: classify.KindPage},
		{ID: "ssrf", URL: "http://ssrf-robots.test/products.json", Kind: classify.KindFeed},
	}, Options{PauseMs: 1, IncludeBody: true})

	if out[0].Outcome != classify.OutcomeOK || !strings.Contains(out[0].Body, "Aventure.2") {
		t.Fatalf("expected apex -> www robots.txt 301 redirect to succeed and fetch products.json, got: %+v", out[0])
	}
	if out[1].Outcome != classify.OutcomeSkip || !strings.Contains(out[1].Problem, "robots.txt disallowed /checkout") {
		t.Fatalf("expected redirected robots.txt rules to block /checkout, got: %+v", out[1])
	}
	if out[2].Outcome != classify.OutcomeStop || !strings.Contains(out[2].Problem, "robots.txt disallowed redirect target") {
		t.Fatalf("expected SSRF robots.txt redirect to fail closed, got: %+v", out[2])
	}
}

func TestStreamingLargePDFExceedingMaxBytesExtractsMarkdownWithoutTruncation(t *testing.T) {
	// Build a valid ~1.5 MiB PDF while setting Options.MaxBytes = 64 KiB so in-memory buffering would fail with "body over 65536 bytes".
	var pdfBuf strings.Builder
	pdfBuf.WriteString("%PDF-1.7\n1 0 obj << /Length 64 >>\nstream\nBT /F1 12 Tf 72 712 Td (GOTRAX Porter Torque Spec 45 Nm) Tj ET\nendstream\nendobj\n")
	pdfBuf.WriteString("%DiagramPadding ")
	pdfBuf.WriteString(strings.Repeat("0123456789ABCDEF", 96*1024)) // +1.5 MiB binary diagram padding
	pdfBuf.WriteString("\n%%EOF\n")
	largePDF := []byte(pdfBuf.String())

	c, _ := newTestCrawler(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/robots.txt":
			w.WriteHeader(http.StatusNotFound)
		case "/GOTRAX_Porter_User_Manual.pdf":
			w.Header().Set("Content-Type", "application/pdf")
			_, _ = w.Write(largePDF)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))

	out := c.Run(context.Background(), []Request{
		{ID: "manual", URL: "http://manuals.test/GOTRAX_Porter_User_Manual.pdf", Kind: classify.KindScrape, Formats: []string{"markdown"}},
	}, Options{PauseMs: 1, MaxBytes: 64 * 1024, IncludeBody: true})

	if out[0].Outcome != classify.OutcomeOK {
		t.Fatalf("expected 1.5 MiB PDF with 64 KiB MaxBytes to stream to /tmp without truncation, got: %+v", out[0])
	}
	if out[0].Bytes != len(largePDF) {
		t.Fatalf("expected raw PDF byte count %d, got %d", len(largePDF), out[0].Bytes)
	}
	if out[0].SHA256 == "" {
		t.Fatalf("expected raw PDF SHA256 to be populated")
	}
	if !strings.Contains(out[0].Markdown, "GOTRAX Porter Torque Spec 45 Nm") {
		t.Fatalf("expected extracted PDF markdown, got %q", out[0].Markdown)
	}
	if len(out[0].Body) >= 4096 || !strings.HasPrefix(out[0].ContentType, "text/markdown") {
		t.Fatalf("expected compact text/markdown Body for R2 upload (len=%d, ct=%q)", len(out[0].Body), out[0].ContentType)
	}
}

func TestPostJsonAndTransientRobotsRetry(t *testing.T) {
	var robotsCalls atomic.Int32
	var receivedMethod string
	var receivedCT string
	var receivedBody string

	c, _ := newTestCrawler(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/robots.txt":
			attempt := robotsCalls.Add(1)
			if attempt == 1 {
				// Simulate a transient TCP reset / EOF on the first /robots.txt probe (P12).
				if hj, ok := w.(http.Hijacker); ok {
					conn, _, err := hj.Hijack()
					if err == nil {
						_ = conn.Close()
						return
					}
				}
			}
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte("User-agent: *\nAllow: /\n"))
		case "/wday/cxs/acme/Careers/jobs":
			receivedMethod = r.Method
			receivedCT = r.Header.Get("Content-Type")
			b, _ := io.ReadAll(r.Body)
			receivedBody = string(b)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"total":1,"jobPostings":[{"title":"Solutions Architect"}]}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))

	out := c.Run(context.Background(), []Request{
		{
			ID:          "wday-post",
			URL:         "http://workday.test/wday/cxs/acme/Careers/jobs",
			Method:      "POST",
			RequestBody: `{"appliedFacets":{},"limit":20,"offset":0,"searchText":"Architect"}`,
			ContentType: "application/json",
			Kind:        classify.KindJSON,
		},
	}, Options{PauseMs: 1, IncludeBody: true})

	if robotsCalls.Load() != 2 {
		t.Fatalf("expected transient /robots.txt failure to retry once (2 calls), got %d", robotsCalls.Load())
	}
	if out[0].Outcome != classify.OutcomeOK {
		t.Fatalf("expected POST CXS request to succeed after /robots.txt retry, got: %+v", out[0])
	}
	if receivedMethod != "POST" || receivedCT != "application/json" || !strings.Contains(receivedBody, `"searchText":"Architect"`) {
		t.Fatalf("unexpected POST payload: method=%q ct=%q body=%q", receivedMethod, receivedCT, receivedBody)
	}
	if out[0].Timing.RobotsMs < 0 {
		t.Fatalf("expected Timing.RobotsMs to be recorded, got: %+v", out[0].Timing)
	}
}
