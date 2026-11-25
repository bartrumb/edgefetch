package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bartrumb/edgefetch/v2/internal/classify"
	"github.com/bartrumb/edgefetch/v2/internal/crawl"
	"github.com/bartrumb/edgefetch/v2/internal/politeness"
)

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

type otlpCaptured struct {
	ServiceName  string
	TraceID      string
	SpanID       string
	ParentSpanID string
	Name         string
	Attributes   map[string]any
}

func startMockOTLPCollector(t *testing.T) (*httptest.Server, func() ([]otlpCaptured, string)) {
	t.Helper()
	var (
		mu       sync.Mutex
		rawBytes []byte
		spans    []otlpCaptured
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/traces" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		b, _ := io.ReadAll(r.Body)
		var payload struct {
			ResourceSpans []struct {
				Resource struct {
					Attributes []struct {
						Key   string `json:"key"`
						Value struct {
							StringValue string `json:"stringValue"`
						} `json:"value"`
					} `json:"attributes"`
				} `json:"resource"`
				ScopeSpans []struct {
					Spans []struct {
						TraceID      string `json:"traceId"`
						SpanID       string `json:"spanId"`
						ParentSpanID string `json:"parentSpanId"`
						Name         string `json:"name"`
						Attributes   []struct {
							Key   string         `json:"key"`
							Value map[string]any `json:"value"`
						} `json:"attributes"`
					} `json:"spans"`
				} `json:"scopeSpans"`
			} `json:"resourceSpans"`
		}
		_ = json.Unmarshal(b, &payload)

		mu.Lock()
		rawBytes = append(rawBytes, b...)
		for _, rs := range payload.ResourceSpans {
			svc := ""
			for _, ra := range rs.Resource.Attributes {
				if ra.Key == "service.name" {
					svc = ra.Value.StringValue
				}
			}
			for _, ss := range rs.ScopeSpans {
				for _, sp := range ss.Spans {
					attrs := make(map[string]any, len(sp.Attributes))
					for _, a := range sp.Attributes {
						for _, val := range a.Value {
							attrs[a.Key] = val
						}
					}
					spans = append(spans, otlpCaptured{
						ServiceName:  svc,
						TraceID:      sp.TraceID,
						SpanID:       sp.SpanID,
						ParentSpanID: sp.ParentSpanID,
						Name:         sp.Name,
						Attributes:   attrs,
					})
				}
			}
		}
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	snapshot := func() ([]otlpCaptured, string) {
		mu.Lock()
		defer mu.Unlock()
		cp := make([]otlpCaptured, len(spans))
		copy(cp, spans)
		return cp, string(rawBytes)
	}
	return srv, snapshot
}

func TestMCPStdioOTLPAndPureStdout(t *testing.T) {
	t.Parallel()
	collector, snapshot := startMockOTLPCollector(t)

	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/robots.txt", "/llms.txt":
			w.WriteHeader(http.StatusNotFound)
		case "/sitemap.xml":
			w.Header().Set("Content-Type", "application/xml")
			_, _ = w.Write([]byte(`<urlset><url><loc>https://docs.example.com/a</loc></url></urlset>`))
		default:
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write([]byte(`<!doctype html><html><head><title>Stdio OTLP</title></head><body><main><h1>Stdio OTLP</h1><p>Pure JSON-RPC stdout.</p></main></body></html>`))
		}
	}))
	defer origin.Close()

	originAddr := origin.Listener.Addr().String()
	tlsCfg := origin.Client().Transport.(*http.Transport).TLSClientConfig
	mockTransport := &http.Transport{
		TLSClientConfig: tlsCfg,
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, originAddr)
		},
	}

	const callerTraceID = "4bf92f3577b34da6a3ce929d0e0e4736"
	const callerSpanID = "00f067aa0ba902b7"
	tp := "00-" + callerTraceID + "-" + callerSpanID + "-01"

	deps := cliDeps{
		getenv: func(k string) string {
			switch k {
			case "OTEL_EXPORTER_OTLP_ENDPOINT":
				return collector.URL
			case "EDGEFETCH_OTEL_STDOUT":
				return "1"
			default:
				return ""
			}
		},
		transport: mockTransport,
		allow:     func(*url.URL) error { return nil },
	}

	stdioInput := strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26"}}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"scrape","arguments":{"url":"https://docs.example.com/page?token=SECRET_STDIO#frag"},"_meta":{"traceparent":"` + tp + `"}}}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"fetch_url","arguments":{"url":"https://docs.example.com/raw?k=SECRET_FETCH"}}}`,
		`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"fetch_batch","arguments":{"urls":["https://docs.example.com/b1"]}}}`,
		`{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"map","arguments":{"url":"https://docs.example.com/"}}}`,
		`{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"doctor","arguments":{}}}`,
		`{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"scrape","arguments":{"url":"bad-url"}}}`,
		`{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"no_such_tool","arguments":{}}}`,
	}, "\n") + "\n"

	var stdout, stderr bytes.Buffer
	if rc := runMCPStdio(context.Background(), strings.NewReader(stdioInput), &stdout, &stderr, deps); rc != 0 {
		t.Fatalf("runMCPStdio failed: rc=%d stderr=%s", rc, stderr.String())
	}

	lines := strings.Split(strings.TrimSpace(stdout.String()), "\n")
	if len(lines) != 8 {
		t.Fatalf("expected strictly 8 JSON-RPC lines on stdout, got %d:\n%s", len(lines), stdout.String())
	}
	for i, ln := range lines {
		var frame map[string]any
		if err := json.Unmarshal([]byte(ln), &frame); err != nil || frame["jsonrpc"] != "2.0" {
			t.Fatalf("stdout line %d is not pure JSON-RPC 2.0: %q (err=%v)", i+1, ln, err)
		}
	}

	spans, raw := snapshot()
	if strings.Contains(raw, "SECRET_STDIO") || strings.Contains(raw, "SECRET_FETCH") || strings.Contains(raw, "#frag") {
		t.Fatalf("SECURITY: secret leaked in stdio MCP OTLP payload:\n%s", raw)
	}

	var mcpScrapeSpanID, batchParentID, fetchParentID, batchSpanID string
	mcpCount := 0
	for _, sp := range spans {
		if sp.ServiceName != "edgefetch-mcp-stdio" {
			t.Fatalf("expected service.name=edgefetch-mcp-stdio, got %q", sp.ServiceName)
		}
		if sp.Name == "edgefetch.mcp.tool" {
			mcpCount++
			if sp.TraceID == callerTraceID && sp.Attributes["mcp.tool.name"] == "scrape" && sp.ParentSpanID == callerSpanID {
				mcpScrapeSpanID = sp.SpanID
			}
		}
		if sp.TraceID == callerTraceID && sp.Name == "edgefetch.go.batch" {
			batchParentID = sp.ParentSpanID
			batchSpanID = sp.SpanID
		}
		if sp.TraceID == callerTraceID && strings.HasPrefix(sp.Name, "edgefetch.go.fetch.") {
			fetchParentID = sp.ParentSpanID
		}
	}
	if mcpCount != 7 {
		t.Fatalf("expected 7 edgefetch.mcp.tool spans, got %d", mcpCount)
	}
	if mcpScrapeSpanID == "" || batchParentID != mcpScrapeSpanID || fetchParentID != batchSpanID {
		t.Fatalf("expected scrape -> batch -> fetch linkage under callerTraceID; mcp=%q batchParent=%q batch=%q fetchParent=%q",
			mcpScrapeSpanID, batchParentID, batchSpanID, fetchParentID)
	}
}

func TestServeAndDesktopModeOTLP(t *testing.T) {
	t.Parallel()
	reListenURL := regexp.MustCompile(`http://127\.0\.0\.1:\d+`)

	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/robots.txt" || r.URL.Path == "/llms.txt" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(`<html><body><main><h1>Serve Desktop OTLP</h1></main></body></html>`))
	}))
	t.Cleanup(origin.Close)

	originAddr := origin.Listener.Addr().String()
	tlsCfg := origin.Client().Transport.(*http.Transport).TLSClientConfig
	mockTransport := &http.Transport{
		TLSClientConfig: tlsCfg,
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, originAddr)
		},
	}

	for _, tc := range []struct {
		mode        string
		wantService string
		args        []string
	}{
		{"serve", "edgefetch-serve", []string{"--port=0"}},
		{"desktop", "edgefetch-desktop", []string{"--port=0", "--no-open"}},
	} {
		tc := tc
		t.Run(tc.mode, func(t *testing.T) {
			t.Parallel()
			collector, snapshot := startMockOTLPCollector(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			var stdout, stderr syncBuffer
			done := make(chan int, 1)
			deps := cliDeps{
				getenv: func(k string) string {
					if k == "OTEL_EXPORTER_OTLP_ENDPOINT" {
						return collector.URL
					}
					return ""
				},
				transport: mockTransport,
				allow:     func(*url.URL) error { return nil },
			}

			go func() {
				if tc.mode == "serve" {
					done <- runServeModeWithDeps(ctx, tc.args, &stdout, &stderr, deps)
				} else {
					done <- runDesktopModeWithDeps(ctx, tc.args, &stdout, &stderr, deps)
				}
			}()

			var baseURL string
			deadline := time.Now().Add(4 * time.Second)
			for time.Now().Before(deadline) {
				if m := reListenURL.FindString(stdout.String()); m != "" {
					baseURL = m
					break
				}
				time.Sleep(20 * time.Millisecond)
			}
			if baseURL == "" {
				cancel()
				t.Fatalf("%s did not print listening URL; stdout=%q stderr=%q", tc.mode, stdout.String(), stderr.String())
			}

			resp, err := http.Post(baseURL+"/v1/scrape", "application/json", strings.NewReader(`{"url":"https://docs.example.com/test?secret=NOPE"}`))
			if err != nil {
				cancel()
				t.Fatalf("POST /v1/scrape failed: %v", err)
			}
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusOK || resp.Header.Get("X-Trace-Id") == "" {
				cancel()
				t.Fatalf("unexpected /v1/scrape response: status=%d trace=%q", resp.StatusCode, resp.Header.Get("X-Trace-Id"))
			}

			cancel()
			select {
			case rc := <-done:
				if rc != 0 {
					t.Fatalf("%s exited %d: stderr=%s", tc.mode, rc, stderr.String())
				}
			case <-time.After(5 * time.Second):
				t.Fatalf("%s shutdown timed out", tc.mode)
			}

			spans, raw := snapshot()
			if strings.Contains(raw, "NOPE") {
				t.Fatalf("SECURITY: query secret leaked in %s OTLP spans: %s", tc.mode, raw)
			}
			sawHTTP := false
			sawFetch := false
			for _, sp := range spans {
				if sp.ServiceName != tc.wantService {
					t.Fatalf("expected service.name=%q, got %q", tc.wantService, sp.ServiceName)
				}
				if sp.Name == "edgefetch.http" {
					sawHTTP = true
				}
				if strings.HasPrefix(sp.Name, "edgefetch.go.fetch.") {
					sawFetch = true
				}
			}
			if !sawHTTP || !sawFetch {
				t.Fatalf("expected edgefetch.http and edgefetch.go.fetch.* spans for %s, got %+v", tc.mode, spans)
			}
		})
	}
}

func TestShouldAllowPrivateOriginAndAgentCrawlPolicy(t *testing.T) {
	t.Parallel()
	if shouldAllowPrivateOrigin(nil, nil) {
		t.Fatal("SECURITY: default shouldAllowPrivateOrigin must be false")
	}
	if shouldAllowPrivateOrigin([]string{"--mode=agent"}, func(k string) string {
		if k == "EDGEFETCH_ALLOW_PRIVATE_ORIGIN" {
			return "0"
		}
		return ""
	}) {
		t.Fatal("SECURITY: EDGEFETCH_ALLOW_PRIVATE_ORIGIN=0 must remain false")
	}
	if !shouldAllowPrivateOrigin([]string{"--mode=agent", "--allow-private"}, nil) {
		t.Fatal("expected --allow-private to enable private origin opt-in")
	}
	if !shouldAllowPrivateOrigin([]string{"--mode=agent"}, func(k string) string {
		if k == "EDGEFETCH_ALLOW_PRIVATE_ORIGIN" {
			return "1"
		}
		return ""
	}) {
		t.Fatal("expected EDGEFETCH_ALLOW_PRIVATE_ORIGIN=1 to enable private origin opt-in")
	}

	mockOrigin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer mockOrigin.Close()
	originParsed, _ := url.Parse(mockOrigin.URL)

	// 1. Default policy (allowPrivate=false): strictly rejects loopback/http URLs and rejects loopback dials at dial-time!
	defAllow, defTr := newAgentCrawlPolicy(false, nil, []string{"http://127.0.0.1:8787"}, 60*time.Second, 2)
	for _, blocked := range []string{
		mockOrigin.URL + "/a",
		"http://localhost:" + originParsed.Port() + "/a",
		"https://127.0.0.1/a",
		"https://example.com:8443/a",
		"http://127.0.0.1:8787/v1/scrape",
	} {
		u, _ := url.Parse(blocked)
		if err := defAllow(u); err == nil {
			t.Fatalf("SECURITY: default allow policy permitted %q", blocked)
		}
	}
	pubU, _ := url.Parse("https://example.com/ok")
	if err := defAllow(pubU); err != nil {
		t.Fatalf("default allow rejected valid public HTTPS URL: %v", err)
	}
	// Verify default transport enforces politeness.RejectNonPublicPeer at dial time!
	if _, err := (&http.Client{Transport: defTr, Timeout: 2 * time.Second}).Get(mockOrigin.URL); !errors.Is(err, politeness.ErrNonPublicPeer) {
		t.Fatalf("SECURITY: expected politeness.ErrNonPublicPeer from default agent transport, got %v", err)
	}

	// 2. Opt-in policy (allowPrivate=true): permits sibling loopback origin port while blocking Hub authority, userinfo, and non-http schemes!
	optAllow, optTr := newAgentCrawlPolicy(true, nil, []string{"http://127.0.0.1:8787"}, 60*time.Second, 2)
	for _, permitted := range []string{
		mockOrigin.URL + "/docs",
		"http://localhost:" + originParsed.Port() + "/docs",
		"https://example.com/docs",
	} {
		u, _ := url.Parse(permitted)
		if err := optAllow(u); err != nil {
			t.Fatalf("opt-in allow rejected valid URL %q: %v", permitted, err)
		}
	}
	for _, stillBlocked := range []string{
		"http://127.0.0.1:8787/v1/scrape",
		"http://localhost:8787/v1/scrape",
		"http://[::1]:8787/agent/ws",
		"file:///etc/passwd",
		"http://user:pass@127.0.0.1:" + originParsed.Port() + "/a",
	} {
		u, _ := url.Parse(stillBlocked)
		if err := optAllow(u); err == nil {
			t.Fatalf("SECURITY: opt-in policy failed to block %q", stillBlocked)
		}
	}
	resp, err := (&http.Client{Transport: optTr, Timeout: 2 * time.Second}).Get(mockOrigin.URL + "/ok")
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("expected opt-in transport to reach loopback mock origin, got resp=%v err=%v", resp, err)
	}
	_ = resp.Body.Close()

	// 3. Unspecified IP addresses (0.0.0.0, ::, ::ffff:0.0.0.0) must always be denied by allowHTTPAndHTTPSNoUserInfo & newAgentCrawlPolicy(true, ...).
	for _, unspec := range []string{
		"http://0.0.0.0:8787/health",
		"http://[::]:8787/health",
		"http://[::ffff:0.0.0.0]:8787/health",
		"http://0.0.0.0:" + originParsed.Port() + "/ok",
		"http://[::]:" + originParsed.Port() + "/ok",
		"http://[::ffff:0.0.0.0]:" + originParsed.Port() + "/ok",
		"http://[::%25lo]:8787/health",
	} {
		u, err := url.Parse(unspec)
		if err != nil {
			t.Fatalf("url.Parse(%q): %v", unspec, err)
		}
		if err := allowHTTPAndHTTPSNoUserInfo(u); err == nil {
			t.Fatalf("SECURITY: allowHTTPAndHTTPSNoUserInfo permitted unspecified IP %q", unspec)
		}
		if err := optAllow(u); err == nil {
			t.Fatalf("SECURITY: opt-in agent policy permitted unspecified IP %q", unspec)
		}
	}

	// 4. Implicit-port & leading-zero-port loopback Hub URL checks.
	if got := normalizeURLPort(&url.URL{Scheme: "http", Host: "127.0.0.1:08787"}); got != "8787" {
		t.Fatalf("expected normalizeURLPort(:08787) == \"8787\", got %q", got)
	}
	if got := normalizeURLPort(&url.URL{Scheme: "http", Host: "localhost:0080"}); got != "80" {
		t.Fatalf("expected normalizeURLPort(:0080) == \"80\", got %q", got)
	}
	for _, blocked := range []string{
		"http://127.0.0.1:08787/health",
		"http://localhost:08787/health",
		"http://[::1]:08787/health",
	} {
		u, _ := url.Parse(blocked)
		if err := optAllow(u); err == nil {
			t.Fatalf("SECURITY: opt-in policy failed to block leading-zero port %q", blocked)
		}
	}

	implicitAllow, _ := newAgentCrawlPolicy(true, nil, []string{"http://127.0.0.1"}, 60*time.Second, 2)
	for _, blocked := range []string{
		"http://127.0.0.1/health",
		"http://localhost/health",
		"http://localhost:80/health",
		"http://localhost:0080/health",
		"http://127.0.0.1:0080/health",
		"http://[::1]:80/health",
		"http://127.0.0.2:80/health",
		"http://0.0.0.0:80/health",
	} {
		u, _ := url.Parse(blocked)
		if err := implicitAllow(u); err == nil {
			t.Fatalf("SECURITY: implicit-port Hub policy failed to block %q", blocked)
		}
	}
	if u, _ := url.Parse("http://127.0.0.1:9999/ok"); implicitAllow(u) != nil {
		t.Fatalf("expected implicit-port Hub policy to allow http://127.0.0.1:9999/ok")
	}

	// 5. Live 302 redirect from mock origin to unspecified IP & leading-zero port aliases on Hub port must be blocked with 0 Hub hits.
	var hubHealthHits atomic.Int32
	mockHub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hubHealthHits.Add(1)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true,"mode":"hub"}`))
	}))
	defer mockHub.Close()
	hubParsed, _ := url.Parse(mockHub.URL)

	redirOrigin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/robots.txt":
			w.WriteHeader(http.StatusNotFound)
		case "/redir-0000":
			http.Redirect(w, r, "http://0.0.0.0:"+hubParsed.Port()+"/health", http.StatusFound)
		case "/redir-v6unspec":
			http.Redirect(w, r, "http://[::]:"+hubParsed.Port()+"/health", http.StatusFound)
		case "/redir-v4mapped":
			http.Redirect(w, r, "http://[::ffff:0.0.0.0]:"+hubParsed.Port()+"/health", http.StatusFound)
		case "/redir-leadingzero":
			http.Redirect(w, r, "http://127.0.0.1:0"+hubParsed.Port()+"/health", http.StatusFound)
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer redirOrigin.Close()

	redirAllow, redirTr := newAgentCrawlPolicy(true, nil, []string{mockHub.URL}, 60*time.Second, 2)
	c := crawl.NewCrawler(redirTr, redirAllow, crawl.DefaultUserAgent, slog.New(slog.NewJSONHandler(io.Discard, nil)))
	defer func() { _ = c.Close() }()
	rep := crawl.ExecuteCall(context.Background(), c, crawl.FetchCall{
		MaxSeconds: 15,
		Options:    crawl.Options{Concurrency: 1, PauseMs: 1, RespectRobots: crawl.Bool(true)},
		Requests: []crawl.Request{
			{ID: "r1", URL: redirOrigin.URL + "/redir-0000", Kind: classify.KindScrape, RenderMode: "off"},
			{ID: "r2", URL: redirOrigin.URL + "/redir-v6unspec", Kind: classify.KindScrape, RenderMode: "off"},
			{ID: "r3", URL: redirOrigin.URL + "/redir-v4mapped", Kind: classify.KindScrape, RenderMode: "off"},
			{ID: "r4", URL: redirOrigin.URL + "/redir-leadingzero", Kind: classify.KindScrape, RenderMode: "off"},
		},
	}, slog.New(slog.NewJSONHandler(io.Discard, nil)))
	if len(rep.Results) != 4 {
		t.Fatalf("expected 4 redirect results, got %d", len(rep.Results))
	}
	for _, res := range rep.Results {
		if res.Outcome != classify.OutcomeBlockedSSRF && res.Outcome != classify.OutcomeError {
			t.Fatalf("SECURITY: expected redirect to unspecified/leading-zero Hub IP to fail, got %+v", res)
		}
	}
	if hubHealthHits.Load() != 0 {
		t.Fatalf("SECURITY: expected 0 hits on mock Hub during unspecified/leading-zero redirect crawl, got %d", hubHealthHits.Load())
	}
}

func TestAgentPrivateTransportDialControlHubGuard(t *testing.T) {
	t.Parallel()
	const hubPort = "18787"
	const originPort = "19999"

	// 1. Direct unit check of Control hook for loopback Hub authority & unspecified IPs.
	ctrl := newAgentPrivateControl([]string{"http://127.0.0.1:" + hubPort})
	for _, denied := range []string{
		"127.0.0.1:" + hubPort,
		"[::1]:" + hubPort,
		"127.0.0.2:" + hubPort,
		"[::ffff:127.0.0.1]:" + hubPort,
		"127.0.0.1:0" + hubPort,
		"0.0.0.0:" + originPort,
		"[::]:" + originPort,
		"[::ffff:0.0.0.0]:" + originPort,
	} {
		if err := ctrl("tcp", denied, nil); err == nil {
			t.Fatalf("SECURITY: expected dial Control to reject %q", denied)
		}
	}
	for _, permitted := range []string{
		"127.0.0.1:" + originPort,
		"[::1]:" + originPort,
		"93.184.216.34:" + hubPort,
	} {
		if err := ctrl("tcp", permitted, nil); err != nil {
			t.Fatalf("expected dial Control to permit %q, got %v", permitted, err)
		}
	}

	// Non-loopback literal Hub IP blocks matching IP+port (including IPv4-mapped IPv6) while allowing other ports/hosts.
	nonLBCtrl := newAgentPrivateControl([]string{"http://10.20.30.40:" + hubPort})
	for _, denied := range []string{
		"10.20.30.40:" + hubPort,
		"[::ffff:10.20.30.40]:" + hubPort,
		"0.0.0.0:" + originPort,
	} {
		if err := nonLBCtrl("tcp", denied, nil); err == nil {
			t.Fatalf("SECURITY: expected non-loopback Hub Control to reject %q", denied)
		}
	}
	for _, permitted := range []string{
		"10.20.30.40:" + originPort,
		"127.0.0.1:" + hubPort,
	} {
		if err := nonLBCtrl("tcp", permitted, nil); err != nil {
			t.Fatalf("expected non-loopback Hub Control to permit %q, got %v", permitted, err)
		}
	}

	// 2. Live dual-stack (or IPv4+IPv6) Hub listener + sibling mock origin probed via opt-in crawlTr (and Crawler).
	siblingOrigin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/robots.txt" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("sibling-ok"))
	}))
	defer siblingOrigin.Close()

	var hubHits atomic.Int32
	hubLn, err := net.Listen("tcp", ":0")
	if err != nil {
		hubLn, err = net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("net.Listen failed: %v", err)
		}
	}
	defer func() { _ = hubLn.Close() }()
	_, liveHubPort, _ := net.SplitHostPort(hubLn.Addr().String())
	hubSrv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hubHits.Add(1)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"ok":true}`))
		}),
	}
	go func() { _ = hubSrv.Serve(hubLn) }()
	defer func() { _ = hubSrv.Close() }()

	liveHubURL := "http://127.0.0.1:" + liveHubPort
	allow, crawlTr := newAgentCrawlPolicy(true, nil, []string{liveHubURL}, 60*time.Second, 2)

	// Verify crawlTr.DialContext itself invokes the Control hook for all blocked addresses before any socket connect.
	for _, dialAddr := range []string{
		"127.0.0.1:" + liveHubPort,
		"[::1]:" + liveHubPort,
		"127.0.0.2:" + liveHubPort,
		"0.0.0.0:" + originPort,
		"[::]:" + originPort,
	} {
		dctx, dcancel := context.WithTimeout(context.Background(), 2*time.Second)
		conn, derr := crawlTr.DialContext(dctx, "tcp", dialAddr)
		dcancel()
		if derr == nil {
			if conn != nil {
				_ = conn.Close()
			}
			t.Fatalf("SECURITY: crawlTr.DialContext(%q) succeeded, expected Control rejection", dialAddr)
		}
	}

	// Verify live http.Client{Transport: crawlTr} (bypassing allow(u)) fails dialing Hub via localhost and ip6-localhost (if resolved).
	httpClient := &http.Client{Transport: crawlTr, Timeout: 2 * time.Second}
	if resp, gerr := httpClient.Get("http://localhost:" + liveHubPort + "/health"); gerr == nil {
		_ = resp.Body.Close()
		t.Fatal("SECURITY: http.Client with opt-in crawlTr reached Hub via localhost")
	}
	if addrs, lerr := net.LookupHost("ip6-localhost"); lerr == nil && len(addrs) > 0 {
		if resp, gerr := httpClient.Get("http://ip6-localhost:" + liveHubPort + "/health"); gerr == nil {
			_ = resp.Body.Close()
			t.Fatal("SECURITY: http.Client with opt-in crawlTr reached Hub via ip6-localhost")
		}
		// Also verify full Crawler execution for ip6-localhost on Hub port fails (both with default robots.txt and with robots bypass) with 0 Hub hits.
		c := crawl.NewCrawler(crawlTr, allow, crawl.DefaultUserAgent, slog.New(slog.NewJSONHandler(io.Discard, nil)))
		rep := crawl.ExecuteCall(context.Background(), c, crawl.FetchCall{
			MaxSeconds: 10,
			Options:    crawl.Options{Concurrency: 1, PauseMs: 1, RespectRobots: crawl.Bool(true)},
			Requests: []crawl.Request{
				{ID: "ip6", URL: "http://ip6-localhost:" + liveHubPort + "/health", Kind: classify.KindScrape, RenderMode: "off"},
			},
		}, slog.New(slog.NewJSONHandler(io.Discard, nil)))
		_ = c.Close()
		if len(rep.Results) != 1 || rep.Results[0].Outcome == classify.OutcomeOK || rep.Results[0].Status != 0 || !strings.Contains(rep.Results[0].Problem, "refusing dial") {
			t.Fatalf("SECURITY: expected crawler ip6-localhost Hub fetch (robots enabled) to be blocked by Control, got %+v", rep.Results)
		}

		c2 := crawl.NewCrawler(crawlTr, allow, crawl.DefaultUserAgent, slog.New(slog.NewJSONHandler(io.Discard, nil)))
		c2.SetRobotsBypassHosts([]string{"ip6-localhost"})
		rep2 := crawl.ExecuteCall(context.Background(), c2, crawl.FetchCall{
			MaxSeconds: 10,
			Options:    crawl.Options{Concurrency: 1, PauseMs: 1, RespectRobots: crawl.Bool(false)},
			Requests: []crawl.Request{
				{ID: "ip6-direct", URL: "http://ip6-localhost:" + liveHubPort + "/health", Kind: classify.KindScrape, RenderMode: "off"},
			},
		}, slog.New(slog.NewJSONHandler(io.Discard, nil)))
		_ = c2.Close()
		if len(rep2.Results) != 1 || rep2.Results[0].Outcome != classify.OutcomeError || rep2.Results[0].Status != 0 || !strings.Contains(rep2.Results[0].Problem, "refusing dial") {
			t.Fatalf("SECURITY: expected crawler ip6-localhost Hub direct fetch to return OutcomeError from Control, got %+v", rep2.Results)
		}
	}

	// Confirm sibling mock origin on another loopback port succeeds through the exact same crawlTr!
	resp, serr := httpClient.Get(siblingOrigin.URL + "/ok")
	if serr != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("expected sibling origin GET to succeed via crawlTr, got resp=%v err=%v", resp, serr)
	}
	_ = resp.Body.Close()

	if hits := hubHits.Load(); hits != 0 {
		t.Fatalf("SECURITY: expected 0 TCP/HTTP hits on live Hub listener, got %d", hits)
	}
}

func TestCLIModeMCPFlagAlignment(t *testing.T) {
	t.Parallel()
	for _, yes := range [][]string{
		{"mcp"},
		{"--mode=mcp"},
		{"-mode=mcp"},
		{"--mode", "mcp"},
		{"-mode", "mcp"},
		{"--mode=mcp", "--addr=127.0.0.1:0"},
		{"--addr=127.0.0.1:0", "--mode=mcp"},
	} {
		if !isOneShotCLI(yes) {
			t.Fatalf("expected isOneShotCLI(%v) == true", yes)
		}
	}
	for _, no := range [][]string{
		nil,
		{"--mode=server"},
		{"--mode=hub"},
		{"--mode=agent"},
		{"--mode=mcp,hub"},
		{"--mode=mcp,agent"},
		{"--mode=agent,mcp"},
		{"--mode=mcp,server"},
		{"--mode"},
	} {
		if isOneShotCLI(no) {
			t.Fatalf("expected isOneShotCLI(%v) == false", no)
		}
	}

	for _, invalid := range [][]string{
		{"--mode=mcp,hub"},
		{"--mode=mcp,agent"},
		{"--mode=mcp,server"},
		{"--mode=unknown"},
		{"--mode="},
		{"--mode"},
		{"--mode", "--addr=127.0.0.1:0"},
	} {
		if _, err := parseRuntimeModes(invalid, "", ""); err == nil {
			t.Fatalf("expected parseRuntimeModes(%v) to reject invalid mode", invalid)
		}
	}
	if m, err := parseRuntimeModes([]string{"--mode=mcp"}, "", ""); err != nil || !m.mcp || m.server || m.hub || m.agent {
		t.Fatalf("expected --mode=mcp -> mcp=true, got %+v err=%v", m, err)
	}
	if m, err := parseRuntimeModes([]string{"--mode", "mcp"}, "", ""); err != nil || !m.mcp {
		t.Fatalf("expected --mode mcp -> mcp=true, got %+v err=%v", m, err)
	}
	if m, err := parseRuntimeModes(nil, "mcp", ""); err != nil || !m.mcp {
		t.Fatalf("expected envMode=mcp -> mcp=true, got %+v err=%v", m, err)
	}

	collector, snapshot := startMockOTLPCollector(t)
	stdioInput := strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26"}}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"doctor","arguments":{}}}`,
	}, "\n") + "\n"

	for _, args := range [][]string{
		{"--mode=mcp", "--addr=127.0.0.1:0"},
		{"--mode", "mcp"},
	} {
		var stdout, stderr bytes.Buffer
		deps := cliDeps{
			getenv: func(k string) string {
				if k == "OTEL_EXPORTER_OTLP_ENDPOINT" {
					return collector.URL
				}
				return ""
			},
			stdin: strings.NewReader(stdioInput),
		}
		if rc := runOneShotCLI(context.Background(), args, &stdout, &stderr, deps); rc != 0 {
			t.Fatalf("runOneShotCLI(%v) failed: rc=%d stderr=%s", args, rc, stderr.String())
		}
		lines := strings.Split(strings.TrimSpace(stdout.String()), "\n")
		if len(lines) != 2 {
			t.Fatalf("expected 2 JSON-RPC stdout lines for %v, got %d:\n%s", args, len(lines), stdout.String())
		}
		for i, ln := range lines {
			var frame map[string]any
			if err := json.Unmarshal([]byte(ln), &frame); err != nil || frame["jsonrpc"] != "2.0" {
				t.Fatalf("stdout line %d for %v is not pure JSON-RPC 2.0: %q (err=%v)", i+1, args, ln, err)
			}
		}
	}

	spans, _ := snapshot()
	mcpDoctorCount := 0
	for _, sp := range spans {
		if sp.ServiceName != "edgefetch-mcp-stdio" {
			t.Fatalf("expected service.name=edgefetch-mcp-stdio, got %q", sp.ServiceName)
		}
		if sp.Name == "edgefetch.mcp.tool" && sp.Attributes["mcp.tool.name"] == "doctor" {
			mcpDoctorCount++
		}
	}
	if mcpDoctorCount != 2 {
		t.Fatalf("expected 2 doctor edgefetch.mcp.tool spans across --mode=mcp and --mode mcp, got %d", mcpDoctorCount)
	}
}
