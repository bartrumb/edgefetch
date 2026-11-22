package agent

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/bartrumb/edgefetch/v2/internal/browser"
	"github.com/bartrumb/edgefetch/v2/internal/classify"
	"github.com/bartrumb/edgefetch/v2/internal/crawl"
	"github.com/bartrumb/edgefetch/v2/internal/otel"
)

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

type errRoundTripper struct {
	err   error
	calls atomic.Int32
}

func (e *errRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	e.calls.Add(1)
	return nil, e.err
}

func TestConfigLoadAndValidationComprehensive(t *testing.T) {
	// LoadConfig wrapper + isDockerBridgeHost custom host + isLoopbackHost variants.
	t.Setenv("EDGEFETCH_HUB_URL", "http://custom-bridge:8787")
	t.Setenv("EDGEFETCH_ALLOW_INSECURE_DOCKER_HUB", "1")
	t.Setenv("EDGEFETCH_INSECURE_HUB_HOST", "custom-bridge")
	t.Setenv("EDGEFETCH_AGENT_TOKEN", "secret-agent-token-0123456789")
	t.Setenv("EDGEFETCH_SITE_ID", "site-custom")
	cfg, err := LoadConfig("")
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.HubURL != "http://custom-bridge:8787" || cfg.SiteID != "site-custom" {
		t.Fatalf("unexpected LoadConfig result: %+v", cfg)
	}

	if !isLoopbackHost("127.0.0.1") || !isLoopbackHost("::1") || !isLoopbackHost("LOCALHOST") || isLoopbackHost("example.com") {
		t.Fatal("isLoopbackHost mismatch")
	}
	for _, h := range []string{"hub", "edgefetch-hub", "edgefetch", "host.docker.internal", "custom-bridge"} {
		if !isDockerBridgeHost(h) {
			t.Fatalf("expected isDockerBridgeHost(%q) == true", h)
		}
	}
	if isDockerBridgeHost("public.example.com") {
		t.Fatal("expected public host to fail isDockerBridgeHost")
	}

	dir := t.TempDir()
	// EISDIR on ReadFile when optionsPath is a directory.
	if _, err := LoadConfigFrom(dir, func(string) string { return "" }); err == nil || !strings.Contains(err.Error(), "read ") {
		t.Fatalf("expected read error for directory path, got %v", err)
	}

	// Malformed JSON options file.
	badJSON := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(badJSON, []byte("{invalid"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfigFrom(badJSON, func(string) string { return "" }); err == nil || !strings.Contains(err.Error(), "parse ") {
		t.Fatalf("expected parse error for bad JSON, got %v", err)
	}

	// Whitespace-only options file + blank user_agent in JSON fallback.
	wsJSON := filepath.Join(dir, "ws.json")
	if err := os.WriteFile(wsJSON, []byte("   \n\t  "), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfigFrom(wsJSON, func(k string) string {
		switch k {
		case "EDGEFETCH_HUB_URL":
			return "https://hub.example.com"
		case "EDGEFETCH_AGENT_TOKEN":
			return "secret-agent-token-0123456789"
		case "EDGEFETCH_SITE_ID":
			return "site-ws"
		default:
			return ""
		}
	}); err != nil {
		t.Fatalf("expected whitespace options.json to succeed: %v", err)
	}

	blankUAJSON := filepath.Join(dir, "blank_ua.json")
	if err := os.WriteFile(blankUAJSON, []byte(`{"hub_url":"https://hub.example.com","agent_token":"secret-agent-token-0123456789","site_id":"site-1","user_agent":"   "}`), 0o600); err != nil {
		t.Fatal(err)
	}
	blankUACfg, err := LoadConfigFrom(blankUAJSON, func(string) string { return "" })
	if err != nil || blankUACfg.UserAgent != crawl.DefaultUserAgent {
		t.Fatalf("expected blank user_agent in JSON to fall back to DefaultUserAgent, got %+v (err=%v)", blankUACfg, err)
	}

	// Env overrides: HUB_URLS dedup, USER_AGENT, PAUSE_MS clamps, JITTER clamps, ALLOWED_HOSTS.
	baseEnv := map[string]string{
		"EDGEFETCH_HUB_URLS":        "https://a.example.com, , wss://b.example.com/agent/ws/, https://a.example.com/",
		"EDGEFETCH_HUB_URL":         "/agent/ws", // normalizes to ""
		"EDGEFETCH_AGENT_TOKEN":     "secret-agent-token-0123456789",
		"EDGEFETCH_SITE_ID":         "site-ha",
		"EDGEFETCH_USER_AGENT":      "CustomEnvBot/1.0 (+https://example.com)",
		"EDGEFETCH_PAUSE_MS":        "100",
		"EDGEFETCH_PAUSE_JITTER_MS": "-5",
		"EDGEFETCH_ALLOWED_HOSTS":   "a.example.com, , b.example.com",
	}
	envFn := func(m map[string]string) func(string) string {
		return func(k string) string { return m[k] }
	}
	haCfg, err := LoadConfigFrom("", envFn(baseEnv))
	if err != nil {
		t.Fatalf("LoadConfigFrom HA env: %v", err)
	}
	if len(haCfg.HubURLs) != 2 || haCfg.HubURL != "https://a.example.com" || haCfg.PauseMs != 1000 || haCfg.PauseJitterMs != 0 || len(haCfg.AllowedHosts) != 2 || haCfg.UserAgent != "CustomEnvBot/1.0 (+https://example.com)" {
		t.Fatalf("unexpected HA config: %+v", haCfg)
	}

	// Upper clamps.
	upperEnv := map[string]string{
		"EDGEFETCH_HUB_URL":         "https://a.example.com",
		"EDGEFETCH_AGENT_TOKEN":     "secret-agent-token-0123456789",
		"EDGEFETCH_SITE_ID":         "site-upper",
		"EDGEFETCH_PAUSE_MS":        "120000",
		"EDGEFETCH_PAUSE_JITTER_MS": "999999",
	}
	upCfg, err := LoadConfigFrom("", envFn(upperEnv))
	if err != nil || upCfg.PauseMs != 60_000 || upCfg.PauseJitterMs != crawl.MaxPauseJitterMs {
		t.Fatalf("expected upper clamps (60000, %d), got %+v (err=%v)", crawl.MaxPauseJitterMs, upCfg, err)
	}

	// Validation error matrix.
	invalidCases := []struct {
		name string
		env  map[string]string
		sub  string
	}{
		{
			name: "invalid pause_ms",
			env:  map[string]string{"EDGEFETCH_HUB_URL": "https://a.example.com", "EDGEFETCH_AGENT_TOKEN": "secret-agent-token-0123456789", "EDGEFETCH_SITE_ID": "s1", "EDGEFETCH_PAUSE_MS": "not-int"},
			sub:  "invalid pause_ms",
		},
		{
			name: "invalid pause_jitter_ms",
			env:  map[string]string{"EDGEFETCH_HUB_URL": "https://a.example.com", "EDGEFETCH_AGENT_TOKEN": "secret-agent-token-0123456789", "EDGEFETCH_SITE_ID": "s1", "EDGEFETCH_PAUSE_JITTER_MS": "not-int"},
			sub:  "invalid pause_jitter_ms",
		},
		{
			name: "missing hub_url",
			env:  map[string]string{"EDGEFETCH_HUB_URL": "/agent/ws", "EDGEFETCH_AGENT_TOKEN": "secret-agent-token-0123456789", "EDGEFETCH_SITE_ID": "s1"},
			sub:  "hub_url is required",
		},
		{
			name: "invalid hub_url empty host",
			env:  map[string]string{"EDGEFETCH_HUB_URL": "https://", "EDGEFETCH_AGENT_TOKEN": "secret-agent-token-0123456789", "EDGEFETCH_SITE_ID": "s1"},
			sub:  "invalid hub_url",
		},
		{
			name: "invalid hub_url parse err",
			env:  map[string]string{"EDGEFETCH_HUB_URL": "://bad", "EDGEFETCH_AGENT_TOKEN": "secret-agent-token-0123456789", "EDGEFETCH_SITE_ID": "s1"},
			sub:  "invalid hub_url",
		},
		{
			name: "invalid user_agent",
			env:  map[string]string{"EDGEFETCH_HUB_URL": "https://a.example.com", "EDGEFETCH_AGENT_TOKEN": "secret-agent-token-0123456789", "EDGEFETCH_SITE_ID": "s1", "EDGEFETCH_USER_AGENT": "Bad\x01Agent"},
			sub:  "user",
		},
		{
			name: "short agent_token",
			env:  map[string]string{"EDGEFETCH_HUB_URL": "https://a.example.com", "EDGEFETCH_AGENT_TOKEN": "short", "EDGEFETCH_SITE_ID": "s1"},
			sub:  "agent_token",
		},
		{
			name: "invalid site_id",
			env:  map[string]string{"EDGEFETCH_HUB_URL": "https://a.example.com", "EDGEFETCH_AGENT_TOKEN": "secret-agent-token-0123456789", "EDGEFETCH_SITE_ID": "bad site!"},
			sub:  "site_id",
		},
	}
	for _, tc := range invalidCases {
		_, err := LoadConfigFrom("", envFn(tc.env))
		if err == nil || !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(tc.sub)) {
			t.Fatalf("%s: expected error containing %q, got %v", tc.name, tc.sub, err)
		}
	}
}

func TestWarmUpAndRunAllSingleMultiAndError(t *testing.T) {
	log := slog.New(slog.NewJSONHandler(io.Discard, nil))
	cr := crawl.NewCrawler(http.DefaultTransport, crawl.PublicHTTPS, crawl.DefaultUserAgent, log)

	// warmUpCrawlerBounded early returns + active call.
	warmUpCrawlerBounded(context.Background(), nil)
	cancelledCtx, cancelNow := context.WithCancel(context.Background())
	cancelNow()
	warmUpCrawlerBounded(cancelledCtx, cr)
	warmUpCrawlerBounded(context.Background(), cr)

	// RunAll with 0 hubs & cancelled ctx.
	if err := RunAll(cancelledCtx, Config{}, cr, crawl.PublicHTTPS, http.DefaultTransport, log, RuntimeOpts{WarmUpOnStart: true}); err != nil {
		t.Fatalf("expected nil on RunAll with cancelled ctx, got %v", err)
	}

	makeHub := func(onConnect func()) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/agent/ws" {
				http.NotFound(w, r)
				return
			}
			sc, err := websocket.Accept(w, r, nil)
			if err != nil {
				return
			}
			defer sc.CloseNow()
			if onConnect != nil {
				onConnect()
			}
			for {
				if _, _, err := sc.Read(r.Context()); err != nil {
					return
				}
			}
		}))
	}

	// Single Hub via fallback cfg.HubURL + WarmUpOnStart.
	var singleConn atomic.Int32
	hub1 := makeHub(func() { singleConn.Add(1) })
	defer hub1.Close()

	ctx1, cancel1 := context.WithCancel(context.Background())
	err1 := make(chan error, 1)
	go func() {
		err1 <- RunAll(ctx1, Config{
			HubURL:     hub1.URL,
			AgentToken: "agent-secret-token-0123456789-abcdef",
			SiteID:     "site-single",
			UserAgent:  crawl.DefaultUserAgent,
		}, cr, crawl.PublicHTTPS, http.DefaultTransport, log, RuntimeOpts{
			WarmUpOnStart: true,
			PingInterval:  time.Second,
			ReadWatchdog:  2 * time.Second,
			OnConnected:   func() { cancel1() },
		})
	}()
	if err := <-err1; err != nil {
		t.Fatalf("RunAll single hub failed: %v", err)
	}
	if singleConn.Load() < 1 {
		t.Fatal("expected single hub connection")
	}

	// Single Hub via cfg.HubURLs (len == 1).
	ctx1b, cancel1b := context.WithCancel(context.Background())
	if err := RunAll(ctx1b, Config{
		HubURLs:    []string{hub1.URL},
		AgentToken: "agent-secret-token-0123456789-abcdef",
		SiteID:     "site-single-urls",
		UserAgent:  crawl.DefaultUserAgent,
	}, cr, crawl.PublicHTTPS, http.DefaultTransport, log, RuntimeOpts{
		PingInterval: time.Second,
		ReadWatchdog: 2 * time.Second,
		OnConnected:  func() { cancel1b() },
	}); err != nil {
		t.Fatalf("RunAll len(HubURLs)==1 failed: %v", err)
	}

	// Multi-hub (len == 2) parallel fanout.
	hub2 := makeHub(nil)
	defer hub2.Close()

	var connectedCount atomic.Int32
	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	err2 := make(chan error, 1)
	go func() {
		err2 <- RunAll(ctx2, Config{
			HubURLs:    []string{hub1.URL, hub2.URL},
			AgentToken: "agent-secret-token-0123456789-abcdef",
			SiteID:     "site-multi",
			UserAgent:  crawl.DefaultUserAgent,
		}, cr, crawl.PublicHTTPS, http.DefaultTransport, log, RuntimeOpts{
			WarmUpOnStart: true,
			PingInterval:  time.Second,
			ReadWatchdog:  2 * time.Second,
			OnConnected: func() {
				if connectedCount.Add(1) >= 2 {
					cancel2()
				}
			},
		})
	}()
	select {
	case err := <-err2:
		if err != nil {
			t.Fatalf("RunAll multi-hub failed: %v", err)
		}
	case <-time.After(4 * time.Second):
		cancel2()
		t.Fatal("timed out waiting for multi-hub RunAll")
	}
	if connectedCount.Load() < 2 {
		t.Fatalf("expected 2 hub connections, got %d", connectedCount.Load())
	}

	// RunAll error propagation via unexported runHubFn seam.
	origRunHub := runHubFn
	t.Cleanup(func() { runHubFn = origRunHub })
	sentinel := errors.New("simulated hub runner failure")
	var callNum atomic.Int32
	runHubFn = func(_ context.Context, _ Config, _ *crawl.Crawler, _ func(*url.URL) error, _ http.RoundTripper, _ *slog.Logger, _ RuntimeOpts) error {
		if callNum.Add(1) == 1 {
			return sentinel
		}
		return nil
	}
	err := RunAll(context.Background(), Config{
		HubURLs: []string{"https://h1.example.com", "https://h2.example.com"},
	}, cr, crawl.PublicHTTPS, http.DefaultTransport, log, RuntimeOpts{})
	if !errors.Is(err, sentinel) {
		t.Fatalf("expected sentinel error from RunAll, got %v", err)
	}
}

func TestRunBackoffCapResetSleepCancelAndRedirectBlock(t *testing.T) {
	var logBuf syncBuffer
	log := slog.New(slog.NewJSONHandler(&logBuf, nil))

	// 1. Pre-cancelled ctx + WarmUpOnStart.
	cr0 := crawl.NewCrawler(http.DefaultTransport, crawl.PublicHTTPS, crawl.DefaultUserAgent, log)
	preCancelled, cancelPre := context.WithCancel(context.Background())
	cancelPre()
	if err := Run(preCancelled, Config{HubURL: "http://127.0.0.1:1"}, cr0, crawl.PublicHTTPS, http.DefaultTransport, log, RuntimeOpts{WarmUpOnStart: true}); err != nil {
		t.Fatalf("expected nil on pre-cancelled Run, got %v", err)
	}

	// 2. HealthyResetDur + CheckRedirect 302 block + control frames + browserVersion/Sandbox.
	fakeBin := filepath.Join(t.TempDir(), "fake-chrome")
	if err := os.WriteFile(fakeBin, []byte("#!/bin/sh\necho \"Chromium 126.0.0.0\"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	rend := browser.NewRenderer(fakeBin, crawl.PublicHTTPS, crawl.DefaultUserAgent, 1, log)
	defer rend.Close()

	cr := crawl.NewCrawler(http.DefaultTransport, crawl.PublicHTTPS, crawl.DefaultUserAgent, log)
	cr.SetRenderer(rend)
	cr.Jitter = func(time.Duration) time.Duration { return 0 } // exercises wait < 250ms floor too

	var redirectStealHits atomic.Int32
	stealSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirectStealHits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer stealSrv.Close()

	var (
		helloMu sync.Mutex
		hellos  []map[string]any
		wsCount atomic.Int32
	)
	mux := http.NewServeMux()
	mux.HandleFunc("/agent/ws", func(w http.ResponseWriter, r *http.Request) {
		sc, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer sc.CloseNow()
		n := wsCount.Add(1)

		_, data, err := sc.Read(r.Context())
		if err != nil {
			return
		}
		var hello map[string]any
		_ = json.Unmarshal(data, &hello)
		helloMu.Lock()
		hellos = append(hellos, hello)
		helloMu.Unlock()

		if n == 1 {
			// Hold open > HealthyResetDur (20ms) then close cleanly so attempt resets to 0 -> next reconnectAttempt is 1.
			time.Sleep(40 * time.Millisecond)
			_ = sc.Close(websocket.StatusNormalClosure, "reset")
			return
		}

		// Send bad JSON, hello, pong, missing jobId/nonce, unknown type, and valid dispatch (blocked URL so fast).
		_ = sc.Write(r.Context(), websocket.MessageText, []byte("{not-json"))
		_ = sc.Write(r.Context(), websocket.MessageText, []byte(`{"type":"hello"}`))
		_ = sc.Write(r.Context(), websocket.MessageText, []byte(`{"type":"pong"}`))
		_ = sc.Write(r.Context(), websocket.MessageText, []byte(`{"type":"dispatch","jobId":"","jobNonce":"n"}`))
		_ = sc.Write(r.Context(), websocket.MessageText, []byte(`{"type":"dispatch","jobId":"j","jobNonce":""}`))
		_ = sc.Write(r.Context(), websocket.MessageText, []byte(`{"type":"unknown_msg"}`))
		_ = sc.Write(r.Context(), websocket.MessageText, []byte(`{"type":"dispatch","jobId":"j-redir","jobNonce":"n-redir","call":{"requests":[{"id":"1","url":"http://127.0.0.1/blocked","kind":"page"}]}}`))
		for {
			if _, _, err := sc.Read(r.Context()); err != nil {
				return
			}
		}
	})
	var got302Reply atomic.Bool
	mux.HandleFunc("/agent/reply", func(w http.ResponseWriter, r *http.Request) {
		got302Reply.Store(true)
		http.Redirect(w, r, stealSrv.URL+"/steal", http.StatusFound)
	})
	hubSrv := httptest.NewServer(mux)
	defer hubSrv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, Config{
			HubURL:     hubSrv.URL,
			AgentToken: "agent-secret-token-0123456789-abcdef",
			SiteID:     "site-cov",
			UserAgent:  crawl.DefaultUserAgent,
			PauseMs:    100,
		}, cr, crawl.PublicHTTPS, http.DefaultTransport, log, RuntimeOpts{
			WarmUpOnStart:   true,
			PingInterval:    time.Second,
			ReadWatchdog:    2 * time.Second,
			HealthyResetDur: 20 * time.Millisecond,
			ShutdownDrain:   200 * time.Millisecond,
		})
	}()

	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		if got302Reply.Load() && strings.Contains(logBuf.String(), "agent_reply_failed") {
			break
		}
		time.Sleep(15 * time.Millisecond)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Run error: %v", err)
	}

	if redirectStealHits.Load() != 0 {
		t.Fatalf("SECURITY: CheckRedirect allowed redirect to %s (%d hits)", stealSrv.URL, redirectStealHits.Load())
	}
	if !strings.Contains(logBuf.String(), "agent_bad_message") ||
		!strings.Contains(logBuf.String(), "agent_missing_job_id") ||
		!strings.Contains(logBuf.String(), "agent_unknown_type") ||
		!strings.Contains(logBuf.String(), "agent_reply_failed") {
		t.Fatalf("expected control-frame and reply-failed logs, got:\n%s", logBuf.String())
	}
	helloMu.Lock()
	if len(hellos) < 2 {
		helloMu.Unlock()
		t.Fatalf("expected >= 2 hellos, got %d", len(hellos))
	}
	if hellos[0]["browserVersion"] != "Chromium 126.0.0.0" {
		helloMu.Unlock()
		t.Fatalf("expected browserVersion in agent_hello, got %+v", hellos[0])
	}
	if ra, _ := hellos[1]["reconnectAttempt"].(float64); ra != 1 {
		helloMu.Unlock()
		t.Fatalf("expected HealthyResetDur to reset reconnectAttempt to 1, got %v", hellos[1]["reconnectAttempt"])
	}
	helloMu.Unlock()

	// 3. maxReconnectBackoff (30s cap) + SleepCtx cancel on closed server.
	closedSrv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	closedURL := closedSrv.URL
	closedSrv.Close()

	crCap := crawl.NewCrawler(http.DefaultTransport, crawl.PublicHTTPS, crawl.DefaultUserAgent, log)
	var sawCap atomic.Bool
	var jCalls atomic.Int32
	ctxCap, cancelCap := context.WithCancel(context.Background())
	defer cancelCap()
	crCap.Jitter = func(ceil time.Duration) time.Duration {
		if ceil == maxReconnectBackoff {
			sawCap.Store(true)
			return 500 * time.Millisecond // trigger SleepCtx wait then cancel
		}
		if jCalls.Add(1) >= 8 {
			cancelCap()
		}
		return 0 // clamped to 250ms floor
	}
	go func() {
		for !sawCap.Load() && ctxCap.Err() == nil {
			time.Sleep(10 * time.Millisecond)
		}
		time.Sleep(40 * time.Millisecond)
		cancelCap()
	}()
	if err := Run(ctxCap, Config{
		HubURL:     closedURL,
		AgentToken: "agent-secret-token-0123456789-abcdef",
		SiteID:     "site-cap",
		UserAgent:  crawl.DefaultUserAgent,
	}, crCap, crawl.PublicHTTPS, http.DefaultTransport, log, RuntimeOpts{
		HealthyResetDur: time.Hour,
	}); err != nil {
		t.Fatalf("Run cap test returned err: %v", err)
	}
	if !sawCap.Load() {
		t.Fatal("expected backoff ceil to reach maxReconnectBackoff (30s)")
	}
}

func TestRunSessionDispatchBackpressureAndPingLoop(t *testing.T) {
	// 1. Direct unit test of runPingLoop write error -> closes socket.
	var closed atomic.Bool
	runPingLoop(context.Background(), 5*time.Millisecond, func(string) error {
		return errors.New("broken pipe")
	}, func() error {
		closed.Store(true)
		return nil
	})
	if !closed.Load() {
		t.Fatal("expected runPingLoop to call closeNow when writePing fails")
	}

	// 2. dispatchCh backpressure (cap 8) hitting `case <-sessionCtx.Done(): return nil`.
	log := slog.New(slog.NewJSONHandler(io.Discard, nil))
	cr := crawl.NewCrawler(http.DefaultTransport, crawl.PublicHTTPS, crawl.DefaultUserAgent, log)
	dispatchCh := make(chan controlMessage, 8)
	// Pre-fill dispatchCh with 8 items so the first dispatch sent by server blocks on `dispatchCh <- msg`.
	for i := 0; i < 8; i++ {
		dispatchCh <- controlMessage{Type: "dispatch", JobID: "prefill", JobNonce: "n"}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sc, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer sc.CloseNow()
		_, _, _ = sc.Read(r.Context()) // read hello
		_ = sc.Write(r.Context(), websocket.MessageText, []byte(`{"type":"dispatch","jobId":"j-block","jobNonce":"n-block"}`))
		time.Sleep(40 * time.Millisecond)
		cancel()
		_, _, _ = sc.Read(r.Context())
	}))
	defer srv.Close()

	err := runSession(ctx, Config{
		HubURL:     srv.URL,
		AgentToken: "agent-secret-token-0123456789-abcdef",
		SiteID:     "site-bp",
		UserAgent:  crawl.DefaultUserAgent,
	}, cr, crawl.PublicHTTPS, srv.Client(), log, RuntimeOpts{
		PingInterval: time.Second,
		ReadWatchdog: 2 * time.Second,
	}.withDefaults(), 0, "", dispatchCh)
	if err != nil {
		t.Fatalf("expected nil on context cancel during dispatchCh backpressure, got %v", err)
	}
}

func TestHandleDispatchTraceR2EdgesAndUploads(t *testing.T) {
	// 1. OTel Trace propagation + R2 stored retention + MaxContentBytes clamp/truncation + empty body (204).
	var spanMu sync.Mutex
	var recordedSpans [][]byte
	otelSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		spanMu.Lock()
		recordedSpans = append(recordedSpans, body)
		spanMu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer otelSrv.Close()

	exp := otel.NewExporterFromEnv(func(k string) string {
		switch k {
		case "OTEL_EXPORTER_OTLP_ENDPOINT":
			return otelSrv.URL
		case "OTEL_SERVICE_NAME":
			return "edgefetch-agent-test"
		default:
			return ""
		}
	}, "edgefetch-agent-test", Version, otelSrv.Client().Transport)
	if exp == nil {
		t.Fatal("expected non-nil OTel exporter")
	}

	originSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/robots.txt":
			w.WriteHeader(http.StatusNotFound)
		case "/empty":
			w.WriteHeader(http.StatusNoContent)
		case "/big":
			w.Header().Set("content-type", "text/plain")
			_, _ = w.Write([]byte(strings.Repeat("X", 200)))
		default:
			w.Header().Set("content-type", "text/plain")
			_, _ = w.Write([]byte("ok-body"))
		}
	}))
	defer originSrv.Close()
	originAddr := originSrv.Listener.Addr().String()
	tr := &http.Transport{
		TLSClientConfig: originSrv.Client().Transport.(*http.Transport).TLSClientConfig,
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, originAddr)
		},
	}

	var logBuf bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&logBuf, nil))
	cr := crawl.NewCrawler(tr, crawl.PublicHTTPS, crawl.DefaultUserAgent, log)
	cr.Sleep = func(context.Context, time.Duration) error { return nil }
	cr.SetOtelExporter(exp)

	var (
		artRetention string
		gotReply     crawl.FetchReply
	)
	hubMux := http.NewServeMux()
	hubMux.HandleFunc("/agent/artifacts/", func(w http.ResponseWriter, r *http.Request) {
		artRetention = r.Header.Get("X-Artifact-Retention")
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusOK)
	})
	hubMux.HandleFunc("/agent/reply", func(w http.ResponseWriter, r *http.Request) {
		gz, _ := gzip.NewReader(r.Body)
		if gz != nil {
			_ = json.NewDecoder(gz).Decode(&gotReply)
			_ = gz.Close()
		}
		w.WriteHeader(http.StatusOK)
	})
	hubSrv := httptest.NewServer(hubMux)
	defer hubSrv.Close()

	cfg := Config{
		HubURL:     hubSrv.URL,
		AgentToken: "agent-secret-token-0123456789-abcdef",
		SiteID:     "site-r2",
		UserAgent:  crawl.DefaultUserAgent,
		PauseMs:    1,
	}

	// Test MaxContentBytes <= 0 clamp + Retention == "stored" + msg.Trace + empty 204 body.
	const traceID = "4bf92f3577b34da6a3ce929d0e0e4736"
	handleDispatchWithOpts(context.Background(), cfg, cr, crawl.PublicHTTPS, hubSrv.Client(), log, RuntimeOpts{}, controlMessage{
		Type:     "dispatch",
		JobID:    "job-trace-stored",
		JobNonce: "nonce-1",
		Trace: map[string]string{
			"traceparent":  "00-" + traceID + "-00f067aa0ba902b7-01",
			"x-trace-id":   traceID,
			"x-span-id":    "00f067aa0ba902b7",
			"x-request-id": "ray-test-1",
		},
		Artifacts: &artifactDispatchPolicy{
			Mode:            "r2",
			Retention:       "stored",
			MaxContentBytes: 0, // triggers clamp to crawl.MaxMaxBytes
		},
		Call: crawl.FetchCall{
			Options: crawl.Options{IncludeBody: true, PauseMs: 1},
			Requests: []crawl.Request{
				{ID: "r-ok", URL: "https://t1.example.com/ok", Kind: classify.KindPage},
				{ID: "r-empty", URL: "https://t2.example.com/empty", Kind: classify.KindPage},
			},
		},
	})
	if artRetention != "stored" {
		t.Fatalf("expected X-Artifact-Retention=stored, got %q", artRetention)
	}
	if len(gotReply.Results) != 2 || gotReply.Results[0].Artifact == nil || gotReply.Results[1].Body != "" {
		t.Fatalf("unexpected R2 stored/empty reply: %+v", gotReply.Results)
	}
	if !strings.Contains(logBuf.String(), traceID) {
		t.Fatalf("expected jobLog to include trace_id %s, got %s", traceID, logBuf.String())
	}
	exp.Shutdown(context.Background())
	spanMu.Lock()
	joinedSpans := string(bytes.Join(recordedSpans, []byte("\n")))
	spanMu.Unlock()
	if !strings.Contains(joinedSpans, traceID) {
		t.Fatalf("expected OTLP exporter to receive traceId %s, got %s", traceID, joinedSpans)
	}

	// Truncation when len(rawBytes) > maxContent.
	handleDispatchWithOpts(context.Background(), cfg, cr, crawl.PublicHTTPS, hubSrv.Client(), log, RuntimeOpts{}, controlMessage{
		Type:     "dispatch",
		JobID:    "job-trunc",
		JobNonce: "nonce-2",
		Artifacts: &artifactDispatchPolicy{
			Mode:            "r2",
			Retention:       "transient",
			MaxContentBytes: 16,
		},
		Call: crawl.FetchCall{
			Options:  crawl.Options{IncludeBody: true, MaxBytes: 4096, PauseMs: 1},
			Requests: []crawl.Request{{ID: "r-big", URL: "https://t3.example.com/big", Kind: classify.KindPage}},
		},
	})
	if len(gotReply.Results) != 1 || !gotReply.Results[0].Truncated || !gotReply.Results[0].BodyOmitted {
		t.Fatalf("expected truncated & omitted result when body > maxContentBytes, got %+v", gotReply.Results)
	}

	// Direct unit test of newR2ArtifactSink malformed base64 decode error branch.
	badSink := newR2ArtifactSink(hubSrv.Client(), cfg, "j", "n", "transient", 1024, time.Second, log)
	decFail := badSink(0, crawl.Result{ID: "bad-b64", Body: "!!!not-base64!!!", BodyEncoding: "base64"})
	if !decFail.BodyOmitted || !strings.Contains(decFail.ArtifactError, "decode body:") {
		t.Fatalf("expected decode body error on malformed base64, got %+v", decFail)
	}

	// 2. uploadArtifact retry, cancel, invalid URL, transport err, and 3x503 exhaustion.
	var artAttempts atomic.Int32
	artRetrySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		if artAttempts.Add(1) == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer artRetrySrv.Close()

	ref, err := uploadArtifact(context.Background(), artRetrySrv.Client(), Config{HubURL: artRetrySrv.URL, AgentToken: "tok", SiteID: "s1", UserAgent: "UA"}, "j1", "n1", "r1", "transient", []byte("hello"))
	if err != nil || ref == nil || artAttempts.Load() != 2 {
		t.Fatalf("expected uploadArtifact to succeed on retry 2, got ref=%+v err=%v attempts=%d", ref, err, artAttempts.Load())
	}

	// SleepCtx cancel during uploadArtifact retry.
	artAlways503 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer artAlways503.Close()
	shortArtCtx, cancelArtShort := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancelArtShort()
	if _, err := uploadArtifact(shortArtCtx, artAlways503.Client(), Config{HubURL: artAlways503.URL}, "j", "n", "r", "transient", []byte("hi")); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected DeadlineExceeded during uploadArtifact retry sleep, got %v", err)
	}

	// Invalid URL -> http.NewRequestWithContext error.
	if _, err := uploadArtifact(context.Background(), http.DefaultClient, Config{HubURL: "http://127.0.0.1\x7f"}, "j", "n", "r", "transient", []byte("hi")); err == nil {
		t.Fatal("expected NewRequestWithContext error for invalid URL in uploadArtifact")
	}

	// Transport error -> 3 attempts, returns transport error; and 3x503 exhaustion without short ctx.
	ert := &errRoundTripper{err: errors.New("dial reset")}
	if _, err := uploadArtifact(context.Background(), &http.Client{Transport: ert}, Config{HubURL: "http://127.0.0.1:1"}, "j", "n", "r", "transient", []byte("hi")); err == nil || ert.calls.Load() != 3 {
		t.Fatalf("expected 3 transport attempts in uploadArtifact, got calls=%d err=%v", ert.calls.Load(), err)
	}
	if _, err := uploadArtifact(context.Background(), artAlways503.Client(), Config{HubURL: artAlways503.URL}, "j", "n", "r", "transient", []byte("hi")); err == nil || !strings.Contains(err.Error(), "HTTP 503") {
		t.Fatalf("expected HTTP 503 after 3 retries in uploadArtifact, got %v", err)
	}

	// 3. uploadReply retry, cancel, invalid URL, transport err, non-retryable 400, 3x503 exhaustion.
	var repAttempts atomic.Int32
	var repMode atomic.Value
	repMode.Store("retry_then_ok")
	repSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		mode, _ := repMode.Load().(string)
		switch mode {
		case "retry_then_ok":
			if repAttempts.Add(1) == 1 {
				w.WriteHeader(http.StatusBadGateway)
				return
			}
			w.WriteHeader(http.StatusOK)
		case "always_503":
			w.WriteHeader(http.StatusServiceUnavailable)
		case "always_400":
			http.Error(w, "bad request", http.StatusBadRequest)
		}
	}))
	defer repSrv.Close()

	if err := uploadReply(context.Background(), repSrv.Client(), Config{HubURL: repSrv.URL}, "j", "n", crawl.FetchReply{}); err != nil || repAttempts.Load() != 2 {
		t.Fatalf("expected uploadReply retry to succeed on attempt 2, got err=%v attempts=%d", err, repAttempts.Load())
	}

	repMode.Store("always_503")
	shortRepCtx, cancelRepShort := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancelRepShort()
	if err := uploadReply(shortRepCtx, repSrv.Client(), Config{HubURL: repSrv.URL}, "j", "n", crawl.FetchReply{}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected DeadlineExceeded during uploadReply retry sleep, got %v", err)
	}

	if err := uploadReply(context.Background(), repSrv.Client(), Config{HubURL: repSrv.URL}, "j", "n", crawl.FetchReply{}); err == nil || !strings.Contains(err.Error(), "HTTP 503") {
		t.Fatalf("expected HTTP 503 after 3 uploadReply attempts, got %v", err)
	}

	repMode.Store("always_400")
	if err := uploadReply(context.Background(), repSrv.Client(), Config{HubURL: repSrv.URL}, "j", "n", crawl.FetchReply{}); err == nil || !strings.Contains(err.Error(), "HTTP 400") {
		t.Fatalf("expected immediate HTTP 400 from uploadReply, got %v", err)
	}

	if err := uploadReply(context.Background(), http.DefaultClient, Config{HubURL: "http://127.0.0.1\x7f"}, "j", "n", crawl.FetchReply{}); err == nil {
		t.Fatal("expected NewRequestWithContext error for invalid URL in uploadReply")
	}

	ert2 := &errRoundTripper{err: errors.New("reply transport down")}
	if err := uploadReply(context.Background(), &http.Client{Transport: ert2}, Config{HubURL: "http://127.0.0.1:1"}, "j", "n", crawl.FetchReply{}); err == nil || ert2.calls.Load() != 3 {
		t.Fatalf("expected 3 transport attempts in uploadReply, got calls=%d err=%v", ert2.calls.Load(), err)
	}

	// errString(nil)
	if errString(nil) != "" || errString(io.EOF) != "eof" || errString(errors.New("boom")) != "boom" {
		t.Fatal("errString mismatch")
	}
}
