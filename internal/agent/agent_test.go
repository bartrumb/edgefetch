package agent

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/bartrumb/edgefetch/v2/internal/classify"
	"github.com/bartrumb/edgefetch/v2/internal/crawl"
)

func TestConfigSecurityGuards(t *testing.T) {
	dir := t.TempDir()
	optPath := filepath.Join(dir, "options.json")
	if err := os.WriteFile(optPath, []byte(`{
		"hub_url": "https://hub.example.com/",
		"agent_token": "secret-agent-token-0123456789",
		"site_id": "Site-ARM64",
		"user_agent": "CustomBot/2.0 (+https://example.com)",
		"robots_bypass_hosts": ["internal.example.com"]
	}`), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadConfigFrom(optPath, func(string) string { return "" })
	if err != nil {
		t.Fatalf("LoadConfigFrom: %v", err)
	}
	if cfg.SiteID != "site-arm64" || cfg.HubURL != "https://hub.example.com" || cfg.UserAgent != "CustomBot/2.0 (+https://example.com)" {
		t.Fatalf("unexpected config: %+v", cfg)
	}
	if len(cfg.RobotsBypassHosts) != 1 || cfg.RobotsBypassHosts[0] != "internal.example.com" {
		t.Fatalf("expected robots_bypass_hosts from options.json, got %+v", cfg.RobotsBypassHosts)
	}

	overrideCfg, err := LoadConfigFrom(optPath, func(k string) string {
		if k == "EDGEFETCH_ROBOTS_BYPASS_HOSTS" {
			return "alpha.example.com, beta.example.com"
		}
		return ""
	})
	if err != nil || len(overrideCfg.RobotsBypassHosts) != 2 || overrideCfg.RobotsBypassHosts[1] != "beta.example.com" {
		t.Fatalf("expected EDGEFETCH_ROBOTS_BYPASS_HOSTS override, got %+v (err=%v)", overrideCfg.RobotsBypassHosts, err)
	}

	// SECURITY S2: Even with EDGEFETCH_ALLOW_INSECURE_HUB=1, cleartext http:// to a remote host MUST be rejected!
	if _, err := LoadConfigFrom("", func(k string) string {
		switch k {
		case "EDGEFETCH_ALLOW_INSECURE_HUB":
			return "1"
		case "EDGEFETCH_HUB_URL":
			return "http://remote-hub.example.com"
		case "EDGEFETCH_AGENT_TOKEN":
			return "secret-agent-token-0123456789"
		case "EDGEFETCH_SITE_ID":
			return "site-1"
		default:
			return ""
		}
	}); err == nil {
		t.Fatal("SECURITY: expected non-loopback http:// hub_url to be rejected even when ALLOW_INSECURE_HUB=1")
	}

	// Loopback http://127.0.0.1 IS allowed when EDGEFETCH_ALLOW_INSECURE_HUB=1 for local httptest suites.
	if _, err := LoadConfigFrom("", func(k string) string {
		switch k {
		case "EDGEFETCH_ALLOW_INSECURE_HUB":
			return "1"
		case "EDGEFETCH_HUB_URL":
			return "http://127.0.0.1:8080"
		case "EDGEFETCH_AGENT_TOKEN":
			return "secret-agent-token-0123456789"
		case "EDGEFETCH_SITE_ID":
			return "site-1"
		default:
			return ""
		}
	}); err != nil {
		t.Fatalf("expected loopback http://127.0.0.1 allowed in test mode: %v", err)
	}

	// wss://<hub>/agent/ws normalizes cleanly to https://<hub> so docker run snippets work with either form!
	wssCfg, err := LoadConfigFrom("", func(k string) string {
		switch k {
		case "EDGEFETCH_HUB_URL":
			return "wss://edgefetch.example.com/agent/ws/"
		case "EDGEFETCH_AGENT_TOKEN":
			return "secret-agent-token-0123456789"
		case "EDGEFETCH_SITE_ID":
			return "vps-1"
		default:
			return ""
		}
	})
	if err != nil || wssCfg.HubURL != "https://edgefetch.example.com" {
		t.Fatalf("expected wss://.../agent/ws normalized to https://edgefetch.example.com, got %+v (err=%v)", wssCfg, err)
	}

	// Docker bridge single-label service name ("ws://hub:8787/agent/ws") works ONLY with EDGEFETCH_ALLOW_INSECURE_DOCKER_HUB=1,
	// while public multi-label domains remain strictly blocked.
	dockerCfg, err := LoadConfigFrom("", func(k string) string {
		switch k {
		case "EDGEFETCH_ALLOW_INSECURE_DOCKER_HUB":
			return "1"
		case "EDGEFETCH_HUB_URL":
			return "ws://hub:8787/agent/ws"
		case "EDGEFETCH_AGENT_TOKEN":
			return "secret-agent-token-0123456789"
		case "EDGEFETCH_SITE_ID":
			return "compose-1"
		default:
			return ""
		}
	})
	if err != nil || dockerCfg.HubURL != "http://hub:8787" {
		t.Fatalf("expected ws://hub:8787/agent/ws normalized to http://hub:8787, got %+v (err=%v)", dockerCfg, err)
	}
	if _, err := LoadConfigFrom("", func(k string) string {
		switch k {
		case "EDGEFETCH_ALLOW_INSECURE_DOCKER_HUB":
			return "1"
		case "EDGEFETCH_HUB_URL":
			return "ws://hub.example.com:8787/agent/ws"
		case "EDGEFETCH_AGENT_TOKEN":
			return "secret-agent-token-0123456789"
		case "EDGEFETCH_SITE_ID":
			return "compose-1"
		default:
			return ""
		}
	}); err == nil {
		t.Fatal("SECURITY: expected multi-label FQDN cleartext ws:// rejected even with EDGEFETCH_ALLOW_INSECURE_DOCKER_HUB=1")
	}
}

func TestAgentSessionReconnectHelloPingAndGzipReply(t *testing.T) {
	originSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/robots.txt" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("content-type", "application/json")
		_, _ = w.Write([]byte(`{"products":[{"id":42}]}`))
	}))
	defer originSrv.Close()
	originAddr := originSrv.Listener.Addr().String()

	tr := &http.Transport{
		TLSClientConfig: originSrv.Client().Transport.(*http.Transport).TLSClientConfig,
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, originAddr)
		},
	}
	log := slog.New(slog.NewJSONHandler(io.Discard, nil))
	crawler := crawl.NewCrawler(tr, crawl.PublicHTTPS, crawl.DefaultUserAgent, log)
	crawler.Sleep = func(context.Context, time.Duration) error { return nil }

	const token = "agent-secret-token-0123456789-abcdef"
	var (
		connects  atomic.Int32
		replyOnce sync.Once
		doneCh    = make(chan crawl.FetchReply, 1)
	)

	mux := http.NewServeMux()
	mux.HandleFunc("/agent/ws", func(w http.ResponseWriter, r *http.Request) {
		sc, err := websocket.Accept(w, r, nil)
		if err != nil {
			t.Errorf("websocket.Accept: %v", err)
			return
		}
		if connects.Add(1) == 1 {
			_ = sc.CloseNow()
			return
		}
		defer sc.CloseNow()

		rctx, rcancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer rcancel()

		sawHello, sawPing := false, false
		for !sawHello || !sawPing {
			typ, payload, err := sc.Read(rctx)
			if err != nil {
				t.Errorf("server Read: %v", err)
				return
			}
			if typ != websocket.MessageText {
				continue
			}
			s := string(payload)
			if s == "ping" {
				sawPing = true
				_ = sc.Write(rctx, websocket.MessageText, []byte("pong"))
			} else if strings.Contains(s, `"agent_hello"`) {
				sawHello = true
			}
		}

		rawDispatch, _ := json.Marshal(map[string]any{
			"type":     "dispatch",
			"jobId":    "job-1",
			"jobNonce": "nonce-1",
			"call": crawl.FetchCall{
				Requests: []crawl.Request{{ID: "store-a", URL: "https://store.example.com/products.json", Kind: classify.KindFeed}},
				Options:  crawl.Options{IncludeBody: true},
			},
		})
		_ = sc.Write(rctx, websocket.MessageText, rawDispatch)
		<-rctx.Done()
	})

	mux.HandleFunc("/agent/reply", func(w http.ResponseWriter, r *http.Request) {
		gz, err := gzip.NewReader(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		defer gz.Close()
		var rep crawl.FetchReply
		if err := json.NewDecoder(gz).Decode(&rep); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		replyOnce.Do(func() { doneCh <- rep })
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	})

	hubSrv := httptest.NewServer(mux)
	defer hubSrv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cfg := Config{
		HubURL:        hubSrv.URL,
		AgentToken:    token,
		SiteID:        "site-arm64",
		UserAgent:     crawl.DefaultUserAgent,
		PauseMs:       3000,
		PauseJitterMs: 1000,
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- Run(ctx, cfg, crawler, crawl.PublicHTTPS, http.DefaultTransport, log, RuntimeOpts{
			PingInterval:  30 * time.Millisecond,
			ReadWatchdog:  2 * time.Second,
			ShutdownDrain: time.Second,
		})
	}()

	var got crawl.FetchReply
	select {
	case got = <-doneCh:
	case <-ctx.Done():
		t.Fatal("timed out waiting for agent reply")
	}
	cancel()
	if err := <-errCh; err != nil {
		t.Fatalf("Run error: %v", err)
	}
	if len(got.Results) != 1 || got.Results[0].Outcome != classify.OutcomeOK {
		t.Fatalf("unexpected reply: %+v", got)
	}
}

func TestShutdownDrainStillUploadsPartialResults(t *testing.T) {
	originSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/robots.txt" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if r.URL.Path == "/1" {
			w.Header().Set("content-type", "text/html")
			_, _ = w.Write([]byte("<html>done-1</html>"))
			return
		}
		<-r.Context().Done()
	}))
	defer originSrv.Close()
	originAddr := originSrv.Listener.Addr().String()

	tr := &http.Transport{
		TLSClientConfig: originSrv.Client().Transport.(*http.Transport).TLSClientConfig,
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, originAddr)
		},
	}
	log := slog.New(slog.NewJSONHandler(io.Discard, nil))
	crawler := crawl.NewCrawler(tr, crawl.PublicHTTPS, crawl.DefaultUserAgent, log)
	crawler.Sleep = crawl.SleepCtx

	replyCh := make(chan crawl.FetchReply, 1)
	hubSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gz, err := gzip.NewReader(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		defer gz.Close()
		var rep crawl.FetchReply
		if err := json.NewDecoder(gz).Decode(&rep); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		replyCh <- rep
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer hubSrv.Close()

	parentCtx, cancelParent := context.WithCancel(context.Background())
	time.AfterFunc(30*time.Millisecond, cancelParent)

	cfg := Config{
		HubURL:        hubSrv.URL,
		AgentToken:    "agent-secret-token-0123456789-abcdef",
		SiteID:        "site-x86",
		UserAgent:     crawl.DefaultUserAgent,
		PauseMs:       10,
		PauseJitterMs: 0,
	}

	handleDispatch(parentCtx, cfg, crawler, crawl.PublicHTTPS, hubSrv.Client(), log, 60*time.Millisecond, controlMessage{
		Type:     "dispatch",
		JobID:    "job-drain",
		JobNonce: "nonce-drain",
		Call: crawl.FetchCall{
			Requests: []crawl.Request{
				{ID: "1", URL: "https://alpha.example.com/1", Kind: classify.KindPage},
				{ID: "2", URL: "https://beta.example.com/2", Kind: classify.KindPage},
			},
			Options: crawl.Options{IncludeBody: true, PauseMs: 10},
		},
	})

	select {
	case rep := <-replyCh:
		if len(rep.Results) != 2 {
			t.Fatalf("expected 2 results uploaded after shutdown drain, got %d", len(rep.Results))
		}
		if rep.Results[0].Outcome != classify.OutcomeOK {
			t.Fatalf("expected first completed result preserved, got %+v", rep.Results[0])
		}
	case <-time.After(2 * time.Second):
		t.Fatal("lost results on shutdown: /agent/reply was never uploaded after ShutdownDrain expired")
	}
}

func TestReconnectWatchdogClosesPreviousSocketImmediately(t *testing.T) {
	firstSocketClosed := make(chan struct{})
	secondConnected := make(chan struct{})
	var connCount atomic.Int32

	mux := http.NewServeMux()
	mux.HandleFunc("/agent/ws", func(w http.ResponseWriter, r *http.Request) {
		sc, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		n := connCount.Add(1)
		if n == 1 {
			go func() {
				defer close(firstSocketClosed)
				defer sc.CloseNow()
				for {
					if _, _, err := sc.Read(context.Background()); err != nil {
						return
					}
				}
			}()
			return
		}
		if n == 2 {
			close(secondConnected)
		}
		_ = sc.CloseNow()
	})

	hubSrv := httptest.NewServer(mux)
	defer hubSrv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	log := slog.New(slog.NewJSONHandler(io.Discard, nil))
	crawler := crawl.NewCrawler(http.DefaultTransport, crawl.PublicHTTPS, crawl.DefaultUserAgent, log)
	cfg := Config{
		HubURL:     hubSrv.URL,
		AgentToken: "agent-secret-token-0123456789-abcdef",
		SiteID:     "site-1",
		UserAgent:  crawl.DefaultUserAgent,
		PauseMs:    100,
	}

	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, cfg, crawler, crawl.PublicHTTPS, http.DefaultTransport, log, RuntimeOpts{
			PingInterval:  time.Second,
			ReadWatchdog:  40 * time.Millisecond,
			ShutdownDrain: 50 * time.Millisecond,
		})
	}()

	select {
	case <-secondConnected:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for second WebSocket connection after watchdog")
	}

	select {
	case <-firstSocketClosed:
	case <-time.After(250 * time.Millisecond):
		t.Fatal("first WebSocket remained open after watchdog session exit and reconnect")
	}

	cancel()
	<-done
}

func TestNormalUploadExceedsLegacyTenSecondCapWithoutLosingReply(t *testing.T) {
	var replyReceived atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		time.Sleep(10200 * time.Millisecond)
		replyReceived.Store(true)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	var logBuf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&logBuf, nil))
	cr := crawl.NewCrawler(http.DefaultTransport, crawl.PublicHTTPS, crawl.DefaultUserAgent, log)
	client := &http.Client{Timeout: 45 * time.Second}

	handleDispatch(
		context.Background(),
		Config{HubURL: srv.URL, AgentToken: "agent-secret-token-0123456789-abcdef", SiteID: "s1", UserAgent: "EdgeFetch/1.0"},
		cr,
		crawl.PublicHTTPS,
		client,
		log,
		time.Second,
		controlMessage{
			Type:     "dispatch",
			JobID:    "j-slow-upload",
			JobNonce: "n-slow-upload",
			Call: crawl.FetchCall{
				Requests: []crawl.Request{{ID: "1", URL: "http://bad.example.com/", Kind: classify.KindPage}},
			},
		},
	)

	if !replyReceived.Load() {
		t.Fatal("expected /agent/reply server handler to receive upload")
	}
	if strings.Contains(logBuf.String(), "agent_reply_failed") {
		t.Fatalf("A2 BUG: normal (non-shutdown) reply upload failed at >10s even within 45s client budget: %s", logBuf.String())
	}
}

func TestArtifactModeStreams40MiBLogicalBatchWithoutBodiesInReply(t *testing.T) {
	eightMiBBody := "<html><body>" + strings.Repeat("EdgeFetchR2-", 700_000)[:(8<<20)-26] + "</body></html>"
	originSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/robots.txt" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("content-type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(eightMiBBody))
	}))
	defer originSrv.Close()
	originAddr := originSrv.Listener.Addr().String()
	tlsCfg := originSrv.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	tlsCfg.InsecureSkipVerify = true
	tr := &http.Transport{
		TLSClientConfig: tlsCfg,
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, originAddr)
		},
	}

	log := slog.New(slog.NewJSONHandler(io.Discard, nil))
	crawler := crawl.NewCrawler(tr, crawl.PublicHTTPS, crawl.DefaultUserAgent, log)
	crawler.Sleep = func(context.Context, time.Duration) error { return nil }

	var (
		uploadedMu      sync.Mutex
		uploadedObjects = map[string]int{}
		replyRawBytes   atomic.Int64
		gotReply        crawl.FetchReply
	)

	hubMux := http.NewServeMux()
	hubMux.HandleFunc("/agent/artifacts/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			http.Error(w, "method", http.StatusMethodNotAllowed)
			return
		}
		if r.Header.Get("Content-Encoding") != "" {
			http.Error(w, "unexpected Content-Encoding", http.StatusBadRequest)
			return
		}
		if r.ContentLength <= 0 {
			http.Error(w, "missing Content-Length", http.StatusLengthRequired)
			return
		}
		if r.Header.Get("X-Request-Id") == "fail-up" {
			_, _ = io.Copy(io.Discard, r.Body)
			http.Error(w, `{"error":"simulated_r2_reject"}`, http.StatusForbidden)
			return
		}
		gzData, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		wantBlobSHA := strings.TrimPrefix(r.URL.Path, "/agent/artifacts/")
		gotDigest := sha256.Sum256(gzData)
		if hex.EncodeToString(gotDigest[:]) != wantBlobSHA {
			http.Error(w, "blob sha mismatch", http.StatusBadRequest)
			return
		}
		uploadedMu.Lock()
		uploadedObjects[r.Header.Get("X-Request-Id")] = len(gzData)
		uploadedMu.Unlock()
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true,"stored":true}`))
	})
	hubMux.HandleFunc("/agent/reply", func(w http.ResponseWriter, r *http.Request) {
		gzRaw, _ := io.ReadAll(r.Body)
		gz, err := gzip.NewReader(bytes.NewReader(gzRaw))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		defer gz.Close()
		plainJSON, err := io.ReadAll(gz)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		replyRawBytes.Store(int64(len(plainJSON)))
		_ = json.Unmarshal(plainJSON, &gotReply)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	})
	hubSrv := httptest.NewServer(hubMux)
	defer hubSrv.Close()

	cfg := Config{
		HubURL:     hubSrv.URL,
		AgentToken: "agent-secret-token-0123456789-abcdef",
		SiteID:     "site-1",
		UserAgent:  crawl.DefaultUserAgent,
		PauseMs:    1,
	}

	// 5 x 8 MiB = 40 MiB logical uncompressed batch (+ 1 simulated upload failure to verify body is omitted, not inline).
	reqs := []crawl.Request{
		{ID: "p1", URL: "https://h1.example.com/1", Kind: classify.KindPage},
		{ID: "p2", URL: "https://h2.example.com/2", Kind: classify.KindPage},
		{ID: "p3", URL: "https://h3.example.com/3", Kind: classify.KindPage},
		{ID: "p4", URL: "https://h4.example.com/4", Kind: classify.KindPage},
		{ID: "p5", URL: "https://h5.example.com/5", Kind: classify.KindPage},
		{ID: "fail-up", URL: "https://h6.example.com/6", Kind: classify.KindPage},
	}

	handleDispatchWithOpts(
		context.Background(),
		cfg,
		crawler,
		crawl.PublicHTTPS,
		hubSrv.Client(),
		log,
		RuntimeOpts{},
		controlMessage{
			Type:     "dispatch",
			JobID:    "job-40mib",
			JobNonce: "nonce-40mib",
			Artifacts: &artifactDispatchPolicy{
				Mode:            "r2",
				Retention:       "transient",
				MaxContentBytes: 16 << 20,
			},
			Call: crawl.FetchCall{
				MaxSeconds: 60,
				Options:    crawl.Options{IncludeBody: true, MaxBytes: 16 << 20, PauseMs: 1},
				Requests:   reqs,
			},
		},
	)

	if len(gotReply.Results) != 6 {
		t.Fatalf("expected 6 results in manifest reply, got %d", len(gotReply.Results))
	}
	if replyRawBytes.Load() > 16_384 {
		t.Fatalf("expected tiny manifest reply (<16 KiB) with zero inline bodies, got %d bytes", replyRawBytes.Load())
	}
	for i := 0; i < 5; i++ {
		r := gotReply.Results[i]
		if r.Outcome != classify.OutcomeOK || r.Body != "" || r.Artifact == nil || r.Artifact.ContentBytes != len(eightMiBBody) {
			t.Fatalf("result %d expected ok R2 artifact ref with empty inline Body, got %+v (artifact=%+v)", i, r, r.Artifact)
		}
	}
	failedArt := gotReply.Results[5]
	if failedArt.Outcome != classify.OutcomeOK || failedArt.Body != "" || !failedArt.BodyOmitted || failedArt.ArtifactError == "" {
		t.Fatalf("failed upload must keep OutcomeOK, omit inline Body, and set ArtifactError; got %+v", failedArt)
	}
}

func TestBurstDispatchConcurrencyCrossDomainGapAndKeepaliveDrain(t *testing.T) {
	originSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/robots.txt" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		time.Sleep(180 * time.Millisecond)
		w.Header().Set("content-type", "text/html")
		_, _ = w.Write([]byte("<html>burst-ok</html>"))
	}))
	defer originSrv.Close()
	originAddr := originSrv.Listener.Addr().String()

	tr := &http.Transport{
		TLSClientConfig: originSrv.Client().Transport.(*http.Transport).TLSClientConfig,
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, originAddr)
		},
	}
	log := slog.New(slog.NewJSONHandler(io.Discard, nil))
	crawler := crawl.NewCrawler(tr, crawl.PublicHTTPS, crawl.DefaultUserAgent, log)

	var (
		wsConns   atomic.Int32
		replyOnce sync.Once
		replyCh   = make(chan crawl.FetchReply, 1)
	)
	mux := http.NewServeMux()
	mux.HandleFunc("/agent/ws", func(w http.ResponseWriter, r *http.Request) {
		wsConns.Add(1)
		sc, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer sc.CloseNow()

		var writeMu sync.Mutex
		writeText := func(payload []byte) {
			writeMu.Lock()
			_ = sc.Write(r.Context(), websocket.MessageText, payload)
			writeMu.Unlock()
		}

		// Wait for agent_hello, then dispatch a 4-domain batch while echoing pings continuously.
		dispatched := false
		for {
			typ, data, err := sc.Read(r.Context())
			if err != nil {
				return
			}
			if typ != websocket.MessageText {
				continue
			}
			s := string(data)
			if s == "ping" {
				writeText([]byte("pong"))
				continue
			}
			if !dispatched && strings.Contains(s, `"agent_hello"`) {
				dispatched = true
				rawDispatch, _ := json.Marshal(map[string]any{
					"type":     "dispatch",
					"jobId":    "job-burst",
					"jobNonce": "nonce-burst",
					"call": crawl.FetchCall{
						Requests: []crawl.Request{
							{ID: "d1", URL: "https://d1.example.com/item", Kind: classify.KindPage},
							{ID: "d2", URL: "https://d2.example.com/item", Kind: classify.KindPage},
							{ID: "d3", URL: "https://d3.example.com/item", Kind: classify.KindPage},
							{ID: "d4", URL: "https://d4.example.com/item", Kind: classify.KindPage},
						},
						Options: crawl.Options{IncludeBody: true},
					},
				})
				writeText(rawDispatch)
			}
		}
	})
	mux.HandleFunc("/agent/reply", func(w http.ResponseWriter, r *http.Request) {
		gz, err := gzip.NewReader(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		defer gz.Close()
		var rep crawl.FetchReply
		if err := json.NewDecoder(gz).Decode(&rep); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		replyOnce.Do(func() { replyCh <- rep })
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	})
	hubSrv := httptest.NewServer(mux)
	defer hubSrv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()

	cfg := Config{
		HubURL:        hubSrv.URL,
		AgentToken:    "agent-secret-token-0123456789-abcdef",
		SiteID:        "site-arm64",
		UserAgent:     crawl.DefaultUserAgent,
		PauseMs:       3000,
		PauseJitterMs: 1000,
	}

	started := time.Now()
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, cfg, crawler, crawl.PublicHTTPS, http.DefaultTransport, log, RuntimeOpts{
			PingInterval:  20 * time.Millisecond,
			ReadWatchdog:  120 * time.Millisecond,
			ShutdownDrain: time.Second,
		})
	}()

	var rep crawl.FetchReply
	select {
	case rep = <-replyCh:
	case <-ctx.Done():
		t.Fatal("timed out waiting for multi-domain burst reply (GapMs or Concurrency starved batch)")
	}
	elapsed := time.Since(started)
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if wsConns.Load() != 1 {
		t.Fatalf("expected 1 uninterrupted WebSocket session (pong frames drained while dispatch ran), got %d", wsConns.Load())
	}
	if elapsed > 4500*time.Millisecond {
		t.Fatalf("expected 4 distinct domains with 250ms cross-domain gap to finish in <4.5s (even with PauseMs=3000), took %s", elapsed)
	}
	for i, res := range rep.Results {
		if res.Outcome != classify.OutcomeOK {
			t.Fatalf("result %d failed: %+v", i, res)
		}
	}
}

func TestSessionReconnectDoesNotBlockOnInFlightDispatch(t *testing.T) {
	originSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/robots.txt" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		select {
		case <-time.After(1600 * time.Millisecond):
		case <-r.Context().Done():
			return
		}
		w.Header().Set("content-type", "text/html")
		_, _ = w.Write([]byte("<html>slow-origin-ok</html>"))
	}))
	defer originSrv.Close()
	originAddr := originSrv.Listener.Addr().String()

	tr := &http.Transport{
		TLSClientConfig: originSrv.Client().Transport.(*http.Transport).TLSClientConfig,
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, originAddr)
		},
	}
	log := slog.New(slog.NewJSONHandler(io.Discard, nil))
	crawler := crawl.NewCrawler(tr, crawl.PublicHTTPS, crawl.DefaultUserAgent, log)
	crawler.Jitter = func(time.Duration) time.Duration { return 250 * time.Millisecond }

	var (
		mu              sync.Mutex
		dropAt          time.Time
		reconnectedAt   time.Time
		wsSessionCount  int
		secondConnected = make(chan struct{})
		replyCh         = make(chan crawl.FetchReply, 1)
	)

	mux := http.NewServeMux()
	mux.HandleFunc("/agent/ws", func(w http.ResponseWriter, r *http.Request) {
		sc, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer sc.CloseNow()

		mu.Lock()
		wsSessionCount++
		sessNum := wsSessionCount
		if sessNum == 2 {
			reconnectedAt = time.Now()
			close(secondConnected)
		}
		mu.Unlock()

		for {
			_, data, err := sc.Read(r.Context())
			if err != nil {
				return
			}
			s := string(data)
			if s == "ping" {
				_ = sc.Write(r.Context(), websocket.MessageText, []byte("pong"))
				continue
			}
			if sessNum == 1 && strings.Contains(s, `"agent_hello"`) {
				rawDispatch, _ := json.Marshal(map[string]any{
					"type":     "dispatch",
					"jobId":    "job-inflight-drop",
					"jobNonce": "nonce-inflight-drop",
					"call": crawl.FetchCall{
						Requests: []crawl.Request{{ID: "slow", URL: "https://slow.example.com/page", Kind: classify.KindPage}},
						Options:  crawl.Options{IncludeBody: true, TimeoutMs: 5000},
					},
				})
				_ = sc.Write(r.Context(), websocket.MessageText, rawDispatch)
				time.Sleep(150 * time.Millisecond)
				mu.Lock()
				dropAt = time.Now()
				mu.Unlock()
				return // Drop first WebSocket while 1.6s origin request is still in flight!
			}
		}
	})
	mux.HandleFunc("/agent/reply", func(w http.ResponseWriter, r *http.Request) {
		gz, err := gzip.NewReader(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		defer gz.Close()
		var rep crawl.FetchReply
		if err := json.NewDecoder(gz).Decode(&rep); err == nil {
			select {
			case replyCh <- rep:
			default:
			}
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	})
	hubSrv := httptest.NewServer(mux)
	defer hubSrv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cfg := Config{
		HubURL:     hubSrv.URL,
		AgentToken: "agent-secret-token-0123456789-abcdef",
		SiteID:     "site-r5",
		UserAgent:  crawl.DefaultUserAgent,
		PauseMs:    1000,
	}

	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, cfg, crawler, crawl.PublicHTTPS, http.DefaultTransport, log, RuntimeOpts{
			PingInterval:  50 * time.Millisecond,
			ReadWatchdog:  time.Second,
			ShutdownDrain: 500 * time.Millisecond,
		})
	}()

	select {
	case <-secondConnected:
	case <-ctx.Done():
		t.Fatal("timed out waiting for immediate WebSocket reconnect while job was in flight")
	}

	mu.Lock()
	reconnectGap := reconnectedAt.Sub(dropAt)
	mu.Unlock()
	if reconnectGap > 900*time.Millisecond {
		t.Fatalf("expected WebSocket reconnect (<900ms) without waiting for 1.6s in-flight job, took %s", reconnectGap)
	}

	var got crawl.FetchReply
	select {
	case got = <-replyCh:
	case <-ctx.Done():
		t.Fatal("in-flight job never uploaded /agent/reply after socket reconnect")
	}
	if len(got.Results) != 1 || got.Results[0].Outcome != classify.OutcomeOK {
		t.Fatalf("expected in-flight job reply OutcomeOK, got %+v", got)
	}

	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Run error: %v", err)
	}
}

func TestR6QueueFullNonBlockingReconnectAndSupersededNonceDrop(t *testing.T) {
	originSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/robots.txt" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		hold := 250 * time.Millisecond
		if strings.HasPrefix(r.Host, "hold.") {
			hold = 3 * time.Second
		}
		select {
		case <-time.After(hold):
		case <-r.Context().Done():
			return
		}
		w.Header().Set("content-type", "text/html")
		_, _ = w.Write([]byte("<html>ok</html>"))
	}))
	defer originSrv.Close()
	originAddr := originSrv.Listener.Addr().String()

	tr := &http.Transport{
		TLSClientConfig: originSrv.Client().Transport.(*http.Transport).TLSClientConfig,
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, originAddr)
		},
	}
	log := slog.New(slog.NewJSONHandler(io.Discard, nil))
	crawler := crawl.NewCrawler(tr, crawl.PublicHTTPS, crawl.DefaultUserAgent, log)
	crawler.Jitter = func(time.Duration) time.Duration { return 250 * time.Millisecond }
	defer crawler.Close()

	makeMsg := func(job, host, nonce string) []byte {
		raw, _ := json.Marshal(map[string]any{
			"type":     "dispatch",
			"jobId":    job,
			"jobNonce": nonce,
			"call": crawl.FetchCall{
				Requests: []crawl.Request{{ID: "1", URL: "https://" + host + ".example.com/x", Kind: classify.KindPage}},
				Options:  crawl.Options{TimeoutMs: 5000},
			},
		})
		return raw
	}

	// Part 1: 12 dispatches (1 running + 8 queued + 3 busy-rejected) followed by socket drop MUST reconnect in <900ms!
	{
		var (
			mu         sync.Mutex
			sessCount  int
			dropAt     time.Time
			reconnAt   time.Time
			busySeen   atomic.Int32
			reconnDone = make(chan struct{})
		)
		mux := http.NewServeMux()
		mux.HandleFunc("/agent/ws", func(w http.ResponseWriter, r *http.Request) {
			sc, err := websocket.Accept(w, r, nil)
			if err != nil {
				return
			}
			defer sc.CloseNow()
			mu.Lock()
			sessCount++
			s := sessCount
			if s == 2 {
				reconnAt = time.Now()
				close(reconnDone)
			}
			mu.Unlock()
			for {
				_, data, err := sc.Read(r.Context())
				if err != nil {
					return
				}
				if s == 1 && strings.Contains(string(data), `"agent_hello"`) {
					for j := 0; j < 12; j++ {
						_ = sc.Write(r.Context(), websocket.MessageText, makeMsg(fmt.Sprintf("qf-%d", j), "hold", "n1"))
					}
					time.Sleep(150 * time.Millisecond)
					mu.Lock()
					dropAt = time.Now()
					mu.Unlock()
					return
				}
			}
		})
		mux.HandleFunc("/agent/reply", func(w http.ResponseWriter, r *http.Request) {
			gz, err := gzip.NewReader(r.Body)
			if err == nil {
				var rep crawl.FetchReply
				if json.NewDecoder(gz).Decode(&rep) == nil && len(rep.Results) > 0 && strings.Contains(rep.Results[0].Problem, "agent_busy") {
					busySeen.Add(1)
				}
				_ = gz.Close()
			}
			_, _ = w.Write([]byte(`{"ok":true}`))
		})
		hub := httptest.NewServer(mux)
		ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
		done := make(chan error, 1)
		go func() {
			done <- Run(ctx, Config{
				HubURL:     hub.URL,
				AgentToken: "agent-secret-token-0123456789-abcdef",
				SiteID:     "site-r6",
				UserAgent:  crawl.DefaultUserAgent,
				PauseMs:    0,
			}, crawler, crawl.PublicHTTPS, http.DefaultTransport, log, RuntimeOpts{ShutdownDrain: 50 * time.Millisecond})
		}()
		select {
		case <-reconnDone:
		case <-ctx.Done():
			t.Fatal("read loop blocked on full dispatch queue; never reconnected after socket drop")
		}
		mu.Lock()
		gap := reconnAt.Sub(dropAt)
		mu.Unlock()
		if gap > 950*time.Millisecond {
			t.Fatalf("expected immediate reconnect (<950ms) when dispatch queue is full, took %s", gap)
		}
		deadline := time.Now().Add(2 * time.Second)
		for busySeen.Load() < 3 && time.Now().Before(deadline) {
			time.Sleep(25 * time.Millisecond)
		}
		if busySeen.Load() < 3 {
			t.Fatalf("expected >=3 agent_busy replies for overflow dispatches, got %d", busySeen.Load())
		}
		cancel()
		<-done
		hub.Close()
	}

	// Part 2: Re-dispatched jobs with a newer nonce supersede queued/in-flight session-1 jobs with zero stale replies!
	{
		var (
			mu          sync.Mutex
			sessCount   int
			stalePosts  int
			freshNonces = make(map[string]string)
			allDone     = make(chan struct{})
		)
		mux := http.NewServeMux()
		mux.HandleFunc("/agent/ws", func(w http.ResponseWriter, r *http.Request) {
			sc, err := websocket.Accept(w, r, nil)
			if err != nil {
				return
			}
			defer sc.CloseNow()
			mu.Lock()
			sessCount++
			s := sessCount
			mu.Unlock()
			for {
				_, data, err := sc.Read(r.Context())
				if err != nil {
					return
				}
				if !strings.Contains(string(data), `"agent_hello"`) {
					continue
				}
				if s == 1 {
					for j := 0; j < 6; j++ {
						host := fmt.Sprintf("job%d", j)
						if j == 0 {
							host = "hold"
						}
						_ = sc.Write(r.Context(), websocket.MessageText, makeMsg(fmt.Sprintf("j%d", j), host, "nonce-s1"))
					}
					time.Sleep(120 * time.Millisecond)
					return
				}
				if s == 2 {
					for j := 0; j < 6; j++ {
						_ = sc.Write(r.Context(), websocket.MessageText, makeMsg(fmt.Sprintf("j%d", j), fmt.Sprintf("s2job%d", j), "nonce-s2"))
					}
					_ = sc.Write(r.Context(), websocket.MessageText, makeMsg("fresh", "s2fresh", "nonce-s2"))
				}
			}
		})
		mux.HandleFunc("/agent/reply", func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.Copy(io.Discard, r.Body)
			jid := r.Header.Get("X-Job-Id")
			nonce := r.Header.Get("X-Job-Nonce")
			mu.Lock()
			if nonce == "nonce-s1" {
				stalePosts++
			} else if nonce == "nonce-s2" {
				freshNonces[jid] = nonce
				if len(freshNonces) == 7 {
					select {
					case <-allDone:
					default:
						close(allDone)
					}
				}
			}
			mu.Unlock()
			_, _ = w.Write([]byte(`{"ok":true}`))
		})
		hub := httptest.NewServer(mux)
		ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
		done := make(chan error, 1)
		go func() {
			done <- Run(ctx, Config{
				HubURL:     hub.URL,
				AgentToken: "agent-secret-token-0123456789-abcdef",
				SiteID:     "site-r6",
				UserAgent:  crawl.DefaultUserAgent,
				PauseMs:    0,
			}, crawler, crawl.PublicHTTPS, http.DefaultTransport, log, RuntimeOpts{ShutdownDrain: 50 * time.Millisecond})
		}()
		select {
		case <-allDone:
		case <-ctx.Done():
			t.Fatalf("timed out waiting for all 7 re-dispatched nonce-s2 replies (got %d)", len(freshNonces))
		}
		mu.Lock()
		sp := stalePosts
		mu.Unlock()
		if sp != 0 {
			t.Fatalf("SECURITY: expected 0 stale nonce-s1 replies after reconnect re-dispatch, got %d", sp)
		}
		cancel()
		<-done
		hub.Close()
	}
}
