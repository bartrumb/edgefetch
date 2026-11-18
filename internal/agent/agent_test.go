package agent

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
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

	"github.com/bartrumb/edgefetch/internal/classify"
	"github.com/bartrumb/edgefetch/internal/crawl"
)

func TestConfigSecurityGuards(t *testing.T) {
	dir := t.TempDir()
	optPath := filepath.Join(dir, "options.json")
	if err := os.WriteFile(optPath, []byte(`{
		"hub_url": "https://hub.example.com/",
		"agent_token": "secret-agent-token-0123456789",
		"site_id": "Site-ARM64",
		"user_agent": "CustomBot/2.0 (+https://example.com)"
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
	var calls atomic.Int32
	originSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/robots.txt" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if calls.Add(1) == 1 {
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
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		time.Sleep(10200 * time.Millisecond)
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

	if strings.Contains(logBuf.String(), "agent_reply_failed") {
		t.Fatalf("A2 BUG: normal (non-shutdown) reply upload failed at >10s even within 45s client budget: %s", logBuf.String())
	}
}
