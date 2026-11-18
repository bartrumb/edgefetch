package agent

import (
	"bufio"
	"compress/gzip"
	"context"
	"encoding/binary"
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

	"github.com/bartrumb/edgefetch/internal/classify"
	"github.com/bartrumb/edgefetch/internal/crawl"
	"github.com/bartrumb/edgefetch/internal/ws"
)

func writeServerFrame(w io.Writer, opcode byte, payload []byte) error {
	n := len(payload)
	hdr := make([]byte, 0, 10+n)
	hdr = append(hdr, 0x80|(opcode&0x0F))
	if n < 126 {
		hdr = append(hdr, byte(n))
	} else {
		hdr = append(hdr, 126, 0, 0)
		binary.BigEndian.PutUint16(hdr[len(hdr)-2:], uint16(n))
	}
	hdr = append(hdr, payload...)
	_, err := w.Write(hdr)
	return err
}

func readClientFrame(br *bufio.Reader) (byte, []byte, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(br, hdr[:]); err != nil {
		return 0, nil, err
	}
	opcode := hdr[0] & 0x0F
	masked := (hdr[1] & 0x80) != 0
	length := uint64(hdr[1] & 0x7F)
	if length == 126 {
		var ext [2]byte
		if _, err := io.ReadFull(br, ext[:]); err != nil {
			return 0, nil, err
		}
		length = uint64(binary.BigEndian.Uint16(ext[:]))
	}
	var mask [4]byte
	if masked {
		if _, err := io.ReadFull(br, mask[:]); err != nil {
			return 0, nil, err
		}
	}
	payload := make([]byte, int(length))
	if _, err := io.ReadFull(br, payload); err != nil {
		return 0, nil, err
	}
	if masked {
		ws.MaskBytes(payload, mask)
	}
	return opcode, payload, nil
}

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
	originSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
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
		hj := w.(http.Hijacker)
		conn, rw, _ := hj.Hijack()
		_, _ = rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " + ws.ComputeAccept(r.Header.Get("Sec-WebSocket-Key")) + "\r\n\r\n")
		_ = rw.Flush()

		if connects.Add(1) == 1 {
			_ = conn.Close()
			return
		}
		defer conn.Close()

		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		sawHello, sawPing := false, false
		for !sawHello || !sawPing {
			op, payload, err := readClientFrame(rw.Reader)
			if err != nil {
				t.Errorf("readClientFrame: %v", err)
				return
			}
			if op != ws.OpText {
				continue
			}
			s := string(payload)
			if s == "ping" {
				sawPing = true
				_ = writeServerFrame(conn, ws.OpText, []byte("pong"))
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
		_ = writeServerFrame(conn, ws.OpText, rawDispatch)
		<-time.After(2 * time.Second)
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
