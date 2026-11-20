package hub

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
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bartrumb/edgefetch/v2/internal/classify"
	"github.com/bartrumb/edgefetch/v2/internal/crawl"
)

func TestGoHubTokenlessLoopbackCSRFAndDNSRebindingProtection(t *testing.T) {
	silentLog := slog.New(slog.NewJSONHandler(io.Discard, nil))
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/robots.txt" || r.URL.Path == "/llms.txt" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte("<html><body><main><h1>Loopback OK</h1></main></body></html>"))
	}))
	defer origin.Close()

	originAddr := origin.Listener.Addr().String()
	tr := &http.Transport{
		TLSClientConfig: origin.Client().Transport.(*http.Transport).TLSClientConfig,
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, originAddr)
		},
	}
	fc := crawl.NewCrawler(tr, func(*url.URL) error { return nil }, crawl.DefaultUserAgent, silentLog)
	defer fc.Close()

	srv := httptest.NewUnstartedServer(nil)
	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	h := NewServer(Config{
		CallerToken:         "", // Tokenless desktop/serve mode!
		AllowedLoopbackPort: port,
		FallbackCrawler:     fc,
		Allow:               func(*url.URL) error { return nil },
		Logger:              silentLog,
	})
	defer h.Close()
	srv.Config.Handler = h
	srv.Start()
	defer srv.Close()

	// 1. DNS rebinding (`Host: rebind.attacker.example`) -> 403 Forbidden
	reqRebind, _ := http.NewRequest(http.MethodPost, srv.URL+"/v1/scrape", strings.NewReader(`{"url":"https://docs.example.com/"}`))
	reqRebind.Host = "rebind.attacker.example:" + port
	reqRebind.Header.Set("Content-Type", "application/json")
	respRebind, err := http.DefaultClient.Do(reqRebind)
	if err != nil {
		t.Fatal(err)
	}
	_ = respRebind.Body.Close()
	if respRebind.StatusCode != http.StatusForbidden {
		t.Fatalf("H2: expected 403 for DNS-rebinding Host header, got %d", respRebind.StatusCode)
	}

	// 2. Cross-origin browser fetch (`Origin: https://evil.example`) -> 403 Forbidden
	reqOrigin, _ := http.NewRequest(http.MethodPost, srv.URL+"/v1/scrape", strings.NewReader(`{"url":"https://docs.example.com/"}`))
	reqOrigin.Header.Set("Origin", "https://evil.example")
	reqOrigin.Header.Set("Content-Type", "application/json")
	respOrigin, err := http.DefaultClient.Do(reqOrigin)
	if err != nil {
		t.Fatal(err)
	}
	_ = respOrigin.Body.Close()
	if respOrigin.StatusCode != http.StatusForbidden {
		t.Fatalf("H2: expected 403 for cross-origin browser request, got %d", respOrigin.StatusCode)
	}

	// 3. Sec-Fetch-Site: cross-site -> 403 Forbidden
	reqSecFetch, _ := http.NewRequest(http.MethodPost, srv.URL+"/v1/scrape", strings.NewReader(`{"url":"https://docs.example.com/"}`))
	reqSecFetch.Header.Set("Sec-Fetch-Site", "cross-site")
	reqSecFetch.Header.Set("Content-Type", "application/json")
	respSecFetch, err := http.DefaultClient.Do(reqSecFetch)
	if err != nil {
		t.Fatal(err)
	}
	_ = respSecFetch.Body.Close()
	if respSecFetch.StatusCode != http.StatusForbidden {
		t.Fatalf("H2: expected 403 for Sec-Fetch-Site: cross-site, got %d", respSecFetch.StatusCode)
	}

	// 4. Simple HTML form CSRF (`Content-Type: text/plain`) -> 415 Unsupported Media Type
	reqForm, _ := http.NewRequest(http.MethodPost, srv.URL+"/v1/scrape", strings.NewReader(`{"url":"https://docs.example.com/"}`))
	reqForm.Header.Set("Content-Type", "text/plain")
	respForm, err := http.DefaultClient.Do(reqForm)
	if err != nil {
		t.Fatal(err)
	}
	_ = respForm.Body.Close()
	if respForm.StatusCode != http.StatusUnsupportedMediaType {
		t.Fatalf("H2: expected 415 for non-JSON POST in tokenless mode, got %d", respForm.StatusCode)
	}

	// 5. Legitimate loopback CLI/MCP request -> 200 OK
	reqOK, _ := http.NewRequest(http.MethodPost, srv.URL+"/v1/scrape", strings.NewReader(`{"url":"https://docs.example.com/"}`))
	reqOK.Header.Set("Content-Type", "application/json")
	respOK, err := http.DefaultClient.Do(reqOK)
	if err != nil {
		t.Fatal(err)
	}
	_ = respOK.Body.Close()
	if respOK.StatusCode != http.StatusOK {
		t.Fatalf("H2: expected 200 for legitimate loopback JSON request, got %d", respOK.StatusCode)
	}
}

func TestGoHubAtomicAgentReplyClaimAndResultIntegrity(t *testing.T) {
	silentLog := slog.New(slog.NewJSONHandler(io.Discard, nil))
	const agentTok = "agent-audit-token-0123456789abcdef"
	h := NewServer(Config{
		CallerToken: "caller-audit-token-0123456789abcdef",
		AgentToken:  agentTok,
		Allow:       func(*url.URL) error { return nil },
		Logger:      silentLog,
	})
	defer h.Close()
	srv := httptest.NewServer(h)
	defer srv.Close()

	// Seed a real pending job expecting ID="req-expected" and URL="https://trusted.example.com/doc"
	pj := &pendingJob{
		jobID:     "job_audit_1",
		jobNonce:  "nonce_audit_0123456789abcdef",
		siteID:    "site-1",
		createdAt: time.Now(),
		requests: []crawl.Request{
			{ID: "req-expected", URL: "https://trusted.example.com/doc", Kind: classify.KindScrape},
		},
		uploadedBlobs: make(map[string]bool),
		doneCh:        make(chan jobOutcome, 1),
	}
	h.mu.Lock()
	h.pending[pj.jobID] = pj
	h.mu.Unlock()

	forgedSha := strings.Repeat("a", 64)
	forgedReply := crawl.FetchReply{
		Results: []crawl.Result{
			{
				ID:       "forged-id",
				URL:      "https://poisoned-cache.example.com/evil",
				Kind:     classify.KindScrape,
				Outcome:  classify.OutcomeOK,
				Status:   200,
				Markdown: "# Clean Content",
				Artifact: &crawl.ArtifactRef{
					BlobSHA256:    forgedSha,
					ContentSHA256: strings.Repeat("b", 64),
					ContentBytes:  100,
					StoredBytes:   80,
					Encoding:      "gzip",
					Retention:     "stored",
				},
			},
		},
	}
	rawJSON, _ := json.Marshal(forgedReply)
	var gzBuf bytes.Buffer
	gz := gzip.NewWriter(&gzBuf)
	_, _ = gz.Write(rawJSON)
	_ = gz.Close()
	gzBytes := gzBuf.Bytes()

	// Fire 10 parallel POST /agent/reply requests for the same pending job (`M3` race test).
	var accepted atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req, _ := http.NewRequest(http.MethodPost, srv.URL+"/agent/reply", bytes.NewReader(gzBytes))
			req.Header.Set("Authorization", "Bearer "+agentTok)
			req.Header.Set("X-Agent-Site", "site-1")
			req.Header.Set("X-Job-Id", pj.jobID)
			req.Header.Set("X-Job-Nonce", pj.jobNonce)
			req.Header.Set("Content-Encoding", "gzip")
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				return
			}
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				accepted.Add(1)
			}
		}()
	}
	wg.Wait()

	if accepted.Load() != 1 {
		t.Fatalf("M3: expected exactly 1 parallel /agent/reply to win atomic claim, got %d", accepted.Load())
	}

	outcome := <-pj.doneCh
	if outcome.err != nil || len(outcome.reply.Results) != 1 {
		t.Fatalf("expected completed reply outcome, got err=%v reply=%+v", outcome.err, outcome.reply)
	}
	got := outcome.reply.Results[0]
	if got.ID != "req-expected" || got.URL != "https://trusted.example.com/doc" {
		t.Fatalf("H6: forged ID/URL was not overwritten! got ID=%q URL=%q", got.ID, got.URL)
	}
	if got.Artifact != nil {
		t.Fatalf("H6: unauthorized Artifact reference should have been stripped, got %+v", got.Artifact)
	}
}
