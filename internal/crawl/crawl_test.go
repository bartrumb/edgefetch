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
