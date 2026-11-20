package crawl

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/bartrumb/edgefetch/v2/internal/classify"
)

func FuzzValidateCustomHeaders(f *testing.F) {
	f.Add("X-Api-Version", "2026-01")
	f.Add("Authorization", "Bearer secret")
	f.Add("Cookie", "sid=123")
	f.Add("Host", "evil.example")
	f.Add("CF-Connecting-IP", "1.2.3.4")
	f.Add("X-Forwarded-For", "127.0.0.1")
	f.Add("Proxy-Authorization", "Basic abc")
	f.Add("X-Inject\r\nEvil", "val")
	f.Add("X-Test", "line1\r\nHost: internal")

	f.Fuzz(func(t *testing.T, k, v string) {
		if len(k) > 8192 || len(v) > 16384 {
			return
		}
		err := ValidateCustomHeaders(map[string]string{k: v})
		if err == nil {
			trimmed := strings.ToLower(strings.TrimSpace(k))
			if trimmed == "" ||
				trimmed == "host" ||
				trimmed == "authorization" ||
				trimmed == "cookie" ||
				strings.HasPrefix(trimmed, "proxy-") ||
				strings.HasPrefix(trimmed, "cf-") ||
				strings.HasPrefix(trimmed, "x-forwarded-") ||
				strings.ContainsAny(k, "\r\n\x00") ||
				strings.ContainsAny(v, "\r\n\x00") {
				t.Fatalf("SECURITY: forbidden custom header accepted: %q=%q", k, v)
			}
		}
	})
}

func FuzzPublicHTTPS(f *testing.F) {
	f.Add("https://example.com/docs")
	f.Add("http://example.com/docs")
	f.Add("https://127.0.0.1/")
	f.Add("https://127.1/")
	f.Add("https://0x7f.0.0.1/")
	f.Add("https://[::1]/")
	f.Add("https://[::ffff:127.0.0.1%25eth0]/")
	f.Add("https://localhost/admin")
	f.Add("https://api.localhost/admin")
	f.Add("https://user:pass@example.com/")
	f.Add("https://example.com:8443/")

	f.Fuzz(func(t *testing.T, raw string) {
		if len(raw) > 2048 {
			return
		}
		u, err := url.Parse(raw)
		if err != nil {
			return
		}
		gotErr := PublicHTTPS(u)
		if gotErr == nil {
			if u.Scheme != "https" {
				t.Fatalf("SECURITY: non-https accepted: %q", raw)
			}
			if u.User != nil {
				t.Fatalf("SECURITY: userinfo accepted: %q", raw)
			}
			if p := u.Port(); p != "" && p != "443" {
				t.Fatalf("SECURITY: non-443 port accepted: %q", raw)
			}
			h := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
			if net.ParseIP(h) != nil {
				t.Fatalf("SECURITY: net.ParseIP literal accepted: %q", raw)
			}
			if _, addrErr := netip.ParseAddr(h); addrErr == nil {
				t.Fatalf("SECURITY: netip.ParseAddr literal accepted: %q", raw)
			}
			if h == "localhost" || strings.HasSuffix(h, ".localhost") || !strings.Contains(h, ".") {
				t.Fatalf("SECURITY: localhost or single-label host accepted: %q", raw)
			}
		}
	})
}

func TestStreamingPDFCutOffAtConfiguredCapAndCrossOriginRedirectHeaderStrip(t *testing.T) {
	t.Setenv("EDGEFETCH_MAX_PDF_BYTES", "4096")

	var leakedHeader atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/robots.txt":
			w.WriteHeader(http.StatusNotFound)
		case "/giant.pdf":
			w.Header().Set("Content-Type", "application/pdf")
			_, _ = w.Write([]byte("%PDF-1.7\n"))
			_, _ = w.Write([]byte(strings.Repeat("A", 16384)))
		case "/start":
			if r.Header.Get("X-Custom-Token") != "origin-only" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			w.Header().Set("Location", "http://second.example/landed")
			w.WriteHeader(http.StatusFound)
		case "/landed":
			if r.Header.Get("X-Custom-Token") != "" {
				leakedHeader.Store(true)
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write([]byte("<html><body><main><h1>Landed</h1></main></body></html>"))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	addr := srv.Listener.Addr().String()
	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		},
	}
	c := NewCrawler(tr, func(*url.URL) error { return nil }, DefaultUserAgent, slog.New(slog.NewJSONHandler(io.Discard, nil)))
	defer c.Close()

	results := c.Run(context.Background(), []Request{
		{ID: "pdf-cap", URL: "http://first.example/giant.pdf", Kind: classify.KindScrape},
		{
			ID:      "redir-strip",
			URL:     "http://first.example/start",
			Kind:    classify.KindScrape,
			Headers: map[string]string{"X-Custom-Token": "origin-only"},
		},
	}, Options{MaxBytes: 1 << 20})

	if !results[0].Truncated || results[0].Outcome != classify.OutcomeError {
		t.Fatalf("expected giant PDF exceeding EDGEFETCH_MAX_PDF_BYTES=4096 to fail truncated, got: %+v", results[0])
	}
	if results[1].Outcome != classify.OutcomeOK {
		t.Fatalf("expected cross-origin redirect to succeed cleanly, got: %+v", results[1])
	}
	if leakedHeader.Load() {
		t.Fatal("SECURITY: custom request header leaked across cross-origin HTTP redirect")
	}
}
