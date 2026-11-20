package browser

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestChromiumLaunchFlagsAndSanitizedChildEnv(t *testing.T) {
	args := buildChromiumLaunchArgs("127.0.0.1:43210", "/tmp/ef-profile")
	joined := strings.Join(args, " ")

	if !strings.Contains(joined, "--proxy-bypass-list=<-loopback>") {
		t.Fatalf("H1: missing --proxy-bypass-list=<-loopback> in Chromium flags: %s", joined)
	}
	if !strings.Contains(joined, "--force-webrtc-ip-handling-policy=disable_non_proxied_udp") {
		t.Fatalf("M1: missing WebRTC non-proxied UDP block flag in Chromium flags: %s", joined)
	}
	if strings.Contains(joined, "IsolateOrigins") || strings.Contains(joined, "site-per-process") {
		t.Fatalf("H9: Chromium site isolation must not be disabled: %s", joined)
	}

	t.Setenv("EDGEFETCH_AGENT_TOKEN", "super-secret-agent-token-0123456789")
	t.Setenv("OPENAI_API_KEY", "sk-live-secret-should-never-leak")
	env := buildSanitizedChildEnv("/tmp/ef-profile")
	for _, kv := range env {
		if strings.HasPrefix(kv, "EDGEFETCH_") || strings.HasPrefix(kv, "OPENAI_") || strings.Contains(kv, "super-secret-agent-token") {
			t.Fatalf("H9: secret env leaked into Chromium child environment: %q", kv)
		}
	}
}

func TestRendererLoopbackProxyBypassBlockedLiveIfChromeInstalled(t *testing.T) {
	chromeBin := FindChromeBinary()
	if chromeBin == "" {
		t.Skip("Chromium/Chrome binary not installed on host; live container smoke runs in docker-multiarch CI")
	}

	var victimHits atomic.Int32
	victim := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		victimHits.Add(1)
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html><body>TOP_SECRET_LOOPBACK_TOKEN</body></html>"))
	}))
	defer victim.Close()

	allowHTTPSPublicOnly := func(u *url.URL) error {
		if u.Scheme != "https" {
			return errors.New("https required")
		}
		h := strings.ToLower(u.Hostname())
		if h == "localhost" || h == "127.0.0.1" || h == "::1" {
			return errors.New("loopback forbidden")
		}
		return nil
	}

	r := NewRenderer(chromeBin, allowHTTPSPublicOnly, "EdgeFetchTest/2.5.3", 1, slog.New(slog.NewJSONHandler(io.Discard, nil)))
	defer r.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	// Attempt to render a data/blank or direct loopback target: SSRFProxy + `<-loopback>` + FinalURL check must block 100% of hits.
	out, err := r.Execute(ctx, Task{
		URL:       victim.URL + "/secret",
		WaitForMs: 300,
	})
	if victimHits.Load() != 0 {
		t.Fatalf("SECURITY (H1): Chromium bypassed SSRFProxy and hit loopback victim %d time(s)!", victimHits.Load())
	}
	if err == nil && strings.Contains(out.HTML, "TOP_SECRET_LOOPBACK_TOKEN") {
		t.Fatalf("SECURITY (H1): loopback response body leaked into rendered output")
	}
}

func TestValidateFinalURLChecksRobotsEvenOnResumedInteractSession(t *testing.T) {
	var checked []string
	r := NewRenderer("", func(u *url.URL) error {
		if u.Scheme != "https" {
			return errors.New("https required")
		}
		return nil
	}, "EdgeFetchTest/2.5.4", 1, nil)
	r.CheckRobots = func(_ context.Context, rawURL string) error {
		checked = append(checked, rawURL)
		if strings.Contains(rawURL, "/private-admin") {
			return errors.New("disallowed by /robots.txt")
		}
		return nil
	}

	sess := &retainedSession{id: "efsess_test123"}
	sess.setLastCheckedURL("https://example.com/public")

	// Resumed interact turn has initialURL == ""; clicking a link to /private-admin MUST invoke CheckRobots and block!
	err := r.validateFinalURL(context.Background(), sess, "https://example.com/private-admin", "")
	if err == nil || !strings.Contains(err.Error(), "robots.txt") {
		t.Fatalf("H8: expected resumed interact cross-URL navigation to be blocked by CheckRobots, got err=%v", err)
	}
	if len(checked) != 1 || checked[0] != "https://example.com/private-admin" {
		t.Fatalf("H8: expected CheckRobots called once on finalURL, got %v", checked)
	}
}
