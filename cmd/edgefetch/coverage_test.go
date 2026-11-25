package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bartrumb/edgefetch/v2/internal/agent"
	"github.com/bartrumb/edgefetch/v2/internal/botauth"
	"github.com/bartrumb/edgefetch/v2/internal/crawl"
)

func TestMainHelpersAndBlockedHubRuleHardening(t *testing.T) {
	t.Parallel()
	// Transport pool defaults
	ht := newHubTransportWithPool(0, 0)
	if ht.IdleConnTimeout != 90*time.Second || ht.MaxIdleConnsPerHost != 2 {
		t.Fatalf("unexpected newHubTransportWithPool defaults: idle=%v maxIdle=%d", ht.IdleConnTimeout, ht.MaxIdleConnsPerHost)
	}
	pt := newAgentPrivateTransportWithPool(0, 0, nil)
	if pt.IdleConnTimeout != 90*time.Second || pt.MaxIdleConnsPerHost != 2 {
		t.Fatalf("unexpected newAgentPrivateTransportWithPool defaults: idle=%v maxIdle=%d", pt.IdleConnTimeout, pt.MaxIdleConnsPerHost)
	}

	// parseCanonicalAddr, allowHTTPAndHTTPSNoUserInfo, canonicalPort, normalizeURLPort, withBlockedAuthority, resolveCrawlPolicy, newAgentCrawlPolicy
	if _, ok := parseCanonicalAddr(""); ok {
		t.Fatal("expected empty parseCanonicalAddr false")
	}
	if _, ok := parseCanonicalAddr("[]"); ok {
		t.Fatal("expected [] parseCanonicalAddr false")
	}
	if err := allowHTTPAndHTTPSNoUserInfo(nil); err == nil {
		t.Fatal("expected nil URL rejected")
	}
	if err := allowHTTPAndHTTPSNoUserInfo(&url.URL{Scheme: "https", Path: "/x"}); err == nil {
		t.Fatal("expected missing host rejected")
	}
	for _, tc := range [][2]string{{"", ""}, {"0", "0"}, {"70000", "70000"}, {"abc", "abc"}, {"0443", "443"}} {
		if got := canonicalPort(tc[0]); got != tc[1] {
			t.Fatalf("canonicalPort(%q) = %q, want %q", tc[0], got, tc[1])
		}
	}
	if got := normalizeURLPort(nil); got != "" {
		t.Fatalf("expected empty normalizeURLPort(nil), got %q", got)
	}
	if got := normalizeURLPort(&url.URL{Scheme: "ftp", Host: "example.com"}); got != "" {
		t.Fatalf("expected empty normalizeURLPort(ftp), got %q", got)
	}

	baseAllow := func(*url.URL) error { return nil }
	if withBlockedAuthority(baseAllow, nil) == nil {
		t.Fatal("expected non-nil allow for nil hubURL")
	}
	hostOnlyBlock := withBlockedAuthority(baseAllow, &url.URL{Scheme: "custom", Host: "hub.example.com"})
	if err := hostOnlyBlock(&url.URL{Scheme: "https", Host: "hub.example.com"}); err == nil {
		t.Fatal("expected host-only blocked authority to reject hub.example.com")
	}

	privAllow, privTr := resolveCrawlPolicy(true, 0, 0)
	if privAllow == nil || privTr == nil {
		t.Fatal("expected non-nil resolveCrawlPolicy(true)")
	}
	polAllow, _ := newAgentCrawlPolicy(true, nil, []string{"://bad", "/rel", "https://hub.example.com"}, 0, 0)
	if err := polAllow(&url.URL{Scheme: "https", Host: "hub.example.com"}); err == nil {
		t.Fatal("expected valid hubURL in list still blocked")
	}

	// Mode parsing & helper edges
	if raw, has, err := extractRawMode([]string{"hub"}); err != nil || has || raw != "hub" {
		t.Fatalf("unexpected extractRawMode positional hub: raw=%q has=%v err=%v", raw, has, err)
	}
	if raw, has, err := extractRawMode([]string{"controller"}); err != nil || has || raw != "controller" {
		t.Fatalf("unexpected extractRawMode positional controller: raw=%q has=%v err=%v", raw, has, err)
	}
	if m, err := parseRuntimeModes([]string{"--mode=hub,,agent"}, "", ""); err != nil || !m.hub || !m.agent {
		t.Fatalf("expected --mode=hub,,agent parsed, got %+v err=%v", m, err)
	}
	if _, err := parseRuntimeModes([]string{"--mode=,"}, "", ""); err == nil {
		t.Fatal("expected --mode=, error")
	}
	if m := resolveRuntimeModes([]string{"--mode=bogus"}, "", ""); m.agent || m.hub || m.server || m.mcp {
		t.Fatalf("expected zero runtimeModes for bogus mode, got %+v", m)
	}
	if got := firstNonEmpty("", "   "); got != "" {
		t.Fatalf("expected empty firstNonEmpty, got %q", got)
	}

	// blockedHubRule.ensureResolved() direct guard, transient DNS failure recovery, TTL refresh, loopback/unmap/dedup, and -race concurrency
	emptyRule := &blockedHubRule{isLoopback: true}
	if ips, lb := emptyRule.ensureResolved(); ips != nil || lb {
		t.Fatalf("expected early return for loopback rule, got %v %v", ips, lb)
	}

	var nowMu sync.Mutex
	curTime := time.Unix(1_700_000_000, 0)
	nowFn := func() time.Time {
		nowMu.Lock()
		defer nowMu.Unlock()
		return curTime
	}

	var calls atomic.Int32
	rule := &blockedHubRule{
		authority: "hub.internal:8443",
		host:      "hub.internal",
		port:      "8443",
		nowFn:     nowFn,
		lookupFn: func(context.Context, string, string) ([]netip.Addr, error) {
			n := calls.Add(1)
			switch n {
			case 1:
				return nil, errors.New("temporary DNS failure")
			case 2:
				return nil, nil // empty result must not negative-cache
			case 3:
				return []netip.Addr{
					{},
					netip.MustParseAddr("::ffff:93.184.216.34"),
					netip.MustParseAddr("93.184.216.34"),
					netip.MustParseAddr("127.0.0.1"),
				}, nil
			default:
				return []netip.Addr{netip.MustParseAddr("203.0.113.55")}, nil
			}
		},
	}

	if ips, lb := rule.ensureResolved(); len(ips) != 0 || lb {
		t.Fatalf("expected transient error to return empty, got %v %v", ips, lb)
	}
	if ips, lb := rule.ensureResolved(); len(ips) != 0 || lb {
		t.Fatalf("expected empty lookup to return empty without caching, got %v %v", ips, lb)
	}
	ips3, lb3 := rule.ensureResolved()
	if !lb3 || len(ips3) != 2 {
		t.Fatalf("expected 2 deduplicated IPs + lb=true on call 3, got %v %v", ips3, lb3)
	}
	// Cached hit within 30s TTL
	ipsCached, _ := rule.ensureResolved()
	if calls.Load() != 3 || len(ipsCached) != 2 {
		t.Fatalf("expected cached hit within TTL, calls=%d ips=%v", calls.Load(), ipsCached)
	}
	// Advance past 30s TTL -> refreshes
	nowMu.Lock()
	curTime = curTime.Add(31 * time.Second)
	nowMu.Unlock()
	ips4, lb4 := rule.ensureResolved()
	if lb4 || len(ips4) != 1 || ips4[0] != netip.MustParseAddr("203.0.113.55") {
		t.Fatalf("expected refreshed IP after TTL, got %v %v", ips4, lb4)
	}

	// Concurrent -race dial control via newAgentPrivateControlWithLookup & default-resolver path
	defCtrl := newAgentPrivateControl([]string{"https://localhost.invalid:8443"})
	_ = defCtrl("tcp", "198.51.100.8:8443", nil)

	var lookupOnce atomic.Int32
	ctrl := newAgentPrivateControlWithLookup([]string{"://bad", "/rel", "https://hub.internal:8443"}, func(context.Context, string, string) ([]netip.Addr, error) {
		if lookupOnce.Add(1) == 1 {
			return nil, errors.New("first lookup failed")
		}
		return []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("::ffff:198.51.100.7")}, nil
	})
	if err := ctrl("tcp", "no-port", nil); err == nil {
		t.Fatal("expected invalid dial address error")
	}
	if err := ctrl("tcp", "badhost:8443", nil); err == nil {
		t.Fatal("expected unparseable peer IP error")
	}
	// Call 1: transient DNS error -> permits 198.51.100.7 initially
	if err := ctrl("tcp", "198.51.100.7:8443", nil); err != nil {
		t.Fatalf("unexpected error during initial transient DNS fail: %v", err)
	}
	// Call 2+: DNS succeeds -> blocks 198.51.100.7 & [::1]:8443 concurrently under -race!
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := ctrl("tcp", "198.51.100.7:8443", nil); err == nil {
				t.Errorf("expected resolved hub IP blocked")
			}
			if err := ctrl("tcp", "[::1]:8443", nil); err == nil {
				t.Errorf("expected resolved loopback hub IP blocked")
			}
			if err := ctrl("tcp", "198.51.100.7:9443", nil); err != nil {
				t.Errorf("expected non-hub port allowed: %v", err)
			}
		}()
	}
	wg.Wait()
}

func TestRunMainAndConfigureCrawlerBotAuth(t *testing.T) {
	t.Parallel()
	silentLog := slog.New(slog.NewJSONHandler(io.Discard, nil))
	c := crawl.NewCrawler(newHubTransport(), crawl.PublicHTTPS, crawl.DefaultUserAgent, silentLog)
	defer c.Close()

	// configureCrawlerBotAuth variants
	if s, err := configureCrawlerBotAuth(c, nil, nil, silentLog); err != nil || s != nil {
		t.Fatalf("expected nil signer when key unset, got %v %v", s, err)
	}
	if _, err := configureCrawlerBotAuth(c, nil, func(k string) string {
		if k == "EDGEFETCH_BOT_SIGNING_KEY" {
			return "not-a-valid-key"
		}
		return ""
	}, silentLog); err == nil {
		t.Fatal("expected invalid bot signing key error")
	}

	kp, err := botauth.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	for _, hubURL := range []string{"ws://hub.example.com:8787/agent/ws", "wss://hub.example.com/agent/ws"} {
		s, err := configureCrawlerBotAuth(c, []string{hubURL}, func(k string) string {
			if k == "EDGEFETCH_BOT_SIGNING_KEY" {
				return kp.PrivateKeySeedB64URL
			}
			return ""
		}, silentLog)
		if err != nil || s == nil {
			t.Fatalf("expected signer for %s, got %v %v", hubURL, s, err)
		}
	}

	// runMain: one-shot CLI
	var out, errBuf bytes.Buffer
	if rc := runMain(context.Background(), []string{"edgefetch", "version"}, &out, &errBuf, mainDeps{}); rc != 0 || !strings.Contains(out.String(), "edgefetch ") {
		t.Fatalf("runMain one-shot version failed: rc=%d out=%q", rc, out.String())
	}

	// runMain: Windows/macOS zero-arg desktop fallback
	desktopCalled := false
	rcDesk := runMain(context.Background(), []string{"edgefetch"}, &out, &errBuf, mainDeps{
		goos:   "windows",
		getenv: func(string) string { return "" },
		runDesktop: func(context.Context, []string, io.Writer, io.Writer) int {
			desktopCalled = true
			return 0
		},
	})
	if rcDesk != 0 || !desktopCalled {
		t.Fatalf("expected windows zero-arg desktop fallback, rc=%d called=%v", rcDesk, desktopCalled)
	}

	// runMain: invalid mode (rc 2), --mode=mcp (rc 0), & EDGEFETCH_MODE=mcp (rc 0)
	errBuf.Reset()
	if rc := runMain(context.Background(), []string{"edgefetch", "--mode=bogus"}, &out, &errBuf, mainDeps{getenv: func(string) string { return "" }}); rc != 2 {
		t.Fatalf("expected rc=2 for bogus mode, got %d", rc)
	}
	out.Reset()
	if rc := runMain(context.Background(), []string{"edgefetch", "--mode=mcp"}, &out, &errBuf, mainDeps{
		getenv: func(string) string { return "" },
		stdin:  strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}` + "\n"),
	}); rc != 0 || !strings.Contains(out.String(), `"result":{}`) {
		t.Fatalf("expected --mode=mcp ping rc=0, got rc=%d out=%q", rc, out.String())
	}
	out.Reset()
	if rc := runMain(context.Background(), []string{"edgefetch"}, &out, &errBuf, mainDeps{
		getenv: func(k string) string {
			if k == "EDGEFETCH_MODE" {
				return "mcp"
			}
			return ""
		},
		stdin: strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}` + "\n"),
	}); rc != 0 || !strings.Contains(out.String(), `"result":{}`) {
		t.Fatalf("expected EDGEFETCH_MODE=mcp ping rc=0, got rc=%d out=%q", rc, out.String())
	}

	// runMain: pure agent mode error paths & success
	agentEnv := func(k string) string {
		switch k {
		case "EDGEFETCH_HUB_URL":
			return "wss://hub.example.com/agent/ws"
		case "EDGEFETCH_AGENT_TOKEN":
			return "agent-secret-token-0123456789abc"
		case "EDGEFETCH_SITE_ID":
			return "site-1"
		default:
			return ""
		}
	}
	if rc := runMain(context.Background(), []string{"edgefetch", "--mode=agent"}, &out, &errBuf, mainDeps{
		getenv: func(string) string { return "" },
	}); rc != 2 {
		t.Fatalf("expected rc=2 for bad agent config, got %d", rc)
	}
	if rc := runMain(context.Background(), []string{"edgefetch", "--mode=agent"}, &out, &errBuf, mainDeps{
		getenv:          agentEnv,
		lockDownSecrets: func(...string) error { return errors.New("lock fail") },
	}); rc != 2 {
		t.Fatalf("expected rc=2 for agent lockdown fail, got %d", rc)
	}
	if rc := runMain(context.Background(), []string{"edgefetch", "--mode=agent"}, &out, &errBuf, mainDeps{
		getenv:          agentEnv,
		lockDownSecrets: func(...string) error { return nil },
		dropRoot:        func() error { return errors.New("drop fail") },
	}); rc != 2 {
		t.Fatalf("expected rc=2 for agent dropRoot fail, got %d", rc)
	}
	if rc := runMain(context.Background(), []string{"edgefetch", "--mode=agent"}, &out, &errBuf, mainDeps{
		getenv: func(k string) string {
			if k == "EDGEFETCH_BOT_SIGNING_KEY" {
				return "bad"
			}
			return agentEnv(k)
		},
		lockDownSecrets: func(...string) error { return nil },
		dropRoot:        func() error { return nil },
	}); rc != 2 {
		t.Fatalf("expected rc=2 for invalid bot key in agent mode, got %d", rc)
	}
	if rc := runMain(context.Background(), []string{"edgefetch", "--mode=agent"}, &out, &errBuf, mainDeps{
		getenv:          agentEnv,
		lockDownSecrets: func(...string) error { return nil },
		dropRoot:        func() error { return nil },
		runAgent: func(context.Context, agent.Config, *crawl.Crawler, func(*url.URL) error, http.RoundTripper, *slog.Logger, agent.RuntimeOpts) error {
			return errors.New("agent stopped")
		},
	}); rc != 1 {
		t.Fatalf("expected rc=1 for RunAll error, got %d", rc)
	}
	if rc := runMain(context.Background(), []string{"edgefetch", "--mode=agent"}, &out, &errBuf, mainDeps{
		getenv:          agentEnv,
		lockDownSecrets: func(...string) error { return nil },
		dropRoot:        func() error { return nil },
		runAgent: func(context.Context, agent.Config, *crawl.Crawler, func(*url.URL) error, http.RoundTripper, *slog.Logger, agent.RuntimeOpts) error {
			return nil
		},
	}); rc != 0 {
		t.Fatalf("expected rc=0 for RunAll success, got %d", rc)
	}

	// runMain: server/hub/hybrid error paths
	if rc := runMain(context.Background(), []string{"edgefetch", "--mode=server"}, &out, &errBuf, mainDeps{
		getenv: func(string) string { return "" }, // binds :8080 without token -> security error
	}); rc != 2 {
		t.Fatalf("expected rc=2 for server security fail, got %d", rc)
	}
	if rc := runMain(context.Background(), []string{"edgefetch", "--mode=server", "--addr=127.0.0.1:0"}, &out, &errBuf, mainDeps{
		getenv: func(k string) string {
			if k == "EDGEFETCH_USER_AGENT" {
				return "bad\nua"
			}
			return ""
		},
	}); rc != 2 {
		t.Fatalf("expected rc=2 for invalid UA, got %d", rc)
	}
	if rc := runMain(context.Background(), []string{"edgefetch", "--mode=hub,agent", "--addr=127.0.0.1:0"}, &out, &errBuf, mainDeps{
		getenv: func(string) string { return "" }, // missing hub url for hybrid agent
	}); rc != 2 {
		t.Fatalf("expected rc=2 for hybrid agent config fail, got %d", rc)
	}
	if rc := runMain(context.Background(), []string{"edgefetch", "--mode=server", "--addr=127.0.0.1:0"}, &out, &errBuf, mainDeps{
		getenv: func(k string) string {
			if k == "EDGEFETCH_BOT_SIGNING_KEY" {
				return "bad"
			}
			return ""
		},
	}); rc != 2 {
		t.Fatalf("expected rc=2 for invalid bot key in server mode, got %d", rc)
	}
	if rc := runMain(context.Background(), []string{"edgefetch", "--mode=hub", "--addr=127.0.0.1:0"}, &out, &errBuf, mainDeps{
		getenv: func(k string) string {
			if k == "EDGEFETCH_AGENT_TOKENS" {
				return "{bad"
			}
			return ""
		},
	}); rc != 2 {
		t.Fatalf("expected rc=2 for bad EDGEFETCH_AGENT_TOKENS, got %d", rc)
	}
	if rc := runMain(context.Background(), []string{"edgefetch", "--mode=hub", "--addr=127.0.0.1:0"}, &out, &errBuf, mainDeps{
		getenv: func(k string) string {
			if k == "EDGEFETCH_AGENT_TOKEN" {
				return "short"
			}
			return ""
		},
	}); rc != 2 {
		t.Fatalf("expected rc=2 for short EDGEFETCH_AGENT_TOKEN, got %d", rc)
	}
	if rc := runMain(context.Background(), []string{"edgefetch", "--mode=server", "--addr=127.0.0.1:99999"}, &out, &errBuf, mainDeps{
		getenv: func(string) string { return "" },
	}); rc != 1 {
		t.Fatalf("expected rc=1 for invalid listen port, got %d", rc)
	}
	if rc := runMain(context.Background(), []string{"edgefetch", "--mode=server", "--addr=127.0.0.1:0"}, &out, &errBuf, mainDeps{
		getenv:          func(string) string { return "" },
		lockDownSecrets: func(...string) error { return errors.New("lock fail") },
	}); rc != 2 {
		t.Fatalf("expected rc=2 for server lockdown fail, got %d", rc)
	}
	if rc := runMain(context.Background(), []string{"edgefetch", "--mode=server", "--addr=127.0.0.1:0"}, &out, &errBuf, mainDeps{
		getenv:          func(string) string { return "" },
		lockDownSecrets: func(...string) error { return nil },
		dropRoot:        func() error { return errors.New("drop fail") },
	}); rc != 2 {
		t.Fatalf("expected rc=2 for server dropRoot fail, got %d", rc)
	}

	// runMain: live hub+agent startup with haPath RobotsBypassHosts fallback, onListen probe & clean cancellation
	haHybrid := filepath.Join(t.TempDir(), "options.json")
	_ = os.WriteFile(haHybrid, []byte(`{"hub_url":"wss://hub.example.com/agent/ws","agent_token":"agent-secret-token-0123456789abc","site_id":"site-1","robots_bypass_hosts":["bypass.example.com"]}`), 0o600)
	hubCtx, hubCancel := context.WithCancel(context.Background())
	defer hubCancel()
	addrCh := make(chan string, 1)
	var hybridOut bytes.Buffer
	hybridDone := make(chan int, 1)
	go func() {
		hybridDone <- runMain(hubCtx, []string{"edgefetch", "--mode=hub,agent", "--addr=127.0.0.1:0"}, &hybridOut, &errBuf, mainDeps{
			getenv:          func(string) string { return "" },
			haPath:          haHybrid,
			lockDownSecrets: func(...string) error { return nil },
			dropRoot:        func() error { return nil },
			runAgent: func(context.Context, agent.Config, *crawl.Crawler, func(*url.URL) error, http.RoundTripper, *slog.Logger, agent.RuntimeOpts) error {
				return errors.New("hybrid stopped")
			},
			onListen: func(a net.Addr) { addrCh <- a.String() },
		})
	}()
	listenAddr := <-addrCh
	resp, gErr := http.Get("http://" + listenAddr + "/health")
	if gErr != nil || resp.StatusCode != http.StatusOK {
		hubCancel()
		t.Fatalf("GET /health on runMain hub failed: resp=%v err=%v", resp, gErr)
	}
	_ = resp.Body.Close()
	hubCancel()
	if rc := <-hybridDone; rc != 0 {
		t.Fatalf("expected runMain hub+agent clean exit 0, got %d", rc)
	}

	// runMain: live server startup + hybrid agentConfig RobotsBypassHosts branch
	srvCtx, srvCancel := context.WithCancel(context.Background())
	srvAddrCh := make(chan string, 1)
	srvDone := make(chan int, 1)
	var srvOut bytes.Buffer
	go func() {
		srvDone <- runMain(srvCtx, []string{"edgefetch", "--mode=server", "--addr=127.0.0.1:0"}, &srvOut, &errBuf, mainDeps{
			getenv:          func(string) string { return "" },
			lockDownSecrets: func(...string) error { return nil },
			dropRoot:        func() error { return nil },
			onListen:        func(a net.Addr) { srvAddrCh <- a.String() },
		})
	}()
	srvListen := <-srvAddrCh
	resp2, gErr2 := http.Get("http://" + srvListen + "/healthz")
	if gErr2 != nil || resp2.StatusCode != http.StatusOK {
		srvCancel()
		t.Fatalf("GET /healthz on runMain server failed: resp=%v err=%v", resp2, gErr2)
	}
	_ = resp2.Body.Close()
	srvCancel()
	if rc := <-srvDone; rc != 0 {
		t.Fatalf("expected runMain server clean exit 0, got %d", rc)
	}
}

func newCoverageMockOrigin(t *testing.T) (cliDeps, *http.Transport) {
	t.Helper()
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/robots.txt":
			w.WriteHeader(http.StatusNotFound)
		case "/llms.txt":
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte("# Index\n- [Guide](https://docs.example.com/guide)\n- [Insecure](http://docs.example.com/bad)\n"))
		case "/sitemap.xml":
			w.Header().Set("Content-Type", "application/xml")
			_, _ = w.Write([]byte(`<urlset><url><loc>https://docs.example.com/api</loc></url><url><loc>https://docs.example.com/api</loc></url></urlset>`))
		case "/utf8":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write([]byte(`<!doctype html><html><body><main><p>Héllo 世界 EdgeFetch</p></main></body></html>`))
		case "/waf":
			w.Header().Set("cf-ray", "12345-ORD")
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`<html><title>Just a moment...</title><body>Checking your browser before accessing... Cloudflare</body></html>`))
		case "/many":
			w.Header().Set("Content-Type", "text/html")
			var links strings.Builder
			for i := 0; i < 12; i++ {
				links.WriteString(`<a href="https://docs.example.com/p/` + string(rune('a'+i)) + `">p</a>`)
			}
			links.WriteString(`<a href="http://docs.example.com/http">h</a><a href="https://other.example.com/ext">e</a>`)
			_, _ = w.Write([]byte(`<html><body><main>` + links.String() + `</main></body></html>`))
		case "/empty":
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusOK)
		default:
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`<html><body><main><a href="https://docs.example.com/blog">Blog</a><a href="https://docs.example.com/blog#sec">Dup</a></main></body></html>`))
		}
	}))
	t.Cleanup(origin.Close)

	originAddr := origin.Listener.Addr().String()
	tlsCfg := origin.Client().Transport.(*http.Transport).TLSClientConfig
	mockTr := &http.Transport{
		TLSClientConfig: tlsCfg,
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, originAddr)
		},
	}
	deps := cliDeps{
		getenv:    func(string) string { return "" },
		transport: mockTr,
		allow: func(u *url.URL) error {
			if u.Scheme != "https" {
				return errors.New("https only")
			}
			return nil
		},
	}
	return deps, mockTr
}

func TestCLISubcommandsMapCrawlScrapeBugReportAndDoctorEdges(t *testing.T) {
	// Non-parallel because we use t.Setenv for Chrome-absent doctor & --render tests
	var out, errBuf bytes.Buffer

	// runOneShotCLI: custom haPath, empty args, unknown subcommand
	tmpDir := t.TempDir()
	haFile := filepath.Join(tmpDir, "options.json")
	_ = os.WriteFile(haFile, []byte(`{"hub_url":"https://hub.example.com","agent_token":"0123456789abcdef0123456789abcdef","site_id":"ha-site"}`), 0o600)

	if rc := runOneShotCLI(context.Background(), nil, &out, &errBuf, cliDeps{haPath: haFile}); rc != 0 || !strings.Contains(out.String(), "Usage:") {
		t.Fatalf("expected help on empty args, got rc=%d out=%q", rc, out.String())
	}
	if rc := runOneShotCLI(context.Background(), []string{"nonexistent"}, &out, &errBuf, cliDeps{}); rc != 2 {
		t.Fatalf("expected rc=2 for unknown subcommand, got %d", rc)
	}
	if rc := runOneShotCLI(context.Background(), []string{"mcp"}, &out, &errBuf, cliDeps{stdin: strings.NewReader("")}); rc != 0 {
		t.Fatalf("expected rc=0 for one-shot mcp, got %d", rc)
	}

	// runVersion plain text & runDoctor without Chrome in PATH + haPath
	out.Reset()
	if rc := runOneShotCLI(context.Background(), []string{"version"}, &out, &errBuf, cliDeps{}); rc != 0 || !strings.Contains(out.String(), "capabilities=") {
		t.Fatalf("unexpected plain version output: rc=%d out=%q", rc, out.String())
	}

	t.Setenv("PATH", tmpDir)
	t.Setenv("EDGEFETCH_CHROME_BIN", "")
	out.Reset()
	if rc := runOneShotCLI(context.Background(), []string{"doctor", "--json"}, &out, &errBuf, cliDeps{
		getenv: func(string) string { return "" },
		haPath: haFile,
	}); rc != 0 || !strings.Contains(out.String(), `"optional"`) || !strings.Contains(out.String(), `site=ha-site`) {
		t.Fatalf("unexpected Chrome-absent doctor output: rc=%d out=%s", rc, out.String())
	}

	// keygen-bot-auth plain & --json
	out.Reset()
	if rc := runOneShotCLI(context.Background(), []string{"keygen-bot-auth"}, &out, &errBuf, cliDeps{}); rc != 0 || !strings.Contains(out.String(), "EDGEFETCH_BOT_SIGNING_KEY=") {
		t.Fatalf("unexpected keygen-bot-auth plain: rc=%d out=%q", rc, out.String())
	}
	out.Reset()
	if rc := runOneShotCLI(context.Background(), []string{"keygen-bot-auth", "--json"}, &out, &errBuf, cliDeps{}); rc != 0 || !strings.Contains(out.String(), `"privateKeySeed"`) {
		t.Fatalf("unexpected keygen-bot-auth json: rc=%d out=%q", rc, out.String())
	}

	// Chrome-absent --render branches for scrape, crawl, and bug-report
	deps, mockTr := newCoverageMockOrigin(t)
	if rc := runOneShotCLI(context.Background(), []string{"scrape", "--render", "--timeout-ms=5000", "https://docs.example.com/"}, &out, &errBuf, cliDeps{
		getenv:    func(string) string { return "" },
		transport: mockTr,
		allow:     deps.allow,
	}); rc != 1 {
		_ = rc
	}
	_ = runOneShotCLI(context.Background(), []string{"crawl", "--render", "--limit=1", "--max-depth=0", "https://docs.example.com/"}, &out, &errBuf, deps)
	_ = runOneShotCLI(context.Background(), []string{"bug-report", "--render", "https://docs.example.com/"}, &out, &errBuf, deps)
}

func TestCLIScrapeMapAndBugReportEdges(t *testing.T) {
	t.Parallel()
	var out, errBuf bytes.Buffer
	deps, mockTr := newCoverageMockOrigin(t)

	// runScrapeCLI flag & error branches
	badScrapeCases := [][]string{
		{"scrape"},
		{"scrape", "--max-chars=-1", "https://docs.example.com/"},
		{"scrape", "--timeout-ms=0", "https://docs.example.com/"},
		{"scrape", "--bogus", "https://docs.example.com/"},
		{"scrape", "https://a.example", "https://b.example"},
		{"scrape", "http://127.0.0.1/"},
	}
	for _, args := range badScrapeCases {
		if rc := runOneShotCLI(context.Background(), args, &out, &errBuf, deps); rc != 2 {
			t.Fatalf("expected rc=2 for %v, got %d", args, rc)
		}
	}
	if rc := runOneShotCLI(context.Background(), []string{"scrape", "https://docs.example.com/"}, &out, &errBuf, cliDeps{
		getenv: func(k string) string {
			if k == "EDGEFETCH_USER_AGENT" {
				return "bad\nua"
			}
			return ""
		},
	}); rc != 2 {
		t.Fatalf("expected rc=2 for bad UA, got %d", rc)
	}

	out.Reset()
	if rc := runOneShotCLI(context.Background(), []string{"scrape", "--max-chars=2", "https://docs.example.com/utf8"}, &out, &errBuf, deps); rc != 0 || len(strings.TrimSpace(out.String())) > 2 {
		t.Fatalf("expected UTF-8 truncated scrape, rc=%d out=%q", rc, out.String())
	}
	out.Reset()
	if rc := runOneShotCLI(context.Background(), []string{"scrape", "--json", "https://docs.example.com/waf"}, &out, &errBuf, deps); rc != 1 {
		t.Fatalf("expected rc=1 for --json WAF non-OK, got %d", rc)
	}
	out.Reset()
	if rc := runOneShotCLI(context.Background(), []string{"scrape", "https://docs.example.com/empty"}, &out, &errBuf, deps); rc != 0 {
		t.Fatalf("expected rc=0 for empty-markdown scrape fallback, rc=%d out=%q err=%q", rc, out.String(), errBuf.String())
	}

	// runMapCLI full branches
	for _, badMap := range [][]string{
		{"map"},
		{"map", "--limit=0", "https://docs.example.com/"},
		{"map", "--bogus", "https://docs.example.com/"},
		{"map", "https://a.example", "https://b.example"},
		{"map", "http://127.0.0.1/"},
	} {
		if rc := runOneShotCLI(context.Background(), badMap, &out, &errBuf, deps); rc != 2 {
			t.Fatalf("expected rc=2 for %v, got %d", badMap, rc)
		}
	}
	out.Reset()
	if rc := runOneShotCLI(context.Background(), []string{"map", "--search=api", "--limit=2000", "https://docs.example.com/"}, &out, &errBuf, cliDeps{
		getenv: func(k string) string {
			if k == "EDGEFETCH_USER_AGENT" {
				return "bad\nua"
			}
			return ""
		},
		transport: mockTr,
		allow:     deps.allow,
	}); rc != 0 || !strings.Contains(out.String(), "https://docs.example.com/api") {
		t.Fatalf("unexpected plain map output: rc=%d out=%q", rc, out.String())
	}
	out.Reset()
	if rc := runOneShotCLI(context.Background(), []string{"map", "--json", "--limit=1", "https://docs.example.com/"}, &out, &errBuf, deps); rc != 0 || !strings.Contains(out.String(), `"total": 1`) {
		t.Fatalf("unexpected json map output: rc=%d out=%q", rc, out.String())
	}
	// Trigger ValidateCallWithCrawler failure in runMapCLI via path-sensitive allow
	pathDeps := deps
	pathDeps.allow = func(u *url.URL) error {
		if strings.HasSuffix(u.Path, "/llms.txt") {
			return errors.New("llms blocked")
		}
		return deps.allow(u)
	}
	if rc := runOneShotCLI(context.Background(), []string{"map", "https://docs.example.com/"}, &out, &errBuf, pathDeps); rc != 2 {
		t.Fatalf("expected rc=2 for path-blocked ValidateCallWithCrawler in map, got %d", rc)
	}

	// slugifyURLForFilename edges
	if got := slugifyURLForFilename("://bad", 1); got != "page-001.md" {
		t.Fatalf("slugifyURLForFilename invalid = %q", got)
	}
	if got := slugifyURLForFilename("https://example.com/", 2); got != "002-index.md" {
		t.Fatalf("slugifyURLForFilename root = %q", got)
	}
	if got := slugifyURLForFilename("https://example.com/"+strings.Repeat("a", 100), 3); len(got) != len("003-.md")+80 {
		t.Fatalf("slugifyURLForFilename >80 = %q (len=%d)", got, len(got))
	}
	if got := slugifyURLForFilename("https://example.com/---", 4); got != "004-page-004.md" {
		t.Fatalf("slugifyURLForFilename punct = %q", got)
	}

	// sanitizeURLForBugReport & runBugReportCLI edges
	if got := sanitizeURLForBugReport("://bad"); got != "<invalid-url>" {
		t.Fatalf("expected <invalid-url>, got %q", got)
	}
	if got := sanitizeURLForBugReport("/rel"); got != "<invalid-url>" {
		t.Fatalf("expected <invalid-url> for /rel, got %q", got)
	}
	if rc := runOneShotCLI(context.Background(), []string{"bug-report", "://bad"}, &out, &errBuf, deps); rc != 2 {
		t.Fatalf("expected rc=2 for bad bug-report URL, got %d", rc)
	}
	if rc := runOneShotCLI(context.Background(), []string{"bug-report", "http://127.0.0.1/"}, &out, &errBuf, deps); rc != 2 {
		t.Fatalf("expected rc=2 for SSRF-rejected bug-report URL, got %d", rc)
	}
	out.Reset()
	if rc := runOneShotCLI(context.Background(), []string{"bug-report", "--json"}, &out, &errBuf, deps); rc != 0 || !strings.Contains(out.String(), "edgefetch.bug_report.environment") {
		t.Fatalf("expected bug-report environment span, rc=%d out=%s", rc, out.String())
	}
	out.Reset()
	if rc := runOneShotCLI(context.Background(), []string{"bug-report", "--json", "https://docs.example.com/waf"}, &out, &errBuf, deps); rc != 0 || !strings.Contains(out.String(), `"wafVendor": "cloudflare"`) {
		t.Fatalf("expected bug-report cloudflare WAF vendor, rc=%d out=%s", rc, out.String())
	}

	// One-shot serve & desktop dispatch with short timeout ctx
	shortCtx, shortCancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer shortCancel()
	_ = runOneShotCLI(shortCtx, []string{"serve", "--port=0"}, io.Discard, io.Discard, deps)
	shortCtx2, shortCancel2 := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer shortCancel2()
	_ = runOneShotCLI(shortCtx2, []string{"desktop", "--port=0", "--no-open"}, io.Discard, io.Discard, deps)
}

func TestCLICrawlMaxLimitAndDepthEdges(t *testing.T) {
	t.Parallel()
	var out, errBuf bytes.Buffer
	deps, mockTr := newCoverageMockOrigin(t)

	for _, badCrawl := range [][]string{
		{"crawl"},
		{"crawl", "--limit=0", "https://docs.example.com/"},
		{"crawl", "--max-depth=-1", "https://docs.example.com/"},
		{"crawl", "--bogus", "https://docs.example.com/"},
		{"crawl", "https://a.example", "https://b.example"},
		{"crawl", "http://127.0.0.1/"},
	} {
		if rc := runOneShotCLI(context.Background(), badCrawl, &out, &errBuf, deps); rc != 2 {
			t.Fatalf("expected rc=2 for %v, got %d", badCrawl, rc)
		}
	}
	existingFile := filepath.Join(t.TempDir(), "not-a-dir")
	_ = os.WriteFile(existingFile, []byte("x"), 0o600)
	if rc := runOneShotCLI(context.Background(), []string{"crawl", "--out=" + existingFile, "https://docs.example.com/"}, &out, &errBuf, deps); rc != 1 {
		t.Fatalf("expected rc=1 for MkdirAll on existing file, got %d", rc)
	}
	out.Reset()
	if rc := runOneShotCLI(context.Background(), []string{"crawl", "--json", "--limit=200", "--max-depth=10", "https://docs.example.com/many"}, &out, &errBuf, cliDeps{
		getenv: func(k string) string {
			if k == "EDGEFETCH_USER_AGENT" {
				return "bad\nua"
			}
			return ""
		},
		transport: mockTr,
		allow:     deps.allow,
	}); rc != 0 || !strings.Contains(out.String(), `"fetched":`) {
		t.Fatalf("unexpected crawl --json /many output: rc=%d out=%q", rc, out.String())
	}

	var crawlAllowCount atomic.Int32
	crawlBreakDeps := deps
	crawlBreakDeps.allow = func(u *url.URL) error {
		if crawlAllowCount.Add(1) > 1 {
			return errors.New("blocked on validate")
		}
		return nil
	}
	_ = runOneShotCLI(context.Background(), []string{"crawl", "--limit=1", "https://docs.example.com/"}, &out, &errBuf, crawlBreakDeps)
}

func TestCLICrawlWaveSliceEdges(t *testing.T) {
	t.Parallel()
	var out, errBuf bytes.Buffer
	deps, _ := newCoverageMockOrigin(t)
	// len(wave) > rem (limit=11 on /many with 12 links)
	if rc := runOneShotCLI(context.Background(), []string{"crawl", "--limit=11", "--max-depth=1", "https://docs.example.com/many"}, &out, &errBuf, deps); rc != 0 {
		t.Fatalf("unexpected crawl --limit=11 output: rc=%d", rc)
	}
}

func TestMCPStdioProtocolAndBatchEdges(t *testing.T) {
	t.Parallel()
	// Mock origin with >4KiB body for fetch_batch truncation & /llms.txt + /sitemap.xml
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/robots.txt":
			w.WriteHeader(http.StatusNotFound)
		case "/llms.txt":
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte("- [A](https://docs.example.com/a)\n- [Bad](http://docs.example.com/bad)\n"))
		case "/sitemap.xml":
			w.Header().Set("Content-Type", "application/xml")
			_, _ = w.Write([]byte(`<urlset><url><loc>https://docs.example.com/b</loc></url><url><loc>https://docs.example.com/b</loc></url></urlset>`))
		case "/big":
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte(strings.Repeat("X", 4096)))
		default:
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`<main><p>Hello 世界!</p><a href="https://docs.example.com/c">c</a></main>`))
		}
	}))
	t.Cleanup(origin.Close)

	originAddr := origin.Listener.Addr().String()
	tlsCfg := origin.Client().Transport.(*http.Transport).TLSClientConfig
	mockTr := &http.Transport{
		TLSClientConfig: tlsCfg,
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, originAddr)
		},
	}

	// 1. runMCPStdio nil deps & invalid UA fallback & cancelled ctx
	var out, errBuf bytes.Buffer
	if rc := runMCPStdio(context.Background(), strings.NewReader(""), &out, &errBuf, cliDeps{
		getenv: func(k string) string {
			if k == "EDGEFETCH_USER_AGENT" {
				return "bad\nua"
			}
			return ""
		},
	}); rc != 0 {
		t.Fatalf("expected rc=0 for empty mcp input, got %d", rc)
	}
	cancelledCtx, cancelNow := context.WithCancel(context.Background())
	cancelNow()
	if rc := runMCPStdio(cancelledCtx, strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`+"\n"), &out, &errBuf, cliDeps{}); rc != 0 {
		t.Fatalf("expected rc=0 on cancelled ctx, got %d", rc)
	}

	// 2. Full JSON-RPC protocol & tool edge cases
	deps := cliDeps{
		getenv: func(k string) string {
			if k == "EDGEFETCH_HUB_URL" {
				return "http://insecure.example.com" // makes doctor return non-zero inside MCP!
			}
			return ""
		},
		transport: mockTr,
		allow: func(u *url.URL) error {
			if u.Scheme != "https" || strings.HasSuffix(u.Path, "/reject-validate") {
				return errors.New("disallowed")
			}
			return nil
		},
	}

	manyURLs := make([]string, 26)
	for i := range manyURLs {
		manyURLs[i] = `"https://docs.example.com/p"`
	}
	frames := strings.Join([]string{
		"",
		"{bad-json",
		`{"jsonrpc":"2.0","method":"ping"}`, // notification (nil id) -> no response
		`{"jsonrpc":"2.0","id":1,"method":"ping"}`,
		`{"jsonrpc":"2.0","id":2,"method":"initialize","params":{"protocolVersion":"2024-11-05"}}`,
		`{"jsonrpc":"2.0","id":3,"method":"unknown/method"}`,
		`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":123}`,
		`{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"doctor","arguments":{},"_meta":{"x-trace-id":"4bf92f3577b34da6a3ce929d0e0e4736","x-span-id":"00f067aa0ba902b7"}}}`,
		`{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"scrape","arguments":{"url":"https://docs.example.com/","maxChars":5}}}`,
		`{"jsonrpc":"2.0","id":16,"method":"tools/call","params":{"name":"scrape","arguments":{"url":"http://127.0.0.1/"}}}`,
		`{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"fetch_url","arguments":{"url":"http://127.0.0.1/"}}}`,
		`{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"fetch_batch","arguments":{"urls":[]}}}`,
		`{"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"fetch_batch","arguments":{"urls":[` + strings.Join(manyURLs, ",") + `]}}}`,
		`{"jsonrpc":"2.0","id":11,"method":"tools/call","params":{"name":"fetch_batch","arguments":{"urls":["http://127.0.0.1/"]}}}`,
		`{"jsonrpc":"2.0","id":12,"method":"tools/call","params":{"name":"fetch_batch","arguments":{"urls":["https://docs.example.com/big"],"includeBody":true}}}`,
		`{"jsonrpc":"2.0","id":13,"method":"tools/call","params":{"name":"map","arguments":{"url":"http://127.0.0.1/"}}}`,
		`{"jsonrpc":"2.0","id":14,"method":"tools/call","params":{"name":"map","arguments":{"url":"https://docs.example.com/reject-validate"}}}`,
		`{"jsonrpc":"2.0","id":15,"method":"tools/call","params":{"name":"map","arguments":{"url":"https://docs.example.com/","search":"b","limit":1}}}`,
	}, "\n") + "\n"

	out.Reset()
	if rc := runMCPStdio(context.Background(), strings.NewReader(frames), &out, &errBuf, deps); rc != 0 {
		t.Fatalf("runMCPStdio frames failed: %d", rc)
	}
	if !strings.Contains(out.String(), "-32700") || !strings.Contains(out.String(), "-32601") || !strings.Contains(out.String(), "-32602") || !strings.Contains(out.String(), `"protocolVersion":"2024-11-05"`) {
		t.Fatalf("missing expected JSON-RPC frames in output:\n%s", out.String())
	}
}

func TestMCPStdioInstallServeAndDesktopCoverage(t *testing.T) {
	// Non-parallel because we use t.Setenv for HOME / PATH / EDGEFETCH_CHROME_BIN
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)
	t.Setenv("PATH", tmpHome)
	t.Setenv("EDGEFETCH_CHROME_BIN", "")

	var out, errBuf bytes.Buffer
	deps, _ := newCoverageMockOrigin(t)

	// Exercise MCP scrape with render=true when Chrome is absent (renderMode falls back to "off")
	renderFrame := `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"scrape","arguments":{"url":"https://docs.example.com/","render":true}}}` + "\n"
	if rc := runMCPStdio(context.Background(), strings.NewReader(renderFrame), &out, &errBuf, deps); rc != 0 {
		t.Fatalf("runMCPStdio render=true Chrome-absent failed: %d", rc)
	}

	// Helper unit edges
	if got := truncateUTF8Safe("abc", 10); got != "abc" {
		t.Fatalf("truncateUTF8Safe short = %q", got)
	}
	if got := truncateUTF8Safe("abc", 0); got != "abc" {
		t.Fatalf("truncateUTF8Safe zero = %q", got)
	}
	if got := marshalJSONNoEscapeHTML(make(chan int), ""); got != "{}" {
		t.Fatalf("marshalJSONNoEscapeHTML unmarshalable = %q", got)
	}
	if wTargets := allMCPClientTargets("windows", tmpHome, filepath.Join(tmpHome, "AppData")); len(wTargets) != 6 {
		t.Fatalf("expected 6 windows targets, got %d", len(wTargets))
	}
	if dTargets := allMCPClientTargets("darwin", tmpHome, ""); len(dTargets) != 6 {
		t.Fatalf("expected 6 darwin targets, got %d", len(dTargets))
	}
	if got := upsertCodexTomlMCP("", "/usr/bin/edgefetch"); !strings.HasPrefix(got, "[mcp_servers.edgefetch]") {
		t.Fatalf("unexpected empty upsertCodexTomlMCP: %q", got)
	}
	replaced := upsertCodexTomlMCP("[mcp_servers.edgefetch]\ncommand = \"old\"\n[other]\nk = 1\n", "/usr/bin/edgefetch")
	if strings.Contains(replaced, `"old"`) || !strings.Contains(replaced, "[other]") {
		t.Fatalf("unexpected replaced upsertCodexTomlMCP: %q", replaced)
	}

	// runInstallMCP: default --exe, --agent=all, --agent=cursor, auto-detect, --dry-run, corrupt JSON, missing mcpServers, MkdirAll/WriteFile errors
	out.Reset()
	errBuf.Reset()
	if rc := runInstallMCP([]string{"--agent=all", "--dry-run"}, &out, &errBuf); rc != 0 || !strings.Contains(out.String(), "Codex") {
		t.Fatalf("runInstallMCP --agent=all --dry-run failed: rc=%d out=%q err=%q", rc, out.String(), errBuf.String())
	}
	if rc := runInstallMCP([]string{"--agent=cursor", "--dry-run"}, &out, &errBuf); rc != 0 {
		t.Fatalf("runInstallMCP --agent=cursor failed: %d", rc)
	}
	if rc := runInstallMCP([]string{"--dry-run"}, &out, &errBuf); rc != 0 {
		t.Fatalf("runInstallMCP auto-detect failed: %d", rc)
	}

	badJSONCfg := filepath.Join(tmpHome, "bad.json")
	_ = os.WriteFile(badJSONCfg, []byte("{corrupt"), 0o600)
	errBuf.Reset()
	if rc := runInstallMCP([]string{"--config=" + badJSONCfg, "--exe=/bin/ef"}, &out, &errBuf); rc != 0 || !strings.Contains(errBuf.String(), "invalid JSON") {
		t.Fatalf("expected corrupt JSON warning, rc=%d err=%q", rc, errBuf.String())
	}
	noServersCfg := filepath.Join(tmpHome, "noservers.json")
	_ = os.WriteFile(noServersCfg, []byte(`{"other":1}`), 0o600)
	if rc := runInstallMCP([]string{"--config=" + noServersCfg, "--exe=/bin/ef"}, &out, &errBuf); rc != 0 {
		t.Fatalf("expected install-mcp success on missing mcpServers, rc=%d", rc)
	}
	// MkdirAll error (parent is a file) & WriteFile error (target is a dir)
	parentFile := filepath.Join(tmpHome, "parent-file")
	_ = os.WriteFile(parentFile, []byte("x"), 0o600)
	errBuf.Reset()
	_ = runInstallMCP([]string{"--config=" + filepath.Join(parentFile, "cfg.json"), "--exe=/bin/ef"}, &out, &errBuf)
	if !strings.Contains(errBuf.String(), "mkdir") {
		t.Fatalf("expected mkdir error, got %q", errBuf.String())
	}
	targetDir := filepath.Join(tmpHome, "target-dir")
	_ = os.MkdirAll(targetDir, 0o755)
	errBuf.Reset()
	_ = runInstallMCP([]string{"--config=" + targetDir, "--exe=/bin/ef"}, &out, &errBuf)
	if !strings.Contains(errBuf.String(), "write") {
		t.Fatalf("expected write error, got %q", errBuf.String())
	}

	// runServeMode & runDesktopMode edges
	if rc := runServeModeWithDeps(context.Background(), []string{"--port=99999"}, io.Discard, io.Discard, cliDeps{}); rc != 1 {
		t.Fatalf("expected rc=1 for invalid serve port, got %d", rc)
	}
	if rc := runDesktopModeWithDeps(context.Background(), []string{"--port=99999"}, io.Discard, io.Discard, cliDeps{}); rc != 1 {
		t.Fatalf("expected rc=1 for invalid desktop port, got %d", rc)
	}
	serveCtx, serveCancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer serveCancel()
	_ = runServeMode(serveCtx, []string{"--port=0", "--allow-private"}, io.Discard, io.Discard)
	serveDefCtx, serveDefCancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer serveDefCancel()
	_ = runServeModeWithDeps(serveDefCtx, nil, io.Discard, io.Discard, cliDeps{getenv: func(string) string { return "" }})

	deskCtx, deskCancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer deskCancel()
	_ = runDesktopMode(deskCtx, []string{"--port=0"}, io.Discard, io.Discard) // exercises !noOpen -> openBrowserBestEffort with empty PATH
	deskDefCtx, deskDefCancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer deskDefCancel()
	_ = runDesktopModeWithDeps(deskDefCtx, []string{"--no-open"}, io.Discard, io.Discard, cliDeps{getenv: func(string) string { return "" }})

	// runInstallService defaults, actual write, MkdirAll error, WriteFile error
	if rc := runInstallService([]string{"--dry-run"}, &out, &errBuf); rc != 0 {
		t.Fatalf("expected runInstallService defaults dry-run rc=0, got %d", rc)
	}
	out.Reset()
	if rc := runInstallService([]string{"--os=linux", "--port=9191", "--exe=/bin/ef"}, &out, &errBuf); rc != 0 || !strings.Contains(out.String(), "[OK]") {
		t.Fatalf("expected runInstallService write rc=0, got rc=%d out=%q err=%q", rc, out.String(), errBuf.String())
	}
	// Force MkdirAll error by placing a file at $HOME/.config
	homeBad := t.TempDir()
	t.Setenv("HOME", homeBad)
	_ = os.WriteFile(filepath.Join(homeBad, ".config"), []byte("file"), 0o600)
	if rc := runInstallService([]string{"--os=linux", "--exe=/bin/ef"}, &out, &errBuf); rc != 1 {
		t.Fatalf("expected rc=1 for install-service MkdirAll error, got %d", rc)
	}
	// Force WriteFile error by placing a dir at destination service path
	homeBad2 := t.TempDir()
	t.Setenv("HOME", homeBad2)
	_ = os.MkdirAll(filepath.Join(homeBad2, ".config", "systemd", "user", "edgefetch-desktop.service"), 0o755)
	if rc := runInstallService([]string{"--os=linux", "--exe=/bin/ef"}, &out, &errBuf); rc != 1 {
		t.Fatalf("expected rc=1 for install-service WriteFile error, got %d", rc)
	}
}
