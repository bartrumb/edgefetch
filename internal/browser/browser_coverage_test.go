package browser

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
)

func TestBrowserHelperProcess(t *testing.T) {
	mode := os.Getenv("EDGEFETCH_CHROME_HELPER")
	if mode == "" {
		return
	}

	hasNoSandbox := false
	hasVersionFlag := false
	for _, a := range os.Args {
		if a == "--no-sandbox" {
			hasNoSandbox = true
		}
		if a == "--version" {
			hasVersionFlag = true
		}
	}

	if hasVersionFlag {
		fmt.Println("Chromium 137.0.7151.55")
		fmt.Println("Copyright 2025")
		os.Exit(0)
	}

	switch mode {
	case "fatal_sandbox":
		fmt.Fprintln(os.Stderr, "[0101/000000:FATAL:zygote_host_impl_linux.cc(127)] No usable sandbox!")
		os.Exit(1)
	case "silent_exit":
		os.Exit(0)
	case "hang":
		time.Sleep(3 * time.Second)
		os.Exit(0)
	case "oversized_frame":
		toParent := os.NewFile(4, "to-parent")
		chunk := make([]byte, 1024*1024)
		for i := range chunk {
			chunk[i] = 'a'
		}
		for i := 0; i < 25; i++ {
			if _, err := toParent.Write(chunk); err != nil {
				break
			}
		}
		time.Sleep(200 * time.Millisecond)
		os.Exit(0)
	case "fallback_ok":
		if !hasNoSandbox {
			fmt.Fprintln(os.Stderr, "[0101/000000:FATAL:zygote_host_impl_linux.cc(127)] No usable sandbox!")
			os.Exit(1)
		}
		fromParent := os.NewFile(3, "from-parent")
		toParent := os.NewFile(4, "to-parent")
		br := bufio.NewReader(fromParent)
		for {
			msg, err := br.ReadBytes(0)
			if len(msg) > 0 {
				raw := strings.TrimRight(string(msg), "\x00")
				var req struct {
					ID     int64  `json:"id"`
					Method string `json:"method"`
				}
				if json.Unmarshal([]byte(raw), &req) == nil && req.ID > 0 {
					var resp []byte
					if req.Method == "Browser.getVersion" {
						resp, _ = json.Marshal(map[string]any{
							"id":     req.ID,
							"result": map[string]any{"product": "HeadlessChrome/137.0.0.0"},
						})
					} else {
						resp, _ = json.Marshal(map[string]any{"id": req.ID, "result": map[string]any{}})
					}
					// Write in two chunks + NUL to cover split-frame reassembly in launchAndDialPipeLocked.
					half := len(resp) / 2
					_, _ = toParent.Write(resp[:half])
					time.Sleep(5 * time.Millisecond)
					_, _ = toParent.Write(append(resp[half:], 0))
				}
			}
			if err != nil {
				break
			}
		}
		os.Exit(0)
	default:
		os.Exit(2)
	}
}

func makeChromeHelperWrapper(t *testing.T, mode string) string {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	scriptPath := filepath.Join(t.TempDir(), "fake-chrome.sh")
	body := fmt.Sprintf("#!/bin/sh\nexport EDGEFETCH_CHROME_HELPER=%s\nexec %q -test.run='^TestBrowserHelperProcess$' -- \"$@\"\n", mode, exe)
	if err := os.WriteFile(scriptPath, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	return scriptPath
}

func TestCDPErrorPathsTimeoutsAndSubscribers(t *testing.T) {
	// 1. dialCDP error on closed port.
	if _, err := dialCDP(context.Background(), "ws://127.0.0.1:1"); err == nil {
		t.Fatal("expected dialCDP error on closed port")
	}

	// 2. readLoop malformed JSON, full subscriber channel (cap 64), RPC error, ctx timeout, write error, mid-flight drop, and post-close call.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer conn.CloseNow()

		for {
			_, raw, err := conn.Read(r.Context())
			if err != nil {
				return
			}
			var req struct {
				ID     int64  `json:"id"`
				Method string `json:"method"`
			}
			if json.Unmarshal(raw, &req) != nil {
				continue
			}
			switch req.Method {
			case "Test.malformedAndEvents":
				_ = conn.Write(r.Context(), websocket.MessageText, []byte("not-valid-json"))
				for i := 0; i < 70; i++ {
					ev, _ := json.Marshal(map[string]any{"method": "Test.ev", "params": map[string]int{"i": i}})
					_ = conn.Write(r.Context(), websocket.MessageText, ev)
				}
				resp, _ := json.Marshal(map[string]any{"id": req.ID, "result": map[string]any{"ok": true}})
				_ = conn.Write(r.Context(), websocket.MessageText, resp)
			case "Test.rpcError":
				resp, _ := json.Marshal(map[string]any{
					"id":    req.ID,
					"error": map[string]any{"code": -32000, "message": "target crashed"},
				})
				_ = conn.Write(r.Context(), websocket.MessageText, resp)
			case "Test.holdTimeout":
				time.Sleep(100 * time.Millisecond)
			case "Test.dropNow":
				_ = conn.CloseNow()
				return
			}
		}
	}))
	defer srv.Close()

	wsURL := "ws://" + strings.TrimPrefix(srv.URL, "http://")
	c, err := dialCDP(context.Background(), wsURL)
	if err != nil {
		t.Fatalf("dialCDP: %v", err)
	}
	if c.isClosed() {
		t.Fatal("expected isClosed() == false before close")
	}

	// Unbuffered/undrained subscriber to hit cap=64 drop default branch.
	ch, unsub := c.subscribe()
	var out struct {
		OK bool `json:"ok"`
	}
	if err := c.call(context.Background(), "", "Test.malformedAndEvents", nil, &out); err != nil || !out.OK {
		t.Fatalf("expected Test.malformedAndEvents to succeed after malformed JSON + 70 events, got out=%+v err=%v", out, err)
	}
	if len(ch) != 64 {
		t.Fatalf("expected subscriber buffer capped at 64, got %d", len(ch))
	}
	unsub()

	// RPC error branch.
	if err := c.call(context.Background(), "", "Test.rpcError", nil, nil); err == nil || !strings.Contains(err.Error(), "-32000") {
		t.Fatalf("expected cdp error -32000, got %v", err)
	}

	// json.Marshal error branch.
	if err := c.call(context.Background(), "", "Test.badMarshal", make(chan int), nil); err == nil {
		t.Fatal("expected json.Marshal error")
	}

	// ctx.Done() timeout branch.
	shortCtx, cancelShort := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancelShort()
	if err := c.call(shortCtx, "", "Test.holdTimeout", nil, nil); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected DeadlineExceeded, got %v", err)
	}

	// writeOverride error branch.
	c.writeOverride = func(string) error { return errors.New("write pipe broken") }
	if err := c.call(context.Background(), "", "Test.writeErr", nil, nil); err == nil || !strings.Contains(err.Error(), "write pipe broken") {
		t.Fatalf("expected writeOverride error, got %v", err)
	}
	c.writeOverride = nil

	// Mid-flight WS drop with crashReason set -> readLoop closes pending channel -> crashError("while awaiting ...").
	c.setCrashReason("FATAL: renderer OOM")
	if err := c.call(context.Background(), "", "Test.dropNow", nil, nil); err == nil || !strings.Contains(err.Error(), "while awaiting Test.dropNow") || !strings.Contains(err.Error(), "renderer OOM") {
		t.Fatalf("expected crashError with suffix and reason, got %v", err)
	}
	<-c.closeCh
	if !c.isClosed() {
		t.Fatal("expected isClosed() == true after drop")
	}
	if err := c.call(context.Background(), "", "Test.afterClose", nil, nil); err == nil || !strings.Contains(err.Error(), "renderer OOM") {
		t.Fatalf("expected crashError after close, got %v", err)
	}

	// Also verify crashError("") when crashMsg == "".
	c2, err := dialCDP(context.Background(), wsURL)
	if err != nil {
		t.Fatal(err)
	}
	_ = c2.close()
	<-c2.closeCh
	if err := c2.call(context.Background(), "", "Test.closedClean", nil, nil); err == nil || err.Error() != "cdp connection closed" {
		t.Fatalf("expected bare 'cdp connection closed', got %v", err)
	}
}

func TestProcUnixGuardsAndProxyEdgeCases(t *testing.T) {
	// proc_unix.go nil/empty guards.
	configureBrowserProcGroup(nil)
	killBrowserProcessGroup(nil)
	killBrowserProcessGroup(&exec.Cmd{})

	// proxy.go listen error via proxyListen seam.
	origListen := proxyListen
	t.Cleanup(func() { proxyListen = origListen })
	proxyListen = func(string, string) (net.Listener, error) {
		return nil, errors.New("bind failed")
	}
	if _, err := NewSSRFProxy(nil, nil); err == nil || !strings.Contains(err.Error(), "listen ssrf proxy") {
		t.Fatalf("expected NewSSRFProxy listen error, got %v", err)
	}
	proxyListen = origListen

	// serveHTTP edge cases using direct call + net.Pipe().
	var closedUpstream atomic.Int32
	upClosedCh := make(chan struct{}, 8)
	p := &SSRFProxy{
		dial: func(context.Context, string, string) (net.Conn, error) {
			c1, c2 := net.Pipe()
			go func() {
				buf := make([]byte, 32)
				_, _ = c2.Read(buf)
				_ = c2.Close()
				closedUpstream.Add(1)
				upClosedCh <- struct{}{}
			}()
			return c1, nil
		},
	}
	waitUpstreamClosed := func(label string, wantCount int32) {
		t.Helper()
		select {
		case <-upClosedCh:
		case <-time.After(time.Second):
			t.Fatalf("%s: timed out waiting for upstream close", label)
		}
		if got := closedUpstream.Load(); got != wantCount {
			t.Fatalf("%s: expected closedUpstream=%d, got %d", label, wantCount, got)
		}
	}

	// 1. ResponseWriter not implementing http.Hijacker -> 500 + closes upstream.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodConnect, "https://example.com:443", nil)
	req.Host = "example.com:443"
	p.serveHTTP(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 when Hijacker unsupported, got %d", rec.Code)
	}
	waitUpstreamClosed("non-hijacker", 1)

	// 2. Hijack() returns error -> closes upstream.
	rec2 := httptest.NewRecorder()
	p.serveHTTP(&hijackFailRW{ResponseRecorder: rec2}, req)
	waitUpstreamClosed("hijackFailRW", 2)

	// 3. clientConn WriteString error (pre-closed net.Pipe clientConn) -> closes upstream.
	clientBadA, clientBadB := net.Pipe()
	_ = clientBadA.Close()
	_ = clientBadB.Close()
	rec3 := httptest.NewRecorder()
	p.serveHTTP(&customHijackRW{
		ResponseRecorder: rec3,
		conn:             clientBadA,
		rw:               bufio.NewReadWriter(bufio.NewReader(strings.NewReader("")), bufio.NewWriter(io.Discard)),
	}, req)
	waitUpstreamClosed("customHijackRW write error", 3)

	// 4. Buffered clientBuf (> 0 bytes) + net.Pipe() lacking CloseWrite() -> exercises clientBuf flush & pump dst.Close().
	upA, upB := net.Pipe()
	var receivedFromEarly []byte
	upDone := make(chan struct{})
	go func() {
		defer close(upDone)
		defer upB.Close()
		receivedFromEarly, _ = io.ReadAll(upB)
	}()
	pBuf := &SSRFProxy{
		dial: func(context.Context, string, string) (net.Conn, error) {
			return upA, nil
		},
	}
	cliA, cliB := net.Pipe()
	br := bufio.NewReader(strings.NewReader("EARLY"))
	_, _ = br.Peek(1) // loads "EARLY" into br's internal buffer so br.Buffered() == 5
	go func() {
		// Drain the 200 Connection Established line from cliB then close cliB so pump finishes.
		buf := make([]byte, 256)
		_, _ = cliB.Read(buf)
		_ = cliB.Close()
	}()
	pBuf.serveHTTP(&customHijackRW{
		ResponseRecorder: httptest.NewRecorder(),
		conn:             cliA,
		rw:               bufio.NewReadWriter(br, bufio.NewWriter(io.Discard)),
	}, req)
	<-upDone
	if string(receivedFromEarly) != "EARLY" {
		t.Fatalf("expected buffered bytes 'EARLY' forwarded to upstream, got %q", string(receivedFromEarly))
	}
}

type hijackFailRW struct {
	*httptest.ResponseRecorder
}

func (h *hijackFailRW) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return nil, nil, errors.New("hijack failed")
}

type customHijackRW struct {
	*httptest.ResponseRecorder
	conn net.Conn
	rw   *bufio.ReadWriter
}

func (c *customHijackRW) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return c.conn, c.rw, nil
}

func TestRendererHelpersHeadersEnvSnapAndHostPolicy(t *testing.T) {
	// canonicalURLOrigin edge cases.
	for _, bad := range []string{"://bad\x7f", "ftp://example.com/a", "javascript:alert(1)", "https:///path", "https://example.com:99999"} {
		if got := canonicalURLOrigin(bad); got != "" {
			t.Fatalf("expected empty canonicalURLOrigin(%q), got %q", bad, got)
		}
	}

	// nil session guards.
	var nilSess *retainedSession
	nilSess.stopFetch()
	if nilSess.getLastCheckedURL() != "" {
		t.Fatal("expected empty getLastCheckedURL on nil session")
	}
	nilSess.setLastCheckedURL("https://example.com")
	sTmp := &retainedSession{}
	sTmp.setLastCheckedURL("")

	// mergeCDPRequestHeaders edge cases.
	merged := mergeCDPRequestHeaders(map[string]any{
		"X-Auth": "old",
		"Nil":    nil,
		"Num":    42,
	}, map[string]string{
		"   ":    "ignored",
		"x-auth": "new",
	})
	if len(merged) != 2 || merged[0].Name != "Num" || merged[0].Value != "42" || merged[1].Name != "x-auth" || merged[1].Value != "new" {
		t.Fatalf("unexpected mergeCDPRequestHeaders output: %+v", merged)
	}

	// hasPositiveSameOriginProof table (Round 9 H8: missing Origin+Referer MUST fail; Sec-Fetch-Site is ignored).
	const initOrigin = "https://victim.test:443"
	if hasPositiveSameOriginProof(nil, initOrigin) || hasPositiveSameOriginProof(map[string]any{"Accept": "*/*"}, initOrigin) {
		t.Fatal("missing Origin and Referer must fail closed")
	}
	if hasPositiveSameOriginProof(map[string]any{"Origin": "https://victim.test"}, "") {
		t.Fatal("empty initOrigin must fail closed")
	}
	if !hasPositiveSameOriginProof(map[string]any{"Nil": nil, "Origin": "https://victim.test", "Referer": "https://victim.test/p"}, initOrigin) {
		t.Fatal("proven same-origin Origin + Referer should allow")
	}
	if !hasPositiveSameOriginProof(map[string]any{"Referer": "https://victim.test/p", "Origin": ""}, initOrigin) {
		t.Fatal("proven same-origin Referer with empty Origin should allow")
	}
	if hasPositiveSameOriginProof(map[string]any{"Origin": "null", "Referer": "https://victim.test/p"}, initOrigin) {
		t.Fatal("Origin: null must fail even when Referer names initOrigin")
	}
	if hasPositiveSameOriginProof(map[string]any{"Origin": "https://evil.test", "Referer": "https://victim.test/p"}, initOrigin) {
		t.Fatal("cross-origin Origin must fail even when Referer names initOrigin")
	}
	if hasPositiveSameOriginProof(map[string]any{"Referer": "https://evil.test/x", "Origin": "https://victim.test"}, initOrigin) {
		t.Fatal("cross-origin Referer must fail even when Origin names initOrigin")
	}

	// handleRequestPaused invalid JSON / empty RequestID.
	sTmp.handleRequestPaused(nil, json.RawMessage("{bad"))
	sTmp.handleRequestPaused(nil, json.RawMessage(`{"requestId":""}`))

	// NewRenderer maxConcurrent clamping + nil receiver guards.
	rMin := NewRenderer("/fake/bin", nil, "", 0, nil)
	if cap(rMin.sem) != 2 {
		t.Fatalf("expected default sem cap 2, got %d", cap(rMin.sem))
	}
	rMax := NewRenderer("/fake/bin", nil, "", 99, nil)
	if cap(rMax.sem) != 4 {
		t.Fatalf("expected clamped sem cap 4, got %d", cap(rMax.sem))
	}
	var nilR *Renderer
	if nilR.Available() || nilR.otelExporter() != nil || nilR.Close() != nil {
		t.Fatal("nil Renderer methods mismatch")
	}
	nilR.SetOtelExporter(nil)
	v, sb := nilR.BrowserInfo()
	if v != "" || sb != "" {
		t.Fatal("nil Renderer BrowserInfo mismatch")
	}

	// buildSanitizedChildEnv with duplicate case-variant key & empty PATH fallback.
	t.Run("sanitized_env_empty_path", func(t *testing.T) {
		t.Setenv("SYSTEMROOT", "C:\\Windows")
		t.Setenv("SystemRoot", "C:\\Windows")
		t.Setenv("PATH", "")
		env := buildSanitizedChildEnv("")
		joinedEnv := strings.Join(env, "\n")
		if !strings.Contains(joinedEnv, "PATH=/usr/local/sbin:") || !strings.Contains(joinedEnv, "HOME="+os.TempDir()) {
			t.Fatalf("unexpected buildSanitizedChildEnv: %v", env)
		}
	})

	// isSandboxStartupFailureText :FATAL: with & without matching EPERM/EACCES and marker.
	if !isSandboxStartupFailureText("ERROR:FATAL:credentials.cc(10) Operation not permitted") {
		t.Fatal("expected :FATAL: credentials.cc with Operation not permitted to match")
	}
	if isSandboxStartupFailureText("ERROR:FATAL:credentials.cc(10) failed") {
		t.Fatal("expected :FATAL: credentials.cc without EPERM/EACCES not to match")
	}
	if isSandboxStartupFailureText("ERROR:FATAL:oom.cc(10) Operation not permitted") {
		t.Fatal("expected :FATAL: oom.cc not to match sandbox failure")
	}

	// R7: canFallbackToNoSandboxLocked policy matrix (default fail-closed; opt-in EDGEFETCH_ALLOW_NO_SANDBOX=1; hard override EDGEFETCH_REQUIRE_BROWSER_SANDBOX=1).
	t.Run("r7_sandbox_fallback_policy", func(t *testing.T) {
		t.Setenv("EDGEFETCH_ALLOW_NO_SANDBOX", "")
		t.Setenv("EDGEFETCH_REQUIRE_BROWSER_SANDBOX", "")
		rDef := NewRenderer("/fake/chrome", nil, "UA", 1, nil)
		if rDef.canFallbackToNoSandboxLocked() {
			t.Fatal("SECURITY: default Renderer must NOT allow --no-sandbox fallback without EDGEFETCH_ALLOW_NO_SANDBOX=1")
		}

		t.Setenv("EDGEFETCH_ALLOW_NO_SANDBOX", "1")
		rOptIn := NewRenderer("/fake/chrome", nil, "UA", 1, nil)
		if !rOptIn.canFallbackToNoSandboxLocked() {
			t.Fatal("expected EDGEFETCH_ALLOW_NO_SANDBOX=1 to allow --no-sandbox fallback when requireSandbox is unset")
		}

		t.Setenv("EDGEFETCH_REQUIRE_BROWSER_SANDBOX", "1")
		rOverride := NewRenderer("/fake/chrome", nil, "UA", 1, nil)
		if rOverride.canFallbackToNoSandboxLocked() {
			t.Fatal("SECURITY: EDGEFETCH_REQUIRE_BROWSER_SANDBOX=1 must override EDGEFETCH_ALLOW_NO_SANDBOX=1")
		}
	})

	// R7: buildChromiumLaunchArgs LAN Cast / MediaRouter / mDNS (:8009) suppression flags & seccomp profile integrity.
	t.Run("r7_cast_suppression_flags_and_seccomp_profile", func(t *testing.T) {
		args := buildChromiumLaunchArgs("/tmp/ud", "http://127.0.0.1:9999")
		joined := strings.Join(args, "\n")
		for _, mustFlag := range []string{
			"--media-router=0",
			"--disable-component-extensions-with-background-pages",
			"--disable-domain-reliability",
			"--disable-client-side-phishing-detection",
			"MediaRouter",
			"DialMediaRouteProvider",
			"CastMediaRouteProvider",
		} {
			if !strings.Contains(joined, mustFlag) {
				t.Fatalf("missing Chromium network-hardening flag %q in %v", mustFlag, args)
			}
		}

		seccompBytes, err := os.ReadFile(filepath.Join("..", "..", "deploy", "seccomp", "chromium-sandbox.json"))
		if err != nil {
			t.Fatalf("read deploy/seccomp/chromium-sandbox.json: %v", err)
		}
		var profile struct {
			DefaultAction string `json:"defaultAction"`
			Syscalls      []struct {
				Names  []string `json:"names"`
				Action string   `json:"action"`
			} `json:"syscalls"`
		}
		if err := json.Unmarshal(seccompBytes, &profile); err != nil {
			t.Fatalf("invalid seccomp JSON: %v", err)
		}
		if profile.DefaultAction != "SCMP_ACT_ERRNO" {
			t.Fatalf("expected defaultAction SCMP_ACT_ERRNO, got %q", profile.DefaultAction)
		}
		allowed := make(map[string]bool)
		for _, rule := range profile.Syscalls {
			if rule.Action == "SCMP_ACT_ALLOW" {
				for _, n := range rule.Names {
					allowed[n] = true
				}
			}
		}
		for _, need := range []string{"clone", "unshare", "chroot", "seccomp", "prctl"} {
			if !allowed[need] {
				t.Fatalf("seccomp profile missing required Chromium sandbox syscall %q", need)
			}
		}
		for _, forbidden := range []string{"kexec_load", "init_module", "finit_module", "bpf", "perf_event_open", "userfaultfd", "keyctl", "mount", "umount2", "pivot_root", "ptrace", "setns", "clone3", "socketcall", "acct", "swapon", "swapoff"} {
			if allowed[forbidden] {
				t.Fatalf("SECURITY: seccomp profile must NOT allow dangerous syscall %q", forbidden)
			}
		}
	})

	if runtime.GOOS != "linux" {
		return
	}

	// isLinuxSnapWrapper cases.
	if !isLinuxSnapWrapper("/snap/bin/chromium") {
		t.Fatal("expected /snap/ path true")
	}
	snapDir := t.TempDir()
	snapTarget := filepath.Join(snapDir, "snap", "bin", "chr")
	if err := os.MkdirAll(filepath.Dir(snapTarget), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(snapTarget, []byte("#!/bin/sh\necho ok\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	symPath := filepath.Join(snapDir, "chr-link")
	if err := os.Symlink(snapTarget, symPath); err != nil {
		t.Fatal(err)
	}
	if !isLinuxSnapWrapper(symPath) {
		t.Fatal("expected symlink into /snap/ true")
	}
	if isLinuxSnapWrapper(filepath.Join(snapDir, "does-not-exist")) {
		t.Fatal("expected missing path false")
	}
	unreadable := filepath.Join(snapDir, "unreadable")
	if err := os.WriteFile(unreadable, []byte("#!/bin/sh\n"), 0o000); err != nil {
		t.Fatal(err)
	}
	if isLinuxSnapWrapper(unreadable) {
		t.Fatal("expected unreadable file to return false")
	}

	// startupReason >300 truncation.
	if got := startupReason("", strings.Repeat("x", 350)); len(got) != 300 {
		t.Fatalf("expected startupReason capped at 300, got %d", len(got))
	}

	// isLinuxProcessZombieOrDead & linuxSandboxBlockedByHostPolicy via readProcFile seam.
	if isLinuxProcessZombieOrDead(0) {
		t.Fatal("pid <= 0 should return false")
	}
	if !isLinuxProcessZombieOrDead(99999999) {
		t.Fatal("nonexistent pid should return true")
	}
	origReadProc := readProcFile
	t.Cleanup(func() { readProcFile = origReadProc })

	readProcFile = func(path string) ([]byte, error) {
		return []byte("malformed"), nil
	}
	if isLinuxProcessZombieOrDead(123) {
		t.Fatal("malformed stat should return false")
	}
	readProcFile = func(path string) ([]byte, error) {
		return []byte("123 (chrome) Z 1 1 1 0 -1 0 0 0 0 0 0 0 0 20 0 1 0 10 0 0 0"), nil
	}
	if !isLinuxProcessZombieOrDead(123) {
		t.Fatal("zombie Z stat should return true")
	}
	for _, prof := range []string{"c3b8e9a1_edgefetch (enforce)", "edgefetch (enforce)", "edgefetch_fat (enforce)"} {
		readProcFile = func(path string) ([]byte, error) {
			if strings.HasSuffix(path, "attr/current") {
				return []byte(prof), nil
			}
			return nil, os.ErrNotExist
		}
		if !linuxSandboxBlockedByHostPolicy() {
			t.Fatalf("expected %q attr to trigger host policy block", prof)
		}
	}
	readProcFile = func(path string) ([]byte, error) {
		if strings.HasSuffix(path, "unprivileged_userns_clone") {
			return []byte("0\n"), nil
		}
		return nil, os.ErrNotExist
	}
	if !linuxSandboxBlockedByHostPolicy() {
		t.Fatal("expected unprivileged_userns_clone=0 to trigger host policy block")
	}
	readProcFile = origReadProc

	// FindChromeBinary: EDGEFETCH_CHROME_BIN via LookPath & os.Stat, snap fallback vs non-snap, empty PATH.
	binDir1 := filepath.Join(t.TempDir(), "b1")
	binDir2 := filepath.Join(t.TempDir(), "b2")
	emptyDir := filepath.Join(t.TempDir(), "empty")
	_ = os.MkdirAll(binDir1, 0o755)
	_ = os.MkdirAll(binDir2, 0o755)
	_ = os.MkdirAll(emptyDir, 0o755)

	snapScript := filepath.Join(binDir1, "chromium-browser")
	_ = os.WriteFile(snapScript, []byte("#!/bin/sh\nsnap run chromium\n"), 0o755)
	realScript := filepath.Join(binDir2, "google-chrome")
	_ = os.WriteFile(realScript, []byte("#!/bin/sh\necho ok\n"), 0o755)

	t.Setenv("EDGEFETCH_CHROME_BIN", "sh")
	if got := FindChromeBinary(); got == "" {
		t.Fatal("expected FindChromeBinary to resolve EDGEFETCH_CHROME_BIN=sh via LookPath")
	}
	nonExec := filepath.Join(t.TempDir(), "non-exec-chrome")
	_ = os.WriteFile(nonExec, []byte("binary"), 0o644)
	t.Setenv("EDGEFETCH_CHROME_BIN", nonExec)
	if got := FindChromeBinary(); got != nonExec {
		t.Fatalf("expected os.Stat fallback %q for non-exec EDGEFETCH_CHROME_BIN, got %q", nonExec, got)
	}
	// Invalid/dir EDGEFETCH_CHROME_BIN falls through to PATH.
	t.Setenv("EDGEFETCH_CHROME_BIN", binDir1)
	t.Setenv("PATH", binDir1)
	if got := FindChromeBinary(); got != snapScript {
		t.Fatalf("expected snap fallback %q when only snap on PATH, got %q", snapScript, got)
	}
	t.Setenv("PATH", binDir1+string(os.PathListSeparator)+binDir2)
	if got := FindChromeBinary(); got != realScript {
		t.Fatalf("expected non-snap %q preferred over snap, got %q", realScript, got)
	}
	t.Setenv("PATH", emptyDir)
	if got := FindChromeBinary(); got != "" {
		t.Fatalf("expected empty FindChromeBinary on empty PATH, got %q", got)
	}
}

func TestRendererActionsSessionsValidationAndErrorsOverMockCDP(t *testing.T) {
	// Mock CDP server programmable for all action types, errors, session lifecycle, and Fetch.requestPaused initiator check.
	var (
		mu                  sync.Mutex
		failCreateBC        bool
		failCreateTarget    bool
		failAttach          bool
		failFetchEnable     bool
		failNavigate        bool
		holdNavigate        bool
		holdRequestInFlight bool
		emitCrossSitePause  bool
		failCaptureShot     bool
		failPrintPDF        bool
		failEval            bool
		evalException       bool
		evalNonString       bool
		evalNonJSONDoc      bool
		evalOversizedDoc    bool
		docURLOverride      string
		actionScrapeURL     string
		postActionChallenge bool
		waitSelPolls        atomic.Int32
		disposedCount       atomic.Int32
		pausedHeadersSaw    atomic.Bool
		pausedOverridden    atomic.Bool
	)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer conn.CloseNow()
		var writeMu sync.Mutex
		send := func(v any) {
			b, _ := json.Marshal(v)
			writeMu.Lock()
			_ = conn.Write(r.Context(), websocket.MessageText, b)
			writeMu.Unlock()
		}

		for {
			_, raw, err := conn.Read(r.Context())
			if err != nil {
				return
			}
			var req struct {
				ID        int64           `json:"id"`
				SessionID string          `json:"sessionId"`
				Method    string          `json:"method"`
				Params    json.RawMessage `json:"params"`
			}
			if json.Unmarshal(raw, &req) != nil {
				continue
			}

			mu.Lock()
			cBC := failCreateBC
			cTgt := failCreateTarget
			cAtt := failAttach
			cFE := failFetchEnable
			cNav := failNavigate
			hNav := holdNavigate
			hReq := holdRequestInFlight
			eCross := emitCrossSitePause
			cShot := failCaptureShot
			cPDF := failPrintPDF
			cEval := failEval
			eEx := evalException
			eNonStr := evalNonString
			eNonJSON := evalNonJSONDoc
			eOver := evalOversizedDoc
			dURL := docURLOverride
			sURL := actionScrapeURL
			pChal := postActionChallenge
			mu.Unlock()

			switch req.Method {
			case "Target.createBrowserContext":
				if cBC {
					send(map[string]any{"id": req.ID, "error": map[string]any{"code": -1, "message": "bc err"}})
					continue
				}
				send(map[string]any{"id": req.ID, "result": map[string]any{"browserContextId": "bc-cov"}})
			case "Target.createTarget":
				if cTgt {
					send(map[string]any{"id": req.ID, "error": map[string]any{"code": -1, "message": "tgt err"}})
					continue
				}
				send(map[string]any{"id": req.ID, "result": map[string]any{"targetId": "tgt-cov"}})
			case "Target.attachToTarget":
				if cAtt {
					send(map[string]any{"id": req.ID, "error": map[string]any{"code": -1, "message": "att err"}})
					continue
				}
				send(map[string]any{"id": req.ID, "result": map[string]any{"sessionId": "s-cov"}})
			case "Target.disposeBrowserContext":
				disposedCount.Add(1)
				send(map[string]any{"id": req.ID, "result": map[string]any{}})
			case "Fetch.enable":
				if cFE {
					send(map[string]any{"id": req.ID, "sessionId": req.SessionID, "error": map[string]any{"code": -1, "message": "fetch err"}})
					continue
				}
				send(map[string]any{"id": req.ID, "sessionId": req.SessionID, "result": map[string]any{}})
			case "Fetch.continueRequest":
				var p struct {
					RequestID string `json:"requestId"`
				}
				var rawMap map[string]json.RawMessage
				_ = json.Unmarshal(req.Params, &p)
				_ = json.Unmarshal(req.Params, &rawMap)
				if p.RequestID == "initiator-cross-site" {
					_, hasHdrs := rawMap["headers"]
					pausedOverridden.Store(hasHdrs)
					pausedHeadersSaw.Store(true)
				}
				send(map[string]any{"id": req.ID, "sessionId": req.SessionID, "result": map[string]any{}})
			case "Page.navigate":
				if cNav {
					send(map[string]any{"id": req.ID, "sessionId": req.SessionID, "error": map[string]any{"code": -1, "message": "nav rpc err"}})
					continue
				}
				if hNav {
					// Mismatched sessionId event first, never send loadEventFired for req.SessionID so navLoadTimeout fires.
					send(map[string]any{"id": req.ID, "sessionId": req.SessionID, "result": map[string]any{"frameId": "f1"}})
					send(map[string]any{"sessionId": "other-session", "method": "Page.loadEventFired", "params": map[string]any{}})
					continue
				}
				send(map[string]any{"id": req.ID, "sessionId": req.SessionID, "result": map[string]any{"frameId": "f1"}})
				if hReq {
					// Emit an uncompleted Document/XHR request so inFlight > 0 triggers staleInFlightTTL / idleDeadline!
					send(map[string]any{
						"sessionId": req.SessionID,
						"method":    "Network.requestWillBeSent",
						"params":    map[string]any{"requestId": "stuck-req", "type": "XHR"},
					})
				}
				if eCross {
					// Subresource to same origin with redirectedCrossOrigin==false so isSameOriginInitiatorHeaders runs!
					send(map[string]any{
						"sessionId": req.SessionID,
						"method":    "Fetch.requestPaused",
						"params": map[string]any{
							"requestId":    "initiator-cross-site",
							"frameId":      "f1",
							"resourceType": "Fetch",
							"request": map[string]any{
								"url": "https://app.example.com/api/secret",
								"headers": map[string]string{
									"Origin":         "https://attacker.test",
									"Sec-Fetch-Site": "cross-site",
								},
							},
						},
					})
				}
				send(map[string]any{"sessionId": req.SessionID, "method": "Page.loadEventFired", "params": map[string]any{}})
			case "Input.insertText":
				if cEval {
					send(map[string]any{"id": req.ID, "sessionId": req.SessionID, "error": map[string]any{"code": -1, "message": "insert err"}})
					continue
				}
				send(map[string]any{"id": req.ID, "sessionId": req.SessionID, "result": map[string]any{}})
			case "Page.captureScreenshot":
				if cShot {
					send(map[string]any{"id": req.ID, "sessionId": req.SessionID, "error": map[string]any{"code": -1, "message": "shot err"}})
					continue
				}
				send(map[string]any{"id": req.ID, "sessionId": req.SessionID, "result": map[string]any{"data": "SHOT_B64"}})
			case "Page.printToPDF":
				if cPDF {
					send(map[string]any{"id": req.ID, "sessionId": req.SessionID, "error": map[string]any{"code": -1, "message": "pdf err"}})
					continue
				}
				send(map[string]any{"id": req.ID, "sessionId": req.SessionID, "result": map[string]any{"data": "PDF_B64"}})
			case "Runtime.evaluate":
				if cEval {
					send(map[string]any{"id": req.ID, "sessionId": req.SessionID, "error": map[string]any{"code": -1, "message": "eval rpc err"}})
					continue
				}
				if eEx {
					send(map[string]any{"id": req.ID, "sessionId": req.SessionID, "result": map[string]any{"exceptionDetails": map[string]any{"text": "ReferenceError: x"}}})
					continue
				}
				var p struct {
					Expression string `json:"expression"`
				}
				_ = json.Unmarshal(req.Params, &p)
				switch {
				case strings.HasPrefix(p.Expression, "Boolean(document.querySelector"):
					val := waitSelPolls.Add(1) >= 2
					send(map[string]any{"id": req.ID, "sessionId": req.SessionID, "result": map[string]any{"result": map[string]any{"type": "boolean", "value": val}}})
				case strings.Contains(p.Expression, "outerHTML"):
					if eNonJSON {
						send(map[string]any{"id": req.ID, "sessionId": req.SessionID, "result": map[string]any{"result": map[string]any{"type": "string", "value": "<html>raw-non-json</html>"}}})
						continue
					}
					if eOver {
						docJSON, _ := json.Marshal(map[string]any{"url": "https://app.example.com/", "html": "", "oversized": 17000000})
						send(map[string]any{"id": req.ID, "sessionId": req.SessionID, "result": map[string]any{"result": map[string]any{"type": "string", "value": string(docJSON)}}})
						continue
					}
					u := "https://app.example.com/page"
					if dURL != "" {
						u = dURL
					}
					if sURL != "" && strings.Contains(p.Expression, "outerHTML") {
						// Return sURL once if requested for actionScrape validation
						u = sURL
					}
					htmlDoc := "<html><body><main>OK</main></body></html>"
					if pChal {
						htmlDoc = `<html><head><title>Just a moment...</title></head><body><div class="cf-turnstile"></div></body></html>`
					}
					docJSON, _ := json.Marshal(map[string]string{"url": u, "html": htmlDoc})
					send(map[string]any{"id": req.ID, "sessionId": req.SessionID, "result": map[string]any{"result": map[string]any{"type": "string", "value": string(docJSON)}}})
				case strings.Contains(p.Expression, "selector_not_found") && strings.Contains(p.Expression, "#missing"):
					send(map[string]any{"id": req.ID, "sessionId": req.SessionID, "result": map[string]any{"result": map[string]any{"type": "string", "value": "selector_not_found"}}})
				case strings.Contains(p.Expression, "selector_not_found") || strings.Contains(p.Expression, "scrollIntoView") || strings.Contains(p.Expression, "scrollBy"):
					send(map[string]any{"id": req.ID, "sessionId": req.SessionID, "result": map[string]any{"result": map[string]any{"type": "string", "value": "ok"}}})
				default:
					if eNonStr {
						send(map[string]any{"id": req.ID, "sessionId": req.SessionID, "result": map[string]any{"result": map[string]any{"type": "number", "value": 123}}})
						continue
					}
					send(map[string]any{"id": req.ID, "sessionId": req.SessionID, "result": map[string]any{"result": map[string]any{"type": "string", "value": "js-ok"}}})
				}
			default:
				send(map[string]any{"id": req.ID, "sessionId": req.SessionID, "result": map[string]any{}})
			}
		}
	}))
	defer srv.Close()

	wsURL := "ws://" + strings.TrimPrefix(srv.URL, "http://")
	allowHTTPS := func(u *url.URL) error {
		if u.Scheme != "https" {
			return errors.New("https required")
		}
		return nil
	}

	// 1. Unavailable renderer, closed renderer, unreachable dialOverrideWS.
	unavail := NewRenderer("", nil, "UA", 1, nil)
	unavail.chromeBin = ""
	if _, err := unavail.Execute(context.Background(), Task{URL: "https://app.example.com/"}); !errors.Is(err, ErrBrowserUnavailable) {
		t.Fatalf("expected ErrBrowserUnavailable, got %v", err)
	}
	badMock := NewMockRenderer("ws://127.0.0.1:1", nil, "UA")
	if _, err := badMock.Execute(context.Background(), Task{URL: "https://app.example.com/"}); err == nil {
		t.Fatal("expected dial error on badMock")
	}
	_ = badMock.Close()
	if _, err := badMock.ensureBrowser(context.Background()); err == nil || !strings.Contains(err.Error(), "closed") {
		t.Fatalf("expected renderer closed error, got %v", err)
	}

	// 2. Semaphore ctx.Done() contention with maxConcurrent=1.
	rSem := NewMockRenderer(wsURL, allowHTTPS, "UA")
	rSem.sem = make(chan struct{}, 1)
	rSem.sem <- struct{}{}
	semCtx, cancelSem := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancelSem()
	if _, err := rSem.Execute(semCtx, Task{URL: "https://app.example.com/"}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected semaphore wait DeadlineExceeded, got %v", err)
	}
	<-rSem.sem
	_ = rSem.Close()

	// 3. CDP setup failures (CreateBC, CreateTarget, Attach, Fetch.enable) + unknown session + header scoping on resumed/new sessions.
	r := NewMockRenderer(wsURL, allowHTTPS, "UA")
	defer r.Close()

	mu.Lock()
	failCreateBC = true
	mu.Unlock()
	if _, err := r.Execute(context.Background(), Task{URL: "https://app.example.com/"}); err == nil || !strings.Contains(err.Error(), "create browser context") {
		t.Fatalf("expected create browser context error, got %v", err)
	}
	mu.Lock()
	failCreateBC = false
	failCreateTarget = true
	mu.Unlock()
	if _, err := r.Execute(context.Background(), Task{URL: "https://app.example.com/"}); err == nil || !strings.Contains(err.Error(), "create target") {
		t.Fatalf("expected create target error, got %v", err)
	}
	mu.Lock()
	failCreateTarget = false
	failAttach = true
	mu.Unlock()
	if _, err := r.Execute(context.Background(), Task{URL: "https://app.example.com/"}); err == nil || !strings.Contains(err.Error(), "attach target") {
		t.Fatalf("expected attach target error, got %v", err)
	}
	mu.Lock()
	failAttach = false
	failFetchEnable = true
	mu.Unlock()
	if _, err := r.Execute(context.Background(), Task{URL: "https://app.example.com/", Headers: map[string]string{"X-K": "v"}}); err == nil || !strings.Contains(err.Error(), "Fetch interception") {
		t.Fatalf("expected Fetch.enable error, got %v", err)
	}
	mu.Lock()
	failFetchEnable = false
	mu.Unlock()

	if _, err := r.Execute(context.Background(), Task{SessionID: "no-such-session"}); err == nil {
		t.Fatal("expected unknown session error")
	}
	if _, err := r.Execute(context.Background(), Task{URL: "ftp://bad.test/", Headers: map[string]string{"X-K": "v"}}); err == nil {
		t.Fatal("expected non-http(s) Headers error")
	}

	// Whitespace-only Headers (enableOriginScopedHeaders len(cloned)==0) + navigate action initOrigin on new session.
	if _, err := r.Execute(context.Background(), Task{
		Headers: map[string]string{"   ": "ignored"},
		Actions: []InteractAction{{Type: "navigate", URL: "https://app.example.com/start", WaitMs: 1}},
	}); err != nil {
		t.Fatalf("expected whitespace headers + navigate action to succeed: %v", err)
	}

	// Resumed session errors: no initialOrigin with Headers, Fetch.enable error on resumed, cross-origin URL without Headers.
	outBlank, err := r.Execute(context.Background(), Task{KeepSession: true})
	if err != nil || outBlank.SessionID == "" {
		t.Fatalf("KeepSession blank failed: %v", err)
	}
	if _, err := r.Execute(context.Background(), Task{SessionID: outBlank.SessionID, Headers: map[string]string{"X-K": "v"}}); err == nil {
		t.Fatal("expected error when scoping headers on session with empty initialOrigin")
	}
	if !r.CloseSession(context.Background(), outBlank.SessionID) {
		t.Fatal("expected CloseSession to return true")
	}
	if r.CloseSession(context.Background(), "") || r.CloseSession(context.Background(), "missing") {
		t.Fatal("expected CloseSession false for empty/unknown")
	}

	// Tainted-by-headers CloseSession triggers shutdownLocked.
	outHdr, err := r.Execute(context.Background(), Task{
		URL:         "https://app.example.com/init",
		Headers:     map[string]string{"X-Secret": "1"},
		KeepSession: true,
		WaitForMs:   5,
	})
	if err != nil {
		t.Fatalf("KeepSession with headers failed: %v", err)
	}
	// Calling enableOriginScopedHeaders again hits !needEnable; Fetch.enable err on resumed session.
	if err := r.sessions[outHdr.SessionID].enableOriginScopedHeaders(context.Background(), r.cdp, map[string]string{"X-Secret": "2"}); err != nil {
		t.Fatalf("expected !needEnable re-enable to succeed: %v", err)
	}
	// Resumed session without Headers navigating cross-origin sets redirectedCrossOrigin.
	if _, err := r.Execute(context.Background(), Task{
		SessionID:   outHdr.SessionID,
		URL:         "https://other.example.com/p",
		KeepSession: true,
		WaitForMs:   5,
	}); err != nil {
		t.Fatalf("resumed cross-origin nav failed: %v", err)
	}
	// Resumed session with changed Headers + no URL/navigate fails closed; succeeds when explicit URL target is given.
	if _, err := r.Execute(context.Background(), Task{
		SessionID:   outHdr.SessionID,
		Headers:     map[string]string{"X-Secret": "3"},
		KeepSession: true,
	}); err == nil || !strings.Contains(err.Error(), "without an explicit navigation target") {
		t.Fatalf("expected resumed session with changed Headers and no navigation target to fail closed, got: %v", err)
	}
	if _, err := r.Execute(context.Background(), Task{
		SessionID:   outHdr.SessionID,
		URL:         "https://app.example.com/reauth",
		Headers:     map[string]string{"X-Secret": "3"},
		KeepSession: true,
		WaitForMs:   5,
	}); err != nil {
		t.Fatalf("resumed session with explicit URL + Headers failed: %v", err)
	}
	if !r.CloseSession(context.Background(), outHdr.SessionID) {
		t.Fatal("expected CloseSession on tainted session true")
	}

	// Verify Task{CloseSession: true, URL: "", Actions: nil}.
	outClose, err := r.Execute(context.Background(), Task{CloseSession: true, SessionID: "any"})
	if err != nil || outClose.SessionID != "any" {
		t.Fatalf("unexpected CloseSession task output: %+v err=%v", outClose, err)
	}

	// 4. Verify isSameOriginInitiatorHeaders is called from handleRequestPaused when redirectedCrossOrigin==false!
	mu.Lock()
	emitCrossSitePause = true
	mu.Unlock()
	if _, err := r.Execute(context.Background(), Task{
		URL:       "https://app.example.com/page",
		Headers:   map[string]string{"X-Api-Key": "secret"},
		WaitForMs: 25,
	}); err != nil {
		t.Fatalf("emitCrossSitePause Execute failed: %v", err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for !pausedHeadersSaw.Load() && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if !pausedHeadersSaw.Load() || pausedOverridden.Load() {
		t.Fatalf("expected cross-site initiator Fetch subrequest blocked without overriding headers (saw=%v overridden=%v)", pausedHeadersSaw.Load(), pausedOverridden.Load())
	}
	mu.Lock()
	emitCrossSitePause = false
	mu.Unlock()

	// 5. Mobile + ScreenshotQuality + ScreenshotFullPage + all 13 InteractAction types!
	outAct, err := r.Execute(context.Background(), Task{
		URL:                "https://app.example.com/page",
		Mobile:             true,
		Screenshot:         true,
		ScreenshotQuality:  80,
		ScreenshotFullPage: true,
		WaitSelector:       "#ready",
		WaitForMs:          10,
		Actions: []InteractAction{
			{Type: "wait", WaitMs: 1},
			{Type: "wait", Milliseconds: 1, Selector: "#ready"},
			{Type: "navigate", URL: "https://app.example.com/next", WaitMs: 1},
			{Type: "click", Selector: "#btn", All: true, WaitMs: 1},
			{Type: "click", Selector: "#btn1", All: false, WaitMs: 1},
			{Type: "write", Text: "hello", WaitMs: 1},
			{Type: "fill", Selector: "#in", Value: "val", WaitMs: 1},
			{Type: "type", Selector: "#in2", Text: "val2", WaitMs: 1},
			{Type: "select", Selector: "#sel", Value: "opt", WaitMs: 1},
			{Type: "press", Key: "", WaitMs: 1},
			{Type: "press", Key: "Tab", WaitMs: 1},
			{Type: "scroll", Direction: "up", Selector: "#sec", WaitMs: 1},
			{Type: "scroll", Direction: "down", WaitMs: 1},
			{Type: "screenshot", FullPage: true, WaitMs: 1},
			{Type: "scrape", WaitMs: 1},
			{Type: "executeJavascript", Script: "1+1", WaitMs: 1},
			{Type: "executeJavascript", Value: "2+2", WaitMs: 1},
			{Type: "pdf", WaitMs: 1},
		},
	})
	if err != nil {
		t.Fatalf("all-actions Execute failed: %v", err)
	}
	if outAct.ScreenshotBase64 != "SHOT_B64" || outAct.PDFBase64 != "PDF_B64" || len(outAct.ActionScreenshots) != 1 || len(outAct.ActionScrapes) != 1 || len(outAct.JavascriptReturns) != 2 {
		t.Fatalf("unexpected all-actions output: %+v", outAct)
	}

	// 6. Action error branches + unsupported action + pause ctx.Done() + waitForCSSSelector timeout/cancel/err.
	for _, act := range []InteractAction{
		{Type: "navigate", URL: "http://not-https.test/"},
		{Type: "click", Selector: ""},
		{Type: "click", Selector: "#missing"},
		{Type: "fill", Selector: ""},
		{Type: "fill", Selector: "#missing", Value: "x"},
		{Type: "executeJavascript"},
		{Type: "bogusAction"},
	} {
		if _, err := r.Execute(context.Background(), Task{Actions: []InteractAction{act}}); err == nil {
			t.Fatalf("expected error for action %+v", act)
		}
	}

	// evalException on executeJavascript & evalString; evalFail on write/screenshot/pdf/scrape/click/fill; captureScreenshot fail.
	mu.Lock()
	evalException = true
	mu.Unlock()
	if _, err := r.Execute(context.Background(), Task{Actions: []InteractAction{{Type: "executeJavascript", Script: "boom"}}}); err == nil {
		t.Fatal("expected js exception on executeJavascript")
	}
	if _, _, err := readDocumentHTML(context.Background(), r.cdp, ""); err == nil {
		t.Fatal("expected evalString js exception")
	}
	mu.Lock()
	evalException = false
	failEval = true
	failPrintPDF = true
	failCaptureShot = true
	mu.Unlock()
	for _, act := range []InteractAction{
		{Type: "click", Selector: "#b"},
		{Type: "write", Text: "x"},
		{Type: "fill", Selector: "#f", Value: "x"},
		{Type: "screenshot"},
		{Type: "scrape"},
		{Type: "executeJavascript", Script: "1"},
		{Type: "pdf"},
	} {
		if _, err := r.Execute(context.Background(), Task{Actions: []InteractAction{act}}); err == nil {
			t.Fatalf("expected CDP error for action %+v", act)
		}
	}
	mu.Lock()
	failEval = false
	failPrintPDF = false
	failCaptureShot = false
	mu.Unlock()

	// evalNonString, evalNonJSONDoc, evalOversizedDoc.
	mu.Lock()
	evalNonString = true
	mu.Unlock()
	if s, err := evalString(context.Background(), r.cdp, "", "123"); err != nil || s != "123" {
		t.Fatalf("expected non-string evalString '123', got %q err=%v", s, err)
	}
	mu.Lock()
	evalNonString = false
	evalNonJSONDoc = true
	mu.Unlock()
	if h, _, err := readDocumentHTML(context.Background(), r.cdp, ""); err != nil || !strings.Contains(h, "raw-non-json") {
		t.Fatalf("expected raw fallback html, got %q err=%v", h, err)
	}
	mu.Lock()
	evalNonJSONDoc = false
	evalOversizedDoc = true
	mu.Unlock()
	if _, err := r.Execute(context.Background(), Task{URL: "https://app.example.com/page", WaitForMs: 5}); err == nil || !strings.Contains(err.Error(), "safety cap") {
		t.Fatalf("expected oversized DOM error, got %v", err)
	}
	mu.Lock()
	evalOversizedDoc = false
	mu.Unlock()

	// URL parse, allow, CheckRobots errors + validateFinalURL error cases + postActionChallenge.
	if _, err := r.Execute(context.Background(), Task{URL: "://bad"}); err == nil {
		t.Fatal("expected url.Parse error")
	}
	if _, err := r.Execute(context.Background(), Task{URL: "http://plain.example.com/"}); err == nil {
		t.Fatal("expected allow error")
	}
	r.CheckRobots = func(context.Context, string) error { return errors.New("robots blocked") }
	if _, err := r.Execute(context.Background(), Task{URL: "https://app.example.com/"}); err == nil {
		t.Fatal("expected CheckRobots error")
	}
	if _, err := r.Execute(context.Background(), Task{Actions: []InteractAction{{Type: "navigate", URL: "https://app.example.com/"}}}); err == nil {
		t.Fatal("expected navigate action CheckRobots error")
	}
	r.CheckRobots = func(_ context.Context, raw string) error {
		if strings.Contains(raw, "final-rob-ok") {
			return nil
		}
		return errors.New("robots blocked")
	}
	if err := r.validateFinalURL(context.Background(), &retainedSession{}, "https://app.example.com/final-rob-ok", "https://app.example.com/init"); err != nil {
		t.Fatalf("expected validateFinalURL CheckRobots pass, got %v", err)
	}
	r.CheckRobots = nil

	for _, tc := range []struct{ finalU, initU string }{
		{"chrome-error://chromewebdata/", "https://app.example.com/"},
		{"about:blank", "https://app.example.com/"},
		{"://bad\x7f", ""},
		{"http://blocked.test/", ""},
	} {
		if err := r.validateFinalURL(context.Background(), nil, tc.finalU, tc.initU); err == nil {
			t.Fatalf("expected validateFinalURL error for %+v", tc)
		}
	}
	if err := r.validateFinalURL(context.Background(), nil, "", ""); err != nil {
		t.Fatalf("empty finalURL should return nil: %v", err)
	}
	if err := r.validateFinalURL(context.Background(), nil, "about:blank", ""); err != nil {
		t.Fatalf("about:blank with empty initialURL should return nil: %v", err)
	}

	// preURL validateFinalURL error + post-action challenge.
	mu.Lock()
	docURLOverride = "chrome-error://chromewebdata/"
	mu.Unlock()
	if _, err := r.Execute(context.Background(), Task{URL: "https://app.example.com/page", WaitForMs: 5}); err == nil {
		t.Fatal("expected preURL chrome-error")
	}
	mu.Lock()
	docURLOverride = ""
	postActionChallenge = true
	mu.Unlock()
	if _, err := r.Execute(context.Background(), Task{Actions: []InteractAction{{Type: "wait", WaitMs: 1}}}); !errors.Is(err, ErrChallengeDetected) {
		t.Fatalf("expected post-action ErrChallengeDetected, got %v", err)
	}
	mu.Lock()
	postActionChallenge = false
	mu.Unlock()

	// 7. 9 KeepSession tasks -> evictOldestSessionLocked + reapExpiredSessions + idleReaperLoop.
	for i := 0; i < 9; i++ {
		if _, err := r.Execute(context.Background(), Task{KeepSession: true}); err != nil {
			t.Fatalf("KeepSession %d failed: %v", i, err)
		}
	}
	// Seed an expired session to cover reapExpiredSessions.
	r.mu.Lock()
	r.sessions["expired-seed"] = &retainedSession{id: "expired-seed", targetID: "t", browserContextID: "b", lastUsed: time.Now().Add(-time.Hour)}
	r.mu.Unlock()
	r.reapExpiredSessions(context.Background(), r.cdp)
	r.mu.Lock()
	_, stillThere := r.sessions["expired-seed"]
	r.mu.Unlock()
	if stillThere {
		t.Fatal("expected expired-seed session reaped")
	}

	// idleReaperLoop with idleReaperInterval seam.
	origIdleInt := idleReaperInterval
	t.Cleanup(func() { idleReaperInterval = origIdleInt })
	idleReaperInterval = 10 * time.Millisecond
	rIdle := NewMockRenderer(wsURL, allowHTTPS, "UA")
	rIdle.log = slog.New(slog.NewJSONHandler(io.Discard, nil))
	cdpIdle, err := rIdle.ensureBrowser(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	rIdle.mu.Lock()
	rIdle.cdp = cdpIdle
	rIdle.taintedByHeaders = true
	rIdle.sessions["exp"] = &retainedSession{id: "exp", lastUsed: time.Now().Add(-time.Hour)}
	rIdle.mu.Unlock()
	go rIdle.idleReaperLoop(cdpIdle)
	deadlineIdle := time.Now().Add(time.Second)
	for time.Now().Before(deadlineIdle) {
		rIdle.mu.Lock()
		cNil := rIdle.cdp == nil
		rIdle.mu.Unlock()
		if cNil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	rIdle.mu.Lock()
	idleStopped := rIdle.cdp == nil
	rIdle.mu.Unlock()
	if !idleStopped {
		t.Fatal("expected idleReaperLoop to shut down tainted browser before deadline")
	}
	// Also test idleReaperLoop exit when r.cdp != target.
	rIdle.mu.Lock()
	rIdle.closed = false
	rIdle.cdp = nil
	rIdle.mu.Unlock()
	rIdle.idleReaperLoop(&cdpConn{closeCh: make(chan struct{})})
	_ = rIdle.Close()

	// 8. navigateAndWait error, navLoadTimeout, staleInFlightTTL, minIdleBudget, waitForCSSSelector timeout/ctx/err.
	origNavTO := navLoadTimeout
	origStale := staleInFlightTTL
	origMinIdle := minIdleBudget
	t.Cleanup(func() {
		navLoadTimeout = origNavTO
		staleInFlightTTL = origStale
		minIdleBudget = origMinIdle
	})
	navLoadTimeout = 15 * time.Millisecond
	staleInFlightTTL = 10 * time.Millisecond
	minIdleBudget = 120 * time.Millisecond

	mu.Lock()
	failNavigate = true
	mu.Unlock()
	if _, err := r.Execute(context.Background(), Task{URL: "https://app.example.com/"}); err == nil {
		t.Fatal("expected Page.navigate RPC error")
	}
	mu.Lock()
	failNavigate = false
	holdNavigate = true
	holdRequestInFlight = false
	mu.Unlock()
	if _, err := r.Execute(context.Background(), Task{URL: "https://app.example.com/", WaitForMs: 1}); err != nil {
		t.Fatalf("expected holdNavigate to finish via navLoadTimeout, got %v", err)
	}
	minIdleBudget = 2 * time.Second
	mu.Lock()
	holdNavigate = false
	holdRequestInFlight = true
	mu.Unlock()
	staleStart := time.Now()
	if _, err := r.Execute(context.Background(), Task{URL: "https://app.example.com/", WaitForMs: 1}); err != nil {
		t.Fatalf("expected holdRequestInFlight to evict stale in-flight request via staleInFlightTTL, got %v", err)
	}
	if elapsed := time.Since(staleStart); elapsed >= 500*time.Millisecond {
		t.Fatalf("expected staleInFlightTTL eviction well before minIdleBudget, took %v", elapsed)
	}
	mu.Lock()
	holdNavigate = false
	holdRequestInFlight = false
	mu.Unlock()

	// waitForCSSSelector timeout + ctx.Done() + evalBool error; runAction wait >15s + ctx.Done() + post-action >5s + ctx.Done().
	waitSelPolls.Store(-1000)
	if err := waitForCSSSelector(context.Background(), r.cdp, "", "#never", 20*time.Millisecond); err == nil {
		t.Fatal("expected waitForCSSSelector timeout")
	}
	ctxWaitCancel, cancelWait := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancelWait()
	if err := waitForCSSSelector(ctxWaitCancel, r.cdp, "", "#never", time.Second); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected waitForCSSSelector DeadlineExceeded, got %v", err)
	}
	if err := r.runAction(ctxWaitCancel, r.cdp, &retainedSession{}, nil, InteractAction{Type: "wait", WaitMs: 20_000}, nil, nil, nil, nil); err == nil {
		t.Fatal("expected wait >15s clamp + ctx cancel error")
	}
	ctxPauseCancel, cancelPause := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancelPause()
	if err := r.runAction(ctxPauseCancel, r.cdp, &retainedSession{}, nil, InteractAction{Type: "press", WaitMs: 10_000}, nil, nil, nil, nil); err == nil {
		t.Fatal("expected post-action pause >5s clamp + ctx cancel error")
	}
	mu.Lock()
	failEval = true
	mu.Unlock()
	if err := waitForCSSSelector(context.Background(), r.cdp, "", "#err", time.Second); err == nil {
		t.Fatal("expected evalBool error")
	}
	mu.Lock()
	failEval = false
	mu.Unlock()
}

func TestRendererProbeStartupPipeLaunchAndSandboxFallback(t *testing.T) {
	// 1. ProbeStartup early returns (nil, empty chromeBin, dialOverrideWS, cancelled ctx).
	var nilR *Renderer
	nilR.ProbeStartup(context.Background())
	NewMockRenderer("ws://127.0.0.1:1", nil, "UA").ProbeStartup(context.Background())
	cancelledCtx, cancelNow := context.WithCancel(context.Background())
	cancelNow()

	if runtime.GOOS != "linux" {
		t.Skip("Linux-specific sandbox fallback & /proc helper test")
	}

	// 2a. Default (EDGEFETCH_ALLOW_NO_SANDBOX unset): fallback_ok MUST fail closed instead of silently running --no-sandbox!
	fallbackBin := makeChromeHelperWrapper(t, "fallback_ok")
	NewRenderer(fallbackBin, nil, "UA", 1, nil).ProbeStartup(cancelledCtx)

	t.Setenv("EDGEFETCH_ALLOW_NO_SANDBOX", "")
	t.Setenv("EDGEFETCH_REQUIRE_BROWSER_SANDBOX", "")
	var logBuf bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&logBuf, nil))
	rDefaultDeny := NewRenderer(fallbackBin, nil, "UA", 1, log)
	defer rDefaultDeny.Close()
	rDefaultDeny.ProbeStartup(context.Background())
	if rDefaultDeny.Available() {
		t.Fatalf("SECURITY: expected ProbeStartup without EDGEFETCH_ALLOW_NO_SANDBOX=1 to fail closed, log=%s", logBuf.String())
	}

	// 2b. Explicit EDGEFETCH_ALLOW_NO_SANDBOX=1: fallback_ok succeeds with --no-sandbox + split-frame pipe response!
	t.Setenv("EDGEFETCH_ALLOW_NO_SANDBOX", "1")
	rFallback := NewRenderer(fallbackBin, nil, "UA", 1, log)
	defer rFallback.Close()
	rFallback.ProbeStartup(context.Background())
	ver, sb := rFallback.BrowserInfo()
	if ver == "" || sb != "off" || !rFallback.Available() {
		t.Fatalf("expected opt-in sandbox fallback to succeed and remain Available, got ver=%q sb=%q avail=%v log=%s", ver, sb, rFallback.Available(), logBuf.String())
	}

	// 3. Helper script: fatal_sandbox with BOTH EDGEFETCH_ALLOW_NO_SANDBOX=1 and EDGEFETCH_REQUIRE_BROWSER_SANDBOX=1 -> disabledByPolicy = true, Available() = false.
	fatalBin := makeChromeHelperWrapper(t, "fatal_sandbox")
	t.Setenv("EDGEFETCH_REQUIRE_BROWSER_SANDBOX", "1")
	rPolicy := NewRenderer(fatalBin, nil, "UA", 1, log)
	defer rPolicy.Close()
	rPolicy.ProbeStartup(context.Background())
	if rPolicy.Available() {
		t.Fatal("expected Available() == false when fatal_sandbox hits EDGEFETCH_REQUIRE_BROWSER_SANDBOX=1")
	}
	t.Setenv("EDGEFETCH_REQUIRE_BROWSER_SANDBOX", "")
	t.Setenv("EDGEFETCH_ALLOW_NO_SANDBOX", "")

	// 4. Nonexistent chromeBin -> cmd.Start() error.
	rMissing := NewRenderer("/nonexistent/chrome-bin-xyz", nil, "UA", 1, nil)
	if _, err := rMissing.ensureBrowser(context.Background()); err == nil || !strings.Contains(err.Error(), "start chromium") {
		t.Fatalf("expected start chromium error, got %v", err)
	}

	// 5. silent_exit helper -> isLinuxProcessZombieOrDead + reason == "" error.
	silentBin := makeChromeHelperWrapper(t, "silent_exit")
	rSilent := NewRenderer(silentBin, nil, "UA", 1, nil)
	rSilent.requireSandbox = false
	if _, err := rSilent.ensureBrowser(context.Background()); err == nil {
		t.Fatal("expected silent_exit ensureBrowser failure")
	}

	// 6. hang helper -> DeadlineExceeded && reason == "" and ctx.Err().
	hangBin := makeChromeHelperWrapper(t, "hang")
	rHang := NewRenderer(hangBin, nil, "UA", 1, nil)
	if _, _, _, err := rHang.launchAndDialPipeLocked(context.Background(), t.TempDir(), []string{}, 40*time.Millisecond); err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("expected timeout error from hang helper, got %v", err)
	}
	hangCtx, cancelHang := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancelHang()
	if _, _, _, err := rHang.launchAndDialPipeLocked(hangCtx, t.TempDir(), []string{}, 5*time.Second); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected parent ctx DeadlineExceeded from hang helper, got %v", err)
	}

	// 7. oversized_frame (> 24 MiB without NUL).
	overBin := makeChromeHelperWrapper(t, "oversized_frame")
	rOver := NewRenderer(overBin, nil, "UA", 1, nil)
	if _, _, _, err := rOver.launchAndDialPipeLocked(context.Background(), t.TempDir(), []string{}, 2*time.Second); err == nil {
		t.Fatal("expected oversized_frame helper to fail probe")
	}

	// 8. ensureBrowser linuxSandboxBlockedByHostPolicy pre-check with requireSandbox=true & false via readProcFile seam.
	origReadProc := readProcFile
	t.Cleanup(func() { readProcFile = origReadProc })
	readProcFile = func(path string) ([]byte, error) {
		if strings.HasSuffix(path, "attr/current") {
			return []byte("edgefetch"), nil
		}
		return nil, os.ErrNotExist
	}
	rPreDeny := NewRenderer(fallbackBin, nil, "UA", 1, log)
	rPreDeny.requireSandbox = true
	if _, err := rPreDeny.ensureBrowser(context.Background()); err == nil || !rPreDeny.disabledByPolicy {
		t.Fatalf("expected pre-check policy denial, got err=%v disabled=%v", err, rPreDeny.disabledByPolicy)
	}
	if _, err := rPreDeny.ensureBrowser(context.Background()); !errors.Is(err, ErrBrowserUnavailable) {
		t.Fatalf("expected ErrBrowserUnavailable on subsequent ensureBrowser when disabledByPolicy is true, got %v", err)
	}
	rPreDefaultDeny := NewRenderer(fallbackBin, nil, "UA", 1, log)
	rPreDefaultDeny.requireSandbox = false
	rPreDefaultDeny.allowNoSandbox = false
	if _, err := rPreDefaultDeny.ensureBrowser(context.Background()); err == nil || !rPreDefaultDeny.disabledByPolicy {
		t.Fatalf("expected pre-check default denial when allowNoSandbox=false, got err=%v disabled=%v", err, rPreDefaultDeny.disabledByPolicy)
	}
	rPreFallback := NewRenderer(fallbackBin, nil, "UA", 1, log)
	rPreFallback.requireSandbox = false
	rPreFallback.allowNoSandbox = true
	defer rPreFallback.Close()
	if _, err := rPreFallback.ensureBrowser(context.Background()); err != nil || !rPreFallback.sandboxFallback {
		t.Fatalf("expected pre-check opt-in sandboxFallback to succeed, got err=%v fallback=%v", err, rPreFallback.sandboxFallback)
	}

	// 9. hang helper + readProcFile returning zombie "Z" stat -> triggers isLinuxProcessZombieOrDead in 50ms ticker and reason == "" error.
	readProcFile = func(path string) ([]byte, error) {
		if strings.HasSuffix(path, "/stat") {
			return []byte("123 (chrome) Z 1 1 1 0 -1 0 0 0 0 0 0 0 0 20 0 1 0 10 0 0 0"), nil
		}
		return nil, os.ErrNotExist
	}
	zombieStart := time.Now()
	if _, _, _, err := rHang.launchAndDialPipeLocked(context.Background(), t.TempDir(), []string{}, 2*time.Second); err == nil ||
		!strings.Contains(err.Error(), "chromium exited before advertising DevTools") || time.Since(zombieStart) >= time.Second {
		t.Fatalf("expected fast zombie termination error (<1s), got err=%v elapsed=%v", err, time.Since(zombieStart))
	}
	readProcFile = origReadProc

	// 10. ensureBrowser NewSSRFProxy listen error via proxyListen seam.
	origProxyListen := proxyListen
	t.Cleanup(func() { proxyListen = origProxyListen })
	proxyListen = func(string, string) (net.Listener, error) {
		return nil, errors.New("proxy listen failed")
	}
	rProxyFail := NewRenderer(fallbackBin, nil, "UA", 1, log)
	rProxyFail.sandboxFallback = true
	if _, err := rProxyFail.ensureBrowser(context.Background()); err == nil || !strings.Contains(err.Error(), "listen ssrf proxy") {
		t.Fatalf("expected ensureBrowser NewSSRFProxy error, got %v", err)
	}
	proxyListen = origProxyListen
}

func TestRendererRemainingReachableBranches(t *testing.T) {
	// 1. enableOriginScopedHeaders nil session & cdp.closeCh exit.
	var nilSess *retainedSession
	if err := nilSess.enableOriginScopedHeaders(context.Background(), nil, nil); err != nil {
		t.Fatal(err)
	}

	var (
		mu             sync.Mutex
		navMode        string
		outerHTMLCalls atomic.Int32
		scrapeBadOnce  bool
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer conn.CloseNow()
		var writeMu sync.Mutex
		send := func(v any) {
			b, _ := json.Marshal(v)
			writeMu.Lock()
			_ = conn.Write(r.Context(), websocket.MessageText, b)
			writeMu.Unlock()
		}
		for {
			_, raw, err := conn.Read(r.Context())
			if err != nil {
				return
			}
			var req struct {
				ID        int64  `json:"id"`
				SessionID string `json:"sessionId"`
				Method    string `json:"method"`
			}
			if json.Unmarshal(raw, &req) != nil {
				continue
			}
			mu.Lock()
			nm := navMode
			sb := scrapeBadOnce
			mu.Unlock()
			switch req.Method {
			case "Target.createBrowserContext":
				send(map[string]any{"id": req.ID, "result": map[string]any{"browserContextId": "bc-rem"}})
			case "Target.createTarget":
				send(map[string]any{"id": req.ID, "result": map[string]any{"targetId": "tgt-rem"}})
			case "Target.attachToTarget":
				send(map[string]any{"id": req.ID, "result": map[string]any{"sessionId": "s-rem"}})
			case "Fetch.enable":
				if nm == "fail_fetch_enable" {
					send(map[string]any{"id": req.ID, "sessionId": req.SessionID, "error": map[string]any{"code": -1, "message": "fe err"}})
					continue
				}
				send(map[string]any{"id": req.ID, "sessionId": req.SessionID, "result": map[string]any{}})
			case "Page.navigate":
				switch nm {
				case "hold_load":
					send(map[string]any{"id": req.ID, "sessionId": req.SessionID, "result": map[string]any{"frameId": "f1"}})
				case "nav_err":
					send(map[string]any{"id": req.ID, "sessionId": req.SessionID, "error": map[string]any{"code": -1, "message": "nav fail"}})
				case "in_flight_after_load":
					send(map[string]any{"id": req.ID, "sessionId": req.SessionID, "result": map[string]any{"frameId": "f1"}})
					send(map[string]any{"sessionId": req.SessionID, "method": "Page.loadEventFired", "params": map[string]any{}})
					go func(sid string) {
						time.Sleep(15 * time.Millisecond)
						send(map[string]any{
							"sessionId": sid,
							"method":    "Network.requestWillBeSent",
							"params":    map[string]any{"requestId": "late-xhr", "type": "XHR"},
						})
					}(req.SessionID)
				default:
					send(map[string]any{"id": req.ID, "sessionId": req.SessionID, "result": map[string]any{"frameId": "f1"}})
					send(map[string]any{"sessionId": req.SessionID, "method": "Page.loadEventFired", "params": map[string]any{}})
				}
			case "Runtime.evaluate":
				u := "https://app.example.com/ok"
				if sb && outerHTMLCalls.Add(1) == 1 {
					u = "chrome-error://chromewebdata/"
				} else if nm == "final_bad_url" {
					u = "chrome-error://chromewebdata/"
				}
				docJSON, _ := json.Marshal(map[string]string{"url": u, "html": "<html><body>ok</body></html>"})
				send(map[string]any{"id": req.ID, "sessionId": req.SessionID, "result": map[string]any{"result": map[string]any{"type": "string", "value": string(docJSON)}}})
			default:
				send(map[string]any{"id": req.ID, "sessionId": req.SessionID, "result": map[string]any{}})
			}
		}
	}))
	defer srv.Close()
	wsURL := "ws://" + strings.TrimPrefix(srv.URL, "http://")

	// cdp.closeCh exit inside enableOriginScopedHeaders goroutine.
	cdpDirect, err := dialCDP(context.Background(), wsURL)
	if err != nil {
		t.Fatal(err)
	}
	sessDirect := &retainedSession{cdpSessionID: "s-rem"}
	if err := sessDirect.enableOriginScopedHeaders(context.Background(), cdpDirect, map[string]string{"X-A": "1"}); err != nil {
		t.Fatal(err)
	}
	_ = cdpDirect.close()
	<-cdpDirect.closeCh

	// Resumed session Fetch.enable error (renderer.go:810-811), final validateFinalURL (1017-1019) & actionScrapes validateFinalURL (1021-1023).
	r := NewMockRenderer(wsURL, func(u *url.URL) error { return nil }, "UA")
	defer r.Close()
	outKeep, err := r.Execute(context.Background(), Task{URL: "https://app.example.com/ok", KeepSession: true, WaitForMs: 5})
	if err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	navMode = "fail_fetch_enable"
	mu.Unlock()
	if _, err := r.Execute(context.Background(), Task{SessionID: outKeep.SessionID, URL: "https://app.example.com/ok", Headers: map[string]string{"X-H": "1"}, KeepSession: true}); err == nil || !strings.Contains(err.Error(), "Fetch interception") {
		t.Fatalf("expected Fetch.enable error on resumed session, got: %v", err)
	}

	mu.Lock()
	navMode = "final_bad_url"
	mu.Unlock()
	if _, err := r.Execute(context.Background(), Task{Actions: []InteractAction{{Type: "press", WaitMs: 1}}}); err == nil {
		t.Fatal("expected final validateFinalURL error when Task.URL == ''")
	}

	mu.Lock()
	navMode = ""
	scrapeBadOnce = true
	mu.Unlock()
	if _, err := r.Execute(context.Background(), Task{Actions: []InteractAction{{Type: "scrape", WaitMs: 1}}}); err == nil {
		t.Fatal("expected actionScrapes[0].URL validateFinalURL error")
	}
	mu.Lock()
	scrapeBadOnce = false
	mu.Unlock()

	// navigateAndWait direct tests for cdp.closeCh (during load & idle), ctx.Done (during load & idle), WaitForMs > 15000 + idleDeadline + in_flight_after_load.
	origNavTO := navLoadTimeout
	origMinIdle := minIdleBudget
	origStale := staleInFlightTTL
	t.Cleanup(func() {
		navLoadTimeout = origNavTO
		minIdleBudget = origMinIdle
		staleInFlightTTL = origStale
	})
	navLoadTimeout = 5 * time.Second
	minIdleBudget = 80 * time.Millisecond
	staleInFlightTTL = 5 * time.Second

	// A. hold_load + cdp.close()
	cA, err := dialCDP(context.Background(), wsURL)
	if err != nil {
		t.Fatal(err)
	}
	evA, unsubA := cA.subscribe()
	mu.Lock()
	navMode = "hold_load"
	mu.Unlock()
	go func() {
		time.Sleep(20 * time.Millisecond)
		_ = cA.close()
	}()
	if _, _, err := navigateAndWait(context.Background(), cA, &retainedSession{cdpSessionID: "s-rem"}, evA, "https://app.example.com/", 10, ""); err == nil {
		t.Fatal("expected cdp close error during Page.navigate load wait")
	}
	unsubA()

	// B. hold_load + ctx cancel
	cB, err := dialCDP(context.Background(), wsURL)
	if err != nil {
		t.Fatal(err)
	}
	defer cB.close()
	evB, unsubB := cB.subscribe()
	defer unsubB()
	ctxB, cancelB := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancelB()
	if _, _, err := navigateAndWait(ctxB, cB, &retainedSession{cdpSessionID: "s-rem"}, evB, "https://app.example.com/", 10, ""); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected ctx DeadlineExceeded during load wait, got %v", err)
	}

	// C. in_flight_after_load + WaitForMs: 20_000 (clamped to 15_000) -> WaitForMs=20000 with short minIdleBudget & short wait?
	// Note minFloor = now.Add(settle ms), so use ctx cancel during idle loop for WaitForMs=20000 AND WaitForMs=10 for idleDeadline!
	mu.Lock()
	navMode = "in_flight_after_load"
	mu.Unlock()
	if _, _, err := navigateAndWait(context.Background(), cB, &retainedSession{cdpSessionID: "s-rem"}, evB, "https://app.example.com/", 10, ""); err != nil {
		t.Fatalf("expected in_flight_after_load to exit cleanly at idleDeadline, got %v", err)
	}
	ctxIdleCancel, cancelIdle := context.WithTimeout(context.Background(), 60*time.Millisecond)
	defer cancelIdle()
	if _, _, err := navigateAndWait(ctxIdleCancel, cB, &retainedSession{cdpSessionID: "s-rem"}, evB, "https://app.example.com/", 20_000, ""); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected ctx DeadlineExceeded during idle loop with WaitForMs=20000, got %v", err)
	}

	// D. cdp.closeCh during idle loop.
	cD, err := dialCDP(context.Background(), wsURL)
	if err != nil {
		t.Fatal(err)
	}
	evD, unsubD := cD.subscribe()
	defer unsubD()
	mu.Lock()
	navMode = ""
	mu.Unlock()
	go func() {
		time.Sleep(30 * time.Millisecond)
		_ = cD.close()
	}()
	if _, _, err := navigateAndWait(context.Background(), cD, &retainedSession{cdpSessionID: "s-rem"}, evD, "https://app.example.com/", 500, ""); err == nil {
		t.Fatal("expected cdp close error during SPA network-idle wait")
	}

	// runAction: wait default 500ms, press with WaitMs=0 (default 250ms pause), navigate invalid URL / navigateAndWait err.
	sAct := &retainedSession{cdpSessionID: "s-rem"}
	if err := r.runAction(context.Background(), cB, sAct, evB, InteractAction{Type: "wait"}, nil, nil, nil, nil); err != nil {
		t.Fatalf("default wait failed: %v", err)
	}
	if err := r.runAction(context.Background(), cB, sAct, evB, InteractAction{Type: "press"}, nil, nil, nil, nil); err != nil {
		t.Fatalf("default press pause failed: %v", err)
	}
	if err := r.runAction(context.Background(), cB, sAct, evB, InteractAction{Type: "navigate", URL: "://bad"}, nil, nil, nil, nil); err == nil {
		t.Fatal("expected navigate url.Parse error")
	}
	mu.Lock()
	navMode = "nav_err"
	mu.Unlock()
	if err := r.runAction(context.Background(), cB, sAct, evB, InteractAction{Type: "navigate", URL: "https://app.example.com/x"}, nil, nil, nil, nil); err == nil {
		t.Fatal("expected navigateAndWait error from navigate action")
	}

	// idleReaperLoop non-shutdown tick (line 2421) before tainted shutdown.
	origIdleInt := idleReaperInterval
	t.Cleanup(func() { idleReaperInterval = origIdleInt })
	idleReaperInterval = 10 * time.Millisecond
	rTick := NewMockRenderer(wsURL, nil, "UA")
	cdpTick, err := rTick.ensureBrowser(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	rTick.mu.Lock()
	rTick.cdp = cdpTick
	rTick.lastUsedAt = time.Now()
	rTick.taintedByHeaders = false
	rTick.mu.Unlock()
	go rTick.idleReaperLoop(cdpTick)
	time.Sleep(35 * time.Millisecond)
	_ = rTick.Close()
}
