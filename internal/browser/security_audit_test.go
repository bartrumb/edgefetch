package browser

import (
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
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
)

func TestChromiumLaunchFlagsAndSanitizedChildEnv(t *testing.T) {
	args := buildChromiumLaunchArgs("127.0.0.1:43210", "/tmp/ef-profile")
	joined := strings.Join(args, " ")

	if !strings.Contains(joined, "--proxy-bypass-list=<-loopback>") {
		t.Fatalf("H1: missing --proxy-bypass-list=<-loopback> in Chromium flags: %s", joined)
	}
	if !strings.Contains(joined, "--webrtc-ip-handling-policy=disable_non_proxied_udp") {
		t.Fatalf("M2: missing --webrtc-ip-handling-policy=disable_non_proxied_udp in Chromium flags: %s", joined)
	}
	if !strings.Contains(joined, "--force-webrtc-ip-handling-policy=disable_non_proxied_udp") {
		t.Fatalf("M1: missing --force-webrtc-ip-handling-policy=disable_non_proxied_udp in Chromium flags: %s", joined)
	}
	if !strings.Contains(joined, "--enforce-webrtc-ip-permission-check") {
		t.Fatalf("M2: missing --enforce-webrtc-ip-permission-check in Chromium flags: %s", joined)
	}
	if strings.Contains(joined, "IsolateOrigins") || strings.Contains(joined, "site-per-process") {
		t.Fatalf("H9: Chromium site isolation must not be disabled: %s", joined)
	}
	if strings.Contains(joined, "--no-sandbox") || strings.Contains(joined, "--disable-setuid-sandbox") || strings.Contains(joined, "--disable-gpu-sandbox") {
		t.Fatalf("default buildChromiumLaunchArgs must keep native OS process sandbox enabled: %s", joined)
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

func TestBuildChromiumLaunchArgsWithSandboxToggleAndPolicy(t *testing.T) {
	sandboxed := strings.Join(buildChromiumLaunchArgsWithSandbox("127.0.0.1:43210", "/tmp/ef-profile", true), " ")
	if strings.Contains(sandboxed, "--no-sandbox") || strings.Contains(sandboxed, "--disable-setuid-sandbox") || strings.Contains(sandboxed, "--disable-gpu-sandbox") {
		t.Fatalf("useSandbox=true must omit --no-sandbox flags, got: %s", sandboxed)
	}

	fallback := strings.Join(buildChromiumLaunchArgsWithSandbox("127.0.0.1:43210", "/tmp/ef-profile", false), " ")
	if !strings.Contains(fallback, "--no-sandbox") || !strings.Contains(fallback, "--disable-setuid-sandbox") || !strings.Contains(fallback, "--disable-gpu-sandbox") {
		t.Fatalf("useSandbox=false must include --no-sandbox fallback flags, got: %s", fallback)
	}

	t.Setenv("EDGEFETCH_REQUIRE_BROWSER_SANDBOX", "1")
	r := NewRenderer("/fake/chromium", nil, "EdgeFetchTest/2.6.0", 1, nil)
	if !r.requireSandbox || !r.Available() {
		t.Fatalf("expected requireSandbox=true and Available()=true initially")
	}
	r.mu.Lock()
	r.browserVersion = "HeadlessChrome/136.0.0.0"
	r.sandboxState = "off"
	r.disabledByPolicy = true
	r.mu.Unlock()
	if r.Available() {
		t.Fatal("expected Available()=false when requireSandbox=true and sandboxState=off")
	}
	ver, sb := r.BrowserInfo()
	if ver != "HeadlessChrome/136.0.0.0" || sb != "off" {
		t.Fatalf("unexpected BrowserInfo: version=%q sandbox=%q", ver, sb)
	}
}

func TestRendererLoopbackProxyBypassBlockedLiveIfChromeInstalled(t *testing.T) {
	t.Parallel()
	chromeBin := FindChromeBinary()
	if chromeBin == "" {
		t.Skip("Chromium/Chrome binary not installed on host; live container smoke runs in docker-multiarch CI")
	}
	acquireLiveChromeSlot(t)

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

	r := NewRenderer(chromeBin, allowHTTPSPublicOnly, "EdgeFetchTest/2.5.5", 1, slog.New(slog.NewJSONHandler(io.Discard, nil)))
	enableNoSandboxOnRestrictedLinuxHost(r)
	defer r.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()

	// 1. Attempt to render a direct loopback target: SSRFProxy + `<-loopback>` + FinalURL check must block 100% of hits.
	out, err := r.Execute(ctx, Task{
		URL:       victim.URL + "/secret",
		WaitForMs: 300,
	})
	if victimHits.Load() != 0 {
		t.Fatalf("SECURITY (H1): Chromium bypassed SSRFProxy and hit loopback victim %d time(s)!", victimHits.Load())
	}
	if err == nil {
		t.Fatalf("SECURITY (H1): expected error when navigating to blocked loopback target, got out=%+v", out)
	}
	if strings.Contains(out.HTML, "TOP_SECRET_LOOPBACK_TOKEN") {
		t.Fatalf("SECURITY (H1): loopback response body leaked into rendered output")
	}
	if ver, sb := r.BrowserInfo(); ver == "" || sb == "" {
		t.Fatalf("expected non-empty BrowserInfo after live Execute, got version=%q sandbox=%q", ver, sb)
	}

	// 2. Live WebRTC STUN UDP loopback leak check (M2): zero STUN UDP packets may reach 127.0.0.1.
	udpConn, uErr := net.ListenPacket("udp4", "127.0.0.1:0")
	if uErr != nil {
		t.Fatalf("listen udp4 loopback: %v", uErr)
	}
	defer udpConn.Close()
	udpPort := udpConn.LocalAddr().(*net.UDPAddr).Port

	var stunPackets atomic.Int32
	go func() {
		buf := make([]byte, 1500)
		for {
			n, _, rErr := udpConn.ReadFrom(buf)
			if n > 0 {
				stunPackets.Add(1)
			}
			if rErr != nil {
				return
			}
		}
	}()

	webrtcScript := fmt.Sprintf(`(async () => {
		try {
			if (typeof RTCPeerConnection !== "function") return "no_webrtc";
			const pc = new RTCPeerConnection({ iceServers: [{ urls: "stun:127.0.0.1:%d" }] });
			pc.createDataChannel("m2-probe");
			const offer = await pc.createOffer();
			await pc.setLocalDescription(offer);
			await new Promise((resolve) => setTimeout(resolve, 500));
			pc.close();
			return "probed";
		} catch (e) {
			return String(e);
		}
	})()`, udpPort)

	webrtcOut, webrtcErr := r.Execute(ctx, Task{
		Actions: []InteractAction{{Type: "executeJavascript", Script: webrtcScript, WaitMs: 100}},
	})
	if webrtcErr != nil {
		t.Fatalf("WebRTC probe Execute failed: %v", webrtcErr)
	}
	if len(webrtcOut.JavascriptReturns) != 1 || (webrtcOut.JavascriptReturns[0].Value != "probed" && webrtcOut.JavascriptReturns[0].Value != "no_webrtc") {
		t.Fatalf("unexpected WebRTC probe return: %+v", webrtcOut.JavascriptReturns)
	}
	if stunPackets.Load() != 0 {
		t.Fatalf("SECURITY (M2): Chromium leaked %d WebRTC STUN UDP packet(s) to 127.0.0.1:%d", stunPackets.Load(), udpPort)
	}
}

func TestValidateFinalURLChecksRobotsEvenOnResumedInteractSession(t *testing.T) {
	t.Parallel()
	var checked []string
	r := NewRenderer("", func(u *url.URL) error {
		if u.Scheme != "https" {
			return errors.New("https required")
		}
		return nil
	}, "EdgeFetchTest/2.5.5", 1, nil)
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

func TestFailedKeepSessionDisposesSlotAndExtraHeadersClearedAfterNavigate(t *testing.T) {
	t.Parallel()
	var (
		mu              sync.Mutex
		disposedCtxs    int
		setExtraHeaders atomic.Int32
		fetchEnabled    atomic.Bool
		allContinued    sync.Once
	)
	continuedHdrs := make(map[string][]fetchHeaderEntry)
	continuedHasOverride := make(map[string]bool)
	allContinuedCh := make(chan struct{})
	failNavigate := true

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		conn, err := websocket.Accept(w, req, nil)
		if err != nil {
			return
		}
		defer conn.CloseNow()

		var writeMu sync.Mutex
		send := func(obj any) {
			b, _ := json.Marshal(obj)
			writeMu.Lock()
			_ = conn.Write(req.Context(), websocket.MessageText, b)
			writeMu.Unlock()
		}

		connFetchEnabled := false
		var docContinuedOnce sync.Once
		docContinuedCh := make(chan struct{})

		for {
			_, rawMsg, err := conn.Read(req.Context())
			if err != nil {
				return
			}
			var rpc struct {
				ID        int64           `json:"id"`
				SessionID string          `json:"sessionId"`
				Method    string          `json:"method"`
				Params    json.RawMessage `json:"params"`
			}
			if json.Unmarshal(rawMsg, &rpc) != nil {
				continue
			}

			switch rpc.Method {
			case "Target.createBrowserContext":
				send(map[string]any{"id": rpc.ID, "result": map[string]any{"browserContextId": "bc-audit"}})
			case "Target.createTarget":
				send(map[string]any{"id": rpc.ID, "result": map[string]any{"targetId": "tgt-audit"}})
			case "Target.attachToTarget":
				send(map[string]any{"id": rpc.ID, "result": map[string]any{"sessionId": "sess-audit"}})
			case "Target.disposeBrowserContext":
				mu.Lock()
				disposedCtxs++
				mu.Unlock()
				send(map[string]any{"id": rpc.ID, "result": map[string]any{}})
			case "Network.setExtraHTTPHeaders":
				setExtraHeaders.Add(1)
				send(map[string]any{"id": rpc.ID, "sessionId": rpc.SessionID, "result": map[string]any{}})
			case "Fetch.enable":
				connFetchEnabled = true
				fetchEnabled.Store(true)
				send(map[string]any{"id": rpc.ID, "sessionId": rpc.SessionID, "result": map[string]any{}})
			case "Fetch.continueRequest":
				var p struct {
					RequestID string             `json:"requestId"`
					Headers   []fetchHeaderEntry `json:"headers"`
				}
				var rawMap map[string]json.RawMessage
				_ = json.Unmarshal(rpc.Params, &p)
				_ = json.Unmarshal(rpc.Params, &rawMap)
				_, hasHdrs := rawMap["headers"]

				mu.Lock()
				continuedHdrs[p.RequestID] = p.Headers
				continuedHasOverride[p.RequestID] = hasHdrs
				doneCount := len(continuedHdrs)
				mu.Unlock()

				send(map[string]any{"id": rpc.ID, "sessionId": rpc.SessionID, "result": map[string]any{}})
				if p.RequestID == "audit-doc" {
					docContinuedOnce.Do(func() { close(docContinuedCh) })
				}
				if doneCount >= 2 {
					allContinued.Do(func() { close(allContinuedCh) })
				}
			case "Page.navigate":
				if failNavigate {
					send(map[string]any{"id": rpc.ID, "sessionId": rpc.SessionID, "result": map[string]any{"frameId": "f1", "errorText": "net::ERR_ABORTED"}})
					continue
				}
				if connFetchEnabled {
					navID := rpc.ID
					navSID := rpc.SessionID
					go func() {
						send(map[string]any{
							"sessionId": navSID,
							"method":    "Fetch.requestPaused",
							"params": map[string]any{
								"requestId":    "audit-doc",
								"frameId":      "f1",
								"resourceType": "Document",
								"request": map[string]any{
									"url":     "https://first.example.com/page",
									"headers": map[string]string{"Accept": "text/html"},
								},
							},
						})
						select {
						case <-docContinuedCh:
						case <-req.Context().Done():
							return
						}
						send(map[string]any{"id": navID, "sessionId": navSID, "result": map[string]any{"frameId": "f1"}})
						send(map[string]any{
							"sessionId": navSID,
							"method":    "Fetch.requestPaused",
							"params": map[string]any{
								"requestId": "audit-cross",
								"request": map[string]any{
									"url":     "https://cdn.other.example/app.js",
									"headers": map[string]string{"Accept": "*/*"},
								},
							},
						})
						send(map[string]any{"sessionId": navSID, "method": "Page.loadEventFired", "params": map[string]any{}})
					}()
					continue
				}
				send(map[string]any{"id": rpc.ID, "sessionId": rpc.SessionID, "result": map[string]any{"frameId": "f1"}})
				send(map[string]any{"sessionId": rpc.SessionID, "method": "Page.loadEventFired", "params": map[string]any{}})
			case "Runtime.evaluate":
				var p struct {
					Expression string `json:"expression"`
				}
				_ = json.Unmarshal(rpc.Params, &p)
				if strings.Contains(p.Expression, "outerHTML") {
					docJSON, _ := json.Marshal(map[string]string{
						"url":  "https://first.example.com/page",
						"html": "<html><body><main><h1>OK</h1></main></body></html>",
					})
					send(map[string]any{"id": rpc.ID, "sessionId": rpc.SessionID, "result": map[string]any{"result": map[string]any{"type": "string", "value": string(docJSON)}}})
				} else {
					send(map[string]any{"id": rpc.ID, "sessionId": rpc.SessionID, "result": map[string]any{"result": map[string]any{"type": "boolean", "value": true}}})
				}
			default:
				send(map[string]any{"id": rpc.ID, "sessionId": rpc.SessionID, "result": map[string]any{}})
			}
		}
	}))
	defer srv.Close()

	r := NewMockRenderer("ws://"+strings.TrimPrefix(srv.URL, "http://"), nil, "EdgeFetchTest/2.6.0")
	defer r.Close()

	// 1. Failed initial KeepSession navigation MUST dispose the browser context and NOT retain a leaked session slot!
	_, navErr := r.Execute(context.Background(), Task{
		URL:         "https://first.example.com/page",
		KeepSession: true,
	})
	if navErr == nil {
		t.Fatal("expected initial navigation error")
	}
	r.mu.Lock()
	leakedSessions := len(r.sessions)
	r.mu.Unlock()
	mu.Lock()
	disposedAfterFail := disposedCtxs
	mu.Unlock()
	if leakedSessions != 0 || disposedAfterFail != 1 {
		t.Fatalf("failed KeepSession leaked session: sessions=%d disposed=%d", leakedSessions, disposedAfterFail)
	}

	// 2. Successful navigation with custom Headers MUST use origin-scoped CDP Fetch interception (never Network.setExtraHTTPHeaders)!
	failNavigate = false
	out, okErr := r.Execute(context.Background(), Task{
		URL:       "https://first.example.com/page",
		Headers:   map[string]string{"X-Api-Version": "2026-11"},
		WaitForMs: 20,
	})
	if okErr != nil || !strings.Contains(out.HTML, "OK") {
		t.Fatalf("expected second render to succeed: err=%v out=%+v", okErr, out)
	}
	select {
	case <-allContinuedCh:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for Fetch.continueRequest calls")
	}
	if setExtraHeaders.Load() != 0 || !fetchEnabled.Load() {
		t.Fatalf("expected setExtraHeaders=0 and fetchEnabled=true, got setExtraHeaders=%d fetchEnabled=%v", setExtraHeaders.Load(), fetchEnabled.Load())
	}
	mu.Lock()
	docHdrs := continuedHdrs["audit-doc"]
	crossOverridden := continuedHasOverride["audit-cross"]
	mu.Unlock()
	sawCustom := false
	for _, h := range docHdrs {
		if strings.EqualFold(h.Name, "X-Api-Version") && h.Value == "2026-11" {
			sawCustom = true
		}
	}
	if !sawCustom || crossOverridden {
		t.Fatalf("expected X-Api-Version on same-origin doc only: docHdrs=%+v crossOverridden=%v", docHdrs, crossOverridden)
	}
}

func TestR8TopNavAndSubresourceSecFetchSiteHeaderResidual(t *testing.T) {
	t.Parallel()
	const boundOrigin = "https://victim.example.com:443"

	// 1. Unit checks on hasPositiveSameOriginProof (Round 9 H8: positive Origin/Referer required; dead Sec-Fetch-Site clause removed):
	if hasPositiveSameOriginProof(nil, boundOrigin) || hasPositiveSameOriginProof(map[string]any{"Accept": "text/html"}, boundOrigin) {
		t.Fatal("SECURITY: missing Origin and Referer must fail closed")
	}
	if hasPositiveSameOriginProof(map[string]any{"Origin": "null", "Referer": "https://victim.example.com/start"}, boundOrigin) {
		t.Fatal("SECURITY: Origin: null must reject even with bound Referer")
	}
	if hasPositiveSameOriginProof(map[string]any{"Origin": "https://evil.example.com", "Referer": "https://victim.example.com/start"}, boundOrigin) {
		t.Fatal("SECURITY: cross-origin Origin must reject even with bound Referer")
	}
	if !hasPositiveSameOriginProof(map[string]any{"Referer": "https://victim.example.com/start"}, boundOrigin) {
		t.Fatal("expected valid bound Referer to pass hasPositiveSameOriginProof")
	}

	// 2. End-to-end Mock-CDP handleRequestPaused simulation for A -> B -> A grandchild top-level navigation
	//    and post-taint subresources.
	var (
		mu          sync.Mutex
		hasOverride = make(map[string]bool)
		sig         = make(map[string]chan struct{})
	)
	chFor := func(id string) chan struct{} {
		mu.Lock()
		defer mu.Unlock()
		c, ok := sig[id]
		if !ok {
			c = make(chan struct{})
			sig[id] = c
		}
		return c
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		conn, err := websocket.Accept(w, req, nil)
		if err != nil {
			return
		}
		defer conn.CloseNow()

		var writeMu sync.Mutex
		send := func(obj any) {
			b, _ := json.Marshal(obj)
			writeMu.Lock()
			_ = conn.Write(req.Context(), websocket.MessageText, b)
			writeMu.Unlock()
		}

		for {
			_, rawMsg, err := conn.Read(req.Context())
			if err != nil {
				return
			}
			var rpc struct {
				ID        int64           `json:"id"`
				SessionID string          `json:"sessionId"`
				Method    string          `json:"method"`
				Params    json.RawMessage `json:"params"`
			}
			if json.Unmarshal(rawMsg, &rpc) != nil {
				continue
			}

			switch rpc.Method {
			case "Target.createBrowserContext":
				send(map[string]any{"id": rpc.ID, "result": map[string]any{"browserContextId": "bc-r8"}})
			case "Target.createTarget":
				send(map[string]any{"id": rpc.ID, "result": map[string]any{"targetId": "tgt-r8"}})
			case "Target.attachToTarget":
				send(map[string]any{"id": rpc.ID, "result": map[string]any{"sessionId": "sess-r8"}})
			case "Fetch.continueRequest":
				var p struct {
					RequestID string `json:"requestId"`
				}
				var rawMap map[string]json.RawMessage
				_ = json.Unmarshal(rpc.Params, &p)
				_ = json.Unmarshal(rpc.Params, &rawMap)
				_, overridden := rawMap["headers"]
				mu.Lock()
				hasOverride[p.RequestID] = overridden
				mu.Unlock()
				send(map[string]any{"id": rpc.ID, "sessionId": rpc.SessionID, "result": map[string]any{}})
				select {
				case <-chFor(p.RequestID):
				default:
					close(chFor(p.RequestID))
				}
			case "Page.navigate":
				navID := rpc.ID
				navSID := rpc.SessionID
				go func() {
					// Initial harness top-level navigation.
					send(map[string]any{
						"sessionId": navSID,
						"method":    "Fetch.requestPaused",
						"params": map[string]any{
							"requestId":    "harness-doc",
							"frameId":      "main-f",
							"resourceType": "Document",
							"request": map[string]any{
								"url":     "https://victim.example.com/start",
								"headers": map[string]string{"Accept": "text/html"},
							},
						},
					})
					<-chFor("harness-doc")
					send(map[string]any{
						"sessionId": navSID,
						"method":    "Page.frameNavigated",
						"params":    map[string]any{"frame": map[string]any{"id": "main-f", "url": "https://victim.example.com/start", "securityOrigin": "https://victim.example.com"}},
					})

					// Positive control: legitimate main-frame subresource Fetch with Referer == boundOrigin.
					send(map[string]any{
						"sessionId": navSID,
						"method":    "Fetch.requestPaused",
						"params": map[string]any{
							"requestId":    "legit-main-subresource",
							"frameId":      "main-f",
							"resourceType": "Fetch",
							"request": map[string]any{
								"url": "https://victim.example.com/api/account",
								"headers": map[string]string{
									"Accept":  "application/json",
									"Referer": "https://victim.example.com/start",
								},
							},
						},
					})
					<-chFor("legit-main-subresource")

					// Uninjected subframe Document loads (evil.other.test/mid), then A -> B -> A grandchild top-nav attempts:
					send(map[string]any{
						"sessionId": navSID,
						"method":    "Fetch.requestPaused",
						"params": map[string]any{
							"requestId":    "uninjected-mid-subdoc",
							"frameId":      "mid-f",
							"resourceType": "Document",
							"request": map[string]any{
								"url":     "https://evil.other.test/mid",
								"headers": map[string]string{"Accept": "text/html", "Referer": "https://victim.example.com/start"},
							},
						},
					})
					<-chFor("uninjected-mid-subdoc")
					send(map[string]any{
						"sessionId": navSID,
						"method":    "Page.frameNavigated",
						"params":    map[string]any{"frame": map[string]any{"id": "mid-f", "parentId": "main-f", "url": "https://evil.other.test/mid", "securityOrigin": "https://evil.other.test"}},
					})
					send(map[string]any{
						"sessionId": navSID,
						"method":    "Page.frameNavigated",
						"params":    map[string]any{"frame": map[string]any{"id": "gc-f", "parentId": "mid-f", "url": "https://victim.example.com/grandchild", "securityOrigin": "https://victim.example.com"}},
					})
					send(map[string]any{
						"sessionId": navSID,
						"method":    "Fetch.requestPaused",
						"params": map[string]any{
							"requestId":    "main-top-nav-after-uninjected-subdoc",
							"frameId":      "main-f",
							"resourceType": "Document",
							"request": map[string]any{
								"url": "https://victim.example.com/steal-after-subdoc",
								"headers": map[string]string{
									"Accept":  "text/html",
									"Referer": "https://victim.example.com/grandchild",
								},
							},
						},
					})
					<-chFor("main-top-nav-after-uninjected-subdoc")

					// Post-taint subresource on main-f MUST also be blocked once main-f saw an uninjected Document navigation!
					send(map[string]any{
						"sessionId": navSID,
						"method":    "Fetch.requestPaused",
						"params": map[string]any{
							"requestId":    "post-taint-sub-fetch",
							"frameId":      "main-f",
							"resourceType": "Fetch",
							"request": map[string]any{
								"url": "https://victim.example.com/api/secret-after-taint",
								"headers": map[string]string{
									"Origin":  "https://victim.example.com",
									"Referer": "https://victim.example.com/start",
								},
							},
						},
					})
					<-chFor("post-taint-sub-fetch")

					send(map[string]any{"id": navID, "sessionId": navSID, "result": map[string]any{"frameId": "main-f"}})
					send(map[string]any{"sessionId": navSID, "method": "Page.loadEventFired", "params": map[string]any{}})
				}()
			case "Runtime.evaluate":
				docJSON, _ := json.Marshal(map[string]string{
					"url":  "https://victim.example.com/start",
					"html": "<html><body><main><h1>OK</h1></main></body></html>",
				})
				send(map[string]any{"id": rpc.ID, "sessionId": rpc.SessionID, "result": map[string]any{"result": map[string]any{"type": "string", "value": string(docJSON)}}})
			default:
				send(map[string]any{"id": rpc.ID, "sessionId": rpc.SessionID, "result": map[string]any{}})
			}
		}
	}))
	defer srv.Close()

	r := NewMockRenderer("ws://"+strings.TrimPrefix(srv.URL, "http://"), nil, "EdgeFetchTest/2.7.4")
	defer r.Close()

	if _, err := r.Execute(context.Background(), Task{
		URL:       "https://victim.example.com/start",
		Headers:   map[string]string{"Authorization": "Bearer TOP_SECRET_R8"},
		WaitForMs: 20,
	}); err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	for _, wantAllowed := range []string{"harness-doc", "legit-main-subresource"} {
		if !hasOverride[wantAllowed] {
			t.Fatalf("expected %q to receive custom headers, got %+v", wantAllowed, hasOverride)
		}
	}
	for _, wantDenied := range []string{
		"uninjected-mid-subdoc",
		"main-top-nav-after-uninjected-subdoc",
		"post-taint-sub-fetch",
	} {
		if hasOverride[wantDenied] {
			t.Fatalf("SECURITY (R8/R9 Header Residual): %q leaked custom headers! got %+v", wantDenied, hasOverride)
		}
	}
}

func TestR8LiveChromeNestedGrandchildTopNavBlocked(t *testing.T) {
	t.Parallel()
	bin := FindChromeBinary()
	if bin == "" {
		t.Skip("no headless Chromium/Chrome binary installed; skipping live R8 nested grandchild top-nav test")
	}
	acquireLiveChromeSlot(t)

	type hit struct {
		Path string
		Auth string
		SFS  string
		Ref  string
	}
	var (
		mu   sync.Mutex
		hits []hit
	)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits = append(hits, hit{
			Path: r.URL.Path,
			Auth: r.Header.Get("Authorization"),
			SFS:  r.Header.Get("Sec-Fetch-Site"),
			Ref:  r.Header.Get("Referer"),
		})
		mu.Unlock()
		hostOnly := r.Host
		if h, _, err := net.SplitHostPort(r.Host); err == nil {
			hostOnly = h
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if strings.EqualFold(hostOnly, "evil.other.test") {
			_, _ = w.Write([]byte(`<!doctype html><html><body><iframe src="https://victim.example.com/grandchild"></iframe></body></html>`))
			return
		}
		switch r.URL.Path {
		case "/start":
			_, _ = w.Write([]byte(`<!doctype html><html><body><iframe src="https://evil.other.test/mid"></iframe></body></html>`))
		case "/grandchild":
			_, _ = w.Write([]byte(`<!doctype html><html><body><script>top.location = 'https://victim.example.com/bounced-top';</script></body></html>`))
		case "/bounced-top":
			_, _ = w.Write([]byte(`<!doctype html><html><body><img src="/api/post-bounce-probe"><main id="bounced-done">Bounced</main></body></html>`))
		case "/api/post-bounce-probe":
			w.Header().Set("Content-Type", "image/gif")
			_, _ = w.Write([]byte("GIF89a\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00\xff\xff\xff!\xf9\x04\x01\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;"))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	srvAddr := srv.Listener.Addr().String()
	r := NewRenderer(bin, func(u *url.URL) error { return nil }, "EdgeFetchTest/2.7.3", 1, nil)
	enableNoSandboxOnRestrictedLinuxHost(r)
	r.extraFlags = []string{"--ignore-certificate-errors"}
	r.proxyDial = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, srvAddr)
	}
	defer r.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	out, err := r.Execute(ctx, Task{
		URL:          "https://victim.example.com/start",
		Headers:      map[string]string{"Authorization": "Bearer R8_LIVE_TOP_SECRET"},
		WaitSelector: "#bounced-done",
		WaitForMs:    500,
	})
	if err != nil {
		t.Fatalf("live Chrome Execute failed: %v", err)
	}
	if !strings.Contains(out.HTML, "Bounced") {
		t.Fatalf("expected grandchild top.location navigation to complete, got HTML=%q", out.HTML)
	}

	mu.Lock()
	recorded := append([]hit(nil), hits...)
	mu.Unlock()

	sawStart := false
	sawBounced := false
	for _, h := range recorded {
		if h.Path == "/start" {
			sawStart = true
			if h.Auth != "Bearer R8_LIVE_TOP_SECRET" {
				t.Fatalf("expected /start to carry Authorization, got %+v", h)
			}
			continue
		}
		if h.Path == "/bounced-top" {
			sawBounced = true
		}
		if h.Auth != "" {
			t.Fatalf("SECURITY (R8 Live A->B->A Top-Nav): caller Authorization leaked on %s! hit=%+v", h.Path, h)
		}
	}
	if !sawStart || !sawBounced {
		t.Fatalf("expected both /start and /bounced-top hits, got %+v", recorded)
	}
}

func TestR9H8All15TaintAndOriginProofScenariosMockAndLive(t *testing.T) {
	t.Parallel()
	// Part A: Deterministic Mock-CDP harness exercising all 15 Round 9 H8 scenarios across isolated sessions.
	runScenario := func(t *testing.T, name string, emit func(navSID string, send func(any), waitCont func(string))) map[string]bool {
		t.Helper()
		var (
			mu          sync.Mutex
			hasOverride = make(map[string]bool)
			sig         = make(map[string]chan struct{})
		)
		chFor := func(id string) chan struct{} {
			mu.Lock()
			defer mu.Unlock()
			c, ok := sig[id]
			if !ok {
				c = make(chan struct{})
				sig[id] = c
			}
			return c
		}
		waitCont := func(id string) {
			select {
			case <-chFor(id):
			case <-time.After(3 * time.Second):
				t.Errorf("[%s] timed out waiting for Fetch.continueRequest(%q)", name, id)
			}
		}

		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			conn, err := websocket.Accept(w, req, nil)
			if err != nil {
				return
			}
			defer conn.CloseNow()
			var writeMu sync.Mutex
			send := func(obj any) {
				b, _ := json.Marshal(obj)
				writeMu.Lock()
				_ = conn.Write(req.Context(), websocket.MessageText, b)
				writeMu.Unlock()
			}
			for {
				_, rawMsg, err := conn.Read(req.Context())
				if err != nil {
					return
				}
				var rpc struct {
					ID        int64           `json:"id"`
					SessionID string          `json:"sessionId"`
					Method    string          `json:"method"`
					Params    json.RawMessage `json:"params"`
				}
				if json.Unmarshal(rawMsg, &rpc) != nil {
					continue
				}
				switch rpc.Method {
				case "Target.createBrowserContext":
					send(map[string]any{"id": rpc.ID, "result": map[string]any{"browserContextId": "bc-" + name}})
				case "Target.createTarget":
					send(map[string]any{"id": rpc.ID, "result": map[string]any{"targetId": "tgt-" + name}})
				case "Target.attachToTarget":
					send(map[string]any{"id": rpc.ID, "result": map[string]any{"sessionId": "sid-" + name}})
				case "Fetch.continueRequest":
					var p struct {
						RequestID string `json:"requestId"`
					}
					var rawMap map[string]json.RawMessage
					_ = json.Unmarshal(rpc.Params, &p)
					_ = json.Unmarshal(rpc.Params, &rawMap)
					_, overridden := rawMap["headers"]
					mu.Lock()
					hasOverride[p.RequestID] = overridden
					mu.Unlock()
					send(map[string]any{"id": rpc.ID, "sessionId": rpc.SessionID, "result": map[string]any{}})
					select {
					case <-chFor(p.RequestID):
					default:
						close(chFor(p.RequestID))
					}
				case "Page.navigate":
					navID := rpc.ID
					navSID := rpc.SessionID
					go func() {
						// Initial harness Document navigation to https://bound.example.com/start
						send(map[string]any{
							"sessionId": navSID,
							"method":    "Fetch.requestPaused",
							"params": map[string]any{
								"requestId":    "init-doc",
								"frameId":      "main-f",
								"resourceType": "Document",
								"request": map[string]any{
									"url":     "https://bound.example.com/start",
									"headers": map[string]string{"Accept": "text/html"},
								},
							},
						})
						waitCont("init-doc")
						send(map[string]any{
							"sessionId": navSID,
							"method":    "Page.frameNavigated",
							"params":    map[string]any{"frame": map[string]any{"id": "main-f", "url": "https://bound.example.com/start", "securityOrigin": "https://bound.example.com"}},
						})
						emit(navSID, send, waitCont)
						send(map[string]any{"id": navID, "sessionId": navSID, "result": map[string]any{"frameId": "main-f"}})
						send(map[string]any{"sessionId": navSID, "method": "Page.loadEventFired", "params": map[string]any{}})
					}()
				case "Runtime.evaluate":
					docJSON, _ := json.Marshal(map[string]string{
						"url":  "https://bound.example.com/start",
						"html": "<html><body><main>ok</main></body></html>",
					})
					send(map[string]any{"id": rpc.ID, "sessionId": rpc.SessionID, "result": map[string]any{"result": map[string]any{"type": "string", "value": string(docJSON)}}})
				default:
					send(map[string]any{"id": rpc.ID, "sessionId": rpc.SessionID, "result": map[string]any{}})
				}
			}
		}))
		defer srv.Close()

		r := NewMockRenderer("ws://"+strings.TrimPrefix(srv.URL, "http://"), nil, "EdgeFetchTest/2.7.4")
		defer r.Close()
		if _, err := r.Execute(context.Background(), Task{
			URL:       "https://bound.example.com/start",
			Headers:   map[string]string{"Authorization": "Bearer R9_SECRET"},
			WaitForMs: 15,
		}); err != nil {
			t.Fatalf("[%s] Execute failed: %v", name, err)
		}
		mu.Lock()
		defer mu.Unlock()
		return hasOverride
	}

	pause := func(navSID, id, frameID, resType, reqURL string, hdrs map[string]string) map[string]any {
		return map[string]any{
			"sessionId": navSID,
			"method":    "Fetch.requestPaused",
			"params": map[string]any{
				"requestId":    id,
				"frameId":      frameID,
				"resourceType": resType,
				"request":      map[string]any{"url": reqURL, "headers": hdrs},
			},
		}
	}

	scenarios := []struct {
		name string
		emit func(navSID string, send func(any), waitCont func(string))
		deny []string
	}{
		{
			name: "01_form_submit_post_and_post_submit_subresource",
			emit: func(sid string, send func(any), wc func(string)) {
				send(pause(sid, "form-post", "main-f", "Document", "https://bound.example.com/form-sink", map[string]string{"Origin": "https://bound.example.com", "Referer": "https://bound.example.com/start"}))
				wc("form-post")
				send(pause(sid, "after-form-xhr", "main-f", "XHR", "https://bound.example.com/api/after", map[string]string{"Referer": "https://bound.example.com/form-sink"}))
				wc("after-form-xhr")
			},
			deny: []string{"form-post", "after-form-xhr"},
		},
		{
			name: "02_form_submit_get",
			emit: func(sid string, send func(any), wc func(string)) {
				send(pause(sid, "form-get", "main-f", "Document", "https://bound.example.com/search?q=leak", map[string]string{"Referer": "https://bound.example.com/start"}))
				wc("form-get")
			},
			deny: []string{"form-get"},
		},
		{
			name: "03_location_reload",
			emit: func(sid string, send func(any), wc func(string)) {
				send(pause(sid, "reload-doc", "main-f", "Document", "https://bound.example.com/start", map[string]string{"Referer": "https://bound.example.com/start"}))
				wc("reload-doc")
				send(pause(sid, "after-reload-fetch", "main-f", "Fetch", "https://bound.example.com/api/me", map[string]string{"Referer": "https://bound.example.com/start"}))
				wc("after-reload-fetch")
			},
			deny: []string{"reload-doc", "after-reload-fetch"},
		},
		{
			name: "04_history_back_bfcache_commit",
			emit: func(sid string, send func(any), wc func(string)) {
				send(map[string]any{
					"sessionId": sid,
					"method":    "Page.frameNavigated",
					"params":    map[string]any{"frame": map[string]any{"id": "main-f", "url": "https://bound.example.com/prev-history", "securityOrigin": "https://bound.example.com"}},
				})
				send(pause(sid, "after-history-fetch", "main-f", "Fetch", "https://bound.example.com/api/history-leak", map[string]string{"Referer": "https://bound.example.com/prev-history"}))
				wc("after-history-fetch")
			},
			deny: []string{"after-history-fetch"},
		},
		{
			name: "05_meta_refresh_navigation",
			emit: func(sid string, send func(any), wc func(string)) {
				send(pause(sid, "meta-refresh-doc", "main-f", "Document", "https://bound.example.com/meta-target", map[string]string{"Referer": "https://bound.example.com/start"}))
				wc("meta-refresh-doc")
			},
			deny: []string{"meta-refresh-doc"},
		},
		{
			name: "06_srcdoc_iframe_subresource_with_parent_referer",
			emit: func(sid string, send func(any), wc func(string)) {
				send(map[string]any{
					"sessionId": sid,
					"method":    "Page.frameAttached",
					"params":    map[string]any{"frameId": "srcdoc-f", "parentFrameId": "main-f"},
				})
				send(pause(sid, "srcdoc-img", "srcdoc-f", "Image", "https://bound.example.com/api/srcdoc-secret", map[string]string{"Referer": "https://bound.example.com/start"}))
				wc("srcdoc-img")
				send(pause(sid, "srcdoc-top-form", "main-f", "Document", "https://bound.example.com/top-sink", map[string]string{"Referer": "https://bound.example.com/start"}))
				wc("srcdoc-top-form")
			},
			deny: []string{"srcdoc-img", "srcdoc-top-form"},
		},
		{
			name: "07_blob_top_frame_navigation_and_fetch",
			emit: func(sid string, send func(any), wc func(string)) {
				send(map[string]any{
					"sessionId": sid,
					"method":    "Page.frameNavigated",
					"params":    map[string]any{"frame": map[string]any{"id": "main-f", "url": "blob:https://bound.example.com/uuid-1", "securityOrigin": "https://bound.example.com"}},
				})
				send(pause(sid, "blob-top-post", "main-f", "Fetch", "https://bound.example.com/api/blob-leak", map[string]string{"Origin": "https://bound.example.com"}))
				wc("blob-top-post")
			},
			deny: []string{"blob-top-post"},
		},
		{
			name: "08_blob_worker_or_blob_documentURL_post",
			emit: func(sid string, send func(any), wc func(string)) {
				send(map[string]any{
					"sessionId": sid,
					"method":    "Network.requestWillBeSent",
					"params":    map[string]any{"requestId": "net-blob-1", "documentURL": "blob:https://bound.example.com/worker-uuid"},
				})
				send(map[string]any{
					"sessionId": sid,
					"method":    "Fetch.requestPaused",
					"params": map[string]any{
						"requestId":    "blob-worker-fetch",
						"networkId":    "net-blob-1",
						"frameId":      "main-f",
						"resourceType": "Fetch",
						"request":      map[string]any{"url": "https://bound.example.com/api/worker-leak", "headers": map[string]string{"Origin": "https://bound.example.com"}},
					},
				})
				wc("blob-worker-fetch")
				send(pause(sid, "empty-frame-worker", "", "Fetch", "https://bound.example.com/api/sw-leak", map[string]string{"Origin": "https://bound.example.com"}))
				wc("empty-frame-worker")
			},
			deny: []string{"blob-worker-fetch", "empty-frame-worker"},
		},
		{
			name: "09_data_iframe_and_about_blank_child_frame",
			emit: func(sid string, send func(any), wc func(string)) {
				send(map[string]any{
					"sessionId": sid,
					"method":    "Page.frameAttached",
					"params":    map[string]any{"frameId": "blank-f", "parentFrameId": "main-f"},
				})
				send(pause(sid, "blank-child-fetch", "blank-f", "Fetch", "https://bound.example.com/api/blank-leak", map[string]string{"Origin": "https://bound.example.com", "Referer": "https://bound.example.com/start"}))
				wc("blank-child-fetch")
				send(map[string]any{
					"sessionId": sid,
					"method":    "Page.frameNavigated",
					"params":    map[string]any{"frame": map[string]any{"id": "data-f", "parentId": "main-f", "url": "data:text/html,hi", "securityOrigin": "://"}},
				})
				send(pause(sid, "data-child-fetch", "data-f", "Image", "https://bound.example.com/api/data-leak", map[string]string{"Origin": "null"}))
				wc("data-child-fetch")
			},
			deny: []string{"blank-child-fetch", "data-child-fetch"},
		},
		{
			name: "10_unload_ping_and_detached_keepalive_beacon",
			emit: func(sid string, send func(any), wc func(string)) {
				send(pause(sid, "sendbeacon-ping", "main-f", "Ping", "https://bound.example.com/api/beacon", map[string]string{"Origin": "https://bound.example.com", "Referer": "https://bound.example.com/start"}))
				wc("sendbeacon-ping")
				send(map[string]any{"sessionId": sid, "method": "Page.frameDetached", "params": map[string]any{"frameId": "main-f"}})
				send(pause(sid, "detached-keepalive", "main-f", "Fetch", "https://bound.example.com/api/unload-keepalive", map[string]string{"Origin": "https://bound.example.com", "Referer": "https://bound.example.com/start"}))
				wc("detached-keepalive")
			},
			deny: []string{"sendbeacon-ping", "detached-keepalive"},
		},
		{
			name: "11_subresource_missing_origin_and_referer",
			emit: func(sid string, send func(any), wc func(string)) {
				send(pause(sid, "noref-img", "main-f", "Image", "https://bound.example.com/api/noref-img", map[string]string{"Accept": "image/*"}))
				wc("noref-img")
				send(pause(sid, "noref-script", "main-f", "Script", "https://bound.example.com/api/noref-js", map[string]string{"Accept": "*/*"}))
				wc("noref-script")
			},
			deny: []string{"noref-img", "noref-script"},
		},
		{
			name: "12_http_204_no_content_taints_frame",
			emit: func(sid string, send func(any), wc func(string)) {
				send(map[string]any{
					"sessionId": sid,
					"method":    "Network.responseReceived",
					"params": map[string]any{
						"requestId": "doc-204",
						"type":      "Document",
						"frameId":   "main-f",
						"response":  map[string]any{"status": 204, "headers": map[string]string{}},
					},
				})
				send(pause(sid, "after-204-fetch", "main-f", "Fetch", "https://bound.example.com/api/after-204", map[string]string{"Referer": "https://bound.example.com/start"}))
				wc("after-204-fetch")
			},
			deny: []string{"after-204-fetch"},
		},
		{
			name: "13_download_will_begin_and_attachment_taint_frame",
			emit: func(sid string, send func(any), wc func(string)) {
				send(map[string]any{
					"sessionId": sid,
					"method":    "Page.downloadWillBegin",
					"params":    map[string]any{"frameId": "main-f"},
				})
				send(pause(sid, "after-download-fetch", "main-f", "Fetch", "https://bound.example.com/api/after-dl", map[string]string{"Referer": "https://bound.example.com/start"}))
				wc("after-download-fetch")
			},
			deny: []string{"after-download-fetch"},
		},
		{
			name: "14_same_origin_iframe_and_inherited_grandchild_taint",
			emit: func(sid string, send func(any), wc func(string)) {
				send(map[string]any{"sessionId": sid, "method": "Page.frameAttached", "params": map[string]any{"frameId": "child-1", "parentFrameId": "main-f"}})
				send(map[string]any{"sessionId": sid, "method": "Page.frameAttached", "params": map[string]any{"frameId": "grandchild-1", "parentFrameId": "child-1"}})
				send(pause(sid, "same-origin-iframe-doc", "child-1", "Document", "https://bound.example.com/embed", map[string]string{"Referer": "https://bound.example.com/start"}))
				wc("same-origin-iframe-doc")
				send(pause(sid, "grandchild-fetch", "grandchild-1", "Fetch", "https://bound.example.com/api/gc-secret", map[string]string{"Referer": "https://bound.example.com/embed"}))
				wc("grandchild-fetch")
			},
			deny: []string{"same-origin-iframe-doc", "grandchild-fetch"},
		},
		{
			name: "15_cross_origin_initiator_veto_despite_bound_referer",
			emit: func(sid string, send func(any), wc func(string)) {
				send(map[string]any{
					"sessionId": sid,
					"method":    "Fetch.requestPaused",
					"params": map[string]any{
						"requestId":    "cross-init-sub",
						"frameId":      "main-f",
						"resourceType": "Fetch",
						"initiator":    map[string]any{"url": "https://attacker.example.net/evil.js"},
						"request":      map[string]any{"url": "https://bound.example.com/api/veto", "headers": map[string]string{"Referer": "https://bound.example.com/start"}},
					},
				})
				wc("cross-init-sub")
			},
			deny: []string{"cross-init-sub"},
		},
	}

	for _, sc := range scenarios {
		got := runScenario(t, sc.name, sc.emit)
		if !got["init-doc"] {
			t.Fatalf("[%s] expected init-doc to receive caller headers", sc.name)
		}
		for _, id := range sc.deny {
			if got[id] {
				t.Fatalf("SECURITY (R9 H8 %s): %q leaked caller headers! got=%+v", sc.name, id, got)
			}
		}
	}

	// Part B: Live Headless Chrome verification of srcdoc subresources, blob: iframe, no-referrer subresources, sendBeacon, and form submit!
	bin := FindChromeBinary()
	if bin == "" {
		t.Skip("no headless Chromium/Chrome binary installed; skipping live Part B of R9 H8 test")
	}
	acquireLiveChromeSlot(t)

	var (
		liveMu     sync.Mutex
		authByPath = make(map[string][]string)
	)
	liveSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		liveMu.Lock()
		authByPath[r.URL.Path] = append(authByPath[r.URL.Path], r.Header.Get("Authorization"))
		liveMu.Unlock()
		switch r.URL.Path {
		case "/start":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write([]byte(`<!doctype html><html><body>
<iframe srcdoc="<img src='https://bound.example.com/leak-srcdoc-img'>"></iframe>
<img src="/leak-noref-img" referrerpolicy="no-referrer">
<form id="f" action="/leak-form-submit" method="POST"><input name="a" value="1"></form>
<script>
(async () => {
  await fetch('/legit-proven-fetch');
  navigator.sendBeacon('/leak-beacon', 'ping');
  const blob = new Blob(["<!doctype html><img src='https://bound.example.com/leak-blob-img'>"], { type: 'text/html' });
  const bf = document.createElement('iframe');
  bf.src = URL.createObjectURL(blob);
  document.body.appendChild(bf);
  await new Promise((r) => setTimeout(r, 250));
  document.getElementById('f').submit();
})();
</script></body></html>`))
		case "/leak-form-submit":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write([]byte(`<!doctype html><html><body><img src="/leak-after-form-sub"><main id="form-landed">Done</main></body></html>`))
		case "/legit-proven-fetch":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"ok":true}`))
		default:
			w.Header().Set("Content-Type", "image/gif")
			_, _ = w.Write([]byte("GIF89a\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00\xff\xff\xff!\xf9\x04\x01\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;"))
		}
	}))
	defer liveSrv.Close()

	liveAddr := liveSrv.Listener.Addr().String()
	rLive := NewRenderer(bin, func(*url.URL) error { return nil }, "EdgeFetchTest/2.7.4", 1, nil)
	enableNoSandboxOnRestrictedLinuxHost(rLive)
	rLive.extraFlags = []string{"--ignore-certificate-errors"}
	rLive.proxyDial = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, liveAddr)
	}
	defer rLive.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, err := rLive.Execute(ctx, Task{
		URL:          "https://bound.example.com/start",
		Headers:      map[string]string{"Authorization": "Bearer R9_LIVE_SECRET"},
		WaitSelector: "#form-landed",
		WaitForMs:    300,
	})
	if err != nil {
		t.Fatalf("live R9 Execute failed: %v", err)
	}
	if !strings.Contains(out.HTML, "Done") {
		t.Fatalf("expected form submit landing HTML, got %q", out.HTML)
	}

	liveMu.Lock()
	defer liveMu.Unlock()
	for _, wantAuthPath := range []string{"/start", "/legit-proven-fetch"} {
		vals := authByPath[wantAuthPath]
		if len(vals) == 0 {
			t.Fatalf("expected live hit on %s, got %+v", wantAuthPath, authByPath)
		}
		for _, v := range vals {
			if v != "Bearer R9_LIVE_SECRET" {
				t.Fatalf("expected Authorization on %s, got %q", wantAuthPath, v)
			}
		}
	}
	for _, leakPath := range []string{
		"/leak-srcdoc-img",
		"/leak-noref-img",
		"/leak-beacon",
		"/leak-blob-img",
		"/leak-form-submit",
		"/leak-after-form-sub",
	} {
		vals := authByPath[leakPath]
		if len(vals) == 0 {
			t.Fatalf("expected live Chrome to exercise %s, got %+v", leakPath, authByPath)
		}
		for _, v := range vals {
			if v != "" {
				t.Fatalf("SECURITY (R9 H8 Live Chrome): caller Authorization leaked on %s: %q", leakPath, v)
			}
		}
	}
}
