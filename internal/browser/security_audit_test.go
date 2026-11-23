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
	chromeBin := FindChromeBinary()
	if chromeBin == "" {
		t.Skip("Chromium/Chrome binary not installed on host; live container smoke runs in docker-multiarch CI")
	}
	allowNoSandboxInTestOnRestrictedLinuxHost(t)

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
								"requestId": "audit-doc",
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
	const boundOrigin = "https://victim.example.com:443"

	// 1. Unit checks on hasPositiveSameOriginProof, isSameOriginInitiatorHeaders & hasExplicitSameOriginSecFetchSite:
	//    Sec-Fetch-Site != "same-origin" MUST reject IMMEDIATELY even when Referer & Origin match boundOrigin!
	for _, badSFS := range []string{"cross-site", "same-site", "none", ""} {
		hdrs := map[string]any{
			"Origin":         "https://victim.example.com",
			"Referer":        "https://victim.example.com/start",
			"Sec-Fetch-Site": badSFS,
		}
		if hasPositiveSameOriginProof(hdrs, boundOrigin) {
			t.Fatalf("SECURITY: hasPositiveSameOriginProof allowed Sec-Fetch-Site=%q with bound Origin/Referer", badSFS)
		}
		if isSameOriginInitiatorHeaders(hdrs, boundOrigin) {
			t.Fatalf("SECURITY: isSameOriginInitiatorHeaders allowed Sec-Fetch-Site=%q with bound Origin/Referer", badSFS)
		}
		if hasExplicitSameOriginSecFetchSite(hdrs) {
			t.Fatalf("SECURITY: hasExplicitSameOriginSecFetchSite allowed Sec-Fetch-Site=%q", badSFS)
		}
	}
	if hasExplicitSameOriginSecFetchSite(map[string]any{"Referer": "https://victim.example.com/start"}) {
		t.Fatal("hasExplicitSameOriginSecFetchSite must return false when Sec-Fetch-Site is absent")
	}
	validSameOrigin := map[string]any{
		"Referer":        "https://victim.example.com/start",
		"Sec-Fetch-Site": "same-origin",
	}
	if !hasPositiveSameOriginProof(validSameOrigin, boundOrigin) ||
		!isSameOriginInitiatorHeaders(validSameOrigin, boundOrigin) ||
		!hasExplicitSameOriginSecFetchSite(validSameOrigin) {
		t.Fatal("expected valid Sec-Fetch-Site: same-origin + bound Referer to pass all three checks")
	}

	// 2. End-to-end Mock-CDP handleRequestPaused simulation for A -> B -> A grandchild top-level navigation
	//    and cross-site/same-site/none subresources carrying Referer: <boundOrigin>.
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
					// Initial harness top-level navigation (Sec-Fetch-Site: none is valid ONLY on harnessHop).
					send(map[string]any{
						"sessionId": navSID,
						"method":    "Fetch.requestPaused",
						"params": map[string]any{
							"requestId":    "harness-doc",
							"frameId":      "main-f",
							"resourceType": "Document",
							"request": map[string]any{
								"url":     "https://victim.example.com/start",
								"headers": map[string]string{"Accept": "text/html", "Sec-Fetch-Site": "none"},
							},
						},
					})
					<-chFor("harness-doc")
					send(map[string]any{
						"sessionId": navSID,
						"method":    "Page.frameNavigated",
						"params":    map[string]any{"frame": map[string]any{"id": "main-f", "url": "https://victim.example.com/start", "securityOrigin": "https://victim.example.com"}},
					})

					// Positive control FIRST (before any uninjected Document taints the session!):
					// Legitimate top-frame link click with Referer == boundOrigin AND Sec-Fetch-Site: same-origin.
					send(map[string]any{
						"sessionId": navSID,
						"method":    "Fetch.requestPaused",
						"params": map[string]any{
							"requestId":    "legit-top-nav-same-origin",
							"frameId":      "main-f",
							"resourceType": "Document",
							"request": map[string]any{
								"url": "https://victim.example.com/account",
								"headers": map[string]string{
									"Accept":         "text/html",
									"Referer":        "https://victim.example.com/start",
									"Sec-Fetch-Site": "same-origin",
								},
							},
						},
					})
					<-chFor("legit-top-nav-same-origin")

					// Attack 0 (Simple Tab-Taint Rule): Once an uninjected subframe Document loads (e.g. evil.other.test/mid),
					// an autonomous top-level navigation lacking Sec-Fetch-Site: same-origin is IMMEDIATELY blocked!
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

					// Attack A: Nested A -> B (cross-site) -> A grandchild executes `top.location = "https://victim.example.com/steal"`.
					// Chromium sends Referer: https://victim.example.com/child AND Sec-Fetch-Site: cross-site!
					for _, sfs := range []string{"cross-site", "same-site", "none"} {
						reqID := "main-top-nav-sfs-" + sfs
						send(map[string]any{
							"sessionId": navSID,
							"method":    "Fetch.requestPaused",
							"params": map[string]any{
								"requestId":    reqID,
								"frameId":      "main-f",
								"resourceType": "Document",
								"request": map[string]any{
									"url": "https://victim.example.com/steal-" + sfs,
									"headers": map[string]string{
										"Accept":         "text/html",
										"Referer":        "https://victim.example.com/grandchild",
										"Sec-Fetch-Site": sfs,
									},
								},
							},
						})
						<-chFor(reqID)
					}

					// Attack B: Real-Chromium A -> B -> A grandchild top-navigation where Fetch.requestPaused fires BEFORE
					// network::SetFetchMetadataHeaders (so Sec-Fetch-Site is absent in paused.Request.Headers!), testing both
					// full grandchild Referer and <meta name="referrer" content="origin"> truncated Referer!
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
							"requestId":    "main-top-nav-gc-full-ref",
							"frameId":      "main-f",
							"resourceType": "Document",
							"request": map[string]any{
								"url": "https://victim.example.com/steal-gc-ref",
								"headers": map[string]string{
									"Accept":  "text/html",
									"Referer": "https://victim.example.com/grandchild",
								},
							},
						},
					})
					<-chFor("main-top-nav-gc-full-ref")
					// Reset cross-taint via simulated Page.frameDetached on gc-f after testing origin-only Referer too
					// (note: uninjected top-nav above tainted session, so even subsequent subrequests are blocked!).

					// Attack C: Subresource fetch with Referer/Origin == boundOrigin but Sec-Fetch-Site in {cross-site, same-site, none}.
					for _, sfs := range []string{"cross-site", "same-site", "none"} {
						reqID := "sub-fetch-sfs-" + sfs
						send(map[string]any{
							"sessionId": navSID,
							"method":    "Fetch.requestPaused",
							"params": map[string]any{
								"requestId":    reqID,
								"frameId":      "main-f",
								"resourceType": "Fetch",
								"request": map[string]any{
									"url": "https://victim.example.com/api/secret-" + sfs,
									"headers": map[string]string{
										"Origin":         "https://victim.example.com",
										"Referer":        "https://victim.example.com/grandchild",
										"Sec-Fetch-Site": sfs,
									},
								},
							},
						})
						<-chFor(reqID)
					}

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

	r := NewMockRenderer("ws://"+strings.TrimPrefix(srv.URL, "http://"), nil, "EdgeFetchTest/2.7.2")
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
	for _, wantAllowed := range []string{"harness-doc", "legit-top-nav-same-origin"} {
		if !hasOverride[wantAllowed] {
			t.Fatalf("expected %q to receive custom headers, got %+v", wantAllowed, hasOverride)
		}
	}
	for _, wantDenied := range []string{
		"uninjected-mid-subdoc",
		"main-top-nav-after-uninjected-subdoc",
		"main-top-nav-sfs-cross-site",
		"main-top-nav-sfs-same-site",
		"main-top-nav-sfs-none",
		"main-top-nav-gc-full-ref",
		"sub-fetch-sfs-cross-site",
		"sub-fetch-sfs-same-site",
		"sub-fetch-sfs-none",
	} {
		if hasOverride[wantDenied] {
			t.Fatalf("SECURITY (R8 Header Residual): %q leaked custom headers! got %+v", wantDenied, hasOverride)
		}
	}
}

func TestR8LiveChromeNestedGrandchildTopNavBlocked(t *testing.T) {
	bin := FindChromeBinary()
	if bin == "" {
		t.Skip("no headless Chromium/Chrome binary installed; skipping live R8 nested grandchild top-nav test")
	}
	allowNoSandboxInTestOnRestrictedLinuxHost(t)

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
	r := NewRenderer(bin, func(u *url.URL) error { return nil }, "EdgeFetchTest/2.7.2", 1, nil)
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
