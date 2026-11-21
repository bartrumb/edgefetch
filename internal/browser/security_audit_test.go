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
	if err == nil && strings.Contains(out.HTML, "TOP_SECRET_LOOPBACK_TOKEN") {
		t.Fatalf("SECURITY (H1): loopback response body leaked into rendered output")
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

	_, _ = r.Execute(ctx, Task{
		Actions: []InteractAction{{Type: "executeJavascript", Script: webrtcScript, WaitMs: 100}},
	})
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
