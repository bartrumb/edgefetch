package browser

import (
	"context"
	"encoding/json"
	"errors"
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

func TestOriginScopedExtraHeadersViaCDPFetchAndWarmBrowserRecycle(t *testing.T) {
	var (
		wsConns              atomic.Int32
		setExtraHeadersCalls atomic.Int32
		fetchEnableCalls     atomic.Int32
		continuedMu          sync.Mutex
		allFourDoneOnce      sync.Once
	)
	continued := make(map[string][]fetchHeaderEntry)
	continuedHasOverride := make(map[string]bool)
	allFourDoneCh := make(chan struct{})

	cdpSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		wsConns.Add(1)
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

		fetchEnabled := false
		var docContinuedOnce sync.Once
		docContinuedCh := make(chan struct{})

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

			switch req.Method {
			case "Network.setExtraHTTPHeaders":
				setExtraHeadersCalls.Add(1)
				send(map[string]any{"id": req.ID, "sessionId": req.SessionID, "result": map[string]any{}})

			case "Fetch.enable":
				fetchEnabled = true
				fetchEnableCalls.Add(1)
				send(map[string]any{"id": req.ID, "sessionId": req.SessionID, "result": map[string]any{}})

			case "Fetch.continueRequest":
				var p struct {
					RequestID string             `json:"requestId"`
					Headers   []fetchHeaderEntry `json:"headers"`
				}
				var rawMap map[string]json.RawMessage
				_ = json.Unmarshal(req.Params, &p)
				_ = json.Unmarshal(req.Params, &rawMap)
				_, hasHdrKey := rawMap["headers"]

				continuedMu.Lock()
				continued[p.RequestID] = p.Headers
				continuedHasOverride[p.RequestID] = hasHdrKey
				doneCount := len(continued)
				continuedMu.Unlock()

				send(map[string]any{"id": req.ID, "sessionId": req.SessionID, "result": map[string]any{}})
				if p.RequestID == "pause-doc" {
					docContinuedOnce.Do(func() { close(docContinuedCh) })
				}
				if doneCount >= 4 {
					allFourDoneOnce.Do(func() { close(allFourDoneCh) })
				}

			case "Target.createBrowserContext":
				send(map[string]any{"id": req.ID, "result": map[string]any{"browserContextId": "bc-1"}})
			case "Target.createTarget":
				send(map[string]any{"id": req.ID, "result": map[string]any{"targetId": "tgt-1"}})
			case "Target.attachToTarget":
				send(map[string]any{"id": req.ID, "result": map[string]any{"sessionId": "s-1"}})

			case "Page.navigate":
				if fetchEnabled {
					navID := req.ID
					navSID := req.SessionID
					// Real Chromium pauses the Document request BEFORE replying to Page.navigate; run in goroutine so conn.Read
					// can receive Fetch.continueRequest without deadlocking.
					go func() {
						send(map[string]any{
							"sessionId": navSID,
							"method":    "Fetch.requestPaused",
							"params": map[string]any{
								"requestId": "pause-doc",
								"request": map[string]any{
									"url":     "https://app.example.com/dashboard",
									"headers": map[string]string{"Accept": "text/html", "User-Agent": "EdgeFetchTest/1.0"},
								},
							},
						})
						send(map[string]any{
							"sessionId": navSID,
							"method":    "Fetch.requestPaused",
							"params": map[string]any{
								"requestId": "pause-cdn",
								"request": map[string]any{
									"url":     "https://cdn.thirdparty.example/sdk.js",
									"headers": map[string]string{"Accept": "*/*"},
								},
							},
						})
						select {
						case <-docContinuedCh:
						case <-r.Context().Done():
							return
						}
						send(map[string]any{"id": navID, "sessionId": navSID, "result": map[string]any{"frameId": "f-1"}})
						send(map[string]any{
							"sessionId": navSID,
							"method":    "Fetch.requestPaused",
							"params": map[string]any{
								"requestId": "pause-same-origin-xhr",
								"request": map[string]any{
									"url":     "https://APP.Example.com./api/v1/items",
									"headers": map[string]string{"Accept": "application/json"},
								},
							},
						})
						send(map[string]any{
							"sessionId": navSID,
							"method":    "Fetch.requestPaused",
							"params": map[string]any{
								"requestId": "pause-cross-xhr",
								"request": map[string]any{
									"url":     "https://telemetry.other.example/collect",
									"headers": map[string]string{"Accept": "*/*"},
								},
							},
						})
						send(map[string]any{"sessionId": navSID, "method": "Page.loadEventFired", "params": map[string]any{}})
					}()
					continue
				}
				send(map[string]any{"id": req.ID, "sessionId": req.SessionID, "result": map[string]any{"frameId": "f-1"}})
				send(map[string]any{"sessionId": req.SessionID, "method": "Page.loadEventFired", "params": map[string]any{}})

			case "Runtime.evaluate":
				docJSON, _ := json.Marshal(map[string]string{
					"url":  "https://app.example.com/dashboard",
					"html": "<html><body><main><h1>Dashboard Ready</h1></main></body></html>",
				})
				send(map[string]any{
					"id":        req.ID,
					"sessionId": req.SessionID,
					"result":    map[string]any{"result": map[string]any{"type": "string", "value": string(docJSON)}},
				})

			default:
				send(map[string]any{"id": req.ID, "sessionId": req.SessionID, "result": map[string]any{}})
			}
		}
	}))
	defer cdpSrv.Close()

	wsURL := "ws://" + strings.TrimPrefix(cdpSrv.URL, "http://")
	r := NewMockRenderer(wsURL, func(*url.URL) error { return nil }, "EdgeFetchTest/1.0")
	defer r.Close()

	// Job 1: Custom Headers -> uses Fetch.enable + Fetch.requestPaused, then recycles browser on exit.
	out1, err := r.Execute(context.Background(), Task{
		URL:       "https://app.example.com/dashboard",
		Headers:   map[string]string{"X-Tenant-ID": "tenant-42"},
		WaitForMs: 25,
	})
	if err != nil {
		t.Fatalf("Job 1 Execute failed: %v", err)
	}
	if !strings.Contains(out1.HTML, "Dashboard Ready") {
		t.Fatalf("unexpected HTML: %q", out1.HTML)
	}

	select {
	case <-allFourDoneCh:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for all 4 Fetch.continueRequest calls")
	}

	if setExtraHeadersCalls.Load() != 0 {
		t.Fatalf("R3-M6: Network.setExtraHTTPHeaders must never be called, got %d", setExtraHeadersCalls.Load())
	}
	if fetchEnableCalls.Load() != 1 {
		t.Fatalf("expected 1 Fetch.enable call, got %d", fetchEnableCalls.Load())
	}

	hasHeader := func(entries []fetchHeaderEntry, name, want string) bool {
		for _, e := range entries {
			if strings.EqualFold(e.Name, name) && e.Value == want {
				return true
			}
		}
		return false
	}

	continuedMu.Lock()
	docHdrs := continued["pause-doc"]
	xhrHdrs := continued["pause-same-origin-xhr"]
	cdnOverridden := continuedHasOverride["pause-cdn"]
	crossOverridden := continuedHasOverride["pause-cross-xhr"]
	continuedMu.Unlock()

	if !hasHeader(docHdrs, "X-Tenant-ID", "tenant-42") || !hasHeader(docHdrs, "Accept", "text/html") {
		t.Fatalf("expected main document to merge X-Tenant-ID + existing Accept, got %+v", docHdrs)
	}
	if !hasHeader(xhrHdrs, "X-Tenant-ID", "tenant-42") || !hasHeader(xhrHdrs, "Accept", "application/json") {
		t.Fatalf("expected same-origin XHR to retain X-Tenant-ID + Accept, got %+v", xhrHdrs)
	}
	if cdnOverridden || crossOverridden {
		t.Fatalf("R3-M6: cross-host requests must NOT receive extra headers (cdn=%v, cross=%v)", cdnOverridden, crossOverridden)
	}

	// Job 2 & Job 3 (no custom Headers): Job 2 must dial a fresh CDP connection (wsConns == 2),
	// and Job 3 must reuse Job 2's warm browser (wsConns stays 2).
	if _, err := r.Execute(context.Background(), Task{URL: "https://app.example.com/dashboard", WaitForMs: 10}); err != nil {
		t.Fatalf("Job 2 Execute failed: %v", err)
	}
	if wsConns.Load() != 2 {
		t.Fatalf("expected browser recycled after custom-Headers Job 1 (wsConns=%d, want 2)", wsConns.Load())
	}
	if _, err := r.Execute(context.Background(), Task{URL: "https://app.example.com/dashboard", WaitForMs: 10}); err != nil {
		t.Fatalf("Job 3 Execute failed: %v", err)
	}
	if wsConns.Load() != 2 {
		t.Fatalf("expected warm browser reused across headerless Jobs 2 & 3 (wsConns=%d, want 2)", wsConns.Load())
	}
}

func TestOriginScopedHeadersStrictSchemeHostPortAndSandboxClassifier(t *testing.T) {
	// 1. Verify canonicalURLOrigin and Fetch.requestPaused strict scheme + host + effective port scoping.
	if canonicalURLOrigin("https://Victim.Test.:443/path") != canonicalURLOrigin("https://victim.test/other") {
		t.Fatal("expected explicit :443 and trailing dot to canonicalize to https://victim.test:443")
	}
	if canonicalURLOrigin("http://victim.test:80/a") != canonicalURLOrigin("http://victim.test/b") {
		t.Fatal("expected explicit :80 to canonicalize to http://victim.test:80")
	}
	if canonicalURLOrigin("https://victim.test:50995/a") == canonicalURLOrigin("https://victim.test:50996/a") {
		t.Fatal("same hostname on different ports must NOT share canonical origin")
	}
	if canonicalURLOrigin("https://victim.test/a") == canonicalURLOrigin("http://victim.test/a") {
		t.Fatal("https vs http must NOT share canonical origin")
	}

	var (
		mu          sync.Mutex
		hasOverride = make(map[string]bool)
		allDoneOnce sync.Once
		allDoneCh   = make(chan struct{})
	)
	cdpSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

		var docDoneOnce sync.Once
		docDoneCh := make(chan struct{})

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
			switch req.Method {
			case "Target.createBrowserContext":
				send(map[string]any{"id": req.ID, "result": map[string]any{"browserContextId": "bc-p"}})
			case "Target.createTarget":
				send(map[string]any{"id": req.ID, "result": map[string]any{"targetId": "tgt-p"}})
			case "Target.attachToTarget":
				send(map[string]any{"id": req.ID, "result": map[string]any{"sessionId": "s-p"}})
			case "Fetch.continueRequest":
				var p struct {
					RequestID string `json:"requestId"`
				}
				var rawMap map[string]json.RawMessage
				_ = json.Unmarshal(req.Params, &p)
				_ = json.Unmarshal(req.Params, &rawMap)
				_, overridden := rawMap["headers"]
				mu.Lock()
				hasOverride[p.RequestID] = overridden
				n := len(hasOverride)
				mu.Unlock()
				send(map[string]any{"id": req.ID, "sessionId": req.SessionID, "result": map[string]any{}})
				if p.RequestID == "same-port-doc" {
					docDoneOnce.Do(func() { close(docDoneCh) })
				}
				if n >= 4 {
					allDoneOnce.Do(func() { close(allDoneCh) })
				}
			case "Page.navigate":
				navID := req.ID
				navSID := req.SessionID
				go func() {
					send(map[string]any{
						"sessionId": navSID,
						"method":    "Fetch.requestPaused",
						"params": map[string]any{
							"requestId": "same-port-doc",
							"request": map[string]any{
								"url":     "https://victim.test:50995/page",
								"headers": map[string]string{"Accept": "text/html"},
							},
						},
					})
					<-docDoneCh
					send(map[string]any{"id": navID, "sessionId": navSID, "result": map[string]any{"frameId": "f-p"}})
					for _, sub := range []struct{ id, url string }{
						{"same-port-trailing-dot", "https://VICTIM.test.:50995/api"},
						{"diff-port", "https://victim.test:50996/steal"},
						{"diff-scheme", "http://victim.test:50995/downgrade"},
					} {
						send(map[string]any{
							"sessionId": navSID,
							"method":    "Fetch.requestPaused",
							"params": map[string]any{
								"requestId": sub.id,
								"request": map[string]any{
									"url":     sub.url,
									"headers": map[string]string{"Accept": "*/*"},
								},
							},
						})
					}
					send(map[string]any{"sessionId": navSID, "method": "Page.loadEventFired", "params": map[string]any{}})
				}()
			case "Runtime.evaluate":
				docJSON, _ := json.Marshal(map[string]string{
					"url":  "https://victim.test:50995/page",
					"html": "<html><body><main>ok</main></body></html>",
				})
				send(map[string]any{
					"id":        req.ID,
					"sessionId": req.SessionID,
					"result":    map[string]any{"result": map[string]any{"type": "string", "value": string(docJSON)}},
				})
			default:
				send(map[string]any{"id": req.ID, "sessionId": req.SessionID, "result": map[string]any{}})
			}
		}
	}))
	defer cdpSrv.Close()

	r := NewMockRenderer("ws://"+strings.TrimPrefix(cdpSrv.URL, "http://"), func(*url.URL) error { return nil }, "EdgeFetchTest/1.0")
	defer r.Close()

	if _, err := r.Execute(context.Background(), Task{
		URL:       "https://victim.test:50995/page",
		Headers:   map[string]string{"X-Api-Key": "secret-port-50995"},
		WaitForMs: 20,
	}); err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	select {
	case <-allDoneCh:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for Fetch.continueRequest calls")
	}

	mu.Lock()
	defer mu.Unlock()
	if !hasOverride["same-port-doc"] || !hasOverride["same-port-trailing-dot"] {
		t.Fatalf("expected same-origin requests on port 50995 to receive headers: %+v", hasOverride)
	}
	if hasOverride["diff-port"] {
		t.Fatalf("SECURITY: same-hostname request on DIFFERENT port (50996 vs 50995) received task.Headers: %+v", hasOverride)
	}
	if hasOverride["diff-scheme"] {
		t.Fatalf("SECURITY: different-scheme request (http vs https) received task.Headers: %+v", hasOverride)
	}

	// 2. Verify isSandboxStartupFailure matches only genuine Linux Chromium sandbox diagnostics, never timeouts or unrelated errors.
	for _, msg := range []string{
		"[0101/000000:FATAL:zygote_host_impl_linux.cc(127)] No usable sandbox!",
		"Failed to move to new namespace: sandbox_linux.cc:374",
		"The setuid sandbox is not running as root",
		"namespace sandbox failed to initialize",
		"Running as root without --no-sandbox is not supported",
	} {
		if !isSandboxStartupFailure(errors.New(msg)) {
			t.Fatalf("expected isSandboxStartupFailure(%q) == true", msg)
		}
	}
	for _, nonSandbox := range []error{
		nil,
		context.DeadlineExceeded,
		errors.New("timed out waiting for chromium DevTools endpoint"),
		errors.New("error while loading shared libraries: libnss3.so: cannot open shared object file"),
	} {
		if isSandboxStartupFailure(nonSandbox) {
			t.Fatalf("SECURITY: expected isSandboxStartupFailure(%v) == false so timeouts/unrelated errors never downgrade to --no-sandbox", nonSandbox)
		}
	}
}
