package browser

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bartrumb/edgefetch/v2/internal/otel"
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
		errors.New("[23:23:ERROR:sandbox_linux.cc(380)] InitializeSandbox() called with multiple threads in process gpu-process."),
		errors.New("[9:9:ERROR:process_singleton_posix.cc(340)] Failed to create /data/namespace sandbox/SingletonLock: No space left on device"),
	} {
		if isSandboxStartupFailure(nonSandbox) {
			t.Fatalf("SECURITY: expected isSandboxStartupFailure(%v) == false so timeouts/unrelated errors never downgrade to --no-sandbox", nonSandbox)
		}
	}
}

func TestResumedNavigateOriginScopingAndCrossOrigin302HeaderStripping(t *testing.T) {
	var (
		mu          sync.Mutex
		hasOverride = make(map[string]bool)
		gotValue    = make(map[string]string)
	)
	waitForID := func(id string) {
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			mu.Lock()
			_, seen := hasOverride[id]
			mu.Unlock()
			if seen {
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
		t.Fatalf("timed out waiting for Fetch.continueRequest(%q)", id)
	}

	var curDocURL atomic.Value
	curDocURL.Store("https://first.test/start")

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

		fetchEnabled := false
		continuedCh := make(map[string]chan struct{})
		var chMu sync.Mutex
		sig := func(id string) chan struct{} {
			chMu.Lock()
			defer chMu.Unlock()
			ch, ok := continuedCh[id]
			if !ok {
				ch = make(chan struct{})
				continuedCh[id] = ch
			}
			return ch
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
			switch req.Method {
			case "Target.createBrowserContext":
				send(map[string]any{"id": req.ID, "result": map[string]any{"browserContextId": "bc-r5"}})
			case "Target.createTarget":
				send(map[string]any{"id": req.ID, "result": map[string]any{"targetId": "tgt-r5"}})
			case "Target.attachToTarget":
				send(map[string]any{"id": req.ID, "result": map[string]any{"sessionId": "s-r5"}})
			case "Fetch.enable":
				fetchEnabled = true
				send(map[string]any{"id": req.ID, "sessionId": req.SessionID, "result": map[string]any{}})
			case "Fetch.continueRequest":
				var p struct {
					RequestID string             `json:"requestId"`
					Headers   []fetchHeaderEntry `json:"headers"`
				}
				var rawMap map[string]json.RawMessage
				_ = json.Unmarshal(req.Params, &p)
				_ = json.Unmarshal(req.Params, &rawMap)
				_, overridden := rawMap["headers"]
				val := ""
				for _, h := range p.Headers {
					if strings.EqualFold(h.Name, "Authorization") {
						val = h.Value
					}
				}
				mu.Lock()
				hasOverride[p.RequestID] = overridden
				gotValue[p.RequestID] = val
				mu.Unlock()
				send(map[string]any{"id": req.ID, "sessionId": req.SessionID, "result": map[string]any{}})
				select {
				case <-sig(p.RequestID):
				default:
					close(sig(p.RequestID))
				}
			case "Page.navigate":
				var np struct {
					URL string `json:"url"`
				}
				_ = json.Unmarshal(req.Params, &np)
				navID := req.ID
				navSID := req.SessionID
				if !fetchEnabled {
					curDocURL.Store(np.URL)
					send(map[string]any{"id": navID, "sessionId": navSID, "result": map[string]any{"frameId": "main-f"}})
					send(map[string]any{"sessionId": navSID, "method": "Page.loadEventFired", "params": map[string]any{}})
					continue
				}
				go func() {
					if strings.Contains(np.URL, "second.test") {
						curDocURL.Store("https://second.test/app")
						send(map[string]any{
							"sessionId": navSID,
							"method":    "Fetch.requestPaused",
							"params": map[string]any{
								"requestId":    "resumed-second-doc",
								"frameId":      "main-f",
								"resourceType": "Document",
								"request": map[string]any{
									"url":     "https://second.test/app",
									"headers": map[string]string{"Accept": "text/html"},
								},
							},
						})
						<-sig("resumed-second-doc")
						send(map[string]any{"id": navID, "sessionId": navSID, "result": map[string]any{"frameId": "main-f"}})
						// Subresource back to first.test MUST NOT receive second.test's secret!
						send(map[string]any{
							"sessionId": navSID,
							"method":    "Fetch.requestPaused",
							"params": map[string]any{
								"requestId":    "resumed-first-img",
								"frameId":      "main-f",
								"resourceType": "Image",
								"request": map[string]any{
									"url":     "https://first.test/logo.png",
									"headers": map[string]string{"Accept": "image/*"},
								},
							},
						})
						send(map[string]any{"sessionId": navSID, "method": "Page.loadEventFired", "params": map[string]any{}})
						return
					}
					// 302 cross-origin redirect scenario: victim.test/redir -> attacker.test/landing -> attacker JS fetches victim.test/api/transfer
					curDocURL.Store("https://attacker.test/landing")
					send(map[string]any{
						"sessionId": navSID,
						"method":    "Fetch.requestPaused",
						"params": map[string]any{
							"requestId":    "redir-hop0-victim",
							"frameId":      "main-f",
							"resourceType": "Document",
							"request": map[string]any{
								"url":     "https://victim.test/redir",
								"headers": map[string]string{"Accept": "text/html"},
							},
						},
					})
					<-sig("redir-hop0-victim")
					send(map[string]any{
						"sessionId": navSID,
						"method":    "Fetch.requestPaused",
						"params": map[string]any{
							"requestId":           "redir-hop1-attacker",
							"frameId":             "main-f",
							"resourceType":        "Document",
							"redirectStatusCode":  302,
							"redirectedRequestId": "redir-hop0-victim",
							"request": map[string]any{
								"url":     "https://attacker.test/landing",
								"headers": map[string]string{"Accept": "text/html"},
							},
						},
					})
					<-sig("redir-hop1-attacker")
					send(map[string]any{"id": navID, "sessionId": navSID, "result": map[string]any{"frameId": "main-f"}})
					send(map[string]any{
						"sessionId": navSID,
						"method":    "Fetch.requestPaused",
						"params": map[string]any{
							"requestId":    "confused-deputy-post",
							"frameId":      "main-f",
							"resourceType": "Fetch",
							"request": map[string]any{
								"url": "https://victim.test/api/transfer",
								"headers": map[string]string{
									"Origin":         "https://attacker.test",
									"Sec-Fetch-Site": "cross-site",
								},
							},
						},
					})
					send(map[string]any{"sessionId": navSID, "method": "Page.loadEventFired", "params": map[string]any{}})
				}()
			case "Runtime.evaluate":
				u, _ := curDocURL.Load().(string)
				docJSON, _ := json.Marshal(map[string]string{
					"url":  u,
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

	// 1. Resumed session with URL=="" + Headers + navigate action updates initialOrigin to second.test (and fails closed on invalid port :0).
	out1, err := r.Execute(context.Background(), Task{
		URL:         "https://first.test/start",
		KeepSession: true,
		WaitForMs:   15,
	})
	if err != nil || out1.SessionID == "" {
		t.Fatalf("Turn 1 failed: err=%v out=%+v", err, out1)
	}
	if _, badErr := r.Execute(context.Background(), Task{
		SessionID:   out1.SessionID,
		URL:         "https://second.test:0/bad",
		Headers:     map[string]string{"Authorization": "Bearer never-send"},
		KeepSession: true,
	}); badErr == nil {
		t.Fatal("expected non-canonical port :0 with custom Headers to fail closed")
	}
	if _, err := r.Execute(context.Background(), Task{
		SessionID: out1.SessionID,
		Headers:   map[string]string{"Authorization": "Bearer secret-second"},
		Actions:   []InteractAction{{Type: "navigate", URL: "https://second.test/app", WaitMs: 15}},
	}); err != nil {
		t.Fatalf("Turn 2 resumed navigate failed: %v", err)
	}
	waitForID("resumed-second-doc")
	waitForID("resumed-first-img")

	mu.Lock()
	secondGot := gotValue["resumed-second-doc"]
	firstLeaked := hasOverride["resumed-first-img"]
	mu.Unlock()
	if secondGot != "Bearer secret-second" || firstLeaked {
		t.Fatalf("expected headers scoped strictly to resumed navigate origin second.test (secondGot=%q, firstLeaked=%v)", secondGot, firstLeaked)
	}

	// 2. Top-level 302 redirect away from victim.test -> attacker.test strips headers on subsequent subrequests back to victim.test!
	if _, err := r.Execute(context.Background(), Task{
		URL:       "https://victim.test/redir",
		Headers:   map[string]string{"Authorization": "Bearer secret-victim"},
		WaitForMs: 20,
	}); err != nil {
		t.Fatalf("302 redirect Execute failed: %v", err)
	}
	waitForID("confused-deputy-post")

	mu.Lock()
	hop0Got := gotValue["redir-hop0-victim"]
	hop1Overridden := hasOverride["redir-hop1-attacker"]
	deputyOverridden := hasOverride["confused-deputy-post"]
	mu.Unlock()
	if hop0Got != "Bearer secret-victim" || hop1Overridden || deputyOverridden {
		t.Fatalf("SECURITY: cross-origin 302 leaked ambient headers (hop0=%q, hop1=%v, deputy=%v)", hop0Got, hop1Overridden, deputyOverridden)
	}
}

func TestRemoteDebuggingPipeExposesZeroListeningTCPPortsIfChromeInstalled(t *testing.T) {
	args := buildChromiumLaunchArgsWithSandbox("127.0.0.1:8888", "/tmp/ef-prof", true)
	var sawPipe, sawPort bool
	for _, a := range args {
		if a == "--remote-debugging-pipe" {
			sawPipe = true
		}
		if strings.HasPrefix(a, "--remote-debugging-port=") {
			sawPort = true
		}
	}
	if runtime.GOOS == "windows" {
		if sawPipe || !sawPort {
			t.Fatalf("expected --remote-debugging-port=0 on windows, got %v", args)
		}
	} else {
		if !sawPipe || sawPort {
			t.Fatalf("expected --remote-debugging-pipe (and zero --remote-debugging-port) on %s, got %v", runtime.GOOS, args)
		}
	}

	if runtime.GOOS != "linux" {
		return
	}
	bin := FindChromeBinary()
	if bin == "" {
		t.Skip("no headless Chromium/Chrome binary installed; skipping live R5-M6 pipe transport check")
	}

	r := NewRenderer(bin, func(*url.URL) error { return nil }, "EdgeFetch/2.6.2", 1, nil)
	defer r.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := r.ensureBrowser(ctx); err != nil {
		t.Fatalf("ensureBrowser via --remote-debugging-pipe failed: %v", err)
	}

	r.mu.Lock()
	pid := 0
	if r.cmd != nil && r.cmd.Process != nil {
		pid = r.cmd.Process.Pid
	}
	userDataDir := r.userDataDir
	ver := r.browserVersion
	r.mu.Unlock()

	if pid <= 0 || ver == "" {
		t.Fatalf("expected live Chromium pid and version, got pid=%d ver=%q", pid, ver)
	}
	info, err := os.Stat(userDataDir)
	if err != nil {
		t.Fatalf("stat userDataDir: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o700 {
		t.Fatalf("expected userDataDir mode 0700, got %04o", perm)
	}

	// Collect listening socket inodes from /proc/net/tcp and /proc/net/tcp6 (state 0A == TCP_LISTEN).
	listenInodes := make(map[string]string)
	for _, procNet := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		raw, err := os.ReadFile(procNet)
		if err != nil {
			continue
		}
		for idx, line := range strings.Split(string(raw), "\n") {
			if idx == 0 {
				continue
			}
			fields := strings.Fields(line)
			if len(fields) >= 10 && fields[3] == "0A" && fields[9] != "0" {
				listenInodes["socket:["+fields[9]+"]"] = fields[1]
			}
		}
	}

	// Inspect Chromium root PID and direct child PIDs to prove zero listening TCP sockets belong to Chromium.
	pids := []int{pid}
	if childrenMatches, _ := filepath.Glob("/proc/" + strconv.Itoa(pid) + "/task/*/children"); len(childrenMatches) > 0 {
		for _, cm := range childrenMatches {
			if b, err := os.ReadFile(cm); err == nil {
				for _, tok := range strings.Fields(string(b)) {
					if cpid, err := strconv.Atoi(tok); err == nil && cpid > 0 {
						pids = append(pids, cpid)
					}
				}
			}
		}
	}
	for _, checkPID := range pids {
		fdDir := "/proc/" + strconv.Itoa(checkPID) + "/fd"
		entries, err := os.ReadDir(fdDir)
		if err != nil {
			continue
		}
		for _, ent := range entries {
			target, err := os.Readlink(filepath.Join(fdDir, ent.Name()))
			if err != nil {
				continue
			}
			if localHex, listening := listenInodes[target]; listening {
				t.Fatalf("SECURITY (R5-M6): Chromium pid %d opened listening TCP socket %s (%s) under --remote-debugging-pipe!", checkPID, target, localHex)
			}
		}
	}
}

func TestMockRendererEmitsBrowserRenderChildSpan(t *testing.T) {
	var challengeMode atomic.Bool
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
			switch req.Method {
			case "Target.createBrowserContext":
				send(map[string]any{"id": req.ID, "result": map[string]any{"browserContextId": "bc-otel"}})
			case "Target.createTarget":
				send(map[string]any{"id": req.ID, "result": map[string]any{"targetId": "tgt-otel"}})
			case "Target.attachToTarget":
				send(map[string]any{"id": req.ID, "result": map[string]any{"sessionId": "s-otel"}})
			case "Page.navigate":
				send(map[string]any{"id": req.ID, "sessionId": req.SessionID, "result": map[string]any{"frameId": "f-otel"}})
				send(map[string]any{"sessionId": req.SessionID, "method": "Page.loadEventFired", "params": map[string]any{}})
			case "Runtime.evaluate":
				htmlBody := "<html><head><title>App</title></head><body><main>Rendered DOM</main></body></html>"
				if challengeMode.Load() {
					htmlBody = "<html><head><title>Just a moment...</title></head><body>Checking your browser before accessing</body></html>"
				}
				docJSON, _ := json.Marshal(map[string]string{
					"url":  "https://app.example.com/dashboard?token=SECRET_BROWSER_TOKEN#frag",
					"html": htmlBody,
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

	var (
		mu        sync.Mutex
		rawBodies []string
	)
	collector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		rawBodies = append(rawBodies, string(b))
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer collector.Close()

	exp := otel.NewExporterFromEnv(func(k string) string {
		if k == "OTEL_EXPORTER_OTLP_ENDPOINT" {
			return collector.URL
		}
		return ""
	}, "edgefetch-browser-test", "2.7.0", collector.Client().Transport)

	r := NewMockRenderer("ws://"+strings.TrimPrefix(cdpSrv.URL, "http://"), func(*url.URL) error { return nil }, "EdgeFetchTest/1.0")
	r.SetOtelExporter(exp)
	defer r.Close()

	parentTC := otel.TraceContext{
		TraceID: "4bf92f3577b34da6a3ce929d0e0e4736",
		SpanID:  "1122334455667788",
		Sampled: true,
	}
	ctx := otel.WithTraceContext(context.Background(), parentTC)

	// 1. Success render emits child edgefetch.browser.render span with sanitized URL.
	out, err := r.Execute(ctx, Task{
		URL:       "https://app.example.com/dashboard?token=SECRET_BROWSER_TOKEN#frag",
		WaitForMs: 10,
	})
	if err != nil || !strings.Contains(out.HTML, "Rendered DOM") {
		t.Fatalf("expected successful mock render, got out=%+v err=%v", out, err)
	}

	// 2. Error render (ErrChallengeDetected) emits status.code == 2 on edgefetch.browser.render.
	challengeMode.Store(true)
	_, chErr := r.Execute(ctx, Task{
		URL:       "https://app.example.com/blocked?api_key=SECRET_2",
		WaitForMs: 10,
	})
	if !errors.Is(chErr, ErrChallengeDetected) {
		t.Fatalf("expected ErrChallengeDetected, got %v", chErr)
	}

	// 3. Unsampled TraceContext (-00) emits 0 spans.
	challengeMode.Store(false)
	unsampledCtx := otel.WithTraceContext(context.Background(), otel.TraceContext{
		TraceID: "cccccccccccccccccccccccccccccccc",
		SpanID:  "3333333333333333",
		Sampled: false,
	})
	if _, uErr := r.Execute(unsampledCtx, Task{URL: "https://app.example.com/unsampled", WaitForMs: 10}); uErr != nil {
		t.Fatalf("unsampled execute failed: %v", uErr)
	}

	_ = exp.Close()

	mu.Lock()
	combined := strings.Join(rawBodies, "\n")
	mu.Unlock()

	if strings.Contains(combined, "SECRET_BROWSER_TOKEN") || strings.Contains(combined, "SECRET_2") || strings.Contains(combined, "#frag") || strings.Contains(combined, "cccccccccccccccccccccccccccccccc") {
		t.Fatalf("SECURITY/SAMPLING: secret or unsampled trace leaked into OTLP output:\n%s", combined)
	}
	if !strings.Contains(combined, `"edgefetch.browser.render"`) ||
		!strings.Contains(combined, `"parentSpanId":"1122334455667788"`) ||
		!strings.Contains(combined, `"https://app.example.com/dashboard"`) ||
		!strings.Contains(combined, `"code":2`) {
		t.Fatalf("expected edgefetch.browser.render parented spans with sanitized URL and error code, got:\n%s", combined)
	}
}
