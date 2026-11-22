package browser

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
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
									"headers": map[string]string{"Accept": "application/json", "Referer": "https://app.example.com/dashboard"},
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
									"headers": map[string]string{"Accept": "*/*", "Referer": "https://victim.test:50995/page"},
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

	// 2. Verify isSandboxStartupFailure matches only genuine Linux Chromium sandbox policy diagnostics (EPERM/EACCES),
	//    never timeouts, shared-library errors, or transient EMFILE/ENOMEM resource exhaustion in credentials.cc!
	for _, msg := range []string{
		"[0101/000000:FATAL:zygote_host_impl_linux.cc(127)] No usable sandbox!",
		"[13:13:1121/215424.490003:FATAL:content/browser/zygote_host/zygote_host_impl_linux.cc:211] Check failed: . : Operation not permitted (1)",
		"[9:9:1121/000000:FATAL:credentials.cc(131)] Check failed: . : Permission denied (13)",
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
		errors.New("[9:9:1121/000000.000000:FATAL:credentials.cc(131)] Check failed: . : Too many open files (24)"),
		errors.New("[9:9:1121/000000.000000:FATAL:sandbox_linux.cc(200)] Check failed: . : Cannot allocate memory (12)"),
	} {
		if isSandboxStartupFailure(nonSandbox) {
			t.Fatalf("SECURITY: expected isSandboxStartupFailure(%v) == false so transient/EMFILE/unrelated errors never downgrade to --no-sandbox", nonSandbox)
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

func allowNoSandboxInTestOnRestrictedLinuxHost(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "linux" {
		return
	}
	if linuxSandboxBlockedByHostPolicy() {
		t.Setenv("EDGEFETCH_ALLOW_NO_SANDBOX", "1")
		return
	}
	for _, sysctlPath := range []string{
		"/proc/sys/kernel/apparmor_restrict_unprivileged_userns",
		"/proc/sys/user/max_user_namespaces",
	} {
		raw, err := os.ReadFile(sysctlPath)
		if err != nil {
			continue
		}
		val := strings.TrimSpace(string(raw))
		if (strings.HasSuffix(sysctlPath, "apparmor_restrict_unprivileged_userns") && val == "1") ||
			(strings.HasSuffix(sysctlPath, "max_user_namespaces") && val == "0") {
			t.Setenv("EDGEFETCH_ALLOW_NO_SANDBOX", "1")
			return
		}
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
	if !sawPipe || sawPort {
		t.Fatalf("expected --remote-debugging-pipe (and zero --remote-debugging-port) on %s, got %v", runtime.GOOS, args)
	}

	if runtime.GOOS != "linux" && runtime.GOOS != "windows" {
		return
	}
	bin := FindChromeBinary()
	if bin == "" {
		t.Skip("no headless Chromium/Chrome binary installed; skipping live R6 pipe transport check")
	}
	allowNoSandboxInTestOnRestrictedLinuxHost(t)

	r := NewRenderer(bin, func(*url.URL) error { return nil }, "EdgeFetch/2.7.0", 1, nil)
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
	if runtime.GOOS != "windows" {
		if perm := info.Mode().Perm(); perm != 0o700 {
			t.Fatalf("expected userDataDir mode 0700, got %04o", perm)
		}
	}
	if _, err := os.Stat(filepath.Join(userDataDir, "DevToolsActivePort")); err == nil {
		t.Fatal("SECURITY: DevToolsActivePort file must not exist under --remote-debugging-pipe")
	}
	if runtime.GOOS == "windows" {
		out, nErr := exec.Command("netstat", "-ano", "-p", "TCP").CombinedOutput()
		if nErr == nil {
			pidStr := strconv.Itoa(pid)
			for _, l := range strings.Split(string(out), "\n") {
				f := strings.Fields(l)
				if len(f) >= 5 && f[3] == "LISTENING" && f[4] == pidStr {
					t.Fatalf("SECURITY (R6): Windows Chromium pid %d opened listening TCP socket %s under --remote-debugging-pipe!", pid, f[1])
				}
			}
		}
		return
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

func TestR6InitiatorProvenHeaderScopingAndRedirectChainProvenance(t *testing.T) {
	var (
		mu          sync.Mutex
		hasOverride = make(map[string]bool)
	)
	waitSeen := func(id string) {
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			mu.Lock()
			_, ok := hasOverride[id]
			mu.Unlock()
			if ok {
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
		t.Fatalf("timed out waiting for Fetch.continueRequest(%q)", id)
	}

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

		sig := make(map[string]chan struct{})
		var sigMu sync.Mutex
		chFor := func(id string) chan struct{} {
			sigMu.Lock()
			defer sigMu.Unlock()
			c, ok := sig[id]
			if !ok {
				c = make(chan struct{})
				sig[id] = c
			}
			return c
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
				send(map[string]any{"id": req.ID, "result": map[string]any{"browserContextId": "bc-m4"}})
			case "Target.createTarget":
				send(map[string]any{"id": req.ID, "result": map[string]any{"targetId": "tgt-m4"}})
			case "Target.attachToTarget":
				send(map[string]any{"id": req.ID, "result": map[string]any{"sessionId": "s-m4"}})
			case "Page.getFrameTree":
				send(map[string]any{
					"id":        req.ID,
					"sessionId": req.SessionID,
					"result": map[string]any{
						"frameTree": map[string]any{
							"frame": map[string]any{"id": "main-f", "url": "about:blank", "securityOrigin": "://"},
						},
					},
				})
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
				mu.Unlock()
				send(map[string]any{"id": req.ID, "sessionId": req.SessionID, "result": map[string]any{}})
				select {
				case <-chFor(p.RequestID):
				default:
					close(chFor(p.RequestID))
				}
			case "Page.navigate":
				navID := req.ID
				navSID := req.SessionID
				go func() {
					// 1. Harness navigation hop 0 -> 302 same-origin redirect hop 1 (both MUST receive headers).
					send(map[string]any{
						"sessionId": navSID,
						"method":    "Fetch.requestPaused",
						"params": map[string]any{
							"requestId":    "nav-hop0",
							"frameId":      "main-f",
							"resourceType": "Document",
							"request": map[string]any{
								"url":     "https://victim.test/login",
								"headers": map[string]string{"Accept": "text/html"},
							},
						},
					})
					<-chFor("nav-hop0")
					send(map[string]any{
						"sessionId": navSID,
						"method":    "Fetch.requestPaused",
						"params": map[string]any{
							"requestId":           "nav-hop1-sameorigin",
							"frameId":             "main-f",
							"resourceType":        "Document",
							"redirectStatusCode":  302,
							"redirectedRequestId": "nav-hop0",
							"request": map[string]any{
								"url":     "https://victim.test/app",
								"headers": map[string]string{"Accept": "text/html"},
							},
						},
					})
					<-chFor("nav-hop1-sameorigin")

					// 2. Before Page.frameNavigated commits, a no-referrer subrequest from an uncommitted/foreign frame MUST be rejected!
					send(map[string]any{
						"sessionId": navSID,
						"method":    "Fetch.requestPaused",
						"params": map[string]any{
							"requestId":    "noref-from-foreign-iframe",
							"frameId":      "evil-subframe",
							"resourceType": "Fetch",
							"request": map[string]any{
								"url":     "https://victim.test/api/delete",
								"headers": map[string]string{"Accept": "*/*"},
							},
						},
					})
					<-chFor("noref-from-foreign-iframe")

					// 3. Commit main-f on https://victim.test via Page.frameNavigated; no-referrer fetch from main-f NOW gets headers!
					send(map[string]any{
						"sessionId": navSID,
						"method":    "Page.frameNavigated",
						"params": map[string]any{
							"frame": map[string]any{
								"id":             "main-f",
								"url":            "https://victim.test/app",
								"securityOrigin": "https://victim.test",
							},
						},
					})
					send(map[string]any{
						"sessionId": navSID,
						"method":    "Fetch.requestPaused",
						"params": map[string]any{
							"requestId":    "noref-from-committed-bound-frame",
							"frameId":      "main-f",
							"resourceType": "Fetch",
							"request": map[string]any{
								"url":     "https://victim.test/api/me",
								"headers": map[string]string{"Accept": "application/json"},
							},
						},
					})
					<-chFor("noref-from-committed-bound-frame")

					// 4. Scenario 38: bound page loads 3P attacker image which 302-redirects back to victim.test/api/delete!
					//    Hop 0 (attacker) did NOT receive headers, so Hop 1 (victim) MUST NOT receive headers even with Referer=victim.test!
					send(map[string]any{
						"sessionId": navSID,
						"method":    "Fetch.requestPaused",
						"params": map[string]any{
							"requestId":    "3p-img-hop0",
							"frameId":      "main-f",
							"resourceType": "Image",
							"request": map[string]any{
								"url":     "https://attacker.test/redir",
								"headers": map[string]string{"Referer": "https://victim.test/app"},
							},
						},
					})
					<-chFor("3p-img-hop0")
					send(map[string]any{
						"sessionId": navSID,
						"method":    "Fetch.requestPaused",
						"params": map[string]any{
							"requestId":           "3p-img-hop1-back-to-victim",
							"frameId":             "main-f",
							"resourceType":        "Image",
							"redirectStatusCode":  302,
							"redirectedRequestId": "3p-img-hop0",
							"request": map[string]any{
								"url":     "https://victim.test/api/delete-via-3p-redirect",
								"headers": map[string]string{"Referer": "https://victim.test/app"},
							},
						},
					})
					<-chFor("3p-img-hop1-back-to-victim")

					// 5. Renderer-initiated top-level Document navigation without Referer (e.g. child frame target=_top or meta refresh) MUST be rejected!
					send(map[string]any{
						"sessionId": navSID,
						"method":    "Fetch.requestPaused",
						"params": map[string]any{
							"requestId":    "renderer-top-nav-no-referer",
							"frameId":      "main-f",
							"resourceType": "Document",
							"request": map[string]any{
								"url":     "https://victim.test/api/logout",
								"headers": map[string]string{"Accept": "text/html"},
							},
						},
					})
					<-chFor("renderer-top-nav-no-referer")

					send(map[string]any{"id": navID, "sessionId": navSID, "result": map[string]any{"frameId": "main-f"}})
					send(map[string]any{"sessionId": navSID, "method": "Page.loadEventFired", "params": map[string]any{}})
				}()
			case "Runtime.evaluate":
				docJSON, _ := json.Marshal(map[string]string{
					"url":  "https://victim.test/app",
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
		URL:       "https://victim.test/login",
		Headers:   map[string]string{"Authorization": "Bearer m4-secret"},
		WaitForMs: 20,
	}); err != nil {
		t.Fatalf("Execute failed: %v", err)
	}
	waitSeen("renderer-top-nav-no-referer")

	mu.Lock()
	defer mu.Unlock()
	for _, mustAllow := range []string{"nav-hop0", "nav-hop1-sameorigin", "noref-from-committed-bound-frame"} {
		if !hasOverride[mustAllow] {
			t.Fatalf("expected %q to receive bound headers, got %+v", mustAllow, hasOverride)
		}
	}
	for _, mustDeny := range []string{"noref-from-foreign-iframe", "3p-img-hop0", "3p-img-hop1-back-to-victim", "renderer-top-nav-no-referer"} {
		if hasOverride[mustDeny] {
			t.Fatalf("SECURITY (M4): %q must NOT receive bound headers! got %+v", mustDeny, hasOverride)
		}
	}
}

func TestR6DirectPipeCDPTransportFramingAndCaps(t *testing.T) {
	// 1. Multi-frame + byte-by-byte + escaped \u0000 + empty \0\0\0 handling.
	{
		toChromeR, toChromeW, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		fromChromeR, fromChromeW, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		conn := newPipeCDPConn(toChromeW, fromChromeR, func() {
			_ = toChromeR.Close()
			_ = fromChromeW.Close()
		})
		defer conn.close()

		evCh, unsub := conn.subscribe()
		defer unsub()

		go func() {
			buf := make([]byte, 4096)
			n, rErr := toChromeR.Read(buf)
			if rErr != nil || n == 0 || buf[n-1] != 0 {
				return
			}
			var req cdpRequest
			_ = json.Unmarshal(buf[:n-1], &req)
			combined := `{"method":"Page.loadEventFired","params":{}}` + "\x00\x00" +
				`{"id":` + strconv.FormatInt(req.ID, 10) + `,"result":{"val":"ok\u0000byte"}}` + "\x00"
			for i := 0; i < len(combined); i++ {
				_, _ = fromChromeW.Write([]byte{combined[i]})
			}
		}()

		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		var out struct {
			Val string `json:"val"`
		}
		if err := conn.call(ctx, "", "Test.echo", nil, &out); err != nil {
			t.Fatalf("pipe call failed: %v", err)
		}
		if out.Val != "ok\x00byte" {
			t.Fatalf("unexpected decoded JSON value: %q", out.Val)
		}
		select {
		case ev := <-evCh:
			if ev.Method != "Page.loadEventFired" {
				t.Fatalf("unexpected event: %+v", ev)
			}
		case <-time.After(time.Second):
			t.Fatal("missing async event from combined pipe read")
		}
	}

	// 2. Oversized frame (> maxCDPFrameBytes without NUL) closes pipe immediately and unblocks call().
	{
		toChromeR, toChromeW, _ := os.Pipe()
		fromChromeR, fromChromeW, _ := os.Pipe()
		conn := newPipeCDPConn(toChromeW, fromChromeR, func() {
			_ = toChromeR.Close()
			_ = fromChromeW.Close()
		})
		go func() {
			buf := make([]byte, 1024)
			_, _ = toChromeR.Read(buf)
			blk := make([]byte, 1<<20)
			for i := range blk {
				blk[i] = 'A'
			}
			for i := 0; i < 30; i++ {
				if _, wErr := fromChromeW.Write(blk); wErr != nil {
					return
				}
			}
		}()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		err := conn.call(ctx, "", "Test.big", nil, nil)
		if err == nil || !conn.isClosed() {
			t.Fatalf("expected oversized non-NUL stream to close pipe cdpConn, got err=%v closed=%v", err, conn.isClosed())
		}
	}
}

func TestR7NestedSubframeDocumentRenavigationHeaderLeakMockCDP(t *testing.T) {
	var (
		mu          sync.Mutex
		hasOverride = make(map[string]bool)
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
		sig := make(map[string]chan struct{})
		var sigMu sync.Mutex
		chFor := func(id string) chan struct{} {
			sigMu.Lock()
			defer sigMu.Unlock()
			c, ok := sig[id]
			if !ok {
				c = make(chan struct{})
				sig[id] = c
			}
			return c
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
				send(map[string]any{"id": req.ID, "result": map[string]any{"browserContextId": "bc-r7"}})
			case "Target.createTarget":
				send(map[string]any{"id": req.ID, "result": map[string]any{"targetId": "tgt-r7"}})
			case "Target.attachToTarget":
				send(map[string]any{"id": req.ID, "result": map[string]any{"sessionId": "s-r7"}})
			case "Page.getFrameTree":
				send(map[string]any{
					"id":        req.ID,
					"sessionId": req.SessionID,
					"result": map[string]any{
						"frameTree": map[string]any{
							"frame": map[string]any{"id": "main-f", "url": "about:blank", "securityOrigin": "://"},
						},
					},
				})
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
				mu.Unlock()
				send(map[string]any{"id": req.ID, "sessionId": req.SessionID, "result": map[string]any{}})
				select {
				case <-chFor(p.RequestID):
				default:
					close(chFor(p.RequestID))
				}
			case "Page.navigate":
				navID := req.ID
				navSID := req.SessionID
				go func() {
					// 1. Harness navigation commits main-f on https://example.com.
					send(map[string]any{
						"sessionId": navSID,
						"method":    "Fetch.requestPaused",
						"params": map[string]any{
							"requestId":    "main-doc",
							"frameId":      "main-f",
							"resourceType": "Document",
							"request":      map[string]any{"url": "https://example.com/start", "headers": map[string]string{"Accept": "text/html"}},
						},
					})
					<-chFor("main-doc")
					send(map[string]any{
						"sessionId": navSID,
						"method":    "Page.frameNavigated",
						"params":    map[string]any{"frame": map[string]any{"id": "main-f", "url": "https://example.com/start", "securityOrigin": "https://example.com"}},
					})

					// 2. Same-site cross-origin subframe (sub.example.com) commits, then creates grandchild iframe `child-f` on https://example.com/benign.
					send(map[string]any{
						"sessionId": navSID,
						"method":    "Page.frameNavigated",
						"params":    map[string]any{"frame": map[string]any{"id": "sub-f", "parentId": "main-f", "url": "https://sub.example.com/embed", "securityOrigin": "https://sub.example.com"}},
					})
					send(map[string]any{
						"sessionId": navSID,
						"method":    "Fetch.requestPaused",
						"params": map[string]any{
							"requestId":    "grandchild-init-doc",
							"frameId":      "child-f",
							"resourceType": "Document",
							"request": map[string]any{
								"url":     "https://example.com/benign",
								"headers": map[string]string{"Referer": "https://sub.example.com/", "Sec-Fetch-Site": "same-site"},
							},
						},
					})
					<-chFor("grandchild-init-doc")
					send(map[string]any{
						"sessionId": navSID,
						"method":    "Page.frameNavigated",
						"params":    map[string]any{"frame": map[string]any{"id": "child-f", "parentId": "sub-f", "url": "https://example.com/benign", "securityOrigin": "https://example.com"}},
					})

					// 3. Medium #1 Attack: sub.example.com re-navigates `child-f` (whose frameOrigins["child-f"] == "https://example.com"!)
					//    to https://example.com/secret with `no-referrer` (omitting Referer & Origin, Sec-Fetch-Site: same-site)!
					//    MUST NOT inject Authorization/Cookie/X-API-Key!
					send(map[string]any{
						"sessionId": navSID,
						"method":    "Fetch.requestPaused",
						"params": map[string]any{
							"requestId":    "grandchild-renav-noref-samesite",
							"frameId":      "child-f",
							"resourceType": "Document",
							"request": map[string]any{
								"url":     "https://example.com/secret",
								"headers": map[string]string{"Accept": "text/html", "Sec-Fetch-Site": "same-site"},
							},
						},
					})
					<-chFor("grandchild-renav-noref-samesite")

					// Also test cross-port nested iframe re-navigation where Sec-Fetch-Site is "same-site" (or even omitted)!
					send(map[string]any{
						"sessionId": navSID,
						"method":    "Fetch.requestPaused",
						"params": map[string]any{
							"requestId":    "grandchild-renav-noref-no-sfs",
							"frameId":      "child-f",
							"resourceType": "Document",
							"request": map[string]any{
								"url":     "https://example.com/secret-2",
								"headers": map[string]string{"Accept": "text/html"},
							},
						},
					})
					<-chFor("grandchild-renav-noref-no-sfs")

					// 4. Legitimate Referer-proven same-origin link click inside `child-f` MUST still receive headers!
					send(map[string]any{
						"sessionId": navSID,
						"method":    "Fetch.requestPaused",
						"params": map[string]any{
							"requestId":    "legit-referer-doc-click",
							"frameId":      "main-f",
							"resourceType": "Document",
							"request": map[string]any{
								"url":     "https://example.com/next-page",
								"headers": map[string]string{"Referer": "https://example.com/start", "Sec-Fetch-Site": "same-origin"},
							},
						},
					})
					<-chFor("legit-referer-doc-click")

					// 5. Page.frameDetached on `child-f` MUST evict `frameOrigins["child-f"]`, so any subsequent no-referrer subresource on reused frameId is denied!
					send(map[string]any{
						"sessionId": navSID,
						"method":    "Page.frameDetached",
						"params":    map[string]any{"frameId": "child-f"},
					})
					send(map[string]any{
						"sessionId": navSID,
						"method":    "Fetch.requestPaused",
						"params": map[string]any{
							"requestId":    "post-detach-subresource",
							"frameId":      "child-f",
							"resourceType": "Fetch",
							"request": map[string]any{
								"url":     "https://example.com/api/after-detach",
								"headers": map[string]string{"Accept": "*/*"},
							},
						},
					})
					<-chFor("post-detach-subresource")

					send(map[string]any{"id": navID, "sessionId": navSID, "result": map[string]any{"frameId": "main-f"}})
					send(map[string]any{"sessionId": navSID, "method": "Page.loadEventFired", "params": map[string]any{}})
				}()
			case "Runtime.evaluate":
				docJSON, _ := json.Marshal(map[string]string{"url": "https://example.com/start", "html": "<html><body>ok</body></html>"})
				send(map[string]any{"id": req.ID, "sessionId": req.SessionID, "result": map[string]any{"result": map[string]any{"type": "string", "value": string(docJSON)}}})
			default:
				send(map[string]any{"id": req.ID, "sessionId": req.SessionID, "result": map[string]any{}})
			}
		}
	}))
	defer cdpSrv.Close()

	r := NewMockRenderer("ws://"+strings.TrimPrefix(cdpSrv.URL, "http://"), func(*url.URL) error { return nil }, "EdgeFetchTest/2.7.0")
	defer r.Close()

	if _, err := r.Execute(context.Background(), Task{
		URL: "https://example.com/start",
		Headers: map[string]string{
			"Authorization": "Bearer TOP_SECRET_BEARER",
			"Cookie":        "sid=TOP_SECRET_COOKIE",
			"X-API-Key":     "TOP_SECRET_API_KEY",
		},
		WaitForMs: 25,
	}); err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	for _, wantTrue := range []string{"main-doc", "legit-referer-doc-click"} {
		if !hasOverride[wantTrue] {
			t.Fatalf("expected %q to receive caller headers, got %+v", wantTrue, hasOverride)
		}
	}
	for _, wantFalse := range []string{
		"grandchild-init-doc",
		"grandchild-renav-noref-samesite",
		"grandchild-renav-noref-no-sfs",
		"post-detach-subresource",
	} {
		if hasOverride[wantFalse] {
			t.Fatalf("SECURITY (R7 Medium #1): %q leaked caller headers! got %+v", wantFalse, hasOverride)
		}
	}
}

func TestR7LiveHeadlessChromeNestedSubframeNoReferrerAndPositiveControls(t *testing.T) {
	bin := FindChromeBinary()
	if bin == "" {
		t.Skip("no headless Chromium/Chrome binary installed; skipping live R7 nested subframe CDP test")
	}
	allowNoSandboxInTestOnRestrictedLinuxHost(t)

	type hitRecord struct {
		Host   string
		Path   string
		Auth   string
		Cookie string
		APIKey string
	}
	var (
		mu   sync.Mutex
		hits []hitRecord
	)
	recordHit := func(r *http.Request) {
		mu.Lock()
		hits = append(hits, hitRecord{
			Host:   r.Host,
			Path:   r.URL.Path,
			Auth:   r.Header.Get("Authorization"),
			Cookie: r.Header.Get("Cookie"),
			APIKey: r.Header.Get("X-API-Key"),
		})
		mu.Unlock()
	}

	var crossPortURL string
	mainSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		recordHit(r)
		hostOnly := r.Host
		if h, _, err := net.SplitHostPort(r.Host); err == nil {
			hostOnly = h
		}
		if strings.EqualFold(hostOnly, "sub.example.com") {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write([]byte(`<!doctype html><html><body>
<script>
const gc = document.createElement('iframe');
gc.name = 'gc_sub';
gc.src = 'https://example.com/benign-child';
let step = 0;
gc.onload = () => {
  step++;
  if (step === 1) {
    gc.referrerPolicy = 'no-referrer';
    gc.src = 'https://example.com/secret-from-sub-renav';
  } else if (step === 2) {
    const a = document.createElement('a');
    a.href = 'https://example.com/secret-from-sub-noreferrer-link';
    a.target = 'gc_sub';
    a.rel = 'noreferrer';
    document.body.appendChild(a);
    a.click();
  } else if (step === 3) {
    parent.postMessage('sub_attack_done', '*');
  }
};
document.body.appendChild(gc);
</script></body></html>`))
			return
		}

		// Bound origin: https://example.com
		switch r.URL.Path {
		case "/start":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write([]byte(`<!doctype html><html><head><meta name="referrer" content="no-referrer"></head><body>
<img src="/api/noref-img">
<iframe src="https://sub.example.com/embed"></iframe>
<iframe src="` + crossPortURL + `/embed-port"></iframe>
<a id="legit-link" href="/legit-next" referrerpolicy="origin">Next</a>
<script>
let doneCount = 0;
let subFetchDone = false;
function checkReady() {
  if (doneCount >= 2 && subFetchDone) {
    document.body.setAttribute('data-attack-finished', '1');
  }
}
window.addEventListener('message', (e) => {
  if (e.data === 'sub_attack_done' || e.data === 'port_attack_done') {
    doneCount++;
    checkReady();
  }
});
fetch('/api/noref-fetch').then(() => { subFetchDone = true; checkReady(); });
</script></body></html>`))
		case "/benign-child", "/secret-from-sub-renav", "/secret-from-sub-noreferrer-link", "/secret-from-port-renav":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write([]byte(`<!doctype html><html><body>child frame</body></html>`))
		case "/api/noref-fetch":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"ok":true}`))
		case "/api/noref-img":
			w.Header().Set("Content-Type", "image/gif")
			_, _ = w.Write([]byte("GIF89a\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00\xff\xff\xff!\xf9\x04\x01\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;"))
		case "/legit-next":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write([]byte(`<!doctype html><html><body><main id="final-ok">Legit Next Page</main></body></html>`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer mainSrv.Close()

	portSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		recordHit(r)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(`<!doctype html><html><body>
<script>
const gc2 = document.createElement('iframe');
gc2.src = 'https://example.com/benign-child';
let pStep = 0;
gc2.onload = () => {
  pStep++;
  if (pStep === 1) {
    gc2.referrerPolicy = 'no-referrer';
    gc2.src = 'https://example.com/secret-from-port-renav';
  } else if (pStep === 2) {
    parent.postMessage('port_attack_done', '*');
  }
};
document.body.appendChild(gc2);
</script></body></html>`))
	}))
	defer portSrv.Close()

	mainAddr := mainSrv.Listener.Addr().String()
	portAddr := portSrv.Listener.Addr().String()
	_, portNum, _ := net.SplitHostPort(portAddr)
	crossPortURL = "https://example.com:" + portNum

	r := NewRenderer(bin, func(u *url.URL) error { return nil }, "EdgeFetchTest/2.7.0", 1, nil)
	r.extraFlags = []string{"--ignore-certificate-errors"}
	r.proxyDial = func(ctx context.Context, network, addr string) (net.Conn, error) {
		_, p, err := net.SplitHostPort(addr)
		if err == nil && p == portNum {
			return (&net.Dialer{}).DialContext(ctx, network, portAddr)
		}
		return (&net.Dialer{}).DialContext(ctx, network, mainAddr)
	}
	defer r.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	const (
		secretAuth   = "Bearer R7_LIVE_SECRET_TOKEN"
		secretCookie = "session=R7_LIVE_SECRET_COOKIE"
		secretKey    = "R7_LIVE_SECRET_API_KEY"
	)
	out, err := r.Execute(ctx, Task{
		URL: "https://example.com/start",
		Headers: map[string]string{
			"Authorization": secretAuth,
			"Cookie":        secretCookie,
			"X-API-Key":     secretKey,
		},
		WaitSelector: "[data-attack-finished='1']",
		Actions: []InteractAction{
			{Type: "click", Selector: "#legit-link", WaitMs: 50},
			{Type: "wait", Selector: "#final-ok", Milliseconds: 5000},
		},
	})
	if err != nil {
		t.Fatalf("live Chrome Execute failed: %v", err)
	}
	if !strings.Contains(out.HTML, "Legit Next Page") {
		t.Fatalf("expected navigation to /legit-next, got URL=%q HTML=%q", out.FinalURL, out.HTML)
	}

	mu.Lock()
	recorded := append([]hitRecord(nil), hits...)
	mu.Unlock()

	sawbyPath := make(map[string][]hitRecord)
	for _, h := range recorded {
		sawbyPath[h.Path] = append(sawbyPath[h.Path], h)
	}

	// 1. Assert attacker nested-iframe re-navigations NEVER received ANY bound caller header!
	for _, forbiddenPath := range []string{
		"/embed",
		"/embed-port",
		"/benign-child",
		"/secret-from-sub-renav",
		"/secret-from-sub-noreferrer-link",
		"/secret-from-port-renav",
	} {
		recs := sawbyPath[forbiddenPath]
		if len(recs) == 0 {
			t.Fatalf("expected live Chrome to actually request %q so attack path is exercised! saw=%+v", forbiddenPath, sawbyPath)
		}
		for _, hr := range recs {
			if hr.Auth != "" || hr.Cookie != "" || hr.APIKey != "" {
				t.Fatalf("SECURITY (R7 Medium #1 LIVE): caller secret header leaked on %s (host=%s): %+v", forbiddenPath, hr.Host, hr)
			}
		}
	}

	// 2. Assert legitimate bound-origin requests (initial doc, no-referrer same-origin fetch & img, and Referer-proven link click) DID receive ALL 3 headers!
	for _, legitPath := range []string{
		"/start",
		"/api/noref-fetch",
		"/api/noref-img",
		"/legit-next",
	} {
		recs := sawbyPath[legitPath]
		if len(recs) == 0 {
			t.Fatalf("expected live Chrome to request legitimate path %q! saw=%+v", legitPath, sawbyPath)
		}
		for _, hr := range recs {
			if hr.Auth != secretAuth || hr.Cookie != secretCookie || hr.APIKey != secretKey {
				t.Fatalf("REGRESSION: legitimate bound request %s missed caller headers: %+v", legitPath, hr)
			}
		}
	}
}

func TestV271ResolveCDPKeySpecUnit(t *testing.T) {
	cases := []struct {
		raw      string
		wantKey  string
		wantCode string
		wantText string
		wantVK   int
	}{
		{"", "Enter", "Enter", "\r", 13},
		{"Enter", "Enter", "Enter", "\r", 13},
		{"Tab", "Tab", "Tab", "", 9},
		{"Escape", "Escape", "Escape", "", 27},
		{"Backspace", "Backspace", "Backspace", "", 8},
		{"Delete", "Delete", "Delete", "", 46},
		{" ", " ", "Space", " ", 32},
		{"Space", " ", "Space", " ", 32},
		{"ArrowDown", "ArrowDown", "ArrowDown", "", 40},
		{"ArrowUp", "ArrowUp", "ArrowUp", "", 38},
		{"ArrowLeft", "ArrowLeft", "ArrowLeft", "", 37},
		{"ArrowRight", "ArrowRight", "ArrowRight", "", 39},
		{"a", "a", "KeyA", "a", 'A'},
		{"G", "G", "KeyG", "G", 'G'},
		{"5", "5", "Digit5", "5", '5'},
		{"/", "/", "/", "/", '/'},
	}
	for _, tc := range cases {
		got := resolveCDPKeySpec(tc.raw)
		if got.key != tc.wantKey || got.code != tc.wantCode || got.text != tc.wantText || got.vk != tc.wantVK {
			t.Fatalf("resolveCDPKeySpec(%q) = %+v, want key=%q code=%q text=%q vk=%d", tc.raw, got, tc.wantKey, tc.wantCode, tc.wantText, tc.wantVK)
		}
	}
}

func TestV271LiveHeadlessChromeFormEnterSubmitClickNavSSRFAndNoEffect(t *testing.T) {
	bin := FindChromeBinary()
	if bin == "" {
		t.Skip("no headless Chromium/Chrome binary installed; skipping live v2.7.1 form Enter + ActionResult test")
	}
	allowNoSandboxInTestOnRestrictedLinuxHost(t)

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		switch r.URL.Path {
		case "/":
			// Multi-input form without a submit button (like Wikipedia #searchInput) so bare keyDown("Enter")
			// without VK_RETURN / char "\r" / requestSubmit fallback fails unless properly handled!
			_, _ = w.Write([]byte(`<!doctype html><html><head><title>Wiki Home</title></head><body>
				<form id="searchForm" action="/search" method="GET">
					<input id="searchInput" name="q" type="text" value="">
					<input id="extraFilter" name="ns" type="text" value="main">
				</form>
				<a id="aboutLink" href="/about">About Wiki</a>
				<a id="robotsBlockedLink" href="/disallowed-dest">Disallowed</a>
				<a id="ssrfLink" href="http://169.254.169.254/latest/meta-data/">SSRF</a>
			</body></html>`))
		case "/search":
			q := r.URL.Query().Get("q")
			ns := r.URL.Query().Get("ns")
			_, _ = w.Write([]byte(`<!doctype html><html><head><title>Search: ` + q + `</title></head><body>
				<main><h1 id="resHeading">Results for ` + q + ` (` + ns + `)</h1></main>
			</body></html>`))
		case "/about":
			_, _ = w.Write([]byte(`<!doctype html><html><head><title>About Page</title></head><body>
				<main><h1>About EdgeFetch Live Navigation</h1></main>
			</body></html>`))
		case "/disallowed-dest":
			_, _ = w.Write([]byte(`<!doctype html><html><body>secret</body></html>`))
		case "/inert":
			_, _ = w.Write([]byte(`<!doctype html><html><head><title>Inert Page</title></head><body>
				<div id="inertBox">Static inert content</div>
			</body></html>`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	srvAddr := srv.Listener.Addr().String()
	allowPublic := func(u *url.URL) error {
		if u.Scheme != "https" || u.Hostname() != "wiki.example.com" {
			return errors.New("blocked by SSRF policy: non-public target")
		}
		return nil
	}
	r := NewRenderer(bin, allowPublic, "EdgeFetchTest/2.7.1", 1, nil)
	r.extraFlags = []string{"--ignore-certificate-errors"}
	r.proxyDial = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, srvAddr)
	}
	r.CheckRobots = func(_ context.Context, rawURL string) error {
		if strings.Contains(rawURL, "/disallowed-dest") {
			return errors.New("robots.txt disallowed /disallowed-dest")
		}
		return nil
	}
	defer r.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	// 1. fill("#searchInput", "Go") + press("Enter") submits the form, awaits navigation, updates FinalURL & HTML, and reports ActionResults!
	outSearch, err := r.Execute(ctx, Task{
		URL: "https://wiki.example.com/",
		Actions: []InteractAction{
			{Type: "fill", Selector: "#searchInput", Value: "Go", WaitMs: 20},
			{Type: "press", Key: "Enter", WaitMs: 50},
		},
	})
	if err != nil {
		t.Fatalf("live Chrome fill + press(Enter) failed: %v", err)
	}
	if !strings.Contains(outSearch.FinalURL, "https://wiki.example.com/search?q=Go") {
		t.Fatalf("expected FinalURL navigated to /search?q=Go, got %q", outSearch.FinalURL)
	}
	if !strings.Contains(outSearch.HTML, "Results for Go (main)") {
		t.Fatalf("expected rendered search results HTML, got %q", outSearch.HTML)
	}
	if len(outSearch.ActionResults) != 2 {
		t.Fatalf("expected 2 ActionResults, got %+v", outSearch.ActionResults)
	}
	enterRes := outSearch.ActionResults[1]
	if enterRes.Status != "ok" || !enterRes.URLChanged || !enterRes.DOMChanged || !strings.Contains(enterRes.FinalURL, "/search?q=Go") {
		t.Fatalf("expected press(Enter) ActionResult urlChanged=true domChanged=true status=ok, got %+v", enterRes)
	}

	// 2. click("#aboutLink") awaits navigation to /about and updates FinalURL & HTML!
	outClick, err := r.Execute(ctx, Task{
		URL: "https://wiki.example.com/",
		Actions: []InteractAction{
			{Type: "click", Selector: "#aboutLink", WaitMs: 50},
		},
	})
	if err != nil {
		t.Fatalf("live Chrome click(#aboutLink) failed: %v", err)
	}
	if outClick.FinalURL != "https://wiki.example.com/about" || !strings.Contains(outClick.HTML, "About EdgeFetch Live Navigation") {
		t.Fatalf("expected click navigation to /about, got FinalURL=%q HTML=%q", outClick.FinalURL, outClick.HTML)
	}
	if len(outClick.ActionResults) != 1 || !outClick.ActionResults[0].URLChanged || outClick.ActionResults[0].Status != "ok" {
		t.Fatalf("unexpected click(#aboutLink) ActionResults: %+v", outClick.ActionResults)
	}

	// 3. Inert page: press("ArrowDown") and click("#inertBox") report status="no_effect", urlChanged=false, domChanged=false, and warning!
	outInert, err := r.Execute(ctx, Task{
		URL: "https://wiki.example.com/inert",
		Actions: []InteractAction{
			{Type: "press", Key: "ArrowDown", WaitMs: 20},
			{Type: "click", Selector: "#inertBox", WaitMs: 20},
		},
	})
	if err != nil {
		t.Fatalf("live Chrome inert page actions failed: %v", err)
	}
	if len(outInert.ActionResults) != 2 {
		t.Fatalf("expected 2 inert ActionResults, got %+v", outInert.ActionResults)
	}
	for idx, ar := range outInert.ActionResults {
		if ar.Status != "no_effect" || ar.URLChanged || ar.DOMChanged || ar.Warning == "" {
			t.Fatalf("inert ActionResults[%d] expected no_effect + urlChanged=false + domChanged=false + warning, got %+v", idx, ar)
		}
	}

	// 4. Navigations triggered by click to robots-disallowed path or SSRF URL MUST fail closed!
	if _, err := r.Execute(ctx, Task{
		URL:     "https://wiki.example.com/",
		Actions: []InteractAction{{Type: "click", Selector: "#robotsBlockedLink", WaitMs: 50}},
	}); err == nil || !strings.Contains(err.Error(), "robots.txt") {
		t.Fatalf("SECURITY: expected click navigation to robots-disallowed path to fail closed, got %v", err)
	}
	if _, err := r.Execute(ctx, Task{
		URL:     "https://wiki.example.com/",
		Actions: []InteractAction{{Type: "click", Selector: "#ssrfLink", WaitMs: 50}},
	}); err == nil {
		t.Fatal("SECURITY: expected click navigation to 169.254.169.254 SSRF URL to fail closed")
	}
}
