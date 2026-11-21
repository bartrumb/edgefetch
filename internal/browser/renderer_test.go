package browser

import (
	"context"
	"encoding/json"
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
