package browser

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/bartrumb/edgefetch/v2/internal/extract"
	"github.com/coder/websocket"
)

type pausedSubresourceSpec struct {
	requestID    string
	frameID      string
	resourceType string
	reqURL       string
}

type mockTrackerCDPResult struct {
	continued []string
	aborted   map[string]string // requestID -> errorReason
}

func runMockCDPTrackerRender(
	t *testing.T,
	r *Renderer,
	task Task,
	subresources []pausedSubresourceSpec,
) (Output, mockTrackerCDPResult) {
	t.Helper()
	var (
		mu      sync.Mutex
		rec     = mockTrackerCDPResult{aborted: make(map[string]string)}
		settled = make(chan struct{})
	)
	expectedTotal := 1 + len(subresources) // 1 top-level Document + subresources
	checkDone := func() {
		if len(rec.continued)+len(rec.aborted) >= expectedTotal {
			select {
			case <-settled:
			default:
				close(settled)
			}
		}
	}

	cdpSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		conn, err := websocket.Accept(w, req, nil)
		if err != nil {
			return
		}
		defer conn.CloseNow()

		var writeMu sync.Mutex
		send := func(v any) {
			b, _ := json.Marshal(v)
			writeMu.Lock()
			_ = conn.Write(req.Context(), websocket.MessageText, b)
			writeMu.Unlock()
		}

		fetchEnabled := false
		docContinued := make(chan struct{})
		var docOnce sync.Once

		for {
			_, raw, err := conn.Read(req.Context())
			if err != nil {
				return
			}
			var rpc struct {
				ID        int64           `json:"id"`
				SessionID string          `json:"sessionId"`
				Method    string          `json:"method"`
				Params    json.RawMessage `json:"params"`
			}
			if json.Unmarshal(raw, &rpc) != nil {
				continue
			}

			switch rpc.Method {
			case "Target.createBrowserContext":
				send(map[string]any{"id": rpc.ID, "result": map[string]any{"browserContextId": "bc-trk"}})
			case "Target.createTarget":
				send(map[string]any{"id": rpc.ID, "result": map[string]any{"targetId": "tgt-trk"}})
			case "Target.attachToTarget":
				send(map[string]any{"id": rpc.ID, "result": map[string]any{"sessionId": "sess-trk"}})
			case "Page.getFrameTree":
				send(map[string]any{
					"id":        rpc.ID,
					"sessionId": rpc.SessionID,
					"result": map[string]any{
						"frameTree": map[string]any{
							"frame": map[string]any{"id": "f-main", "url": "about:blank"},
						},
					},
				})
			case "Fetch.enable":
				fetchEnabled = true
				send(map[string]any{"id": rpc.ID, "sessionId": rpc.SessionID, "result": map[string]any{}})
			case "Fetch.continueRequest":
				var p struct {
					RequestID string `json:"requestId"`
				}
				_ = json.Unmarshal(rpc.Params, &p)
				mu.Lock()
				rec.continued = append(rec.continued, p.RequestID)
				checkDone()
				mu.Unlock()
				send(map[string]any{"id": rpc.ID, "sessionId": rpc.SessionID, "result": map[string]any{}})
				if p.RequestID == "req-main-doc" {
					docOnce.Do(func() { close(docContinued) })
				}
			case "Fetch.failRequest":
				var p struct {
					RequestID   string `json:"requestId"`
					ErrorReason string `json:"errorReason"`
				}
				_ = json.Unmarshal(rpc.Params, &p)
				mu.Lock()
				rec.aborted[p.RequestID] = p.ErrorReason
				checkDone()
				mu.Unlock()
				send(map[string]any{"id": rpc.ID, "sessionId": rpc.SessionID, "result": map[string]any{}})
			case "Page.navigate":
				var navP struct {
					URL string `json:"url"`
				}
				_ = json.Unmarshal(rpc.Params, &navP)
				navID := rpc.ID
				navSID := rpc.SessionID
				if !fetchEnabled {
					// If Fetch.enable wasn't enabled (e.g. no tracker list loaded or blockTrackers=false), all requests proceed unpaused!
					mu.Lock()
					rec.continued = append(rec.continued, "req-main-doc")
					for _, sr := range subresources {
						rec.continued = append(rec.continued, sr.requestID)
					}
					checkDone()
					mu.Unlock()
					send(map[string]any{"id": navID, "sessionId": navSID, "result": map[string]any{"frameId": "f-main", "loaderId": "ldr-1"}})
					send(map[string]any{
						"sessionId": navSID,
						"method":    "Page.frameNavigated",
						"params": map[string]any{
							"frame": map[string]any{"id": "f-main", "loaderId": "ldr-1", "url": navP.URL},
						},
					})
					send(map[string]any{"sessionId": navSID, "method": "Page.loadEventFired", "params": map[string]any{}})
					continue
				}
				go func() {
					send(map[string]any{
						"sessionId": navSID,
						"method":    "Fetch.requestPaused",
						"params": map[string]any{
							"requestId":    "req-main-doc",
							"frameId":      "f-main",
							"resourceType": "Document",
							"request":      map[string]any{"url": navP.URL, "method": "GET", "headers": map[string]string{"Accept": "text/html"}},
						},
					})
					select {
					case <-docContinued:
					case <-req.Context().Done():
						return
					}
					send(map[string]any{"id": navID, "sessionId": navSID, "result": map[string]any{"frameId": "f-main", "loaderId": "ldr-1"}})
					send(map[string]any{
						"sessionId": navSID,
						"method":    "Page.frameNavigated",
						"params": map[string]any{
							"frame": map[string]any{"id": "f-main", "loaderId": "ldr-1", "url": navP.URL},
						},
					})
					for _, sr := range subresources {
						frameID := sr.frameID
						if frameID == "" {
							frameID = "f-main"
						}
						if frameID != "f-main" {
							send(map[string]any{
								"sessionId": navSID,
								"method":    "Page.frameAttached",
								"params":    map[string]any{"frameId": frameID, "parentFrameId": "f-main"},
							})
						}
						send(map[string]any{
							"sessionId": navSID,
							"method":    "Fetch.requestPaused",
							"params": map[string]any{
								"requestId":    sr.requestID,
								"frameId":      frameID,
								"resourceType": sr.resourceType,
								"request":      map[string]any{"url": sr.reqURL, "method": "GET", "headers": map[string]string{"Accept": "*/*"}},
							},
						})
					}
					<-settled
					send(map[string]any{"sessionId": navSID, "method": "Page.loadEventFired", "params": map[string]any{}})
				}()
			case "Runtime.evaluate":
				docJSON, _ := json.Marshal(map[string]string{
					"url":  task.URL,
					"html": "<!doctype html><html><head><title>Example Test</title></head><body><main><h1>Rendered OK</h1></main></body></html>",
				})
				send(map[string]any{
					"id":        rpc.ID,
					"sessionId": rpc.SessionID,
					"result":    map[string]any{"result": map[string]any{"type": "string", "value": string(docJSON)}},
				})
			default:
				send(map[string]any{"id": rpc.ID, "sessionId": rpc.SessionID, "result": map[string]any{}})
			}
		}
	}))
	defer cdpSrv.Close()

	r.mu.Lock()
	if r.cdp != nil {
		r.cdp.close()
		r.cdp = nil
	}
	r.dialOverrideWS = "ws://" + strings.TrimPrefix(cdpSrv.URL, "http://")
	r.mu.Unlock()

	out, err := r.Execute(context.Background(), task)
	if err != nil {
		t.Fatalf("Renderer.Execute failed: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	return out, rec
}

func TestAcceptance3_4_5_7_TrackerBlockingInRenderer(t *testing.T) {
	t.Parallel()
	allowAll := func(*url.URL) error { return nil }

	// --- Acceptance 7 (part B): Agent with NO tracker list blocks nothing ---
	rNoList := NewMockRenderer("ws://127.0.0.1:1", allowAll, "EdgeFetch/2.7")
	defer rNoList.Close()
	outNoList, recNoList := runMockCDPTrackerRender(t, rNoList, Task{
		URL:       "https://example.test/article",
		WaitForMs: 10,
	}, []pausedSubresourceSpec{
		{requestID: "sr-ga", resourceType: "Script", reqURL: "https://www.google-analytics.com/analytics.js"},
	})
	if outNoList.BlockedTrackers != 0 || len(recNoList.aborted) != 0 {
		t.Fatalf("agent with no list must block nothing: BlockedTrackers=%d aborted=%v", outNoList.BlockedTrackers, recNoList.aborted)
	}

	// --- Acceptance 3: Page on example.test loading listed third-party tracker vs first-party, target-is-tracker, iframe Document, shared hosting & unknown suffix ---
	r := NewMockRenderer("ws://127.0.0.1:1", allowAll, "EdgeFetch/2.7")
	defer r.Close()
	r.SetTrackerList("2026112401", []string{
		"google-analytics.com",
		"session-replay.tracker.test",
		"example.test",        // Even if the page's own host is in the list, first-party requests MUST NOT be blocked!
		"tracker.github.io",   // Shared-hosting suffix -> uncertain registrable domain -> MUST NOT be blocked!
		"tracker.unknown-tld", // Unknown suffix -> uncertain registrable domain -> MUST NOT be blocked!
		// Acceptance 4 defense-in-depth: never-block hosts MUST NOT be blocked even if present in SetTrackerList!
		"challenges.cloudflare.com",
		"datadome.co",
		"captcha-delivery.com",
		"perimeterx.net",
		"humansecurity.com",
		"akamaihd.net",
		"arkoselabs.com",
		"recaptcha.net",
		"hcaptcha.com",
		"launchdarkly.com",
		"optimizely.com",
		"statsig.com",
		"split.io",
		"growthbook.io",
	})
	if gotVer := r.TrackerListVersion(); gotVer != "2026112401" {
		t.Fatalf("TrackerListVersion() = %q, want 2026112401", gotVer)
	}

	out3, rec3 := runMockCDPTrackerRender(t, r, Task{
		URL:       "https://example.test/article",
		WaitForMs: 10,
	}, []pausedSubresourceSpec{
		// Listed third-party script + parent-label subdomain match -> MUST BLOCK with BlockedByClient!
		{requestID: "sr-tp-script-1", resourceType: "Script", reqURL: "https://www.google-analytics.com/analytics.js"},
		{requestID: "sr-tp-xhr-2", resourceType: "XHR", reqURL: "https://ingest.session-replay.tracker.test/v1/events"},
		// Same host / subdomain of top-level page -> MUST NOT block!
		{requestID: "sr-fp-same", resourceType: "Script", reqURL: "https://example.test/static/app.js"},
		{requestID: "sr-fp-sub", resourceType: "Script", reqURL: "https://cdn.example.test/static/vendor.js"},
		// Listed host as an iframe Document navigation -> MUST NOT block!
		{requestID: "sr-iframe-doc", frameID: "f-child-1", resourceType: "Document", reqURL: "https://www.google-analytics.com/frame.html"},
		// Uncertain registrable domain (shared hosting & unknown suffix) -> MUST NOT block!
		{requestID: "sr-shared-host", resourceType: "Script", reqURL: "https://tracker.github.io/collect.js"},
		{requestID: "sr-unknown-tld", resourceType: "Script", reqURL: "https://tracker.unknown-tld/collect.js"},
		// Acceptance 4: Never-block allow-list hosts -> MUST NOT block!
		{requestID: "sr-cf-chal", resourceType: "Script", reqURL: "https://challenges.cloudflare.com/turnstile/v0/api.js"},
		{requestID: "sr-datadome", resourceType: "Script", reqURL: "https://js.datadome.co/tags.js"},
		{requestID: "sr-px", resourceType: "Script", reqURL: "https://client.perimeterx.net/PX123/main.min.js"},
		{requestID: "sr-ld", resourceType: "Fetch", reqURL: "https://app.launchdarkly.com/sdk/evalx/env/users"},
		{requestID: "sr-optimizely", resourceType: "Script", reqURL: "https://cdn.optimizely.com/js/123.js"},
		{requestID: "sr-statsig", resourceType: "Fetch", reqURL: "https://api.statsig.com/v1/initialize"},
		{requestID: "sr-split", resourceType: "Fetch", reqURL: "https://sdk.split.io/api/splitChanges"},
		{requestID: "sr-growthbook", resourceType: "Fetch", reqURL: "https://cdn.growthbook.io/api/features/key"},
	})

	if out3.BlockedTrackers != 2 {
		t.Fatalf("expected exactly 2 blocked third-party trackers, got BlockedTrackers=%d (aborted=%v)", out3.BlockedTrackers, rec3.aborted)
	}
	if rec3.aborted["sr-tp-script-1"] != "BlockedByClient" || rec3.aborted["sr-tp-xhr-2"] != "BlockedByClient" {
		t.Fatalf("expected sr-tp-script-1 and sr-tp-xhr-2 aborted with BlockedByClient, got %v", rec3.aborted)
	}
	for _, mustAllow := range []string{
		"req-main-doc",
		"sr-fp-same",
		"sr-fp-sub",
		"sr-iframe-doc",
		"sr-shared-host",
		"sr-unknown-tld",
		"sr-cf-chal",
		"sr-datadome",
		"sr-px",
		"sr-ld",
		"sr-optimizely",
		"sr-statsig",
		"sr-split",
		"sr-growthbook",
	} {
		if reason, wasAborted := rec3.aborted[mustAllow]; wasAborted {
			t.Fatalf("request %q must NOT be blocked, but was aborted with %q", mustAllow, reason)
		}
	}

	// --- Acceptance 3 (sub-bullet 3): A listed host as the scrape target itself is fetched normally (and its own subresources are not blocked) ---
	outTargetIsListed, recTargetIsListed := runMockCDPTrackerRender(t, r, Task{
		URL:       "https://www.google-analytics.com/about",
		WaitForMs: 10,
	}, []pausedSubresourceSpec{
		{requestID: "sr-target-own-js", resourceType: "Script", reqURL: "https://ssl.google-analytics.com/bundle.js"},
		{requestID: "sr-target-parent-js", resourceType: "Script", reqURL: "https://google-analytics.com/core.js"},
	})
	if outTargetIsListed.BlockedTrackers != 0 || len(recTargetIsListed.aborted) != 0 {
		t.Fatalf("listed host scraped directly as target must not block itself or its parent/sibling hosts: BlockedTrackers=%d aborted=%v",
			outTargetIsListed.BlockedTrackers, recTargetIsListed.aborted)
	}

	// --- Acceptance 5: `BlockTrackers: false` disables blocking for THAT request only; subsequent default request still blocks! ---
	disable := false
	outOptOut, recOptOut := runMockCDPTrackerRender(t, r, Task{
		URL:           "https://example.test/article",
		BlockTrackers: &disable,
		WaitForMs:     10,
	}, []pausedSubresourceSpec{
		{requestID: "sr-ga-optout", resourceType: "Script", reqURL: "https://www.google-analytics.com/analytics.js"},
	})
	if outOptOut.BlockedTrackers != 0 || len(recOptOut.aborted) != 0 {
		t.Fatalf("BlockTrackers=false must disable blocking for that request: BlockedTrackers=%d aborted=%v", outOptOut.BlockedTrackers, recOptOut.aborted)
	}

	outAfterOptOut, recAfterOptOut := runMockCDPTrackerRender(t, r, Task{
		URL:       "https://example.test/article",
		WaitForMs: 10,
	}, []pausedSubresourceSpec{
		{requestID: "sr-ga-default-again", resourceType: "Script", reqURL: "https://www.google-analytics.com/analytics.js"},
	})
	if outAfterOptOut.BlockedTrackers != 1 || recAfterOptOut.aborted["sr-ga-default-again"] != "BlockedByClient" {
		t.Fatalf("subsequent default request must still block trackers: BlockedTrackers=%d aborted=%v", outAfterOptOut.BlockedTrackers, recAfterOptOut.aborted)
	}
}

func TestRetainedSessionCrossOriginBounceTaintsStep2HeadersWhenTrackerBlockingActive(t *testing.T) {
	t.Parallel()
	allowAll := func(*url.URL) error { return nil }

	var (
		mu             sync.Mutex
		step2SubHdrs   map[string]string
		step2SubPaused = make(chan struct{})
	)

	cdpSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		conn, err := websocket.Accept(w, req, nil)
		if err != nil {
			return
		}
		defer conn.CloseNow()

		var writeMu sync.Mutex
		send := func(v any) {
			b, _ := json.Marshal(v)
			writeMu.Lock()
			_ = conn.Write(req.Context(), websocket.MessageText, b)
			writeMu.Unlock()
		}

		hop1Cont := make(chan struct{})
		hop2Cont := make(chan struct{})
		hop3Cont := make(chan struct{})

		for {
			_, raw, err := conn.Read(req.Context())
			if err != nil {
				return
			}
			var rpc struct {
				ID        int64           `json:"id"`
				SessionID string          `json:"sessionId"`
				Method    string          `json:"method"`
				Params    json.RawMessage `json:"params"`
			}
			if json.Unmarshal(raw, &rpc) != nil {
				continue
			}

			switch rpc.Method {
			case "Target.createBrowserContext":
				send(map[string]any{"id": rpc.ID, "result": map[string]any{"browserContextId": "bc-s4"}})
			case "Target.createTarget":
				send(map[string]any{"id": rpc.ID, "result": map[string]any{"targetId": "tgt-s4"}})
			case "Target.attachToTarget":
				send(map[string]any{"id": rpc.ID, "result": map[string]any{"sessionId": "sess-s4"}})
			case "Page.getFrameTree":
				send(map[string]any{
					"id":        rpc.ID,
					"sessionId": rpc.SessionID,
					"result": map[string]any{
						"frameTree": map[string]any{
							"frame": map[string]any{"id": "f-main", "url": "about:blank"},
						},
					},
				})
			case "Fetch.continueRequest":
				var p struct {
					RequestID string `json:"requestId"`
					Headers   []struct {
						Name  string `json:"name"`
						Value string `json:"value"`
					} `json:"headers"`
				}
				_ = json.Unmarshal(rpc.Params, &p)
				send(map[string]any{"id": rpc.ID, "sessionId": rpc.SessionID, "result": map[string]any{}})
				switch p.RequestID {
				case "hop-1":
					close(hop1Cont)
				case "hop-2":
					close(hop2Cont)
				case "hop-3":
					close(hop3Cont)
				case "step2-api":
					mu.Lock()
					step2SubHdrs = make(map[string]string, len(p.Headers))
					for _, h := range p.Headers {
						step2SubHdrs[strings.ToLower(h.Name)] = h.Value
					}
					mu.Unlock()
					close(step2SubPaused)
				}
			case "Page.navigate":
				navID := rpc.ID
				navSID := rpc.SessionID
				go func() {
					// Hop 1: initial origin `https://app.test/start`
					send(map[string]any{
						"sessionId": navSID,
						"method":    "Fetch.requestPaused",
						"params": map[string]any{
							"requestId":    "hop-1",
							"networkId":    "net-nav-1",
							"frameId":      "f-main",
							"resourceType": "Document",
							"request":      map[string]any{"url": "https://app.test/start", "method": "GET", "headers": map[string]string{"Accept": "text/html"}},
						},
					})
					<-hop1Cont
					// Hop 2: cross-origin bounce `https://bounce.other.test/hop`
					send(map[string]any{
						"sessionId": navSID,
						"method":    "Fetch.requestPaused",
						"params": map[string]any{
							"requestId":           "hop-2",
							"redirectedRequestId": "hop-1",
							"networkId":           "net-nav-1",
							"frameId":             "f-main",
							"resourceType":        "Document",
							"request":             map[string]any{"url": "https://bounce.other.test/hop", "method": "GET", "headers": map[string]string{"Accept": "text/html"}},
						},
					})
					<-hop2Cont
					// Hop 3: redirects back to initial origin `https://app.test/land`
					send(map[string]any{
						"sessionId": navSID,
						"method":    "Fetch.requestPaused",
						"params": map[string]any{
							"requestId":           "hop-3",
							"redirectedRequestId": "hop-2",
							"networkId":           "net-nav-1",
							"frameId":             "f-main",
							"resourceType":        "Document",
							"request":             map[string]any{"url": "https://app.test/land", "method": "GET", "headers": map[string]string{"Accept": "text/html"}},
						},
					})
					<-hop3Cont
					send(map[string]any{"id": navID, "sessionId": navSID, "result": map[string]any{"frameId": "f-main", "loaderId": "ldr-1"}})
					send(map[string]any{
						"sessionId": navSID,
						"method":    "Page.frameNavigated",
						"params": map[string]any{
							"frame": map[string]any{"id": "f-main", "loaderId": "ldr-1", "url": "https://app.test/land"},
						},
					})
					send(map[string]any{"sessionId": navSID, "method": "Page.loadEventFired", "params": map[string]any{}})
				}()
			case "Runtime.evaluate":
				var evalP struct {
					Expression string `json:"expression"`
				}
				_ = json.Unmarshal(rpc.Params, &evalP)
				// During Step 2 wait/eval, emit a same-origin XHR from the committed document
				mu.Lock()
				alreadyFired := step2SubHdrs != nil
				mu.Unlock()
				if !alreadyFired && strings.Contains(evalP.Expression, "step2-trigger") {
					navSID := rpc.SessionID
					evalID := rpc.ID
					go func() {
						send(map[string]any{
							"sessionId": navSID,
							"method":    "Network.requestWillBeSent",
							"params": map[string]any{
								"requestId":   "net-step2-api",
								"loaderId":    "ldr-1",
								"documentURL": "https://app.test/land",
								"frameId":     "f-main",
								"type":        "XHR",
								"request":     map[string]any{"url": "https://app.test/api/me", "method": "GET"},
							},
						})
						send(map[string]any{
							"sessionId": navSID,
							"method":    "Fetch.requestPaused",
							"params": map[string]any{
								"requestId":    "step2-api",
								"networkId":    "net-step2-api",
								"frameId":      "f-main",
								"resourceType": "XHR",
								"request": map[string]any{
									"url":     "https://app.test/api/me",
									"method":  "GET",
									"headers": map[string]string{"Referer": "https://app.test/land", "Origin": "https://app.test"},
								},
							},
						})
						<-step2SubPaused
						send(map[string]any{
							"id":        evalID,
							"sessionId": navSID,
							"result":    map[string]any{"result": map[string]any{"type": "boolean", "value": true}},
						})
					}()
					continue
				}
				docJSON, _ := json.Marshal(map[string]string{
					"url":  "https://app.test/land",
					"html": "<!doctype html><html><body><main>Landed</main></body></html>",
				})
				send(map[string]any{
					"id":        rpc.ID,
					"sessionId": rpc.SessionID,
					"result":    map[string]any{"result": map[string]any{"type": "string", "value": string(docJSON)}},
				})
			default:
				send(map[string]any{"id": rpc.ID, "sessionId": rpc.SessionID, "result": map[string]any{}})
			}
		}
	}))
	defer cdpSrv.Close()

	r := NewMockRenderer("ws://"+strings.TrimPrefix(cdpSrv.URL, "http://"), allowAll, "EdgeFetch/2.7")
	defer r.Close()
	r.SetTrackerList("2026112401", []string{"google-analytics.com"})

	// Step 1: No task.Headers, KeepSession: true, tracker blocking active -> experiences cross-origin redirect bounce
	step1Out, err := r.Execute(context.Background(), Task{
		URL:         "https://app.test/start",
		KeepSession: true,
		WaitForMs:   10,
	})
	if err != nil {
		t.Fatalf("Step 1 Execute failed: %v", err)
	}
	if step1Out.SessionID == "" {
		t.Fatal("expected retained SessionID from Step 1")
	}

	// Step 2: Resumes SessionID WITH sensitive custom header and no navigation target -> MUST either reject fail-closed
	// (`canReuseActiveHeadersWithoutNavigation`) OR withhold X-Secret because Step 1 bounced cross-origin!
	_, err = r.Execute(context.Background(), Task{
		SessionID:    step1Out.SessionID,
		CloseSession: true,
		Headers:      map[string]string{"X-Secret": "top-secret-token"},
		WaitSelector: "#step2-trigger",
		WaitForMs:    10,
	})
	if err != nil && !strings.Contains(err.Error(), "cannot attach custom headers") {
		t.Fatalf("Step 2 Execute failed with unexpected error: %v", err)
	}

	mu.Lock()
	gotSecret := step2SubHdrs["x-secret"]
	mu.Unlock()
	if gotSecret != "" {
		t.Fatalf("SECURITY REGRESSION: Step 2 leaked X-Secret=%q onto tab tainted by Step 1 cross-origin bounce!", gotSecret)
	}
}

func TestPostCommitRedirectUsesCommittedDocForTrackerScoping(t *testing.T) {
	t.Parallel()
	r := NewMockRenderer("ws://127.0.0.1:1", func(*url.URL) error { return nil }, "EdgeFetch/2.7")
	defer r.Close()
	r.SetTrackerList("2026112401", []string{"short-tracker.test", "google-analytics.com"})

	// Before navigation commits (pageDocURL == ""), targetURL ("https://short-tracker.test/go") protects target's own subresources:
	if r.shouldBlockTrackerSubresource("https://cdn.short-tracker.test/boot.js", "", "https://short-tracker.test/go") {
		t.Fatal("pre-commit subresource matching targetURL must not be blocked")
	}
	// Once redirected page commits on `https://publisher.test/article` (targetURL passed as ""), `short-tracker.test` IS third-party to `publisher.test` and MUST be blocked!
	if !r.shouldBlockTrackerSubresource("https://cdn.short-tracker.test/pixel.js", "https://publisher.test/article", "") {
		t.Fatal("post-commit subresource to initial shortener/tracker host on third-party publisher page must be blocked")
	}
}

func TestZeroAllocTrackerHotPath(t *testing.T) {
	// Warm up sync.Once PSL table first
	_, _ = extract.LookupKnownRegistrableDomain("www.google-analytics.com")

	pslAllocs := testing.AllocsPerRun(100, func() {
		reg, ok := extract.LookupKnownRegistrableDomain("www.google-analytics.com")
		if !ok || reg != "google-analytics.com" {
			t.Fatalf("unexpected PSL result: %q, %v", reg, ok)
		}
	})
	if pslAllocs != 0 {
		t.Fatalf("expected 0 allocs/op for LookupKnownRegistrableDomain on lowercase ASCII host, got %v", pslAllocs)
	}

	r := NewMockRenderer("ws://127.0.0.1:1", nil, "EdgeFetch/2.7")
	defer r.Close()
	r.SetTrackerList("2026112401", []string{"google-analytics.com", "hotjar.com", "segment.io"})

	blockAllocs := testing.AllocsPerRun(100, func() {
		if !r.shouldBlockTrackerSubresource(
			"https://www.google-analytics.com/analytics.js",
			"https://docs.example.com/guide",
			"",
		) {
			t.Fatal("expected tracker to be blocked")
		}
	})
	if blockAllocs != 0 {
		t.Fatalf("expected 0 allocs/op for shouldBlockTrackerSubresource hot path, got %v", blockAllocs)
	}
}

func BenchmarkLookupKnownRegistrableDomain(b *testing.B) {
	_, _ = extract.LookupKnownRegistrableDomain("www.google-analytics.com")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = extract.LookupKnownRegistrableDomain("www.google-analytics.com")
	}
}

func BenchmarkShouldBlockTrackerSubresource(b *testing.B) {
	r := NewMockRenderer("ws://127.0.0.1:1", nil, "EdgeFetch/2.7")
	defer r.Close()
	r.SetTrackerList("2026112401", []string{"google-analytics.com", "hotjar.com", "segment.io"})
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = r.shouldBlockTrackerSubresource(
			"https://www.google-analytics.com/analytics.js",
			"https://docs.example.com/guide",
			"",
		)
	}
}
