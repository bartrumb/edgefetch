package browser

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
)

func newR10MockCDPServer(t *testing.T, onMsg func(send func(any), raw []byte)) *httptest.Server {
	t.Helper()
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
			onMsg(send, raw)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestR10P2RetainedSessionPreCommitHeaderIsolationAndPostCommitUsability(t *testing.T) {
	var mu sync.Mutex
	gotAuth := make(map[string]string)
	hasOverride := make(map[string]bool)
	reqDone := make(map[string]chan struct{})
	sigCh := func(id string) chan struct{} {
		mu.Lock()
		defer mu.Unlock()
		ch, ok := reqDone[id]
		if !ok {
			ch = make(chan struct{})
			reqDone[id] = ch
		}
		return ch
	}

	var curDocURL atomic.Value
	curDocURL.Store("https://app.example.test/page-a")
	var stepNum atomic.Int32

	cdpSrv := newR10MockCDPServer(t, func(send func(any), raw []byte) {
		var req struct {
			ID        int64           `json:"id"`
			SessionID string          `json:"sessionId"`
			Method    string          `json:"method"`
			Params    json.RawMessage `json:"params"`
		}
		if json.Unmarshal(raw, &req) != nil {
			return
		}
		switch req.Method {
		case "Browser.getVersion":
			send(map[string]any{"id": req.ID, "result": map[string]any{"product": "HeadlessChrome/135.0"}})
		case "Target.createBrowserContext":
			send(map[string]any{"id": req.ID, "result": map[string]any{"browserContextId": "ctx-r10"}})
		case "Target.createTarget":
			send(map[string]any{"id": req.ID, "result": map[string]any{"targetId": "tgt-r10"}})
		case "Target.attachToTarget":
			send(map[string]any{"id": req.ID, "result": map[string]any{"sessionId": "sid-r10"}})
		case "Page.getFrameTree":
			send(map[string]any{
				"id":        req.ID,
				"sessionId": req.SessionID,
				"result": map[string]any{
					"frameTree": map[string]any{
						"frame": map[string]any{
							"id":       "main-f",
							"loaderId": "loader-boot",
							"url":      "about:blank",
						},
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
			_ = json.Unmarshal(req.Params, &p)
			send(map[string]any{"id": req.ID, "sessionId": req.SessionID, "result": map[string]any{}})
			ch := sigCh(p.RequestID)
			mu.Lock()
			if len(p.Headers) > 0 {
				hasOverride[p.RequestID] = true
				for _, h := range p.Headers {
					if strings.EqualFold(h.Name, "Authorization") {
						gotAuth[p.RequestID] = h.Value
					}
				}
			}
			select {
			case <-ch:
			default:
				close(ch)
			}
			mu.Unlock()
		case "Page.navigate":
			var np struct {
				URL string `json:"url"`
			}
			_ = json.Unmarshal(req.Params, &np)
			navID := req.ID
			navSID := req.SessionID
			curStep := stepNum.Add(1)

			go func() {
				switch curStep {
				case 1:
					// Step 1: Normal authenticated page load on Page A + legitimate same-origin API fetch,
					// followed by an iframe attach that taints Page A before Step 2 begins!
					curDocURL.Store("https://app.example.test/page-a")
					send(map[string]any{
						"sessionId": navSID,
						"method":    "Network.requestWillBeSent",
						"params": map[string]any{
							"requestId":   "net-step1-doc",
							"loaderId":    "loader-step1",
							"type":        "Document",
							"documentURL": "https://app.example.test/page-a",
							"initiator":   map[string]any{"type": "other"},
						},
					})
					send(map[string]any{
						"sessionId": navSID,
						"method":    "Fetch.requestPaused",
						"params": map[string]any{
							"requestId":    "step1-doc",
							"networkId":    "net-step1-doc",
							"frameId":      "main-f",
							"resourceType": "Document",
							"request": map[string]any{
								"url":     "https://app.example.test/page-a",
								"headers": map[string]string{"Accept": "text/html"},
							},
						},
					})
					<-sigCh("step1-doc")
					send(map[string]any{
						"sessionId": navSID,
						"method":    "Page.frameNavigated",
						"params": map[string]any{
							"frame": map[string]any{
								"id":             "main-f",
								"loaderId":       "loader-step1",
								"url":            "https://app.example.test/page-a",
								"securityOrigin": "https://app.example.test",
							},
						},
					})
					send(map[string]any{"id": navID, "sessionId": navSID, "result": map[string]any{"frameId": "main-f", "loaderId": "loader-step1"}})

					// Legitimate post-commit same-origin API fetch on Step 1 MUST get Step 1's header!
					send(map[string]any{
						"sessionId": navSID,
						"method":    "Network.requestWillBeSent",
						"params": map[string]any{
							"requestId":   "net-step1-api",
							"loaderId":    "loader-step1",
							"type":        "Fetch",
							"documentURL": "https://app.example.test/page-a",
							"initiator":   map[string]any{"type": "script", "url": "https://app.example.test/app.js"},
						},
					})
					send(map[string]any{
						"sessionId": navSID,
						"method":    "Fetch.requestPaused",
						"params": map[string]any{
							"requestId":    "step1-api",
							"networkId":    "net-step1-api",
							"frameId":      "main-f",
							"resourceType": "Fetch",
							"request": map[string]any{
								"url": "https://app.example.test/api/me",
								"headers": map[string]string{
									"Origin":  "https://app.example.test",
									"Referer": "https://app.example.test/page-a",
								},
							},
						},
					})
					<-sigCh("step1-api")

					// Now taint Page A (e.g., JS-triggered subdocument/location navigation) at the end of Step 1!
					send(map[string]any{
						"sessionId": navSID,
						"method":    "Fetch.requestPaused",
						"params": map[string]any{
							"requestId":    "step1-tainting-subdoc",
							"frameId":      "main-f",
							"resourceType": "Document",
							"initiator":    map[string]any{"type": "script", "url": "https://app.example.test/app.js"},
							"request": map[string]any{
								"url":     "https://app.example.test/page-a-tainted",
								"headers": map[string]string{"Referer": "https://app.example.test/page-a"},
							},
						},
					})
					<-sigCh("step1-tainting-subdoc")
					send(map[string]any{"sessionId": navSID, "method": "Page.loadEventFired", "params": map[string]any{}})

				case 2:
					// Step 2 (Core P2 Bug): Navigate to slow `/page-b` with `Bearer STEP2_SECRET`.
					// BEFORE `Page.frameNavigated` commits `/page-b`, tainted Page A fires timer & beforeunload same-origin fetches!
					send(map[string]any{
						"sessionId": navSID,
						"method":    "Fetch.requestPaused",
						"params": map[string]any{
							"requestId":    "step2-pre-doc-timer-from-page-a",
							"frameId":      "main-f",
							"resourceType": "Fetch",
							"request": map[string]any{
								"url": "https://app.example.test/api/exfil-before-doc-req",
								"headers": map[string]string{
									"Origin":  "https://app.example.test",
									"Referer": "https://app.example.test/page-a",
								},
							},
						},
					})
					<-sigCh("step2-pre-doc-timer-from-page-a")

					// Harness top-level Document request for `/page-b` starts (slow server hasn't responded/committed yet).
					send(map[string]any{
						"sessionId": navSID,
						"method":    "Network.requestWillBeSent",
						"params": map[string]any{
							"requestId":   "net-step2-doc",
							"loaderId":    "loader-step2",
							"type":        "Document",
							"documentURL": "https://app.example.test/page-b",
							"initiator":   map[string]any{"type": "other"},
						},
					})
					send(map[string]any{
						"sessionId": navSID,
						"method":    "Fetch.requestPaused",
						"params": map[string]any{
							"requestId":    "step2-doc",
							"networkId":    "net-step2-doc",
							"frameId":      "main-f",
							"resourceType": "Document",
							"request": map[string]any{
								"url":     "https://app.example.test/page-b",
								"headers": map[string]string{"Accept": "text/html"},
							},
						},
					})
					<-sigCh("step2-doc")

					// STILL BEFORE `Page.frameNavigated` commits `/page-b`: Page A fires `beforeunload` / `XHR`!
					// Even if networkId/loaderId is omitted by CDP on one request and tagged with `loader-step1` on another,
					// BOTH MUST receive ZERO caller headers because `/page-b` has NOT committed yet!
					send(map[string]any{
						"sessionId": navSID,
						"method":    "Network.requestWillBeSent",
						"params": map[string]any{
							"requestId":   "net-step2-unload-loader1",
							"loaderId":    "loader-step1",
							"type":        "XHR",
							"documentURL": "https://app.example.test/page-a",
							"initiator":   map[string]any{"type": "script", "url": "https://app.example.test/page-a.js"},
						},
					})
					send(map[string]any{
						"sessionId": navSID,
						"method":    "Fetch.requestPaused",
						"params": map[string]any{
							"requestId":    "step2-precommit-xhr-loader1",
							"networkId":    "net-step2-unload-loader1",
							"frameId":      "main-f",
							"resourceType": "XHR",
							"request": map[string]any{
								"url": "https://app.example.test/api/exfil-during-slow-nav",
								"headers": map[string]string{
									"Origin":  "https://app.example.test",
									"Referer": "https://app.example.test/page-a",
								},
							},
						},
					})
					<-sigCh("step2-precommit-xhr-loader1")

					send(map[string]any{
						"sessionId": navSID,
						"method":    "Fetch.requestPaused",
						"params": map[string]any{
							"requestId":    "step2-precommit-fetch-noloader",
							"frameId":      "main-f",
							"resourceType": "Fetch",
							"request": map[string]any{
								"url": "https://app.example.test/api/exfil-noloader",
								"headers": map[string]string{
									"Origin":  "https://app.example.test",
									"Referer": "https://app.example.test/page-a",
								},
							},
						},
					})
					<-sigCh("step2-precommit-fetch-noloader")

					// NOW `/page-b` commits (`Page.frameNavigated` on `main-f` with `loader-step2`)!
					curDocURL.Store("https://app.example.test/page-b")
					send(map[string]any{
						"sessionId": navSID,
						"method":    "Page.frameNavigated",
						"params": map[string]any{
							"frame": map[string]any{
								"id":             "main-f",
								"loaderId":       "loader-step2",
								"url":            "https://app.example.test/page-b",
								"securityOrigin": "https://app.example.test",
							},
						},
					})
					send(map[string]any{"id": navID, "sessionId": navSID, "result": map[string]any{"frameId": "main-f", "loaderId": "loader-step2"}})

					// Post-commit same-origin API fetch initiated by committed `/page-b` (`loader-step2`) MUST receive `Bearer STEP2_SECRET`!
					send(map[string]any{
						"sessionId": navSID,
						"method":    "Network.requestWillBeSent",
						"params": map[string]any{
							"requestId":   "net-step2-postcommit-api",
							"loaderId":    "loader-step2",
							"type":        "Fetch",
							"documentURL": "https://app.example.test/page-b",
							"initiator":   map[string]any{"type": "script", "url": "https://app.example.test/page-b.js"},
						},
					})
					send(map[string]any{
						"sessionId": navSID,
						"method":    "Fetch.requestPaused",
						"params": map[string]any{
							"requestId":    "step2-postcommit-api",
							"networkId":    "net-step2-postcommit-api",
							"frameId":      "main-f",
							"resourceType": "Fetch",
							"request": map[string]any{
								"url": "https://app.example.test/api/page-b-dashboard",
								"headers": map[string]string{
									"Origin":  "https://app.example.test",
									"Referer": "https://app.example.test/page-b",
								},
							},
						},
					})
					<-sigCh("step2-postcommit-api")

					// Late keepalive request carrying stale `loader-step1` even after commit MUST still be blocked!
					send(map[string]any{
						"sessionId": navSID,
						"method":    "Network.requestWillBeSent",
						"params": map[string]any{
							"requestId":   "net-late-stale-loader1",
							"loaderId":    "loader-step1",
							"type":        "Fetch",
							"documentURL": "https://app.example.test/page-a",
							"initiator":   map[string]any{"type": "script", "url": "https://app.example.test/page-a.js"},
						},
					})
					send(map[string]any{
						"sessionId": navSID,
						"method":    "Fetch.requestPaused",
						"params": map[string]any{
							"requestId":    "step2-late-stale-loader1",
							"networkId":    "net-late-stale-loader1",
							"frameId":      "main-f",
							"resourceType": "Fetch",
							"request": map[string]any{
								"url":     "https://app.example.test/api/late-keepalive",
								"headers": map[string]string{"Origin": "https://app.example.test"},
							},
						},
					})
					<-sigCh("step2-late-stale-loader1")
					send(map[string]any{"sessionId": navSID, "method": "Page.loadEventFired", "params": map[string]any{}})

				case 3:
					// Step 3: Cross-origin redirect during top-level navigation BEFORE commit -> must taint new document immediately on commit!
					send(map[string]any{
						"sessionId": navSID,
						"method":    "Fetch.requestPaused",
						"params": map[string]any{
							"requestId":    "step3-hop0",
							"frameId":      "main-f",
							"resourceType": "Document",
							"request": map[string]any{
								"url":     "https://app.example.test/step3-redir",
								"headers": map[string]string{"Accept": "text/html"},
							},
						},
					})
					<-sigCh("step3-hop0")
					send(map[string]any{
						"sessionId": navSID,
						"method":    "Fetch.requestPaused",
						"params": map[string]any{
							"requestId":           "step3-hop1-cross",
							"frameId":             "main-f",
							"resourceType":        "Document",
							"redirectStatusCode":  302,
							"redirectedRequestId": "step3-hop0",
							"request": map[string]any{
								"url":     "https://idp.other.test/login",
								"headers": map[string]string{"Accept": "text/html"},
							},
						},
					})
					<-sigCh("step3-hop1-cross")
					// Even if bounce redirects back to app.example.test and commits there, pendingNavCrossOrigin MUST taint on commit!
					curDocURL.Store("https://app.example.test/bounced")
					send(map[string]any{
						"sessionId": navSID,
						"method":    "Page.frameNavigated",
						"params": map[string]any{
							"frame": map[string]any{
								"id":             "main-f",
								"loaderId":       "loader-step3",
								"url":            "https://app.example.test/bounced",
								"securityOrigin": "https://app.example.test",
							},
						},
					})
					send(map[string]any{"id": navID, "sessionId": navSID, "result": map[string]any{"frameId": "main-f", "loaderId": "loader-step3"}})
					send(map[string]any{
						"sessionId": navSID,
						"method":    "Fetch.requestPaused",
						"params": map[string]any{
							"requestId":    "step3-post-bounce-fetch",
							"frameId":      "main-f",
							"resourceType": "Fetch",
							"request": map[string]any{
								"url":     "https://app.example.test/api/after-cross-bounce",
								"headers": map[string]string{"Origin": "https://app.example.test", "Referer": "https://app.example.test/bounced"},
							},
						},
					})
					<-sigCh("step3-post-bounce-fetch")
					send(map[string]any{"sessionId": navSID, "method": "Page.loadEventFired", "params": map[string]any{}})
				}
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
	})

	r := NewMockRenderer("ws://"+strings.TrimPrefix(cdpSrv.URL, "http://"), func(*url.URL) error { return nil }, "EdgeFetch-R10/1.0")
	defer r.Close()

	// Execute Step 1
	out1, err := r.Execute(context.Background(), Task{
		URL:         "https://app.example.test/page-a",
		Headers:     map[string]string{"Authorization": "Bearer STEP1_SECRET"},
		KeepSession: true,
		WaitForMs:   20,
	})
	if err != nil || out1.SessionID == "" {
		t.Fatalf("Step 1 Execute failed: err=%v out=%+v", err, out1)
	}

	// Execute Step 2 on the retained session
	if _, err := r.Execute(context.Background(), Task{
		SessionID:   out1.SessionID,
		URL:         "https://app.example.test/page-b",
		Headers:     map[string]string{"Authorization": "Bearer STEP2_SECRET"},
		KeepSession: true,
		WaitForMs:   20,
	}); err != nil {
		t.Fatalf("Step 2 Execute failed: %v", err)
	}

	// Execute Step 3 (cross-origin bounce before commit)
	if _, err := r.Execute(context.Background(), Task{
		SessionID: out1.SessionID,
		URL:       "https://app.example.test/step3-redir",
		Headers:   map[string]string{"Authorization": "Bearer STEP3_SECRET"},
		WaitForMs: 20,
	}); err != nil {
		t.Fatalf("Step 3 Execute failed: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()

	// Usability checks: legitimate target Document + committed target-document API fetches MUST receive headers!
	if gotAuth["step1-doc"] != "Bearer STEP1_SECRET" || gotAuth["step1-api"] != "Bearer STEP1_SECRET" {
		t.Fatalf("expected Step 1 target Document and post-commit API fetch to receive STEP1_SECRET, got doc=%q api=%q", gotAuth["step1-doc"], gotAuth["step1-api"])
	}
	if gotAuth["step2-doc"] != "Bearer STEP2_SECRET" || gotAuth["step2-postcommit-api"] != "Bearer STEP2_SECRET" {
		t.Fatalf("expected Step 2 target Document and post-commit API fetch to receive STEP2_SECRET, got doc=%q api=%q", gotAuth["step2-doc"], gotAuth["step2-postcommit-api"])
	}

	// Security checks (P2): EVERY pre-commit request from Page A, stale-loader request, JS subdoc, and post-cross-origin-bounce request MUST get ZERO headers!
	for _, mustBlockID := range []string{
		"step1-tainting-subdoc",
		"step2-pre-doc-timer-from-page-a",
		"step2-precommit-xhr-loader1",
		"step2-precommit-fetch-noloader",
		"step2-late-stale-loader1",
		"step3-hop1-cross",
		"step3-post-bounce-fetch",
	} {
		if hasOverride[mustBlockID] || gotAuth[mustBlockID] != "" {
			t.Fatalf("SECURITY (P2): request %q leaked caller headers (override=%v auth=%q)!", mustBlockID, hasOverride[mustBlockID], gotAuth[mustBlockID])
		}
	}
}

func TestR10P2FrameMapsBoundedAndEvictedOnDetachAndCommit(t *testing.T) {
	initOrig := canonicalURLOrigin("https://app.example.test")
	sess := &retainedSession{
		mainFrameID:   "main-root",
		initialOrigin: initOrig,
		frameOrigins:  map[string]string{"main-root": initOrig},
		frameTainted:  map[string]bool{"main-root": false},
		childFrames:   make(map[string]string),
	}

	// 1. Attach and navigate 600 child frames (> maxSessionFrameEntries == 256) and verify hard cap holds at every step!
	for i := 0; i < 600; i++ {
		fid := fmt.Sprintf("child-frame-%04d", i)
		attachJSON, _ := json.Marshal(map[string]any{"frameId": fid, "parentFrameId": "main-root"})
		sess.noteFrameAttached(attachJSON)

		navJSON, _ := json.Marshal(map[string]any{
			"frame": map[string]any{
				"id":             fid,
				"parentId":       "main-root",
				"loaderId":       fmt.Sprintf("ldr-%d", i),
				"url":            fmt.Sprintf("https://embed.example.test/frame/%d", i),
				"securityOrigin": "https://embed.example.test",
			},
		})
		sess.noteFrameNavigated(navJSON)

		sess.mu.Lock()
		nOrigins := len(sess.frameOrigins)
		nChildren := len(sess.childFrames)
		nTainted := len(sess.frameTainted)
		sess.mu.Unlock()
		if nOrigins > maxSessionFrameEntries || nChildren > maxSessionFrameEntries || nTainted > maxSessionFrameEntries {
			t.Fatalf("frame map exceeded cap %d at iter %d: origins=%d children=%d tainted=%d", maxSessionFrameEntries, i, nOrigins, nChildren, nTainted)
		}
	}

	// 2. Detaching a child frame immediately evicts it from frameOrigins, childFrames, and frameTainted.
	lastID := "child-frame-0599"
	detachJSON, _ := json.Marshal(map[string]any{"frameId": lastID})
	sess.noteFrameDetached(detachJSON)
	sess.mu.Lock()
	_, inOrigins := sess.frameOrigins[lastID]
	_, inChildren := sess.childFrames[lastID]
	_, inTainted := sess.frameTainted[lastID]
	sess.mu.Unlock()
	if inOrigins || inChildren || inTainted {
		t.Fatalf("expected detached frame %s evicted from all maps (origins=%v children=%v tainted=%v)", lastID, inOrigins, inChildren, inTainted)
	}

	// 3. Uncommitted navigation failure (204 No Content / clearExpectedHarnessNavigation) keeps prior tainted page tainted!
	sess.mu.Lock()
	sess.hasCommittedDoc = true
	sess.frameTainted["main-root"] = true
	sess.redirectedCrossOrigin = true
	sess.mu.Unlock()
	sess.expectHarnessNavigation("https://app.example.test/no-content")
	resp204, _ := json.Marshal(map[string]any{
		"requestId": "req-204",
		"type":      "Document",
		"frameId":   "main-root",
		"response":  map[string]any{"status": 204, "headers": map[string]string{}},
	})
	sess.noteNetworkResponseReceived(resp204)
	sess.clearExpectedHarnessNavigation()
	sess.mu.Lock()
	stillTainted := sess.frameTainted["main-root"] && sess.redirectedCrossOrigin
	sess.mu.Unlock()
	if !stillTainted {
		t.Fatal("expected uncommitted 204 navigation on tainted session to preserve main-root taint")
	}

	// 4. Committing a new valid top-level document clears all residual child frame entries and resets taint cleanly!
	sess.expectHarnessNavigation("https://app.example.test/clean-step")
	topCommit, _ := json.Marshal(map[string]any{
		"frame": map[string]any{
			"id":             "main-root",
			"loaderId":       "ldr-top-clean",
			"url":            "https://app.example.test/clean-step",
			"securityOrigin": "https://app.example.test",
		},
	})
	sess.noteFrameNavigated(topCommit)
	sess.mu.Lock()
	defer sess.mu.Unlock()
	if len(sess.childFrames) != 0 || len(sess.frameOrigins) != 1 || sess.frameTainted["main-root"] || sess.redirectedCrossOrigin {
		t.Fatalf("expected top-level commit to clear child frames and untaint main-root, got children=%d origins=%+v tainted=%+v redir=%v",
			len(sess.childFrames), sess.frameOrigins, sess.frameTainted, sess.redirectedCrossOrigin)
	}
}

func TestR10P2LiveChromiumRetainedSessionSlowStepHeaderIsolationIfInstalled(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "windows" {
		return
	}
	bin := FindChromeBinary()
	if bin == "" {
		t.Skip("no headless Chromium/Chrome binary installed; skipping live P2 retained-session test")
	}
	allowNoSandboxInTestOnRestrictedLinuxHost(t)

	var mu sync.Mutex
	seenHeader := make(map[string]string)

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sec := r.Header.Get("X-R10-Step-Secret")
		mu.Lock()
		seenHeader[r.URL.Path] = sec
		mu.Unlock()

		switch r.URL.Path {
		case "/page-a":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			// Embed an iframe so Page A is tainted, and fire timer + pagehide fetches while Step 2 is slow to respond!
			_, _ = w.Write([]byte(`<!doctype html><html><body>
				<iframe src="about:blank"></iframe>
				<script>
					fetch('/api/from-a-initial');
					setInterval(() => { fetch('/api/from-a-timer').catch(() => {}); }, 25);
					window.addEventListener('pagehide', () => { fetch('/api/from-a-unload', {keepalive: true}).catch(() => {}); });
				</script>
				<main>Page A</main>
			</body></html>`))
		case "/page-b":
			// Hold response for 180ms so Page A's 25ms interval timer fires WHILE Step 2 navigation is in flight before commit!
			time.Sleep(180 * time.Millisecond)
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write([]byte(`<!doctype html><html><body>
				<script>fetch('/api/from-b-committed');</script>
				<main>Page B</main>
			</body></html>`))
		default:
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"ok":true}`))
		}
	}))
	defer srv.Close()
	srvAddr := srv.Listener.Addr().String()

	r := NewRenderer(bin, func(*url.URL) error { return nil }, "EdgeFetch-R10-Live/1.0", 1, nil)
	r.extraFlags = []string{"--ignore-certificate-errors"}
	r.proxyDial = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, srvAddr)
	}
	defer r.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
	defer cancel()

	out1, err := r.Execute(ctx, Task{
		URL:         "https://r10-live.example.com/page-a",
		Headers:     map[string]string{"X-R10-Step-Secret": "SECRET_A"},
		KeepSession: true,
		WaitForMs:   120,
	})
	if err != nil || out1.SessionID == "" {
		t.Fatalf("live Step 1 failed: err=%v out=%+v", err, out1)
	}

	out2, err := r.Execute(ctx, Task{
		SessionID: out1.SessionID,
		URL:       "https://r10-live.example.com/page-b",
		Headers:   map[string]string{"X-R10-Step-Secret": "SECRET_B"},
		WaitForMs: 200,
	})
	if err != nil || !strings.Contains(out2.HTML, "Page B") {
		t.Fatalf("live Step 2 failed: err=%v html=%q", err, out2.HTML)
	}

	mu.Lock()
	defer mu.Unlock()
	if seenHeader["/page-b"] != "SECRET_B" || seenHeader["/api/from-b-committed"] != "SECRET_B" {
		t.Fatalf("expected /page-b and /api/from-b-committed to receive SECRET_B, got seenHeader=%+v", seenHeader)
	}
	for _, fromAPath := range []string{"/api/from-a-timer", "/api/from-a-unload"} {
		if seenHeader[fromAPath] == "SECRET_B" {
			t.Fatalf("SECURITY (P2): live Chromium leaked Step 2 SECRET_B to Page A request %s! seenHeader=%+v", fromAPath, seenHeader)
		}
	}
}
