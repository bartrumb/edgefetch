package browser

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"image/png"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"runtime"
	"strconv"
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
	if runtime.GOOS != "linux" && runtime.GOOS != "windows" {
		return
	}
	bin := FindChromeBinary()
	if bin == "" {
		t.Skip("no headless Chromium/Chrome binary installed; skipping live P2 retained-session test")
	}
	acquireLiveChromeSlot(t)

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
					let ticks = 0;
					const iv = setInterval(() => {
						if (++ticks > 16) { clearInterval(iv); return; }
						fetch('/api/from-a-timer').catch(() => {});
					}, 25);
					window.addEventListener('pagehide', () => {
						fetch('/api/from-a-unload', {keepalive: true}).catch(() => {});
						fetch('/api/from-a-pagehide-noref', {method: 'POST', body: 'x', keepalive: true, referrerPolicy: 'no-referrer'}).catch(() => {});
						fetch('/api/from-a-pagehide-origin', {method: 'POST', body: 'x', keepalive: true, referrerPolicy: 'origin'}).catch(() => {});
						fetch('/api/from-a-spoofed-referrer', {method: 'POST', body: 'spoof', keepalive: true, referrer: 'https://r10-live.example.com/page-b'}).catch(() => {});
					});
				</script>
				<main>Page A</main>
			</body></html>`))
		case "/page-b":
			// Hold response for 180ms so Page A's 25ms interval timer fires WHILE Step 2 navigation is in flight before commit!
			time.Sleep(180 * time.Millisecond)
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write([]byte(`<!doctype html><html><body>
				<script>
					Promise.all([
						fetch('/api/from-b-committed'),
						fetch('/api/from-b-post-noref', {method: 'POST', body: 'ok', referrerPolicy: 'no-referrer'}),
					]).then(() => {
						const f = document.createElement('iframe');
						f.src = 'about:blank';
						document.body.appendChild(f);
					});
					window.addEventListener('pagehide', () => {
						fetch('/api/from-b-origin-to-root', {method: 'POST', body: 'root', keepalive: true, referrerPolicy: 'origin'}).catch(() => {});
						fetch('/api/from-b-spoofed-root', {method: 'POST', body: 'spoof-root', keepalive: true, referrer: 'https://r10-live.example.com/'}).catch(() => {});
					});
				</script>
				<main>Page B</main>
			</body></html>`))
		case "/":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			if sec == "SECRET_C_ROOT" {
				_, _ = w.Write([]byte(`<!doctype html><html><body>
					<script>
						fetch('/api/from-root-step3').then(() => {
							const f = document.createElement('iframe');
							f.src = 'about:blank';
							document.body.appendChild(f);
						});
						window.addEventListener('pagehide', () => {
							fetch('/api/from-root-same-url-pagehide', {method: 'POST', body: 'same', keepalive: true, referrer: 'https://r10-live.example.com/'}).catch(() => {});
						});
					</script>
					<main>Root Step 3</main>
				</body></html>`))
			} else {
				_, _ = w.Write([]byte(`<!doctype html><html><body>
					<script>fetch('/api/from-root-step4');</script>
					<main>Root Step 4</main>
				</body></html>`))
			}
		default:
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"ok":true}`))
		}
	}))
	defer srv.Close()
	srvAddr := srv.Listener.Addr().String()

	r := NewRenderer(bin, func(*url.URL) error { return nil }, "EdgeFetch-R10-Live/1.0", 1, nil)
	enableNoSandboxOnRestrictedLinuxHost(r)
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
		SessionID:   out1.SessionID,
		URL:         "https://r10-live.example.com/page-b",
		Headers:     map[string]string{"X-R10-Step-Secret": "SECRET_B"},
		KeepSession: true,
		WaitForMs:   200,
	})
	if err != nil || !strings.Contains(out2.HTML, "Page B") {
		t.Fatalf("live Step 2 failed: err=%v html=%q", err, out2.HTML)
	}

	out3, err := r.Execute(ctx, Task{
		SessionID:   out1.SessionID,
		URL:         "https://r10-live.example.com/",
		Headers:     map[string]string{"X-R10-Step-Secret": "SECRET_C_ROOT"},
		KeepSession: true,
		WaitForMs:   150,
	})
	if err != nil || !strings.Contains(out3.HTML, "Root Step 3") {
		t.Fatalf("live Step 3 failed: err=%v html=%q", err, out3.HTML)
	}

	out4, err := r.Execute(ctx, Task{
		SessionID: out1.SessionID,
		URL:       "https://r10-live.example.com/",
		Headers:   map[string]string{"X-R10-Step-Secret": "SECRET_D_SAME_URL"},
		WaitForMs: 150,
	})
	if err != nil || !strings.Contains(out4.HTML, "Root Step 4") {
		t.Fatalf("live Step 4 failed: err=%v html=%q", err, out4.HTML)
	}

	mu.Lock()
	defer mu.Unlock()
	if seenHeader["/page-b"] != "SECRET_B" || seenHeader["/api/from-b-committed"] != "SECRET_B" || seenHeader["/api/from-b-post-noref"] != "SECRET_B" {
		t.Fatalf("expected /page-b, /api/from-b-committed, and /api/from-b-post-noref to receive SECRET_B, got seenHeader=%+v", seenHeader)
	}
	if seenHeader["/api/from-root-step3"] != "SECRET_C_ROOT" || seenHeader["/api/from-root-step4"] != "SECRET_D_SAME_URL" {
		t.Fatalf("expected Step 3 & Step 4 root fetches to receive their respective headers, got seenHeader=%+v", seenHeader)
	}
	if seenHeader["/api/from-a-timer"] == "SECRET_B" || seenHeader["/api/from-a-timer"] == "SECRET_C_ROOT" || seenHeader["/api/from-a-timer"] == "SECRET_D_SAME_URL" {
		t.Fatalf("SECURITY (P2): live Chromium leaked subsequent step header %q to /api/from-a-timer! seenHeader=%+v", seenHeader["/api/from-a-timer"], seenHeader)
	}
	for _, fromAPath := range []string{"/api/from-a-unload", "/api/from-a-pagehide-noref", "/api/from-a-pagehide-origin", "/api/from-a-spoofed-referrer"} {
		if seenHeader[fromAPath] != "" {
			t.Fatalf("SECURITY (P2 / EF-BLIND-01): live Chromium leaked header %q to tainted Page A pagehide request %s! seenHeader=%+v", seenHeader[fromAPath], fromAPath, seenHeader)
		}
	}
	for _, fromBPath := range []string{"/api/from-b-origin-to-root", "/api/from-b-spoofed-root"} {
		if seenHeader[fromBPath] != "" {
			t.Fatalf("SECURITY (EF-BLIND-01-R1): live Chromium leaked header %q to tainted Page B pagehide request %s! seenHeader=%+v", seenHeader[fromBPath], fromBPath, seenHeader)
		}
	}
	if seenHeader["/api/from-root-same-url-pagehide"] != "" {
		t.Fatalf("SECURITY (EF-BLIND-01-R1): live Chromium leaked header %q on same-URL re-navigation pagehide! seenHeader=%+v", seenHeader["/api/from-root-same-url-pagehide"], seenHeader)
	}
}

func TestR11S4ResumedSessionHeaderAttachmentAndPreNavigateIsolation(t *testing.T) {
	t.Parallel()
	var (
		mu          sync.Mutex
		gotAPIKey   = make(map[string]string)
		hasOverride = make(map[string]bool)
		reqDone     = make(map[string]chan struct{})
	)
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
	curDocURL.Store("about:blank")
	var curLoaderID atomic.Value
	curLoaderID.Store("loader-blank")
	var fetchEnabled atomic.Bool

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
			send(map[string]any{"id": req.ID, "result": map[string]any{"product": "HeadlessChrome/137.0"}})
		case "Target.createBrowserContext":
			send(map[string]any{"id": req.ID, "result": map[string]any{"browserContextId": "bc-r11-s4"}})
		case "Target.createTarget":
			send(map[string]any{"id": req.ID, "result": map[string]any{"targetId": "tgt-r11-s4"}})
		case "Target.attachToTarget":
			send(map[string]any{"id": req.ID, "result": map[string]any{"sessionId": "sid-r11-s4"}})
		case "Fetch.enable":
			fetchEnabled.Store(true)
			send(map[string]any{"id": req.ID, "sessionId": req.SessionID, "result": map[string]any{}})
		case "Page.getFrameTree":
			u, _ := curDocURL.Load().(string)
			ldr, _ := curLoaderID.Load().(string)
			send(map[string]any{
				"id":        req.ID,
				"sessionId": req.SessionID,
				"result": map[string]any{
					"frameTree": map[string]any{
						"frame": map[string]any{
							"id":       "main-f",
							"loaderId": ldr,
							"url":      u,
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
					if strings.EqualFold(h.Name, "X-Api-Key") {
						gotAPIKey[p.RequestID] = h.Value
					}
				}
			}
			select {
			case <-ch:
			default:
				close(ch)
			}
			mu.Unlock()
		case "Network.getResponseBody":
			var p struct {
				RequestID string `json:"requestId"`
			}
			_ = json.Unmarshal(req.Params, &p)
			body := `{"items":[{"title":"Chosen Authed Secret"}]}`
			if strings.Contains(p.RequestID, "unchosen") {
				body = `{"items":[{"title":"UNCHOSEN_PAGE_LEAK"}]}`
			}
			send(map[string]any{
				"id":        req.ID,
				"sessionId": req.SessionID,
				"result":    map[string]any{"body": body, "base64Encoded": false},
			})
		case "Page.navigate":
			var np struct {
				URL string `json:"url"`
			}
			_ = json.Unmarshal(req.Params, &np)
			navID := req.ID
			navSID := req.SessionID
			go func() {
				switch np.URL {
				case "https://app.example.test/landing":
					// Step 1 (no headers): harness navigates to /landing, then page JS redirects to /secret-api-loader.
					curDocURL.Store("https://app.example.test/landing")
					curLoaderID.Store("ldr-step1-landing")
					send(map[string]any{
						"sessionId": navSID,
						"method":    "Page.frameNavigated",
						"params": map[string]any{
							"frame": map[string]any{
								"id":             "main-f",
								"loaderId":       "ldr-step1-landing",
								"url":            "https://app.example.test/landing",
								"securityOrigin": "https://app.example.test",
							},
						},
					})
					send(map[string]any{"id": navID, "sessionId": navSID, "result": map[string]any{"frameId": "main-f", "loaderId": "ldr-step1-landing"}})
					// In-page redirect to /secret-api-loader (not chosen by harness).
					curDocURL.Store("https://app.example.test/secret-api-loader")
					curLoaderID.Store("ldr-step1-unchosen")
					send(map[string]any{
						"sessionId": navSID,
						"method":    "Page.frameNavigated",
						"params": map[string]any{
							"frame": map[string]any{
								"id":             "main-f",
								"loaderId":       "ldr-step1-unchosen",
								"url":            "https://app.example.test/secret-api-loader",
								"securityOrigin": "https://app.example.test",
							},
						},
					})
					send(map[string]any{"sessionId": navSID, "method": "Page.loadEventFired", "params": map[string]any{}})

				case "https://app.example.test/authed":
					if fetchEnabled.Load() {
						send(map[string]any{
							"sessionId": navSID,
							"method":    "Network.requestWillBeSent",
							"params": map[string]any{
								"requestId":   "net-authed-doc",
								"loaderId":    "ldr-authed",
								"type":        "Document",
								"documentURL": "https://app.example.test/authed",
								"initiator":   map[string]any{"type": "other"},
							},
						})
						send(map[string]any{
							"sessionId": navSID,
							"method":    "Fetch.requestPaused",
							"params": map[string]any{
								"requestId":    "authed-doc",
								"networkId":    "net-authed-doc",
								"frameId":      "main-f",
								"resourceType": "Document",
								"request": map[string]any{
									"url":     "https://app.example.test/authed",
									"headers": map[string]string{"Accept": "text/html"},
								},
							},
						})
						<-sigCh("authed-doc")
					}
					curDocURL.Store("https://app.example.test/authed")
					curLoaderID.Store("ldr-authed")
					send(map[string]any{
						"sessionId": navSID,
						"method":    "Page.frameNavigated",
						"params": map[string]any{
							"frame": map[string]any{
								"id":             "main-f",
								"loaderId":       "ldr-authed",
								"url":            "https://app.example.test/authed",
								"securityOrigin": "https://app.example.test",
							},
						},
					})
					send(map[string]any{"id": navID, "sessionId": navSID, "result": map[string]any{"frameId": "main-f", "loaderId": "ldr-authed"}})

					if fetchEnabled.Load() {
						send(map[string]any{
							"sessionId": navSID,
							"method":    "Network.requestWillBeSent",
							"params": map[string]any{
								"requestId":   "net-authed-api",
								"frameId":     "main-f",
								"loaderId":    "ldr-authed",
								"type":        "Fetch",
								"documentURL": "https://app.example.test/authed",
								"initiator":   map[string]any{"type": "script", "url": "https://app.example.test/authed.js"},
								"request":     map[string]any{"url": "https://app.example.test/api/authed.json", "method": "GET"},
							},
						})
						send(map[string]any{
							"sessionId": navSID,
							"method":    "Fetch.requestPaused",
							"params": map[string]any{
								"requestId":    "authed-api",
								"networkId":    "net-authed-api",
								"frameId":      "main-f",
								"resourceType": "Fetch",
								"request": map[string]any{
									"url": "https://app.example.test/api/authed.json",
									"headers": map[string]string{
										"Origin":  "https://app.example.test",
										"Referer": "https://app.example.test/authed",
									},
								},
							},
						})
						<-sigCh("authed-api")
						send(map[string]any{
							"sessionId": navSID,
							"method":    "Network.responseReceived",
							"params": map[string]any{
								"requestId": "net-authed-api",
								"frameId":   "main-f",
								"type":      "Fetch",
								"response": map[string]any{
									"url":      "https://app.example.test/api/authed.json",
									"status":   200,
									"mimeType": "application/json",
								},
							},
						})
						send(map[string]any{
							"sessionId": navSID,
							"method":    "Network.loadingFinished",
							"params":    map[string]any{"requestId": "net-authed-api", "encodedDataLength": 42},
						})
					}
					send(map[string]any{"sessionId": navSID, "method": "Page.loadEventFired", "params": map[string]any{}})

				case "https://app.example.test/headerless-next":
					if fetchEnabled.Load() {
						send(map[string]any{
							"sessionId": navSID,
							"method":    "Fetch.requestPaused",
							"params": map[string]any{
								"requestId":    "headerless-next-doc",
								"frameId":      "main-f",
								"resourceType": "Document",
								"request": map[string]any{
									"url":     "https://app.example.test/headerless-next",
									"headers": map[string]string{"Accept": "text/html"},
								},
							},
						})
						<-sigCh("headerless-next-doc")
					}
					curDocURL.Store("https://app.example.test/headerless-next")
					curLoaderID.Store("ldr-next")
					send(map[string]any{
						"sessionId": navSID,
						"method":    "Page.frameNavigated",
						"params": map[string]any{
							"frame": map[string]any{
								"id":             "main-f",
								"loaderId":       "ldr-next",
								"url":            "https://app.example.test/headerless-next",
								"securityOrigin": "https://app.example.test",
							},
						},
					})
					send(map[string]any{"id": navID, "sessionId": navSID, "result": map[string]any{"frameId": "main-f", "loaderId": "ldr-next"}})
					send(map[string]any{"sessionId": navSID, "method": "Page.loadEventFired", "params": map[string]any{}})
				}
			}()
		case "Runtime.evaluate":
			var p struct {
				Expression string `json:"expression"`
			}
			_ = json.Unmarshal(req.Params, &p)
			switch {
			case strings.Contains(p.Expression, "#missing-abort"):
				send(map[string]any{"id": req.ID, "sessionId": req.SessionID, "result": map[string]any{"result": map[string]any{"type": "string", "value": "selector_not_found"}}})
			case strings.Contains(p.Expression, "#trigger-pre-nav-xhr"):
				sid := req.SessionID
				go func() {
					// Unchosen page fires a same-origin JSON XHR during click BEFORE the navigate action runs!
					send(map[string]any{
						"sessionId": sid,
						"method":    "Network.requestWillBeSent",
						"params": map[string]any{
							"requestId":   "net-unchosen-xhr",
							"frameId":     "main-f",
							"loaderId":    "ldr-step1-unchosen",
							"type":        "XHR",
							"documentURL": "https://app.example.test/secret-api-loader",
							"initiator":   map[string]any{"type": "script", "url": "https://app.example.test/loader.js"},
							"request":     map[string]any{"url": "https://app.example.test/api/unchosen.json", "method": "GET"},
						},
					})
					if fetchEnabled.Load() {
						send(map[string]any{
							"sessionId": sid,
							"method":    "Fetch.requestPaused",
							"params": map[string]any{
								"requestId":    "unchosen-xhr",
								"networkId":    "net-unchosen-xhr",
								"frameId":      "main-f",
								"resourceType": "XHR",
								"request": map[string]any{
									"url": "https://app.example.test/api/unchosen.json",
									"headers": map[string]string{
										"Origin":  "https://app.example.test",
										"Referer": "https://app.example.test/secret-api-loader",
									},
								},
							},
						})
						<-sigCh("unchosen-xhr")
					}
					send(map[string]any{
						"sessionId": sid,
						"method":    "Network.responseReceived",
						"params": map[string]any{
							"requestId": "net-unchosen-xhr",
							"frameId":   "main-f",
							"type":      "XHR",
							"response": map[string]any{
								"url":      "https://app.example.test/api/unchosen.json",
								"status":   200,
								"mimeType": "application/json",
							},
						},
					})
					send(map[string]any{
						"sessionId": sid,
						"method":    "Network.loadingFinished",
						"params":    map[string]any{"requestId": "net-unchosen-xhr", "encodedDataLength": 40},
					})
					send(map[string]any{
						"id":        req.ID,
						"sessionId": sid,
						"result":    map[string]any{"result": map[string]any{"type": "string", "value": "ok"}},
					})
				}()
			case strings.Contains(p.Expression, "outerHTML"):
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
				send(map[string]any{
					"id":        req.ID,
					"sessionId": req.SessionID,
					"result":    map[string]any{"result": map[string]any{"type": "string", "value": "ok"}},
				})
			}
		default:
			send(map[string]any{"id": req.ID, "sessionId": req.SessionID, "result": map[string]any{}})
		}
	})

	r := NewMockRenderer("ws://"+strings.TrimPrefix(cdpSrv.URL, "http://"), func(*url.URL) error { return nil }, "EdgeFetch-R11/1.0")
	defer r.Close()

	// Step 1: Headerless render leaves tab on /secret-api-loader.
	out1, err := r.Execute(context.Background(), Task{
		URL:         "https://app.example.test/landing",
		KeepSession: true,
		WaitForMs:   15,
	})
	if err != nil || out1.SessionID == "" {
		t.Fatalf("Step 1 failed: err=%v out=%+v", err, out1)
	}

	// Step 2a (Core S4): Resuming session with custom Headers and NO navigation target MUST fail closed immediately.
	out2a, err := r.Execute(context.Background(), Task{
		SessionID:   out1.SessionID,
		Headers:     map[string]string{"X-Api-Key": "SHOULD_NEVER_ATTACH"},
		KeepSession: true,
		Actions:     []InteractAction{{Type: "wait", WaitMs: 30}},
	})
	if err == nil || !strings.Contains(err.Error(), "without an explicit navigation target") {
		t.Fatalf("SECURITY (S4): expected resumed session with Headers and no navigation target to fail closed, got err=%v out=%+v", err, out2a)
	}
	if len(out2a.CapturedJSON) != 0 {
		t.Fatalf("SECURITY (S4): expected zero CapturedJSON on rejected step, got %+v", out2a.CapturedJSON)
	}

	// Step 2b (Uncommitted pendingStepHeaders cleanup): Pre-navigate action aborts BEFORE navigate runs;
	// staged headers must NOT linger onto a subsequent headerless navigation!
	if _, err := r.Execute(context.Background(), Task{
		SessionID:   out1.SessionID,
		Headers:     map[string]string{"X-Api-Key": "ABORTED_STEP_SECRET"},
		KeepSession: true,
		Actions: []InteractAction{
			{Type: "click", Selector: "#missing-abort", WaitMs: 5},
			{Type: "navigate", URL: "https://app.example.test/authed", WaitMs: 10},
		},
	}); err == nil {
		t.Fatal("expected click #missing-abort to fail before navigate")
	}
	if _, err := r.Execute(context.Background(), Task{
		SessionID:   out1.SessionID,
		URL:         "https://app.example.test/headerless-next",
		KeepSession: true,
		WaitForMs:   15,
	}); err != nil {
		t.Fatalf("headerless follow-up navigation failed: %v", err)
	}
	mu.Lock()
	leakedAborted := hasOverride["headerless-next-doc"] || gotAPIKey["headerless-next-doc"] != ""
	mu.Unlock()
	if leakedAborted {
		t.Fatalf("SECURITY (S4): aborted step's pendingStepHeaders leaked onto subsequent headerless navigation: %+v", gotAPIKey)
	}

	// Step 2c: Resuming session with [click("#trigger-pre-nav-xhr"), navigate("/authed")] + Headers:
	// pre-navigate XHR from unchosen page MUST get ZERO headers and MUST NOT be harvested, while /authed & /api/authed.json DO succeed!
	out2c, err := r.Execute(context.Background(), Task{
		SessionID:   out1.SessionID,
		Headers:     map[string]string{"X-Api-Key": "R11_STEP_SECRET"},
		KeepSession: true,
		Actions: []InteractAction{
			{Type: "click", Selector: "#trigger-pre-nav-xhr", WaitMs: 10},
			{Type: "navigate", URL: "https://app.example.test/authed", WaitMs: 15},
		},
	})
	if err != nil {
		t.Fatalf("Step 2c failed: %v", err)
	}

	mu.Lock()
	unchosenOverridden := hasOverride["unchosen-xhr"] || gotAPIKey["unchosen-xhr"] != ""
	authedDocKey := gotAPIKey["authed-doc"]
	authedAPIKey := gotAPIKey["authed-api"]
	mu.Unlock()
	if unchosenOverridden {
		t.Fatalf("SECURITY (S4): pre-navigate XHR on unchosen page leaked caller headers! got=%+v", gotAPIKey)
	}
	if authedDocKey != "R11_STEP_SECRET" || authedAPIKey != "R11_STEP_SECRET" {
		t.Fatalf("expected /authed Document and post-commit API to receive R11_STEP_SECRET, got doc=%q api=%q", authedDocKey, authedAPIKey)
	}
	if len(out2c.CapturedJSON) != 1 || out2c.CapturedJSON[0].URL != "https://app.example.test/api/authed.json" || strings.Contains(out2c.CapturedJSON[0].Body, "UNCHOSEN") {
		t.Fatalf("expected only /api/authed.json in CapturedJSON, got %+v", out2c.CapturedJSON)
	}

	// Step 2d: Repeating the IDENTICAL already-bound headers on the untainted harness-committed /authed session succeeds,
	// while changing headers without a navigation target fails closed!
	if _, err := r.Execute(context.Background(), Task{
		SessionID:   out1.SessionID,
		Headers:     map[string]string{"X-Api-Key": "R11_STEP_SECRET"},
		KeepSession: true,
		Actions:     []InteractAction{{Type: "wait", WaitMs: 5}},
	}); err != nil {
		t.Fatalf("expected repeating identical active headers on untainted harness-committed doc to succeed: %v", err)
	}
	if _, err := r.Execute(context.Background(), Task{
		SessionID: out1.SessionID,
		Headers:   map[string]string{"X-Api-Key": "DIFFERENT_SECRET_NO_NAV"},
		Actions:   []InteractAction{{Type: "wait", WaitMs: 5}},
	}); err == nil || !strings.Contains(err.Error(), "without an explicit navigation target") {
		t.Fatalf("SECURITY (S4): expected changing headers on resumed session without nav target to fail closed, got %v", err)
	}
}

func TestR11S4LiveChromiumResumedSessionHeaderIsolationIfInstalled(t *testing.T) {
	t.Parallel()
	if runtime.GOOS != "linux" && runtime.GOOS != "windows" {
		return
	}
	bin := FindChromeBinary()
	if bin == "" {
		t.Skip("no headless Chromium/Chrome binary installed; skipping live S4 test")
	}
	acquireLiveChromeSlot(t)

	var (
		mu        sync.Mutex
		sawSecret = make(map[string][]string)
	)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sec := r.Header.Get("X-R11-Secret")
		mu.Lock()
		sawSecret[r.URL.Path] = append(sawSecret[r.URL.Path], sec)
		mu.Unlock()

		switch r.URL.Path {
		case "/public":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write([]byte(`<!doctype html><html><body>
				<a id="to-unchosen" href="/secret-api-loader">Go</a>
				<main>Public Start</main>
			</body></html>`))
		case "/secret-api-loader":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write([]byte(`<!doctype html><html><body>
				<script>
					let n = 0;
					const iv = setInterval(() => {
						if (++n > 20) { clearInterval(iv); return; }
						fetch('/api/unchosen-poll.json').catch(() => {});
					}, 25);
				</script>
				<main id="on-unchosen">Unchosen Loader</main>
			</body></html>`))
		case "/api/unchosen-poll.json":
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			_, _ = w.Write([]byte(`{"items":[{"title":"UNCHOSEN_POLL_SECRET","hdr":` + strconv.Quote(sec) + `}]}`))
		case "/chosen":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write([]byte(`<!doctype html><html><body>
				<script>fetch('/api/chosen.json');</script>
				<main id="on-chosen">Chosen Page</main>
			</body></html>`))
		case "/api/chosen.json":
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			_, _ = w.Write([]byte(`{"items":[{"title":"CHOSEN_OK","hdr":` + strconv.Quote(sec) + `}]}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	srvAddr := srv.Listener.Addr().String()

	r := NewRenderer(bin, func(*url.URL) error { return nil }, "EdgeFetch-R11-Live/1.0", 1, nil)
	enableNoSandboxOnRestrictedLinuxHost(r)
	r.extraFlags = []string{"--ignore-certificate-errors"}
	r.proxyDial = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, srvAddr)
	}
	defer r.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
	defer cancel()

	// Step 1 (headerless): navigate to /public, then click link to /secret-api-loader.
	out1, err := r.Execute(ctx, Task{
		URL:         "https://r11-s4.example.com/public",
		KeepSession: true,
		WaitForMs:   50,
		Actions: []InteractAction{
			{Type: "click", Selector: "#to-unchosen", WaitMs: 50},
			{Type: "wait", Selector: "#on-unchosen", Milliseconds: 3000},
		},
	})
	if err != nil || out1.SessionID == "" {
		t.Fatalf("live Step 1 failed: err=%v out=%+v", err, out1)
	}

	// Step 2a: Resuming with custom Headers and NO navigation target fails closed.
	if _, err := r.Execute(ctx, Task{
		SessionID:   out1.SessionID,
		Headers:     map[string]string{"X-R11-Secret": "LIVE_S4_SECRET"},
		KeepSession: true,
		Actions:     []InteractAction{{Type: "wait", WaitMs: 80}},
	}); err == nil {
		t.Fatal("SECURITY (S4 LIVE): expected resuming with Headers and no navigation target to fail closed")
	}

	// Step 2b: Resuming with [wait(90ms), navigate("/chosen")] + Headers must NOT send LIVE_S4_SECRET to /api/unchosen-poll.json!
	out2b, err := r.Execute(ctx, Task{
		SessionID: out1.SessionID,
		Headers:   map[string]string{"X-R11-Secret": "LIVE_S4_SECRET"},
		Actions: []InteractAction{
			{Type: "wait", WaitMs: 90},
			{Type: "navigate", URL: "https://r11-s4.example.com/chosen", WaitMs: 150},
		},
	})
	if err != nil || !strings.Contains(out2b.HTML, "Chosen Page") {
		t.Fatalf("live Step 2b failed: err=%v html=%q", err, out2b.HTML)
	}

	mu.Lock()
	unchosenHits := append([]string(nil), sawSecret["/api/unchosen-poll.json"]...)
	chosenDocHits := append([]string(nil), sawSecret["/chosen"]...)
	chosenAPIHits := append([]string(nil), sawSecret["/api/chosen.json"]...)
	mu.Unlock()

	for _, s := range unchosenHits {
		if s != "" {
			t.Fatalf("SECURITY (S4 LIVE): /api/unchosen-poll.json received caller header %q! hits=%+v", s, unchosenHits)
		}
	}
	if len(chosenDocHits) == 0 || chosenDocHits[0] != "LIVE_S4_SECRET" || len(chosenAPIHits) == 0 || chosenAPIHits[0] != "LIVE_S4_SECRET" {
		t.Fatalf("expected /chosen and /api/chosen.json to receive LIVE_S4_SECRET, got doc=%+v api=%+v", chosenDocHits, chosenAPIHits)
	}
	for _, cj := range out2b.CapturedJSON {
		if strings.Contains(cj.URL, "unchosen") || strings.Contains(cj.Body, "UNCHOSEN") {
			t.Fatalf("SECURITY (S4 LIVE): unchosen page JSON leaked into CapturedJSON: %+v", out2b.CapturedJSON)
		}
	}
}

func TestR11M4FullPageScreenshotClampingAndErrorPropagation(t *testing.T) {
	t.Parallel()
	// 1. Unit check on clampScreenshotClip for 100,000px height, wide pages, retina DPR=2, and zero/NaN fallback.
	clipTall := clampScreenshotClip(1366, 100_000, 1366, 900, 1.0)
	wTall, _ := clipTall["width"].(float64)
	hTall, _ := clipTall["height"].(float64)
	if wTall != 1366 || hTall > maxScreenshotHeight || wTall*hTall > maxScreenshotArea || hTall != 12282 {
		t.Fatalf("unexpected 100k tall clip: %+v (area=%v)", clipTall, wTall*hTall)
	}
	clipMobile := clampScreenshotClip(390, 100_000, 390, 844, 2.0)
	wMob, _ := clipMobile["width"].(float64)
	hMob, _ := clipMobile["height"].(float64)
	if wMob*hMob*4 > maxScreenshotArea {
		t.Fatalf("mobile DPR=2 device area exceeded maxScreenshotArea: clip=%+v", clipMobile)
	}
	clipFallback := clampScreenshotClip(0, 0, 1366, 900, 1.0)
	if clipFallback["width"] != float64(1366) || clipFallback["height"] != float64(900) {
		t.Fatalf("expected viewport fallback clip 1366x900, got %+v", clipFallback)
	}

	// 2. Mock CDP verification of Page.getLayoutMetrics -> clamped clip AND error propagation on BOTH top-level & action screenshots.
	var (
		mu             sync.Mutex
		failShot       bool
		capturedParams []map[string]any
	)
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
		case "Target.createBrowserContext":
			send(map[string]any{"id": req.ID, "result": map[string]any{"browserContextId": "bc-m4"}})
		case "Target.createTarget":
			send(map[string]any{"id": req.ID, "result": map[string]any{"targetId": "tgt-m4"}})
		case "Target.attachToTarget":
			send(map[string]any{"id": req.ID, "result": map[string]any{"sessionId": "sid-m4"}})
		case "Page.navigate":
			send(map[string]any{"id": req.ID, "sessionId": req.SessionID, "result": map[string]any{"frameId": "f1"}})
			send(map[string]any{"sessionId": req.SessionID, "method": "Page.loadEventFired", "params": map[string]any{}})
		case "Page.getLayoutMetrics":
			send(map[string]any{
				"id":        req.ID,
				"sessionId": req.SessionID,
				"result": map[string]any{
					"cssContentSize": map[string]any{"width": 2000, "height": 100000},
				},
			})
		case "Page.captureScreenshot":
			var p map[string]any
			_ = json.Unmarshal(req.Params, &p)
			mu.Lock()
			capturedParams = append(capturedParams, p)
			shouldFail := failShot
			mu.Unlock()
			if shouldFail {
				send(map[string]any{"id": req.ID, "sessionId": req.SessionID, "error": map[string]any{"code": -32000, "message": "screenshot failed"}})
				return
			}
			send(map[string]any{"id": req.ID, "sessionId": req.SessionID, "result": map[string]any{"data": "CLAMPED_PNG_B64"}})
		case "Runtime.evaluate":
			docJSON, _ := json.Marshal(map[string]string{"url": "https://app.example.test/tall", "html": "<html><body>tall</body></html>"})
			send(map[string]any{"id": req.ID, "sessionId": req.SessionID, "result": map[string]any{"result": map[string]any{"type": "string", "value": string(docJSON)}}})
		default:
			send(map[string]any{"id": req.ID, "sessionId": req.SessionID, "result": map[string]any{}})
		}
	})

	r := NewMockRenderer("ws://"+strings.TrimPrefix(cdpSrv.URL, "http://"), func(*url.URL) error { return nil }, "EdgeFetch-R11/1.0")
	defer r.Close()

	out, err := r.Execute(context.Background(), Task{
		URL:                "https://app.example.test/tall",
		WaitForMs:          10,
		Screenshot:         true,
		ScreenshotFullPage: true,
		Actions:            []InteractAction{{Type: "screenshot", FullPage: true, WaitMs: 1}},
	})
	if err != nil {
		t.Fatalf("Execute full-page screenshot failed: %v", err)
	}
	if out.ScreenshotBase64 != "CLAMPED_PNG_B64" || len(out.ActionScreenshots) != 1 || out.ActionScreenshots[0] != "CLAMPED_PNG_B64" {
		t.Fatalf("unexpected screenshot output: %+v", out)
	}

	mu.Lock()
	paramsSnap := append([]map[string]any(nil), capturedParams...)
	mu.Unlock()
	if len(paramsSnap) != 2 {
		t.Fatalf("expected 2 Page.captureScreenshot calls, got %d", len(paramsSnap))
	}
	for idx, p := range paramsSnap {
		clip, ok := p["clip"].(map[string]any)
		if !ok {
			t.Fatalf("call %d missing clamped clip: %+v", idx, p)
		}
		cw, _ := clip["width"].(float64)
		ch, _ := clip["height"].(float64)
		// 2000 * 8388 == 16,776,000 <= 16,777,216
		if cw != 2000 || ch != 8388 || cw*ch > maxScreenshotArea {
			t.Fatalf("call %d unexpected clamped clip dimensions: %+v", idx, clip)
		}
	}

	// Verify top-level Task{Screenshot: true} propagates Page.captureScreenshot errors instead of swallowing them!
	mu.Lock()
	failShot = true
	mu.Unlock()
	if _, err := r.Execute(context.Background(), Task{
		URL:        "https://app.example.test/tall",
		WaitForMs:  10,
		Screenshot: true,
	}); err == nil || !strings.Contains(err.Error(), "capture screenshot") {
		t.Fatalf("expected top-level Task.Screenshot error to be returned, got: %v", err)
	}
	if _, err := r.Execute(context.Background(), Task{
		URL:       "https://app.example.test/tall",
		WaitForMs: 10,
		Actions:   []InteractAction{{Type: "screenshot", FullPage: true, WaitMs: 1}},
	}); err == nil || !strings.Contains(err.Error(), "capture screenshot") {
		t.Fatalf("expected screenshot action error to be returned, got: %v", err)
	}
}

func TestR11M4CDPOversizedReplyIsolationOnPipeAndWebSocket(t *testing.T) {
	t.Parallel()
	// Direct chunk-boundary & escape edge cases for cdpStreamingIDScanner fast-forward path.
	{
		raw := `  {"longTopKeyWith\"Escapes\\": "val\\\"id\":777\\\\", "result":{"id":888,"s":"a\"b\\c"},"i\u0064":111,"id" : 4242}`
		for step := 1; step <= 17; step += 4 {
			var sc cdpStreamingIDScanner
			for off := 0; off < len(raw); off += step {
				end := off + step
				if end > len(raw) {
					end = len(raw)
				}
				sc.feed([]byte(raw[off:end]))
			}
			if got := sc.resultID(); got != 4242 {
				t.Fatalf("cdpStreamingIDScanner step=%d expected id=4242, got %d", step, got)
			}
		}
	}

	bigPayloadLen := maxCDPFrameBytes + (2 << 20) // 26 MiB > 24 MiB cap
	bigPad := strings.Repeat("X", bigPayloadLen)

	t.Run("pipe_transport_isolates_oversized_reply_and_keeps_conn_alive", func(t *testing.T) {
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

		go func() {
			var buf []byte
			tmp := make([]byte, 4096)
			for {
				n, rErr := toChromeR.Read(tmp)
				if n > 0 {
					buf = append(buf, tmp[:n]...)
					for {
						nul := bytes.IndexByte(buf, 0)
						if nul < 0 {
							break
						}
						frame := buf[:nul]
						buf = buf[nul+1:]
						var req cdpRequest
						if json.Unmarshal(frame, &req) != nil {
							continue
						}
						switch req.Method {
						case "Test.oversizedPrefixID":
							// Standard Chromium layout: "id" at start, followed by >24 MiB payload + NUL,
							// plus an oversized async event with nested decoy "id" and NO top-level "id"!
							evMsg := `{"method":"Network.dataReceived","params":{"nested":{"id":999999},"blob":"` + bigPad + `"}}` + "\x00"
							_, _ = fromChromeW.Write([]byte(evMsg))
							reply := fmt.Sprintf(`{"id":%d,"result":{"data":"%s"}}`+"\x00", req.ID, bigPad)
							_, _ = fromChromeW.Write([]byte(reply))
						case "Test.oversizedTrailingID":
							// Adversarial/struct field order: nested decoy "id" inside "result", real top-level "id" at the VERY END after 26 MiB!
							reply := fmt.Sprintf(`{"sessionId":"s1","result":{"id":888888,"data":"%s"},"id":%d}`+"\x00", bigPad, req.ID)
							_, _ = fromChromeW.Write([]byte(reply))
						default:
							resp, _ := json.Marshal(map[string]any{
								"id":     req.ID,
								"result": map[string]any{"echo": req.Method},
							})
							_, _ = fromChromeW.Write(append(resp, 0))
						}
					}
				}
				if rErr != nil {
					return
				}
			}
		}()

		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()

		// Fire concurrent oversized call + healthy sibling call on the SAME shared pipe cdpConn!
		var wg sync.WaitGroup
		var bigErr1, bigErr2, siblingErr error
		var siblingOut struct {
			Echo string `json:"echo"`
		}
		wg.Add(3)
		go func() {
			defer wg.Done()
			bigErr1 = conn.call(ctx, "tab-a", "Test.oversizedPrefixID", nil, nil)
		}()
		go func() {
			defer wg.Done()
			bigErr2 = conn.call(ctx, "tab-a", "Test.oversizedTrailingID", nil, nil)
		}()
		go func() {
			defer wg.Done()
			siblingErr = conn.call(ctx, "tab-b", "Test.concurrentHealthyTab", nil, &siblingOut)
		}()
		wg.Wait()

		if !errors.Is(bigErr1, errCDPFrameTooLarge) {
			t.Fatalf("expected Test.oversizedPrefixID to fail with errCDPFrameTooLarge, got: %v", bigErr1)
		}
		if !errors.Is(bigErr2, errCDPFrameTooLarge) {
			t.Fatalf("expected Test.oversizedTrailingID to fail with errCDPFrameTooLarge, got: %v", bigErr2)
		}
		if siblingErr != nil || siblingOut.Echo != "Test.concurrentHealthyTab" {
			t.Fatalf("sibling tab call failed when another tab exceeded frame cap: err=%v out=%+v", siblingErr, siblingOut)
		}
		if conn.isClosed() {
			t.Fatal("shared pipe cdpConn MUST remain open after isolating oversized per-call replies")
		}

		// Subsequent call on the same pipe cdpConn must also succeed!
		var afterOut struct {
			Echo string `json:"echo"`
		}
		if err := conn.call(ctx, "tab-c", "Test.afterOversized", nil, &afterOut); err != nil || afterOut.Echo != "Test.afterOversized" {
			t.Fatalf("subsequent call after oversized frame failed: err=%v out=%+v", err, afterOut)
		}
	})

	t.Run("websocket_transport_isolates_oversized_reply_and_keeps_conn_alive", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			wsConn, err := websocket.Accept(w, r, nil)
			if err != nil {
				return
			}
			wsConn.SetReadLimit(maxCDPDrainBytes)
			defer wsConn.CloseNow()

			var writeMu sync.Mutex
			sendRaw := func(b []byte) {
				writeMu.Lock()
				_ = wsConn.Write(r.Context(), websocket.MessageText, b)
				writeMu.Unlock()
			}
			for {
				_, raw, err := wsConn.Read(r.Context())
				if err != nil {
					return
				}
				var req cdpRequest
				if json.Unmarshal(raw, &req) != nil {
					continue
				}
				go func(req cdpRequest) {
					switch req.Method {
					case "Test.wsOversized":
						reply := fmt.Sprintf(`{"result":{"data":"%s"},"id":%d}`, bigPad, req.ID)
						sendRaw([]byte(reply))
					default:
						resp, _ := json.Marshal(map[string]any{"id": req.ID, "result": map[string]any{"echo": req.Method}})
						sendRaw(resp)
					}
				}(req)
			}
		}))
		defer srv.Close()

		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()

		conn, err := dialCDP(ctx, "ws://"+strings.TrimPrefix(srv.URL, "http://"))
		if err != nil {
			t.Fatalf("dialCDP: %v", err)
		}
		defer conn.close()

		var wg sync.WaitGroup
		var overErr, okErr error
		var okOut struct {
			Echo string `json:"echo"`
		}
		wg.Add(2)
		go func() {
			defer wg.Done()
			overErr = conn.call(ctx, "s-over", "Test.wsOversized", nil, nil)
		}()
		go func() {
			defer wg.Done()
			okErr = conn.call(ctx, "s-ok", "Test.wsHealthyConcurrent", nil, &okOut)
		}()
		wg.Wait()

		if !errors.Is(overErr, errCDPFrameTooLarge) {
			t.Fatalf("expected WS oversized call to fail with errCDPFrameTooLarge, got: %v", overErr)
		}
		if okErr != nil || okOut.Echo != "Test.wsHealthyConcurrent" {
			t.Fatalf("expected concurrent WS call to succeed, got err=%v out=%+v", okErr, okOut)
		}
		if conn.isClosed() {
			t.Fatal("shared WebSocket cdpConn MUST remain open after isolating oversized reply")
		}

		var postOut struct {
			Echo string `json:"echo"`
		}
		if err := conn.call(ctx, "s-post", "Test.wsAfterOversized", nil, &postOut); err != nil || postOut.Echo != "Test.wsAfterOversized" {
			t.Fatalf("expected post-oversized WS call to succeed, got err=%v out=%+v", err, postOut)
		}
	})
}

func TestR11M4LiveChromium100kTallFullPageScreenshotClampedIfInstalled(t *testing.T) {
	t.Parallel()
	if runtime.GOOS != "linux" && runtime.GOOS != "windows" {
		return
	}
	bin := FindChromeBinary()
	if bin == "" {
		t.Skip("no headless Chromium/Chrome binary installed; skipping live M4 tall screenshot test")
	}
	acquireLiveChromeSlot(t)

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(`<!doctype html><html><body style="margin:0;padding:0">
			<div style="width:1366px;height:100000px;background:#123"><h1>100k Tall Page</h1></div>
		</body></html>`))
	}))
	defer srv.Close()
	srvAddr := srv.Listener.Addr().String()

	r := NewRenderer(bin, func(*url.URL) error { return nil }, "EdgeFetch-R11-M4/1.0", 2, nil)
	enableNoSandboxOnRestrictedLinuxHost(r)
	r.extraFlags = []string{"--ignore-certificate-errors"}
	r.proxyDial = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, srvAddr)
	}
	defer r.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	out, err := r.Execute(ctx, Task{
		URL:                "https://r11-m4.example.com/tall",
		WaitForMs:          50,
		Screenshot:         true,
		ScreenshotFullPage: true,
		Actions:            []InteractAction{{Type: "screenshot", FullPage: true, WaitMs: 10}},
	})
	if err != nil {
		t.Fatalf("live 100,000px full-page screenshot failed: %v", err)
	}
	if out.ScreenshotBase64 == "" || len(out.ActionScreenshots) != 1 {
		t.Fatalf("expected non-empty top-level and action screenshots, got len(top)=%d actions=%d", len(out.ScreenshotBase64), len(out.ActionScreenshots))
	}
	rawPNG, err := base64.StdEncoding.DecodeString(out.ScreenshotBase64)
	if err != nil {
		t.Fatalf("decode PNG base64: %v", err)
	}
	cfg, err := png.DecodeConfig(bytes.NewReader(rawPNG))
	if err != nil {
		t.Fatalf("png.DecodeConfig: %v", err)
	}
	if cfg.Height > maxScreenshotHeight || cfg.Width*cfg.Height > maxScreenshotArea {
		t.Fatalf("expected PNG dimensions clamped within maxScreenshotHeight=%d and maxScreenshotArea=%d, got %dx%d",
			maxScreenshotHeight, maxScreenshotArea, cfg.Width, cfg.Height)
	}
}

func TestR11S4AuditNetFloodPushStateResumeAndHeaderlessRedirectJSON(t *testing.T) {
	t.Parallel()
	// 1. Finding 1: Queueing > maxSessionNetEntries (512) benign OR tainted requests MUST NEVER wipe taintedNetReqs
	//    or allow an earlier 3rd-party-script-initiated request ("net-evil-1") to receive caller Headers or be harvested.
	t.Run("net_request_flood_never_wipes_taint_and_saturates_closed", func(t *testing.T) {
		t.Parallel()
		var (
			mu          sync.Mutex
			evilHeaders []any
		)
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
			case "Target.createBrowserContext":
				send(map[string]any{"id": req.ID, "result": map[string]any{"browserContextId": "bc-f1"}})
			case "Target.createTarget":
				send(map[string]any{"id": req.ID, "result": map[string]any{"targetId": "tgt-f1"}})
			case "Target.attachToTarget":
				send(map[string]any{"id": req.ID, "result": map[string]any{"sessionId": "sid-f1"}})
			case "Page.getFrameTree":
				send(map[string]any{
					"id":        req.ID,
					"sessionId": req.SessionID,
					"result": map[string]any{
						"frameTree": map[string]any{
							"frame": map[string]any{"id": "main-f1", "loaderId": "ldr-init", "url": "about:blank"},
						},
					},
				})
			case "Page.navigate":
				send(map[string]any{"id": req.ID, "sessionId": req.SessionID, "result": map[string]any{"frameId": "main-f1", "loaderId": "ldr-f1"}})
				send(map[string]any{
					"sessionId": req.SessionID,
					"method":    "Fetch.requestPaused",
					"params": map[string]any{
						"requestId":    "f-doc-1",
						"networkId":    "n-doc-1",
						"frameId":      "main-f1",
						"resourceType": "Document",
						"request":      map[string]any{"url": "https://app.example.test/home", "method": "GET", "headers": map[string]any{}},
					},
				})
			case "Fetch.continueRequest":
				var p struct {
					RequestID string `json:"requestId"`
					Headers   []any  `json:"headers"`
				}
				_ = json.Unmarshal(req.Params, &p)
				send(map[string]any{"id": req.ID, "sessionId": req.SessionID, "result": map[string]any{}})
				switch p.RequestID {
				case "f-doc-1":
					send(map[string]any{
						"sessionId": req.SessionID,
						"method":    "Page.frameNavigated",
						"params": map[string]any{
							"frame": map[string]any{
								"id":             "main-f1",
								"loaderId":       "ldr-f1",
								"url":            "https://app.example.test/home",
								"securityOrigin": "https://app.example.test",
							},
						},
					})
					// 3rd-party script queues "net-evil-1" FIRST, then floods 600 benign + 600 tainted requests before Fetch.requestPaused!
					send(map[string]any{
						"sessionId": req.SessionID,
						"method":    "Network.requestWillBeSent",
						"params": map[string]any{
							"requestId":   "net-evil-1",
							"loaderId":    "ldr-f1",
							"frameId":     "main-f1",
							"type":        "Fetch",
							"documentURL": "https://app.example.test/home",
							"request":     map[string]any{"url": "https://app.example.test/api/keys.json", "method": "GET"},
							"initiator":   map[string]any{"type": "script", "url": "https://cdn.evil.test/sdk.js"},
						},
					})
					for i := 0; i < 600; i++ {
						send(map[string]any{
							"sessionId": req.SessionID,
							"method":    "Network.requestWillBeSent",
							"params": map[string]any{
								"requestId":   fmt.Sprintf("net-benign-%d", i),
								"loaderId":    "ldr-f1",
								"frameId":     "main-f1",
								"type":        "Fetch",
								"documentURL": "https://app.example.test/home",
								"request":     map[string]any{"url": "https://app.example.test/ping", "method": "GET"},
								"initiator":   map[string]any{"type": "script", "url": "https://app.example.test/app.js"},
							},
						})
					}
					for i := 0; i < 600; i++ {
						send(map[string]any{
							"sessionId": req.SessionID,
							"method":    "Network.requestWillBeSent",
							"params": map[string]any{
								"requestId":   fmt.Sprintf("net-flood-evil-%d", i),
								"loaderId":    "ldr-f1",
								"frameId":     "main-f1",
								"type":        "Fetch",
								"documentURL": "https://app.example.test/home",
								"request":     map[string]any{"url": "https://cdn.evil.test/beacon", "method": "GET"},
								"initiator":   map[string]any{"type": "script", "url": "https://cdn.evil.test/sdk.js"},
							},
						})
					}
					// Now pause "net-evil-1" with initiator omitted on Fetch.requestPaused (relying on Network.requestWillBeSent taint!).
					send(map[string]any{
						"sessionId": req.SessionID,
						"method":    "Fetch.requestPaused",
						"params": map[string]any{
							"requestId":    "f-evil-1",
							"networkId":    "net-evil-1",
							"frameId":      "main-f1",
							"resourceType": "Fetch",
							"request": map[string]any{
								"url":     "https://app.example.test/api/keys.json",
								"method":  "GET",
								"headers": map[string]any{"Referer": "https://app.example.test/home"},
							},
						},
					})
				case "f-evil-1":
					mu.Lock()
					evilHeaders = p.Headers
					mu.Unlock()
					send(map[string]any{
						"sessionId": req.SessionID,
						"method":    "Network.responseReceived",
						"params": map[string]any{
							"requestId": "net-evil-1",
							"frameId":   "main-f1",
							"type":      "Fetch",
							"response": map[string]any{
								"url":      "https://app.example.test/api/keys.json",
								"status":   200,
								"mimeType": "application/json",
							},
						},
					})
					send(map[string]any{
						"sessionId": req.SessionID,
						"method":    "Network.loadingFinished",
						"params":    map[string]any{"requestId": "net-evil-1", "encodedDataLength": 24},
					})
					send(map[string]any{"sessionId": req.SessionID, "method": "Page.loadEventFired", "params": map[string]any{}})
				}
			case "Network.getResponseBody":
				send(map[string]any{"id": req.ID, "sessionId": req.SessionID, "result": map[string]any{"body": `{"leaked":true}`}})
			case "Runtime.evaluate":
				docJSON, _ := json.Marshal(map[string]string{"url": "https://app.example.test/home", "html": "<html><body>ok</body></html>"})
				send(map[string]any{"id": req.ID, "sessionId": req.SessionID, "result": map[string]any{"result": map[string]any{"type": "string", "value": string(docJSON)}}})
			default:
				send(map[string]any{"id": req.ID, "sessionId": req.SessionID, "result": map[string]any{}})
			}
		})

		r := NewMockRenderer("ws://"+strings.TrimPrefix(cdpSrv.URL, "http://"), func(*url.URL) error { return nil }, "EdgeFetch-R11/1.0")
		defer r.Close()

		out, err := r.Execute(context.Background(), Task{
			URL:       "https://app.example.test/home",
			Headers:   map[string]string{"Authorization": "Bearer TOP_SECRET_F1"},
			WaitForMs: 30,
		})
		if err != nil {
			t.Fatalf("Execute failed: %v", err)
		}
		mu.Lock()
		hdrsRaw, _ := json.Marshal(evilHeaders)
		mu.Unlock()
		if strings.Contains(string(hdrsRaw), "TOP_SECRET_F1") {
			t.Fatalf("SECURITY (Finding 1): >512 request flood wiped taint and leaked Authorization header: %s", string(hdrsRaw))
		}
		if len(out.CapturedJSON) != 0 {
			t.Fatalf("SECURITY (Finding 1): tainted request JSON harvested after >512 flood: %+v", out.CapturedJSON)
		}
	})

	// 2. Finding 2: In-document pushState (`Page.navigatedWithinDocument`) OR `Page.getFrameTree` failure on resume
	//    MUST block resuming a session with custom Headers and no explicit navigation target.
	t.Run("pushstate_and_getframetree_error_fail_closed_on_resume", func(t *testing.T) {
		t.Parallel()
		var (
			mu               sync.Mutex
			currentTreeURL   = "about:blank"
			failGetFrameTree bool
		)
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
			case "Target.createBrowserContext":
				send(map[string]any{"id": req.ID, "result": map[string]any{"browserContextId": "bc-f2"}})
			case "Target.createTarget":
				send(map[string]any{"id": req.ID, "result": map[string]any{"targetId": "tgt-f2"}})
			case "Target.attachToTarget":
				send(map[string]any{"id": req.ID, "result": map[string]any{"sessionId": "sid-f2"}})
			case "Page.getFrameTree":
				mu.Lock()
				u := currentTreeURL
				shouldFail := failGetFrameTree
				mu.Unlock()
				if shouldFail {
					send(map[string]any{"id": req.ID, "sessionId": req.SessionID, "error": map[string]any{"code": -32000, "message": "tree unavailable"}})
					return
				}
				send(map[string]any{
					"id":        req.ID,
					"sessionId": req.SessionID,
					"result": map[string]any{
						"frameTree": map[string]any{
							"frame": map[string]any{"id": "main-f2", "loaderId": "ldr-f2", "url": u},
						},
					},
				})
			case "Page.navigate":
				send(map[string]any{"id": req.ID, "sessionId": req.SessionID, "result": map[string]any{"frameId": "main-f2", "loaderId": "ldr-f2"}})
				send(map[string]any{
					"sessionId": req.SessionID,
					"method":    "Fetch.requestPaused",
					"params": map[string]any{
						"requestId":    "f-nav-f2",
						"frameId":      "main-f2",
						"resourceType": "Document",
						"request":      map[string]any{"url": "https://spa.example.test/chosen", "method": "GET", "headers": map[string]any{}},
					},
				})
			case "Fetch.continueRequest":
				send(map[string]any{"id": req.ID, "sessionId": req.SessionID, "result": map[string]any{}})
				mu.Lock()
				currentTreeURL = "https://spa.example.test/unchosen-pushstate"
				mu.Unlock()
				send(map[string]any{
					"sessionId": req.SessionID,
					"method":    "Page.frameNavigated",
					"params": map[string]any{
						"frame": map[string]any{
							"id":             "main-f2",
							"loaderId":       "ldr-f2",
							"url":            "https://spa.example.test/chosen",
							"securityOrigin": "https://spa.example.test",
						},
					},
				})
				// SPA immediately calls history.pushState to an unchosen route!
				send(map[string]any{
					"sessionId": req.SessionID,
					"method":    "Page.navigatedWithinDocument",
					"params": map[string]any{
						"frameId": "main-f2",
						"url":     "https://spa.example.test/unchosen-pushstate",
					},
				})
				send(map[string]any{"sessionId": req.SessionID, "method": "Page.loadEventFired", "params": map[string]any{}})
			case "Runtime.evaluate":
				mu.Lock()
				u := currentTreeURL
				mu.Unlock()
				docJSON, _ := json.Marshal(map[string]string{"url": u, "html": "<html><body>spa</body></html>"})
				send(map[string]any{"id": req.ID, "sessionId": req.SessionID, "result": map[string]any{"result": map[string]any{"type": "string", "value": string(docJSON)}}})
			default:
				send(map[string]any{"id": req.ID, "sessionId": req.SessionID, "result": map[string]any{}})
			}
		})

		r := NewMockRenderer("ws://"+strings.TrimPrefix(cdpSrv.URL, "http://"), func(*url.URL) error { return nil }, "EdgeFetch-R11/1.0")
		defer r.Close()

		out1, err := r.Execute(context.Background(), Task{
			URL:         "https://spa.example.test/chosen",
			Headers:     map[string]string{"Authorization": "Bearer SPA_SECRET"},
			KeepSession: true,
			WaitForMs:   20,
		})
		if err != nil || out1.SessionID == "" {
			t.Fatalf("Step 1 failed: err=%v out=%+v", err, out1)
		}

		// Step 2a: Resuming with same Headers and NO navigation target after pushState MUST fail closed!
		if _, err := r.Execute(context.Background(), Task{
			SessionID:   out1.SessionID,
			Headers:     map[string]string{"Authorization": "Bearer SPA_SECRET"},
			KeepSession: true,
			Actions:     []InteractAction{{Type: "wait", WaitMs: 10}},
		}); err == nil {
			t.Fatal("SECURITY (Finding 2): expected resume with Headers and no navigation target after pushState to fail closed")
		}

		// Step 2b: Even if Page.getFrameTree errors on resume, resume with Headers and no nav target MUST fail closed!
		mu.Lock()
		failGetFrameTree = true
		mu.Unlock()
		if _, err := r.Execute(context.Background(), Task{
			SessionID: out1.SessionID,
			Headers:   map[string]string{"Authorization": "Bearer SPA_SECRET"},
			Actions:   []InteractAction{{Type: "wait", WaitMs: 10}},
		}); err == nil {
			t.Fatal("SECURITY (Finding 2): expected Page.getFrameTree error on resume to fail closed")
		}
	})

	// 3. Finding 3: Headerless cross-origin 302 redirect (e.g. careers vanity URL -> hosted ATS board) AND resumed
	//    headerless cross-origin navigation MUST still harvest legitimate same-origin XHR/Fetch CapturedJSON, while
	//    still rejecting 3rd-party-script-initiated XHRs!
	t.Run("headerless_cross_origin_redirect_and_resume_harvest_legitimate_json", func(t *testing.T) {
		t.Parallel()
		var (
			mu      sync.Mutex
			treeURL = "about:blank"
		)
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
			case "Target.createBrowserContext":
				send(map[string]any{"id": req.ID, "result": map[string]any{"browserContextId": "bc-f3"}})
			case "Target.createTarget":
				send(map[string]any{"id": req.ID, "result": map[string]any{"targetId": "tgt-f3"}})
			case "Target.attachToTarget":
				send(map[string]any{"id": req.ID, "result": map[string]any{"sessionId": "sid-f3"}})
			case "Page.getFrameTree":
				mu.Lock()
				u := treeURL
				mu.Unlock()
				send(map[string]any{
					"id":        req.ID,
					"sessionId": req.SessionID,
					"result": map[string]any{
						"frameTree": map[string]any{
							"frame": map[string]any{"id": "main-f3", "loaderId": "ldr-f3", "url": u},
						},
					},
				})
			case "Page.navigate":
				var navP struct {
					URL string `json:"url"`
				}
				_ = json.Unmarshal(req.Params, &navP)
				landedURL := "https://jobs.ats.example.test/acme"
				apiURL := "https://jobs.ats.example.test/api/postings.json"
				if strings.Contains(navP.URL, "second-ats.example.test") {
					landedURL = "https://second-ats.example.test/board"
					apiURL = "https://second-ats.example.test/api/roles.json"
				}
				mu.Lock()
				treeURL = landedURL
				mu.Unlock()
				send(map[string]any{"id": req.ID, "sessionId": req.SessionID, "result": map[string]any{"frameId": "main-f3", "loaderId": "ldr-f3"}})
				send(map[string]any{
					"sessionId": req.SessionID,
					"method":    "Page.frameNavigated",
					"params": map[string]any{
						"frame": map[string]any{
							"id":             "main-f3",
							"loaderId":       "ldr-f3",
							"url":            landedURL,
							"securityOrigin": canonicalURLOrigin(landedURL),
						},
					},
				})
				// Legitimate first-party ATS JSON XHR
				send(map[string]any{
					"sessionId": req.SessionID,
					"method":    "Network.requestWillBeSent",
					"params": map[string]any{
						"requestId":   "req-good-json",
						"loaderId":    "ldr-f3",
						"frameId":     "main-f3",
						"type":        "Fetch",
						"documentURL": landedURL,
						"request":     map[string]any{"url": apiURL, "method": "GET"},
						"initiator":   map[string]any{"type": "script", "url": landedURL + "/bundle.js"},
					},
				})
				send(map[string]any{
					"sessionId": req.SessionID,
					"method":    "Network.responseReceived",
					"params": map[string]any{
						"requestId": "req-good-json",
						"frameId":   "main-f3",
						"type":      "Fetch",
						"response":  map[string]any{"url": apiURL, "status": 200, "mimeType": "application/json"},
					},
				})
				send(map[string]any{"sessionId": req.SessionID, "method": "Network.loadingFinished", "params": map[string]any{"requestId": "req-good-json", "encodedDataLength": 32}})
				// 3rd-party-script-initiated JSON XHR (must still be rejected even on headerless session!)
				send(map[string]any{
					"sessionId": req.SessionID,
					"method":    "Network.requestWillBeSent",
					"params": map[string]any{
						"requestId":   "req-3p-evil",
						"loaderId":    "ldr-f3",
						"frameId":     "main-f3",
						"type":        "Fetch",
						"documentURL": landedURL,
						"request":     map[string]any{"url": apiURL + "?evil=1", "method": "GET"},
						"initiator":   map[string]any{"type": "script", "url": "https://cdn.evil.test/tracker.js"},
					},
				})
				send(map[string]any{
					"sessionId": req.SessionID,
					"method":    "Network.responseReceived",
					"params": map[string]any{
						"requestId": "req-3p-evil",
						"frameId":   "main-f3",
						"type":      "Fetch",
						"response":  map[string]any{"url": apiURL + "?evil=1", "status": 200, "mimeType": "application/json"},
					},
				})
				send(map[string]any{"sessionId": req.SessionID, "method": "Network.loadingFinished", "params": map[string]any{"requestId": "req-3p-evil", "encodedDataLength": 32}})
				send(map[string]any{"sessionId": req.SessionID, "method": "Page.loadEventFired", "params": map[string]any{}})
			case "Network.getResponseBody":
				var bp struct {
					RequestID string `json:"requestId"`
				}
				_ = json.Unmarshal(req.Params, &bp)
				if bp.RequestID == "req-3p-evil" {
					send(map[string]any{"id": req.ID, "sessionId": req.SessionID, "result": map[string]any{"body": `{"evil":true}`}})
				} else {
					send(map[string]any{"id": req.ID, "sessionId": req.SessionID, "result": map[string]any{"body": `{"jobs":[{"title":"Staff Engineer"}]}`}})
				}
			case "Runtime.evaluate":
				mu.Lock()
				u := treeURL
				mu.Unlock()
				docJSON, _ := json.Marshal(map[string]string{"url": u, "html": "<html><body><h1>Jobs</h1></body></html>"})
				send(map[string]any{"id": req.ID, "sessionId": req.SessionID, "result": map[string]any{"result": map[string]any{"type": "string", "value": string(docJSON)}}})
			default:
				send(map[string]any{"id": req.ID, "sessionId": req.SessionID, "result": map[string]any{}})
			}
		})

		r := NewMockRenderer("ws://"+strings.TrimPrefix(cdpSrv.URL, "http://"), func(*url.URL) error { return nil }, "EdgeFetch-R11/1.0")
		defer r.Close()

		// Step 1: Vanity URL 302-redirecting cross-origin to hosted ATS board (headerless)
		out1, err := r.Execute(context.Background(), Task{
			URL:         "https://acme.example.test/careers",
			KeepSession: true,
			WaitForMs:   20,
		})
		if err != nil {
			t.Fatalf("headerless redirect Execute failed: %v", err)
		}
		if len(out1.CapturedJSON) != 1 || !strings.Contains(out1.CapturedJSON[0].Body, "Staff Engineer") {
			t.Fatalf("expected 1 harvested ATS JSON after headerless cross-origin redirect, got: %+v", out1.CapturedJSON)
		}

		// Step 2: Resumed headerless session navigating to a second cross-origin domain
		out2, err := r.Execute(context.Background(), Task{
			SessionID: out1.SessionID,
			URL:       "https://second-ats.example.test/board",
			WaitForMs: 20,
		})
		if err != nil {
			t.Fatalf("resumed headerless Execute failed: %v", err)
		}
		if len(out2.CapturedJSON) != 1 || !strings.Contains(out2.CapturedJSON[0].URL, "second-ats.example.test/api/roles.json") {
			t.Fatalf("expected 1 harvested JSON on resumed headerless cross-origin step, got: %+v", out2.CapturedJSON)
		}
	})
}
