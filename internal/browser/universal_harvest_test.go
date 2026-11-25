package browser

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
)

func TestJSONResponseHarvesterSameOriginIsolationAndBounds(t *testing.T) {
	t.Parallel()
	bodies := map[string]struct {
		body string
		b64  bool
	}{
		"req-same-1": {
			body: `{"total":2,"items":[{"title":"Role A","url":"https://app.example.com/jobs/1"},{"title":"Role B","url":"https://app.example.com/jobs/2"}]}`,
		},
		"req-same-b64": {
			body: base64.StdEncoding.EncodeToString([]byte(`[{"title":"Encoded Item","url":"https://app.example.com/p/1"}]`)),
			b64:  true,
		},
		"req-cross-origin": {
			body: `{"items":[{"title":"Cross Origin Leak"}]}`,
		},
		"req-child-frame": {
			body: `{"items":[{"title":"Iframe Subresource Leak"}]}`,
		},
		"req-non-json": {
			body: `<html><body>not json</body></html>`,
		},
		"req-invalid-json": {
			body: `{truncated`,
		},
	}

	var requestedBodyIDs []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		conn, err := websocket.Accept(w, req, nil)
		if err != nil {
			return
		}
		defer conn.CloseNow()
		for {
			_, raw, err := conn.Read(req.Context())
			if err != nil {
				return
			}
			var msg struct {
				ID        int64           `json:"id"`
				SessionID string          `json:"sessionId"`
				Method    string          `json:"method"`
				Params    json.RawMessage `json:"params"`
			}
			if err := json.Unmarshal(raw, &msg); err != nil {
				continue
			}
			reply := func(res any) {
				b, _ := json.Marshal(map[string]any{
					"id":        msg.ID,
					"sessionId": msg.SessionID,
					"result":    res,
				})
				_ = conn.Write(req.Context(), websocket.MessageText, b)
			}
			switch msg.Method {
			case "Network.getResponseBody":
				var params struct {
					RequestID string `json:"requestId"`
				}
				_ = json.Unmarshal(msg.Params, &params)
				requestedBodyIDs = append(requestedBodyIDs, params.RequestID)
				entry := bodies[params.RequestID]
				reply(map[string]any{
					"body":          entry.body,
					"base64Encoded": entry.b64,
				})
			default:
				reply(map[string]any{})
			}
		}
	}))
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")
	cdp, err := dialCDP(context.Background(), wsURL)
	if err != nil {
		t.Fatalf("dialCDP: %v", err)
	}
	defer cdp.close()

	const sid = "sess-1"
	h := newJSONResponseHarvester(sid, "main-frame")

	emit := func(method string, payload any) {
		raw, _ := json.Marshal(payload)
		h.handleEvent(cdpEvent{SessionID: sid, Method: method, Params: raw})
	}

	// Top-level navigation commit resets prior state and pins mainFrameID
	emit("Page.frameNavigated", map[string]any{
		"frame": map[string]any{"id": "main-frame", "parentId": ""},
	})
	// Attach child iframe -> must be marked untrusted
	emit("Page.frameAttached", map[string]any{
		"frameId": "child-iframe", "parentFrameId": "main-frame",
	})

	// 1. Valid same-origin XHR JSON
	emit("Network.requestWillBeSent", map[string]any{
		"requestId":   "req-same-1",
		"frameId":     "main-frame",
		"type":        "XHR",
		"documentURL": "https://app.example.com/jobs",
		"initiator":   map[string]any{"url": "https://app.example.com/static/app.js"},
		"request":     map[string]any{"url": "https://app.example.com/api/jobs", "method": "POST"},
	})
	emit("Network.responseReceived", map[string]any{
		"requestId": "req-same-1",
		"frameId":   "main-frame",
		"type":      "XHR",
		"response": map[string]any{
			"url":      "https://app.example.com/api/jobs",
			"status":   200,
			"mimeType": "application/json",
			"headers":  map[string]string{"content-type": "application/json; charset=utf-8"},
		},
	})
	emit("Network.loadingFinished", map[string]any{"requestId": "req-same-1", "encodedDataLength": 140})

	// 2. Valid same-origin Fetch with base64Encoded body and +json MIME
	emit("Network.requestWillBeSent", map[string]any{
		"requestId":   "req-same-b64",
		"frameId":     "main-frame",
		"type":        "Fetch",
		"documentURL": "https://app.example.com/jobs",
		"request":     map[string]any{"url": "https://app.example.com/api/featured", "method": "GET"},
	})
	emit("Network.responseReceived", map[string]any{
		"requestId": "req-same-b64",
		"frameId":   "main-frame",
		"type":      "Fetch",
		"response": map[string]any{
			"url":      "https://app.example.com/api/featured",
			"status":   200,
			"mimeType": "application/vnd.api+json",
		},
	})
	emit("Network.loadingFinished", map[string]any{"requestId": "req-same-b64", "encodedDataLength": 80})

	// 3. Cross-origin XHR -> MUST NOT even call Network.getResponseBody!
	emit("Network.requestWillBeSent", map[string]any{
		"requestId":   "req-cross-origin",
		"frameId":     "main-frame",
		"type":        "Fetch",
		"documentURL": "https://app.example.com/jobs",
		"request":     map[string]any{"url": "https://api.other-origin.example/v1/jobs", "method": "GET"},
	})
	emit("Network.responseReceived", map[string]any{
		"requestId": "req-cross-origin",
		"frameId":   "main-frame",
		"type":      "Fetch",
		"response": map[string]any{
			"url":      "https://api.other-origin.example/v1/jobs",
			"status":   200,
			"mimeType": "application/json",
		},
	})
	emit("Network.loadingFinished", map[string]any{"requestId": "req-cross-origin", "encodedDataLength": 42})

	// 4. Child iframe same-origin XHR -> MUST be rejected!
	emit("Network.requestWillBeSent", map[string]any{
		"requestId": "req-child-frame",
		"frameId":   "child-iframe",
		"type":      "XHR",
		"request":   map[string]any{"url": "https://app.example.com/api/iframe-secret", "method": "GET"},
	})
	emit("Network.responseReceived", map[string]any{
		"requestId": "req-child-frame",
		"frameId":   "child-iframe",
		"type":      "XHR",
		"response": map[string]any{
			"url":      "https://app.example.com/api/iframe-secret",
			"status":   200,
			"mimeType": "application/json",
		},
	})
	emit("Network.loadingFinished", map[string]any{"requestId": "req-child-frame", "encodedDataLength": 42})

	// 5. Oversized (> 256 KiB) same-origin XHR -> MUST be dropped before getResponseBody!
	emit("Network.requestWillBeSent", map[string]any{
		"requestId": "req-oversized",
		"frameId":   "main-frame",
		"type":      "Fetch",
		"request":   map[string]any{"url": "https://app.example.com/api/huge", "method": "GET"},
	})
	emit("Network.responseReceived", map[string]any{
		"requestId": "req-oversized",
		"frameId":   "main-frame",
		"type":      "Fetch",
		"response": map[string]any{
			"url":      "https://app.example.com/api/huge",
			"status":   200,
			"mimeType": "application/json",
		},
	})
	emit("Network.loadingFinished", map[string]any{"requestId": "req-oversized", "encodedDataLength": float64(maxSingleCapturedJSONBytes + 1024)})

	// 6. Truncated/invalid JSON -> dropped after json.Valid check
	emit("Network.requestWillBeSent", map[string]any{
		"requestId":   "req-invalid-json",
		"frameId":     "main-frame",
		"type":        "Fetch",
		"documentURL": "https://app.example.com/jobs",
		"request":     map[string]any{"url": "https://app.example.com/api/broken", "method": "GET"},
	})
	emit("Network.responseReceived", map[string]any{
		"requestId": "req-invalid-json",
		"frameId":   "main-frame",
		"type":      "Fetch",
		"response": map[string]any{
			"url":      "https://app.example.com/api/broken",
			"status":   200,
			"mimeType": "application/json",
		},
	})
	emit("Network.loadingFinished", map[string]any{"requestId": "req-invalid-json", "encodedDataLength": 10})

	// 7. [HIGH-2] Cross-origin 302 redirect (`evil.example/bounce -> 302 -> app.example.com/api/jobs`) MUST be tombstoned and NEVER resurrected by responseReceived!
	bodies["req-xorigin-redir"] = struct {
		body string
		b64  bool
	}{body: `{"items":[{"title":"Cross Origin Redirect Poison"}]}`}
	emit("Network.requestWillBeSent", map[string]any{
		"requestId":   "req-xorigin-redir",
		"frameId":     "main-frame",
		"type":        "Fetch",
		"documentURL": "https://app.example.com/jobs",
		"request":     map[string]any{"url": "https://evil.example/bounce", "method": "GET"},
	})
	emit("Network.requestWillBeSent", map[string]any{
		"requestId":        "req-xorigin-redir",
		"frameId":          "main-frame",
		"type":             "Fetch",
		"documentURL":      "https://app.example.com/jobs",
		"redirectResponse": map[string]any{"status": 302, "url": "https://evil.example/bounce"},
		"request":          map[string]any{"url": "https://app.example.com/api/jobs", "method": "GET"},
	})
	emit("Network.responseReceived", map[string]any{
		"requestId": "req-xorigin-redir",
		"frameId":   "main-frame",
		"type":      "Fetch",
		"response": map[string]any{
			"url":      "https://app.example.com/api/jobs",
			"status":   200,
			"mimeType": "application/json",
		},
	})
	emit("Network.loadingFinished", map[string]any{"requestId": "req-xorigin-redir", "encodedDataLength": 55})

	// 8. [HIGH-2] Orphan `responseReceived` without prior `requestWillBeSent` MUST be rejected!
	bodies["req-orphan-resp"] = struct {
		body string
		b64  bool
	}{body: `{"items":[{"title":"Orphan Response Poison"}]}`}
	emit("Network.responseReceived", map[string]any{
		"requestId": "req-orphan-resp",
		"frameId":   "main-frame",
		"type":      "Fetch",
		"response": map[string]any{
			"url":      "https://app.example.com/api/orphan",
			"status":   200,
			"mimeType": "application/json",
		},
	})
	emit("Network.loadingFinished", map[string]any{"requestId": "req-orphan-resp", "encodedDataLength": 44})

	// 9. [MEDIUM-1] Same-origin XHR disallowed by `CheckRobots` (`Disallow: /api/internal/`) MUST NOT be harvested!
	bodies["req-robots-blocked"] = struct {
		body string
		b64  bool
	}{body: `{"items":[{"title":"Robots Disallowed API"}]}`}
	emit("Network.requestWillBeSent", map[string]any{
		"requestId":   "req-robots-blocked",
		"frameId":     "main-frame",
		"type":        "Fetch",
		"documentURL": "https://app.example.com/jobs",
		"request":     map[string]any{"url": "https://app.example.com/api/internal/secret", "method": "GET"},
	})
	emit("Network.responseReceived", map[string]any{
		"requestId": "req-robots-blocked",
		"frameId":   "main-frame",
		"type":      "Fetch",
		"response": map[string]any{
			"url":      "https://app.example.com/api/internal/secret",
			"status":   200,
			"mimeType": "application/json",
		},
	})
	emit("Network.loadingFinished", map[string]any{"requestId": "req-robots-blocked", "encodedDataLength": 45})

	r := &Renderer{
		allow: func(u *url.URL) error { return nil },
		CheckRobots: func(_ context.Context, targetURL string) error {
			if strings.Contains(targetURL, "/api/internal/") {
				return net.InvalidAddrError("disallowed by robots.txt")
			}
			return nil
		},
	}
	sess := &retainedSession{
		cdpSessionID: sid,
		mainFrameID:  "main-frame",
	}

	got := r.harvestSameOriginJSONBodies(context.Background(), cdp, sess, h, "https://app.example.com/jobs")
	if len(got) != 2 {
		t.Fatalf("expected exactly 2 valid same-origin JSON responses, got %d: %+v", len(got), got)
	}
	if got[0].URL != "https://app.example.com/api/jobs" || got[0].Method != "POST" || !strings.Contains(got[0].Body, "Role A") {
		t.Fatalf("unexpected first captured JSON: %+v", got[0])
	}
	if got[1].URL != "https://app.example.com/api/featured" || !strings.Contains(got[1].Body, "Encoded Item") {
		t.Fatalf("unexpected second captured JSON: %+v", got[1])
	}
	for _, id := range requestedBodyIDs {
		switch id {
		case "req-cross-origin", "req-child-frame", "req-oversized", "req-xorigin-redir", "req-orphan-resp", "req-robots-blocked":
			t.Fatalf("Network.getResponseBody must NEVER be called for rejected candidate %q", id)
		}
	}
}

func TestLiveChromiumHiddenDOMPruningAndDetailsPreservationIfInstalled(t *testing.T) {
	t.Parallel()
	bin := FindChromeBinary()
	if bin == "" {
		t.Skip("no local Chrome/Chromium binary installed")
	}
	acquireLiveChromeSlot(t)

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		switch req.URL.Path {
		case "/api/items.json":
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			_, _ = w.Write([]byte(`{"total":2,"items":[{"title":"Live Harvested Item","url":"https://example.com/items/1"}]}`))
		case "/api/cross-origin.json":
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			_, _ = w.Write([]byte(`{"items":[{"title":"CROSS_ORIGIN_XHR_MUST_NOT_CAPTURE"}]}`))
		case "/challenge-in-hidden-div":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write([]byte(`<!doctype html><html><head><title>Just a moment...</title></head><body>
				<div style="display:none"><div class="cf-turnstile" data-sitekey="0x4AAAAAA_KEEP_WIDGET"></div></div>
			</body></html>`))
		case "/datadome-hidden-iframe":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write([]byte(`<!doctype html><html><head><title>example.com</title></head><body>
				<div style="visibility:hidden"><iframe src="https://geo.captcha-delivery.com/captcha/?initialCid=123"></iframe></div>
			</body></html>`))
		default:
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write([]byte(`<!doctype html><html><head>
				<title>Live Pruning Check</title>
				<script type="application/ld+json">{"@context":"https://schema.org","@type":"FAQPage","name":"Kept JSON-LD"}</script>
				<style>.css-hidden { display: none; } .vis-hidden { visibility: hidden; } .ghost-overlay { opacity: 0; pointer-events: none; position: fixed; top: 0; left: 0; }</style>
			</head><body>
				<main>
					<h1>Visible Primary Heading</h1>
					<p>Visible article paragraph with clean prose.</p>
					<form><input name="tagName"><input name="nodeType"><input name="style"><input name="childNodes"></form>
					<div class="css-hidden">CSS_DISPLAY_NONE_NOISE</div>
					<div class="vis-hidden">CSS_VISIBILITY_HIDDEN_NOISE</div>
					<div aria-hidden="true">ARIA_HIDDEN_TICKER_CLONE</div>
					<div hidden>HTML_HIDDEN_ATTR_NOISE</div>
					<div class="ghost-overlay">INVISIBLE_FIXED_OVERLAY_INJECTION</div>
					<details><summary>Specifications</summary><p>CLOSED_DETAILS_CONTENT_MUST_SURVIVE</p></details>
				</main>
				<script id="__NEXT_DATA__" type="application/json">{"props":{"pageProps":{"kept":true}}}</script>
				<script>
					Promise.allSettled([
						fetch("/api/items.json"),
						fetch("https://other.example.org/api/cross-origin.json")
					]).then(() => { document.body.setAttribute("data-xhr-done", "1"); });
				</script>
			</body></html>`))
		}
	}))
	defer srv.Close()

	srvAddr := srv.Listener.Addr().String()
	r := NewRenderer(bin, func(_ *url.URL) error { return nil }, "EdgeFetch-Test/2.7.8", 1, nil)
	r.SetAllowNoSandbox(true)
	r.extraFlags = []string{"--ignore-certificate-errors"}
	r.proxyDial = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, srvAddr)
	}
	defer func() { _ = r.Close() }()

	// 90s, not 30s: this t.Parallel() test cold-starts a real Chromium under `go test -race` alongside the other
	// browser tests, and on a 2-vCPU CI runner that alone has exceeded 30s ("context deadline exceeded").
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	out, err := r.Execute(ctx, Task{
		URL:          "https://example.com/page",
		WaitSelector: "[data-xhr-done='1']",
		WaitForMs:    250,
	})
	if err != nil {
		if strings.Contains(err.Error(), "sandbox") {
			t.Skipf("skipping live Chromium sandbox constraint: %v", err)
		}
		t.Fatalf("Execute failed: %v", err)
	}

	for _, mustKeep := range []string{
		"Visible Primary Heading",
		"Kept JSON-LD",
		"__NEXT_DATA__",
		"CLOSED_DETAILS_CONTENT_MUST_SURVIVE",
	} {
		if !strings.Contains(out.HTML, mustKeep) {
			t.Errorf("expected rendered HTML to preserve %q, got:\n%s", mustKeep, out.HTML)
		}
	}
	for _, mustPrune := range []string{
		"CSS_DISPLAY_NONE_NOISE",
		"CSS_VISIBILITY_HIDDEN_NOISE",
		"ARIA_HIDDEN_TICKER_CLONE",
		"HTML_HIDDEN_ATTR_NOISE",
		"INVISIBLE_FIXED_OVERLAY_INJECTION",
	} {
		if strings.Contains(out.HTML, mustPrune) {
			t.Errorf("expected rendered HTML to prune hidden subtree %q, got:\n%s", mustPrune, out.HTML)
		}
	}
	if len(out.CapturedJSON) != 1 || !strings.Contains(out.CapturedJSON[0].Body, "Live Harvested Item") {
		t.Fatalf("expected exactly 1 same-origin CapturedJSON entry, got %+v", out.CapturedJSON)
	}
	for _, cj := range out.CapturedJSON {
		if strings.Contains(cj.Body, "CROSS_ORIGIN_XHR_MUST_NOT_CAPTURE") {
			t.Fatalf("cross-origin XHR leaked into CapturedJSON: %+v", cj)
		}
	}

	// [MEDIUM-2 & NEW-MEDIUM-1] Verify hidden wrappers containing `.cf-turnstile` OR DataDome `captcha-delivery.com` `<iframe>` are NOT pruned and trigger ErrChallengeDetected!
	_, chalErr := r.Execute(ctx, Task{
		URL:       "https://example.com/challenge-in-hidden-div",
		WaitForMs: 50,
	})
	if !errors.Is(chalErr, ErrChallengeDetected) {
		t.Fatalf("expected ErrChallengeDetected when .cf-turnstile is inside a display:none wrapper, got %v", chalErr)
	}
	_, ddErr := r.Execute(ctx, Task{
		URL:       "https://example.com/datadome-hidden-iframe",
		WaitForMs: 50,
	})
	if !errors.Is(ddErr, ErrChallengeDetected) {
		t.Fatalf("expected ErrChallengeDetected when DataDome iframe is inside a visibility:hidden wrapper, got %v", ddErr)
	}
}
