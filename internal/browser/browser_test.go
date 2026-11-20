package browser

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
)

func TestSSRFProxyBlocksPlainHTTPNon443AndPrivateLANIPs(t *testing.T) {
	allow := func(u *url.URL) error {
		if u.Scheme != "https" || (u.Port() != "" && u.Port() != "443") {
			return errors.New("https:443 required")
		}
		if net.ParseIP(u.Hostname()) != nil || u.Hostname() == "hub.example.com" {
			return errors.New("disallowed host")
		}
		return nil
	}

	proxy, err := NewSSRFProxy(allow, func(ctx context.Context, network, addr string) (net.Conn, error) {
		return nil, errors.New("kernel dialer blocked non-public peer 192.168.1.1")
	})
	if err != nil {
		t.Fatalf("NewSSRFProxy: %v", err)
	}
	defer proxy.Close()

	// 1. Plain HTTP GET via proxy -> 403 Forbidden
	proxyURL, _ := url.Parse("http://" + proxy.Addr())
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}, Timeout: 3 * time.Second}
	resp, err := client.Get("http://example.com/")
	if err != nil {
		t.Fatalf("plain HTTP GET failed: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for plain HTTP proxy request, got %d", resp.StatusCode)
	}

	// 2. CONNECT to blocked hub host -> 403 Forbidden
	statusHub := rawConnectStatus(t, proxy.Addr(), "hub.example.com:443")
	if statusHub != http.StatusForbidden {
		t.Fatalf("expected 403 for blocked hub host, got %d", statusHub)
	}

	// 3. CONNECT to non-443 port -> 403 Forbidden
	statusPort := rawConnectStatus(t, proxy.Addr(), "example.com:8123")
	if statusPort != http.StatusForbidden {
		t.Fatalf("expected 403 for HAOS port 8123, got %d", statusPort)
	}

	// 4. CONNECT where DNS resolves to private LAN IP -> 502 Bad Gateway before TCP SYN
	statusLAN := rawConnectStatus(t, proxy.Addr(), "rebind.example.com:443")
	if statusLAN != http.StatusBadGateway {
		t.Fatalf("expected 502 when RejectNonPublicPeer blocks LAN IP, got %d", statusLAN)
	}

	// 5. Malformed CONNECT authority without port -> 400 Bad Request
	statusMalformed := rawConnectStatus(t, proxy.Addr(), "missing-port")
	if statusMalformed != http.StatusBadRequest {
		t.Fatalf("expected 400 for malformed CONNECT authority, got %d", statusMalformed)
	}

	// 6. Close() is idempotent
	if err := proxy.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := proxy.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

func TestSSRFProxyBidirectionalConnectRelay(t *testing.T) {
	upstreamLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upstreamLn.Close()

	go func() {
		conn, acceptErr := upstreamLn.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 4)
		if _, rErr := conn.Read(buf); rErr == nil && string(buf) == "PING" {
			_, _ = conn.Write([]byte("PONG"))
		}
	}()

	proxy, err := NewSSRFProxy(func(u *url.URL) error {
		if u.Hostname() != "allowed.example.com" {
			return errors.New("unexpected host")
		}
		return nil
	}, func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, upstreamLn.Addr().String())
	})
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()

	conn, err := net.DialTimeout("tcp", proxy.Addr(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_, _ = fmt.Fprintf(conn, "CONNECT allowed.example.com:443 HTTP/1.1\r\nHost: allowed.example.com:443\r\n\r\n")
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT failed: status=%v err=%v", resp, err)
	}
	if _, err := conn.Write([]byte("PING")); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 4)
	if _, err := br.Read(reply); err != nil || string(reply) != "PONG" {
		t.Fatalf("expected tunnel PONG, got %q (%v)", string(reply), err)
	}
}

func rawConnectStatus(t *testing.T, proxyAddr, target string) int {
	t.Helper()
	conn, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()
	_, _ = fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatalf("read CONNECT response: %v", err)
	}
	return resp.StatusCode
}

func TestRendererExecuteInteractAndChallengeStopOverCDP(t *testing.T) {
	serveChallenge := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer conn.CloseNow()

		clicks := 0
		for {
			_, rawMsg, err := conn.Read(r.Context())
			if err != nil {
				return
			}
			var req struct {
				ID        int64           `json:"id"`
				SessionID string          `json:"sessionId"`
				Method    string          `json:"method"`
				Params    json.RawMessage `json:"params"`
			}
			if json.Unmarshal(rawMsg, &req) != nil {
				continue
			}

			send := func(obj any) {
				b, _ := json.Marshal(obj)
				_ = conn.Write(r.Context(), websocket.MessageText, b)
			}

			switch req.Method {
			case "Target.createBrowserContext":
				send(map[string]any{"id": req.ID, "result": map[string]any{"browserContextId": "bc-1"}})
			case "Target.createTarget":
				send(map[string]any{"id": req.ID, "result": map[string]any{"targetId": "tgt-1"}})
			case "Target.attachToTarget":
				send(map[string]any{"id": req.ID, "result": map[string]any{"sessionId": "sess-1"}})
			case "Page.navigate":
				send(map[string]any{"id": req.ID, "sessionId": req.SessionID, "result": map[string]any{"frameId": "frame-1"}})
				send(map[string]any{
					"sessionId": req.SessionID,
					"method":    "Network.responseReceived",
					"params": map[string]any{
						"type":    "Document",
						"frameId": "frame-1",
						"response": map[string]any{
							"status":  200,
							"headers": map[string]string{"content-type": "text/html"},
						},
					},
				})
				send(map[string]any{"sessionId": req.SessionID, "method": "Page.loadEventFired", "params": map[string]any{}})
			case "Runtime.evaluate":
				var p struct {
					Expression string `json:"expression"`
				}
				_ = json.Unmarshal(req.Params, &p)
				switch {
				case strings.Contains(p.Expression, "el.click()"):
					clicks++
					send(map[string]any{"id": req.ID, "sessionId": req.SessionID, "result": map[string]any{"result": map[string]any{"type": "string", "value": "ok"}}})
				case strings.Contains(p.Expression, "outerHTML"):
					htmlDoc := fmt.Sprintf("<html><head><title>Pricing</title></head><body><main><h1>Rendered Plans (clicks=%d)</h1></main></body></html>", clicks)
					if serveChallenge {
						htmlDoc = `<html><head><title>Just a moment...</title></head><body><div class="cf-turnstile"></div></body></html>`
					}
					docJSON, _ := json.Marshal(map[string]string{
						"url":  "https://spa.example.com/pricing",
						"html": htmlDoc,
					})
					send(map[string]any{"id": req.ID, "sessionId": req.SessionID, "result": map[string]any{"result": map[string]any{"type": "string", "value": string(docJSON)}}})
				default:
					send(map[string]any{"id": req.ID, "sessionId": req.SessionID, "result": map[string]any{"result": map[string]any{"type": "boolean", "value": true}}})
				}
			case "Page.captureScreenshot":
				send(map[string]any{"id": req.ID, "sessionId": req.SessionID, "result": map[string]any{"data": "iVBORw0KGgo="}})
			default:
				send(map[string]any{"id": req.ID, "sessionId": req.SessionID, "result": map[string]any{}})
			}
		}
	}))
	defer srv.Close()

	r := NewRenderer("", nil, "EdgeFetch/2.0", 2, nil)
	r.dialOverrideWS = "ws://" + strings.TrimPrefix(srv.URL, "http://")
	defer r.Close()

	ctx := context.Background()
	out1, err := r.Execute(ctx, Task{
		URL:         "https://spa.example.com/pricing",
		WaitForMs:   20,
		Screenshot:  true,
		KeepSession: true,
	})
	if err != nil {
		t.Fatalf("Execute 1 failed: %v", err)
	}
	if out1.Status != 200 || out1.SessionID == "" || out1.ScreenshotBase64 != "iVBORw0KGgo=" || !strings.Contains(out1.HTML, "clicks=0") {
		t.Fatalf("unexpected render output: %+v", out1)
	}

	// Resume session with a click action (`firecrawl_interact` follow-up) and close it!
	out2, err := r.Execute(ctx, Task{
		SessionID:    out1.SessionID,
		Actions:      []InteractAction{{Type: "click", Selector: "#annual-toggle", WaitMs: 10}},
		CloseSession: true,
	})
	if err != nil {
		t.Fatalf("Execute 2 interact failed: %v", err)
	}
	if !strings.Contains(out2.HTML, "clicks=1") {
		t.Fatalf("expected click state in resumed session HTML, got: %s", out2.HTML)
	}

	// Verify anti-bot challenge DOM halts immediately with ErrChallengeDetected BEFORE running any click actions!
	serveChallenge = true
	_, chErr := r.Execute(ctx, Task{
		URL:     "https://spa.example.com/pricing",
		Actions: []InteractAction{{Type: "click", Selector: "#challenge-btn"}},
	})
	if !errors.Is(chErr, ErrChallengeDetected) {
		t.Fatalf("expected ErrChallengeDetected on anti-bot challenge DOM, got: %v", chErr)
	}
}

func TestStartupReasonKeepsTheFatalLine(t *testing.T) {
	reason := ""
	for _, line := range []string{
		"[8:26:1119/061255.270716:ERROR:dbus/bus.cc:408] Failed to connect to the bus",
		"[8:25:1119/061428.993984:FATAL:components/bookmarks/browser/titled_url_index.cc:176] failed to create a normalizer: U_FILE_ACCESS_ERROR",
		"Aborted (core dumped)",
		"",
	} {
		reason = startupReason(reason, line)
	}
	if !strings.Contains(reason, "U_FILE_ACCESS_ERROR") {
		t.Fatalf("reason = %q, want the FATAL line", reason)
	}
	if got := startupReason("", "only line"); got != "only line" {
		t.Fatalf("reason = %q", got)
	}
}
