package agent_test

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bartrumb/edgefetch/v2/internal/agent"
	"github.com/bartrumb/edgefetch/v2/internal/browser"
	"github.com/bartrumb/edgefetch/v2/internal/crawl"
	"github.com/bartrumb/edgefetch/v2/internal/hub"
	"github.com/coder/websocket"
)

func buildGzippedTrackerMsg(version string, hosts []string) map[string]any {
	joined := strings.Join(hosts, "\n")
	sum := sha256.Sum256([]byte(joined))
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	_, _ = zw.Write([]byte(joined))
	_ = zw.Close()
	return map[string]any{
		"type":         "tracker_list",
		"version":      version,
		"sha256":       hex.EncodeToString(sum[:]),
		"hostCount":    len(hosts),
		"hostsGzipB64": base64.StdEncoding.EncodeToString(gz.Bytes()),
	}
}

func TestAcceptance7_AgentReceivesTrackerListOnConnectReconnectAndGoHubReportsUnavailable(t *testing.T) {
	var (
		mu          sync.Mutex
		connCount   int
		ackedVers   []string
		gotAckV1    = make(chan struct{})
		gotAckV2    = make(chan struct{})
		gotReconnV2 = make(chan struct{})
	)

	mockHub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path != "/agent/ws" {
			http.NotFound(w, req)
			return
		}
		wsConn, err := websocket.Accept(w, req, &websocket.AcceptOptions{
			Subprotocols: []string{"edgefetch-agent"},
		})
		if err != nil {
			return
		}
		defer wsConn.CloseNow()

		mu.Lock()
		connCount++
		thisConn := connCount
		mu.Unlock()

		sendJSON := func(v any) {
			b, _ := json.Marshal(v)
			_ = wsConn.Write(req.Context(), websocket.MessageText, b)
		}

		if thisConn == 1 {
			sendJSON(buildGzippedTrackerMsg("2026112401", []string{"google-analytics.com", "hotjar.com"}))
		} else {
			sendJSON(buildGzippedTrackerMsg("2026112501", []string{"google-analytics.com", "hotjar.com", "mixpanel.com"}))
		}

		for {
			_, raw, err := wsConn.Read(req.Context())
			if err != nil {
				return
			}
			var msg struct {
				Type    string `json:"type"`
				Version string `json:"version"`
			}
			if json.Unmarshal(raw, &msg) != nil {
				continue
			}
			if msg.Type == "tracker_list_ack" {
				mu.Lock()
				ackedVers = append(ackedVers, msg.Version)
				mu.Unlock()
				if thisConn == 1 && msg.Version == "2026112401" {
					select {
					case <-gotAckV1:
					default:
						close(gotAckV1)
					}
					// Push a live version change over the open WebSocket, then close to trigger reconnect
					sendJSON(buildGzippedTrackerMsg("2026112501", []string{"google-analytics.com", "hotjar.com", "mixpanel.com"}))
				} else if thisConn == 1 && msg.Version == "2026112501" {
					select {
					case <-gotAckV2:
					default:
						close(gotAckV2)
					}
					_ = wsConn.Close(websocket.StatusGoingAway, "simulate reconnect")
					return
				} else if thisConn >= 2 && msg.Version == "2026112501" {
					select {
					case <-gotReconnV2:
					default:
						close(gotReconnV2)
					}
				}
			}
		}
	}))
	defer mockHub.Close()

	r := browser.NewMockRenderer("ws://127.0.0.1:1", func(*url.URL) error { return nil }, "EdgeFetch/2.7")
	defer r.Close()
	c := crawl.NewCrawler(http.DefaultTransport, func(*url.URL) error { return nil }, "EdgeFetch/2.7", nil)
	c.SetRenderer(r)

	cfg := agent.Config{
		HubURL:     mockHub.URL,
		AgentToken: "ef_agent_secret_0123456789abcdef0123456789",
		SiteID:     "node-sync-1",
		UserAgent:  "EdgeFetch/2.7",
	}
	silentLog := slog.New(slog.NewTextHandler(io.Discard, nil))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		_ = agent.Run(ctx, cfg, c, func(*url.URL) error { return nil }, http.DefaultTransport, silentLog, agent.RuntimeOpts{})
	}()

	for _, ch := range []chan struct{}{gotAckV1, gotAckV2, gotReconnV2} {
		select {
		case <-ch:
		case <-time.After(5 * time.Second):
			t.Fatal("timed out waiting for agent tracker_list sync / reconnect")
		}
	}
	cancel()

	if got := r.TrackerListVersion(); got != "2026112501" {
		t.Fatalf("expected reconnected Renderer.TrackerListVersion() = 2026112501, got %q", got)
	}

	// Verify Go `--mode=hub` explicitly reports tracker blocking as unavailable (no half-implementation)
	goHub := hub.NewServer(hub.Config{
		CallerToken: "ef_caller_secret_0123456789abcdef0123456789",
		AgentToken:  "ef_agent_secret_0123456789abcdef0123456789",
	})
	hubSrv := httptest.NewServer(goHub)
	defer hubSrv.Close()

	capReq, _ := http.NewRequest(http.MethodGet, hubSrv.URL+"/v1/capabilities", nil)
	capReq.Header.Set("Authorization", "Bearer ef_caller_secret_0123456789abcdef0123456789")
	capResp, err := http.DefaultClient.Do(capReq)
	if err != nil {
		t.Fatalf("GET /v1/capabilities failed: %v", err)
	}
	defer capResp.Body.Close()
	var capBody map[string]any
	if err := json.NewDecoder(capResp.Body).Decode(&capBody); err != nil {
		t.Fatalf("decode capabilities: %v", err)
	}
	tbObj, ok := capBody["trackerBlocking"].(map[string]any)
	if !ok || tbObj["available"] != false {
		t.Fatalf("expected Go --mode=hub /v1/capabilities trackerBlocking.available=false, got %+v", capBody["trackerBlocking"])
	}
}
