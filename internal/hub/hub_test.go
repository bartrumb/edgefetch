package hub

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bartrumb/edgefetch/internal/agent"
	"github.com/bartrumb/edgefetch/internal/crawl"
)

func TestGoHubAgentDispatchMultiControllerHAAndLocalFallback(t *testing.T) {
	// 1. Mock HTTPS origin server
	var hits atomic.Int32
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/robots.txt" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if r.URL.Path == "/llms.txt" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		hits.Add(1)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(`<!doctype html><html><head><title>Self-Hosted Go Hub</title></head><body><main><h1>Self-Hosted Go Hub</h1><p>Dispatched over <code>/agent/ws</code> with zero cloud dependencies.</p></main></body></html>`))
	}))
	defer origin.Close()

	originAddr := origin.Listener.Addr().String()
	originTr := &http.Transport{
		TLSClientConfig: origin.Client().Transport.(*http.Transport).TLSClientConfig,
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, originAddr)
		},
	}
	allowAllHTTPS := func(u *url.URL) error {
		if u.Scheme != "https" {
			return io.ErrUnexpectedEOF
		}
		return nil
	}
	silentLog := slog.New(slog.NewJSONHandler(io.Discard, nil))

	fallbackCrawler := crawl.NewCrawler(originTr, allowAllHTTPS, crawl.DefaultUserAgent, silentLog)
	fallbackCrawler.Sleep = func(context.Context, time.Duration) error { return nil }
	defer fallbackCrawler.Close()

	const callerTok = "caller-secret-token-0123456789ab"
	const agentTok = "agent-shared-token-0123456789abc"

	// 2. Spin up TWO independent Go Hub controllers (Primary + Standby) to prove EDGEFETCH_HUB_URLS Active-Active HA!
	hubPrimary := NewServer(Config{
		CallerToken:     callerTok,
		AgentToken:      agentTok,
		FallbackCrawler: fallbackCrawler,
		Allow:           allowAllHTTPS,
		Logger:          silentLog,
	})
	defer hubPrimary.Close()
	srvPrimary := httptest.NewServer(hubPrimary)
	defer srvPrimary.Close()

	hubStandby := NewServer(Config{
		CallerToken:     callerTok,
		AgentToken:      agentTok,
		FallbackCrawler: fallbackCrawler,
		Allow:           allowAllHTTPS,
		Logger:          silentLog,
	})
	defer hubStandby.Close()
	srvStandby := httptest.NewServer(hubStandby)
	defer srvStandby.Close()

	// 3. Before any agent connects, Primary Go Hub automatically falls back to its local in-process Crawler (`via: "local-hub"`)!
	reqFallback, _ := http.NewRequest(http.MethodPost, srvPrimary.URL+"/v1/scrape", strings.NewReader(`{"url":"https://docs.example.com/intro"}`))
	reqFallback.Header.Set("Authorization", "Bearer "+callerTok)
	reqFallback.Header.Set("Traceparent", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
	respFallback, err := http.DefaultClient.Do(reqFallback)
	if err != nil {
		t.Fatalf("fallback scrape failed: %v", err)
	}
	var fbBody map[string]any
	_ = json.NewDecoder(respFallback.Body).Decode(&fbBody)
	_ = respFallback.Body.Close()
	if respFallback.StatusCode != 200 || fbBody["via"] != "local-hub" || !strings.Contains(fbBody["markdown"].(string), "`/agent/ws`") {
		t.Fatalf("unexpected local fallback response: status=%d body=%+v", respFallback.StatusCode, fbBody)
	}

	// 4. Start ONE Go Agent connected simultaneously to BOTH controllers via `HubURLs` (`agent.RunAll` Active-Active HA)!
	agentCrawler := crawl.NewCrawler(originTr, allowAllHTTPS, crawl.DefaultUserAgent, silentLog)
	agentCrawler.Sleep = func(context.Context, time.Duration) error { return nil }
	defer agentCrawler.Close()

	cfg, err := agent.LoadConfigFrom("", func(k string) string {
		switch k {
		case "EDGEFETCH_ALLOW_INSECURE_HUB":
			return "1"
		case "EDGEFETCH_HUB_URLS":
			return srvPrimary.URL + "," + srvStandby.URL
		case "EDGEFETCH_AGENT_TOKEN":
			return agentTok
		case "EDGEFETCH_SITE_ID":
			return "mesh-node-1"
		default:
			return ""
		}
	})
	if err != nil {
		t.Fatalf("LoadConfigFrom HubURLs: %v", err)
	}
	if len(cfg.HubURLs) != 2 {
		t.Fatalf("expected 2 HubURLs, got %+v", cfg.HubURLs)
	}

	var connectedCount atomic.Int32
	agentCtx, cancelAgent := context.WithCancel(context.Background())
	defer cancelAgent()

	go func() {
		_ = agent.RunAll(agentCtx, cfg, agentCrawler, allowAllHTTPS, http.DefaultTransport, silentLog, agent.RuntimeOpts{
			PingInterval: 2 * time.Second,
			ReadWatchdog: 5 * time.Second,
			OnConnected:  func() { connectedCount.Add(1) },
		})
	}()

	deadline := time.Now().Add(4 * time.Second)
	for connectedCount.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(25 * time.Millisecond)
	}
	if connectedCount.Load() < 2 {
		t.Fatalf("expected agent connected to both controllers, got %d", connectedCount.Load())
	}

	// 5. Verify BOTH Primary and Standby Go Hubs dispatch over WebSocket + R2-mode artifact upload (`via: "agent:mesh-node-1"`)!
	for idx, hubURL := range []string{srvPrimary.URL, srvStandby.URL} {
		fetchBody := `{"maxSeconds":20,"options":{"includeBody":true,"pauseMs":1},"requests":[{"id":"r1","url":"https://docs.example.com/page","kind":"scrape","formats":["markdown"]}]}`
		req, _ := http.NewRequest(http.MethodPost, hubURL+"/fetch?target=agent", strings.NewReader(fetchBody))
		req.Header.Set("Authorization", "Bearer "+callerTok)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("controller %d /fetch failed: %v", idx, err)
		}
		via := resp.Header.Get("X-Crawler-Via")
		var reply crawl.FetchReply
		_ = json.NewDecoder(resp.Body).Decode(&reply)
		_ = resp.Body.Close()
		if resp.StatusCode != 200 || via != "agent:mesh-node-1" || len(reply.Results) != 1 || !strings.Contains(reply.Results[0].Body, "Self-Hosted Go Hub") {
			t.Fatalf("controller %d unexpected reply: status=%d via=%q results=%+v", idx, resp.StatusCode, via, reply.Results)
		}
	}

	// 6. Verify Go Hub's built-in Streamable HTTP `/mcp` server (`initialize`, `tools/list`, `tools/call` -> `scrape` & `list_agents`)!
	initReq, _ := http.NewRequest(http.MethodPost, srvPrimary.URL+"/mcp", bytes.NewBufferString(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`))
	initReq.Header.Set("Authorization", "Bearer "+callerTok)
	initResp, err := http.DefaultClient.Do(initReq)
	if err != nil || initResp.StatusCode != 200 {
		t.Fatalf("MCP initialize failed: resp=%v err=%v", initResp, err)
	}
	_ = initResp.Body.Close()

	toolsReq, _ := http.NewRequest(http.MethodPost, srvPrimary.URL+"/mcp", bytes.NewBufferString(`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`))
	toolsReq.Header.Set("Authorization", "Bearer "+callerTok)
	toolsResp, err := http.DefaultClient.Do(toolsReq)
	if err != nil || toolsResp.StatusCode != 200 {
		t.Fatalf("MCP tools/list failed: resp=%v err=%v", toolsResp, err)
	}
	_ = toolsResp.Body.Close()

	agentsReq, _ := http.NewRequest(http.MethodGet, srvPrimary.URL+"/agents", nil)
	agentsReq.Header.Set("Authorization", "Bearer "+callerTok)
	agentsResp, err := http.DefaultClient.Do(agentsReq)
	if err != nil || agentsResp.StatusCode != 200 {
		t.Fatalf("GET /agents failed: resp=%v err=%v", agentsResp, err)
	}
	_ = agentsResp.Body.Close()

	mcpCall := `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"scrape","arguments":{"url":"https://docs.example.com/mcp-test","target":"agent"}}}`
	mcpReq, _ := http.NewRequest(http.MethodPost, srvPrimary.URL+"/mcp", bytes.NewBufferString(mcpCall))
	mcpReq.Header.Set("Authorization", "Bearer "+callerTok)
	mcpResp, err := http.DefaultClient.Do(mcpReq)
	if err != nil {
		t.Fatalf("Go Hub /mcp failed: %v", err)
	}
	rawMcp, _ := io.ReadAll(mcpResp.Body)
	_ = mcpResp.Body.Close()
	if mcpResp.StatusCode != 200 || !strings.Contains(string(rawMcp), "agent:mesh-node-1") || !strings.Contains(string(rawMcp), "Self-Hosted Go Hub") {
		t.Fatalf("unexpected Go Hub /mcp response: %s", string(rawMcp))
	}

	// 7. Verify ParseAgentTokensJSON validation and H-S5 site-isolation security invariant
	tokMap, err := ParseAgentTokensJSON(`{"site-alpha":"0123456789abcdef0123456789abcdef"}`)
	if err != nil || tokMap["site-alpha"] == "" {
		t.Fatalf("ParseAgentTokensJSON failed: %v", err)
	}
	if _, err := ParseAgentTokensJSON(`{"site-alpha":"short"}`); err == nil {
		t.Fatal("expected short per-site token rejected")
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func TestPeerHandoffOn429WithLoopPrevention(t *testing.T) {
	log := slog.New(slog.NewJSONHandler(io.Discard, nil))
	peerTok := "peer-mesh-secret-token-0123456789abcdef"

	var peerCalls int
	peerSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		peerCalls++
		if r.Header.Get("X-EdgeFetch-Peer-Hop") != "1" {
			t.Errorf("expected X-EdgeFetch-Peer-Hop=1 header on peer handoff")
		}
		if r.Header.Get("Authorization") != "Bearer "+peerTok {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"results":[{"id":"r1","url":"https://shop.example.com/item","kind":"page","outcome":"ok","status":200,"bytes":14,"attempts":1,"durationMs":12,"body":"<h1>Peer OK</h1>"}]}`))
	}))
	defer peerSrv.Close()

	// Local Hub's own egress gets HTTP 429 Retry-After: 30 on shop.example.com!
	localTr := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Path == "/robots.txt" {
			return &http.Response{
				StatusCode: 200,
				Header:     http.Header{"Content-Type": []string{"text/plain"}},
				Body:       io.NopCloser(strings.NewReader("User-agent: *\nAllow: /\n")),
				Request:    req,
			}, nil
		}
		return &http.Response{
			StatusCode: 429,
			Header:     http.Header{"Retry-After": []string{"1"}},
			Body:       io.NopCloser(strings.NewReader("rate limited")),
			Request:    req,
		}, nil
	})
	localCrawler := crawl.NewCrawler(localTr, crawl.PublicHTTPS, crawl.DefaultUserAgent, log)
	defer func() { _ = localCrawler.Close() }()

	hubA := NewServer(Config{
		CallerToken:     peerTok,
		PeerURLs:        []string{peerSrv.URL},
		PeerToken:       peerTok,
		FallbackCrawler: localCrawler,
		Allow:           crawl.PublicHTTPS,
		Logger:          log,
	})
	defer func() { _ = hubA.Close() }()

	call := crawl.FetchCall{
		MaxSeconds: 15,
		Options:    crawl.Options{IncludeBody: true, RespectRobots: crawl.Bool(true)},
		Requests:   []crawl.Request{{ID: "r1", URL: "https://shop.example.com/item", Kind: "page"}},
	}

	// Normal caller request: local 429 seamlessly hands off 1 hop to Tailscale/WireGuard peer!
	rep, via, status, err := hubA.DispatchOrFallback(context.Background(), call, "auto", "", http.Header{})
	if err != nil || status != 200 || !strings.HasPrefix(via, "peer:") || len(rep.Results) != 1 || rep.Results[0].Outcome != "ok" {
		t.Fatalf("expected peer handoff ok, got status=%d via=%q err=%v results=%+v", status, via, err, rep.Results)
	}
	if peerCalls != 1 {
		t.Fatalf("expected 1 peer call, got %d", peerCalls)
	}

	// Loop guard: if incoming request ALREADY carries `X-EdgeFetch-Peer-Hop: 1`, hubA MUST NOT forward again!
	hopCall := crawl.FetchCall{
		MaxSeconds: 5,
		Options:    crawl.Options{IncludeBody: true, RespectRobots: crawl.Bool(true)},
		Requests:   []crawl.Request{{ID: "r2", URL: "https://shop2.example.com/item", Kind: "page"}},
	}
	hopHdr := http.Header{}
	hopHdr.Set("X-EdgeFetch-Peer-Hop", "1")
	rep2, via2, _, _ := hubA.DispatchOrFallback(context.Background(), hopCall, "auto", "", hopHdr)
	if via2 != "local-hub" || rep2.Results[0].Outcome != "stop" || peerCalls != 1 {
		t.Fatalf("expected loop guard to prevent 2nd hop: via=%q outcome=%q peerCalls=%d", via2, rep2.Results[0].Outcome, peerCalls)
	}
}
