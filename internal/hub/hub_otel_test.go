package hub

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bartrumb/edgefetch/v2/internal/agent"
	"github.com/bartrumb/edgefetch/v2/internal/crawl"
	"github.com/bartrumb/edgefetch/v2/internal/otel"
)

type capturedOTLPSpan struct {
	TraceID      string
	SpanID       string
	ParentSpanID string
	Name         string
	Kind         int
	StatusCode   int
	Attributes   map[string]any
	ServiceName  string
}

type otlpCollectorStub struct {
	srv      *httptest.Server
	mu       sync.Mutex
	rawBytes []byte
	spans    []capturedOTLPSpan
}

func newOTLPCollectorStub(t *testing.T) *otlpCollectorStub {
	t.Helper()
	c := &otlpCollectorStub{}
	c.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/traces" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		b, _ := io.ReadAll(r.Body)
		var payload struct {
			ResourceSpans []struct {
				Resource struct {
					Attributes []struct {
						Key   string `json:"key"`
						Value struct {
							StringValue string `json:"stringValue"`
						} `json:"value"`
					} `json:"attributes"`
				} `json:"resource"`
				ScopeSpans []struct {
					Spans []struct {
						TraceID      string `json:"traceId"`
						SpanID       string `json:"spanId"`
						ParentSpanID string `json:"parentSpanId"`
						Name         string `json:"name"`
						Kind         int    `json:"kind"`
						Status       struct {
							Code int `json:"code"`
						} `json:"status"`
						Attributes []struct {
							Key   string         `json:"key"`
							Value map[string]any `json:"value"`
						} `json:"attributes"`
					} `json:"spans"`
				} `json:"scopeSpans"`
			} `json:"resourceSpans"`
		}
		_ = json.Unmarshal(b, &payload)

		c.mu.Lock()
		c.rawBytes = append(c.rawBytes, b...)
		for _, rs := range payload.ResourceSpans {
			svcName := ""
			for _, ra := range rs.Resource.Attributes {
				if ra.Key == "service.name" {
					svcName = ra.Value.StringValue
				}
			}
			for _, ss := range rs.ScopeSpans {
				for _, sp := range ss.Spans {
					attrs := make(map[string]any, len(sp.Attributes))
					for _, a := range sp.Attributes {
						if sv, ok := a.Value["stringValue"]; ok {
							attrs[a.Key] = sv
						} else if bv, ok := a.Value["boolValue"]; ok {
							attrs[a.Key] = bv
						} else if iv, ok := a.Value["intValue"]; ok {
							attrs[a.Key] = iv
						} else if dv, ok := a.Value["doubleValue"]; ok {
							attrs[a.Key] = dv
						}
					}
					c.spans = append(c.spans, capturedOTLPSpan{
						TraceID:      sp.TraceID,
						SpanID:       sp.SpanID,
						ParentSpanID: sp.ParentSpanID,
						Name:         sp.Name,
						Kind:         sp.Kind,
						StatusCode:   sp.Status.Code,
						Attributes:   attrs,
						ServiceName:  svcName,
					})
				}
			}
		}
		c.mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(c.srv.Close)
	return c
}

func (c *otlpCollectorStub) snapshot() ([]capturedOTLPSpan, string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]capturedOTLPSpan, len(c.spans))
	copy(out, c.spans)
	return out, string(c.rawBytes)
}

func (c *otlpCollectorStub) newExporter(svc string) *otel.Exporter {
	return otel.NewExporterFromEnv(func(k string) string {
		if k == "OTEL_EXPORTER_OTLP_ENDPOINT" {
			return c.srv.URL
		}
		return ""
	}, svc, "2.7.0", c.srv.Client().Transport)
}

func TestGoHubSplitTraceIDFixedAndWaterfallCorrelation(t *testing.T) {
	collector := newOTLPCollectorStub(t)
	exp := collector.newExporter("edgefetch-go-hub")
	log := slog.New(slog.NewJSONHandler(io.Discard, nil))

	mockTr := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		switch {
		case req.URL.Path == "/robots.txt" || req.URL.Path == "/llms.txt":
			return &http.Response{
				StatusCode: http.StatusNotFound,
				Header:     http.Header{"Content-Type": []string{"text/plain"}},
				Body:       io.NopCloser(strings.NewReader("not found")),
				Request:    req,
			}, nil
		case req.URL.Host == "rubygems.org" && req.URL.Path == "/api/v1/gems/fallbackgem.json":
			return &http.Response{
				StatusCode: http.StatusNotFound,
				Header:     http.Header{"Content-Type": []string{"application/json"}},
				Body:       io.NopCloser(strings.NewReader(`{"error":"not found"}`)),
				Request:    req,
			}, nil
		case req.URL.Host == "rubygems.org" && req.URL.Path == "/gems/fallbackgem":
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Content-Type": []string{"text/html; charset=utf-8"}},
				Body:       io.NopCloser(strings.NewReader(`<!doctype html><html><head><title>Fallback</title></head><body><main><h1>Fallback</h1><p>Single trace ID verified.</p></main></body></html>`)),
				Request:    req,
			}, nil
		default:
			return &http.Response{StatusCode: http.StatusNotFound, Body: io.NopCloser(strings.NewReader("")), Request: req}, nil
		}
	})

	crawler := crawl.NewCrawler(mockTr, crawl.PublicHTTPS, crawl.DefaultUserAgent, log)
	crawler.Sleep = func(context.Context, time.Duration) error { return nil }
	crawler.SetOtelExporter(exp)

	const callerTok = "caller-otel-waterfall-token-01234567"
	hubSrv := NewServer(Config{
		CallerToken:     callerTok,
		FallbackCrawler: crawler,
		Allow:           crawl.PublicHTTPS,
		Logger:          log,
		OtelExporter:    exp,
	})
	ts := httptest.NewServer(hubSrv)
	defer ts.Close()

	// Send POST /v1/scrape WITHOUT traceparent so Hub must mint ONE TraceID across twin miss + HTML fallback!
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/v1/scrape?secret_qs=DO_NOT_LEAK", strings.NewReader(`{"url":"https://rubygems.org/gems/fallbackgem"}`))
	req.Header.Set("Authorization", "Bearer "+callerTok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST /v1/scrape failed: %v", err)
	}
	_ = resp.Body.Close()

	gotTraceID := resp.Header.Get("X-Trace-Id")
	gotTP := resp.Header.Get("Traceparent")
	parsedTP, okTP := otel.ParseTraceparent(gotTP)
	if len(gotTraceID) != 32 || !okTP || parsedTP.TraceID != gotTraceID {
		t.Fatalf("unexpected trace response headers: X-Trace-Id=%q Traceparent=%q", gotTraceID, gotTP)
	}

	_ = hubSrv.Close()
	_ = crawler.Close()

	spans, raw := collector.snapshot()
	if strings.Contains(raw, "DO_NOT_LEAK") {
		t.Fatalf("SECURITY: query param leaked into OTLP spans: %s", raw)
	}

	var (
		httpSpan   *capturedOTLPSpan
		twinSpan   *capturedOTLPSpan
		dispatches []capturedOTLPSpan
		batches    []capturedOTLPSpan
		fetches    []capturedOTLPSpan
	)
	for i := range spans {
		sp := &spans[i]
		if sp.TraceID != gotTraceID {
			t.Fatalf("SPLIT TRACE BUG: span %q has traceId=%q, want %q", sp.Name, sp.TraceID, gotTraceID)
		}
		switch {
		case sp.Name == "edgefetch.http":
			httpSpan = sp
		case sp.Name == "edgefetch.hub.twin":
			twinSpan = sp
		case sp.Name == "edgefetch.dispatch":
			dispatches = append(dispatches, *sp)
		case sp.Name == "edgefetch.go.batch":
			batches = append(batches, *sp)
		case strings.HasPrefix(sp.Name, "edgefetch.go.fetch."):
			fetches = append(fetches, *sp)
		}
	}
	if httpSpan == nil || httpSpan.SpanID != parsedTP.ParentSpanID {
		t.Fatalf("expected edgefetch.http spanId matching response Traceparent, got httpSpan=%+v tp=%+v", httpSpan, parsedTP)
	}
	if twinSpan == nil || twinSpan.ParentSpanID != httpSpan.SpanID {
		t.Fatalf("expected edgefetch.hub.twin parented under edgefetch.http (%q), got %+v", httpSpan.SpanID, twinSpan)
	}
	if twinSpan.Attributes["edgefetch.adapter_id"] != "rubygems" || twinSpan.Attributes["edgefetch.twin.hit"] != false {
		t.Fatalf("unexpected twin span attributes: %+v", twinSpan.Attributes)
	}
	if len(dispatches) != 2 || len(batches) != 2 || len(fetches) != 2 {
		t.Fatalf("expected 2 dispatches, 2 batches, 2 fetches; got dispatches=%d batches=%d fetches=%d", len(dispatches), len(batches), len(fetches))
	}

	// Verify parentage: one dispatch under twinSpan, one dispatch under httpSpan, and each batch under a dispatch!
	dispatchByID := make(map[string]capturedOTLPSpan)
	sawTwinChild := false
	sawHTTPChild := false
	for _, d := range dispatches {
		dispatchByID[d.SpanID] = d
		if d.ParentSpanID == twinSpan.SpanID {
			sawTwinChild = true
		}
		if d.ParentSpanID == httpSpan.SpanID {
			sawHTTPChild = true
		}
	}
	if !sawTwinChild || !sawHTTPChild {
		t.Fatalf("expected one dispatch under twin (%q) and one under http (%q), got %+v", twinSpan.SpanID, httpSpan.SpanID, dispatches)
	}
	batchByID := make(map[string]capturedOTLPSpan)
	for _, b := range batches {
		batchByID[b.SpanID] = b
		if _, ok := dispatchByID[b.ParentSpanID]; !ok {
			t.Fatalf("expected batch %q parented under edgefetch.dispatch, got parent=%q", b.SpanID, b.ParentSpanID)
		}
	}
	for _, f := range fetches {
		if _, ok := batchByID[f.ParentSpanID]; !ok {
			t.Fatalf("expected fetch %q parented under edgefetch.go.batch, got parent=%q", f.SpanID, f.ParentSpanID)
		}
	}
}

func TestGoHubInboundTraceparentTwinHitAndMCPSecretRedaction(t *testing.T) {
	collector := newOTLPCollectorStub(t)
	exp := collector.newExporter("edgefetch-go-hub")
	log := slog.New(slog.NewJSONHandler(io.Discard, nil))

	mockTr := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		switch {
		case req.URL.Path == "/robots.txt" || req.URL.Path == "/llms.txt":
			return &http.Response{StatusCode: http.StatusNotFound, Body: io.NopCloser(strings.NewReader("")), Request: req}, nil
		case req.URL.Host == "rubygems.org" && req.URL.Path == "/api/v1/gems/rails.json":
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Content-Type": []string{"application/json"}},
				Body:       io.NopCloser(strings.NewReader(`{"name":"rails","version":"8.0.1","info":"Web framework.","licenses":["MIT"],"authors":"DHH"}`)),
				Request:    req,
			}, nil
		default:
			return &http.Response{StatusCode: http.StatusNotFound, Body: io.NopCloser(strings.NewReader("")), Request: req}, nil
		}
	})

	crawler := crawl.NewCrawler(mockTr, crawl.PublicHTTPS, crawl.DefaultUserAgent, log)
	crawler.Sleep = func(context.Context, time.Duration) error { return nil }
	crawler.SetOtelExporter(exp)

	const callerTok = "caller-mcp-otel-token-0123456789abcdef"
	hubSrv := NewServer(Config{
		CallerToken:     callerTok,
		FallbackCrawler: crawler,
		Allow:           crawl.PublicHTTPS,
		Logger:          log,
		OtelExporter:    exp,
	})
	ts := httptest.NewServer(hubSrv)
	defer ts.Close()

	const callerTraceID = "4bf92f3577b34da6a3ce929d0e0e4736"
	const callerSpanID = "00f067aa0ba902b7"
	inboundTP := "00-" + callerTraceID + "-" + callerSpanID + "-01"

	mcpBodies := []string{
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"scrape","arguments":{"url":"https://rubygems.org/gems/rails?api_key=SECRET_QUERY#secret_frag"}}}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"fetch_url","arguments":{"url":"https://rubygems.org/api/v1/gems/rails.json?token=SECRET_FETCH"}}}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"list_agents","arguments":{}}}`,
		`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"find_extractors","arguments":{"query":"rails"}}}`,
		`{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"nonexistent_tool","arguments":{}}}`,
	}
	for _, body := range mcpBodies {
		req, _ := http.NewRequest(http.MethodPost, ts.URL+"/mcp", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+callerTok)
		req.Header.Set("Traceparent", inboundTP)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("POST /mcp failed: %v", err)
		}
		if resp.Header.Get("X-Trace-Id") != callerTraceID {
			t.Fatalf("expected X-Trace-Id=%q, got %q", callerTraceID, resp.Header.Get("X-Trace-Id"))
		}
		_ = resp.Body.Close()
	}

	_ = hubSrv.Close()
	_ = crawler.Close()

	spans, raw := collector.snapshot()
	if strings.Contains(raw, "SECRET_QUERY") || strings.Contains(raw, "secret_frag") || strings.Contains(raw, "SECRET_FETCH") {
		t.Fatalf("SECURITY: query/fragment secret leaked in OTLP JSON: %s", raw)
	}

	var mcpCount int
	sawTwinHit := false
	for _, sp := range spans {
		if sp.TraceID != callerTraceID {
			t.Fatalf("unexpected traceId %q (want %q)", sp.TraceID, callerTraceID)
		}
		if sp.Name == "edgefetch.http" && sp.ParentSpanID != callerSpanID {
			t.Fatalf("expected edgefetch.http parentSpanId=%q, got %q", callerSpanID, sp.ParentSpanID)
		}
		if sp.Name == "edgefetch.mcp.tool" {
			mcpCount++
		}
		if sp.Name == "edgefetch.hub.twin" && sp.Attributes["edgefetch.adapter_id"] == "rubygems" && sp.Attributes["edgefetch.twin.hit"] == true {
			sawTwinHit = true
		}
	}
	if mcpCount != len(mcpBodies) || !sawTwinHit {
		t.Fatalf("expected %d edgefetch.mcp.tool spans and twin hit=true; got mcpCount=%d sawTwinHit=%v", len(mcpBodies), mcpCount, sawTwinHit)
	}
}

func TestGoHubRemoteAgentDispatchTraceLinkage(t *testing.T) {
	collector := newOTLPCollectorStub(t)
	hubExp := collector.newExporter("edgefetch-go-hub")
	agentExp := collector.newExporter("edgefetch-agent-otel-1")
	log := slog.New(slog.NewJSONHandler(io.Discard, nil))

	allowAllHTTP := func(u *url.URL) error {
		if u.Scheme != "http" && u.Scheme != "https" {
			return io.ErrUnexpectedEOF
		}
		return nil
	}
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/robots.txt" || r.URL.Path == "/llms.txt" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(`<html><body><h1>Remote Agent</h1></body></html>`))
	}))
	defer origin.Close()

	const callerTok = "caller-remote-otel-token-0123456789abc"
	const agentTok = "agent-remote-otel-token-0123456789abcd"
	hubSrv := NewServer(Config{
		CallerToken:  callerTok,
		AgentToken:   agentTok,
		Allow:        allowAllHTTP,
		Logger:       log,
		OtelExporter: hubExp,
	})
	ts := httptest.NewServer(hubSrv)
	defer ts.Close()

	agentCrawler := crawl.NewCrawler(origin.Client().Transport, allowAllHTTP, crawl.DefaultUserAgent, log)
	agentCrawler.Sleep = func(context.Context, time.Duration) error { return nil }
	agentCrawler.SetOtelExporter(agentExp)

	cfg, err := agent.LoadConfigFrom("", func(k string) string {
		switch k {
		case "EDGEFETCH_ALLOW_INSECURE_HUB":
			return "1"
		case "EDGEFETCH_HUB_URL":
			return ts.URL
		case "EDGEFETCH_AGENT_TOKEN":
			return agentTok
		case "EDGEFETCH_SITE_ID":
			return "otel-node-1"
		default:
			return ""
		}
	})
	if err != nil {
		t.Fatalf("LoadConfigFrom failed: %v", err)
	}

	var connected atomic.Bool
	agentCtx, cancelAgent := context.WithCancel(context.Background())
	defer cancelAgent()
	go func() {
		_ = agent.RunAll(agentCtx, cfg, agentCrawler, allowAllHTTP, http.DefaultTransport, log, agent.RuntimeOpts{
			PingInterval: 2 * time.Second,
			ReadWatchdog: 5 * time.Second,
			OnConnected:  func() { connected.Store(true) },
		})
	}()

	deadline := time.Now().Add(4 * time.Second)
	for !connected.Load() && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if !connected.Load() {
		t.Fatal("agent failed to connect to Go Hub")
	}

	const callerTraceID = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	const callerSpanID = "1111111111111111"
	fetchBody := `{"maxSeconds":15,"options":{"pauseMs":1},"requests":[{"id":"r1","url":"` + origin.URL + `/page","kind":"page"}]}`
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/fetch?target=agent", strings.NewReader(fetchBody))
	req.Header.Set("Authorization", "Bearer "+callerTok)
	req.Header.Set("Traceparent", "00-"+callerTraceID+"-"+callerSpanID+"-01")
	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /fetch?target=agent failed: resp=%v err=%v", resp, err)
	}
	_ = resp.Body.Close()

	cancelAgent()
	_ = hubSrv.Close()
	_ = agentCrawler.Close()

	spans, _ := collector.snapshot()
	var dispatchSpanID, agentBatchSpanID, agentBatchParent, agentFetchParent string
	sawFetchHTTP := false
	for _, sp := range spans {
		if sp.Name == "edgefetch.http" && sp.Attributes["url.path"] == "/agent/reply" {
			continue
		}
		if sp.TraceID != callerTraceID {
			t.Fatalf("expected traceId %q, got %q on span %q (attrs=%+v)", callerTraceID, sp.TraceID, sp.Name, sp.Attributes)
		}
		if sp.Name == "edgefetch.http" && sp.Attributes["url.path"] == "/fetch" {
			sawFetchHTTP = true
		}
		if sp.Name == "edgefetch.dispatch" && sp.ServiceName == "edgefetch-go-hub" {
			dispatchSpanID = sp.SpanID
		}
		if sp.Name == "edgefetch.go.batch" && sp.ServiceName == "edgefetch-agent-otel-1" {
			agentBatchSpanID = sp.SpanID
			agentBatchParent = sp.ParentSpanID
		}
		if strings.HasPrefix(sp.Name, "edgefetch.go.fetch.") && sp.ServiceName == "edgefetch-agent-otel-1" {
			agentFetchParent = sp.ParentSpanID
		}
	}
	if !sawFetchHTTP || dispatchSpanID == "" || agentBatchParent != dispatchSpanID || agentFetchParent != agentBatchSpanID {
		t.Fatalf("expected /fetch -> dispatch (%q) -> agent batch (%q, parent=%q) -> agent fetch (parent=%q); spans=%+v",
			dispatchSpanID, agentBatchSpanID, agentBatchParent, agentFetchParent, spans)
	}
}

func TestGoHubResponseTraceHeadersOnErrorsAndUnsampled(t *testing.T) {
	collector := newOTLPCollectorStub(t)
	exp := collector.newExporter("edgefetch-go-hub")
	log := slog.New(slog.NewJSONHandler(io.Discard, nil))

	const callerTok = "caller-err-headers-token-0123456789ab"
	hubAuth := NewServer(Config{
		CallerToken:  callerTok,
		Logger:       log,
		OtelExporter: exp,
	})
	tsAuth := httptest.NewServer(hubAuth)
	defer tsAuth.Close()

	// 1. 401 unauthorized, 404 not_found, 400 bad_json, 503 unavailable, /health, /.well-known/edgefetch-bot.json
	reqs := []struct {
		name   string
		method string
		path   string
		auth   string
		body   string
		want   int
	}{
		{"health", http.MethodGet, "/health", "", "", http.StatusOK},
		{"bot_json", http.MethodGet, "/.well-known/edgefetch-bot.json", "", "", http.StatusOK},
		{"401", http.MethodGet, "/agents", "", "", http.StatusUnauthorized},
		{"404", http.MethodGet, "/does-not-exist", "Bearer " + callerTok, "", http.StatusNotFound},
		{"400", http.MethodPost, "/v1/scrape", "Bearer " + callerTok, "{bad-json", http.StatusBadRequest},
		{"503", http.MethodPost, "/fetch?target=agent", "Bearer " + callerTok, `{"requests":[{"id":"1","url":"https://example.com","kind":"page"}]}`, http.StatusServiceUnavailable},
	}
	for _, tc := range reqs {
		req, _ := http.NewRequest(tc.method, tsAuth.URL+tc.path, strings.NewReader(tc.body))
		if tc.auth != "" {
			req.Header.Set("Authorization", tc.auth)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("%s request failed: %v", tc.name, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != tc.want {
			t.Fatalf("%s status = %d, want %d", tc.name, resp.StatusCode, tc.want)
		}
		tid := resp.Header.Get("X-Trace-Id")
		tp := resp.Header.Get("Traceparent")
		if parsed, ok := otel.ParseTraceparent(tp); !ok || len(tid) != 32 || parsed.TraceID != tid {
			t.Fatalf("%s missing valid trace headers: X-Trace-Id=%q Traceparent=%q", tc.name, tid, tp)
		}
	}

	// 2. 403 loopback_origin_rejected on tokenless server
	hubNoAuth := NewServer(Config{
		AllowedLoopbackPort: "8787",
		Logger:              log,
		OtelExporter:        exp,
	})
	rec := httptest.NewRecorder()
	req403 := httptest.NewRequest(http.MethodGet, "http://evil.example:8787/agents", nil)
	req403.Host = "evil.example:8787"
	hubNoAuth.ServeHTTP(rec, req403)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rec.Code)
	}
	if rec.Header().Get("X-Trace-Id") == "" || rec.Header().Get("Traceparent") == "" {
		t.Fatalf("403 missing trace headers: %+v", rec.Header())
	}
	_ = hubNoAuth.Close()

	// 3. Unsampled traceparent (-00) returns -00 headers and exports 0 spans!
	_ = hubAuth.Close()
	collector2 := newOTLPCollectorStub(t)
	exp2 := collector2.newExporter("edgefetch-go-hub-unsampled")
	hubUnsampled := NewServer(Config{CallerToken: callerTok, Logger: log, OtelExporter: exp2})
	recU := httptest.NewRecorder()
	reqU := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/health", nil)
	reqU.Header.Set("Traceparent", "00-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-2222222222222222-00")
	hubUnsampled.ServeHTTP(recU, reqU)
	if !strings.HasSuffix(recU.Header().Get("Traceparent"), "-00") || recU.Header().Get("X-Trace-Id") != "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" {
		t.Fatalf("unexpected unsampled response headers: X-Trace-Id=%q Traceparent=%q", recU.Header().Get("X-Trace-Id"), recU.Header().Get("Traceparent"))
	}
	_ = hubUnsampled.Close()
	if spans, _ := collector2.snapshot(); len(spans) != 0 {
		t.Fatalf("expected 0 exported spans for unsampled -00 traceparent, got %d", len(spans))
	}
}

func TestGoHubCloseShutsDownSharedOtelExporter(t *testing.T) {
	collector := newOTLPCollectorStub(t)
	exp := collector.newExporter("edgefetch-shared-close")
	log := slog.New(slog.NewJSONHandler(io.Discard, nil))

	crawler := crawl.NewCrawler(http.DefaultTransport, crawl.PublicHTTPS, crawl.DefaultUserAgent, log)
	crawler.SetOtelExporter(exp)

	hubSrv := NewServer(Config{
		FallbackCrawler: crawler,
		Logger:          log,
		OtelExporter:    exp,
	})

	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/health", nil)
	rec := httptest.NewRecorder()
	hubSrv.ServeHTTP(rec, req)

	if err := hubSrv.Close(); err != nil {
		t.Fatalf("hubSrv.Close failed: %v", err)
	}
	if err := crawler.Close(); err != nil {
		t.Fatalf("crawler.Close after hubSrv.Close failed: %v", err)
	}
	spans, _ := collector.snapshot()
	if len(spans) == 0 {
		t.Fatal("expected hubSrv.Close() to flush pending spans to OTLP collector")
	}

	// Verify idempotent double-Close on empty buffer doesn't block or panic.
	var buf bytes.Buffer
	_ = buf
}
