package hub

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/bartrumb/edgefetch/v2/internal/classify"
	"github.com/bartrumb/edgefetch/v2/internal/crawl"
)

type routeTestEnv struct {
	handler     *RouteHandler
	collector   *otlpCollectorStub
	mu          sync.Mutex
	env         map[string]string
	hasBrowser  bool
	mockHandler func(req crawl.Request, opts crawl.Options) crawl.Result
}

func newRouteTestEnv(t *testing.T, opClient *http.Client) *routeTestEnv {
	t.Helper()
	col := newOTLPCollectorStub(t)
	exp := col.newExporter("edgefetch-routes-test")
	rte := &routeTestEnv{
		collector: col,
		env:       map[string]string{},
	}
	deps := RouteDeps{
		DispatchFetch: func(_ context.Context, call crawl.FetchCall, _, _ string, _ http.Header) (crawl.FetchReply, string, int, error) {
			results := make([]crawl.Result, 0, len(call.Requests))
			for _, rq := range call.Requests {
				rte.mu.Lock()
				fn := rte.mockHandler
				rte.mu.Unlock()
				if fn != nil {
					res := fn(rq, call.Options)
					res.ID = rq.ID
					if res.URL == "" {
						res.URL = rq.URL
					}
					results = append(results, res)
				} else {
					results = append(results, crawl.Result{
						ID: rq.ID, URL: rq.URL, FinalURL: rq.URL, Status: 200, Outcome: classify.OutcomeOK,
						Body: `<!doctype html><html><head><title>Default Page</title></head><body><main><h1>Hello</h1><p>Body text <a href="https://example.com/p2">Link</a></p></main></body></html>`,
					})
				}
			}
			return crawl.FetchReply{Results: results}, "agent:mock-1", 200, nil
		},
		HasBrowserCapability: func() bool {
			rte.mu.Lock()
			defer rte.mu.Unlock()
			return rte.hasBrowser
		},
		AllowURL:          crawl.PublicHTTPS,
		OperatorClient:    opClient,
		OtelExporter:      exp,
		Getenv:            func(k string) string { rte.mu.Lock(); defer rte.mu.Unlock(); return rte.env[k] },
		RobotsBypassHosts: []string{"bypass.example.com"},
		SessionSecret:     "super-secret-session-signing-key-123456",
		PublicOrigin:      "https://hub.edgefetch.test",
		ListAgents:        func() map[string]any { return map[string]any{"connected": 1, "agents": []string{"mock-1"}} },
		ExecuteWebSearch: func(_ context.Context, req WebSearchRequest) (*WebSearchResponse, error) {
			return &WebSearchResponse{Provider: "mock-search", Query: req.Query, Results: []WebSearchHit{{Title: "Result 1", URL: "https://example.com/r1", Snippet: "Mock search snippet", Score: 0.95}}}, nil
		},
		ListConnectedMcp: func(_ context.Context, _ string) ([]ConnectedMcpConfig, error) {
			rte.mu.Lock()
			ep := rte.env["MOCK_FED_MCP_URL"]
			rte.mu.Unlock()
			if ep == "" {
				return nil, nil
			}
			return []ConnectedMcpConfig{{ID: "docs-mcp", Name: "Docs MCP", EndpointURL: ep, Transport: "streamable-http", AuthType: "headers", Enabled: true, PlainHeaders: map[string]string{"X-Custom-Token": "secret-tok-999"}}}, nil
		},
	}
	rte.handler = NewRouteHandler(deps)
	t.Cleanup(func() { _ = exp.Close() })
	return rte
}

func doJSONReq(t *testing.T, h http.Handler, method, target string, body any, hdrs map[string]string, principal *AuthPrincipal) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	var rdr io.Reader
	switch v := body.(type) {
	case nil:
	case string:
		rdr = strings.NewReader(v)
	case []byte:
		rdr = bytes.NewReader(v)
	default:
		b, _ := json.Marshal(v)
		rdr = bytes.NewReader(b)
	}
	req := httptest.NewRequest(method, target, rdr)
	req.Header.Set("Content-Type", "application/json")
	for k, v := range hdrs {
		req.Header.Set(k, v)
	}
	if principal != nil {
		req = req.WithContext(WithPrincipal(req.Context(), *principal))
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec, out
}

func TestScrapeHTMLFallbackContentSignalX402TwinT2C6SpaAndPaging(t *testing.T) {
	spaSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, 200, map[string]any{"results": []any{map[string]any{"title": "SPA Title", "markdown": "# Rendered by Crawl4AI"}}})
	}))
	defer spaSrv.Close()

	rte := newRouteTestEnv(t, spaSrv.Client())

	// 1. Payload > 1 MiB -> 413 & private URL -> 400
	rec413, _ := doJSONReq(t, rte.handler, "POST", "/v1/scrape", strings.Repeat("x", (1<<20)+64), nil, nil)
	if rec413.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413 on >1MiB scrape body, got %d", rec413.Code)
	}
	rec400, b400 := doJSONReq(t, rte.handler, "POST", "/v1/scrape", map[string]any{"url": "http://127.0.0.1:8080/admin"}, nil, nil)
	if rec400.Code != http.StatusBadRequest || b400["error"] != "bad_url" {
		t.Fatalf("expected 400 bad_url, got %d %v", rec400.Code, b400)
	}

	// 2. Raw HTML body extraction fallback (mock WS agent returns raw HTML with empty res.Markdown) + Hydration + SchemaOrg + Framework + Paging + Cache
	rte.mockHandler = func(rq crawl.Request, _ crawl.Options) crawl.Result {
		htmlDoc := `<!doctype html><html lang="en"><head><title>Widget Article</title><meta name="generator" content="Next.js">
<script type="application/ld+json">{"@context":"https://schema.org","@type":"Article","headline":"Widget LD"}</script>
<script id="__NEXT_DATA__" type="application/json">{"props":{"pageProps":{"article":{"title":"Hydrated Widget","content":"` + strings.Repeat("Hydrated SSR Next.js article prose with meaningful technical details. ", 5) + `"}}}}</script>
</head><body><main><h1>Widget Heading</h1><p>` + strings.Repeat("Detailed paragraph content here. ", 15) + `<a href="https://example.com/more">More</a></p></main></body></html>`
		return crawl.Result{URL: rq.URL, FinalURL: rq.URL, Status: 200, Outcome: classify.OutcomeOK, Body: htmlDoc}
	}
	recOK, bOK := doJSONReq(t, rte.handler, "POST", "/v1/scrape", map[string]any{"url": "https://example.com/post", "maxChars": 120}, nil, nil)
	if recOK.Code != 200 || bOK["title"] != "Widget Article" || bOK["truncated"] != true || strField(bOK["markdownArtifactId"]) == "" {
		t.Fatalf("raw HTML fallback or paging failed: %d %+v", recOK.Code, bOK)
	}
	if bOK["hydration"] == nil || bOK["schemaOrg"] == nil || bOK["framework"] == nil {
		t.Fatalf("expected hydration, schemaOrg, and framework from raw HTML fallback: %+v", bOK)
	}
	etag := recOK.Header().Get("ETag")
	recCache, bCache := doJSONReq(t, rte.handler, "POST", "/v1/scrape", map[string]any{"url": "https://example.com/post", "maxAge": 60000}, nil, nil)
	if recCache.Code != 200 || bCache["cached"] != true || recCache.Header().Get("X-Crawler-Via") != "cache:r2-d1" {
		t.Fatalf("expected cache hit, got %d %v via=%s", recCache.Code, bCache, recCache.Header().Get("X-Crawler-Via"))
	}
	rec304, _ := doJSONReq(t, rte.handler, "POST", "/v1/scrape", map[string]any{"url": "https://example.com/post", "maxAge": 60000}, map[string]string{"If-None-Match": etag}, nil)
	if rec304.Code != http.StatusNotModified {
		t.Fatalf("expected 304 Not Modified, got %d", rec304.Code)
	}

	// 3. Content-Signal: ai-input=no -> 451
	rte.mockHandler = func(rq crawl.Request, _ crawl.Options) crawl.Result {
		return crawl.Result{URL: rq.URL, Status: 200, Outcome: classify.OutcomeOK, ResponseHeaders: map[string]string{"Content-Signal": "search=yes, ai-input=no"}}
	}
	rec451, b451 := doJSONReq(t, rte.handler, "POST", "/v1/scrape", map[string]any{"url": "https://example.com/no-ai"}, nil, nil)
	if rec451.Code != 451 || b451["outcome"] != "content_signal_disallowed" || b451["blockedReason"] != "content-signal" {
		t.Fatalf("expected 451 content_signal_disallowed, got %d %+v", rec451.Code, b451)
	}

	// 4. x402 Payment Required -> 402
	rte.mockHandler = func(rq crawl.Request, _ crawl.Options) crawl.Result {
		return crawl.Result{
			URL: rq.URL, Status: 402, Outcome: "payment_required",
			ResponseHeaders: map[string]string{"X-Payment": `{"x402Version":1,"accepts":[{"scheme":"exact","network":"base","maxAmountRequired":"10000","payTo":"0xabc123","asset":"USDC"}]}`},
		}
	}
	rec402, b402 := doJSONReq(t, rte.handler, "POST", "/v1/scrape", map[string]any{"url": "https://example.com/paid"}, nil, nil)
	if rec402.Code != 402 || b402["outcome"] != "payment_required" {
		t.Fatalf("expected 402 payment_required, got %d %+v", rec402.Code, b402)
	}

	// 5. T2-C6 Invariant: Twin 500 & malformed JSON MUST NOT set edgefetch.adapter_id or extractorId!
	for _, badBody := range []struct {
		status int
		body   string
	}{{500, "internal error"}, {200, "{not-valid-json"}} {
		st, bd := badBody.status, badBody.body
		rte.mockHandler = func(rq crawl.Request, _ crawl.Options) crawl.Result {
			if strings.Contains(rq.URL, "/api/v1/gems/") {
				return crawl.Result{URL: rq.URL, FinalURL: rq.URL, Status: st, Outcome: classify.OutcomeOK, Body: bd}
			}
			return crawl.Result{URL: rq.URL, FinalURL: rq.URL, Status: 200, Outcome: classify.OutcomeOK, Body: `<html><body><main><h1>Gem Fallback HTML</h1></main></body></html>`}
		}
		recTF, bTF := doJSONReq(t, rte.handler, "POST", "/v1/scrape", map[string]any{"url": "https://rubygems.org/gems/broken-gem"}, nil, nil)
		if recTF.Code != 200 || bTF["extractorId"] != nil {
			t.Fatalf("T2-C6 violated (status=%d): twin failure must not set extractorId: %+v", st, bTF)
		}
	}

	// 6. External SPA fallback via Crawl4AI
	rte.mu.Lock()
	rte.env["CRAWL4AI_API_URL"] = spaSrv.URL
	rte.mu.Unlock()
	rte.mockHandler = func(rq crawl.Request, _ crawl.Options) crawl.Result {
		return crawl.Result{URL: rq.URL, FinalURL: rq.URL, Status: 200, Outcome: classify.OutcomeOK, Body: `<html><body><div id="root"></div><noscript>Enable JavaScript</noscript></body></html>`}
	}
	recSPA, bSPA := doJSONReq(t, rte.handler, "POST", "/v1/scrape", map[string]any{"url": "https://example.com/spa", "spaFallback": true}, nil, nil)
	if recSPA.Code != 200 || recSPA.Header().Get("X-Crawler-Via") != "spa-fallback:crawl4ai" || !strings.Contains(strField(bSPA["markdown"]), "Crawl4AI") {
		t.Fatalf("expected Crawl4AI SPA fallback, got %d via=%s %+v", recSPA.Code, recSPA.Header().Get("X-Crawler-Via"), bSPA)
	}

	_ = rte.handler.deps.OtelExporter.Close()
	spans, _ := rte.collector.snapshot()
	sawCandidateWithoutAdapter := false
	sawContentSignalSpan := false
	for _, sp := range spans {
		if sp.Name == "edgefetch.hub.twin" && sp.Attributes["edgefetch.twin.candidate"] == "rubygems" {
			if _, hasAdapter := sp.Attributes["edgefetch.adapter_id"]; hasAdapter {
				t.Fatalf("T2-C6 OTLP violation: failed twin span set edgefetch.adapter_id: %+v", sp.Attributes)
			}
			sawCandidateWithoutAdapter = true
		}
		if sp.Name == "edgefetch.scrape" && sp.Attributes["crawler.outcome"] == "content_signal_disallowed" {
			sawContentSignalSpan = true
		}
	}
	if !sawCandidateWithoutAdapter || !sawContentSignalSpan {
		t.Fatalf("missing expected spans: twinCandidate=%v contentSignal=%v", sawCandidateWithoutAdapter, sawContentSignalSpan)
	}
}

func TestInteractIngestTabJobsCatalogAgentAndCompatRoutes(t *testing.T) {
	llmSecret := "sk-proj-DO-NOT-LEAK-THIS-SECRET-KEY-999999"
	llmStep := 0
	mockAuxSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/chat/completions"):
			llmStep++
			if llmStep == 1 {
				writeJSON(w, 200, map[string]any{
					"choices": []any{map[string]any{"message": map[string]any{
						"role": "assistant",
						"tool_calls": []any{map[string]any{
							"id": "call_1", "type": "function",
							"function": map[string]any{"name": "scrape_url", "arguments": `{"url":"https://example.com/about"}`},
						}},
					}}},
				})
				return
			}
			writeJSON(w, 200, map[string]any{
				"choices": []any{map[string]any{"message": map[string]any{"role": "assistant", "content": `{"summary":"Example Corp builds tools."}`}}},
			})
		case strings.Contains(r.URL.Path, "/v0/servers"):
			writeJSON(w, 200, map[string]any{"servers": []any{map[string]any{
				"name": "io.github.test/docs", "description": "Docs MCP", "version": "1.0.0",
				"remotes": []any{map[string]any{"type": "streamable-http", "url": "https://mcp.example.com/mcp"}},
			}}})
		case strings.Contains(r.URL.Path, "/api/mcp/v1/servers"):
			writeJSON(w, 200, map[string]any{"servers": []any{}})
		case r.URL.Path == "/remote-mcp":
			var rpc map[string]any
			_ = json.NewDecoder(r.Body).Decode(&rpc)
			if rpc["method"] == "tools/list" {
				writeJSON(w, 200, map[string]any{"jsonrpc": "2.0", "id": rpc["id"], "result": map[string]any{
					"tools": []any{map[string]any{"name": "read_doc", "description": "Read docs", "inputSchema": map[string]any{"type": "object"}}},
				}})
				return
			}
			writeJSON(w, 200, map[string]any{"jsonrpc": "2.0", "id": rpc["id"], "result": map[string]any{
				"content": []any{map[string]any{"type": "text", "text": "Clean remote doc answer"}},
			}})
		default:
			w.WriteHeader(404)
		}
	}))
	defer mockAuxSrv.Close()

	rte := newRouteTestEnv(t, mockAuxSrv.Client())
	rte.mu.Lock()
	rte.env["MCP_OFFICIAL_REGISTRY_URL"] = mockAuxSrv.URL + "/v0/servers"
	rte.env["MCP_GLAMA_REGISTRY_URL"] = mockAuxSrv.URL + "/api/mcp/v1/servers"
	rte.env["MOCK_FED_MCP_URL"] = mockAuxSrv.URL + "/remote-mcp"
	rte.env["EDGEFETCH_ALLOW_LOCAL_LLM_OVERRIDE"] = "true"
	rte.env["EDGEFETCH_LLM_PROVIDER"] = "openai"
	rte.env["EDGEFETCH_LLM_BASE_URL"] = mockAuxSrv.URL + "/v1"
	rte.env["EDGEFETCH_LLM_API_KEY"] = llmSecret
	rte.env["EDGEFETCH_LLM_MODEL"] = "gpt-4o-mini"
	rte.mu.Unlock()

	// 1. /v1/interact T2-A4: 503 when no browser capability, 200 + HMAC session + close when enabled
	rec503, b503 := doJSONReq(t, rte.handler, "POST", "/v1/interact", map[string]any{"url": "https://example.com"}, nil, nil)
	if rec503.Code != 503 || b503["error"] != "browser_unavailable" {
		t.Fatalf("expected 503 browser_unavailable, got %d %+v", rec503.Code, b503)
	}
	rte.mu.Lock()
	rte.hasBrowser = true
	rte.mu.Unlock()
	recInt, bInt := doJSONReq(t, rte.handler, "POST", "/v1/interact", map[string]any{"url": "https://example.com", "actions": []any{map[string]any{"type": "wait", "ms": 50}}}, nil, nil)
	sessID := strField(bInt["sessionId"])
	if recInt.Code != 200 || !strings.HasPrefix(sessID, "efi_") {
		t.Fatalf("expected minted efi_ session, got %d %+v", recInt.Code, bInt)
	}
	recClose, bClose := doJSONReq(t, rte.handler, "POST", "/v1/interact", map[string]any{"sessionId": sessID, "close": true}, nil, nil)
	if recClose.Code != 200 || bClose["closed"] != true {
		t.Fatalf("expected session close, got %d %+v", recClose.Code, bClose)
	}

	// 2. /v1/ingest-tab T2-A6: OPTIONS 204, javascript: 400, whitespace 400, 4.2MB 413, valid clip + collection search
	recOpt, _ := doJSONReq(t, rte.handler, "OPTIONS", "/v1/ingest-tab", nil, nil, nil)
	if recOpt.Code != 204 || recOpt.Header().Get("Access-Control-Allow-Origin") != "*" {
		t.Fatalf("expected 204 CORS on OPTIONS /v1/ingest-tab, got %d", recOpt.Code)
	}
	recJS, bJS := doJSONReq(t, rte.handler, "POST", "/v1/ingest-tab", map[string]any{"url": "javascript:alert(1)", "markdown": "hi"}, nil, nil)
	if recJS.Code != 400 || bJS["error"] != "invalid_url" {
		t.Fatalf("expected 400 invalid_url, got %d %+v", recJS.Code, bJS)
	}
	recWS, bWS := doJSONReq(t, rte.handler, "POST", "/v1/ingest-tab", map[string]any{"url": "https://example.com", "html": "   \n\t  "}, nil, nil)
	if recWS.Code != 400 || bWS["error"] != "empty_content" {
		t.Fatalf("expected 400 empty_content, got %d %+v", recWS.Code, bWS)
	}
	recBig, _ := doJSONReq(t, rte.handler, "POST", "/v1/ingest-tab", strings.Repeat("a", 4_200_000), nil, nil)
	if recBig.Code != 413 {
		t.Fatalf("expected 413 on 4.2MB /v1/ingest-tab, got %d", recBig.Code)
	}
	recClip, bClip := doJSONReq(t, rte.handler, "POST", "/v1/ingest-tab", map[string]any{
		"url": "https://example.com/clip", "collectionId": "notes", "html": "<html><head><title>Clipped</title></head><body><main><p>UniqueKeywordZebra</p></main></body></html>",
	}, nil, nil)
	if recClip.Code != 200 || bClip["ok"] != true {
		t.Fatalf("ingest-tab failed: %d %+v", recClip.Code, bClip)
	}
	recCol, bCol := doJSONReq(t, rte.handler, "GET", "/v1/collections/notes/search?q=UniqueKeywordZebra", nil, nil, nil)
	if recCol.Code != 200 || len(bCol["hits"].([]any)) != 1 {
		t.Fatalf("collection search failed: %d %+v", recCol.Code, bCol)
	}

	// 3. /v1/jobs Greenhouse adapter + OTLP edgefetch.adapter_id
	rte.mockHandler = func(rq crawl.Request, _ crawl.Options) crawl.Result {
		if strings.Contains(rq.URL, "boards-api.greenhouse.io") {
			return crawl.Result{
				URL: rq.URL, FinalURL: rq.URL, Status: 200, Outcome: classify.OutcomeOK,
				Body: `{"jobs":[{"id":101,"title":"Staff Go Engineer","absolute_url":"https://boards.greenhouse.io/acme/jobs/101","location":{"name":"Remote - US"},"updated_at":"2026-01-10T00:00:00Z","content":"&lt;p&gt;Build distributed crawlers. $190,000 - $220,000 USD/year&lt;/p&gt;"}]}`,
			}
		}
		return crawl.Result{URL: rq.URL, FinalURL: rq.URL, Status: 200, Outcome: classify.OutcomeOK, Body: `<html><body><main><h1>About Example Corp</h1></main></body></html>`}
	}
	recJobs, bJobs := doJSONReq(t, rte.handler, "POST", "/v1/jobs", map[string]any{"url": "https://boards.greenhouse.io/acme", "query": "Go Engineer"}, nil, nil)
	if recJobs.Code != 200 || bJobs["adapterId"] != "greenhouse" || len(bJobs["jobs"].([]any)) != 1 {
		t.Fatalf("jobs Greenhouse failed: %d %+v", recJobs.Code, bJobs)
	}

	// 4. /v1/catalog Shopify pull + status + records + snapshot diffing on 2nd run
	catRun := 0
	rte.mockHandler = func(rq crawl.Request, _ crawl.Options) crawl.Result {
		if strings.Contains(rq.URL, "/products.json") {
			catRun++
			price := "29.00"
			if catRun > 1 {
				price = "24.00"
			}
			return crawl.Result{
				URL: rq.URL, FinalURL: rq.URL, Status: 200, Outcome: classify.OutcomeOK,
				Body: `{"products":[{"id":9001,"title":"Edge Mug","handle":"edge-mug","vendor":"EdgeShop","product_type":"Merch","tags":["mug"],"variants":[{"id":91,"title":"Default","sku":"MUG-1","price":"` + price + `","available":true}]}]}`,
			}
		}
		return crawl.Result{URL: rq.URL, FinalURL: rq.URL, Status: 200, Outcome: classify.OutcomeOK, Body: `<html><body><main><h1>About</h1></main></body></html>`}
	}
	recCat1, bCat1 := doJSONReq(t, rte.handler, "POST", "/v1/catalog", map[string]any{"url": "https://shop.example.com", "maxPages": 1}, nil, nil)
	catID := strField(bCat1["catalogId"])
	if recCat1.Code != 200 || catID == "" || bCat1["platform"] != "shopify" {
		t.Fatalf("catalog run 1 failed: %d %+v", recCat1.Code, bCat1)
	}
	recCatSt, _ := doJSONReq(t, rte.handler, "GET", "/v1/catalog/"+catID, nil, nil, nil)
	recCatRecs, bCatRecs := doJSONReq(t, rte.handler, "GET", "/v1/catalog/"+catID+"/records?vendor=EdgeShop", nil, nil, nil)
	if recCatSt.Code != 200 || recCatRecs.Code != 200 || bCatRecs["matchedProducts"] != float64(1) {
		t.Fatalf("catalog status/records failed: %d %d %+v", recCatSt.Code, recCatRecs.Code, bCatRecs)
	}
	recCat2, bCat2 := doJSONReq(t, rte.handler, "POST", "/v1/catalog", map[string]any{"url": "https://shop.example.com", "maxPages": 1}, nil, nil)
	diffMap, _ := bCat2["diff"].(map[string]any)
	if recCat2.Code != 200 || diffMap == nil || diffMap["changed"] != float64(1) {
		t.Fatalf("expected catalog snapshot diff changed=1 on 2nd pull: %+v", bCat2)
	}

	// 5. /v1/agent JSON + SSE + trace + zero-key OTLP span verification
	recAgt, bAgt := doJSONReq(t, rte.handler, "POST", "/v1/agent", map[string]any{"prompt": "Summarize Example Corp", "urls": []string{"https://example.com/about"}}, nil, nil)
	agtID := strField(bAgt["id"])
	if recAgt.Code != 200 || agtID == "" {
		t.Fatalf("POST /v1/agent failed: %d %+v", recAgt.Code, bAgt)
	}
	recTrace, bTrace := doJSONReq(t, rte.handler, "GET", "/v1/agent/"+agtID+"/trace", nil, nil, nil)
	if recTrace.Code != 200 || bTrace["ok"] != true {
		t.Fatalf("GET /v1/agent/:id/trace failed: %d %+v", recTrace.Code, bTrace)
	}
	llmStep = 0
	recSSE, _ := doJSONReq(t, rte.handler, "POST", "/v1/agent", map[string]any{"prompt": "Stream summary", "stream": true}, nil, nil)
	sseBody := recSSE.Body.String()
	if recSSE.Code != 200 || !strings.Contains(recSSE.Header().Get("Content-Type"), "text/event-stream") || !strings.Contains(sseBody, "event: agent.started") || !strings.Contains(sseBody, "event: agent.completed") {
		t.Fatalf("SSE /v1/agent failed: %d ct=%s body=%s", recSSE.Code, recSSE.Header().Get("Content-Type"), sseBody)
	}

	// 6. Firecrawl v2 & Tavily compatibility + ExtractTavilyBodyAPIKey
	if gotKey := ExtractTavilyBodyAPIKey([]byte(`{"api_key":"tvly-secret-123","query":"golang"}`)); gotKey != "tvly-secret-123" {
		t.Fatalf("ExtractTavilyBodyAPIKey got %q", gotKey)
	}
	recFC, bFC := doJSONReq(t, rte.handler, "POST", "/v2/scrape", map[string]any{"url": "https://example.com/about"}, nil, nil)
	if recFC.Code != 200 || bFC["success"] != true {
		t.Fatalf("/v2/scrape failed: %d %+v", recFC.Code, bFC)
	}
	recFCB, bFCB := doJSONReq(t, rte.handler, "POST", "/v2/batch/scrape", map[string]any{"urls": []string{"https://example.com/about"}}, nil, nil)
	if recFCB.Code != 200 || bFCB["success"] != true {
		t.Fatalf("/v2/batch/scrape failed: %d %+v", recFCB.Code, bFCB)
	}
	recTavS, bTavS := doJSONReq(t, rte.handler, "POST", "/compat/tavily/search", map[string]any{"api_key": "tvly-1", "query": "edgefetch"}, nil, nil)
	recTavE, bTavE := doJSONReq(t, rte.handler, "POST", "/compat/tavily/extract", map[string]any{"urls": []string{"https://example.com/about"}}, nil, nil)
	if recTavS.Code != 200 || bTavS["query"] != "edgefetch" || recTavE.Code != 200 || len(bTavE["results"].([]any)) != 1 {
		t.Fatalf("Tavily compat failed: search=%d %+v extract=%d %+v", recTavS.Code, bTavS, recTavE.Code, bTavE)
	}

	// 7. Verify zero LLM API key or raw session secret leaked into OTLP spans
	_ = rte.handler.deps.OtelExporter.Close()
	spans, rawSpans := rte.collector.snapshot()
	if strings.Contains(rawSpans, llmSecret) || strings.Contains(rawSpans, sessID) {
		t.Fatalf("SECURITY: secret leaked in OTLP spans!")
	}
	sawJobsAdapter, sawLLMTurn := false, false
	for _, sp := range spans {
		if sp.Name == "edgefetch.jobs" && sp.Attributes["edgefetch.adapter_id"] == "greenhouse" {
			sawJobsAdapter = true
		}
		if sp.Name == "edgefetch.llm.turn" && sp.Attributes["gen_ai.system"] == "openai" && sp.Attributes["gen_ai.request.model"] == "gpt-4o-mini" {
			sawLLMTurn = true
		}
	}
	if !sawJobsAdapter || !sawLLMTurn {
		t.Fatalf("missing OTLP spans: jobsAdapter=%v llmTurn=%v", sawJobsAdapter, sawLLMTurn)
	}
}

func TestStreamableHTTPMCPAll17ToolsGuardsScopesAndRobots(t *testing.T) {
	fedSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/v0/servers") {
			writeJSON(w, 200, map[string]any{"servers": []any{map[string]any{"name": "io.test/srv", "description": "Srv", "remotes": []any{map[string]any{"type": "streamable-http", "url": "https://mcp.example.com/sse"}}}}})
			return
		}
		if strings.Contains(r.URL.Path, "/api/mcp/v1/servers") {
			writeJSON(w, 200, map[string]any{"servers": []any{}})
			return
		}
		var rpc map[string]any
		_ = json.NewDecoder(r.Body).Decode(&rpc)
		writeJSON(w, 200, map[string]any{"jsonrpc": "2.0", "id": rpc["id"], "result": map[string]any{
			"content": []any{map[string]any{"type": "text", "text": "Connected MCP result"}},
		}})
	}))
	defer fedSrv.Close()

	rte := newRouteTestEnv(t, fedSrv.Client())
	rte.mu.Lock()
	rte.hasBrowser = true
	rte.env["MCP_OFFICIAL_REGISTRY_URL"] = fedSrv.URL + "/v0/servers"
	rte.env["MCP_GLAMA_REGISTRY_URL"] = fedSrv.URL + "/api/mcp/v1/servers"
	rte.env["MOCK_FED_MCP_URL"] = fedSrv.URL + "/mcp"
	rte.mu.Unlock()
	artID := rte.handler.persistArtifact(context.Background(), "Stored artifact content", "owner", "public")

	rte.mockHandler = func(rq crawl.Request, _ crawl.Options) crawl.Result {
		if strings.Contains(rq.URL, "/products.json") {
			return crawl.Result{URL: rq.URL, FinalURL: rq.URL, Status: 200, Outcome: classify.OutcomeOK, Body: `{"products":[{"id":1,"title":"Cap","handle":"cap","variants":[{"id":2,"price":"10.00","available":true}]}]}`}
		}
		return crawl.Result{URL: rq.URL, FinalURL: rq.URL, Status: 200, Outcome: classify.OutcomeOK, Body: `<html><head><title>MCP Test</title></head><body><main><h1>MCP OK</h1><a href="https://example.com/2">Next</a></main></body></html>`}
	}

	// Guards: GET/DELETE -> 405, untrusted Origin -> 403, >256KiB -> 413, bad protocol -> -32022, Mcp-Method mismatch -> -32020, [] / 21 batch -> 400
	for _, m := range []string{"GET", "DELETE"} {
		rec, _ := doJSONReq(t, rte.handler, m, "/mcp", nil, nil, nil)
		if rec.Code != http.StatusMethodNotAllowed {
			t.Fatalf("expected 405 on %s /mcp, got %d", m, rec.Code)
		}
	}
	recOrig, _ := doJSONReq(t, rte.handler, "POST", "/mcp", map[string]any{"jsonrpc": "2.0", "id": 1, "method": "ping"}, map[string]string{"Origin": "https://evil.attacker.example"}, nil)
	if recOrig.Code != http.StatusForbidden {
		t.Fatalf("expected 403 on untrusted Origin, got %d", recOrig.Code)
	}
	recLoop, _ := doJSONReq(t, rte.handler, "POST", "/mcp", map[string]any{"jsonrpc": "2.0", "id": 1, "method": "ping"}, map[string]string{"Origin": "http://127.0.0.1:5173"}, nil)
	if recLoop.Code != 200 {
		t.Fatalf("expected 200 on loopback Origin, got %d", recLoop.Code)
	}
	rec413, _ := doJSONReq(t, rte.handler, "POST", "/mcp", strings.Repeat("x", (256<<10)+32), nil, nil)
	if rec413.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413 on >256KiB /mcp body, got %d", rec413.Code)
	}
	_, bVer := doJSONReq(t, rte.handler, "POST", "/mcp", map[string]any{"jsonrpc": "2.0", "id": 1, "method": "ping"}, map[string]string{"Mcp-Protocol-Version": "1999-01-01"}, nil)
	if bVer["error"].(map[string]any)["code"] != float64(-32022) {
		t.Fatalf("expected -32022, got %+v", bVer)
	}
	_, bMeth := doJSONReq(t, rte.handler, "POST", "/mcp", map[string]any{"jsonrpc": "2.0", "id": 1, "method": "ping"}, map[string]string{"Mcp-Method": "tools/list"}, nil)
	if bMeth["error"].(map[string]any)["code"] != float64(-32020) {
		t.Fatalf("expected -32020, got %+v", bMeth)
	}
	recEmptyBatch, _ := doJSONReq(t, rte.handler, "POST", "/mcp", "[]", nil, nil)
	many := make([]any, 21)
	for i := range many {
		many[i] = map[string]any{"jsonrpc": "2.0", "id": i + 1, "method": "ping"}
	}
	rec21, _ := doJSONReq(t, rte.handler, "POST", "/mcp", many, nil, nil)
	if recEmptyBatch.Code != 400 || rec21.Code != 400 {
		t.Fatalf("expected 400 on [] and 21-item batches, got %d and %d", recEmptyBatch.Code, rec21.Code)
	}

	// Notifications (202), initialize, server/discover (2026-07-28), tools/list (all 17 canonical tools)
	recNotif, _ := doJSONReq(t, rte.handler, "POST", "/mcp", map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"}, nil, nil)
	if recNotif.Code != http.StatusAccepted {
		t.Fatalf("expected 202 on notification, got %d", recNotif.Code)
	}
	_, bDisc := doJSONReq(t, rte.handler, "POST", "/mcp", map[string]any{"jsonrpc": "2.0", "id": 2, "method": "server/discover"}, map[string]string{"Mcp-Protocol-Version": "2026-07-28"}, nil)
	if bDisc["result"].(map[string]any)["resultType"] != "complete" {
		t.Fatalf("unexpected server/discover result: %+v", bDisc)
	}
	// The tool list is fixed per build, so no change notifications are promised.
	if caps, _ := bDisc["result"].(map[string]any)["capabilities"].(map[string]any); caps == nil ||
		caps["tools"].(map[string]any)["listChanged"] != false {
		t.Fatalf("server/discover must advertise tools.listChanged=false, got %+v", bDisc["result"])
	}

	// MCP 2026-07-28 subscriptions/listen: an SSE stream with the acknowledgment (no notification types honored) and
	// then a graceful "complete" result, both tagged with the subscription ID (the request ID). Not "Method not found".
	recListen, _ := doJSONReq(t, rte.handler, "POST", "/mcp", map[string]any{
		"jsonrpc": "2.0", "id": "listen-1", "method": "subscriptions/listen",
		"params": map[string]any{"notifications": map[string]any{"toolsListChanged": true}},
	}, map[string]string{"Mcp-Protocol-Version": "2026-07-28", "Accept": "application/json, text/event-stream"}, nil)
	if recListen.Code != http.StatusOK || !strings.HasPrefix(recListen.Header().Get("Content-Type"), "text/event-stream") {
		t.Fatalf("subscriptions/listen: expected 200 text/event-stream, got %d %q: %s", recListen.Code, recListen.Header().Get("Content-Type"), recListen.Body.String())
	}
	var listenMsgs []map[string]any
	for _, line := range strings.Split(recListen.Body.String(), "\n") {
		if data, ok := strings.CutPrefix(line, "data: "); ok {
			var m map[string]any
			if err := json.Unmarshal([]byte(data), &m); err != nil {
				t.Fatalf("subscriptions/listen: bad SSE data %q: %v", data, err)
			}
			listenMsgs = append(listenMsgs, m)
		}
	}
	if len(listenMsgs) != 2 {
		t.Fatalf("subscriptions/listen: expected ack + final result, got %d messages: %s", len(listenMsgs), recListen.Body.String())
	}
	ackParams, _ := listenMsgs[0]["params"].(map[string]any)
	ackMeta, _ := ackParams["_meta"].(map[string]any)
	ackNotifs, _ := ackParams["notifications"].(map[string]any)
	if listenMsgs[0]["method"] != "notifications/subscriptions/acknowledged" || ackMeta["io.modelcontextprotocol/subscriptionId"] != "listen-1" || ackNotifs == nil || len(ackNotifs) != 0 {
		t.Fatalf("subscriptions/listen: bad acknowledgment %+v", listenMsgs[0])
	}
	finRes, _ := listenMsgs[1]["result"].(map[string]any)
	finMeta, _ := finRes["_meta"].(map[string]any)
	if listenMsgs[1]["id"] != "listen-1" || finRes["resultType"] != "complete" || finMeta["io.modelcontextprotocol/subscriptionId"] != "listen-1" {
		t.Fatalf("subscriptions/listen: bad final result %+v", listenMsgs[1])
	}
	_, bList := doJSONReq(t, rte.handler, "POST", "/mcp", map[string]any{"jsonrpc": "2.0", "id": 3, "method": "tools/list"}, nil, nil)
	toolsArr := bList["result"].(map[string]any)["tools"].([]any)
	if len(toolsArr) != 17 {
		t.Fatalf("expected 17 canonical tools, got %d", len(toolsArr))
	}

	// Exercise all 17 canonical tools via JSON-RPC batch (chunks of <= 20)
	toolCalls := []struct {
		name string
		args map[string]any
	}{
		{"list_agents", map[string]any{}},
		{"fetch_url", map[string]any{"url": "https://example.com?secret=REDACT_ME"}},
		{"fetch_batch", map[string]any{"urls": []string{"https://example.com/1", "https://example.com/2"}}},
		{"scrape", map[string]any{"url": "https://example.com"}},
		{"extract", map[string]any{"urls": []string{"https://example.com"}}},
		{"map", map[string]any{"url": "https://example.com"}},
		{"crawl", map[string]any{"url": "https://example.com", "limit": 1}},
		{"search", map[string]any{"query": "golang"}},
		{"search_collection", map[string]any{"collectionId": "default", "query": "test"}},
		{"interact", map[string]any{"url": "https://example.com"}},
		{"read_artifact", map[string]any{"artifactId": artID}},
		{"jobs", map[string]any{"url": "https://example.com/jobs"}},
		{"find_extractors", map[string]any{"query": "github"}},
		{"catalog", map[string]any{"url": "https://shop.example.com", "maxPages": 1}},
		{"agent", map[string]any{"prompt": "Research Example", "urls": []string{"https://example.com"}}},
		{"discover_mcp_servers", map[string]any{"query": "srv"}},
		{"call_connected_mcp", map[string]any{"action": "call_tool", "server": "docs-mcp", "tool": "read_doc", "arguments": map[string]any{}}},
	}
	batchReq := make([]any, len(toolCalls))
	for i, tc := range toolCalls {
		batchReq[i] = map[string]any{"jsonrpc": "2.0", "id": i + 10, "method": "tools/call", "params": map[string]any{"name": tc.name, "arguments": tc.args}}
	}
	bBytes, _ := json.Marshal(batchReq)
	recBatch, _ := doJSONReq(t, rte.handler, "POST", "/mcp", bBytes, nil, nil)
	if recBatch.Code != 200 {
		t.Fatalf("17-tool batch failed: %d %s", recBatch.Code, recBatch.Body.String())
	}
	var batchReplies []map[string]any
	_ = json.Unmarshal(recBatch.Body.Bytes(), &batchReplies)
	if len(batchReplies) != 17 {
		t.Fatalf("expected 17 batch replies, got %d", len(batchReplies))
	}
	for i, rep := range batchReplies {
		if resObj, _ := rep["result"].(map[string]any); resObj == nil || resObj["isError"] == true {
			t.Fatalf("tool %d (%s) returned error: %+v", i, toolCalls[i].name, rep)
		}
	}

	// Scope & respectRobots:false enforcement + RobotsBypassHosts allowlist
	readOnlyP := &AuthPrincipal{Authenticated: true, Kind: "oauth", UserID: "u1", Scopes: []string{"crawl:read"}}
	recScopeErr, _ := doJSONReq(t, rte.handler, "POST", "/mcp", map[string]any{
		"jsonrpc": "2.0", "id": 90, "method": "tools/call", "params": map[string]any{"name": "scrape", "arguments": map[string]any{"url": "https://example.com"}},
	}, nil, readOnlyP)
	if recScopeErr.Code != http.StatusForbidden || !strings.Contains(recScopeErr.Header().Get("WWW-Authenticate"), "insufficient_scope") {
		t.Fatalf("expected 403 + WWW-Authenticate insufficient_scope for crawl:read calling scrape: code=%d hdr=%q", recScopeErr.Code, recScopeErr.Header().Get("WWW-Authenticate"))
	}
	_, bRobDeny := doJSONReq(t, rte.handler, "POST", "/mcp", map[string]any{
		"jsonrpc": "2.0", "id": 91, "method": "tools/call", "params": map[string]any{"name": "scrape", "arguments": map[string]any{"url": "https://example.com", "respectRobots": false}},
	}, nil, nil)
	if bRobDeny["result"].(map[string]any)["isError"] != true {
		t.Fatalf("expected respectRobots:false to be rejected on non-bypassed host: %+v", bRobDeny)
	}
	_, bRobAllow := doJSONReq(t, rte.handler, "POST", "/mcp", map[string]any{
		"jsonrpc": "2.0", "id": 92, "method": "tools/call", "params": map[string]any{"name": "scrape", "arguments": map[string]any{"url": "https://sub.bypass.example.com/page", "respectRobots": false}},
	}, nil, nil)
	if bRobAllow["result"].(map[string]any)["isError"] == true {
		t.Fatalf("expected respectRobots:false to succeed on RobotsBypassHosts match: %+v", bRobAllow)
	}

	_ = rte.handler.deps.OtelExporter.Close()
	_, rawSpans := rte.collector.snapshot()
	if strings.Contains(rawSpans, "REDACT_ME") {
		t.Fatalf("SECURITY: MCP tool URL query leaked into OTLP spans: %s", rawSpans)
	}
}
