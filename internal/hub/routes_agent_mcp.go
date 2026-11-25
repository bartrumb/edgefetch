package hub

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/bartrumb/edgefetch/v2/internal/agentloop"
	"github.com/bartrumb/edgefetch/v2/internal/mcpfed"
	"github.com/bartrumb/edgefetch/v2/internal/otel"
)

// HandleAgent serves `POST /v1/agent` (JSON or `text/event-stream` SSE).
func (h *RouteHandler) HandleAgent(w http.ResponseWriter, r *http.Request) {
	p, ok := h.requireScope(w, r, "crawl:fetch")
	if !ok {
		return
	}
	payload, okBody := readV1JSON(w, r)
	if !okBody {
		return
	}
	wantSSE := boolField(payload["stream"]) || strings.Contains(strings.ToLower(r.Header.Get("Accept")), "text/event-stream")
	if wantSSE {
		w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Connection", "keep-alive")
		flusher, _ := w.(http.Flusher)
		wroteHdr := false
		emit := func(ev string, data map[string]any) {
			if !wroteHdr {
				w.WriteHeader(http.StatusOK)
				wroteHdr = true
			}
			b, _ := json.Marshal(data)
			_, _ = fmt.Fprintf(w, "event: %s\ndata: %s\n\n", ev, string(b))
			if flusher != nil {
				flusher.Flush()
			}
		}
		out, st := h.ExecuteAgent(r.Context(), payload, r.Header, p, emit)
		if !wroteHdr && st >= 400 {
			w.Header().Set("Content-Type", "application/json")
			writeJSON(w, st, out)
			return
		}
		emit("agent.completed", out)
		return
	}
	out, status := h.ExecuteAgent(r.Context(), payload, r.Header, p, nil)
	writeJSON(w, status, out)
}

// ExecuteAgent resolves BYO-LLM configuration, executes `agentloop.RunAgentLoop` with OTLP `edgefetch.llm.turn` spans, and persists state.
func (h *RouteHandler) ExecuteAgent(
	ctx context.Context, payload map[string]any, hdr http.Header, p AuthPrincipal, onSSE func(string, map[string]any),
) (map[string]any, int) {
	ctx, span, _ := otel.StartChildSpan(ctx, h.deps.OtelExporter, "edgefetch.agent", 1, nil)
	statusOut := http.StatusOK
	defer func() { span.End(statusOut < 400, "") }()

	prompt := strings.TrimSpace(strField(payload["prompt"]))
	if prompt == "" {
		statusOut = http.StatusBadRequest
		return map[string]any{"ok": false, "error": "missing_prompt"}, statusOut
	}
	rawSeeds := stringSliceField(payload["urls"])
	for _, su := range rawSeeds {
		if u, err := url.Parse(su); err != nil || h.allowURL(u) != nil {
			statusOut = http.StatusBadRequest
			return map[string]any{"ok": false, "error": "bad_url", "message": "invalid seed url"}, statusOut
		}
	}

	llmOut := agentloop.ResolveLLMConfig(agentloop.ResolveLLMConfigInput{
		Env:        h.llmEnvConfig(),
		RequestLLM: rawJSONField(payload["llm"]),
		SelfHost:   hostOfURL(h.publicOriginOf(nil)),
	})
	if !llmOut.OK {
		statusOut = http.StatusBadRequest
		return map[string]any{"ok": false, "error": llmOut.Error, "message": llmOut.Message}, statusOut
	}

	agentID := "agt_" + randomHex(10)
	ownerID := p.EffectiveOwnerID()
	if onSSE != nil {
		onSSE("agent.started", map[string]any{"id": agentID, "status": "processing"})
	}

	schema, _ := payload["schema"].(map[string]any)
	var transport agentloop.LLMTransportFunc
	if llmOut.Config != nil {
		transport = h.llmTransportFor(ctx, *llmOut.Config)
	}

	persistRec := func(rec *agentloop.AgentRunRecord) error {
		h.putJob(ctx, AsyncJobRecord{
			Kind: "agent", ID: rec.ID, OwnerID: ownerID, Status: string(rec.Status),
			Total: rec.MaxSteps, Completed: rec.StepsUsed, Payload: structToMap(rec),
			CreatedAtMs: rec.CreatedAt, UpdatedAtMs: rec.UpdatedAt,
		})
		return nil
	}

	rec, err := agentloop.RunAgentLoop(ctx, agentloop.RunAgentLoopInput{
		AgentID: agentID, UserID: ownerID, ThreadID: strField(payload["threadId"]),
		Prompt: prompt, SeedURLs: rawSeeds, StrictConstrainToURLs: boolField(payload["strictConstrainToUrls"]),
		Effort: agentloop.AgentEffort(strField(payload["effort"])), MaxSteps: intField(payload["maxSteps"], 0, 0, 20),
		MaxPages: intField(payload["maxPages"], 0, 0, 30), ZeroDataRetention: boolField(payload["zeroDataRetention"]),
		HasSearchCollection: true, Schema: schema, LLMConfig: llmOut.Config,
	}, agentloop.AgentLoopCallbacks{
		LLMTransport: transport,
		ExecuteTool: func(tCtx context.Context, inv agentloop.AgentToolInvocation) (agentloop.AgentToolExecutionOutput, error) {
			out := h.executeAgentTool(tCtx, inv, hdr, p)
			if onSSE != nil {
				onSSE("agent.step", map[string]any{"id": agentID, "step": inv.Step, "tool": inv.ToolCall.Name, "ok": out.OK})
			}
			return out, nil
		},
		IsCancelled: func() bool {
			j, ok := h.getJob(ctx, "agent", agentID, ownerID)
			return ok && j.Status == "cancelled"
		},
		OnPersist: persistRec,
		OnEvent: func(ev string, data map[string]any) {
			if onSSE != nil && ev != "agent.started" && ev != "agent.completed" {
				onSSE("agent.step", data)
			}
		},
	})
	if err != nil {
		statusOut = http.StatusBadRequest
		return map[string]any{"ok": false, "error": "agent_error", "message": err.Error()}, statusOut
	}
	if !rec.ZeroDataRetention {
		_ = persistRec(rec)
	}
	return agentloop.FormatPublicAgentResponse(*rec, boolField(payload["includeTrace"])), http.StatusOK
}

func (h *RouteHandler) executeAgentTool(ctx context.Context, inv agentloop.AgentToolInvocation, hdr http.Header, p AuthPrincipal) agentloop.AgentToolExecutionOutput {
	args := inv.ToolCall.Arguments
	ownerID := p.EffectiveOwnerID()
	switch inv.ToolCall.Name {
	case "scrape_url":
		u := strField(args["url"])
		sc, _, st := h.ExecuteScrape(ctx, ScrapeRequest{URL: u, Query: strField(args["query"]), MaxChars: 12000}, hdr, ownerID)
		md, title := strField(sc["markdown"]), strField(sc["title"])
		var adapters []string
		if ex := strField(sc["extractorId"]); ex != "" {
			adapters = []string{ex}
		}
		return agentloop.AgentToolExecutionOutput{
			OK: st == http.StatusOK && sc["ok"] == true, ConsumedPage: true, SummaryForLLM: firstNonEmpty(md, strField(sc["error"])),
			Sources: []agentloop.AgentSourceRef{{URL: u, Title: title}}, Evidence: []agentloop.AgentEvidenceItem{{URL: u, Title: title, Markdown: md}}, DiscoveredAdapters: adapters,
		}
	case "web_search":
		sr, st := h.ExecuteSearch(ctx, map[string]any{"query": strField(args["query"]), "limit": 5}, hdr, ownerID)
		b, _ := json.Marshal(sr["results"])
		return agentloop.AgentToolExecutionOutput{OK: st == http.StatusOK, SummaryForLLM: string(b)}
	case "map_site":
		mp, _, st := h.ExecuteMap(ctx, map[string]any{"url": strField(args["url"]), "search": strField(args["search"]), "limit": 40}, hdr)
		b, _ := json.Marshal(mp["links"])
		return agentloop.AgentToolExecutionOutput{OK: st == http.StatusOK, SummaryForLLM: string(b)}
	case "search_jobs":
		jb, st := h.ExecuteJobs(ctx, args, hdr, ownerID)
		b, _ := json.Marshal(jb["jobs"])
		return agentloop.AgentToolExecutionOutput{OK: st == http.StatusOK, ConsumedPage: true, SummaryForLLM: string(b)}
	case "search_collection":
		hits := h.searchCollectionDocs(ctx, firstNonEmpty(strField(args["collectionId"]), "default"), strField(args["query"]), ownerID, 5)
		b, _ := json.Marshal(hits)
		return agentloop.AgentToolExecutionOutput{OK: true, SummaryForLLM: string(b)}
	default:
		return agentloop.AgentToolExecutionOutput{OK: false, SummaryForLLM: "unsupported tool: " + inv.ToolCall.Name}
	}
}

// llmTransportFor wraps each outbound BYO-LLM HTTP call in child span `edgefetch.llm.turn` with zero API keys.
func (h *RouteHandler) llmTransportFor(parentCtx context.Context, cfg agentloop.ResolvedLLMConfig) agentloop.LLMTransportFunc {
	return func(ctx context.Context, req agentloop.LLMTransportRequest) (agentloop.LLMTransportResponse, error) {
		if ctx == nil {
			ctx = parentCtx
		}
		endpoint := cfg.BaseURL
		if req.HTTP != nil && req.HTTP.Endpoint != "" {
			endpoint = req.HTTP.Endpoint
		}
		tCtx, span, _ := otel.StartChildSpan(ctx, h.deps.OtelExporter, "edgefetch.llm.turn", 3, map[string]any{
			"gen_ai.system":        string(req.Provider),
			"gen_ai.request.model": firstNonEmpty(req.Model, cfg.Model),
			"url.full":             otel.SanitizeURL(endpoint),
		})
		if req.HTTP == nil || req.HTTP.Kind != "http" {
			span.End(false, "unsupported_llm_kind")
			return agentloop.LLMTransportResponse{}, fmt.Errorf("unsupported LLM transport kind")
		}
		pu, uErr := url.Parse(endpoint)
		if uErr != nil || pu.Host == "" {
			span.End(false, "bad_url")
			return agentloop.LLMTransportResponse{}, fmt.Errorf("invalid LLM endpoint")
		}
		if cfg.UseSafePublicFetch && !cfg.IsOfflineLocal {
			if h.allowURL(pu) != nil {
				span.End(false, "ssrf_blocked")
				return agentloop.LLMTransportResponse{}, fmt.Errorf("disallowed LLM endpoint")
			}
		}
		httpReq, err := http.NewRequestWithContext(tCtx, firstNonEmpty(req.HTTP.Method, http.MethodPost), endpoint, strings.NewReader(req.HTTP.Body))
		if err != nil {
			span.End(false, "bad_request")
			return agentloop.LLMTransportResponse{}, fmt.Errorf("invalid LLM request")
		}
		for k, v := range req.HTTP.Headers {
			httpReq.Header.Set(k, v)
		}
		resp, err := h.safeOutboundClientFor(pu).Do(httpReq)
		if err != nil {
			span.End(false, "transport_error")
			return agentloop.LLMTransportResponse{}, fmt.Errorf("LLM transport failed")
		}
		defer func() { _ = resp.Body.Close() }()
		b, _ := io.ReadAll(io.LimitReader(resp.Body, agentloop.MaxLLMResponseBytes))
		span.SetAttribute("http.response.status_code", resp.StatusCode)
		span.End(resp.StatusCode >= 200 && resp.StatusCode < 300, "")
		return agentloop.LLMTransportResponse{Status: resp.StatusCode, Body: b}, nil
	}
}

func (h *RouteHandler) HandleAgentByID(w http.ResponseWriter, r *http.Request, id string) {
	_, span, _ := otel.StartChildSpan(r.Context(), h.deps.OtelExporter, "edgefetch.agent", 1, nil)
	defer span.End(true, "")
	if r.Method == http.MethodGet {
		p, ok := h.requireScope(w, r, "crawl:read")
		if !ok {
			return
		}
		job, found := h.getJob(r.Context(), "agent", id, p.EffectiveOwnerID())
		if !found || job.Payload == nil {
			writeJSON(w, http.StatusNotFound, map[string]any{"ok": false, "error": "agent_not_found"})
			return
		}
		var rec agentloop.AgentRunRecord
		b, _ := json.Marshal(job.Payload)
		_ = json.Unmarshal(b, &rec)
		writeJSON(w, http.StatusOK, agentloop.FormatPublicAgentResponse(rec, false))
		return
	}
	if r.Method == http.MethodDelete {
		p, ok := h.requireScope(w, r, "crawl:fetch")
		if !ok {
			return
		}
		okCancel := h.cancelJob(r.Context(), "agent", id, p.EffectiveOwnerID())
		st := http.StatusOK
		if !okCancel {
			st = http.StatusNotFound
		}
		writeJSON(w, st, map[string]any{"ok": okCancel, "id": id, "status": "cancelled"})
		return
	}
	writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": "method_not_allowed"})
}

func (h *RouteHandler) HandleAgentTrace(w http.ResponseWriter, r *http.Request, id string) {
	p, ok := h.requireScope(w, r, "crawl:read")
	if !ok {
		return
	}
	_, span, _ := otel.StartChildSpan(r.Context(), h.deps.OtelExporter, "edgefetch.agent", 1, map[string]any{"edgefetch.op": "trace"})
	defer span.End(true, "")
	job, found := h.getJob(r.Context(), "agent", id, p.EffectiveOwnerID())
	if !found || job.Payload == nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"ok": false, "error": "agent_not_found"})
		return
	}
	var rec agentloop.AgentRunRecord
	b, _ := json.Marshal(job.Payload)
	_ = json.Unmarshal(b, &rec)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "success": true, "id": rec.ID, "threadId": rec.ThreadID,
		"status": rec.Status, "count": len(rec.Trace), "spans": rec.Trace, "trace": rec.Trace,
	})
}

func (h *RouteHandler) HandleSearch(w http.ResponseWriter, r *http.Request) {
	p, ok := h.requireScope(w, r, "crawl:read")
	if !ok {
		return
	}
	payload, okBody := readV1JSON(w, r)
	if !okBody {
		return
	}
	if boolField(payload["scrape"]) && !p.HasScope("crawl:fetch") {
		w.Header().Set("WWW-Authenticate", `Bearer error="insufficient_scope", scope="crawl:fetch"`)
		writeJSON(w, http.StatusForbidden, map[string]any{"ok": false, "error": "insufficient_scope", "required": "crawl:fetch"})
		return
	}
	out, status := h.ExecuteSearch(r.Context(), payload, r.Header, p.EffectiveOwnerID())
	writeJSON(w, status, out)
}

func (h *RouteHandler) ExecuteSearch(ctx context.Context, payload map[string]any, hdr http.Header, ownerID string) (map[string]any, int) {
	ctx, span, _ := otel.StartChildSpan(ctx, h.deps.OtelExporter, "edgefetch.search", 1, nil)
	statusOut := http.StatusOK
	defer func() { span.End(statusOut < 400, "") }()

	q := strings.TrimSpace(firstNonEmpty(strField(payload["query"]), strField(payload["q"])))
	if q == "" {
		statusOut = http.StatusBadRequest
		return map[string]any{"ok": false, "error": "missing_query"}, statusOut
	}
	limit := intField(firstNonEmptyAny(payload["limit"], payload["max_results"], payload["maxResults"]), 5, 1, 20)
	wantScrape := boolField(payload["scrape"])
	col := strings.TrimSpace(firstNonEmpty(strField(payload["collection"]), strField(payload["collectionId"])))
	if col == "" {
		if cols := stringSliceField(payload["collections"]); len(cols) > 0 {
			col = cols[0]
		}
	}
	sources := stringSliceField(firstNonEmptyAny(payload["sources"], payload["providers"]))
	if h.deps.ExecuteWebSearch == nil {
		statusOut = http.StatusServiceUnavailable
		return map[string]any{"ok": false, "error": "search_not_configured"}, statusOut
	}
	res, err := h.deps.ExecuteWebSearch(ctx, WebSearchRequest{Query: q, Limit: limit, Collection: col, Sources: sources, Scrape: wantScrape, OwnerID: ownerID})
	if err != nil || res == nil {
		statusOut = http.StatusBadGateway
		return map[string]any{"ok": false, "error": "search_failed"}, statusOut
	}
	hits := append([]WebSearchHit(nil), res.Results...)
	if wantScrape {
		for i := range hits {
			if hits[i].Markdown == "" && hits[i].URL != "" {
				sc, _, st := h.ExecuteScrape(ctx, ScrapeRequest{URL: hits[i].URL, MaxChars: intField(payload["maxChars"], 4000, 256, 65536)}, hdr, ownerID)
				if st == http.StatusOK {
					hits[i].Markdown = strField(sc["markdown"])
				}
			}
		}
	}
	return map[string]any{"ok": true, "provider": res.Provider, "query": q, "results": hits}, http.StatusOK
}

func (h *RouteHandler) HandleHosts(w http.ResponseWriter, r *http.Request, gaps bool) {
	if _, ok := h.requireScope(w, r, "crawl:read"); !ok {
		return
	}
	spanName := "edgefetch.hosts"
	if gaps {
		spanName = "edgefetch.hosts_gaps"
	}
	_, span, _ := otel.StartChildSpan(r.Context(), h.deps.OtelExporter, spanName, 1, nil)
	defer span.End(true, "")
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	if gaps {
		var list []map[string]any
		if h.deps.ListHostGaps != nil {
			list, _ = h.deps.ListHostGaps(r.Context(), limit)
		}
		if list == nil {
			list = []map[string]any{}
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "gaps": list})
		return
	}
	var list []map[string]any
	if h.deps.ListHosts != nil {
		list, _ = h.deps.ListHosts(r.Context(), limit)
	}
	if list == nil {
		list = []map[string]any{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "hosts": list})
}

func (h *RouteHandler) HandleMCPRegistry(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.requireScope(w, r, "crawl:read"); !ok {
		return
	}
	q := strings.TrimSpace(firstNonEmpty(r.URL.Query().Get("q"), r.URL.Query().Get("query")))
	remoteOnly := r.URL.Query().Get("remoteOnly") == "true" || r.URL.Query().Get("remoteOnly") == "1"
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	out, status := h.ExecuteDiscoverMcpRegistry(r.Context(), q, remoteOnly, limit)
	writeJSON(w, status, out)
}

func (h *RouteHandler) ExecuteDiscoverMcpRegistry(ctx context.Context, query string, remoteOnly bool, limit int) (map[string]any, int) {
	ctx, span, _ := otel.StartChildSpan(ctx, h.deps.OtelExporter, "edgefetch.mcp_registry", 1, nil)
	defer span.End(true, "")
	if limit <= 0 || limit > 50 {
		limit = 20
	}
	fetchRaw := func(baseURL, qParam string) []byte {
		u, err := url.Parse(baseURL)
		if err != nil {
			return nil
		}
		qp := u.Query()
		if query != "" {
			qp.Set(qParam, query)
		}
		qp.Set("limit", strconv.Itoa(limit))
		u.RawQuery = qp.Encode()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
		if err != nil {
			return nil
		}
		req.Header.Set("Accept", "application/json")
		resp, err := h.safeOutboundClientFor(u).Do(req)
		if err != nil {
			return nil
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusOK {
			return nil
		}
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
		return b
	}
	var offEntries, glamaEntries []mcpfed.NormalizedMCPRegistryEntry
	if b := fetchRaw(firstNonEmpty(h.getenv("MCP_OFFICIAL_REGISTRY_URL"), mcpfed.OfficialMCPRegistryURL), "search"); len(b) > 0 {
		offEntries, _ = mcpfed.ParseOfficialRegistryPayload(b, "")
	}
	if b := fetchRaw(firstNonEmpty(h.getenv("MCP_GLAMA_REGISTRY_URL"), mcpfed.GlamaMCPRegistryURL), "query"); len(b) > 0 {
		glamaEntries, _ = mcpfed.ParseGlamaRegistryPayload(b, "")
	}
	fused := mcpfed.FuseRegistryEntries(offEntries, glamaEntries)
	filtered := make([]mcpfed.NormalizedMCPRegistryEntry, 0, len(fused))
	qLow := strings.ToLower(query)
	for _, e := range fused {
		if remoteOnly && !e.HasRemote {
			continue
		}
		if qLow != "" && !strings.Contains(strings.ToLower(e.Name+" "+e.Title+" "+e.Description+" "+e.Slug), qLow) {
			continue
		}
		filtered = append(filtered, e)
		if len(filtered) >= limit {
			break
		}
	}
	return map[string]any{"ok": true, "query": query, "remoteOnly": remoteOnly, "count": len(filtered), "servers": filtered, "sanitized": true, "fullySanitized": true}, http.StatusOK
}

func (h *RouteHandler) HandleMCPQuery(w http.ResponseWriter, r *http.Request) {
	p := h.principalOf(r)
	if !p.Authenticated {
		w.Header().Set("WWW-Authenticate", "Bearer")
		writeJSON(w, http.StatusUnauthorized, map[string]any{"ok": false, "error": "unauthorized"})
		return
	}
	payload, okBody := readV1JSON(w, r)
	if !okBody {
		return
	}
	out, status := h.ExecuteFederatedMcpQuery(r.Context(), payload, p)
	writeJSON(w, status, out)
}

func (h *RouteHandler) ExecuteFederatedMcpQuery(ctx context.Context, payload map[string]any, p AuthPrincipal) (map[string]any, int) {
	ctx, span, _ := otel.StartChildSpan(ctx, h.deps.OtelExporter, "edgefetch.mcp_query", 1, nil)
	statusOut := http.StatusOK
	defer func() { span.End(statusOut < 400, "") }()

	action := firstNonEmpty(strField(payload["action"]), "list_connected")
	if (action == "list_tools" || action == "call_tool") && !p.HasScope("mcp:call") {
		statusOut = http.StatusForbidden
		return map[string]any{"ok": false, "error": "insufficient_scope", "required": "mcp:call"}, statusOut
	}
	if !p.HasScope("crawl:read") && !p.HasScope("mcp:call") {
		statusOut = http.StatusForbidden
		return map[string]any{"ok": false, "error": "insufficient_scope", "required": "crawl:read"}, statusOut
	}
	var cfgs []ConnectedMcpConfig
	if h.deps.ListConnectedMcp != nil {
		cfgs, _ = h.deps.ListConnectedMcp(ctx, p.EffectiveOwnerID())
	}
	if action == "list_connected" {
		summaries := make([]map[string]any, 0, len(cfgs))
		for _, c := range cfgs {
			summaries = append(summaries, map[string]any{"id": c.ID, "slug": mcpfed.NormalizeMCPConnectorSlug(firstNonEmpty(c.ID, c.Name)), "name": c.Name, "endpointUrl": c.EndpointURL, "enabled": c.Enabled, "authType": c.AuthType})
		}
		return map[string]any{"ok": true, "action": "list_connected", "visibility": "private", "count": len(summaries), "servers": summaries, "sanitized": true, "fullySanitized": true}, http.StatusOK
	}

	targetSrv := strings.ToLower(strings.TrimSpace(firstNonEmpty(strField(payload["server"]), strField(payload["serverId"]))))
	var found *ConnectedMcpConfig
	for i := range cfgs {
		slug := mcpfed.NormalizeMCPConnectorSlug(firstNonEmpty(cfgs[i].ID, cfgs[i].Name))
		if strings.EqualFold(cfgs[i].ID, targetSrv) || strings.EqualFold(slug, targetSrv) || strings.EqualFold(cfgs[i].Name, targetSrv) {
			found = &cfgs[i]
			break
		}
	}
	if found == nil || !found.Enabled {
		statusOut = http.StatusNotFound
		return map[string]any{"ok": false, "error": "mcp_server_not_found", "sanitized": true, "fullySanitized": true}, statusOut
	}
	epURL, err := url.Parse(strings.TrimSpace(found.EndpointURL))
	if err != nil || epURL.Host == "" {
		statusOut = http.StatusBadRequest
		return map[string]any{"ok": false, "error": "invalid_mcp_endpoint"}, statusOut
	}
	if !(isLoopbackHostnameOnly(epURL.Hostname()) && h.deps.OperatorClient != nil) {
		if !mcpfed.IsSafePublicHTTPSURL(found.EndpointURL, hostOfURL(h.publicOriginOf(nil))).OK {
			statusOut = http.StatusForbidden
			return map[string]any{"ok": false, "error": "disallowed_mcp_endpoint"}, statusOut
		}
	}
	remoteOrigin := epURL.Scheme + "://" + epURL.Host
	secret, okSec := h.resolveMcpSecret(*found, p.EffectiveOwnerID(), remoteOrigin)
	if !okSec {
		statusOut = http.StatusBadGateway
		return map[string]any{"ok": false, "error": "vault_unseal_failed"}, statusOut
	}
	hdrsObj, okH, msgH := mcpfed.BuildPinnedOutboundHeaders(secret, remoteOrigin, "")
	if !okH {
		statusOut = http.StatusForbidden
		return map[string]any{"ok": false, "error": "origin_pin_mismatch", "message": msgH}, statusOut
	}

	rpcMethod, rpcParams, toolName := "tools/list", map[string]any{}, strings.TrimSpace(strField(payload["tool"]))
	if action == "call_tool" {
		if !mcpfed.IsSafeMCPIdentifier(toolName) {
			statusOut = http.StatusBadRequest
			return map[string]any{"ok": false, "error": "invalid_tool_name"}, statusOut
		}
		rpcMethod = "tools/call"
		argsMap, _ := payload["arguments"].(map[string]any)
		if argsMap == nil {
			argsMap = map[string]any{}
		}
		rpcParams = map[string]any{"name": toolName, "arguments": argsMap}
	}
	reqBytes, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": "fed-1", "method": rpcMethod, "params": rpcParams})
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, found.EndpointURL, bytes.NewReader(reqBytes))
	if err != nil {
		statusOut = http.StatusBadRequest
		return map[string]any{"ok": false, "error": "bad_request"}, statusOut
	}
	for _, kv := range hdrsObj {
		if vs, ok := kv.Value.(string); ok {
			httpReq.Header.Set(kv.Key, vs)
		}
	}
	resp, err := h.safeOutboundClientFor(epURL).Do(httpReq)
	if err != nil {
		statusOut = http.StatusBadGateway
		return map[string]any{"ok": false, "error": "upstream_unreachable"}, statusOut
	}
	defer func() { _ = resp.Body.Close() }()
	rawBody, _ := io.ReadAll(io.LimitReader(resp.Body, mcpfed.MaxRemoteMCPResponseBytes))
	rpcObj, _, okRPC := mcpfed.ParseRemoteJSONRPCBody(string(rawBody), resp.Header.Get("Content-Type"), mcpfed.RPCID{Present: true, Str: "fed-1"})
	if !okRPC {
		statusOut = http.StatusBadGateway
		return map[string]any{"ok": false, "error": "invalid_remote_jsonrpc"}, statusOut
	}
	slug := mcpfed.NormalizeMCPConnectorSlug(firstNonEmpty(found.ID, found.Name))
	if action == "list_tools" {
		resObj, _ := rpcObj.GetObject("result")
		toolsArr, _ := resObj.Get("tools")
		tb, _ := mcpfed.MarshalUnescapedJSON(toolsArr)
		sanTools := mcpfed.SanitizeRemoteMCPToolDefs(tb)
		return map[string]any{
			"ok": true, "action": "list_tools", "visibility": "private", "server": slug,
			"tools": sanTools.Tools, "sanitized": true, "fullySanitized": !sanTools.OversizedRejected,
			"promptInjection": map[string]any{"detected": sanTools.PromptInjectionScrubbed, "scrubbed": sanTools.PromptInjectionScrubbed, "triggers": []string{}},
		}, http.StatusOK
	}
	st, ordBody := mcpfed.SanitizeCallToolRPCResponse(rpcObj, slug, found.Name, remoteOrigin, toolName, remoteOrigin, "", false, secret)
	statusOut = st
	jb, _ := mcpfed.MarshalUnescapedJSON(ordBody)
	var outMap map[string]any
	_ = json.Unmarshal(jb, &outMap)
	return outMap, st
}

func (h *RouteHandler) resolveMcpSecret(c ConnectedMcpConfig, ownerID, remoteOrigin string) (*mcpfed.VaultSecretPayload, bool) {
	if c.SealedAuth != "" {
		uRes := mcpfed.UnsealVaultCredentials(mcpfed.UnsealVaultParams{
			VaultMasterKey: firstNonEmpty(h.deps.VaultMasterKey, h.getenv("VAULT_MASTER_KEY")),
			UserID:         ownerID, RemoteOrigin: remoteOrigin, RemoteURL: c.EndpointURL, Ciphertext: c.SealedAuth,
		})
		if !uRes.OK {
			return nil, false
		}
		sec, err := mcpfed.ParseVaultSecretPayloadObject(uRes.Payload)
		if err != nil {
			return nil, false
		}
		return &sec, true
	}
	if len(c.PlainHeaders) > 0 {
		ord := make(mcpfed.OrderedObject, 0, len(c.PlainHeaders))
		for k, v := range c.PlainHeaders {
			ord.Set(k, v)
		}
		return &mcpfed.VaultSecretPayload{Kind: "headers", PinnedOrigin: remoteOrigin, Headers: ord}, true
	}
	return &mcpfed.VaultSecretPayload{Kind: "none", PinnedOrigin: remoteOrigin}, true
}
