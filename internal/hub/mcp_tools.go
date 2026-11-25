package hub

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"

	"github.com/bartrumb/edgefetch/v2/internal/classify"
	"github.com/bartrumb/edgefetch/v2/internal/crawl"
	"github.com/bartrumb/edgefetch/v2/internal/extract"
	"github.com/bartrumb/edgefetch/v2/internal/otel"
)

// CanonicalMCPToolNames lists all 17 MCP tools exposed by EdgeFetch Go Hub.
var CanonicalMCPToolNames = []string{
	"list_agents",
	"fetch_url",
	"fetch_batch",
	"scrape",
	"extract",
	"map",
	"crawl",
	"search",
	"search_collection",
	"interact",
	"read_artifact",
	"jobs",
	"find_extractors",
	"catalog",
	"agent",
	"discover_mcp_servers",
	"call_connected_mcp",
}

func buildMCPCanonicalToolDefinitions() []map[string]any {
	objProp := func(req []string, props map[string]any) map[string]any {
		s := map[string]any{"type": "object", "properties": props}
		if len(req) > 0 {
			s["required"] = req
		}
		return s
	}
	sType := map[string]any{"type": "string"}
	iType := map[string]any{"type": "integer"}
	bType := map[string]any{"type": "boolean"}

	return []map[string]any{
		{"name": "list_agents", "description": "List connected EdgeFetch worker nodes and capabilities.", "inputSchema": objProp(nil, map[string]any{})},
		{"name": "fetch_url", "description": "Fetch one public HTTPS URL with status, headers, timing, and body.", "inputSchema": objProp([]string{"url"}, map[string]any{"url": sType, "kind": sType, "target": sType, "respectRobots": bType})},
		{"name": "fetch_batch", "description": "Fetch 1..25 public HTTPS URLs politely with per-host pacing.", "inputSchema": objProp([]string{"urls"}, map[string]any{"urls": map[string]any{"type": "array", "items": sType}, "target": sType, "respectRobots": bType})},
		{"name": "scrape", "description": "Scrape a public HTTPS URL into sanitized GitHub-Flavored Markdown.", "inputSchema": objProp([]string{"url"}, map[string]any{"url": sType, "query": sType, "maxChars": iType, "renderMode": sType, "respectRobots": bType})},
		{"name": "extract", "description": "Extract structured JSON across 1..10 URLs via schema or prompt.", "inputSchema": objProp([]string{"urls"}, map[string]any{"urls": map[string]any{"type": "array", "items": sType}, "prompt": sType, "schema": map[string]any{"type": "object"}})},
		{"name": "map", "description": "Discover site URLs from /llms.txt, /sitemap.xml, and page links.", "inputSchema": objProp([]string{"url"}, map[string]any{"url": sType, "search": sType, "limit": iType})},
		{"name": "crawl", "description": "Crawl a site up to limit pages or inspect/cancel an existing crawlId.", "inputSchema": objProp(nil, map[string]any{"url": sType, "crawlId": sType, "limit": iType, "maxDepth": iType, "cancel": bType, "respectRobots": bType})},
		{"name": "search", "description": "Search the public web and optionally scrape result pages.", "inputSchema": objProp([]string{"query"}, map[string]any{"query": sType, "limit": iType, "scrape": bType})},
		{"name": "search_collection", "description": "Search indexed Markdown pages inside a named collection.", "inputSchema": objProp([]string{"query"}, map[string]any{"collectionId": sType, "query": sType, "limit": iType})},
		{"name": "interact", "description": "Execute interactive browser actions in a caller-bound session.", "inputSchema": objProp(nil, map[string]any{"url": sType, "sessionId": sType, "actions": map[string]any{"type": "array"}, "close": bType})},
		{"name": "read_artifact", "description": "Read a slice of a stored Markdown or raw artifact by artifactId.", "inputSchema": objProp([]string{"artifactId"}, map[string]any{"artifactId": sType, "offset": iType, "limit": iType})},
		{"name": "jobs", "description": "Discover and filter structured job postings from ATS boards and JSON-LD.", "inputSchema": objProp(nil, map[string]any{"url": sType, "company": sType, "domain": sType, "query": sType, "remoteOnly": bType, "limit": iType})},
		{"name": "find_extractors", "description": "Search built-in declarative keyless site adapters.", "inputSchema": objProp(nil, map[string]any{"query": sType, "category": sType, "limit": iType})},
		{"name": "catalog", "description": "Extract normalized Shopify or WooCommerce product catalogs and diffs.", "inputSchema": objProp(nil, map[string]any{"url": sType, "catalogId": sType, "platform": sType, "fields": sType, "maxPages": iType})},
		{"name": "agent", "description": "Run a bounded research/extraction agent loop over web & site tools.", "inputSchema": objProp(nil, map[string]any{"prompt": sType, "agentId": sType, "urls": map[string]any{"type": "array", "items": sType}, "effort": sType})},
		{"name": "discover_mcp_servers", "description": "Search Official MCP Registry and Glama MCP Directory.", "inputSchema": objProp(nil, map[string]any{"query": sType, "remoteOnly": bType, "limit": iType})},
		{"name": "call_connected_mcp", "description": "List or invoke tools on a user-connected federated MCP server.", "inputSchema": objProp(nil, map[string]any{"action": sType, "server": sType, "tool": sType, "arguments": map[string]any{"type": "object"}})},
	}
}

func requiredScopeForMCPTool(name string, args map[string]any) string {
	switch name {
	case "list_agents", "find_extractors", "read_artifact", "search_collection", "discover_mcp_servers", "discover_mcps":
		return "crawl:read"
	case "call_connected_mcp", "query_mcp":
		act := firstNonEmpty(strField(args["action"]), "call_tool")
		if act == "list_connected" {
			return "crawl:read"
		}
		return "mcp:call"
	case "fetch_url", "fetch_batch", "scrape", "extract", "map", "crawl", "search", "interact", "jobs", "catalog", "agent":
		return "crawl:fetch"
	default:
		return ""
	}
}

func primaryURLFromMCPArgs(args map[string]any) string {
	if u := strings.TrimSpace(strField(args["url"])); u != "" {
		return u
	}
	if urls := stringSliceField(args["urls"]); len(urls) > 0 {
		return urls[0]
	}
	return ""
}

func (h *RouteHandler) checkMCPRobotsBypassAllowed(args map[string]any, targetURLs []string) bool {
	rr, hasRR := args["respectRobots"].(bool)
	rb, hasRB := args["robots"].(bool)
	wantsDisable := (hasRR && !rr) || (hasRB && !rb)
	if !wantsDisable {
		return true
	}
	if len(targetURLs) == 0 {
		return false
	}
	for _, u := range targetURLs {
		if !IsRobotBypassedHost(u, h.deps.RobotsBypassHosts) {
			return false
		}
	}
	return true
}

func formatMCPToolPayload(v any, isErr bool) map[string]any {
	b, _ := json.MarshalIndent(v, "", "  ")
	return map[string]any{
		"isError": isErr,
		"content": []map[string]any{{"type": "text", "text": string(b)}},
	}
}

func formatMCPUntrustedText(text string, isErr bool) map[string]any {
	return map[string]any{
		"isError": isErr,
		"content": []map[string]any{{"type": "text", "text": text}},
	}
}

func (h *RouteHandler) executeMCPToolCall(
	ctx context.Context, hdr http.Header, name string, args map[string]any, p AuthPrincipal,
) map[string]any {
	spanAttrs := map[string]any{"mcp.tool.name": name}
	if rawU := primaryURLFromMCPArgs(args); rawU != "" {
		spanAttrs["url.full"] = otel.SanitizeURL(rawU)
	}
	ctx, span, _ := otel.StartChildSpan(ctx, h.deps.OtelExporter, "edgefetch.mcp.tool", 1, spanAttrs)
	isErr := false
	errReason := ""
	defer func() {
		span.SetAttribute("mcp.is_error", isErr)
		span.End(!isErr, errReason)
	}()

	neededScope := requiredScopeForMCPTool(name, args)
	if neededScope != "" && !p.HasScope(neededScope) {
		if !(neededScope == "crawl:read" && p.HasScope("mcp:call") && (name == "call_connected_mcp" || name == "query_mcp")) {
			isErr = true
			errReason = "insufficient_scope"
			return formatMCPToolPayload(map[string]any{
				"ok":       false,
				"error":    "insufficient_scope",
				"required": neededScope,
				"message":  "Insufficient OAuth scope: " + neededScope + " is required.",
			}, true)
		}
	}

	ownerID := p.EffectiveOwnerID()

	switch name {
	case "list_agents":
		return formatMCPToolPayload(h.listAgents(), false)

	case "find_extractors":
		matches := extract.FindDeclarativeAdapters(strField(args["query"]), strField(args["category"]), intField(args["limit"], 10, 1, 50))
		return formatMCPToolPayload(map[string]any{
			"ok":         true,
			"count":      len(matches),
			"runtime":    "go-declarative",
			"extractors": matches,
		}, false)

	case "read_artifact":
		artID := firstNonEmpty(strField(args["artifactId"]), strField(args["blobSha256"]))
		pg, st, code := h.readArtifact(ctx, ArtifactSliceRequest{
			ArtifactID: artID,
			OwnerID:    ownerID,
			Visibility: strField(args["visibility"]),
			Format:     strField(args["format"]),
			Offset:     intField(args["offset"], 0, 0, 1<<30),
			Limit:      intField(args["limit"], 32768, 1, 262144),
		})
		if st != http.StatusOK || pg == nil {
			isErr = true
			errReason = firstNonEmpty(code, "artifact_not_found")
			return formatMCPToolPayload(map[string]any{"ok": false, "status": st, "error": errReason}, true)
		}
		return formatMCPToolPayload(pg, false)

	case "search_collection":
		colID := firstNonEmpty(strField(args["collectionId"]), "default")
		q := strField(args["query"])
		hits := h.searchCollectionDocs(ctx, colID, q, ownerID, intField(args["limit"], 10, 1, 100))
		return formatMCPToolPayload(map[string]any{"ok": true, "collectionId": colID, "query": q, "hits": hits}, false)

	case "fetch_url":
		u := strings.TrimSpace(strField(args["url"]))
		if !h.checkMCPRobotsBypassAllowed(args, nonEmptySingleton(u)) {
			isErr = true
			errReason = "robots_bypass_forbidden"
			return formatMCPUntrustedText("Disabling robots.txt via MCP is not permitted.", true)
		}
		pu, err := url.Parse(u)
		if err != nil || pu.Host == "" || h.allowURL(pu) != nil {
			isErr = true
			errReason = "bad_url"
			return formatMCPToolPayload(map[string]any{"ok": false, "error": "bad_url"}, true)
		}
		if h.deps.DispatchFetch == nil {
			isErr = true
			errReason = "hub_unavailable"
			return formatMCPToolPayload(map[string]any{"ok": false, "error": "hub_unavailable"}, true)
		}
		respect := !(args["respectRobots"] == false || args["robots"] == false)
		k := classify.Kind(firstNonEmpty(strField(args["kind"]), string(classify.KindPage)))
		rep, via, st, dErr := h.deps.DispatchFetch(ctx, crawl.FetchCall{
			MaxSeconds: 45,
			Options:    crawl.Options{Concurrency: 1, IncludeBody: true, RespectRobots: crawl.Bool(respect)},
			Requests:   []crawl.Request{{ID: "mcp-1", URL: u, Kind: k}},
		}, strField(args["target"]), strField(args["site"]), hdr)
		if dErr != nil {
			isErr = true
			errReason = dErr.Error()
			return formatMCPToolPayload(map[string]any{"ok": false, "status": st, "error": dErr.Error()}, true)
		}
		isErr = st >= 400
		return formatMCPToolPayload(map[string]any{"ok": !isErr, "via": via, "httpStatus": st, "results": rep.Results, "summary": rep.Summary}, isErr)

	case "fetch_batch":
		urls := stringSliceField(args["urls"])
		if !h.checkMCPRobotsBypassAllowed(args, urls) {
			isErr = true
			errReason = "robots_bypass_forbidden"
			return formatMCPUntrustedText("Disabling robots.txt via MCP is not permitted.", true)
		}
		if len(urls) == 0 || len(urls) > 25 {
			isErr = true
			errReason = "invalid_urls"
			return formatMCPUntrustedText("urls must contain 1 to 25 HTTPS URLs", true)
		}
		reqs := make([]crawl.Request, 0, len(urls))
		for i, u := range urls {
			pu, err := url.Parse(u)
			if err != nil || pu.Host == "" || h.allowURL(pu) != nil {
				isErr = true
				errReason = "bad_url"
				return formatMCPToolPayload(map[string]any{"ok": false, "error": "bad_url", "url": u}, true)
			}
			reqs = append(reqs, crawl.Request{ID: "mcp-" + string(rune('1'+i)), URL: u, Kind: classify.KindPage})
		}
		if h.deps.DispatchFetch == nil {
			isErr = true
			errReason = "hub_unavailable"
			return formatMCPToolPayload(map[string]any{"ok": false, "error": "hub_unavailable"}, true)
		}
		respect := !(args["respectRobots"] == false || args["robots"] == false)
		rep, via, st, dErr := h.deps.DispatchFetch(ctx, crawl.FetchCall{
			MaxSeconds: 60,
			Options:    crawl.Options{Concurrency: 4, IncludeBody: true, RespectRobots: crawl.Bool(respect)},
			Requests:   reqs,
		}, strField(args["target"]), strField(args["site"]), hdr)
		if dErr != nil {
			isErr = true
			errReason = dErr.Error()
			return formatMCPToolPayload(map[string]any{"ok": false, "error": dErr.Error()}, true)
		}
		isErr = st >= 400
		return formatMCPToolPayload(map[string]any{"ok": !isErr, "via": via, "httpStatus": st, "results": rep.Results, "summary": rep.Summary}, isErr)

	case "scrape":
		u := strings.TrimSpace(strField(args["url"]))
		if !h.checkMCPRobotsBypassAllowed(args, nonEmptySingleton(u)) {
			isErr = true
			errReason = "robots_bypass_forbidden"
			return formatMCPUntrustedText("Disabling robots.txt via MCP is not permitted.", true)
		}
		var req ScrapeRequest
		b, _ := json.Marshal(args)
		_ = json.Unmarshal(b, &req)
		out, _, st := h.ExecuteScrape(ctx, req, hdr, ownerID)
		delete(out, "_etag")
		isErr = st != http.StatusOK || out["ok"] == false
		if isErr {
			errReason = firstNonEmpty(strField(out["problem"]), strField(out["error"]), "scrape_failed")
		}
		return formatMCPToolPayload(out, isErr)

	case "extract":
		out, st := h.ExecuteExtract(ctx, args, hdr, ownerID)
		isErr = st != http.StatusOK || out["ok"] == false
		return formatMCPToolPayload(out, isErr)

	case "map":
		out, _, st := h.ExecuteMap(ctx, args, hdr)
		isErr = st != http.StatusOK || out["ok"] == false
		return formatMCPToolPayload(out, isErr)

	case "crawl":
		u := strings.TrimSpace(strField(args["url"]))
		if !h.checkMCPRobotsBypassAllowed(args, nonEmptySingleton(u)) {
			isErr = true
			errReason = "robots_bypass_forbidden"
			return formatMCPUntrustedText("Disabling robots.txt via MCP is not permitted.", true)
		}
		if cid := strings.TrimSpace(strField(args["crawlId"])); cid != "" {
			if boolField(args["cancel"]) {
				okC := h.cancelJob(ctx, "crawl", cid, ownerID)
				isErr = !okC
				return formatMCPToolPayload(map[string]any{"ok": okC, "crawlId": cid, "status": "cancelled"}, isErr)
			}
			rec, found := h.getJob(ctx, "crawl", cid, ownerID)
			if !found {
				isErr = true
				return formatMCPToolPayload(map[string]any{"ok": false, "error": "crawl_not_found"}, true)
			}
			return formatMCPToolPayload(rec, false)
		}
		out, st := h.ExecuteCrawl(ctx, args, hdr, ownerID, "")
		isErr = st >= 400
		return formatMCPToolPayload(out, isErr)

	case "search":
		out, st := h.ExecuteSearch(ctx, args, hdr, ownerID)
		isErr = st != http.StatusOK
		return formatMCPToolPayload(out, isErr)

	case "interact":
		out, _, st := h.ExecuteInteract(ctx, args, hdr, ownerID)
		isErr = st != http.StatusOK || out["ok"] == false
		if isErr {
			errReason = firstNonEmpty(strField(out["error"]), "interact_failed")
		}
		return formatMCPToolPayload(out, isErr)

	case "jobs":
		out, st := h.ExecuteJobs(ctx, args, hdr, ownerID)
		isErr = st != http.StatusOK
		return formatMCPToolPayload(out, isErr)

	case "catalog":
		out, st := h.ExecuteCatalog(ctx, args, hdr, p)
		isErr = st >= 400
		return formatMCPToolPayload(out, isErr)

	case "agent":
		if aid := strings.TrimSpace(strField(args["agentId"])); aid != "" {
			if boolField(args["cancel"]) {
				okC := h.cancelJob(ctx, "agent", aid, ownerID)
				isErr = !okC
				return formatMCPToolPayload(map[string]any{"ok": okC, "id": aid, "status": "cancelled"}, isErr)
			}
			rec, found := h.getJob(ctx, "agent", aid, ownerID)
			if !found {
				isErr = true
				return formatMCPToolPayload(map[string]any{"ok": false, "error": "agent_not_found"}, true)
			}
			return formatMCPToolPayload(rec.Payload, false)
		}
		out, st := h.ExecuteAgent(ctx, args, hdr, p, nil)
		isErr = st >= 400
		return formatMCPToolPayload(out, isErr)

	case "discover_mcp_servers", "discover_mcps":
		out, st := h.ExecuteDiscoverMcpRegistry(ctx, strField(args["query"]), boolField(args["remoteOnly"]), intField(args["limit"], 20, 1, 50))
		isErr = st >= 400
		return formatMCPToolPayload(out, isErr)

	case "call_connected_mcp", "query_mcp":
		callArgs := cloneMap(args)
		if callArgs["action"] == nil {
			if strField(callArgs["tool"]) != "" {
				callArgs["action"] = "call_tool"
			} else {
				callArgs["action"] = "list_connected"
			}
		}
		out, st := h.ExecuteFederatedMcpQuery(ctx, callArgs, p)
		isErr = st >= 400 || out["isError"] == true || out["ok"] == false
		return formatMCPToolPayload(out, isErr)

	default:
		isErr = true
		errReason = "unknown_tool"
		return formatMCPUntrustedText("Unknown tool: "+name, true)
	}
}

func nonEmptySingleton(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	return []string{strings.TrimSpace(s)}
}
