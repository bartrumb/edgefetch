package hub

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"

	"github.com/bartrumb/edgefetch/v2/internal/agent"
)

const (
	maxMCPBodyBytes        = 256 << 10 // 256 KiB (`T2-A4`)
	defaultMCPProtocolVer  = "2025-03-26"
	modernMCPProtocolVer   = "2026-07-28"
	maxMCPBatchRequests    = 20
	mcpServerDiscoveryTTL  = 60000
	mcpToolsListCacheTTLMs = 300000
)

var supportedMCPProtocolVersions = []string{
	"2026-07-28",
	"2025-06-18",
	"2025-03-26",
	"2024-11-05",
}

type jsonRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

func (r jsonRPCRequest) isNotification() bool {
	return len(r.ID) == 0
}

func (r jsonRPCRequest) parsedID() any {
	if len(r.ID) == 0 {
		return nil
	}
	var v any
	if err := json.Unmarshal(r.ID, &v); err != nil {
		return nil
	}
	return v
}

func mcpJSONRPCError(id any, code int, msg string, data any) map[string]any {
	errObj := map[string]any{"code": code, "message": msg}
	if data != nil {
		errObj["data"] = data
	}
	return map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
		"error":   errObj,
	}
}

func mcpJSONRPCResult(id any, result map[string]any) map[string]any {
	return map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
		"result":  result,
	}
}

func isSupportedMCPVersion(v string) bool {
	for _, s := range supportedMCPProtocolVersions {
		if s == v {
			return true
		}
	}
	return false
}

func isAllowedMCPOriginHeader(rawOrigin, hubPublicOrigin string) bool {
	rawOrigin = strings.TrimSpace(rawOrigin)
	if rawOrigin == "" {
		return true
	}
	ou, err := url.Parse(rawOrigin)
	if err != nil || (ou.Scheme != "http" && ou.Scheme != "https") || ou.Host == "" || ou.User != nil {
		return false
	}
	if isLoopbackHostnameOnly(ou.Hostname()) {
		return true
	}
	normalized := strings.ToLower(ou.Scheme + "://" + ou.Host)
	return strings.EqualFold(normalized, strings.TrimRight(strings.TrimSpace(hubPublicOrigin), "/"))
}

func applyMCPResponseCORS(w http.ResponseWriter, r *http.Request) {
	if origin := strings.TrimSpace(r.Header.Get("Origin")); origin != "" {
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Vary", "Origin")
		w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, X-API-Key, Mcp-Protocol-Version, Mcp-Method, Mcp-Name, Mcp-Session-Id, Traceparent")
		w.Header().Set("Access-Control-Expose-Headers", "Mcp-Protocol-Version, X-Trace-Id, Traceparent")
	}
}

// HandleMCP serves Streamable HTTP MCP (`2026-07-28` & `2025-03-26`) over `POST /mcp`.
func (h *RouteHandler) HandleMCP(w http.ResponseWriter, r *http.Request) {
	pubOrigin := h.publicOriginOf(r)
	if !isAllowedMCPOriginHeader(r.Header.Get("Origin"), pubOrigin) {
		writeJSON(w, http.StatusForbidden, map[string]any{"ok": false, "error": "forbidden_origin"})
		return
	}
	applyMCPResponseCORS(w, r)

	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method == http.MethodGet || r.Method == http.MethodDelete {
		w.Header().Set("Allow", "POST, OPTIONS")
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST, OPTIONS")
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method_not_allowed"})
		return
	}

	p := h.principalOf(r)
	if !p.Authenticated {
		w.Header().Set("WWW-Authenticate", "Bearer")
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
		return
	}

	buf, tooLarge, err := ReadBoundedBody(w, r, maxMCPBodyBytes)
	if tooLarge {
		writeJSON(w, http.StatusRequestEntityTooLarge, mcpJSONRPCError(nil, -32600, "MCP payload exceeds 256 KiB", nil))
		return
	}
	if err != nil {
		writeJSON(w, http.StatusBadRequest, mcpJSONRPCError(nil, -32700, "Parse error", nil))
		return
	}

	hdrVer := strings.TrimSpace(r.Header.Get("Mcp-Protocol-Version"))
	if hdrVer != "" && !isSupportedMCPVersion(hdrVer) {
		writeJSON(w, http.StatusBadRequest, mcpJSONRPCError(nil, -32022, "Unsupported protocol version", map[string]any{
			"supported": supportedMCPProtocolVersions,
			"requested": hdrVer,
		}))
		return
	}

	trimmed := bytes.TrimSpace(buf)
	if len(trimmed) == 0 {
		writeJSON(w, http.StatusBadRequest, mcpJSONRPCError(nil, -32700, "Parse error", nil))
		return
	}

	if trimmed[0] == '[' {
		var batch []json.RawMessage
		if err := json.Unmarshal(trimmed, &batch); err != nil {
			writeJSON(w, http.StatusBadRequest, mcpJSONRPCError(nil, -32700, "Parse error", nil))
			return
		}
		if len(batch) == 0 || len(batch) > maxMCPBatchRequests {
			writeJSON(w, http.StatusBadRequest, mcpJSONRPCError(nil, -32600, "Invalid batch length (must be 1..20)", nil))
			return
		}
		isModern := hdrVer == modernMCPProtocolVer
		replies := make([]map[string]any, 0, len(batch))
		for _, item := range batch {
			var msg jsonRPCRequest
			if err := json.Unmarshal(item, &msg); err != nil {
				replies = append(replies, mcpJSONRPCError(nil, -32600, "Invalid Request", nil))
				continue
			}
			if needed := missingMCPToolScope(msg, p); needed != "" {
				w.Header().Set("WWW-Authenticate", `Bearer error="insufficient_scope", scope="`+needed+`"`)
				w.Header().Set("Mcp-Protocol-Version", firstNonEmpty(hdrVer, defaultMCPProtocolVer))
				writeJSON(w, http.StatusForbidden, mcpJSONRPCError(msg.parsedID(), -32001, "Insufficient OAuth scope: "+needed+" is required.", map[string]any{"required": needed}))
				return
			}
			rep, _ := h.dispatchMCPMessage(r.Context(), r.Header, msg, p, isModern)
			if rep != nil {
				replies = append(replies, rep)
			}
		}
		if len(replies) == 0 {
			w.WriteHeader(http.StatusAccepted)
			return
		}
		w.Header().Set("Mcp-Protocol-Version", firstNonEmpty(hdrVer, defaultMCPProtocolVer))
		writeJSON(w, http.StatusOK, replies)
		return
	}

	var msg jsonRPCRequest
	if err := json.Unmarshal(trimmed, &msg); err != nil {
		writeJSON(w, http.StatusBadRequest, mcpJSONRPCError(nil, -32700, "Parse error", nil))
		return
	}

	metaVer := extractMetaProtocolVersion(msg.Params)
	if metaVer != "" && !isSupportedMCPVersion(metaVer) {
		writeJSON(w, http.StatusBadRequest, mcpJSONRPCError(msg.parsedID(), -32022, "Unsupported protocol version", map[string]any{
			"supported": supportedMCPProtocolVersions,
			"requested": metaVer,
		}))
		return
	}
	if metaVer != "" && hdrVer != "" && metaVer != hdrVer {
		writeJSON(w, http.StatusBadRequest, mcpJSONRPCError(msg.parsedID(), -32020, "Header mismatch: Mcp-Protocol-Version does not match _meta", nil))
		return
	}
	if hdrMethod := strings.TrimSpace(r.Header.Get("Mcp-Method")); hdrMethod != "" && hdrMethod != msg.Method {
		writeJSON(w, http.StatusBadRequest, mcpJSONRPCError(msg.parsedID(), -32020, "Header mismatch: Mcp-Method does not match JSON-RPC method", nil))
		return
	}
	if msg.Method == "tools/call" {
		if hdrName := strings.TrimSpace(r.Header.Get("Mcp-Name")); hdrName != "" {
			decName, decErr := url.QueryUnescape(hdrName)
			if decErr != nil {
				decName = hdrName
			}
			var cp struct {
				Name string `json:"name"`
			}
			_ = json.Unmarshal(msg.Params, &cp)
			if decName != cp.Name && hdrName != cp.Name {
				writeJSON(w, http.StatusBadRequest, mcpJSONRPCError(msg.parsedID(), -32020, "Header mismatch: Mcp-Name does not match params.name", nil))
				return
			}
		}
	}

	effectiveVer := firstNonEmpty(metaVer, hdrVer, defaultMCPProtocolVer)
	isModern := effectiveVer == modernMCPProtocolVer || msg.Method == "server/discover"
	if needed := missingMCPToolScope(msg, p); needed != "" {
		w.Header().Set("WWW-Authenticate", `Bearer error="insufficient_scope", scope="`+needed+`"`)
		w.Header().Set("Mcp-Protocol-Version", effectiveVer)
		writeJSON(w, http.StatusForbidden, mcpJSONRPCError(msg.parsedID(), -32001, "Insufficient OAuth scope: "+needed+" is required.", map[string]any{"required": needed}))
		return
	}
	rep, httpStatus := h.dispatchMCPMessage(r.Context(), r.Header, msg, p, isModern)
	if rep == nil {
		w.WriteHeader(http.StatusAccepted)
		return
	}
	w.Header().Set("Mcp-Protocol-Version", effectiveVer)
	if msg.Method == "subscriptions/listen" {
		writeMCPSubscriptionListenSSE(w, msg.parsedID(), rep)
		return
	}
	writeJSON(w, httpStatus, rep)
}

// writeMCPSubscriptionListenSSE answers an MCP 2026-07-28 subscriptions/listen request as an SSE stream carrying
// notifications/subscriptions/acknowledged (honoring no notification types: the hub's tool list is fixed per build and
// it advertises listChanged: false) followed by the final "complete" result, i.e. a graceful end of the subscription
// so the client does not reconnect.
func writeMCPSubscriptionListenSSE(w http.ResponseWriter, id any, final map[string]any) {
	ack := map[string]any{
		"jsonrpc": "2.0",
		"method":  "notifications/subscriptions/acknowledged",
		"params": map[string]any{
			"_meta":         map[string]any{"io.modelcontextprotocol/subscriptionId": id},
			"notifications": map[string]any{},
		},
	}
	w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	for _, m := range []map[string]any{ack, final} {
		b, err := json.Marshal(m)
		if err != nil {
			return
		}
		_, _ = w.Write([]byte("event: message\ndata: "))
		_, _ = w.Write(b)
		_, _ = w.Write([]byte("\n\n"))
	}
	if fl, ok := w.(http.Flusher); ok {
		fl.Flush()
	}
}

func missingMCPToolScope(msg jsonRPCRequest, p AuthPrincipal) string {
	if msg.Method != "tools/call" {
		return ""
	}
	var cp struct {
		Name      string         `json:"name"`
		Arguments map[string]any `json:"arguments"`
	}
	if json.Unmarshal(msg.Params, &cp) != nil || cp.Name == "" {
		return ""
	}
	needed := requiredScopeForMCPTool(cp.Name, cp.Arguments)
	if needed != "" && !p.HasScope(needed) && !(needed == "crawl:read" && p.HasScope("mcp:call") && (cp.Name == "call_connected_mcp" || cp.Name == "query_mcp")) {
		return needed
	}
	return ""
}

func extractMetaProtocolVersion(rawParams json.RawMessage) string {
	if len(rawParams) == 0 {
		return ""
	}
	var p struct {
		Meta map[string]any `json:"_meta"`
	}
	if json.Unmarshal(rawParams, &p) != nil || p.Meta == nil {
		return ""
	}
	if v, ok := p.Meta["io.modelcontextprotocol/protocolVersion"].(string); ok {
		return strings.TrimSpace(v)
	}
	return ""
}

func (h *RouteHandler) dispatchMCPMessage(
	ctx context.Context, hdr http.Header, msg jsonRPCRequest, p AuthPrincipal, isModern bool,
) (map[string]any, int) {
	id := msg.parsedID()
	if msg.JSONRPC != "2.0" || strings.TrimSpace(msg.Method) == "" {
		return mcpJSONRPCError(id, -32600, "Invalid JSON-RPC 2.0 request", nil), http.StatusOK
	}
	if msg.isNotification() || strings.HasPrefix(msg.Method, "notifications/") {
		return nil, http.StatusAccepted
	}

	serverInfo := map[string]any{"name": "edgefetch-go-hub", "version": agent.Version}
	addModern := func(m map[string]any) map[string]any {
		if isModern {
			m["resultType"] = "complete"
			m["_meta"] = map[string]any{"io.modelcontextprotocol/serverInfo": serverInfo}
		}
		return m
	}

	switch msg.Method {
	case "server/discover":
		return mcpJSONRPCResult(id, map[string]any{
			"resultType":        "complete",
			"supportedVersions": supportedMCPProtocolVersions,
			"capabilities":      map[string]any{"tools": map[string]any{"listChanged": false}},
			"_meta":             map[string]any{"io.modelcontextprotocol/serverInfo": serverInfo},
			"ttlMs":             mcpServerDiscoveryTTL,
			"cacheScope":        "private",
		}), http.StatusOK

	case "initialize":
		var ip struct {
			ProtocolVersion string `json:"protocolVersion"`
		}
		_ = json.Unmarshal(msg.Params, &ip)
		negVer := defaultMCPProtocolVer
		if isSupportedMCPVersion(strings.TrimSpace(ip.ProtocolVersion)) {
			negVer = strings.TrimSpace(ip.ProtocolVersion)
		}
		return mcpJSONRPCResult(id, map[string]any{
			"protocolVersion": negVer,
			"capabilities":    map[string]any{"tools": map[string]any{"listChanged": false}},
			"serverInfo":      serverInfo,
		}), http.StatusOK

	case "ping", "logging/setLevel":
		return mcpJSONRPCResult(id, addModern(map[string]any{})), http.StatusOK

	case "subscriptions/listen":
		// No notification types are honored (listChanged: false), so the subscription ends at once with a graceful
		// "complete" result; the HTTP handler streams it after notifications/subscriptions/acknowledged.
		return mcpJSONRPCResult(id, map[string]any{
			"resultType": "complete",
			"_meta":      map[string]any{"io.modelcontextprotocol/subscriptionId": id},
		}), http.StatusOK

	case "tools/list":
		res := addModern(map[string]any{"tools": buildMCPCanonicalToolDefinitions()})
		if isModern {
			res["ttlMs"] = mcpToolsListCacheTTLMs
			res["cacheScope"] = "private"
		}
		return mcpJSONRPCResult(id, res), http.StatusOK

	case "tools/call":
		var cp struct {
			Name      string         `json:"name"`
			Arguments map[string]any `json:"arguments"`
		}
		if err := json.Unmarshal(msg.Params, &cp); err != nil || strings.TrimSpace(cp.Name) == "" {
			return mcpJSONRPCError(id, -32602, "Invalid params: missing tool name", nil), http.StatusOK
		}
		if cp.Arguments == nil {
			cp.Arguments = map[string]any{}
		}
		toolRes := h.executeMCPToolCall(ctx, hdr, cp.Name, cp.Arguments, p)
		return mcpJSONRPCResult(id, addModern(toolRes)), http.StatusOK

	default:
		return mcpJSONRPCError(id, -32601, "Method not found: "+msg.Method, nil), http.StatusOK
	}
}
