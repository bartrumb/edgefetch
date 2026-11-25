package mcpfed

import (
	"bytes"
	"encoding/json"
	"net/url"
	"regexp"
	"sort"
	"strings"
)

var (
	mcpQueryTokenSplitRe   = regexp.MustCompile(`[\s<>()"'\[\]{},;]+`)
	sensitiveQueryParamRe  = regexp.MustCompile(`(?i)^(?:token|access_token|id_token|refresh_token|api[_.-]?key|key|secret|password|passwd|pwd|sig|signature|x-amz-signature|x-goog-signature|code|session|session_id|jwt|auth)$`)
	scrapeReadToolPrefixRe = regexp.MustCompile(`(?i)^(?:get|fetch|read|retrieve|resolve|view|inspect|page|search)(?:[_.-]|$|[A-Z])`)
	mcpSessionIDHeaderRe   = regexp.MustCompile(`^[\x21-\x7e]{1,256}$`)
)

// RPCID represents an optional string or numeric JSON-RPC 2.0 request ID.
type RPCID struct {
	Present bool
	IsNum   bool
	Str     string
	Num     float64
}

// UnmarshalJSON parses an optional string or number JSON-RPC ID.
func (id *RPCID) UnmarshalJSON(data []byte) error {
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" || trimmed == "null" {
		*id = RPCID{}
		return nil
	}
	if strings.HasPrefix(trimmed, `"`) {
		var s string
		if err := json.Unmarshal(data, &s); err != nil {
			return err
		}
		*id = RPCID{Present: true, IsNum: false, Str: s}
		return nil
	}
	f, ok := numberToFiniteFloat(json.Number(trimmed))
	if ok {
		*id = RPCID{Present: true, IsNum: true, Num: f}
	}
	return nil
}

func matchesRPCID(msg OrderedObject, expected RPCID) bool {
	if !expected.Present {
		return true
	}
	rawID, hasID := msg.Get("id")
	if !hasID || rawID == nil {
		return false
	}
	if expected.IsNum {
		n, isNum := rawID.(json.Number)
		if !isNum {
			return false
		}
		f, ok := numberToFiniteFloat(n)
		return ok && f == expected.Num
	}
	s, isStr := rawID.(string)
	return isStr && s == expected.Str
}

func hasRPCResultOrError(msg OrderedObject) bool {
	if _, ok := msg.Get("result"); ok {
		return true
	}
	if _, ok := msg.Get("error"); ok {
		return true
	}
	return false
}

// ParseSSEJSONRPCResponse parses a Streamable HTTP text/event-stream SSE payload and extracts the JSON-RPC 2.0 response matching expected.
func ParseSSEJSONRPCResponse(sseText string, expected RPCID) (OrderedObject, bool) {
	normalized := strings.ReplaceAll(sseText, "\r\n", "\n")
	normalized = strings.ReplaceAll(normalized, "\r", "\n")
	blocks := strings.Split(normalized, "\n\n")

	var fallback OrderedObject
	hasFallback := false

	for _, block := range blocks {
		if strings.TrimSpace(block) == "" {
			continue
		}
		var dataLines []string
		for _, line := range strings.Split(block, "\n") {
			if strings.HasPrefix(line, ":") {
				continue
			}
			if strings.HasPrefix(line, "data:") {
				after := strings.TrimPrefix(line[5:], " ")
				dataLines = append(dataLines, after)
			}
		}
		if len(dataLines) == 0 {
			continue
		}
		rawData := strings.TrimSpace(strings.Join(dataLines, "\n"))
		if rawData == "" || rawData == "[DONE]" {
			continue
		}
		if !IsJSONDepthWithinLimit(rawData, 32) {
			continue
		}
		parsedAny, err := ParseOrderedJSON([]byte(rawData), 32)
		if err != nil {
			continue
		}
		var candidates []any
		if arr, isArr := parsedAny.([]any); isArr {
			candidates = arr
		} else {
			candidates = []any{parsedAny}
		}
		for _, item := range candidates {
			msg, isObj := item.(OrderedObject)
			if !isObj || !hasRPCResultOrError(msg) {
				continue
			}
			if expected.Present {
				if matchesRPCID(msg, expected) {
					return msg, true
				}
				continue
			}
			fallback = msg
			hasFallback = true
		}
	}

	if expected.Present {
		return nil, false
	}
	return fallback, hasFallback
}

// ParseRemoteJSONRPCBody parses either application/json or text/event-stream JSON-RPC responses matching expected.
func ParseRemoteJSONRPCBody(bodyText, contentType string, expected RPCID) (rpc OrderedObject, depthExceeded bool, found bool) {
	ctLower := strings.ToLower(contentType)
	if strings.Contains(ctLower, "text/event-stream") {
		msg, ok := ParseSSEJSONRPCResponse(bodyText, expected)
		return msg, false, ok
	}
	trimmed := strings.TrimSpace(bodyText)
	if trimmed == "" {
		return nil, false, false
	}
	if !IsJSONDepthWithinLimit(trimmed, 32) {
		return nil, true, false
	}
	parsedAny, err := ParseOrderedJSON([]byte(trimmed), 32)
	if err != nil {
		msg, ok := ParseSSEJSONRPCResponse(bodyText, expected)
		return msg, false, ok
	}
	var candidates []any
	if arr, isArr := parsedAny.([]any); isArr {
		candidates = arr
	} else {
		candidates = []any{parsedAny}
	}
	for _, cand := range candidates {
		msg, isObj := cand.(OrderedObject)
		if !isObj || !hasRPCResultOrError(msg) {
			continue
		}
		if expected.Present {
			if matchesRPCID(msg, expected) {
				return msg, false, true
			}
		} else {
			return msg, false, true
		}
	}
	return nil, false, false
}

// ExtractMarkdownFromQueryMCPBody extracts joined Markdown/text from a query_mcp response body.
func ExtractMarkdownFromQueryMCPBody(rawBody json.RawMessage) string {
	parsedAny, err := ParseOrderedJSON(rawBody, 32)
	if err != nil {
		return ""
	}
	body, isObj := parsedAny.(OrderedObject)
	if !isObj {
		return ""
	}
	if md, ok := body.GetString("markdown"); ok && md != "" {
		return md
	}
	if contentArr, ok := body.GetArray("content"); ok && len(contentArr) > 0 {
		parts := make([]string, 0, len(contentArr))
		for _, item := range contentArr {
			block, isB := item.(OrderedObject)
			if !isB {
				continue
			}
			bType, _ := block.GetString("type")
			if bType == "text" {
				if txt, ok := block.GetString("text"); ok && txt != "" {
					parts = append(parts, txt)
				}
			} else if bType == "resource" {
				if resObj, ok := block.GetObject("resource"); ok {
					if txt, ok := resObj.GetString("text"); ok && txt != "" {
						parts = append(parts, txt)
					}
				}
			}
		}
		if len(parts) > 0 {
			return strings.Join(parts, "\n\n")
		}
	}
	if sc, hasSC := body.Get("structuredContent"); hasSC && sc != nil {
		if scStr, isStr := sc.(string); isStr {
			return scStr
		}
		var buf bytes.Buffer
		enc := json.NewEncoder(&buf)
		enc.SetEscapeHTML(false)
		enc.SetIndent("", "  ")
		if err := enc.Encode(sc); err == nil {
			return strings.TrimRight(buf.String(), "\n")
		}
	}
	return ""
}

// MatchedConnectedMCP ranks an enabled connected MCP server against target URLs and query text.
type MatchedConnectedMCP struct {
	Server         PublicMCPServerSummary `json:"server"`
	MatchedDomains []string               `json:"matchedDomains"`
	Score          int                    `json:"score"`
}

func extractCleanHostnameForMatch(rawURL string) string {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return ""
	}
	h := strings.ToLower(u.Hostname())
	h = strings.TrimPrefix(h, "www.")
	return h
}

// MatchConnectedMCPsForContext ranks a user's enabled connected MCP servers against URLs and query text.
func MatchConnectedMCPsForContext(servers []StoredMCPServerRow, query string, urls []string) []MatchedConnectedMCP {
	qSliced, _ := sliceUTF16(query, 4096)
	qLower := strings.ToLower(qSliced)

	urlHosts := make([]string, 0, len(urls)+2)
	seenHosts := make(map[string]bool, len(urls)+2)
	addHost := func(h string) {
		if h != "" && !seenHosts[h] {
			seenHosts[h] = true
			urlHosts = append(urlHosts, h)
		}
	}
	for _, rawU := range urls {
		addHost(extractCleanHostnameForMatch(rawU))
	}
	for _, tok := range mcpQueryTokenSplitRe.Split(qLower, -1) {
		if !strings.HasPrefix(tok, "http://") && !strings.HasPrefix(tok, "https://") {
			continue
		}
		addHost(extractCleanHostnameForMatch(tok))
	}

	out := make([]MatchedConnectedMCP, 0)
	for _, row := range servers {
		if !row.Enabled {
			continue
		}
		score := 0
		matchedDomains := make([]string, 0)
		seenMatched := make(map[string]bool)

		for _, dom := range row.Domains {
			cleanDom := strings.ToLower(dom)
			cleanDom = strings.TrimPrefix(cleanDom, "*.")
			cleanDom = strings.TrimPrefix(cleanDom, "www.")
			if cleanDom == "" {
				continue
			}
			for _, uh := range urlHosts {
				if uh == cleanDom || strings.HasSuffix(uh, "."+cleanDom) {
					score += 40
					if !seenMatched[cleanDom] {
						seenMatched[cleanDom] = true
						matchedDomains = append(matchedDomains, cleanDom)
					}
				}
			}
			if strings.Contains(qLower, cleanDom) {
				score += 25
				if !seenMatched[cleanDom] {
					seenMatched[cleanDom] = true
					matchedDomains = append(matchedDomains, cleanDom)
				}
			}
		}

		slugClean := strings.ToLower(row.Slug)
		nameClean := strings.ToLower(row.Name)
		if utf16Len(slugClean) >= 3 && strings.Contains(qLower, slugClean) {
			score += 20
		} else if utf16Len(nameClean) >= 3 && strings.Contains(qLower, nameClean) {
			score += 16
		}

		if score > 0 {
			out = append(out, MatchedConnectedMCP{
				Server:         ToPublicMCPServerSummary(row),
				MatchedDomains: matchedDomains,
				Score:          score,
			})
		}
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].Score != out[j].Score {
			return out[i].Score > out[j].Score
		}
		return out[i].Server.Slug < out[j].Server.Slug
	})
	return out
}

// SanitizeTargetURLForMCPForwarding validates targetURL as safe public HTTPS and strips credentials, hash, and sensitive query params.
func SanitizeTargetURLForMCPForwarding(rawURL, selfHost string) (safeForwardURL string, normalizedTarget string, ok bool) {
	check := IsSafePublicHTTPSURL(rawURL, selfHost)
	if !check.OK {
		return "", "", false
	}
	u, err := url.Parse(check.Normalized)
	if err != nil {
		return "", "", false
	}
	u.User = nil
	u.Fragment = ""
	u.RawFragment = ""

	if u.RawQuery != "" {
		var kept []string
		for _, pair := range strings.Split(u.RawQuery, "&") {
			if pair == "" {
				continue
			}
			rawK := pair
			if eq := strings.IndexByte(pair, '='); eq >= 0 {
				rawK = pair[:eq]
			}
			decodedK, err := url.QueryUnescape(rawK)
			if err != nil {
				decodedK = rawK
			}
			if sensitiveQueryParamRe.MatchString(strings.TrimSpace(decodedK)) {
				continue
			}
			kept = append(kept, pair)
		}
		u.RawQuery = strings.Join(kept, "&")
		u.ForceQuery = false
	}
	return u.String(), check.Normalized, true
}

// ScrapeMCPPlan describes the selected MCP connector & read-only URL tool for tryScrapeViaConnectedMcp.
type ScrapeMCPPlan struct {
	Matched          bool          `json:"matched"`
	NormalizedTarget string        `json:"normalizedTarget,omitempty"`
	SafeForwardURL   string        `json:"safeForwardUrl,omitempty"`
	ServerSlug       string        `json:"serverSlug,omitempty"`
	ToolName         string        `json:"toolName,omitempty"`
	ToolArguments    OrderedObject `json:"toolArguments,omitempty"`
}

// SelectScrapeMCPCandidate evaluates H1/S6 opt-in scrape routing rules and selects a permitted read-oriented URL tool.
func SelectScrapeMCPCandidate(
	allRows []StoredMCPServerRow,
	targetURL string,
	query string,
	preferMCP bool,
	hasAllowedServerIDs bool,
	allowedServerIDs map[string]bool,
	allowedTools map[string]bool,
	requireExplicitReadOnlyHint bool,
	selfHost string,
) ScrapeMCPPlan {
	safeForwardURL, normalizedTarget, ok := SanitizeTargetURLForMCPForwarding(targetURL, selfHost)
	if !ok || len(allRows) == 0 {
		return ScrapeMCPPlan{Matched: false}
	}

	eligible := make([]StoredMCPServerRow, 0, len(allRows))
	for _, r := range allRows {
		if !r.Enabled || !IsValidMCPConnectorSlug(r.Slug) {
			continue
		}
		if hasAllowedServerIDs && !allowedServerIDs[r.ID] {
			continue
		}
		if !preferMCP && !r.AutoRouteScrape {
			continue
		}
		eligible = append(eligible, r)
	}
	if len(eligible) == 0 {
		return ScrapeMCPPlan{Matched: false}
	}

	matches := MatchConnectedMCPsForContext(eligible, "", []string{safeForwardURL})
	if len(matches) == 0 || len(matches[0].MatchedDomains) == 0 {
		return ScrapeMCPPlan{Matched: false}
	}
	top := matches[0]
	topSlugLower := strings.ToLower(top.Server.Slug)

	rawToolsBytes, err := MarshalUnescapedJSON(top.Server.Tools)
	if err != nil {
		return ScrapeMCPPlan{Matched: false}
	}
	safeTools := FilterSafeCachedMCPTools(rawToolsBytes)

	var chosen *CachedMCPToolSchema
	for i := range safeTools {
		t := &safeTools[i]
		if !IsSafeMCPIdentifier(t.Name) {
			continue
		}
		explicitlyAllowed := allowedTools[topSlugLower+"/"+t.Name]
		if !explicitlyAllowed {
			if requireExplicitReadOnlyHint && (t.ReadOnlyHint == nil || !*t.ReadOnlyHint) {
				continue
			}
			if (t.ReadOnlyHint != nil && !*t.ReadOnlyHint) || (t.DestructiveHint != nil && *t.DestructiveHint) {
				continue
			}
		}
		isReadName := explicitlyAllowed ||
			scrapeReadToolPrefixRe.MatchString(t.Name) ||
			(t.ReadOnlyHint != nil && *t.ReadOnlyHint)
		if !isReadName {
			continue
		}
		props, hasProps := t.InputSchema.GetObject("properties")
		if !hasProps {
			continue
		}
		_, hasURL := props.Get("url")
		_, hasURI := props.Get("uri")
		if hasURL || hasURI {
			chosen = t
			break
		}
	}
	if chosen == nil {
		return ScrapeMCPPlan{Matched: false}
	}

	props, _ := chosen.InputSchema.GetObject("properties")
	toolArgs := make(OrderedObject, 0, 2)
	if _, hasURL := props.Get("url"); hasURL {
		toolArgs.Set("url", safeForwardURL)
	} else {
		toolArgs.Set("uri", safeForwardURL)
	}
	if query != "" {
		if _, hasQ := props.Get("query"); hasQ {
			qSliced, _ := sliceUTF16(query, 500)
			toolArgs.Set("query", qSliced)
		}
	}

	return ScrapeMCPPlan{
		Matched:          true,
		NormalizedTarget: normalizedTarget,
		SafeForwardURL:   safeForwardURL,
		ServerSlug:       top.Server.Slug,
		ToolName:         chosen.Name,
		ToolArguments:    toolArgs,
	}
}

// BuildPinnedOutboundHeaders verifies secret.pinnedOrigin === targetOrigin and constructs outbound JSON-RPC headers.
func BuildPinnedOutboundHeaders(secret *VaultSecretPayload, targetOrigin, sessionID string) (OrderedObject, bool, string) {
	headers := OrderedObject{
		{Key: "content-type", Value: "application/json"},
		{Key: "accept", Value: "application/json, text/event-stream"},
		{Key: "user-agent", Value: "EdgeFetch-MCP-Federation/2.7"},
		{Key: "mcp-protocol-version", Value: "2025-03-26"},
	}
	if sessionID != "" && mcpSessionIDHeaderRe.MatchString(sessionID) {
		headers.Set("mcp-session-id", sessionID)
	}
	if secret == nil || secret.Kind == "none" {
		return headers, true, ""
	}
	if !strings.EqualFold(secret.PinnedOrigin, targetOrigin) {
		return nil, false, "Refusing to attach vault credentials: target origin does not match pinnedOrigin"
	}
	if secret.Kind == "oauth2" && secret.OAuth != nil && secret.OAuth.AccessToken != "" {
		headers.Set("authorization", "Bearer "+secret.OAuth.AccessToken)
	} else if secret.Kind == "headers" {
		for _, entry := range secret.Headers {
			valStr, ok := entry.Value.(string)
			if !ok {
				continue
			}
			if !containsCRorLForNUL(entry.Key) && !containsCRorLForNUL(valStr) {
				headers.Set(entry.Key, valStr)
			}
		}
	}
	return headers, true, ""
}

func containsCRorLForNUL(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == '\r' || s[i] == '\n' || s[i] == 0 {
			return true
		}
	}
	return false
}
