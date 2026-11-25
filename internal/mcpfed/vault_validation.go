package mcpfed

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

const (
	maxSecretHeadersTotalBytes = 32 * 1024
)

var (
	safeMCPIdentifierRe = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)
	promptInjMCPIDRe    = regexp.MustCompile(`(?i)(?:^|[_.-])(?:ignore|disregard|override|bypass|exfiltrate|jailbreak|forget)(?:[_.-]|$|[A-Z])|system[_.-]?(?:prompt|instruction|message|override)|developer[_.-]?(?:prompt|instruction|message)|prompt[_.-]?injection`)
	safeMCPSlugRe       = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,47}$`)
	doubleUnderscoreRe  = regexp.MustCompile(`__+`)
	httpTokenHeaderRe   = regexp.MustCompile("^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,80}$")
)

var forbiddenMCPIdentifiers = map[string]bool{
	"__proto__":   true,
	"constructor": true,
	"prototype":   true,
}

var forbiddenSecretHeaderNames = map[string]bool{
	"host":                   true,
	":authority":             true,
	":method":                true,
	":path":                  true,
	":scheme":                true,
	"content-length":         true,
	"transfer-encoding":      true,
	"connection":             true,
	"keep-alive":             true,
	"upgrade":                true,
	"te":                     true,
	"trailer":                true,
	"proxy-connection":       true,
	"proxy-authorization":    true,
	"content-type":           true,
	"content-encoding":       true,
	"accept":                 true,
	"accept-encoding":        true,
	"user-agent":             true,
	"origin":                 true,
	"referer":                true,
	"expect":                 true,
	"forwarded":              true,
	"x-forwarded-for":        true,
	"x-forwarded-host":       true,
	"x-forwarded-proto":      true,
	"x-real-ip":              true,
	"cf-connecting-ip":       true,
	"true-client-ip":         true,
	"fly-client-ip":          true,
	"x-http-method-override": true,
	"last-event-id":          true,
	"cookie":                 true,
	"cookie2":                true,
	"mcp-session-id":         true,
	"mcp-protocol-version":   true,
}

// CachedMCPToolSchema describes a sanitized tool cached on a connected MCP server row.
type CachedMCPToolSchema struct {
	Name            string        `json:"name"`
	Title           string        `json:"title,omitempty"`
	Description     string        `json:"description,omitempty"`
	InputSchema     OrderedObject `json:"inputSchema"`
	ReadOnlyHint    *bool         `json:"readOnlyHint,omitempty"`
	DestructiveHint *bool         `json:"destructiveHint,omitempty"`
}

// MaskedAuthSummary is the write-only public badge describing connector authentication without secrets.
type MaskedAuthSummary struct {
	AuthMode        string   `json:"authMode"`
	HeaderNames     []string `json:"headerNames"`
	MaskedBadge     string   `json:"maskedBadge"`
	HasRefreshToken *bool    `json:"hasRefreshToken,omitempty"`
	TokenExpiresAt  *int64   `json:"tokenExpiresAt,omitempty"`
}

// StoredMCPServerRow represents a user_mcp_servers persistence row.
type StoredMCPServerRow struct {
	ID                   string                `json:"id"`
	UserID               string                `json:"userId"`
	Slug                 string                `json:"slug"`
	Name                 string                `json:"name"`
	RemoteURL            string                `json:"remoteUrl"`
	RemoteOrigin         string                `json:"remoteOrigin"`
	Transport            string                `json:"transport"`
	AuthType             string                `json:"authType"`
	EncryptedCredentials *string               `json:"encryptedCredentials"`
	SecretVersion        *int                  `json:"secretVersion,omitempty"`
	AuthSummary          MaskedAuthSummary     `json:"authSummary"`
	Domains              []string              `json:"domains"`
	AutoRouteScrape      bool                  `json:"autoRouteScrape,omitempty"`
	CachedTools          []CachedMCPToolSchema `json:"cachedTools"`
	ToolCount            int                   `json:"toolCount"`
	Enabled              bool                  `json:"enabled"`
	LastVerifiedAt       *int64                `json:"lastVerifiedAt"`
	LastError            *string               `json:"lastError"`
	CreatedAt            int64                 `json:"createdAt"`
	UpdatedAt            int64                 `json:"updatedAt"`
}

// PublicMCPServerSummary is the secret-free projection returned to /admin and query_mcp(list_connected).
type PublicMCPServerSummary struct {
	ID              string                `json:"id"`
	UserID          string                `json:"userId"`
	Slug            string                `json:"slug"`
	Name            string                `json:"name"`
	RemoteURL       string                `json:"remoteUrl"`
	RemoteOrigin    string                `json:"remoteOrigin"`
	Transport       string                `json:"transport"`
	AuthType        string                `json:"authType"`
	AuthSummary     MaskedAuthSummary     `json:"authSummary"`
	Domains         []string              `json:"domains"`
	AutoRouteScrape bool                  `json:"autoRouteScrape"`
	Tools           []CachedMCPToolSchema `json:"tools"`
	ToolCount       int                   `json:"toolCount"`
	Enabled         bool                  `json:"enabled"`
	LastVerifiedAt  *int64                `json:"lastVerifiedAt"`
	LastError       *string               `json:"lastError"`
	CreatedAt       int64                 `json:"createdAt"`
	UpdatedAt       int64                 `json:"updatedAt"`
}

// IsSafeMCPIdentifier validates tool/property names against prototype pollution, "__", and prompt-injection verbs.
func IsSafeMCPIdentifier(raw string) bool {
	if raw == "" || !safeMCPIdentifierRe.MatchString(raw) || forbiddenMCPIdentifiers[raw] {
		return false
	}
	if strings.Contains(raw, "__") {
		return false
	}
	return !promptInjMCPIDRe.MatchString(raw)
}

// IsValidMCPConnectorSlug validates lowercase connector slugs (1..48 chars, no "__").
func IsValidMCPConnectorSlug(raw string) bool {
	if raw == "" || !safeMCPSlugRe.MatchString(raw) || strings.Contains(raw, "__") {
		return false
	}
	return IsSafeMCPIdentifier(raw)
}

// NormalizeMCPConnectorSlug derives a safe lowercase connector slug from an arbitrary server name.
func NormalizeMCPConnectorSlug(rawName string) string {
	base := SlugifyMCPServerName(rawName)
	base = doubleUnderscoreRe.ReplaceAllString(base, "-")
	base = strings.Trim(base, "-_")
	if base == "" {
		base = "mcp-server"
	}
	if len(base) > 48 {
		base = base[:48]
	}
	candidate := strings.TrimRight(base, "-_")
	if candidate == "" {
		candidate = "mcp-server"
	}
	if IsValidMCPConnectorSlug(candidate) {
		return candidate
	}
	return "mcp-server"
}

// ParseAllowedMCPTools validates exact "<slug>/<tool>" allowlist entries (<= 128 items, no wildcards or "__").
func ParseAllowedMCPTools(raw json.RawMessage) (allowed []string, ok bool, errCode string, message string) {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" || trimmed == "null" {
		return []string{}, true, "", ""
	}
	var rawArr []json.RawMessage
	if err := json.Unmarshal(raw, &rawArr); err != nil {
		return nil, false, "invalid_allowed_mcp_tools", `allowedMcpTools must be an array of exact "<slug>/<tool>" strings.`
	}
	if len(rawArr) > 128 {
		return nil, false, "invalid_allowed_mcp_tools", "allowedMcpTools exceeds maximum of 128 entries."
	}
	seen := make(map[string]bool, len(rawArr))
	out := make([]string, 0, len(rawArr))
	for _, itemRaw := range rawArr {
		var entry string
		if err := json.Unmarshal(itemRaw, &entry); err != nil || strings.TrimSpace(string(itemRaw)) == "null" {
			return nil, false, "invalid_allowed_mcp_tools", `Every allowedMcpTools entry must be a "<slug>/<tool>" string.`
		}
		t := strings.TrimSpace(entry)
		if t == "" || utf16Len(t) > 113 || strings.Contains(t, "*") || strings.Contains(t, "__") {
			return nil, false, "invalid_allowed_mcp_tools", fmt.Sprintf(
				`Invalid allowedMcpTools entry %q: wildcards and "__" are forbidden; expected exact "<slug>/<tool>".`, t,
			)
		}
		parts := strings.Split(t, "/")
		if len(parts) != 2 {
			return nil, false, "invalid_allowed_mcp_tools", fmt.Sprintf(
				`Invalid allowedMcpTools entry %q: expected exact "<slug>/<tool>" format.`, t,
			)
		}
		slug, tool := parts[0], parts[1]
		if !IsValidMCPConnectorSlug(slug) || !IsSafeMCPIdentifier(tool) {
			return nil, false, "invalid_allowed_mcp_tools", fmt.Sprintf(
				`Invalid allowedMcpTools entry %q: "<slug>" and "<tool>" must be safe MCP identifiers without "__".`, t,
			)
		}
		canon := slug + "/" + tool
		if !seen[canon] {
			seen[canon] = true
			out = append(out, canon)
		}
	}
	return out, true, "", ""
}

// IsCachedMCPToolPermitted enforces S6 readOnlyHint/destructiveHint gating unless explicitly allowlisted as "<slug>/<tool>".
func IsCachedMCPToolPermitted(serverSlug string, tool CachedMCPToolSchema, allowedSet map[string]bool) bool {
	cleanSlug := strings.ToLower(strings.TrimSpace(serverSlug))
	if !IsValidMCPConnectorSlug(cleanSlug) || !IsSafeMCPIdentifier(tool.Name) {
		return false
	}
	if tool.ReadOnlyHint != nil && *tool.ReadOnlyHint && (tool.DestructiveHint == nil || !*tool.DestructiveHint) {
		return true
	}
	return allowedSet[cleanSlug+"/"+tool.Name]
}

// ResolveCallerUserID resolves the isolated tenant user_id per the Pillar 1 shared interface contract.
func ResolveCallerUserID(userID, principal string) string {
	trimmedUID := strings.TrimSpace(userID)
	if trimmedUID != "" {
		s, _ := sliceUTF16(trimmedUID, 128)
		return s
	}
	rawPrincipal := strings.TrimSpace(principal)
	switch rawPrincipal {
	case "", "owner_token", "mcp_token", "api", "mcp", "client":
		return "owner"
	default:
		s, _ := sliceUTF16(rawPrincipal, 128)
		return s
	}
}

// ToPublicMCPServerSummary strips ciphertext and secretVersion for safe /admin and query_mcp exposure.
func ToPublicMCPServerSummary(row StoredMCPServerRow) PublicMCPServerSummary {
	domains := row.Domains
	if domains == nil {
		domains = []string{}
	}
	tools := row.CachedTools
	if tools == nil {
		tools = []CachedMCPToolSchema{}
	}
	authSum := row.AuthSummary
	if authSum.HeaderNames == nil {
		authSum.HeaderNames = []string{}
	}
	return PublicMCPServerSummary{
		ID:              row.ID,
		UserID:          row.UserID,
		Slug:            row.Slug,
		Name:            row.Name,
		RemoteURL:       row.RemoteURL,
		RemoteOrigin:    row.RemoteOrigin,
		Transport:       row.Transport,
		AuthType:        row.AuthType,
		AuthSummary:     authSum,
		Domains:         domains,
		AutoRouteScrape: row.AutoRouteScrape,
		Tools:           tools,
		ToolCount:       row.ToolCount,
		Enabled:         row.Enabled,
		LastVerifiedAt:  row.LastVerifiedAt,
		LastError:       row.LastError,
		CreatedAt:       row.CreatedAt,
		UpdatedAt:       row.UpdatedAt,
	}
}

func hasHeaderControlByte(s string) bool {
	for i := 0; i < len(s); i++ {
		b := s[i]
		if b <= 0x08 || (b >= 0x0a && b <= 0x1f) || b == 0x7f {
			return true
		}
	}
	return false
}

func stripLeadingBearerPrefix(s string) string {
	t := strings.TrimSpace(s)
	if len(t) >= 7 && strings.EqualFold(t[:6], "bearer") && (t[6] == ' ' || t[6] == '\t' || t[6] == '\r' || t[6] == '\n') {
		return strings.TrimSpace(t[6:])
	}
	return t
}

// SanitizeSecretHeadersInput validates custom secret headers and optional bearerToken against smuggling/hop-by-hop headers.
func SanitizeSecretHeadersInput(bearerToken *string, rawHeaders json.RawMessage, hasHeaders bool) (OrderedObject, bool, string) {
	cleaned := make(OrderedObject, 0, 4)
	seenLower := make(map[string]bool, 4)
	totalBytes := 0

	if bearerToken != nil && strings.TrimSpace(*bearerToken) != "" {
		tok := stripLeadingBearerPrefix(*bearerToken)
		if tok == "" || hasHeaderControlByte(tok) || utf16Len(tok) > 4096 {
			return nil, false, "Invalid Bearer token format or control characters"
		}
		authVal := "Bearer " + tok
		cleaned.Set("Authorization", authVal)
		seenLower["authorization"] = true
		totalBytes += len("Authorization") + utf16Len(authVal)
	}

	if hasHeaders {
		trimmedHdrs := strings.TrimSpace(string(rawHeaders))
		if trimmedHdrs != "" && trimmedHdrs != "null" {
			parsedAny, err := ParseOrderedJSON(rawHeaders, 8)
			if err != nil {
				return nil, false, "headers must be a JSON object mapping header names to string values"
			}
			hdrObj, isObj := parsedAny.(OrderedObject)
			if !isObj {
				return nil, false, "headers must be a JSON object mapping header names to string values"
			}
			if len(hdrObj) > 20 {
				return nil, false, "At most 20 custom headers are supported per MCP connector"
			}
			for _, entry := range hdrObj {
				rawKey := entry.Key
				if entry.Value == nil {
					continue
				}
				rawVal, isStr := entry.Value.(string)
				if !isStr {
					return nil, false, fmt.Sprintf("Header %q value must be a string", rawKey)
				}
				if rawVal == "" {
					continue
				}
				key := strings.TrimSpace(rawKey)
				if key == "" || !httpTokenHeaderRe.MatchString(key) {
					return nil, false, fmt.Sprintf("Invalid HTTP header name %q", rawKey)
				}
				lowerKey := strings.ToLower(key)
				if forbiddenSecretHeaderNames[lowerKey] {
					return nil, false, fmt.Sprintf("Disallowed reserved HTTP header %q", key)
				}
				val := strings.TrimSpace(rawVal)
				if val == "" {
					continue
				}
				if hasHeaderControlByte(val) || utf16Len(val) > 8192 {
					return nil, false, fmt.Sprintf("Header %q contains control characters or exceeds 8 KiB", key)
				}
				if seenLower[lowerKey] {
					return nil, false, fmt.Sprintf("Duplicate HTTP header %q (case-insensitive collision)", key)
				}
				totalBytes += utf16Len(key) + utf16Len(val)
				if totalBytes > maxSecretHeadersTotalBytes {
					return nil, false, "Combined custom headers exceed 32 KiB limit"
				}
				seenLower[lowerKey] = true
				cleaned = append(cleaned, OrderedEntry{Key: key, Value: val})
			}
		}
	}

	return cleaned, true, ""
}

// BuildMaskedAuthSummary builds a public MaskedAuthSummary without exposing secret values.
func BuildMaskedAuthSummary(payload VaultSecretPayload) MaskedAuthSummary {
	if payload.Kind == "oauth2" && payload.OAuth != nil {
		hasRefresh := payload.OAuth.RefreshToken != ""
		badge := "OAuth 2.1 PKCE"
		if hasRefresh {
			badge = "OAuth 2.1 PKCE (Auto-Refresh)"
		}
		out := MaskedAuthSummary{
			AuthMode:        "oauth2",
			HeaderNames:     []string{"Authorization"},
			MaskedBadge:     badge,
			HasRefreshToken: &hasRefresh,
		}
		if payload.OAuth.ExpiresAt != nil && *payload.OAuth.ExpiresAt != 0 {
			out.TokenExpiresAt = payload.OAuth.ExpiresAt
		}
		return out
	}

	names := make([]string, 0, len(payload.Headers))
	var authVal string
	hasAuth := false
	for _, entry := range payload.Headers {
		s, ok := entry.Value.(string)
		if !ok {
			continue
		}
		names = append(names, entry.Key)
		if !hasAuth && strings.EqualFold(entry.Key, "authorization") {
			hasAuth = true
			authVal = s
		}
	}
	if len(names) == 0 {
		return MaskedAuthSummary{
			AuthMode:    "none",
			HeaderNames: []string{},
			MaskedBadge: "Public (No Auth)",
		}
	}
	if hasAuth && len(names) == 1 && len(authVal) >= 7 && strings.EqualFold(authVal[:6], "bearer") && (authVal[6] == ' ' || authVal[6] == '\t') {
		return MaskedAuthSummary{
			AuthMode:    "bearer",
			HeaderNames: []string{"Authorization"},
			MaskedBadge: "AES-256-GCM \u2022 Bearer \u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022",
		}
	}
	return MaskedAuthSummary{
		AuthMode:    "headers",
		HeaderNames: names,
		MaskedBadge: fmt.Sprintf("AES-256-GCM \u2022 %s (\u2022\u2022\u2022\u2022)", strings.Join(names, ", ")),
	}
}

func filterSafeSchemaNode(rawNode any, depth int) OrderedObject {
	src, isObj := rawNode.(OrderedObject)
	if !isObj || depth > 6 {
		if depth == 0 {
			return OrderedObject{
				{Key: "type", Value: "object"},
				{Key: "properties", Value: OrderedObject{}},
			}
		}
		return OrderedObject{}
	}

	out := make(OrderedObject, 0, len(src)+1)
	for _, entry := range src {
		if forbiddenMCPIdentifiers[entry.Key] {
			continue
		}
		out = append(out, entry)
	}

	var validProps map[string]bool
	if rawProps, hasProps := src.Get("properties"); hasProps && rawProps != nil {
		if propsObj, ok := rawProps.(OrderedObject); ok {
			cleanProps := make(OrderedObject, 0, min(len(propsObj), 32))
			validProps = make(map[string]bool, min(len(propsObj), 32))
			limit := min(len(propsObj), 32)
			for i := 0; i < limit; i++ {
				cleanK := strings.TrimSpace(StripMCPSmugglingChars(propsObj[i].Key))
				if !IsSafeMCPIdentifier(cleanK) {
					continue
				}
				cleanProps.Set(cleanK, filterSafeSchemaNode(propsObj[i].Value, depth+1))
				validProps[cleanK] = true
			}
			out.Set("properties", cleanProps)
		} else if depth == 0 {
			out.Set("properties", OrderedObject{})
		}
	} else if depth == 0 {
		out.Set("properties", OrderedObject{})
	}

	if rawReq, hasReq := src.GetArray("required"); hasReq {
		cleanReq := make([]any, 0, len(rawReq))
		for _, item := range rawReq {
			rStr, ok := item.(string)
			if ok && IsSafeMCPIdentifier(rStr) && (validProps == nil || validProps[rStr]) {
				cleanReq = append(cleanReq, rStr)
			}
		}
		if len(cleanReq) > 0 {
			out.Set("required", cleanReq)
		} else {
			out.Delete("required")
		}
	}

	if rawItems, hasItems := src.Get("items"); hasItems && rawItems != nil {
		if itemsObj, ok := rawItems.(OrderedObject); ok {
			out.Set("items", filterSafeSchemaNode(itemsObj, depth+1))
		}
	}

	return out
}

// FilterSafeCachedMCPTools filters persisted cached_tools_json rows (<= 64 tools, safe names & schema keys).
func FilterSafeCachedMCPTools(rawTools json.RawMessage) []CachedMCPToolSchema {
	parsedAny, err := ParseOrderedJSON(rawTools, 32)
	if err != nil {
		return []CachedMCPToolSchema{}
	}
	arr, isArr := parsedAny.([]any)
	if !isArr {
		return []CachedMCPToolSchema{}
	}
	limit := min(len(arr), 64)
	out := make([]CachedMCPToolSchema, 0, limit)
	for i := 0; i < limit; i++ {
		obj, isObj := arr[i].(OrderedObject)
		if !isObj {
			continue
		}
		rawName, _ := obj.GetString("name")
		cleanName := strings.TrimSpace(StripMCPSmugglingChars(rawName))
		if !IsSafeMCPIdentifier(cleanName) {
			continue
		}
		rawSchema, _ := obj.Get("inputSchema")
		item := CachedMCPToolSchema{
			Name:        cleanName,
			InputSchema: filterSafeSchemaNode(rawSchema, 0),
		}
		if title, ok := obj.GetString("title"); ok && title != "" {
			item.Title = title
		}
		if desc, ok := obj.GetString("description"); ok && desc != "" {
			item.Description = desc
		}
		if ro, ok := obj.GetBool("readOnlyHint"); ok {
			roCopy := ro
			item.ReadOnlyHint = &roCopy
		}
		if dh, ok := obj.GetBool("destructiveHint"); ok {
			dhCopy := dh
			item.DestructiveHint = &dhCopy
		}
		out = append(out, item)
	}
	return out
}
