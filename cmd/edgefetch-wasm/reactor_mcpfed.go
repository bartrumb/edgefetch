package main

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/bartrumb/edgefetch/v2/internal/mcpfed"
)

func init() {
	phase2McpRPC = handlePhase2McpRPC
	phase2McpRawRPC = handlePhase2McpRawRPC
}

func decodeOptionalVaultSecret(raw json.RawMessage) *mcpfed.VaultSecretPayload {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" || trimmed == "null" {
		return nil
	}
	parsedAny, err := mcpfed.ParseOrderedJSON(raw, 16)
	if err != nil {
		return nil
	}
	obj, ok := parsedAny.(mcpfed.OrderedObject)
	if !ok {
		return nil
	}
	sec, err := mcpfed.ParseVaultSecretPayloadObject(obj)
	if err != nil {
		return nil
	}
	return &sec
}

func handlePhase2McpRPC(op string, payload json.RawMessage) (any, bool, error) {
	switch op {
	case "mcp_vault_validate_master_key":
		var p struct {
			VaultMasterKey string `json:"vaultMasterKey"`
		}
		if err := json.Unmarshal(payload, &p); err != nil {
			return nil, true, err
		}
		clean, ok, msg := mcpfed.ValidateVaultMasterKey(p.VaultMasterKey)
		if !ok {
			return map[string]any{
				"ok":      false,
				"status":  503,
				"error":   "vault_master_key_unconfigured",
				"message": msg,
			}, true, nil
		}
		return map[string]any{"ok": true, "key": clean}, true, nil

	case "mcp_vault_seal_credentials":
		var p struct {
			VaultMasterKey string               `json:"vaultMasterKey"`
			UserID         string               `json:"userId"`
			RemoteOrigin   string               `json:"remoteOrigin"`
			ID             *string              `json:"id"`
			ServerID       *string              `json:"serverId"`
			Slug           *string              `json:"slug"`
			AuthType       *string              `json:"authType"`
			Payload        mcpfed.OrderedObject `json:"payload"`
		}
		if err := json.Unmarshal(payload, &p); err != nil {
			return nil, true, err
		}
		return mcpfed.SealVaultCredentials(mcpfed.SealVaultParams{
			VaultMasterKey: p.VaultMasterKey,
			UserID:         p.UserID,
			RemoteOrigin:   p.RemoteOrigin,
			ID:             p.ID,
			ServerID:       p.ServerID,
			Slug:           p.Slug,
			AuthType:       p.AuthType,
			Payload:        p.Payload,
		}), true, nil

	case "mcp_vault_unseal_credentials":
		var p struct {
			VaultMasterKey string  `json:"vaultMasterKey"`
			UserID         string  `json:"userId"`
			RemoteOrigin   string  `json:"remoteOrigin"`
			RemoteURL      string  `json:"remoteUrl"`
			ID             *string `json:"id"`
			ServerID       *string `json:"serverId"`
			Slug           *string `json:"slug"`
			AuthType       *string `json:"authType"`
			SecretVersion  *int    `json:"secretVersion"`
			Ciphertext     string  `json:"ciphertext"`
		}
		if err := json.Unmarshal(payload, &p); err != nil {
			return nil, true, err
		}
		return mcpfed.UnsealVaultCredentials(mcpfed.UnsealVaultParams{
			VaultMasterKey: p.VaultMasterKey,
			UserID:         p.UserID,
			RemoteOrigin:   p.RemoteOrigin,
			RemoteURL:      p.RemoteURL,
			ID:             p.ID,
			ServerID:       p.ServerID,
			Slug:           p.Slug,
			AuthType:       p.AuthType,
			SecretVersion:  p.SecretVersion,
			Ciphertext:     p.Ciphertext,
		}), true, nil

	case "mcp_vault_seal_pkce":
		var p struct {
			VaultMasterKey string               `json:"vaultMasterKey"`
			UserID         string               `json:"userId"`
			RemoteOrigin   string               `json:"remoteOrigin"`
			Blob           mcpfed.OrderedObject `json:"blob"`
		}
		if err := json.Unmarshal(payload, &p); err != nil {
			return nil, true, err
		}
		ct, err := mcpfed.SealPKCEStateBlob(p.VaultMasterKey, p.UserID, p.RemoteOrigin, p.Blob)
		if err != nil {
			return nil, true, err
		}
		return map[string]any{"ok": true, "ciphertext": ct}, true, nil

	case "mcp_vault_unseal_pkce":
		var p struct {
			VaultMasterKey string `json:"vaultMasterKey"`
			UserID         string `json:"userId"`
			RemoteOrigin   string `json:"remoteOrigin"`
			Ciphertext     string `json:"ciphertext"`
		}
		if err := json.Unmarshal(payload, &p); err != nil {
			return nil, true, err
		}
		blob, ok := mcpfed.UnsealPKCEStateBlob(p.VaultMasterKey, p.UserID, p.RemoteOrigin, p.Ciphertext)
		if !ok {
			return map[string]any{"ok": false}, true, nil
		}
		return map[string]any{"ok": true, "blob": blob}, true, nil

	case "mcp_vault_oauth_bind_hmac":
		var p struct {
			VaultMasterKey  string  `json:"vaultMasterKey"`
			UserID          string  `json:"userId"`
			State           string  `json:"state"`
			SessionCSRF     string  `json:"sessionCsrf"`
			VerifyPresented *string `json:"verifyPresented"`
		}
		if err := json.Unmarshal(payload, &p); err != nil {
			return nil, true, err
		}
		sig := mcpfed.ComputeMCPOAuthBindHMAC(p.VaultMasterKey, p.UserID, p.State, p.SessionCSRF)
		out := map[string]any{"ok": true, "hmac": sig, "stateHash": mcpfed.SHA256Base64URL(p.State)}
		if p.VerifyPresented != nil {
			out["matched"] = mcpfed.VerifyMCPOAuthBindHMAC(*p.VerifyPresented, p.VaultMasterKey, p.UserID, p.State, p.SessionCSRF)
		}
		return out, true, nil

	case "mcp_vault_oauth_pkce_init":
		var p struct {
			VaultMasterKey        string   `json:"vaultMasterKey"`
			UserID                string   `json:"userId"`
			SessionCSRF           string   `json:"sessionCsrf"`
			RemoteOrigin          string   `json:"remoteOrigin"`
			AuthorizationEndpoint string   `json:"authorizationEndpoint"`
			TokenEndpoint         string   `json:"tokenEndpoint"`
			ClientID              string   `json:"clientId"`
			ClientSecret          string   `json:"clientSecret"`
			RedirectURI           string   `json:"redirectUri"`
			Scope                 string   `json:"scope"`
			ScopesSupported       []string `json:"scopesSupported"`
			Resource              string   `json:"resource"`
			ConfirmedAuthOrigin   string   `json:"confirmedAuthOrigin"`
			Issuer                string   `json:"issuer"`
		}
		if err := json.Unmarshal(payload, &p); err != nil {
			return nil, true, err
		}
		codeVerifier, err := mcpfed.RandomBase64URL(32)
		if err != nil {
			return nil, true, err
		}
		codeChallenge := mcpfed.SHA256Base64URL(codeVerifier)
		state, err := mcpfed.RandomBase64URL(32)
		if err != nil {
			return nil, true, err
		}
		stateHash := mcpfed.SHA256Base64URL(state)
		bindCookieVal := mcpfed.ComputeMCPOAuthBindHMAC(p.VaultMasterKey, p.UserID, state, p.SessionCSRF)

		blob := mcpfed.OrderedObject{
			{Key: "codeVerifier", Value: codeVerifier},
		}
		if p.Issuer != "" {
			blob.Set("issuer", p.Issuer)
		}
		blob.Set("tokenEndpoint", p.TokenEndpoint)
		if p.ConfirmedAuthOrigin != "" {
			blob.Set("confirmedAuthOrigin", p.ConfirmedAuthOrigin)
		}
		blob.Set("clientId", p.ClientID)
		if p.ClientSecret != "" {
			blob.Set("clientSecret", p.ClientSecret)
		}
		blob.Set("redirectUri", p.RedirectURI)
		blob.Set("resource", p.Resource)

		encryptedPkceBlob, err := mcpfed.SealPKCEStateBlob(p.VaultMasterKey, p.UserID, p.RemoteOrigin, blob)
		if err != nil {
			return nil, true, err
		}

		authURL, err := url.Parse(p.AuthorizationEndpoint)
		if err != nil {
			return nil, true, err
		}
		q := authURL.Query()
		q.Set("response_type", "code")
		q.Set("client_id", p.ClientID)
		q.Set("redirect_uri", p.RedirectURI)
		q.Set("code_challenge", codeChallenge)
		q.Set("code_challenge_method", "S256")
		q.Set("state", state)
		effectiveScope := strings.TrimSpace(p.Scope)
		if effectiveScope == "" && len(p.ScopesSupported) > 0 {
			effectiveScope = strings.Join(p.ScopesSupported, " ")
		}
		if effectiveScope != "" {
			q.Set("scope", effectiveScope)
		}
		q.Set("resource", p.Resource)
		authURL.RawQuery = q.Encode()

		return map[string]any{
			"ok":                true,
			"authorizationUrl":  authURL.String(),
			"bindCookieValue":   bindCookieVal,
			"stateHash":         stateHash,
			"encryptedPkceBlob": encryptedPkceBlob,
		}, true, nil

	case "mcp_vault_is_safe_id":
		var p struct {
			Raw string `json:"raw"`
		}
		if err := json.Unmarshal(payload, &p); err != nil {
			return nil, true, err
		}
		return map[string]any{"ok": mcpfed.IsSafeMCPIdentifier(p.Raw)}, true, nil

	case "mcp_vault_is_valid_slug":
		var p struct {
			Raw string `json:"raw"`
		}
		if err := json.Unmarshal(payload, &p); err != nil {
			return nil, true, err
		}
		return map[string]any{"ok": mcpfed.IsValidMCPConnectorSlug(p.Raw)}, true, nil

	case "mcp_vault_normalize_slug":
		var p struct {
			RawName string `json:"rawName"`
		}
		if err := json.Unmarshal(payload, &p); err != nil {
			return nil, true, err
		}
		return map[string]any{"slug": mcpfed.NormalizeMCPConnectorSlug(p.RawName)}, true, nil

	case "mcp_vault_parse_allowed_tools":
		var p struct {
			Raw json.RawMessage `json:"raw"`
		}
		if err := json.Unmarshal(payload, &p); err != nil {
			return nil, true, err
		}
		allowed, ok, errCode, msg := mcpfed.ParseAllowedMCPTools(p.Raw)
		if !ok {
			return map[string]any{"ok": false, "error": errCode, "message": msg}, true, nil
		}
		return map[string]any{"ok": true, "allowed": allowed}, true, nil

	case "mcp_vault_is_tool_permitted":
		var p struct {
			ServerSlug string                     `json:"serverSlug"`
			Tool       mcpfed.CachedMCPToolSchema `json:"tool"`
			Allowed    []string                   `json:"allowed"`
		}
		if err := json.Unmarshal(payload, &p); err != nil {
			return nil, true, err
		}
		allowedSet := make(map[string]bool, len(p.Allowed))
		for _, a := range p.Allowed {
			allowedSet[a] = true
		}
		return map[string]any{"permitted": mcpfed.IsCachedMCPToolPermitted(p.ServerSlug, p.Tool, allowedSet)}, true, nil

	case "mcp_vault_resolve_user_id":
		var p struct {
			UserID    string `json:"userId"`
			Principal string `json:"principal"`
		}
		if err := json.Unmarshal(payload, &p); err != nil {
			return nil, true, err
		}
		return map[string]any{"userId": mcpfed.ResolveCallerUserID(p.UserID, p.Principal)}, true, nil

	case "mcp_vault_public_summary":
		var p struct {
			Row mcpfed.StoredMCPServerRow `json:"row"`
		}
		if err := json.Unmarshal(payload, &p); err != nil {
			return nil, true, err
		}
		return map[string]any{"summary": mcpfed.ToPublicMCPServerSummary(p.Row)}, true, nil

	case "mcp_vault_sanitize_headers":
		var p struct {
			BearerToken *string         `json:"bearerToken"`
			Headers     json.RawMessage `json:"headers"`
			HasHeaders  bool            `json:"hasHeaders"`
		}
		if err := json.Unmarshal(payload, &p); err != nil {
			return nil, true, err
		}
		hdrs, ok, errMsg := mcpfed.SanitizeSecretHeadersInput(p.BearerToken, p.Headers, p.HasHeaders)
		if !ok {
			return map[string]any{"ok": false, "error": errMsg}, true, nil
		}
		return map[string]any{"ok": true, "headers": hdrs}, true, nil

	case "mcp_vault_masked_auth_summary":
		var p struct {
			Payload json.RawMessage `json:"payload"`
		}
		if err := json.Unmarshal(payload, &p); err != nil {
			return nil, true, err
		}
		sec := decodeOptionalVaultSecret(p.Payload)
		var val mcpfed.VaultSecretPayload
		if sec != nil {
			val = *sec
		}
		return map[string]any{"summary": mcpfed.BuildMaskedAuthSummary(val)}, true, nil

	case "mcp_vault_filter_cached_tools":
		var p struct {
			Tools json.RawMessage `json:"tools"`
		}
		if err := json.Unmarshal(payload, &p); err != nil {
			return nil, true, err
		}
		return map[string]any{"tools": mcpfed.FilterSafeCachedMCPTools(p.Tools)}, true, nil

	case "mcp_vault_oauth_prepare_probe":
		var p struct {
			RemoteURL           string `json:"remoteUrl"`
			ConfirmedAuthOrigin string `json:"confirmedAuthOrigin"`
			SelfHost            string `json:"selfHost"`
		}
		if err := json.Unmarshal(payload, &p); err != nil {
			return nil, true, err
		}
		return map[string]any{"plan": mcpfed.PrepareOAuthProbe(p.RemoteURL, p.ConfirmedAuthOrigin, p.SelfHost)}, true, nil

	case "mcp_vault_oauth_validate_prm":
		var p struct {
			PRM                 json.RawMessage `json:"prm"`
			RemoteURL           string          `json:"remoteUrl"`
			ConfirmedAuthOrigin string          `json:"confirmedAuthOrigin"`
			SelfHost            string          `json:"selfHost"`
		}
		if err := json.Unmarshal(payload, &p); err != nil {
			return nil, true, err
		}
		return map[string]any{
			"result": mcpfed.ValidateOAuthProtectedResource(p.PRM, p.RemoteURL, p.ConfirmedAuthOrigin, p.SelfHost),
		}, true, nil

	case "mcp_vault_oauth_validate_asm":
		var p struct {
			ASM               json.RawMessage `json:"asm"`
			ExpectedIssuerURL string          `json:"expectedIssuerUrl"`
			AllowedAuthOrigin string          `json:"allowedAuthOrigin"`
			ConnectorOrigin   string          `json:"connectorOrigin"`
			ResourceURI       string          `json:"resourceUri"`
			PRScopes          []string        `json:"prScopes"`
			SelfHost          string          `json:"selfHost"`
		}
		if err := json.Unmarshal(payload, &p); err != nil {
			return nil, true, err
		}
		meta, abort := mcpfed.ValidateOAuthAuthorizationServer(
			p.ASM, p.ExpectedIssuerURL, p.AllowedAuthOrigin, p.ConnectorOrigin, p.ResourceURI, p.PRScopes, p.SelfHost,
		)
		return map[string]any{"meta": meta, "abort": abort}, true, nil

	case "mcp_vault_oauth_validate_token_ep":
		var p struct {
			TokenEndpoint       string `json:"tokenEndpoint"`
			ExpectedIssuer      string `json:"expectedIssuer"`
			ConfirmedAuthOrigin string `json:"confirmedAuthOrigin"`
			RemoteOrigin        string `json:"remoteOrigin"`
			SelfHost            string `json:"selfHost"`
		}
		if err := json.Unmarshal(payload, &p); err != nil {
			return nil, true, err
		}
		return mcpfed.ValidateOAuthTokenEndpoint(
			p.TokenEndpoint, p.ExpectedIssuer, p.ConfirmedAuthOrigin, p.RemoteOrigin, p.SelfHost,
		), true, nil

	case "mcp_fed_neutralize_boundary_tags":
		var p struct {
			Input string `json:"input"`
		}
		if err := json.Unmarshal(payload, &p); err != nil {
			return nil, true, err
		}
		return map[string]any{"out": mcpfed.NeutralizeUntrustedMCPBoundaryTags(p.Input)}, true, nil

	case "mcp_fed_format_envelope":
		var p struct {
			Tag        string               `json:"tag"`
			Attributes mcpfed.OrderedObject `json:"attributes"`
			Content    string               `json:"content"`
			MaxChars   int                  `json:"maxChars"`
		}
		if err := json.Unmarshal(payload, &p); err != nil {
			return nil, true, err
		}
		return map[string]any{
			"out": mcpfed.FormatFenceSafeUntrustedMCPEnvelope(p.Tag, p.Attributes, p.Content, p.MaxChars),
		}, true, nil

	case "mcp_fed_rebuild_schema":
		var p struct {
			RawNode json.RawMessage `json:"rawNode"`
			Depth   int             `json:"depth"`
		}
		if err := json.Unmarshal(payload, &p); err != nil {
			return nil, true, err
		}
		var nodeAny any
		if len(strings.TrimSpace(string(p.RawNode))) > 0 {
			nodeAny, _ = mcpfed.ParseOrderedJSON(p.RawNode, 16)
		}
		schema, scrubbed := mcpfed.RebuildSafeMCPInputSchema(nodeAny, p.Depth)
		return map[string]any{"schema": schema, "scrubbed": scrubbed}, true, nil

	case "mcp_fed_extract_markdown":
		var p struct {
			Body json.RawMessage `json:"body"`
		}
		if err := json.Unmarshal(payload, &p); err != nil {
			return nil, true, err
		}
		return map[string]any{"markdown": mcpfed.ExtractMarkdownFromQueryMCPBody(p.Body)}, true, nil

	case "mcp_fed_match_context":
		var p struct {
			Servers []mcpfed.StoredMCPServerRow `json:"servers"`
			Query   string                      `json:"query"`
			URLs    []string                    `json:"urls"`
		}
		if err := json.Unmarshal(payload, &p); err != nil {
			return nil, true, err
		}
		return map[string]any{"matches": mcpfed.MatchConnectedMCPsForContext(p.Servers, p.Query, p.URLs)}, true, nil

	case "mcp_fed_select_scrape_tool":
		var p struct {
			Servers                     []mcpfed.StoredMCPServerRow `json:"servers"`
			TargetURL                   string                      `json:"targetUrl"`
			Query                       string                      `json:"query"`
			PreferMCP                   bool                        `json:"preferMcp"`
			HasAllowedServerIDs         bool                        `json:"hasAllowedServerIds"`
			AllowedServerIDs            []string                    `json:"allowedServerIds"`
			AllowedTools                []string                    `json:"allowedTools"`
			RequireExplicitReadOnlyHint bool                        `json:"requireExplicitReadOnlyHint"`
			SelfHost                    string                      `json:"selfHost"`
		}
		if err := json.Unmarshal(payload, &p); err != nil {
			return nil, true, err
		}
		srvSet := make(map[string]bool, len(p.AllowedServerIDs))
		for _, id := range p.AllowedServerIDs {
			srvSet[id] = true
		}
		toolSet := make(map[string]bool, len(p.AllowedTools))
		for _, t := range p.AllowedTools {
			toolSet[t] = true
		}
		plan := mcpfed.SelectScrapeMCPCandidate(
			p.Servers, p.TargetURL, p.Query, p.PreferMCP,
			p.HasAllowedServerIDs, srvSet, toolSet, p.RequireExplicitReadOnlyHint, p.SelfHost,
		)
		return map[string]any{"plan": plan}, true, nil

	case "mcp_fed_build_outbound_headers":
		var p struct {
			Secret       json.RawMessage `json:"secret"`
			TargetOrigin string          `json:"targetOrigin"`
			SessionID    string          `json:"sessionId"`
		}
		if err := json.Unmarshal(payload, &p); err != nil {
			return nil, true, err
		}
		hdrs, ok, errMsg := mcpfed.BuildPinnedOutboundHeaders(decodeOptionalVaultSecret(p.Secret), p.TargetOrigin, p.SessionID)
		if !ok {
			return map[string]any{"ok": false, "error": errMsg}, true, nil
		}
		return map[string]any{"ok": true, "headers": hdrs}, true, nil

	case "mcp_fed_redact_secrets":
		var p struct {
			Raw    string          `json:"raw"`
			Secret json.RawMessage `json:"secret"`
		}
		if err := json.Unmarshal(payload, &p); err != nil {
			return nil, true, err
		}
		return map[string]any{"out": mcpfed.RedactVaultSecretsFromText(p.Raw, decodeOptionalVaultSecret(p.Secret))}, true, nil

	case "mcp_reg_strip_smuggling":
		var p struct {
			Text string `json:"text"`
		}
		if err := json.Unmarshal(payload, &p); err != nil {
			return nil, true, err
		}
		return map[string]any{"out": mcpfed.StripMCPSmugglingChars(p.Text)}, true, nil

	case "mcp_reg_check_https_url":
		var p struct {
			RawURL   string `json:"rawUrl"`
			SelfHost string `json:"selfHost"`
		}
		if err := json.Unmarshal(payload, &p); err != nil {
			return nil, true, err
		}
		return mcpfed.IsSafePublicHTTPSURL(p.RawURL, p.SelfHost), true, nil

	case "mcp_reg_sanitize_manifest_str":
		var p struct {
			Raw    string `json:"raw"`
			MaxLen int    `json:"maxLen"`
		}
		if err := json.Unmarshal(payload, &p); err != nil {
			return nil, true, err
		}
		return map[string]any{"out": mcpfed.SanitizeManifestString(p.Raw, p.MaxLen)}, true, nil

	case "mcp_reg_slugify":
		var p struct {
			RawName string `json:"rawName"`
		}
		if err := json.Unmarshal(payload, &p); err != nil {
			return nil, true, err
		}
		return map[string]any{"slug": mcpfed.SlugifyMCPServerName(p.RawName)}, true, nil

	case "mcp_reg_is_shared_hosting":
		var p struct {
			Hostname string `json:"hostname"`
		}
		if err := json.Unmarshal(payload, &p); err != nil {
			return nil, true, err
		}
		return map[string]any{"shared": mcpfed.IsSharedHostingHostname(p.Hostname)}, true, nil

	case "mcp_reg_registrable_domain":
		var p struct {
			Hostname string `json:"hostname"`
		}
		if err := json.Unmarshal(payload, &p); err != nil {
			return nil, true, err
		}
		return map[string]any{"domain": mcpfed.ExtractRegistrableDomain(p.Hostname)}, true, nil

	case "mcp_reg_validate_domains":
		var p struct {
			RawDomains            json.RawMessage `json:"rawDomains"`
			RemoteOrigin          string          `json:"remoteOrigin"`
			AllowUnrelatedDomains bool            `json:"allowUnrelatedDomains"`
		}
		if err := json.Unmarshal(payload, &p); err != nil {
			return nil, true, err
		}
		doms, ok, errMsg := mcpfed.ValidateConnectorDomains(p.RawDomains, p.RemoteOrigin, p.AllowUnrelatedDomains)
		if !ok {
			return map[string]any{"ok": false, "error": errMsg}, true, nil
		}
		return map[string]any{"ok": true, "domains": doms}, true, nil

	case "mcp_reg_infer_domains":
		return map[string]any{"domains": mcpfed.InferAssociatedDomains()}, true, nil

	case "mcp_reg_fuse":
		var p struct {
			Official []mcpfed.NormalizedMCPRegistryEntry `json:"official"`
			Glama    []mcpfed.NormalizedMCPRegistryEntry `json:"glama"`
		}
		if err := json.Unmarshal(payload, &p); err != nil {
			return nil, true, err
		}
		return map[string]any{"entries": mcpfed.FuseRegistryEntries(p.Official, p.Glama)}, true, nil

	default:
		return nil, false, nil
	}
}

func handlePhase2McpRawRPC(op string, meta json.RawMessage, rawStr string) (any, bool, error) {
	switch op {
	case "mcp_fed_sanitize_markdown":
		var m struct {
			BaseURL  string `json:"baseUrl"`
			MaxChars int    `json:"maxChars"`
		}
		if len(meta) > 0 {
			_ = json.Unmarshal(meta, &m)
		}
		return map[string]any{"out": mcpfed.SanitizeMCPMarkdownOutput(rawStr, m.BaseURL, m.MaxChars)}, true, nil

	case "mcp_fed_sanitize_remote_text":
		var m struct {
			MaxChars int `json:"maxChars"`
		}
		if len(meta) > 0 {
			_ = json.Unmarshal(meta, &m)
		}
		return mcpfed.SanitizeRemoteMCPText(rawStr, m.MaxChars), true, nil

	case "mcp_fed_sanitize_connector_text":
		var m struct {
			MaxChars     int             `json:"maxChars"`
			BaseURL      string          `json:"baseUrl"`
			ApplyRedact  bool            `json:"applyRedact"`
			RedactSecret json.RawMessage `json:"redactSecret"`
		}
		if len(meta) > 0 {
			_ = json.Unmarshal(meta, &m)
		}
		return mcpfed.SanitizeConnectorText(
			rawStr, m.MaxChars, m.BaseURL, m.ApplyRedact, decodeOptionalVaultSecret(m.RedactSecret),
		), true, nil

	case "mcp_fed_measure_json_size":
		var m struct {
			MaxBytes int `json:"maxBytes"`
		}
		if len(meta) > 0 {
			_ = json.Unmarshal(meta, &m)
		}
		parsedAny, err := mcpfed.ParseOrderedJSON([]byte(rawStr), 64)
		if err != nil {
			return map[string]any{"size": m.MaxBytes + 1}, true, nil
		}
		return map[string]any{"size": mcpfed.MeasureOrderedJSONSizeCapped(parsedAny, m.MaxBytes)}, true, nil

	case "mcp_fed_sanitize_structured":
		var m struct {
			BaseURL                string          `json:"baseUrl"`
			ApplyRedact            bool            `json:"applyRedact"`
			RedactSecret           json.RawMessage `json:"redactSecret"`
			MaxDepth               int             `json:"maxDepth"`
			MaxEntriesPerContainer int             `json:"maxEntriesPerContainer"`
			MaxNodeBudget          int             `json:"maxNodeBudget"`
			MaxStringChars         int             `json:"maxStringChars"`
			MaxTotalChars          *int            `json:"maxTotalChars"`
		}
		if len(meta) > 0 {
			_ = json.Unmarshal(meta, &m)
		}
		parsedAny, err := mcpfed.ParseOrderedJSON([]byte(rawStr), 128)
		if err != nil {
			return mcpfed.SanitizedConnectorStructuredResult{
				Value:          "[truncated]",
				Sanitized:      true,
				FullySanitized: false,
				Truncated:      true,
				Triggers:       []string{},
			}, true, nil
		}
		return mcpfed.SanitizeConnectorStructuredValue(parsedAny, mcpfed.StructuredSanitizeOptions{
			BaseURL:                m.BaseURL,
			ApplyRedact:            m.ApplyRedact,
			RedactSecret:           decodeOptionalVaultSecret(m.RedactSecret),
			MaxDepth:               m.MaxDepth,
			MaxEntriesPerContainer: m.MaxEntriesPerContainer,
			MaxNodeBudget:          m.MaxNodeBudget,
			MaxStringChars:         m.MaxStringChars,
			MaxTotalChars:          m.MaxTotalChars,
		}), true, nil

	case "mcp_fed_sanitize_tool_defs":
		return mcpfed.SanitizeRemoteMCPToolDefs([]byte(rawStr)), true, nil

	case "mcp_fed_parse_sse_rpc":
		var m struct {
			ExpectedID mcpfed.RPCID `json:"expectedId"`
		}
		if len(meta) > 0 {
			_ = json.Unmarshal(meta, &m)
		}
		rpc, ok := mcpfed.ParseSSEJSONRPCResponse(rawStr, m.ExpectedID)
		if !ok {
			return map[string]any{"rpc": nil}, true, nil
		}
		return map[string]any{"rpc": rpc}, true, nil

	case "mcp_fed_parse_remote_rpc":
		var m struct {
			ContentType string       `json:"contentType"`
			ExpectedID  mcpfed.RPCID `json:"expectedId"`
		}
		if len(meta) > 0 {
			_ = json.Unmarshal(meta, &m)
		}
		rpc, depthExceeded, found := mcpfed.ParseRemoteJSONRPCBody(rawStr, m.ContentType, m.ExpectedID)
		out := map[string]any{
			"found":         found,
			"depthExceeded": depthExceeded,
		}
		if found {
			out["rpc"] = rpc
		}
		return out, true, nil

	case "mcp_fed_parse_and_sanitize_call_result":
		var m struct {
			ContentType       string          `json:"contentType"`
			ExpectedID        mcpfed.RPCID    `json:"expectedId"`
			AllowSessionRetry bool            `json:"allowSessionRetry"`
			ServerSlug        string          `json:"serverSlug"`
			ServerName        string          `json:"serverName"`
			RemoteOrigin      string          `json:"remoteOrigin"`
			ToolName          string          `json:"toolName"`
			SanitizeBaseURL   string          `json:"sanitizeBaseUrl"`
			SelfHost          string          `json:"selfHost"`
			TokenRefreshed    bool            `json:"tokenRefreshed"`
			ActiveSecret      json.RawMessage `json:"activeSecret"`
		}
		if err := json.Unmarshal(meta, &m); err != nil {
			return nil, true, err
		}
		rpc, depthExceeded, found := mcpfed.ParseRemoteJSONRPCBody(rawStr, m.ContentType, m.ExpectedID)
		if depthExceeded || !found {
			return map[string]any{"found": found, "depthExceeded": depthExceeded}, true, nil
		}
		if m.AllowSessionRetry {
			if errObj, hasErr := rpc.GetObject("error"); hasErr {
				if msg, okM := errObj.GetString("message"); okM {
					low := strings.ToLower(msg)
					if strings.Contains(low, "session") || (strings.Contains(low, "not") && strings.Contains(low, "initialized")) {
						return map[string]any{"found": true, "needsSessionInit": true}, true, nil
					}
				}
			}
		}
		status, body := mcpfed.SanitizeCallToolRPCResponse(
			rpc, m.ServerSlug, m.ServerName, m.RemoteOrigin, m.ToolName,
			m.SanitizeBaseURL, m.SelfHost, m.TokenRefreshed, decodeOptionalVaultSecret(m.ActiveSecret),
		)
		return map[string]any{"found": true, "status": status, "body": body}, true, nil

	case "mcp_fed_sanitize_call_result":
		var m struct {
			ServerSlug      string          `json:"serverSlug"`
			ServerName      string          `json:"serverName"`
			RemoteOrigin    string          `json:"remoteOrigin"`
			ToolName        string          `json:"toolName"`
			SanitizeBaseURL string          `json:"sanitizeBaseUrl"`
			SelfHost        string          `json:"selfHost"`
			TokenRefreshed  bool            `json:"tokenRefreshed"`
			ActiveSecret    json.RawMessage `json:"activeSecret"`
		}
		if err := json.Unmarshal(meta, &m); err != nil {
			return nil, true, err
		}
		parsedAny, err := mcpfed.ParseOrderedJSON([]byte(rawStr), 64)
		if err != nil {
			return nil, true, fmt.Errorf("invalid rpc JSON: %w", err)
		}
		rpcObj, isObj := parsedAny.(mcpfed.OrderedObject)
		if !isObj {
			return nil, true, fmt.Errorf("expected rpc JSON object")
		}
		status, body := mcpfed.SanitizeCallToolRPCResponse(
			rpcObj, m.ServerSlug, m.ServerName, m.RemoteOrigin, m.ToolName,
			m.SanitizeBaseURL, m.SelfHost, m.TokenRefreshed, decodeOptionalVaultSecret(m.ActiveSecret),
		)
		return map[string]any{"status": status, "body": body}, true, nil

	case "mcp_reg_json_depth":
		var m struct {
			MaxDepth int `json:"maxDepth"`
		}
		if len(meta) > 0 {
			_ = json.Unmarshal(meta, &m)
		}
		return map[string]any{"withinLimit": mcpfed.IsJSONDepthWithinLimit(rawStr, m.MaxDepth)}, true, nil

	case "mcp_reg_parse_official":
		var m struct {
			SelfHost string `json:"selfHost"`
		}
		if len(meta) > 0 {
			_ = json.Unmarshal(meta, &m)
		}
		entries, err := mcpfed.ParseOfficialRegistryPayload(json.RawMessage(rawStr), m.SelfHost)
		if err != nil {
			return nil, true, err
		}
		return map[string]any{"entries": entries}, true, nil

	case "mcp_reg_parse_glama":
		var m struct {
			SelfHost string `json:"selfHost"`
		}
		if len(meta) > 0 {
			_ = json.Unmarshal(meta, &m)
		}
		entries, err := mcpfed.ParseGlamaRegistryPayload(json.RawMessage(rawStr), m.SelfHost)
		if err != nil {
			return nil, true, err
		}
		return map[string]any{"entries": entries}, true, nil

	default:
		return nil, false, nil
	}
}
