package main

import (
	"encoding/json"

	"github.com/bartrumb/edgefetch/v2/internal/mcpfed"
)

// handleHubPolicyRPC serves hub_secrets_* (admin-managed secret overrides) and access_policy_* (tool/route
// policy + MCP server shares) ops for hub/src/hub-secrets.ts and hub/src/access-policy.ts. Dispatched from
// handlePhase2McpRPC's default branch so reactor.go's hook list is untouched.
func handleHubPolicyRPC(op string, payload json.RawMessage) (any, bool, error) {
	switch op {
	case "hub_secrets_catalog":
		return map[string]any{
			"managed":       mcpfed.HubManagedSecretNames(),
			"bootstrap":     mcpfed.HubBootstrapSecretNames(),
			"urlNames":      mcpfed.HubSecretURLNames(),
			"plainConfig":   mcpfed.HubPlainConfigNames(),
			"maxValueBytes": mcpfed.MaxHubSecretValueBytes,
		}, true, nil

	case "hub_secrets_prepare_seal":
		var p struct {
			VaultMasterKey string `json:"vaultMasterKey"`
			Name           string `json:"name"`
			Value          string `json:"value"`
		}
		if err := json.Unmarshal(payload, &p); err != nil {
			return nil, true, err
		}
		return mcpfed.PrepareHubSecretSeal(p.VaultMasterKey, p.Name, p.Value), true, nil

	case "hub_secrets_prepare_unseal":
		var p struct {
			VaultMasterKey string `json:"vaultMasterKey"`
			Name           string `json:"name"`
			Ciphertext     string `json:"ciphertext"`
		}
		if err := json.Unmarshal(payload, &p); err != nil {
			return nil, true, err
		}
		return mcpfed.PrepareHubSecretUnseal(p.VaultMasterKey, p.Name, p.Ciphertext), true, nil

	case "hub_secrets_verify_unseal":
		var p struct {
			Name      string `json:"name"`
			Plaintext string `json:"plaintext"`
		}
		if err := json.Unmarshal(payload, &p); err != nil {
			return nil, true, err
		}
		value, ok := mcpfed.VerifyHubSecretPlaintext(p.Name, []byte(p.Plaintext))
		if !ok {
			return map[string]any{"ok": false}, true, nil
		}
		return map[string]any{"ok": true, "value": value}, true, nil

	case "hub_secrets_validate_name":
		var p struct {
			Name string `json:"name"`
		}
		if err := json.Unmarshal(payload, &p); err != nil {
			return nil, true, err
		}
		name, nErr := mcpfed.ValidateHubSecretName(p.Name)
		if nErr != nil {
			return map[string]any{"ok": false, "status": nErr.Status, "error": nErr.Error, "message": nErr.Message}, true, nil
		}
		return map[string]any{"ok": true, "name": name}, true, nil

	case "hub_secrets_build_status":
		var p struct {
			Env       []mcpfed.HubSecretEnvProbe     `json:"env"`
			Overrides []mcpfed.HubSecretOverrideMeta `json:"overrides"`
		}
		if err := json.Unmarshal(payload, &p); err != nil {
			return nil, true, err
		}
		return map[string]any{"secrets": mcpfed.BuildHubSecretStatus(p.Env, p.Overrides)}, true, nil

	case "access_policy_normalize_rule":
		var p struct {
			Rule mcpfed.AccessRule `json:"rule"`
		}
		if err := json.Unmarshal(payload, &p); err != nil {
			return nil, true, err
		}
		rule, rErr := mcpfed.NormalizeAccessRule(p.Rule)
		if rErr != nil {
			return map[string]any{"ok": false, "status": rErr.Status, "error": rErr.Error, "message": rErr.Message}, true, nil
		}
		return map[string]any{"ok": true, "rule": rule}, true, nil

	case "access_policy_normalize_share":
		var p struct {
			Share mcpfed.MCPServerShare `json:"share"`
		}
		if err := json.Unmarshal(payload, &p); err != nil {
			return nil, true, err
		}
		share, sErr := mcpfed.NormalizeMCPServerShare(p.Share)
		if sErr != nil {
			return map[string]any{"ok": false, "status": sErr.Status, "error": sErr.Error, "message": sErr.Message}, true, nil
		}
		return map[string]any{"ok": true, "share": share}, true, nil

	case "access_policy_normalize_route":
		var p struct {
			Path string `json:"path"`
		}
		if err := json.Unmarshal(payload, &p); err != nil {
			return nil, true, err
		}
		norm, ok := mcpfed.NormalizeAccessRoutePath(p.Path)
		return map[string]any{"ok": ok, "path": norm}, true, nil

	case "access_policy_evaluate":
		var p struct {
			Rules    []mcpfed.AccessRule `json:"rules"`
			Caller   mcpfed.AccessCaller `json:"caller"`
			Resource string              `json:"resource"`
		}
		if err := json.Unmarshal(payload, &p); err != nil {
			return nil, true, err
		}
		return mcpfed.EvaluateAccess(p.Rules, p.Caller, p.Resource), true, nil

	case "access_policy_filter_tools":
		var p struct {
			Rules  []mcpfed.AccessRule `json:"rules"`
			Caller mcpfed.AccessCaller `json:"caller"`
			Names  []string            `json:"names"`
		}
		if err := json.Unmarshal(payload, &p); err != nil {
			return nil, true, err
		}
		return map[string]any{"names": mcpfed.FilterAllowedToolNames(p.Rules, p.Caller, p.Names)}, true, nil

	case "access_policy_evaluate_share":
		var p struct {
			Rules        []mcpfed.AccessRule     `json:"rules"`
			Shares       []mcpfed.MCPServerShare `json:"shares"`
			CallerUserID string                  `json:"callerUserId"`
			OwnerUserID  string                  `json:"ownerUserId"`
			Slug         string                  `json:"slug"`
		}
		if err := json.Unmarshal(payload, &p); err != nil {
			return nil, true, err
		}
		return mcpfed.EvaluateSharedServerAccess(p.Rules, p.Shares, p.CallerUserID, p.OwnerUserID, p.Slug), true, nil

	case "access_policy_list_shared":
		var p struct {
			Rules        []mcpfed.AccessRule     `json:"rules"`
			Shares       []mcpfed.MCPServerShare `json:"shares"`
			CallerUserID string                  `json:"callerUserId"`
		}
		if err := json.Unmarshal(payload, &p); err != nil {
			return nil, true, err
		}
		return map[string]any{"servers": mcpfed.ListSharedServersFor(p.Rules, p.Shares, p.CallerUserID)}, true, nil

	case "access_policy_resolve_shared":
		var p struct {
			Rules        []mcpfed.AccessRule     `json:"rules"`
			Shares       []mcpfed.MCPServerShare `json:"shares"`
			CallerUserID string                  `json:"callerUserId"`
			Ref          string                  `json:"ref"`
		}
		if err := json.Unmarshal(payload, &p); err != nil {
			return nil, true, err
		}
		res, rErr := mcpfed.ResolveSharedServerRef(p.Rules, p.Shares, p.CallerUserID, p.Ref)
		if rErr != nil {
			return map[string]any{"ok": false, "status": rErr.Status, "error": rErr.Error, "message": rErr.Message}, true, nil
		}
		return map[string]any{"ok": true, "ownerUserId": res.OwnerUserID, "slug": res.Slug, "ref": res.Ref}, true, nil

	default:
		return nil, false, nil
	}
}
