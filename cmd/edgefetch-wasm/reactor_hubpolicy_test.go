package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func callHubPolicyOp(t *testing.T, op string, payload any) map[string]any {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"op": op, "payload": payload})
	if err != nil {
		t.Fatal(err)
	}
	_ = efInPtr(uint32(len(raw)))
	copy(wasmInBuf, raw)
	n := efCall(uint32(len(raw)))
	var out map[string]any
	if err := json.Unmarshal(wasmOutBuf[:n], &out); err != nil {
		t.Fatalf("%s: bad json %q", op, string(wasmOutBuf[:n]))
	}
	return out
}

const hubPolicyTestKey = "ef_hub_secrets_master_key_32chars_minimum"

func TestHubSecretsWasmOps(t *testing.T) {
	cat := callHubPolicyOp(t, "hub_secrets_catalog", map[string]any{})
	if m, _ := cat["managed"].([]any); len(m) < 20 {
		t.Fatalf("catalog %+v", cat)
	}
	seal := callHubPolicyOp(t, "hub_secrets_prepare_seal", map[string]any{"vaultMasterKey": hubPolicyTestKey, "name": "SERPER_API_KEY", "value": " v "})
	if seal["ok"] != true || seal["aad"] != "hs1|hub_secrets:value|3:hub|14:SERPER_API_KEY" || seal["normalizedValue"] != "v" {
		t.Fatalf("seal %+v", seal)
	}
	if bad := callHubPolicyOp(t, "hub_secrets_prepare_seal", map[string]any{"vaultMasterKey": hubPolicyTestKey, "name": "CALLER_TOKEN", "value": "x"}); bad["ok"] == true || bad["error"] != "bootstrap_secret_readonly" {
		t.Fatalf("bootstrap %+v", bad)
	}
	if bad := callHubPolicyOp(t, "hub_secrets_prepare_seal", map[string]any{"vaultMasterKey": "", "name": "SERPER_API_KEY", "value": "x"}); bad["error"] != "vault_master_key_unconfigured" {
		t.Fatalf("no key %+v", bad)
	}
	ver := callHubPolicyOp(t, "hub_secrets_verify_unseal", map[string]any{"name": "SERPER_API_KEY", "plaintext": seal["plaintext"]})
	if ver["ok"] != true || ver["value"] != "v" {
		t.Fatalf("verify %+v", ver)
	}
	if ver := callHubPolicyOp(t, "hub_secrets_verify_unseal", map[string]any{"name": "BRAVE_API_KEY", "plaintext": seal["plaintext"]}); ver["ok"] != false {
		t.Fatalf("swapped verify %+v", ver)
	}
	st := callHubPolicyOp(t, "hub_secrets_build_status", map[string]any{"env": []any{map[string]any{"name": "BRAVE_API_KEY", "fingerprint": "abcdef01"}}})
	if s, _ := st["secrets"].([]any); len(s) == 0 || !strings.Contains(mustJSON(t, st), `"source":"env"`) {
		t.Fatalf("status %+v", st)
	}
}

func TestAccessPolicyWasmOps(t *testing.T) {
	rules := []map[string]any{{"subject": "*", "resource": "tool:agent", "effect": "deny"}}
	ev := callHubPolicyOp(t, "access_policy_evaluate", map[string]any{"rules": rules, "caller": map[string]any{"userId": "gh_2", "role": "member"}, "resource": "tool:agent"})
	if ev["allowed"] != false || ev["reason"] != "policy_deny" {
		t.Fatalf("eval %+v", ev)
	}
	f := callHubPolicyOp(t, "access_policy_filter_tools", map[string]any{"rules": rules, "caller": map[string]any{"userId": "gh_2", "role": "member"}, "names": []string{"agent", "scrape"}})
	if n, _ := f["names"].([]any); len(n) != 1 || n[0] != "scrape" {
		t.Fatalf("filter %+v", f)
	}
	shares := []map[string]any{{"ownerUserId": "gh_1", "slug": "notes", "subject": "*"}}
	res := callHubPolicyOp(t, "access_policy_resolve_shared", map[string]any{"shares": shares, "callerUserId": "gh_2", "ref": "notes"})
	if res["ok"] != true || res["ownerUserId"] != "gh_1" {
		t.Fatalf("resolve %+v", res)
	}
	norm := callHubPolicyOp(t, "access_policy_normalize_rule", map[string]any{"rule": map[string]any{"subject": "*", "resource": "route:/admin", "effect": "deny"}})
	if norm["ok"] != false || norm["error"] != "invalid_policy_resource" {
		t.Fatalf("normalize %+v", norm)
	}
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
