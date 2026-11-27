package mcpfed

import "testing"

func r(subject, resource, effect string) AccessRule {
	return AccessRule{Subject: subject, Resource: resource, Effect: effect}
}

func TestEvaluateAccessPrecedenceMatrix(t *testing.T) {
	member := AccessCaller{UserID: "gh_2", Role: "member"}
	cases := []struct {
		name     string
		rules    []AccessRule
		resource string
		allowed  bool
		reason   string
	}{
		{"no rules default allow tool", nil, "tool:scrape", true, "default_allow"},
		{"no rules default allow route", nil, "route:/v1/scrape", true, "default_allow"},
		{"global deny", []AccessRule{r("*", "tool:scrape", "deny")}, "tool:scrape", false, "policy_deny"},
		{"global deny other tool", []AccessRule{r("*", "tool:crawl", "deny")}, "tool:scrape", true, "default_allow"},
		{"user allow beats global deny", []AccessRule{r("*", "tool:scrape", "deny"), r("gh_2", "tool:scrape", "allow")}, "tool:scrape", true, "policy_allow"},
		{"user deny beats global allow", []AccessRule{r("*", "tool:scrape", "allow"), r("gh_2", "tool:scrape", "deny")}, "tool:scrape", false, "policy_deny"},
		{"deny beats allow same global", []AccessRule{r("*", "tool:scrape", "allow"), r("*", "tool:scrape", "deny")}, "tool:scrape", false, "policy_deny"},
		{"deny beats allow same user", []AccessRule{r("gh_2", "tool:scrape", "deny"), r("gh_2", "tool:scrape", "allow")}, "tool:scrape", false, "policy_deny"},
		{"other user's rule ignored", []AccessRule{r("gh_3", "tool:scrape", "deny")}, "tool:scrape", true, "default_allow"},
		{"wildcard deny", []AccessRule{r("*", "tool:*", "deny")}, "tool:scrape", false, "policy_deny"},
		{"exact allow beats wildcard deny (allowlist)", []AccessRule{r("*", "tool:*", "deny"), r("*", "tool:scrape", "allow")}, "tool:scrape", true, "policy_allow"},
		{"allowlist blocks others", []AccessRule{r("*", "tool:*", "deny"), r("*", "tool:scrape", "allow")}, "tool:crawl", false, "policy_deny"},
		{"user wildcard allow beats global exact deny", []AccessRule{r("*", "tool:scrape", "deny"), r("gh_2", "tool:*", "allow")}, "tool:scrape", true, "policy_allow"},
		{"longer prefix wins", []AccessRule{r("*", "route:/v1/*", "deny"), r("*", "route:/v1/agent*", "allow")}, "route:/v1/agent/run", true, "policy_allow"},
		{"route prefix deny", []AccessRule{r("*", "route:/v1/agent*", "deny")}, "route:/v1/agent", false, "policy_deny"},
		{"route normalization trailing slash", []AccessRule{r("*", "route:/v1/scrape", "deny")}, "route:/v1/scrape/", false, "policy_deny"},
		{"route query stripped", []AccessRule{r("*", "route:/v1/scrape", "deny")}, "route:/v1/scrape?x=1", false, "policy_deny"},
		{"tool rule does not hit route", []AccessRule{r("*", "tool:*", "deny")}, "route:/v1/scrape", true, "default_allow"},
		{"invalid resource denied", nil, "route:/admin", false, "invalid_resource"},
		{"percent-encoded id segment allowed", []AccessRule{r("*", "route:/v1/collections/*", "deny")}, "route:/v1/collections/my%20docs/search", false, "policy_deny"},
		{"dot segment rejected", nil, "route:/v1/../admin", false, "invalid_resource"},
	}
	for _, c := range cases {
		d := EvaluateAccess(c.rules, member, c.resource)
		if d.Allowed != c.allowed || d.Reason != c.reason {
			t.Errorf("%s: got %+v want allowed=%v reason=%s", c.name, d, c.allowed, c.reason)
		}
	}
}

func TestEvaluateAccessOwnerBypass(t *testing.T) {
	owner := AccessCaller{UserID: "gh_1", Role: "owner"}
	rules := []AccessRule{r("*", "tool:*", "deny"), r("gh_1", "tool:scrape", "deny"), r("*", "route:/v1/*", "deny")}
	for _, res := range []string{"tool:scrape", "tool:crawl", "route:/v1/agent"} {
		if d := EvaluateAccess(rules, owner, res); !d.Allowed || d.Reason != "owner_bypass" {
			t.Fatalf("owner must bypass %s: %+v", res, d)
		}
	}
	// Owner role does not bypass access to another user's MCP server.
	if d := EvaluateAccess(nil, owner, "mcp_server:gh_2/notes"); d.Allowed {
		t.Fatalf("owner must not see unshared server: %+v", d)
	}
}

func TestFilterAllowedToolNames(t *testing.T) {
	member := AccessCaller{UserID: "gh_2", Role: "member"}
	rules := []AccessRule{r("*", "tool:agent", "deny"), r("gh_2", "tool:crawl", "deny")}
	got := FilterAllowedToolNames(rules, member, []string{"scrape", "agent", "crawl", "search"})
	if len(got) != 2 || got[0] != "scrape" || got[1] != "search" {
		t.Fatalf("got %v", got)
	}
	if all := FilterAllowedToolNames(rules, AccessCaller{UserID: "gh_1", Role: "owner"}, []string{"agent", "crawl"}); len(all) != 2 {
		t.Fatalf("owner filter %v", all)
	}
}

func TestNormalizeAccessRuleAndShare(t *testing.T) {
	good := []struct{ in, want string }{
		{"tool:scrape", "tool:scrape"},
		{" tool:* ", "tool:*"},
		{"tool:query_*", "tool:query_*"},
		{"route:/v1/scrape/", "route:/v1/scrape"},
		{"route:/v1/*", "route:/v1/*"},
		{"route:/v1/agent/*", "route:/v1/agent/*"},
		{"mcp_server:gh_1/Notes", "mcp_server:gh_1/notes"},
	}
	for _, g := range good {
		out, err := NormalizeAccessRule(AccessRule{Subject: "*", Resource: g.in, Effect: "DENY"})
		if err != nil || out.Resource != g.want || out.Effect != "deny" {
			t.Fatalf("%q: %+v %+v", g.in, out, err)
		}
	}
	for _, bad := range []string{"", "tool:", "tool:a b", "route:/admin", "route:/v1/../admin", "route:/v1//x", "mcp_server:gh_1", "mcp_server:gh_1/a__b", "file:/etc"} {
		if _, err := NormalizeAccessRule(AccessRule{Subject: "*", Resource: bad, Effect: "allow"}); err == nil {
			t.Fatalf("%q must be rejected", bad)
		}
	}
	if _, err := NormalizeAccessRule(AccessRule{Subject: "a/b", Resource: "tool:x", Effect: "allow"}); err == nil {
		t.Fatal("bad subject must be rejected")
	}
	if _, err := NormalizeAccessRule(AccessRule{Subject: "*", Resource: "tool:x", Effect: "maybe"}); err == nil {
		t.Fatal("bad effect must be rejected")
	}
	if s, err := NormalizeMCPServerShare(MCPServerShare{OwnerUserID: "gh_1", Slug: "Notes", Subject: "*"}); err != nil || s.Slug != "notes" {
		t.Fatalf("share %+v %+v", s, err)
	}
	if _, err := NormalizeMCPServerShare(MCPServerShare{OwnerUserID: "gh_1", Slug: "notes", Subject: "gh_1"}); err == nil {
		t.Fatal("self-share must be rejected")
	}
	if _, err := NormalizeMCPServerShare(MCPServerShare{OwnerUserID: "gh_1", Slug: "bad__slug", Subject: "*"}); err == nil {
		t.Fatal("bad slug must be rejected")
	}
}

func TestSharedServerResolution(t *testing.T) {
	shares := []MCPServerShare{
		{OwnerUserID: "gh_1", Slug: "notes", Subject: "*"},
		{OwnerUserID: "gh_1", Slug: "crm", Subject: "gh_2"},
		{OwnerUserID: "gh_3", Slug: "notes", Subject: "gh_2"},
		{OwnerUserID: "gh_3", Slug: "wiki", Subject: "gh_4"},
	}
	// Default deny without a share.
	if d := EvaluateSharedServerAccess(nil, nil, "gh_2", "gh_1", "notes"); d.Allowed || d.Reason != "default_deny" {
		t.Fatalf("unshared %+v", d)
	}
	if d := EvaluateSharedServerAccess(nil, shares, "gh_1", "gh_1", "anything"); !d.Allowed || d.Reason != "server_owner" {
		t.Fatalf("owner %+v", d)
	}
	if d := EvaluateSharedServerAccess(nil, shares, "gh_5", "gh_1", "notes"); !d.Allowed {
		t.Fatalf("global share %+v", d)
	}
	if d := EvaluateSharedServerAccess(nil, shares, "gh_5", "gh_1", "crm"); d.Allowed {
		t.Fatalf("user share must not leak %+v", d)
	}
	// User-specific deny revokes a "*" share; global deny does NOT beat a user-specific share.
	deny := []AccessRule{r("gh_5", "mcp_server:gh_1/notes", "deny"), r("*", "mcp_server:gh_1/crm", "deny")}
	if d := EvaluateSharedServerAccess(deny, shares, "gh_5", "gh_1", "notes"); d.Allowed {
		t.Fatalf("user deny must revoke %+v", d)
	}
	if d := EvaluateSharedServerAccess(deny, shares, "gh_2", "gh_1", "crm"); !d.Allowed {
		t.Fatalf("user share beats global deny %+v", d)
	}

	list := ListSharedServersFor(nil, shares, "gh_2")
	if len(list) != 3 || list[0].Ref != "gh_1/crm" || list[1].Ref != "gh_1/notes" || list[2].Ref != "gh_3/notes" {
		t.Fatalf("list %+v", list)
	}
	if own := ListSharedServersFor(nil, shares, "gh_1"); len(own) != 0 {
		t.Fatalf("owner must not see own shares %+v", own)
	}

	if res, err := ResolveSharedServerRef(nil, shares, "gh_2", "crm"); err != nil || res.OwnerUserID != "gh_1" || res.Slug != "crm" {
		t.Fatalf("resolve crm %+v %+v", res, err)
	}
	if _, err := ResolveSharedServerRef(nil, shares, "gh_2", "notes"); err == nil || err.Status != 409 {
		t.Fatalf("ambiguous must 409 %+v", err)
	}
	if res, err := ResolveSharedServerRef(nil, shares, "gh_2", "gh_3/NOTES"); err != nil || res.Ref != "gh_3/notes" {
		t.Fatalf("explicit %+v %+v", res, err)
	}
	if _, err := ResolveSharedServerRef(nil, shares, "gh_2", "gh_3/wiki"); err == nil || err.Status != 404 {
		t.Fatalf("unshared explicit must 404 %+v", err)
	}
	if _, err := ResolveSharedServerRef(nil, shares, "gh_2", "gh_2/notes"); err == nil {
		t.Fatal("self ref must not resolve as share")
	}
	if _, err := ResolveSharedServerRef(nil, shares, "gh_2", "../x"); err == nil {
		t.Fatal("garbage ref must 404")
	}
}
