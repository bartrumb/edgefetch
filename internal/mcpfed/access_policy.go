package mcpfed

import (
	"sort"
	"strings"
)

// Hub access policy (`access_policies` + `mcp_server_shares` DO SQLite tables).
//
// Rule model: {subject: "*" | <userId>, resource, effect: "allow" | "deny"} with resources
//
//	tool:<mcpToolName>               first-party /mcp tool (tools/list filter + tools/call gate)
//	route:/v1/<path>                 /v1 HTTP route
//	mcp_server:<ownerUserId>/<slug>  another user's connected MCP server
//
// A tool/route resource may end in "*" for a prefix match ("tool:*", "route:/v1/agent*").
//
// Precedence (first difference wins):
//  1. subject specificity: a rule naming the caller's userId beats a "*" rule;
//  2. resource specificity: an exact resource beats a "*" prefix, and a longer prefix beats a shorter one;
//  3. effect: deny beats allow.
//
// Defaults when no rule matches: tool:/route: ALLOW (today's behaviour); mcp_server: DENY.
// Callers with role "owner" bypass tool:/route: policy entirely so an admin can never lock the hub out of
// /admin, /mcp, or the routes needed to undo a bad rule. Owner role does NOT bypass mcp_server: access —
// another user's vault-backed server is only reachable when that owner (or policy) shares it.
//
// Shares (`mcp_server_shares`) are allow grants: each row (owner, slug, subject) acts as an allow rule on
// "mcp_server:<owner>/<slug>" for that subject, evaluated together with explicit mcp_server: policy rules
// under the same precedence, so a user-specific deny still revokes a "*" share. A server's own owner always
// has access. Credentials never leave the owner's vault: callers resolve to (ownerUserID, slug) and the
// host loads the owner's row server-side.

const (
	AccessSubjectAll  = "*"
	AccessEffectAllow = "allow"
	AccessEffectDeny  = "deny"

	AccessKindTool      = "tool"
	AccessKindRoute     = "route"
	AccessKindMCPServer = "mcp_server"

	maxAccessUserIDLen    = 128
	maxAccessToolNameLen  = 128
	maxAccessRoutePathLen = 256
	// MaxAccessPolicyRules bounds evaluation input.
	MaxAccessPolicyRules = 2000
	// MaxMCPServerShares bounds evaluation input.
	MaxMCPServerShares = 2000
)

// AccessRule is one stored policy rule.
type AccessRule struct {
	Subject  string `json:"subject"`
	Resource string `json:"resource"`
	Effect   string `json:"effect"`
}

// AccessCaller is the authenticated identity being evaluated.
type AccessCaller struct {
	UserID string `json:"userId"`
	Role   string `json:"role"`
}

// AccessDecision is the evaluation outcome.
type AccessDecision struct {
	Allowed bool   `json:"allowed"`
	Reason  string `json:"reason"`
	// MatchedRule is the deciding rule (nil for defaults/bypass). Share grants appear as allow rules.
	MatchedRule *AccessRule `json:"matchedRule,omitempty"`
}

// MCPServerShare is one share grant row.
type MCPServerShare struct {
	OwnerUserID string `json:"ownerUserId"`
	Slug        string `json:"slug"`
	Subject     string `json:"subject"`
	CreatedAt   int64  `json:"createdAt,omitempty"`
}

// SharedServerRef identifies a server the caller may use through a share.
type SharedServerRef struct {
	OwnerUserID string `json:"ownerUserId"`
	Slug        string `json:"slug"`
	Ref         string `json:"ref"`
}

// AccessPolicyError is a structured validation/resolution failure.
type AccessPolicyError struct {
	Status  int    `json:"status"`
	Error   string `json:"error"`
	Message string `json:"message"`
}

// IsSafeAccessUserID accepts hub user ids (e.g. "owner", "gh_12345"): 1..128 of [A-Za-z0-9_.:@-], first char
// alphanumeric. "/" and "*" are excluded so ids can't collide with resource separators or the wildcard.
func IsSafeAccessUserID(raw string) bool {
	if raw == "" || len(raw) > maxAccessUserIDLen {
		return false
	}
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		alnum := (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
		if i == 0 && !alnum {
			return false
		}
		if !alnum && c != '_' && c != '.' && c != ':' && c != '@' && c != '-' {
			return false
		}
	}
	return true
}

func isSafeAccessToolName(raw string) bool {
	if raw == "" || len(raw) > maxAccessToolNameLen {
		return false
	}
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '.' || c == '-') {
			return false
		}
	}
	return true
}

// accessRoutePathPunct is the RFC 3986 pchar punctuation accepted in route paths ("*" is excluded: it is the
// rule wildcard). Paths stay percent-encoded exactly as URL.pathname reports them, matching the router.
const accessRoutePathPunct = "/_.-:%~@+=,!$&'();"

// NormalizeAccessRoutePath strips query/fragment and trailing slashes from a /v1 path. ok is false when the
// path is not under /v1/ or contains unsafe characters / dot segments.
func NormalizeAccessRoutePath(raw string) (string, bool) {
	p := strings.TrimSpace(raw)
	if i := strings.IndexAny(p, "?#"); i >= 0 {
		p = p[:i]
	}
	for len(p) > 1 && strings.HasSuffix(p, "/") {
		p = p[:len(p)-1]
	}
	if p == "" || len(p) > maxAccessRoutePathLen || (p != "/v1" && !strings.HasPrefix(p, "/v1/")) {
		return "", false
	}
	for i := 0; i < len(p); i++ {
		c := p[i]
		if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || strings.IndexByte(accessRoutePathPunct, c) >= 0) {
			return "", false
		}
	}
	if strings.Contains(p, "//") || strings.Contains(p, "/./") || strings.Contains(p, "/../") || strings.HasSuffix(p, "/..") || strings.HasSuffix(p, "/.") {
		return "", false
	}
	return p, true
}

// ParsedAccessResource is a validated resource string.
type ParsedAccessResource struct {
	Kind string
	// Target is the part after "<kind>:" without any trailing "*".
	Target string
	Prefix bool
	// Canonical is the normalized resource string as stored.
	Canonical string
}

// ParseAccessResource validates a rule resource (allowWildcard) or a concrete evaluated resource.
func ParseAccessResource(raw string, allowWildcard bool) (ParsedAccessResource, bool) {
	res := strings.TrimSpace(raw)
	kind, target, found := strings.Cut(res, ":")
	if !found {
		return ParsedAccessResource{}, false
	}
	switch kind {
	case AccessKindTool:
		prefix := false
		if allowWildcard && strings.HasSuffix(target, "*") {
			prefix = true
			target = strings.TrimSuffix(target, "*")
			if target == "" {
				return ParsedAccessResource{Kind: kind, Prefix: true, Canonical: "tool:*"}, true
			}
		}
		if !isSafeAccessToolName(target) {
			return ParsedAccessResource{}, false
		}
		canon := "tool:" + target
		if prefix {
			canon += "*"
		}
		return ParsedAccessResource{Kind: kind, Target: target, Prefix: prefix, Canonical: canon}, true
	case AccessKindRoute:
		prefix := false
		if allowWildcard && strings.HasSuffix(target, "*") {
			prefix = true
			target = strings.TrimSuffix(target, "*")
			if target == "/v1/" || target == "/v1" {
				return ParsedAccessResource{Kind: kind, Target: "/v1/", Prefix: true, Canonical: "route:/v1/*"}, true
			}
			// Keep the literal prefix (a trailing "/" is meaningful for prefix rules).
			trimmed := strings.TrimSuffix(target, "/")
			norm, ok := NormalizeAccessRoutePath(trimmed)
			if !ok {
				return ParsedAccessResource{}, false
			}
			if strings.HasSuffix(target, "/") {
				norm += "/"
			}
			return ParsedAccessResource{Kind: kind, Target: norm, Prefix: true, Canonical: "route:" + norm + "*"}, true
		}
		norm, ok := NormalizeAccessRoutePath(target)
		if !ok {
			return ParsedAccessResource{}, false
		}
		return ParsedAccessResource{Kind: kind, Target: norm, Prefix: prefix, Canonical: "route:" + norm}, true
	case AccessKindMCPServer:
		owner, slug, ok := ParseSharedServerRef(target)
		if !ok {
			return ParsedAccessResource{}, false
		}
		t := owner + "/" + slug
		return ParsedAccessResource{Kind: kind, Target: t, Canonical: "mcp_server:" + t}, true
	default:
		return ParsedAccessResource{}, false
	}
}

// ParseSharedServerRef splits "<ownerUserId>/<slug>" (slug lowercased) and validates both parts.
func ParseSharedServerRef(raw string) (owner, slug string, ok bool) {
	o, s, found := strings.Cut(strings.TrimSpace(raw), "/")
	if !found {
		return "", "", false
	}
	s = strings.ToLower(strings.TrimSpace(s))
	o = strings.TrimSpace(o)
	if !IsSafeAccessUserID(o) || !IsValidMCPConnectorSlug(s) {
		return "", "", false
	}
	return o, s, true
}

// NormalizeAccessRule validates and canonicalizes a rule for storage.
func NormalizeAccessRule(r AccessRule) (AccessRule, *AccessPolicyError) {
	subject := strings.TrimSpace(r.Subject)
	if subject != AccessSubjectAll && !IsSafeAccessUserID(subject) {
		return AccessRule{}, &AccessPolicyError{Status: 400, Error: "invalid_policy_subject", Message: `subject must be "*" or a hub user id.`}
	}
	effect := strings.ToLower(strings.TrimSpace(r.Effect))
	if effect != AccessEffectAllow && effect != AccessEffectDeny {
		return AccessRule{}, &AccessPolicyError{Status: 400, Error: "invalid_policy_effect", Message: `effect must be "allow" or "deny".`}
	}
	parsed, ok := ParseAccessResource(r.Resource, true)
	if !ok {
		return AccessRule{}, &AccessPolicyError{
			Status:  400,
			Error:   "invalid_policy_resource",
			Message: `resource must be "tool:<name>[*]", "route:/v1/<path>[*]", or "mcp_server:<ownerUserId>/<slug>".`,
		}
	}
	return AccessRule{Subject: subject, Resource: parsed.Canonical, Effect: effect}, nil
}

// NormalizeMCPServerShare validates a share row for storage.
func NormalizeMCPServerShare(s MCPServerShare) (MCPServerShare, *AccessPolicyError) {
	owner := strings.TrimSpace(s.OwnerUserID)
	slug := strings.ToLower(strings.TrimSpace(s.Slug))
	subject := strings.TrimSpace(s.Subject)
	if !IsSafeAccessUserID(owner) {
		return MCPServerShare{}, &AccessPolicyError{Status: 400, Error: "invalid_share_owner", Message: "ownerUserId must be a hub user id."}
	}
	if !IsValidMCPConnectorSlug(slug) {
		return MCPServerShare{}, &AccessPolicyError{Status: 400, Error: "invalid_share_slug", Message: "slug must be a valid connector slug."}
	}
	if subject != AccessSubjectAll && !IsSafeAccessUserID(subject) {
		return MCPServerShare{}, &AccessPolicyError{Status: 400, Error: "invalid_share_subject", Message: `subject must be "*" or a hub user id.`}
	}
	if subject == owner {
		return MCPServerShare{}, &AccessPolicyError{Status: 400, Error: "invalid_share_subject", Message: "A server is always available to its owner; share it with another user or \"*\"."}
	}
	return MCPServerShare{OwnerUserID: owner, Slug: slug, Subject: subject, CreatedAt: s.CreatedAt}, nil
}

type accessCandidate struct {
	rule         AccessRule
	userSpecific bool
	exact        bool
	prefixLen    int
	deny         bool
}

// better reports whether a outranks b under the documented precedence.
func (a accessCandidate) better(b accessCandidate) bool {
	if a.userSpecific != b.userSpecific {
		return a.userSpecific
	}
	if a.exact != b.exact {
		return a.exact
	}
	if a.prefixLen != b.prefixLen {
		return a.prefixLen > b.prefixLen
	}
	if a.deny != b.deny {
		return a.deny
	}
	return false
}

func matchRule(rule AccessRule, userID string, target ParsedAccessResource) (accessCandidate, bool) {
	if rule.Subject != AccessSubjectAll && rule.Subject != userID {
		return accessCandidate{}, false
	}
	parsed, ok := ParseAccessResource(rule.Resource, true)
	if !ok || parsed.Kind != target.Kind {
		return accessCandidate{}, false
	}
	c := accessCandidate{
		rule:         rule,
		userSpecific: rule.Subject != AccessSubjectAll,
		deny:         rule.Effect == AccessEffectDeny,
	}
	if parsed.Prefix {
		if !strings.HasPrefix(target.Target, parsed.Target) {
			return accessCandidate{}, false
		}
		c.prefixLen = len(parsed.Target)
		return c, true
	}
	if parsed.Target != target.Target {
		return accessCandidate{}, false
	}
	c.exact = true
	return c, true
}

func evaluateWithDefault(rules []AccessRule, userID string, target ParsedAccessResource, defaultAllow bool) AccessDecision {
	var best *accessCandidate
	for i, r := range rules {
		if i >= MaxAccessPolicyRules+MaxMCPServerShares {
			break
		}
		if r.Effect != AccessEffectAllow && r.Effect != AccessEffectDeny {
			continue
		}
		c, ok := matchRule(r, userID, target)
		if !ok {
			continue
		}
		if best == nil || c.better(*best) {
			cc := c
			best = &cc
		}
	}
	if best == nil {
		if defaultAllow {
			return AccessDecision{Allowed: true, Reason: "default_allow"}
		}
		return AccessDecision{Allowed: false, Reason: "default_deny"}
	}
	matched := best.rule
	if best.deny {
		return AccessDecision{Allowed: false, Reason: "policy_deny", MatchedRule: &matched}
	}
	return AccessDecision{Allowed: true, Reason: "policy_allow", MatchedRule: &matched}
}

// EvaluateAccess decides a concrete tool:/route: resource (mcp_server: resources go through
// EvaluateSharedServerAccess so shares are considered).
func EvaluateAccess(rules []AccessRule, caller AccessCaller, resource string) AccessDecision {
	target, ok := ParseAccessResource(resource, false)
	if !ok {
		return AccessDecision{Allowed: false, Reason: "invalid_resource"}
	}
	if target.Kind == AccessKindMCPServer {
		owner, slug, _ := ParseSharedServerRef(target.Target)
		return EvaluateSharedServerAccess(rules, nil, caller.UserID, owner, slug)
	}
	if caller.Role == "owner" {
		return AccessDecision{Allowed: true, Reason: "owner_bypass"}
	}
	return evaluateWithDefault(rules, strings.TrimSpace(caller.UserID), target, true)
}

// FilterAllowedToolNames returns the subset of names the caller may see/call, preserving order.
func FilterAllowedToolNames(rules []AccessRule, caller AccessCaller, names []string) []string {
	out := make([]string, 0, len(names))
	for _, n := range names {
		if EvaluateAccess(rules, caller, "tool:"+n).Allowed {
			out = append(out, n)
		}
	}
	return out
}

func shareRules(shares []MCPServerShare, ownerUserID, slug string) []AccessRule {
	out := make([]AccessRule, 0, 4)
	for i, s := range shares {
		if i >= MaxMCPServerShares {
			break
		}
		if s.OwnerUserID != ownerUserID || strings.ToLower(s.Slug) != slug {
			continue
		}
		if s.Subject != AccessSubjectAll && !IsSafeAccessUserID(s.Subject) {
			continue
		}
		out = append(out, AccessRule{Subject: s.Subject, Resource: "mcp_server:" + ownerUserID + "/" + slug, Effect: AccessEffectAllow})
	}
	return out
}

// EvaluateSharedServerAccess decides whether callerUserID may use ownerUserID's server slug.
func EvaluateSharedServerAccess(rules []AccessRule, shares []MCPServerShare, callerUserID, ownerUserID, slug string) AccessDecision {
	caller := strings.TrimSpace(callerUserID)
	owner := strings.TrimSpace(ownerUserID)
	slug = strings.ToLower(strings.TrimSpace(slug))
	if !IsSafeAccessUserID(caller) || !IsSafeAccessUserID(owner) || !IsValidMCPConnectorSlug(slug) {
		return AccessDecision{Allowed: false, Reason: "invalid_resource"}
	}
	if caller == owner {
		return AccessDecision{Allowed: true, Reason: "server_owner"}
	}
	target := ParsedAccessResource{Kind: AccessKindMCPServer, Target: owner + "/" + slug}
	combined := make([]AccessRule, 0, len(rules)+4)
	for i, r := range rules {
		if i >= MaxAccessPolicyRules {
			break
		}
		combined = append(combined, r)
	}
	combined = append(combined, shareRules(shares, owner, slug)...)
	return evaluateWithDefault(combined, caller, target, false)
}

// ListSharedServersFor returns the distinct (owner, slug) pairs shared with callerUserID that policy still
// allows, excluding the caller's own servers, sorted by owner then slug.
func ListSharedServersFor(rules []AccessRule, shares []MCPServerShare, callerUserID string) []SharedServerRef {
	caller := strings.TrimSpace(callerUserID)
	seen := make(map[string]bool)
	out := make([]SharedServerRef, 0)
	for i, s := range shares {
		if i >= MaxMCPServerShares {
			break
		}
		if s.OwnerUserID == caller || (s.Subject != AccessSubjectAll && s.Subject != caller) {
			continue
		}
		slug := strings.ToLower(s.Slug)
		key := s.OwnerUserID + "/" + slug
		if seen[key] {
			continue
		}
		seen[key] = true
		if EvaluateSharedServerAccess(rules, shares, caller, s.OwnerUserID, slug).Allowed {
			out = append(out, SharedServerRef{OwnerUserID: s.OwnerUserID, Slug: slug, Ref: key})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].OwnerUserID != out[j].OwnerUserID {
			return out[i].OwnerUserID < out[j].OwnerUserID
		}
		return out[i].Slug < out[j].Slug
	})
	return out
}

// ResolveSharedServerRef maps a caller-supplied ref to a shared (owner, slug). The host resolves the caller's
// OWN servers first; this is only consulted when that lookup misses. Accepted forms:
//
//	"<ownerUserId>/<slug>"  explicit; must be shared with (and not policy-denied to) the caller
//	"<slug>"                 resolves only when exactly one allowed share has that slug (409 when ambiguous)
func ResolveSharedServerRef(rules []AccessRule, shares []MCPServerShare, callerUserID, ref string) (SharedServerRef, *AccessPolicyError) {
	notFound := &AccessPolicyError{Status: 404, Error: "mcp_server_not_connected", Message: "No connected or shared MCP server matches that reference for the current user."}
	clean := strings.TrimSpace(ref)
	if clean == "" || len(clean) > maxAccessUserIDLen+64 {
		return SharedServerRef{}, notFound
	}
	if strings.Contains(clean, "/") {
		owner, slug, ok := ParseSharedServerRef(clean)
		if !ok {
			return SharedServerRef{}, notFound
		}
		if owner == strings.TrimSpace(callerUserID) {
			return SharedServerRef{}, notFound
		}
		if !EvaluateSharedServerAccess(rules, shares, callerUserID, owner, slug).Allowed {
			// Same 404 as "missing" so callers can't probe which servers other users have connected.
			return SharedServerRef{}, notFound
		}
		return SharedServerRef{OwnerUserID: owner, Slug: slug, Ref: owner + "/" + slug}, nil
	}
	slug := strings.ToLower(clean)
	if !IsValidMCPConnectorSlug(slug) {
		return SharedServerRef{}, notFound
	}
	var matches []SharedServerRef
	for _, s := range ListSharedServersFor(rules, shares, callerUserID) {
		if s.Slug == slug {
			matches = append(matches, s)
		}
	}
	switch len(matches) {
	case 0:
		return SharedServerRef{}, notFound
	case 1:
		return matches[0], nil
	default:
		return SharedServerRef{}, &AccessPolicyError{Status: 409, Error: "ambiguous_shared_server", Message: `More than one shared MCP server uses that slug; pass "<ownerUserId>/<slug>".`}
	}
}
