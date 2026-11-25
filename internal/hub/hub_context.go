package hub

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// AuthPrincipal identifies the authenticated caller across `/v1/*`, `/mcp`, `/oauth/*`, and `/admin/*`.
type AuthPrincipal struct {
	Authenticated bool
	Kind          string // "owner", "mcp_token", "oauth", "github", "admin_cookie", "loopback"
	UserID        string
	GitHubLogin   string
	Role          string // "owner", "member", ""
	Scopes        []string
	GrantID       string
	ClientID      string
	IsOwner       bool
}

// HasScope reports whether the principal holds `want` (owners hold all scopes).
func (p AuthPrincipal) HasScope(want string) bool {
	if !p.Authenticated {
		return false
	}
	if p.IsOwner || p.Kind == "owner" || p.Kind == "loopback" {
		return true
	}
	want = strings.TrimSpace(want)
	if want == "" {
		return true
	}
	for _, s := range p.Scopes {
		if s == want || s == "*" {
			return true
		}
		// crawl:fetch implies crawl:read parity with hub/src/oauth.ts
		if want == "crawl:read" && s == "crawl:fetch" {
			return true
		}
	}
	return false
}

// EffectiveOwnerID returns the tenant namespace key (`"owner"` for single-tenant owner/loopback callers, or `UserID`).
func (p AuthPrincipal) EffectiveOwnerID() string {
	if p.IsOwner || p.UserID == "" {
		return "owner"
	}
	return p.UserID
}

type principalCtxKey struct{}

// WithPrincipal attaches `p` onto `ctx`.
func WithPrincipal(ctx context.Context, p AuthPrincipal) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, principalCtxKey{}, p)
}

// PrincipalFromContext returns the `AuthPrincipal` stored on `ctx` (zero value when unauthenticated).
func PrincipalFromContext(ctx context.Context) AuthPrincipal {
	if ctx == nil {
		return AuthPrincipal{}
	}
	if p, ok := ctx.Value(principalCtxKey{}).(AuthPrincipal); ok {
		return p
	}
	return AuthPrincipal{}
}

// IsRobotBypassedHost reports whether `rawURL`'s host matches `bypassHosts` (exact or subdomain).
func IsRobotBypassedHost(rawURL string, bypassHosts []string) bool {
	if len(bypassHosts) == 0 {
		return false
	}
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return false
	}
	h := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	if h == "" {
		return false
	}
	for _, entry := range bypassHosts {
		b := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(entry)), ".")
		if b == "" {
			continue
		}
		if h == b || strings.HasSuffix(h, "."+b) {
			return true
		}
	}
	return false
}

// ReadBoundedBody reads at most `maxBytes` from `r.Body`, returning `(nil, true, nil)` when the payload exceeds `maxBytes`.
func ReadBoundedBody(w http.ResponseWriter, r *http.Request, maxBytes int64) ([]byte, bool, error) {
	if r.ContentLength > maxBytes {
		return nil, true, nil
	}
	mr := http.MaxBytesReader(w, r.Body, maxBytes)
	defer func() { _ = mr.Close() }()
	buf, err := io.ReadAll(mr)
	if err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			return nil, true, nil
		}
		return nil, false, err
	}
	return buf, false, nil
}
