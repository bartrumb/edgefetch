// Package hubauth implements authentication, authorization, OAuth 2.1 + PKCE
// (S256), multi-user GitHub OAuth, the /admin Control Center & AES-256-GCM MCP
// credential vault, and connection/origin/header hardening for the Go Hub.
package hubauth

import (
	"context"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/bartrumb/edgefetch/v2/internal/agent"
	"github.com/bartrumb/edgefetch/v2/internal/mcpfed"
	"github.com/bartrumb/edgefetch/v2/internal/otel"
)

const (
	CookieOAuthCSRFDev    = "ef_oauth_csrf"
	CookieOAuthCSRFSecure = "__Host-ef_oauth_csrf"
	CookieAdminDev        = "ef_admin_session"
	CookieAdminSecure     = "__Host-ef_admin_session"
	CookieUserDev         = "ef_user_session"
	CookieUserSecure      = "__Host-ef_user_session"
	CookieGHStateDev      = "ef_gh_oauth"
	CookieGHStateSecure   = "__Host-ef_gh_oauth"

	oauthCodeTTL    = 5 * time.Minute
	accessTokenTTL  = time.Hour
	refreshTokenTTL = 90 * 24 * time.Hour
	adminSessionTTL = 8 * time.Hour
	loginLockWindow = 10 * time.Minute
	loginMaxFails   = 5
)

var (
	SupportedScopes = []string{"crawl:read", "crawl:fetch", "mcp:call"}
	DefaultScopes   = []string{"crawl:read", "crawl:fetch"}
)

// Principal describes an authenticated caller or browser session.
type Principal struct {
	Authenticated bool     `json:"authenticated"`
	Kind          string   `json:"kind"` // "owner", "mcp_token", "oauth", "github", "admin_cookie", "loopback"
	UserID        string   `json:"userId,omitempty"`
	GitHubLogin   string   `json:"githubLogin,omitempty"`
	AvatarURL     string   `json:"avatarUrl,omitempty"`
	Role          string   `json:"role,omitempty"` // "owner", "member"
	Scopes        []string `json:"scopes,omitempty"`
	GrantID       string   `json:"grantId,omitempty"`
	ClientID      string   `json:"clientId,omitempty"`
	IsOwner       bool     `json:"isOwner"`
}

// HasScope reports whether Principal holds want (crawl:fetch implies crawl:read; owners hold all scopes).
func (p Principal) HasScope(want string) bool {
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
		if s == want || s == "*" || (want == "crawl:read" && s == "crawl:fetch") {
			return true
		}
	}
	return false
}

// EffectiveOwnerID returns the isolated tenant key ("owner" for single-tenant owner/loopback, else UserID).
func (p Principal) EffectiveOwnerID() string {
	if p.IsOwner || strings.TrimSpace(p.UserID) == "" {
		return "owner"
	}
	return p.UserID
}

// Decision is the result of AuthorizeCaller.
type Decision struct {
	Allowed         bool
	Status          int
	WWWAuthenticate string
	Principal       Principal
}

// GitHubConfig configures optional multi-user GitHub OAuth sign-in.
type GitHubConfig struct {
	ClientID, ClientSecret   string
	OwnerID, OwnerLogin      string
	SignupMode, AllowedUsers string // SignupMode: "closed" (default), "allowlist", "open"
	AuthorizeURL, TokenURL   string
	APIBaseURL               string
}

// AdminHubState carries live fleet/affinity/event state into GET /admin/api/state.
type AdminHubState struct {
	Connected         int                 `json:"connected"`
	DistinctPublicIPs int                 `json:"distinctPublicIps"`
	Agents            []FleetAgentVersion `json:"-"`
	AgentsRaw         any                 `json:"agents"`
	Affinities        any                 `json:"affinities"`
	TrackerList       any                 `json:"trackerList,omitempty"`
	Events            any                 `json:"events"`
}

// AdminFetchRequest represents an interactive fetch triggered from /admin.
type AdminFetchRequest struct {
	URL           string `json:"url"`
	Kind          string `json:"kind"`
	Target        string `json:"target"`
	Site          string `json:"site,omitempty"`
	PauseMs       int    `json:"pauseMs,omitempty"`
	PauseJitterMs int    `json:"pauseJitterMs,omitempty"`
	RespectRobots bool   `json:"respectRobots"`
	IncludeBody   bool   `json:"includeBody"`
}

// Callbacks connects /admin endpoints to live Hub operations.
type Callbacks struct {
	GetAdminState     func(ctx context.Context) (AdminHubState, error)
	ExecuteAdminFetch func(ctx context.Context, req AdminFetchRequest) (status int, via string, body []byte, err error)
	ClearAffinities   func(ctx context.Context, siteID string) error
	ClearEvents       func(ctx context.Context) error
}

// Config configures a hubauth Manager.
type Config struct {
	DataDir, ServiceName, McpSlug, HubVersion   string
	CallerToken, McpToken                       string
	SessionSecret, VaultMasterKey, PublicOrigin string
	AllowedLoopbackPort, ReleaseAPIURL          string
	TrustProxy, TrustFly, DisableUpdateCheck    bool
	RedirectAllowlist                           []string
	GitHub                                      GitHubConfig
	Getenv                                      func(string) string
	HTTPClient                                  *http.Client
	OtelExporter                                *otel.Exporter
	Now                                         func() time.Time
	Callbacks                                   Callbacks
}

type loginBucket struct {
	Count   int   `json:"count"`
	ResetAt int64 `json:"resetAt"`
}

// OAuthClient represents a dynamically registered RFC 7591 OAuth client.
type OAuthClient struct {
	ClientID     string   `json:"clientId"`
	ClientName   string   `json:"clientName"`
	RedirectURIs []string `json:"redirectUris"`
	CreatedAt    int64    `json:"createdAt"`
}

type oauthCodeRecord struct {
	CodeHash      string   `json:"codeHash"`
	ClientID      string   `json:"clientId"`
	ClientName    string   `json:"clientName"`
	RedirectURI   string   `json:"redirectUri"`
	CodeChallenge string   `json:"codeChallenge"`
	Scopes        []string `json:"scopes"`
	Resource      string   `json:"resource"`
	UserID        string   `json:"userId"`
	Role          string   `json:"role"`
	Consumed      bool     `json:"consumed"`
	ExpiresAt     int64    `json:"expiresAt"`
}

// OAuthGrant represents a persistent OAuth 2.1 refresh lineage.
type OAuthGrant struct {
	GrantID           string   `json:"grantId"`
	ClientID          string   `json:"clientId"`
	ClientName        string   `json:"clientName"`
	UserID            string   `json:"userId"`
	Role              string   `json:"role"`
	Scopes            []string `json:"scopes"`
	Resource          string   `json:"resource"`
	CurrentGen        int      `json:"currentGen"`
	RefreshSecretHash string   `json:"refreshSecretHash"`
	Revoked           bool     `json:"revoked"`
	CreatedAt         int64    `json:"createdAt"`
	ExpiresAt         int64    `json:"expiresAt"`
}

type oauthAccessToken struct {
	TokenHash string   `json:"tokenHash"`
	GrantID   string   `json:"grantId"`
	ClientID  string   `json:"clientId"`
	UserID    string   `json:"userId"`
	Role      string   `json:"role"`
	Scopes    []string `json:"scopes"`
	Resource  string   `json:"resource"`
	CreatedAt int64    `json:"createdAt"`
	ExpiresAt int64    `json:"expiresAt"`
}

func extractPresentedToken(r *http.Request) (tok string, hadAuthHeader bool) {
	if r == nil {
		return "", false
	}
	if auth := strings.TrimSpace(r.Header.Get("Authorization")); auth != "" {
		if len(auth) > 7 && strings.EqualFold(auth[:7], "Bearer ") {
			if cand := strings.TrimSpace(auth[7:]); cand != "" && !strings.ContainsAny(cand, " \t\r\n") {
				return cand, true
			}
		}
		return "", true
	}
	if apiKey := strings.TrimSpace(r.Header.Get("X-Api-Key")); apiKey != "" && !strings.ContainsAny(apiKey, " \t\r\n") {
		return apiKey, false
	}
	return "", false
}

type persistedState struct {
	Clients         map[string]OAuthClient               `json:"clients"`
	Codes           map[string]oauthCodeRecord           `json:"codes"`
	Grants          map[string]*OAuthGrant               `json:"grants"`
	AccessTokens    map[string]oauthAccessToken          `json:"accessTokens"`
	Users           map[string]GitHubUser                `json:"users"`
	RevokedSessions map[string]int64                     `json:"revokedSessions"`
	McpServers      map[string]mcpfed.StoredMCPServerRow `json:"mcpServers"`
	TelemetryOptIn  *bool                                `json:"telemetryOptIn,omitempty"`
}

// Manager coordinates OAuth 2.1, GitHub OAuth, /admin sessions, and the MCP credential vault.
type Manager struct {
	cfg                                    Config
	stateFilePath, signingSecret, vaultKey string
	httpClient                             *http.Client

	mu          sync.Mutex
	st          persistedState
	loginFails  map[string]loginBucket
	updateCache *cachedReleaseStatus
}

func ensureStateMaps(st *persistedState) {
	if st.Clients == nil {
		st.Clients = make(map[string]OAuthClient)
	}
	if st.Codes == nil {
		st.Codes = make(map[string]oauthCodeRecord)
	}
	if st.Grants == nil {
		st.Grants = make(map[string]*OAuthGrant)
	}
	if st.AccessTokens == nil {
		st.AccessTokens = make(map[string]oauthAccessToken)
	}
	if st.Users == nil {
		st.Users = make(map[string]GitHubUser)
	}
	if st.RevokedSessions == nil {
		st.RevokedSessions = make(map[string]int64)
	}
	if st.McpServers == nil {
		st.McpServers = make(map[string]mcpfed.StoredMCPServerRow)
	}
}

// NewManager initializes a Manager and loads persisted state from DataDir/state/oauth_state.json when DataDir != "".
func NewManager(cfg Config) (*Manager, error) {
	if strings.TrimSpace(cfg.ServiceName) == "" {
		cfg.ServiceName = "EdgeFetch Hub"
	}
	if strings.TrimSpace(cfg.McpSlug) == "" {
		cfg.McpSlug = "edgefetch"
	}
	if strings.TrimSpace(cfg.HubVersion) == "" {
		cfg.HubVersion = agent.Version
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	hc := cfg.HTTPClient
	if hc == nil {
		hc = &http.Client{
			Timeout:       10 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		}
	}
	vaultKey, err := resolveVaultKey(cfg)
	if err != nil {
		return nil, err
	}
	m := &Manager{cfg: cfg, signingSecret: resolveSigningSecret(cfg), vaultKey: vaultKey, httpClient: hc, loginFails: make(map[string]loginBucket)}
	ensureStateMaps(&m.st)
	if d := strings.TrimSpace(cfg.DataDir); d != "" {
		m.stateFilePath = filepath.Join(d, "state", "oauth_state.json")
		if err := m.loadFromDisk(); err != nil {
			return nil, err
		}
	}
	return m, nil
}

func resolveSigningSecret(cfg Config) string {
	if s := strings.TrimSpace(cfg.SessionSecret); len(s) >= 16 {
		return s
	}
	caller := strings.TrimSpace(cfg.CallerToken)
	ghSec := strings.TrimSpace(cfg.GitHub.ClientSecret)
	if strings.TrimSpace(cfg.GitHub.ClientID) != "" && len(ghSec) >= 16 {
		if len(caller) >= 16 {
			return "gh-sess:" + caller + ":" + ghSec
		}
		return ghSec
	}
	if caller != "" {
		return caller
	}
	return randomHex(32)
}

func resolveVaultKey(cfg Config) (string, error) {
	if raw := strings.TrimSpace(cfg.VaultMasterKey); raw != "" {
		clean, ok, msg := mcpfed.ValidateVaultMasterKey(raw)
		if !ok {
			return "", errors.New(msg)
		}
		return clean, nil
	}
	seed := strings.TrimSpace(cfg.SessionSecret)
	if seed == "" {
		seed = strings.TrimSpace(cfg.CallerToken)
	}
	if seed == "" {
		return "", nil
	}
	derived, err := hkdf.Key(sha256.New, []byte(seed), []byte("edgefetch-hubauth-vault-salt-v1"), "edgefetch-vault-master-key-v1", 32)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(derived), nil
}

func (m *Manager) loadFromDisk() error {
	raw, err := os.ReadFile(m.stateFilePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	var loaded persistedState
	if err := json.Unmarshal(raw, &loaded); err != nil {
		return fmt.Errorf("corrupt oauth_state.json: %w", err)
	}
	ensureStateMaps(&loaded)
	m.st = loaded
	return nil
}

func (m *Manager) saveLocked() error {
	if m.stateFilePath == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(m.stateFilePath), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(m.st, "", "  ")
	if err != nil {
		return err
	}
	tmp := m.stateFilePath + ".tmp." + randomHex(6)
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, wErr := f.Write(data); wErr != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return wErr
	}
	_ = f.Sync()
	if cErr := f.Close(); cErr != nil {
		_ = os.Remove(tmp)
		return cErr
	}
	if rErr := os.Rename(tmp, m.stateFilePath); rErr != nil {
		_ = os.Remove(tmp)
		return rErr
	}
	_ = os.Chmod(m.stateFilePath, 0o600)
	return nil
}

func (m *Manager) startSpan(r *http.Request, name string, attrs map[string]any) *otel.ActiveSpan {
	var ctx context.Context
	if r != nil {
		ctx = r.Context()
	}
	_, span, _ := otel.StartChildSpan(ctx, m.cfg.OtelExporter, name, 1, attrs)
	return span
}

func randomHex(byteLen int) string {
	buf := make([]byte, byteLen)
	_, _ = rand.Read(buf)
	return hex.EncodeToString(buf)
}

func randomB64URL(byteLen int) string {
	buf := make([]byte, byteLen)
	_, _ = rand.Read(buf)
	return base64.RawURLEncoding.EncodeToString(buf)
}

func sha256B64URL(s string) string {
	sum := sha256.Sum256([]byte(s))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func hmacB64URL(key, msg string) string {
	mac := hmac.New(sha256.New, []byte(key))
	_, _ = mac.Write([]byte(msg))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func constantTimeEqual(a, b string) bool {
	return a != "" && len(a) == len(b) && subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func isHTTPSOrigin(origin string) bool {
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(origin)), "https://")
}

func writeJSONResp(w http.ResponseWriter, isHTTPS bool, status int, v any) {
	ApplySecurityHeaders(w, isHTTPS)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func readCappedBody(w http.ResponseWriter, r *http.Request, maxBytes int64) ([]byte, bool, error) {
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

func readCookieVal(r *http.Request, name string) string {
	if r == nil {
		return ""
	}
	c, err := r.Cookie(name)
	if err != nil || c == nil {
		return ""
	}
	if strings.Contains(c.Value, "%") {
		if dec, uErr := url.QueryUnescape(c.Value); uErr == nil {
			return dec
		}
	}
	return c.Value
}

func parseFormOrJSONBody(w http.ResponseWriter, r *http.Request, maxBytes int64) (vals map[string]string, tooBig bool, ok bool) {
	buf, exceeded, err := readCappedBody(w, r, maxBytes)
	if exceeded {
		return nil, true, false
	}
	if err != nil {
		return nil, false, false
	}
	out := make(map[string]string)
	if strings.Contains(strings.ToLower(r.Header.Get("Content-Type")), "application/json") {
		if len(strings.TrimSpace(string(buf))) == 0 {
			return out, false, true
		}
		var raw map[string]any
		if json.Unmarshal(buf, &raw) != nil {
			return nil, false, false
		}
		for k, v := range raw {
			if s, isStr := v.(string); isStr {
				out[k] = s
			}
		}
		return out, false, true
	}
	parsed, pErr := url.ParseQuery(string(buf))
	if pErr != nil {
		return nil, false, false
	}
	for k, v := range parsed {
		if len(v) > 0 {
			out[k] = v[0]
		}
	}
	return out, false, true
}

// AuthorizeCaller evaluates Bearer, X-Api-Key, OAuth efa_*, GitHub session cookies, and tokenless loopback mode.
func (m *Manager) AuthorizeCaller(r *http.Request, requiredScope string, allowMcpToken bool, ownerOnly bool) Decision {
	const unauthHdr = "Bearer"
	tok, hadExplicitAuthHdr := extractPresentedToken(r)
	callerTok, mcpTok := strings.TrimSpace(m.cfg.CallerToken), strings.TrimSpace(m.cfg.McpToken)
	if tok != "" {
		if callerTok != "" && constantTimeEqual(tok, callerTok) {
			p := Principal{Authenticated: true, Kind: "owner", UserID: "owner", Role: "owner", Scopes: append([]string(nil), SupportedScopes...), IsOwner: true}
			return Decision{Allowed: true, Status: http.StatusOK, Principal: p}
		}
		if mcpTok != "" && constantTimeEqual(tok, mcpTok) {
			if ownerOnly || !allowMcpToken {
				return Decision{Allowed: false, Status: http.StatusForbidden}
			}
			p := Principal{Authenticated: true, Kind: "mcp_token", UserID: "owner", Role: "owner", Scopes: append([]string(nil), SupportedScopes...)}
			return Decision{Allowed: true, Status: http.StatusOK, Principal: p}
		}
		if strings.HasPrefix(tok, "efa_") {
			nowMs := m.cfg.Now().UnixMilli()
			m.mu.Lock()
			at, ok := m.st.AccessTokens[sha256B64URL(tok)]
			grant := m.st.Grants[at.GrantID]
			valid := ok && at.ExpiresAt > nowMs && grant != nil && !grant.Revoked && grant.ExpiresAt > nowMs
			if valid && at.UserID != "" && at.UserID != "owner" {
				if u, uOK := m.st.Users[at.UserID]; !uOK || u.Disabled {
					valid = false
				}
			}
			m.mu.Unlock()
			if !valid {
				return Decision{Allowed: false, Status: http.StatusUnauthorized, WWWAuthenticate: unauthHdr}
			}
			p := Principal{Authenticated: true, Kind: "oauth", UserID: at.UserID, Role: at.Role, Scopes: append([]string(nil), at.Scopes...), GrantID: at.GrantID, ClientID: at.ClientID}
			if ownerOnly {
				return Decision{Allowed: false, Status: http.StatusForbidden, Principal: p}
			}
			if requiredScope != "" && !p.HasScope(requiredScope) {
				return Decision{Allowed: false, Status: http.StatusForbidden, WWWAuthenticate: fmt.Sprintf("Bearer error=\"insufficient_scope\", scope=%q", requiredScope), Principal: p}
			}
			return Decision{Allowed: true, Status: http.StatusOK, Principal: p}
		}
		return Decision{Allowed: false, Status: http.StatusUnauthorized, WWWAuthenticate: unauthHdr}
	}
	if hadExplicitAuthHdr {
		return Decision{Allowed: false, Status: http.StatusUnauthorized, WWWAuthenticate: unauthHdr}
	}
	isHTTPS := (r != nil && r.TLS != nil) || isHTTPSOrigin(m.cfg.PublicOrigin)
	if sess, ok := m.verifySessionFromRequest(r, isHTTPS, m.cfg.Now()); ok && sess.Kind == "github" {
		if r != nil && isMutatingMethod(r.Method) && !m.isSameOriginRequest(r, m.cfg.PublicOrigin) {
			return Decision{Allowed: false, Status: http.StatusForbidden}
		}
		if ownerOnly && !sess.IsOwner {
			return Decision{Allowed: false, Status: http.StatusForbidden, Principal: sess.Principal}
		}
		if requiredScope != "" && !sess.HasScope(requiredScope) {
			return Decision{Allowed: false, Status: http.StatusForbidden, WWWAuthenticate: fmt.Sprintf("Bearer error=\"insufficient_scope\", scope=%q", requiredScope), Principal: sess.Principal}
		}
		return Decision{Allowed: true, Status: http.StatusOK, Principal: sess.Principal}
	}
	if callerTok == "" && mcpTok == "" && !m.isGitHubConfigured() {
		p := Principal{Authenticated: true, Kind: "loopback", UserID: "owner", Role: "owner", Scopes: append([]string(nil), SupportedScopes...), IsOwner: true}
		return Decision{Allowed: true, Status: http.StatusOK, Principal: p}
	}
	return Decision{Allowed: false, Status: http.StatusUnauthorized, WWWAuthenticate: unauthHdr}
}
