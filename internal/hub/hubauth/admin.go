package hubauth

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/bartrumb/edgefetch/v2/internal/mcpfed"
	"github.com/bartrumb/edgefetch/v2/internal/otel"
)

// ConnectedMcpServer holds a decrypted user-scoped MCP connector for /v1/mcp/query and call_connected_mcp.
type ConnectedMcpServer struct {
	ID              string                       `json:"id"`
	UserID          string                       `json:"userId"`
	Slug            string                       `json:"slug"`
	Name            string                       `json:"name"`
	RemoteURL       string                       `json:"remoteUrl"`
	RemoteOrigin    string                       `json:"remoteOrigin"`
	Transport       string                       `json:"transport"`
	AuthType        string                       `json:"authType"`
	Domains         []string                     `json:"domains"`
	AutoRouteScrape bool                         `json:"autoRouteScrape"`
	Tools           []mcpfed.CachedMCPToolSchema `json:"tools"`
	Headers         map[string]string            `json:"-"`
	OAuth           *mcpfed.VaultSecretOAuth     `json:"-"`
}

type adminCookiePayload struct {
	Sub  string `json:"sub"`
	Role string `json:"role"`
	Auth string `json:"auth"`
	JTI  string `json:"jti"`
	CSRF string `json:"csrf"`
	Exp  int64  `json:"exp"`
}

type verifiedSession struct {
	Principal
	CSRF   string
	JTI    string
	SigKey string
	ExpMs  int64
}

func (m *Manager) mintAdminCookie(now time.Time) (cookieVal, csrf string) {
	csrf = randomHex(20)
	raw, _ := json.Marshal(adminCookiePayload{
		Sub: "owner", Role: "owner", Auth: "owner_token",
		JTI: "jti_" + randomB64URL(16), CSRF: csrf, Exp: now.Add(adminSessionTTL).UnixMilli(),
	})
	payloadB64 := base64.RawURLEncoding.EncodeToString(raw)
	return payloadB64 + "." + hmacB64URL("admin-cookie:"+m.signingSecret, payloadB64+"."+csrf) + "." + csrf, csrf
}

func (m *Manager) verifySessionFromRequest(r *http.Request, isHTTPS bool, now time.Time) (verifiedSession, bool) {
	if r == nil {
		return verifiedSession{}, false
	}
	candidates := []string{CookieAdminDev, CookieAdminSecure, CookieUserDev, CookieUserSecure}
	if isHTTPS {
		candidates = []string{CookieAdminSecure, CookieUserSecure}
	}
	for _, name := range candidates {
		if raw := readCookieVal(r, name); raw != "" {
			if sess, ok := m.verifySessionToken(raw, now); ok {
				return sess, true
			}
		}
	}
	return verifiedSession{}, false
}

func (m *Manager) verifySessionToken(raw string, now time.Time) (verifiedSession, bool) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return verifiedSession{}, false
	}
	nowMs := now.UnixMilli()

	// 1. Owner session cookie: <payloadB64Url>.<sigB64Url>.<csrfHex>
	if constantTimeEqual(parts[1], hmacB64URL("admin-cookie:"+m.signingSecret, parts[0]+"."+parts[2])) {
		decoded, err := base64.RawURLEncoding.DecodeString(parts[0])
		var p adminCookiePayload
		if err != nil || json.Unmarshal(decoded, &p) != nil || p.Exp <= nowMs || p.JTI == "" || len(p.CSRF) < 16 || !constantTimeEqual(p.CSRF, parts[2]) {
			return verifiedSession{}, false
		}
		sigKey, jtiKey := "sig:"+sha256B64URL(parts[1]), "jti:"+sha256B64URL(p.JTI)
		m.mu.Lock()
		rev := m.st.RevokedSessions[sigKey] > nowMs || m.st.RevokedSessions[jtiKey] > nowMs
		m.mu.Unlock()
		if rev {
			return verifiedSession{}, false
		}
		return verifiedSession{
			Principal: Principal{Authenticated: true, Kind: "admin_cookie", UserID: "owner", Role: "owner", Scopes: append([]string(nil), SupportedScopes...), IsOwner: true},
			CSRF:      p.CSRF, JTI: p.JTI, SigKey: sigKey, ExpMs: p.Exp,
		}, true
	}

	// 2. HS256 GitHub session JWT: <headerB64Url>.<payloadB64Url>.<sigB64Url>
	claims, jwtOK := VerifyGitHubSessionJWT(raw, m.signingSecret, now)
	if !jwtOK {
		return verifiedSession{}, false
	}
	sigKey, jtiKey := "sig:"+sha256B64URL(parts[2]), "jti:"+sha256B64URL(claims.JTI)
	m.mu.Lock()
	rev := m.st.RevokedSessions[sigKey] > nowMs || m.st.RevokedSessions[jtiKey] > nowMs
	liveUser, hasUser := m.st.Users[claims.Sub]
	m.mu.Unlock()
	if rev || !hasUser || liveUser.Disabled || max(liveUser.SessionEpoch, 1) != max(claims.Epoch, 1) {
		return verifiedSession{}, false
	}
	return verifiedSession{
		Principal: Principal{
			Authenticated: true, Kind: "github", UserID: liveUser.UserID, GitHubLogin: liveUser.GitHubLogin,
			AvatarURL: liveUser.AvatarURL, Role: liveUser.Role, Scopes: append([]string(nil), SupportedScopes...), IsOwner: liveUser.Role == "owner",
		},
		CSRF: claims.CSRF, JTI: claims.JTI, SigKey: sigKey, ExpMs: claims.Exp * 1000,
	}, true
}

func (m *Manager) isLoginLocked(bucket string, now time.Time) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	b, ok := m.loginFails[bucket]
	if !ok || b.ResetAt <= now.UnixMilli() {
		delete(m.loginFails, bucket)
		return false
	}
	return b.Count >= loginMaxFails
}

func (m *Manager) recordFailedLogin(bucket string, now time.Time) bool {
	nowMs := now.UnixMilli()
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.loginFails[bucket]; !exists && len(m.loginFails) >= 512 {
		for k, v := range m.loginFails {
			if v.ResetAt <= nowMs {
				delete(m.loginFails, k)
			}
		}
		if len(m.loginFails) >= 512 {
			var evictKey string
			var evictReset int64
			for k, v := range m.loginFails {
				if v.Count < loginMaxFails && (evictKey == "" || v.ResetAt < evictReset) {
					evictKey, evictReset = k, v.ResetAt
				}
			}
			if evictKey == "" {
				for k, v := range m.loginFails {
					if evictKey == "" || v.ResetAt < evictReset {
						evictKey, evictReset = k, v.ResetAt
					}
				}
			}
			if evictKey != "" {
				delete(m.loginFails, evictKey)
			}
		}
	}
	cur, ok := m.loginFails[bucket]
	if !ok || cur.ResetAt <= nowMs {
		m.loginFails[bucket] = loginBucket{Count: 1, ResetAt: now.Add(loginLockWindow).UnixMilli()}
		return false
	}
	cur.Count++
	m.loginFails[bucket] = cur
	return cur.Count > loginMaxFails
}

func (m *Manager) clearFailedLogin(bucket string) {
	m.mu.Lock()
	delete(m.loginFails, bucket)
	m.mu.Unlock()
}

func isMutatingMethod(method string) bool {
	return method == http.MethodPost || method == http.MethodPut || method == http.MethodPatch || method == http.MethodDelete
}

func (m *Manager) isSameOriginRequest(r *http.Request, origin string) bool {
	if r == nil {
		return false
	}
	sfs := strings.ToLower(strings.TrimSpace(r.Header.Get("Sec-Fetch-Site")))
	if sfs == "cross-site" || sfs == "same-site" {
		return false
	}
	rawOrigin := strings.TrimSpace(r.Header.Get("Origin"))
	if rawOrigin == "" {
		return true
	}
	if strings.EqualFold(rawOrigin, "null") {
		return sfs == "same-origin"
	}
	reqOrig := parseOriginCandidate(rawOrigin)
	if reqOrig == "" {
		return false
	}
	for _, allowed := range []string{origin, m.cfg.PublicOrigin} {
		if a := parseOriginCandidate(allowed); a != "" && strings.EqualFold(reqOrig, a) {
			return true
		}
	}
	if r.Host != "" {
		scheme := "http"
		if r.TLS != nil || isHTTPSOrigin(origin) {
			scheme = "https"
		}
		if hostOrig, err := formatCanonicalOrigin(scheme, r.Host); err == nil && strings.EqualFold(reqOrig, hostOrig) {
			return true
		}
	}
	return false
}

// HandleAdmin routes /admin and /admin/* requests, returning true if the path belongs to /admin.
func (m *Manager) HandleAdmin(w http.ResponseWriter, r *http.Request, origin string) bool {
	p := r.URL.Path
	if p != "/admin" && !strings.HasPrefix(p, "/admin/") {
		return false
	}
	origin = strings.TrimRight(strings.TrimSpace(origin), "/")
	isHTTPS := isHTTPSOrigin(origin) || r.TLS != nil

	switch {
	case p == "/admin/auth/github" && r.Method == http.MethodGet:
		m.HandleGitHubStart(w, r, origin)
		return true
	case p == "/admin/auth/github/callback" && r.Method == http.MethodGet:
		m.HandleGitHubCallback(w, r, origin)
		return true
	case p == "/admin/login":
		m.HandleAdminLogin(w, r, origin)
		return true
	case p == "/admin" && r.Method == http.MethodGet:
		m.HandleAdminPage(w, r, origin)
		return true
	case p == "/admin/logout" && r.Method == http.MethodPost:
		m.HandleAdminLogout(w, r, origin)
		return true
	}

	if p == "/admin/api/tracker-list/refresh" && r.Method == http.MethodPost {
		if tok, _ := extractPresentedToken(r); tok != "" {
			callerTok := strings.TrimSpace(m.cfg.CallerToken)
			if callerTok != "" && constantTimeEqual(tok, callerTok) && strings.ToLower(strings.TrimSpace(r.Header.Get("Sec-Fetch-Site"))) != "cross-site" {
				m.HandleAdminTrackerListRefresh(w, r, verifiedSession{
					Principal: Principal{Authenticated: true, Kind: "owner", UserID: "owner", Role: "owner", IsOwner: true},
				}, isHTTPS)
				return true
			}
			writeJSONResp(w, isHTTPS, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return true
		}
	}

	if isMutatingMethod(r.Method) && !m.isSameOriginRequest(r, origin) {
		writeJSONResp(w, isHTTPS, http.StatusForbidden, map[string]string{"error": "invalid_origin"})
		return true
	}
	sess, ok := m.verifySessionFromRequest(r, isHTTPS, m.cfg.Now())
	if !ok {
		writeJSONResp(w, isHTTPS, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return true
	}
	if isMutatingMethod(r.Method) && !constantTimeEqual(strings.TrimSpace(r.Header.Get("X-CSRF-Token")), sess.CSRF) {
		writeJSONResp(w, isHTTPS, http.StatusForbidden, map[string]string{"error": "invalid_csrf"})
		return true
	}

	switch {
	case p == "/admin/api/state" && r.Method == http.MethodGet:
		m.HandleAdminState(w, r, sess, isHTTPS)
	case p == "/admin/api/fetch" && r.Method == http.MethodPost:
		m.HandleAdminFetch(w, r, sess, isHTTPS)
	case p == "/admin/api/affinity/clear" && r.Method == http.MethodPost:
		m.HandleAdminAffinityClear(w, r, sess, isHTTPS)
	case p == "/admin/api/events/clear" && r.Method == http.MethodPost:
		m.HandleAdminEventsClear(w, r, sess, isHTTPS)
	case p == "/admin/api/grants/revoke" && r.Method == http.MethodPost:
		m.HandleAdminGrantsRevoke(w, r, sess, isHTTPS)
	case p == "/admin/api/mcp/servers" || p == "/admin/api/mcp/connect" || p == "/admin/api/mcp/disconnect" || strings.HasPrefix(p, "/admin/api/mcp/servers/"):
		m.HandleAdminMcpServers(w, r, sess, origin, isHTTPS)
	case p == "/admin/api/telemetry" && (r.Method == http.MethodGet || r.Method == http.MethodPost):
		m.HandleAdminTelemetry(w, r, sess, isHTTPS)
	case p == "/admin/api/tracker-list/refresh" && r.Method == http.MethodPost:
		m.HandleAdminTrackerListRefresh(w, r, sess, isHTTPS)
	default:
		writeJSONResp(w, isHTTPS, http.StatusNotFound, map[string]string{"error": "not_found"})
	}
	return true
}

// HandleAdminPage renders the /admin Control Center or login HTML.
func (m *Manager) HandleAdminPage(w http.ResponseWriter, r *http.Request, origin string) {
	isHTTPS := isHTTPSOrigin(origin) || r.TLS != nil
	sess, ok := m.verifySessionFromRequest(r, isHTTPS, m.cfg.Now())
	if !ok {
		writeHTML(w, isHTTPS, http.StatusOK, renderAdminLoginHTML(m.cfg.ServiceName, "", m.isGitHubConfigured(), strings.TrimSpace(m.cfg.CallerToken) != ""))
		return
	}
	viewer := sess.UserID
	if sess.GitHubLogin != "" {
		viewer = "@" + sess.GitHubLogin
	}
	writeHTML(w, isHTTPS, http.StatusOK, renderAdminDashboardHTML(m.cfg.ServiceName, m.cfg.McpSlug, origin, sess.CSRF, viewer, sess.Role))
}

// HandleAdminLogin authenticates POST /admin/login with per-IP brute-force lockout.
func (m *Manager) HandleAdminLogin(w http.ResponseWriter, r *http.Request, origin string) {
	isHTTPS := isHTTPSOrigin(origin) || r.TLS != nil
	if r.Method == http.MethodGet {
		ApplySecurityHeaders(w, isHTTPS)
		http.Redirect(w, r, "/admin", http.StatusFound)
		return
	}
	span := m.startSpan(r, "edgefetch.admin.login", nil)
	finish := func(status int, success bool) {
		span.SetAttribute("auth.success", success)
		span.SetAttribute("http.response.status_code", status)
		span.End(status >= 200 && status < 400, "")
	}
	if r.Method != http.MethodPost {
		finish(http.StatusMethodNotAllowed, false)
		writeJSONResp(w, isHTTPS, http.StatusMethodNotAllowed, map[string]string{"error": "method_not_allowed"})
		return
	}
	if !m.isSameOriginRequest(r, origin) {
		finish(http.StatusForbidden, false)
		writeJSONResp(w, isHTTPS, http.StatusForbidden, map[string]string{"error": "invalid_origin"})
		return
	}
	now := m.cfg.Now()
	bucket := "admin:" + ResolveClientIP(r, m.cfg.TrustProxy, m.cfg.TrustFly)
	if m.isLoginLocked(bucket, now) {
		w.Header().Set("Retry-After", "600")
		finish(http.StatusTooManyRequests, false)
		writeHTML(w, isHTTPS, http.StatusTooManyRequests, renderAdminLoginHTML(m.cfg.ServiceName, "Too many failed login attempts.", m.isGitHubConfigured(), true))
		return
	}
	formMap, tooBig, ok := parseFormOrJSONBody(w, r, 8192)
	if tooBig || !ok {
		st := http.StatusBadRequest
		if tooBig {
			st = http.StatusRequestEntityTooLarge
		}
		finish(st, false)
		writeHTML(w, isHTTPS, st, renderAdminLoginHTML(m.cfg.ServiceName, "Invalid login payload.", m.isGitHubConfigured(), true))
		return
	}
	callerTok := strings.TrimSpace(m.cfg.CallerToken)
	if callerTok == "" || !constantTimeEqual(strings.TrimSpace(formMap["token"]), callerTok) {
		if m.recordFailedLogin(bucket, now) {
			w.Header().Set("Retry-After", "600")
			finish(http.StatusTooManyRequests, false)
			writeHTML(w, isHTTPS, http.StatusTooManyRequests, renderAdminLoginHTML(m.cfg.ServiceName, "Too many failed login attempts.", m.isGitHubConfigured(), callerTok != ""))
			return
		}
		finish(http.StatusUnauthorized, false)
		writeHTML(w, isHTTPS, http.StatusUnauthorized, renderAdminLoginHTML(m.cfg.ServiceName, "Invalid caller token.", m.isGitHubConfigured(), callerTok != ""))
		return
	}
	m.clearFailedLogin(bucket)
	cookieVal, _ := m.mintAdminCookie(now)
	cookieName := CookieAdminDev
	if isHTTPS {
		cookieName = CookieAdminSecure
	}
	http.SetCookie(w, &http.Cookie{
		Name: cookieName, Value: cookieVal, Path: "/", MaxAge: int(adminSessionTTL.Seconds()),
		HttpOnly: true, Secure: isHTTPS, SameSite: http.SameSiteLaxMode,
	})
	finish(http.StatusFound, true)
	ApplySecurityHeaders(w, isHTTPS)
	http.Redirect(w, r, "/admin", http.StatusFound)
}

// HandleAdminLogout revokes the active session cookie and redirects to /admin.
func (m *Manager) HandleAdminLogout(w http.ResponseWriter, r *http.Request, origin string) {
	isHTTPS := isHTTPSOrigin(origin) || r.TLS != nil
	span := m.startSpan(r, "edgefetch.admin.logout", nil)
	finish := func(status int) {
		span.SetAttribute("http.response.status_code", status)
		span.End(status >= 200 && status < 400, "")
	}
	if !m.isSameOriginRequest(r, origin) {
		finish(http.StatusForbidden)
		writeJSONResp(w, isHTTPS, http.StatusForbidden, map[string]string{"error": "invalid_origin"})
		return
	}
	now := m.cfg.Now()
	sess, ok := m.verifySessionFromRequest(r, isHTTPS, now)
	formMap, _, _ := parseFormOrJSONBody(w, r, 4096)
	csrfCand := strings.TrimSpace(formMap["csrf"])
	if csrfCand == "" {
		csrfCand = strings.TrimSpace(r.Header.Get("X-CSRF-Token"))
	}
	if !ok || !constantTimeEqual(csrfCand, sess.CSRF) {
		finish(http.StatusForbidden)
		writeJSONResp(w, isHTTPS, http.StatusForbidden, map[string]string{"error": "invalid_csrf"})
		return
	}
	expMs := max(sess.ExpMs, now.Add(adminSessionTTL).UnixMilli())
	m.mu.Lock()
	for k, v := range m.st.RevokedSessions {
		if v <= now.UnixMilli() {
			delete(m.st.RevokedSessions, k)
		}
	}
	if sess.SigKey != "" {
		m.st.RevokedSessions[sess.SigKey] = expMs
	}
	if sess.JTI != "" {
		m.st.RevokedSessions["jti:"+sha256B64URL(sess.JTI)] = expMs
	}
	_ = m.saveLocked()
	m.mu.Unlock()

	for _, cname := range []string{CookieAdminSecure, CookieUserSecure, CookieAdminDev, CookieUserDev} {
		http.SetCookie(w, &http.Cookie{Name: cname, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: isHTTPS, SameSite: http.SameSiteLaxMode})
	}
	finish(http.StatusFound)
	ApplySecurityHeaders(w, isHTTPS)
	http.Redirect(w, r, "/admin", http.StatusFound)
}

// HandleAdminState serves GET /admin/api/state.
func (m *Manager) HandleAdminState(w http.ResponseWriter, r *http.Request, sess verifiedSession, isHTTPS bool) {
	var hubSt AdminHubState
	if m.cfg.Callbacks.GetAdminState != nil {
		hubSt, _ = m.cfg.Callbacks.GetAdminState(r.Context())
	}
	if hubSt.AgentsRaw == nil {
		hubSt.AgentsRaw = []any{}
	}
	if hubSt.Affinities == nil {
		hubSt.Affinities = []any{}
	}
	if hubSt.Events == nil {
		hubSt.Events = []any{}
	}
	nowMs := m.cfg.Now().UnixMilli()
	ownerID := sess.EffectiveOwnerID()

	m.mu.Lock()
	grants := make([]map[string]any, 0, len(m.st.Grants))
	for _, g := range m.st.Grants {
		if g.Revoked || g.ExpiresAt <= nowMs || (!sess.IsOwner && g.UserID != ownerID) {
			continue
		}
		grants = append(grants, map[string]any{
			"grantId": g.GrantID, "clientId": g.ClientID, "clientName": g.ClientName,
			"scopes": g.Scopes, "userId": g.UserID, "createdAt": g.CreatedAt, "expiresAt": g.ExpiresAt,
		})
	}
	mcpSummaries := m.listPublicMcpServersLocked(ownerID)
	tel := m.currentTelemetryViewLocked()
	m.mu.Unlock()

	if !sess.IsOwner {
		writeJSONResp(w, isHTTPS, http.StatusOK, map[string]any{
			"ok": true, "connected": hubSt.Connected, "distinctPublicIps": 0, "agents": []any{}, "affinities": []any{},
			"grants": grants, "mcpServers": mcpSummaries, "telemetry": tel, "devTelemetry": tel, "events": []any{},
		})
		return
	}
	upd := m.CheckHubUpdateStatus(r.Context(), hubSt.Agents)
	writeJSONResp(w, isHTTPS, http.StatusOK, map[string]any{
		"ok": true, "connected": hubSt.Connected, "distinctPublicIps": hubSt.DistinctPublicIPs,
		"agents": hubSt.AgentsRaw, "affinities": hubSt.Affinities, "grants": grants, "mcpServers": mcpSummaries,
		"telemetry": tel, "devTelemetry": tel, "trackerList": hubSt.TrackerList, "updateStatus": upd, "events": hubSt.Events,
	})
}

// HandleAdminFetch serves POST /admin/api/fetch.
func (m *Manager) HandleAdminFetch(w http.ResponseWriter, r *http.Request, sess verifiedSession, isHTTPS bool) {
	span := m.startSpan(r, "edgefetch.admin.fetch", nil)
	finish := func(status int) {
		span.SetAttribute("http.response.status_code", status)
		span.End(status >= 200 && status < 400, "")
	}
	if !sess.IsOwner {
		finish(http.StatusForbidden)
		writeJSONResp(w, isHTTPS, http.StatusForbidden, map[string]string{"error": "forbidden_role"})
		return
	}
	buf, tooBig, err := readCappedBody(w, r, 65536)
	if tooBig {
		finish(http.StatusRequestEntityTooLarge)
		writeJSONResp(w, isHTTPS, http.StatusRequestEntityTooLarge, map[string]string{"error": "payload_too_large"})
		return
	}
	req := AdminFetchRequest{RespectRobots: true, IncludeBody: true}
	if err != nil || json.Unmarshal(buf, &req) != nil || strings.TrimSpace(req.URL) == "" {
		finish(http.StatusBadRequest)
		writeJSONResp(w, isHTTPS, http.StatusBadRequest, map[string]string{"error": "missing_url"})
		return
	}
	span.SetAttribute("url.full", otel.SanitizeURL(req.URL))
	if m.cfg.Callbacks.ExecuteAdminFetch == nil {
		finish(http.StatusNotImplemented)
		writeJSONResp(w, isHTTPS, http.StatusNotImplemented, map[string]string{"error": "not_implemented"})
		return
	}
	st, via, outBody, fErr := m.cfg.Callbacks.ExecuteAdminFetch(r.Context(), req)
	if fErr != nil && st == 0 {
		st = http.StatusBadGateway
	}
	if st == 0 {
		st = http.StatusOK
	}
	if via != "" {
		w.Header().Set("X-Crawler-Via", via)
	}
	finish(st)
	if len(outBody) > 0 && json.Valid(outBody) {
		ApplySecurityHeaders(w, isHTTPS)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(st)
		_, _ = w.Write(outBody)
		return
	}
	writeJSONResp(w, isHTTPS, st, map[string]any{"ok": st < 400, "via": via, "body": string(outBody)})
}

// HandleAdminAffinityClear serves POST /admin/api/affinity/clear with a strict 64 KiB body cap.
func (m *Manager) HandleAdminAffinityClear(w http.ResponseWriter, r *http.Request, sess verifiedSession, isHTTPS bool) {
	span := m.startSpan(r, "edgefetch.admin.affinity.clear", nil)
	finish := func(status int) {
		span.SetAttribute("http.response.status_code", status)
		span.End(status >= 200 && status < 400, "")
	}
	if !sess.IsOwner {
		finish(http.StatusForbidden)
		writeJSONResp(w, isHTTPS, http.StatusForbidden, map[string]string{"error": "forbidden_role"})
		return
	}
	buf, tooBig, _ := readCappedBody(w, r, 65536)
	if tooBig {
		finish(http.StatusRequestEntityTooLarge)
		writeJSONResp(w, isHTTPS, http.StatusRequestEntityTooLarge, map[string]string{"error": "payload_too_large"})
		return
	}
	var body struct {
		SiteID string `json:"siteId"`
	}
	if len(strings.TrimSpace(string(buf))) > 0 {
		_ = json.Unmarshal(buf, &body)
	}
	if m.cfg.Callbacks.ClearAffinities != nil {
		_ = m.cfg.Callbacks.ClearAffinities(r.Context(), strings.TrimSpace(body.SiteID))
	}
	finish(http.StatusOK)
	writeJSONResp(w, isHTTPS, http.StatusOK, map[string]bool{"ok": true})
}

// HandleAdminEventsClear serves POST /admin/api/events/clear.
func (m *Manager) HandleAdminEventsClear(w http.ResponseWriter, r *http.Request, sess verifiedSession, isHTTPS bool) {
	span := m.startSpan(r, "edgefetch.admin.events.clear", nil)
	finish := func(status int) {
		span.SetAttribute("http.response.status_code", status)
		span.End(status >= 200 && status < 400, "")
	}
	if !sess.IsOwner {
		finish(http.StatusForbidden)
		writeJSONResp(w, isHTTPS, http.StatusForbidden, map[string]string{"error": "forbidden_role"})
		return
	}
	if _, tooBig, _ := readCappedBody(w, r, 65536); tooBig {
		finish(http.StatusRequestEntityTooLarge)
		writeJSONResp(w, isHTTPS, http.StatusRequestEntityTooLarge, map[string]string{"error": "payload_too_large"})
		return
	}
	if m.cfg.Callbacks.ClearEvents != nil {
		_ = m.cfg.Callbacks.ClearEvents(r.Context())
	}
	finish(http.StatusOK)
	writeJSONResp(w, isHTTPS, http.StatusOK, map[string]bool{"ok": true})
}

// HandleAdminGrantsRevoke serves POST /admin/api/grants/revoke.
func (m *Manager) HandleAdminGrantsRevoke(w http.ResponseWriter, r *http.Request, sess verifiedSession, isHTTPS bool) {
	span := m.startSpan(r, "edgefetch.admin.grants.revoke", nil)
	finish := func(status int) {
		span.SetAttribute("http.response.status_code", status)
		span.End(status >= 200 && status < 400, "")
	}
	buf, tooBig, _ := readCappedBody(w, r, 65536)
	if tooBig {
		finish(http.StatusRequestEntityTooLarge)
		writeJSONResp(w, isHTTPS, http.StatusRequestEntityTooLarge, map[string]string{"error": "payload_too_large"})
		return
	}
	var body struct {
		GrantID string `json:"grantId"`
	}
	_ = json.Unmarshal(buf, &body)
	gid := strings.TrimSpace(body.GrantID)
	if gid == "" {
		finish(http.StatusBadRequest)
		writeJSONResp(w, isHTTPS, http.StatusBadRequest, map[string]string{"error": "missing_grant_id"})
		return
	}
	m.mu.Lock()
	revoked := false
	if g, ok := m.st.Grants[gid]; ok && (sess.IsOwner || g.UserID == sess.EffectiveOwnerID()) {
		revoked = m.revokeGrantLocked(gid)
		_ = m.saveLocked()
	}
	m.mu.Unlock()
	span.SetAttribute("admin.grant_id", gid)
	finish(http.StatusOK)
	writeJSONResp(w, isHTTPS, http.StatusOK, map[string]any{"ok": true, "revoked": revoked})
}
