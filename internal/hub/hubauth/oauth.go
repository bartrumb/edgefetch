package hubauth

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/bartrumb/edgefetch/v2/internal/otel"
)

var (
	rePKCEChallenge = regexp.MustCompile(`^[A-Za-z0-9_-]{43,128}$`)
	rePKCEVerifier  = regexp.MustCompile(`^[A-Za-z0-9._~-]{43,128}$`)
)

func (m *Manager) startOAuthSpan(r *http.Request, op string) (*otel.ActiveSpan, func(int, string)) {
	span := m.startSpan(r, "edgefetch.oauth."+op, map[string]any{"oauth.op": op})
	return span, func(status int, outcome string) {
		span.SetAttribute("http.response.status_code", status)
		span.SetAttribute("oauth.outcome", outcome)
		span.End(status >= 200 && status < 400, "")
	}
}

func oauthJSONErr(w http.ResponseWriter, isHTTPS bool, finish func(int, string), status int, outcome, errCode string) {
	finish(status, outcome)
	writeJSONResp(w, isHTTPS, status, map[string]string{"error": errCode})
}

func oauthHTMLErr(w http.ResponseWriter, isHTTPS bool, finish func(int, string), status int, outcome, msg string) {
	finish(status, outcome)
	writeHTML(w, isHTTPS, status, msg)
}

func serveDiscoveryJSON(w http.ResponseWriter, r *http.Request, origin string, build func(string) map[string]any) {
	origin = strings.TrimRight(strings.TrimSpace(origin), "/")
	isHTTPS := isHTTPSOrigin(origin)
	if r.Method == http.MethodOptions {
		ApplySecurityHeaders(w, isHTTPS)
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method != http.MethodGet {
		writeJSONResp(w, isHTTPS, http.StatusMethodNotAllowed, map[string]string{"error": "method_not_allowed"})
		return
	}
	writeJSONResp(w, isHTTPS, http.StatusOK, build(origin))
}

// HandleOAuthOrWellKnown dispatches OAuth 2.1 and RFC 9728/8414 discovery routes, returning true if handled.
func (m *Manager) HandleOAuthOrWellKnown(w http.ResponseWriter, r *http.Request, origin string) bool {
	switch r.URL.Path {
	case "/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource/mcp":
		m.HandleProtectedResourceMetadata(w, r, origin)
		return true
	case "/.well-known/oauth-authorization-server", "/.well-known/openid-configuration":
		m.HandleAuthServerMetadata(w, r, origin)
		return true
	case "/oauth/register":
		m.HandleRegister(w, r)
		return true
	case "/oauth/authorize":
		m.HandleAuthorize(w, r, origin)
		return true
	case "/oauth/token":
		m.HandleToken(w, r, origin)
		return true
	case "/oauth/revoke":
		m.HandleRevoke(w, r)
		return true
	default:
		return false
	}
}

// HandleProtectedResourceMetadata serves RFC 9728 Protected Resource Metadata.
func (m *Manager) HandleProtectedResourceMetadata(w http.ResponseWriter, r *http.Request, origin string) {
	serveDiscoveryJSON(w, r, origin, func(orig string) map[string]any {
		return map[string]any{
			"resource":                 orig + "/mcp",
			"authorization_servers":    []string{orig},
			"bearer_methods_supported": []string{"header"},
			"scopes_supported":         SupportedScopes,
			"resource_name":            m.cfg.ServiceName,
		}
	})
}

// HandleAuthServerMetadata serves RFC 8414 Authorization Server Metadata.
func (m *Manager) HandleAuthServerMetadata(w http.ResponseWriter, r *http.Request, origin string) {
	serveDiscoveryJSON(w, r, origin, func(orig string) map[string]any {
		return map[string]any{
			"issuer":                                         orig,
			"authorization_endpoint":                         orig + "/oauth/authorize",
			"token_endpoint":                                 orig + "/oauth/token",
			"registration_endpoint":                          orig + "/oauth/register",
			"revocation_endpoint":                            orig + "/oauth/revoke",
			"response_types_supported":                       []string{"code"},
			"response_modes_supported":                       []string{"query"},
			"grant_types_supported":                          []string{"authorization_code", "refresh_token"},
			"token_endpoint_auth_methods_supported":          []string{"none"},
			"code_challenge_methods_supported":               []string{"S256"},
			"authorization_response_iss_parameter_supported": true,
			"scopes_supported":                               SupportedScopes,
		}
	})
}

func (m *Manager) isAllowedRedirectURI(raw string) bool {
	if len(raw) == 0 || len(raw) > 512 || strings.ContainsAny(raw, " \t\r\n") {
		return false
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.Fragment != "" || u.User != nil || strings.Contains(raw, "#") {
		return false
	}
	scheme, host := strings.ToLower(u.Scheme), strings.ToLower(u.Hostname())
	if scheme == "http" {
		return host == "127.0.0.1" || host == "localhost" || host == "::1"
	}
	if scheme != "https" {
		return false
	}
	candOrigin, oErr := formatCanonicalOrigin("https", u.Host)
	if oErr != nil {
		return false
	}
	for _, entry := range m.cfg.RedirectAllowlist {
		rule := strings.TrimSpace(entry)
		if rule == "" {
			continue
		}
		if rule == raw || strings.EqualFold(strings.TrimRight(rule, "/"), candOrigin) {
			return true
		}
		cleanDomain := strings.TrimSuffix(strings.TrimPrefix(strings.ToLower(rule), "*."), ".")
		if !strings.Contains(cleanDomain, "://") && !strings.Contains(cleanDomain, "/") && (host == cleanDomain || strings.HasSuffix(host, "."+cleanDomain)) {
			return true
		}
	}
	return false
}

func matchesRegisteredRedirect(requested string, registered []string) bool {
	if slices.Contains(registered, requested) {
		return true
	}
	reqU, err := url.Parse(requested)
	if err != nil || strings.ToLower(reqU.Scheme) != "http" || !isLoopbackHostname(reqU.Hostname()) {
		return false
	}
	for _, r := range registered {
		regU, rErr := url.Parse(r)
		if rErr == nil && strings.ToLower(regU.Scheme) == "http" &&
			strings.EqualFold(regU.Hostname(), reqU.Hostname()) &&
			regU.Port() == "" && regU.Path == reqU.Path && regU.RawQuery == reqU.RawQuery {
			return true
		}
	}
	return false
}

// HandleRegister implements POST /oauth/register (RFC 7591 Dynamic Client Registration).
func (m *Manager) HandleRegister(w http.ResponseWriter, r *http.Request) {
	isHTTPS := r.TLS != nil || isHTTPSOrigin(m.cfg.PublicOrigin)
	span, finish := m.startOAuthSpan(r, "register")
	if r.Method != http.MethodPost {
		oauthJSONErr(w, isHTTPS, finish, http.StatusMethodNotAllowed, "method_not_allowed", "method_not_allowed")
		return
	}
	now := m.cfg.Now()
	regBucket := "reg:" + ResolveClientIP(r, m.cfg.TrustProxy, m.cfg.TrustFly)
	if m.isLoginLocked(regBucket, now) || m.recordFailedLogin(regBucket, now) {
		w.Header().Set("Retry-After", "600")
		oauthJSONErr(w, isHTTPS, finish, http.StatusTooManyRequests, "rate_limited", "Too many client registrations.")
		return
	}
	buf, tooBig, err := readCappedBody(w, r, 16384)
	if tooBig {
		oauthJSONErr(w, isHTTPS, finish, http.StatusRequestEntityTooLarge, "payload_too_large", "invalid_client_metadata")
		return
	}
	var req struct {
		ClientName   string   `json:"client_name"`
		RedirectURIs []string `json:"redirect_uris"`
	}
	if err != nil || json.Unmarshal(buf, &req) != nil || len(req.RedirectURIs) == 0 || len(req.RedirectURIs) > 10 {
		oauthJSONErr(w, isHTTPS, finish, http.StatusBadRequest, "invalid_redirect_uri", "invalid_redirect_uri")
		return
	}
	for _, u := range req.RedirectURIs {
		if !m.isAllowedRedirectURI(u) {
			oauthJSONErr(w, isHTTPS, finish, http.StatusBadRequest, "invalid_redirect_uri", "invalid_redirect_uri")
			return
		}
	}
	name := strings.TrimSpace(req.ClientName)
	if name == "" {
		name = "MCP Client"
	} else if len(name) > 80 {
		name = name[:80]
	}
	clientID := "mcp_" + randomHex(12)
	m.mu.Lock()
	if len(m.st.Clients) >= 512 {
		activeClients := map[string]bool{}
		for _, g := range m.st.Grants {
			if !g.Revoked {
				activeClients[g.ClientID] = true
			}
		}
		var oldestID string
		var oldestAt int64
		for cid, cl := range m.st.Clients {
			if !activeClients[cid] && (oldestID == "" || cl.CreatedAt < oldestAt) {
				oldestID, oldestAt = cid, cl.CreatedAt
			}
		}
		if oldestID != "" {
			delete(m.st.Clients, oldestID)
		}
	}
	m.st.Clients[clientID] = OAuthClient{ClientID: clientID, ClientName: name, RedirectURIs: req.RedirectURIs, CreatedAt: now.UnixMilli()}
	_ = m.saveLocked()
	m.mu.Unlock()

	span.SetAttribute("oauth.client_id", clientID)
	finish(http.StatusCreated, "registered")
	writeJSONResp(w, isHTTPS, http.StatusCreated, map[string]any{
		"client_id":                  clientID,
		"client_id_issued_at":        now.Unix(),
		"client_name":                name,
		"redirect_uris":              req.RedirectURIs,
		"grant_types":                []string{"authorization_code", "refresh_token"},
		"response_types":             []string{"code"},
		"token_endpoint_auth_method": "none",
	})
}

func parseOAuthScopes(raw string) ([]string, bool) {
	if strings.TrimSpace(raw) == "" {
		return append([]string(nil), DefaultScopes...), true
	}
	var out []string
	for _, tok := range strings.Fields(raw) {
		if tok == "offline_access" {
			continue
		}
		if !slices.Contains(SupportedScopes, tok) {
			return nil, false
		}
		if !slices.Contains(out, tok) {
			out = append(out, tok)
		}
	}
	if len(out) == 0 {
		return append([]string(nil), DefaultScopes...), true
	}
	return out, true
}

func redirectWithOAuthParams(w http.ResponseWriter, r *http.Request, isHTTPS bool, redirectURI, k, v, state string) {
	cb, _ := url.Parse(redirectURI)
	q := cb.Query()
	q.Set(k, v)
	if state != "" {
		q.Set("state", state)
	}
	cb.RawQuery = q.Encode()
	ApplySecurityHeaders(w, isHTTPS)
	http.Redirect(w, r, cb.String(), http.StatusFound)
}

// HandleAuthorize serves GET and POST /oauth/authorize (OAuth 2.1 + PKCE S256 consent).
func (m *Manager) HandleAuthorize(w http.ResponseWriter, r *http.Request, origin string) {
	origin = strings.TrimRight(strings.TrimSpace(origin), "/")
	isHTTPS := isHTTPSOrigin(origin)
	csrfCookieName := CookieOAuthCSRFDev
	if isHTTPS {
		csrfCookieName = CookieOAuthCSRFSecure
	}
	span, finish := m.startOAuthSpan(r, "authorize")
	now := m.cfg.Now()

	if r.Method == http.MethodGet {
		q := r.URL.Query()
		clientID, redirectURI, challenge := strings.TrimSpace(q.Get("client_id")), strings.TrimSpace(q.Get("redirect_uri")), strings.TrimSpace(q.Get("code_challenge"))
		m.mu.Lock()
		client, exists := m.st.Clients[clientID]
		m.mu.Unlock()
		scopes, scopesOK := parseOAuthScopes(q.Get("scope"))
		resURI, resOK := normalizeOAuthResource(q.Get("resource"), origin)
		if !exists || redirectURI == "" || !m.isAllowedRedirectURI(redirectURI) ||
			!matchesRegisteredRedirect(redirectURI, client.RedirectURIs) ||
			strings.TrimSpace(q.Get("response_type")) != "code" ||
			strings.TrimSpace(q.Get("code_challenge_method")) != "S256" ||
			!rePKCEChallenge.MatchString(challenge) || !scopesOK || !resOK {
			oauthHTMLErr(w, isHTTPS, finish, http.StatusBadRequest, "invalid_request", "Invalid OAuth 2.1 authorization request.")
			return
		}
		csrf := randomB64URL(24)
		sc := sealedConsent{
			ClientID: client.ClientID, ClientName: client.ClientName, RedirectURI: redirectURI,
			CodeChallenge: challenge, Scopes: scopes, State: q.Get("state"),
			Resource: resURI, CSRF: csrf, Exp: now.Add(10 * time.Minute).UnixMilli(),
		}
		payloadBytes, _ := json.Marshal(sc)
		payloadB64 := base64.RawURLEncoding.EncodeToString(payloadBytes)
		sealed := payloadB64 + "." + hmacB64URL("oauth-consent:"+m.signingSecret, payloadB64)
		sess, hasSess := m.verifySessionFromRequest(r, isHTTPS, now)
		ghLoginURL := ""
		if m.isGitHubConfigured() {
			ghLoginURL = "/admin/auth/github?return_to=" + url.QueryEscape(r.URL.RequestURI())
		}
		http.SetCookie(w, &http.Cookie{Name: csrfCookieName, Value: csrf, Path: "/", MaxAge: 600, HttpOnly: true, Secure: isHTTPS, SameSite: http.SameSiteLaxMode})
		span.SetAttribute("oauth.client_id", client.ClientID)
		finish(http.StatusOK, "consent_rendered")
		v := oauthConsentView{ServiceName: m.cfg.ServiceName, ClientName: client.ClientName, RedirectURI: redirectURI, Scopes: scopes, Sealed: sealed, CSRF: csrf}
		v.SignedInUser, v.HasSession, v.GitHubURL = sess.GitHubLogin, hasSess && sess.Kind == "github", ghLoginURL
		writeHTML(w, isHTTPS, http.StatusOK, renderOAuthConsentHTML(v))
		return
	}

	if r.Method != http.MethodPost {
		oauthJSONErr(w, isHTTPS, finish, http.StatusMethodNotAllowed, "method_not_allowed", "method_not_allowed")
		return
	}
	if !m.isSameOriginRequest(r, origin) {
		oauthHTMLErr(w, isHTTPS, finish, http.StatusForbidden, "invalid_origin", "Cross-origin authorization rejected.")
		return
	}
	formMap, tooBig, ok := parseFormOrJSONBody(w, r, 32768)
	if tooBig || !ok {
		st := http.StatusBadRequest
		if tooBig {
			st = http.StatusRequestEntityTooLarge
		}
		oauthHTMLErr(w, isHTTPS, finish, st, "invalid_request", "Invalid authorization form.")
		return
	}
	cookieCSRF := readCookieVal(r, csrfCookieName)
	if cookieCSRF == "" && !isHTTPS {
		cookieCSRF = readCookieVal(r, CookieOAuthCSRFSecure)
	}
	sealedRaw := formMap["sealed"]
	dot := strings.IndexByte(sealedRaw, '.')
	if dot <= 0 || !constantTimeEqual(sealedRaw[dot+1:], hmacB64URL("oauth-consent:"+m.signingSecret, sealedRaw[:dot])) {
		oauthHTMLErr(w, isHTTPS, finish, http.StatusBadRequest, "invalid_csrf", "Invalid consent signature.")
		return
	}
	rawConsent, err := base64.RawURLEncoding.DecodeString(sealedRaw[:dot])
	var sc sealedConsent
	if err != nil || json.Unmarshal(rawConsent, &sc) != nil || sc.Exp <= now.UnixMilli() ||
		!constantTimeEqual(cookieCSRF, sc.CSRF) || !constantTimeEqual(formMap["csrf"], sc.CSRF) {
		oauthHTMLErr(w, isHTTPS, finish, http.StatusBadRequest, "invalid_csrf", "Expired or invalid CSRF token.")
		return
	}
	if formMap["decision"] == "deny" {
		finish(http.StatusFound, "access_denied")
		redirectWithOAuthParams(w, r, isHTTPS, sc.RedirectURI, "error", "access_denied", sc.State)
		return
	}

	clientBucket := "oauth:" + ResolveClientIP(r, m.cfg.TrustProxy, m.cfg.TrustFly)
	if m.isLoginLocked(clientBucket, now) {
		w.Header().Set("Retry-After", "600")
		oauthHTMLErr(w, isHTTPS, finish, http.StatusTooManyRequests, "rate_limited", "Too many failed attempts.")
		return
	}
	userID, role, authed := "owner", "owner", false
	sess, hasSess := m.verifySessionFromRequest(r, isHTTPS, now)
	suppliedTok := strings.TrimSpace(formMap["owner_token"])
	if suppliedTok == "" {
		suppliedTok = strings.TrimSpace(formMap["token"])
	}
	if suppliedTok != "" && (constantTimeEqual(suppliedTok, strings.TrimSpace(m.cfg.CallerToken)) ||
		constantTimeEqual(suppliedTok, strings.TrimSpace(m.cfg.McpToken))) {
		authed = true
		m.clearFailedLogin(clientBucket)
	} else if hasSess && sess.Kind == "github" {
		authed, userID, role = true, sess.UserID, sess.Role
	}
	if !authed {
		if m.recordFailedLogin(clientBucket, now) {
			w.Header().Set("Retry-After", "600")
			oauthHTMLErr(w, isHTTPS, finish, http.StatusTooManyRequests, "rate_limited", "Too many failed attempts.")
			return
		}
		oauthHTMLErr(w, isHTTPS, finish, http.StatusUnauthorized, "unauthorized", "Invalid token.")
		return
	}

	rawCode := "efc_" + randomB64URL(32)
	codeRec := oauthCodeRecord{CodeHash: sha256B64URL(rawCode), ClientID: sc.ClientID, ClientName: sc.ClientName, RedirectURI: sc.RedirectURI}
	codeRec.CodeChallenge, codeRec.Scopes, codeRec.Resource = sc.CodeChallenge, sc.Scopes, sc.Resource
	codeRec.UserID, codeRec.Role, codeRec.ExpiresAt = userID, role, now.Add(oauthCodeTTL).UnixMilli()
	m.mu.Lock()
	m.st.Codes[codeRec.CodeHash] = codeRec
	_ = m.saveLocked()
	m.mu.Unlock()

	http.SetCookie(w, &http.Cookie{Name: csrfCookieName, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: isHTTPS, SameSite: http.SameSiteLaxMode})
	span.SetAttribute("oauth.client_id", sc.ClientID)
	finish(http.StatusFound, "approved")
	redirectWithOAuthParams(w, r, isHTTPS, sc.RedirectURI, "code", rawCode, sc.State)
}

func (m *Manager) issueAccessTokenLocked(grantID, clientID, userID, role, resource string, scopes []string, nowMs int64) string {
	tok := "efa_" + randomB64URL(32)
	at := oauthAccessToken{TokenHash: sha256B64URL(tok), GrantID: grantID, ClientID: clientID, UserID: userID, Role: role}
	at.Scopes, at.Resource, at.CreatedAt, at.ExpiresAt = append([]string(nil), scopes...), resource, nowMs, nowMs+accessTokenTTL.Milliseconds()
	m.st.AccessTokens[at.TokenHash] = at
	return tok
}

func writeTokenSuccess(w http.ResponseWriter, isHTTPS bool, accessTok, refreshTok string, scopes []string) {
	writeJSONResp(w, isHTTPS, http.StatusOK, map[string]any{
		"access_token":  accessTok,
		"token_type":    "Bearer",
		"expires_in":    int(accessTokenTTL.Seconds()),
		"refresh_token": refreshTok,
		"scope":         strings.Join(scopes, " "),
	})
}

// HandleToken implements POST /oauth/token (authorization_code + rotating refresh_token).
func (m *Manager) HandleToken(w http.ResponseWriter, r *http.Request, origin string) {
	origin = strings.TrimRight(strings.TrimSpace(origin), "/")
	isHTTPS := isHTTPSOrigin(origin)
	span, finish := m.startOAuthSpan(r, "token")
	if r.Method != http.MethodPost {
		oauthJSONErr(w, isHTTPS, finish, http.StatusMethodNotAllowed, "method_not_allowed", "method_not_allowed")
		return
	}
	params, tooBig, ok := parseFormOrJSONBody(w, r, 32768)
	if tooBig || !ok {
		st := http.StatusBadRequest
		if tooBig {
			st = http.StatusRequestEntityTooLarge
		}
		oauthJSONErr(w, isHTTPS, finish, st, "invalid_request", "invalid_request")
		return
	}
	grantType := strings.TrimSpace(params["grant_type"])
	span.SetAttribute("oauth.grant_type", grantType)
	nowMs := m.cfg.Now().UnixMilli()

	switch grantType {
	case "authorization_code":
		code, verifier := strings.TrimSpace(params["code"]), strings.TrimSpace(params["code_verifier"])
		clientID, redirectURI := strings.TrimSpace(params["client_id"]), strings.TrimSpace(params["redirect_uri"])
		if code == "" || clientID == "" || redirectURI == "" || !rePKCEVerifier.MatchString(verifier) {
			oauthJSONErr(w, isHTTPS, finish, http.StatusBadRequest, "invalid_request", "invalid_request")
			return
		}
		codeHash := sha256B64URL(code)
		m.mu.Lock()
		rec, exists := m.st.Codes[codeHash]
		if !exists || rec.Consumed || rec.ExpiresAt <= nowMs {
			m.mu.Unlock()
			oauthJSONErr(w, isHTTPS, finish, http.StatusBadRequest, "invalid_grant", "invalid_grant")
			return
		}
		rec.Consumed = true
		m.st.Codes[codeHash] = rec
		if rec.ClientID != clientID || rec.RedirectURI != redirectURI || !constantTimeEqual(sha256B64URL(verifier), rec.CodeChallenge) {
			_ = m.saveLocked()
			m.mu.Unlock()
			oauthJSONErr(w, isHTTPS, finish, http.StatusBadRequest, "invalid_grant", "invalid_grant")
			return
		}
		if rawRes := strings.TrimSpace(params["resource"]); rawRes != "" {
			if normRes, resOK := normalizeOAuthResource(rawRes, origin); !resOK || (rec.Resource != "" && normRes != rec.Resource) {
				_ = m.saveLocked()
				m.mu.Unlock()
				oauthJSONErr(w, isHTTPS, finish, http.StatusBadRequest, "invalid_target", "invalid_target")
				return
			}
		}
		grantID, secret := "efg_"+randomHex(12), randomB64URL(24)
		refreshTok := fmt.Sprintf("efr_%s.1.%s", grantID, secret)
		g := &OAuthGrant{GrantID: grantID, ClientID: rec.ClientID, ClientName: rec.ClientName, UserID: rec.UserID, Role: rec.Role, CurrentGen: 1}
		g.Scopes, g.Resource, g.RefreshSecretHash = append([]string(nil), rec.Scopes...), rec.Resource, sha256B64URL(secret)
		g.CreatedAt, g.ExpiresAt = nowMs, nowMs+refreshTokenTTL.Milliseconds()
		m.st.Grants[grantID] = g
		accessTok := m.issueAccessTokenLocked(grantID, rec.ClientID, rec.UserID, rec.Role, rec.Resource, rec.Scopes, nowMs)
		_ = m.saveLocked()
		m.mu.Unlock()

		span.SetAttribute("oauth.client_id", rec.ClientID)
		span.SetAttribute("oauth.grant_id", grantID)
		finish(http.StatusOK, "issued")
		writeTokenSuccess(w, isHTTPS, accessTok, refreshTok, rec.Scopes)

	case "refresh_token":
		grantID, gen, secret, parsedOK := parseRefreshToken(strings.TrimSpace(params["refresh_token"]))
		clientID := strings.TrimSpace(params["client_id"])
		if !parsedOK || clientID == "" {
			oauthJSONErr(w, isHTTPS, finish, http.StatusBadRequest, "invalid_grant", "invalid_grant")
			return
		}
		m.mu.Lock()
		grant, exists := m.st.Grants[grantID]
		if !exists || grant.Revoked || grant.ExpiresAt <= nowMs {
			m.mu.Unlock()
			oauthJSONErr(w, isHTTPS, finish, http.StatusBadRequest, "invalid_grant", "invalid_grant")
			return
		}
		// T2-C1 step 3: verify client_id BEFORE consuming or revoking!
		if grant.ClientID != clientID {
			m.mu.Unlock()
			oauthJSONErr(w, isHTTPS, finish, http.StatusBadRequest, "invalid_client", "invalid_grant")
			return
		}
		// T2-C1 step 5: replay of rotated generation revokes ENTIRE grant & all efa_* tokens!
		if gen < grant.CurrentGen {
			m.revokeGrantLocked(grantID)
			_ = m.saveLocked()
			m.mu.Unlock()
			span.SetAttribute("oauth.grant_id", grantID)
			span.SetAttribute("oauth.replay_detected", true)
			oauthJSONErr(w, isHTTPS, finish, http.StatusBadRequest, "replay_detected", "invalid_grant")
			return
		}
		if gen != grant.CurrentGen || !constantTimeEqual(sha256B64URL(secret), grant.RefreshSecretHash) {
			m.mu.Unlock()
			oauthJSONErr(w, isHTTPS, finish, http.StatusBadRequest, "invalid_grant", "invalid_grant")
			return
		}
		newGen, newSecret := grant.CurrentGen+1, randomB64URL(24)
		newRefresh := fmt.Sprintf("efr_%s.%d.%s", grantID, newGen, newSecret)
		grant.CurrentGen, grant.RefreshSecretHash, grant.ExpiresAt = newGen, sha256B64URL(newSecret), nowMs+refreshTokenTTL.Milliseconds()
		for h, at := range m.st.AccessTokens {
			if at.GrantID == grantID {
				delete(m.st.AccessTokens, h)
			}
		}
		scopesCopy := append([]string(nil), grant.Scopes...)
		newAccess := m.issueAccessTokenLocked(grantID, grant.ClientID, grant.UserID, grant.Role, grant.Resource, scopesCopy, nowMs)
		_ = m.saveLocked()
		m.mu.Unlock()

		span.SetAttribute("oauth.grant_id", grantID)
		finish(http.StatusOK, "rotated")
		writeTokenSuccess(w, isHTTPS, newAccess, newRefresh, scopesCopy)

	default:
		oauthJSONErr(w, isHTTPS, finish, http.StatusBadRequest, "unsupported_grant_type", "unsupported_grant_type")
	}
}

func parseRefreshToken(raw string) (grantID string, gen int, secret string, ok bool) {
	if !strings.HasPrefix(raw, "efr_") {
		return "", 0, "", false
	}
	parts := strings.Split(strings.TrimPrefix(raw, "efr_"), ".")
	if len(parts) != 3 || parts[0] == "" || parts[2] == "" {
		return "", 0, "", false
	}
	g, err := strconv.Atoi(parts[1])
	if err != nil || g < 1 {
		return "", 0, "", false
	}
	return parts[0], g, parts[2], true
}

func (m *Manager) revokeGrantLocked(grantID string) bool {
	g, exists := m.st.Grants[grantID]
	if !exists {
		return false
	}
	wasActive := !g.Revoked
	g.Revoked = true
	for h, at := range m.st.AccessTokens {
		if at.GrantID == grantID {
			delete(m.st.AccessTokens, h)
		}
	}
	return wasActive
}

// HandleRevoke implements POST /oauth/revoke (RFC 7009).
func (m *Manager) HandleRevoke(w http.ResponseWriter, r *http.Request) {
	isHTTPS := r.TLS != nil || isHTTPSOrigin(m.cfg.PublicOrigin)
	_, finish := m.startOAuthSpan(r, "revoke")
	if r.Method != http.MethodPost {
		oauthJSONErr(w, isHTTPS, finish, http.StatusMethodNotAllowed, "method_not_allowed", "method_not_allowed")
		return
	}
	params, tooBig, _ := parseFormOrJSONBody(w, r, 32768)
	if tooBig {
		oauthJSONErr(w, isHTTPS, finish, http.StatusRequestEntityTooLarge, "payload_too_large", "invalid_request")
		return
	}
	if tok := strings.TrimSpace(params["token"]); tok != "" {
		m.mu.Lock()
		if strings.HasPrefix(tok, "efa_") {
			if at, ok := m.st.AccessTokens[sha256B64URL(tok)]; ok {
				m.revokeGrantLocked(at.GrantID)
				_ = m.saveLocked()
			}
		} else if grantID, gen, secret, ok := parseRefreshToken(tok); ok {
			if g, gOK := m.st.Grants[grantID]; gOK && gen == g.CurrentGen && constantTimeEqual(sha256B64URL(secret), g.RefreshSecretHash) {
				m.revokeGrantLocked(grantID)
				_ = m.saveLocked()
			}
		}
		m.mu.Unlock()
	}
	finish(http.StatusOK, "revoked")
	writeJSONResp(w, isHTTPS, http.StatusOK, map[string]bool{"ok": true})
}
