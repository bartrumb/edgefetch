package hubauth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	ghJWTIssuer   = "urn:edgefetch:hub"
	ghJWTAudience = "urn:edgefetch:admin"
	ghStateTTL    = 10 * time.Minute
)

var (
	reGitHubLogin     = regexp.MustCompile(`(?i)^[a-z0-9](?:[a-z0-9-]{0,38})$`)
	reGitHubNumericID = regexp.MustCompile(`^[1-9][0-9]{0,19}$`)
)

// GitHubUser stores a multi-user GitHub identity and role in oauth_state.json.
type GitHubUser struct {
	UserID           string `json:"userId"`
	GitHubID         string `json:"githubId"`
	GitHubLogin      string `json:"githubLogin"`
	AvatarURL        string `json:"avatarUrl,omitempty"`
	Role             string `json:"role"` // "owner" or "member"
	SessionEpoch     int    `json:"sessionEpoch"`
	Disabled         bool   `json:"disabled,omitempty"`
	AdmittedVia      string `json:"admittedVia,omitempty"`
	AdmittedOrg      string `json:"admittedOrg,omitempty"`
	EncryptedGHToken string `json:"encryptedGhToken,omitempty"`
	CreatedAt        int64  `json:"createdAt"`
	LastLoginAt      int64  `json:"lastLoginAt"`
}

// GitHubAllowlist holds parsed GITHUB_ALLOWED_USERS entries.
type GitHubAllowlist struct {
	Users   map[string]bool
	UserIDs map[string]bool
	Orgs    map[string]bool
}

// NormalizeSignupMode normalizes SIGNUP_MODE ("closed" default, "allowlist", "open").
func NormalizeSignupMode(raw, allowedUsers string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "open":
		return "open"
	case "allowlist":
		return "allowlist"
	case "closed":
		return "closed"
	default:
		if strings.TrimSpace(allowedUsers) != "" {
			return "allowlist"
		}
		return "closed"
	}
}

// ParseGitHubAllowlist parses comma/whitespace-separated logins, id:<num>, and @org entries.
func ParseGitHubAllowlist(raw string) GitHubAllowlist {
	out := GitHubAllowlist{Users: make(map[string]bool), UserIDs: make(map[string]bool), Orgs: make(map[string]bool)}
	for _, part := range strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t' || r == '\r' || r == '\n'
	}) {
		tok := strings.ToLower(strings.TrimSpace(part))
		switch {
		case tok == "":
		case strings.HasPrefix(tok, "@"):
			if org := tok[1:]; reGitHubLogin.MatchString(org) {
				out.Orgs[org] = true
			}
		case strings.HasPrefix(tok, "id:"):
			if id := tok[3:]; reGitHubNumericID.MatchString(id) {
				out.UserIDs[id] = true
			}
		case strings.HasPrefix(tok, "login:"):
			if login := tok[6:]; reGitHubLogin.MatchString(login) {
				out.Users[login] = true
			}
		default:
			if strings.Trim(tok, "0123456789") != "" && reGitHubLogin.MatchString(tok) {
				out.Users[tok] = true
			}
		}
	}
	return out
}

func (m *Manager) isGitHubConfigured() bool {
	return strings.TrimSpace(m.cfg.GitHub.ClientID) != "" && len(strings.TrimSpace(m.cfg.GitHub.ClientSecret)) >= 16
}

func deriveGitHubTokenAESKey(secret string, salt []byte, userID string) ([]byte, error) {
	if len(strings.TrimSpace(secret)) < 16 {
		return nil, errors.New("session secret must be at least 16 characters")
	}
	return hkdf.Key(sha256.New, []byte(secret), salt, fmt.Sprintf("edgefetch-gh-org-token-v1:%d:%s", len(userID), userID), 32)
}

// SealGitHubToken encrypts a GitHub user token using HKDF-SHA256 + AES-256-GCM ("ght1.<salt>.<iv>.<ct>").
func SealGitHubToken(secret, userID, plainToken string) (string, error) {
	tok := strings.TrimSpace(plainToken)
	if tok == "" || strings.ContainsAny(tok, "\r\n\x00") {
		return "", errors.New("invalid GitHub token")
	}
	salt, iv := make([]byte, 16), make([]byte, 12)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	if _, err := rand.Read(iv); err != nil {
		return "", err
	}
	key, err := deriveGitHubTokenAESKey(secret, salt, userID)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	aad := fmt.Appendf(nil, "gh-org-token:%d:%s", len(userID), userID)
	ct := gcm.Seal(nil, iv, []byte(tok), aad)
	return fmt.Sprintf("ght1.%s.%s.%s",
		base64.RawURLEncoding.EncodeToString(salt),
		base64.RawURLEncoding.EncodeToString(iv),
		base64.RawURLEncoding.EncodeToString(ct),
	), nil
}

// OpenGitHubToken decrypts and authenticates a "ght1." AES-256-GCM GitHub token ciphertext.
func OpenGitHubToken(secret, userID, ciphertext string) (string, error) {
	parts := strings.Split(ciphertext, ".")
	if len(parts) != 4 || parts[0] != "ght1" {
		return "", errors.New("malformed ght1 envelope")
	}
	salt, e1 := base64.RawURLEncoding.DecodeString(parts[1])
	iv, e2 := base64.RawURLEncoding.DecodeString(parts[2])
	ct, e3 := base64.RawURLEncoding.DecodeString(parts[3])
	if e1 != nil || e2 != nil || e3 != nil || len(salt) != 16 || len(iv) != 12 || len(ct) < 17 {
		return "", errors.New("invalid ght1 envelope parameters")
	}
	key, err := deriveGitHubTokenAESKey(secret, salt, userID)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	plain, err := gcm.Open(nil, iv, ct, fmt.Appendf(nil, "gh-org-token:%d:%s", len(userID), userID))
	if err != nil || !utf8.Valid(plain) {
		return "", errors.New("ght1 decryption failed")
	}
	tok := strings.TrimSpace(string(plain))
	if tok == "" || strings.ContainsAny(tok, "\r\n\x00") {
		return "", errors.New("invalid decrypted token")
	}
	return tok, nil
}

func deriveSessionJWTKey(secret string) ([]byte, error) {
	return hkdf.Key(sha256.New, []byte(secret), []byte("edgefetch-v2.7-session-salt"), "edgefetch-admin-jwt-hs256-v1", 32)
}

type sessionJWTClaims struct {
	Sub    string `json:"sub"`
	Role   string `json:"role"`
	Auth   string `json:"auth"`
	Login  string `json:"login,omitempty"`
	Avatar string `json:"avatar,omitempty"`
	CSRF   string `json:"csrf"`
	JTI    string `json:"jti"`
	Epoch  int    `json:"ep"`
	Iss    string `json:"iss"`
	Aud    string `json:"aud"`
	Iat    int64  `json:"iat"`
	Exp    int64  `json:"exp"`
}

// MintGitHubSessionJWT mints an HS256 JWT derived via HKDF-SHA256 from secret.
func MintGitHubSessionJWT(secret string, u GitHubUser, now time.Time, ttl time.Duration) (token, jti, csrf string, err error) {
	key, err := deriveSessionJWTKey(secret)
	if err != nil {
		return "", "", "", err
	}
	jti, csrf = "jti_"+randomB64URL(18), randomHex(20)
	hdrB64 := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	claimsBytes, err := json.Marshal(sessionJWTClaims{
		Sub: u.UserID, Role: u.Role, Auth: "github", Login: u.GitHubLogin, Avatar: u.AvatarURL,
		CSRF: csrf, JTI: jti, Epoch: max(u.SessionEpoch, 1), Iss: ghJWTIssuer, Aud: ghJWTAudience,
		Iat: now.Unix(), Exp: now.Add(ttl).Unix(),
	})
	if err != nil {
		return "", "", "", err
	}
	signingInput := hdrB64 + "." + base64.RawURLEncoding.EncodeToString(claimsBytes)
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(signingInput))
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), jti, csrf, nil
}

// VerifyGitHubSessionJWT verifies an HS256 session JWT against secret and now.
func VerifyGitHubSessionJWT(token, secret string, now time.Time) (sessionJWTClaims, bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 || secret == "" {
		return sessionJWTClaims{}, false
	}
	hdrRaw, err := base64.RawURLEncoding.DecodeString(parts[0])
	var hdr struct {
		Alg string `json:"alg"`
	}
	if err != nil || json.Unmarshal(hdrRaw, &hdr) != nil || hdr.Alg != "HS256" {
		return sessionJWTClaims{}, false
	}
	key, err := deriveSessionJWTKey(secret)
	if err != nil {
		return sessionJWTClaims{}, false
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(parts[0] + "." + parts[1]))
	if subtle.ConstantTimeCompare([]byte(parts[2]), []byte(base64.RawURLEncoding.EncodeToString(mac.Sum(nil)))) != 1 {
		return sessionJWTClaims{}, false
	}
	payloadRaw, err := base64.RawURLEncoding.DecodeString(parts[1])
	var c sessionJWTClaims
	if err != nil || json.Unmarshal(payloadRaw, &c) != nil {
		return sessionJWTClaims{}, false
	}
	if c.Iss != ghJWTIssuer || c.Aud != ghJWTAudience || c.Sub == "" || c.JTI == "" || len(c.CSRF) < 16 || c.Exp <= now.Unix() {
		return sessionJWTClaims{}, false
	}
	if c.Role != "owner" && c.Role != "member" {
		return sessionJWTClaims{}, false
	}
	return c, true
}

type sealedGHState struct {
	State        string `json:"state"`
	Nonce        string `json:"nonce"`
	CodeVerifier string `json:"codeVerifier"`
	ReturnTo     string `json:"returnTo"`
	Exp          int64  `json:"exp"`
}

func sanitizeReturnTo(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" || !strings.HasPrefix(s, "/") || strings.HasPrefix(s, "//") || strings.HasPrefix(s, `/\`) || strings.ContainsAny(s, "\r\n\x00") {
		return "/admin"
	}
	pathPart := s
	if q := strings.IndexByte(s, '?'); q >= 0 {
		pathPart = s[:q]
	}
	if pathPart == "/oauth/authorize" {
		if len(s) > 1024 {
			return s[:1024]
		}
		return s
	}
	return "/admin"
}

// HandleGitHubStart initiates GET /admin/auth/github PKCE + state redirect.
func (m *Manager) HandleGitHubStart(w http.ResponseWriter, r *http.Request, origin string) {
	origin = strings.TrimRight(strings.TrimSpace(origin), "/")
	isHTTPS := isHTTPSOrigin(origin)
	if !m.isGitHubConfigured() {
		writeJSONResp(w, isHTTPS, http.StatusServiceUnavailable, map[string]string{"error": "github_oauth_not_configured"})
		return
	}
	ownerID, ownerLogin := strings.TrimSpace(m.cfg.GitHub.OwnerID), strings.TrimSpace(m.cfg.GitHub.OwnerLogin)
	if (ownerID != "" && !reGitHubNumericID.MatchString(ownerID)) || (ownerID == "" && ownerLogin != "") {
		writeJSONResp(w, isHTTPS, http.StatusServiceUnavailable, map[string]string{"error": "owner_id_required"})
		return
	}
	now := m.cfg.Now()
	verifier, state := randomB64URL(32), randomB64URL(24)
	rawState, _ := json.Marshal(sealedGHState{
		State: state, Nonce: randomB64URL(18), CodeVerifier: verifier,
		ReturnTo: sanitizeReturnTo(r.URL.Query().Get("return_to")), Exp: now.Add(ghStateTTL).UnixMilli(),
	})
	payloadB64 := base64.RawURLEncoding.EncodeToString(rawState)
	cookieName := CookieGHStateDev
	if isHTTPS {
		cookieName = CookieGHStateSecure
	}
	http.SetCookie(w, &http.Cookie{
		Name: cookieName, Value: payloadB64 + "." + hmacB64URL("gh-oauth-state:"+m.signingSecret, payloadB64),
		Path: "/", MaxAge: int(ghStateTTL.Seconds()), HttpOnly: true, Secure: isHTTPS, SameSite: http.SameSiteLaxMode,
	})
	ghScope := "read:user"
	if len(ParseGitHubAllowlist(m.cfg.GitHub.AllowedUsers).Orgs) > 0 {
		ghScope = "read:user read:org"
	}
	authEndpoint := strings.TrimSpace(m.cfg.GitHub.AuthorizeURL)
	if authEndpoint == "" {
		authEndpoint = "https://github.com/login/oauth/authorize"
	}
	u, _ := url.Parse(authEndpoint)
	q := u.Query()
	q.Set("client_id", strings.TrimSpace(m.cfg.GitHub.ClientID))
	q.Set("redirect_uri", origin+"/admin/auth/github/callback")
	q.Set("response_type", "code")
	q.Set("scope", ghScope)
	q.Set("state", state)
	q.Set("code_challenge", sha256B64URL(verifier))
	q.Set("code_challenge_method", "S256")
	u.RawQuery = q.Encode()
	ApplySecurityHeaders(w, isHTTPS)
	http.Redirect(w, r, u.String(), http.StatusFound)
}

// HandleGitHubCallback completes GET /admin/auth/github/callback, enforcing founder pinning and SIGNUP_MODE.
func (m *Manager) HandleGitHubCallback(w http.ResponseWriter, r *http.Request, origin string) {
	origin = strings.TrimRight(strings.TrimSpace(origin), "/")
	isHTTPS := isHTTPSOrigin(origin)
	if !m.isGitHubConfigured() {
		writeJSONResp(w, isHTTPS, http.StatusServiceUnavailable, map[string]string{"error": "github_oauth_not_configured"})
		return
	}
	stateCookieName := CookieGHStateDev
	if isHTTPS {
		stateCookieName = CookieGHStateSecure
	}
	clearState := func() {
		http.SetCookie(w, &http.Cookie{Name: stateCookieName, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: isHTTPS, SameSite: http.SameSiteLaxMode})
	}
	failHTML := func(status int, title, msg string) {
		clearState()
		writeHTML(w, isHTTPS, status, renderGitHubErrorHTML(m.cfg.ServiceName, title, msg))
	}
	ownerID, ownerLogin := strings.TrimSpace(m.cfg.GitHub.OwnerID), strings.ToLower(strings.TrimSpace(m.cfg.GitHub.OwnerLogin))
	if (ownerID != "" && !reGitHubNumericID.MatchString(ownerID)) || (ownerID == "" && ownerLogin != "") {
		failHTML(http.StatusServiceUnavailable, "Owner ID Required", "Configure GITHUB_OWNER_ID to your numeric GitHub user ID.")
		return
	}
	now := m.cfg.Now()
	rawCookie := readCookieVal(r, stateCookieName)
	dot := strings.IndexByte(rawCookie, '.')
	if dot <= 0 || !constantTimeEqual(rawCookie[dot+1:], hmacB64URL("gh-oauth-state:"+m.signingSecret, rawCookie[:dot])) {
		failHTML(http.StatusBadRequest, "Invalid Sign-In State", "Missing or invalid OAuth state cookie.")
		return
	}
	decoded, err := base64.RawURLEncoding.DecodeString(rawCookie[:dot])
	var st sealedGHState
	code := strings.TrimSpace(r.URL.Query().Get("code"))
	if err != nil || json.Unmarshal(decoded, &st) != nil || st.Exp <= now.UnixMilli() || code == "" || !constantTimeEqual(r.URL.Query().Get("state"), st.State) {
		failHTML(http.StatusBadRequest, "Invalid OAuth Callback", "Expired state or callback mismatch.")
		return
	}

	replayKey := "gh_state:" + sha256B64URL(st.State+":"+st.Nonce)
	m.mu.Lock()
	if m.st.RevokedSessions[replayKey] > now.UnixMilli() {
		m.mu.Unlock()
		failHTML(http.StatusBadRequest, "State Already Used", "This GitHub OAuth state has already been consumed.")
		return
	}
	m.st.RevokedSessions[replayKey] = now.Add(ghStateTTL + time.Minute).UnixMilli()
	m.mu.Unlock()

	ghAccessToken, err := m.exchangeGitHubCode(r, code, st.CodeVerifier, origin+"/admin/auth/github/callback")
	if err != nil {
		failHTML(http.StatusUnauthorized, "GitHub Token Exchange Failed", "Unable to exchange authorization code.")
		return
	}
	ghIDStr, ghLogin, ghAvatar, err := m.fetchGitHubUser(r, ghAccessToken)
	if err != nil {
		failHTML(http.StatusBadGateway, "GitHub Profile Error", "Unable to verify GitHub user profile.")
		return
	}
	userID, loginLower := "gh_"+ghIDStr, strings.ToLower(ghLogin)
	isFounder := ownerID != "" && ghIDStr == ownerID
	if !isFounder && ownerLogin != "" && loginLower == ownerLogin {
		failHTML(http.StatusForbidden, "Owner Identity Mismatch", "GitHub login does not match configured numeric GITHUB_OWNER_ID.")
		return
	}

	mode := NormalizeSignupMode(m.cfg.GitHub.SignupMode, m.cfg.GitHub.AllowedUsers)
	allow := ParseGitHubAllowlist(m.cfg.GitHub.AllowedUsers)
	allowed, role, admittedVia, admittedOrg, sealedTok := isFounder, "member", "", "", ""
	if isFounder {
		role, admittedVia = "owner", "owner"
	} else if mode != "closed" {
		if allow.UserIDs[ghIDStr] {
			allowed, admittedVia = true, "allowlist_id"
		} else if allow.Users[loginLower] {
			allowed, admittedVia = true, "allowlist_login"
		} else if len(allow.Orgs) > 0 {
			if matchedOrg := m.checkGitHubOrgs(r, ghAccessToken, allow.Orgs); matchedOrg != "" {
				allowed, admittedVia, admittedOrg = true, "org", matchedOrg
				sealedTok, _ = SealGitHubToken(m.signingSecret, userID, ghAccessToken)
			}
		}
		if !allowed && mode == "open" {
			allowed, admittedVia = true, "open"
		}
	}
	if !allowed {
		failHTML(http.StatusForbidden, "Account Not Authorized", "Your GitHub account is not authorized on this Hub.")
		return
	}

	m.mu.Lock()
	existing, hasExisting := m.st.Users[userID]
	if !isFounder && hasExisting && existing.Disabled {
		m.mu.Unlock()
		failHTML(http.StatusForbidden, "Account Disabled", "This GitHub account has been disabled.")
		return
	}
	for id, u := range m.st.Users {
		if id != userID && !u.Disabled && strings.EqualFold(u.GitHubLogin, ghLogin) {
			if isFounder {
				u.Disabled, u.SessionEpoch, u.GitHubLogin = true, u.SessionEpoch+1, "__evicted_"+u.UserID
				m.st.Users[id] = u
			} else {
				m.mu.Unlock()
				failHTML(http.StatusForbidden, "Handle Conflict", "GitHub login is already bound to another numeric ID.")
				return
			}
		}
	}
	epoch, createdAt := 1, now.UnixMilli()
	if hasExisting {
		epoch, createdAt = max(existing.SessionEpoch, 1), existing.CreatedAt
		if !isFounder && existing.Role == "owner" {
			role = "owner"
		}
	}
	userRec := GitHubUser{
		UserID: userID, GitHubID: ghIDStr, GitHubLogin: ghLogin, AvatarURL: ghAvatar, Role: role,
		SessionEpoch: epoch, AdmittedVia: admittedVia, AdmittedOrg: admittedOrg,
		EncryptedGHToken: sealedTok, CreatedAt: createdAt, LastLoginAt: now.UnixMilli(),
	}
	m.st.Users[userID] = userRec
	_ = m.saveLocked()
	m.mu.Unlock()

	jwtTok, _, _, err := MintGitHubSessionJWT(m.signingSecret, userRec, now, adminSessionTTL)
	if err != nil {
		failHTML(http.StatusInternalServerError, "Session Error", "Could not mint session token.")
		return
	}
	clearState()
	userCookie, adminCookie := CookieUserDev, CookieAdminDev
	if isHTTPS {
		userCookie, adminCookie = CookieUserSecure, CookieAdminSecure
	}
	for _, cname := range []string{userCookie, adminCookie} {
		http.SetCookie(w, &http.Cookie{
			Name: cname, Value: jwtTok, Path: "/", MaxAge: int(adminSessionTTL.Seconds()),
			HttpOnly: true, Secure: isHTTPS, SameSite: http.SameSiteLaxMode,
		})
	}
	ApplySecurityHeaders(w, isHTTPS)
	http.Redirect(w, r, sanitizeReturnTo(st.ReturnTo), http.StatusFound)
}

func (m *Manager) exchangeGitHubCode(r *http.Request, code, verifier, redirectURI string) (string, error) {
	tokenURL := strings.TrimSpace(m.cfg.GitHub.TokenURL)
	if tokenURL == "" {
		tokenURL = "https://github.com/login/oauth/access_token"
	}
	form := url.Values{
		"client_id": {strings.TrimSpace(m.cfg.GitHub.ClientID)}, "client_secret": {strings.TrimSpace(m.cfg.GitHub.ClientSecret)},
		"code": {code}, "redirect_uri": {redirectURI}, "code_verifier": {verifier},
	}
	req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := m.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 65536))
	var out struct {
		AccessToken string `json:"access_token"`
	}
	if err != nil || resp.StatusCode != http.StatusOK || json.Unmarshal(body, &out) != nil || strings.TrimSpace(out.AccessToken) == "" {
		return "", errors.New("token exchange failed")
	}
	return strings.TrimSpace(out.AccessToken), nil
}

func (m *Manager) fetchGitHubUser(r *http.Request, accessToken string) (idStr, login, avatar string, err error) {
	apiBase := strings.TrimRight(strings.TrimSpace(m.cfg.GitHub.APIBaseURL), "/")
	if apiBase == "" {
		apiBase = "https://api.github.com"
	}
	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, apiBase+"/user", nil)
	if err != nil {
		return "", "", "", err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := m.httpClient.Do(req)
	if err != nil {
		return "", "", "", err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 131072))
	var prof struct {
		ID        int64  `json:"id"`
		Login     string `json:"login"`
		AvatarURL string `json:"avatar_url"`
	}
	if err != nil || resp.StatusCode != http.StatusOK || json.Unmarshal(body, &prof) != nil || prof.ID <= 0 || !reGitHubLogin.MatchString(strings.TrimSpace(prof.Login)) {
		return "", "", "", errors.New("invalid github profile")
	}
	av := strings.TrimSpace(prof.AvatarURL)
	if !strings.HasPrefix(av, "https://") {
		av = ""
	}
	return strconv.FormatInt(prof.ID, 10), strings.TrimSpace(prof.Login), av, nil
}

func (m *Manager) checkGitHubOrgs(r *http.Request, accessToken string, allowedOrgs map[string]bool) string {
	apiBase := strings.TrimRight(strings.TrimSpace(m.cfg.GitHub.APIBaseURL), "/")
	if apiBase == "" {
		apiBase = "https://api.github.com"
	}
	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, apiBase+"/user/orgs?per_page=100", nil)
	if err != nil {
		return ""
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := m.httpClient.Do(req)
	if err != nil {
		return ""
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 262144))
	var orgs []struct {
		Login string `json:"login"`
	}
	if err != nil || resp.StatusCode != http.StatusOK || json.Unmarshal(body, &orgs) != nil {
		return ""
	}
	for _, o := range orgs {
		if cand := strings.ToLower(strings.TrimSpace(o.Login)); allowedOrgs[cand] {
			return cand
		}
	}
	return ""
}
