package hubauth

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bartrumb/edgefetch/v2/internal/otel"
)

func pkcePair(verifier string) (string, string) {
	sum := sha256.Sum256([]byte(verifier))
	return verifier, base64.RawURLEncoding.EncodeToString(sum[:])
}

func newTestServer(t *testing.T, cfg Config) (*Manager, *httptest.Server) {
	t.Helper()
	if cfg.CallerToken == "" && cfg.McpToken == "" && cfg.GitHub.ClientID == "" {
		cfg.CallerToken = "ef_caller_secret_token_for_tests_12345"
	}
	mgr, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		orig, ok := ResolveRequestPublicOrigin(r, cfg.PublicOrigin, srv.URL, cfg.TrustProxy)
		if !ok {
			http.Error(w, "bad host", http.StatusBadRequest)
			return
		}
		rootTC := otel.ExtractOrNew(r.Header)
		r = r.WithContext(otel.WithTraceContext(r.Context(), rootTC))
		if mgr.HandleOAuthOrWellKnown(w, r, orig) || mgr.HandleAdmin(w, r, orig) {
			return
		}
		switch r.URL.Path {
		case "/mcp":
			wantScope := "crawl:read"
			if r.URL.Query().Get("op") == "scrape" {
				wantScope = "crawl:fetch"
			}
			dec := mgr.AuthorizeCaller(r, wantScope, true, false)
			if !dec.Allowed {
				if dec.WWWAuthenticate != "" {
					w.Header().Set("WWW-Authenticate", dec.WWWAuthenticate)
				}
				w.WriteHeader(dec.Status)
				return
			}
			writeJSONResp(w, false, http.StatusOK, map[string]any{"ok": true, "principal": dec.Principal})
		case "/agents":
			dec := mgr.AuthorizeCaller(r, "crawl:read", false, true)
			if !dec.Allowed {
				w.WriteHeader(dec.Status)
				return
			}
			writeJSONResp(w, false, http.StatusOK, map[string]any{"ok": true})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return mgr, srv
}

func runPKCEFlow(t *testing.T, baseURL, callerToken, scopes string) (clientID, redirectURI, code, verifier string, tokResp map[string]any) {
	t.Helper()
	redirectURI = "http://127.0.0.1:19999/cb"
	regBody, _ := json.Marshal(map[string]any{"client_name": "audit-client", "redirect_uris": []string{redirectURI}})
	res, err := http.Post(baseURL+"/oauth/register", "application/json", bytes.NewReader(regBody))
	if err != nil || res.StatusCode != http.StatusCreated {
		t.Fatalf("register status=%v err=%v", res, err)
	}
	var reg map[string]any
	_ = json.NewDecoder(res.Body).Decode(&reg)
	_ = res.Body.Close()
	clientID, _ = reg["client_id"].(string)

	verifier, challenge := pkcePair("verifier_secret_string_at_least_43_characters_long_xyz_123")
	authU, _ := url.Parse(baseURL + "/oauth/authorize")
	q := authU.Query()
	q.Set("client_id", clientID)
	q.Set("redirect_uri", redirectURI)
	q.Set("response_type", "code")
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")
	q.Set("scope", scopes)
	q.Set("state", "st_123")
	q.Set("resource", baseURL+"/mcp")
	authU.RawQuery = q.Encode()

	getRes, err := http.Get(authU.String())
	if err != nil || getRes.StatusCode != http.StatusOK {
		t.Fatalf("GET authorize: %v %v", getRes, err)
	}
	htmlBytes, _ := io.ReadAll(getRes.Body)
	_ = getRes.Body.Close()
	htmlStr := string(htmlBytes)

	csrfCookie := regexp.MustCompile(`ef_oauth_csrf=([^;]+)`).FindStringSubmatch(getRes.Header.Get("Set-Cookie"))
	sealedMatch := regexp.MustCompile(`name="sealed"\s+value="([^"]+)"`).FindStringSubmatch(htmlStr)
	csrfMatch := regexp.MustCompile(`name="csrf"\s+value="([^"]+)"`).FindStringSubmatch(htmlStr)
	if len(csrfCookie) < 2 || len(sealedMatch) < 2 || len(csrfMatch) < 2 {
		t.Fatalf("consent form regex mismatch")
	}

	noRedir := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	form := url.Values{"sealed": {sealedMatch[1]}, "csrf": {csrfMatch[1]}, "owner_token": {callerToken}, "decision": {"approve"}}
	postReq, _ := http.NewRequest(http.MethodPost, baseURL+"/oauth/authorize", strings.NewReader(form.Encode()))
	postReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	postReq.Header.Set("Cookie", "ef_oauth_csrf="+csrfCookie[1])
	postRes, err := noRedir.Do(postReq)
	if err != nil || postRes.StatusCode != http.StatusFound {
		t.Fatalf("POST authorize: status=%v err=%v", postRes, err)
	}
	_ = postRes.Body.Close()
	loc, _ := url.Parse(postRes.Header.Get("Location"))
	code = loc.Query().Get("code")
	if !strings.HasPrefix(code, "efc_") || loc.Query().Get("state") != "st_123" {
		t.Fatalf("unexpected callback redirect: %s", loc)
	}

	tokRes, err := http.PostForm(baseURL+"/oauth/token", url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "code_verifier": {verifier},
		"client_id": {clientID}, "redirect_uri": {redirectURI}, "resource": {baseURL + "/mcp"},
	})
	if err != nil || tokRes.StatusCode != http.StatusOK {
		t.Fatalf("POST token: %v %v", tokRes, err)
	}
	tokResp = make(map[string]any)
	_ = json.NewDecoder(tokRes.Body).Decode(&tokResp)
	_ = tokRes.Body.Close()
	return clientID, redirectURI, code, verifier, tokResp
}

func TestOAuthPKCEFlowRefreshReplayAndScopes(t *testing.T) {
	var otlpMu sync.Mutex
	var otlpBodies []string
	collector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		otlpMu.Lock()
		otlpBodies = append(otlpBodies, string(b))
		otlpMu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer collector.Close()

	exp := otel.NewExporterFromEnv(func(k string) string {
		if k == "OTEL_EXPORTER_OTLP_ENDPOINT" {
			return collector.URL
		}
		return ""
	}, "edgefetch-hub-test", "2.7.8", nil)

	dataDir := t.TempDir()
	callerTok := "ef_caller_secret_token_t2c1_12345678"
	mcpTok := "ef_mcp_secondary_token_t2c4_12345678"
	_, srv := newTestServer(t, Config{DataDir: dataDir, CallerToken: callerTok, McpToken: mcpTok, OtelExporter: exp})

	for _, ep := range []string{"/.well-known/oauth-protected-resource", "/.well-known/oauth-authorization-server"} {
		r, _ := http.Get(srv.URL + ep)
		if r.StatusCode != http.StatusOK {
			t.Fatalf("%s status=%d", ep, r.StatusCode)
		}
		_ = r.Body.Close()
	}

	badReg, _ := http.Post(srv.URL+"/oauth/register", "application/json", strings.NewReader(`{"client_name":"evil","redirect_uris":["https://evil.example.org/cb"]}`))
	if badReg.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for untrusted redirect_uri, got %d", badReg.StatusCode)
	}
	_ = badReg.Body.Close()

	clientID, redirectURI, code, verifier, tok1 := runPKCEFlow(t, srv.URL, callerTok, "crawl:read")
	access1, _ := tok1["access_token"].(string)
	refresh1, _ := tok1["refresh_token"].(string)
	if _, err := os.Stat(filepath.Join(dataDir, "state", "oauth_state.json")); err != nil {
		t.Fatalf("oauth_state.json missing: %v", err)
	}

	// Step-up scopes (T2-C4)
	reqRead, _ := http.NewRequest(http.MethodPost, srv.URL+"/mcp?op=read", nil)
	reqRead.Header.Set("Authorization", "Bearer "+access1)
	resRead, _ := http.DefaultClient.Do(reqRead)
	if resRead.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for crawl:read, got %d", resRead.StatusCode)
	}
	_ = resRead.Body.Close()

	reqFetch, _ := http.NewRequest(http.MethodPost, srv.URL+"/mcp?op=scrape", nil)
	reqFetch.Header.Set("Authorization", "Bearer "+access1)
	resFetch, _ := http.DefaultClient.Do(reqFetch)
	if resFetch.StatusCode != http.StatusForbidden || !strings.Contains(resFetch.Header.Get("WWW-Authenticate"), "insufficient_scope") {
		t.Fatalf("expected 403 insufficient_scope, got %d", resFetch.StatusCode)
	}
	_ = resFetch.Body.Close()

	for _, nonOwnerTok := range []string{access1, mcpTok} {
		reqOwner, _ := http.NewRequest(http.MethodGet, srv.URL+"/agents", nil)
		reqOwner.Header.Set("Authorization", "Bearer "+nonOwnerTok)
		resOwner, _ := http.DefaultClient.Do(reqOwner)
		if resOwner.StatusCode != http.StatusForbidden {
			t.Fatalf("expected 403 on ownerOnly route, got %d", resOwner.StatusCode)
		}
		_ = resOwner.Body.Close()
	}

	// Single-use code replay -> 400
	reuseRes, _ := http.PostForm(srv.URL+"/oauth/token", url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "code_verifier": {verifier}, "client_id": {clientID}, "redirect_uri": {redirectURI},
	})
	if reuseRes.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 on code reuse, got %d", reuseRes.StatusCode)
	}
	_ = reuseRes.Body.Close()

	// Wrong client_id refresh -> 400 without burning grant (T2-C1 step 3)
	wrongRes, _ := http.PostForm(srv.URL+"/oauth/token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refresh1}, "client_id": {"mcp_wrong"}})
	if wrongRes.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 on wrong client_id, got %d", wrongRes.StatusCode)
	}
	_ = wrongRes.Body.Close()

	// Valid refresh succeeds
	rotRes, _ := http.PostForm(srv.URL+"/oauth/token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refresh1}, "client_id": {clientID}})
	if rotRes.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 on valid refresh, got %d", rotRes.StatusCode)
	}
	var rotTok map[string]any
	_ = json.NewDecoder(rotRes.Body).Decode(&rotTok)
	_ = rotRes.Body.Close()
	access2, _ := rotTok["access_token"].(string)

	// Replay old refresh1 -> revokes ENTIRE grant & invalidates access2 (T2-C1 step 5)!
	replayRes, _ := http.PostForm(srv.URL+"/oauth/token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refresh1}, "client_id": {clientID}})
	if replayRes.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 on refresh replay, got %d", replayRes.StatusCode)
	}
	_ = replayRes.Body.Close()

	reqAfter, _ := http.NewRequest(http.MethodPost, srv.URL+"/mcp?op=read", nil)
	reqAfter.Header.Set("Authorization", "Bearer "+access2)
	resAfter, _ := http.DefaultClient.Do(reqAfter)
	if resAfter.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 for access2 after refresh replay revocation, got %d", resAfter.StatusCode)
	}
	_ = resAfter.Body.Close()

	_ = exp.Close()
	otlpMu.Lock()
	joinedSpans := strings.Join(otlpBodies, "\n")
	otlpMu.Unlock()
	for _, secret := range []string{callerTok, code, verifier, access1, refresh1, access2} {
		if strings.Contains(joinedSpans, secret) {
			t.Fatalf("secret leaked into OTLP spans: %s", secret[:8])
		}
	}
	if !strings.Contains(joinedSpans, "edgefetch.oauth.register") || !strings.Contains(joinedSpans, "edgefetch.oauth.token") {
		t.Fatalf("missing expected edgefetch.oauth.* spans")
	}
}

func TestAdminLockoutLogoutCSRFBodyCapVaultAndPersistence(t *testing.T) {
	callerTok := "ef_admin_owner_secret_token_987654321"
	vaultKey := "vkey_super_secret_master_key_32chars!"
	dataDir := t.TempDir()
	dntVal := "0"
	relSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"tag_name":"v2.8.0","html_url":"https://github.com/bartrumb/edgefetch/releases/tag/v2.8.0"}`))
	}))
	defer relSrv.Close()

	cfg := Config{
		DataDir:        dataDir,
		CallerToken:    callerTok,
		VaultMasterKey: vaultKey,
		HubVersion:     "2.7.8",
		ReleaseAPIURL:  relSrv.URL,
		Getenv: func(k string) string {
			if k == "DO_NOT_TRACK" {
				return dntVal
			}
			return ""
		},
		Callbacks: Callbacks{
			GetAdminState: func(context.Context) (AdminHubState, error) {
				return AdminHubState{Connected: 1, DistinctPublicIPs: 1, AgentsRaw: []any{"node-1"}}, nil
			},
			ExecuteAdminFetch: func(_ context.Context, req AdminFetchRequest) (int, string, []byte, error) {
				return http.StatusOK, "agent:node-1", []byte(`{"ok":true,"url":` + strconv.Quote(req.URL) + `}`), nil
			},
			ClearAffinities: func(context.Context, string) error { return nil },
			ClearEvents:     func(context.Context) error { return nil },
		},
	}
	mgr, srv := newTestServer(t, cfg)
	noRedir := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

	loginRes, err := noRedir.PostForm(srv.URL+"/admin/login", url.Values{"token": {callerTok}})
	if err != nil || loginRes.StatusCode != http.StatusFound {
		t.Fatalf("admin login status=%v err=%v", loginRes, err)
	}
	_ = loginRes.Body.Close()
	cookieVal := regexp.MustCompile(`ef_admin_session=([^;]+)`).FindStringSubmatch(loginRes.Header.Get("Set-Cookie"))[1]
	csrf := strings.Split(cookieVal, ".")[2]
	cookieHdr := "ef_admin_session=" + cookieVal

	// GET /admin + GET /admin/api/state (includes update check v2.8.0 > v2.7.8)
	stReq, _ := http.NewRequest(http.MethodGet, srv.URL+"/admin/api/state", nil)
	stReq.Header.Set("Cookie", cookieHdr)
	stRes, _ := http.DefaultClient.Do(stReq)
	var stJSON map[string]any
	_ = json.NewDecoder(stRes.Body).Decode(&stJSON)
	_ = stRes.Body.Close()
	updMap, _ := stJSON["updateStatus"].(map[string]any)
	if updMap["pillStatus"] != "update_available" {
		t.Fatalf("expected update_available from release mock, got %+v", updMap)
	}

	// CSRF rejection (403) & 64 KiB body cap on /admin/api/affinity/clear -> 413 (T2-C3)
	badReq, _ := http.NewRequest(http.MethodPost, srv.URL+"/admin/api/events/clear", strings.NewReader(`{}`))
	badReq.Header.Set("Cookie", cookieHdr)
	badReq.Header.Set("X-CSRF-Token", "wrong_csrf")
	badRes, _ := http.DefaultClient.Do(badReq)
	if badRes.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 bad CSRF, got %d", badRes.StatusCode)
	}
	_ = badRes.Body.Close()

	bigReq, _ := http.NewRequest(http.MethodPost, srv.URL+"/admin/api/affinity/clear", strings.NewReader(`{"pad":"`+strings.Repeat("a", 70000)+`"}`))
	bigReq.Header.Set("Cookie", cookieHdr)
	bigReq.Header.Set("X-CSRF-Token", csrf)
	bigRes, _ := http.DefaultClient.Do(bigReq)
	if bigRes.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413 on >64KiB affinity/clear, got %d", bigRes.StatusCode)
	}
	_ = bigRes.Body.Close()

	// MCP v2. AES-256-GCM Vault round-trip + SSRF rejection
	ssrfReq, _ := http.NewRequest(http.MethodPost, srv.URL+"/admin/api/mcp/servers", strings.NewReader(`{"name":"bad","remoteUrl":"http://127.0.0.1:8080/mcp"}`))
	ssrfReq.Header.Set("Cookie", cookieHdr)
	ssrfReq.Header.Set("X-CSRF-Token", csrf)
	ssrfRes, _ := http.DefaultClient.Do(ssrfReq)
	if ssrfRes.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 on loopback MCP URL, got %d", ssrfRes.StatusCode)
	}
	_ = ssrfRes.Body.Close()

	saveReq, _ := http.NewRequest(http.MethodPost, srv.URL+"/admin/api/mcp/servers",
		strings.NewReader(`{"name":"Linear","slug":"linear","remoteUrl":"https://mcp.linear.app/mcp","bearerToken":"lin_api_secret_token_999","domains":["linear.app"]}`))
	saveReq.Header.Set("Cookie", cookieHdr)
	saveReq.Header.Set("X-CSRF-Token", csrf)
	saveRes, _ := http.DefaultClient.Do(saveReq)
	saveRaw, _ := io.ReadAll(saveRes.Body)
	_ = saveRes.Body.Close()
	if saveRes.StatusCode != http.StatusOK || strings.Contains(string(saveRaw), "lin_api_secret_token_999") {
		t.Fatalf("MCP vault save failed or leaked secret: %d", saveRes.StatusCode)
	}

	decrypted, err := mgr.ListDecryptedMcpServers("owner")
	if err != nil || len(decrypted) != 1 || decrypted[0].Headers["Authorization"] != "Bearer lin_api_secret_token_999" {
		t.Fatalf("ListDecryptedMcpServers mismatch: %+v err=%v", decrypted, err)
	}

	// DO_NOT_TRACK=1 hard disable
	dntVal = "1"
	telReq, _ := http.NewRequest(http.MethodPost, srv.URL+"/admin/api/telemetry", strings.NewReader(`{"enabled":true}`))
	telReq.Header.Set("Cookie", cookieHdr)
	telReq.Header.Set("X-CSRF-Token", csrf)
	telRes, _ := http.DefaultClient.Do(telReq)
	var telJSON map[string]any
	_ = json.NewDecoder(telRes.Body).Decode(&telJSON)
	_ = telRes.Body.Close()
	if telSub, _ := telJSON["telemetry"].(map[string]any); telSub["enabled"] != false || telSub["doNotTrack"] != true {
		t.Fatalf("DO_NOT_TRACK=1 must force telemetry off: %+v", telJSON)
	}

	// 5 failed logins rotating spoofed X-Forwarded-For with trustProxy=false -> 6th returns 429 Retry-After: 600 (T2-C2)
	for i := range 5 {
		fReq, _ := http.NewRequest(http.MethodPost, srv.URL+"/admin/login", strings.NewReader("token=wrong_"+strconv.Itoa(i)))
		fReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		fReq.Header.Set("X-Forwarded-For", "198.51.100."+strconv.Itoa(10+i))
		fRes, _ := noRedir.Do(fReq)
		if fRes.StatusCode != http.StatusUnauthorized {
			t.Fatalf("attempt %d expected 401, got %d", i+1, fRes.StatusCode)
		}
		_ = fRes.Body.Close()
	}
	lockReq, _ := http.NewRequest(http.MethodPost, srv.URL+"/admin/login", strings.NewReader("token=wrong_6"))
	lockReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	lockReq.Header.Set("X-Forwarded-For", "203.0.113.99")
	lockRes, _ := noRedir.Do(lockReq)
	if lockRes.StatusCode != http.StatusTooManyRequests || lockRes.Header.Get("Retry-After") != "600" {
		t.Fatalf("expected 429 Retry-After=600, got %d (%q)", lockRes.StatusCode, lockRes.Header.Get("Retry-After"))
	}
	_ = lockRes.Body.Close()

	// Logout revokes cookie immediately -> /admin/api/state returns 401 even after Manager reload from disk!
	outReq, _ := http.NewRequest(http.MethodPost, srv.URL+"/admin/logout", strings.NewReader("csrf="+url.QueryEscape(csrf)))
	outReq.Header.Set("Cookie", cookieHdr)
	outReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	outRes, _ := noRedir.Do(outReq)
	if outRes.StatusCode != http.StatusFound {
		t.Fatalf("logout expected 302, got %d", outRes.StatusCode)
	}
	_ = outRes.Body.Close()

	reloaded, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("reload NewManager: %v", err)
	}
	if _, ok := reloaded.verifySessionToken(cookieVal, time.Now()); ok {
		t.Fatalf("revoked cookie accepted after disk reload!")
	}
	reloadedMCP, err := reloaded.ListDecryptedMcpServers("owner")
	if err != nil || len(reloadedMCP) != 1 || reloadedMCP[0].Headers["Authorization"] != "Bearer lin_api_secret_token_999" {
		t.Fatalf("vault reload failed: %+v err=%v", reloadedMCP, err)
	}
}

func TestGitHubOAuthAndTokenSealing(t *testing.T) {
	sealed, err := SealGitHubToken("super_secret_session_key_1234", "gh_42", "gho_live_secret_tok")
	if err != nil || !strings.HasPrefix(sealed, "ght1.") {
		t.Fatalf("SealGitHubToken: %q err=%v", sealed, err)
	}
	if opened, err := OpenGitHubToken("super_secret_session_key_1234", "gh_42", sealed); err != nil || opened != "gho_live_secret_tok" {
		t.Fatalf("OpenGitHubToken: %q err=%v", opened, err)
	}
	if _, err := OpenGitHubToken("super_secret_session_key_1234", "gh_99", sealed); err == nil {
		t.Fatalf("expected cross-user AAD failure")
	}

	ghMock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/login/oauth/access_token" {
			_ = r.ParseForm()
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"access_token":"tok_` + r.Form.Get("code") + `"}`))
			return
		}
		if strings.HasSuffix(r.Header.Get("Authorization"), "tok_founder") {
			_, _ = w.Write([]byte(`{"id":777,"login":"founder"}`))
		} else {
			_, _ = w.Write([]byte(`{"id":888,"login":"outsider"}`))
		}
	}))
	defer ghMock.Close()

	_, srv := newTestServer(t, Config{
		SessionSecret: "session_secret_at_least_24_chars!",
		GitHub: GitHubConfig{
			ClientID: "gh_cid", ClientSecret: "gh_csecret_1234567890", OwnerID: "777", OwnerLogin: "founder",
			SignupMode: "closed", TokenURL: ghMock.URL + "/login/oauth/access_token", APIBaseURL: ghMock.URL,
		},
	})
	noRedir := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

	startRes, _ := noRedir.Get(srv.URL + "/admin/auth/github")
	_ = startRes.Body.Close()
	stLoc, _ := url.Parse(startRes.Header.Get("Location"))
	ghCookie := regexp.MustCompile(`ef_gh_oauth=([^;]+)`).FindStringSubmatch(startRes.Header.Get("Set-Cookie"))[1]

	outReq, _ := http.NewRequest(http.MethodGet, srv.URL+"/admin/auth/github/callback?code=outsider&state="+url.QueryEscape(stLoc.Query().Get("state")), nil)
	outReq.Header.Set("Cookie", "ef_gh_oauth="+ghCookie)
	outRes, _ := noRedir.Do(outReq)
	if outRes.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for outsider in closed mode, got %d", outRes.StatusCode)
	}
	_ = outRes.Body.Close()

	startRes2, _ := noRedir.Get(srv.URL + "/admin/auth/github")
	_ = startRes2.Body.Close()
	loc2, _ := url.Parse(startRes2.Header.Get("Location"))
	ghCookie2 := regexp.MustCompile(`ef_gh_oauth=([^;]+)`).FindStringSubmatch(startRes2.Header.Get("Set-Cookie"))[1]

	cbReq, _ := http.NewRequest(http.MethodGet, srv.URL+"/admin/auth/github/callback?code=founder&state="+url.QueryEscape(loc2.Query().Get("state")), nil)
	cbReq.Header.Set("Cookie", "ef_gh_oauth="+ghCookie2)
	cbRes, _ := noRedir.Do(cbReq)
	if cbRes.StatusCode != http.StatusFound {
		t.Fatalf("expected 302 for pinned founder, got %d", cbRes.StatusCode)
	}
	_ = cbRes.Body.Close()
	userJWT := regexp.MustCompile(`ef_user_session=([^;]+)`).FindStringSubmatch(strings.Join(cbRes.Header.Values("Set-Cookie"), "; "))[1]

	agReq, _ := http.NewRequest(http.MethodGet, srv.URL+"/agents", nil)
	agReq.Header.Set("Cookie", "ef_user_session="+userJWT)
	agRes, _ := http.DefaultClient.Do(agReq)
	if agRes.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 on /agents for founder GitHub session, got %d", agRes.StatusCode)
	}
	_ = agRes.Body.Close()
}

type mockAddr string

func (a mockAddr) Network() string { return "tcp" }
func (a mockAddr) String() string  { return string(a) }

type addrConn struct {
	net.Conn
	raddr net.Addr
}

func (c addrConn) RemoteAddr() net.Addr { return c.raddr }

type channelListener struct{ ch chan net.Conn }

func (l *channelListener) Accept() (net.Conn, error) {
	if c, ok := <-l.ch; ok {
		return c, nil
	}
	return nil, net.ErrClosed
}
func (l *channelListener) Close() error   { close(l.ch); return nil }
func (l *channelListener) Addr() net.Addr { return mockAddr("0.0.0.0:8787") }

func TestGuardedListenerOriginsAndHeaders(t *testing.T) {
	rawLn := &channelListener{ch: make(chan net.Conn, 16)}
	gl := WrapListener(rawLn, ConnGuardOptions{MaxTotal: 3, MaxPerIP: 2, LoopbackReserved: 2})
	accepted := make(chan net.Conn, 16)
	go func() {
		for {
			c, err := gl.Accept()
			if err != nil {
				return
			}
			accepted <- c
		}
	}()
	dialMock := func(remote string) net.Conn {
		c1, s1 := net.Pipe()
		rawLn.ch <- addrConn{Conn: s1, raddr: mockAddr(remote)}
		select {
		case acc := <-accepted:
			_ = c1.Close()
			return acc
		case <-time.After(60 * time.Millisecond):
			_ = c1.Close()
			return nil
		}
	}

	a1, a2, a3 := dialMock("203.0.113.10:4001"), dialMock("203.0.113.10:4002"), dialMock("203.0.113.10:4003")
	a4, a5, lb := dialMock("203.0.113.11:4001"), dialMock("203.0.113.12:4001"), dialMock("127.0.0.1:50000")
	if a1 == nil || a2 == nil || a3 != nil || a4 == nil || a5 != nil || lb == nil {
		t.Fatalf("GuardedListener cap/loopback invariant failed")
	}
	for _, c := range []net.Conn{a1, a2, a4, lb} {
		_ = c.Close()
	}
	_ = gl.Close()

	httpSrv := &http.Server{}
	TrackConnState(httpSrv, ConnGuardOptions{MaxTotal: 4, MaxPerIP: 2})
	if httpSrv.ConnState == nil || httpSrv.ReadHeaderTimeout <= 0 {
		t.Fatalf("TrackConnState did not configure http.Server")
	}

	if orig := ResolveConfiguredPublicOrigin(func(k string) string {
		if k == "FLY_APP_NAME" {
			return "My-EdgeFetch"
		}
		return ""
	}); orig != "https://my-edgefetch.fly.dev" {
		t.Fatalf("unexpected Fly origin %q", orig)
	}
	badReq := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8787/health", nil)
	badReq.Host = "["
	if _, valid := ResolveRequestPublicOrigin(badReq, "", "http://127.0.0.1:8787", false); valid {
		t.Fatalf("expected malformed Host: [ to return validHost=false")
	}
	xffReq := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8787/admin/login", nil)
	xffReq.RemoteAddr = "198.51.100.7:54321"
	xffReq.Header.Set("X-Forwarded-For", "1.1.1.1, 203.0.113.44")
	xffReq.Header.Set("Fly-Client-IP", "203.0.113.88")
	if ResolveClientIP(xffReq, false, false) != "198.51.100.7" || ResolveClientIP(xffReq, true, false) != "203.0.113.44" || ResolveClientIP(xffReq, true, true) != "203.0.113.88" {
		t.Fatalf("ResolveClientIP mismatch")
	}
	rec := httptest.NewRecorder()
	ApplySecurityHeaders(rec, true)
	if rec.Header().Get("X-Frame-Options") != "DENY" || !strings.Contains(rec.Header().Get("Strict-Transport-Security"), "max-age=31536000") {
		t.Fatalf("missing security headers")
	}
}

func TestRegisterRateLimitAndPersistedTelemetrySync(t *testing.T) {
	t.Parallel()
	dataDir := t.TempDir()
	callerTok := "caller_secret_token_abcdefghijklmnopqrstuvwxyz"
	var toggleCalls []bool
	mgr, srv := newTestServer(t, Config{
		DataDir:     dataDir,
		CallerToken: callerTok,
		Getenv: func(k string) string {
			if k == "EDGEFETCH_DEV_TELEMETRY" {
				return "1"
			}
			return ""
		},
		Callbacks: Callbacks{
			OnTelemetryToggle: func(enabled bool) {
				toggleCalls = append(toggleCalls, enabled)
			},
		},
	})
	_ = mgr

	// 5 valid dynamic client registrations from the same IP succeed; the 6th returns 429 Retry-After: 600.
	regPayload := `{"client_name":"cli","redirect_uris":["http://127.0.0.1:53123/cb"]}`
	for i := range 5 {
		res, err := http.Post(srv.URL+"/oauth/register", "application/json", strings.NewReader(regPayload))
		if err != nil {
			t.Fatalf("register %d: %v", i+1, err)
		}
		_ = res.Body.Close()
		if res.StatusCode != http.StatusCreated {
			t.Fatalf("register %d expected 201, got %d", i+1, res.StatusCode)
		}
	}
	res6, err := http.Post(srv.URL+"/oauth/register", "application/json", strings.NewReader(regPayload))
	if err != nil {
		t.Fatalf("register 6: %v", err)
	}
	_ = res6.Body.Close()
	if res6.StatusCode != http.StatusTooManyRequests || res6.Header.Get("Retry-After") != "600" {
		t.Fatalf("expected 429 Retry-After=600 on 6th /oauth/register, got %d (%q)", res6.StatusCode, res6.Header.Get("Retry-After"))
	}

	// Admin opts out of telemetry -> persisted to oauth_state.json -> fresh Manager reload calls OnTelemetryToggle(false).
	noRedir := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	loginRes, err := noRedir.PostForm(srv.URL+"/admin/login", url.Values{"token": {callerTok}})
	if err != nil || loginRes.StatusCode != http.StatusFound {
		t.Fatalf("admin login failed: %v status=%v", err, loginRes)
	}
	_ = loginRes.Body.Close()
	cookieVal := regexp.MustCompile(`ef_admin_session=([^;]+)`).FindStringSubmatch(loginRes.Header.Get("Set-Cookie"))[1]
	csrf := strings.Split(cookieVal, ".")[2]
	sessionCookie := "ef_admin_session=" + cookieVal

	optOutReq, _ := http.NewRequest(http.MethodPost, srv.URL+"/admin/api/telemetry", strings.NewReader(`{"enabled":false}`))
	optOutReq.Header.Set("Cookie", sessionCookie)
	optOutReq.Header.Set("X-CSRF-Token", csrf)
	optOutRes, _ := http.DefaultClient.Do(optOutReq)
	_ = optOutRes.Body.Close()
	if optOutRes.StatusCode != http.StatusOK || len(toggleCalls) != 1 || toggleCalls[0] != false {
		t.Fatalf("expected live OnTelemetryToggle(false), got status=%d calls=%v", optOutRes.StatusCode, toggleCalls)
	}

	var startupToggles []bool
	reloaded, rErr := NewManager(Config{
		DataDir:     dataDir,
		CallerToken: callerTok,
		Getenv: func(k string) string {
			if k == "EDGEFETCH_DEV_TELEMETRY" {
				return "1"
			}
			return ""
		},
		Callbacks: Callbacks{
			OnTelemetryToggle: func(enabled bool) {
				startupToggles = append(startupToggles, enabled)
			},
		},
	})
	if rErr != nil || reloaded == nil {
		t.Fatalf("reload NewManager: %v", rErr)
	}
	if len(startupToggles) != 1 || startupToggles[0] != false {
		t.Fatalf("expected persisted TelemetryOptIn=false to sync on Hub startup, got %v", startupToggles)
	}
}
