package hubauth

import (
	"context"
	"encoding/json"
	"errors"
	"html"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/bartrumb/edgefetch/v2/internal/mcpfed"
	"github.com/bartrumb/edgefetch/v2/internal/otel"
)

const (
	defaultGitHubReleaseURL = "https://api.github.com/repos/bartrumb/edgefetch/releases/latest"
	releaseSigningSPKIB64   = "MCowBQYDK2VwAyEAv8+ZT9d/404KI0pY1PILOVBzsUvTHWaL0aLghciWy90="
)

var reSemverTag = regexp.MustCompile(`^v?([0-9]+)\.([0-9]+)\.([0-9]+)(?:-([0-9A-Za-z._-]+))?$`)

// FleetAgentVersion describes a connected worker node version for CheckHubUpdateStatus.
type FleetAgentVersion struct {
	SiteID  string `json:"siteId"`
	Version string `json:"version,omitempty"`
}

// UpdateStatus summarizes Hub and worker fleet release status for /admin.
type UpdateStatus struct {
	Enabled            bool                `json:"enabled"`
	PillStatus         string              `json:"pillStatus"`
	PillLabel          string              `json:"pillLabel"`
	CurrentVersion     string              `json:"currentVersion"`
	LatestVersion      string              `json:"latestVersion,omitempty"`
	LatestTag          string              `json:"latestTag,omitempty"`
	ReleaseURL         string              `json:"releaseUrl,omitempty"`
	HubUpdateAvailable bool                `json:"hubUpdateAvailable"`
	OutdatedAgents     []FleetAgentVersion `json:"outdatedAgents"`
	CheckedAt          int64               `json:"checkedAt,omitempty"`
	SigningKeySPKIB64  string              `json:"signingKeySpkiB64"`
}

type cachedReleaseStatus struct {
	ok            bool
	latestTag     string
	latestVersion string
	releaseURL    string
	checkedAt     int64
	expiresAt     int64
}

type sealedConsent struct {
	ClientID      string   `json:"client_id"`
	ClientName    string   `json:"client_name"`
	RedirectURI   string   `json:"redirect_uri"`
	CodeChallenge string   `json:"code_challenge"`
	Scopes        []string `json:"scope"`
	State         string   `json:"state"`
	Resource      string   `json:"resource"`
	CSRF          string   `json:"csrf"`
	Exp           int64    `json:"exp"`
}

func (m *Manager) getenv(k string) string {
	if m.cfg.Getenv != nil {
		return m.cfg.Getenv(k)
	}
	return ""
}

func (m *Manager) currentTelemetryViewLocked() map[string]any {
	dnt := otel.IsDoNotTrack(m.getenv("DO_NOT_TRACK"))
	endpoint := strings.TrimSpace(m.getenv("EDGEFETCH_DEV_TELEMETRY_URL"))
	if endpoint == "" {
		endpoint = strings.TrimSpace(m.getenv("EDGEFETCH_DEV_TELEMETRY_ENDPOINT"))
	}
	if endpoint == "" {
		endpoint = otel.DefaultDevTelemetryURL
	}
	if dnt {
		return map[string]any{"enabled": false, "source": "do_not_track", "doNotTrack": true, "endpoint": endpoint}
	}
	if m.st.TelemetryOptIn != nil {
		src := "admin_opt_out"
		if *m.st.TelemetryOptIn {
			src = "admin_opt_in"
		}
		return map[string]any{"enabled": *m.st.TelemetryOptIn, "source": src, "doNotTrack": false, "endpoint": endpoint}
	}
	envOn := otel.IsDevTelemetryEnabled(m.cfg.Getenv)
	src := "default_off"
	if envOn {
		src = "env"
	}
	return map[string]any{"enabled": envOn, "source": src, "doNotTrack": false, "endpoint": endpoint}
}

// HandleAdminTelemetry serves GET and POST /admin/api/telemetry, enforcing DO_NOT_TRACK=1 hard disable.
func (m *Manager) HandleAdminTelemetry(w http.ResponseWriter, r *http.Request, sess verifiedSession, isHTTPS bool) {
	if r.Method == http.MethodGet {
		m.mu.Lock()
		view := m.currentTelemetryViewLocked()
		m.mu.Unlock()
		writeJSONResp(w, isHTTPS, http.StatusOK, map[string]any{"ok": true, "telemetry": view, "devTelemetry": view})
		return
	}
	if !sess.IsOwner {
		writeJSONResp(w, isHTTPS, http.StatusForbidden, map[string]string{"error": "forbidden_role"})
		return
	}
	buf, tooBig, err := readCappedBody(w, r, 4096)
	if tooBig {
		writeJSONResp(w, isHTTPS, http.StatusRequestEntityTooLarge, map[string]string{"error": "payload_too_large"})
		return
	}
	var body struct {
		Enabled *bool `json:"enabled"`
	}
	if err != nil || json.Unmarshal(buf, &body) != nil || body.Enabled == nil {
		writeJSONResp(w, isHTTPS, http.StatusBadRequest, map[string]string{"error": "invalid_enabled_flag"})
		return
	}
	m.mu.Lock()
	var toggled *bool
	if !otel.IsDoNotTrack(m.getenv("DO_NOT_TRACK")) {
		v := *body.Enabled
		m.st.TelemetryOptIn = &v
		toggled = &v
		_ = m.saveLocked()
	}
	view := m.currentTelemetryViewLocked()
	m.mu.Unlock()
	if toggled != nil && m.cfg.Callbacks.OnTelemetryToggle != nil {
		m.cfg.Callbacks.OnTelemetryToggle(*toggled)
	}
	writeJSONResp(w, isHTTPS, http.StatusOK, map[string]any{"ok": true, "telemetry": view, "devTelemetry": view})
}

// HandleAdminTrackerListRefresh serves POST /admin/api/tracker-list/refresh (owner-only).
func (m *Manager) HandleAdminTrackerListRefresh(w http.ResponseWriter, r *http.Request, sess verifiedSession, isHTTPS bool) {
	span := m.startSpan(r, "edgefetch.admin.tracker_refresh", nil)
	finish := func(status int, ok bool) {
		span.SetAttribute("http.response.status_code", status)
		span.End(ok, "")
	}
	if !sess.IsOwner {
		finish(http.StatusForbidden, false)
		writeJSONResp(w, isHTTPS, http.StatusForbidden, map[string]string{"error": "forbidden_role"})
		return
	}
	if _, tooBig, _ := readCappedBody(w, r, 4096); tooBig {
		finish(http.StatusRequestEntityTooLarge, false)
		writeJSONResp(w, isHTTPS, http.StatusRequestEntityTooLarge, map[string]string{"error": "payload_too_large"})
		return
	}
	if m.cfg.Callbacks.RefreshTrackerList == nil {
		finish(http.StatusNotImplemented, false)
		writeJSONResp(w, isHTTPS, http.StatusNotImplemented, map[string]string{"error": "tracker_refresh_unavailable"})
		return
	}
	updated, trkStatus, err := m.cfg.Callbacks.RefreshTrackerList(r.Context())
	if err != nil {
		finish(http.StatusBadGateway, false)
		writeJSONResp(w, isHTTPS, http.StatusBadGateway, map[string]any{"ok": false, "updated": false, "reason": err.Error(), "trackerList": trkStatus})
		return
	}
	finish(http.StatusOK, true)
	writeJSONResp(w, isHTTPS, http.StatusOK, map[string]any{"ok": true, "updated": updated, "trackerList": trkStatus})
}

// CheckHubUpdateStatus returns cached GitHub release status (skipping network when EDGEFETCH_DISABLE_UPDATE_CHECK=1).
func (m *Manager) CheckHubUpdateStatus(ctx context.Context, agents []FleetAgentVersion) UpdateStatus {
	curVer := strings.TrimPrefix(strings.TrimSpace(m.cfg.HubVersion), "v")
	if curVer == "" {
		curVer = "2.8.1"
	}
	disRaw := strings.ToLower(strings.TrimSpace(m.getenv("EDGEFETCH_DISABLE_UPDATE_CHECK")))
	if m.cfg.DisableUpdateCheck || disRaw == "1" || disRaw == "true" || disRaw == "yes" || disRaw == "on" {
		return UpdateStatus{
			Enabled: false, PillStatus: "disabled", PillLabel: "v" + curVer, CurrentVersion: "v" + curVer,
			OutdatedAgents: []FleetAgentVersion{}, SigningKeySPKIB64: releaseSigningSPKIB64,
		}
	}
	nowMs := m.cfg.Now().UnixMilli()
	m.mu.Lock()
	cached := m.updateCache
	m.mu.Unlock()
	if cached == nil || cached.expiresAt <= nowMs {
		cached = m.fetchLatestRelease(ctx, curVer, nowMs)
		m.mu.Lock()
		m.updateCache = cached
		m.mu.Unlock()
	}
	if !cached.ok {
		return UpdateStatus{
			Enabled: true, PillStatus: "unknown", PillLabel: "v" + curVer, CurrentVersion: "v" + curVer,
			OutdatedAgents: []FleetAgentVersion{}, CheckedAt: cached.checkedAt, SigningKeySPKIB64: releaseSigningSPKIB64,
		}
	}
	hubOutdated := compareSemverSimple(cached.latestVersion, curVer) > 0
	outdated := make([]FleetAgentVersion, 0)
	for _, a := range agents {
		av := strings.TrimPrefix(strings.TrimSpace(a.Version), "v")
		if av == "" {
			outdated = append(outdated, FleetAgentVersion{SiteID: a.SiteID, Version: "legacy"})
		} else if compareSemverSimple(cached.latestVersion, av) > 0 {
			outdated = append(outdated, FleetAgentVersion{SiteID: a.SiteID, Version: "v" + av})
		}
	}
	pillStatus, pillLabel := "up_to_date", "Up to date (v"+curVer+")"
	if hubOutdated || len(outdated) > 0 {
		pillStatus, pillLabel = "update_available", "Update available ("+cached.latestTag+")"
	}
	return UpdateStatus{
		Enabled: true, PillStatus: pillStatus, PillLabel: pillLabel, CurrentVersion: "v" + curVer,
		LatestVersion: "v" + cached.latestVersion, LatestTag: cached.latestTag, ReleaseURL: cached.releaseURL,
		HubUpdateAvailable: hubOutdated, OutdatedAgents: outdated, CheckedAt: cached.checkedAt, SigningKeySPKIB64: releaseSigningSPKIB64,
	}
}

func (m *Manager) fetchLatestRelease(ctx context.Context, curVer string, nowMs int64) *cachedReleaseStatus {
	apiURL := strings.TrimSpace(m.cfg.ReleaseAPIURL)
	if apiURL == "" {
		apiURL = defaultGitHubReleaseURL
	}
	failEntry := &cachedReleaseStatus{ok: false, checkedAt: nowMs, expiresAt: nowMs + (5 * time.Minute).Milliseconds()}
	reqCtx, cancel := context.WithTimeout(ctx, 2500*time.Millisecond)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, apiURL, nil)
	if err != nil {
		return failEntry
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "EdgeFetch-Hub/"+curVer)
	resp, err := m.httpClient.Do(req)
	if err != nil {
		return failEntry
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 65536))
	var rel struct {
		TagName string `json:"tag_name"`
		HTMLURL string `json:"html_url"`
		Draft   bool   `json:"draft"`
	}
	if err != nil || resp.StatusCode != http.StatusOK || json.Unmarshal(raw, &rel) != nil || rel.Draft || !reSemverTag.MatchString(strings.TrimSpace(rel.TagName)) {
		return failEntry
	}
	latestVer := strings.TrimPrefix(strings.TrimSpace(rel.TagName), "v")
	latestTag := "v" + latestVer
	relURL := "https://github.com/bartrumb/edgefetch/releases/tag/" + url.PathEscape(latestTag)
	if strings.HasPrefix(rel.HTMLURL, "https://github.com/bartrumb/edgefetch/releases/") {
		relURL = rel.HTMLURL
	}
	return &cachedReleaseStatus{
		ok: true, latestTag: latestTag, latestVersion: latestVer,
		releaseURL: relURL, checkedAt: nowMs, expiresAt: nowMs + time.Hour.Milliseconds(),
	}
}

func compareSemverSimple(a, b string) int {
	ma, mb := reSemverTag.FindStringSubmatch(strings.TrimSpace(a)), reSemverTag.FindStringSubmatch(strings.TrimSpace(b))
	if len(ma) < 4 || len(mb) < 4 {
		return strings.Compare(a, b)
	}
	for i := 1; i <= 3; i++ {
		na, _ := strconv.Atoi(ma[i])
		nb, _ := strconv.Atoi(mb[i])
		if na != nb {
			if na < nb {
				return -1
			}
			return 1
		}
	}
	if ma[4] == mb[4] {
		return 0
	}
	if ma[4] == "" {
		return 1
	}
	if mb[4] == "" {
		return -1
	}
	return strings.Compare(ma[4], mb[4])
}

func writeHTML(w http.ResponseWriter, isHTTPS bool, status int, body string) {
	ApplySecurityHeaders(w, isHTTPS)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(body))
}

type oauthConsentView struct {
	ServiceName  string
	ClientName   string
	RedirectURI  string
	Scopes       []string
	Sealed       string
	CSRF         string
	SignedInUser string
	HasSession   bool
	GitHubURL    string
}

func renderOAuthConsentHTML(v oauthConsentView) string {
	var scopeItems strings.Builder
	for _, s := range v.Scopes {
		scopeItems.WriteString("<li><code>" + html.EscapeString(s) + "</code></li>")
	}
	ghLink := ""
	if v.GitHubURL != "" {
		ghLink = `<p><a href="` + html.EscapeString(v.GitHubURL) + `">Sign in with GitHub</a></p>`
	}
	authBlock := `<label for="token">Caller Token</label><input id="token" name="token" type="password" autocomplete="current-password" placeholder="Paste CALLER_TOKEN">`
	if v.HasSession {
		authBlock = `<p>Authenticated as <strong>@` + html.EscapeString(v.SignedInUser) + `</strong>.</p>`
	}
	return `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Authorize MCP Access — ` + html.EscapeString(v.ServiceName) + `</title></head><body><main>` +
		`<h1>Connect MCP client to ` + html.EscapeString(v.ServiceName) + `?</h1>` +
		`<p>Client: <code>` + html.EscapeString(v.ClientName) + `</code> &middot; Redirect: <code>` + html.EscapeString(v.RedirectURI) + `</code></p>` +
		`<ul>` + scopeItems.String() + `</ul>` + ghLink +
		`<form method="post" action="/oauth/authorize">` +
		`<input type="hidden" name="sealed" value="` + html.EscapeString(v.Sealed) + `">` +
		`<input type="hidden" name="csrf" value="` + html.EscapeString(v.CSRF) + `">` +
		authBlock +
		`<button type="submit" name="decision" value="approve">Approve MCP Access</button>` +
		`<button type="submit" name="decision" value="deny" formnovalidate>Deny</button>` +
		`</form></main></body></html>`
}

func renderAdminLoginHTML(serviceName, errMsg string, ghEnabled, ownerTokenEnabled bool) string {
	errBanner, ghBtn, tokForm := "", "", ""
	if errMsg != "" {
		errBanner = `<div class="err">` + html.EscapeString(errMsg) + `</div>`
	}
	if ghEnabled {
		ghBtn = `<p><a class="gh-btn" href="/admin/auth/github">Sign in with GitHub</a></p>`
	}
	if ownerTokenEnabled {
		tokForm = `<form method="post" action="/admin/login"><label for="token">Caller Token</label><input id="token" name="token" type="password" required autocomplete="current-password"><button type="submit">Open Control Center</button></form>`
	}
	return `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>` + html.EscapeString(serviceName) + ` — Admin Sign In</title></head><body><main><h1>` + html.EscapeString(serviceName) + `</h1>` + errBanner + ghBtn + tokForm + `</main></body></html>`
}

func renderAdminDashboardHTML(serviceName, mcpSlug, origin, csrf, viewer, role string) string {
	escService, escCSRF := html.EscapeString(serviceName), html.EscapeString(csrf)
	escViewer := html.EscapeString(viewer + " (" + role + ")")
	escCmd := html.EscapeString("claude mcp add --transport http " + mcpSlug + " " + origin + "/mcp")
	csrfJSON, _ := json.Marshal(csrf)
	return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="csrf-token" content="` + escCSRF + `"><title>` + escService + ` — Control Center</title></head><body>` +
		`<header><h1>` + escService + `</h1><span>` + escViewer + `</span>` +
		`<form method="post" action="/admin/logout"><input type="hidden" name="csrf" value="` + escCSRF + `"><button type="submit">Sign Out</button></form></header>` +
		`<main><p><code>` + escCmd + `</code></p><pre id="state-view">Loading /admin/api/state...</pre></main>` +
		`<script>const CSRF = ` + string(csrfJSON) + `;fetch('/admin/api/state',{credentials:'same-origin'}).then((r)=>r.json()).then((d)=>{document.getElementById('state-view').textContent=JSON.stringify(d,null,2);}).catch(()=>{});</script>` +
		`</body></html>`
}

func renderGitHubErrorHTML(serviceName, title, msg string) string {
	return `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>` + html.EscapeString(title) + ` — ` + html.EscapeString(serviceName) + `</title></head><body><main><h1>` + html.EscapeString(title) + `</h1><div class="err">` + html.EscapeString(msg) + `</div><a href="/admin">Back to Sign In</a></main></body></html>`
}

// ValidateFederatedMcpServerURL validates a 3rd-party HTTPS MCP server URL via internal/mcpfed.
func ValidateFederatedMcpServerURL(rawURL, selfHost string) mcpfed.SafeHTTPSURLResult {
	return mcpfed.IsSafePublicHTTPSURL(rawURL, selfHost)
}

// SealVaultPayload encrypts a VaultSecretPayload with v2. AES-256-GCM row-bound AAD.
func SealVaultPayload(params mcpfed.SealVaultParams) mcpfed.SealVaultResult {
	return mcpfed.SealVaultCredentials(params)
}

// OpenVaultPayload authenticates and decrypts a v2. AES-256-GCM vault ciphertext.
func OpenVaultPayload(params mcpfed.UnsealVaultParams) mcpfed.UnsealVaultResult {
	return mcpfed.UnsealVaultCredentials(params)
}

func (m *Manager) listPublicMcpServersLocked(ownerID string) []mcpfed.PublicMCPServerSummary {
	out := make([]mcpfed.PublicMCPServerSummary, 0)
	for _, row := range m.st.McpServers {
		if row.UserID == ownerID {
			out = append(out, mcpfed.ToPublicMCPServerSummary(row))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Slug < out[j].Slug })
	return out
}

// HandleAdminMcpServers implements GET/POST/DELETE /admin/api/mcp/servers(/:id).
func (m *Manager) HandleAdminMcpServers(w http.ResponseWriter, r *http.Request, sess verifiedSession, origin string, isHTTPS bool) {
	ownerID, p := sess.EffectiveOwnerID(), r.URL.Path
	if p == "/admin/api/mcp/servers" && r.Method == http.MethodGet {
		m.mu.Lock()
		list := m.listPublicMcpServersLocked(ownerID)
		m.mu.Unlock()
		_, vaultOK, _ := mcpfed.ValidateVaultMasterKey(m.vaultKey)
		writeJSONResp(w, isHTTPS, http.StatusOK, map[string]any{"ok": true, "userId": ownerID, "vaultConfigured": vaultOK, "servers": list})
		return
	}
	if (p == "/admin/api/mcp/servers" || p == "/admin/api/mcp/connect") && r.Method == http.MethodPost {
		m.handleUpsertMcpServer(w, r, ownerID, origin, isHTTPS)
		return
	}
	if (strings.HasPrefix(p, "/admin/api/mcp/servers/") && r.Method == http.MethodDelete) || (p == "/admin/api/mcp/disconnect" && r.Method == http.MethodPost) {
		target := strings.TrimSpace(strings.TrimPrefix(p, "/admin/api/mcp/servers/"))
		if p == "/admin/api/mcp/disconnect" {
			buf, tooBig, _ := readCappedBody(w, r, 16384)
			if tooBig {
				writeJSONResp(w, isHTTPS, http.StatusRequestEntityTooLarge, map[string]string{"error": "payload_too_large"})
				return
			}
			var b struct {
				ID   string `json:"id"`
				Slug string `json:"slug"`
			}
			_ = json.Unmarshal(buf, &b)
			if target = strings.TrimSpace(b.Slug); target == "" {
				target = strings.TrimSpace(b.ID)
			}
		}
		if dec, err := url.PathUnescape(target); err == nil {
			target = strings.TrimSpace(dec)
		}
		if target == "" {
			writeJSONResp(w, isHTTPS, http.StatusBadRequest, map[string]string{"error": "missing_id"})
			return
		}
		deleted := false
		m.mu.Lock()
		for k, row := range m.st.McpServers {
			if row.UserID == ownerID && (row.ID == target || row.Slug == target) {
				delete(m.st.McpServers, k)
				deleted = true
				break
			}
		}
		if deleted {
			_ = m.saveLocked()
		}
		m.mu.Unlock()
		writeJSONResp(w, isHTTPS, http.StatusOK, map[string]any{"ok": true, "deleted": deleted})
		return
	}
	writeJSONResp(w, isHTTPS, http.StatusMethodNotAllowed, map[string]string{"error": "method_not_allowed"})
}

func (m *Manager) handleUpsertMcpServer(w http.ResponseWriter, r *http.Request, ownerID, origin string, isHTTPS bool) {
	buf, tooBig, err := readCappedBody(w, r, 65536)
	if tooBig {
		writeJSONResp(w, isHTTPS, http.StatusRequestEntityTooLarge, map[string]string{"error": "payload_too_large"})
		return
	}
	var body struct {
		Name            string          `json:"name"`
		Slug            string          `json:"slug"`
		RemoteURL       string          `json:"remoteUrl"`
		URL             string          `json:"url"`
		Transport       string          `json:"transport"`
		BearerToken     *string         `json:"bearerToken"`
		Headers         json.RawMessage `json:"headers"`
		Domains         json.RawMessage `json:"domains"`
		AutoRouteScrape bool            `json:"autoRouteScrape"`
		Enabled         *bool           `json:"enabled"`
	}
	if err != nil || json.Unmarshal(buf, &body) != nil {
		writeJSONResp(w, isHTTPS, http.StatusBadRequest, map[string]string{"error": "invalid_json"})
		return
	}
	rawRemote := strings.TrimSpace(body.RemoteURL)
	if rawRemote == "" {
		rawRemote = strings.TrimSpace(body.URL)
	}
	selfHost := ""
	if u, uErr := url.Parse(origin); uErr == nil {
		selfHost = u.Hostname()
	}
	urlCheck := ValidateFederatedMcpServerURL(rawRemote, selfHost)
	if !urlCheck.OK {
		writeJSONResp(w, isHTTPS, http.StatusBadRequest, map[string]any{"ok": false, "error": "invalid_remote_url", "message": urlCheck.Reason})
		return
	}
	hdrs, hdrOK, hdrMsg := mcpfed.SanitizeSecretHeadersInput(body.BearerToken, body.Headers, len(body.Headers) > 0)
	if !hdrOK {
		writeJSONResp(w, isHTTPS, http.StatusBadRequest, map[string]any{"ok": false, "error": "invalid_headers", "message": hdrMsg})
		return
	}
	domains, domOK, domMsg := mcpfed.ValidateConnectorDomains(body.Domains, urlCheck.Origin, body.AutoRouteScrape)
	if !domOK {
		writeJSONResp(w, isHTTPS, http.StatusBadRequest, map[string]any{"ok": false, "error": "invalid_domains", "message": domMsg})
		return
	}
	cleanName := strings.TrimSpace(mcpfed.StripMCPSmugglingChars(body.Name))
	if cleanName == "" {
		cleanName = urlCheck.Hostname
	}
	slug := strings.ToLower(strings.TrimSpace(body.Slug))
	if slug != "" {
		if !mcpfed.IsValidMCPConnectorSlug(slug) {
			writeJSONResp(w, isHTTPS, http.StatusBadRequest, map[string]any{"ok": false, "error": "invalid_slug"})
			return
		}
	} else {
		slug = mcpfed.NormalizeMCPConnectorSlug(cleanName)
	}

	authType, kind := "none", "none"
	if len(hdrs) > 0 {
		authType, kind = "headers", "headers"
	}
	nowMs, mapKey := m.cfg.Now().UnixMilli(), ownerID+"|"+slug
	m.mu.Lock()
	existing, hasExisting := m.st.McpServers[mapKey]
	serverID, createdAt := "mcp_"+randomHex(10), nowMs
	if hasExisting {
		serverID, createdAt = existing.ID, existing.CreatedAt
	}
	m.mu.Unlock()

	var encCreds *string
	secVer := 2
	payloadObj := mcpfed.OrderedObject{{Key: "kind", Value: kind}, {Key: "pinnedOrigin", Value: urlCheck.Origin}, {Key: "pinnedUrl", Value: urlCheck.Normalized}}
	if len(hdrs) > 0 {
		payloadObj.Set("headers", hdrs)
		sp := mcpfed.SealVaultParams{VaultMasterKey: m.vaultKey, UserID: ownerID, RemoteOrigin: urlCheck.Origin, Payload: payloadObj}
		sp.ID, sp.Slug, sp.AuthType = &serverID, &slug, &authType
		sealed := SealVaultPayload(sp)
		if !sealed.OK {
			st := sealed.Status
			if st == 0 {
				st = http.StatusServiceUnavailable
			}
			writeJSONResp(w, isHTTPS, st, sealed)
			return
		}
		ct := sealed.Ciphertext
		encCreds, secVer = &ct, sealed.SecretVersion
	}
	transport := "streamable-http"
	if body.Transport == "sse" {
		transport = "sse"
	}
	parsedSec, _ := mcpfed.ParseVaultSecretPayloadObject(payloadObj)
	row := mcpfed.StoredMCPServerRow{ID: serverID, UserID: ownerID, Slug: slug, Name: cleanName, RemoteURL: urlCheck.Normalized}
	row.RemoteOrigin, row.Transport, row.AuthType, row.EncryptedCredentials, row.SecretVersion = urlCheck.Origin, transport, authType, encCreds, &secVer
	row.AuthSummary, row.Domains, row.AutoRouteScrape = mcpfed.BuildMaskedAuthSummary(parsedSec), domains, body.AutoRouteScrape
	row.CachedTools, row.ToolCount, row.Enabled = existing.CachedTools, len(existing.CachedTools), body.Enabled == nil || *body.Enabled
	row.CreatedAt, row.UpdatedAt = createdAt, nowMs
	m.mu.Lock()
	m.st.McpServers[mapKey] = row
	_ = m.saveLocked()
	m.mu.Unlock()
	writeJSONResp(w, isHTTPS, http.StatusOK, map[string]any{"ok": true, "server": mcpfed.ToPublicMCPServerSummary(row)})
}

// ListDecryptedMcpServers decrypts all enabled MCP servers belonging to ownerID for /v1/mcp/query and call_connected_mcp.
func (m *Manager) ListDecryptedMcpServers(ownerID string) ([]ConnectedMcpServer, error) {
	ownerID = mcpfed.ResolveCallerUserID(ownerID, "")
	m.mu.Lock()
	rows := make([]mcpfed.StoredMCPServerRow, 0)
	for _, r := range m.st.McpServers {
		if r.UserID == ownerID && r.Enabled {
			rows = append(rows, r)
		}
	}
	m.mu.Unlock()
	sort.Slice(rows, func(i, j int) bool { return rows[i].Slug < rows[j].Slug })
	out := make([]ConnectedMcpServer, 0, len(rows))
	for _, row := range rows {
		hdrMap := make(map[string]string)
		var oauthTok *mcpfed.VaultSecretOAuth
		if row.EncryptedCredentials != nil && *row.EncryptedCredentials != "" && row.AuthType != "none" {
			idCopy, slugCopy, authCopy := row.ID, row.Slug, row.AuthType
			up := mcpfed.UnsealVaultParams{VaultMasterKey: m.vaultKey, UserID: ownerID, RemoteOrigin: row.RemoteOrigin, RemoteURL: row.RemoteURL}
			up.ID, up.Slug, up.AuthType, up.SecretVersion, up.Ciphertext = &idCopy, &slugCopy, &authCopy, row.SecretVersion, *row.EncryptedCredentials
			unsealed := OpenVaultPayload(up)
			if !unsealed.OK {
				return nil, errors.New(unsealed.Message)
			}
			parsed, err := mcpfed.ParseVaultSecretPayloadObject(unsealed.Payload)
			if err != nil {
				return nil, err
			}
			for _, e := range parsed.Headers {
				if s, ok := e.Value.(string); ok {
					hdrMap[e.Key] = s
				}
			}
			oauthTok = parsed.OAuth
		}
		item := ConnectedMcpServer{ID: row.ID, UserID: row.UserID, Slug: row.Slug, Name: row.Name, RemoteURL: row.RemoteURL, RemoteOrigin: row.RemoteOrigin}
		item.Transport, item.AuthType, item.Domains, item.AutoRouteScrape = row.Transport, row.AuthType, row.Domains, row.AutoRouteScrape
		item.Tools, item.Headers, item.OAuth = row.CachedTools, hdrMap, oauthTok
		out = append(out, item)
	}
	return out, nil
}
