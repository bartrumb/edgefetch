# hubauth

## Overview
Package `hubauth` implements OAuth 2.1 + PKCE (`S256`) + Dynamic Client Registration (RFC 7591) + Protected Resource & Authorization Server Metadata (RFC 9728 / RFC 8414), multi-user GitHub OAuth with founder pinning and `ght1.` AES-256-GCM token sealing, the `/admin` Control Center & `v2.` AES-256-GCM MCP credential vault, and listener/proxy/origin/header hardening for the Go Hub.

## Interface
- `[doc.go:Config]`, `[doc.go:Manager]`, `[doc.go:NewManager]`, `[doc.go:Principal]`, `[doc.go:Decision]`, `[doc.go:Callbacks]`, `[doc.go:Manager.AuthorizeCaller]`: Central authenticator/authorizer (`CallerToken`, `McpToken`, OAuth `efa_*` step-up scopes where `crawl:fetch` implies `crawl:read`, GitHub session cookies, tokenless loopback) with atomic `0600` disk persistence (`filepath.Join(dataDir, "state", "oauth_state.json")`).
- `[oauth.go:Manager.HandleOAuthOrWellKnown]`, `[oauth.go:Manager.HandleProtectedResourceMetadata]`, `[oauth.go:Manager.HandleAuthServerMetadata]`, `[oauth.go:Manager.HandleRegister]`, `[oauth.go:Manager.HandleAuthorize]`, `[oauth.go:Manager.HandleToken]`, `[oauth.go:Manager.HandleRevoke]`: RFC 9728/8414 discovery, RFC 7591 registration, PKCE `S256` consent, rotating refresh tokens (`efr_<grantId>.<gen>.<secret>`), and RFC 7009 revocation.
- `[github_auth.go:Manager.HandleGitHubStart]`, `[github_auth.go:Manager.HandleGitHubCallback]`, `[github_auth.go:SealGitHubToken]`, `[github_auth.go:OpenGitHubToken]`, `[github_auth.go:MintGitHubSessionJWT]`, `[github_auth.go:VerifyGitHubSessionJWT]`: Multi-user GitHub OAuth flow (`/admin/auth/github`, `/admin/auth/github/callback`), `ght1.` HKDF-SHA256 + AES-256-GCM token sealing, and `HS256` session JWTs.
- `[admin.go:Manager.HandleAdmin]`, `[admin.go:Manager.HandleAdminPage]`, `[admin.go:Manager.HandleAdminLogin]`, `[admin.go:Manager.HandleAdminLogout]`, `[admin.go:Manager.HandleAdminState]`, `[admin.go:Manager.HandleAdminFetch]`, `[admin.go:Manager.HandleAdminAffinityClear]`, `[admin.go:Manager.HandleAdminEventsClear]`, `[admin.go:Manager.HandleAdminGrantsRevoke]`, `[admin_html.go:Manager.HandleAdminMcpServers]`, `[admin_html.go:Manager.ListDecryptedMcpServers]`, `[admin_html.go:Manager.HandleAdminTelemetry]`, `[admin_html.go:Manager.CheckHubUpdateStatus]`: `/admin` UI/APIs, MCP `v2.` vault CRUD & decryption, `DO_NOT_TRACK=1` telemetry enforcement, and cached GitHub release checks.
- `[conn_guard.go:WrapListener]`, `[conn_guard.go:TrackConnState]`, `[conn_guard.go:ResolveClientIP]`, `[conn_guard.go:ResolveConfiguredPublicOrigin]`, `[conn_guard.go:ResolveRequestPublicOrigin]`, `[conn_guard.go:ApplySecurityHeaders]`, `[conn_guard.go:ParseRedirectAllowlist]`: Per-IP & global socket caps with loopback bypass headroom, trusted proxy client IP & origin resolution, redirect allowlist parsing, and baseline security headers.

## Invariants
- **Refresh Lineage & Replay Revocation (`T2-C1`)**: `HandleToken` verifies `grant.ClientID == client_id` before touching grant state; replaying an already-rotated `gen < grant.CurrentGen` with matching `client_id` immediately revokes the entire grant and deletes all active `efa_*` access tokens.
- **Brute-Force Lockout & Logout Revocation (`T2-C2`, `T2-C3`)**: `HandleAdminLogin` locks out an IP (`429`, `Retry-After: 600`) after `5` failed attempts within `10m` using `ResolveClientIP` (ignoring spoofed `X-Forwarded-For` when `trustProxy == false`), `HandleAdminLogout` persists session revocation so replayed cookies immediately return `401`, and mutating `/admin/api/*` routes enforce CSRF + same-origin `Origin` + `64 KiB` body caps (`413`).
- **Zero-Secret OTLP Spans**: `edgefetch.oauth.*` and `edgefetch.admin.*` spans never record bearer tokens, authorization codes, PKCE verifiers, cookies, CSRF tokens, or URL query parameters.

## Side Effects
- Atomically writes `filepath.Join(dataDir, "state", "oauth_state.json")` (`0600`) when `DataDir != ""`, reads `crypto/rand.Read`, performs outbound HTTP via injected `HTTPClient` for GitHub OAuth and release checks (unless `EDGEFETCH_DISABLE_UPDATE_CHECK=1`), and records OTLP spans via `otel.Exporter`.

## Verification
- Run: `go test -race -v ./internal/hub/hubauth/...`
