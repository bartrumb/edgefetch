# Security Policy & Threat Model

EdgeFetch is designed to run safely inside private networks (such as Home Assistant OS servers, homelabs, or branch offices) without exposing those networks to lateral movement, inbound attacks, or privilege escalation.

## Threat Model & Defense-in-Depth Controls

### 1. Zero Inbound Attack Surface
- **Outbound-only sockets in `agent` mode:** `edgefetch --mode=agent` never calls `net.Listen`. Router port-forwarding, UPnP, and VPN/tunnel daemons are unnecessary.
- **No generic proxy protocol:** EdgeFetch is **not** an HTTP `CONNECT` or SOCKS5 relay. It accepts structured JSON `FetchCall` dispatches over a single authenticated TLS 1.2/1.3 WebSocket and executes bounded HTTP `GET` requests only.

### 2. Least-Privilege Token Separation (`CALLER_TOKEN`, `AGENT_TOKENS`, & `EDGEFETCH_SERVER_TOKEN`)
- **Caller Token (`CALLER_TOKEN`):** Authorizes upstream workflows to submit `POST /fetch` batches and view `GET /agents` on the Hub. Never place `CALLER_TOKEN` on standby nodes.
- **Standalone Server Token (`EDGEFETCH_SERVER_TOKEN`):** In `--mode=server`, `edgefetch` refuses to bind non-loopback addresses (`:8080`, `0.0.0.0:8080`) unless `EDGEFETCH_SERVER_TOKEN` (`>= 24` random chars, verified in constant time via SHA-256 + `subtle.ConstantTimeCompare` on `POST /fetch`) is configured, or `--allow-unauthenticated` (`EDGEFETCH_ALLOW_UNAUTHENTICATED=1`) is explicitly passed inside an isolated container bridge.
- **Per-Site Agent Tokens (`AGENT_TOKENS`):** Standby nodes hold site-scoped tokens (`{"site-1":"...","site-2":"..."}`) accepted **only** on `GET /agent/ws` and `POST /agent/reply`.
  - Comparisons use length-independent constant-time byte XOR (`sameBytes`), failing closed whenever a token is unset, `< 24` characters, or malformed JSON.
  - `siteId` is bound to the matched token key on the server so `site-1` cannot spoof `site-2`, and any fallback `AGENT_TOKEN` cannot claim a `siteId` present in `AGENT_TOKENS`.
  - Every `POST /agent/reply` must present both the server-generated `X-Job-Id` and constant-time verified one-time `X-Job-Nonce` actively pending for that exact `siteId` (`verifyPendingJob` checked before decompressing request streams; `413` replies fail the job immediately without peer re-crawls).
- **Mandatory TLS for Non-Loopback Hubs:** `internal/agent/config.go` refuses cleartext `http://` / `ws://` hub URLs on any non-loopback address (`127.0.0.1` / `::1`), even if `EDGEFETCH_ALLOW_INSECURE_HUB=1` is set in the environment.

### 3. Multi-Layer SSRF, Redirect & Robots Protection
Even if a caller token were compromised, an agent cannot be used to probe local LAN devices, Home Assistant APIs, Tailscale peers, cloud metadata endpoints, or robots-disallowed paths:
1. **Hop-by-Hop URL & RFC 9309 `/robots.txt` Validation (`crawl.PublicHTTPS` + `WithBlockedHost` + `WithAllowedHosts`):**
   - Automatic HTTP client redirects are disabled in both Go and Cloudflare overflow. Every hop (up to 5) re-evaluates URL rules (`https://:443` multi-label DNS host, no IP literals, no `localhost`, no `user:pass@`), per-host locks/pacing, and `/robots.txt` (`512 KiB` parse cap, UTF-8 BOM stripping, percent-encoding normalization, exact product-token matching).
   - Callers cannot disable `robots.txt` (`400 robots_required`) unless the hub/agent owner explicitly configures `ROBOTS_BYPASS_HOSTS` / `EDGEFETCH_ROBOTS_BYPASS_HOSTS` (empty by default, audited in `hub_events`).
2. **Dial-Time Socket Peer Inspection (`politeness.RejectNonPublicPeer` via `net.Dialer.Control` & `net/netip`):**
   - Runs inside Go's dialer *after* DNS resolution creates the OS socket and *immediately before* `connect()` fires — eliminating DNS-rebinding TOCTOU races, and permanent SSRF refusals (`ErrNonPublicPeer`) are never retried.
   - Permits IPv6 **only** inside `2000::/3` global unicast before applying exclusions, blocking `0.0.0.0/8`, loopback (`127.0.0.0/8`, `::1`), RFC 1918 LANs (`10/8`, `172.16/12` including Home Assistant's `172.30.32.0/23` bridge, `192.168/16`), RFC 6598 CGNAT / Tailscale (`100.64.0.0/10`), link-local / cloud metadata (`169.254.0.0/16`, `fe80::/10`), 6to4 relay (`192.88.99.0/24`), ULA (`fc00::/7`), site-local (`fec0::/10`), ORCHID/ORCHIDv2 (`2001:10::/28`, `2001:20::/28`), documentation (`2001:db8::/32`, `3fff::/20`), SRv6 (`5f00::/16`), and IPv6-to-IPv4 transition prefixes (`::/96`, `0:0:0:0:ffff:0::/96`, `64:ff9b::/96`, `64:ff9b:1::/48`, `2002::/16`, `2001::/32`, `100::/64`).
3. **Headless Browser Subresource Isolation (`internal/browser/proxy.go` + `edgefetch_fat`):**
   - `/robots.txt` is verified **before** launching or navigating Chromium (including every `interact` `navigate` step).
   - Chromium runs with `--proxy-server=http://127.0.0.1:<port>`, `--host-resolver-rules="MAP * ~NOTFOUND , EXCLUDE 127.0.0.1"`, and `--disable-quic`, forcing 100% of browser subresources through `SSRFProxy` (`CONNECT :443` + `RejectNonPublicPeer`) so untrusted page JS can never probe Home Assistant (`:8123`) or RFC 1918 LAN IPs.
   - If a rendered page presents a CAPTCHA or anti-bot challenge (`DetectRenderedChallenge`), EdgeFetch halts immediately (`outcome: "challenge"`) and never attempts to solve, click through, or wait out challenges.
   - Search (`POST /v1/search`) uses Brave Search API / SearXNG JSON / local `SEARCH` D1 FTS5 only — search-engine HTML scraping is **never** routed through residential HAOS nodes.
4. **Untrusted Agent Artifact Verification & Safe Serving (`hub/src/storage.ts`, `hub/src/ingest.ts`):**
   - Agent R2 uploads (`PUT /agent/artifacts/<blobSha256>`) enforce per-job nonce/site/requestId/quota authorization, `Content-Length` caps, and R2 `sha256` + `If-None-Match: *` create-once checks.
   - `IngestWorkflow` streams stored gzip blobs through `DecompressionStream('gzip')` with a hard `16 MiB` decompression-bomb cutoff and verifies `SHA-256(uncompressed)` before setting `artifacts.verified_at`; poisoned or bombed blobs are deleted from R2 and scrubbed from `META` D1, and unverified blobs are **never** derived into `documents` or indexed in `SEARCH` D1 FTS5.
   - `GET /v1/artifacts/<blobSha256>` serves raw content strictly as `text/plain; charset=utf-8` with `X-Content-Type-Options: nosniff`, `Content-Security-Policy: sandbox`, and `Content-Disposition: attachment` (never active HTML).

### 4. Container Hardening, Reproducible Supply Chain & Memory Bounds
- **Distroless Runtime & Checked-Out Context Builds:** Production images use `gcr.io/distroless/static-debian12` (~9 MB total, no `/bin/sh`, no package manager) built directly from the checked-out repository commit with SHA-pinned GitHub Actions, `govulncheck`, `staticcheck`, and SLSA provenance attestations.
- **Linux `PR_SET_NO_NEW_PRIVS` + `AllThreadsSyscall6` (`internal/priv/priv_linux.go`):** Reads `/data/options.json` (`0600 root:root`), performs best-effort zeroing of the raw read buffer (noting `json.Unmarshal` allocates Go `string` values on the heap), applies `prctl(PR_SET_NO_NEW_PRIVS, 1)` across **all** Go runtime OS threads via `syscall.AllThreadsSyscall6`, clears supplementary groups (`Setgroups([])`), drops all threads to UID/GID `65532:65532`, and verifies `uid == 65532` before opening any socket.
- **AppArmor Profile (`edgefetch_fat/apparmor.txt`):** Denies raw/packet sockets, `mount`, `ptrace`, `sys_admin`, `net_admin`, and `/proc/kcore` / `/sys/firmware`, paired with `hassio_api: false`, `homeassistant_api: false`, and `host_network: false`.
- **Bounded Memory, Server Concurrency & SQLite State:** Enforces `MaxResponseHeaderBytes = 64 KiB`, `io.LimitReader(maxBytes + 1)` per-URL caps, `MaxTotalBytes = 16 MiB` default per-batch body budget, `MaxConcurrentServerCalls = 4` (`503 server_busy`), `ReadTimeout = 30s` / `IdleTimeout = 120s`, `MaxTrackedHosts = 512` LRU host eviction, `1 MiB` UTF-8 WebSocket frame caps, `20 MiB` streaming gunzip caps, and daily Durable Object `alarm()` SQLite cleanup.

### 5. Self-Hosted OAuth 2.1, `/mcp` & `/admin` Hardening
- **Loopback-Only Default Redirects:** Dynamic Client Registration (`POST /oauth/register`) is rate-limited per IP, omits ring-buffer noise, evicts only ungranted clients, and rejects non-loopback redirect URIs unless the host matches `OAUTH_REDIRECT_ALLOWLIST` (requiring explicit `CALLER_TOKEN` entry on consent even when signed into `/admin`, and labeling `client_name` as unverified self-reported).
- **Atomic Refresh Rotation & Replay Revocation:** Refresh tokens rotate inside a single synchronous Durable Object SQLite method (`oauthRotateRefreshToken`) requiring `client_id`, keeping consumed token hashes until grant expiry, and revoking the **entire grant** immediately if a rotated refresh token is replayed.
- **Pre-Check Lockout & Query-String Redaction:** Brute-force lockouts on `/admin/login` and `/oauth/authorize` are checked before evaluating tokens (`auth_failures` bounded against IPv6 sprays), and URL query strings / fragments are stripped before writing crawl or MCP activity events.

### 6. Cryptographic Release Signing, SLSA Provenance & Contributor Secret Isolation
- **Owner-Only Ed25519 Release Signatures (`checksums.txt.sig`):** Official `v*` GitHub Releases sign `checksums.txt` using an owner-only Ed25519 private key stored exclusively in GitHub Actions Sealed Secrets (`RELEASE_SIGNING_PRIVATE_KEY`) and verified against [`keys/release-signing-pub.pem`](keys/release-signing-pub.pem). Fork pull requests never receive repository secrets, and GitHub Repository Rulesets restrict `v*` tag creation/mutation and `main` force-pushes to the repository owner.
- **GitHub SLSA Build Provenance Attestations:** Every release archive (`*.tar.gz`, `*.zip`, `checksums.txt`) and multi-arch GHCR container digest (`ghcr.io/bartrumb/edgefetch-agent`, `ghcr.io/bartrumb/edgefetch`) publishes cryptographic SLSA provenance attestations verifiable via `gh attestation verify --owner bartrumb`.
- **Operator-Level Web Bot Auth Isolation (`BOT_SIGNING_PRIVATE_KEY`):** Open-source builds never embed a shared bot-signing private key. Each self-hosted operator mints a dedicated Ed25519 keypair (`edgefetch keygen-bot-auth`) for their own Hub domain (`/.well-known/http-message-signatures-directory`), preventing third-party key abuse.

## Safe Deployment Checklist

1. Generate tokens with at least 32 bytes of cryptographic randomness (`openssl rand -hex 32`).
2. Use per-site `AGENT_TOKENS` JSON so a decommissioned device can be revoked individually without rotating other sites.
3. Set `allowed_hosts` in your Home Assistant Add-on configuration whenever your workload targets a known set of domains.

## Reporting a Vulnerability

Please report security issues privately via [GitHub Security Advisories](https://github.com/bartrumb/edgefetch/security/advisories/new) rather than opening a public issue.
