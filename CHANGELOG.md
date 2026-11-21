# Changelog

All notable changes to EdgeFetch are documented in this file. This project adheres to [Semantic Versioning](https://semver.org/).

## [2.6.1] - 2026-11-21

### Security
- **Eliminated residual superlinear scanner & regex paths (`R4-H1`, `R4-H2`, `R4-H3`):**
  - Cached monotonic `nextNameBoundary` offsets inside `tryParseTagAt` (`hub/src/safe-input.ts`) so repeated `<x` pseudo-tags finish in linear $O(N)$ time (`< 5 ms` at 16K chars).
  - Anchored HTML attribute scanning with a `64 KiB` tag cap (`parseTagAttributes`), eliminated V8 ConsString rope flattening in `sanitizeAndResolveMarkdownProseLinksLinear`, cached `>` offsets per line in `extractMarkdownLinksAndImages`, and fixed an unanchored `.myshopify.com` detector pattern (`hub/src/scrape.ts`, `hub/src/extractors/providers/commerce-social/shopify.ts`).
  - Hardened `compileSafeUserRegex` (`hub/src/safe-input.ts`) so non-terminal optional/branch groups containing unbounded quantifiers (e.g. `a*(b)?aa*(b)?aa*$`) cannot reset ambiguity tracking unless followed by a disjoint mandatory barrier or true pattern end.
- **Markdown sanitization & inline-code stash preservation (`R4-M6`, `R4-M7`):**
  - Honored CommonMark backslash-escaped backticks (`\``) during inline code-span scanning so `` \`<img src=x onerror=...>` `` cannot smuggle raw HTML past tag stripping.
  - Hardened `hasDangerousUriScheme` against entity-encoded schemes (`javascript&colon;...`, numeric entities, and undecoded `&...;` before `/`/`?`/`#`) and stripped dangerous URI schemes on multi-line `[label\nlabel2](...)` links (`hub/src/scrape.ts`).
  - Preserved internal `\u0000EF...\u0000` inline-code stash sentinels across NUL-stripping passes (`hub/src/safe-input.ts`) so inline backtick spans survive `<svg>` removal (`SCRAPE_PIPELINE_VERSION = 28`).
- **Go worker, Chromium header scope, Portable Hub & Vouch Gate hardening (`R4-M*`, `D-L1`..`D-L4`):**
  - Scoped CDP `Fetch.requestPaused` caller headers to exact `(scheme, canonicalHost, effectivePort)`, restricted Linux `--no-sandbox` fallback strictly to Chromium sandbox-init diagnostics (`isSandboxStartupFailure`), bounded detached `/robots.txt` contexts + partial `1 MiB` trailing lines, and drained `runSession` worker goroutines unconditionally (`internal/browser`, `internal/crawl`, `internal/agent`, `internal/politeness`).
  - Hardened Portable Node/Deno Hub against `Host` header overrides in `safe-fetch.ts`, `1xx` response loops, unbounded origin streams (`32 MiB`), slowloris `POST` drips (`requestTimeout = 30s`), unmasked RFC 6455 client WebSocket frames (`1002`), and unvalidated `X-Forwarded-Host` issuer spoofing (`hub/portable/*`).
  - Fixed `.github/workflows/vouch.yml` to read `.github/VOUCHED.td` from `${BASE_SHA}` (preventing self-vouching in PR branches) and check DCO `Signed-off-by:` trailers across every non-merge commit in a multi-commit PR.
  - Removed destructive global `deduplicateClonedProseParagraphs` (`D-M1`, keeping scoped DOM carousel-clone class stripping), capped `salvageAshbyBoardFromTruncatedJson` at `5,000` jobs + verify concurrency `2` (`D-L1`), required `status === 200` on truncated ATS formatters (`D-L2`), restored `1h` OAuth access TTL alongside `90d` refresh TTL (`D-L3`), aligned MCP `capabilities.tools` (`D-L4`), and escaped `/admin` inline `<script>` backslashes/newlines.

### Fixed
- **ATS `jobs` search precision, Workday domain discovery & `similarOpenRoles` ranking (`hub/src/jobs.ts`, `hub/src/mcp.ts`):**
  - Replaced any-token `query` matching with phrase-first (`matchedOn: "phrase"`) and all-tokens (`matchedOn: "all_tokens"`) relevance filtering, ranking exact phrase matches first.
  - Added `minBaseMode: "floor" | "ceiling"` (default `"floor"`, checking `pay.min >= minBase`) and `strictPay` (default `false`, surfacing unlisted-pay roles with `payUnknown: true` and `payUnknownCount`).
  - Separated geographic `locations` filters from `"Remote"` workplace eligibility so `locations: ["United States", "Remote"]` enforces US geography instead of matching worldwide remote postings.
  - Added Workday CXS tenant/site probes (`wd5`/`wd1`) and search-assisted ATS discovery to `domains`, reported explicit `boardStatus: "not_found"` + `tried` when a domain has no ATS board, prevented cross-company bleed when `domains` or `company` is set, made `includePublicFeeds` strictly opt-in (`default: false`) with `sourcesUsed` telemetry, and restricted `verify` `similarOpenRoles` to distinctive title-token matches.

## [2.6.0] - 2026-11-20

### Added
- **Full-store `catalog` sync (`POST /v1/catalog` & MCP `catalog` tool):** Polite (`>= 2s` + jitter) whole-catalog pagination for Shopify (`/products.json` + custom-domain `.js` inventory enrichment) and WooCommerce Store API (`/wp-json/wc/store/v1/products`), NDJSON R2 snapshot streaming, `shrink` projection, `sinceArtifactId` diffing, and UCP `robots.txt` discovery (`SCRAPE_PIPELINE_VERSION = 26`..`27`).
- **ATS `jobs` reliability, `verify` mode & 16 MiB board support:** Added batch job-liveness `mode: "verify"` (`live`, `closed` + `similarOpenRoles`, `board_gone`, `unknown`), domain-to-ATS auto-discovery, `iCIMS` (`?ss=1&in_iframe=1`) and Workday (`onsite` + `?offset=` paging) enhancements, `16 MiB` Ashby board support with linear truncated-JSON salvaging, and Go `KindText` `Accept` allowlist alignment.
- **RFC 9309 full compliance, 3-strikes `429` backoff & 64 KiB linear framework detection:** Added 5-hop `/robots.txt` redirect handling, `Cache-Control: max-age` clamping (`[60s, 24h]`), `robots_unreachable` classification, `ROBOTS_BYPASS_HOSTS` operator override, 3-attempt adaptive `429` backoff, `detectSiteFrameworkLinear`, Inertia `data-page` SSR hydration unlock, fault-isolated `runAdapterSyncInBulkhead`, Chromium native OS sandbox probing, 4-way multi-domain agent concurrency, and `.github/VOUCHED.td` contributor gate.

### Security
- **Round 3 security re-audit fixes (`R3-H1`..`R3-H3`, `R3-M1`..`R3-M10`):** Replaced quadratic HTML/Markdown/provider regexes with linear scanners, prevented split-tag `<im<form></form>g>` reassembly, rejected stacked quantifiers in `compileSafeUserRegex`, pinned dial-time DNS resolutions in `safe-fetch.ts`, sanitized `origin-markdown` HTML/WAF/prompt-injection vectors, scoped CDP custom headers via `Fetch.requestPaused` + `taintedByHeaders` browser recycling, pinned `O_NOFOLLOW` descriptor `fchmod`/`fchown` in `internal/priv`, and tag-locked GitHub `release` environment secrets (`v*`).

## [2.5.5] - 2026-11-20

### Added
- **Agentic Web Standards (`G1`–`G3`):**
  - **Markdown for Agents (`G1`):** Page and default scrape requests negotiate `Accept: text/markdown, text/html;q=0.9, application/xhtml+xml;q=0.8, */*;q=0.7` so origins with Cloudflare Markdown for Agents enabled return Markdown directly (`contentSource: "origin-markdown"`), skipping HTML tag stripping while preserving BM25 passage reranking and optional PII redaction.
  - **Cloudflare Content Signals in `/robots.txt` (`G2`):** `politeness.ParseRobotsTxt` and Hub overflow honor `Content-Signal: ai-input=yes|no` per RFC 9309 `User-agent` group specificity (`edgefetch` overrides `*`), halting retrieval with `disallowed by /robots.txt Content-Signal: ai-input=no` and advertising `"contentSignals": "honored (ai-input)"` in `/.well-known/edgefetch-bot.json`.
  - **HTTP `402 Payment Required` / `x402` (`G3`):** Classifies HTTP `402` responses as `outcome: "payment_required"` (`StopsHost == true`, never retried and never auto-paid) and surfaces parsed x402 payment requirements cleanly to calling agents.

### Security
- **Chromium WebRTC STUN UDP, session & custom-header hardening (`M2`, `Low`):** Added `--webrtc-ip-handling-policy=disable_non_proxied_udp` and `--enforce-webrtc-ip-permission-check` alongside `--force-webrtc-ip-handling-policy=disable_non_proxied_udp` (verified by a live loopback UDP listener check), disposed `keepSession` browser contexts when initial navigation/actions fail, and cleared `Network.setExtraHTTPHeaders` immediately after initial-host navigation completes so cross-origin JS requests never inherit caller headers.
- **Linux `PR_SET_DUMPABLE=0`, AppArmor `/proc` rules & All-in-One UID isolation (`H2`, `H3`, `M7`):** Applied `prctl(PR_SET_DUMPABLE, 0)` across all OS threads in `priv.DropRoot`, added `deny /proc/*/mem` and `deny /proc/*/environ` to `edgefetch_fat/apparmor.txt`, separated `Dockerfile.all-in-one` into `node:node` (`1000:1000`, `0700 /data/hub`) for the Hub and `65532:65532` (`su-exec` + `env -i` forwarding worker-scoped `EDGEFETCH_*` / `TZ` / `SSL_CERT_FILE`) for the Go worker + Chromium, and verified AppArmor/UID/`Dumpable: 0` invariants in `docker-multiarch` CI.
- **Embedded error URL scrubbing, PDF `maxBytes`, SDK TLS & supply-chain pins (`M2`, `M10`, `M11`):** Scrubbed query strings, `#fragments`, and `user:pass@` from embedded URLs inside `Result.Problem`, crawl logs, OTLP spans, and `edgefetch bug-report`; honored explicit `Options.MaxBytes` in streaming PDF fetches; rejected non-loopback cleartext `http://` Hub URLs by default in the Python and TypeScript SDKs; scoped `release.yml` job permissions with `needs: [release]` on `ghcr-release`; pinned Go 1.27-compatible `staticcheck@v0.8.2` / `govulncheck@v1.10.0` in CI and `:2.5.5` image tags across deployment manifests; and added an explicit 32-bit ARM source-build message in `install-termux-agent.sh`.

## [2.5.4] - 2026-11-20

### Fixed
- **Home Assistant OS Headless Chromium launch under AppArmor 3.x (`edgefetch_fat/apparmor.txt`, `internal/priv`):** Replaced the AppArmor 4.0-specific `mrCx -> &chromium` stacked subprofile transition (which returned `fork/exec /usr/lib/chromium/chromium: permission denied` on Home Assistant OS Buildroot AppArmor 3.1 after Supervisor `adjust_profile` slug rewriting) with portable VFS DAC lockdown (`priv.LockDownSecretPaths` enforcing `0700 /data` and `0600 /data/options.json` owned by `0:0` right before `priv.DropRoot()` drops all threads to `65532:65532`) paired with `/usr/lib/chromium/** mrix` and explicit `deny capability dac_override` / `dac_read_search`.
- **CI HAOS AppArmor slug simulation (`.github/workflows/ci.yml`):** Updated the live container smoke test to rewrite `profile edgefetch_fat` -> `profile c3b8e9a1_edgefetch_fat` (matching Home Assistant Supervisor `adjust_profile`) and verify both Chromium rendering and `UID 65532` `EACCES` denial on `/data/options.json`.

### Security
- **Resumed `interact` session `robots.txt` check (`internal/browser/renderer.go`):** Track `lastCheckedURL` per retained browser session so follow-up `interact` turns (`task.URL == ""`) that navigate via `click` or `executeJavascript` still enforce `CheckRobots` on the resulting `finalURL`.
- **Caller-bound `interact` session tokens (`hub/src/scrape.ts`, `hub/src/index.ts`):** Added HMAC-SHA256 principal binding (`<siteId>.<efsess_id>.<hmac32>`) on retained `interact` session IDs so one OAuth client cannot resume or close another caller's browser session on a shared Hub.

## [2.5.3] - 2026-11-20

### Security
- **Origin-locked operator LLM credentials (`C1`):** Bound `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `GEMINI_API_KEY`, `OPENROUTER_API_KEY`, and `EDGEFETCH_LLM_API_KEY` to their canonical provider origin or `EDGEFETCH_LLM_BASE_URL` origin, enforced `redirect: "manual"` on LLM requests, and capped LLM JSON responses at `4 MiB`.
- **Chromium loopback, WebRTC & child-env hardening (`H1`, `M1`, `H9`):** Added `--proxy-bypass-list=<-loopback>` and `--force-webrtc-ip-handling-policy=disable_non_proxied_udp`, re-verified `FinalURL` against SSRF and `robots.txt` after render, preserved Chromium site isolation, scrubbed child-process `cmd.Env` for `chromium` and `pdftotext`, and stacked a child `edgefetch_fat//chromium` AppArmor subprofile denying `/data/**`.
- **Tokenless loopback & Portable Node Hub hardening (`H2`, `H3`, `H4`, `H5`, `H7`):**
  - Enforced `Host`, `Origin`, `Sec-Fetch-Site`, and `Content-Type: application/json` DNS-rebinding and CSRF checks in tokenless `desktop` and `serve` modes.
  - Guarded Portable Hub WebSocket `upgrade` and HTTP request parsing against malformed `Host` headers (`400 Bad Request`), stripped untrusted `CF-Connecting-IP` and `X-Forwarded-*` headers unless `EDGEFETCH_TRUST_PROXY=1`, added server-side `/admin/logout` session revocation, normalized IPv6 rate-limit keys to `/64`, enforced `options.sha256` in `S3ArtifactBucket.put`, and added dial-time `net.BlockList` DNS/IP verification (`hub/portable/safe-fetch.ts`).
- **Agent reply & artifact integrity (`H6`, `M3`, `M7`):** Enforced atomic single-winner `/agent/reply` claims, bound reply `id`/`url` to server-dispatched requests, required SHA-256 proof-of-possession before authorizing `blobSha256` references or R2 deduplication, preserved previously verified R2 blobs on mismatched claims, and clamped `Retry-After` cooldowns to `MAX_COOLDOWN_MS`.
- **Linear HTML scanners & safe user regexes (`M4`, `M5`, `M6`, `M8`):** Replaced backtracking HTML tag/comment regexes with linear `indexOf` scanners (`2 MiB` cap), rejected nested/quantified groups and backreferences in user crawl/JSON regexes, enforced streaming request-body caps across `/mcp` and `/v1/*`, and restricted `/v1/agent` `interact_browser` to a non-JS/non-navigate action allowlist.
- **Extension, container & release supply chain (`H8`, `M10`, `M11`):** Moved `https://*/*` to `optional_host_permissions` in the MV3 clipper extension, bound `docker-compose.yml` to `127.0.0.1:8787`, digest-pinned Alpine `3.24` / Node `24` / Go `1.27` / Distroless base images, added `io.modelcontextprotocol.server.name` OCI labels across all Dockerfiles, updated `server.json` to MCP Registry schema `2025-12-11` pinned to `:2.5.3`, enforced Ed25519 signing before GitHub Release creation in `release.yml`, verified signatures in install scripts, and stripped `Authorization` across cross-origin redirects in Go and the Python SDK.

### Added
- **`edgefetch bug-report [url]` & `EDGEFETCH_OTEL_STDOUT=1`:** CLI diagnostic command that emits a token-scrubbed Markdown bundle and sanitized OTLP/JSON trace spans for GitHub Issue reporting, paired with `SUPPORT.md` and updated issue templates.
- **Fuzz & security regression tests:** Added `FuzzExtractPDFPureGo`, `FuzzBotAuthVerifyRequest`, `FuzzValidateCustomHeaders`, `FuzzPublicHTTPS`, Go `hub_security_test.go` / `browser/security_audit_test.go`, and TypeScript `hub/test/security-audit.test.ts`.

## [2.5.2] - 2026-11-20

### Added
- **Release signing & provenance:** Added Ed25519 signature generation and verification (`checksums.txt.sig` + `keys/release-signing-pub.pem`) and GitHub Actions SLSA build-provenance attestations on GoReleaser archives and GHCR images.
- **Governance & RFC 9421 directory:** Added self-signed `draft-meunier-http-message-signatures-directory` headers (`Content-Digest`, `nbf`), `CODE_OF_CONDUCT.md`, `.github/CODEOWNERS`, `.github/dependabot.yml`, and `docs/REGISTRATION.md`.

### Fixed
- Switched GitLab adapter twins from `robots.txt`-disallowed `/-/raw/` paths to allowed `/-/blob/...?format=json&viewer=simple` endpoints, cleaned JSR navigation chrome, and deduplicated USWDS print-stylesheet link suffixes.

## [2.5.1] - 2026-11-20

### Fixed
- Scoped CDP response tracking to main-frame `Document` events so subresource `image/png` or `404` responses do not overwrite rendered page status/content-type.
- Added covering index on `hub_events(level, id DESC)` in Durable Object SQLite, enriched fast-path API twins with `summary` / `json` / `product` formats, and tightened `<80`-word JS proof-of-work WAF detection.

## [2.5.0] - 2026-11-20

### Added
- **Autonomous `/v1/agent`:** Added multi-step web research endpoint supporting BYO-LLM providers (Ollama, LM Studio, vLLM, Workers AI, OpenAI, Anthropic, Gemini, OpenRouter), SSE streaming, URL constraints, and zero-data-retention mode.
- **Public-API & ATS adapter plugin registry:** Refactored `hub/src/extractors/` into modular domain adapters with contributor JSON fixtures (`npm run adapter:new`) covering public research/government APIs and public ATS job boards.
- **CLI subcommands:** Added `edgefetch init`, `edgefetch map`, `edgefetch crawl`, and `edgefetch serve`, plus `/v2/*` Firecrawl-compatible routes.

## [2.4.1] - 2026-11-20

### Added
- Improved CDP `XHR`/`Fetch` network-idle settling, open Shadow-DOM serialization, Next.js App Router RSC hydration recovery, and optional operator-configured Crawl4AI / Firecrawl SPA fallback.

## [2.4.0] - 2026-11-20

### Added
- Fixed Go `/v2` module path (`github.com/bartrumb/edgefetch/v2`) for `go install`, added GoReleaser multi-OS archive workflow, RFC 9421 Web Bot Auth (`edgefetch keygen-bot-auth`), WAF signature classification with false-positive vetoes, `contentState` detection, conditional `304` `ETag` revalidation, adaptive host health tracking, and opt-in Wayback `5xx` fallback.

## [2.3.0] - 2026-11-19

### Added
- Added structured `POST /v1/jobs` and MCP `jobs` tool across public ATS endpoints and Schema.org `JobPosting` JSON-LD, plus TypeScript and Python SDK `jobs()` methods.

## [2.2.0] - 2026-11-19

### Added
- Added site extractor registry (`npm`, `crates.io`, PyPI, GitHub, Reddit, Stack Overflow, Hacker News, Wikipedia, arXiv, RFCs), offline synthetic benchmark (`bench/`), Portable Node 22+ Hub (`node:sqlite` FTS5 + S3 SigV4 / Turso HTTP adapters), `EDGEFETCH_PEERS` mesh failover, MV3 browser clipper, and `wasip1/wasm` extractor build.

## [2.1.0] - 2026-11-18

### Added
- Added local `edgefetch mcp` stdio server, `edgefetch desktop` launchpad, one-shot `scrape` / `doctor` CLI commands, vendor-agnostic OTLP/HTTP trace export, and multi-hub HA failover (`EDGEFETCH_HUB_URLS`).

## [2.0.0] - 2026-11-18

### Added
- Added SSRF-proxied Headless Chromium (`browser-v1` + `interact`), Poppler / pure-Go PDF extraction (`pdf-v1`), optional R2 + D1 (`META` + `SEARCH` FTS5) storage pipeline, OAuth 2.1 + PKCE remote `/mcp` server, and `/admin` control center on top of the Go HTTP/2 + Cloudflare Hibernating Durable Object architecture.
