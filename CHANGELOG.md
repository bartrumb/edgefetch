# Changelog

All notable changes to EdgeFetch are documented in this file. This project adheres to [Semantic Versioning](https://semver.org/).

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
