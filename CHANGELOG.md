# Changelog

All notable changes to EdgeFetch are documented in this file. This project adheres to [Semantic Versioning](https://semver.org/).

## [2.5.3] - 2026-11-20

### Security
- **Origin-Locked Operator LLM Keys (`C1`):** Bound server-side `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `GEMINI_API_KEY`, `OPENROUTER_API_KEY`, and `EDGEFETCH_LLM_API_KEY` strictly to their canonical provider origin (or `EDGEFETCH_LLM_BASE_URL` origin), enforced `redirect: "manual"` on LLM requests, and capped LLM JSON responses at `4 MiB`.
- **Headless Chromium Loopback & Environment Hardening (`H1`, `M1`, `H9`):** Added `--proxy-bypass-list=<-loopback>` and `--force-webrtc-ip-handling-policy=disable_non_proxied_udp` to Chromium launch flags, re-verified `FinalURL` against SSRF/robots policy after render, kept Chromium site isolation active, scrubbed child-process `cmd.Env` for both `chromium` and `pdftotext`, and added a dedicated `edgefetch_fat//chromium` AppArmor subprofile denying `/data/**`.
- **Tokenless Local Mode & Portable Node Hub Hardening (`H2`, `H3`, `H4`, `H5`, `H7`):**
  - Enforced `Host`, `Origin`, `Sec-Fetch-Site`, and `Content-Type: application/json` DNS-rebinding/CSRF guards on tokenless loopback `desktop` and `serve` modes.
  - Hardened Portable Hub WebSocket `upgrade` and HTTP request parsing against malformed `Host` headers (`400 Bad Request` instead of uncaught `TypeError`), stripped untrusted `CF-Connecting-IP` / `X-Forwarded-*` headers unless `EDGEFETCH_TRUST_PROXY=1`, added server-side `/admin/logout` cookie revocation, normalized IPv6 rate-limit buckets to `/64`, enforced `options.sha256` in `S3ArtifactBucket.put`, and wired dial-time `net.BlockList` DNS/IP verification (`hub/portable/safe-fetch.ts`).
- **Agent Reply & Artifact Proof-of-Possession (`H6`, `M3`, `M7`):** Enforced atomic single-winner `/agent/reply` claims, bound reply `id`/`url` to server-dispatched requests, required verified SHA-256 proof-of-possession before authorizing `blobSha256` references or R2 deduplication, preserved previously verified R2 blobs on mismatched claims, and clamped `Retry-After` cooldowns to `MAX_COOLDOWN_MS`.
- **Linear O(N) HTML Scanners & Safe User Regexes (`M4`, `M5`, `M6`, `M8`):** Replaced backtracking HTML tag/comment regexes with linear `indexOf` scanners (`2 MiB` cap), rejected nested/quantified groups and backreferences in user crawl/JSON regexes, enforced streaming body-size caps across `/mcp` and `/v1/*`, and restricted `/v1/agent` `interact_browser` to a safe non-JS/non-navigate action allowlist.
- **MV3 Clipper, Docker & Release Supply Chain (`H8`, `M10`, `M11`):** Moved `https://*/*` to `optional_host_permissions` in the MV3 extension with public-HTTPS redirect/size guards, bound `docker-compose.yml` to `127.0.0.1:8787`, digest-pinned Alpine `3.24` / Node `24` / Go `1.27` / Distroless base images, enforced Ed25519 signature verification BEFORE release publication in `release.yml` and install scripts, and stripped `Authorization` across cross-origin redirects in Go and the Python SDK.

### Added
- **`edgefetch bug-report [url]` & `EDGEFETCH_OTEL_STDOUT=1`:** One-command CLI diagnostic bundle that captures W3C `traceparent` + sanitized OTLP/JSON timing spans while redacting all tokens and URL query strings for safe GitHub Issue reporting, paired with `SUPPORT.md` and updated issue templates.
- **Expanded Fuzz & Security Regression Suites:** Added `FuzzExtractPDFPureGo`, `FuzzBotAuthVerifyRequest`, `FuzzValidateCustomHeaders`, `FuzzPublicHTTPS`, Go `hub_security_test.go` / `browser/security_audit_test.go`, and TypeScript `hub/test/security-audit.test.ts`.

## [2.5.2] - 2026-11-20

### Added
- **Ed25519 Release Signing & SLSA Provenance:** Added cryptographic `checksums.txt.sig` verification (`keys/release-signing-pub.pem`), GitHub Actions SLSA build provenance attestations on all GoReleaser archives and GHCR multi-arch images, and `CODE_OF_CONDUCT.md`, `CONTRIBUTING.md`, `GOVERNANCE.md`, and `.github/CODEOWNERS`.

## [2.5.1] - 2026-11-20

### Fixed
- **Live Fleet QA & Extraction Fidelity:** Hardened rendered subresource binary guards, twin JSON/summary enrichment, JS PoW WAF classification without false positives, and empty SPA shell prevention.

## [2.5.0] - 2026-11-19

### Added
- **Autonomous `/v1/agent` (BYO-LLM Offline & Online):** Added multi-step web research agent supporting Ollama, LM Studio, vLLM, Workers AI, OpenAI, Anthropic, Gemini, and OpenRouter with SSE streaming, strict URL constraints, and `$0` zero-data-retention mode.
- **49+ Keyless Public Data & ATS Adapters:** Added Alexandria public API adapters (SEC EDGAR, OpenAlex, Semantic Scholar, ClinicalTrials.gov, arXiv, Crossref, FRED/World Bank/USGS, registries) and bulk ATS board extractors (Workable, Recruitee, SmartRecruiters, BreezyHR, Personio, JazzHR, Dover, Gem, Pinpoint, Rippling, Ashby, Lever, Greenhouse, Workday).

## [2.4.1] - 2026-11-18

### Added
- **RFC 9421 Web Bot Auth & Portable Node 22+ Hub:** Added `edgefetch keygen-bot-auth` + `/.well-known/http-message-signatures-directory`, Next.js App Router RSC hydration recovery, optional ethical Crawl4AI / Firecrawl heavy-SPA fallback, and zero-dependency self-hosted `portable-server.mjs` (`node:sqlite` FTS5 + S3/FS artifacts).
