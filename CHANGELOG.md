# Changelog

All notable changes to EdgeFetch are documented in this file. This project adheres to [Semantic Versioning](https://semver.org/).

## [2.7.1] - 2026-11-22

### Security
- **Round 7 Multi-User, GitHub OAuth & Shared Cache Hardening (`H1`, `H2`, `H4`–`H6`, `hub/migrations/meta/0003_round7_multiuser_hardening.sql`):**
  - **Session revocation & numeric GitHub ID pinning (`H1`, `H5`):** Added `session_epoch` and `disabled` columns to `users` with live Durable Object / D1 verification on every authenticated request, pinned founder/owner identity to immutable numeric `github_id` (preventing GitHub handle-rename takeover), enforced `__Host-` cookie prefixes on HTTPS origins, and immediately invalidated OAuth grants and sessions when an account is disabled or de-allowlisted.
  - **End-to-end tenant & shared-cache isolation (`H4`, `H6`):** Enforced `visibility: "private"` (`Cache-Control: private, no-store`, zero shared R2/D1 cache reads or writes) whenever a scrape carries custom headers, cookies, auth, `preferMcp`, or a non-owner tenant, and enforced strict `user_id` ownership across `crawl`, `batch/scrape`, `catalog`, and `/v1/hosts`.
- **MCP Vault, Downstream OAuth & Federated Tool Safety (`H2`, `H3`, `hub/src/mcp-vault.ts`, `hub/src/mcp-federation.ts`, `hub/src/mcp.ts`):**
  - Bound downstream MCP OAuth 2.1 `resource` and `iss` origins strictly to the registered connector origin, walked remote MCP JSON Schemas through a `16 KiB` depth-bounded structural allowlist before exposing them to LLMs, enforced explicit `mcp:call` OAuth scope on `query_mcp` (`action: "call_tool"`) and `POST /v1/mcp/query`, gated keyless unauthenticated auto-routing strictly on `readOnlyHint: true`, and hardened `llm.ts` redirect/origin checks.
- **Markdown Sanitizer, Linear Prompt-Injection Scanner & Declarative Adapter Guards (`H7`, `SCRAPE_PIPELINE_VERSION = 31`):**
  - Closed all CommonMark/GFM code-fence, reference-link, HTML entity, and inline-backtick smuggling vectors across TypeScript (`hub/src/scrape.ts`) and Go (`internal/extract/sanitize.go`, 278 CommonMark/GFM vectors), and hardened the $O(N)$ prompt-injection scanner across `58/58` Markdown and `20/20` HTML evasion variants (`< 25 ms` on `2 MiB`, stripping Khmer, Braille blank, musical format, variation selector, and NEL/bidi smuggling runes).
  - Enforced Public Suffix List (PSL) wildcard bounds and cross-manifest domain-collision rejection in `hub/scripts/compile-manifests.mjs`, deterministic sorted + lazy `itemVars` evaluation in Go & TS, strict public `https://` feed links, and `1,179` schema-driven linear-time fuzz cases (`339` formatting hits) in `npm run adapter:test`.
- **Portable/Deno Hub Socket Headroom & Zero-Hostname Telemetry Hardening (`H8`, `H9`, `hub/portable/*`, `telemetry/`):**
  - Reserved dedicated loopback socket headroom with silent-socket idle eviction in `portable-server.ts` (`H8`), added single-DNS-resolution IP-pinned SSRF validation in `deno-server.ts` / `safe-fetch.ts` and cryptographic slot tokens, gated OTLP trace export strictly behind authenticated callers (`H9`), honored `DO_NOT_TRACK` in `/admin` Console UI, scrubbed SemVer `+buildmetadata` hostnames/slugs from opt-in dev error telemetry, and hardened the standalone `telemetry/` collector with `/48` + `/64` IPv6 rate-limiting and `count = 1` eviction indexing (`0002_eviction_idx.sql`).
- **Go Browser Sandbox, Windows Handle/Job Isolation, Politeness & Supply-Chain CI (`internal/browser`, `internal/politeness`, `cmd/edgefetch`, `.github/workflows/*`):**
  - Restricted `Fetch.requestPaused` bound-frame fallback strictly to non-Document subresources (`!isDocReq`) with `Page.frameDetached` tracking, scoped Windows Chromium handle inheritance via `STARTUPINFOEXW` `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` + `CREATE_SUSPENDED` kill-on-close Job Object attachment, disabled Chromium Cast/mDNS (`:8009`), gated Linux `--no-sandbox` fail-closed behind `EDGEFETCH_ALLOW_NO_SANDBOX=1` while shipping `deploy/seccomp/chromium-sandbox.json`, completed `153/153` Go/TS `robots.txt` ASCII + ZWSP parity with a `10s` tarpit cap, added `edgefetch update` downgrade refusal (`--allow-downgrade`) + Windows `.old` crash recovery, and gated `release.yml` + `addon-ghcr.yml` on full test suites with Ed25519-signed `release-manifest.json` tag+commit+SHA-256 verification in `upstream-sync.yml` and `.github/`/`keys/` protection in `vouch.yml`.

### Fixed
- **Live MCP Audit Functional, Extraction & Tool-Surface Fixes (`internal/browser`, `internal/classify`, `hub/src/*`):**
  - **`interact` form submission, navigation awaiting & paging:** Mapped CDP virtual key codes (`Enter` `vk=13`, `text="\r"` + buttonless `<form>` `requestSubmit()` fallback), awaited triggered navigations (`Page.frameStartedLoading` / `Page.loadEventFired` + SSRF/`robots.txt` validation), added per-action `urlChanged` / `domChanged` / `no_effect` diagnostics, and added `maxChars` + `offset` + `remainingChars` paging metadata across `scrape` and `interact`.
  - **Distinct `dns_not_found` & error metadata:** Separated non-retryable DNS `NXDOMAIN` (`dns_not_found`) from transient `robots_unreachable` while scrubbing internal `:53` resolver socket addresses, separated HTTP `404` (`not_found`) from `410` (`gone`), surfaced structured `blocked: { reason: "ssrf", retryable: false }` on non-public/metadata targets, and standardized `artifact_not_found` (`404`) across `read_artifact`.
  - **Options-keyed scrape cache, `CrawlWorkflow` & extraction fidelity:** Keyed R2 scrape caches by output-affecting options (`onlyMainContent`, `renderMode`, `formats`, `includeTags`, `excludeTags`) with full response-shape parity (`wordCount`, `favicon`, `contentType`, `rendered`), bound `CrawlWorkflow` (`CRAWL`) in production `wrangler.toml` with inline completion (`<= 25s`) for small MCP crawls, skipped Chromium `browser-auto` on scriptless static HTML while rescuing `<header><h1>`, stripped MediaWiki `.mw-editsection` chrome and RFC `¶` pilcrows, expanded heading-only `includeTags` (`#id`) to full sections, hardened heuristic JSON-schema extraction (`null` instead of hallucinated nav links), deduplicated `extract` `rawContent` / `search_collection` `snippet` with zero-match (`noRelevantMatch: true`) and real BM25 scores, and polished all `17/17` MCP tool schemas (`listChanged: true`, plain-English descriptions, `ToolSearch` batch-loading guidance, deduplicated `search` properties).

## [2.7.0] - 2026-11-22

### Added
- **Sign in with GitHub & Multi-User Tenant Isolation (`hub/src/github-auth.ts`, `hub/src/oauth.ts`, `hub/migrations/meta/0002_multiuser.sql`):**
  - Added standards-compliant GitHub OAuth 2.1 + PKCE (`S256`) login (`GET /admin/auth/github`, `GET /admin/auth/github/callback`, and `/oauth/authorize` consent flow) powered by `oauth4webapi@3.8.9` and `jose@6.2.18` (`HS256` `jti`-revocable `HttpOnly; SameSite=Lax` session cookies via `SESSION_SECRET`), while preserving zero-config headless `CALLER_TOKEN` (`owner`) compatibility.
  - Added `invite_only` (default, `GITHUB_ALLOWED_USERS` + `GITHUB_OWNER_LOGIN` / first-user owner bootstrap) and `open` (`SIGNUP_MODE=open`) onboarding modes with `owner` vs `member` RBAC (`POST /admin/api/users/role` and fleet/telemetry mutations strictly `owner`-only).
  - Enforced strict end-to-end `user_id` isolation across OAuth 2.1 grants, `visibility: "private"` R2 scrape caches (`cache:private-r2`), private R2 artifacts, `private:<userId>:<collectionId>` D1/SQLite `FTS5` search collections, `/v1/agent` runs/traces/threads, and retained `interact` browser session HMACs.
- **Dual-Source MCP Registry Discovery & Per-User `AES-256-GCM` Connector Vault (`hub/src/mcp-registry.ts`, `hub/src/mcp-vault.ts`, `hub/src/admin.ts`):**
  - Added live MCP discovery (`GET /v1/mcp/registry`, `/admin/api/mcp/registry`, and MCP `discover_mcps` tool) fusing Official MCP Registry (`registry.modelcontextprotocol.io/v0/servers`) and Glama MCP Directory (`glama.ai/api/mcp/v1/servers`) results with TTL caching, graceful partial-source fallback, SSRF URL filtering, prompt-injection scrubbing, and automatic domain/header inference.
  - Added a per-user `AES-256-GCM` credential vault (`user_mcp_servers` + `mcp_oauth_states` in SQLite/Durable Object storage) deriving unique per-user, per-origin keys via WebCrypto `HKDF-SHA256` (`VAULT_MASTER_KEY`, 96-bit random IV, `AAD = "${userId}|${remoteOrigin}"`, write-only secret storage) plus 1-click downstream OAuth 2.1 + PKCE (`RFC 9728` / `RFC 8414` + Dynamic Client Registration + automatic `refresh_token` rotation) and interactive **MCP Registry & Encrypted Connectors** UI in `/admin`.
- **Federated Agent-to-Agent MCP Routing (`hub/src/mcp-federation.ts`, `hub/src/agent-runner.ts`, `hub/src/mcp.ts`):**
  - Added federated `query_mcp` (`list_connected`, `list_tools`, `call_tool`) and `POST /v1/mcp/query` over Streamable HTTP JSON-RPC and SSE (`text/event-stream`), expanding EdgeFetch's canonical MCP surface to `17/17` tools with zero prompt-schema bloat.
  - Added Tier-1 MCP-First Domain Routing in `POST /v1/agent` (both BYO-LLM and deterministic zero-LLM modes) and `POST /v1/scrape` (`useConnectedMcp`), automatically invoking a user's authenticated official MCP connector for matching domains before falling back to keyless YAML adapters or HTML scraping, sanitizing remote MCP outputs (`stripInvisibleSmugglingChars` + `detectPromptInjection`), and enforcing `visibility: "private"` (`Cache-Control: private, no-store`, zero shared cache writes).
- **Universal Ed25519 Self-Updater & Fork Auto-Sync (`cmd/edgefetch/update.go`, `hub/src/update-check.ts`, `.github/workflows/upstream-sync.yml`):**
  - Added `edgefetch update` (`--check`, `--yes`) for Linux, macOS, and Windows binaries: verifies the GitHub release tag, downloads `checksums.txt` + `checksums.txt.sig`, verifies the raw Ed25519 signature against the compiled-in owner public key (`SPKI SHA-256: 2ed9e6f815d727738d51bc48c176f2b63d5176c92975f52943fefcf0afe03272`) BEFORE unpacking, verifies the archive SHA-256 digest, and atomically swaps the executable in place.
  - Added non-blocking 24h-cached background update notices in `edgefetch mcp` (`stderr` only, honoring `EDGEFETCH_DISABLE_UPDATE_CHECK=1`), a 1h-cached owner-only `/admin` version & outdated-worker status pill, scheduled fork upstream sync (`.github/workflows/upstream-sync.yml`), and safe `wrangler d1 migrations apply` steps in `.github/workflows/deploy-hub.yml`.
- **Strictly Opt-In, Zero-PII OTLP Structural Error Telemetry (`hub/src/dev-telemetry.ts`, `internal/otel/dev_telemetry.go`, `telemetry/`):**
  - Added default-`OFF` (`0` unattended network calls; `DO_NOT_TRACK=1` hard disable override) structural error telemetry across TypeScript Hubs (`EDGEFETCH_DEV_TELEMETRY=1` or owner-only `/admin` toggle) and Go binaries (`EDGEFETCH_DEV_TELEMETRY=1`), scrubbing `ERROR` spans down to an 11-key structural allowlist (`schemaVersion`, `version`, `runtime`, `os`, `arch`, `mode`, `spanName`, `adapterId`, `wafVendor`, `httpStatus`, `errorClass`) with zero URLs, zero hostnames, zero paths, zero content, and zero secrets.
  - Added standalone Cloudflare Collector Worker (`telemetry/src/index.ts` + `telemetry/migrations/0001_errors.sql`) enforcing an `8 KiB` body cap, IPv6 `/64` token-bucket rate limiting (`30 req/min`), `400` rejection of any payload containing `://` or unexpected keys, SHA-256 fingerprint deduplication in D1, and `TELEMETRY_ADMIN_TOKEN`-authenticated `GET /v1/dev-errors/summary`.

## [2.6.3] - 2026-11-21

### Security
- **Round 6 Security Closure (`R6-H1`..`R6-H6`, `R6-M1`..`R6-M12`, `SCRAPE_PIPELINE_VERSION = 30`):**
  - **Markdown & `/v1/extract` sanitizer closure (`R6-H1`, `R6-H2`, `R6-H3`):** Hardened `splitMarkdownByCodeFences` against indented (`> 3` spaces) and list-nested code-fence state smuggling (`R6-H1`), applied full Markdown/HTML/dangerous-URI sanitization after JSON-LD/meta rescue paths in `/v1/extract` (`R6-H2`), and inserted safe delimiter spacing before inline backticks immediately following bare GFM autolinks (`R6-H3`).
  - **Portable/Deno Hub raw TCP caps & proxy trust (`R6-H4`):** Enforced per-IP raw TCP and pre-header idle socket caps (`destroy()` on `429` before body reads), isolated `/health` and `/readyz` liveness probes, enforced malformed `Host` `400` + full security headers on Deno, and set explicit `EDGEFETCH_TRUST_PROXY` in cloud reverse-proxy blueprints.
  - **Single-compiler YAML IR, host-claim bounds & Go sanitizer (`R6-H5`, `R6-M2`, `R6-M6`..`R6-M8`):** Compiled all YAML manifests through a single checked compiler (`hub/scripts/compile-manifests.mjs`) rejecting anchors (`&`), aliases (`*`), merge keys (`<<`), explicit tags (`!`), non-ASCII keys, and broad TLD wildcards (`*.com`), verified exact case-sensitive ASCII struct keys in Go (`DisallowUnknownFields`), blocked cross-domain twin redirects, and added linear $O(N)$ `SanitizeScrapedMarkdown` / `SanitizeScrapedMeta` in Go.
  - **Ed25519 release-signing key rotation & tag-gated isolation (`R6-H6`, `R5-M7`):** Rotated the owner Ed25519 release-signing keypair (`SPKI SHA-256: 2ed9e6f815d727738d51bc48c176f2b63d5176c92975f52943fefcf0afe03272`), sealed `RELEASE_SIGNING_PRIVATE_KEY` exclusively inside the tag-gated `release` GitHub Actions environment, and enforced zero-bypass (`can_admins_bypass: false`) immutable `v*` tag rulesets.
  - **Zero-TCP direct pipe CDP, initiator-proven headers & runtime bounds (`R6-M1`, `R6-M3`, `R6-M9`..`R6-M12`):** Enabled zero-TCP direct OS pipe CDP transport across Linux, macOS, and Windows (`0` listening Chromium ports), required top-level document initiator provenance before attaching caller headers in `Fetch.requestPaused`, added bounded $O(N)$ CSS selector memoization (`ChainMemo` + depth/visit caps) in `parseHtmlDoc`, added an LRU cache + bounded-repetition guard around linear `re2js` NFA compilation, capped `catalog` `variantHashes` inside the `32 MiB` global LRU with a `120s` wall-clock ceiling and `<= 2` gunzip semaphore, and achieved `150/153` TypeScript-Go `robots.txt` + `Content-Signal` parity (completed to `153/153` in `2.7.1`).

### Added
- **100% Declarative YAML Site Adapters (`56/56`, `internal/extract/manifests/*.yaml`, `compiled.json`):**
  - Converted all remaining TypeScript provider files into `#`-commented, `MIT`-licensed declarative `.yaml` manifests (`56/56` total across 7 categories, `0` `.ts` files under `providers/`) compiled into `internal/extract/manifests/compiled.json` (`//go:embed`) with reusable storefront normalization in `hub/src/extractors/commerce-engine.ts` for 1:1 Go + TypeScript parity.
- **OpenAPI `3.1.0` Specification (`GET /openapi.json`, `docs/openapi.json`):**
  - Added unauthenticated `GET /openapi.json` (`application/json` and `application/openapi+json` content negotiation, strict `Host`/`Origin` sanitization) across Cloudflare Worker, Node.js Portable Hub, Deno Deploy, and pure-Go `--mode=hub`, sharing canonical JSON Schema 2020-12 definitions directly with `MCP_TOOL_SCHEMAS` (`15/15` tools) and guarded by automated `/v1/*` route-parity contract tests.
- **Full-Stack OpenTelemetry (`OTLP/HTTP` + W3C `traceparent`) & E2E Audit Matrix:**
  - Wired request-scoped `AsyncLocalStorage` `RequestTracer` (`x-trace-id` + `traceparent` headers, `edgefetch.adapter_id` tags, zero-secret span attribute scrubbing) across Cloudflare/Node/Deno Hubs, Go `--mode=hub` / `--mode=mcp` / Chromium CDP renderer, and the official TypeScript (`sdk/ts`) & Python (`sdk/py`) `EdgeFetchClient` SDKs (`traceparent` + `lastTraceId`), backed by Miniflare `workerd`, Deno `v2.2.4`, cross-process OTLP + RFC 9421, and opaque-box E2E suites.
  - Automated Official MCP Registry (`registry.modelcontextprotocol.io`) `server.json` validation and GitHub OIDC publishing in `.github/workflows/release.yml`.

### Changed
- **Licensing & Governance Clarity (`LICENSE`, `hub/LICENSE`, `CONTRIBUTING.md`, `docs/ADAPTERS.md`):**
  - Unified documentation around *"open-source worker, SDKs, and adapters (`MIT`), fair-source hub (`FSL-1.1`, `MIT` after two years)"*, `Inbound = MIT + DCO` (`git commit -s`), and explicit `EdgeFetch™` trademark notice.

## [2.6.2] - 2026-11-21

### Security
- **Round 5 Hub, Catalog, Sanitizer & Portable Closure (`R5-H1`..`R5-H4`, `R5-M1`..`R5-M5`, `SCRAPE_PIPELINE_VERSION = 29`):**
  - **Bounded `catalog` memory, concurrency & pacing (`R5-H1`, `R5-M4`):** Wired `maxBytes: 16_777_216` through Hub fetch wrappers, enforced a `16 MiB` per-run in-memory retention cap (`32 MiB` global LRU across 8 runs, streaming full NDJSON to R2), capped concurrent async runs at `2` per caller, and bounded per-run pacing sleep budgets.
  - **Linear Shopify image deduplication & code-fence headers (`R5-H2`, `R5-H3`):** Replaced quadratic `allImageUrls.includes(u)` in `normalizeShopifyProductRecord` with a `Set` (`<= 250` images/product) and capped code-fence info-string header cleaning at `512` chars (`hub/src/extractors/providers/commerce-social/shopify.ts`, `hub/src/scrape.ts`).
  - **Multi-line CommonMark code-span, list-indented fence & residual `javascript:` sanitization (`R5-H4`, `R5-M2`, `R5-M3`):** Tracked cross-line unmatched backtick runs (`computeTickPoisonedLines`), closed indented fences on dedent in `splitMarkdownByCodeFences`, stripped residual nested-bracket/blockquote-reference `javascript:` destinations, stripped entry NUL bytes before sentinel stashing, and sanitized twin Markdown stored via `/v1/extract`.
  - **Google RE2 Thompson NFA regex engine + per-IP Portable Hub slot cap (`R5-M1`, `R5-M5`):** Swapped `compileSafeUserRegex` execution onto `re2js` (plus rejecting optional groups before `$` like `(a*aaa*)?$`), replaced hand-rolled RFC 6455 frame parsing with `ws`, and added per-IP in-flight request slot limits + `100 Continue` / `Content-Length` / `Host` hardening in `hub/portable/*`.
- **Round 5 Go Renderer, Crawler & CI Hardening (`R5-M6`..`R5-M8` + Lows):**
  - **Zero-TCP `--remote-debugging-pipe` Chromium & `302` header stripping (`R5-M6`):** Launched Linux/macOS Chromium over inherited OS pipes (`--remote-debugging-pipe`, `0` listening TCP sockets on Chromium, `0700` `userDataDir`), updated `initialOrigin` on resumed `navigate` actions, stripped custom caller headers after cross-origin `302` redirects, tightened `:fatal:` sandbox failure classification, and logged `browser_sandbox_fallback` warnings.
  - **Non-blocking session reconnect, quoted URL scrubbing & exact `1 MiB` `/robots.txt`:** Hoisted `dispatchCh` into `agent.Run` so WebSocket reconnects never block on slow in-flight jobs, scrubbed `strconv.Quote`'d URLs containing spaces/backslashes in `RedactEmbeddedURLs`, read `RobotsMaxBytes + 1` so exact-`1 MiB` `/robots.txt` files retain their final rule, and enforced a single `5s` non-retrying `/robots.txt` tarpit ceiling.
  - **Enforced Vouch + DCO ruleset & `release` environment gates (`R5-M7`, `R5-M8`):** Switched `vouch.yml` to safe `pull_request_target` (`permissions: contents: read`, zero untrusted code execution), added `Verify Vouched Contributor & DCO Sign-Off` to `main`'s required status checks, and gated release container tag jobs on `environment: release`.

### Added
- **Shared Go + TypeScript Declarative YAML Site Adapters (`internal/extract/manifests/*.yaml`, `internal/extract/yaml_subset.go`, `hub/src/extractors/declarative.ts`):**
  - Converted 10 pure API-twin site adapters (`rubygems`, `packagist`, `hex-pm`, `dev-to`, `huggingface`, `lobsters`, `doi-crossref`, `usaspending`, `polymarket`, `openrouter`) into `#`-commented YAML manifests (`maxAliasCount: 0` / `&` and `*` alias-bomb rejection).
  - Embedded `manifests/*.yaml` into `edgefetch --mode=hub` via `//go:embed` (`0` Go dependencies added) and wired `ResolveDeclarativeTwin`, `GET /v1/extractors`, and MCP `find_extractors` into `internal/hub/hub.go` so the standalone pure-Go Hub natively runs site adapters with zero TypeScript runtime.
- **Adapter Authoring Workbench & CSS-Selector HTML Engine (`hub/src/extractors/html-doc.ts`, `hub/scripts/test-adapter.mjs`, `hub/scripts/new-adapter.mjs`):**
  - Added `parseHtmlDoc()` (`htmlparser2` WHATWG HTML5 DOM + linear CSS selectors: `select`, `first`, `text`, `html`, `attr`, `dlMap`, `tableRows`) and `compileLinearRegex()` (`re2js`), refactoring `icims` and `openfoodfacts`.
  - Added `npm run adapter:test [<id>] [<https://url>] [--record]` for `robots.txt`-checked live previews, fixture recording, and 390-case `100 KB+` linear-time bulkhead fuzzing, plus `.yaml`-by-default scaffolding in `npm run adapter:new`.

### Changed
- **Open-Source Worker & Adapters / Fair-Source Hub Licensing (`LICENSE`, `hub/src/extractors/LICENSE`, `hub/LICENSE`):** Kept the Go worker, CLI, `stdio` MCP, SDKs, and **all** site adapters (`cmd/`, `internal/`, `sdk/`, `extensions/`, `internal/extract/manifests/`, `hub/src/extractors/`) open source under `MIT`, while licensing the rest of the Hub coordinator plane (`hub/`) as fair source under `FSL-1.1-MIT` (free to self-host personally or internally; prohibits competing third-party hosted SaaS; converts to `MIT` after two years). Inbound contributions remain `MIT` + DCO (`git commit -s`), with explicit `EdgeFetch™` trademark notice in `README.md`.

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
