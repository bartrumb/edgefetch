# Changelog

All notable changes to EdgeFetch are documented in this file. This project adheres to [Semantic Versioning](https://semver.org/).

## [2.8.20] - 2026-11-27

### Fixed
- LLM default models: the Anthropic default was the retired `claude-3-5-haiku-latest`, so every `agent` call failed when only `ANTHROPIC_API_KEY` was set. Anthropic now defaults to `claude-haiku-5-5`, and OpenRouter to `anthropic/claude-haiku-5.5`. Set `EDGEFETCH_LLM_MODEL` to override either (#117).
- `GOOGLE_MAPS_API_KEY` (admin-managed secret) now works. When the caller has no Google Maps MCP connected, `company` uses it to call Google Places API (New) Text Search for headquarters details. A connected Maps MCP still takes precedence (#117).

## [2.8.19] - 2026-11-27

### Added
- **`company` tool** and `POST /v1/company` (#114).
  - Builds a sourced company profile from: the company website (schema.org Organization, socials); Wikidata, accepted only when its official website matches the company domain; SEC EDGAR (legal name, SIC code, latest annual revenue); GitHub; the official ATS hiring board; and, when a Google Maps MCP is connected, Google Maps place details.
  - Every field carries its source.
- **`salaries` tool** and `POST /v1/salaries` (#114).
  - Every `jobs` search records the employer-posted pay ranges it returns.
  - Ranges are aggregated by title family, seniority, location and company: p10, p25, median, p75 and p90, with sample postings.
  - When data is thin, it tops up with a live jobs search.
- **Google Maps (official MCP):** Google's hosted Maps MCP (`mapstools.googleapis.com/mcp`, `X-Goog-Api-Key`) is a first-party preset in MCP discovery (#114).
- **New search providers** (#114):
  - **Cloudflare Web Search API:** Workers AI binding or REST; Ceramic by default, or Exa or Linkup.
  - **Ceramic.ai direct:** `CERAMIC_API_KEY`.
  - In waterfall mode both run before Serper, the cheapest first. Neither is used for `site:`-scoped or time-range queries.
- **Admin-managed secrets** (#114):
  - Provider keys can be set, rotated and cleared in the admin UI as vault-encrypted overrides on top of the deployed env.
  - Secret values are shown only as fingerprints. Bootstrap secrets stay deploy-only.
  - Overrides apply to requests and to the crawl and ingest workflows.
- **Access policy** (#114):
  - Global and per-user allow/deny rules for MCP tools and `/v1` routes, including the `/v2` and compat aliases.
  - Owners bypass tool and route policy, so the hub can't be locked out. Members fail closed if the policy store is unavailable.
- **MCP server sharing:** connected MCP servers can be shared with everyone or with named users. Credentials stay in the owner's vault, and members never see the URL or keys. New route: `GET /v1/mcp/shared` (#114).
- **Admin UI:** new cards for secrets and provider keys, access policy, and MCP server sharing (#114).

### Security
- `search` is a `crawl:read` tool, but its `site:` crawl, Wikipedia title guess and `include_raw_content` extraction fetched sites chosen by the caller. Those live fetches now require `crawl:fetch`, the same as `/v1/map`. A `crawl:read` token gets results from stored collections and search providers only, and the skipped options are listed in `unhonoredOptions` (#103).

## [2.8.18] - 2026-11-27

### Fixed
- Re-release of the 2.8.17 changes. The `v2.8.17` tag was pushed at the wrong commit, its release jobs were cancelled, and it has no binaries or images, so use 2.8.18 instead. Includes: `jobs` Lever boards are fetched in server-side pages (`skip`/`limit=100`), so large boards (one live board: 305 postings, 5.9 MB) return jobs instead of degrading to an HTML scrape (#112).

## [2.8.17] - 2026-11-27 (not released — superseded by 2.8.18)

### Fixed
- `jobs`: Lever boards are fetched in server-side pages (`skip`/`limit=100`). A large company's full postings list (one live board: 305 postings, 5.9 MB) exceeded the fetch body cap and silently degraded to an HTML scrape with no `jobs[]`, so direct-first company searches fell back to web search. Large boards now return jobs, with `N+` counts and a next cursor. The `scrape` twin requests the first 100 postings (#112).

## [2.8.16] - 2026-11-27

### Added
- `jobs`: direct-first company search. The company's Greenhouse, Ashby, Lever and SmartRecruiters boards are probed before any web search, and a board that lists jobs skips the search step (#110).
- `jobs`: known-boards index (META D1 `jobs_known_boards`). Boards that returned jobs for a company in an earlier search are probed first for 30 days, so Workday companies skip the web search after their first lookup (#110).
- `jobs`: ATS JSON APIs (Greenhouse, Lever, Ashby, SmartRecruiters, Workday) are fetched from the Cloudflare edge instead of home nodes. Up to 3 fetches run at once per ATS API host. A failed edge fetch retries once via the nodes, and `JOBS_EDGE_ATS_FETCH=off` disables edge fetching (#110).
- `jobs`: ATS board responses are cached for 10 minutes across calls (R2 behind a D1 index) (#110).
- Declarative adapters: new `preferWhere` option, which picks an array element by field value. Wikidata population and dates use the preferred-rank claim (#110).

### Fixed
- `jobs`: once a company search has read the board, posting detail fetches are capped at 2× the remaining result slots. The time-budget note no longer tells company-scoped callers to add `company` (#110).
- Titles and descriptions decode the full HTML5 named-entity set (`&Eacute;` → `É`) without unescaping `<` or `>` (#110).
- Favicons prefer `rel=icon`, ignore `apple-touch-icon href="/"` and other origin-root candidates, and resolve protocol-relative URLs (#110).
- A browser-rendered app shell with no main content is re-extracted full-page, with hidden subtrees stripped, instead of returning empty Markdown (#110).
- Inline `jobs[]` respects `maxChars`, the same as `records[]` (#110).

### Changed
- `SCRAPE_PIPELINE_VERSION` is now 37 (#110).

## [2.8.15] - 2026-11-27

### Added
- New content state `temporarily_unavailable` for maintenance and "try again later" pages: 2xx, under 250 words, a present-tense maintenance notice plus a retry phrase, and no rich JSON-LD. Such pages are returned with that label but are never cached or indexed. `jobs` verify reports them as `unknown`, and a jobs search skips them without marking the board closed (#108).

### Fixed
- Node and CLI scrapes use the full-document extractor, so `display:none` text and `<script>` content no longer leak into Markdown. The hub never falls back to node-supplied Markdown for HTML bodies. **Update your nodes** to get the node half of this fix (#108).
- Next.js RSC hydration: `T` rows are framed by their byte length, so a text row with no newline no longer swallows the rows after it. `TableSpecContents` spec tables (models and attributes) are now extracted, which fixes empty Shimano spec tables (#108).
- `<html lang>` accepts only BCP 47 shaped tags, so route parameters like `{lang}` no longer appear as the page language (#108).
- Registry-twin adapter output goes through the content-state classifier instead of always being reported as `active` (#108).
- Adapters (#108):
  - NuGet shows the newest stable version first, plus a "Latest Prerelease" bullet.
  - Maven's versioned route uses `central.sonatype.com`.
  - Wikidata has curated claims (instance of, gender, citizenship, occupation, birth, death, inception, website).
  - Open Library takes the author from `by_statement`, falling back to `contributions`.
  - iCIMS skips generic headings as job titles and has a company fallback.
  - Federal Register warns when the publication date doesn't match the date in the URL.

### Changed
- CLI and node Markdown now escape `<` inside inline code spans (`Promise&lt;void>`), the same as the hub's sanitizer (#108).
- `SCRAPE_PIPELINE_VERSION` is now 36, so cached scrapes that may contain leaked node Markdown are refreshed (#108).

## [2.8.14] - 2026-11-27

### Fixed
- Inline `records[]` (catalog, twin and adapter rows) now respect the `maxChars` budget. Whole records are kept, and the body reports `recordsTruncated`, `recordsReturned`, `recordsTotal` and `recordsHint` (#106).
- `jobs`: a 40 s wall-clock budget. Broad searches check at most 6 candidate boards per call and return a query-bound `continueCursor` plus `remainingCandidates` for the next chunk. The "configure SERPER_API_KEY" note appears only when no search provider is configured (#106).
- `gtin` is set only for plausible GTIN-8/12/13/14 codes, so store IDs no longer appear as `gtin` (#106).
- Hosts with a host-specific HTML adapter are fetched as `text/html`, so Markdown-for-agents responses no longer bypass the adapter (#106).
- Registry twins whose final URL is an error or 404 page on a different path are rejected (#106).
- Budgeted extract/search dispatches round the remaining budget to the nearest second. Flooring cut a 5 s budget to a 4 s batch after a few ms of setup.
- Adapter routes: sram-models service pages, tq-ebike `e-bike-system`, zendesk-hc on `support.sram.com`, and osv-ghsa severity labels (#106).

### Changed
- `SCRAPE_PIPELINE_VERSION` is now 35, so cached scrapes from earlier pipelines are refreshed (#106).

## [2.8.13] - 2026-11-27

### Added
- **Adapter expansion (85 declarative manifests: 29 new, 5 updated):**
  - Keyless twins: Zendesk help centers, Federal Register, CPSC recalls (bounded saferproducts.gov), eCFR via govinfo, EUR-Lex, Terraform Registry, Docker Hub, Maven Central, NuGet, Homebrew, OSV/GHSA, Wikidata/Open Library.
  - Commerce: Shopify collection and WooCommerce category upgrades, plus new Squarespace, BigCommerce, SFCC/Demandware and Shopware/Magento engines.
  - Forums and docs: XenForo threads, SRAM docs, Bosch eBike help (HTML/SSR only).
  - ATS and public APIs: Workday CXS and iCIMS hardening, UKG/Paylocity/Dover, NHTSA vPIC/recalls, FCC ID.
  - Log-mined adapters: NFPA (Sitecore JSS), Giant/Liv, bumm.de, Bicycle Retailer, Cornell LII, SRAM models, TQ eBike, a YouTube watch fast-path, and a Next.js RSC spec-table parser. Hosts behind robots rules, paywalls or WAFs fail closed and are documented in `docs/LOG-MINING-2026-11.md` (#104).
- **Go core:** microdata/spec-table product fallback for pages without JSON-LD, relative `product.url` resolution, bounded companion and HTML modes, and sanitizer hardening (#104).

### Fixed
- **L-01..L-05 audit follow-ups:**
  - the `jsonFilter` cache key;
  - `edgeBudgetExceeded`;
  - `>4 MiB` `rawBase64` / `parsers: []` inline hydration up to the wire budget, with an `artifactId` fallback;
  - product-record backfill;
  - `maxInlineBodyBytes` on renders.

  Robots, SSRF, `isTrustedTwinRedirectUrl` and `MAX_WASM_INPUT_BYTES` guards apply to every new adapter (#104).

## [2.8.12] - 2026-11-26

### Added
- **`/v1/*` 401s say why:** `authorizeMcpRequest` records a reason, and `/v1/*` 401 bodies add `reason` (`missing_token`, `token_rejected` or `grant_revoked`) and a `message`. `error: "unauthorized"` and the `WWW-Authenticate` challenge are unchanged. Each `token_rejected` or `grant_revoked` logs a warn-level `caller_auth_rejected` line with the path and a 10-character token-hash fingerprint (`tokenFp`, never the token), so repeated rejections of one caller's token can be alerted on (#101).
- **Caller-token rotation overlap:** an optional `CALLER_TOKEN_PREVIOUS` secret is accepted beside `CALLER_TOKEN` on `/v1/*`, `/fetch`, `/fetch/batch` and `/agents`. Each use logs `caller_token_previous_used`, so it can be removed once no caller sends it. It's a separate secret, not a list inside `CALLER_TOKEN`, because `CALLER_TOKEN` also serves as the fallback session HMAC key (#101).

## [2.8.11] - 2026-11-26

### Fixed
- **Cold scrapes logged false R2 errors:** every cold public scrape first did a blind `bucket.get()` on its options-cache key, and Workers Observability logs an R2 `NoSuchKey` as an error-level `r2_get` span. That was 147 of 148 error events in a 30-minute production window. Writing a cache entry now also upserts a `scrape_cache_index` row in META D1 (created lazily with `CREATE TABLE IF NOT EXISTS`), and lookups read that row first: no row or a stale row is a miss without touching R2, and a failed index query falls back to the R2 read. Existing entries are missed once and rewritten (#99).

## [2.8.10] - 2026-11-26

### Changed
- **`search` keeps each result's real URL:** result URLs were canonicalized without their trailing slash, which is a good dedupe key, but it was also the URL that search returned and fetched. Docs sites redirect `/page` to `/page/`, and the node waits a full same-host politeness pause before following it, so each such page cost 4.4-7.8 s against a ~20 ms first byte and enrichment kept hitting its 15 s budget. Results now return, and enrichment now fetches, the provider's own URL (with its slash). Fusion still dedupes on the slashless key (#97).

## [2.8.9] - 2026-11-26

### Changed
- **`search` enrichment spreads its budget across hosts:** nodes fetch same-host URLs one at a time behind the per-host politeness floor (about 2.5-4 s per page), so results clustered on one docs site used up the 15 s budget and still came back without `rawContent`. Extract gains an optional `maxFetchPerHost`, and `search` passes 2. Further same-host results are served from the 1 h scrape cache when fresh, and otherwise keep their search snippet (`failedResults` `error: "host_fetch_cap"`) (#95).

### Fixed
- **`fetch_batch` misread docs pages as JSON:** an `/api/` segment anywhere in the path inferred `kind: json`, so pages such as MDN's `/docs/Web/API/*` failed with `not JSON (text/html)` and stopped the rest of that host's batch. JSON is now inferred only for a leading `/api` segment or a versioned `/api/v<N>` (#95).

## [2.8.8] - 2026-11-26

### Fixed
- **Sign-ins logged false D1 errors:** the first GitHub sign-in on a cold Worker isolate ran seven `ALTER TABLE users ADD COLUMN` statements and ignored the expected `duplicate column name` failures, but Workers Observability recorded each failure as an error-level `d1_run` span. The hub now reads `PRAGMA table_info(users)` once, adds only the missing columns, and caches the result per isolate (#92).

### Changed
- **Faster `search` with `include_raw_content`:** page enrichment now runs under a 15 s wall-clock budget. Every node dispatch is capped to the time remaining, and optional follow-ups (HTML retry, Workday stub, browser-auto render, external SPA fallback) are skipped once too little is left. Before, a single search could take 11-79 s. Pages that miss the budget keep their search snippet and just omit `rawContent`. The standalone `extract` tool is unchanged (#93).

## [2.8.7] - 2026-11-26

### Fixed
- advertise listChanged: false and end subscriptions/listen gracefully (#90)

## [2.8.6] - 2026-11-26

### Fixed
- serve MCP Streamable HTTP at the site root as well as /mcp (#88)

## [2.8.5] - 2026-11-26

### Fixed
- accept GitHub RFC 9207 iss on OAuth callbacks (#86)

## [2.8.4] - 2026-11-26

### Fixed
- fetch_batch includeBody:false still returns artifactIds; label JSON auto-kind results as json (#84)

## [2.8.3] - 2026-11-26

### Fixed
- **Scrape cache ignored `jsonFilter` (L-01):** a `jsonFilter` scrape of a URL that was already cached could return the earlier unfiltered result, either as a cache hit or through `304` revalidation (`+cache:304`, including with `maxAgeMs: 0`). The filter now counts as a non-default cache option, so the plain META D1 lookup and `304` revalidation are skipped, and the trimmed filter is part of the options cache hash, so filtered and unfiltered results, and different filters, never share a cache entry. Requests without `jsonFilter` keep the same cache hash, so no existing cache entry is invalidated.

### Changed
- CI: publish the versioned add-on image from `main` when a new version lands (#82).

## [2.8.2] - 2026-11-25

### Fixed
- **Go-node extraction of >4 MiB pages (#79):** the primary agent path now applies the same acceptance rules as the offload path (non-empty in-budget markdown; flagged response otherwise); nodes apply `includeTags`/`excludeTags` and confirm with `contentScopingApplied`, so tag-scoped large pages succeed on updated nodes and can never leak excluded content from older ones; node-offloaded origin markdown is no longer empty; node `links`/`favicon`/`images` are sanitized; `jsonFilter` is applied on the node; JSON over 2 MiB keeps OpenAPI/notebook formatting.
- **Scrape fidelity (#79):** sanitizer output that grows past the budget is bounded and flagged (`truncated`, `sourceTruncated`, `sourceChars`); `totalChars`/`nextOffset`/`remainingChars` count the sanitized artifact that `read_artifact` serves; the sanitizer budget cut no longer discards long single-line documents (e.g. minified JSON after a short first line); `parsers: []` returns `artifactId` and a warning when `rawBase64` is too large to inline.
- **Batch & catalog (#79):** batch scrape retries `429 isolate_memory_busy` (bounded) and reports still-busy items as `retryable` with `retryAfter`; catalog fetches cap inline bodies and stop with `page_too_large_for_edge` instead of silently ending.
- **WASM bridge (#79):** an RE2 recompile failure after a reactor swap fails closed (crawl include/exclude filtering denies) instead of reporting "no match"; `parseHtmlDoc` retries once after an eviction during parsing, then errors instead of returning an empty document.

### Changed
- Release tooling (#78): `make release-bump BUMP=patch|minor|major` rewrites every version marker and drafts the changelog; `make release-check` runs on every PR. The hub deploy job now fails when `CLOUDFLARE_API_TOKEN` is missing instead of passing after a dry run.
- Hub deploy verification: the deploy job tags the Cloudflare Worker Version with the release tag and commit, then `hub/scripts/verify-deploy.mjs` fails the job unless the newest deployment serves exactly that version at 100%, it carries the tag, live `/openapi.json` reports the release version, and `/health` is ok.
- `hub/wrangler.toml` states `[env.production.observability]` explicitly (#79).

## [2.8.1] - 2026-11-25

### Fixed
- **Worker memory safety (#71, #73, #74):**
  - Fresh WASM reactor startup memory cut from 51 MiB to 7.25 MiB by moving vault crypto to host WebCrypto (byte-for-byte compatible with existing sealed secrets, including v1 / v2.7.0 legacy envelopes and downgrade blocking) and lazy-compiling package-level regexes.
  - Global 4 MiB WASM input budget measured in UTF-8 bytes across all raw/JSON/RE2 entry points, a fail-closed oversized-markdown sanitizer (cut at a line break, then sanitize once; linear TS fallback that escapes `&`, `<` and `>`), and a 12 MiB per-isolate byte semaphore (`429 isolate_memory_busy`).
  - Reactor eviction only after >8 MiB calls or >64 MiB total linear memory (no rebuild churn on ordinary 2 MB documents), no second retry instance for >8 MiB inputs, and RE2 / DOM handles bound to their reactor instance.
  - Greenhouse boards fetched in lite mode (`content=false`) in both search and verify modes, with capped per-posting enrichment for pay and snippets.
- **Go-node offload of >4 MiB documents (#73, #76):** requests using `includeTags`/`excludeTags` are no longer offloaded (excluded content could leak); node results are accepted only when they contain in-budget markdown (no more silent empty 200s for unformattable bodies such as sitemaps, and over-budget origin markdown is cut and sanitized at the edge); responses warn when `html`/`rawHtml`/`product`/`attributes`/`json`/`jsonFilter` are unavailable for a node-extracted page; the busy-isolate path applies the WAF, prompt-injection and content-state guards.
- **Extraction (#72, #76):** JSR `<pre>` blocks with copy buttons keep their code; product `sku` falls back to the primary Offer (Shopify), and `json` schema extraction sees custom-domain Shopify / adapter records.
- **Budgets & plumbing (#76):** base64 bodies count toward the batch body budget (`bodyBase64Omitted` + hub warning instead of exceeding the 20 MiB agent reply cap); secondary fetches (Workday stub, commerce twins, alternate markdown, `llms.txt`) omit bodies over the WASM budget; catalog probe `timeoutMs` is sent where the Go fetcher reads it; an explicit root tracer no longer hides the active child span.
- **Post-2.8.0 fixes (#66–#70):** multi-MiB ATS boards are streamed and catalog probes are bounded (#70); `fetchFn` is detached from its params object to avoid workerd `Illegal invocation` (#69); the declarative `ExtractHTMLDocumentFull` callback passes `IsFragment=true` (#68); a cold-R2 EasyPrivacy bootstrap with refresh API and pkg.go.dev toolbar-chrome cleanup (#66).

### Changed
- Single-pass Go WASM EasyPrivacy validator and fragment `defaultHTMLToMD` (#67).
- CI: shared retrying CPU-budget helper for linear-time regression tests and fixed OTLP span-count races (#75); the M4 adversarial-HTML check now retries against its unchanged 350 ms budget; hub dev dependencies bumped, including TypeScript 7 (#56).

## [2.8.0] - 2026-11-25

### Changed
- **Go-First Architecture Consolidation (2 Runtimes Down From 4):**
  - Consolidated all HTML-to-Markdown extraction, CommonMark `S1`–`S5` fence sanitization, `read_artifact` slice paging, Schema.org JSON-LD, framework state hydration, CMS auto-twins, Wikipedia linear cleaning, 56 declarative YAML manifests, ATS `jobs` + `x402`, Shopify/WooCommerce `catalog` diffing, BYO-LLM `/v1/agent` loop, and AES-256-GCM MCP federation/vault into Go (`internal/extract`, `internal/jobs`, `internal/catalog`, `internal/agentloop`, `internal/mcpfed`) compiled to embedded `edgefetch-core.wasm` for Cloudflare Workers.
  - Promoted Pure-Go `edgefetch --mode=hub` (`internal/hub`, `internal/hub/hubstore`, `internal/hub/hubauth`) to full 17-tool MCP, REST `/v1/*` + `/v2/*`, OAuth 2.1 PKCE `S256`, GitHub OAuth, `/admin`, and Tavily/Firecrawl compatibility parity, switched `Dockerfile.all-in-one` to `alpine:3.24` (`UID 1000` Hub + `UID 65532` Chromium worker, zero Node.js/Deno), and removed `hub/portable/*` (`portable-server.ts` and `deno-server.ts`), cutting `hub/package.json` runtime dependencies down to `jose` and `oauth4webapi` while keeping `go.mod` at `1` external dependency (`github.com/coder/websocket`).

### Security
- **Post-Consolidation Clean-Room Hardening:**
  - Enforced dial-time `politeness.RejectNonPublicPeer` (`Proxy: nil`, TLS 1.2+) across BYO-LLM and outbound 3rd-party MCP discovery/federation, pre-comparison per-IP / IPv6 `/64` brute-force lockouts on `/oauth/authorize` and `/oauth/register`, SHA-256 digest `constantTimeEqual`, RFC 6750 `WWW-Authenticate` scope step-up across `search` (`scrape: true`), REST, and MCP JSON-RPC batch requests, and OTLP pre-auth `401` suppression.

## [2.7.8] - 2026-11-23

### Added
- **Universal Web Extraction Funnel (`SCRAPE_PIPELINE_VERSION = 34`, `hub/src/extractors/schema-org.ts`, `hub/src/extractors/cms-twins.ts`, `hub/src/extractors/framework-hydration.ts`):**
  - Added linear `O(N)` universal Schema.org JSON-LD extraction (`FAQPage`, `QAPage`, `DiscussionForumPosting`, `ItemList`/`CollectionPage`/`SearchResultsPage`, `Article`/`NewsArticle`/`BlogPosting`/`TechArticle`/`ScholarlyArticle`, `Event`, `SoftwareApplication`, `Dataset`, `Recipe`, `LocalBusiness`) with quote-aware prompt-injection inspection and strict anti-false-zero semantics.
  - Added polite same-origin HTTPS auto-twins (`respectRobots: true`) for WordPress REST API (`<link rel="alternate" type="application/json" href=".../wp-json/wp/v2/(posts|pages)/<id>">`) and Gatsby `/page-data/<path>/page-data.json`.
  - Upgraded SSR Framework State Hydrator (`R6` v2) with a linear `O(N)` Next.js App Router RSC Flight scanner (`self.__next_f.push`), a bounded cycle-safe Nuxt 3 `devalue` flat-array dereferencer (`#__NUXT_DATA__`), Angular `#ng-state`, Wix `#wix-viewer-model`, Squarespace `Static.SQUARESPACE_CONTEXT`, Substack `window._preloads`, and homogeneous `records[]` + GFM table extraction.
- **Chromium CDP Hidden-DOM Pruning & Same-Origin JSON XHR Harvesting (`internal/browser/renderer.go`, `internal/crawl/crawl.go`, `internal/crawl/llms_scrape.go`):**
  - Pruned computed-hidden `<body>` subtrees (`display:none`, `visibility:hidden`, `aria-hidden="true"`, `hidden`, and zero-opacity `pointer-events:none` fixed/absolute overlays) in `readDocumentHTML` while preserving `<head>`, JSON-LD/state `<script>` blocks, `<details>` disclosures, open Shadow DOM, and challenge widgets.
  - Added bounded (`<= 6` responses, `<= 256 KiB` each, `<= 512 KiB` total) untainted main-frame same-origin `200 OK` `application/json` XHR/Fetch response harvesting (`capturedJson[]`) distilled by the Hub into sanitized `records[]` and `structured` metadata.
- **Telemetry-Driven Adapter Gap Radar & Offline Manifest Proposer (`hub/src/gap-radar.ts`, `hub/scripts/propose-manifest.mjs`, `hub/src/admin.ts`, `hub/src/index.ts`):**
  - Added `GET /v1/hosts/gaps` and `/admin` Adapter Gap Radar ranking origin hosts by `META` D1 headless browser fallback duration (`auto-render-1`) and non-OK rates, cross-referenced against registered site adapters.
  - Added `npm run adapter:propose -- <https-url>` offline declarative YAML manifest + test fixture generator with DNS-pinned SSRF checks, `robots.txt` verification, and `M2` PSL domain validation.
- **Optional Headless Chromium Third-Party Tracker Blocking (`hub/src/tracker-list.ts`, `hub/src/index.ts`, `hub/portable/portable-server.ts`, `hub/portable/deno-server.ts`, `internal/browser/renderer.go`, `internal/agent/agent.go`):**
  - Outbound network notice: when enabled (default on Cloudflare, Portable Node, and Deno Hubs), the Hub makes a once-daily conditional HTTP `GET` (`If-None-Match` / `If-Modified-Since`, minimum 6-hour retry interval, never during startup) to `https://easylist.to/easylist/easyprivacy.txt` ([EasyPrivacy Licence](https://easylist.to/pages/licence.html)) via the Hub's safe-fetch layer; set `EDGEFETCH_TRACKER_LIST=off` to disable this outbound request completely (`0` requests). Standalone `edgefetch scrape`, `edgefetch mcp`, `edgefetch --mode=hub`, and worker agents never fetch `easylist.to`.
  - Validated `||host^` rules (with bot-challenge/WAF and feature-flag allow-listing) are pushed over `/agent/ws` to browser workers, which abort third-party tracking subresources via CDP `Fetch.failRequest` (`BlockedByClient`), report `metadata.blockedTrackers` on `scrape` and `interact`, honor per-request `blockTrackers: false`, and expose `trackerListVersion` on `list_agents` and owner-only metadata on `/admin`.

### Fixed
- **ATS Parity & Wikipedia Linear ReDoS/URL Hardening (`hub/src/jobs.ts`, `hub/src/scrape.ts`, `hub/src/wikipedia.ts`, `internal/extract/manifests/icims.yaml`):**
  - Added `%20` Ashby board slug support (`isValidAshbySlug`), compact-slug fallback probing and explicit non-`live` `reason` codes in `jobs` `verify`, multi-page Workday CXS pagination (`cursor`/`offset`) preserving page-0 `total` across `offset > 0` pages, Markdown truncation footers on `scrape`, `detected.adapter` reporting, and iCIMS root `/` inner-portal twin resolution rejecting `#icims_content_iframe` wrapper shells.

## [2.7.7] - 2026-11-23

### Security
- **Blind Security Audit Hardening (`EF-BLIND-01`–`06`, `internal/browser/renderer.go`, `internal/politeness/redact.go`, `hub/src/storage.ts`, `hub/src/otel.ts`, `hub/src/scrape-advanced.ts`):**
  - Enforced mandatory post-rotation `Network.requestWillBeSent` `loaderId` proof (`stepRotated` + `needsAsyncLoaderProof`) on retained Chromium sessions in `internal/browser/renderer.go`, eliminating late `pagehide` `{keepalive: true}` header leaks across `referrerPolicy: "no-referrer"`, `referrerPolicy: "origin"` (including root `/` navigations), same-origin `RequestInit.referrer` spoofing, and same-URL re-navigations (`EF-BLIND-01`), and added `--bwsi` plus Optimization Guide / Privacy Sandbox feature disables (`EF-BLIND-06`).
  - Added streaming `DecompressionStream('gzip')` uncompressed byte-length and `SHA-256` verification in `handleAgentArtifactUpload` prior to deduplication or R2 writes and deduplicated `'transient'` uploads cleanly after `'stored'` promotion in `META.artifacts` (`EF-BLIND-02`).
  - Hardened schemeless `user:secret@host` terminator clamping (preserving IPv6 `@[::1]` literals while clamping outer `]`, `{`, `}`, `;`, `\`, `` ` ``, `|`, and UTF-8 `U+0085`/`U+2028`/`U+2029` line breaks) and HTAB-delimited inline auth redaction in Go (`EF-BLIND-03`) and unified `scrubFreeTextUrlsAndSecrets` across `sanitizeErrorMessageForSpan` and `sanitizeSpanAttributes` in Hub OTel (`EF-BLIND-04`).
  - Replaced scalar `activeListIndent` tracking in `computeMarkdownSliceCheckpoints` and `sanitizeMarkdownPageSlice` with a `listIndents` stack so nested-list dedents never invert CommonMark fence state (`EF-BLIND-05`).

### Fixed
- **Live MCP Observability, Jobs, Catalog Currency & Screenshot Artifacts (`hub/src/index.ts`, `hub/src/otel.ts`, `hub/src/jobs.ts`, `hub/src/catalog.ts`, `hub/src/scrape.ts`, `hub/src/mcp.ts`):**
  - Wired `metaDb: env.META` into `handleAgentArtifactUpload` (eliminating unnecessary `r2_head` spans on deduplicated uploads) and preserved caller W3C TraceContext `-00` unsampled flags on data-plane routes.
  - Added `screenshotArtifactId` (`private/<userId>/tmp/sha256/...` R2 storage) on `interact` and `scrape` screenshots while stripping 188K-char inline `screenshotBase64` payloads from MCP `tools/call` text responses so browser screenshots never overflow agent context windows.
  - Switched Shopify currency resolution to probe `/meta.json` (permitted by Shopify `robots.txt`) before `/cart.js` with bounded 256-origin positive/negative caching and `crawl:fetch`-gated lazy currency backfill on stored `catalogId` snapshots.
  - Tightened `jobs` query relevance to word-boundary token matching (so `"Engineer"` no longer matches `"Engineering Manager"`), added `minBaseMode: "overlap"`, promoted Workday board discovery + path-scoped SmartRecruiters search, extracted Lever multi-location NY salary ranges, and capped test runner concurrency via `os.availableParallelism()`.

## [2.7.6] - 2026-11-23

### Security
- **Browser `pagehide`/`keepalive` Unload Header Isolation & Byte-Table URL Query Scan (`P2`, `internal/browser/renderer.go`, `internal/politeness/redact.go`):**
  - Staged next-step `task.Headers` (`pendingStepHeaders`) until `Page.frameNavigated` commits on `mainFrameID`, retained prior `reqLoaderIDs`, and tracked retired `staleStepDocURLs` across `Referer`, `Initiator.URL`, and `Network.requestWillBeSent` `documentURL` so late `pagehide`/`unload` `{keepalive: true}` requests from a previous page can never receive newly bound step headers in live Chromium.
  - Replaced UTF-8 rune-by-rune `strings.IndexAny` query scanning and oversized `strings.Builder.Grow` allocation in `RedactEmbeddedURLs` with a 256-byte stop-table and exact output sizing so 1 MiB query redaction runs in `< 1 ms` even under Go `-fuzz` instrumentation.

## [2.7.5] - 2026-11-23

### Security
- **Fail-Closed Markdown `<` Escaping, Bounded Container Depth & Isolated SHA-256 Artifact Cache (`S1`–`S5`, `SCRAPE_PIPELINE_VERSION = 33`, `hub/src/scrape.ts`, `hub/src/scrape-advanced.ts`, `hub/src/storage.ts`, `internal/extract/sanitize.go`):**
  - Removed the inline-code `<`-restorer (`escapeResidualLtPreservingSafeCodeSpansLinear`) and restored unconditional escaping of every `<` to `&lt;` outside recognized CommonMark fenced code blocks across `sanitizeInlineHtmlInMarkdown`, `finalizeScrapedMarkdown`, `sanitizeFullMarkdownDocumentForArtifact`, and `sanitizeMarkdownPageSlice` (`SCRAPE_PIPELINE_VERSION = 33`), running 512 KiB single-line `` `<a>` `` payloads in linear time.
  - Capped `recognizeAndHardenMarkdownFences` container nesting at `32` (`MAX_MD_CONTAINER_DEPTH`) with O(1) container-flag bitmasks, replaced `.trim()` blank-line checks with strict CommonMark §2.1 ASCII space/tab checks (`0x20`/`0x09`), preserved newline boundaries across truncated unclosed `<script>`/`<style>`/`<textarea>`/`<title>`/`<xmp>`/hidden subtrees/comments before fences with a second fence-hardening pass, aligned CommonMark §2.2 4-column tab-stop fence openers/closers and lazy paragraph-continuation rules across TS and Go, and separated `safeOffset > 0` synthetic slice fence boundaries on contiguous page concatenation.
  - Split `readArtifactPage` sanitized-document caching into a dedicated public LRU pool (`32` entries / `16 MiB`) and isolated per-user private LRU pools (`64` users, `4` entries / `4 MiB` per user, `null` scope when `privateOnly` lacks `userId`), validated by full-document SHA-256 over R2 `arrayBuffer()` bytes.
- **64-Bit-Only Seccomp, Exact Connector IDs, Multi-User OAuth Rotation & Vault v2 AAD (`S6`–`S8`, `U1`–`U2`, `P1`–`P8`, `deploy/seccomp/chromium-sandbox.json`, `hub/src/*`, `hub/portable/*`, `internal/browser/renderer.go`, `internal/extract/*`, `internal/hub/hub.go`):**
  - Removed 32-bit `SCMP_ARCH_X86`, `SCMP_ARCH_X32`, and `SCMP_ARCH_ARM` from `chromium-sandbox.json` (blocking 32-bit `socketcall` bypasses), bound `renderer.go` `frameTainted` resets strictly to committed `Page.frameNavigated` events on `mainFrameID` with a `256`-frame cap, required trailing `/` on all `{host}`/`{origin}` manifest templates, wired `twin.ValidateRedirectTarget` in Go `hub.go`, and enforced non-destructive commerce field/timestamp escaping plus `https:`-only public commerce image URLs.
  - Restricted `/v1/agent` `mcpServers` matching and dispatch strictly to exact connector `id` or `slug`, recursively sanitized connector `structuredContent`, JSON-RPC errors, `discover_mcps`, `list_connected`, `list_tools`, and tool schema descriptions, returned raw `POST /fetch` and `/fetch/batch` strictly to `CALLER_TOKEN`, added `O(1)` `refresh_used` generation-counter replay detection + `6/60s` per-grant refresh rate limits + rotation quota checks (`0005_round10_vault_and_oauth.sql`), bound `v2.` vault HKDF/AAD to `(userId, id, slug, authType, remoteOrigin)` with downgrade-proof `secret_version >= 2`, guarded `admin_disable` atomically against concurrent `owner` promotion, and protected slow-first-byte (`bytesRead > 0`) and veteran keep-alive sockets in `portable-server.ts` / `deno-server.ts`.

### Fixed
- **Live MCP `jobs` Search, Expressive Code Lines & Cold-Isolate D1 Cleanups (`hub/src/jobs.ts`, `hub/src/agent-hub.ts`, `hub/src/scrape.ts`, `internal/extract/extract.go`, `internal/crawl/crawl.go`, `internal/politeness/redact.go`):**
  - Retired legacy `fat_agent_required` error codes in favor of `browser_worker_required` with Home Assistant OS `allow_no_sandbox_browser` guidance, fixed `jobs` `postedWithinDays <= 30` dropping Ashby/Greenhouse results via Serper `tbs=qdr:*` filters, added a 5-minute LRU board/job cache with single-flight coalescing and 4-way concurrency bulkheads (eliminating repeat Ashby board downloads and 6-way parallel `jobs` timeouts), added SmartRecruiters board discovery (`jobs.smartrecruiters.com/{Company}`) and Lever/Greenhouse/JSON-LD pay-transparency extraction, preserved empty lines in Starlight/Expressive Code `<div class="ec-line">` blocks across TS and Go, eliminated cold-isolate D1 `duplicate column name: user_id` OTel spans via `PRAGMA table_info(...)`, and made `update-psl.mjs --check` deterministic offline.

## [2.7.4] - 2026-11-23

### Security
- **CommonMark Fence Hardening, Unconditional Residual `<` Escaping & Linear Link/Paging Guards (`H1`, `H2`, `SCRAPE_PIPELINE_VERSION = 33`, `hub/src/scrape.ts`, `hub/src/scrape-advanced.ts`, `hub/src/storage.ts`, `internal/extract/sanitize.go`):**
  - Hardened full-document Markdown fence recognition in TypeScript (`recognizeAndHardenMarkdownFences`) and updated Go (`SanitizeMarkdown`) while tracking paged artifact slices via `16 KiB`-checkpointed slice fence state (`computeMarkdownSliceCheckpoints` / `sanitizeMarkdownPageSlice`), normalizing `U+2028`, `U+2029`, and `U+0085` upfront, enforcing ordered-list `1.` paragraph-interruption rules (`42.` after prose stays paragraph text), and re-hardening prose after comment/tag/entity stripping (`escapeSynthesizedBlockHazardsInProse`).
  - Escaped every residual `<` to `&lt;` outside recognized CommonMark fenced code blocks (including inside inline backtick code spans) while preserving linked image badges (`[![alt](img)](href)`).
  - Replaced repeated `.includes()` rescans in `isDisallowedMarkdownLinkDestination` with a running `sawDelim` flag + `4,096`-char cap (`H2`), clamped `readArtifactPage` to `SCRAPE_PIPELINE_VERSION = 33` with per-user/public SHA-256 cached `16 KiB`-checkpointed slices, sanitized scraped metadata fields (`title`, `description`), raised `detectPromptInjection` to `8 MiB` with obfuscated-token reconstruction and reduced `.sr-only` UI false positives, stripped trailing dots in `compile-manifests.mjs`, escaped commerce titles/SKUs, and enforced wildcard twin redirect target validation (`ValidateRedirectTarget`).
- **Federated MCP Linear Bounds & `/v1/agent` LLM Connector Isolation (`H3`, `H4`, `hub/src/mcp-federation.ts`, `hub/src/agent-runner.ts`, `hub/src/mcp-vault.ts`, `hub/src/mcp.ts`):**
  - Capped remote MCP content blocks (`<= 64`) and per-block text (`<= 64 KiB`) before linear link/style sanitization (`H3`), and wrapped untrusted MCP outputs in dynamic fence-safe envelopes (`formatFenceSafeUntrustedMcpEnvelope`).
  - Required explicit `mcpServers` allowlists on `/v1/agent` (`preferMcp: true` alone exposes zero connectors), resolved connectors via `vaultStore.getServer` before checking per-run `allowedConnectorIds` (removing bare `.endsWith()` domain matching), gated callable tools on cached `readOnlyHint === true && destructiveHint !== true` unless explicitly allowlisted with `mcp:call` scope, kept remote tool/property names strictly out of the `SYSTEM` message (`H4`), required `mcp:call` on `list_tools`, wired `confirmedAuthOrigin` across probe/start routes, and prefixed new vault/PKCE envelopes (`v2.` / `pkce2.`, `@deprecated Remove in v2.7.5` on `v1.` legacy fallback).
- **Atomic Conditional Multi-User Updates, Founder Recovery & Tenant Quotas (`H5`, `H6`, `hub/src/github-auth.ts`, `hub/src/oauth.ts`, `hub/src/admin.ts`, `hub/src/index.ts`, `hub/migrations/meta/0004_round9_founder_pinning.sql`):**
  - Replaced stale post-`await` user-row upserts across GitHub OAuth sign-in, `@org` re-verification, and token refresh with live re-reads and conditional `UPDATE ... WHERE COALESCE(disabled, 0) = 0 AND COALESCE(session_epoch, 1) = ?` guards so concurrent account disables, deletions, or demotions can never be undone by an in-flight request (`H5`).
  - Evaluated `GITHUB_OWNER_ID` founder identity first on login, added `promoted_by_owner_id` reconciliation (`enforcePinnedFounderOwners`) to demote non-founder-promoted `owner` rows on upgraded databases while enforcing allowlist/`@org` checks on secondary owners (`H6`), replaced global OAuth FIFO eviction with per-user grant caps (`MAX_OAUTH_GRANTS_PER_USER = 64`), isolated non-owner `fetch_url`/`fetch_batch`/`catalog` R2 artifacts under `private/<userId>/`, and enforced per-user `extract` (`4` runs / `16` URLs) and `map` (`4` runs) concurrency quotas.
- **Portable Hub Keep-Alive Eviction, OTel Audit Preservation, Browser Frame-Taint & Seccomp Hardening (`H7`, `H8`, `hub/portable/*`, `hub/src/otel.ts`, `internal/browser/renderer.go`, `deploy/seccomp/chromium-sandbox.json`, `cmd/edgefetch/update.go`, `internal/politeness/redact.go`):**
  - Added established keep-alive socket caps (`16` per IP, `128` global idle) with LRU-idle eviction, `2 MiB` slow-read pipelining backpressure, and a `32 MiB` Deno stream guard (`H7`), plus unsuppressible `security_audit` OTLP export when callers send `traceparent: ...-00`.
  - Replaced `frameCommitted` header fallbacks in `internal/browser/renderer.go` with per-frame `frameTainted` inheritance across all child frames, non-harness navigations (`reload`, `history`, `<form>`, `204`/`205`, downloads), and subresources requiring positive `Origin`/`Referer` same-origin proof (`H8`), blocked `setns`, `clone3` (`ENOSYS`), and `AF_PACKET`/`SOCK_RAW` in `deploy/seccomp/chromium-sandbox.json`, failed closed on unparseable/`dev` SemVer floors in `edgefetch update`, and expanded Go URL redaction and `jobs.ts` ATS slug verification.

### Fixed
- **Live MCP Reliability, Home Assistant OS Browser Opt-In & Tool Polish (`internal/browser`, `internal/crawl`, `addon/`, `hub/src/*`):**
  - Added an opt-in `allow_no_sandbox_browser` (`EDGEFETCH_ALLOW_NO_SANDBOX`) toggle in the Home Assistant add-on configuration (default `false`, fail-closed) to advertise `browser-v1` under HAOS AppArmor confinement, surfaced `warnings` when `renderMode: "auto"` hits a thin SPA without `browser-v1`, persisted `owner` crawl pages immediately so `crawl` never returns empty `data: []` before `IngestWorkflow` completes, retried `map` discovery via container overflow instead of returning `ok: true` when all sources are `not_tried`, returned structured JSON (`retryable: false`) on IP-literal/policy URL rejections, isolated per-item `fetch_batch` invalid URLs while echoing `effectivePauseMs`, separated `scheme_downgrade` redirects from synthetic `403` SSRF redirect blocks, projected lean `catalog` records with `/cart.js` Shopify currency detection and `ok: true, truncated: true` on caller `maxPages`, tightened `find_extractors` category boosts and `search` `via` attribution, and deduplicated animated slot-counter text.

## [2.7.3] - 2026-11-22

### Fixed
- **Deterministic 2-vCPU CI Release-Gate Parity (`hub/test/*`, `.github/workflows/*`, `hub/src/mcp-vault.ts`):** Eliminated a shared-runner wall-clock timing flake in `round8-sanitizer-paging-cpu.test.ts` when `npm test` ran 17 bundles in parallel without `NODE_V8_COVERAGE` on 2-vCPU GitHub Actions runners (blocking the `v2.7.2` tag test gate before signing/publish while preserving strict `8x` `256 KiB -> 2 MiB` linear scaling-ratio assertions), added uninstrumented `npm test` execution to `.github/workflows/ci.yml` alongside V8 coverage for 1:1 release-gate parity, aligned `psl:check` + `build:portable` across `release.yml`, `addon-ghcr.yml`, and `deploy-hub.yml`, bumped `deploy/winget/*.yaml` to `2.7.3`, and extended the legacy `v2.7.0` vault auto-reseal deprecation target to `v2.7.4`.

## [2.7.2] - 2026-11-22

### Security
- **Fail-Closed Markdown & Paged-Slice Sanitization + Single `SCRAPE_PIPELINE_VERSION = 31` (`H1`, `H2`, `H8`, `hub/src/storage.ts`, `hub/src/scrape.ts`, `hub/src/scrape-advanced.ts`, `internal/extract/sanitize.go`):**
  - Replaced paragraph-boundary heuristics with an unconditional fail-closed rule in both TypeScript and Go: outside recognized CommonMark fenced code blocks, every residual `<` is escaped to `&lt;` and every disallowed inline `](...)` link, `[id]: ...` reference definition, HTML `<a href>`/`<img src>` attribute, GFM task-list checkbox (including nested list markers), and bare protocol-relative `//host.tld` linkify target is neutralized — **inline backtick code spans included**.
  - Exported `SCRAPE_PIPELINE_VERSION = 31` from `hub/src/storage.ts` imported across `scrape.ts` and `index.ts`; removed legacy `< 31` derived-Markdown cache fallbacks in `readArtifactPage` and re-sanitized full documents and fence-aware slices (`sanitizeMarkdownPageSlice`) across `read_artifact`, `scrape`, and `interact`.
  - Ported dead-offset memoized WHATWG HTML5 comment stripping (`<!--...-->`, `--!>`, abrupt `<!-->`, `<!--->`) and cached last-backtick indices to Go `SanitizeMarkdown`.
- **Linear $O(N)$ Scanners & Unconditional Prompt-Injection Guard (`H3`, `hub/src/scrape.ts`, `hub/src/scrape-advanced.ts`, `internal/politeness/redact.go`):**
  - Replaced backtracking trailing-whitespace and underscore regexes with linear char-code loops (`trimAsciiWhitespaceLinear`, `.replace(/_+/g, ' ')`), indexed closing HTML tags in a single pass (`closeFirstByTag`/`closeMoreByTag`), and added a zero-allocation `schemelessSpanCache` in Go's `RedactEmbeddedURLs`.
  - Removed all input-class skip gates from `detectPromptInjection` (running `scanSpaced`, `scanWordStream`, and `scanStripped` unconditionally), preserved image `![alt]`, `[ref]: url "title"` titles, and hyphenated pipe-table domains during link unwrapping, scanned hidden CSS/DOM/`<template>`/`<noscript>` subtrees against all `INJECTION_PATTERNS`, and prevented attacker-supplied `[SCRUBBED]` strings from mimicking redaction markers.
- **Multi-User GitHub Auth, Org Revocation, Tenant Cache Isolation & MCP Vault Hardening (`H4`, `H5`, `hub/src/github-auth.ts`, `hub/src/map-crawl.ts`, `hub/src/mcp-vault.ts`, `hub/src/mcp-federation.ts`, `hub/src/agent-runner.ts`):**
  - Removed the `@org` session-revocation bypass in `github-auth.ts`, recorded `admitted_via` / `admitted_org` / `encrypted_gh_token` / `org_verified_at` (`0002_multiuser.sql`), re-verified live GitHub `/user/orgs` membership on token refresh and stale TTL, rejected bare-digit entries in `GITHUB_ALLOWED_USERS` (requiring explicit `id:` or `login:`), and required explicit `GITHUB_OWNER_ID` configuration without auto-deriving owner pins from mutable rows (blocking secondary owners from mutating owner accounts in `admin.ts`).
  - Isolated non-owner `crawl` runs, `redactPii` scrapes, and private PDF OCR temporary blobs strictly out of shared R2/D1 caches, enforced per-user concurrency quotas (`16` `scrape`, `4` `interact`, `4` `agent` -> `429 user_quota_exceeded`), enforced `crawl:read` / `crawl:fetch` OAuth scopes across all `/v1/*` and `/v2/*` routes, and isolated memory-only `catalog` LRU state per `userId`.
  - Enforced `mcp:call` scope on `scrape` MCP routing (`preferMcp`), required explicit connector opt-in on `/v1/agent`, validated remote MCP tool and property names against `SAFE_MCP_IDENTIFIER_RE = /^[A-Za-z0-9_.-]{1,64}$/`, required explicit `confirmedAuthOrigin` (`409 cross_origin_auth_confirmation_required`) when a downstream MCP OAuth Authorization Server origin differs from the connector origin, and auto-resealed legacy `v2.7.0` vault ciphertexts to `v2.7.1+` length-prefixed AAD on first decrypt (`@deprecated Remove in v2.7.4`).
- **Vendored Mozilla PSL, Simplified Manifest & Browser Tab-Taint Rules (`H7`, `hub/scripts/compile-manifests.mjs`, `hub/scripts/update-psl.mjs`, `internal/extract`, `internal/browser/renderer.go`):**
  - Vendored Mozilla's `public_suffix_list.dat` (`npm run psl:check`) across TypeScript (`hub/src/psl.ts`) and Go (`internal/extract/psl.go`), enforcing exact-domain uniqueness across all `56` declarative YAML manifests, allowlisted wildcards only, same-registrable-domain `twin.fetchUrl` targets (plus a frozen 5-pair public-archive map), redirect-target domain verification on TS twins, a strict `shopify | woocommerce` `catalog.platform` allowlist in `commerce-engine.ts`, and full manifest validation at startup in Go (`ValidateDeclarativeManifests`).
  - Simplified headless Chromium custom-header isolation in `internal/browser/renderer.go` to an auditable tab-taint invariant (`sawUninjectedSubdoc` + `redirectedCrossOrigin`, cleared only on explicit harness navigation, plus `Sec-Fetch-Site == "same-origin"`), shipped a structured architecture-gated `deploy/seccomp/chromium-sandbox.json` profile, and removed `EDGEFETCH_ALLOW_NO_SANDBOX=1` from `.github/workflows/ci.yml`.
- **Portable Hub Pre-Header Eviction, In-Process OTLP Gate, Anti-Pinning Collector, Jobs, Robots & OpenAPI (`H6`, `hub/portable/*`, `hub/src/otel.ts`, `telemetry/`, `hub/src/jobs.ts`, `hub/src/overflow.ts`):**
  - Replaced `x-ef-verified-auth` header checks with an in-process `WeakSet<Request>` (`markRequestVerifiedInProcess`), updated `portable-server.ts` global pre-header eviction to evict aged (`>= 250 ms`) stalled sockets first before falling back to the heaviest other multi-socket IP bucket (raising `MAX_PREHEADER_SOCKETS_PER_IP` to `32` with `>= 50 ms` shared-NAT squatter eviction and reserved public-discovery headroom), removed hardcoded `EDGEFETCH_PUBLIC_ORIGIN` from `fly.toml`, and added hourly per-IP/subnet fingerprint budgets + a 5-minute freshness tier in `telemetry/`.
  - Rebuilt `matchesAllowedCompanyOrDomain` in `jobs.ts` around dual domain/ATS-slug + subsidiary display-name provenance, implemented `1` polite `200 ms` retry on `502/503/504` primary fetches, treated `/robots.txt` redirects to DNS-failing hosts as `unreachable: true` across Go & TS with a shared cross-language `robots-parity-corpus.json` suite, bumped `deploy/winget/*.yaml` to `2.7.2`, and added an OpenAPI `3.1.0` contract validator (`42` paths).

### Changed
- **Home Assistant Add-on Clean Cutover (`addon/`, `slug: "edgefetch"`):** Renamed `edgefetch_fat/` to `addon/`, simplified the add-on slug to `edgefetch` (`ghcr.io/bartrumb/edgefetch-addon-{arch}`), updated the AppArmor profile (`profile edgefetch`), and removed legacy `"fat"` terminology across Go/Hub messages, OpenAPI schemas, and CI workflows while retaining backward-compatible AppArmor label detection and wire error codes.
- **Zero Default Phone-Home in `edgefetch mcp` (`cmd/edgefetch/cli.go`, `cmd/edgefetch/update.go`):** Made the 24h background GitHub release check in `edgefetch mcp` strictly opt-in behind `EDGEFETCH_CHECK_UPDATES=1` (default `OFF`, honoring `EDGEFETCH_DISABLE_UPDATE_CHECK=1` and `DO_NOT_TRACK=1`), while keeping on-demand Ed25519-verified `edgefetch update` and `edgefetch update --check` available anytime.

### Fixed
- **CI Runner Pinning & GitHub `release` Environment Gate (`.github/workflows/*`):** Pinned CI, release, deploy, and GHCR workflow runners to `ubuntu-24.04` and configured required-reviewer protection (`can_admins_bypass: false`) alongside the `v*` tag policy on the GitHub `release` environment.

## [2.7.1] - 2026-11-22

### Security
- **Round 7 Multi-User, GitHub OAuth & Shared Cache Hardening (`H1`, `H2`, `H4`–`H6`, `hub/migrations/meta/0003_round7_multiuser_hardening.sql`):**
  - **Session revocation & numeric GitHub ID pinning (`H1`, `H5`):** Added `session_epoch` and `disabled` columns to `users` with live Durable Object / D1 verification on every authenticated request, pinned founder/owner identity to immutable numeric `github_id` (preventing GitHub handle-rename takeover), enforced `__Host-` cookie prefixes on HTTPS origins, and immediately invalidated OAuth grants and sessions when an account is disabled or de-allowlisted.
  - **End-to-end tenant & shared-cache isolation (`H4`, `H6`):** Enforced `visibility: "private"` (`Cache-Control: private, no-store`, zero shared R2/D1 cache reads or writes) whenever a scrape carries custom headers, cookies, auth, `preferMcp`, or a non-owner tenant, and enforced strict `user_id` ownership across `crawl`, `batch/scrape`, `catalog`, and `/v1/hosts`.
- **MCP Vault, Downstream OAuth & Federated Tool Safety (`H2`, `H3`, `hub/src/mcp-vault.ts`, `hub/src/mcp-federation.ts`, `hub/src/mcp.ts`):**
  - Bound downstream MCP OAuth 2.1 `resource` and `iss` origins strictly to the registered connector origin, walked remote MCP JSON Schemas through a `16 KiB` depth-bounded structural allowlist before exposing them to LLMs, enforced explicit `mcp:call` OAuth scope on `query_mcp` (`action: "call_tool"`) and `POST /v1/mcp/query`, gated keyless unauthenticated auto-routing strictly on `readOnlyHint: true`, and hardened `llm.ts` redirect/origin checks.
- **Markdown Sanitizer, Linear Prompt-Injection Scanner & Declarative Adapter Guards (`H7`, `SCRAPE_PIPELINE_VERSION = 31`):**
  - Closed CommonMark/GFM code-fence, reference-link, HTML entity, and inline-backtick smuggling vectors across TypeScript (`hub/src/scrape.ts`) and Go (`internal/extract/sanitize.go`), and hardened the $O(N)$ prompt-injection scanner across Markdown and HTML evasion variants (stripping Khmer, Braille blank, musical format, variation selector, and NEL/bidi smuggling runes without input-class skip gates).
  - Enforced Public Suffix List (PSL) wildcard bounds and cross-manifest domain-collision rejection in `hub/scripts/compile-manifests.mjs`, deterministic sorted + lazy `itemVars` evaluation in Go & TS, strict public `https://` feed links, and schema-driven linear-time fuzz testing in `npm run adapter:test`.
- **Portable/Deno Hub Socket Headroom & Zero-Hostname Telemetry Hardening (`H8`, `H9`, `hub/portable/*`, `telemetry/`):**
  - Reserved dedicated loopback socket headroom with silent-socket idle eviction in `portable-server.ts` (`H8`), added single-DNS-resolution IP-pinned SSRF validation in `deno-server.ts` / `safe-fetch.ts` and cryptographic slot tokens, gated OTLP trace export strictly behind authenticated callers (`H9`), honored `DO_NOT_TRACK` in `/admin` Console UI, scrubbed SemVer `+buildmetadata` hostnames/slugs from opt-in dev error telemetry, and hardened the standalone `telemetry/` collector with `/48` + `/64` IPv6 rate-limiting and `count = 1` eviction indexing (`0002_eviction_idx.sql`).
- **Go Browser Sandbox, Windows Handle/Job Isolation, Politeness & Supply-Chain CI (`internal/browser`, `internal/politeness`, `cmd/edgefetch`, `.github/workflows/*`):**
  - Restricted `Fetch.requestPaused` bound-frame fallback strictly to non-Document subresources (`!isDocReq`) with `Page.frameDetached` tracking, scoped Windows Chromium handle inheritance via `STARTUPINFOEXW` `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` + `CREATE_SUSPENDED` kill-on-close Job Object attachment, disabled Chromium Cast/mDNS (`:8009`), gated Linux `--no-sandbox` fail-closed behind `EDGEFETCH_ALLOW_NO_SANDBOX=1` while shipping `deploy/seccomp/chromium-sandbox.json`, hardened Go/TS `robots.txt` ASCII + ZWSP handling with a `10s` tarpit cap, added `edgefetch update` downgrade refusal (`--allow-downgrade`) + Windows `.old` crash recovery, and gated `release.yml` + `addon-ghcr.yml` on full test suites with Ed25519-signed `release-manifest.json` tag+commit+SHA-256 verification in `upstream-sync.yml` and `.github/`/`keys/` protection in `vouch.yml`.

### Fixed
- **Live MCP Audit Functional, Extraction & Tool-Surface Fixes (`internal/browser`, `internal/classify`, `hub/src/*`):**
  - **`interact` form submission, navigation awaiting & paging:** Mapped CDP virtual key codes (`Enter` `vk=13`, `text="\r"` + buttonless `<form>` `requestSubmit()` fallback), awaited triggered navigations (`Page.frameStartedLoading` / `Page.loadEventFired` + SSRF/`robots.txt` validation), added per-action `urlChanged` / `domChanged` / `no_effect` diagnostics, and added `maxChars` + `offset` + `remainingChars` paging metadata across `scrape` and `interact`.
  - **Distinct `dns_not_found` & error metadata:** Separated non-retryable DNS `NXDOMAIN` (`dns_not_found`) from transient `robots_unreachable` while scrubbing internal `:53` resolver socket addresses, separated HTTP `404` (`not_found`) from `410` (`gone`), surfaced structured `blocked: { reason: "ssrf", retryable: false }` on non-public/metadata targets, and standardized `artifact_not_found` (`404`) across `read_artifact`.
  - **Options-keyed scrape cache, `CrawlWorkflow` & extraction fidelity:** Keyed R2 scrape caches by output-affecting options (`onlyMainContent`, `renderMode`, `formats`, `includeTags`, `excludeTags`, `mobile`, `location`) with full response-shape fields (`wordCount`, `favicon`, `contentType`, `rendered`) and strict `H4` tenant/credential isolation, bound `CrawlWorkflow` (`CRAWL`) in production `wrangler.toml`, skipped Chromium `browser-auto` on scriptless static HTML while rescuing `<header><h1>`, stripped MediaWiki `.mw-editsection` chrome and RFC `¶` pilcrows, hardened heuristic JSON-schema extraction (`null` instead of hallucinated nav links), deduplicated `extract` `rawContent` / `search_collection` `snippet` with zero-match (`noRelevantMatch: true`) and real BM25 scores, and polished the `17` MCP tool schemas (`listChanged: true`, plain-English descriptions, `ToolSearch` batch-loading guidance, deduplicated `search` properties).

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
  - Added federated `query_mcp` (`list_connected`, `list_tools`, `call_tool`) and `POST /v1/mcp/query` over Streamable HTTP JSON-RPC and SSE (`text/event-stream`), expanding EdgeFetch's canonical MCP surface to `17` tools with zero prompt-schema bloat.
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
  - **Zero-TCP direct pipe CDP, initiator-proven headers & runtime bounds (`R6-M1`, `R6-M3`, `R6-M9`..`R6-M12`):** Enabled zero-TCP direct OS pipe CDP transport across Linux, macOS, and Windows (`0` listening Chromium ports), required top-level document initiator provenance before attaching caller headers in `Fetch.requestPaused`, added bounded $O(N)$ CSS selector memoization (`ChainMemo` + depth/visit caps) in `parseHtmlDoc`, added an LRU cache + bounded-repetition guard around linear `re2js` NFA compilation, capped `catalog` `variantHashes` inside the `32 MiB` global LRU with a `120s` wall-clock ceiling and `<= 2` gunzip semaphore, and tightened TypeScript-Go `robots.txt` + `Content-Signal` alignment.

### Added
- **Declarative YAML Site Adapters (`internal/extract/manifests/*.yaml`, `compiled.json`):**
  - Converted remaining TypeScript provider files into `#`-commented, `MIT`-licensed declarative `.yaml` manifests (`56` manifests across 7 categories, `0` `.ts` files under `providers/`) compiled into `internal/extract/manifests/compiled.json` (`//go:embed`) with reusable storefront normalization in `hub/src/extractors/commerce-engine.ts`.
- **OpenAPI `3.1.0` Specification (`GET /openapi.json`, `docs/openapi.json`):**
  - Added unauthenticated `GET /openapi.json` (`application/json` and `application/openapi+json` content negotiation, strict `Host`/`Origin` sanitization) across Cloudflare Worker, Node.js Portable Hub, Deno Deploy, and pure-Go `--mode=hub`, sharing canonical JSON Schema 2020-12 definitions directly with `MCP_TOOL_SCHEMAS` (`15` tools) and guarded by automated `/v1/*` route contract tests.
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
  - Added `npm run adapter:test [<id>] [<https://url>] [--record]` for `robots.txt`-checked live previews, fixture recording, and linear-time bulkhead fuzz testing, plus `.yaml`-by-default scaffolding in `npm run adapter:new`.

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
