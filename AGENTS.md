# EdgeFetch Agent & Contributor Engineering Rules (`AGENTS.md`)

These rules govern **all** coding agents (Antigravity, Claude, Codex, Cursor) and human contributors working in this repository:

1. **Go-First Single-Implementation Architecture (NEVER Duplicate Logic in TypeScript):**
   - **EdgeFetch is a Go project (`cmd/`, `internal/`).** Every parser, HTML-to-Markdown extractor, CommonMark fence/prose sanitizer, `read_artifact` slice pager, declarative YAML/site adapter, ATS `jobs` engine, `catalog` engine, `/v1/agent` BYO-LLM loop, MCP federation/vault logic, `robots.txt` / `Content-Signal` evaluator, PSL lookup, and self-hosted Hub feature MUST be implemented **once, in Go** (`internal/*`, `go.mod` = strictly `github.com/coder/websocket` with `CGO_ENABLED=0`).
   - **Thin Cloudflare Edge Boundary (`hub/`):** TypeScript in `hub/` exists **solely** for Cloudflare-specific platform glue (`AgentHubDO` hibernating WebSockets, R2 `ARTIFACTS`, D1 `META`/`SEARCH`, Cloudflare Workflows, `scheduled()` cron, and thin HTTP/OAuth routing).
   - **Use Go WASM (`cmd/edgefetch-wasm`) on the Edge Instead of Writing TypeScript:** Whenever the Cloudflare Worker needs CPU-bound parsing, sanitization, Markdown slicing, adapter formatting, or offline fallback without a connected Go worker node, compile and call the Go `wasip1/wasm` module (`cmd/edgefetch-wasm`) — **never** port or re-implement Go logic in TypeScript, and **never** add Node/Deno portable Hub shims (self-hosted and Docker deployments run the native Go binary `edgefetch --mode=hub`).
2. **Every Outbound Request Has a Deadline & Drains/Cancels Unread Bodies:**
   - Every HTTP/WebSocket call (`http.NewRequestWithContext` in `internal/`, `fetch` in thin `hub/` glue) MUST bind an explicit timeout (`context.WithTimeout(...)` or `AbortSignal.timeout(...)`).
   - Whenever an HTTP response body is not read to completion (e.g., `3xx` redirects, header-only checks, early size-cap aborts), cancel or bounded-drain + close `resp.Body` immediately so sockets never leak or hang host queues.
3. **Strict Anti-Bypass & Politeness Invariants:**
   - Never weaken RFC 9309 `/robots.txt` evaluation, `Content-Signal: ai-input=no` enforcement, `HTTP 402` (`payment_required`) non-payment, dial-time SSRF `RejectNonPublicPeer` / `net.BlockList` checks, or immediate halt on WAF/CAPTCHA challenges.
   - Anti-bot browser fingerprinting, TLS/HTTP2 fingerprint spoofing, stealth plugins, and CAPTCHA solvers are permanently out of scope.
4. **Zero-Secret Adapter Sandboxing:**
   - Declarative YAML manifests (`internal/extract/manifests/*.yaml`) and Go site/ATS extractors (`internal/extract`, `internal/jobs`) are pure data transforms (`URL + raw text/HTML -> structured Markdown/records`). They MUST NEVER receive Hub secrets, storage credentials, or unrestricted network handles.
5. **Linear `O(N)` Untrusted Input Processing:**
   - Never run unbounded or nested-quantifier regular expressions or quadratic scans over untrusted HTML, Markdown, XML, or headers. Keep untrusted input scanning strictly linear `O(N)` in Go (`internal/extract`, `internal/politeness`) within bounded byte caps.
   - Keep wall-clock microbenchmarks in dedicated `Benchmark*` / `bench/` suites rather than flaky millisecond assertions inside `-race` / `-fuzz` functional unit tests.
6. **Pinned Bidirectional Conformance & Process Discipline:**
   - Conformance and security regression suites pin expected outcomes in both directions: unexpected failures AND unexpected silent behavior shifts fail CI until deliberately reviewed.
   - Never loosen test assertions/thresholds or add skips to get green; never re-run a failed CI workflow without fixing the root cause; never push directly to `main`, modify GitHub branch/environment rules, or push `v*` release tags / deploy production Workers without explicit operator instruction. Keep durable architectural contracts in package `EGM.md` files and code comments rather than committing scratch handoff notes.
