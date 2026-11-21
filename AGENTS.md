# EdgeFetch Agent & Contributor Engineering Rules (`AGENTS.md`)

These rules govern coding agents and human contributors working in this repository:

1. **Every Outbound Request Has a Deadline & Drains/Cancels Unread Bodies:**
   - Every HTTP/WebSocket call (`fetch` in `hub/`, `http.NewRequestWithContext` in `internal/`) MUST bind an explicit timeout (`AbortSignal.timeout(...)` / `AbortSignal.any(...)` or `context.WithTimeout(...)`).
   - Whenever an HTTP response body is not read to completion (e.g., `3xx` redirects, header-only checks, early size-cap aborts), cancel or bounded-drain + close `resp.Body` immediately so sockets never leak or hang host queues.
2. **Strict Anti-Bypass & Politeness Invariants:**
   - Never weaken RFC 9309 `/robots.txt` evaluation, `Content-Signal: ai-input=no` enforcement, `HTTP 402` (`payment_required`) non-payment, dial-time SSRF `RejectNonPublicPeer` / `net.BlockList` checks, or immediate halt on WAF/CAPTCHA challenges.
   - Anti-bot browser fingerprinting, TLS/HTTP2 fingerprint spoofing, stealth plugins, and CAPTCHA solvers are permanently out of scope.
3. **Zero-Secret Adapter Sandboxing:**
   - Site and ATS adapters under `hub/src/extractors/providers/` are pure data transforms (`URL + raw text/HTML -> structured Markdown/records`). They MUST NEVER receive `env`, Hub secrets, storage bindings, or network `fetch` handles, and run inside fault-isolated, time-bounded bulkheads (or disposable Dynamic Worker isolates when `ADAPTER_ISOLATE_LOADER` is bound).
4. **Linear `O(N)` Untrusted Input Processing:**
   - Never run unbounded or nested-quantifier regular expressions (`[\s\S]*?` without `indexOf` guards, `[^>]*` with backtracking suffixes, or user-supplied regexes bypassing `compileSafeUserRegex`) over untrusted HTML, Markdown, XML, or headers. All untrusted HTML/Markdown scanning must use `hub/src/safe-input.ts` linear scanners within `MAX_HTML_SCAN_CHARS` (`2 MiB`).
5. **Pinned Bidirectional Conformance Expectations:**
   - Benchmark and security regression suites (`bench/run-bench.mjs`, `hub/test/security-audit.test.ts`) pin expected outcomes in both directions: unexpected failures AND unexpected silent behavior shifts (e.g., a closed posting turning `active` or a blocked fixture turning `ok`) fail CI until deliberately reviewed and rebaselined.
6. **Agents Never Deploy or Push Release Tags Unilaterally:**
   - Automated coding agents do not push `v*` release tags, overwrite production secrets, or deploy production Workers without explicit operator instruction. Keep durable architectural contracts in package `EGM.md` files and code comments rather than committing scratch handoff notes.
