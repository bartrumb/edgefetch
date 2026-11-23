# Engineering Security & Reliability Bug Log (Rounds 1–8)

> [!IMPORTANT]
> **This is an engineering log of real security and reliability bugs found and fixed across 8 adversarial review rounds (using independent LLM reviewers + executed local PoCs), NOT a third-party security certification.**

EdgeFetch connects AI agents to untrusted web servers, HTML/Markdown parsers, PDF streams, and optional headless Chromium processes. Because the codebase was built with coding agents, treating "tests pass" as sufficient would be irresponsible. Across 8 structured adversarial review rounds (`v2.5.1` through `v2.7.2`), independent reviewer passes wrote local proof-of-concept payloads against our Go and TypeScript components until they broke, and every confirmed bug was turned into a permanent regression test in [`hub/test/security-audit.test.ts`](../hub/test/security-audit.test.ts), [`internal/browser/security_audit_test.go`](../internal/browser/security_audit_test.go), or [`internal/hub/hub_security_test.go`](../internal/hub/hub_security_test.go).

For the active threat model, deployment hardening checklist, and private vulnerability reporting process, see **[SECURITY.md](../SECURITY.md)**.

---

## Summary of Major Bug Classes Caught & Closed

| Area | Key Files | Failure Mode Caught by Local PoCs | Fix & Regression Guard |
|---|---|---|---|
| **1. Markdown Sanitizer vs. CommonMark/GFM Differentials** | [`hub/src/scrape.ts`](../hub/src/scrape.ts), [`internal/extract/sanitize.go`](../internal/extract/sanitize.go) | Line-by-line fence & backtick state disagreed with `marked` and `micromark+GFM`, letting raw HTML or `javascript:` links escape outside code blocks | Differential harness against `marked` + `micromark+GFM` across **278 CommonMark/GFM vectors** in both TS and Go |
| **2. Multi-User Auth, Session Revocation & Shared Cache Isolation** | [`hub/src/github-auth.ts`](../hub/src/github-auth.ts), [`hub/src/scrape.ts`](../hub/src/scrape.ts), [`0003_round7_multiuser_hardening.sql`](../hub/migrations/meta/0003_round7_multiuser_hardening.sql) | Stateless JWT survival after user disable, GitHub username-rename owner takeover, and credentialed/tenant scrapes hitting shared R2 cache keys | Live `session_epoch` + `disabled` check, immutable numeric `github_id` pinning, strict `visibility: "private"` across primary + options-keyed caches, GitHub OAuth off by default |
| **3. Algorithmic Complexity / ReDoS & Quadratic Scanners** | [`hub/src/safe-input.ts`](../hub/src/safe-input.ts), [`hub/src/scrape-advanced.ts`](../hub/src/scrape-advanced.ts), [`hub/src/extractors/html-doc.ts`](../hub/src/extractors/html-doc.ts) | Backtracking regex groups and $O(N^2)$ `<x`, `](`, `[`, and CSS-combinator scans stalling isolates on `2 MiB` adversarial inputs | `re2js` Thompson NFAs, monotonic dead-offset caching, bounded DOM `ChainMemo`, `< 25 ms` on `2 MiB` with zero input-class skip bypasses |
| **4. Dial-Time SSRF & Headless Browser Subresource Isolation** | [`internal/politeness`](../internal/politeness), [`internal/browser`](../internal/browser), [`deploy/seccomp/chromium-sandbox.json`](../deploy/seccomp/chromium-sandbox.json) | DNS-rebinding TOCTOU, browser WebRTC/DNS leaks, cross-origin custom-header inheritance on `Fetch.requestPaused`, Windows handle inheritance, Linux `--no-sandbox` fallback | `net.Dialer.Control` `RejectNonPublicPeer`, loopback `CONNECT` `SSRFProxy` (`MAP * ~NOTFOUND`), `!isDocReq` + initiator header guard, Windows `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` + Job Object, fail-closed Linux seccomp sandbox |
| **5. Portable/Deno Socket Exhaustion & Zero-Hostname Telemetry** | [`hub/portable/`](../hub/portable), [`telemetry/`](../telemetry), [`hub/src/dev-telemetry.ts`](../hub/src/dev-telemetry.ts), [`internal/otel/dev_telemetry.go`](../internal/otel/dev_telemetry.go) | Pre-header TCP exhaustion starving `/health`, double-DNS-resolution TOCTOU in `safe-fetch`, unauthenticated OTLP spam, SemVer `+buildmetadata` hostname leaks | Raw TCP per-IP caps + reserved loopback `/health` headroom, single-resolution IP-pinned `safe-fetch`, auth-gated OTLP export, `+buildmetadata` scrubbing, opt-in-only telemetry |

---

## 1. Markdown Sanitizer vs. CommonMark/GFM Renderer Differentials

**Files:** [`hub/src/scrape.ts`](../hub/src/scrape.ts), [`internal/extract/sanitize.go`](../internal/extract/sanitize.go)

Downstream agent UIs frequently render scraped Markdown through `marked` or `micromark` + `micromark-extension-gfm` without an additional DOMPurify pass, while preserving raw `<T>` generics inside fenced and inline code spans is essential for technical documentation. Any disagreement between EdgeFetch's sanitizer and a CommonMark/GFM parser creates a classic parser-differential bug: EdgeFetch thinks `<img src=x onerror=...>` is safely inside a code span or fence, while the downstream renderer parses it as live HTML.

### What PoCs Broke (Including a `v2.6.3` → `v2.7.0` Regression)
- **Indented pseudo-fences (`> 3` spaces):** In CommonMark, a line starting with 4 spaces (`    ``` `) is an indented code block, *not* a fenced code block. An early line-by-line splitter treated `    ``` ` as opening a fence, leaving subsequent unindented prose unescaped until the next ` ``` `.
- **Container-prefixed list and blockquote fences:** A fenced block opened inside a blockquote (`> ``` `) or list item (`- ``` `) closes *implicitly* in CommonMark as soon as a subsequent line drops the `>` marker or dedents past the list content column — even without a closing ` ``` ` line. Naive fence trackers stayed in "code mode" for the rest of the document.
- **Bare GFM autolinks glued to inline backticks:** In `micromark-extension-gfm`, `https://example.com`<img src=x onerror=1>`` consumes the first backtick as part of the bare URL path, shifting backtick open/close parity for the remainder of the paragraph!
- **Setext underlines, backslash-escaped backticks, and entity-obfuscated URIs:** Backslash-escaped backticks (`` \` ``) before raw HTML, NUL-byte collisions with internal stash sentinels, multi-line `[label\nlabel2](javascript:...)` links, and HTML entity / whitespace obfuscation (`javascript&colon;`, numeric entities, or undecoded `&...;` before `/`, `?`, `#`) bypassed naive regex scheme checks.
- **How `v2.6.3` regressed in `v2.7.0` before closing in `v2.7.1`:** In `v2.6.3`, we hardened `splitMarkdownByCodeFences` against `> 3`-space indents and inserted delimiter spacing between bare autolinks and backticks. When `v2.7.0` added federated MCP tool outputs and Unicode whitespace trimming around frontmatter, trimming Unicode non-breaking spaces *after* fence normalization re-aligned a `> 3`-space indented fence into a `0..3`-space fence, and mixed `\r` / `\r\n` endings + nested blockquote-list dedents still disagreed with `micromark+GFM` on edge cases.

### How It Was Fixed
In `v2.7.2` (`SCRAPE_PIPELINE_VERSION = 31`, imported from a single canonical constant in `hub/src/storage.ts` with stale `< 31` cache entries invalidated), both [`hub/src/scrape.ts`](../hub/src/scrape.ts) and [`internal/extract/sanitize.go`](../internal/extract/sanitize.go) enforce a simple fail-closed invariant instead of paragraph-boundary guessing: outside recognized CommonMark fenced code blocks, **every** residual `<` is escaped to `&lt;` and **every** disallowed link destination, reference definition, GFM task-list `<input>`, and bare protocol-relative `//host.tld` linkify target is neutralized — **inline backtick code spans included** — across full documents and fence-aware paged slices (`sanitizeMarkdownPageSlice`).

---

## 2. Multi-User Auth, Session Revocation & Shared Cache Isolation

**Files:** [`hub/src/github-auth.ts`](../hub/src/github-auth.ts), [`hub/src/scrape.ts`](../hub/src/scrape.ts), [`hub/migrations/meta/0003_round7_multiuser_hardening.sql`](../hub/migrations/meta/0003_round7_multiuser_hardening.sql)

`v2.7.0` introduced optional multi-user Hub support (GitHub OAuth 2.1 + PKCE via `oauth4webapi`, `HS256` session cookies via `jose`, and per-user `AES-256-GCM` MCP connector vaults). Adversarial review immediately targeted cross-tenant state and account lifecycle edges:

### What PoCs Broke
- **JWT session survival after account disable:** Because browser sessions used `8h` signed JWTs (`ef_gh_session`), disabling a user or removing them from `GITHUB_ALLOWED_USERS` did not immediately invalidate already-minted session cookies that hadn't individually been logged out by `jti`.
- **GitHub username-rename takeover:** Bootstrapping or matching `owner` privileges solely against a mutable GitHub login string (`GITHUB_OWNER_LOGIN`) meant that if an operator ever renamed their GitHub account and a third party registered the old username, the new holder of that handle could match the string allowlist.
- **Options-keyed & primary R2 cache cross-tenant bleed:** When options-keyed R2 scrape caching (`onlyMainContent`, `renderMode`, `formats`, `includeTags`) was added alongside the primary R2 cache, any scrape using custom `headers` / `Cookie`, `preferMcp` / connected MCP routing, or a non-owner tenant risked reading or populating a shared R2 cache entry unless *both* cache tiers enforced private scoping identically.

### How It Was Fixed
1. **Live `session_epoch`, `disabled` & `@org` membership re-verification (`0002_multiuser.sql`, `0003_round7_multiuser_hardening.sql`):** Every authenticated request verifies the live user record (`disabled === 0` and `jwt.epoch === user.session_epoch`) regardless of whether `@org` entries exist in `GITHUB_ALLOWED_USERS`, records `admitted_via` / `admitted_org`, and re-verifies live GitHub `/user/orgs` membership on token refresh and stale TTL.
2. **Explicit immutable numeric `GITHUB_OWNER_ID`:** Owner identity requires explicit `GITHUB_OWNER_ID` configuration (never auto-deriving pins from existing rows or bare digits in `GITHUB_ALLOWED_USERS`), blocks secondary owners from mutating owner accounts, and enforces `__Host-` cookie attributes on HTTPS origins.
3. **End-to-end `visibility: "private"` cache & row isolation:** Requests carrying custom headers, cookies, auth, `redactPii`, connected MCP routing, private PDF OCR, or non-owner user context (including `crawl`) are forced to `visibility: "private"` (`Cache-Control: private, no-store`, isolated `cache:private-r2` keys, zero shared R2/D1 reads or writes), with per-user concurrency caps (`16` `scrape`, `4` `interact`, `4` `agent`) and `user_id` isolation across `crawl`, `batch/scrape`, `catalog`, and `/v1/hosts`.
4. **Disabled by default:** Multi-user GitHub OAuth sign-in remains completely inactive unless the operator explicitly configures `GITHUB_CLIENT_ID` and `GITHUB_CLIENT_SECRET` (and defaults to `SIGNUP_MODE='invite_only'` when enabled).

---

## 3. Algorithmic Complexity / ReDoS & Linear HTML/Prompt-Injection Scanners

**Files:** [`hub/src/safe-input.ts`](../hub/src/safe-input.ts), [`hub/src/scrape-advanced.ts`](../hub/src/scrape-advanced.ts), [`hub/src/extractors/html-doc.ts`](../hub/src/extractors/html-doc.ts)

Because a single `2 MiB` web page can contain tens of thousands of malformed `<` characters, unclosed `[` brackets, or nested DOM wrappers, any backtracking regular expression or nested `indexOf` retry loop turns into a single-request CPU denial of service inside a Worker isolate.

### What PoCs Broke
- **Subtle quantifier ambiguity in custom regex validators:** Before adopting `re2js`, our hand-written `compileSafeUserRegex` AST checker rejected nested star-height (`(a+)+`), yet adversarial review crafted flat patterns with non-terminal optional groups (`a*(b)?aa*(b)?aa*$`) and optional trailing groups (`(a*aaa*)?$`) that still triggered exponential V8 backtracking.
- **Quadratic `<x` pseudo-tag and Markdown link scans:** In `tryParseTagAt` (`hub/src/safe-input.ts`), an adversarial string of `16,000` `<x` repetitions with no closing `>` re-scanned to the end of the buffer on each `<`. Similar quadratic behavior was found on `64 KiB+` malformed tag attributes, V8 `ConsString` rope concatenation in `sanitizeAndResolveMarkdownProseLinksLinear`, repeated `](` / `[` scans in Markdown link resolvers, and deeply nested descendant CSS selectors in `parseHtmlDoc`.
- **Why "skip scanning if input looks pathological" is a security bug:** Skipping sanitization or prompt-injection checks when an input contains many `<` or `[` characters would hand attackers a trivial padding bypass: prepend `10,000` dummy brackets, then append the payload.

### How It Was Fixed
- **Google RE2 Thompson NFAs (`re2js`):** User crawl filters and declarative YAML `regexExtract` rules compile and execute via `re2js` linear-time automata (with bounded `{m,n}` repetition caps and an LRU compiled-pattern cache).
- **Monotonic dead-offset & `ChainMemo` bounds:** `ScannerDeadState` in `hub/src/safe-input.ts` caches `nextNameBoundary`, `nextGtPos`, and comment-close positions so failed `<x` or `<!--` probes advance monotonically in $O(N)$ time; `parseHtmlDoc` enforces `MAX_DOM_DEPTH = 128`, `MAX_DOM_NODES = 40_000`, `MAX_DOC_TOTAL_VISITS = 90_000`, and selector `ChainMemo` memoization.
- **Full $O(N)$ coverage without skip bypasses:** Both the HTML/Markdown sanitizer and the prompt-injection scanner (`58/58` Markdown and `20/20` HTML evasion variants — stripping Khmer, Braille blank, musical format, variation selector, Unicode Tag `U+E0000`–`U+E007F`, and NEL/bidi smuggling runes) process `2 MiB` adversarial inputs in `< 25 ms`.

---

## 4. Dial-Time SSRF & Browser Subresource Isolation

**Files:** [`internal/politeness/ssrf.go`](../internal/politeness), [`internal/browser/proxy.go`](../internal/browser), [`internal/browser/renderer.go`](../internal/browser), [`deploy/seccomp/chromium-sandbox.json`](../deploy/seccomp/chromium-sandbox.json)

Validating a URL string *before* calling `http.Get(u)` or navigating Chromium does not stop SSRF: DNS rebinding (`TTL = 0` flipping from a public IP to `127.0.0.1` or `169.254.169.254`), HTTP `30x` redirects, browser `<img>`/`fetch()` subresources, WebRTC STUN UDP packets, and inherited OS file descriptors all bypass naive pre-flight checks.

### What PoCs Broke & What Was Hardened
1. **Dial-time socket verification (`RejectNonPublicPeer`):** Runs inside Go's `net.Dialer.Control` on the resolved `netip.AddrPort` socket immediately before `connect()`, blocking loopback, RFC 1918 LANs (including Home Assistant's `172.30.32.0/23` bridge), CGNAT/Tailscale `100.64.0.0/10`, link-local metadata `169.254.0.0/16`, and non-`2000::/3` or NAT64/6to4/Teredo IPv6 transition ranges. Automatic redirects are disabled so every hop re-verifies URL rules and `robots.txt`.
2. **Loopback `CONNECT` `SSRFProxy` + WebRTC/mDNS lockdown:** Headless Chromium communicates with Go over inherited OS pipes (`--remote-debugging-pipe`, zero listening CDP TCP ports) and routes network traffic through an in-process loopback `CONNECT` proxy (`--host-resolver-rules="MAP * ~NOTFOUND , EXCLUDE 127.0.0.1"`, `--proxy-bypass-list=<-loopback>`, `--webrtc-ip-handling-policy=disable_non_proxied_udp`, `--enforce-webrtc-ip-permission-check`, `--disable-quic`, and Chromium Cast/mDNS `:8009` disabled).
3. **Origin-scoped & initiator-proven caller headers in CDP:** Early versions cleared `Network.setExtraHTTPHeaders` after navigation, which still raced concurrent subresources. Moving to CDP `Fetch.requestPaused` exposed two subtler bugs caught in Rounds 6–7: matching by hostname alone ignored port/scheme, and bound-frame fallbacks could attach caller headers to a cross-origin iframe top-level navigation. Caller headers now require exact `(scheme, canonicalHost, effectivePort)` match, verified top-level document initiator provenance, and `!isDocReq` non-Document subresource scoping (with `Page.frameDetached` cleanup, header stripping on `302` redirects, and browser-instance recycling after custom-header jobs).
4. **Windows handle inheritance & Job Object lifecycle:** On Windows, spawning Chromium without an explicit handle allowlist let child browser processes inherit open Go listener/WebSocket descriptors or hold `.old` binary handles across crashes. Chromium now launches `CREATE_SUSPENDED` with `STARTUPINFOEXW` `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` (inheriting only its exact pipe handles) and attaches to a kill-on-close Windows Job Object before `ResumeThread`.
5. **Fail-closed Linux Chromium sandboxing:** Many Dockerized scrapers hardcode `--no-sandbox` in their container entrypoint. EdgeFetch probes Chromium's namespace sandbox at startup and **fails closed** (disabling browser rendering rather than silently dropping `--no-sandbox`) unless run with [`deploy/seccomp/chromium-sandbox.json`](../deploy/seccomp/chromium-sandbox.json) or explicitly overridden at runtime by the operator via `EDGEFETCH_ALLOW_NO_SANDBOX=1` (and `EDGEFETCH_REQUIRE_BROWSER_SANDBOX=1` forbids `--no-sandbox` unconditionally).

---

## 5. Portable/Deno Socket Exhaustion & Zero-Hostname Telemetry

**Files:** [`hub/portable/`](../hub/portable), [`telemetry/`](../telemetry), [`hub/src/dev-telemetry.ts`](../hub/src/dev-telemetry.ts), [`internal/otel/dev_telemetry.go`](../internal/otel/dev_telemetry.go)

Self-hosted operators running `hub/portable/` on a small VPS or Deno Deploy face direct internet scanner traffic without Cloudflare's outer proxy layer, while CLI/MCP users rightfully expect zero unrequested background network traffic.

### What PoCs Broke & How It Was Fixed
- **Pre-header TCP exhaustion & 1-byte eviction regressions (`v2.7.0` → `v2.7.2`):** Opening idle raw TCP sockets (never sending a complete HTTP header line) bypassed HTTP-layer rate limits and could exhaust file descriptors until `/health` probes failed. In `v2.7.1`, an initial silent-socket eviction pass (`bytesRead === 0`) backfired when a Round 8 PoC sent `1` byte (`'G'`) across 33 addresses (`132` sockets), tricking the `bytesRead === 0` fallback into evicting brand-new `< 1 ms` legitimate TCP handshakes while `MAX_PREHEADER_SOCKETS_PER_IP = 4` dropped 8-connection bursts and shared-NAT peers. `portable-server.ts` now evicts aged (`>= 250 ms`) stalled pre-header sockets first (preferring the fullest bucket among aged entries), falls back to the heaviest *other* multi-socket IP bucket (`bCount >= 2`) during active sub-250ms floods so bursts never self-cannibalize, raises `MAX_PREHEADER_SOCKETS_PER_IP` to `32` with aged (`>= 50 ms`) same-IP squatter eviction for shared NATs, and reserves dedicated concurrency headroom for loopback `/health` and public discovery routes (`/openapi.json`, `/.well-known/*`).
- **Single-DNS-resolution IP pinning in `safe-fetch`:** Early portable/Deno `safe-fetch` validated DNS via `dns.lookup` and then passed the hostname to `fetch()`, leaving a second DNS resolution window. Outbound webhook, SPA-fallback, and custom-LLM fetches now pin to the single verified public IP from resolution through `socket.remoteAddress` verification while preserving TLS SNI and locking the `Host` header.
- **In-process authenticated OTLP gate, SemVer `+buildmetadata` scrubbing & anti-pinning collector eviction:** Unauthenticated `401`/`404` probes previously emitted OTLP error spans when `OTEL_EXPORTER_OTLP_ENDPOINT` was configured; Round 8 also caught that passing pre-auth state via an internal `x-ef-verified-auth: 1` request header allowed unauthenticated callers on Cloudflare Workers (where no outer proxy stripped the header) to forge authenticated status for telemetry export, and that `count >= 2` fake rows in `telemetry/` could cause `count = 1` slot thrashing. Pre-verified auth state is now passed strictly via an in-process `WeakSet<Request>` (never via HTTP headers), SemVer `+buildmetadata` is stripped prior to export, and the `telemetry/` collector enforces per-IP/subnet hourly new-fingerprint budgets plus a 5-minute freshness protection tier on D1 eviction.
