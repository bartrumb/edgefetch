# Contributing to EdgeFetch

Thanks for checking out EdgeFetch! EdgeFetch combines an **open-source worker, SDKs, and adapters ([MIT](LICENSE)), fair-source hub ([FSL-1.1](hub/LICENSE), `MIT` after two years)**. Participation is governed by our [Code of Conduct](CODE_OF_CONDUCT.md).

---

## Contributor Model: Issues Welcome, Code PRs by Invitation (`VOUCHED.td`)

EdgeFetch is a maintainer-driven, AI-built system with strict privilege boundaries between declarative YAML site adapters and core engine/security code:

- **Welcome from everyone (no invitation needed):**
  - **Bug reports & reproducible regressions** (`edgefetch bug-report <url>` emits a token-scrubbed diagnostic bundle).
  - **Broken-adapter reports & new site adapter requests** (include sample public URLs and `https://<domain>/robots.txt` rules).
  - **WAF false-positive / false-negative HTML samples** for [`internal/classify/waf_test.go`](internal/classify/waf_test.go) and [`hub/src/waf.ts`](hub/src/waf.ts).
  - **Hardware / platform verification reports** (macOS, FreeBSD/OPNsense, OpenWrt, NAS appliances, Raspberry Pi).
- **Code pull requests are by invitation ([`.github/VOUCHED.td`](.github/VOUCHED.td)):**
  - Pull requests from unvouched GitHub accounts are blocked by `.github/workflows/vouch.yml` (reading `.github/VOUCHED.td` from `BASE_SHA`) before privileged CI workflows run, ensuring untrusted inputs never steer privileged runners or release gates.
  - If you would like to contribute an adapter or fix directly, open an issue first with the proposed target/approach so the maintainer can coordinate and vouch your GitHub handle.
- **Security vulnerabilities:** Report privately via **[SECURITY.md](SECURITY.md)** (never in public issues). Past security and parser-differential bugs caught across our 8-round audit loop are documented in **[docs/SECURITY-LOG.md](docs/SECURITY-LOG.md)**.

---

## Non-Negotiable Project Invariants

Every change in EdgeFetch must preserve these ethical, security, and supply-chain invariants:

1. **Politeness & Ethics First:**
   - **Never weaken `robots.txt` enforcement** (`internal/politeness/robots.go`, `hub/src/overflow.ts`), `Crawl-delay` / `Retry-After` handling, or dial-time SSRF peer checks (`internal/politeness/ssrf.go`).
   - **Verify `robots.txt` for every site adapter:** Before adding or modifying a `twin` endpoint (`internal/extract/manifests/*.yaml`), check `https://<domain>/robots.txt` and ensure `User-agent: *` permits the path. When an `/api` or `/raw` path is disallowed, use `robots.txt`-allowed paths or `htmlRoutes` on the public HTML page instead.
   - **No anti-bot, TLS/browser fingerprinting, or CAPTCHA bypasses:** Anti-bot evasion, TLS/JA3/JA4/HTTP2 fingerprint spoofing, stealth browser patches, Turnstile/reCAPTCHA/hCaptcha solvers, and residential proxy rotation pools are permanently out of scope. EdgeFetch classifies challenges (`outcome: "challenge"`) and stops immediately on the first attempt.
   - **Zero default background phone-home:** `edgefetch scrape` and `edgefetch mcp` must make **zero** background telemetry or update-check calls by default (`EDGEFETCH_DEV_TELEMETRY` and `EDGEFETCH_CHECK_UPDATES` are strictly opt-in, and `DO_NOT_TRACK=1` hard-disables both).
   - **Explicit deadlines on every outbound request:** Every `fetch` / `http.Client.Do` call in Hub or Go code must attach a bounded `AbortSignal` or `context.WithTimeout` deadline and drain or cancel unread response bodies.
2. **Two-Ring Change Isolation & Adapter Validation Gate:**
   - **Ring 1 (`internal/extract/manifests/*.yaml`):** All `56` built-in site adapters are pure declarative YAML compiled via [`hub/scripts/compile-manifests.mjs`](hub/scripts/compile-manifests.mjs) into `internal/extract/manifests/compiled.json`, running inside a zero-secret, zero-network Go WASM / native bulkhead (`npm run adapter:test`).
   - **Ring 0 (`cmd/`, `internal/`, `hub/src/`, `.github/`, `keys/`):** Core engine, auth, vault, sanitizer, SSRF, and workflow files require direct maintainer review and human-gated `release` environment approval before Ed25519 binary signing.
3. **Minimal, Auditable Supply Chain & Go-First Architecture:**
   - **Go-First Single Implementation (`cmd/`, `internal/`):** All domain, extraction, sanitization, jobs/ATS, storefront catalog, BYO-LLM agent, MCP federation, and self-hosted Hub (`edgefetch --mode=hub`) logic lives once in Go (`go.mod`: strictly **`1` external dependency**, `github.com/coder/websocket`, `0` transitive dependencies, `CGO_ENABLED=0`). Do not duplicate Go domain logic in TypeScript; Cloudflare Workers invoke Go via `cmd/edgefetch-wasm` (`edgefetch-core.wasm`).
   - **Cloudflare Worker Edge Router (`hub/package.json`):** Runtime dependencies are restricted to **`2` pinned packages** (`jose`, `oauth4webapi`). Do not add runtime npm packages without maintainer approval.
4. **Keyless Built-In Adapters (`MIT`):**
   - Built-in site and ATS adapters under [`internal/extract/manifests/`](internal/extract/manifests/) and [`hub/src/extractors/`](hub/src/extractors/) are open-source (`MIT`) and work with public JSON/XML endpoints, feeds, JSON-LD, or HTML selectors — never requiring paid B2B API keys.
5. **Licensing (`Inbound = MIT + DCO`):**
   - Sign off every commit with `git commit -s` (`Signed-off-by: Your Name <you@example.com>`) certifying the [Developer Certificate of Origin](https://developercertificate.org/).
   - By submitting a pull request (whether to the `MIT` worker, SDKs, and adapters or to the fair-source `FSL-1.1` Hub), you license your contribution inbound under the [MIT License](LICENSE) alongside your DCO sign-off so it may be distributed in both the `MIT` components and the `FSL-1.1-MIT` Hub (`MIT` after two years). No separate CLA is required.
6. **Deterministic Fixtures & Tests:**
   - Every bug fix or declarative YAML adapter (`internal/extract/manifests/<slug>.yaml`) must include a deterministic fixture in `hub/test/fixtures/adapters/<slug>.json` or unit tests. See **[docs/ADAPTERS.md](docs/ADAPTERS.md)**.

---

## Local Verification Commands

### Go Worker, CLI & Go Hub (`Go 1.26+`)

```bash
gofmt -s -w .
go vet ./...
go test -race ./...
```

### Cloudflare Worker Hub & Go WASM (`Node.js 22.5+`)

```bash
cd hub
npm ci
npm run adapter:check
npm run type-check
npm test
npm run deploy:dry
```

### Reproducible Extraction & Go Hot-Path Benchmarks

```bash
node bench/run-bench.mjs
go test -bench=. -benchmem ./...
```
