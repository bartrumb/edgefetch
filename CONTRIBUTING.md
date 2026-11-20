# Contributing to EdgeFetch

Thanks for checking out EdgeFetch! This is a personal MIT-licensed open-source project; issues and pull requests are **triaged weekly**.

---

## Ground Rules

Before opening a PR, please keep EdgeFetch's core invariants intact:

1. **Politeness & Ethics First (Non-Negotiable):**
   - Never weaken `robots.txt` enforcement, `Retry-After` handling, or dial-time SSRF checks (`internal/politeness/ssrf.go`).
   - Never add CAPTCHA solvers, stealth fingerprint spoofers, or anti-bot bypasses. EdgeFetch classifies challenges accurately and halts on the first attempt.
2. **Minimal Supply Chain:**
   - The Go module (`go.mod`) intentionally has **one external dependency** (`github.com/coder/websocket`, zero transitive dependencies). CI enforces this check on every PR — use the Go standard library (`net/http`, `crypto/*`, `encoding/*`, etc.).
   - The Cloudflare/Portable Hub (`hub/`) uses **zero npm runtime dependencies** (`devDependencies` only for TypeScript, esbuild, Wrangler, and Miniflare tests).
3. **Tests Required:**
   - Bug fixes and new site extractors (`hub/src/extractors/providers/<category>/<slug>.ts` or `hub/src/jobs.ts`) should include a JSON fixture in `hub/test/fixtures/adapters/<slug>.json` (auto-run by `npm test`) or a unit test. See **[docs/ADAPTERS.md](docs/ADAPTERS.md)** for the 3-step `npm run adapter:new <category>/<slug>` generator.

---

## Local Verification Commands

### Go Worker, CLI & Go Hub (`Go 1.26+`)

```bash
gofmt -s -w .
go vet ./...
go test -race ./...
```

### TypeScript Hub & Portable Runtime (`Node.js 22.5+`)

```bash
cd hub
npm ci
npm run type-check
npm run build:portable
npm test
```

### Extraction Fidelity Benchmark

```bash
node bench/run-bench.mjs
```

---

## High-Impact Contributions Welcome

- **Site, Open-Data & ATS Adapters:** Scaffold a single-file keyless adapter with `cd hub && npm run adapter:new <category>/<slug>` under [`hub/src/extractors/providers/`](hub/src/extractors/providers/) — full walkthrough in **[docs/ADAPTERS.md](docs/ADAPTERS.md)**.
- **WAF False-Positive Fixtures:** Sharing HTML fixtures where a normal page was misclassified (or a new WAF interstitial slipped through) in [`internal/classify/waf_test.go`](internal/classify/waf_test.go) and [`hub/src/waf.ts`](hub/src/waf.ts).
- **Platform Reports:** Verifying binaries or deployment manifests on hardware in the README platform table (FreeBSD/OPNsense, OpenWrt routers, NAS appliances, macOS, Raspberry Pi) so we can promote rows from *Build Verified* to *Live-Tested*.
- **Security Issues:** Please report vulnerabilities privately via [SECURITY.md](SECURITY.md) rather than opening a public issue.
