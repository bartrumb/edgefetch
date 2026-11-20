# Contributing to EdgeFetch

Thanks for checking out EdgeFetch! This is an MIT-licensed open-source project; issues and pull requests are **triaged weekly** and governed by our [Code of Conduct](CODE_OF_CONDUCT.md).

---

## Non-Negotiable Project Invariants (Contributor Rules)

Every pull request must preserve EdgeFetch's ethical, security, and supply-chain invariants:

1. **Politeness & Ethics First:**
   - **Never weaken `robots.txt` enforcement** (`internal/politeness/robots.go`, `hub/src/robots.ts`), `Crawl-delay` / `Retry-After` handling, or dial-time SSRF peer checks (`internal/politeness/ssrf.go`).
   - **Verify `robots.txt` for every new adapter:** Before adding or modifying a `resolveTwin` endpoint (`hub/src/extractors/providers/`), check `https://<domain>/robots.txt` and ensure `User-agent: *` permits the twin path. If an API/raw path is disallowed (e.g., `api.smartrecruiters.com` or `gitlab.com/*/raw`), use `robots.txt`-allowed paths or `extractHtml` on the public HTML page instead.
   - **Zero anti-bot or CAPTCHA bypasses:** Never add CAPTCHA solvers, Turnstile/reCAPTCHA clickers, stealth fingerprint spoofers, or residential proxy rotation marketplaces. EdgeFetch classifies challenges (`outcome: "challenge"`) and halts immediately on the first attempt.
2. **Minimal, Auditable Supply Chain:**
   - **Go (`go.mod`):** Strictly **one external dependency** (`github.com/coder/websocket`, zero transitive dependencies) with `CGO_ENABLED=0`. CI fails automatically if `go mod graph` gains any unexpected module.
   - **TypeScript Hub (`hub/package.json`):** Strictly **zero npm runtime `dependencies`** (`devDependencies` only for TypeScript, esbuild, Wrangler, and Miniflare tests).
3. **Keyless Built-In Adapters Only:**
   - Built-in site and ATS adapters under [`hub/src/extractors/providers/`](hub/src/extractors/providers/) must work out of the box with **zero paid B2B API keys** (public JSON/XML twins, JSON-LD, SSR metadata, or HTML cleanup). Paid fallbacks belong strictly to optional operator-configured `FIRECRAWL_API_KEY` / BYO-LLM settings.
4. **Release Signing & Secret Isolation:**
   - Official release binaries (`checksums.txt.sig`) and OCI images are cryptographically signed with an owner-only Ed25519 key (`RELEASE_SIGNING_PRIVATE_KEY` in GitHub Actions Sealed Secrets, verified against [`keys/release-signing-pub.pem`](keys/release-signing-pub.pem)) plus GitHub SLSA Build Provenance attestations.
   - Fork pull requests **never** receive access to repository secrets, and `main` + `v*` release tags are enforced by GitHub Repository Rulesets and [`.github/CODEOWNERS`](.github/CODEOWNERS). Never modify `.github/workflows/release.yml` or `keys/` in contributor PRs unless explicitly coordinated with the maintainer.
5. **Licensing & AI-Assisted Contributions:**
   - Inbound = Outbound (**MIT License**): By submitting a pull request, you confirm that you have the right to license your contribution under [LICENSE](LICENSE) and that no proprietary or copyleft-incompatible code is included.
   - AI-assisted PRs are welcome **only** if you have personally reviewed every line, verified live `robots.txt` behavior, and run the local test suite below before opening the PR.
6. **Tests & Deterministic Fixtures Required:**
   - Every bug fix or new adapter (`hub/src/extractors/providers/<category>/<slug>.ts`) must include a deterministic JSON fixture in `hub/test/fixtures/adapters/<slug>.json` (auto-discovered by `npm test`) or unit tests. See **[docs/ADAPTERS.md](docs/ADAPTERS.md)** for the 3-step `npm run adapter:new <category>/<slug>` scaffold.

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
npm run build:portable
npm run type-check
npm test
npm run deploy:dry
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
