# EdgeFetch FAQ & Design Trade-Offs

Straight answers to common architectural, operational, security, and ethical questions about EdgeFetch.

---

## 1. How is EdgeFetch different from Firecrawl or Crawl4AI?

| Question | **EdgeFetch** | **Firecrawl (Self-Hosted)** | **Crawl4AI** |
|---|---|---|---|
| **What do I have to run?** | **1 `~8 MB` static Go binary** (`edgefetch scrape` / `edgefetch mcp`) *or* **1 container** (`node:sqlite` + `/data` — no Redis, Postgres, or RabbitMQ) | Docker Compose with Redis, PostgreSQL, RabbitMQ, Playwright, and API (`2–4 GB+` RAM) | Python 3.10+ environment + Playwright (`600 MB–1.5 GB` RAM) |
| **License** | **Open-source worker, SDKs, and adapters (`MIT`), fair-source hub (`FSL-1.1`, `MIT` after two years)** | AGPL-3.0 (core) | Apache-2.0 (+ attribution) |
| **Network model** | Workers dial **outbound** over `WSS /agent/ws` to **your own Hub** (`0` open inbound ports on home/NAS/RPi boxes) | Inbound HTTP service + optional paid proxy pool | Local Python library or inbound Docker API |
| **Anti-bot stance** | **Enforces `robots.txt` & `Retry-After` on every hop; stops immediately at CAPTCHAs** | Paid cloud tier offers stealth/proxy escalation | Optional stealth / undetected-browser plugins |

If you want a managed SaaS that attempts to bypass anti-bot walls for a per-credit fee, use a commercial provider with legal coverage for that workload. If you want a self-hosted web and search MCP layer (*open-source worker, SDKs, and adapters (`MIT`), fair-source hub (`FSL-1.1`, `MIT` after two years)*) that runs as a single binary or single container on hardware you already own, EdgeFetch was built for that.

---

## 2. Isn't scraping from home / residential IPs or calling site APIs sketchy?

Unthrottled stealth scraping through shared residential proxy pools is abusive — EdgeFetch does the opposite:

1. **No shared proxy network:** An EdgeFetch worker connects *only* your own Raspberry Pi, Home Assistant box, or VPS to *your own* Hub using your secret `AGENT_TOKEN`. Nobody else's traffic ever transits your IP.
2. **`robots.txt` and `Content-Signal` enforced on every hop:** Checked on the initial URL, every `30x` redirect hop, every declarative YAML adapter `twin` URL, and every headless Chromium navigation. Callers over `/mcp` cannot disable `robots.txt`.
3. **Public APIs and pages, never undocumented bypasses:** All `57` built-in declarative YAML adapters (`internal/extract/manifests/*.yaml`) target public feeds, registries, ATS boards, or `robots.txt`-permitted HTML pages. When `/api` is disallowed by `robots.txt` (e.g., `arxiv`, `clinicaltrials`, `openfoodfacts`), EdgeFetch uses `robots.txt`-permitted public HTML routes instead.
4. **Immediate stop on CAPTCHAs and challenges:** When an origin serves a Cloudflare, Akamai, DataDome, PerimeterX, AWS WAF, or Imperva challenge, EdgeFetch classifies it (`outcome: "challenge"`), stops on the first attempt without retrying, and returns a `blocked.suggestion` pointing to official public APIs or feeds.
5. **Per-host serialization & honest identity:** Workers serialize requests per host (`Concurrency = 1` per node with configurable `pause_ms` + jitter), honor `Crawl-delay` and `Retry-After`, and support IETF RFC 9421 Web Bot Auth (`Ed25519` HTTP Message Signatures via `edgefetch keygen-bot-auth`) so site operators can verify or block your instance cleanly.

---

## 3. Does `edgefetch` phone home or run background update checks?

**No.** Both `edgefetch scrape` and `edgefetch mcp` make **zero** background telemetry or update-check calls by default:

- `EDGEFETCH_DEV_TELEMETRY` (structural adapter/WAF error codes, containing zero URLs, hostnames, paths, or page content) and `EDGEFETCH_CHECK_UPDATES` are **strictly opt-in** (`OFF` unless explicitly enabled).
- Setting `DO_NOT_TRACK=1` acts as an unconditional hard disable override across both the Go binary and the TypeScript Hub even if opt-in flags are set.

---

## 4. Was EdgeFetch built with AI, and how do you prevent AI-generated security bugs?

**Yes — EdgeFetch was built with coding agents and audited across 8 adversarial security review rounds.**

- **Two-ring change control:**
  - **Ring 1 — Declarative YAML Site Adapters (`internal/extract/manifests/*.yaml`):** Pure data (no executable code), compiled by [`hub/scripts/compile-manifests.mjs`](../hub/scripts/compile-manifests.mjs), monitored by a daily read-only live canary ([`edgefetch.dev/adapters/status/`](https://edgefetch.dev/adapters/status/)), and gated by [`hub/scripts/verify-adapter-only-diff.mjs`](../hub/scripts/verify-adapter-only-diff.mjs) so domain claims or `fetchUrl` hosts cannot widen without human sign-off.
  - **Ring 0 — Core Engine, Auth, Vault, Sanitizer & SSRF (`cmd/`, `internal/`, `hub/src/`, `.github/`):** Human-approved merges, human-gated `release` environment before Ed25519 binary signing, and executed local PoC regression suites.
- **Public engineering bug log:** Read **[docs/SECURITY-LOG.md](SECURITY-LOG.md)** for a candid breakdown of real bugs caught and fixed across Rounds 1–8 (including Markdown sanitizer vs. `marked`/`micromark+GFM` parser differentials, multi-user session/cache edge cases, ReDoS/quadratic scanner inputs, and CDP browser header isolation).
- **Contributor expectations:** Issues, reproducible bug reports, WAF false-positive samples, and adapter requests are welcome; code pull requests are by invitation ([`.github/VOUCHED.td`](../.github/VOUCHED.td)). See **[CONTRIBUTING.md](../CONTRIBUTING.md)**.

---

## 5. Why direct CDP + OS Chrome on desktop, and how are browser containers sandboxed?

- **Profile isolation on desktop (`Windows` & `macOS`):** When `edgefetch mcp` renders JS via pre-installed Edge, Chrome, or Brave, it spawns a headless process with `--user-data-dir=<ephemeral-temp-dir> --disable-extensions --disable-sync` and a disposable incognito `Target.createBrowserContext` per request. It never reads your personal cookies, logins, history, or extensions.
- **Fail-closed sandboxed Chromium in Docker (`ghcr.io/bartrumb/edgefetch-agent:2.7.2`):** Browser-capable containers bundle Alpine `chromium` + `poppler-utils` behind an in-process loopback `CONNECT` proxy (`--host-resolver-rules="MAP * ~NOTFOUND , EXCLUDE 127.0.0.1"`) so every browser subresource passes through Go's dial-time `RejectNonPublicPeer` SSRF check. On Linux, Chromium's OS namespace sandbox is probed at startup and **fails closed** unless run with `--security-opt seccomp=./deploy/seccomp/chromium-sandbox.json` (never silently running `--no-sandbox`).
- **Home Assistant OS (`addon/`):** The Home Assistant add-on (`slug: "edgefetch"`, `ghcr.io/bartrumb/edgefetch-addon-{arch}`) keeps **Home Assistant Protection Mode ON** (`hassio_api: false`, `homeassistant_api: false`, `host_network: false`), handling HTTP/2 + pure-Go PDF fetches locally while delegating headless browser jobs to sandboxed Docker or desktop/VM nodes in your fleet.

---

## 6. Who runs the Hub, and do I need a Cloudflare account?

**You run your own Hub (if you even need one) — there is no vendor cloud, and Cloudflare is optional:**

1. **Local `stdio` MCP (`edgefetch mcp`):** No Hub or Docker required — coding agents spawn `edgefetch mcp` locally over `stdio` (`0` open ports).
2. **Self-Hosted Docker (`docker compose up -d` or Fly.io / Railway / Render):** Runs the 17-tool Hub, `57` declarative YAML adapters, `/admin` UI, and `node:sqlite` FTS5 + `/data` disk artifacts with zero cloud accounts.
3. **Standalone Go Hub (`edgefetch --mode=hub`):** Single static Go binary on any Linux/BSD VPS or Tailscale node.
4. **Cloudflare Workers (`hub/`):** Hibernating WebSocket Durable Object (`AgentHubDO`) that sleeps at `$0` idle while keeping outbound worker WebSockets connected via edge auto-ping/pong, with optional R2 + D1 FTS5 storage.

---

## 7. What does it cost to run?

- **Local CLI / `stdio` MCP (`edgefetch scrape`, `edgefetch mcp`) + SearXNG / `edge-map`:** **`$0 / month`**.
- **Cloudflare Hub + 1–3 home/VPS workers:** **`$0 – $5 / month`** (Workers Free `$0` or Workers Paid `$5/mo`, within R2 `10 GB` and D1 `5 GB` monthly allowances for typical personal/team workloads).
- **Web search (`search` tool):** Bring your own optional keys (`SERPER_API_KEY`, `BRAVE_API_KEY`, `TAVILY_API_KEY`) or point `SEARXNG_URL` at a self-hosted SearXNG container for `$0`.

---

## 8. Aren't 57 site adapters brittle whack-a-mole, and do workers need redeploying when a site changes?

No on both counts:
1. **Hub-side declarative YAML (`internal/extract/manifests/*.yaml`):** All `57` adapters compile into `compiled.json` on the Hub. Outbound Go workers (`--mode=agent`) are transport, SSRF, CDP, and PDF engines — updating a YAML adapter on the Hub requires zero worker redeploys, and [`edgefetch.dev/adapters/status/`](https://edgefetch.dev/adapters/status/) runs a daily read-only canary to spot upstream schema drift early.
2. **Fail-open bulkhead:** Every adapter executes inside an isolated bulkhead (`runAdapterSyncInBulkhead`). If a site changes a JSON key or DOM selector, the adapter returns `null` and EdgeFetch falls back automatically to standard HTML / JSON-LD / SSR hydration extraction.

---

## 9. How does EdgeFetch defend against Indirect Prompt Injection?

Web pages are untrusted input. Before returning Markdown, EdgeFetch:
- Drops HTML comments (`<!-- ... -->`), `<script>`, `<style>`, `<template>`, and `<noscript>` blocks.
- Strips hidden DOM subtrees (`[hidden]`, `display: none`, `visibility: hidden`, `opacity: 0`, `font-size: 0px`) while preserving KaTeX/MathML formulas.
- Strips invisible smuggling runes (Unicode Tag `U+E0000`–`U+E007F`, bidi overrides `U+202A`–`U+2069`, Braille blank, variation selectors) in linear $O(N)$ time, and supports `checkPromptInjection: true` fail-fast blocking.
- Agent harnesses should still keep human confirmation on destructive local actions when browsing untrusted sites.

---

## 10. Why a linear HTML-to-Markdown pipeline instead of JSDOM + Readability + Turndown?

- **Small, portable runtime:** `hub/` runs identically across Cloudflare Workers (`workerd`), Deno, and Node.js with `6` runtime npm packages in `hub/package.json` (`htmlparser2`, `jose`, `oauth4webapi`, `re2js`, `ws`, `yaml`), and the Go binary uses `1` external Go module (`github.com/coder/websocket`).
- **Technical `<T>` generic & fence fidelity:** Naive HTML tag strippers corrupt `<T>` or `Promise<Array<string>>` as unknown HTML tags or leave `<script>`/`<nav>` noise in context. Verify locally in `< 3` seconds with `node bench/compare.mjs` (offline) or `node bench/compare.mjs --live` (**[bench/RESULTS.md](../bench/RESULTS.md)**).
