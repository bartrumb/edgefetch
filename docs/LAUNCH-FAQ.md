# EdgeFetch FAQ & Design Trade-Offs

Straight answers to common architectural, operational, and ethical questions about EdgeFetch.

---

## 1. How is EdgeFetch different from Firecrawl or Crawl4AI?

| Question | **EdgeFetch** | **Firecrawl (Self-Hosted)** | **Crawl4AI** |
|---|---|---|---|
| **What do I have to run?** | **1 ~8 MB static Go binary** (`edgefetch mcp` or `--mode=hub,agent`) *or* **1 container** (`node:sqlite` + `/data` — **0 Redis, 0 Postgres, 0 RabbitMQ**) | Docker Compose with **Redis, PostgreSQL, RabbitMQ, Playwright, and API** (`2–4 GB+` RAM) | Python 3.10+ environment + Playwright (`600 MB–1.5 GB` RAM) |
| **License** | **Open-source worker, SDKs & adapters (`MIT`); fair-source hub (`FSL-1.1`, `MIT` after 2 yrs)** | AGPL-3.0 (core) | Apache-2.0 (+ attribution) |
| **Network model** | Workers dial **outbound** over `WSS /agent/ws` (**0 open inbound ports** on home/NAS/RPi boxes) | Inbound HTTP service + optional paid proxy pool | Local Python library or inbound Docker API |
| **Anti-bot stance** | **Strictly respects `robots.txt` & `Retry-After`; halts immediately at CAPTCHAs** | Paid cloud tier offers stealth/proxy escalation | Optional stealth / undetected-browser plugins |

If you want a managed SaaS that attempts to bypass anti-bot walls for a per-credit fee, or hosted vertical datasets (`Alexandria`), use Firecrawl Cloud. If you want a **self-hosted, zero-Redis/Postgres web + search MCP layer** (**open-source worker and adapters under `MIT`, fair-source hub under `FSL-1.1`**) that you can run on hardware you already own for `$0–$5/mo`, EdgeFetch was built for that.

---

## 2. Isn't scraping from home / residential IPs abusive?

Unthrottled, stealth-bypass scraping from residential proxy botnets is abusive — and EdgeFetch is deliberately designed as the opposite:

1. **`robots.txt` is enforced by default on every hop** (including `30x` redirects and headless Chromium renders). Callers over `/mcp` cannot disable `robots.txt`.
2. **Per-host serialization & `Retry-After` compliance:** Every worker serializes requests per host (`Concurrency = 1` per node with configurable `pause_ms` + random jitter), honors `Crawl-delay` and HTTP `429 Retry-After`, and auto-escalates per-host pause windows (`GET /v1/hosts`) if a site signals load.
3. **Never bypasses CAPTCHAs or anti-bot challenges:** When an origin serves a Cloudflare, Akamai, DataDome, PerimeterX, AWS WAF, or Imperva challenge, EdgeFetch classifies it accurately, halts on the first attempt (`outcome: "challenge"`), and suggests official APIs or feeds instead of retrying.
4. **Honest Bot Identity (IETF RFC 9421 Web Bot Auth):** EdgeFetch identifies itself with a clear `User-Agent` linking to its operator/repo and supports cryptographic `Ed25519` HTTP Message Signatures (`/.well-known/http-message-signatures-directory` + `edgefetch keygen-bot-auth`) so site owners can verify or block your instance cleanly.
5. **Your own hardware only:** EdgeFetch connects **your own** Raspberry Pi, Home Assistant box, or VPS to **your own** Hub using your secret `AGENT_TOKEN` — there is no shared peer-to-peer proxy pool.

---

## 3. Why direct CDP + OS Chrome on desktop, and does it touch my personal browser profile?

- **Complete profile isolation on desktop (`Windows` & `macOS`):** When the standalone `~8 MB` binary (`edgefetch mcp`) renders JS via pre-installed Microsoft Edge, Chrome, or Brave, it launches a headless process with `--user-data-dir=<ephemeral-temp-dir> --disable-extensions --disable-sync` and creates a disposable incognito `Target.createBrowserContext` per request. **It never reads your personal cookies, saved logins, browsing history, or extensions**, and deletes the temporary directory on exit.
- **Pinned Chromium bundled in containers (`Dockerfile.agent`, `Dockerfile.all-in-one`, Home Assistant OS):** You do **not** rely on host browsers on servers — Fat containers bundle pinned Alpine `chromium` + `chromium-swiftshader` + `poppler-utils` (`pdftotext`) inside the image, locked behind an in-process loopback `CONNECT` proxy (`--host-resolver-rules=MAP * ~NOTFOUND`) so every browser subresource (`fetch()`, `<img>`, `<script>`, redirects) passes through Go's dial-time SSRF IP check (`RejectNonPublicPeer`).
- **Modern SPA & heavy-JS support (`v2.4.1+`):** Native CDP rendering tracks in-flight `XHR`/`Fetch` requests to true network-idle, runs lazy-scroll + `MutationObserver` quiescence, flattens open Web Component `shadowRoot` trees, recovers Next.js App Router RSC (`self.__next_f.push`) & `__NEXT_DATA__` payloads without launching a browser, and supports optional `CRAWL4AI_API_URL` / `FIRECRAWL_API_KEY` fallback for extreme SPAs.

---

## 4. Who runs the Hub, and do I need a Cloudflare account?

**You run your own Hub — there is no shared vendor cloud, and Cloudflare is completely optional.** Pick whichever fits your setup:

1. **Zero-daemon Desktop `stdio` MCP (`edgefetch mcp`):** No Hub or Docker needed — Claude Code, Claude Desktop, Cursor, or VS Code spawns `edgefetch mcp` locally over `stdio` (`0` open ports), exposing 5 local tools (`scrape`, `fetch_url`, `fetch_batch`, `map`, `doctor`).
2. **Single Docker Container (`docker compose up -d` or Fly.io / Railway / Render):** Runs the full **17-tool Hub** (`agent`, `discover_mcps`, `query_mcp`, `find_extractors`, `scrape`, `extract`, `map`, `crawl`, `search`, `jobs`, `catalog`, `search_collection`, `interact`, `read_artifact`, `fetch_url`, `fetch_batch`, `list_agents`), **56 declarative YAML site/ATS adapters**, `/admin` UI, and `node:sqlite` FTS5 + `/data` disk artifacts with zero external cloud accounts.
3. **Single Go Binary Hub (`edgefetch --mode=hub` or `--mode=hub,agent`):** Runs on any `$4` Linux/BSD VPS or Tailscale node.
4. **Cloudflare Workers (`hub/`):** Uses a Hibernating WebSocket Durable Object (`AgentHubDO`) that sleeps at `$0` idle while keeping outbound home worker WebSockets connected via edge auto-ping/pong, with optional R2 + D1 FTS5 storage.

---

## 5. What does it actually cost to run?

- **Desktop `stdio` MCP (`edgefetch mcp`) + SearXNG / `edge-map`:** **`$0 / month`**.
- **Cloudflare Hub + 1–3 home nodes (Home Assistant / RPi / spare mini-PC):** **`$0 – $5 / month`** depending on whether your account uses Workers Free or Workers Paid (`$5/mo`), staying well inside R2's `10 GB` and D1's `5 GB` free allowances for typical personal/team agent usage.
- **Web search providers (`search` tool):** EdgeFetch never marks up search credits — you bring your own optional API keys (`SERPER_API_KEY`, `BRAVE_API_KEY`, `TAVILY_API_KEY`, each offering free starter tiers) or point `SEARXNG_URL` at a self-hosted SearXNG container for **`$0`**. Even with zero search keys configured, `site:domain.com` queries work via `$0` `edge-map` (`robots.txt` + `sitemap.xml` + `/llms.txt`) and private FTS5 collections.

---

## 6. How mature is EdgeFetch, and what is the support policy?

EdgeFetch is a **young personal project** (started in November 2026) built to replace paid per-page scraping APIs in daily AI-agent workflows.
- It runs daily on the author's 3-node personal fleet (`arm64`, Home Assistant OS `x86_64`, and a Windows VM) and is gated by Go `-race`, fuzzing, `staticcheck`, `govulncheck`, and `workerd` E2E tests in CI.
- **Licensing & support expectation:** Open-source worker, SDKs, and adapters ([MIT](../LICENSE)); fair-source hub ([FSL-1.1-MIT](../hub/LICENSE), MIT after two years). Issues and pull requests are **triaged weekly**. Reproducible bug reports and new site extractor PRs are very welcome — see [CONTRIBUTING.md](../CONTRIBUTING.md).

---

## 7. Aren't 56 site adapters brittle whack-a-mole, and do I have to recompile Go nodes when a site changes?

No on both counts:
1. **Declarative YAML manifests (`internal/extract/manifests/*.yaml`):** All 56 adapters live in auditable declarative YAML specs compiled into `compiled.json` (shared between `hub/` and standalone `edgefetch --mode=hub`). Outbound Go fleet workers (`--mode=agent`) are pure transport, SSRF, CDP, and PDF engines, so updating an adapter on your Hub requires **zero redeploys** on remote Raspberry Pi, Home Assistant, or VM worker nodes.
2. **Fault-isolated fail-open fallback:** Every adapter runs inside an isolated `try / catch` bulkhead. If a site renames a JSON field or DOM class tomorrow, the adapter returns `null` and EdgeFetch **automatically falls back** to standard HTML / Schema.org JSON-LD / SSR Hydration / Headless CDP extraction instead of failing the call.
3. **Public APIs over brittle DOM selectors:** Most adapters upgrade noisy web URLs to stable, official keyless APIs (`data.sec.gov`, `registry.npmjs.org`, `crates.io/api/v1`, `api.crossref.org`, `api.openalex.org`, Socrata SODA, CKAN, Workable, Greenhouse, Ashby, Lever) rather than scraping fragile CSS classes.

---

## 8. How does EdgeFetch defend against Indirect Prompt Injection from untrusted web pages?

Any tool that feeds live web content into an LLM must treat web pages as untrusted input. EdgeFetch strips common hidden-instruction smuggling vectors before returning Markdown:
- Drops HTML comments (`<!-- ... -->`), `<script>`, `<style>`, `<template>`, and `<noscript>` blocks.
- Strips hidden DOM subtrees (`[hidden]`, `.d-none`, `display: none`, `visibility: hidden`, `opacity: 0`, `font-size: 0px`) while preserving legitimate KaTeX/MathML formulas.
- Strips invisible **Unicode Tag ASCII-smuggling characters (`U+E0000`–`U+E007F`)** and **Bidi directional override controls (`U+202A`–`U+202E`, `U+2066`–`U+2069`)** in both the Go worker and TypeScript Hub.
- Agent harnesses should still keep human-in-the-loop approval on destructive local tool calls when browsing untrusted URLs.

---

## 9. Why a custom linear HTML-to-Markdown pipeline instead of JSDOM + Readability + Turndown?

- **WinterCG Isolate Portability & Minimal Supply Chain:** `hub/` runs identically on Cloudflare Workers (`workerd`), Deno, and Node.js with only 6 vetted runtime packages (`re2js`, `htmlparser2`, `jose`, `oauth4webapi`, `ws`, `yaml` — bundled into a single `dist/portable-server.mjs` with `0` `node_modules` in containers, and `1` Go dependency `coder/websocket` in the Go binary).
- **Code & Technical Fidelity:** Naive HTML sanitizers strip `<T>` or `<Array<string>>` inside TypeScript, Rust, Go, and C++ prose/code blocks as "unknown HTML tags". EdgeFetch stashes code spans/fences first, preserves variable-length CommonMark fences, converts KaTeX/MathML to LaTeX, and runs in `<2 ms` per document (`node bench/run-bench.mjs`).
