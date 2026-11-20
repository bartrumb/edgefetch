# EdgeFetch FAQ & Design Trade-Offs

Straight answers to common architectural, operational, and ethical questions about EdgeFetch.

---

## 1. How is EdgeFetch different from Firecrawl or Crawl4AI?

| Question | **EdgeFetch** | **Firecrawl (Self-Hosted)** | **Crawl4AI** |
|---|---|---|---|
| **What do I have to run?** | **1 ~8 MB static Go binary** (`edgefetch mcp` or `--mode=hub,agent`) *or* **1 container** (`node:sqlite` + `/data` — **0 Redis, 0 Postgres, 0 RabbitMQ**) | Docker Compose with **Redis, PostgreSQL, RabbitMQ, Playwright, and API** (`2–4 GB+` RAM) | Python 3.10+ environment + Playwright (`600 MB–1.5 GB` RAM) |
| **License** | **MIT** | AGPL-3.0 (core) | Apache-2.0 (+ attribution) |
| **Network model** | Workers dial **outbound** over `WSS /agent/ws` (**0 open inbound ports** on home/NAS/RPi boxes) | Inbound HTTP service + optional paid proxy pool | Local Python library or inbound Docker API |
| **Anti-bot stance** | **Strictly respects `robots.txt` & `Retry-After`; halts immediately at CAPTCHAs** | Paid cloud tier offers stealth/proxy escalation | Optional stealth / undetected-browser plugins |

If you want a managed SaaS that attempts to bypass anti-bot walls for a per-credit fee, or hosted vertical datasets (`Alexandria`), use Firecrawl Cloud. If you want an **MIT-licensed, zero-Redis/Postgres web + search MCP layer** you can run on hardware you already own for `$0–$5/mo`, EdgeFetch was built for that.

---

## 2. Isn't scraping from home / residential IPs abusive?

Unthrottled, stealth-bypass scraping from residential proxy botnets is abusive — and EdgeFetch is deliberately designed as the opposite:

1. **`robots.txt` is enforced by default on every hop** (including `30x` redirects and headless Chromium renders). Callers over `/mcp` cannot disable `robots.txt`.
2. **Per-host serialization & `Retry-After` compliance:** Every worker serializes requests per host (`Concurrency = 1` per node with configurable `pause_ms` + random jitter), honors `Crawl-delay` and HTTP `429 Retry-After`, and auto-escalates per-host pause windows (`GET /v1/hosts`) if a site signals load.
3. **Never bypasses CAPTCHAs or anti-bot challenges:** When an origin serves a Cloudflare, Akamai, DataDome, PerimeterX, AWS WAF, or Imperva challenge, EdgeFetch classifies it accurately, halts on the first attempt (`outcome: "challenge"`), and suggests official APIs or feeds instead of retrying.
4. **Honest Bot Identity (IETF RFC 9421 Web Bot Auth):** EdgeFetch identifies itself with a clear `User-Agent` linking to its operator/repo and supports cryptographic `Ed25519` HTTP Message Signatures (`/.well-known/http-message-signatures-directory` + `edgefetch keygen-bot-auth`) so site owners can verify or block your instance cleanly.
5. **Your own hardware only:** EdgeFetch connects **your own** Raspberry Pi, Home Assistant box, or VPS to **your own** Hub using your secret `AGENT_TOKEN` — there is no shared peer-to-peer proxy pool.

---

## 3. Why direct CDP + OS Chrome instead of bundling Playwright?

- **On desktops (`Windows` & `macOS`):** Your machine almost certainly already has Microsoft Edge, Google Chrome, or Brave installed. Speaking the Chrome DevTools Protocol (CDP) directly over a local WebSocket lets `edgefetch` ship as a **single ~8 MB binary** with zero Node/Python runtime and zero duplicate 300 MB browser download.
- **In containers (`Dockerfile.agent`, `Dockerfile.all-in-one`, Home Assistant OS):** Alpine's system `chromium` + `poppler-utils` (`pdftotext`) are pre-installed and locked behind an in-process loopback `CONNECT` proxy (`--host-resolver-rules=MAP * ~NOTFOUND`) so every browser subresource (`fetch()`, `<img>`, `<script>`, redirects) passes through Go's dial-time SSRF IP check (`RejectNonPublicPeer`).
- **Avoiding unnecessary browser launches:** Most documentation pages, APIs, Next.js `__NEXT_DATA__` SSR pages, and ATS job boards (Greenhouse, Ashby, Lever, Workday CXS) don't need a browser at all. EdgeFetch fetches them over pooled HTTP/2 first and only launches Chromium when visible HTML is genuinely thin (`renderMode: "auto"`).

---

## 4. Who runs the Hub, and do I need a Cloudflare account?

**You run your own Hub — there is no shared vendor cloud, and Cloudflare is completely optional.** Pick whichever fits your setup:

1. **Zero-daemon Desktop `stdio` MCP (`edgefetch mcp`):** No Hub at all! Claude Code, Claude Desktop, Cursor, or VS Code spawns `edgefetch mcp` locally over `stdio` (`0` open ports).
2. **Single Docker Container (`docker compose up -d` or Fly.io / Railway / Render):** Runs the TypeScript Hub (`node:sqlite` FTS5 + local `/data` disk artifacts) + Go worker in one container with zero external cloud accounts.
3. **Single Go Binary Hub (`edgefetch --mode=hub` or `--mode=hub,agent`):** Runs on any `$4` Linux/BSD VPS or Tailscale node.
4. **Cloudflare Workers (`hub/`):** Uses a Hibernating WebSocket Durable Object (`AgentHubDO`) that sleeps at `$0` idle while keeping outbound home worker WebSockets connected via edge auto-ping/pong, with optional R2 + D1 FTS5 storage.

---

## 5. What does it actually cost to run?

- **Desktop `stdio` MCP (`edgefetch mcp`) + SearXNG / `edge-map`:** **`$0 / month`**.
- **Cloudflare Hub + 1–3 home nodes (Home Assistant / RPi / spare mini-PC):** **`$0 – $5 / month`** depending on whether your account uses Workers Free or Workers Paid (`$5/mo`), staying well inside R2's `10 GB` and D1's `5 GB` free allowances for typical personal/team agent usage.
- **Web search providers (`search` tool):** EdgeFetch never marks up search credits — you bring your own optional API keys (`SERPER_API_KEY`, `BRAVE_API_KEY`, `TAVILY_API_KEY`, each offering free starter tiers) or point `SEARXNG_URL` at a self-hosted SearXNG container for **`$0`**. Even with zero search keys configured, `site:domain.com` queries work via `$0` `edge-map` (`robots.txt` + `sitemap.xml` + `/llms.txt`) and private FTS5 collections.

---

## 6. How mature is EdgeFetch, and what is the support policy?

EdgeFetch is a **young personal open-source project** (started in November 2026) built to replace paid per-page scraping APIs in daily AI-agent workflows.
- It runs daily on the author's 3-node personal fleet (`arm64`, Home Assistant OS `x86_64`, and a Windows VM) and is gated by Go `-race`, fuzzing, `staticcheck`, `govulncheck`, and `workerd` E2E tests in CI.
- **Support expectation:** MIT-licensed personal project; issues and pull requests are **triaged weekly**. Reproducible bug reports and new site extractor PRs are very welcome — see [CONTRIBUTING.md](../CONTRIBUTING.md).
