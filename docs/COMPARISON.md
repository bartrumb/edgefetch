# EdgeFetch vs. Other AI Web Crawlers & MCP Servers

This document compares **EdgeFetch (`v2.7.4`)** against common open-source and commercial web-data stacks for AI agents across architecture, supply chain, security boundaries, extraction fidelity, observability, and cost — including honest guidance on when another tool is a better fit.

---

## 1. Architecture & Operational Comparison

| Capability / Architecture | **EdgeFetch (`v2.7.4`)** | **Firecrawl (Self-Hosted & `firecrawl-local`)** | **Firecrawl / Tavily (Cloud)** | **Crawl4AI** | **Jina Reader (`reader`)** | **Defuddle / Trafilatura** |
|---|---|---|---|---|---|---|
| **License** | **Open-source worker, SDKs, and adapters (`MIT`), fair-source hub (`FSL-1.1`, `MIT` after two years)** | AGPL-3.0 (core) | Proprietary SaaS | Apache-2.0 (+ attribution) | Apache-2.0 | MIT / Apache-2.0 |
| **Minimum Self-Hosted Stack** | **1 `~8 MB` static Go binary** *or* **1 container** (`node:sqlite` + `/data`, no Redis, Postgres, or RabbitMQ) | Full stack: Redis + PostgreSQL + RabbitMQ + Playwright + API (`2–4 GB+` RAM); `firecrawl-local` requires Node 22 `npx` + Rust/C toolchain | Cloud API key only | Python 3.10+ + Playwright (`~600 MB–1.5 GB` RAM) | Node.js + Puppeteer / Firebase deps | Library / CLI only (no crawler fleet or MCP server) |
| **Auditable Dependencies** | **Go: `1` module (`github.com/coder/websocket`, `0` transitive); Hub: `6` npm packages (`htmlparser2`, `jose`, `oauth4webapi`, `re2js`, `ws`, `yaml`)** | Dozens of npm + Rust + system packages | Vendor SaaS | 40+ Python / PyPI packages | Dozens of npm packages | 0–5 library packages |
| **Outbound-Only Edge Workers (`0` Open Ports)** | **Yes — workers dial *your own* Hub over `WSS /agent/ws` (works behind CGNAT, Starlink, Home Assistant OS, NAS)** | No (requires inbound ports, VPN tunnel, or external proxy service) | Managed proxy pool (billed per credit) | No (single-host or DIY queue) | No | N/A |
| **Local `stdio` MCP (`edgefetch mcp`) & Background Telemetry** | **Yes — `~8 MB` binary; `0` background telemetry or update checks by default (`EDGEFETCH_DEV_TELEMETRY` & `EDGEFETCH_CHECK_UPDATES` opt-in; `DO_NOT_TRACK=1` hard override)** | `firecrawl-local` requires Node 22+ `npx`, sends install telemetry, and disables private-IP blocks in `mcp` mode | Requires cloud API key (`npx firecrawl-mcp` / `tavily-mcp`) | Python + Playwright environment | Cloud URL or Node server | No |
| **SSRF & Browser Subresource Isolation** | **Dial-time `net.Dialer.Control` `RejectNonPublicPeer` + loopback `CONNECT` `SSRFProxy` (`MAP * ~NOTFOUND`) + fail-closed Linux seccomp sandbox** | Application-level URL blocklist | Vendor-managed | Optional / application-level | Application-level | None (caller fetches) |
| **Default `robots.txt` & Anti-Bot Stance** | **RFC 9309 `robots.txt` + `Content-Signal` on every hop; stops immediately on first CAPTCHA/challenge** | Optional `robots.txt`; cloud tier escalates stealth/proxies | Varies by endpoint | Optional (`check_robots_txt`) + stealth plugins | Optional | Caller-managed |
| **Remote `/mcp` & Multi-User Hub** | **17 MCP tools, self-hosted OAuth 2.1 + PKCE, optional `AES-256-GCM` connector vault, optional BYO-LLM `/v1/agent` (GitHub OAuth off by default)** | Cloud OAuth; self-hosted uses static bearer key | Hosted cloud | Static token / wrappers | Bearer key | No |
| **OpenTelemetry (`OTLP/HTTP` + W3C `traceparent`)** | **Stitched Hub → Go `httptrace` (`dnsMs`, `connectMs`, `tlsMs`, `ttfbMs`) to any collector** | Internal logs / BullMQ UI | Vendor dashboard only | Python logging | Internal logs | None |
| **API Compatibility** | **`/v1/*`, `/v2/*`, `/compat/firecrawl/v2/*`, `/compat/tavily/*`, TypeScript & Python SDKs** | Firecrawl `/v1` & `/v2` | Separate Firecrawl or Tavily plans | Crawl4AI REST/SDK | `r.jina.ai/<url>` | Library API |

---

## 2. Extraction & Search Capabilities

Reproduce HTML-to-Markdown extraction, `<T>` generic preservation, code-fence balance, and latency locally in `< 3` seconds via `node bench/compare.mjs` (**[bench/RESULTS.md](../bench/RESULTS.md)**).

| Content / RAG Capability | **EdgeFetch (`v2.7.4`)** | **Firecrawl** | **Crawl4AI** | **Jina Reader** | **Tavily** |
|---|:---:|:---:|:---:|:---:|:---:|
| **`<code>` & Generic `<T>` Preservation (`Promise<Array<string>>`)** | **Yes** | Yes | Partial | Yes | Partial |
| **CommonMark/GFM Sanitizer Differential Suite (278 vectors vs `marked` + `micromark`)** | **Yes ([docs/SECURITY-LOG.md](SECURITY-LOG.md))** | N/A | N/A | N/A | N/A |
| **`/llms.txt` Discovery + `Accept: text/markdown` Negotiation** | **Yes** | Partial | Partial | No | No |
| **SSR Hydration Recovery (`__NEXT_DATA__`, Next.js RSC `__next_f`, Nuxt, Remix, Apollo)** | **Yes (1 HTTP pass)** | Partial | Browser render | Browser render | Partial |
| **Link-Density Pruning → BM25 Passage Reranking (`query`)** | **Yes (Hub + Go)** | Yes | Yes (`Pruning` + `BM25`) | Partial | Yes (`chunks_per_source`) |
| **Jupyter Notebooks (`.ipynb`) & OpenAPI 3.x Specs → Structured Markdown** | **Yes** | Partial | Partial | Raw JSON | No |
| **Streaming PDFs (up to 256 MiB Poppler + pure-Go fallback)** | **Yes** | Yes (credit-tiered per page) | Python PDF | Partial | Partial |
| **Declarative YAML Site, Commerce & ATS Adapters (`internal/extract/manifests/*.yaml`)** | **`57` built-in (`MIT`, keyless)** | Partial | Custom code | Partial | Partial |
| **Multi-Provider Search (`Serper` / `Brave` / `Tavily` BYOK + `$0` `SearXNG` + D1/SQLite FTS5)** | **Yes** | Proprietary / SearXNG | Bring-your-own | `s.jina.ai` | Proprietary index |

---

## 3. Architectural Differences in Detail

### 1. Outbound-Only Edge Workers (Your Own Hardware, Zero Open Ports)
Self-hosted crawlers usually force a choice between datacenter VPS IPs (which frequently hit `429` rate limits on documentation CDNs and storefronts) or opening inbound ports / tunnels into a home network.
- EdgeFetch workers (`edgefetch --mode=agent`) dial **outbound** over TLS `WSS /agent/ws` to **your own Hub** using your private `AGENT_TOKEN` (there is never a shared third-party proxy pool).
- On **Home Assistant OS** (`addon/`, `slug: "edgefetch"`), Protection Mode stays **ON** (`hassio_api: false`, `homeassistant_api: false`, `host_network: false`), handling HTTP/2 and pure-Go PDF jobs while delegating headless Chromium jobs to sandboxed Docker (`ghcr.io/bartrumb/edgefetch-agent:2.7.4` with `--security-opt seccomp=./deploy/seccomp/chromium-sandbox.json`) or desktop/VM nodes.

### 2. Minimal Dependency Surface
Running Firecrawl self-hosted requires operating Redis, PostgreSQL, RabbitMQ, Playwright, and a Node API under AGPL-3.0.
- EdgeFetch's worker, CLI, `stdio` MCP, and pure-Go Hub compile into a single `~8 MB` static binary (`go list -m all` -> `1` external Go dependency: `github.com/coder/websocket`).
- EdgeFetch's optional TypeScript Hub (`hub/package.json`) uses `6` runtime npm packages (`htmlparser2`, `jose`, `oauth4webapi`, `re2js`, `ws`, `yaml`) and bundles into a single `dist/portable-server.mjs` backed by built-in `node:sqlite` FTS5 + a `/data` directory.

### 3. Defense-in-Depth SSRF & Public Security Bug Log
Pointing an HTTP client or headless browser at agent-supplied URLs exposes high-severity SSRF, ReDoS, and Markdown XSS surfaces:
- `politeness.RejectNonPublicPeer` verifies resolved peer IPs inside Go's `net.Dialer.Control` right before `connect()` (blocking DNS-rebinding TOCTOU), and Chromium subresources route through an in-process loopback `CONNECT` `SSRFProxy` (`--host-resolver-rules="MAP * ~NOTFOUND , EXCLUDE 127.0.0.1"`).
- Real vulnerabilities caught and fixed across 8 adversarial review rounds are documented in **[docs/SECURITY-LOG.md](SECURITY-LOG.md)**.

### 4. Typical Infrastructure Cost (50,000 Scrapes + 5,000 Searches / Month)

| Stack | Typical Monthly Cost | Notes |
|---|---:|---|
| **EdgeFetch on Cloudflare Workers + 1–3 Own Nodes + Self-Hosted SearXNG** | **`$0 – $5 / mo`** | Hibernating DO sleeps at `$0` idle (`$0` Workers Free or `$5/mo` Workers Paid); R2 10 GB + D1 5 GB monthly allowances; `$0` SearXNG |
| **EdgeFetch All-in-One Container (Fly.io / Hetzner / Railway)** | **`$4 – $7 / mo`** | Single `512 MB–1 GB` container + persistent `/data` volume |
| **Self-Hosted Firecrawl (4 GB+ VPS + Proxy Bandwidth)** | **`$25 – $80+ / mo`** | Multi-service RAM footprint + external proxy bandwidth |
| **Firecrawl Cloud + Tavily Cloud SaaS** | **`$49 – $130+ / mo`** | Separate metered credit plans for scraping and search |

---

## 4. Honest Trade-Offs: When Another Tool Fits Better

EdgeFetch is opinionated about **politeness, clear boundaries, and small infrastructure**. Use a different tool when:

1. **You need anti-bot, CAPTCHA, or login-wall circumvention:** EdgeFetch enforces `robots.txt` on every hop and stops immediately (`outcome: "challenge"`) when gated by Cloudflare Turnstile, reCAPTCHA, DataDome, PerimeterX, or login walls. If your workload requires residential proxy pools or stealth browser patches to bypass bot protection on third-party sites, EdgeFetch will refuse by design.
2. **You need proprietary B2B contact/enrichment databases (Crunchbase, PitchBook, ZoomInfo, Apollo):** EdgeFetch's `57` declarative YAML adapters target keyless public APIs, registries, ATS job boards, SEC EDGAR, open government portals, and scientific literature. For paid commercial datasets, query those vendor APIs directly.
3. **You only want an in-process HTML-to-Markdown library inside an existing Python or Node app:** If your application already fetches HTML strings itself and does not need an MCP server, CLI, SSRF-hardened fetcher, or remote worker fleet, `kepano/defuddle` (TypeScript) or `adbar/trafilatura` (Python) are great focused libraries.
