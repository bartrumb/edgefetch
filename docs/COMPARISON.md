# EdgeFetch vs. Other AI Web Crawlers & MCP Servers

This document compares **EdgeFetch (`v2.5`)** against the leading open-source and commercial web-data stacks for AI agents across architecture, operational footprint, security, extraction fidelity, autonomous `/agent` mode, `firecrawl-local`, observability, and cost.

---

## 1. Executive Architecture Face-Off

| Capability / Architecture | **EdgeFetch (`v2.6`)** | **Firecrawl (Self-Hosted & `firecrawl-local`)** | **Firecrawl / Tavily (Cloud)** | **Crawl4AI** | **Jina Reader (`reader`)** | **Defuddle / Trafilatura** |
|---|---|---|---|---|---|---|
| **License** | **Open-source worker, SDKs & adapters (`MIT`); fair-source hub (`FSL-1.1`, `MIT` after 2 yrs)** | AGPL-3.0 (core) | Proprietary SaaS | Apache-2.0 (+ attribution) | Apache-2.0 | MIT / Apache-2.0 |
| **Minimum Self-Hosted Stack** | **1 ~8 MB static Go binary** *or* **1 container** (`node:sqlite` + `/data`, **0 Redis, 0 Postgres, 0 Node/Rust toolchain**) | Full stack: **Redis + PostgreSQL + RabbitMQ + Playwright + API** (`2–4 GB+` RAM); `firecrawl-local`: requires **Rust + C compiler + Node 22 `npx` + telemetry install ID** | Cloud API key only | Python 3.10+ + Playwright (`~600 MB–1.5 GB` RAM) | Node.js + Puppeteer / Firebase deps | Library / CLI only (no crawler fleet or MCP server) |
| **Go Worker External Dependencies** | **1 (`coder/websocket`, 0 transitive deps)** | Dozens of npm + Rust + system packages | N/A | 40+ Python / PyPI packages | Dozens of npm packages | 0–5 library packages |
| **Outbound-Only Residential / Edge Fleet (Zero Open Ports)** | **Yes — native outbound `WSS /agent/ws` (works behind CGNAT, Starlink, Home Assistant OS, NAS)** | No (requires inbound ports, VPN tunnel, or paid proxy service) | Managed proxy pool (billed per credit) | No (single-host or DIY queue) | No | N/A |
| **Cloudflare `$0`-Idle Control Plane** | **Yes — Hibernating WebSocket Durable Object (`AgentHubDO`) + D1 FTS5 + R2** | No | N/A | No | No | N/A |
| **Active-Active Multi-Controller HA & Offline Mesh** | **Yes (`EDGEFETCH_HUB_URLS` fan-out + `HUB_SHARDS` DO ring + `--mode=hub,agent` standby + SDK `baseUrls`)** | Manual load-balancer + shared Redis/Postgres cluster | Vendor-managed single cloud | Manual | Manual | N/A |
| **Desktop Zero-Setup Local `stdio` MCP (`edgefetch init` / `mcp`)** | **Yes (~8 MB binary auto-configures Claude Code, Claude Desktop, Cursor, Windsurf, Gemini CLI & Codex with `.bak` backups; 0 Node/npx, 0 telemetry, public-only SSRF on by default)** | `firecrawl-local` requires Node 22+ `npx firecrawl-mcp`, phones home install telemetry, ignores `actions`/`json`/`summary`, and allows private LAN SSRF in `mcp` mode | Requires cloud API key (`npx firecrawl-mcp` / `tavily-mcp`) | Python + Playwright environment | Cloud URL or Node server | No |
| **Autonomous `/agent` Mode (Offline + Online BYO-LLM)** | **Yes (`/v1/agent` & `/v2/agent` — offline `Ollama`/`LM Studio`/`vLLM` + online OpenAI/Anthropic/Gemini/Workers AI, live SSE streaming, `$0` ZDR, dynamic routing across 49+ adapters with zero 3-source cap)** | Cloud-only (`spark-2` proprietary) | Proprietary `spark-2` (`<=3` sources / `<=5` toolkits, no SSE streaming, 2× Enterprise surcharge for ZDR) | Custom Python scripts | DeepSearch (cloud credits) | No |
| **Remote OAuth 2.1 PKCE + Dynamic Client Registration MCP** | **Built-in (`/mcp` + `/admin` grant console, 14 tools, MCP `2026-07-28` & `2025-03-26`)** | Cloud-only OAuth (`fco_...`); self-hosted uses static key | Yes (hosted cloud) | Static token / community wrappers | Bearer key | No |
| **Dial-Time DNS-Rebinding SSRF Immunity + Browser Subresource Proxy** | **Yes (`net.Dialer.Control` `RejectNonPublicPeer` + loopback `CONNECT` `SSRFProxy` + `MAP * ~NOTFOUND`)** | Partial URL-level blocklists (`firecrawl-local` disables private IP block in `mcp` mode) | Vendor-managed | Optional / application-level | Application-level | None (caller fetches) |
| **Strict Default `robots.txt` + Per-Host `Retry-After` Cooldowns + Multi-IP Failover** | **Enforced on every hop (including 30x redirects & headless renders), `0 allocs/op` RFC 9309** | Optional / configurable | Varies by endpoint | Optional (`check_robots_txt`) | Optional | Caller-managed |
| **Prompt Injection Protection (`checkPromptInjection`)** | **Built-in at `$0` (strips hidden CSS/DOM + Unicode Tag smuggling + optional `403` fail-fast)** | Cloud-only (+4 credits/page) | +4 credits/page | Manual | No | No |
| **Anti-Bot / CAPTCHA Handling** | **Strict ethical halt (`challenge` outcome — never bypasses CAPTCHAs or ToS gates)** | Stealth / residential proxy escalation (+4–5 credits) | Managed | Undetected-browser plugins | Headless fallback | N/A |
| **Vendor-Agnostic OpenTelemetry (`OTLP/HTTP` + W3C `traceparent`)** | **Built-in Hub → Go `httptrace` (`dnsMs`, `connectMs`, `tlsMs`, `ttfbMs`) stitched spans** | Custom logging / BullMQ UI | Vendor dashboard only | Python logging | Internal logs | None |
| **Drop-In API Compatibility** | **Root `/v2/*` + `/v1/*` + `/compat/firecrawl/v2/*` + `/compat/tavily/*` + TS & Python SDKs** | Firecrawl `/v1` & `/v2` | Firecrawl *or* Tavily (separate subscriptions) | Crawl4AI REST/SDK | `r.jina.ai/<url>` | Library API |

---

## 2. Extraction & Search Feature Matrix

| Content / RAG Capability | **EdgeFetch (`v2.4`)** | **Firecrawl** | **Crawl4AI** | **Jina Reader** | **Tavily** |
|---|:---:|:---:|:---:|:---:|:---:|
| **Sentinel-Protected `<pre><code>` & Generic `<T>` Preservation (`Promise<void>`)** | **Yes** | Yes | Partial | Yes | Partial |
| **`/llms.txt` Discovery + `Accept: text/markdown` 1-Hop Upgrade** | **Yes (automatic)** | Partial | Partial | No | No |
| **Two-Stage Link-Density Pruning → BM25 Passage Reranking (`query`)** | **Yes (Hub + Go)** | Yes | Yes (`Pruning` + `BM25`) | Partial | Yes (`chunks_per_source`) |
| **Jupyter Notebooks (`.ipynb`) → Cell + Output Markdown** | **Yes** | Partial (`/v2/parse`) | Partial | No | No |
| **OpenAPI 3.x / Swagger 2.0 JSON → Structured API Docs Markdown** | **Yes** | Raw JSON | Raw JSON | Raw JSON | No |
| **Large Streaming PDFs (up to 256 MiB disk-streamed Poppler + pure-Go fallback + optional OCR)** | **Yes (256 MiB)** | Yes (credit-tiered per page) | Basic Python PDF | Partial | Partial |
| **YouTube Clean Transcript Extraction (`interact` without timestamp spam)** | **Yes** | Yes (`scrape`) | Custom script | Partial | No |
| **CSV/TSV Tables, RSS/Atom Feeds, iCal (`.ics`), vCard (`.vcf`), Git `.patch` Diffs** | **Yes (all 5)** | Partial | Partial | Partial | No |
| **Site-Specific & ATS Job Adapters (Greenhouse, Ashby, Lever, Workday CXS, `JobPosting` JSON-LD, GitHub, npm, ArXiv, HN)** | **Yes (25+ built-in)** | Partial | Custom | Partial | Partial |
| **Multi-Provider Search (`Serper` / `Brave` / `Tavily` BYOK + `$0` `SearXNG` + `edge-map` + Private SQLite/D1 FTS5)** | **Yes (bring your own keys; SearXNG & `edge-map` for `$0`)** | Proprietary / SearXNG | Bring-your-own | `s.jina.ai` | Proprietary index |
| **Content-Addressed Artifact Store (`SHA-256` gzip in R2 / disk + `read_artifact` offset paging)** | **Yes (zero 64 KB truncation loss)** | Workspace / S3 | Local cache | Ephemeral | Ephemeral |

---

## 3. Where EdgeFetch Is Architecturally Superior

### 1. Zero-Port Residential & Multi-Site Egress Without Monthly Proxy Bills
Most self-hosted crawlers force an unpleasant trade-off:
- Deploy on a cheap VPS → datacenter ASNs (`AWS`, `Hetzner`, `DigitalOcean`, `Cloudflare`) get HTTP `429` or `403` on Shopify, documentation CDNs, and forums unless you pay `$15–$100+/mo` for residential proxies.
- Deploy at home → requires opening router ports, maintaining tunnels, or exposing your LAN.

**EdgeFetch flips the connection direction:** lightweight Go agents running on **Home Assistant OS**, **Raspberry Pi**, **Unraid/Synology NAS**, **Mac Mini**, or **Docker** dial *outbound* over TLS `WSS /agent/ws` to your Hub. Zero inbound firewall ports are opened, CGNAT/Starlink works transparently, and when one WAN IP receives `429 Retry-After`, the Hub cools down that IP and fails over to a sibling site on a distinct WAN IP automatically.

### 2. `~8 MB` Single-Dependency Go Binary vs. Heavy Multi-Service Stacks
Self-hosting Firecrawl requires running and patching **Redis**, **PostgreSQL**, **RabbitMQ**, **Playwright**, and a **Node.js API** under **AGPL-3.0**.
- EdgeFetch's worker and Go Hub compile to a **single ~8 MB static binary** (`CGO_ENABLED=0`) with **1 external Go module (`github.com/coder/websocket`) and 0 transitive dependencies**.
- Even EdgeFetch's full **All-in-One Container** (`Dockerfile.all-in-one` — TypeScript Hub + `/admin` UI + OAuth 2.1 + 12-tool `/mcp` + `node:sqlite` FTS5 + Go HTTP/2 + Headless Chromium + Poppler PDF) runs in **one container with a `/data` volume** — zero Redis, zero Postgres, zero message broker.
- On Windows and macOS desktops, `edgefetch mcp` and `edgefetch desktop` piggyback your **already-installed Microsoft Edge, Chrome, or Brave** binary for headless CDP rendering — delivering full JS rendering in an **8 MB download** instead of a 300+ MB Playwright bundle.

### 3. Defense-in-Depth SSRF & Sandbox Hardening
Pointing a headless browser at arbitrary agent-supplied URLs is one of the highest-risk surfaces in modern AI infrastructure:
- **URL-string SSRF filters are vulnerable to DNS rebinding** (an attacker's domain resolves to `93.184.216.34` during validation and `169.254.169.254` or `192.168.1.1` 50 ms later when `connect()` runs). EdgeFetch enforces `politeness.RejectNonPublicPeer` inside Go's `net.Dialer.Control` **on the resolved `netip.AddrPort` socket right before `connect()`**, eliminating TOCTOU DNS rebinding completely.
- **Headless Chromium subresources (`<img>`, `<script>`, `fetch()`, WebRTC, redirects) cannot bypass Go's SSRF policy:** Chromium launches with `--proxy-server=http://127.0.0.1:<ephemeral>` and `--host-resolver-rules=MAP * ~NOTFOUND , EXCLUDE 127.0.0.1`, forcing every browser sub-request through EdgeFetch's in-process `SSRFProxy`.

### 4. End-to-End Stitched OpenTelemetry (`OTLP/HTTP` + W3C `traceparent`)
When an AI agent scrape is slow, other crawlers give you an opaque `duration: 4200ms`. EdgeFetch emits W3C `traceparent` across Hub → WebSocket `dispatch` → Go `net/http/httptrace`, exporting exact phase spans (`dnsMs`, `connectMs`, `tlsMs`, `ttfbMs`, `reused`, `proto`) to **Grafana Tempo**, **Jaeger**, **Honeycomb**, **Axiom**, or **SigNoz** with zero caller latency overhead.

### 5. Total Cost of Ownership (50,000 Scrapes + 5,000 Searches / Month)

| Stack | Monthly Infrastructure / API Cost | Notes |
|---|---:|---|
| **EdgeFetch on Cloudflare Workers + 1–3 Home Assistant / Homelab Nodes + Self-Hosted SearXNG (or BYOK Free Tiers)** | **`$0 – $5 / mo`** | Hibernating DO sleeps at `$0` idle (`$0` Workers Free or `$5/mo` Workers Paid); R2 10 GB free; D1 5 GB free; SearXNG is `$0` (or bring your own Serper/Brave/Tavily API keys) |
| **EdgeFetch All-in-One Container (Fly.io / Hetzner / Railway)** | **`$4 – $7 / mo`** | Single 512 MB–1 GB container + persistent `/data` volume |
| **Self-Hosted Firecrawl (4 GB+ VPS + Residential Proxy Bandwidth)** | **`$25 – $80+ / mo`** | Multi-container RAM footprint + commercial proxy GB fees |
| **Firecrawl Cloud + Tavily Cloud SaaS** | **`$49 – $130+ / mo`** | Separate monthly credit plans for scraping/crawling and search |

*Cost assumptions checked November 20, 2026: compares self-hosted EdgeFetch running on Cloudflare Workers Free (`$0`) or Workers Paid (`$5/mo`) within R2 (`10 GB`) and D1 (`5 GB`) monthly free tiers plus self-hosted SearXNG (`$0`, excluding hardware/ISP electricity you already run at home) against published monthly pricing for Firecrawl Standard (`$19–$99/mo` for 3k–100k credits) plus Tavily Researcher (`$30+/mo` beyond the 1,000-credit free tier).*

---

## 4. Honest Trade-Offs: When Another Tool Fits Better

EdgeFetch is opinionated about **politeness, legality, and minimal infrastructure**. Another tool may fit better when:

1. **You need anti-bot / CAPTCHA / login-wall circumvention:** EdgeFetch strictly honors `robots.txt` by default, identifies itself honestly, and halts immediately with `outcome: "challenge"` when gated by Cloudflare Turnstile, reCAPTCHA, DataDome, or authentication walls. If your business depends on managed stealth residential proxy pools to bypass bot challenges on sites you do not own, use a commercial provider with legal coverage for that workload.
2. **You want paid commercial B2B enrichment databases (Crunchbase, PitchBook, ZoomInfo, Apollo):** EdgeFetch's 49+ built-in adapters (`GET /v1/extractors` & dynamic `find_extractors` router) cover keyless public APIs, ATS boards, SEC EDGAR, open government portals, and scientific literature at `$0` with zero third-party clickwrap terms gates. If you specifically want paid commercial B2B contact/funding brokers, you can either pass `FIRECRAWL_API_KEY` as an optional fallback or query those commercial APIs directly.
3. **You only want an in-process Python/JS HTML-to-Markdown library (no fleet, no HTTP/2 crawler, no MCP server):** If your app already fetches HTML strings itself and just wants DOM cleanup inside Node or Python, `kepano/defuddle` (TypeScript) or `adbar/trafilatura` (Python) are excellent lightweight libraries — in fact, EdgeFetch incorporates several of their best extraction heuristics directly into `scrape.ts` and `internal/extract`!
