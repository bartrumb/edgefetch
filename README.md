# EdgeFetch

[![CI](https://github.com/bartrumb/edgefetch/actions/workflows/ci.yml/badge.svg)](https://github.com/bartrumb/edgefetch/actions/workflows/ci.yml)
[![Go 1.26+](https://img.shields.io/badge/Go-1.26%2B-00ADD8?logo=go)](go.mod)
[![Worker, SDKs & Adapters: MIT](https://img.shields.io/badge/Worker%2C%20SDKs%20%26%20Adapters-MIT-blue.svg)](LICENSE)
[![Hub: FSL-1.1-MIT](https://img.shields.io/badge/Hub-FSL--1.1--MIT%20(Fair%20Source)-0ea5e9.svg)](hub/LICENSE)

**EdgeFetch** turns URLs into clean Markdown and structured JSON for AI agents via CLI, `stdio` MCP, or HTTP — combining an **open-source worker, SDKs, and adapters ([MIT](LICENSE)), fair-source hub ([FSL-1.1](hub/LICENSE), `MIT` after two years)**. The worker and CLI ship as a single static Go binary with `1` external Go dependency ([`github.com/coder/websocket`](go.mod)), enforce `robots.txt` (RFC 9309) and `Content-Signal: ai-input` on every hop including redirects, stop immediately on the first CAPTCHA or anti-bot challenge, and pair with `56` readable declarative YAML site adapters in [`internal/extract/manifests/`](internal/extract/manifests) targeting public APIs, feeds, and pages.

> Polite by default: enforces `robots.txt` and `Content-Signal` on every hop, identifies itself honestly (with optional RFC 9421 Web Bot Auth signatures), stops on anti-bot challenges instead of bypassing them, and makes **zero** background telemetry or update-check calls unless explicitly opted in (`DO_NOT_TRACK=1` hard-disables both).

## Quick Start

### 1. Standalone Go Binary (`CLI` & Local `stdio` MCP — Zero Containers, Zero Open Ports)

```bash
# macOS / Linux (Homebrew) or Go 1.26+:
brew install bartrumb/tap/edgefetch
# or: go install github.com/bartrumb/edgefetch/v2/cmd/edgefetch@latest

# Scrape any robots.txt-allowed URL to clean Markdown or structured JSON:
edgefetch scrape https://go.dev/doc/effective_go
edgefetch scrape --json --query="concurrency" https://go.dev/doc/effective_go

# Or wire local stdio MCP into Claude Code, Claude Desktop, Cursor, Windsurf, Gemini CLI, or Codex:
edgefetch init && edgefetch doctor
```

Both `edgefetch scrape` and `edgefetch mcp` make **zero** background telemetry or update-check network calls by default (`EDGEFETCH_DEV_TELEMETRY` and `EDGEFETCH_CHECK_UPDATES` are strictly opt-in, and `DO_NOT_TRACK=1` hard-disables them).

### 2. Self-Hosted Docker (`docker compose up -d` — Zero Cloud Account, No Redis or Postgres)

```bash
git clone https://github.com/bartrumb/edgefetch.git && cd edgefetch
export CALLER_TOKEN="$(openssl rand -hex 24)" \
       AGENT_TOKEN="$(openssl rand -hex 24)" \
       VAULT_MASTER_KEY="$(openssl rand -hex 24)"
docker compose up --build -d
# Open http://127.0.0.1:8787/admin and sign in with $CALLER_TOKEN
```

### 3. Optional Cloud & Home Assistant Deployments

<p>
  <a href="https://deploy.workers.cloudflare.com/?url=https://github.com/bartrumb/edgefetch/tree/main/hub">
    <img src="https://deploy.workers.cloudflare.com/button" alt="Deploy to Cloudflare" height="34">
  </a>
  &nbsp;
  <a href="https://render.com/deploy?repo=https://github.com/bartrumb/edgefetch">
    <img src="https://render.com/images/deploy-to-render-button.svg" alt="Deploy to Render" height="34">
  </a>
  &nbsp;
  <a href="https://railway.com/new/github/bartrumb/edgefetch">
    <img src="https://railway.com/button.svg" alt="Deploy on Railway" height="34">
  </a>
  &nbsp;
  <a href="https://console.deno.com/new?clone=https://github.com/bartrumb/edgefetch&entrypoint=hub/portable/deno-server.ts">
    <img src="https://deno.com/button" alt="Deploy on Deno" height="34">
  </a>
  &nbsp;
  <a href="https://my.home-assistant.io/redirect/supervisor_add_addon_repository/?repository_url=https%3A%2F%2Fgithub.com%2Fbartrumb%2Fedgefetch">
    <img src="https://my.home-assistant.io/badges/supervisor_add_addon_repository.svg" alt="Add EdgeFetch Repository to Home Assistant" height="34">
  </a>
</p>

---

## Core Design & Reproducible Properties

- **Single-dependency Go data plane (`cmd/`, `internal/`):** `go list -m all` lists `1` external Go module (`github.com/coder/websocket`, `0` transitive dependencies, `CGO_ENABLED=0`). Handles HTTP/2 fetching, RFC 9309 `robots.txt` + `Content-Signal` checks, dial-time SSRF socket verification, streaming PDF parsing, local `stdio` MCP (`edgefetch mcp`), and standalone Go Hub mode (`edgefetch --mode=hub`).
- **Dial-time SSRF & browser subresource isolation:** `politeness.RejectNonPublicPeer` inspects resolved peer IPs inside Go's `net.Dialer.Control` immediately before `connect()` (blocking DNS-rebinding TOCTOU against RFC 1918 LANs, loopback, CGNAT/Tailscale `100.64.0.0/10`, and `169.254.169.254`), while headless Chromium subresources are forced through an in-process loopback `CONNECT` proxy (`--host-resolver-rules="MAP * ~NOTFOUND , EXCLUDE 127.0.0.1"`).
- **Your own hardware, never a shared proxy pool:** Outbound workers (`edgefetch --mode=agent`) dial *only* your own Hub URL using your private `AGENT_TOKEN` over TLS WebSockets (`WSS /agent/ws`), opening zero inbound ports on your LAN. Outbound requests originate from your worker's WAN IP (or Cloudflare's edge when using overflow) and serialize per host with `Retry-After` compliance.
- **56 readable YAML site adapters ([`internal/extract/manifests/`](internal/extract/manifests)):** Pure-data YAML manifests (`MIT`) upgrade noisy HTML pages to public JSON/XML endpoints, registries, ATS job boards (Greenhouse, Ashby, Lever, Workday CXS), and structured HTML selectors while enforcing `robots.txt` on every hop and failing open to standard HTML extraction if an upstream schema changes. When a site blocks automated access via `robots.txt` or an anti-bot challenge, EdgeFetch stops immediately and returns a structured `blocked.suggestion` pointing to official public APIs or feeds.
- **Optional Hub coordinator (`hub/`):** For multi-node fleets, remote HTTP `/mcp`, FTS5 search collections, encrypted downstream MCP connector credentials (`AES-256-GCM` via WebCrypto `HKDF-SHA256`), and optional BYO-LLM `/v1/agent` workflows, the Hub runs on Cloudflare Workers (Hibernating Durable Objects + D1 + R2) or self-hosted `node:sqlite` (`dist/portable-server.mjs`) with `6` runtime npm packages in [`hub/package.json`](hub/package.json) (`htmlparser2`, `jose`, `oauth4webapi`, `re2js`, `ws`, `yaml`). Multi-user GitHub OAuth sign-in is disabled by default until explicitly configured by the operator.

<p align="center">
  <img src="docs/assets/admin-console.jpg" alt="EdgeFetch /admin Web Control Center" width="880">
</p>

---

## Built by AI, for AI — How Changes Are Controlled

EdgeFetch was built with coding agents and hardened across 8 adversarial security review rounds (using independent LLM reviewers paired with executed local proof-of-concept exploits). Rather than hiding AI authorship, the repository enforces hard privilege boundaries between declarative site rules and privileged engine code:

- **Ring 1 — Declarative YAML Site Adapters ([`internal/extract/manifests/*.yaml`](internal/extract/manifests)):** Pure data with zero executable TypeScript/Go code, zero `eval`, and linear `re2js` regular expressions. Every manifest compiles through a single strict schema compiler ([`compile-manifests.mjs`](hub/scripts/compile-manifests.mjs)), which enforces domain pattern validation, prevents wildcard/subdomain overlap, and rejects unapproved cross-domain `fetchUrl` hosts.
- **Ring 0 — Core Engine, Auth, Vault, Sanitizer & SSRF (`cmd/`, `internal/`, `hub/src/`, `.github/`):** Protected by human-approved merges, immutable `v*` tag rulesets, and a human-gated GitHub `release` environment before Ed25519 binary signing (`keys/release-signing-pub.pem`). Real sanitizer differentials, auth edge cases, ReDoS vectors, and SSRF bypasses caught and fixed across Rounds 1–8 are documented candidly in **[docs/SECURITY-LOG.md](docs/SECURITY-LOG.md)**.
- **Contributor model:** EdgeFetch is a maintainer-driven system. **Issues, reproducible bug reports, WAF false-positive samples, and adapter requests are welcome; code pull requests are by invitation ([`.github/VOUCHED.td`](.github/VOUCHED.td))** so untrusted inputs never steer privileged workflows. See **[CONTRIBUTING.md](CONTRIBUTING.md)**.

---

## Comparison vs. Other AI Web Crawlers & MCP Servers

Full architectural breakdown & trade-offs (including when *not* to use EdgeFetch): **[docs/COMPARISON.md](docs/COMPARISON.md)** · FAQ: **[docs/LAUNCH-FAQ.md](docs/LAUNCH-FAQ.md)**

| Dimension | **EdgeFetch (`v2.7.6`)** | **Firecrawl (Self-Hosted)** | **Firecrawl / Tavily (Cloud)** | **Crawl4AI** | **Jina Reader** |
|---|---|---|---|---|---|
| **License** | **Open-source worker, SDKs, and adapters (`MIT`), fair-source hub (`FSL-1.1`, `MIT` after two years)** | AGPL-3.0 (core) | Proprietary SaaS | Apache-2.0 (+ attribution) | Apache-2.0 |
| **Minimum Self-Hosted Stack** | **1 `~8 MB` Go binary** *or* **1 container** (`node:sqlite` + `/data`, no Redis or Postgres) | Docker Compose + Redis + PostgreSQL + RabbitMQ + Playwright (`2–4 GB+` RAM) | Cloud API key | Python 3.10+ + Playwright (`600 MB–1.5 GB` RAM) | Node.js + Puppeteer |
| **Worker Supply Chain** | **`1` Go module (`github.com/coder/websocket`, `0` transitive deps)** | Dozens of npm + OS packages | Vendor SaaS | 40+ PyPI packages | Dozens of npm packages |
| **Outbound Home/Edge Workers (`WSS`)** | **Yes — dials your own Hub with `0` open inbound ports** | Needs inbound ports, VPN, or proxy service | Managed proxy credits | Single-host or DIY queue | No |
| **Local `stdio` MCP (`edgefetch mcp`)** | **Yes — `~8 MB` binary, `0` background telemetry, uses installed OS Chrome/Edge/Brave if needed** | `npx` + cloud key or full Docker stack | Cloud API key required | Python + Playwright setup | Cloud URL or Node server |
| **SSRF & Browser Subresource Guard** | **Dial-time `RejectNonPublicPeer` + loopback `CONNECT` `SSRFProxy` (`MAP * ~NOTFOUND`)** | Application URL blocklist | Vendor-managed | Optional / app-level | App-level |
| **Anti-Bot / CAPTCHA Policy** | **Enforces `robots.txt` on every hop; stops on first challenge** | Paid cloud stealth/proxy escalation | Vendor-managed | Optional stealth plugins | Headless fallback |
| **Typical Cost (50k scrapes + 5k searches / mo)¹** | **`$0 – $5 / mo`** (Cloudflare Hibernating DO + own worker + SearXNG) | `$25 – $80+ / mo` (VPS + proxy GBs) | `$49 – $130+ / mo` | `$10 – $40+ / mo` (VPS + proxies) | Credit-metered |

*¹ Compares Cloudflare Workers Free (`$0`) or Paid (`$5/mo`) within R2 (`10 GB`) and D1 (`5 GB`) monthly allowances plus self-hosted SearXNG (`$0` on existing hardware) against published Firecrawl Standard (`$19–$99/mo`) + Tavily Researcher (`$30+/mo`) plans.*

---

## Deployment Options

### Option A: Standalone Docker Workers (Browser-Capable vs. Distroless Lite)

Multi-arch OCI images (`linux/amd64` + `linux/arm64`) run as non-root `65532:65532`:

```bash
# Browser-capable worker (Go HTTP/2 + sandboxed Headless Chromium + Poppler PDF):
docker run -d --name edgefetch-agent --restart=unless-stopped \
  --security-opt no-new-privileges:true \
  --security-opt seccomp=./deploy/seccomp/chromium-sandbox.json \
  -e EDGEFETCH_HUB_URL=https://<your-hub-domain> \
  -e EDGEFETCH_AGENT_TOKEN="<YOUR_AGENT_TOKEN>" \
  -e EDGEFETCH_SITE_ID="node-1" \
  ghcr.io/bartrumb/edgefetch-agent:2.7.6

# Distroless Lite worker (~9 MB image, HTTP/2 + Markdown + pure-Go PDF, ~15 MiB RAM):
docker run -d --name edgefetch-lite --restart=unless-stopped --read-only \
  -e EDGEFETCH_HUB_URL=https://<your-hub-domain> \
  -e EDGEFETCH_AGENT_TOKEN="<YOUR_AGENT_TOKEN>" \
  -e EDGEFETCH_SITE_ID="lite-1" \
  ghcr.io/bartrumb/edgefetch-agent:lite --mode=agent
```

On Linux, Chromium namespace sandboxing is probed at startup and **fails closed** unless run with [`deploy/seccomp/chromium-sandbox.json`](deploy/seccomp/chromium-sandbox.json) (rather than silently falling back to `--no-sandbox`).

### Option B: Home Assistant OS Add-on (`addon/`)

Install from the Home Assistant Add-on Store button above (`slug: "edgefetch"`, images `ghcr.io/bartrumb/edgefetch-addon-{arch}` for `amd64` and `aarch64`), set `hub_url`, `agent_token`, and `site_id`, and start the add-on. **Home Assistant Protection Mode stays ON** (`hassio_api: false`, `homeassistant_api: false`, `host_network: false`); heavy headless browser rendering is delegated cleanly to sandboxed Docker (`edgefetch-agent:2.7.6` with `chromium-sandbox.json`) or native desktop/VM worker nodes in your fleet.

> **Upgrading from pre-`v2.7.2` (`EdgeFetch Fat`):** In `v2.7.2`, the Home Assistant add-on slug changed from `edgefetch_fat` to `edgefetch`. Because Home Assistant Supervisor keys installed add-ons by slug, existing pre-`v2.7.2` users should open **Settings → Add-ons → Add-on Store**, click **⋮ → Check for updates**, install **EdgeFetch**, copy over `hub_url`, `agent_token`, and `site_id`, start **EdgeFetch**, and uninstall the retired *EdgeFetch Fat* entry.

### Option C: CLI, Ed25519 Self-Updater & Pure-Go Hub

```bash
# Configure local stdio MCP for desktop coding agents:
edgefetch install-mcp

# Manually check or apply Ed25519-verified release updates (never runs automatically unless opted in):
edgefetch update --check

# Mint an optional IETF RFC 9421 Ed25519 Web Bot Auth keypair for your Hub:
edgefetch keygen-bot-auth

# Or run a standalone pure-Go Hub + /v1/scrape + /mcp server on any small VPS:
EDGEFETCH_CALLER_TOKEN="<32-char-secret>" EDGEFETCH_AGENT_TOKEN="<32-char-secret>" \
  edgefetch --mode=hub --addr=0.0.0.0:8080
```

---

## Reproducible Benchmarks

Anyone with Node.js 22+ (`cd hub && npm ci`) or Go 1.26+ can reproduce both extraction fidelity and hot-path benchmarks locally in under 3 seconds with zero API keys or running servers:

```bash
# 1. Multi-format synthetic regression gate (HTML, .ipynb, OpenAPI 3.1, YAML frontmatter):
node bench/run-bench.mjs

# 2. Go hot-path microbenchmarks:
go test -bench=. -benchmem ./...
```

| Go Benchmark (`go test -bench=. -benchmem ./...`) | Latency | Heap Allocations |
|---|---:|---:|
| `BenchmarkParseRetryAfter` | `4.45 ns/op` | `0 B/op` (`0 allocs/op`) |
| `BenchmarkRobotsMatch` (`*` wildcards + `$` anchor) | `52.17 ns/op` | `0 B/op` (`0 allocs/op`) |
| `BenchmarkIsPublicIP` (IPv4 + NAT64 IPv6 check) | `155.50 ns/op` | `0 B/op` (`0 allocs/op`) |
| `BenchmarkClassifyFeedJSON` | `1,229 ns/op` | `1,416 B/op` (`28 allocs/op`) |

Full extraction benchmark tables: **[bench/RESULTS.md](bench/RESULTS.md)**.

---

## Documentation

- **Security Bug & Adversarial Audit Log (Rounds 1–8):** **[docs/SECURITY-LOG.md](docs/SECURITY-LOG.md)**
- **Security Policy, Threat Model & SSRF Controls:** **[SECURITY.md](SECURITY.md)**
- **Launch & Design Trade-Off FAQ:** **[docs/LAUNCH-FAQ.md](docs/LAUNCH-FAQ.md)**
- **Detailed Comparison & When Not to Use EdgeFetch:** **[docs/COMPARISON.md](docs/COMPARISON.md)**
- **Extraction & Token-Efficiency Benchmarks:** **[bench/RESULTS.md](bench/RESULTS.md)**
- **Declarative YAML Site Adapter Guide (`56` manifests):** **[docs/ADAPTERS.md](docs/ADAPTERS.md)**
- **Operations, OTLP Tracing, HA Mesh & MCP Reference:** **[docs/USAGE.md](docs/USAGE.md)**
- **Hub ↔ Go Worker Wire Protocol:** **[docs/PROTOCOL.md](docs/PROTOCOL.md)**
- **Go Concurrency & Internals:** **[docs/INTERNALS.md](docs/INTERNALS.md)**
- **Bot, WAF & MCP Registry Guide:** **[docs/REGISTRATION.md](docs/REGISTRATION.md)**
- **Contributing Policy & Vouch Gate:** **[CONTRIBUTING.md](CONTRIBUTING.md)** · **[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)**

## License & Trademarks

EdgeFetch uses an **open-source worker, SDKs, and adapters (`MIT`), fair-source hub (`FSL-1.1`, `MIT` after two years)** license split:

- **Open-Source Worker, CLI, SDKs & All Site Adapters (`cmd/`, `internal/`, `sdk/`, `extensions/`, `internal/extract/manifests/`, `hub/src/extractors/`):** **[MIT](LICENSE)** (and [`hub/src/extractors/LICENSE`](hub/src/extractors/LICENSE)).
- **Fair-Source Hub (`hub/`, excluding `hub/src/extractors/`):** **[FSL-1.1-MIT](hub/LICENSE)** (*Functional Source License 1.1, MIT after two years*) — free to read, modify, and self-host personally or internally within your organization; third parties may not offer the Hub as a competing commercial hosted/managed service, and each release converts to `MIT` two years after publication.
- **Contributions:** Inbound = `MIT` + DCO sign-off (`git commit -s`), per **[CONTRIBUTING.md](CONTRIBUTING.md)**.

**Trademarks:** **EdgeFetch™** and the EdgeFetch raven logo are trademarks of Brett Bartrum. Neither the MIT License nor the Functional Source License grants permission to use the EdgeFetch name, `edgefetch.dev` domain, or project logos to brand, endorse, or market a third-party product or hosted service.
