# EdgeFetch Operations, C&C Protocol, Tuning, `/admin` & MCP Guide

## 1. Security Boundary: Hub vs. Edge Nodes

EdgeFetch strictly separates **coordination/control** from **edge execution**:

- **Cloudflare Hub (`hub/`):** The **only** public HTTPS surface. Hosts the Web Control Center (`/admin`), the Stateless Streamable HTTP MCP server (`/mcp`), Self-Hosted OAuth 2.1 (`/.well-known/*`, `/oauth/*`), the REST API (`POST /fetch`, `GET /agents`), and the Hibernating WebSocket coordinator (`GET /agent/ws`, `POST /agent/reply`).
- **Edge Nodes (Home Assistant OS / Docker Go binary):** Host **zero** inbound ports, **zero** `/admin` UI, and **zero** `/mcp` server. Edge nodes drop root privileges (`65532:65532`), dial outbound `wss://` to `GET /agent/ws`, and only execute polite `https://:443` public fetches dispatched by their configured Hub.

---

## 2. How the Outbound C&C Lifecycle Works

```mermaid
sequenceDiagram
    participant Caller as Caller / Admin UI / Claude Code MCP
    participant Hub as Cloudflare Hub Worker + AgentHubDO (SQLite)
    participant Edge as Home Assistant OS Edge Node (Go)
    participant Origin as Public HTTPS Target (:443)

    Edge->>Hub: 1. Outbound WSS Upgrade GET /agent/ws (Bearer AGENT_TOKEN)
    Hub-->>Edge: 101 Switching Protocols + {"type":"hello","siteId":"site-arm64"}
    Edge->>Hub: {"type":"agent_hello","arch":"arm64","goVersion":"go1.25"}
    loop Every 30s while idle (~$0 DO cost)
        Edge->>Hub: "ping"
        Note over Hub: Cloudflare Edge Auto-Response ("pong") — 0 DO wakeups!
        Hub-->>Edge: "pong"
    end
    Caller->>Hub: 2. POST /fetch or MCP fetch_url (target=auto)
    Note over Hub: Load-balance across healthy remote nodes by LRU (skipping any 429-cooled-down site)
    Hub->>Edge: {"type":"dispatch","jobId":"...","jobNonce":"...","call":{...}}
    Edge->>Origin: 3. Polite HTTP/2 GET (robots.txt + RejectNonPublicPeer SSRF guard)
    Origin-->>Edge: 200 OK + httptrace (dnsMs, connectMs, tlsMs, ttfbMs)
    Edge->>Hub: 4. POST /agent/reply (gzip FetchReply + X-Job-Id + X-Job-Nonce)
    Hub-->>Caller: 200 OK (x-crawler-via: agent:site-arm64) + OTel Span & Logs
```

### LRU Load-Balancing + 429-Only Cloudflare Overflow
- **Even Load-Balancing Across Remote Nodes (Tier 1 Primary):** `AgentHubDO` orders connected remote nodes (`site-arm64`, `site-win-vm`, `site-x86`) by `lastJobAt` ascending (Least-Recently-Used), rotating sequential requests evenly across all sites and sharding multi-URL batches in parallel across all healthy sites.
- **Per-Site `429` Cooldowns + Peer Failover:** If one remote node receives HTTP `429`, `AgentHubDO` places `(host, siteId)` into cooldown in SQLite (`site_cooldowns`, honoring `Retry-After` or defaulting to 5 minutes) and retries across remaining non-429 remote nodes first.
- **Cloudflare Overflow ONLY on `429` (Tier 2 Fallback):** Cloudflare egress (`CrawlerContainer` or Worker `fetch`) stays asleep during normal operation and is invoked in `target=auto` **only** if remote nodes hit HTTP `429` (or if zero remote nodes are connected). Responses like `200`, `304`, `403`, `404`, `503`, and `cf-mitigated` challenges never wake Cloudflare.

---

## 3. Two-Tier Politeness & Tuning Reference

EdgeFetch uses a **two-tier tuning model** so upstream callers can tune crawls per job without ever overriding an edge node's local safety floor:

### Tier A — Edge Node Local Safety Floor (Home Assistant Add-on UI / Env)

| Option / Env | Default | Behavior |
|---|---|---|
| `pause_ms` (`EDGEFETCH_PAUSE_MS`) | `1500` | **Hard minimum** per-host delay in ms. Upstream calls requesting a smaller `pauseMs` are clamped up to this floor. |
| `pause_jitter_ms` (`EDGEFETCH_PAUSE_JITTER_MS`) | `750` | **Hard minimum** random positive jitter (`[0, jitter)`) added to `pause_ms` on every fetch. |
| `allowed_hosts` (`EDGEFETCH_ALLOWED_HOSTS`) | `[]` (all public HTTPS) | Optional domain suffix allowlist (e.g. `example.com` permits `example.com` and `*.example.com`). Regardless of this list, `RejectNonPublicPeer` **always** blocks RFC 1918 LANs, loopback, Tailscale `100.64/10`, cloud metadata, and NAT64/6to4/Teredo IPv6 ranges at dial time. |
| `Concurrency` | Fixed `1` on agents | Edge nodes always serialize outbound jobs (`Concurrency = 1`) to protect residential upload bandwidth. |

### Tier B — Per-Call Request & Tuning Schema (`POST /fetch`)

- `POST https://<your-hub>.workers.dev/fetch` — auto-selects sticky/LRU site
- `POST https://<your-hub>.workers.dev/fetch?site=site-arm64` — pins a specific standby site

```bash
curl -X POST "https://<your-hub>.workers.dev/fetch?site=site-arm64" \
  -H "Authorization: Bearer $CALLER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "maxSeconds": 60,
    "options": {
      "includeBody": true,
      "robots": true,
      "pauseMs": 2000,
      "pauseJitterMs": 1000,
      "gapMs": 2000,
      "timeoutMs": 30000,
      "maxBytes": 8388608,
      "retries": 1
    },
    "requests": [
      {
        "id": "feed-1",
        "url": "https://example.com/feed.json",
        "kind": "feed",
        "ifNoneMatch": "\"etag-from-previous-run\""
      }
    ]
  }'
```

| Field | Default / Max | Description |
|---|---|---|
| `requests[].kind` | `"feed"` \| `"page"` | `"feed"` sends `Accept: application/json` and validates JSON structure; `"page"` sends `Accept: text/html,application/xhtml+xml`. |
| `requests[].ifNoneMatch` / `ifModifiedSince` | optional | Conditional `304 Not Modified` headers — saves bandwidth when upstream content hasn't changed. |
| `options.includeBody` | `false` | Set `true` to return the response UTF-8 body string alongside status/headers/timing. |
| `options.robots` | `false` (`true` via MCP/Admin) | Fetches & caches `/robots.txt` per host for 24h (`Allow`/`Disallow` longest-match + `Crawl-delay`). |
| `options.maxBytes` | `8 MiB` (max `16 MiB`) | Streaming body cap via `io.LimitReader(maxBytes + 1)`. Oversized responses stop immediately with `truncated: true`. |
| `options.retries` | `0` (max `3`) | Retries **only** transport/500/502/504 errors with exponential jitter. `403`, `429`, `503`, and challenges are **never** retried. |

---

## 4. Built-in Web Control Center (`/admin`)

Open `https://<your-hub>.workers.dev/admin` in any browser and sign in with your `CALLER_TOKEN`:

- **Session Security:** Uses an 8-hour HMAC-SHA256 `HttpOnly; Secure; SameSite=Lax` cookie, per-session CSRF token (`x-csrf-token`), strict CSP (`frame-ancestors 'none'`), and SQLite brute-force rate limiting (`5` failures / `5m` -> `429`).
- **Capabilities:**
  1. **Live Standby Fleet Cards:** Real-time connected sites, CPU architecture (`amd64` / `arm64`), uptime, last job time, and `jobsOk` / `jobsErr` counters (auto-refreshing every 10s).
  2. **Interactive Crawl & Tuning Runner:** Test any `https://` URL across `feed`/`page`, pin a specific site, tune `pauseMs` / `pauseJitterMs` / `robots`, and inspect a visual **DNS / TCP / TLS / TTFB** waterfall bar + JSON reply.
  3. **15-Minute Host-Sticky Affinity Table:** View every currently pinned origin domain (`host -> siteId`, remaining TTL) and clear pins with one click.
  4. **Active OAuth 2.1 MCP Grants:** Inspect connected Claude Code / MCP clients and revoke any session immediately.

---

## 5. Connecting Claude Code via Self-Hosted OAuth 2.1 MCP (`/mcp`)

`hub/` hosts a complete, zero-external-IdP **OAuth 2.1 + PKCE (`S256`) + Dynamic Client Registration (RFC 7591)** server backed directly by `AgentHubDO` SQLite (requiring **zero** separate KV namespaces or third-party auth providers):

- `GET /.well-known/oauth-protected-resource` (RFC 9728 Protected Resource Metadata)
- `GET /.well-known/oauth-authorization-server` (RFC 8414 Authorization Server Metadata)
- `POST /oauth/register` (RFC 7591 Dynamic Client Registration — strictly restricted to loopback `http://localhost` / `127.0.0.1` or external `https://` callbacks)
- `GET` / `POST /oauth/authorize` (Confused-deputy-safe consent screen displaying exact callback host + requested scopes)
- `POST /oauth/token` & `POST /oauth/revoke` (Single-use 90s auth codes, constant-time PKCE `S256`, 1h access tokens, rotating 30d refresh tokens)

### Add Directly to Claude Code

```bash
claude mcp add --transport http edgefetch https://<your-hub>.workers.dev/mcp
```

When Claude Code connects for the first time, it discovers `/.well-known/oauth-protected-resource`, registers dynamically, and opens your browser to `/oauth/authorize`. Paste your `CALLER_TOKEN` once (or click **Approve** immediately if already signed into `/admin`) — **no raw bearer tokens are ever saved in `.claude.json` or shell history**.

### Exposed MCP Tools

| Tool | Required Scope | Description |
|---|---|---|
| `list_agents` | `crawl:read` | Lists connected standby agents (`siteId`, `arch`, `jobsOk`, `jobsErr`) and active 15m domain-affinity pins. |
| `fetch_url` | `crawl:fetch` | Politely fetches a single public `https://` URL (`feed` or `page`, optional `site` pin, `robots`, `ifNoneMatch`) with full phase timing + body preview. |
| `fetch_batch` | `crawl:fetch` | Politely fetches up to 25 public `https://` URLs with configurable `pauseMs` and `pauseJitterMs`. |

*(Direct machine-to-machine MCP clients may also pass `Authorization: Bearer $CALLER_TOKEN` on `POST /mcp`.)*

---

## 6. Single-Pane-of-Glass Observability (Cloudflare Logs & Traces)

`hub/wrangler.toml` enables both `[observability.logs]` and `[observability.traces]` at `100%` sampling:

1. Open **Cloudflare Dashboard -> Workers & Pages -> `edgefetch-hub` -> Observability**.
2. **Traces tab:** Inspect end-to-end `edgefetch.dispatch` / `crawler.fetch` spans tagged with `edgefetch.site` / `crawler.via` and HTTP status codes.
3. **Logs tab:** Query structured JSON events (`agent_ready`, `agent_reconnected`, `fetch_forwarded`, `agent_failover`) across every connected edge site in one place.
