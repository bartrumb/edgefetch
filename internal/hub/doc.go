// Package hub implements EdgeFetch's self-hosted Go multi-node WebSocket controller (`--mode=hub` and
// hybrid mesh `--mode=hub,agent`), allowing one static Go binary to serve as both central fleet coordinator
// and fallback HTTP/2 + Chromium worker with zero external runtime dependencies beyond `coder/websocket`.
//
// # Capabilities
//
//   - Accepts outbound Go worker connections on `GET /agent/ws` (authenticated via `EDGEFETCH_AGENT_TOKEN` or
//     per-site `EDGEFETCH_AGENT_TOKENS`), streaming gzipped artifacts on `PUT /agent/artifacts/{sha}` and
//     job completions on `POST /agent/reply`.
//   - Routes requests across connected nodes using sticky host affinity, Least-Recently-Used (`lastJobAt`)
//     fairness, capability matching (`browser-v1`), and per-`(site, host)` `429` cooldown failover, falling
//     back automatically to the local in-process `*crawl.Crawler` when no remote agents are available.
//   - Exposes `GET /health`, `GET /agents`, `GET /v1/capabilities`, `POST /fetch`, `POST /v1/scrape`, and a
//     built-in Streamable HTTP Model Context Protocol server on `POST /mcp`.
//   - When paired with `--mode=hub,agent` and `EDGEFETCH_HUB_URLS`, enables active-active multi-controller
//     and Tailscale/LAN standby mesh topologies.
package hub
