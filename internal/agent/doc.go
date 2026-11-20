// Package agent implements the outbound-only WebSocket worker loop connecting EdgeFetch standby nodes
// (Docker containers, Home Assistant OS add-ons, Raspberry Pis, or bare-metal binaries) to Cloudflare's
// Hibernating WebSocket Durable Object (AgentHubDO).
//
// # Architecture & Security Invariants
//
//   - Zero inbound ports: nodes initiate outbound TLS 1.3 WebSockets (`wss://<hub>/agent/ws`) authenticated via
//     `Authorization: Bearer <agent_token>` (>= 24 characters) and self-identify capabilities (`http2-v1`,
//     `scrape-v2`, `llms-v1`, `browser-v1`, `interact-v1`, `pdf-v1`) via `X-Agent-*` headers and `agent_hello`.
//   - Hibernation keepalive: sends lightweight `"ping"` text frames so Cloudflare's edge answers `"pong"` via
//     `setWebSocketAutoResponse` at $0 Durable Object wall-clock duration cost while idle.
//   - Out-of-band R2 streaming: when `artifacts.mode == "r2"`, response bodies are gzipped, SHA-256 hashed, and
//     uploaded directly via `PUT /agent/artifacts/:blobSha256` before the metadata envelope is sent to
//     `POST /agent/reply`, preventing multi-megabyte payloads from passing through Durable Object memory.
//   - Graceful SIGTERM drain: active jobs continue up to `ShutdownDrain` (default 25s) before container exit.
package agent
