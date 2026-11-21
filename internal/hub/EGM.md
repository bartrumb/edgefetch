# hub

## Overview
Package `hub` implements EdgeFetch's self-hosted multi-node WebSocket controller and hybrid local-fallback HTTP/MCP server, coordinating outbound standby agents, single-hop peer hubs, sticky host affinity, bounded in-memory artifact hydration, Firecrawl-compatible scrape/map endpoints, and Streamable HTTP Model Context Protocol (`POST /mcp`).

## Interface
- `[hub.go:Config]`, `[hub.go:AgentInfo]`, `[hub.go:Server]`, `[hub.go:NewServer]`, `[hub.go:Server.Close]`: Hub configuration and `http.Handler` server lifecycle (`Close` sends `websocket.StatusGoingAway` to connected agents).
- `[hub.go:ParseAgentTokensJSON]`: `func ParseAgentTokensJSON(raw string) (map[string]string, error)` — parses `EDGEFETCH_AGENT_TOKENS` per-site token map.
- `[hub.go:Server.ListAgents]`, `[hub.go:Server.DispatchOrFallback]`: Inspect connected worker fleet (`connected`, `distinctPublicIps`, `agents`) and dispatch `crawl.FetchCall` across remote agents (`agent:<siteID>`), 1-hop peers (`peer:<host>`), or `FallbackCrawler` (`local-hub` / `hub`).
- `[hub.go:Server.ServeHTTP]`, `[hub.go:Server.handleBotTransparencyRoutes]`: Unauthenticated routes `GET /health`, `GET /healthz`, `GET|HEAD /.well-known/http-message-signatures-directory`, and `GET|HEAD /.well-known/edgefetch-bot.json`.
- `[hub.go:Server.handleAgentWS]`, `[hub.go:Server.handleAgentArtifactPut]`, `[hub.go:Server.handleAgentReply]`: Agent control/data-plane routes `GET /agent/ws`, `PUT /agent/artifacts/{sha}`, and `POST /agent/reply`.
- `[hub.go:Server.ServeHTTP]`, `[hub.go:Server.handleCallerFetch]`, `[hub.go:Server.handleCallerScrape]`, `[hub.go:Server.handleFirecrawlV2Scrape]`, `[hub.go:Server.handleCallerMap]`, `[hub.go:Server.serveDesktopLaunchpad]`: Caller-plane routes `GET /` (tokenless loopback launchpad only), `GET /agents`, `GET /v1/capabilities`, `POST /fetch`, `POST /v1/scrape`, `POST /v2/scrape`, `POST /compat/firecrawl/v2/scrape`, `POST /v1/map`, `POST /v2/map`, and `POST /compat/firecrawl/v2/map`.
- `[hub.go:Server.handleMCP]`: Streamable HTTP JSON-RPC 2.0 MCP endpoint on `POST /mcp` (`protocolVersion: "2025-03-26"`, methods `initialize`, `ping`, `notifications/initialized`, `notifications/cancelled`, `tools/list`, and `tools/call` for `list_agents`, `scrape`, and `fetch_url`).

## Invariants
- `[hub.go:Server.authorizeAgent]`, `[hub.go:ParseAgentTokensJSON]`, `[hub.go:reSiteID]`: Requires `siteID` matching `^[a-z0-9][a-z0-9_-]{0,31}$` and agent tokens `>= agent.MinTokenLength` (`24`) verified via `constantTimeEquals`; maintains at most one active WebSocket session per `siteID` (`1 MiB` frame cap, compression disabled).
- `[hub.go:Server.isCallerAuthorized]`, `[hub.go:Server.validateTokenlessLoopbackRequest]`, `[hub.go:Server.withCallerConcurrencyGate]`: Requires constant-time Bearer/`X-Api-Key` match when `CallerToken != ""`; when `CallerToken == ""`, restricts requests to loopback `Host` (`127.0.0.1`, `localhost`, `[::1]` matching `AllowedLoopbackPort`), non-`cross-site` `Sec-Fetch-Site`, loopback `Origin`, and `Content-Type: application/json*` on mutating methods; gates work routes with non-blocking semaphore `callSem` (default `8`, `503` on overflow).
- `[hub.go:Server.handleAgentArtifactPut]`, `[hub.go:Server.storeBlob]`, `[hub.go:Server.handleAgentReply]`: Validates active pending `(jobID, jobNonce, siteID)` ownership, caps per-job artifact uploads at `32` (`sha256(gzBytes) == blobSHA`, `<= crawl.MaxMaxBytes`), bounds total in-memory blob storage at `MaxArtifactMemory` (default `64 MiB`, FIFO eviction), claims `replyClaimed` atomically (`<= 20 MiB` gzip / `<= 32 MiB` decoded JSON), overwrites `Result.ID`/`Result.URL` from `dispatchedReqs`, clamps `RetryAfterMs <= 120000`, and zeroes unverified `Result.Artifact` refs.
- `[hub.go:Server.DispatchOrFallback]`, `[hub.go:Server.pickAgent]`, `[hub.go:Server.tryPeerHandoff]`: Tries up to `3` distinct idle agents matching `browser-v1` capability when required (preferring `10m` sticky host affinity then LRU `lastJobAt`), prevents peer loops via `X-EdgeFetch-Peer-Hop: 1`, and rejects non-HTTPS peer URLs unless loopback `http://`.
- `[hub.go:Server.executeScrape]`, `[hub.go:Server.handleCallerMap]`, `[hub.go:Server.handleMCP]`: Enforces `s.allow` SSRF checks across `/fetch`, scrape, map, and MCP `fetch_url` inputs, caps `/mcp` POST bodies at `256 KiB`, and sets `Cache-Control: no-store` on caller JSON/HTML responses.

## Side Effects
- `[hub.go:Server.handleAgentWS]`, `[hub.go:Server.dispatchToSession]`, `[hub.go:Server.Close]`: Upgrades inbound agent WebSockets, exchanges `hello`/`ping`/`pong`/`dispatch` frames, reads `crypto/rand.Read` for `jobID`/`jobNonce`, and closes superseded or shutting-down sockets.
- `[hub.go:Server.storeBlob]`, `[hub.go:Server.completePending]`, `[hub.go:Server.pickAgent]`: Mutates in-memory session registry, pending job map, FIFO artifact blob cache, `10m` sticky host affinities, and per-`(site, host)` / peer cooldown maps under `s.mu`.
- `[hub.go:Server.tryPeerHandoff]`, `[hub.go:Server.DispatchOrFallback]`, `[hub.go:Server.ServeHTTP]`: Performs outbound `POST <peer>/fetch` requests, invokes local `FallbackCrawler` via `crawl.ExecuteCallWithTrace`, signs directory headers via `BotSigner.SignDirectoryResponse`, writes HTTP/MCP responses, and logs via `slog.Logger`.

## Verification
- Run: `go test ./internal/hub`
