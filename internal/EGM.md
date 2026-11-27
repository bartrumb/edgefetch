# internal

## Overview
Directory `internal` contains EdgeFetch's core Go packages implementing polite HTTP/2 batch crawling, SSRF-isolated headless Chromium rendering, HTML/PDF/`llms.txt` extraction, response/WAF classification, per-host politeness and dial-time peer IP enforcement, outbound WebSocket standby worker loops, self-hosted multi-node hub/MCP coordination, RFC 9421 `web-bot-auth` message signing, W3C/OTLP trace export, and Linux root privilege dropping.

## Subdirectories & Boundaries
- `agent`: [./agent/EGM.md](./agent/EGM.md) - Outbound-only WebSocket worker loop (`GET <HubURL>/agent/ws`), configuration loader, out-of-band gzipped artifact uploader (`PUT /agent/artifacts/{sha}`), and graceful SIGTERM job drainer (`POST /agent/reply`).
- `botauth`: [./botauth/EGM.md](./botauth/EGM.md) - RFC 9421 Ed25519 HTTP Message Signatures (`web-bot-auth`), RFC 7638 JWK thumbprints, and `/.well-known/http-message-signatures-directory` signing and verification.
- `browser`: [./browser/EGM.md](./browser/EGM.md) - Headless Chromium CDP driver, stateful `efsess_*` interaction runner, and loopback `127.0.0.1:0` `CONNECT` `SSRFProxy` isolating subresource sockets.
- `classify`: [./classify/EGM.md](./classify/EGM.md) - Pure response classifier mapping HTTP status, headers, and payload bytes into crawl `Outcome` values, outbound `Accept` headers, host short-circuit signals, and multi-vendor WAF/challenge matches.
- `company`: [./company/EGM.md](./company/EGM.md) - No-I/O company profile planner and merger (homepage JSON-LD, Wikidata, SEC EDGAR, GitHub, ATS, Google Maps places) exposed to the Worker via `company_*` WASM ops.
- `crawl`: [./crawl/EGM.md](./crawl/EGM.md) - Bounded-concurrency polite HTTP/2 batch `Crawler`, hop-by-hop redirect SSRF/robots validator, `/llms.txt` companion Markdown enrichment, disk-streamed PDF pipeline, and standalone `/fetch` HTTP handler.
- `extract`: [./extract/EGM.md](./extract/EGM.md) - Standard-library HTML-to-GFM Markdown/text converter, CSS branding extractor, BM25 passage reranker, PII redactor, `/llms.txt` parser, and Poppler/pure-Go PDF text extractor.
- `hub`: [./hub/EGM.md](./hub/EGM.md) - Self-hosted multi-node WebSocket fleet coordinator, 1-hop peer handoff router, sticky-affinity scheduler, bounded in-memory artifact store, Firecrawl-compatible scrape/map server, and Streamable HTTP MCP endpoint (`POST /mcp`).
- `otel`: [./otel/EGM.md](./otel/EGM.md) - Zero-dependency W3C `traceparent` parser/propagator and asynchronous buffered OTLP/HTTP JSON span exporter (`/v1/traces`).
- `politeness`: [./politeness/EGM.md](./politeness/EGM.md) - Per-host concurrency locks, `Retry-After` cooldowns, three-state dead-origin circuit breaker, linear-time RFC 9309 `/robots.txt` matcher, and `net.Dialer.Control` public-IP SSRF guard (`RejectNonPublicPeer`).
- `priv`: [./priv/EGM.md](./priv/EGM.md) - Linux startup privilege drop (`PR_SET_NO_NEW_PRIVS` + UID/GID `65532:65532` across all Go OS threads) with a non-Linux no-op stub.
- `ws`: [./ws/EGM.md](./ws/EGM.md) - Hardened `coder/websocket` client pinned to HTTP/1.1 ALPN, classic ECDHE curves, `1 MiB` frame cap, disabled compression, and zero proxy/redirect credential forwarding.
