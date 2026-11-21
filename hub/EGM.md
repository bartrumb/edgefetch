# hub

## Overview
`hub` groups the TypeScript/JavaScript coordinator runtime, portable Node.js/Deno self-hosted server adapters, SQLite/D1 tracking and full-text search schemas, and developer build/scaffolding tooling for the EdgeFetch Hub (`edgefetch-hub`). It coordinates outbound-only worker nodes over hibernating WebSockets, enforces OAuth 2.1 and constant-time Bearer authentication, executes multi-format HTML/PDF/twin scraping (`SCRAPE_PIPELINE_VERSION = 23`), and indexes verified documents into R2/S3 and D1/SQLite/Turso FTS5 stores with zero runtime `npm` dependencies on Cloudflare Workers.

## Subdirectories & Boundaries
- `src`: [./src/EGM.md](./src/EGM.md) - Cloudflare Worker entrypoints (`default.fetch`, `default.scheduled`), `AgentHubDO` hibernating WebSocket coordinator, `CrawlWorkflow` & `IngestWorkflow`, OAuth 2.1 authorization server, 14-tool Streamable HTTP `/mcp` server, `/admin` portal, `/v1/*` and Firecrawl/Tavily compatibility APIs, Tier-2 overflow fetcher, R2/D1 storage & FTS5 search index, multi-provider web search, ATS job discovery, BYO-LLM `/v1/agent` runner, and the 54-provider `./src/extractors` adapter registry.
- `portable`: [./portable/EGM.md](./portable/EGM.md) - Self-hosted Node.js (`startPortableHub`) and Deno (`startDenoHub`) Hub servers, `cloudflare:workers` shims, local `node:sqlite` D1 and filesystem R2 adapters, AWS SigV4 `S3ArtifactBucket`, `TursoHttpD1Database`, and DNS-pinned SSRF-safe `createSafeOutboundFetch`.
- `migrations`: [./migrations/EGM.md](./migrations/EGM.md) - SQLite / Cloudflare D1 `STRICT` DDL schemas split across operational metadata tracking (`./migrations/meta/EGM.md`) and external-content FTS5 full-text search (`./migrations/search/EGM.md`).
- `scripts`: [./scripts/EGM.md](./scripts/EGM.md) - Node.js ESM build (`build-portable.mjs`), contributor adapter generator (`new-adapter.mjs`), and Node + `workerd` integration test runner (`run-tests.mjs`).
