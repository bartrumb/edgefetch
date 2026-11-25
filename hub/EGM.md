# hub

## Overview
`hub` contains the thin Cloudflare Worker edge router (`hub/src/`), SQLite/D1 tracking and FTS5 schemas (`hub/migrations/`), and Node/`workerd` test & manifest compilation scripts (`hub/scripts/`). Pure-CPU HTML/PDF/JSON extraction, sanitization, jobs/ATS intelligence, storefront catalog diffing, BYO-LLM agent orchestration, and MCP federation execute inside Go WASM (`cmd/edgefetch-wasm`), while self-hosted Hub deployments run natively on the single Pure-Go binary (`edgefetch --mode=hub`, zero Node.js).

## Subdirectories & Boundaries
- `src`: [./src/EGM.md](./src/EGM.md) - Cloudflare Worker entrypoints (`default.fetch`, `default.scheduled`), `AgentHubDO` hibernating WebSockets coordinator, `CrawlWorkflow` & `IngestWorkflow`, OAuth 2.1 + GitHub OAuth authorization server, 17-tool Streamable HTTP `/mcp` server, `/admin` portal with MCP Registry & `AES-256-GCM` connector vault, `/v1/*` and Firecrawl/Tavily compatibility APIs, R2/D1 storage & FTS5 search index, and `wasm-bridge.ts` WASI reactor host.
- `migrations`: [./migrations/EGM.md](./migrations/EGM.md) - SQLite / Cloudflare D1 `STRICT` DDL schemas split across operational metadata tracking (`./migrations/meta/EGM.md`) and external-content FTS5 full-text search (`./migrations/search/EGM.md`).
- `scripts`: [./scripts/EGM.md](./scripts/EGM.md) - Node.js ESM manifest compiler (`compile-manifests.mjs`), contributor adapter generator (`new-adapter.mjs`), adapter fuzzer (`test-adapter.mjs`), OpenAPI generator (`generate-openapi.mjs`), and Node + `workerd` integration test runner (`run-tests.mjs`).
