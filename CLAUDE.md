# EdgeFetch Instructions (`CLAUDE.md`)

Read and follow [`AGENTS.md`](./AGENTS.md) at all times.

## Non-Negotiable Architecture Rule: Go First, Never Duplicate in TypeScript

- **Single Source of Truth in Go (`cmd/`, `internal/`):** EdgeFetch is a **Go** codebase (`CGO_ENABLED=0`, single external module `github.com/coder/websocket`). Implement all extraction, HTML-to-Markdown conversion, CommonMark fence/prose sanitization, `read_artifact` slicing, YAML/site adapters, ATS `jobs`, storefront `catalog`, `/v1/agent` LLM orchestration, MCP federation/vault, politeness/SSRF checks, and self-hosted Hub (`edgefetch --mode=hub`) features **once, in Go**.
- **Thin Cloudflare Edge Only (`hub/`):** TypeScript under `hub/` is restricted strictly to thin Cloudflare Worker bindings (`AgentHubDO` WebSockets, R2, D1, Workflows, `scheduled()` cron, and edge HTTP/OAuth glue).
- **Go WASM (`cmd/edgefetch-wasm`) Over TypeScript:** Whenever the Cloudflare Worker needs parsing, sanitization, adapter execution, paging, or offline fallback without a live Go worker node, expose that Go package through `cmd/edgefetch-wasm` (`GOOS=wasip1 GOARCH=wasm`) and invoke the WASM module from the Worker. **Never** port or duplicate Go logic into TypeScript, and **never** introduce Node.js or Deno Hub shims.
