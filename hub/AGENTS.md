# `hub/` Directory Rules (`hub/AGENTS.md`)

**STOP BEFORE ADDING TYPESCRIPT HERE:**

1. **`hub/` is Strictly a Thin Cloudflare Worker Adapter:**
   - Only Cloudflare-native binding glue belongs in `hub/` (`AgentHubDO` hibernating WebSocket Durable Object, R2 `ARTIFACTS`, D1 `META`/`SEARCH`, Cloudflare Workflows, `scheduled()` cron triggers, and thin edge auth/route wiring).
2. **Zero Domain or Parser Logic in TypeScript:**
   - Do **NOT** implement or expand HTML parsers, Markdown/CommonMark sanitizers, `read_artifact` slice pagers, site/YAML adapters, ATS `jobs` scrapers, `catalog` scrapers, `/v1/agent` LLM loops, `robots.txt` / WAF / PSL parsers, or Node/Deno portable server shims in TypeScript.
3. **Delegate to Go Workers or Go WASM (`cmd/edgefetch-wasm`):**
   - Implement all domain, extraction, sanitization, and orchestration logic **once in Go** (`../internal/*`).
   - On Cloudflare Workers, dispatch live network/browser work to connected Go worker nodes (`--mode=agent`) and run CPU-bound/offline fallback work via the compiled Go `wasip1/wasm` binary (`../cmd/edgefetch-wasm`).
   - Self-hosted and Docker deployments use the native Go binary (`edgefetch --mode=hub`), never Node.js or Deno shims.
