# cmd

## Overview

`cmd` groups the Go executable entry-point packages for EdgeFetch, separating the full-featured native CLI/daemon/MCP binary from the standalone pure-stdlib WASI WebAssembly HTML-to-Markdown extractor.

## Subdirectories & Boundaries

- `edgefetch`: [./edgefetch/EGM.md](./edgefetch/EGM.md) - Primary native binary supporting daemon modes (`agent`, `server`, `hub`, hybrid), one-shot CLI commands (`scrape`, `map`, `crawl`, `doctor`, `version`, `keygen-bot-auth`, `bug-report`), stdio MCP serving (`mcp`), loopback HTTP/Launchpad modes (`serve`, `desktop`), and client/service installers (`init`, `install-mcp`, `install-service`).
- `edgefetch-wasm`: [./edgefetch-wasm/EGM.md](./edgefetch-wasm/EGM.md) - Standalone WASI (`GOOS=wasip1 GOARCH=wasm`) command-line extractor reading up to 16 MiB of HTML from `stdin` and emitting extracted Markdown or JSON to `stdout` via `internal/extract`.
