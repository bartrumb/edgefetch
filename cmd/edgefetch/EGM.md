# edgefetch

## Overview

`cmd/edgefetch` provides the primary Go binary entry point (`package main`) for EdgeFetch. It supports daemon execution modes (`agent`, `server`, `hub`/`controller`, and hybrid combinations), one-shot CLI utilities (`scrape`, `map`, `crawl`, `doctor`, `version`, `keygen-bot-auth`, `bug-report`, `help`), local loopback HTTP/Launchpad servers (`serve`, `desktop`), newline-delimited JSON-RPC 2.0 MCP stdio serving (`mcp`), and AI client / OS startup installers (`init`, `install-mcp`, `install-service`).

## Interface

- `[main.go:main]` — Binary entry point handling `SIGTERM`/`SIGINT` cancellation, one-shot CLI routing, zero-argument Windows/macOS desktop launchpad fallback, and daemon startup (`agent`, `server`, `hub`, or hybrid).
- `[main.go:runtimeModes]`, `[main.go:resolveRuntimeModes]`, `[main.go:shouldRunAgent]` — Resolves daemon runtime modes from CLI flags (`[main.go:--mode=]`, `[main.go:-mode=]`), positional mode tokens (`agent`, `server`, `hub`, `controller`), environment variables (`[main.go:EDGEFETCH_MODE]`, `[main.go:CRAWLER_MODE]`), Home Assistant config presence (`agent.DefaultHAOptionsPath`), or default `server` mode.
- `[main.go:--addr=]`, `[main.go:--allow-unauthenticated]`, `[main.go:PORT]`, `[main.go:EDGEFETCH_BIND_ADDR]`, `[main.go:EDGEFETCH_CALLER_TOKEN]`, `[main.go:CALLER_TOKEN]`, `[main.go:EDGEFETCH_SERVER_TOKEN]`, `[main.go:CRAWLER_TOKEN]`, `[main.go:EDGEFETCH_ALLOW_UNAUTHENTICATED]` — Daemon HTTP listener bind address and Bearer authentication flags/environment variables.
- `[main.go:EDGEFETCH_USER_AGENT]`, `[main.go:CRAWLER_USER_AGENT]`, `[main.go:EDGEFETCH_ROBOTS_BYPASS_HOSTS]` — Crawler `User-Agent` override and comma-separated `robots.txt` bypass host configuration.
- `[main.go:EDGEFETCH_AGENT_TOKENS]`, `[main.go:AGENT_TOKENS]`, `[main.go:EDGEFETCH_AGENT_TOKEN]`, `[main.go:AGENT_TOKEN]`, `[main.go:EDGEFETCH_PEERS]`, `[main.go:EDGEFETCH_PEER_TOKEN]`, `[main.go:BOT_CONTACT_URL]` — Self-hosted Go Hub worker authentication, peer federation, and bot contact environment variables.
- `[main.go:configureCrawlerBotAuth]`, `[main.go:EDGEFETCH_BOT_SIGNING_KEY]`, `[main.go:BOT_SIGNING_PRIVATE_KEY]`, `[main.go:EDGEFETCH_BOT_DIRECTORY_URL]`, `[main.go:BOT_DIRECTORY_URL]` — RFC 9421 Web Bot Auth Ed25519 request-signing setup.
- `[main.go:newHTTPServer]`, `[main.go:newCrawlTransport]`, `[main.go:newHubTransport]`, `[main.go:validateServerSecurity]`, `[main.go:isLoopbackBind]` — HTTP server, HTTP/2 transport, and bind-security constructors/validators.
- `[cli.go:cliDeps]`, `[cli.go:isOneShotCLI]`, `[cli.go:runOneShotCLI]`, `[cli.go:printUsage]` — One-shot CLI dispatcher for `[cli.go:help]` (`[cli.go:--help]`, `[cli.go:-h]`), `[cli.go:version]` (`[cli.go:--version]`, `[cli.go:-v]`), `[cli.go:doctor]` (`[cli.go:--doctor]`), `[cli.go:scrape]`, `[cli.go:map]`, `[cli.go:crawl]`, `[cli.go:mcp]`, `[cli.go:init]`, `[cli.go:install-mcp]`, `[cli.go:install-service]`, `[cli.go:keygen-bot-auth]`, `[cli.go:bug-report]`, `[cli.go:serve]`, and `[cli.go:desktop]`.
- `[cli.go:runVersion]` — Prints build version, Go runtime, `GOOS`/`GOARCH`, and host capabilities (`[cli.go:--json]`).
- `[cli.go:runDoctor]`, `[cli.go:doctorCheck]` — Runs `ssrf_guard`, `ssrf_connect_proxy`, `chromium`, `pdftotext`, and conditional `agent_config` self-checks (`[cli.go:--json]`).
- `[cli.go:runScrapeCLI]` — Single-URL polite HTTPS scraper supporting `[cli.go:--json]`, `[cli.go:--render]`, `[cli.go:--query=]`, `[cli.go:--max-chars=]`, and `[cli.go:--timeout-ms=]`.
- `[cli.go:runMapCLI]` — Site URL discovery across `/llms.txt`, `/sitemap.xml`, and page links supporting `[cli.go:--json]`, `[cli.go:--search=]`, and `[cli.go:--limit=]`.
- `[cli.go:runCrawlCLI]`, `[cli.go:slugifyURLForFilename]` — Same-host breadth-first HTTPS crawler supporting `[cli.go:--json]`, `[cli.go:--render]`, `[cli.go:--limit=]`, `[cli.go:--max-depth=]`, and `[cli.go:--out=]`.
- `[cli.go:runKeygenBotAuth]` — Generates an Ed25519 RFC 9421 Web Bot Auth keypair (`[cli.go:--json]`).
- `[cli.go:runBugReportCLI]`, `[cli.go:sanitizeURLForBugReport]` — Produces a token-redacted diagnostic report with W3C `traceparent`, redacted environment key status, and optional live probe trace spans (`[cli.go:--render]`, `[cli.go:--json]`).
- `[mcp_stdio.go:runMCPStdio]` — Newline-delimited JSON-RPC 2.0 stdio MCP server (`edgefetch-local`) handling `ping`, `initialize`, `tools/list`, and `tools/call` for tools `scrape`, `fetch_url`, `fetch_batch`, `map`, and `doctor`.
- `[mcp_stdio.go:runInstallMCP]`, `[mcp_stdio.go:allMCPClientTargets]`, `[mcp_stdio.go:upsertCodexTomlMCP]` — Registers the `edgefetch` MCP stdio server in `claude-desktop`, `cursor`, `claude-code`, `windsurf`, `gemini` (JSON), and `codex` (TOML) configs (`[mcp_stdio.go:--dry-run]`, `[mcp_stdio.go:--agent=]`, `[mcp_stdio.go:--exe=]`, `[mcp_stdio.go:--config=]`).
- `[mcp_stdio.go:runServeMode]` — Runs a local loopback HTTP API/MCP server on `127.0.0.1:<port>` (default `3002`; flags `[mcp_stdio.go:--port=]`, `[mcp_stdio.go:--allow-private]`).
- `[mcp_stdio.go:runDesktopMode]`, `[mcp_stdio.go:openBrowserBestEffort]` — Runs the local loopback Desktop MCP Launchpad server on `127.0.0.1:<port>` (default `8787`; flags `[mcp_stdio.go:--port=]`, `[mcp_stdio.go:--no-open]`).
- `[mcp_stdio.go:runInstallService]` — Installs an OS user startup service (`LaunchAgents` plist, Windows Startup `.cmd`, or systemd user unit) invoking `desktop --no-open --port=<port>` (`[mcp_stdio.go:--dry-run]`, `[mcp_stdio.go:--port=]`, `[mcp_stdio.go:--exe=]`, `[mcp_stdio.go:--os=]`).

## Invariants

- `[main.go:maxResponseHeaderBytes]`, `[main.go:newHTTPServer]`, `[main.go:newCrawlTransport]`, `[main.go:newHubTransport]` — Caps HTTP request and response headers at 64 KiB (`64 << 10`), disables ambient proxy environment variables (`Proxy: nil`), enables HTTP/2 (`ForceAttemptHTTP2: true`) with `ws.ClassicTLSConfig()`, and enforces dial-time SSRF peer rejection (`politeness.RejectNonPublicPeer`) on `newCrawlTransport`.
- `[main.go:validateServerSecurity]`, `[main.go:isLoopbackBind]`, `[main.go:main]` — Rejects unauthenticated non-loopback server binds unless `--allow-unauthenticated` or truthy `EDGEFETCH_ALLOW_UNAUTHENTICATED` is set; enforces a minimum 24-character length (`agent.MinTokenLength`) on non-empty server and shared Hub agent tokens (exiting `2` otherwise).
- `[main.go:main]` — Restricts pure/hybrid agent crawl targets via `crawl.WithAllowedHosts(crawl.PublicHTTPS, cfg.AllowedHosts)`, blocks every configured Hub hostname via `crawl.WithBlockedHost`, and drops root privileges via `priv.DropRoot()` before serving or running workers (exiting `2` on failure).
- `[cli.go:runScrapeCLI]`, `[cli.go:runMapCLI]`, `[cli.go:runCrawlCLI]` — Enforce `crawl.PublicHTTPS` by default, `RespectRobots: true`, bounded limits (`map` clamped `<= 1000`; `crawl` clamped `limit <= 100`, `max-depth <= 5`, same-hostname `https://` links only), and UTF-8 rune-safe truncation (`[mcp_stdio.go:truncateUTF8Safe]`, `utf8.RuneStart`).
- `[cli.go:sanitizeURLForBugReport]`, `[cli.go:runBugReportCLI]` — Strips URL userinfo, query parameters, and fragments and emits only `"set (redacted)"` or `"unset"` for environment variable diagnostics.
- `[mcp_stdio.go:runMCPStdio]` — Discards crawler logs (`io.Discard`) so `stdout` carries strictly newline-delimited JSON-RPC 2.0 frames (2 MiB max line buffer, HTML escaping disabled); emits zero frames for JSON-RPC notifications (`notifications/*` or `nil` `id`); enforces `fetch_batch` bounds of `1..25` URLs and `map` bounds of `1..500` `https://` URLs.
- `[mcp_stdio.go:runInstallMCP]` — Skips existing client JSON configuration files that fail `json.Unmarshal` rather than overwriting corrupt/unparseable configs.
- `[mcp_stdio.go:runServeMode]`, `[mcp_stdio.go:runDesktopMode]` — Bind strictly to loopback `127.0.0.1:<port>`; even when `--allow-private` is passed to `serve`, non-`http`/`https` schemes and URLs containing userinfo credentials remain rejected.

## Side Effects

- `[main.go:main]` — Subscribes to `SIGTERM`/`SIGINT`, drops OS root privileges (`priv.DropRoot()`), opens TCP listeners (`net.Listen`) for HTTP/WebSocket servers, dials outbound WebSocket Hub sessions (`agent.RunAll`), executes outbound HTTP/2 and headless Chromium crawls, exports optional OTel spans, and calls `os.Exit`.
- `[cli.go:runDoctor]`, `[cli.go:runVersion]`, `[cli.go:runBugReportCLI]`, `[cli.go:runKeygenBotAuth]` — Probe local `PATH`/filesystem for Chromium and `pdftotext`, bind/close an ephemeral loopback SSRF proxy listener (`browser.NewSSRFProxy` in `runDoctor`), read HAOS config when present, and read OS CSPRNG entropy (`botauth.GenerateKeyPair`).
- `[cli.go:runCrawlCLI]` — Creates output directories (`os.MkdirAll` `0755`) and writes Markdown files with YAML frontmatter (`os.WriteFile` `0644`) when `--out=` is set.
- `[mcp_stdio.go:runMCPStdio]` — Reads JSON-RPC requests from `stdin`, writes responses to `stdout`, probes local Chromium, and executes outbound network/browser fetches.
- `[mcp_stdio.go:runInstallMCP]`, `[mcp_stdio.go:runInstallService]` — Create user config/service directories (`0o755`), write `.bak` backups (`0o600`) and updated MCP client JSON/TOML files (`0o600`), and write OS user startup service definitions (`0o644`) unless `--dry-run` is set.
- `[mcp_stdio.go:runServeMode]`, `[mcp_stdio.go:runDesktopMode]`, `[mcp_stdio.go:openBrowserBestEffort]` — Bind loopback TCP listeners on `127.0.0.1:<port>` and spawn detached OS browser launchers (`rundll32`, `open`, or `xdg-open`) unless `--no-open` is passed.

## Verification

- Run: `go test ./cmd/edgefetch`
