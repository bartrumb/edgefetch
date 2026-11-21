# browser

## Overview
Package `browser` drives a sandboxed headless Chromium process over the Chrome DevTools Protocol (CDP) for SPA rendering, multi-step browser interactions, screenshots, and PDF generation while forcing all subresource sockets through an in-process SSRF-guarded loopback `CONNECT` proxy.

## Interface
- `[proxy.go:ErrBrowserUnavailable]`, `[renderer.go:ErrChallengeDetected]`: Sentinel errors for missing headless Chromium binary and rendered anti-bot/CAPTCHA challenge detection.
- `[proxy.go:SSRFProxy]`, `[proxy.go:NewSSRFProxy]`, `[proxy.go:SSRFProxy.Addr]`, `[proxy.go:SSRFProxy.Close]`: Loopback-only (`127.0.0.1:0`) HTTP `CONNECT` proxy enforcing caller `allow(*url.URL)` policy and dial-time peer IP guards.
- `[renderer.go:InteractAction]`, `[renderer.go:ActionScrapeSnapshot]`, `[renderer.go:ActionJSReturn]`: Structured interaction action inputs (`click`, `fill`, `type`, `write`, `press`, `wait`, `scroll`, `select`, `navigate`, `screenshot`, `scrape`, `executeJavascript`, `pdf`) and per-step outputs.
- `[renderer.go:Task]`, `[renderer.go:Output]`: Stateless render and stateful `SessionID` execution request/response contracts.
- `[renderer.go:FindChromeBinary]`: `func FindChromeBinary() string` — discovers Chromium/Chrome/Edge/Brave via `EDGEFETCH_CHROME_BIN`, `PATH`, or OS-standard paths.
- `[renderer.go:Renderer]`, `[renderer.go:NewRenderer]`, `[renderer.go:NewMockRenderer]`: Manage shared Chromium subprocess, `SSRFProxy`, concurrency semaphore, retained sessions, and optional `CheckRobots func(ctx context.Context, rawURL string) error` hook (`[renderer.go:Renderer.CheckRobots]`).
- `[renderer.go:Renderer.Available]`, `[renderer.go:Renderer.Execute]`, `[renderer.go:Renderer.CloseSession]`, `[renderer.go:Renderer.Close]`: Availability check, isolated browser context execution, session teardown, and idempotent process/profile cleanup.

## Invariants
- `[proxy.go:NewSSRFProxy]`, `[proxy.go:SSRFProxy.serveHTTP]`: Binds exclusively to `127.0.0.1:0`, rejects non-`CONNECT` HTTP requests with `403 Forbidden`, validates `https://<host[:port]>/` against `allow(u)` prior to TCP dial, attaches `politeness.RejectNonPublicPeer` when `customDial == nil`, and caps hijacked tunnel lifetime at `90s`.
- `[renderer.go:buildChromiumLaunchArgs]`, `[renderer.go:buildSanitizedChildEnv]`: Launches Chromium with `--proxy-server=http://<proxyAddr>`, `--host-resolver-rules=MAP * ~NOTFOUND , EXCLUDE 127.0.0.1`, `--disable-quic`, `--force-webrtc-ip-handling-policy=disable_non_proxied_udp`, and `--remote-debugging-address=127.0.0.1`, passing only an explicit allowlist of sanitized host environment variables.
- `[cdp.go:maxCDPFrameBytes]`, `[renderer.go:maxRenderedDOMChars]`, `[renderer.go:readDocumentHTML]`: Caps CDP WebSocket frames at `24 MiB` and rendered DOM extraction at `16 MiB` (`16,777,216` chars/bytes) in both JS and Go so oversized DOMs cannot drop the shared CDP socket.
- `[renderer.go:NewRenderer]`, `[renderer.go:maxActiveSessions]`, `[renderer.go:sessionIdleTTL]`, `[renderer.go:browserIdleTTL]`: Clamps `maxConcurrent` to `[1, 4]` (default `2`), caps retained `efsess_*` sessions at `8` (evicting oldest), and enforces `3m` session and browser idle TTLs.
- `[renderer.go:Renderer.Execute]`, `[renderer.go:Renderer.runAction]`, `[renderer.go:Renderer.validateFinalURL]`: Enforces `r.allow` and `r.CheckRobots` on initial, navigated, redirected, and scraped URLs (tracking `lastCheckedURL` on `retainedSession` so resumed `interact` turns with `task.URL == ""` still enforce `CheckRobots` on click/JS navigations); clears custom extra HTTP headers on cross-host `navigate` steps; and halts immediately with `ErrChallengeDetected` when `extract.DetectRenderedChallenge` matches rendered HTML.

## Side Effects
- `[proxy.go:NewSSRFProxy]`, `[proxy.go:SSRFProxy.serveHTTP]`, `[cdp.go:dialCDP]`: Binds `127.0.0.1:0`, dials outbound TCP tunnels, hijacks HTTP `CONNECT` streams, and maintains a background CDP WebSocket `readLoop` goroutine.
- `[renderer.go:FindChromeBinary]`, `[renderer.go:Renderer.ensureBrowser]`, `[renderer.go:Renderer.Close]`: Reads `EDGEFETCH_CHROME_BIN` and OS path variables, creates and removes `edgefetch-chrome-*` temp profile directories (`os.MkdirTemp` / `os.RemoveAll`), spawns/kills the headless Chromium child process, and runs a `30s` `idleReaperLoop` goroutine.
- `[renderer.go:Renderer.Execute]`, `[renderer.go:Renderer.runAction]`: Dispatches CDP target, network, emulation, input, JS runtime, screenshot, and PDF commands and invokes `r.CheckRobots` when configured.

## Verification
- Run: `go test ./internal/browser`
