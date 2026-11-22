# agent

## Overview
Package `agent` implements the outbound-only WebSocket worker loop connecting EdgeFetch standby nodes to a remote or self-hosted coordination hub (`AgentHubDO` or `internal/hub`), executing dispatched crawl batches, streaming optional out-of-band gzipped artifacts, and draining active jobs gracefully on shutdown.

## Interface
- `[agent.go:Version]`: `var Version = "2.6.3"` — build-overridable release string advertised in `X-Agent-Version` and `agent_hello`.
- `[agent.go:DefaultPingInterval]`, `[agent.go:DefaultReadWatchdog]`, `[agent.go:DefaultHealthyResetDur]`, `[agent.go:DefaultShutdownDrain]`, `[agent.go:DefaultUploadTimeout]`, `[agent.go:DefaultShutdownUploadTimeout]`: Default session timing constants (`30s`, `50s`, `30s`, `25s`, `45s`, `10s`).
- `[agent.go:RuntimeOpts]`: `struct` configuring `PingInterval`, `ReadWatchdog`, `HealthyResetDur`, `ShutdownDrain`, `UploadTimeout`, `ShutdownUploadTimeout`, and `OnConnected` callback.
- `[agent.go:RunAll]`: `func RunAll(ctx context.Context, cfg Config, crawler *crawl.Crawler, allow func(*url.URL) error, hubTransport http.RoundTripper, log *slog.Logger, rtOpts RuntimeOpts) error` — warms `crawler` (`6s` bounded timeout) and runs concurrent outbound sessions across all configured `cfg.HubURLs` (or `cfg.HubURL`).
- `[agent.go:Run]`: `func Run(ctx context.Context, cfg Config, crawler *crawl.Crawler, allow func(*url.URL) error, hubTransport http.RoundTripper, log *slog.Logger, rtOpts RuntimeOpts) error` — warms `crawler` (`6s` bounded timeout) and maintains a single hub WebSocket reconnect loop with jittered exponential backoff.
- `[config.go:DefaultHAOptionsPath]`, `[config.go:DefaultPauseMs]`, `[config.go:DefaultPauseJitterMs]`, `[config.go:MinTokenLength]`: Configuration defaults (`"/data/options.json"`, `3000`, `1500`, `24`).
- `[config.go:Config]`: `struct` holding `HubURL` (`hub_url`), `HubURLs` (`hub_urls`), `AgentToken` (`agent_token`), `SiteID` (`site_id`), `UserAgent` (`user_agent`), `PauseMs` (`pause_ms`), `PauseJitterMs` (`pause_jitter_ms`), `AllowedHosts` (`allowed_hosts`), and `RobotsBypassHosts` (`robots_bypass_hosts`).
- `[config.go:LoadConfig]`, `[config.go:LoadConfigFrom]`: Load JSON options file overlaid with `EDGEFETCH_HUB_URL` / `CRAWLER_HUB_URL`, `EDGEFETCH_HUB_URLS` / `CRAWLER_HUB_URLS`, `EDGEFETCH_AGENT_TOKEN` / `CRAWLER_AGENT_TOKEN`, `EDGEFETCH_SITE_ID` / `CRAWLER_SITE_ID`, `EDGEFETCH_USER_AGENT` / `CRAWLER_USER_AGENT`, `EDGEFETCH_PAUSE_MS` / `CRAWLER_PAUSE_MS`, `EDGEFETCH_PAUSE_JITTER_MS` / `CRAWLER_PAUSE_JITTER_MS`, `EDGEFETCH_ALLOWED_HOSTS` / `CRAWLER_ALLOWED_HOSTS`, `EDGEFETCH_ROBOTS_BYPASS_HOSTS` / `CRAWLER_ROBOTS_BYPASS_HOSTS`, `EDGEFETCH_ALLOW_INSECURE_HUB` / `CRAWLER_ALLOW_INSECURE_HUB`, `EDGEFETCH_ALLOW_INSECURE_DOCKER_HUB`, and `EDGEFETCH_INSECURE_HUB_HOST`.
- `[agent.go:runSession]`, `[agent.go:uploadArtifact]`, `[agent.go:uploadReply]`: Outbound hub protocol endpoints `GET <HubURL>/agent/ws` (`X-Agent-Browser-Sandbox`, `agent_hello` with `browserVersion`/`browserSandbox`, `"ping"`/`"pong"`, `dispatch`), `PUT <HubURL>/agent/artifacts/<blobSHA256>`, and `POST <HubURL>/agent/reply`.

## Invariants
- `[agent.go:Run]`, `[agent.go:runSession]`: Zero inbound listening sockets; all hub control and data traffic is outbound and authenticated via `Authorization: Bearer <AgentToken>`, and `dispatch` frames run on a single controller-lifetime worker goroutine (`dispatchCh` buffered at `8`, drained via `dispatchWG.Wait()` when `Run` exits) so `conn.ReadText` continuously drains `"pong"` frames without tripping `ReadWatchdog` and transient socket drops reconnect immediately without blocking on in-flight crawls.
- `[config.go:normalizeHubURL]`, `[config.go:LoadConfigFrom]`: Converts `wss://` to `https://` and `ws://` to `http://`, strips trailing `/` and `/agent/ws`, deduplicates `HubURLs`, and rejects cleartext `http://` unless loopback (`EDGEFETCH_ALLOW_INSECURE_HUB=1` or `CRAWLER_ALLOW_INSECURE_HUB=1` on `127.0.0.1`, `::1`, `localhost`) or allowlisted Docker bridge host (`EDGEFETCH_ALLOW_INSECURE_DOCKER_HUB=1` on `hub`, `edgefetch-hub`, `edgefetch`, `host.docker.internal`, or `EDGEFETCH_INSECURE_HUB_HOST`).
- `[config.go:LoadConfigFrom]`, `[config.go:MinTokenLength]`, `[config.go:validSiteID]`: Requires `len(AgentToken) >= 24`, `SiteID` matching `^[a-z0-9][a-z0-9_-]{0,31}$`, valid `UserAgent` via `crawl.ValidateUserAgent`, `PauseMs` clamped to `[1000, 60000]`, `PauseJitterMs` clamped to `[0, crawl.MaxPauseJitterMs]`, and zeroes raw `optionsPath` bytes in memory before returning.
- `[agent.go:Run]`: `replyClient.CheckRedirect` returns `http.ErrUseLastResponse` so bearer tokens never follow redirects; reconnect counter resets after `HealthyResetDur` (`30s`) of uptime.
- `[agent.go:handleDispatchWithOpts]`: Skips `dispatch` frames missing `JobID` or `JobNonce`, clamps `call.Options.Concurrency` to `1` for single-URL dispatches and up to `4` (`crawl.MaxConcurrency`) for multi-URL batches, enforces per-host `PauseMs`/`PauseJitterMs` floors and a `min(cfg.PauseMs, 250)` cross-domain `GapMs` floor, drains active jobs up to `ShutdownDrain` (`25s`) after `parentCtx` cancellation, and strips inline `res.Body`/`res.BodyEncoding` whenever `msg.Artifacts.Mode == "r2"` and `call.Options.IncludeBody` is set.
- `[agent.go:uploadArtifact]`, `[agent.go:uploadReply]`: Gzip-compress payloads and retry up to 3 attempts on transport errors or HTTP `502`/`503`/`504` (plus `409` on `uploadArtifact`).

## Side Effects
- `[config.go:LoadConfigFrom]`, `[config.go:isDockerBridgeHost]`: Reads `optionsPath` from disk via `os.ReadFile` and reads process environment variables.
- `[agent.go:RunAll]`, `[agent.go:runSession]`: Spawns per-hub session goroutines and per-session keepalive ticker goroutines sending `"ping"` text frames over `<HubURL>/agent/ws`.
- `[agent.go:handleDispatchWithOpts]`, `[agent.go:uploadArtifact]`, `[agent.go:uploadReply]`: Executes target crawls via `crawl.ExecuteCallWithTrace`, performs outbound `PUT <HubURL>/agent/artifacts/<blobSHA256>` and `POST <HubURL>/agent/reply` HTTP calls, schedules `ShutdownDrain` timers, and emits structured `slog` events.

## Verification
- Run: `go test ./internal/agent`
