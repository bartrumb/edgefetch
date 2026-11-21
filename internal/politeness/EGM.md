# politeness

## Overview
Package `politeness` enforces per-origin request serialization, RFC 9110 `Retry-After` cooldowns, three-state dead-origin circuit breaking, zero-allocation RFC 9309 `/robots.txt` parsing and matching, and dial-time `net.Dialer.Control` DNS-rebinding SSRF protection.

## Interface
- `[politeness.go:MaxTrackedHosts]`, `[politeness.go:HostIdleTTL]`, `[politeness.go:MaxRetryAfter]`, `[politeness.go:DefaultThrottlePause]`, `[politeness.go:CircuitFailureThreshold]`, `[politeness.go:CircuitFailureWindow]`, `[politeness.go:CircuitOpenCooldown]`, `[politeness.go:RobotsCacheTTL]`, `[politeness.go:RobotsDistressTTL]`, `[politeness.go:RobotsMaxBytes]`, `[politeness.go:RobotsTimeout]`, `[politeness.go:MaxCrawlDelay]`: Politeness, circuit-breaker, and `robots.txt` tuning constants.
- `[politeness.go:HostState]`: Per-host state exposing `Acquire`, `Release`, `CheckCircuit`, `WaitDelay`, `CrawlDelay`, `CachedRobots`, `SetRobots`, and `RecordOutcome`.
- `[politeness.go:Registry]`, `[politeness.go:NewRegistry]`, `[politeness.go:Registry.Get]`, `[politeness.go:CanonicalHost]`: Bounded (`512`-host) concurrency-safe host state registry.
- `[politeness.go:ParseRetryAfter]`: `func ParseRetryAfter(val string, now time.Time) time.Duration` — parses RFC 9110 delta-seconds or HTTP-date headers clamped to `[0, MaxRetryAfter]`.
- `[politeness.go:RobotsRule]`, `[politeness.go:RobotsEntry]`, `[politeness.go:RobotsEntry.Allowed]`, `[politeness.go:RobotsEntry.ContentSignalBlocked]`, `[politeness.go:NormalizeRobotsURI]`, `[politeness.go:ParseRobotsTxt]`: RFC 9309 `/robots.txt` + Cloudflare `Content-Signal:` (`ai-input`) parser, URI normalizer, and linear-time rule matcher.
- `[politeness.go:ErrNonPublicPeer]`, `[politeness.go:IsPublicIP]`, `[politeness.go:IsPublicAddr]`, `[politeness.go:CheckPublicPeerAddress]`, `[politeness.go:RejectNonPublicPeer]`: Public unicast IP validators and `net.Dialer.Control` SSRF hook.

## Invariants
- `[politeness.go:HostState.Acquire]`, `[politeness.go:HostState.Release]`: Enforces single in-flight request exclusivity per host via a capacity-1 buffered channel (`inFlight`) decoupled from `h.mu` so `Acquire` unblocks immediately on `ctx.Done()`.
- `[politeness.go:HostState.SetRobots]`, `[politeness.go:HostState.RecordOutcome]`, `[politeness.go:HostState.CheckCircuit]`: `nextAllowed` advances monotonically; `RecordOutcome` trips the circuit breaker (`CircuitOpenCooldown = 30s`) only after `CircuitFailureThreshold` (`5`) consecutive `transientDead` failures within `CircuitFailureWindow` (`60s`), whereas HTTP `429` (`transientDead == false`) applies `Retry-After` / `DefaultThrottlePause` (`15s`) without opening the dead-origin circuit.
- `[politeness.go:Registry.Get]`: Canonicalizes host keys (lowercased, trailing `.` stripped) and evicts idle/LRU unlocked (`len(inFlight) == 0`) entries at `MaxTrackedHosts` (`512`), never evicting active in-flight entries.
- `[politeness.go:RobotsEntry.Allowed]`, `[politeness.go:RobotsEntry.ContentSignalBlocked]`, `[politeness.go:robotsMatch]`, `[politeness.go:ParseRobotsTxt]`: `Distressed == true` or `DisallowAIInput == true` (`Content-Signal: ai-input=no` resolved per RFC 9309 `User-agent` specificity) disallows retrieval; longest pattern length wins (ties broken in favor of `Allow == true`); `*` and `$` wildcards evaluate via `strings.Cut` in `O(P * T)` time with zero heap allocations; `Crawl-delay` clamps to `MaxCrawlDelay` (`30s`).
- `[politeness.go:IsPublicAddr]`, `[politeness.go:RejectNonPublicPeer]`: Unmaps IPv4-mapped IPv6 addresses, requires IPv6 addresses to fall within `2000::/3`, rejects loopback/private/link-local/multicast/unspecified and 23 IANA special-purpose CIDR prefixes (`[politeness.go:nonPublicPrefixes]`), and wraps `ErrNonPublicPeer` to abort non-public sockets before TCP SYN.

## Side Effects
- `[politeness.go:ipv6GlobalUnicastPrefix]`, `[politeness.go:nonPublicPrefixes]`: Parses `2000::/3` and 23 special-purpose `netip.Prefix` blocks at package init.
- `[politeness.go:HostState.Acquire]`, `[politeness.go:HostState.Release]`, `[politeness.go:HostState.SetRobots]`, `[politeness.go:HostState.RecordOutcome]`, `[politeness.go:Registry.Get]`: Mutate per-host semaphore channels, timestamps (`lastSeen`, `nextAllowed`), circuit-breaker counters, cached `RobotsEntry`, and `Registry.hosts` map entries under mutexes.
- `[politeness.go:RejectNonPublicPeer]`: Aborts OS `connect()` syscalls on non-public peer addresses when attached to `net.Dialer.Control`.

## Verification
- Run: `go test ./internal/politeness`
