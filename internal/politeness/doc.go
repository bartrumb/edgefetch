// Package politeness enforces per-origin serialization, RFC 9110 `Retry-After` cooldowns, three-state
// dead-origin circuit breaking, zero-allocation RFC 9309 `/robots.txt` matching, and dial-time DNS-rebinding
// SSRF protection (`net.Dialer.Control`).
//
// # Concurrency & SSRF Design
//
//   - Context-aware host locks: [HostState] pairs a buffered `chan struct{}` (capacity 1) with a metadata
//     `sync.Mutex` so waiting goroutines unblock immediately when a caller's `context.Context` cancels.
//   - Rate-limit vs dead-origin separation: HTTP `429` honors `Retry-After` on `nextAllowed` without tripping
//     the dead-socket circuit breaker, whereas 5 consecutive transport/5xx failures open the circuit for 30s.
//   - Linear-time `robots.txt` matching: wildcard `*` and `$` rules evaluate via `strings.Cut` in $O(P \times T)$
//     time with `0 allocs/op` and zero regular-expression backtracking risk.
//   - Dial-time SSRF guard: [RejectNonPublicPeer] inspects the resolved `netip.Addr` inside `net.Dialer.Control`
//     right before the OS `connect()` syscall, eliminating DNS-rebinding TOCTOU races while preserving Happy
//     Eyeballs dual-stack fallback and `httptrace` DNS timing hooks.
package politeness
