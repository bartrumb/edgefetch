// Package politeness enforces per-origin serialization, Retry-After cooldowns, three-state circuit breaking,
// RFC 9309 robots.txt caching, and kernel-level DNS-rebinding SSRF protection (`net.Dialer.Control`).
//
// For Go learners reading this package:
//   - Notice how Go separates **concurrency coordination** (`chan struct{}` buffered channels that work with `select`
//     and `context.Context` deadlines) from **short critical-section locking** (`sync.Mutex` protecting struct fields
//     and `map` access for nanoseconds).
//   - Every exported identifier starts with an uppercase letter (`Registry`, `HostState`, `RejectNonPublicPeer`);
//     unexported helpers (`robotsMatch`, `nonPublicCIDRs`) stay private to this package while remaining directly
//     testable by `politeness_test.go` in the same folder.
package politeness

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Tuning bounds for per-host politeness, circuit breaking, and `/robots.txt` caching.
// In Go, `time.Duration` is a typed `int64` nanosecond count, so expressions like `5 * time.Minute` fold to constants
// at compile time with zero runtime overhead.
const (
	MaxTrackedHosts         = 512
	HostIdleTTL             = 24 * time.Hour
	MaxRetryAfter           = 5 * time.Minute
	DefaultThrottlePause    = 15 * time.Second
	CircuitFailureThreshold = 5
	CircuitFailureWindow    = 60 * time.Second
	CircuitOpenCooldown     = 30 * time.Second
	RobotsCacheTTL          = 24 * time.Hour
	RobotsDistressTTL       = 5 * time.Minute
	RobotsMaxBytes          = 64 << 10 // 64 KiB ceiling prevents an oversized /robots.txt from exhausting heap RAM.
	RobotsTimeout           = 10 * time.Second
	MaxCrawlDelay           = 30 * time.Second
)

// HostState coordinates concurrent callers targeting the same hostname across independent crawl invocations.
//
// Why combine `inFlight chan struct{}` AND `mu sync.Mutex`?
//   - `sync.Mutex.Lock()` cannot be interrupted by a `context.Context` cancellation! If goroutine A is mid-way through
//     a 20 s download on a slow host and goroutine B arrives with a 2 s deadline, `mu.Lock()` would block B for all 20 s.
//   - A 1-element buffered channel (`make(chan struct{}, 1)`) acts as a **context-cancellable mutex**: `Acquire(ctx)`
//     uses `select` to wait for EITHER the single token (`h.inFlight <- struct{}{}`) OR `<-ctx.Done()`.
//     (`struct{}` occupies 0 bytes of memory in Go.)
//   - `mu sync.Mutex` guards fast, non-blocking reads/writes to timestamps, counters, and cached `robots.txt` rules.
type HostState struct {
	inFlight chan struct{}

	mu                sync.Mutex
	nextAllowed       time.Time
	consecutiveErrors int
	firstErrorAt      time.Time
	circuitOpenUntil  time.Time
	robots            *RobotsEntry
	lastSeen          time.Time
}

func newHostState(now time.Time) *HostState {
	return &HostState{
		inFlight: make(chan struct{}, 1),
		lastSeen: now,
	}
}

// Acquire claims exclusive in-flight access to this host, or returns `ctx.Err()` immediately if `ctx` cancels first.
func (h *HostState) Acquire(ctx context.Context) error {
	select {
	case h.inFlight <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Release frees the single in-flight host token. Pair with `defer hs.Release()` right after `Acquire` succeeds.
func (h *HostState) Release() {
	<-h.inFlight
}

// CheckCircuit returns a non-empty reason when the host's dead-origin circuit breaker is currently Open.
// Once `now` passes `circuitOpenUntil`, it returns `""` so a single Half-Open probe request is allowed through.
func (h *HostState) CheckCircuit(now time.Time, host string) string {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.lastSeen = now
	if !h.circuitOpenUntil.IsZero() && now.Before(h.circuitOpenUntil) {
		rem := h.circuitOpenUntil.Sub(now).Round(time.Second)
		if rem < time.Second {
			rem = time.Second
		}
		return fmt.Sprintf("circuit open for %s (%s remaining after %d consecutive errors)", host, rem, h.consecutiveErrors)
	}
	return ""
}

// WaitDelay returns any remaining cooldown before the next request to this host may start.
func (h *HostState) WaitDelay(now time.Time) time.Duration {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.lastSeen = now
	if h.nextAllowed.After(now) {
		return h.nextAllowed.Sub(now)
	}
	return 0
}

// CrawlDelay returns the cached `/robots.txt` `Crawl-delay` for this host (`0` when unset or expired).
func (h *HostState) CrawlDelay(now time.Time) time.Duration {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.robots != nil && now.Before(h.robots.ExpiresAt) {
		return h.robots.CrawlDelay
	}
	return 0
}

// CachedRobots returns the cached `RobotsEntry` when fresh (`nil` when absent or expired).
func (h *HostState) CachedRobots(now time.Time) *RobotsEntry {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.robots != nil && now.Before(h.robots.ExpiresAt) {
		return h.robots
	}
	return nil
}

// SetRobots stores a parsed (or distressed) `RobotsEntry` and applies an optional polite pause on `5xx` distress.
func (h *HostState) SetRobots(now time.Time, entry *RobotsEntry, distressPause time.Duration) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.robots = entry
	if distressPause > 0 {
		if until := now.Add(distressPause); until.After(h.nextAllowed) {
			h.nextAllowed = until
		}
	}
}

// RecordOutcome updates `nextAllowed` and drives the three-state dead-origin circuit breaker (Closed -> Open -> Half-Open).
//
// Why don't HTTP 403 or 429 responses trip the dead-origin circuit breaker?
// Because an HTTP 429 proves the TCP/TLS server is healthy and asking us to slow down — so we honor `Retry-After` (or
// `DefaultThrottlePause`) on `nextAllowed` instead of misclassifying a rate limit as a dead socket.
func (h *HostState) RecordOutcome(now time.Time, minPause, retryAfter time.Duration, status int, throttled, transientDead bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.lastSeen = now

	pause := minPause
	if h.robots != nil && now.Before(h.robots.ExpiresAt) && h.robots.CrawlDelay > pause {
		pause = h.robots.CrawlDelay
	}
	if retryAfter > pause {
		pause = retryAfter
	} else if throttled && DefaultThrottlePause > pause {
		pause = DefaultThrottlePause
	}
	if next := now.Add(pause); next.After(h.nextAllowed) {
		h.nextAllowed = next
	}

	if transientDead {
		if h.consecutiveErrors == 0 || (!h.circuitOpenUntil.IsZero() && !now.Before(h.circuitOpenUntil)) || now.Sub(h.firstErrorAt) > CircuitFailureWindow {
			if !h.circuitOpenUntil.IsZero() && !now.Before(h.circuitOpenUntil) {
				// Half-open probe failed: re-open immediately for another cooldown window.
				h.circuitOpenUntil = now.Add(CircuitOpenCooldown)
				return
			}
			h.consecutiveErrors = 1
			h.firstErrorAt = now
		} else {
			h.consecutiveErrors++
		}
		if h.consecutiveErrors >= CircuitFailureThreshold {
			h.circuitOpenUntil = now.Add(CircuitOpenCooldown)
		}
		return
	}

	// `time.Time{}` is Go's zero-value timestamp (`IsZero() == true`), resetting circuit state cleanly without pointers.
	h.consecutiveErrors = 0
	h.firstErrorAt = time.Time{}
	h.circuitOpenUntil = time.Time{}
}

// Registry tracks `HostState` entries across domains with bounded memory eviction.
//
// Go Concurrency Note — Two-Tier Map Locking:
// Built-in Go `map` values are NOT safe for concurrent read + write (`fatal error: concurrent map read and map write`).
// `r.mu` is held only for sub-microsecond map lookup/insertion, while each `*HostState` carries its own mutex so
// rate-limit updates on `alpha.example.com` never contend with `beta.example.com`.
type Registry struct {
	mu    sync.Mutex
	hosts map[string]*HostState
}

// NewRegistry creates an empty per-host politeness registry.
func NewRegistry() *Registry {
	return &Registry{hosts: make(map[string]*HostState)}
}

// Get returns the persistent `HostState` for `host`, evicting idle (>24 h) entries when capacity exceeds `MaxTrackedHosts`.
func (r *Registry) Get(host string, now time.Time) *HostState {
	key := strings.ToLower(host)
	r.mu.Lock()
	defer r.mu.Unlock()
	if st, ok := r.hosts[key]; ok {
		return st
	}
	if len(r.hosts) >= MaxTrackedHosts {
		for k, v := range r.hosts {
			v.mu.Lock()
			idle := now.Sub(v.lastSeen) > HostIdleTTL && len(v.inFlight) == 0
			v.mu.Unlock()
			if idle {
				// Deleting from a Go `map` while iterating it with `range` is explicitly defined and safe in the Go spec.
				delete(r.hosts, k)
			}
		}
	}
	st := newHostState(now)
	r.hosts[key] = st
	return st
}

// ParseRetryAfter parses an RFC 9110 `Retry-After` header (delta-seconds or HTTP-date), clamped to `[0, MaxRetryAfter]`.
func ParseRetryAfter(val string, now time.Time) time.Duration {
	val = strings.TrimSpace(val)
	if val == "" {
		return 0
	}
	if secs, err := strconv.Atoi(val); err == nil {
		if secs <= 0 {
			return 0
		}
		d := time.Duration(secs) * time.Second
		if d > MaxRetryAfter {
			return MaxRetryAfter
		}
		return d
	}
	// Go's `http.ParseTime` checks RFC 1123 (`Mon, 02 Jan 2006 15:04:05 GMT`), RFC 850, and ANSI C formats.
	if t, err := http.ParseTime(val); err == nil {
		d := t.Sub(now)
		if d <= 0 {
			return 0
		}
		if d > MaxRetryAfter {
			return MaxRetryAfter
		}
		return d
	}
	return 0
}

// RobotsRule represents one `Allow` or `Disallow` path directive inside `/robots.txt`.
type RobotsRule struct {
	Pattern string
	Allow   bool
}

// RobotsEntry caches parsed `/robots.txt` rules and `Crawl-delay` for one origin.
type RobotsEntry struct {
	Rules      []RobotsRule
	CrawlDelay time.Duration
	Distressed bool
	ExpiresAt  time.Time
}

// Allowed evaluates RFC 9309 longest-match precedence: whichever matching `Allow` or `Disallow` rule has the longest
// pattern wins; ties break in favor of `Allow`.
func (e *RobotsEntry) Allowed(pathAndQuery string) bool {
	if e == nil || len(e.Rules) == 0 {
		return true
	}
	if pathAndQuery == "" {
		pathAndQuery = "/"
	}
	bestLen := -1
	bestAllow := true
	for _, r := range e.Rules {
		if r.Pattern == "" {
			continue
		}
		if robotsMatch(r.Pattern, pathAndQuery) {
			l := len(r.Pattern)
			if l > bestLen || (l == bestLen && r.Allow) {
				bestLen = l
				bestAllow = r.Allow
			}
		}
	}
	return bestAllow
}

// robotsMatch evaluates `/robots.txt` `*` wildcards and trailing `$` anchors in guaranteed O(P * T) time with zero
// heap allocations (`0 allocs/op` when no `*` wildcard splits are needed, or single small slice otherwise) and zero
// catastrophic regex backtracking risk on untrusted `/robots.txt` input.
func robotsMatch(pattern, target string) bool {
	anchoredEnd := strings.HasSuffix(pattern, "$")
	if anchoredEnd {
		pattern = strings.TrimSuffix(pattern, "$")
	}
	// Fast path when pattern has no `*` wildcards: pure string prefix / exact check with 0 allocations!
	if strings.IndexByte(pattern, '*') < 0 {
		if anchoredEnd {
			return target == pattern
		}
		return strings.HasPrefix(target, pattern)
	}

	pos := 0
	first := true
	rem := pattern
	var lastNonEmpty string
	trailingStar := strings.HasSuffix(pattern, "*")

	// Iterate `*`-separated segments using `strings.Cut` instead of `strings.Split` so wildcard matching allocates
	// ZERO heap slices (`0 B/op`, `0 allocs/op` in `BenchmarkRobotsMatch`)!
	for {
		part, rest, hasStar := strings.Cut(rem, "*")
		if part != "" {
			lastNonEmpty = part
			if first {
				if !strings.HasPrefix(target, part) {
					return false
				}
				pos = len(part)
			} else {
				idx := strings.Index(target[pos:], part)
				if idx < 0 {
					return false
				}
				pos += idx + len(part)
			}
		}
		first = false
		if !hasStar {
			break
		}
		rem = rest
	}

	if anchoredEnd && !trailingStar && lastNonEmpty != "" {
		return strings.HasSuffix(target, lastNonEmpty)
	}
	return true
}

// ParseRobotsTxt extracts directives matching `agentToken` (lowercase product token, preferred per RFC 9309 specificity)
// or fallback `*`, plus `Crawl-delay` clamped to `MaxCrawlDelay`.
func ParseRobotsTxt(body, agentToken string, expiresAt time.Time) *RobotsEntry {
	agentToken = strings.ToLower(strings.TrimSpace(agentToken))
	type group struct {
		agents     []string
		rules      []RobotsRule
		crawlDelay time.Duration
	}
	var groups []group
	var cur group
	seenDirective := false

	for _, rawLine := range strings.Split(body, "\n") {
		if idx := strings.IndexByte(rawLine, '#'); idx >= 0 {
			rawLine = rawLine[:idx]
		}
		line := strings.TrimSpace(rawLine)
		if line == "" {
			if seenDirective && len(cur.agents) > 0 {
				groups = append(groups, cur)
				cur = group{}
				seenDirective = false
			}
			continue
		}
		colon := strings.IndexByte(line, ':')
		if colon <= 0 {
			continue
		}
		field := strings.ToLower(strings.TrimSpace(line[:colon]))
		val := strings.TrimSpace(line[colon+1:])
		switch field {
		case "user-agent":
			if seenDirective && len(cur.agents) > 0 {
				groups = append(groups, cur)
				cur = group{}
				seenDirective = false
			}
			cur.agents = append(cur.agents, strings.ToLower(val))
		case "allow":
			if len(cur.agents) > 0 {
				seenDirective = true
				cur.rules = append(cur.rules, RobotsRule{Pattern: val, Allow: true})
			}
		case "disallow":
			if len(cur.agents) > 0 {
				seenDirective = true
				if val == "" {
					cur.rules = append(cur.rules, RobotsRule{Pattern: "/", Allow: true})
				} else {
					cur.rules = append(cur.rules, RobotsRule{Pattern: val, Allow: false})
				}
			}
		case "crawl-delay":
			if len(cur.agents) > 0 {
				seenDirective = true
				if secs, err := strconv.ParseFloat(val, 64); err == nil && secs > 0 {
					d := time.Duration(secs * float64(time.Second))
					if d > MaxCrawlDelay {
						d = MaxCrawlDelay
					}
					cur.crawlDelay = d
				}
			}
		}
	}
	if len(cur.agents) > 0 {
		groups = append(groups, cur)
	}

	var specificRules, wildcardRules []RobotsRule
	var specificDelay, wildcardDelay time.Duration
	matchedSpecific, matchedWildcard := false, false

	for _, g := range groups {
		for _, ua := range g.agents {
			if agentToken != "" && strings.Contains(ua, agentToken) {
				matchedSpecific = true
				specificRules = append(specificRules, g.rules...)
				if g.crawlDelay > specificDelay {
					specificDelay = g.crawlDelay
				}
			} else if ua == "*" {
				matchedWildcard = true
				wildcardRules = append(wildcardRules, g.rules...)
				if g.crawlDelay > wildcardDelay {
					wildcardDelay = g.crawlDelay
				}
			}
		}
	}

	out := &RobotsEntry{ExpiresAt: expiresAt}
	if matchedSpecific {
		out.Rules = specificRules
		out.CrawlDelay = specificDelay
	} else if matchedWildcard {
		out.Rules = wildcardRules
		out.CrawlDelay = wildcardDelay
	}
	return out
}

// ── Kernel-level DNS-rebinding & IPv6-transition SSRF guard (`net.Dialer.Control`) ─────────────────────────────

// nonPublicCIDRs pre-parses special-use IPv4 and IPv6 blocks at package initialization so `IsPublicIP` performs pure
// byte-slice comparisons on every socket dial without re-parsing CIDR strings.
//
// Security Note — IPv6-to-IPv4 Transition Ranges:
// Go's `ip.To4()` unwraps IPv4-mapped IPv6 (`::ffff:192.168.1.1`), whereas NAT64 (`64:ff9b::c0a8:0101`), RFC 8215
// local-use NAT64 (`64:ff9b:1::/48`), 6to4 (`2002::/16`), and Teredo (`2001::/32`) appear to `ip.IsGlobalUnicast()` as
// normal global IPv6 addresses! Explicitly blocking these transition prefixes prevents DNS AAAA records from reaching
// private LAN devices through dual-stack or NAT64 home routers.
var nonPublicCIDRs = func() []*net.IPNet {
	cidrs := []string{
		"100.64.0.0/10",   // RFC 6598 Carrier-Grade NAT & Tailscale mesh IPs
		"192.0.0.0/24",    // RFC 6890 IETF Protocol Assignments
		"192.0.2.0/24",    // RFC 5737 TEST-NET-1
		"198.18.0.0/15",   // RFC 2544 Benchmarking
		"198.51.100.0/24", // RFC 5737 TEST-NET-2
		"203.0.113.0/24",  // RFC 5737 TEST-NET-3
		"240.0.0.0/4",     // RFC 1112 Reserved
		"100::/64",        // RFC 6666 Discard-Only Prefix
		"64:ff9b::/96",    // RFC 6052 IPv4-IPv6 NAT64 Well-Known Prefix
		"64:ff9b:1::/48",  // RFC 8215 Local-Use IPv4/IPv6 Translation Prefix
		"2001::/32",       // RFC 4380 Teredo Tunneling
		"2001:2::/48",     // RFC 5180 Benchmarking
		"2001:db8::/32",   // RFC 3849 Documentation
		"2002::/16",       // RFC 3056 6to4 Transition Anycast
	}
	out := make([]*net.IPNet, 0, len(cidrs))
	for _, s := range cidrs {
		if _, n, err := net.ParseCIDR(s); err == nil {
			out = append(out, n)
		}
	}
	return out
}()

// IsPublicIP returns true ONLY for globally routable public unicast IPv4/IPv6 addresses.
func IsPublicIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	// Normalize IPv4-mapped IPv6 (`::ffff:127.0.0.1`) to 4-byte IPv4 so IPv4 checks cannot be bypassed.
	if ip4 := ip.To4(); ip4 != nil {
		ip = ip4
	}
	if !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
		return false
	}
	for _, n := range nonPublicCIDRs {
		if n.Contains(ip) {
			return false
		}
	}
	return true
}

// CheckPublicPeerAddress validates the resolved `IP:port` string right before the OS `connect()` syscall fires.
func CheckPublicPeerAddress(address string) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("invalid dial address %q: %w", address, err)
	}
	ip := net.ParseIP(host)
	if !IsPublicIP(ip) {
		return fmt.Errorf("refusing connection to non-public IP %s", host)
	}
	return nil
}

// RejectNonPublicPeer is a `net.Dialer.Control` hook (`func(network, address string, c syscall.RawConn) error`).
//
// Why inspect the peer IP in `Dialer.Control` instead of calling `net.LookupIP` beforehand?
//  1. Eliminates DNS-rebinding TOCTOU (time-of-check to time-of-use) races: `address` is the exact resolved IP the
//     kernel socket is about to `connect()` to.
//  2. Preserves Go's built-in RFC 8305 Happy Eyeballs dual-stack fallback and `httptrace` DNS timing hooks.
func RejectNonPublicPeer(_, address string, _ syscall.RawConn) error {
	return CheckPublicPeerAddress(address)
}
