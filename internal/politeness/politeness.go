package politeness

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net"
	"net/http"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Tuning bounds for per-host politeness, circuit breaking, and `/robots.txt` caching.
const (
	MaxTrackedHosts         = 512
	HostIdleTTL             = 24 * time.Hour
	MaxRetryAfter           = 5 * time.Minute
	DefaultThrottlePause    = 15 * time.Second
	CircuitFailureThreshold = 5
	CircuitFailureWindow    = 60 * time.Second
	CircuitOpenCooldown     = 30 * time.Second
	RobotsCacheTTL          = 24 * time.Hour
	RobotsDistressTTL       = 60 * time.Second
	RobotsMaxBytes          = 1 << 20 // 1 MiB (>= 500 KiB minimum required by RFC 9309 §2.5; closes 520 KiB padding bypass).
	RobotsTimeout           = 5 * time.Second
	MaxRobotsFetchTimeout   = 10 * time.Second
	MaxCrawlDelay           = 30 * time.Second
)

// HostState coordinates concurrent callers targeting the same hostname across independent crawl invocations.
// `inFlight` (capacity 1) provides context-cancellable per-host serialization, while `mu` guards non-blocking metadata updates.
type HostState struct {
	inFlight chan struct{}

	mu                sync.Mutex
	nextAllowed       time.Time
	rateLimitedUntil  time.Time
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

// NoteRateLimit records an active HTTP 429 backoff window so concurrent callers whose contexts expire while waiting on
// `Acquire` can report `Status: 429` with `RetryAfterMs` instead of a generic cancellation.
func (h *HostState) NoteRateLimit(now time.Time, wait time.Duration) {
	if wait <= 0 {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.lastSeen = now
	if until := now.Add(wait); until.After(h.rateLimitedUntil) {
		h.rateLimitedUntil = until
	}
}

// CoolingDownRetryAfterMs returns the remaining HTTP 429 cooldown in milliseconds (`0` when not cooling down from a 429).
func (h *HostState) CoolingDownRetryAfterMs(now time.Time) int64 {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.rateLimitedUntil.After(now) {
		ms := h.rateLimitedUntil.Sub(now).Milliseconds()
		if ms < 1 {
			return 1
		}
		return ms
	}
	return 0
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
	next := now.Add(pause)
	if next.After(h.nextAllowed) {
		h.nextAllowed = next
	}
	if status == http.StatusTooManyRequests {
		if next.After(h.rateLimitedUntil) {
			h.rateLimitedUntil = next
		}
	} else if !transientDead && status >= 200 && status < 400 {
		h.rateLimitedUntil = time.Time{}
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

// Registry tracks HostState entries across domains with bounded memory eviction.
// Two-tier locking keeps map lookups sub-microsecond while per-host updates run under each HostState's own mutex.
type Registry struct {
	mu    sync.Mutex
	hosts map[string]*HostState
}

// NewRegistry creates an empty per-host politeness registry.
func NewRegistry() *Registry {
	return &Registry{hosts: make(map[string]*HostState)}
}

// CanonicalHost normalizes a hostname to lowercase ASCII with any trailing FQDN dot stripped.
func CanonicalHost(host string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
}

// Get returns the persistent `HostState` for `host`, updating `lastSeen` and evicting idle / LRU unlocked entries
// whenever capacity reaches `MaxTrackedHosts`.
func (r *Registry) Get(host string, now time.Time) *HostState {
	key := CanonicalHost(host)
	r.mu.Lock()
	defer r.mu.Unlock()
	if st, ok := r.hosts[key]; ok {
		st.mu.Lock()
		st.lastSeen = now
		st.mu.Unlock()
		return st
	}
	if len(r.hosts) >= MaxTrackedHosts {
		for k, v := range r.hosts {
			v.mu.Lock()
			idle := now.Sub(v.lastSeen) > HostIdleTTL && len(v.inFlight) == 0
			v.mu.Unlock()
			if idle {
				delete(r.hosts, k)
			}
		}
		for len(r.hosts) >= MaxTrackedHosts {
			oldestKey := ""
			var oldestTime time.Time
			for k, v := range r.hosts {
				v.mu.Lock()
				unlocked := len(v.inFlight) == 0
				seen := v.lastSeen
				v.mu.Unlock()
				if !unlocked {
					continue
				}
				if oldestKey == "" || seen.Before(oldestTime) {
					oldestKey = k
					oldestTime = seen
				}
			}
			if oldestKey == "" {
				break
			}
			delete(r.hosts, oldestKey)
		}
	}
	st := newHostState(now)
	r.hosts[key] = st
	return st
}

// ParseRetryAfter parses an RFC 9110 `Retry-After` header (delta-seconds or HTTP-date), clamped to `[0, MaxRetryAfter]`.
// Clamps `secs` before multiplying by `time.Second` so large headers like `Retry-After: 9227000000` cannot overflow `int64`.
func ParseRetryAfter(val string, now time.Time) time.Duration {
	val = strings.TrimSpace(val)
	if val == "" {
		return 0
	}
	const maxSecs = int64(MaxRetryAfter / time.Second)
	if secs, err := strconv.ParseInt(val, 10, 64); err == nil {
		if secs <= 0 {
			return 0
		}
		if secs >= maxSecs {
			return MaxRetryAfter
		}
		return time.Duration(secs) * time.Second
	} else if errors.Is(err, strconv.ErrRange) && !strings.HasPrefix(val, "-") {
		return MaxRetryAfter
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

const maxRobotsMatchScanBytes = 4 << 20 // 4 MiB total scan ceiling across rules per Allowed() call

type compiledRobotsRule struct {
	origLen      int
	allow        bool
	anchoredEnd  bool
	hasStar      bool
	trailingStar bool
	cleanPat     string // collapsed consecutive '*' and stripped trailing '$'
	firstLit     string
	lastLit      string
	minLen       int
	reqBytes     [4]uint64
}

func compileRobotsRule(r RobotsRule) compiledRobotsRule {
	pat := r.Pattern
	c := compiledRobotsRule{
		origLen: len(pat),
		allow:   r.Allow,
	}
	if strings.HasSuffix(pat, "$") {
		c.anchoredEnd = true
		pat = pat[:len(pat)-1]
	}
	if strings.Contains(pat, "**") {
		var sb strings.Builder
		sb.Grow(len(pat))
		prevStar := false
		for i := 0; i < len(pat); i++ {
			if pat[i] == '*' {
				if prevStar {
					continue
				}
				prevStar = true
			} else {
				prevStar = false
			}
			sb.WriteByte(pat[i])
		}
		pat = sb.String()
	}
	c.cleanPat = pat
	if strings.IndexByte(pat, '*') < 0 {
		c.firstLit = pat
		c.lastLit = pat
		c.minLen = len(pat)
		for i := 0; i < len(pat); i++ {
			b := pat[i]
			c.reqBytes[b>>6] |= 1 << (b & 63)
		}
		return c
	}
	c.hasStar = true
	c.trailingStar = strings.HasSuffix(pat, "*")
	rem := pat
	first := true
	for {
		part, rest, ok := strings.Cut(rem, "*")
		if first {
			c.firstLit = part
			first = false
		}
		if part != "" {
			c.lastLit = part
			c.minLen += len(part)
			for i := 0; i < len(part); i++ {
				b := part[i]
				c.reqBytes[b>>6] |= 1 << (b & 63)
			}
		}
		if !ok {
			break
		}
		rem = rest
	}
	return c
}

func compileAndSortRobotsRules(rules []RobotsRule) []compiledRobotsRule {
	if len(rules) == 0 {
		return nil
	}
	out := make([]compiledRobotsRule, 0, len(rules))
	for _, r := range rules {
		if r.Pattern == "" {
			continue
		}
		out = append(out, compileRobotsRule(r))
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].origLen != out[j].origLen {
			return out[i].origLen > out[j].origLen
		}
		return out[i].allow && !out[j].allow
	})
	return out
}

func deduplicateRobotsRules(rules []RobotsRule) []RobotsRule {
	if len(rules) <= 1 {
		return rules
	}
	type ruleKey struct {
		pat   string
		allow bool
	}
	seen := make(map[ruleKey]struct{}, len(rules))
	out := make([]RobotsRule, 0, len(rules))
	for _, r := range rules {
		if r.Pattern == "" {
			continue
		}
		k := ruleKey{pat: r.Pattern, allow: r.Allow}
		if _, dup := seen[k]; dup {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, r)
	}
	return out
}

// RobotsEntry caches parsed `/robots.txt` rules, Content Signals, and `Crawl-delay` for one origin.
// When `Distressed` is true (RFC 9309 §2.3.1.4 unreachable: network error, 429, or 5xx), all paths are treated as disallowed.
// When `DisallowAIInput` is true (`Content-Signal: ai-input=no`), all paths are disallowed for user-triggered agent retrieval.
type RobotsEntry struct {
	Rules           []RobotsRule
	CrawlDelay      time.Duration
	DisallowAIInput bool
	Distressed      bool
	DNSNotFound     bool
	SSRFBlocked     bool
	Reason          string
	ExpiresAt       time.Time
	compiled        []compiledRobotsRule
}

// ContentSignalBlocked reports whether `/robots.txt` disallowed agent retrieval via `Content-Signal: ai-input=no`.
func (e *RobotsEntry) ContentSignalBlocked() bool {
	return e != nil && !e.Distressed && e.DisallowAIInput
}

// Allowed evaluates RFC 9309 longest-match precedence: whichever matching `Allow` or `Disallow` rule has the longest
// pattern wins; ties break in favor of `Allow`. Also evaluates dot-segment/collapsed-slash/matrix-stripped path
// canonicalization (`/../`, `/./`, `//`, `;param`) so origin path normalization cannot bypass a `Disallow` rule.
func (e *RobotsEntry) Allowed(pathAndQuery string) bool {
	if e == nil {
		return true
	}
	if e.Distressed || e.DisallowAIInput {
		return false
	}
	if len(e.Rules) == 0 {
		return true
	}
	if h := strings.IndexByte(pathAndQuery, '#'); h >= 0 {
		pathAndQuery = pathAndQuery[:h]
	}
	if pathAndQuery == "" {
		pathAndQuery = "/"
	}
	normRaw := NormalizeRobotsURI(pathAndQuery)
	if !e.allowedSingle(normRaw) {
		return false
	}
	normCanon := canonicalizeRobotsTarget(normRaw)
	if normCanon != normRaw && !e.allowedSingle(normCanon) {
		return false
	}
	return true
}

func (e *RobotsEntry) allowedSingle(target string) bool {
	comp := e.compiled
	if len(comp) == 0 && len(e.Rules) > 0 {
		comp = compileAndSortRobotsRules(deduplicateRobotsRules(e.Rules))
	}
	if len(comp) == 0 {
		return true
	}

	var targetMask [4]uint64
	maskEligible := len(comp) >= 8 || len(target) >= 256
	maskBuilt := false

	var scanned int64
	for i := range comp {
		r := &comp[i]
		if len(target) < r.minLen {
			continue
		}
		if r.firstLit != "" && !strings.HasPrefix(target, r.firstLit) {
			continue
		}
		if r.anchoredEnd && !r.trailingStar && r.lastLit != "" && !strings.HasSuffix(target, r.lastLit) {
			continue
		}
		if maskEligible {
			if !maskBuilt {
				for j := 0; j < len(target); j++ {
					b := target[j]
					targetMask[b>>6] |= 1 << (b & 63)
				}
				maskBuilt = true
			}
			if (r.reqBytes[0]&^targetMask[0])|(r.reqBytes[1]&^targetMask[1])|(r.reqBytes[2]&^targetMask[2])|(r.reqBytes[3]&^targetMask[3]) != 0 {
				continue
			}
		}
		matched, work := matchCompiledRobotsRule(r, target)
		scanned += int64(work)
		if matched {
			return r.allow
		}
		if scanned > maxRobotsMatchScanBytes {
			// Pathological rule × path complexity budget exceeded: fail closed.
			return false
		}
	}
	return true
}

func canonicalizeRobotsTarget(norm string) string {
	pathPart := norm
	queryPart := ""
	hasQuery := false
	if q := strings.IndexByte(norm, '?'); q >= 0 {
		pathPart = norm[:q]
		queryPart = norm[q:]
		hasQuery = true
	}
	// Fast SIMD check: if pathPart starts with '/', has no "//", no "/.", and no ';', nothing changes!
	needsClean := pathPart == "" ||
		pathPart[0] != '/' ||
		strings.IndexByte(pathPart, ';') >= 0 ||
		strings.Contains(pathPart, "//") ||
		strings.Contains(pathPart, "/.")
	if !needsClean {
		return norm
	}

	trailingSlash := strings.HasSuffix(pathPart, "/") || strings.HasSuffix(pathPart, "/.") || strings.HasSuffix(pathPart, "/..")
	var segs []string
	rem := pathPart
	for len(rem) > 0 {
		var seg string
		if sl := strings.IndexByte(rem, '/'); sl >= 0 {
			seg = rem[:sl]
			rem = rem[sl+1:]
		} else {
			seg = rem
			rem = ""
		}
		if semi := strings.IndexByte(seg, ';'); semi >= 0 {
			seg = seg[:semi]
		}
		switch seg {
		case "", ".":
			continue
		case "..":
			if len(segs) > 0 {
				segs = segs[:len(segs)-1]
			}
		default:
			segs = append(segs, seg)
		}
	}
	var b strings.Builder
	b.Grow(len(norm))
	b.WriteByte('/')
	for i, s := range segs {
		if i > 0 {
			b.WriteByte('/')
		}
		b.WriteString(s)
	}
	if trailingSlash && len(segs) > 0 {
		b.WriteByte('/')
	}
	if hasQuery {
		b.WriteString(queryPart)
	}
	return b.String()
}

// NormalizeRobotsURI normalizes percent-encoding in `/robots.txt` patterns and target paths per RFC 9309 §2.2.2:
//   - Unreserved ASCII octets (`A-Z`, `a-z`, `0-9`, `-`, `.`, `_`, `~`) encoded as `%XX` decode to literal ASCII.
//   - Valid `%xx` sequences for reserved or non-ASCII octets uppercase to `%XX` (`%c3%a9` -> `%C3%A9`).
//   - Raw non-ASCII UTF-8 bytes (`>= 0x80`) encode to uppercase `%XX`.
//   - Pure ASCII strings without `%` return `s` directly with zero allocations (`0 B/op`).
func NormalizeRobotsURI(s string) string {
	needsWork := false
	for i := 0; i < len(s); i++ {
		if s[i] == '%' || s[i] >= 0x80 {
			needsWork = true
			break
		}
	}
	if !needsWork {
		return s
	}

	const upperHex = "0123456789ABCDEF"
	var b strings.Builder
	b.Grow(len(s) + 8)
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if ch == '%' && i+2 < len(s) {
			hi, ok1 := fromHex(s[i+1])
			lo, ok2 := fromHex(s[i+2])
			if ok1 && ok2 {
				decoded := (hi << 4) | lo
				if isUnreservedURIByte(decoded) {
					b.WriteByte(decoded)
				} else {
					b.WriteByte('%')
					b.WriteByte(upperHex[hi])
					b.WriteByte(upperHex[lo])
				}
				i += 2
				continue
			}
		}
		if ch >= 0x80 {
			b.WriteByte('%')
			b.WriteByte(upperHex[ch>>4])
			b.WriteByte(upperHex[ch&0x0F])
			continue
		}
		b.WriteByte(ch)
	}
	return b.String()
}

func fromHex(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	default:
		return 0, false
	}
}

func isUnreservedURIByte(c byte) bool {
	return (c >= 'A' && c <= 'Z') ||
		(c >= 'a' && c <= 'z') ||
		(c >= '0' && c <= '9') ||
		c == '-' || c == '.' || c == '_' || c == '~'
}

func matchCompiledRobotsRule(r *compiledRobotsRule, target string) (bool, int) {
	if !r.hasStar {
		if r.anchoredEnd {
			return target == r.cleanPat, len(r.cleanPat)
		}
		return strings.HasPrefix(target, r.cleanPat), len(r.cleanPat)
	}
	if r.firstLit != "" && !strings.HasPrefix(target, r.firstLit) {
		return false, len(r.firstLit)
	}
	if r.anchoredEnd && !r.trailingStar && r.lastLit != "" && !strings.HasSuffix(target, r.lastLit) {
		return false, len(r.lastLit)
	}

	pos := len(r.firstLit)
	work := pos
	remLit := r.minLen - pos
	_, rem, hasStar := strings.Cut(r.cleanPat, "*")
	for hasStar {
		if len(target)-pos < remLit {
			return false, work
		}
		var part string
		part, rem, hasStar = strings.Cut(rem, "*")
		if part != "" {
			idx := strings.Index(target[pos:], part)
			if idx < 0 {
				work += len(target) - pos
				return false, work
			}
			step := idx + len(part)
			pos += step
			work += step
			remLit -= len(part)
		}
	}
	return true, work
}

// robotsMatch evaluates `/robots.txt` `*` wildcards and trailing `$` anchors in guaranteed O(P * T) time with zero
// heap allocations (`0 allocs/op` when no `*` wildcard splits are needed) and zero catastrophic regex backtracking risk.
func robotsMatch(pattern, target string) bool {
	c := compileRobotsRule(RobotsRule{Pattern: pattern})
	matched, _ := matchCompiledRobotsRule(&c, target)
	return matched
}

var robotsLineReplacer = strings.NewReplacer(
	"\r\n", "\n",
	"\r", "\n",
	"\u0085", "\n",
	"\u2028", "\n",
	"\u2029", "\n",
)

func trimRobotsWS(s string) string {
	return strings.Trim(s, " \t")
}

func isZeroWidthRobotsRune(r rune) bool {
	switch r {
	case '\uFEFF', '\u200B', '\u200C', '\u200D', '\u2060':
		return true
	default:
		return false
	}
}

func trimRobotsWSAndZeroWidth(s string) string {
	return strings.TrimFunc(s, func(r rune) bool {
		return r == ' ' || r == '\t' || isZeroWidthRobotsRune(r)
	})
}

func asciiLowerRobotsString(s string) string {
	hasUpper := false
	for i := 0; i < len(s); i++ {
		if s[i] >= 'A' && s[i] <= 'Z' {
			hasUpper = true
			break
		}
	}
	if !hasUpper {
		return s
	}
	b := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		b[i] = c
	}
	return string(b)
}

func isValidCrawlDelayDecimal(s string) bool {
	if s == "" {
		return false
	}
	i := 0
	if s[i] == '+' || s[i] == '-' {
		i++
	}
	if i >= len(s) {
		return false
	}
	sawDigit := false
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		sawDigit = true
		i++
	}
	if i < len(s) && s[i] == '.' {
		i++
		for i < len(s) && s[i] >= '0' && s[i] <= '9' {
			sawDigit = true
			i++
		}
	}
	if !sawDigit {
		return false
	}
	if i < len(s) && (s[i] == 'e' || s[i] == 'E') {
		i++
		if i < len(s) && (s[i] == '+' || s[i] == '-') {
			i++
		}
		expDigits := 0
		for i < len(s) && s[i] >= '0' && s[i] <= '9' {
			expDigits++
			i++
		}
		if expDigits == 0 {
			return false
		}
	}
	return i == len(s)
}

// ParseRobotsTxt extracts directives matching `agentToken` (lowercase product token, preferred per RFC 9309 specificity)
// or fallback `*`, plus `Crawl-delay` clamped to `MaxCrawlDelay` and `Content-Signal` (`ai-input`).
func ParseRobotsTxt(body, agentToken string, expiresAt time.Time) *RobotsEntry {
	if len(body) > RobotsMaxBytes {
		body = body[:RobotsMaxBytes]
		if nl := strings.LastIndexAny(body, "\r\n\u0085\u2028\u2029"); nl >= 0 {
			body = body[:nl]
		} else {
			body = ""
		}
	}
	// RFC 9309 §2.1: strip any leading UTF-8 BOMs and zero-width format characters so the first directive is never corrupted.
	body = strings.TrimLeftFunc(body, isZeroWidthRobotsRune)
	agentToken = canonicalProductToken(agentToken)
	type group struct {
		agents          []string
		rules           []RobotsRule
		crawlDelay      time.Duration
		aiInputDisallow *bool
	}
	var groups []group
	var cur group
	var preGroupAiInput *bool
	seenDirective := false
	seenAnyUserAgent := false

	normalizedBody := robotsLineReplacer.Replace(body)
	for _, rawLine := range strings.Split(normalizedBody, "\n") {
		if idx := strings.IndexByte(rawLine, '#'); idx >= 0 {
			rawLine = rawLine[:idx]
		}
		line := strings.TrimLeftFunc(rawLine, func(r rune) bool {
			return r == ' ' || r == '\t' || isZeroWidthRobotsRune(r)
		})
		line = trimRobotsWS(line)
		if line == "" {
			// RFC 9309 §2.2.1: blank lines inside a group do NOT terminate the current User-agent group;
			// a group only ends when a subsequent User-agent line appears after a rule directive.
			continue
		}
		colon := strings.IndexByte(line, ':')
		if colon <= 0 {
			continue
		}
		rawField := line[:colon]
		if strings.IndexByte(rawField, 0) >= 0 {
			continue
		}
		field := asciiLowerRobotsString(trimRobotsWSAndZeroWidth(rawField))
		rawVal := trimRobotsWS(line[colon+1:])
		val := rawVal
		if nul := strings.IndexByte(val, 0); nul >= 0 {
			val = trimRobotsWS(val[:nul])
		}
		switch field {
		case "user-agent":
			seenAnyUserAgent = true
			if seenDirective && len(cur.agents) > 0 {
				groups = append(groups, cur)
				cur = group{}
				seenDirective = false
			}
			ua := canonicalProductToken(val)
			if ua == "" {
				continue
			}
			cur.agents = append(cur.agents, ua)
		case "allow":
			if len(cur.agents) > 0 {
				seenDirective = true
				if val != "" {
					pat := NormalizeRobotsURI(val)
					if strings.HasPrefix(pat, "/") || strings.HasPrefix(pat, "*") {
						cur.rules = append(cur.rules, RobotsRule{Pattern: pat, Allow: true})
					}
				}
			}
		case "disallow":
			if len(cur.agents) > 0 {
				seenDirective = true
				if val != "" {
					pat := NormalizeRobotsURI(val)
					if strings.HasPrefix(pat, "/") || strings.HasPrefix(pat, "*") {
						cur.rules = append(cur.rules, RobotsRule{Pattern: pat, Allow: false})
					}
				}
			}
		case "crawl-delay":
			if len(cur.agents) > 0 {
				seenDirective = true
				if isValidCrawlDelayDecimal(val) {
					if secs, err := strconv.ParseFloat(val, 64); err == nil && !math.IsNaN(secs) && !math.IsInf(secs, 0) && secs > 0 {
						maxSecs := float64(MaxCrawlDelay) / float64(time.Second)
						if secs >= maxSecs {
							cur.crawlDelay = MaxCrawlDelay
						} else {
							cur.crawlDelay = time.Duration(secs * float64(time.Second))
						}
					}
				}
			}
		case "content-signal":
			if len(cur.agents) > 0 {
				seenDirective = true
				if disallow, found := parseContentSignalAIInput(rawVal); found {
					v := disallow
					cur.aiInputDisallow = &v
				}
			} else if !seenAnyUserAgent {
				if disallow, found := parseContentSignalAIInput(rawVal); found {
					v := disallow
					preGroupAiInput = &v
				}
			}
		}
	}
	if len(cur.agents) > 0 {
		groups = append(groups, cur)
	}

	var specificRules, wildcardRules []RobotsRule
	var specificDelay, wildcardDelay time.Duration
	var specificSetAI, specificDisallowAI, wildcardSetAI, wildcardDisallowAI bool
	matchedSpecific, matchedWildcard := false, false

	for _, g := range groups {
		groupSpecific := false
		groupWildcard := false
		for _, ua := range g.agents {
			if agentToken != "" && ua == agentToken {
				groupSpecific = true
			} else if ua == "*" {
				groupWildcard = true
			}
		}
		if groupSpecific {
			matchedSpecific = true
			specificRules = append(specificRules, g.rules...)
			if g.crawlDelay > specificDelay {
				specificDelay = g.crawlDelay
			}
			if g.aiInputDisallow != nil {
				specificSetAI = true
				if *g.aiInputDisallow {
					specificDisallowAI = true
				}
			}
		}
		if groupWildcard {
			matchedWildcard = true
			wildcardRules = append(wildcardRules, g.rules...)
			if g.crawlDelay > wildcardDelay {
				wildcardDelay = g.crawlDelay
			}
			if g.aiInputDisallow != nil {
				wildcardSetAI = true
				if *g.aiInputDisallow {
					wildcardDisallowAI = true
				}
			}
		}
	}

	out := &RobotsEntry{ExpiresAt: expiresAt}
	if matchedSpecific {
		out.Rules = deduplicateRobotsRules(specificRules)
		out.CrawlDelay = specificDelay
		if specificSetAI {
			out.DisallowAIInput = specificDisallowAI
		} else if wildcardSetAI {
			out.DisallowAIInput = wildcardDisallowAI
		} else if preGroupAiInput != nil {
			out.DisallowAIInput = *preGroupAiInput
		}
	} else if matchedWildcard {
		out.Rules = deduplicateRobotsRules(wildcardRules)
		out.CrawlDelay = wildcardDelay
		if wildcardSetAI {
			out.DisallowAIInput = wildcardDisallowAI
		} else if preGroupAiInput != nil {
			out.DisallowAIInput = *preGroupAiInput
		}
	} else if preGroupAiInput != nil {
		out.DisallowAIInput = *preGroupAiInput
	}
	out.compiled = compileAndSortRobotsRules(out.Rules)
	return out
}

func parseContentSignalAIInput(val string) (disallow, found bool) {
	if len(val) > 524_288 {
		val = val[:524_288]
	}
	for _, item := range strings.FieldsFunc(val, func(r rune) bool { return r == ',' || r == ';' }) {
		if strings.IndexByte(item, 0) >= 0 {
			continue
		}
		k, v, ok := strings.Cut(item, "=")
		if !ok {
			continue
		}
		if asciiLowerRobotsString(trimRobotsWS(k)) != "ai-input" {
			continue
		}
		cleanV := trimRobotsWS(v)
		if len(cleanV) >= 2 && ((cleanV[0] == '"' && cleanV[len(cleanV)-1] == '"') || (cleanV[0] == '\'' && cleanV[len(cleanV)-1] == '\'')) {
			cleanV = trimRobotsWS(cleanV[1 : len(cleanV)-1])
		}
		switch asciiLowerRobotsString(cleanV) {
		case "no":
			disallow = true
			found = true
		case "yes":
			disallow = false
			found = true
		}
	}
	return disallow, found
}

func canonicalProductToken(raw string) string {
	tok := asciiLowerRobotsString(trimRobotsWS(raw))
	if tok == "*" {
		return "*"
	}
	if slash := strings.IndexByte(tok, '/'); slash >= 0 {
		tok = trimRobotsWS(tok[:slash])
	}
	if sp := strings.IndexAny(tok, " \t"); sp >= 0 {
		tok = trimRobotsWS(tok[:sp])
	}
	return tok
}

// ── Dial-time DNS-rebinding & special-purpose IP SSRF guard (net.Dialer.Control) ─────────────────────────────────

var ipv6GlobalUnicastPrefix = netip.MustParsePrefix("2000::/3")

// nonPublicPrefixes pre-parses IANA special-purpose IPv4 and IPv6 blocks (RFC 6890 / RFC 3879 / RFC 4291 / RFC 6052 /
// RFC 7526 / RFC 9637 / RFC 4843 / RFC 7343 / RFC 9602) at package initialization using netip.Prefix.
var nonPublicPrefixes = func() []netip.Prefix {
	cidrs := []string{
		"0.0.0.0/8",           // RFC 1122 "This host on this network" (e.g. 0.1.2.3 -> local stack on Linux)
		"100.64.0.0/10",       // RFC 6598 Carrier-Grade NAT & Tailscale mesh IPs
		"192.0.0.0/24",        // RFC 6890 IETF Protocol Assignments
		"192.0.2.0/24",        // RFC 5737 TEST-NET-1
		"192.88.99.0/24",      // RFC 7526 Deprecated 6to4 Relay Anycast
		"198.18.0.0/15",       // RFC 2544 Benchmarking
		"198.51.100.0/24",     // RFC 5737 TEST-NET-2
		"203.0.113.0/24",      // RFC 5737 TEST-NET-3
		"240.0.0.0/4",         // RFC 1112 Reserved
		"::/96",               // RFC 4291 §2.5.5.1 Deprecated IPv4-Compatible IPv6 (e.g. ::7f00:1)
		"0:0:0:0:ffff:0::/96", // RFC 2765 SIIT IPv4-Translated IPv6 (e.g. ::ffff:0:127.0.0.1)
		"100::/64",            // RFC 6666 Discard-Only Prefix
		"64:ff9b::/96",        // RFC 6052 IPv4-IPv6 NAT64 Well-Known Prefix
		"64:ff9b:1::/48",      // RFC 8215 Local-Use IPv4/IPv6 Translation Prefix
		"2001::/32",           // RFC 4380 Teredo Tunneling
		"2001:2::/48",         // RFC 5180 Benchmarking
		"2001:10::/28",        // RFC 4843 ORCHID
		"2001:20::/28",        // RFC 7343 ORCHIDv2
		"2001:db8::/32",       // RFC 3849 Documentation
		"2002::/16",           // RFC 3056 6to4 Transition Anycast
		"3fff::/20",           // RFC 9637 IPv6 Documentation Prefix
		"5f00::/16",           // RFC 9602 Segment Routing over IPv6 (SRv6) SIDs
		"fec0::/10",           // RFC 3879 Deprecated Site-Local IPv6 (e.g. fec0::1)
	}
	out := make([]netip.Prefix, 0, len(cidrs))
	for _, s := range cidrs {
		if p, err := netip.ParsePrefix(s); err == nil {
			out = append(out, p)
		}
	}
	return out
}()

// IsPublicIP returns true ONLY for globally routable public unicast IPv4/IPv6 addresses.
func IsPublicIP(ip net.IP) bool {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	return IsPublicAddr(addr)
}

// IsPublicAddr evaluates a value-typed netip.Addr with zero heap allocations.
func IsPublicAddr(addr netip.Addr) bool {
	if !addr.IsValid() || addr.Zone() != "" {
		return false
	}
	// Unwrap IPv4-mapped IPv6 (::ffff:127.0.0.1 -> 127.0.0.1) so IPv4 prefixes apply uniformly.
	addr = addr.Unmap()
	if addr.Is6() && !ipv6GlobalUnicastPrefix.Contains(addr) {
		return false
	}
	if !addr.IsGlobalUnicast() || addr.IsPrivate() || addr.IsLoopback() || addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() || addr.IsMulticast() || addr.IsUnspecified() {
		return false
	}
	for _, p := range nonPublicPrefixes {
		if p.Contains(addr) {
			return false
		}
	}
	return true
}

// ErrNonPublicPeer is returned when dial-time resolution maps a hostname onto a non-public IP address.
var ErrNonPublicPeer = errors.New("non-public peer IP")

// CheckPublicPeerAddress validates the resolved IP:port string right before the OS connect() syscall fires.
func CheckPublicPeerAddress(address string) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("invalid dial address %q: %w", address, err)
	}
	addr, err := netip.ParseAddr(host)
	if err != nil || !IsPublicAddr(addr) {
		return fmt.Errorf("%w: refusing connection to non-public IP %s", ErrNonPublicPeer, host)
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
