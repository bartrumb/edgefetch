package politeness

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestHostStateSerializesConcurrentCallersAndCancelsCleanly(t *testing.T) {
	reg := NewRegistry()
	now := time.Unix(1_700_000_000, 0)
	hs := reg.Get("Example.COM", now)

	if err := hs.Acquire(context.Background()); err != nil {
		t.Fatalf("first Acquire failed: %v", err)
	}

	// Second caller with a tight deadline cancels while the first caller still holds the token, proving
	// `chan struct{}` avoids blocking past context expiration unlike `sync.Mutex.Lock()`.
	shortCtx, cancel := context.WithTimeout(context.Background(), 15*time.Millisecond)
	defer cancel()
	if err := hs.Acquire(shortCtx); err == nil {
		t.Fatal("expected Acquire to fail on expired context while host lock is held")
	}

	hs.Release()

	// Verify 4 goroutines never overlap on the same host under `-race`.
	var active, maxActive atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := hs.Acquire(context.Background()); err != nil {
				t.Errorf("Acquire: %v", err)
				return
			}
			defer hs.Release()
			if cur := active.Add(1); cur > maxActive.Load() {
				maxActive.Store(cur)
			}
			time.Sleep(5 * time.Millisecond)
			active.Add(-1)
		}()
	}
	wg.Wait()
	if got := maxActive.Load(); got != 1 {
		t.Fatalf("max concurrent in-flight = %d, want 1", got)
	}
}

func TestCircuitBreakerTransitionsClosedOpenHalfOpen(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	hs := NewRegistry().Get("origin.example.com", now)

	// 4 transient failures keep circuit Closed; 5th opens it.
	for i := 1; i <= CircuitFailureThreshold; i++ {
		if why := hs.CheckCircuit(now, "origin.example.com"); why != "" {
			t.Fatalf("attempt %d unexpectedly open: %s", i, why)
		}
		hs.RecordOutcome(now, 2*time.Second, 0, 502, false, true)
		now = now.Add(time.Second)
	}

	if why := hs.CheckCircuit(now, "origin.example.com"); why == "" {
		t.Fatal("expected circuit Open after 5 consecutive 502s")
	}

	// Advance past cooldown -> Half-Open allows one probe; HTTP 200 resets to Closed.
	now = now.Add(CircuitOpenCooldown + time.Second)
	if why := hs.CheckCircuit(now, "origin.example.com"); why != "" {
		t.Fatalf("expected Half-Open after cooldown, got %q", why)
	}
	hs.RecordOutcome(now, 2*time.Second, 0, 200, false, false)
	if why := hs.CheckCircuit(now, "origin.example.com"); why != "" {
		t.Fatalf("expected Closed after healthy probe, got %q", why)
	}
}

func TestParseRobotsTxtAndLongestMatchPrecedence(t *testing.T) {
	raw := `
User-agent: *
Disallow: /admin
Allow: /admin/public
Disallow: /*.php$
Crawl-delay: 4

User-agent: EdgeFetch
Disallow: /private-feed
Crawl-delay: 2
`
	exp := time.Now().Add(time.Hour)

	// Specific `edgefetch` group wins over `*` per RFC 9309.
	specific := ParseRobotsTxt(raw, "edgefetch", exp)
	if specific.CrawlDelay != 2*time.Second {
		t.Fatalf("specific CrawlDelay = %s, want 2s", specific.CrawlDelay)
	}
	if specific.Allowed("/private-feed/items.json") {
		t.Error("expected /private-feed/items.json disallowed for edgefetch")
	}
	if !specific.Allowed("/admin") {
		t.Error("specific group replaces wildcard group per RFC 9309")
	}

	// Wildcard fallback checks longest-match (`Allow: /admin/public` beats `Disallow: /admin`) and `$` anchor.
	wild := ParseRobotsTxt(raw, "otherbot", exp)
	if wild.Allowed("/admin/secret") {
		t.Error("expected /admin/secret disallowed")
	}
	if !wild.Allowed("/admin/public/doc") {
		t.Error("expected /admin/public/doc allowed by longer rule")
	}
	if wild.Allowed("/legacy/login.php") {
		t.Error("expected /legacy/login.php disallowed by /*.php$")
	}
	if !wild.Allowed("/legacy/login.php?next=1") {
		t.Error("expected query string not to match end-anchored /*.php$")
	}
}

func TestRobotsRFC9309EdgeCasesBOMPercentEncodingProductTokenAnd500KiB(t *testing.T) {
	exp := time.Now().Add(time.Hour)

	// 1. UTF-8 BOM at byte 0 must NOT swallow the first User-agent group.
	bomRobots := "\xef\xbb\xbfUser-agent: *\nDisallow: /\n"
	if ParseRobotsTxt(bomRobots, "edgefetch", exp).Allowed("/anything") {
		t.Fatal("A4 BUG: UTF-8 BOM caused Disallow: / group to be ignored")
	}

	// 2. Percent-encoding case & unreserved normalization per RFC 9309 §2.2.2.
	pctRobots := "User-agent: *\nDisallow: /caf%C3%A9\nDisallow: /~admin\n"
	pctEntry := ParseRobotsTxt(pctRobots, "edgefetch", exp)
	if pctEntry.Allowed("/caf%c3%a9/menu") {
		t.Fatalf("%s", "A4 BUG: lowercase /caf%c3%a9 bypassed /caf%C3%A9 rule")
	}
	if pctEntry.Allowed("/café/menu") {
		t.Fatalf("%s", "A4 BUG: raw UTF-8 /café bypassed /caf%C3%A9 rule")
	}
	if pctEntry.Allowed("/%7eadmin/panel") {
		t.Fatalf("%s", "A4 BUG: encoded unreserved /%7eadmin bypassed /~admin rule")
	}

	// 3. Substring User-agent (`notedgefetchbot`) must NOT match `edgefetch`.
	subRobots := "User-agent: notedgefetchbot\nDisallow: /\n\nUser-agent: *\nDisallow: /secret\n"
	subEntry := ParseRobotsTxt(subRobots, "edgefetch", exp)
	if !subEntry.Allowed("/public") {
		t.Fatal("A4 BUG: User-agent: notedgefetchbot falsely matched edgefetch")
	}
	if subEntry.Allowed("/secret") {
		t.Fatal("expected wildcard Disallow: /secret to apply")
	}

	// 4. RFC 9309 §2.5 requires parsing at least 500 KiB of robots.txt.
	if RobotsMaxBytes < 500*1024 {
		t.Fatalf("A4 BUG: RobotsMaxBytes = %d, RFC 9309 requires >= 512000", RobotsMaxBytes)
	}
}

func FuzzParseRobotsTxt(f *testing.F) {
	f.Add("User-agent: *\nDisallow: /admin\nAllow: /admin/public\n")
	f.Add("\xef\xbb\xbfUser-agent: EdgeFetch/1.0\r\nDisallow: /*.json$\r\nCrawl-delay: 1.5\r\n")
	f.Add("User-agent: *\nDisallow: /caf%C3%A9/*\nAllow: /%7Euser/\n")
	f.Fuzz(func(t *testing.T, body string) {
		entry := ParseRobotsTxt(body, "edgefetch", time.Unix(1_800_000_000, 0))
		_ = entry.Allowed("/")
		_ = entry.Allowed("/caf%c3%a9/items.json?page=1")
		_ = entry.Allowed("/%7euser/profile")
	})
}

func TestSSRFGuardBlocksPrivateLoopbackCGNATAndIPv6TransitionRanges(t *testing.T) {
	blocked := []string{
		"127.0.0.1:443",
		"10.0.0.5:443",
		"172.30.32.2:8123",          // Home Assistant OS internal Supervisor bridge!
		"192.168.1.1:443",           // Home/shop LAN router
		"100.100.100.100:443",       // Tailscale MagicDNS / RFC 6598 CGNAT
		"169.254.169.254:80",        // Cloud instance metadata
		"[::1]:443",                 // IPv6 loopback
		"[::ffff:192.168.1.10]:443", // IPv4-mapped IPv6 LAN address
		"[fe80::1]:443",             // IPv6 link-local
		"[fd00::1234]:443",          // IPv6 Unique Local Address (ULA)
		"[64:ff9b::c0a8:101]:443",   // NAT64 well-known prefix wrapping 192.168.1.1!
		"[64:ff9b:1::7f00:1]:443",   // Local-use NAT64 wrapping 127.0.0.1!
		"[2002:c0a8:101::1]:443",    // 6to4 wrapping 192.168.1.1
		"[2001:0000:4136:e378:8000:63bf:3fff:fdd2]:443", // Teredo tunnel
		"0.1.2.3:443",              // RFC 1122 0.0.0.0/8 "this network"
		"[fec0::1]:443",            // RFC 3879 deprecated site-local IPv6
		"[::7f00:1]:443",           // RFC 4291 deprecated IPv4-compatible IPv6 (127.0.0.1)
		"[::ffff:0:127.0.0.1]:443", // RFC 2765 SIIT IPv4-translated IPv6
		"[100::1]:443",             // RFC 6666 discard prefix
		"[2001:db8::1]:443",        // RFC 3849 documentation prefix
		"192.88.99.1:443",          // RFC 7526 deprecated 6to4 relay anycast (A7)
		"[3fff::1]:443",            // RFC 9637 IPv6 documentation prefix (A7)
		"[2001:10::1]:443",         // RFC 4843 ORCHID (A7)
		"[2001:20::1]:443",         // RFC 7343 ORCHIDv2 (A7)
		"[5f00::1]:443",            // RFC 9602 SRv6 SIDs / outside 2000::/3 (A7)
		"[4000::1]:443",            // IANA reserved IPv6 outside 2000::/3 global unicast (A7)
	}
	for _, addr := range blocked {
		if err := CheckPublicPeerAddress(addr); err == nil {
			t.Errorf("SECURITY: expected %s to be blocked by SSRF guard, but it was allowed", addr)
		}
	}

	allowed := []string{
		"1.1.1.1:443",
		"8.8.8.8:443",
		"93.184.216.34:443",
		"[::ffff:93.184.216.34]:443",
		"[2001:4860:4860::8888]:443",
		"[2606:4700:4700::1111]:443",
	}
	for _, addr := range allowed {
		if err := CheckPublicPeerAddress(addr); err != nil {
			t.Errorf("expected public peer %s allowed, got %v", addr, err)
		}
	}

	if got := CanonicalHost("HUB.Example.COM."); got != "hub.example.com" {
		t.Fatalf("CanonicalHost trailing dot = %q, want hub.example.com", got)
	}
	distressed := &RobotsEntry{Distressed: true}
	if distressed.Allowed("/public") {
		t.Fatal("RFC 9309: distressed/unreachable RobotsEntry must disallow all paths")
	}
}

func TestRegistryBoundsTrackedHostsWithLRUEviction(t *testing.T) {
	r := NewRegistry()
	now := time.Unix(1_700_000_000, 0)
	hotHost := "hot.example.com"
	hotState := r.Get(hotHost, now)

	for i := 0; i < 5000; i++ {
		now = now.Add(time.Millisecond)
		if i%100 == 0 {
			// Refresh `hotHost` via Get so its lastSeen stays recent and survives LRU eviction!
			if got := r.Get(hotHost, now); got != hotState {
				t.Fatalf("A8 BUG: frequently accessed hot host was evicted at iteration %d", i)
			}
		}
		r.Get(fmt.Sprintf("h%d.example.com", i), now)
	}

	if len(r.hosts) > MaxTrackedHosts {
		t.Fatalf("A8 BUG: Registry grew to %d hosts, want <= %d (MaxTrackedHosts)", len(r.hosts), MaxTrackedHosts)
	}
	if got := r.Get(hotHost, now); got != hotState {
		t.Fatal("A8 BUG: hot host did not survive LRU eviction")
	}
}

// ── Allocation & Throughput Microbenchmarks (`go test -bench=. -benchmem`) ────────────────────────────

func BenchmarkRobotsMatch(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = robotsMatch("/*/collections/*/products/*.json$", "/en-us/collections/featured/products/widget.json")
	}
}

func BenchmarkIsPublicIP(b *testing.B) {
	v4 := net.ParseIP("93.184.216.34")
	nat64 := net.ParseIP("64:ff9b::c0a8:101")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = IsPublicIP(v4)
		_ = IsPublicIP(nat64)
	}
}

func BenchmarkParseRetryAfter(b *testing.B) {
	now := time.Unix(1_700_000_000, 0)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = ParseRetryAfter("120", now)
	}
}
