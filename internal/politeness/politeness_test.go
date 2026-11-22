package politeness

import (
	"context"
	"fmt"
	"net"
	"strings"
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

	// 4. RFC 9309 §2.5 requires parsing at least 500 KiB of robots.txt; EdgeFetch enforces 1 MiB + 60s distress TTL.
	if RobotsMaxBytes != 1<<20 {
		t.Fatalf("RobotsMaxBytes = %d, want %d (1 MiB)", RobotsMaxBytes, 1<<20)
	}
	if RobotsDistressTTL != 60*time.Second {
		t.Fatalf("RobotsDistressTTL = %s, want 60s", RobotsDistressTTL)
	}

	// 5. G2 Cloudflare Content Signals: ai-input=no blocks wildcard, while specific `edgefetch` group overrides `*`!
	cfWildBlocked := "User-agent: *\nContent-Signal: search=yes, ai-input=no, ai-train=no\nAllow: /\n"
	wildBlockedEntry := ParseRobotsTxt(cfWildBlocked, "edgefetch", exp)
	if !wildBlockedEntry.DisallowAIInput || !wildBlockedEntry.ContentSignalBlocked() || wildBlockedEntry.Allowed("/docs") {
		t.Fatalf("G2: expected Content-Signal: ai-input=no to disallow retrieval, got %+v", wildBlockedEntry)
	}

	// ai-train=no with ai-input=yes MUST allow EdgeFetch (non-training user-triggered agent).
	cfTrainBlockedOnly := "User-agent: *\nContent-Signal: search=yes, ai-input=yes, ai-train=no\nAllow: /\n"
	trainOnlyEntry := ParseRobotsTxt(cfTrainBlockedOnly, "edgefetch", exp)
	if trainOnlyEntry.DisallowAIInput || trainOnlyEntry.ContentSignalBlocked() || !trainOnlyEntry.Allowed("/docs") {
		t.Fatalf("G2: expected Content-Signal: ai-input=yes, ai-train=no to allow EdgeFetch, got %+v", trainOnlyEntry)
	}

	// Specific `User-agent: edgefetch` group overrides wildcard `Content-Signal: ai-input=no` per RFC 9309 specificity.
	cfSpecificAllow := "User-agent: *\nContent-Signal: search=yes, ai-input=no, ai-train=no\nDisallow: /\n\nUser-agent: edgefetch\nContent-Signal: ai-input=yes, ai-train=no\nAllow: /\n"
	specAllowEntry := ParseRobotsTxt(cfSpecificAllow, "edgefetch", exp)
	if specAllowEntry.DisallowAIInput || !specAllowEntry.Allowed("/docs") {
		t.Fatalf("G2: expected specific edgefetch group to override wildcard Content-Signal, got %+v", specAllowEntry)
	}
}

func TestRobotsRFC9309FullParityAndContentSignalInheritance(t *testing.T) {
	exp := time.Now().Add(time.Hour)

	// 1. Repeated UTF-8 BOMs, NEL/LS/PS line separators, NUL before colon, and trailing # comments.
	weird := "\xef\xbb\xbf\xef\xbb\xbfUser-agent:\tedgefetch # inline comment\u0085" +
		"Disallow\x00: /ignored-nul\u2028" +
		"Disallow: relative-without-slash\u2029" +
		"Disallow: *.bak$\n" +
		"Content-Signal: search=yes, ai-input=\"NO\";foo=bar # ai-input=yes\n"
	we := ParseRobotsTxt(weird, "edgefetch", exp)
	if !we.DisallowAIInput || we.Allowed("/index.html") {
		t.Fatalf("expected quoted parameterized ai-input=\"NO\";foo=bar to block, got %+v", we)
	}
	// Verify underlying rule parsing by clearing DisallowAIInput on a copy.
	weRulesOnly := *we
	weRulesOnly.DisallowAIInput = false
	if !weRulesOnly.Allowed("/ignored-nul") || !weRulesOnly.Allowed("/relative-without-slash") {
		t.Fatalf("expected NUL field and non-slash/non-star Disallow to be ignored: %+v", weRulesOnly.Rules)
	}
	if weRulesOnly.Allowed("/backup/db.bak") {
		t.Fatalf("expected leading-* Disallow: *.bak$ to match /backup/db.bak: %+v", weRulesOnly.Rules)
	}

	// 2. Empty Disallow: adds no rule and MUST NOT override Disallow: / when multiple groups combine!
	combined := "User-agent: *\nDisallow: /\n\nUser-agent: *\nDisallow:\n"
	if ParseRobotsTxt(combined, "edgefetch", exp).Allowed("/secret") {
		t.Fatal("RFC 9309 §2.2.1: empty Disallow: in second * group must not defeat Disallow: / in first * group")
	}
	emptyOnly := "User-agent: *\nDisallow:\n"
	if !ParseRobotsTxt(emptyOnly, "edgefetch", exp).Allowed("/public") {
		t.Fatal("empty Disallow: alone must allow all paths")
	}

	// 3. Consecutive User-agent lines separated by blank/comment lines form a single group.
	multiUA := "User-agent: googlebot\n\n# comment between UAs\nUser-agent: edgefetch\nDisallow: /only-bots\n"
	if ParseRobotsTxt(multiUA, "edgefetch", exp).Allowed("/only-bots/1") {
		t.Fatal("expected consecutive User-agent lines separated by blank/comment lines to share one group")
	}

	// 4. Within ONE group, later Content-Signal overrides earlier (no->yes and yes->no).
	singleOverrideAllow := "User-agent: *\nContent-Signal: ai-input=no\nContent-Signal: ai-input=yes\nAllow: /\n"
	if ParseRobotsTxt(singleOverrideAllow, "edgefetch", exp).DisallowAIInput {
		t.Fatal("within single group, later ai-input=yes must override earlier ai-input=no")
	}
	singleOverrideDeny := "User-agent: *\nContent-Signal: ai-input=yes\nContent-Signal: ai-input=no\nAllow: /\n"
	if !ParseRobotsTxt(singleOverrideDeny, "edgefetch", exp).DisallowAIInput {
		t.Fatal("within single group, later ai-input=no must override earlier ai-input=yes")
	}

	// 5. Across MULTIPLE combined groups of same specificity, ANY group resolving to ai-input=no blocks!
	multiGroupDeny := "User-agent: edgefetch\nContent-Signal: ai-input=yes\nAllow: /\n\nUser-agent: edgefetch\nContent-Signal: ai-input=no\nDisallow: /admin\n"
	if !ParseRobotsTxt(multiGroupDeny, "edgefetch", exp).DisallowAIInput {
		t.Fatal("across combined groups of same specificity, any ai-input=no must disallow")
	}

	// 6. Specific group without Content-Signal inherits from * group, or pre-group file default!
	inheritFromWild := "User-agent: *\nContent-Signal: ai-input=no\nDisallow: /all\n\nUser-agent: edgefetch\nDisallow: /sub\n"
	if !ParseRobotsTxt(inheritFromWild, "edgefetch", exp).DisallowAIInput {
		t.Fatal("specific edgefetch group without Content-Signal must inherit ai-input=no from * group")
	}
	inheritFromPreGroup := "Content-Signal: ai-input=no\n\nUser-agent: edgefetch\nAllow: /\n"
	if !ParseRobotsTxt(inheritFromPreGroup, "edgefetch", exp).DisallowAIInput {
		t.Fatal("specific edgefetch group without Content-Signal must inherit pre-group Content-Signal: ai-input=no")
	}
	preGroupOnly := "Content-Signal: ai-input=no\n"
	if !ParseRobotsTxt(preGroupOnly, "edgefetch", exp).DisallowAIInput {
		t.Fatal("top-level pre-group Content-Signal: ai-input=no without User-agent groups must disallow")
	}

	// 7. Semicolon-separated Content-Signal (`search=yes;ai-input=no`), single-quoted `'no'`, and empty `User-agent:` group isolation.
	semiSignal := "User-agent: *\nContent-Signal: search=yes;ai-input=no\nAllow: /\n"
	if se := ParseRobotsTxt(semiSignal, "edgefetch", exp); !se.DisallowAIInput || se.Allowed("/docs") {
		t.Fatalf("expected Content-Signal: search=yes;ai-input=no to disallow ai-input, got %+v", se)
	}
	singleQuoted := "User-agent: *\nContent-Signal: search=yes, ai-input=' no '\nAllow: /\n"
	if sq := ParseRobotsTxt(singleQuoted, "edgefetch", exp); !sq.DisallowAIInput || sq.Allowed("/docs") {
		t.Fatalf("expected Content-Signal: ai-input='no' to disallow ai-input, got %+v", sq)
	}
	singleQuotedExact := "User-agent: *\nContent-Signal: ai-input='no'\nAllow: /\n"
	if sq2 := ParseRobotsTxt(singleQuotedExact, "edgefetch", exp); !sq2.DisallowAIInput || sq2.Allowed("/docs") {
		t.Fatalf("expected Content-Signal: ai-input='no' to disallow ai-input, got %+v", sq2)
	}
	emptyUAAfterGroup := "User-agent: *\nAllow: /\n\nUser-agent:\nDisallow: /\n"
	if !ParseRobotsTxt(emptyUAAfterGroup, "edgefetch", exp).Allowed("/public") {
		t.Fatal("empty User-agent: after a valid group must terminate the group and NOT attach Disallow: / to unnamed or previous group")
	}
	emptyUATop := "User-agent:\nDisallow: /\nContent-Signal: ai-input=no\n"
	if topEmpty := ParseRobotsTxt(emptyUATop, "edgefetch", exp); topEmpty.DisallowAIInput || !topEmpty.Allowed("/public") {
		t.Fatalf("empty User-agent: at top of file must not attach Disallow or Content-Signal, got %+v", topEmpty)
	}

	// 8. HostState 429 cooldown tracking (`NoteRateLimit` & `CoolingDownRetryAfterMs`).
	now := time.Unix(1_750_000_000, 0)
	hs := NewRegistry().Get("throttle.example.com", now)
	if got := hs.CoolingDownRetryAfterMs(now); got != 0 {
		t.Fatalf("initial CoolingDownRetryAfterMs = %d, want 0", got)
	}
	hs.NoteRateLimit(now, 8*time.Second)
	if got := hs.CoolingDownRetryAfterMs(now.Add(3 * time.Second)); got != 5000 {
		t.Fatalf("CoolingDownRetryAfterMs = %d, want 5000", got)
	}
	hs.RecordOutcome(now.Add(4*time.Second), time.Second, 0, 200, false, false)
	if got := hs.CoolingDownRetryAfterMs(now.Add(4 * time.Second)); got != 0 {
		t.Fatalf("expected HTTP 200 RecordOutcome to clear 429 cooldown, got %d", got)
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

func TestR6RobotsCanonicalPathBOMTruncationAndSub25msComplexity(t *testing.T) {
	exp := time.Now().Add(time.Hour)

	// 1. Dot-segment, double-slash, encoded dot, and matrix-parameter canonicalization against Disallow: /private.
	entry := ParseRobotsTxt("User-agent: *\nAllow: /public\nDisallow: /private\n", "edgefetch", exp)
	for _, blocked := range []string{
		"/private",
		"/private/x",
		"/./private",
		"/./private/x",
		"//private/x",
		"/%2e/private/x",
		"/%2E/private/x",
		"/public/../private/x",
		"/public/%2e%2e/private/x",
		"/;/private/x",
		"/private;jsessionid=123/x",
		"/%70rivate/x",
		"/pri%76ate?x=1",
	} {
		if entry.Allowed(blocked) {
			t.Fatalf("SECURITY: expected %q to be disallowed by Disallow: /private", blocked)
		}
	}
	if !entry.Allowed("/Private") {
		t.Fatal("expected case-sensitive /Private to remain allowed per RFC 9309")
	}

	// RFC 9309 §2.2.2: %2F vs literal '/' must stay distinct.
	slEntry := ParseRobotsTxt("User-agent: *\nDisallow: /a%2Fb\n", "edgefetch", exp)
	if !slEntry.Allowed("/a/b") || slEntry.Allowed("/a%2fb") {
		t.Fatal("RFC 9309 %2F vs '/' distinction broken")
	}
	slEntry2 := ParseRobotsTxt("User-agent: *\nDisallow: /a/b\n", "edgefetch", exp)
	if !slEntry2.Allowed("/a%2fb") || slEntry2.Allowed("/a/b") {
		t.Fatal("RFC 9309 '/' vs %2f distinction broken")
	}

	// Longest-match precedence preserves original pattern length including wildcards (/x* len 3 > /x len 2).
	prec := ParseRobotsTxt("User-agent: *\nDisallow: /x*\nAllow: /x\n", "edgefetch", exp)
	if prec.Allowed("/x") {
		t.Fatal("expected Disallow: /x* (len 3) to beat Allow: /x (len 2)")
	}

	// 2. BOM after blank/space, NUL in value, and partial-line truncation at RobotsMaxBytes.
	if ParseRobotsTxt("\n  \xef\xbb\xbfUser-agent: *\nDisallow: /x\x00zzz\n", "edgefetch", exp).Allowed("/x/y") {
		t.Fatal("expected BOM-after-blank and NUL-in-value Disallow: /x\\x00zzz to block /x/y")
	}
	hdr := "User-agent: *\nDisallow: /\n"
	padLen := RobotsMaxBytes - len(hdr) - len("Allow: /")
	truncBody := hdr + strings.Repeat("#", padLen-1) + "\nAllow: /public-docs"
	if ParseRobotsTxt(truncBody, "edgefetch", exp).Allowed("/secret") {
		t.Fatal("SECURITY: partial Allow line split across RobotsMaxBytes boundary turned into Allow: /")
	}

	// 3. Pathological 1 MiB robots.txt × 1 MiB target path MUST complete in < 25ms (previously 15.1s).
	bigPath := "/" + strings.Repeat("a", 1<<20)
	build1MiBRobots := func(makeRule func(i int) string) *RobotsEntry {
		var sb strings.Builder
		sb.Grow(RobotsMaxBytes)
		sb.WriteString("User-agent: *\n")
		for i := 0; ; i++ {
			line := makeRule(i)
			if sb.Len()+len(line) > RobotsMaxBytes {
				break
			}
			sb.WriteString(line)
		}
		return ParseRobotsTxt(sb.String(), "edgefetch", exp)
	}

	cases := []struct {
		name string
		ent  *RobotsEntry
		path string
		want bool
	}{
		{
			name: "400-star anchored",
			ent:  build1MiBRobots(func(i int) string { return fmt.Sprintf("Disallow: /%d%sb$\n", i%500, strings.Repeat("*a", 200)) }),
			path: bigPath,
			want: true,
		},
		{
			name: "11k distinct long needles",
			ent:  build1MiBRobots(func(i int) string { return fmt.Sprintf("Disallow: /*%05d%sb\n", i, strings.Repeat("a", 75)) }),
			path: bigPath,
			want: true,
		},
		{
			name: "74k tiny rules",
			ent:  build1MiBRobots(func(i int) string { return "Disallow: /*b\n" }),
			path: bigPath,
			want: true,
		},
		{
			name: "matching-alphabet budget cap",
			ent:  build1MiBRobots(func(i int) string { return fmt.Sprintf("Disallow: /*%04d%sb\n", i, strings.Repeat("a", 75)) }),
			path: "/0123456789b" + strings.Repeat("a", 1<<20),
			want: false, // exceeds scan budget -> fails closed in < 25ms
		},
	}
	for _, tc := range cases {
		t0 := time.Now()
		got := tc.ent.Allowed(tc.path)
		dur := time.Since(t0)
		if got != tc.want {
			t.Fatalf("%s: Allowed = %v, want %v", tc.name, got, tc.want)
		}
		// Allow generous margin for -race instrumentation while strictly enforcing < 25ms uninstrumented (< 100ms under -race).
		if dur > 100*time.Millisecond {
			t.Fatalf("%s: Allowed() took %s on 1 MiB path, want fast bounded execution", tc.name, dur)
		}
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
