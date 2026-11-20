package politeness

import (
	"net"
	"net/netip"
	"testing"
	"time"
)

func FuzzRobotsParseAndMatch(f *testing.F) {
	f.Add("User-agent: *\nDisallow: /admin/*\nAllow: /admin/public$\nCrawl-delay: 2.5\n", "EdgeFetch/2.1", "/admin/public")
	f.Add("\xef\xbb\xbfUser-agent: edgefetch\nDisallow: /*.pdf$\n", "EdgeFetch/2.1", "/manuals/spec%20v1.pdf")
	f.Add("User-agent: *\nDisallow: /%7Euser/\n", "Mozilla/5.0", "/~user/profile")

	exp := time.Unix(1_800_000_000, 0)
	f.Fuzz(func(t *testing.T, robotsBody, userAgent, targetPath string) {
		if len(robotsBody) > 64<<10 || len(targetPath) > 4096 {
			return
		}
		entry := ParseRobotsTxt(robotsBody, userAgent, exp)
		if entry == nil {
			t.Fatal("ParseRobotsTxt returned nil")
		}
		if entry.CrawlDelay < 0 || entry.CrawlDelay > MaxCrawlDelay {
			t.Fatalf("CrawlDelay out of bounds: %v", entry.CrawlDelay)
		}
		_ = entry.Allowed(targetPath)
	})
}

func FuzzParseRetryAfter(f *testing.F) {
	f.Add("120")
	f.Add("0")
	f.Add("-5")
	f.Add("999999999")
	f.Add("9227000000")
	f.Add("99999999999999999999999")
	f.Add("Wed, 21 Oct 2026 07:28:00 GMT")

	now := time.Date(2026, 10, 21, 7, 27, 0, 0, time.UTC)
	f.Fuzz(func(t *testing.T, headerVal string) {
		d := ParseRetryAfter(headerVal, now)
		if d < 0 || d > MaxRetryAfter {
			t.Fatalf("ParseRetryAfter(%q) = %v outside [0, %v]", headerVal, d, MaxRetryAfter)
		}
	})
}

func FuzzIsPublicIP(f *testing.F) {
	f.Add("127.0.0.1")
	f.Add("192.168.1.1")
	f.Add("100.64.0.1")
	f.Add("1.1.1.1")
	f.Add("::ffff:127.0.0.1")
	f.Add("64:ff9b::7f00:1")
	f.Add("2606:4700:4700::1111")

	f.Fuzz(func(t *testing.T, raw string) {
		ip := net.ParseIP(raw)
		gotSlice := IsPublicIP(ip)
		if addr, err := netip.ParseAddr(raw); err == nil {
			gotAddr := IsPublicAddr(addr)
			if ip != nil && gotSlice != gotAddr {
				t.Fatalf("IsPublicIP(%q)=%v != IsPublicAddr=%v", raw, gotSlice, gotAddr)
			}
			if gotAddr && (addr.Unmap().IsLoopback() || addr.Unmap().IsPrivate() || addr.Unmap().IsMulticast() || addr.Unmap().IsUnspecified()) {
				t.Fatalf("SECURITY: non-public address %s classified as public", addr)
			}
		}
	})
}
