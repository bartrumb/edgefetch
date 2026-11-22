package politeness

import (
	"strings"
	"testing"
	"time"
)

func TestRedactEmbeddedURLsDNSResolverIPs(t *testing.T) {
	cases := []struct {
		in      string
		forbid  []string
		require string
	}{
		{
			in:      `Get "https://missing.example/robots.txt?api_key=SECRET_1": dial tcp: lookup missing.example on 127.0.0.11:53: no such host`,
			forbid:  []string{"127.0.0.11", "SECRET_1"},
			require: "on [redacted-resolver]:53: no such host",
		},
		{
			in:      `lookup slow.example on 10.96.0.10:53: read udp 172.17.0.4:52134->10.96.0.10:53: i/o timeout`,
			forbid:  []string{"10.96.0.10", "172.17.0.4", "52134"},
			require: "lookup slow.example on [redacted-resolver]:53: read udp [redacted-resolver]:53: i/o timeout",
		},
		{
			in:      `lookup ipv6.example on [fd00::10]:53: write udp [fd00::2]:44112->[fd00::10]:53: network is unreachable`,
			forbid:  []string{"fd00::10", "fd00::2"},
			require: "lookup ipv6.example on [redacted-resolver]:53: write udp [redacted-resolver]:53: network is unreachable",
		},
		{
			in:      `dial udp 127.0.0.53:53: connect: connection refused`,
			forbid:  []string{"127.0.0.53"},
			require: "dial udp [redacted-resolver]:53: connect: connection refused",
		},
		{
			in:      `dial tcp 10.0.0.2:53: i/o timeout`,
			forbid:  []string{"10.0.0.2"},
			require: "dial tcp [redacted-resolver]:53: i/o timeout",
		},
	}
	for _, tc := range cases {
		got := RedactEmbeddedURLs(tc.in)
		for _, bad := range tc.forbid {
			if strings.Contains(got, bad) {
				t.Fatalf("SECURITY: internal DNS resolver IP %q leaked in %q (input=%q)", bad, got, tc.in)
			}
		}
		if !strings.Contains(got, tc.require) {
			t.Fatalf("expected %q to contain %q, got %q", tc.in, tc.require, got)
		}
	}
}

func TestRobotsBlankLinesInGroupAndCROnlyEndings(t *testing.T) {
	exp := time.Unix(1_800_000_000, 0)

	// RFC 9309 §2.2.1: Blank lines inside a User-agent group MUST NOT reset or close the active group.
	withBlankLines := "User-agent: *\n\nDisallow: /private/\n\nAllow: /private/public\nCrawl-delay: 2\n"
	entryBlank := ParseRobotsTxt(withBlankLines, "edgefetch", exp)
	if entryBlank.Allowed("/private/secret") {
		t.Fatal("expected /private/secret to be disallowed across blank lines inside User-agent group")
	}
	if !entryBlank.Allowed("/private/public") {
		t.Fatal("expected /private/public to remain allowed across blank lines inside User-agent group")
	}
	if entryBlank.CrawlDelay != 2*time.Second {
		t.Fatalf("expected Crawl-delay 2s across blank lines, got %v", entryBlank.CrawlDelay)
	}

	// Consecutive User-agent lines separated by a blank line belong to the same group.
	multiAgentBlank := "User-agent: edgefetch\n\nUser-agent: otherbot\nDisallow: /internal\n"
	entryMulti := ParseRobotsTxt(multiAgentBlank, "edgefetch", exp)
	if entryMulti.Allowed("/internal/doc") {
		t.Fatal("expected User-agent separated by blank line to stay in same group and honor Disallow")
	}

	// Classic CR-only (\r) line endings must split cleanly rather than collapsing into the User-agent token.
	crOnly := "User-agent: *\rDisallow: /secret\rAllow: /secret/open\r"
	entryCR := ParseRobotsTxt(crOnly, "edgefetch", exp)
	if entryCR.Allowed("/secret/file") {
		t.Fatal("expected CR-only robots.txt to honor Disallow: /secret")
	}
	if !entryCR.Allowed("/secret/open") {
		t.Fatal("expected CR-only robots.txt to honor Allow: /secret/open")
	}
}
