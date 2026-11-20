package politeness

import (
	"testing"
	"time"
)

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
