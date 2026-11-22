package extract

import (
	"fmt"
	"strings"
	"testing"
)

func TestParseLlmsTxtEdgeCases(t *testing.T) {
	if _, ok := ParseLlmsTxt("short", "https://example.com/llms.txt"); ok {
		t.Fatal("expected <8 char llms.txt to be rejected")
	}
	if _, ok := ParseLlmsTxt("<html><div>not llms</div></html>", "https://example.com/llms.txt"); ok {
		t.Fatal("expected <html prefix to be rejected")
	}
	if _, ok := ParseLlmsTxt("some text <body>error</body>", "https://example.com/llms.txt"); ok {
		t.Fatal("expected <body> soft-404 to be rejected")
	}
	if _, ok := ParseLlmsTxt("Just a plain paragraph with no markdown heading, quote, or links.", "https://example.com/llms.txt"); ok {
		t.Fatal("expected plain paragraph without title/summary/links to return false")
	}

	// Invalid link skipped (`javascript:`), > 500 links capped, and > 4096-byte RawPreview truncated.
	var sb strings.Builder
	sb.WriteString("# Large Index\n> Summary line\n\n## Docs\n")
	sb.WriteString("- [Bad](http://insecure.example.com/page): ignored\n")
	for i := 0; i < 505; i++ {
		fmt.Fprintf(&sb, "- [Page %d](https://example.com/p/%d): item %d\n", i, i, i)
	}
	doc, ok := ParseLlmsTxt(sb.String(), "https://example.com/llms.txt")
	if !ok {
		t.Fatal("expected large valid llms.txt to parse")
	}
	if len(doc.Links) != 500 {
		t.Fatalf("expected Links capped at 500, got %d", len(doc.Links))
	}
	if len(doc.RawPreview) != 4096 {
		t.Fatalf("expected RawPreview capped at 4096, got %d", len(doc.RawPreview))
	}
}

func TestLlmsMatchPageAndCandidateCompanion(t *testing.T) {
	var nilDoc *LlmsDocument
	if m, comp, rel := nilDoc.MatchPage("https://example.com/docs"); m != nil || comp != "" || rel != nil {
		t.Fatal("nil LlmsDocument.MatchPage must return zero values")
	}

	doc := &LlmsDocument{
		SourceURL: "https://example.com/llms.txt",
		Links: []LlmsLink{
			{Section: "Other", Title: "CrossHost", URL: "https://other.example.com/home"},
			{Section: "Other", Title: "BadURL", URL: "://bad"},
			{Section: "Core", Title: "Root", URL: "https://example.com"},
			{Section: "Core", Title: "Guide", URL: "https://example.com/guide"},
			{Section: "Core", Title: "IndexMd", URL: "https://example.com/pkg/index.html.md"},
			{Section: "Other", Title: "Unrelated", URL: "https://example.com/other"},
		},
	}
	for i := 0; i < 10; i++ {
		doc.Links = append(doc.Links, LlmsLink{
			Section: "Core",
			Title:   fmt.Sprintf("Extra %d", i),
			URL:     fmt.Sprintf("https://example.com/extra/%d", i),
		})
	}

	if m, _, _ := doc.MatchPage("://invalid"); m != nil {
		t.Fatal("invalid pageURL should return nil match")
	}

	// Root URL matches root link and caps related at 8 within matching section
	mRoot, compRoot, relRoot := doc.MatchPage("https://example.com")
	if mRoot == nil || mRoot.Title != "Root" || compRoot != "" {
		t.Fatalf("root match = (%+v, %q)", mRoot, compRoot)
	}
	if len(relRoot) != 8 {
		t.Fatalf("expected 8 related links in Core section, got %d", len(relRoot))
	}
	for _, r := range relRoot {
		if r.Section != "Core" {
			t.Fatalf("expected only Core section related links, got %+v", r)
		}
	}

	// index.html.md companion match
	mIdx, compIdx, _ := doc.MatchPage("https://example.com/pkg/")
	if mIdx == nil || compIdx != "https://example.com/pkg/index.html.md" {
		t.Fatalf("index.html.md match = (%+v, %q)", mIdx, compIdx)
	}

	// CandidateCompanionMarkdownURL cases
	emptyCases := []string{
		"://bad",
		"http://example.com/docs",
		"https://example.com/docs?q=1",
		"https://example.com",
		"https://example.com/",
		"https://example.com/guide.md",
		"https://example.com/manual.pdf",
		"https://example.com/feed.json",
	}
	for _, u := range emptyCases {
		if got := CandidateCompanionMarkdownURL(u); got != "" {
			t.Fatalf("CandidateCompanionMarkdownURL(%q) = %q, want empty", u, got)
		}
	}
	if got := CandidateCompanionMarkdownURL("https://example.com/guide.html#top"); got != "https://example.com/guide.html.md" {
		t.Fatalf("CandidateCompanionMarkdownURL(.html) = %q", got)
	}
	if got := CandidateCompanionMarkdownURL("https://example.com/guide.htm"); got != "https://example.com/guide.htm.md" {
		t.Fatalf("CandidateCompanionMarkdownURL(.htm) = %q", got)
	}
}
