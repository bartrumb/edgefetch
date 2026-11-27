package extract

import (
	"strings"
	"testing"
)

func TestExtractHTMLDocumentFullStripHiddenSubtreesFullPage(t *testing.T) {
	page := `<html><head><title>Shell</title></head><body>` +
		`<aside><blockquote><p>VISIBLE_ASIDE_TEXT explains this small app in a sentence of prose.</p></blockquote></aside>` +
		`<div style="display:none">HIDDEN_STYLE_TEXT</div><div hidden>HIDDEN_ATTR_TEXT</div>` +
		`<footer><p>Footer note</p></footer></body></html>`

	kept := ExtractHTMLDocumentFull(page, FullExtractOptions{BaseURL: "https://shell.example.com/", OnlyMainContent: false})
	if !strings.Contains(kept.Markdown, "HIDDEN_STYLE_TEXT") {
		t.Fatalf("default full-page extraction is unchanged (keeps hidden text); got %q", kept.Markdown)
	}

	stripped := ExtractHTMLDocumentFull(page, FullExtractOptions{BaseURL: "https://shell.example.com/", OnlyMainContent: false, StripHiddenSubtrees: true})
	if !strings.Contains(stripped.Markdown, "VISIBLE_ASIDE_TEXT") {
		t.Fatalf("expected visible aside text with StripHiddenSubtrees, got %q", stripped.Markdown)
	}
	for _, hidden := range []string{"HIDDEN_STYLE_TEXT", "HIDDEN_ATTR_TEXT"} {
		if strings.Contains(stripped.Markdown, hidden) {
			t.Fatalf("StripHiddenSubtrees must drop %s, got %q", hidden, stripped.Markdown)
		}
	}
}
