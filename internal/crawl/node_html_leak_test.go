package crawl

import (
	"context"
	"strings"
	"testing"

	"github.com/bartrumb/edgefetch/v2/internal/classify"
)

// The node HTML path must use the full extractor: hidden subtrees, `<script>` bodies (including
// ones placed inside or straddling `<main>`), and HTML comments never reach Markdown or Text.
func TestNodeHTMLExtractionDropsScriptsHiddenAndComments(t *testing.T) {
	raw := `<!doctype html><html lang="en"><head><title>Leak Check</title>
<script>var headSecret = "HEAD_SCRIPT_LEAK";</script></head><body>
<!-- <main><p>COMMENT_MAIN_DECOY paragraph that is long enough to win main selection easily.</p></main> -->
<div style="display:none">HIDDEN_DISPLAY_NONE_TEXT should never be visible to readers.</div>
<div hidden>HIDDEN_ATTR_TEXT should never be visible either.</div>
<script>document.write("<main>");var straddle = "STRADDLE_SCRIPT_LEAK";</script>
<main>
<h1>Visible Article</h1>
<p>This is the visible article body with enough words to be selected as main content by the extractor.</p>
<script>window.inMain = "INSIDE_MAIN_SCRIPT_LEAK"; if (a < b && c > d) { run(); }</script>
<p>Second visible paragraph that readers can actually see on the page.</p>
<!-- COMMENT_INSIDE_MAIN -->
</main>
<script>var tail = "</main>TAIL_SCRIPT_LEAK";</script>
</body></html>`

	disc := false
	r := Request{
		URL:          "https://example.com/article",
		Kind:         classify.KindScrape,
		Formats:      []string{"markdown", "text"},
		DiscoverLlms: &disc,
	}
	res := &Result{
		Outcome:     classify.OutcomeOK,
		ContentType: "text/html; charset=utf-8",
		FinalURL:    "https://example.com/article",
	}
	c := &Crawler{}
	c.enrichResult(context.Background(), r, Options{}, []byte(raw), res)

	if !strings.Contains(res.Markdown, "visible article body") || !strings.Contains(res.Markdown, "Second visible paragraph") {
		t.Fatalf("expected visible main content in markdown, got:\n%s", res.Markdown)
	}
	leaks := []string{
		"HEAD_SCRIPT_LEAK", "STRADDLE_SCRIPT_LEAK", "INSIDE_MAIN_SCRIPT_LEAK", "TAIL_SCRIPT_LEAK",
		"document.write", "window.inMain", "HIDDEN_DISPLAY_NONE_TEXT", "HIDDEN_ATTR_TEXT",
		"COMMENT_MAIN_DECOY", "COMMENT_INSIDE_MAIN",
	}
	for _, field := range []struct{ name, val string }{{"Markdown", res.Markdown}, {"Text", res.Text}} {
		for _, leak := range leaks {
			if strings.Contains(field.val, leak) {
				t.Errorf("%s leaked %q:\n%s", field.name, leak, field.val)
			}
		}
	}
	if res.Title != "Leak Check" {
		t.Errorf("expected title preserved, got %q", res.Title)
	}
}
