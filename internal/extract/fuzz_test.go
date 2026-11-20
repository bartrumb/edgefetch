package extract

import "testing"

func FuzzExtractHTML(f *testing.F) {
	f.Add(`<!doctype html><html><head><title>Doc</title></head><body><main><h1>Title</h1><p><code>Promise&lt;void&gt;</code></p><table><tr><th>A</th><th>B</th></tr><tr><td>1</td><td>2</td></tr></table></main></body></html>`, "Promise")
	f.Add(`<pre><code class="language-go">package main</code></pre><a href="/next">Next</a>`, "")

	f.Fuzz(func(t *testing.T, rawHTML, query string) {
		if len(rawHTML) > 64<<10 || len(query) > 256 {
			return
		}
		got := ExtractHTML(rawHTML, ExtractOptions{
			BaseURL:         "https://example.com/docs/page",
			OnlyMainContent: true,
			IncludeLinks:    true,
			IncludeImages:   true,
			IncludeBranding: true,
			RedactPII:       true,
			Query:           query,
			MaxChars:        4096,
		})
		if len(got.Markdown) > 4096 {
			t.Fatalf("MaxChars exceeded: %d > 4096", len(got.Markdown))
		}
		_ = NeedsBrowserRender(rawHTML)
		_ = DetectRenderedChallenge(rawHTML)
	})
}

func FuzzParseLlmsTxt(f *testing.F) {
	f.Add("# Site\n> Summary\n## Docs\n- [Intro](/intro.md): Notes\n", "https://example.com/llms.txt")
	f.Add("<!doctype html><html><body>404</body></html>", "https://example.com/llms.txt")

	f.Fuzz(func(t *testing.T, raw, src string) {
		if len(raw) > 64<<10 || len(src) > 512 {
			return
		}
		doc, ok := ParseLlmsTxt(raw, src)
		if ok && doc != nil {
			_, _, _ = doc.MatchPage("https://example.com/intro")
		}
	})
}
