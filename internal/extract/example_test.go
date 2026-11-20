package extract_test

import (
	"fmt"

	"github.com/bartrumb/edgefetch/internal/extract"
)

func ExampleExtractHTML() {
	rawHTML := `<!doctype html>
<html>
  <head><title>Async Runtime</title></head>
  <body>
    <nav><a href="/home">Home</a></nav>
    <main>
      <h1>Async Runtime</h1>
      <p>Returns <code>Promise&lt;void&gt;</code> when complete.</p>
    </main>
  </body>
</html>`
	page := extract.ExtractHTML(rawHTML, extract.ExtractOptions{
		BaseURL:         "https://docs.example.com/guide",
		OnlyMainContent: true,
	})
	fmt.Println(page.Markdown)
	// Output:
	// # Async Runtime
	//
	// Returns `Promise<void>` when complete.
}

func ExampleParseLlmsTxt() {
	raw := `# EdgeFetch Docs
> Distributed edge web crawler for AI agents.

## Guides
- [Quickstart](/docs/quickstart.md): Deploy Hub + Go Worker in 60 seconds
`
	doc, ok := extract.ParseLlmsTxt(raw, "https://docs.example.com/llms.txt")
	fmt.Println("valid:", ok, "| title:", doc.Title, "| firstUrl:", doc.Links[0].URL)
	// Output:
	// valid: true | title: EdgeFetch Docs | firstUrl: https://docs.example.com/docs/quickstart.md
}
