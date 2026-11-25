package crawl

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/bartrumb/edgefetch/v2/internal/classify"
)

func TestNodeOffloadOverBudgetDocumentsAndNoMarkdownTruncation(t *testing.T) {
	const budget = 512 * 1024 // 512 KiB inline budget for fast deterministic unit testing

	bigHTML := "<!doctype html><html><head><title>Large Node HTML</title></head><body>" +
		"<div class=\"nav-chrome\" data-blob=\"" + strings.Repeat("x", 600_000) + "\"></div>" +
		"<main><h1>Node Offload Heading</h1><p>" +
		strings.Repeat("Structured paragraph words for native Go extraction. ", 600) +
		"</p><p><a href=\"https://example.com/ref\">Ref</a> FINAL_NODE_HTML_TOKEN</p></main></body></html>"
	bigCSV := "id,name,price\n" + strings.Repeat("1,Widget,19.99\n", 45_000)
	// Markdown whose extracted output ITSELF exceeds `budget` -> must set `MarkdownOverBudget = true` and `Markdown = ""` (NEVER truncate!).
	hugeOriginMD := "# Huge Origin Markdown\n\n" + strings.Repeat("Plain prose line that stays over budget after extraction.\n", 12_000)

	mux := http.NewServeMux()
	mux.HandleFunc("/robots.txt", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("User-agent: *\nAllow: /\n"))
	})
	mux.HandleFunc("/big.html", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(bigHTML))
	})
	mux.HandleFunc("/big.csv", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		_, _ = w.Write([]byte(bigCSV))
	})
	mux.HandleFunc("/huge.md", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
		_, _ = w.Write([]byte(hugeOriginMD))
	})
	c, _ := newTestCrawler(t, mux)
	var sinkSawRawBytes int
	results := c.RunWithSink(
		context.Background(),
		[]Request{
			{ID: "html-1", URL: "http://shop.test/big.html", Kind: classify.KindScrape, Formats: []string{"markdown", "links"}},
			{ID: "csv-1", URL: "http://shop.test/big.csv", Kind: classify.KindScrape, Formats: []string{"markdown"}},
			{ID: "md-1", URL: "http://shop.test/huge.md", Kind: classify.KindScrape, Formats: []string{"markdown"}},
		},
		Options{
			IncludeBody:        true,
			MaxBytes:           8 << 20,
			MaxInlineBodyBytes: budget,
			PauseMs:            1,
			GapMs:              0,
		},
		c.Logger(),
		func(_ int, res Result) Result {
			// Verify R2 artifact sink still sees the full raw body BEFORE inline body omission!
			if res.ID == "html-1" {
				sinkSawRawBytes = len(res.Body)
			}
			return res
		},
	)

	if len(results) != 3 {
		t.Fatalf("expected 3 results, got %d", len(results))
	}
	if sinkSawRawBytes != len(bigHTML) {
		t.Fatalf("expected R2 sink to receive full %d-byte HTML body before inline omission, got %d", len(bigHTML), sinkSawRawBytes)
	}

	htmlRes := results[0]
	if !htmlRes.ExtractedOnNode || !htmlRes.BodyOmitted || htmlRes.Body != "" {
		t.Fatalf("expected HTML >budget to extract on node and omit inline body, got extractedOnNode=%v bodyOmitted=%v bodyLen=%d",
			htmlRes.ExtractedOnNode, htmlRes.BodyOmitted, len(htmlRes.Body))
	}
	if htmlRes.Title != "Large Node HTML" || !strings.Contains(htmlRes.Markdown, "FINAL_NODE_HTML_TOKEN") {
		t.Fatalf("expected full Go HTML extraction without 2MiB/budget truncation, got title=%q mdLen=%d", htmlRes.Title, len(htmlRes.Markdown))
	}

	csvRes := results[1]
	if !csvRes.ExtractedOnNode || !csvRes.BodyOmitted || csvRes.Body != "" || !strings.Contains(csvRes.Markdown, "| id | name | price |") {
		t.Fatalf("expected CSV >budget to extract bounded GFM table on node and omit inline body, got %+v", csvRes)
	}

	mdRes := results[2]
	if !mdRes.ExtractedOnNode || !mdRes.MarkdownOverBudget || mdRes.Markdown != "" || mdRes.Body != "" || !mdRes.BodyOmitted {
		t.Fatalf("expected over-budget Markdown to set MarkdownOverBudget=true with empty Markdown (never truncated!), got extractedOnNode=%v overBudget=%v mdLen=%d bodyLen=%d",
			mdRes.ExtractedOnNode, mdRes.MarkdownOverBudget, len(mdRes.Markdown), len(mdRes.Body))
	}
}
