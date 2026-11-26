package crawl

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/bartrumb/edgefetch/v2/internal/classify"
)

// Over-budget JSON record arrays extracted on the node must honor `jsonFilter` (the edge's chunkJsonRecords filter)
// instead of returning every record, while OpenAPI documents keep their dedicated formatter.
func TestNodeOffloadAppliesJSONFilterToOverBudgetRecordArrays(t *testing.T) {
	const budget = 256 * 1024
	pad := strings.Repeat("filler words for an over budget record body ", 8)
	records := make([]map[string]any, 0, 1200)
	for i := 0; i < 1200; i++ {
		team := "Sales"
		title := fmt.Sprintf("Account Executive %d", i)
		if i%400 == 7 {
			team = "Platform"
			title = fmt.Sprintf("Platform Engineer %d", i)
		}
		records = append(records, map[string]any{
			"id":               fmt.Sprintf("job-%d", i),
			"title":            title,
			"team":             team,
			"descriptionPlain": pad,
		})
	}
	recordsJSON, err := json.Marshal(records)
	if err != nil {
		t.Fatal(err)
	}
	if len(recordsJSON) <= budget {
		t.Fatalf("fixture must exceed the inline budget, got %d bytes", len(recordsJSON))
	}

	var pathsJSON strings.Builder
	pathsJSON.WriteString("{")
	for i := 0; i < 40; i++ {
		if i > 0 {
			pathsJSON.WriteString(",")
		}
		fmt.Fprintf(&pathsJSON, `"/v1/resource-%d":{"get":{"summary":"Read resource %d"}}`, i, i)
	}
	pathsJSON.WriteString("}")
	// A large vendor-extension blob pushes the raw spec over the inline budget without inflating the formatted output.
	blob, _ := json.Marshal(strings.Repeat("vendor extension padding ", 14_000))
	openapiJSON := `{"openapi":"3.0.0","info":{"title":"Big API","version":"1"},"x-padding":` + string(blob) +
		`,"paths":` + pathsJSON.String() + `}`
	if len(openapiJSON) <= budget {
		t.Fatalf("openapi fixture must exceed the inline budget, got %d bytes", len(openapiJSON))
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/robots.txt", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("User-agent: *\nAllow: /\n"))
	})
	mux.HandleFunc("/jobs.json", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(recordsJSON)
	})
	mux.HandleFunc("/openapi.json", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(openapiJSON))
	})
	c, _ := newTestCrawler(t, mux)
	results := c.Run(
		context.Background(),
		[]Request{
			{ID: "filtered", URL: "http://shop.test/jobs.json", Kind: classify.KindScrape, Formats: []string{"markdown"}, JSONFilter: "team=Platform"},
			{ID: "nomatch", URL: "http://shop.test/jobs.json", Kind: classify.KindScrape, Formats: []string{"markdown"}, JSONFilter: "team=Nobody"},
			{ID: "openapi", URL: "http://shop.test/openapi.json", Kind: classify.KindScrape, Formats: []string{"markdown"}, JSONFilter: "team=Platform"},
		},
		Options{IncludeBody: true, MaxBytes: 8 << 20, MaxInlineBodyBytes: budget, PauseMs: 1, GapMs: 0},
	)
	if len(results) != 3 {
		t.Fatalf("expected 3 results, got %d", len(results))
	}

	filtered := results[0]
	if !filtered.ExtractedOnNode || filtered.MarkdownOverBudget {
		t.Fatalf("filtered JSON must be extracted on node within budget, got extractedOnNode=%v overBudget=%v mdLen=%d",
			filtered.ExtractedOnNode, filtered.MarkdownOverBudget, len(filtered.Markdown))
	}
	for _, want := range []string{"Platform Engineer 7", "Platform Engineer 407", "Platform Engineer 807"} {
		if !strings.Contains(filtered.Markdown, want) {
			t.Fatalf("filtered markdown missing %q (len=%d)", want, len(filtered.Markdown))
		}
	}
	if strings.Contains(filtered.Markdown, "Account Executive") {
		t.Fatalf("jsonFilter team=Platform must drop non-matching records, markdown still has Sales records")
	}
	if !strings.Contains(filtered.Title, "3 of 1200 records") {
		t.Fatalf("expected chunker title to report 3 of 1200 records, got %q", filtered.Title)
	}

	noMatch := results[1]
	if !noMatch.ExtractedOnNode || !strings.Contains(noMatch.Markdown, "No records matched jsonFilter") {
		t.Fatalf("zero-match jsonFilter must return a non-empty notice (not all records), got %q", noMatch.Markdown)
	}

	openapiRes := results[2]
	if strings.Contains(openapiRes.Markdown, "No records matched jsonFilter") {
		t.Fatalf("OpenAPI document must keep its dedicated formatter even with jsonFilter set")
	}
	if !openapiRes.ExtractedOnNode || openapiRes.MarkdownOverBudget {
		t.Fatalf("over-budget OpenAPI spec must be formatted on the node, got extractedOnNode=%v overBudget=%v",
			openapiRes.ExtractedOnNode, openapiRes.MarkdownOverBudget)
	}
	if strings.Contains(openapiRes.Markdown, "JSON payload truncated") || !strings.Contains(openapiRes.Markdown, "/v1/resource-12") {
		t.Fatalf("over-budget OpenAPI spec must use the OpenAPI formatter (not the 512 KiB generic preview), got %d chars: %.300s",
			len(openapiRes.Markdown), openapiRes.Markdown)
	}
}

func TestIsOpenAPIOrNotebookJSON(t *testing.T) {
	cases := map[string]bool{
		`{"openapi":"3.1.0","paths":{}}`:                 true,
		` {"info":{"openapi":"nested"},"swagger":"2.0"}`: true,
		`{"cells":[],"nbformat":4}`:                      true,
		`{"info":{"openapi":"nested only"}}`:             false,
		`[{"openapi":"in array"}]`:                       false,
		`{"jobs":[{"title":"x"}]}`:                       false,
		`{"broken":`:                                     false,
	}
	for in, want := range cases {
		if got := isOpenAPIOrNotebookJSON(in); got != want {
			t.Errorf("isOpenAPIOrNotebookJSON(%q) = %v, want %v", in, got, want)
		}
	}
}
