package jobs

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func leverPageJSON(n int) string {
	items := make([]map[string]any, 0, n)
	for i := 0; i < n; i++ {
		items = append(items, map[string]any{
			"id":         fmt.Sprintf("job-%03d", i),
			"text":       fmt.Sprintf("Software Engineer %d", i),
			"hostedUrl":  fmt.Sprintf("https://jobs.lever.co/bigco/job-%03d", i),
			"categories": map[string]any{"location": "New York, NY"},
		})
	}
	b, _ := json.Marshal(items)
	return string(b)
}

func TestLeverBoardIsServerPaged(t *testing.T) {
	spec := ResolveATSPreFetchSpec("https://jobs.lever.co/bigco?offset=100")
	if spec == nil || spec.FetchURL != "https://api.lever.co/v0/postings/bigco?mode=json&skip=100&limit=100" {
		t.Fatalf("expected server-paged Lever fetch URL, got %+v", spec)
	}

	// A full page from offset 100: all 100 records returned (no re-slicing), "more remain", next cursor 200.
	full := spec.Format(leverPageJSON(LeverBoardPageSize), "https://jobs.lever.co/bigco?offset=100", nil)
	if full == nil || len(full.Jobs) != LeverBoardPageSize {
		t.Fatalf("expected %d jobs from a full page, got %+v", LeverBoardPageSize, full)
	}
	if full.Truncated == nil || !*full.Truncated || full.NextCursor != "200" {
		t.Fatalf("full page must be truncated with cursor 200, got truncated=%v cursor=%q", full.Truncated, full.NextCursor)
	}
	if !strings.Contains(full.Markdown, "200+ open roles") {
		t.Fatalf("expected an open-ended count label, got %q", strings.SplitN(full.Markdown, "\n", 2)[0])
	}

	// A short page is the last one: not truncated, exact total.
	last := spec.Format(leverPageJSON(7), "https://jobs.lever.co/bigco?offset=100", nil)
	if last == nil || len(last.Jobs) != 7 || (last.Truncated != nil && *last.Truncated) || last.NextCursor != "" {
		t.Fatalf("short page must be final, got %+v", last)
	}
	if last.Total == nil || *last.Total != 107 {
		t.Fatalf("expected total 107 (offset + page), got %v", last.Total)
	}
}
