package politeness

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type robotsParityCheck struct {
	Path    string `json:"path"`
	Allowed bool   `json:"allowed"`
}

type robotsParityCase struct {
	ID              string              `json:"id"`
	Robots          string              `json:"robots"`
	UA              string              `json:"ua"`
	CrawlDelayMs    int64               `json:"crawlDelayMs"`
	DisallowAIInput bool                `json:"disallowAiInput"`
	Checks          []robotsParityCheck `json:"checks"`
}

func TestSharedGoTypeScriptRobotsParityCorpus(t *testing.T) {
	corpusPath := filepath.Join("..", "..", "hub", "test", "fixtures", "robots-parity-corpus.json")
	raw, err := os.ReadFile(corpusPath)
	if err != nil {
		t.Fatalf("read shared robots parity corpus %s: %v", corpusPath, err)
	}
	var cases []robotsParityCase
	if err := json.Unmarshal(raw, &cases); err != nil {
		t.Fatalf("unmarshal shared robots parity corpus: %v", err)
	}
	if len(cases) < 20 {
		t.Fatalf("expected >= 20 cases in shared corpus, got %d", len(cases))
	}

	exp := time.Unix(1_800_000_000, 0)
	totalChecks := 0
	for _, tc := range cases {
		entry := ParseRobotsTxt(tc.Robots, tc.UA, exp)
		if gotDelay := entry.CrawlDelay.Milliseconds(); gotDelay != tc.CrawlDelayMs {
			t.Fatalf("[%s] CrawlDelay = %dms, want %dms", tc.ID, gotDelay, tc.CrawlDelayMs)
		}
		if entry.DisallowAIInput != tc.DisallowAIInput {
			t.Fatalf("[%s] DisallowAIInput = %v, want %v", tc.ID, entry.DisallowAIInput, tc.DisallowAIInput)
		}
		for _, chk := range tc.Checks {
			totalChecks++
			if got := entry.Allowed(chk.Path); got != chk.Allowed {
				t.Fatalf("[%s] Allowed(%q) = %v, want %v (rules=%+v)", tc.ID, chk.Path, got, chk.Allowed, entry.Rules)
			}
		}
	}
	if totalChecks < 60 {
		t.Fatalf("expected >= 60 path checks in shared corpus, ran %d", totalChecks)
	}
}
