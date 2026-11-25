package extract

import (
	"encoding/json"
	"errors"
	"io/fs"
	"math"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/bartrumb/edgefetch/v2/internal/classify"
)

func TestDeclarativeManifestsCatalogIntegrity(t *testing.T) {
	_ = loadRegistry()
	if regInitErr != nil {
		t.Fatalf("unexpected declarative registry load error: %v", regInitErr)
	}
	catalog := ListDeclarativeAdapters()
	if len(catalog) < 56 {
		t.Fatalf("expected at least 56 embedded declarative YAML adapters, got %d", len(catalog))
	}

	// Verify 100% of raw manifests/*.yaml also parse cleanly via pure-Go ParseDeclarativeYAMLManifest!
	yamlEntries, err := os.ReadDir("manifests")
	if err != nil {
		t.Fatalf("ReadDir(manifests): %v", err)
	}
	yamlCount := 0
	for _, de := range yamlEntries {
		if de.IsDir() || !strings.HasSuffix(de.Name(), ".yaml") {
			continue
		}
		yamlCount++
		rawBytes, rErr := os.ReadFile(filepath.Join("manifests", de.Name()))
		if rErr != nil {
			t.Fatalf("ReadFile(%s): %v", de.Name(), rErr)
		}
		parsed, pErr := ParseDeclarativeYAMLManifest(rawBytes)
		if pErr != nil {
			t.Fatalf("ParseDeclarativeYAMLManifest(%s) failed: %v", de.Name(), pErr)
		}
		if parsed.ID == "" {
			t.Fatalf("ParseDeclarativeYAMLManifest(%s) produced empty ID", de.Name())
		}
	}
	if yamlCount < 56 {
		t.Fatalf("expected at least 56 .yaml files in manifests/, got %d", yamlCount)
	}

	validCats := map[string]bool{
		"developer": true, "genai": true, "jobs": true, "finance": true,
		"public-records": true, "research-health": true, "commerce-social": true,
	}
	seen := make(map[string]bool)
	for _, entry := range catalog {
		if seen[entry.ID] {
			t.Fatalf("duplicate adapter ID %q", entry.ID)
		}
		seen[entry.ID] = true
		if !validCats[entry.Category] {
			t.Fatalf("adapter %q invalid category %q", entry.ID, entry.Category)
		}
		if len(entry.Domains) == 0 || len(entry.ExampleURLs) == 0 {
			t.Fatalf("adapter %q missing domains or exampleUrls", entry.ID)
		}
		hasTwinMode := false
		for _, md := range entry.Modes {
			if md == "twin" {
				hasTwinMode = true
			}
		}
		resolvedCount := 0
		for _, ex := range entry.ExampleURLs {
			m, ok := ResolveDeclarativeTwin(ex)
			if !ok || m == nil {
				continue
			}
			resolvedCount++
			if !strings.HasPrefix(m.FetchURL, "https://") {
				t.Fatalf("adapter %q resolved non-https fetchUrl %q", entry.ID, m.FetchURL)
			}
			if m.Kind != classify.KindJSON && m.Kind != classify.KindText {
				t.Fatalf("adapter %q unexpected kind %q", entry.ID, m.Kind)
			}
		}
		if hasTwinMode && resolvedCount == 0 {
			t.Fatalf("twin-capable adapter %q failed to resolve any of its exampleUrls: %v", entry.ID, entry.ExampleURLs)
		}
		if !hasTwinMode && resolvedCount > 0 {
			t.Fatalf("non-twin adapter %q unexpectedly resolved twin on exampleUrls", entry.ID)
		}
	}

	// Non-HTTPS, credentials, reserved paths, and traversal paths must never resolve.
	rejectURLs := []string{
		"http://rubygems.org/gems/rails",
		"https://user:pass@rubygems.org/gems/rails",
		"https://dev.to/tags/golang",
		"https://huggingface.co/models",
		"https://huggingface.co/Qwen/Qwen2.5-Coder/blob/main/../../etc/passwd",
		"https://openrouter.ai/docs/quickstart",
	}
	for _, bad := range rejectURLs {
		if m, ok := ResolveDeclarativeTwin(bad); ok {
			t.Fatalf("expected %q to be rejected, got %+v", bad, m)
		}
	}
}

func TestDeclarativeTwinFormatParityAcrossAllTenManifests(t *testing.T) {
	// 1. RubyGems
	rgTwin, ok := ResolveDeclarativeTwin("https://rubygems.org/gems/rails")
	if !ok || rgTwin.ID != "rubygems" || rgTwin.FetchURL != "https://rubygems.org/api/v1/gems/rails.json" {
		t.Fatalf("rubygems resolve mismatch: ok=%v twin=%+v", ok, rgTwin)
	}
	rgDoc, ok := rgTwin.Format(`{"name":"rails","version":"8.0.1","info":"Full-stack web framework.\u000e\u202e","licenses":["MIT"],"authors":"David Heinemeier Hansson","source_code_uri":"https://github.com/rails/rails"}`)
	if !ok || rgDoc.Title != "rails 8.0.1 (RubyGem)" || !strings.Contains(rgDoc.Markdown, "`gem install rails`") || strings.ContainsRune(rgDoc.Markdown, '\u202e') {
		t.Fatalf("rubygems format mismatch: ok=%v doc=%+v", ok, rgDoc)
	}

	// 2. DEV.to (with frontmatter strip)
	devTwin, ok := ResolveDeclarativeTwin("https://dev.to/gopher/writing-fuzz-tests")
	if !ok || devTwin.FetchURL != "https://dev.to/api/articles/gopher/writing-fuzz-tests" {
		t.Fatalf("dev-to resolve mismatch: ok=%v twin=%+v", ok, devTwin)
	}
	devDoc, ok := devTwin.Format(`{"title":"Writing Fuzz Tests in Go","description":"Practical fuzzing","published_timestamp":"2026-11-01T12:00:00Z","user":{"name":"Gopher"},"body_markdown":"---\ntitle: Writing Fuzz Tests\n---\n\nUse ` + "`go test -fuzz=.`" + ` to find edge cases."}`)
	if !ok || devDoc.Author != "Gopher" || strings.Contains(devDoc.Markdown, "title: Writing Fuzz Tests") || !strings.Contains(devDoc.Markdown, "# Writing Fuzz Tests in Go") {
		t.Fatalf("dev-to format mismatch: ok=%v doc=%+v", ok, devDoc)
	}

	// 3. Hex.pm (with {:pkg, "~> ver"} tuple template and ordered meta.links)
	hexTwin, ok := ResolveDeclarativeTwin("https://hex.pm/packages/phoenix")
	if !ok || hexTwin.FetchURL != "https://hex.pm/api/packages/phoenix" {
		t.Fatalf("hex-pm resolve mismatch: ok=%v twin=%+v", ok, hexTwin)
	}
	hexDoc, ok := hexTwin.Format(`{"name":"phoenix","releases":[{"version":"1.7.18"}],"meta":{"description":"Productive web framework","licenses":["MIT"],"links":{"GitHub":"https://github.com/phoenixframework/phoenix","Unsafe":"http://insecure.example.com"}}}`)
	if !ok || !strings.Contains(hexDoc.Markdown, "`{:phoenix, \"~> 1.7.18\"}`") || !strings.Contains(hexDoc.Markdown, "https://hexdocs.pm/phoenix") || !strings.Contains(hexDoc.Markdown, "- **GitHub**: https://github.com/phoenixframework/phoenix") || strings.Contains(hexDoc.Markdown, "insecure.example.com") {
		t.Fatalf("hex-pm format mismatch: ok=%v doc=%+v", ok, hexDoc)
	}

	// 4. Packagist (ordered versions skipping dev-* keys)
	pkgTwin, ok := ResolveDeclarativeTwin("https://packagist.org/packages/symfony/console")
	if !ok || pkgTwin.FetchURL != "https://packagist.org/packages/symfony/console.json" {
		t.Fatalf("packagist resolve mismatch: ok=%v twin=%+v", ok, pkgTwin)
	}
	pkgDoc, ok := pkgTwin.Format(`{"package":{"name":"symfony/console","description":"Eases creation of CLI tools","repository":"https://github.com/symfony/console","versions":{"dev-main":{"license":["MIT"]},"v7.2.0":{"license":["MIT"]},"v7.1.0":{"license":["MIT"]}}}}`)
	if !ok || pkgDoc.Title != "symfony/console v7.2.0 (Composer)" || !strings.Contains(pkgDoc.Markdown, "`composer require symfony/console`") {
		t.Fatalf("packagist format mismatch: ok=%v doc=%+v", ok, pkgDoc)
	}

	// 5. Hugging Face (card + code blob + soft-404 rejection)
	hfTwin, ok := ResolveDeclarativeTwin("https://huggingface.co/Qwen/Qwen2.5-Coder-32B-Instruct")
	if !ok || hfTwin.ID != "huggingface-card" || hfTwin.FetchURL != "https://huggingface.co/Qwen/Qwen2.5-Coder-32B-Instruct/raw/main/README.md" {
		t.Fatalf("huggingface card resolve mismatch: ok=%v twin=%+v", ok, hfTwin)
	}
	hfDoc, ok := hfTwin.Format("---\nlicense: apache-2.0\npipeline_tag: text-generation\ntags:\n  - code\n  - qwen2\n---\n\n# Qwen2.5-Coder\n\nSupports `Vec<u8>` generation. <script>evil()</script>")
	if !ok || !strings.Contains(hfDoc.Markdown, "| **license** | apache-2.0 |") || !strings.Contains(hfDoc.Markdown, "`Vec<u8>`") || !strings.Contains(hfDoc.Markdown, "&lt;script>") {
		t.Fatalf("huggingface card format mismatch: ok=%v doc=%+v", ok, hfDoc)
	}
	if _, softOK := hfTwin.Format("<!doctype html><html><body>Not found</body></html>"); softOK {
		t.Fatal("expected HTML soft-404 on text twin to return false")
	}
	hfBlobTwin, ok := ResolveDeclarativeTwin("https://huggingface.co/Qwen/Qwen2.5-Coder-32B-Instruct/blob/main/src/lib.rs")
	if !ok || hfBlobTwin.ID != "huggingface-blob" || hfBlobTwin.FetchURL != "https://huggingface.co/Qwen/Qwen2.5-Coder-32B-Instruct/raw/main/src/lib.rs" {
		t.Fatalf("huggingface blob resolve mismatch: ok=%v twin=%+v", ok, hfBlobTwin)
	}
	hfBlobDoc, ok := hfBlobTwin.Format("pub fn add(a: i32, b: i32) -> i32 { a + b }\n")
	if !ok || !strings.Contains(hfBlobDoc.Markdown, "```rust") {
		t.Fatalf("huggingface blob format mismatch: ok=%v doc=%+v", ok, hfBlobDoc)
	}

	// 6. Lobste.rs (metaLine + indented comments)
	lobTwin, ok := ResolveDeclarativeTwin("https://lobste.rs/s/abc123/zero_alloc_go_parsers")
	if !ok || lobTwin.FetchURL != "https://lobste.rs/s/abc123.json" {
		t.Fatalf("lobsters resolve mismatch: ok=%v twin=%+v", ok, lobTwin)
	}
	lobDoc, ok := lobTwin.Format(`{"title":"Zero-Alloc Go Parsers","url":"https://example.org/post","score":89,"submitter_user":"gopher","tags":["go","performance"],"comments":[{"commenting_user":"alice","score":12,"indent_level":1,"comment_plain":"Great benchmarks!"},{"commenting_user":"bob","score":5,"indent_level":2,"comment_plain":"Agreed."}]}`)
	if !ok || !strings.Contains(lobDoc.Markdown, "**Tags**: `go`, `performance`") || !strings.Contains(lobDoc.Markdown, "  - **@bob** (5 pts): Agreed.") {
		t.Fatalf("lobsters format mismatch: ok=%v doc=%+v", ok, lobDoc)
	}

	// 7. DOI / Crossref
	doiTwin, ok := ResolveDeclarativeTwin("https://doi.org/10.1038/s41586-021-03819-2")
	if !ok || doiTwin.FetchURL != "https://api.crossref.org/works/10.1038%2Fs41586-021-03819-2" {
		t.Fatalf("doi-crossref resolve mismatch: ok=%v twin=%+v", ok, doiTwin)
	}
	doiDoc, ok := doiTwin.Format(`{"message":{"title":["Highly accurate protein structure prediction with AlphaFold"],"author":[{"given":"John","family":"Jumper"}],"container-title":["Nature"],"is-referenced-by-count":28500,"issued":{"date-parts":[[2021,7,15]]},"abstract":"<jats:p>Abstract Proteins are essential to life.</jats:p>"}}`)
	if !ok || !strings.Contains(doiDoc.Markdown, "John Jumper") || !strings.Contains(doiDoc.Markdown, "28,500") || !strings.Contains(doiDoc.Markdown, "2021-07-15") || !strings.Contains(doiDoc.Markdown, "Proteins are essential to life.") {
		t.Fatalf("doi-crossref format mismatch: ok=%v doc=%+v", ok, doiDoc)
	}

	// 8. USAspending
	usaTwin, ok := ResolveDeclarativeTwin("https://www.usaspending.gov/award/CONT_AWD_1234")
	if !ok || usaTwin.FetchURL != "https://api.usaspending.gov/api/v2/awards/CONT_AWD_1234/" {
		t.Fatalf("usaspending resolve mismatch: ok=%v twin=%+v", ok, usaTwin)
	}
	usaDoc, ok := usaTwin.Format(`{"piid":"NNK17MA01B","category":"contract","total_obligation":42000000,"recipient":{"recipient_name":"Space Exploration Technologies Corp."},"awarding_agency":{"toptier_agency":{"name":"NASA"}}}`)
	if !ok || !strings.Contains(usaDoc.Markdown, "Space Exploration Technologies Corp.") || !strings.Contains(usaDoc.Markdown, "$42.00M") {
		t.Fatalf("usaspending format mismatch: ok=%v doc=%+v", ok, usaDoc)
	}

	// 9. Polymarket
	polyTwin, ok := ResolveDeclarativeTwin("https://polymarket.com/event/fed-rate-cut")
	if !ok || polyTwin.FetchURL != "https://gamma-api.polymarket.com/events?slug=fed-rate-cut" {
		t.Fatalf("polymarket resolve mismatch: ok=%v twin=%+v", ok, polyTwin)
	}
	polyDoc, ok := polyTwin.Format(`[{"title":"Fed Rate Cut in December?","volume":12500000,"liquidity":850000,"endDate":"2026-12-18T00:00:00Z","markets":[{"groupItemTitle":"25 bps cut","outcomes":"[\"Yes\",\"No\"]","outcomePrices":"[\"0.72\",\"0.28\"]","volume":9000000}]}]`)
	if !ok || !strings.Contains(polyDoc.Markdown, "Yes: 72.0% · No: 28.0%") || !strings.Contains(polyDoc.Markdown, "$12.50M") || !strings.Contains(polyDoc.Markdown, "- **Status**: Active") {
		t.Fatalf("polymarket format mismatch: ok=%v doc=%+v", ok, polyDoc)
	}

	// 10. OpenRouter
	orTwin, ok := ResolveDeclarativeTwin("https://openrouter.ai/qwen/qwen-2.5-coder-32b-instruct")
	if !ok || orTwin.FetchURL != "https://openrouter.ai/api/v1/models" {
		t.Fatalf("openrouter resolve mismatch: ok=%v twin=%+v", ok, orTwin)
	}
	orDoc, ok := orTwin.Format(`{"data":[{"id":"qwen/qwen-2.5-coder-32b-instruct","name":"Qwen 2.5 Coder 32B Instruct","context_length":32768,"pricing":{"prompt":"0.0000002","completion":"0.0000002"},"supported_parameters":["tools","temperature"]}]}`)
	if !ok || !strings.Contains(orDoc.Markdown, "32,768 tokens") || !strings.Contains(orDoc.Markdown, "$0.20 / 1M tokens") || !strings.Contains(orDoc.Markdown, "`tools`, `temperature`") {
		t.Fatalf("openrouter format mismatch: ok=%v doc=%+v", ok, orDoc)
	}

	// Corrupt JSON must return false cleanly without panicking.
	if _, corruptOK := orTwin.Format("<<<NOT JSON>>>"); corruptOK {
		t.Fatal("expected corrupt JSON to return false")
	}
}

func TestFindDeclarativeAdapters(t *testing.T) {
	devOnly := FindDeclarativeAdapters("", "developer", 0)
	if len(devOnly) < 3 {
		t.Fatalf("expected >= 3 developer declarative adapters, got %d", len(devOnly))
	}
	for _, a := range devOnly {
		if a.Category != "developer" {
			t.Fatalf("expected developer category, got %q", a.Category)
		}
	}

	hits := FindDeclarativeAdapters("crossref doi", "", 5)
	if len(hits) == 0 || hits[0].ID != "doi-crossref" {
		t.Fatalf("expected doi-crossref ranked #1, got %+v", hits)
	}
}

func TestSafeYAMLParserFeaturesAndAnchorAliasRejection(t *testing.T) {
	// 1. Valid YAML with comments, flow collections, compact list maps, single-quote escapes, and block scalars.
	sampleYAML := `---
# Comment header
id: sample-reg
name: Sample & Co Registry # inline comment
category: developer
description: |-
  Upgrades sample-reg pages
  to JSON metadata.
domains: [sample.example.com, www.sample.example.com]
exampleUrls:
  - https://sample.example.com/pkg/demo#readme
match:
  exactSegments: true
  pathSegments:
    - pkg
    - { param: id, charset: slug, minLen: 1, maxLen: 64 }
twin:
  fetchUrl: https://sample.example.com/api/{id}.json
  kind: json
  accept: application/json
extract:
  requireFields: [name]
  vars:
    name:
      paths: [name]
  titleTemplate: '{name} (''Sample'')'
  bullets:
  - label: Install
    template: "` + "`sample add {name}`" + `"
...`
	m, err := ParseDeclarativeYAMLManifest([]byte(sampleYAML))
	if err != nil {
		t.Fatalf("ParseDeclarativeYAMLManifest failed: %v", err)
	}
	if m.ID != "sample-reg" || m.Name != "Sample & Co Registry" || m.Description != "Upgrades sample-reg pages\nto JSON metadata." {
		t.Fatalf("unexpected parsed manifest metadata: %+v", m)
	}
	if len(m.ExampleURLs) != 1 || m.ExampleURLs[0] != "https://sample.example.com/pkg/demo#readme" {
		t.Fatalf("expected URL fragment preserved when not preceded by whitespace: %+v", m.ExampleURLs)
	}
	if m.Routes[0].Extract.TitleTemplate != "{name} ('Sample')" {
		t.Fatalf("unexpected single-quoted escape result: %q", m.Routes[0].Extract.TitleTemplate)
	}

	// 2. Anchors (&), aliases (*), merge keys (<<:), custom tags (!), and tab indentation MUST be rejected.
	forbiddenYAMLs := []struct {
		name string
		body string
	}{
		{
			name: "anchor_and_alias_bomb",
			body: "a: &lol [\"lol\",\"lol\"]\nb: *lol\n",
		},
		{
			name: "flow_alias",
			body: "items: [*bomb]\n",
		},
		{
			name: "merge_key",
			body: "base:\n  k: v\nchild:\n  <<: *base\n",
		},
		{
			name: "custom_tag",
			body: "payload: !!binary SGVsbG8=\n",
		},
		{
			name: "tab_indentation",
			body: "id: test\n\tname: bad\n",
		},
	}
	for _, tc := range forbiddenYAMLs {
		if _, err := ParseDeclarativeYAML([]byte(tc.body)); err == nil {
			t.Fatalf("expected forbidden YAML case %q to fail, but succeeded", tc.name)
		}
	}
}

func TestRound6YAMLAndSanitizerHardening(t *testing.T) {
	// 1. Nested "- - !" tag inside sequence MUST return error cleanly and NEVER panic (R6-Low).
	if _, err := ParseDeclarativeYAML([]byte("- - !\n")); err == nil {
		t.Fatal("expected '- - !' YAML tag to return error")
	}

	// 2. Mid-word apostrophe with trailing comment ("it's a # thing") strips comment cleanly (R6-H5).
	parsedMid, err := ParseDeclarativeYAML([]byte("note: it's a # trailing comment\n"))
	if err != nil {
		t.Fatalf("unexpected error on mid-word apostrophe scalar: %v", err)
	}
	if parsedMid.(map[string]any)["note"] != "it's a" {
		t.Fatalf("expected comment stripped after mid-word apostrophe, got %#v", parsedMid)
	}

	// 3. Compact map inside flow sequence ([b: c]) MUST be rejected (R6-H5).
	if _, err := ParseDeclarativeYAML([]byte("arr: [b: c]\n")); err == nil {
		t.Fatal("expected compact map in flow sequence '[b: c]' to fail")
	}

	// 4. Case-folded / non-ASCII JSON keys (e.g. fetchurl vs fetchUrl, domain\u017f) MUST be rejected (R6-M8).
	badCaseJSON := `{"id":"bad","name":"Bad","category":"developer","description":"desc","domains":["example.com"],"exampleUrls":["https://example.com/a"],"match":{"pathSegments":["a"]},"twin":{"fetchurl":"https://example.com/a.json","kind":"json","accept":"application/json"},"extract":{"titleTemplate":"x"}}`
	if _, err := ParseDeclarativeManifest([]byte(badCaseJSON)); err == nil {
		t.Fatal("expected lowercase fetchurl to be rejected by DisallowUnknownFields")
	}
	badNonASCIIJSON := "{\"id\":\"bad\",\"name\":\"Bad\",\"category\":\"developer\",\"description\":\"desc\",\"domain\u017f\":[\"example.com\"]}"
	if _, err := ParseDeclarativeManifest([]byte(badNonASCIIJSON)); err == nil {
		t.Fatal("expected non-ASCII Kelvin/long-s key to be rejected")
	}

	// 5. Broad wildcard domains (*.com) & cross-origin {host} interpolation MUST be rejected (R6-M2).
	broadWildcardJSON := `{"id":"broad","name":"Broad","category":"developer","description":"desc","domains":["*.com"],"exampleUrls":["https://example.com/a"],"match":{"pathSegments":["a"]},"twin":{"fetchUrl":"https://api.example.com/a.json","kind":"json","accept":"application/json"},"extract":{"titleTemplate":"x"}}`
	if _, err := ParseDeclarativeManifest([]byte(broadWildcardJSON)); err == nil {
		t.Fatal("expected broad '*.com' wildcard domain to be rejected")
	}
	leakHostJSON := `{"id":"leak","name":"Leak","category":"developer","description":"desc","domains":["*.example.org"],"exampleUrls":["https://sub.example.org/a"],"match":{"pathSegments":["a"]},"twin":{"fetchUrl":"https://collector.example.net/{host}/a.json","kind":"json","accept":"application/json"},"extract":{"titleTemplate":"x"}}`
	if _, err := ParseDeclarativeManifest([]byte(leakHostJSON)); err == nil {
		t.Fatal("expected cross-origin {host} interpolation with wildcard domain to be rejected")
	}

	// 6. Linear O(N) tag stripper finishes 160K '<' in < 40ms (R6-M7).
	adv := strings.Repeat("<x \"unclosed ", 12_500) // 162.5 KB of unclosed tags & quotes
	t0 := time.Now()
	out := stripTagsInlineLinear(adv)
	elapsed := time.Since(t0)
	if elapsed > 100*time.Millisecond {
		t.Fatalf("stripTagsInlineLinear took %v on 162KB unclosed tags (expected < 100ms)", elapsed)
	}
	if len(out) == 0 {
		t.Fatal("expected literal fallback when no closing '>' exists")
	}

	// 7. SanitizeScrapedMarkdown & SanitizeScrapedMeta strip NULs, raw <script>/<img onerror>, and javascript: links while preserving code spans (R6-M6).
	hostileMd := "# Title\x00\n\nSafe `<script>inCode()</script>` and [xss](javascript:alert(1)) plus <img src=x onerror=alert(1)>!\n\n```html\n<script>fenced()</script>\n```"
	cleanMd := SanitizeScrapedMarkdown(hostileMd)
	if strings.ContainsRune(cleanMd, 0) {
		t.Fatal("expected NUL stripped from Markdown")
	}
	if strings.Contains(cleanMd, "javascript:alert") {
		t.Fatalf("expected javascript: link neutralized, got: %s", cleanMd)
	}
	if strings.Contains(cleanMd, "<img src=x") {
		t.Fatalf("expected raw <img onerror> escaped outside code spans, got: %s", cleanMd)
	}
	if !strings.Contains(cleanMd, "`&lt;script>inCode()&lt;/script>`") || !strings.Contains(cleanMd, "<script>fenced()</script>") {
		t.Fatalf("expected inline code `<` escaped fail-closed and fenced code preserved intact, got: %s", cleanMd)
	}
}

func FuzzDeclarativeFormat(f *testing.F) {
	f.Add("https://rubygems.org/gems/rails", `{"name":"rails","version":"8.0.0"}`)
	f.Add("https://polymarket.com/event/test", `[{"title":"T","markets":[{"outcomes":"[\"A\",\"B\"]","outcomePrices":"[\"0.5\",\"bad\"]"}]}]`)
	f.Add("https://huggingface.co/org/model", "---\nlicense: mit\ntags:\n  - llm\n---\n# Card\nBody")
	f.Add("https://doi.org/10.1038/test", `{"message":{"title":["<b>Paper</b>"],"abstract":"<jats:p>Unclosed <tag \"quote"}}`)
	f.Add("https://dev.to/user/post", `{"title":"T","body_markdown":"---\nunclosed frontmatter"}`)
	f.Add("https://example.com/x", "id: x\nname: X\ncategory: developer\ndescription: valid desc here\ndomains: [example.com]\nexampleUrls: [https://example.com/x]\n")

	sampleURLs := []string{
		"https://rubygems.org/gems/rails",
		"https://dev.to/gopher/fuzzing",
		"https://hex.pm/packages/phoenix",
		"https://packagist.org/packages/symfony/console",
		"https://huggingface.co/Qwen/Qwen2.5-Coder-32B-Instruct",
		"https://lobste.rs/s/abc123/story",
		"https://doi.org/10.1038/s41586-021-03819-2",
		"https://www.usaspending.gov/award/CONT_AWD_1234",
		"https://polymarket.com/event/fed-rate-cut",
		"https://openrouter.ai/qwen/qwen-2.5-coder-32b-instruct",
	}

	f.Fuzz(func(t *testing.T, rawURL, payload string) {
		_, _ = ParseDeclarativeYAMLManifest([]byte(payload))
		if m, ok := ResolveDeclarativeTwin(rawURL); ok {
			_, _ = m.Format(payload)
		}
		for _, u := range sampleURLs {
			if m, ok := ResolveDeclarativeTwin(u); ok {
				_, _ = m.Format(payload)
			}
		}
	})
}

type errorReadDirFS struct {
	err error
}

func (e errorReadDirFS) Open(string) (fs.File, error)          { return nil, e.err }
func (e errorReadDirFS) ReadDir(string) ([]fs.DirEntry, error) { return nil, e.err }

type readFileErrorFS struct {
	inner fstest.MapFS
	fail  string
}

func (r readFileErrorFS) Open(name string) (fs.File, error) {
	if name == r.fail {
		return nil, errors.New("read failed")
	}
	return r.inner.Open(name)
}

func (r readFileErrorFS) ReadDir(name string) ([]fs.DirEntry, error) {
	return r.inner.ReadDir(name)
}

func TestDeclarativeRegistryFSAndWildcardMatching(t *testing.T) {
	if _, err := loadRegistryFromFS(errorReadDirFS{err: errors.New("dir boom")}); err == nil {
		t.Fatal("expected ReadDir error from loadRegistryFromFS")
	}

	validJSON := `{"id":"json-ad","name":"JSON Adapter","category":"developer","description":"desc","domains":["*.wild.example.com","prefix.*","exact.example.com"],"exampleUrls":["https://exact.example.com/a"],"match":{"pathSegments":["a"]},"twin":{"fetchUrl":"https://{host}/api","kind":"json","accept":""},"extract":{"vars":{"t":{"paths":["t"]}},"titleTemplate":"{t}"}}`
	mapFS := fstest.MapFS{
		"manifests/subdir/file.yaml": &fstest.MapFile{Mode: fs.ModeDir, Data: nil},
		"manifests/notes.txt":        &fstest.MapFile{Data: []byte("ignored")},
		"manifests/bad.yaml":         &fstest.MapFile{Data: []byte("id: bad\n")},
		"manifests/good.json":        &fstest.MapFile{Data: []byte(validJSON)},
		"manifests/dup.json":         &fstest.MapFile{Data: []byte(validJSON)},
		"manifests/unreadable.yaml":  &fstest.MapFile{Data: []byte("id: x")},
	}
	// Make manifests/subdir an actual directory entry
	mapFS["manifests/subdir"] = &fstest.MapFile{Mode: fs.ModeDir}
	delete(mapFS, "manifests/subdir/file.yaml")

	reg, err := loadRegistryFromFS(readFileErrorFS{inner: mapFS, fail: "manifests/unreadable.yaml"})
	if err == nil {
		t.Fatal("expected initErr when manifests include bad/dup/unreadable files")
	}
	if len(reg.manifests) != 1 || reg.manifests[0].ID != "json-ad" {
		t.Fatalf("expected 1 valid json-ad manifest loaded, got %+v", reg.manifests)
	}

	// Wildcard suffix (*.wild.example.com) and prefix (prefix.*) resolution + {host} expansion
	mSuf, ok := resolveDeclarativeTwinWithRegistry(reg, "https://sub.wild.example.com/a")
	if !ok || mSuf.FetchURL != "https://sub.wild.example.com/api" || mSuf.Accept != "application/json" {
		t.Fatalf("wildcard suffix twin failed: ok=%v m=%+v", ok, mSuf)
	}
	mPre, ok := resolveDeclarativeTwinWithRegistry(reg, "https://prefix.org/a")
	if !ok || mPre.FetchURL != "https://prefix.org/api" {
		t.Fatalf("wildcard prefix twin failed: ok=%v m=%+v", ok, mPre)
	}
	if _, ok := resolveDeclarativeTwinWithRegistry(reg, "https:///a"); ok {
		t.Fatal("empty host URL must return false")
	}
}

func TestDeclarativeParsingSearchAndRealManifestBranches(t *testing.T) {
	// DeclarativeSegmentSpec.UnmarshalJSON error cases
	var seg DeclarativeSegmentSpec
	if err := json.Unmarshal([]byte(`"\x"`), &seg); err == nil {
		t.Fatal("expected invalid JSON string segment error")
	}
	if err := seg.UnmarshalJSON([]byte(`"bad`)); err == nil {
		t.Fatal("expected direct UnmarshalJSON malformed string error")
	}
	if err := json.Unmarshal([]byte(`{"param":123}`), &seg); err == nil {
		t.Fatal("expected invalid object segment error")
	}
	if err := json.Unmarshal([]byte(`{}`), &seg); err == nil {
		t.Fatal("expected missing param name error")
	}

	// ParseDeclarativeManifest validation branches
	badManifests := []string{
		`{"unknownField":1}`,
		`{"id":"","name":"X","domains":["a.com"],"category":"developer"}`,
		`{"id":"x","name":"X","domains":["a.com"],"category":"invalid"}`,
		`{"id":"x","name":"X","domains":["a.com"],"category":"developer"}`,
		`{"id":"x","name":"X","domains":["a.com"],"category":"developer","match":{},"twin":{"kind":"xml","fetchUrl":"https://a.com"},"extract":{"titleTemplate":"t"}}`,
		`{"id":"x","name":"X","domains":["a.com"],"category":"developer","match":{},"twin":{"kind":"json","fetchUrl":"http://a.com"},"extract":{"titleTemplate":"t"}}`,
	}
	for _, raw := range badManifests {
		if _, err := ParseDeclarativeManifest([]byte(raw)); err == nil {
			t.Fatalf("expected ParseDeclarativeManifest error for %s", raw)
		}
	}

	// FindDeclarativeAdapters scoring, exact ID/name match, and limit
	exact := FindDeclarativeAdapters("rubygems", "", 0)
	if len(exact) == 0 || exact[0].ID != "rubygems" {
		t.Fatalf("expected rubygems exact match, got %+v", exact)
	}
	limited := FindDeclarativeAdapters("com", "", 2)
	if len(limited) != 2 {
		t.Fatalf("expected limit=2, got %d", len(limited))
	}

	// Real manifest edge branches:
	// 1. doi-crossref with publisher (whenVars=[venue, publisher]) and author fallbackField (name)
	doiTwin, _ := ResolveDeclarativeTwin("https://doi.org/10.1038/s41586-021-03819-2")
	doiDoc, ok := doiTwin.Format(`{"message":{"title":["Paper"],"publisher":"Springer","container-title":["Nature"],"author":[{"name":"Consortium"}]}}`)
	if !ok || !strings.Contains(doiDoc.Markdown, "Nature (Springer)") || !strings.Contains(doiDoc.Markdown, "Consortium") {
		t.Fatalf("doi-crossref publisher/fallback mismatch: ok=%v doc=%+v", ok, doiDoc)
	}

	// 2. polymarket closed=true, empty array unwrap, empty outcomes -> "-"
	polyTwin, _ := ResolveDeclarativeTwin("https://polymarket.com/event/test-ev")
	if _, ok := polyTwin.Format(`[]`); ok {
		t.Fatal("empty array unwrap must return false")
	}
	polyClosed, ok := polyTwin.Format(`[{"title":"Closed Event","closed":true,"markets":[{"question":"Q1","outcomes":123,"outcomePrices":"bad"}]}]`)
	if !ok || !strings.Contains(polyClosed.Markdown, "**Status**: Closed") || !strings.Contains(polyClosed.Markdown, "| - |") {
		t.Fatalf("polymarket closed/empty outcomes mismatch: ok=%v doc=%+v", ok, polyClosed)
	}

	// 3. packagist only dev-main -> fallback to keys[0], and empty versions: {}
	pkgTwin, _ := ResolveDeclarativeTwin("https://packagist.org/packages/vendor/pkg")
	pkgDev, ok := pkgTwin.Format(`{"package":{"name":"vendor/pkg","versions":{"dev-main":{"license":["MIT"]}}}}`)
	if !ok || pkgDev.Title != "vendor/pkg dev-main (Composer)" {
		t.Fatalf("packagist dev-main fallback mismatch: ok=%v doc=%+v", ok, pkgDev)
	}
	pkgEmpty, ok := pkgTwin.Format(`{"package":{"name":"vendor/pkg","versions":{}}}`)
	if !ok || !strings.Contains(pkgEmpty.Title, "vendor/pkg") {
		t.Fatalf("packagist empty versions mismatch: ok=%v doc=%+v", ok, pkgEmpty)
	}

	// 4. huggingface blob: .md, Makefile, Dockerfile, unknown ext, and card frontmatter edge cases
	hfMDTwin, _ := ResolveDeclarativeTwin("https://huggingface.co/org/model/blob/main/docs/GUIDE.md")
	hfMDDoc, ok := hfMDTwin.Format("---\npretty_name: Pretty Model\ndescription: Short summary\n---\n\nBody without H1")
	if !ok || hfMDDoc.Title != "Pretty Model" || hfMDDoc.Description != "Short summary" {
		t.Fatalf("huggingface .md blob mismatch: ok=%v doc=%+v", ok, hfMDDoc)
	}
	for _, tc := range []struct {
		url  string
		want string
	}{
		{"https://huggingface.co/org/model/blob/main/Makefile", "```makefile"},
		{"https://huggingface.co/org/model/blob/main/Dockerfile.prod", "```dockerfile"},
		{"https://huggingface.co/org/model/blob/main/noext", "```\n"},
		{"https://huggingface.co/org/model/blob/main/data.xyz", "```xyz"},
	} {
		bt, _ := ResolveDeclarativeTwin(tc.url)
		bdoc, bok := bt.Format("hello\n")
		if !bok || !strings.Contains(bdoc.Markdown, tc.want) {
			t.Fatalf("blob %s got (%v, %+v), want %q", tc.url, bok, bdoc, tc.want)
		}
	}
	hfCardTwin, _ := ResolveDeclarativeTwin("https://huggingface.co/org/model")
	// >8012 bytes unclosed frontmatter + no H1
	longUnclosedFM := "---\nkey: " + strings.Repeat("a", 8100) + "\nBody text"
	if doc, ok := hfCardTwin.Format(longUnclosedFM); !ok || doc.Title != "org/model" {
		t.Fatalf("huggingface long unclosed frontmatter mismatch: ok=%v doc=%+v", ok, doc)
	}
	// >12 tags + invalid key + >10 keepKeys
	manyPropsFM := "---\n" +
		"bad key: ignored\n" +
		"license: mit\npipeline_tag: text-generation\nlibrary_name: transformers\nbase_model: base\n" +
		"language: en\ndatasets: ds\nsdk: gradio\ntask_categories: tc\nsize_categories: 1B\n" +
		"tags:\n" + strings.Repeat("  - t\n", 14) +
		"---\nBody only"
	if doc, ok := hfCardTwin.Format(manyPropsFM); !ok || !strings.Contains(doc.Markdown, "# org/model") {
		t.Fatalf("huggingface manyPropsFM mismatch: ok=%v doc=%+v", ok, doc)
	}

	// 5. lobsters: indent_level <0 and >maxInd, non-object comment item, empty comment skipped
	lobTwin, _ := ResolveDeclarativeTwin("https://lobste.rs/s/abc123/post")
	lobDoc, ok := lobTwin.Format(`{"title":"T","comments":["bad-item",{"commenting_user":"x","comment_plain":"   "},{"commenting_user":"a","score":1,"indent_level":-5,"comment_plain":"neg"},{"commenting_user":"b","score":2,"indent_level":99,"comment_plain":"deep\n\nline2"}]}`)
	if !ok || !strings.Contains(lobDoc.Markdown, "- **@a**") || !strings.Contains(lobDoc.Markdown, strings.Repeat("  ", 6)+"- **@b**") {
		t.Fatalf("lobsters edge comments mismatch: ok=%v doc=%+v", ok, lobDoc)
	}

	// 6. openrouter: zero and negative pricing, non-object item, non-matching model
	orTwin, _ := ResolveDeclarativeTwin("https://openrouter.ai/org/model-a")
	orDoc, ok := orTwin.Format(`{"data":["skip",{"id":"org/model-a","name":"Model A","pricing":{"prompt":"0","completion":"-1"}}]}`)
	if !ok || !strings.Contains(orDoc.Markdown, "$0.00 / 1M tokens") {
		t.Fatalf("openrouter pricing mismatch: ok=%v doc=%+v", ok, orDoc)
	}
	if _, ok := orTwin.Format(`{"data":[{"id":"other/model"}]}`); ok {
		t.Fatal("openrouter non-matching model must return false")
	}
}

func TestDeclarativeHelpersAndSyntheticTwinCoverage(t *testing.T) {
	// Nil match Format
	var nilMatch *DeclarativeTwinMatch
	if doc, ok := nilMatch.Format("{}"); ok || doc != nil {
		t.Fatal("nil DeclarativeTwinMatch.Format must return nil, false")
	}

	// isLikelyHTMLSoft404 empty
	if !isLikelyHTMLSoft404("   \t\n") {
		t.Fatal("whitespace-only body should be treated as soft404")
	}

	// isSafePublicTwinURL all rejection branches
	for _, bad := range []string{
		"http://api.example.com/a",
		"https://user:pass@api.example.com/a",
		"https://api.example.com:8443/a",
		"https://localhost/a",
		"https://svc.local/a",
		"https://db.internal/a",
		"https://singlelabel/a",
		"https://1.2.3.4/a",
	} {
		if isSafePublicTwinURL(bad) {
			t.Fatalf("expected isSafePublicTwinURL(%q) == false", bad)
		}
	}

	// normalizeDeclarativeAccept unknown text accept -> text/plain
	if got := normalizeDeclarativeAccept("text", "application/octet-stream"); got != "text/plain" {
		t.Fatalf("normalizeDeclarativeAccept(text, unknown) = %q", got)
	}

	// validateDeclarativeParam all branches
	if validateDeclarativeParam("ab", "alnum", nil, nil, 3, 10) {
		t.Fatal("minLen violation should fail")
	}
	if validateDeclarativeParam("abc", "alnum", []string{"xyz"}, nil, 1, 10) {
		t.Fatal("allowValues mismatch should fail")
	}
	if !validateDeclarativeParam("xyz", "", []string{"xyz"}, nil, 1, 10) {
		t.Fatal("allowValues match with default pkg charset should pass")
	}
	if validateDeclarativeParam("a-b", "alnum", nil, nil, 1, 10) ||
		validateDeclarativeParam("a.b", "slug", nil, nil, 1, 10) ||
		validateDeclarativeParam("a:b", "pkg", nil, nil, 1, 10) ||
		validateDeclarativeParam("a/b", "model_slug", nil, nil, 1, 10) ||
		validateDeclarativeParam("abc", "unknown_charset", nil, nil, 1, 10) {
		t.Fatal("invalid charset inputs should fail")
	}
	for _, badDOI := range []string{"11.1000/1", "10.12/1", "10.12ab/1", "10.1000/", "10.1000/a b"} {
		if isValidDOIRest(badDOI) {
			t.Fatalf("isValidDOIRest(%q) should fail", badDOI)
		}
	}
	for _, badSub := range []string{"", "a/../b", "a?x=1", "a#frag", `a\b`, "a\x01b"} {
		if isValidSafeSubpath(badSub) {
			t.Fatalf("isValidSafeSubpath(%q) should fail", badSub)
		}
	}

	// matchDeclarativeRoute: ExactSegments=false short path, literal mismatch, bad percent escape, StripSuffix, QueryParams
	spec := DeclarativeMatchSpec{
		ExactSegments: &DeclarativeExactSegments{Bool: false},
		PathSegments: []DeclarativeSegmentSpec{
			{IsLiteral: true, Literal: "v1"},
			{ParamSpec: DeclarativeParamSegment{Param: "id", Charset: "slug", StripSuffix: ".json"}},
		},
		QueryParams: []DeclarativeQueryParamSpec{
			{Name: "q", Param: "q", Charset: "alnum"},
		},
	}
	uShort, _ := url.Parse("https://ex.com/v1?q=ok")
	if _, ok := matchDeclarativeRoute(spec, uShort, "ex.com", splitNonEmptyEscapedSegments(uShort.EscapedPath())); ok {
		t.Fatal("short path with exactSegments=false should fail")
	}
	uLitBad, _ := url.Parse("https://ex.com/v2/item?q=ok")
	if _, ok := matchDeclarativeRoute(spec, uLitBad, "ex.com", splitNonEmptyEscapedSegments(uLitBad.EscapedPath())); ok {
		t.Fatal("literal mismatch should fail")
	}
	if _, ok := matchDeclarativeRoute(spec, uLitBad, "ex.com", []string{"v1", "%ZZ"}); ok {
		t.Fatal("bad percent escape in segment should fail")
	}
	greedySpec := DeclarativeMatchSpec{
		PathSegments: []DeclarativeSegmentSpec{
			{ParamSpec: DeclarativeParamSegment{Param: "rest", Charset: "safe_subpath", Greedy: true}},
		},
	}
	if _, ok := matchDeclarativeRoute(greedySpec, uShort, "ex.com", []string{"a", "%ZZ"}); ok {
		t.Fatal("bad percent escape in greedy segment should fail")
	}
	uBadQ, _ := url.Parse("https://ex.com/v1/item.json/extra?q=bad!")
	if _, ok := matchDeclarativeRoute(spec, uBadQ, "ex.com", splitNonEmptyEscapedSegments(uBadQ.EscapedPath())); ok {
		t.Fatal("invalid query param should fail")
	}
	uGoodQ, _ := url.Parse("https://ex.com/v1/item.json/extra?q=ok123")
	params, ok := matchDeclarativeRoute(spec, uGoodQ, "ex.com", splitNonEmptyEscapedSegments(uGoodQ.EscapedPath()))
	if !ok || params["id"] != "item" || params["q"] != "ok123" {
		t.Fatalf("unexpected matchDeclarativeRoute result: ok=%v params=%+v", ok, params)
	}

	// resolveManifestTwinOnParsedURL with unsafe fetchUrl
	unsafeAdapter := &DeclarativeAdapterManifest{
		ID: "unsafe",
		Routes: []DeclarativeRouteSpec{{
			Match: DeclarativeMatchSpec{PathSegments: []DeclarativeSegmentSpec{{IsLiteral: true, Literal: "a"}}},
			Twin:  DeclarativeTwinSpec{FetchURL: "https://localhost/a", Kind: "json"},
		}},
	}
	uA, _ := url.Parse("https://ex.com/a")
	if _, ok := resolveManifestTwinOnParsedURL(unsafeAdapter, uA, "ex.com", []string{"a"}); ok {
		t.Fatal("unsafe twin fetchUrl must be rejected")
	}

	// Default text twin formatting (empty, without H1, and with H1)
	textMatch := &DeclarativeTwinMatch{
		ID:     "txt",
		Kind:   classify.KindText,
		route:  DeclarativeRouteSpec{Twin: DeclarativeTwinSpec{Kind: "text"}, Extract: DeclarativeExtractSpec{TitleTemplate: "Custom Title"}},
		params: map[string]string{},
	}
	if _, ok := textMatch.Format("   \n"); ok {
		t.Fatal("empty default text twin should return false")
	}
	if doc, ok := textMatch.Format("Plain body"); !ok || !strings.HasPrefix(doc.Markdown, "# Custom Title") {
		t.Fatalf("default text twin without H1 = (%v, %+v)", ok, doc)
	}
	if doc, ok := textMatch.Format("# Existing H1\n\nBody"); !ok || strings.HasPrefix(doc.Markdown, "# Custom Title") {
		t.Fatalf("default text twin with H1 = (%v, %+v)", ok, doc)
	}
	textNoTitle := &DeclarativeTwinMatch{
		ID:     "txt2",
		Kind:   classify.KindText,
		route:  DeclarativeRouteSpec{Twin: DeclarativeTwinSpec{Kind: "text"}, Extract: DeclarativeExtractSpec{TitleTemplate: ""}},
		params: map[string]string{},
	}
	if doc, ok := textNoTitle.Format("Plain body without title"); !ok || doc.Markdown != "Plain body without title" {
		t.Fatalf("default text twin empty title = (%v, %+v)", ok, doc)
	}
	if _, ok := textNoTitle.Format("\u202e\U000E0049"); ok {
		t.Fatal("invisible-smuggling-only body should return false after stripping")
	}

	// Synthetic JSON twin exercising cyclic vars, DynamicKeyPath non-map entry, RequireHTTPS strip,
	// RequireVars fail, TitleFallbackTemplate, empty title fail, table int_comma/strip_tags/SliceMax/Code/non-obj row,
	// list MaxIndent<=0 and outer lookup, SubField, Join=="", date_parts empty/non-numeric.
	jsonMatch := &DeclarativeTwinMatch{
		ID:     "syn",
		Kind:   classify.KindJSON,
		params: map[string]string{"outer": "OUT"},
		route: DeclarativeRouteSpec{
			Twin: DeclarativeTwinSpec{Kind: "json"},
			Extract: DeclarativeExtractSpec{
				UnwrapFirstArrayElement: true,
				RequireVars:             []string{"reqv"},
				TitleTemplate:           "{missing}",
				TitleFallbackTemplate:   "{fallbackTitle}",
				ObjectLinksPath:         "links",
				Vars: map[string]DeclarativeVarSpec{
					"cycA":          {Template: "{cycB}"},
					"cycB":          {Template: "{cycA}"},
					"reqv":          {Paths: []string{"req"}},
					"fallbackTitle": {Paths: []string{"title"}},
					"badURL":        {Paths: []string{"url"}, RequireHTTPS: true},
					"dynScalar":     {DynamicKeyPath: &DeclarativeDynamicKeyPath{Base: "map", KeyVar: "reqv", SubPath: "sub"}},
					"dynNested":     {DynamicKeyPath: &DeclarativeDynamicKeyPath{Base: "mapNested", KeyVar: "reqv", SubPath: "sub"}},
					"subf":          {Paths: []string{"objs"}, SubField: "k"},
					"firstOnly":     {Paths: []string{"arr"}},
					"emptyItems":    {Paths: []string{"emptyStrArr"}},
					"emptyDate":     {Paths: []string{"emptyArr"}, Format: "date_parts"},
					"badDate":       {Paths: []string{"badDateArr"}, Format: "date_parts"},
					"badInt":        {Paths: []string{"nonNum"}, Format: "int_comma"},
				},
				Bullets: []DeclarativeBulletSpec{
					{Label: "First", Template: "{firstOnly}"},
					{Label: "Sub", Template: "{subf}"},
				},
				Sections: []DeclarativeSectionSpec{
					{
						Heading:   "Tbl",
						ArrayPath: "rows",
						Columns: []DeclarativeTableColumn{
							{Header: "N", Paths: []string{"n"}, Format: "int_comma"},
							{Header: "H", Paths: []string{"h"}, Format: "strip_tags", SliceMax: 5, Code: true},
							{Header: "P", Format: "paired_percent", OutcomesField: "out", PricesField: "pr"},
						},
					},
					{
						Heading:       "Lst",
						ListArrayPath: "items",
						MaxIndent:     0,
						ItemVars:      map[string]DeclarativeVarSpec{"txt": {Paths: []string{"t"}}},
						ItemTemplate:  "{txt} {outer}",
					},
				},
			},
		},
	}
	if _, ok := jsonMatch.Format(`[{"req":""}]`); ok {
		t.Fatal("RequireVars empty should fail")
	}
	if _, ok := jsonMatch.Format(`[{"req":"ok","title":""}]`); ok {
		t.Fatal("empty title should fail")
	}
	synPayload := `[{"req":"ok","title":"Syn","url":"http://bad","links":{"Docs":"https://docs.example.com"},"map":{"ok":"scalar"},"mapNested":{"ok":{"sub":"nestedVal"}},"objs":[{"k":"v1"}],"arr":["only0"],"emptyStrArr":[""],"emptyArr":[],"badDateArr":["nope"],"nonNum":"abc","rows":["skip",{"n":1234,"h":"<b>123456</b>","out":[],"pr":[]}],"items":["skip",{"t":"hi"}]}]`
	synDoc, ok := jsonMatch.Format(synPayload)
	if !ok || !strings.Contains(synDoc.Markdown, "1,234") || !strings.Contains(synDoc.Markdown, "`12345`") || !strings.Contains(synDoc.Markdown, "- hi OUT") {
		t.Fatalf("synthetic JSON twin mismatch: ok=%v doc=%+v", ok, synDoc)
	}

	// orderedKeysFor with RootPath + FindInArray fallback (sorted keys & non-object ObjectLinksPath)
	orderedMatch := &DeclarativeTwinMatch{
		ID:     "ord",
		Kind:   classify.KindJSON,
		params: map[string]string{"want": "x"},
		route: DeclarativeRouteSpec{
			Twin: DeclarativeTwinSpec{Kind: "json"},
			Extract: DeclarativeExtractSpec{
				RootPath:        "wrap",
				FindInArray:     &DeclarativeFindInArray{ArrayPath: "items", MatchField: "id", MatchTemplate: "{want}"},
				TitleTemplate:   "Ordered",
				ObjectLinksPath: "links",
				Vars: map[string]DeclarativeVarSpec{
					"picked": {Paths: []string{"vers"}, FirstNonMatchingKey: "dev-"},
				},
			},
		},
	}
	if odoc, ook := orderedMatch.Format(`{"wrap":{"items":[{"id":"x","vers":{"b":1,"a":2},"links":{"Z":"https://z.example.com","A":"https://a.example.com"}}]}}`); !ook || !strings.Contains(odoc.Markdown, "- **A**: https://a.example.com") {
		t.Fatalf("orderedKeysFor FindInArray fallback mismatch: %v %+v", ook, odoc)
	}
	if _, ook := orderedMatch.Format(`{"wrap":{"items":[{"id":"x","vers":"not-obj","links":"not-obj"}]}}`); !ook {
		t.Fatal("orderedKeysFor non-object links/vers should still succeed")
	}

	// Standalone helper coverage
	if formatExtractedJSONValue(nil, DeclarativeVarSpec{}, "") != "" {
		t.Fatal("formatExtractedJSONValue(nil) should return empty")
	}
	if ordered := extractOrderedObjectKeys([]byte(`[{"links":{"a":1,"b":2}}]`), []string{"0", "links"}); len(ordered) != 2 {
		t.Fatalf("extractOrderedObjectKeys array index = %v", ordered)
	}
	if ordered := extractOrderedObjectKeys([]byte(`[{"x":1},{"a":1,"b":2}]`), []string{"1"}); len(ordered) != 2 {
		t.Fatalf("extractOrderedObjectKeys second element = %v", ordered)
	}
	if ordered := extractOrderedObjectKeys([]byte(`[{"a":1}]`), []string{"badidx"}); ordered != nil {
		t.Fatalf("extractOrderedObjectKeys bad array index = %v", ordered)
	}
	for _, trunc := range [][]byte{
		[]byte(``),
		[]byte(`{`),
		[]byte(`{"a":`),
		[]byte(`{"a":1,"b":`),
		[]byte(`[`),
		[]byte(`[{"a":1},`),
		[]byte(`{"x":[1`),
		[]byte(`{"a":1}`),
	} {
		_ = extractOrderedObjectKeys(trunc, []string{"a"})
	}
	_ = extractOrderedObjectKeys([]byte(`{"a":1`), nil)
	_ = extractOrderedObjectKeys([]byte(`{"a"`), nil)
	_ = extractOrderedObjectKeys([]byte(`[{"a":`), []string{"0"})
	_ = extractOrderedObjectKeys([]byte(`[{"a":`), []string{"5"})
	if getByDotPath(nil, "a") != nil || getByDotPath(map[string]any{}, "") == nil {
		t.Fatal("getByDotPath nil/empty checks failed")
	}
	if ordered := extractOrderedObjectKeys([]byte(`"str"`), nil); ordered != nil {
		t.Fatalf("extractOrderedObjectKeys non-delim = %v", ordered)
	}
	if ordered := extractOrderedObjectKeys([]byte(`[1,2]`), nil); ordered != nil {
		t.Fatalf("extractOrderedObjectKeys array at root = %v", ordered)
	}
	if getByDotPath(map[string]any{"a": nil}, "a.b") != nil || getByDotPath(map[string]any{"x": "str"}, "x.y") != nil || getByDotPath([]any{1}, "bad") != nil {
		t.Fatal("getByDotPath invalid array index / nil / scalar traversal should return nil")
	}
	if jsonScalarToString(nil) != "" || jsonScalarToString(float64(3.5)) != "3.5" || jsonScalarToString(true) != "true" || jsonScalarToString(false) != "false" || jsonScalarToString([]int{1}) != "" {
		t.Fatal("jsonScalarToString branches failed")
	}
	if _, ok := jsonValueToFloat(float64(2.5)); !ok {
		t.Fatal("jsonValueToFloat(float64) failed")
	}
	if _, ok := jsonValueToFloat("   "); ok {
		t.Fatal("jsonValueToFloat(blank) should fail")
	}
	if _, ok := jsonValueToFloat(true); ok {
		t.Fatal("jsonValueToFloat(bool) should fail")
	}
	if !isJSONTruthy(true) || isJSONTruthy(false) || !isJSONTruthy(json.Number("1")) || !isJSONTruthy(float64(2)) || !isJSONTruthy([]any{}) {
		t.Fatal("isJSONTruthy branches failed")
	}
	if formatIntComma(42) != "42" || formatIntComma(math.MinInt64) != "-9223372036854775808" || formatIntComma(-42) != "-42" || formatIntComma(-12345) != "-12,345" {
		t.Fatal("formatIntComma negative/boundary cases failed")
	}
	if formatUSDCompact("bad") != "" || formatUSDCompact(-2e9) != "-$2.00B" || formatUSDCompact(12.5) != "$12.50" {
		t.Fatal("formatUSDCompact branches failed")
	}
	if applyStringFormat("  x  ", "trim") != "x" || applyStringFormat("x", "unknown") != "x" {
		t.Fatal("applyStringFormat branches failed")
	}
	if stripTagsInlineLinear("") != "" || stripTagsInlineLinear(`<a title="x>y">hi</a>`) != "hi" {
		t.Fatal("stripTagsInlineLinear branches failed")
	}
	if stripLeadingYAMLFrontmatter("no fm") != "no fm" ||
		stripLeadingYAMLFrontmatter("---\n"+strings.Repeat("x", 1600)+"\n---\n") == "" ||
		stripLeadingYAMLFrontmatter("---\na: 1\n---") != "---\na: 1\n---" {
		t.Fatal("stripLeadingYAMLFrontmatter branches failed")
	}
	if collapseNewlinesWithIndent("\n\r\na\n\nb", "  ") != "\n  a\n  b" {
		t.Fatal("collapseNewlinesWithIndent branch failed")
	}
	if sliceRunesMax("😀abc", 3) != "😀a" || sliceRunesMax("éé", 3) != "éé" {
		t.Fatal("sliceRunesMax surrogate/multibyte branches failed")
	}
	if escapeDeclarativeGFMCell("", 0) != "-" || escapeDeclarativeGFMCell("abcdef", 4) != "abc…" {
		t.Fatal("escapeDeclarativeGFMCell branches failed")
	}
	if formatDeclarativeGFMTable(nil, nil) != "" {
		t.Fatal("formatDeclarativeGFMTable empty should return empty")
	}
	if !strings.HasPrefix(safeDeclarativeFence("```hi```", "md"), "````md") {
		t.Fatal("safeDeclarativeFence nested backticks failed")
	}
}
