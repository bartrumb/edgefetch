package extract

import (
	"strings"
	"testing"

	"github.com/bartrumb/edgefetch/v2/internal/classify"
)

func TestDeclarativeManifestsCatalogIntegrity(t *testing.T) {
	_ = loadRegistry()
	if regInitErr != nil {
		t.Fatalf("unexpected declarative registry load error: %v", regInitErr)
	}
	catalog := ListDeclarativeAdapters()
	if len(catalog) < 10 {
		t.Fatalf("expected at least 10 embedded declarative adapters, got %d", len(catalog))
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
		for _, ex := range entry.ExampleURLs {
			m, ok := ResolveDeclarativeTwin(ex)
			if !ok || m == nil {
				t.Fatalf("adapter %q exampleUrl %q failed to resolve twin", entry.ID, ex)
			}
			if !strings.HasPrefix(m.FetchURL, "https://") {
				t.Fatalf("adapter %q resolved non-https fetchUrl %q", entry.ID, m.FetchURL)
			}
			if m.Kind != classify.KindJSON && m.Kind != classify.KindText {
				t.Fatalf("adapter %q unexpected kind %q", entry.ID, m.Kind)
			}
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
	hfDoc, ok := hfTwin.Format("---\nlicense: apache-2.0\npipeline_tag: text-generation\ntags:\n  - code\n  - qwen2\n---\n\n# Qwen2.5-Coder\n\nSupports `Vec<u8>` generation.")
	if !ok || !strings.Contains(hfDoc.Markdown, "| **license** | apache-2.0 |") || !strings.Contains(hfDoc.Markdown, "Vec<u8>") {
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
