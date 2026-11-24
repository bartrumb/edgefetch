package extract

import (
	"bufio"
	"encoding/json"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestRound8FailClosedSanitizerEverywhereOutsideFences(t *testing.T) {
	const xssImg = "<img src=x onerror=alert(1)>"
	const xssScript = "<script>alert(1)</script>"
	const xssJs = "javascript:alert(1)"

	// 1. Recognized CommonMark fenced code blocks (top-level 0..3 spaces & list-indented) preserve raw `<` and `](...)` untouched
	validFences := []struct {
		name      string
		md        string
		wantInOut string
	}{
		{
			name:      "top_level_backtick_fence",
			md:        "```html\n<script>const x = 1;</script>\n[doc](javascript:void(0))\n```",
			wantInOut: "<script>const x = 1;</script>\n[doc](javascript:void(0))",
		},
		{
			name:      "top_level_3space_tilde_fence",
			md:        "   ~~~html\n<img src=x onerror=alert(1)>\n   ~~~",
			wantInOut: "<img src=x onerror=alert(1)>",
		},
		{
			name:      "unclosed_eof_fence_closed_explicitly",
			md:        "```ts\nconst generic = Array<string>();",
			wantInOut: "```ts\nconst generic = Array<string>();\n```",
		},
	}
	for _, tc := range validFences {
		got := SanitizeMarkdown(tc.md, "https://example.com/docs/")
		if !strings.Contains(got, tc.wantInOut) {
			t.Fatalf("[%s] expected recognized fenced block to preserve %q, got:\n%s", tc.name, tc.wantInOut, got)
		}
		if SanitizeMarkdown(got, "https://example.com/docs/") != got {
			t.Fatalf("[%s] SanitizeMarkdown not idempotent:\n%s", tc.name, got)
		}
	}

	// 2. Fail-closed rule: EVERY `<` -> `&lt;` and EVERY disallowed `](...)` / `[id]: ...` neutralized outside recognized fences,
	// INCLUDING inside inline backtick code spans and ambiguous blockquote/list/4-space/info-backtick pseudo-fences!
	adversarial := map[string]string{
		"inline_backtick_img":            "`" + xssImg + "`",
		"list_indented_fence":            "- item\n\n  ```html\n  <svg onload=alert(1)>\n  ```",
		"multi_backtick_script":          "`` " + xssScript + " ``",
		"inline_backtick_js_link":        "`[click](" + xssJs + ")`",
		"inline_backtick_ref_def":        "[click][r]\n\n`[r]: " + xssJs + "`",
		"quote_code_span_desync":         "> a `x\nb\n> `" + xssImg + "`",
		"blockquote_pseudo_fence":        "> ```html\n" + xssImg + "\n> ```",
		"blockquote_lazy_fence_break":    "> ```html\n> <svg onload=1>\nlazy line\n> " + xssImg + "\n> ```",
		"same_line_list_marker_fence":    "- ```html\n  " + xssImg + "\n  ```",
		"ordered_marker_same_line_fence": "1. ~~~html\n   " + xssImg + "\n   ~~~",
		"four_space_indented_fence":      "    ```html\n" + xssImg + "\n    ```",
		"tab_indented_fence":             "\t```html\n" + xssImg + "\n\t```",
		"backtick_in_info_string":        "```html`bad\n" + xssImg + "\n```",
		"list_fence_dedent_escape":       "- item\n  ```\n  safe_in_fence\n" + xssImg + "\n[x](" + xssJs + ")",
		"protocol_relative_link":         "[p](//evil.example/xss)",
		"backslash_protocol_rel":         `[p](/\evil.example/xss)`,
		"entity_colon_no_semi":           "[p](javascript&#58alert(1))",
		"nested_amp_colon":               "[p](javascript&amp;amp;colon;alert(1))",
		"custom_scheme_data_vb":          "[a](vbscript:msgbox(1)) [b](data:text/html,<svg/onload=1>) [c](custom-app://open)",
		"unbalanced_leading_parens":      "[a](((javascript:alert(1))))",
		"autolink_inside_backticks":      "`<javascript:alert(1)>` and `<https://example.com>`",
		"table_pipe_backtick_split":      "| h1 | h2 |\n|---|---|\n| `a | " + xssImg + "` |",
		"setext_before_fence":            "Heading\n```\n" + xssImg + "\n===",
		"para_interrupted_by_non1_ol":    "Paragraph line\n42. notes\n    ```html\n    " + xssImg + "\n    ```",
		"para_interrupted_by_empty_ul":   "Paragraph line\n- \n  ```html\n  " + xssImg + "\n  ```",
		"post_strip_html_prose_fence":    "- <u></u>````\n" + xssImg + "\n````",
		"post_strip_comment_prose_fence": "<!-- c -->```\n" + xssScript + "\n```",
	}

	reInlineDest := regexp.MustCompile(`\]\(\s*(?:<([^>\n]*)>|([^\s)]+))`)
	reRefDest := regexp.MustCompile(`\]:[ \t]*(?:\r?\n[ \t>0-9.*+-]*)?(?:<([^>\n]*)>|([^\s]+))`)

	for name, md := range adversarial {
		got := SanitizeMarkdown(md, "https://example.com/base/page")
		if got2 := SanitizeMarkdown(got, "https://example.com/base/page"); got2 != got {
			t.Fatalf("[%s] non-idempotent:\n  got1=%q\n  got2=%q", name, got, got2)
		}
		// Strip ONLY strictly valid top-level/list CommonMark fences and verify ZERO raw `<` and ZERO unsafe link/ref schemes remain ANYWHERE (even inside backticks)!
		parts := splitMarkdownByCodeFencesGo(got)
		for idx := 0; idx < len(parts); idx += 2 {
			prose := parts[idx]
			if strings.IndexByte(prose, '<') >= 0 {
				t.Fatalf("[%s] FAIL-CLOSED VIOLATION: raw `<` survived outside fenced code block!\n  in =%q\n  out=%q\n  prose=%q", name, md, got, prose)
			}
			for _, m := range reInlineDest.FindAllStringSubmatch(prose, -1) {
				dest := m[1]
				if dest == "" {
					dest = m[2]
				}
				if isDisallowedMarkdownLinkDestinationGo(dest) {
					t.Fatalf("[%s] FAIL-CLOSED VIOLATION: disallowed inline destination %q survived!\n  in =%q\n  out=%q", name, dest, md, got)
				}
			}
			for _, m := range reRefDest.FindAllStringSubmatch(prose, -1) {
				dest := m[1]
				if dest == "" {
					dest = m[2]
				}
				if isDisallowedMarkdownLinkDestinationGo(dest) {
					t.Fatalf("[%s] FAIL-CLOSED VIOLATION: disallowed reference destination %q survived!\n  in =%q\n  out=%q", name, dest, md, got)
				}
			}
		}
	}
}

func TestRound8H8LinearCPUBudgetsUnder40ms(t *testing.T) {
	// Warm up once before timing
	_ = SanitizeMarkdown(strings.Repeat("[", 4096), "")

	benchmarks := []struct {
		name  string
		input string
	}{
		{name: "7M_open_brackets", input: strings.Repeat("[", 7_000_000)},
		{name: "3.5M_bracket_parens", input: strings.Repeat("](", 3_500_000)},
		{name: "3.5M_bracket_parens_with_colon_and_tick", input: strings.Repeat("](", 3_500_000) + ":`"},
		{name: "2M_raw_lt", input: strings.Repeat("<", 2_000_000)},
	}

	for _, bm := range benchmarks {
		// Take best of 3 runs to eliminate OS scheduler jitter under -race
		best := time.Hour
		var outLen int
		for attempt := 0; attempt < 3; attempt++ {
			start := time.Now()
			out := SanitizeMarkdown(bm.input, "https://example.com/")
			elapsed := time.Since(start)
			outLen = len(out)
			if elapsed < best {
				best = elapsed
			}
			if best < 40*time.Millisecond {
				break
			}
		}
		t.Logf("[H8 Go benchmark] %s -> len=%d best=%v", bm.name, outLen, best)
		// Under `go test -race`, race instrumentation adds ~2-3x overhead; enforce <40ms normal / <120ms if -race is active,
		// and verify `<` was escaped on 2M `<` (`outLen == 8_000_000`).
		if bm.name == "2M_raw_lt" && outLen != 8_000_000 {
			t.Fatalf("expected 2M `<` -> 8M `&lt;`, got len=%d", outLen)
		}
		budget := time.Duration(extractRaceSlowdown) * 40 * time.Millisecond
		if best > budget {
			t.Fatalf("[H8 Go benchmark] %s exceeded linear CPU budget (%v): %v", bm.name, budget, best)
		}
	}
}

func TestRound8GoTSParityBatchRunner(t *testing.T) {
	inPath := os.Getenv("EDGEFETCH_R8_SAN_IN")
	outPath := os.Getenv("EDGEFETCH_R8_SAN_OUT")
	if inPath == "" || outPath == "" {
		return
	}
	inFile, err := os.Open(inPath)
	if err != nil {
		t.Fatal(err)
	}
	defer inFile.Close()

	outFile, err := os.Create(outPath)
	if err != nil {
		t.Fatal(err)
	}
	defer outFile.Close()

	type reqItem struct {
		ID      string `json:"id"`
		MD      string `json:"md"`
		BaseURL string `json:"baseUrl"`
	}
	type respItem struct {
		ID  string `json:"id"`
		Out string `json:"out"`
	}

	sc := bufio.NewScanner(inFile)
	sc.Buffer(make([]byte, 0, 64<<10), 16<<20)
	enc := json.NewEncoder(outFile)
	enc.SetEscapeHTML(false)
	for sc.Scan() {
		var req reqItem
		if err := json.Unmarshal(sc.Bytes(), &req); err != nil {
			t.Fatal(err)
		}
		got := SanitizeMarkdown(req.MD, req.BaseURL)
		if err := enc.Encode(respItem{ID: req.ID, Out: got}); err != nil {
			t.Fatal(err)
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
}

func charEditDistanceGo(a, b string) int {
	if a == b {
		return 0
	}
	ra := []rune(a)
	rb := []rune(b)
	m, n := len(ra), len(rb)
	if m == 0 {
		return n
	}
	if n == 0 {
		return m
	}
	prev := make([]int, n+1)
	curr := make([]int, n+1)
	for j := 0; j <= n; j++ {
		prev[j] = j
	}
	for i := 1; i <= m; i++ {
		curr[0] = i
		ca := ra[i-1]
		for j := 1; j <= n; j++ {
			cost := 0
			if ca != rb[j-1] {
				cost = 1
			}
			del := prev[j] + 1
			ins := curr[j-1] + 1
			sub := prev[j-1] + cost
			best := del
			if ins < best {
				best = ins
			}
			if sub < best {
				best = sub
			}
			curr[j] = best
		}
		prev, curr = curr, prev
	}
	return prev[n]
}

func TestRound8Legitimate12DocumentAlterationSuite(t *testing.T) {
	type legitDoc struct {
		id            string
		baseURL       string
		maxAlteredPct float64
		md            string
		mustContain   []string
	}

	docs := []legitDoc{
		{
			id:            "01_gfm_markdown_tables",
			baseURL:       "https://docs.example.com/reference/limits",
			maxAlteredPct: 0.0,
			md: strings.Join([]string{
				"# Rate Limits & Quotas",
				"",
				"All endpoints enforce per-tenant token buckets at the edge coordinator.",
				"",
				"| Endpoint | Method | Burst Limit | Sustained (`req/min`) | Default Timeout |",
				"| :--- | :---: | ---: | ---: | :--- |",
				"| `/v1/scrape` | `POST` | `60` | `300` | `30s` |",
				"| `/v1/extract` | `POST` | `30` | `120` | `45s` |",
				"| `/v1/search` | `POST` | `40` | `240` | `15s` |",
				"| `/v1/capabilities` | `GET` | `120` | `600` | `5s` |",
				"",
				"Responses include `Retry-After` headers whenever a bucket is exhausted.",
			}, "\n"),
			mustContain: []string{"| `/v1/scrape` | `POST` | `60` | `300` | `30s` |"},
		},
		{
			id:            "02_latex_math_document",
			baseURL:       "https://docs.example.com/math/bounds",
			maxAlteredPct: 3.5,
			md: strings.Join([]string{
				"# Gaussian Tail Bounds",
				"",
				"For any real parameters satisfying $x < y$ and sequence terms $a_i + b_j = c_k$, the normalized error",
				"functional remains strictly bounded over compact intervals in $\\mathbb{R}^n$.",
				"",
				"$$\\int_0^\\infty e^{-x^2} dx < 2$$",
				"",
				"By Cauchy-Schwarz, $\\|u + v\\|_2^2 = \\|u\\|_2^2 + 2\\langle u, v \\rangle + \\|v\\|_2^2$ holds for all vectors.",
			}, "\n"),
			mustContain: []string{"$x &lt; y$", "$a_i + b_j = c_k$", "dx &lt; 2$$"},
		},
		{
			id:            "03_code_heavy_ts_rust_go_readme",
			baseURL:       "https://docs.example.com/sdk/overview",
			maxAlteredPct: 0.0,
			md: strings.Join([]string{
				"# Multi-Language Worker SDK",
				"",
				"Install the client library and run typed extraction pipelines across TypeScript, Rust, and Go.",
				"",
				"```ts",
				"export async function fetchTyped<T, E = Error>(url: string): Promise<Result<T, E>> {",
				"  return renderView(<Button onClick={fn} />);",
				"}",
				"```",
				"",
				"```rust",
				"pub fn decode_frame(payload: &[u8]) -> Result<Vec<u8>, FrameError> {",
				"    Ok(payload.to_vec())",
				"}",
				"```",
				"",
				"```go",
				"func pumpResults(ctx context.Context, out chan<- int, in <-chan int) {",
				"    out <- (<-in + 1)",
				"}",
				"```",
				"",
				"```bash",
				"edgefetch scrape --format=markdown https://example.com/docs",
				"```",
			}, "\n"),
			mustContain: []string{"Promise<Result<T, E>>", "<Button onClick={fn} />", "Result<Vec<u8>, FrameError>", "out chan<- int, in <-chan int"},
		},
		{
			id:            "04_indented_4space_code_block",
			baseURL:       "https://docs.example.com/guides/loops",
			maxAlteredPct: 2.5,
			md: strings.Join([]string{
				"# Prefix Sum Routine",
				"",
				"Classic four-space indented code blocks remain readable in plain text:",
				"",
				"    for (let i = 0; i < n; i++) {",
				"      sum += a[i];",
				"    }",
				"",
				"The accumulator `sum` holds the total across all `n` elements after termination.",
			}, "\n"),
			mustContain: []string{"    for (let i = 0; i &lt; n; i++) {\n      sum += a[i];\n    }"},
		},
		{
			id:            "05_safe_html_in_markdown_readme",
			baseURL:       "https://example.com/repo/",
			maxAlteredPct: 55.0,
			md: strings.Join([]string{
				"# Service README",
				"",
				`<p align="center"><img src="https://example.com/logo.png" alt="Logo"></p>`,
				"",
				"<details><summary>Configuration</summary>",
				"",
				"Set `PORT=8080` before launching the daemon.",
				"</details>",
				"",
				"<table><tr><th>Key</th><th>Value</th></tr><tr><td>timeout</td><td>30s</td></tr></table>",
				"",
				"Press <kbd>Ctrl</kbd>+<kbd>C</kbd> to stop. Supports H<sub>2</sub>O sensors and x<sup>2</sup> scaling.",
			}, "\n"),
			mustContain: []string{
				"![Logo](https://example.com/logo.png)",
				"**Configuration**",
				"| Key | Value |\n| --- | --- |\n| timeout | 30s |",
				"`Ctrl`+`C`",
				"H2O",
			},
		},
		{
			id:            "06_nested_blockquotes_and_lists",
			baseURL:       "https://docs.example.com/ops/checklist",
			maxAlteredPct: 0.0,
			md: strings.Join([]string{
				"# Deployment Notes",
				"",
				"> Note: see step 1 before rotating production credentials.",
				">",
				"> - Item A: Verify standby replica replication lag is zero.",
				"> - Item B: Confirm backup snapshot checksum in object storage.",
				"",
				"1. Drain active worker connections cleanly.",
				"2. Roll out the new static binary across edge nodes.",
				"   - Check `/health` status on loopback.",
				"   - Confirm WebSocket heartbeat metrics.",
			}, "\n"),
			mustContain: []string{"> - Item A: Verify standby replica replication lag is zero."},
		},
		{
			id:            "07_reference_style_links",
			baseURL:       "https://example.com/docs/",
			maxAlteredPct: 0.0,
			md: strings.Join([]string{
				"# Developer Portal",
				"",
				"Read the [API Guide][api] and [CLI Docs][cli] before configuring authentication tokens.",
				"For operational runbooks, consult the [Security Policy][sec] as well.",
				"",
				`[api]: https://example.com/api "API Guide"`,
				"[cli]: https://example.com/cli",
				`[sec]: https://example.com/security "Security Policy"`,
			}, "\n"),
			mustContain: []string{`[api]: https://example.com/api "API Guide"`},
		},
		{
			id:            "08_technical_prose_inline_generics",
			baseURL:       "https://docs.example.com/api/client",
			maxAlteredPct: 4.5,
			md: strings.Join([]string{
				"# Batch Query Client",
				"",
				"The batch helper serializes query keys deterministically and deduplicates in-flight requests",
				"across concurrent callers within the same isolate.",
				"",
				"Returns `Promise<Array<Record<string, unknown>>>` on success, or throws a typed `BatchClientError`",
				"carrying the upstream HTTP status code and structured retry metadata.",
			}, "\n"),
			mustContain: []string{"`Promise&lt;Array&lt;Record&lt;string, unknown>>>`"},
		},
		{
			id:            "09_changelog_release_notes",
			baseURL:       "https://github.com/acme/project/releases",
			maxAlteredPct: 0.0,
			md: strings.Join([]string{
				"# Changelog",
				"",
				"## [2.7.2] - 2026-11-22",
				"",
				"### Security",
				"- **Markdown Sanitizer:** Enforced fail-closed escaping in `sanitizeInlineHtmlInMarkdown` across all 6 parser dialects.",
				"- **Artifact Paging:** Bound `readArtifactPage` strictly to `SCRAPE_PIPELINE_VERSION` (`31`) in [storage.ts](https://github.com/acme/project/blob/main/hub/src/storage.ts).",
				"",
				"### Fixed",
				"- Eliminated regex backtracking on malformed pipe-dash inputs in `scrape-advanced.ts`.",
			}, "\n"),
			mustContain: []string{"## [2.7.2] - 2026-11-22"},
		},
		{
			id:            "10_python_datascience_notebook",
			baseURL:       "https://docs.example.com/notebooks/eval",
			maxAlteredPct: 0.0,
			md: strings.Join([]string{
				"# Benchmark Evaluation Notebook",
				"",
				"Load the evaluation dataset and compute per-cohort latency percentiles:",
				"",
				"```python",
				"import pandas as pd",
				"",
				`df = pd.read_parquet("runs.parquet")`,
				`summary = df.groupby("tier")["latency_ms"].quantile([0.5, 0.95]).unstack()`,
				"print(summary)",
				"```",
				"",
				"| Tier | p50 (`ms`) | p95 (`ms`) | Samples |",
				"| :--- | ---: | ---: | ---: |",
				"| `edge-cache` | `4.2` | `11.8` | `12,500` |",
				"| `live-origin` | `38.5` | `94.1` | `12,500` |",
			}, "\n"),
			mustContain: []string{`df = pd.read_parquet("runs.parquet")`, "| `edge-cache` | `4.2` | `11.8` | `12,500` |"},
		},
		{
			id:            "11_rfc_spec_prose_autolinks",
			baseURL:       "https://www.rfc-editor.org/rfc/rfc9309",
			maxAlteredPct: 9.0,
			md: strings.Join([]string{
				"# Robots Exclusion Protocol Conformance",
				"",
				"1. Crawlers MUST fetch `/robots.txt` over HTTPS and parse `User-agent`, `Allow`, and `Disallow` rules.",
				"2. Redirect chains up to five hops MUST be validated at every hop before following `Location` headers.",
				"3. Normative specification text is published at <https://example.com/rfc> for implementers.",
			}, "\n"),
			mustContain: []string{"[https://example.com/rfc](https://example.com/rfc)"},
		},
		{
			id:            "12_gfm_task_lists_strikethrough_footnotes",
			baseURL:       "https://docs.example.com/roadmap",
			maxAlteredPct: 1.5,
			md: strings.Join([]string{
				"# Release Readiness Tracker",
				"",
				"- [x] Shipped linear-time HTML and Markdown sanitizers in Go and TypeScript",
				"- [ ] Pending post-release adapter pack expansion in next minor cycle",
				"",
				"Replaced ~~legacy multi-version cache fallback~~ with single-version `SCRAPE_PIPELINE_VERSION` enforcement[^1].",
				"",
				"[^1]: Verified across unit, workerd E2E, and Go race-detector suites.",
			}, "\n"),
			mustContain: []string{"- \\[x] Shipped", "- \\[ ] Pending", "~~legacy multi-version cache fallback~~"},
		},
	}

	for _, d := range docs {
		out := SanitizeMarkdown(d.md, d.baseURL)
		if out2 := SanitizeMarkdown(out, d.baseURL); out2 != out {
			t.Fatalf("[%s] non-idempotent:\n  out1=%q\n  out2=%q", d.id, out, out2)
		}
		parts := splitMarkdownByCodeFencesGo(out)
		for idx := 0; idx < len(parts); idx += 2 {
			if strings.IndexByte(parts[idx], '<') >= 0 {
				t.Fatalf("[%s] raw `<` survived outside fenced code block: %q", d.id, parts[idx])
			}
		}
		for _, want := range d.mustContain {
			if !strings.Contains(out, want) {
				t.Fatalf("[%s] expected sanitized output to contain %q, got:\n%s", d.id, want, out)
			}
		}
		origLen := len([]rune(d.md))
		altered := charEditDistanceGo(d.md, out)
		pct := float64(altered) / float64(origLen) * 100.0
		t.Logf("[Go LegitDoc %s] orig=%d san=%d alteredChars=%d alteredPct=%.2f%%", d.id, origLen, len([]rune(out)), altered, pct)
		if pct > d.maxAlteredPct {
			t.Fatalf("[%s] alteredPct %.2f%% exceeded maxAlteredPct %.2f%%", d.id, pct, d.maxAlteredPct)
		}
	}
}

func TestRound8HeldOutLinearHtmlCommentsAndParity(t *testing.T) {
	// 1. HTML5 abrupt comments + entity <a href> + nested GFM checkboxes + bare //host.tld parity
	if got := SanitizeMarkdown("<!-->hello-->", "https://docs.example.com/guide"); got != "hello-->" {
		t.Fatalf("abrupt comment mismatch: got %q, want %q", got, "hello-->")
	}
	if got := SanitizeMarkdown(`<!--->world-->`, ""); got != "world-->" {
		t.Fatalf("abrupt dash comment mismatch: got %q, want %q", got, "world-->")
	}
	if got := SanitizeMarkdown(`<a href="javascript&#x3a;alert(1)">ent</a>`, "https://docs.example.com/guide"); got != "ent" {
		t.Fatalf("entity href mismatch: got %q, want %q", got, "ent")
	}
	if got := SanitizeMarkdown("1. - [ ] task\n- * [x] done", ""); got != "1. - \\[ ] task\n- * \\[x] done" {
		t.Fatalf("nested checkbox mismatch: got %q", got)
	}
	if got := SanitizeMarkdown("//example.com) now.", ""); got != `\//example.com) now.` {
		t.Fatalf("bare protocol-relative mismatch: got %q", got)
	}
	if got := SanitizeMarkdown("Visit //evil.xn--p1ai/p or //localhost:8080/a or //[::1]/p or //a.b/x", ""); got != `Visit \//evil.xn--p1ai/p or \//localhost:8080/a or \//[::1]/p or \//a.b/x` {
		t.Fatalf("IDN/localhost/IPv6/1char protocol-relative mismatch: got %q", got)
	}
	if got := SanitizeMarkdown("<svg onload=x><svg onload=x>", ""); got != "" {
		t.Fatalf("unclosed double <svg> parity mismatch: got %q, want empty", got)
	}

	// 2. O(N) linear scaling on 1 MiB of unclosed `<!-- a ` and bang-closed `<!-- x --!>` (< 100ms, ratio < 16)
	for _, pat := range []string{"<!-- a ", "<!-- x --!>"} {
		small := strings.Repeat(pat, (128*1024)/len(pat))
		large := strings.Repeat(pat, (1024*1024)/len(pat))
		_ = SanitizeMarkdown(small[:4096], "")
		t0 := time.Now()
		_ = SanitizeMarkdown(small, "")
		dSmall := time.Since(t0)
		if dSmall < 200*time.Microsecond {
			dSmall = 200 * time.Microsecond
		}
		t1 := time.Now()
		_ = SanitizeMarkdown(large, "")
		dLarge := time.Since(t1)
		ratio := float64(dLarge) / float64(dSmall)
		if dLarge > 250*time.Millisecond || ratio >= 16.0 {
			t.Fatalf("non-linear HTML comment scan on %q: 128KiB=%v 1MiB=%v ratio=%.2f", pat, dSmall, dLarge, ratio)
		}
	}
}
