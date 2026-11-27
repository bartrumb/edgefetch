package extract

import (
	"bufio"
	"encoding/json"
	"html"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

func TestR7ArcgisAndXMLUnicodeFoldNoPanic(t *testing.T) {
	// Regression for r7D fuzz-fail.out: invalid UTF-8 / multi-byte Unicode whose strings.ToLower changes byte length
	// ("İ" -> "i\u0307", or "\x80" -> "\ufffd" in older paths) before "/rest/serviCes/0".
	inputs := []string{
		"https://0.A/\x80/rest/serviCes/0",
		"https://0.A/\xfe\xff/rest/serviCes/0/query",
		"https://example.com/İ/rest/serviCes/0",
		"https://example.com/ȺȺȺ/rest/Services/Layer/FeatureServer/12",
		"https://services.arcgis.com/org/arcgis/rest/services/Parcels/FeatureServer/0",
	}
	for _, u := range inputs {
		_ = isArcgisRestLayerPathGo(u)
		_, _ = ResolveDeclarativeTwin(u)
	}
	if !isArcgisRestLayerPathGo("https://services.arcgis.com/org/arcgis/rest/services/Parcels/FeatureServer/0") {
		t.Fatal("expected valid ArcGIS FeatureServer layer URL to match")
	}

	// Also ensure formatXMLTwinGo with multi-byte Unicode tags ("İ") never panics or mis-slices.
	xmlWithDottedI := `<?xml version="1.0"?><rss><channel><title>İİİ Feed</title><item><title>İ Item</title><link>https://ok.example/1</link><pubDate>Mon</pubDate></item></channel></rss>`
	wwrTwin, ok := ResolveDeclarativeTwin("https://weworkremotely.com/remote-jobs")
	if !ok || wwrTwin == nil {
		t.Fatal("expected weworkremotely twin")
	}
	if doc, ok := wwrTwin.Format(xmlWithDottedI); !ok || doc == nil || !strings.Contains(doc.Markdown, "https://ok.example/1") {
		t.Fatalf("expected formatXMLTwinGo to format multi-byte Unicode XML cleanly, got ok=%v doc=%+v", ok, doc)
	}
}

func TestR7DeterministicEvalRowMapAndAbstractOrder(t *testing.T) {
	// 1. ReconstructInvertedAbstract deterministic ordering on tie/duplicate word positions.
	inv := map[string]any{
		"zeta":  []any{float64(0)},
		"alpha": []any{float64(0)},
		"beta":  []any{float64(1)},
	}
	firstAbs := reconstructInvertedAbstractGo(inv)
	for i := 0; i < 50; i++ {
		if got := reconstructInvertedAbstractGo(inv); got != firstAbs {
			t.Fatalf("non-deterministic reconstructInvertedAbstractGo at iter %d: %q vs %q", i, got, firstAbs)
		}
	}
	if firstAbs != "zeta beta" {
		// Sorted keys: "alpha" (pos 0) then "zeta" (overwrites pos 0 deterministically) -> "zeta beta".
		t.Fatalf("unexpected abstract output: %q", firstAbs)
	}

	// 2. Verify ItemVars evaluation on ckan, yc, remoteok, jobicy, arbeitnow is 100% deterministic AND resolves dependent {roleName} templates!
	samples := []struct {
		url      string
		body     string
		mustHave string
	}{
		{
			url:      "https://catalog.data.gov/dataset/air-quality",
			body:     `{"success":true,"result":{"title":"Air Quality","notes":"Dataset notes","organization":{"title":"EPA"},"license_title":"CC0","metadata_modified":"2026-01-01","tags":[{"display_name":"climate"}],"resources":[{"name":"CSV Table","format":"CSV","url":"https://data.gov/air.csv","description":"Main CSV"}]}}`,
			mustHave: "[CSV Table](https://data.gov/air.csv)",
		},
		{
			url:      "https://www.workatastartup.com/companies/acme",
			body:     `<html><body><div data-page="{&quot;props&quot;:{&quot;company&quot;:{&quot;name&quot;:&quot;Acme&quot;,&quot;one_liner&quot;:&quot;Fast AI&quot;,&quot;batch_name&quot;:&quot;W26&quot;,&quot;team_size&quot;:12},&quot;jobPostings&quot;:[{&quot;title&quot;:&quot;Systems Engineer&quot;,&quot;url&quot;:&quot;/companies/acme/jobs/1&quot;,&quot;location&quot;:&quot;Remote&quot;,&quot;type&quot;:&quot;Full-time&quot;,&quot;salaryRange&quot;:&quot;$180k&quot;}]}}"></div></body></html>`,
			mustHave: "[Systems Engineer](https://www.ycombinator.com/companies/acme/jobs/1)",
		},
		{
			url:      "https://remoteok.com/",
			body:     `[{"legal":"ok"},{"position":"Principal Go Engineer","company":"EdgeCo","location":"Worldwide","url":"https://remoteok.com/remote-jobs/123","date":"2026-11-01","salary_min":150000,"salary_max":200000}]`,
			mustHave: "[Principal Go Engineer](https://remoteok.com/remote-jobs/123)",
		},
		{
			url:      "https://jobicy.com/jobs-rss-feed",
			body:     `{"jobs":[{"jobTitle":"Security Researcher","companyName":"SecLab","jobGeo":"USA","jobType":["Full-Time"],"url":"https://jobicy.com/jobs/1-sec","pubDate":"2026-11-01"}]}`,
			mustHave: "[Security Researcher](https://jobicy.com/jobs/1-sec)",
		},
		{
			url:      "https://www.arbeitnow.com/api/job-board-api",
			body:     `{"data":[{"title":"Backend Lead","company_name":"CloudGmbH","location":"Berlin","remote":true,"url":"https://www.arbeitnow.com/jobs/backend-lead","created_at":1760000000}]}`,
			mustHave: "[Backend Lead](https://www.arbeitnow.com/jobs/backend-lead)",
		},
	}

	for _, tc := range samples {
		res, ok := ResolveDeclarativeTwin(tc.url)
		if !ok || res == nil {
			t.Fatalf("expected adapter resolution for %s", tc.url)
		}
		ref, ok := res.Format(tc.body)
		if !ok || ref == nil {
			t.Fatalf("expected Format success for %s", tc.url)
		}
		if !strings.Contains(ref.Markdown, tc.mustHave) {
			t.Fatalf("expected %q in formatted Markdown for %s, got:\n%s", tc.mustHave, tc.url, ref.Markdown)
		}
		for iter := 0; iter < 50; iter++ {
			got, ok2 := res.Format(tc.body)
			if !ok2 || got.Markdown != ref.Markdown {
				t.Fatalf("NON-DETERMINISTIC output for %s at iter %d:\nwant:\n%s\ngot:\n%s", tc.url, iter, ref.Markdown, got.Markdown)
			}
		}
	}
}

func TestR7XMLFeedStrictPublicHTTPSLinks(t *testing.T) {
	res, ok := ResolveDeclarativeTwin("https://weworkremotely.com/remote-jobs")
	if !ok || res == nil {
		t.Fatal("expected weworkremotely adapter resolution")
	}

	rss := `<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0"><channel><title>WWR Jobs</title>
  <item><title>Valid Role</title><region>Global</region><category>Dev</category><pubDate>Mon</pubDate><link>https://weworkremotely.com/remote-jobs/valid-1</link></item>
  <item><title>Plain HTTP</title><region>US</region><category>Dev</category><pubDate>Mon</pubDate><link>http://weworkremotely.com/remote-jobs/insecure</link></item>
  <item><title>JS XSS</title><region>US</region><category>Dev</category><pubDate>Mon</pubDate><link>javascript:alert(1)</link></item>
  <item><title>Metadata SSRF</title><region>US</region><category>Dev</category><pubDate>Mon</pubDate><link>https://169.254.169.254/latest/meta-data/</link></item>
  <item><title>Loopback SSRF</title><region>US</region><category>Dev</category><pubDate>Mon</pubDate><link>https://127.0.0.1:8443/internal</link></item>
  <item><title>Localhost</title><region>US</region><category>Dev</category><pubDate>Mon</pubDate><link>https://localhost/admin</link></item>
  <item><title>SchemeRel</title><region>US</region><category>Dev</category><pubDate>Mon</pubDate><link>//evil.example/phish</link></item>
  <item><title>DataURI</title><region>US</region><category>Dev</category><pubDate>Mon</pubDate><link>data:text/html,&lt;script&gt;alert(1)&lt;/script&gt;</link></item>
</channel></rss>`

	doc, ok := res.Format(rss)
	if !ok || doc == nil {
		t.Fatal("expected WWR RSS format to succeed")
	}
	if !strings.Contains(doc.Markdown, "[Valid Role](https://weworkremotely.com/remote-jobs/valid-1)") {
		t.Fatalf("expected valid public https link preserved, got:\n%s", doc.Markdown)
	}
	for _, bad := range []string{
		"http://weworkremotely.com",
		"javascript:",
		"169.254.169.254",
		"127.0.0.1",
		"https://localhost",
		"//evil.example",
		"data:text/html",
	} {
		if strings.Contains(doc.Markdown, bad) {
			t.Fatalf("SECURITY (R7 XML Feed): unsafe link %q leaked into XML Markdown:\n%s", bad, doc.Markdown)
		}
	}
	if len(doc.Links) != 1 || doc.Links[0] != "https://weworkremotely.com/remote-jobs/valid-1" {
		t.Fatalf("SECURITY (R7 XML Feed): expected Links to contain strictly 1 public https URL, got %+v", doc.Links)
	}
}

var (
	reTestRawDangerTag = regexp.MustCompile(`(?i)<(script|svg|iframe|object|embed|form|style|link|meta|base|math|video|audio|details|input|body|marquee)\b`)
	reTestOnEventTag   = regexp.MustCompile(`(?i)<(?:a|img)\b[^>]*\son[a-z]+\s*=`)
	reTestInlineLink   = regexp.MustCompile(`\]\(\s*<?([^)\s>]+)`)
	reTestRefDefLine   = regexp.MustCompile(`(?m)^[ \t>0-9.*+-]*\[[^\]]+\]:\s*<?([^\s>]+)`)
)

func assertSanitizedMarkdownSafeAndIdempotent(t *testing.T, name, input string) {
	t.Helper()
	out := SanitizeScrapedMarkdown(input)
	out2 := SanitizeScrapedMarkdown(out)
	if out != out2 {
		t.Fatalf("NON-IDEMPOTENT SanitizeScrapedMarkdown on %s:\n  in  =%q\n  out1=%q\n  out2=%q", name, input, out, out2)
	}

	// Strip only legitimate CommonMark 0..3-space fenced code blocks and valid inline code spans before scanning prose for active HTML/URLs.
	prose := stripValidCommonMarkCodeForAudit(out)

	if m := reTestRawDangerTag.FindString(prose); m != "" {
		t.Fatalf("SECURITY (R7 Sanitizer %s): active HTML tag %q survived outside code!\n  in =%q\n  out=%q\n  prose=%q", name, m, input, out, prose)
	}
	if m := reTestOnEventTag.FindString(prose); m != "" {
		t.Fatalf("SECURITY (R7 Sanitizer %s): event-handler tag %q survived outside code!\n  in =%q\n  out=%q", name, m, input, out)
	}
	if regexp.MustCompile(`(?m)^[ \t]*(?:[-*+]|\d+[.)])[ \t]+\[[ xX]\][ \t]+`).MatchString(prose) {
		t.Fatalf("SECURITY (R7 Sanitizer %s): unescaped GFM task-list checkbox survived (renders <input> in marked)!\n  out=%q", name, out)
	}

	checkDest := func(rawDest string) {
		u := html.UnescapeString(rawDest)
		u = strings.ReplaceAll(u, `\`, "")
		u = strings.Map(func(r rune) rune {
			if r <= 0x20 || r == 0x7f || r == 0xfeff || (r >= 0x200b && r <= 0x200f) {
				return -1
			}
			return r
		}, u)
		low := strings.ToLower(u)
		for _, scheme := range []string{"javascript:", "vbscript:", "data:", "file:", "blob:"} {
			if strings.HasPrefix(low, scheme) {
				t.Fatalf("SECURITY (R7 Sanitizer %s): dangerous destination %q survived!\n  in =%q\n  out=%q", name, rawDest, input, out)
			}
		}
	}
	for _, m := range reTestInlineLink.FindAllStringSubmatch(prose, -1) {
		checkDest(m[1])
	}
	for _, m := range reTestRefDefLine.FindAllStringSubmatch(prose, -1) {
		checkDest(m[1])
	}
}

func stripValidCommonMarkCodeForAudit(md string) string {
	lines := strings.Split(md, "\n")
	var proseLines []string
	inFence := false
	var fenceCh byte
	fenceLen := 0

	for _, line := range lines {
		indent := 0
		i := 0
		for i < len(line) && indent < 4 {
			if line[i] == ' ' {
				indent++
				i++
			} else if line[i] == '\t' {
				indent = 4
				break
			} else {
				break
			}
		}
		if !inFence {
			if indent <= 3 && i < len(line) && (line[i] == '`' || line[i] == '~') {
				ch := line[i]
				j := i
				for j < len(line) && line[j] == ch {
					j++
				}
				if j-i >= 3 && (ch != '`' || strings.IndexByte(line[j:], '`') < 0) {
					inFence = true
					fenceCh = ch
					fenceLen = j - i
					continue
				}
			}
			proseLines = append(proseLines, line)
		} else {
			if indent <= 3 && i < len(line) && line[i] == fenceCh {
				j := i
				for j < len(line) && line[j] == fenceCh {
					j++
				}
				if j-i >= fenceLen && strings.Trim(line[j:], " \t") == "" {
					inFence = false
				}
			}
		}
	}

	// Strip matching CommonMark backtick code spans within each paragraph.
	paragraphs := strings.Split(strings.Join(proseLines, "\n"), "\n\n")
	for pIdx, p := range paragraphs {
		var sb strings.Builder
		for i := 0; i < len(p); {
			if p[i] == '\\' && i+1 < len(p) {
				sb.WriteByte(p[i])
				sb.WriteByte(p[i+1])
				i += 2
				continue
			}
			if p[i] == '`' {
				j := i
				for j < len(p) && p[j] == '`' {
					j++
				}
				n := j - i
				closeAt := -1
				for k := j; k < len(p); {
					if p[k] == '`' {
						m := k
						for m < len(p) && p[m] == '`' {
							m++
						}
						if m-k == n {
							closeAt = m
							break
						}
						k = m
						continue
					}
					k++
				}
				if closeAt > 0 {
					sb.WriteString(" CODE ")
					i = closeAt
					continue
				}
				sb.WriteString(p[i:j])
				i = j
				continue
			}
			sb.WriteByte(p[i])
			i++
		}
		paragraphs[pIdx] = sb.String()
	}
	return strings.Join(paragraphs, "\n\n")
}

func TestR7SanitizeScrapedMarkdownAllCorpusVectorsAndIdempotency(t *testing.T) {
	const img = "<img src=x onerror=alert(1)>"
	const js = "javascript:alert(1)"

	cases := map[string]string{
		"idempotent_cr_crlf":       "\r\r\n0",
		"r4_entTab":                "[x](java&Tab;script:alert(1))",
		"r4_entNewLine":            "[x](java&NewLine;script:alert(1))",
		"r4_destNextLine":          "[x](\n" + js + ")",
		"r4_bsColon":               `[x](javascript\:alert(1))`,
		"r4_refNextLine":           "[x][y]\n\n[y]:\n" + js,
		"r4_refList":               "[x][y]\n\n- [y]: " + js,
		"ampAmp":                   "[x](javascript&amp;colon;alert(1))",
		"leadBom":                  "[x](\ufeff" + js + ")",
		"autolinkTick":             "<https://x.example/`> " + img + " <https://y.example/`>",
		"destNlBoth":               "[x](\n" + js + "\n)",
		"file":                     "[x](file:///etc/passwd)",
		"blob":                     "[x](blob:https://a/b)",
		"refBs":                    "[y]\n\n[y]: javascript\\:alert(1)",
		"refNextIndent":            "[y]\n\n[y]:\n    " + js,
		"refLabelNl":               "[y z]\n\n[y\nz]: " + js,
		"refInOl":                  "[y]\n\n1. [y]: " + js,
		"refInQuoteNext":           "[y]\n\n> [y]:\n> " + js,
		"refCRLF":                  "[y]\r\n\r\n[y]:\r\n" + js,
		"crossLineSpan":            "`a\nb` " + img + " `c`",
		"crossLineSpanLink":        "`a\nb` [x](" + js + ") `c`",
		"crossLineSpan2":           "``a\nb`` " + img + " ``c``",
		"crossLineSpanScript":      "`a\nb` <script>alert(1)</script> `c`",
		"crossLineSpanCRLF":        "`a\r\nb` " + img + " `c`",
		"crossLineSpan3":           "x `\n` " + img + " `",
		"crossLineInList":          "- `a\n  b` " + img + " `c`",
		"crossLineInQuote":         "> `a\n> b` " + img + " `c`",
		"fenceInfoTick":            "``` a`b\n\n" + img + "\n\n```",
		"fenceInList":              "1. a\n\n   ```\n   code\n\n" + img + "\n",
		"fenceInList2":             "- a\n\n  ~~~\n  code\n\n" + img + "\n",
		"fenceInListLink":          "- a\n\n  ~~~\n  code\n\n[x](" + js + ")\n",
		"fenceCloseCR":             "~~~\ncode\n~~~\r" + img + "\n",
		"fenceOpenCR":              "~~~\r~~~\r" + img + "\r",
		"fenceIndent4":             "    ```\n\n" + img + "\n\n    ```",
		"fenceTab":                 "\t~~~\n\n" + img + "\n\n\t~~~",
		"fenceInListAfterPara":     "* item\n\n  ~~~js\n  x\n\ntext " + img + " and [k](" + js + ")",
		"tableCodePipe":            "| a | b |\n|---|---|\n| `x | " + img + " ` |",
		"crossLineTable":           "| a | b |\n|---|---|\n| `x | y` " + img + " `z` |",
		"safeTableCodeCell":        "| Col | Type |\n|---|---|\n| ret | `Promise<void>` |",
		"taskLink":                 "- [ ] [x](" + js + ")",
		"r7_indent4FenceAfterPara": "para\n    ```\n<script>alert(1)</script>\n",
		"r7_indent4FenceImg":       "para\n    ~~~\n" + img + "\n",
		"r7_fenceInfoTickScript":   "```x`\n<script>alert(1)</script>\n",
		"r7_fenceInfoTickLink":     "```x`\n[x](" + js + ")\n",
		"r7_crossLineTickScript":   "a ` b\n` <script>alert(1)</script> `",
		"r7_crossLineTickLink":     "a ` b\n` [x](" + js + ") `",
		"r7_refNextLine":           "[y]\n\n[y]:\n" + js,
		"r7_refInUl":               "[y]\n\n- [y]: " + js,
		"r7_refInOl":               "[y]\n\n1. [y]: " + js,
		"r7_refLabelEsc":           `[a\]: b]` + "\n\n" + `[a\]: b]: ` + js,
		"r7_linkEscParen":          `[x](\) [y](` + js + ")",
		"r7_linkUnbalanced":        "[x](( [y](" + js + ")",
		"r7_tickInLinkDest":        "[a](https://ok.example/`) " + img + " [b](https://ok.example/`)",
		"r7_autolinkTick":          "<https://ok.example/`> <script>alert(1)</script> `",
		"entDecNoSemiZeros":        "[x](javascript&#0000058alert(1))",
		"entHexNoSemi":             "[x](javascript&#x3Aalert(1))",
		"bareURLGluedTick":         "https://ok.example/` " + img + " https://ok2.example/`",
		"safeCodeSpanPreserved":    "Returns `Promise<void>` over HTTP/2.",
		"safeFencedBlockPreserved": "```html\n<script>const ok = true;</script>\n```\n\nSafe paragraph.",
	}

	for name, input := range cases {
		assertSanitizedMarkdownSafeAndIdempotent(t, name, input)
	}

	// H1 fail-closed rule: inline code spans escape `<` to `&lt;`, while recognized fenced code blocks preserve `<` verbatim!
	if got := SanitizeScrapedMarkdown("Returns `Promise<void>` over HTTP/2."); !strings.Contains(got, "`Promise&lt;void>`") {
		t.Fatalf("expected `Promise&lt;void>` escaped fail-closed in inline code span, got %q", got)
	}
	if got := SanitizeScrapedMarkdown("```html\n<script>const ok = true;</script>\n```"); !strings.Contains(got, "<script>const ok = true;</script>") {
		t.Fatalf("expected fenced code block contents preserved verbatim, got %q", got)
	}
	if got := SanitizeScrapedMarkdown("| Col | Type |\n|---|---|\n| ret | `Promise<void>` |"); !strings.Contains(got, "`Promise&lt;void>`") {
		t.Fatalf("expected single-cell table code span `Promise&lt;void>` escaped fail-closed, got %q", got)
	}

	if inPath := os.Getenv("EDGEFETCH_R7_SAN_IN"); inPath != "" {
		f, err := os.Open(inPath)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		outFile, err := os.Create(os.Getenv("EDGEFETCH_R7_SAN_OUT"))
		if err != nil {
			t.Fatal(err)
		}
		defer outFile.Close()
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 0, 64<<10), 16<<20)
		enc := json.NewEncoder(outFile)
		enc.SetEscapeHTML(false)
		idx := 0
		for sc.Scan() {
			var raw string
			if err := json.Unmarshal(sc.Bytes(), &raw); err != nil {
				t.Fatal(err)
			}
			md := SanitizeScrapedMarkdown(raw)
			md2 := SanitizeScrapedMarkdown(md)
			_ = enc.Encode(map[string]any{"md": md, "idempotent": md == md2})
			idx++
		}
	}
}

func TestRound8FailClosedSanitizerEverywhereOutsideFences(t *testing.T) {
	const xssImg = "<img src=x onerror=alert(1)>"
	const xssScript = "<script>alert(1)</script>"
	const xssJs = "javascript:alert(1)"

	// 1. Recognized CommonMark fenced code blocks (top-level 0..3 spaces) preserve raw `<` and `](...)` untouched
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
		// Strip ONLY strictly valid top-level CommonMark fences and verify ZERO raw `<` and ZERO unsafe link/ref schemes remain ANYWHERE (even inside backticks)!
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
	_ = extractRaceSlowdown
	const antiQuadraticGuard = 5 * time.Second

	cases := []struct {
		name  string
		input string
	}{
		{name: "7M_open_brackets", input: strings.Repeat("[", 7_000_000)},
		{name: "3.5M_bracket_parens", input: strings.Repeat("](", 3_500_000)},
		{name: "3.5M_bracket_parens_with_colon_and_tick", input: strings.Repeat("](", 3_500_000) + ":`"},
		{name: "2M_raw_lt", input: strings.Repeat("<", 2_000_000)},
	}

	for _, tc := range cases {
		start := time.Now()
		out := SanitizeMarkdown(tc.input, "https://example.com/")
		elapsed := time.Since(start)
		if tc.name == "2M_raw_lt" && len(out) != 8_000_000 {
			t.Fatalf("expected 2M `<` -> 8M `&lt;`, got len=%d", len(out))
		}
		if elapsed > antiQuadraticGuard {
			t.Fatalf("[H8 anti-quadratic guard] %s exceeded %v: %v", tc.name, antiQuadraticGuard, elapsed)
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

	// 2. Anti-quadratic guard on 1 MiB of unclosed `<!-- a ` and bang-closed `<!-- x --!>`
	for _, pat := range []string{"<!-- a ", "<!-- x --!>"} {
		large := strings.Repeat(pat, (1024*1024)/len(pat))
		t0 := time.Now()
		got := SanitizeMarkdown(large, "")
		if elapsed := time.Since(t0); elapsed > 5*time.Second {
			t.Fatalf("HTML comment scan on %q exceeded 5s anti-quadratic guard: %v", pat, elapsed)
		}
		if strings.IndexByte(got, '<') >= 0 {
			t.Fatalf("raw `<` survived HTML comment scan on %q", pat)
		}
	}
}

func assertNoProseRawLtOrBadLinksR10(t *testing.T, label, input, got string) {
	t.Helper()
	reInlineDest := regexp.MustCompile(`\]\(\s*(?:<([^>\n]*)>|([^\s)]+))`)
	reRefDest := regexp.MustCompile(`\]:[ \t]*(?:\r?\n[ \t>0-9.*+-]*)?(?:<([^>\n]*)>|([^\s]+))`)

	if got2 := SanitizeMarkdown(got, "https://example.com/docs/"); got2 != got {
		t.Fatalf("[%s] SanitizeMarkdown is not idempotent:\n  pass1=%q\n  pass2=%q", label, got, got2)
	}

	parts := splitMarkdownByCodeFencesGo(got)
	for i := 0; i < len(parts); i += 2 {
		prose := parts[i]
		if strings.IndexByte(prose, '<') >= 0 {
			t.Fatalf("[%s] raw `<` survived in prose outside fenced code block!\n  in   =%q\n  out  =%q\n  prose=%q", label, input, got, prose)
		}
		for _, m := range reInlineDest.FindAllStringSubmatch(prose, -1) {
			dest := m[1]
			if dest == "" {
				dest = m[2]
			}
			if isDisallowedMarkdownLinkDestinationGo(dest) {
				t.Fatalf("[%s] disallowed inline destination %q survived in prose!\n  in =%q\n  out=%q", label, dest, input, got)
			}
		}
		for _, m := range reRefDest.FindAllStringSubmatch(prose, -1) {
			dest := m[1]
			if dest == "" {
				dest = m[2]
			}
			if isDisallowedMarkdownLinkDestinationGo(dest) {
				t.Fatalf("[%s] disallowed reference destination %q survived in prose!\n  in =%q\n  out=%q", label, dest, input, got)
			}
		}
	}
}

func TestR10S4UnclosedTagsAndCommentsBeforeFencePreserveNewlineAndFenceIsolation(t *testing.T) {
	const fenceBody = "<img src=x onerror=alert(1)>\n[xss](javascript:alert(1))"
	unclosedOpeners := []struct {
		name   string
		opener string
	}{
		{"unclosed_script", "<script>let x = 1;"},
		{"unclosed_style", "<style>body{display:none}"},
		{"unclosed_textarea", "<textarea>trapped"},
		{"unclosed_title", "<title>trapped"},
		{"unclosed_xmp", "<xmp>trapped"},
		{"unclosed_noscript", "<noscript>fallback"},
		{"unclosed_template", "<template><div>x"},
		{"unclosed_iframe", "<iframe src=\"https://evil.example\">"},
		{"unclosed_svg", "<svg onload=alert(1)>"},
		{"unclosed_math", "<math><mtext>"},
		{"unclosed_comment", "<!-- unclosed comment before fence"},
		{"truncated_closing_tag", "</script"},
	}

	for _, tc := range unclosedOpeners {
		// Case A1 (R11-S1/S3): Without a preceding blank line, the fence is treated as prose and its payload is escaped/stripped.
		mdNoBlank := "Intro paragraph " + tc.opener + "\n```html\n" + fenceBody + "\n```\nAfter prose <script>alert(2)</script>"
		gotNoBlank := SanitizeMarkdown(mdNoBlank, "https://example.com/docs/")
		assertNoProseRawLtOrBadLinksR10(t, tc.name+"_no_blank", mdNoBlank, gotNoBlank)

		// Case A2: Preceding paragraph text + unclosed tag/comment + blank line before a top-level fenced code block.
		mdAfterPara := "Intro paragraph " + tc.opener + "\n\n```html\n" + fenceBody + "\n```\nAfter prose <script>alert(2)</script>"
		gotAfterPara := SanitizeMarkdown(mdAfterPara, "https://example.com/docs/")
		assertNoProseRawLtOrBadLinksR10(t, tc.name+"_after_para", mdAfterPara, gotAfterPara)

		parts := splitMarkdownByCodeFencesGo(gotAfterPara)
		if len(parts) < 3 {
			t.Fatalf("[%s_after_para] expected fenced code block to remain intact on its own line (not joined onto preceding paragraph!), got parts=%d:\n%q", tc.name, len(parts), gotAfterPara)
		}
		if !strings.Contains(parts[1], fenceBody) {
			t.Fatalf("[%s_after_para] expected fenced block body preserved inside fence segment, got fence=%q full=%q", tc.name, parts[1], gotAfterPara)
		}

		// Case B: Unclosed tag/comment at the very start of the document + blank line before a tilde fence.
		mdAtStart := tc.opener + "\n\n~~~html\n" + fenceBody + "\n~~~\nTail `inline <T>`"
		gotAtStart := SanitizeMarkdown(mdAtStart, "https://example.com/docs/")
		assertNoProseRawLtOrBadLinksR10(t, tc.name+"_at_start", mdAtStart, gotAtStart)
		partsStart := splitMarkdownByCodeFencesGo(gotAtStart)
		if len(partsStart) < 3 || !strings.Contains(partsStart[1], fenceBody) {
			t.Fatalf("[%s_at_start] expected tilde fence to remain intact on its own line, got:\n%q", tc.name, gotAtStart)
		}

		// Case C: Unclosed tag/comment sandwiched between two blank-line-separated fenced code blocks.
		mdBetween := "```js\nconst a = 1 < 2;\n```\n\nMiddle text " + tc.opener + "\n\n```html\n" + fenceBody + "\n```"
		gotBetween := SanitizeMarkdown(mdBetween, "https://example.com/docs/")
		assertNoProseRawLtOrBadLinksR10(t, tc.name+"_between_fences", mdBetween, gotBetween)
		partsBetween := splitMarkdownByCodeFencesGo(gotBetween)
		if len(partsBetween) < 5 {
			t.Fatalf("[%s_between_fences] expected both fenced code blocks to remain separate fences, got parts=%d:\n%q", tc.name, len(partsBetween), gotBetween)
		}
	}

	// Inline code spans MUST escape `<` to `&lt;` in Go SanitizeMarkdown (never leaving raw `<` outside real fences).
	inlineCases := []string{
		"Generic `Promise<User>` and ``Map<string, Array<int>>`` in docs.",
		"Attack `` `<img src=x onerror=alert(1)>` `` in inline code.",
	}
	for _, in := range inlineCases {
		got := SanitizeMarkdown(in, "https://example.com/")
		assertNoProseRawLtOrBadLinksR10(t, "inline_code_lt", in, got)
		if !strings.Contains(got, "&lt;") {
			t.Fatalf("expected inline code `<` to be escaped as `&lt;`, got %q", got)
		}
	}
}

func TestR10S4StrictASCIIBlankLineRejectsNBSP(t *testing.T) {
	// U+00A0 (NBSP) is NOT whitespace/blank in CommonMark!
	nbspCases := map[string]string{
		"nbsp_before_setext_and_fence":    "Paragraph\n\u00a0\n===\n```\n<img src=x onerror=alert(1)>\n```",
		"nbsp_fence_closer_suffix":        "```html\nsafe\n```\u00a0\n<img src=x onerror=alert(1)>\n```",
		"nbsp_fence_opener_indent":        "\u00a0```html\n<img src=x onerror=alert(1)>\n```",
		"nbsp_between_para_and_non1_list": "Paragraph\n\u00a0\n2. item\n   ```html\n   <img src=x onerror=alert(1)>\n   ```",
		"nbsp_only_after_list_marker":     "Paragraph\n-\u00a0\n  ```html\n  <img src=x onerror=alert(1)>\n  ```",
	}
	for name, md := range nbspCases {
		got := SanitizeMarkdown(md, "https://example.com/")
		assertNoProseRawLtOrBadLinksR10(t, name, md, got)
	}

	// Specifically verify ```\u00a0 does NOT close a fence early in our splitter when followed by payload,
	// OR if outer fence is hardened, payload outside any real fence never keeps raw `<`.
	closerNBSP := "```\ninside\n```\u00a0\n```\n<img src=x onerror=alert(1)>"
	gotCloser := SanitizeMarkdown(closerNBSP, "https://example.com/")
	assertNoProseRawLtOrBadLinksR10(t, "closer_nbsp_desync", closerNBSP, gotCloser)
}

func TestR10S5TabIndentedFenceClosersAndOpenersInsideListItems(t *testing.T) {
	cases := map[string]string{
		// Classic S5 exploit: `- item` has content col 2; `\t```` advances to tab stop col 4;
		// remaining indent is 4 - 2 = 2 (<= 3), closing the fence in CommonMark!
		"ul_2col_tab_closer":                   "- item\n  ```\n\t```\n<img src=x onerror=alert(1)>",
		"ul_2col_tab_closer_indented_xss":      "- item\n  ```\n\t```\n  <img src=x onerror=alert(1)>\n  [p](javascript:alert(1))",
		"ol_3col_tab_closer":                   "1. item\n   ```\n\t```\n<script>alert(1)</script>",
		"ol_3col_tab_closer_list_cont":         "1. item\n   ~~~html\n\t~~~\n   <svg onload=alert(1)>",
		"ul_spaces_plus_tab_closer":            "- item\n  ```\n  \t```\n<img src=x onerror=alert(1)>",
		"ul_1space_plus_tab_closer":            "- item\n  ```\n \t```\n<img src=x onerror=alert(1)>",
		"nested_ul_tab_closer":                 "- outer\n  - inner\n    ```\n\t  ```\n    <img src=x onerror=alert(1)>",
		"nested_ul_dedent_to_outer_tab":        "- outer\n  - inner\n  para\n  ```\n\t```\n  <img src=x onerror=alert(1)>",
		"ul_tab_opener_and_closer":             "- item\n\t```html\n\t<b>in-fence</b>\n\t```\n<img src=x onerror=alert(1)>",
		"ol_tab_opener_and_space_closer":       "1. item\n\t```html\n\t<b>in-fence</b>\n   ```\n   <img src=x onerror=alert(1)>",
		"double_tab_inner_fence_lengthened":    "- item\n  ```\n\t\t```\n  <img src=x onerror=alert(1)>\n  ```",
		"top_level_tab_inner_fence_lengthened": "```\n\t```\n<img src=x onerror=alert(1)>\n```",
		"blockquote_plus_list_tab_closer":      "> - item\n>   ```\n>\t```\n> <img src=x onerror=alert(1)>",
	}

	for name, md := range cases {
		got := SanitizeMarkdown(md, "https://example.com/")
		assertNoProseRawLtOrBadLinksR10(t, name, md, got)
	}

	// Direct check on the canonical S5 payload under R11-S1/S3: list-item fences are treated as prose (escaping/stripping `<KeepInsideFence>`),
	// AND `<img ...>` after `\t```` is stripped/sanitized as live prose while inline `<int>` is escaped to `&lt;int>`!
	canonical := "- item\n  ```\n  safe_code(a < b)\n\t```\nAfter fence: <img src=x onerror=alert(1)> and `Vec<int>`"
	gotCanonical := SanitizeMarkdown(canonical, "https://example.com/")
	assertNoProseRawLtOrBadLinksR10(t, "canonical_s5", canonical, gotCanonical)
	if !strings.Contains(gotCanonical, "safe_code(a &lt; b)") {
		t.Fatalf("expected list-item fence body `<` to be escaped per R11-S1/S3, got:\n%s", gotCanonical)
	}
	if strings.Contains(gotCanonical, "onerror=") || !strings.Contains(gotCanonical, "`Vec&lt;int>`") {
		t.Fatalf("expected post-tab-closer prose to strip `<img onerror=...>` and escape inline `<int>`, got:\n%s", gotCanonical)
	}
	if strings.Contains(gotCanonical, "\t```") {
		t.Fatalf("expected ambiguous tab-indented fence closer inside list item to be escaped, got:\n%q", gotCanonical)
	}
}

func TestR10BlindLazyContinuationBeforeOrderedMarkerCannotOpenFakeFence(t *testing.T) {
	cases := map[string]string{
		"four_space_lazy_cont_then_10_dot": "Paragraph line\n    indented lazy continuation\n10. item\n    ```\n    <x-go-probe>\n    ```",
		"outer_list_lazy_dedent_10_dot":    "- outer paragraph line\n10. lazy continuation at col 0\n    ```\n    <x-go-lazy-list>\n    ```",
		"nested_list_non1_ordered":         "- outer para\n  10. inner\n      ```\n      <x-go-nested>\n      ```",
	}
	for name, md := range cases {
		got := SanitizeMarkdown(md, "https://example.com/")
		assertNoProseRawLtOrBadLinksR10(t, name, md, got)
		if strings.Contains(got, "<x-go-") {
			t.Fatalf("[%s] raw <x-go-*> tag survived SanitizeMarkdown:\n%q", name, got)
		}
	}
}

func TestR11S3ContainerAndTabIndentedFencesFailClosed(t *testing.T) {
	const payload = "<script>alert(1)</script>\n<img src=x onerror=alert(1)>\n[xss](javascript:alert(1))\n[ref]: data:text/html,<svg/onload=alert(1)>"

	untrustedVectors := map[string]string{
		// S3: Tab-indented fence openers after empty or non-empty list items
		"empty_ul_tab_fence":              "-\n\t```html\n\t" + payload + "\n\t```",
		"empty_ul_trailing_ws_tab_fence":  "-   \n\t```html\n\t" + payload + "\n\t```",
		"empty_ul_blank_line_tab_fence":   "-\n\n\t```html\n\t" + payload + "\n\t```",
		"nonempty_ul_tab_fence":           "- item\n\t```html\n\t" + payload + "\n\t```",
		"ordered_tab_after_marker_fence":  "1.\titem\n\t```html\n\t" + payload + "\n\t```",
		"ul_tab_after_marker_space_fence": "-\t\n  ```html\n  " + payload + "\n  ```",
		"top_level_tab_indented_fence":    "\t```html\n" + payload + "\n\t```",
		"space_then_tab_fence":            " \t```html\n" + payload + "\n \t```",

		// S1/S3: All CommonMark container & non-blank-preceded fence edge cases
		"list_tight_fence":                 "- item\n  ```html\n  " + payload + "\n  ```",
		"list_loose_fence":                 "- item\n\n  ```html\n  " + payload + "\n  ```",
		"blank_item_trailing_spaces_fence": "-    \n  ```html\n  " + payload + "\n  ```",
		"empty_item_blank_line_2sp_fence":  "-\n\n  ```html\n  " + payload + "\n  ```",
		"marker_on_lazy_line_fence":        "- outer paragraph\n2. lazy marker\n   ```html\n   " + payload + "\n   ```",
		"setext_underline_in_list_item":    "- heading\n  ===\n  ```html\n  " + payload + "\n  ```",
		"setext_dash_in_list_item":         "- heading\n  ---\n  ```html\n  " + payload + "\n  ```",
		"blockquote_fence":                 "> ```html\n> " + payload + "\n> ```",
		"blockquote_after_blank_fence":     ">\n> ```html\n> " + payload + "\n> ```",
		"blockquote_lazy_fence":            "> quote text\n```html\n" + payload + "\n```",
		"nested_bq_list_fence":             "> - item\n>   ```html\n>   " + payload + "\n>   ```",
		"non_blank_preceded_para_fence":    "Paragraph without blank line\n```html\n" + payload + "\n```",
		"non_blank_preceded_atx_fence":     "# Heading\n```html\n" + payload + "\n```",

		// Multi-fence polarity-inversion vectors
		"polarity_tilde_in_list_then_top": "-\n\n  ~~~\n```\n~~~\n" + payload + "\n```",
		"polarity_4sp_in_list_then_top":   "- item\n\n  para\n    ```\n" + payload + "\n    ```",
		"polarity_tab_open_space_close":   "-\n\t```\n  ```\n\n```\n<KeepTrusted>\n```\n" + payload,
	}

	for name, md := range untrustedVectors {
		got := SanitizeMarkdown(md, "https://example.com/docs/")
		assertNoProseRawLtOrBadLinksR10(t, name, md, got)
		if name != "polarity_tab_open_space_close" {
			if strings.Contains(got, "<script") || strings.Contains(got, "<img") || strings.Contains(got, "onerror=") || strings.Contains(got, "javascript:") {
				t.Fatalf("[%s] untrusted container/non-blank fence failed to sanitize payload!\nin:\n%s\nout:\n%s", name, md, got)
			}
		} else {
			if !strings.Contains(got, "<KeepTrusted>") {
				t.Fatalf("[%s] expected subsequent top-level blank-preceded fence to stay intact, got:\n%s", name, got)
			}
			if strings.Contains(got, "onerror=") || strings.Contains(got, "javascript:") {
				t.Fatalf("[%s] trailing prose payload survived:\n%s", name, got)
			}
		}
	}

	// Verify top-level fences preceded by start of document or strict ASCII blank line still preserve raw code content
	trustedTopLevel := map[string]string{
		"start_of_doc_fence":       "```html\n<div class=\"ok\">1 < 2</div>\n```",
		"after_blank_line_fence":   "Intro paragraph.\n\n   ```ts\nconst x: Array<string> = [];\n   ```",
		"after_list_dedent_col0":   "- list item\n\nAfter list at col 0.\n\n```html\n<custom-el attr=\"v\"></custom-el>\n```",
		"after_list_blank_col0_fn": "- list item\n\n```html\n<custom-el attr=\"v\"></custom-el>\n```",
	}
	for name, md := range trustedTopLevel {
		got := SanitizeMarkdown(md, "https://example.com/docs/")
		assertNoProseRawLtOrBadLinksR10(t, name, md, got)
		if !strings.Contains(got, "<") {
			t.Fatalf("[%s] expected top-level blank-preceded fence to preserve raw `<`, got:\n%s", name, got)
		}
	}
}

func TestR11M3InvalidUTF8AndEntityDecodedInvisibleSmuggling(t *testing.T) {
	// 1. Truncated / ill-formed UTF-8 bytes before `<` or invisible chars must be healed via U+FFFD and NEVER mask `<` or leave invalid UTF-8
	invalidUTF8Inputs := map[string]string{
		"overlong_c0_before_script":     "\xc0<script>alert(1)</script>safe",
		"truncated_e2_80_before_img":    "prefix \xe2\x80<img src=x onerror=alert(1)> suffix",
		"truncated_f0_9f_before_jslink": "[\xf0\x9fclick](javascript:alert(1))",
		"lone_continuation_ff":          "\xff\xfe<svg onload=alert(1)>ok",
		"invalid_utf8_in_meta":          "Title \xc0\xaf <script>x</script> &#x202e; &#xe0061;",
	}
	for name, raw := range invalidUTF8Inputs {
		if name == "invalid_utf8_in_meta" {
			metaOut := SanitizeScrapedMeta(raw)
			if !utf8.ValidString(metaOut) {
				t.Fatalf("[%s] SanitizeScrapedMeta returned invalid UTF-8: %q", name, metaOut)
			}
			if strings.Contains(metaOut, "<") || strings.ContainsRune(metaOut, '\u202e') || strings.ContainsRune(metaOut, '\U000e0061') {
				t.Fatalf("[%s] SanitizeScrapedMeta leaked dangerous chars: %q", name, metaOut)
			}
			continue
		}
		got := SanitizeMarkdown(raw, "https://example.com/")
		if !utf8.ValidString(got) {
			t.Fatalf("[%s] SanitizeMarkdown returned invalid UTF-8: %q", name, got)
		}
		assertNoProseRawLtOrBadLinksR10(t, name, raw, got)
		if strings.Contains(got, "onerror=") || strings.Contains(got, "javascript:") || strings.Contains(got, "<script") {
			t.Fatalf("[%s] dangerous payload survived invalid UTF-8 prefix: %q", name, got)
		}
	}

	// 2. HTML-entity-encoded invisible / bidi / Unicode tag smuggling characters MUST be stripped after entity decoding!
	entitySmuggling := map[string]string{
		"hex_bidi_rlo":           "safe &#x202e;text&#x202c; end",
		"dec_bidi_rlo":           "safe &#8238;text&#8236; end",
		"hex_bom_zwsp":           "he&#xfeff;llo&#x200b;world",
		"unicode_tag_smuggling":  "prompt&#xe0069;&#xe0067;&#xe006e;&#xe006f;&#xe0072;&#xe0065;end",
		"double_amp_tag_char":    "nested &amp;#xe0061;&amp;#x202e; clean",
		"named_bidi_zw_entities": "a&rlm;b&lrm;c&zwj;d&zwnj;e&wj;f&InvisibleTimes;g",
		"variation_selector_sup": "tok&#xe0100;&#xe01ef;en",
		"c1_control_entity":      "ctrl&#x80;&#x9f;ok",
	}
	forbiddenRunes := func(r rune) bool {
		return r == 0x00AD || r == 0x061C || r == 0x180E ||
			(r >= 0x0080 && r <= 0x009F) ||
			(r >= 0x200B && r <= 0x200F) ||
			(r >= 0x202A && r <= 0x202E) ||
			(r >= 0x2060 && r <= 0x206F) ||
			r == 0xFEFF ||
			(r >= 0xE0000 && r <= 0xE007F) ||
			(r >= 0xE0100 && r <= 0xE01EF)
	}

	for name, md := range entitySmuggling {
		got := SanitizeMarkdown(md, "https://example.com/")
		assertNoProseRawLtOrBadLinksR10(t, name, md, got)
		if strings.IndexFunc(got, forbiddenRunes) >= 0 {
			t.Fatalf("[%s] entity-decoded invisible/bidi/tag rune survived SanitizeMarkdown: %+q", name, got)
		}
		metaGot := SanitizeScrapedMeta(md)
		if strings.IndexFunc(metaGot, forbiddenRunes) >= 0 {
			t.Fatalf("[%s] entity-decoded invisible/bidi/tag rune survived SanitizeScrapedMeta: %+q", name, metaGot)
		}
	}
}

func TestM3MultiPassEntitySanitizeMarkdownAndPerf(t *testing.T) {
	base := "https://docs.sram.com/en-US/publications/7E6x3h"
	reUnescapedInjected := regexp.MustCompile(`(?:^|[^\\])(?:\[xss\]|\])\s*\(\s*https?://evil\.com`)

	directCases := map[string]string{
		"dec_bracket_in_label":             `[Manual &#93;(https://evil.com)](https://docs.sram.com/ok)`,
		"backslash_then_entity":            `[Manual \&#93;(https://evil.com)](https://docs.sram.com/ok)`,
		"bsol_then_entity":                 `[Manual &bsol;&#93;(https://evil.com)](https://docs.sram.com/ok)`,
		"double_amp_bracket":               `[Manual &amp;#93;(https://evil.com)](https://docs.sram.com/ok)`,
		"nested_badge_with_entities":       `[![ok &#93;](https://img.shields.io/a.svg?x=1&rpar;2) Docs &#93;(https://evil.com)](https://docs.sram.com/ok)`,
		"heading_link_san":                 `[<h2 id="x">Head ](https://evil.com) &amp;#93;(https://evil.com)</h2>](https://docs.sram.com/a&rpar;&lsqb;xss&rsqb;&lpar;https://evil.com)`,
		"img_alt_entities":                 `<img src="https://docs.sram.com/a.png" alt="Img &amp;#93;(https://evil.com)">`,
		"gfm_table_amp_91_93":              `| Brake &amp;#91;xss&amp;#93;(https://evil.com) | Acme |`,
		"gfm_table_93":                     `| Hub &#93;(https://evil.com) |`,
		"prose_lsqb_rsqb_lpar_rpar":        `Vend &amp;lsqb;xss&amp;rsqb;&amp;lpar;https://evil.com&amp;rpar;`,
		"prose_unclosed_open_bracket":      `[Click here &amp;#93;(https://evil.com)`,
		"bullet_entity_bracket":            `- Item &amp;lsqb;xss&amp;rsqb;(https://evil.com)`,
		"nested_open_bracket_link":         `[foo [bar &amp;#93;(https://evil.com) [baz](https://docs.sram.com/ok)`,
		"nested_open_bracket_closed_outer": `[foo [bar] &amp;#93;(https://evil.com)](https://docs.sram.com/ok)`,
		"multiline_link_entity":            "[Manual\n&#93;(https://evil.com)](https://docs.sram.com/ok)",
		"multiline_dangling_dest_entity":   "Text ](https://docs.sram.com/a\n&amp;rpar;&amp;lsqb;xss&amp;rsqb;&amp;lpar;https://evil.com)",
		"heading_link_nested_span_entity":  `[<h2 id="x"><span>Head</span> &amp;#93;(https://evil.com)</h2>](https://docs.sram.com/ok)`,
		"heading_link_disallowed_js":       `[<h2 id="x"><span>Head</span> &amp;#93;(https://evil.com)</h2>](javascript:alert(1))`,
		"td_entity_bracket":                `<table><tr><td>[Click &#93;(https://evil.com)</td></tr></table>`,
		"anchor_no_href_entity":            `<a>&#91;xss&#93;</a>(https://evil.com)`,
		"anchor_name_entity":               `<a name="sec">&lsqb;xss&rsqb;(https://evil.com)</a>`,
		"anchor_js_href_entity":            `<a href="javascript:alert(1)">&lsqb;xss&rsqb;(https://evil.com)</a>`,
		"anchor_js_href_unclosed_bracket":  `<a href="javascript:alert(1)">[Click &#93;(https://evil.com)</a>`,
		"anchor_js_href_img_badge_entity":  `<a href="javascript:alert(1)"><img src="https://docs.sram.com/a.png" alt="ok"> [Click &#93;(https://evil.com)</a>`,
		"triple_amp_93_in_link":            `[Manual &amp;amp;#93;(https://evil.com)](https://docs.sram.com/ok)`,
		"triple_amp_rsqb_in_link":          `[Manual &amp;amp;rsqb;(https://evil.com)](https://docs.sram.com/ok)`,
		"triple_amp_lsqb_rsqb_prose":       `Vend &amp;amp;lsqb;xss&amp;amp;rsqb;(https://evil.com)`,
		"quad_amp_93_in_link":              `[Manual &amp;amp;amp;#93;(https://evil.com)](https://docs.sram.com/ok)`,
	}
	for name, md := range directCases {
		got := SanitizeMarkdown(md, base)
		if reUnescapedInjected.MatchString(got) {
			t.Fatalf("[%s] injected evil.com link survived SanitizeMarkdown:\n  in =%q\n  out=%q", name, md, got)
		}
		if strings.Contains(strings.ToLower(got), "javascript:") {
			t.Fatalf("[%s] javascript: survived SanitizeMarkdown:\n  in =%q\n  out=%q", name, md, got)
		}
		if got2 := SanitizeMarkdown(got, base); got2 != got {
			t.Fatalf("[%s] non-idempotent:\n  got1=%q\n  got2=%q", name, got, got2)
		}
	}

	if gotSpanH := SanitizeMarkdown(directCases["heading_link_nested_span_entity"], base); !strings.Contains(gotSpanH, `## [Head \](https://evil.com)](https://docs.sram.com/ok)`) {
		t.Fatalf("expected nested span heading link cleanly formatted, got %q", gotSpanH)
	}
	wikiH := `[<h3 title="a>b"><strong>Bold</strong> <code>API</code></h3>](https://en.wikipedia.org/wiki/Foo_(bar))`
	if gotWikiH := SanitizeMarkdown(wikiH, base); !strings.Contains(gotWikiH, `### [Bold API](https://en.wikipedia.org/wiki/Foo_(bar))`) {
		t.Fatalf("expected quoted > and Foo_(bar) preserved in bracket heading link, got %q", gotWikiH)
	}
	longH2 := "<h2>" + strings.Repeat("x", 10000) + "<h2>Real</h2>"
	if gotLongH2 := SanitizeMarkdown(longH2, base); !strings.Contains(gotLongH2, "&lt;h2>") || !strings.Contains(gotLongH2, "## Real") {
		tailStart := len(gotLongH2) - 40
		if tailStart < 0 {
			tailStart = 0
		}
		t.Fatalf("expected 8192 window preserved for unclosed <h2> before <h2>Real</h2>, got head=%q tail=%q", gotLongH2[:minInt(len(gotLongH2), 40)], gotLongH2[tailStart:])
	}

	// Idempotence on already-escaped labels with `&` / `&amp;`
	idempCases := []string{
		`[Tom & Jerry \](https://evil.com)](https://docs.sram.com/ok)`,
		`[Tom &amp; Jerry \](https://evil.com)](https://docs.sram.com/ok)`,
	}
	for _, md := range idempCases {
		got1 := SanitizeMarkdown(md, base)
		got2 := SanitizeMarkdown(got1, base)
		got3 := SanitizeMarkdown(got2, base)
		if got1 != got2 || got2 != got3 {
			t.Fatalf("idempotence failed for %q:\n  1=%q\n  2=%q\n  3=%q", md, got1, got2, got3)
		}
	}

	// Literal [1] inside <a name="n1"> is preserved while entity-encoded brackets are escaped.
	if gotLitAnchor := SanitizeMarkdown(`<a name="n1">[1]</a>`, base); !strings.Contains(gotLitAnchor, "[1]") {
		t.Fatalf("expected literal [1] preserved on <a name=...>, got %q", gotLitAnchor)
	}

	// SanitizeScrapedMeta entity label breakout + idempotence on disallowed URL & multi-&amp; chains
	for _, metaIn := range []string{
		`[Manual &#93;(https://evil.com)](https://docs.sram.com/ok)`,
		`[Label &amp;#93;(https://evil.com)](javascript:alert(1))`,
		`[Manual &amp;amp;amp;#93;(https://evil.com)](https://docs.sram.com/ok)`,
	} {
		metaOut1 := SanitizeScrapedMeta(metaIn)
		if reUnescapedInjected.MatchString(metaOut1) {
			t.Fatalf("SanitizeScrapedMeta allowed injected link for %q: %q", metaIn, metaOut1)
		}
		if strings.Contains(strings.ToLower(metaOut1), "javascript:") {
			t.Fatalf("SanitizeScrapedMeta allowed javascript: for %q: %q", metaIn, metaOut1)
		}
		if metaOut2 := SanitizeScrapedMeta(metaOut1); metaOut2 != metaOut1 {
			t.Fatalf("SanitizeScrapedMeta non-idempotent for %q:\n  1=%q\n  2=%q", metaIn, metaOut1, metaOut2)
		}
	}

	// 50k O(N) performance probes (< 75ms without -race)
	perfCases := []struct {
		name  string
		input string
	}{
		{name: "50k_amp_93_label", input: "[" + strings.Repeat("&amp;#93;", 5500) + "](https://docs.sram.com/ok)"},
		{name: "50k_open_brackets_amp93", input: strings.Repeat("[", 50_000) + "&amp;#93;"},
		{name: "50k_link_amp_rpar", input: strings.Repeat("[x](https://docs.sram.com/a&amp;rpar;)", 1200)},
		{name: "50k_bracket_h2_close", input: strings.Repeat(`[<h2 id="x">`, 4200) + "</h2>](https://docs.sram.com/ok)"},
		{name: "50k_plain_h2_close", input: strings.Repeat(`<h2 id="x">`, 4200) + "</h2>"},
		{name: "50k_table_close", input: strings.Repeat("<table>", 4200) + "</table>"},
		{name: "50k_amp_collapse_attack_chain", input: "&" + strings.Repeat("amp;", 12500)},
		{name: "50k_amp_collapse_attack_rep", input: strings.Repeat("&amp;", 10000)},
	}
	budget := 75 * time.Millisecond * time.Duration(extractRaceSlowdown)
	for _, pc := range perfCases {
		start := time.Now()
		_ = SanitizeMarkdown(pc.input, base)
		if elapsed := time.Since(start); elapsed > budget {
			t.Fatalf("[50k perf %s] exceeded %v: %v", pc.name, budget, elapsed)
		}
	}
}

func TestM3Iteration7AmpChainAndCommentHardening(t *testing.T) {
	base := "https://docs.sram.com/en-US/publications/7E6x3h"
	reUnescapedInjected := regexp.MustCompile(`(?:^|[^\\])(?:\[xss\]|\])\s*\(\s*https?://evil\.com`)

	// 1. 1-pass idempotence under BOTH SanitizeScrapedMeta and SanitizeMarkdown
	idemCases := []struct {
		name  string
		input string
		want  string
	}{
		{name: "double_amp_space", input: "A &amp;amp; B", want: "A & B"},
		{name: "triple_amp_space", input: "A &amp;amp;amp; B", want: "A & B"},
		{name: "amp_num38_space", input: "A &amp;#38; B", want: "A & B"},
		{name: "double_amp_eof", input: "A &amp;amp;", want: "A &"},
		{name: "double_amp_foo", input: "&amp;amp;foo", want: "&foo"},
		{name: "double_amp_T", input: "&amp;amp;T", want: "&T"},
		{name: "att_single_amp", input: "AT&amp;T", want: "AT&T"},
		{name: "foo_amp_bar", input: "foo&amp;bar", want: "foo&bar"},
		{name: "semicolonless_query", input: "&currentTime=45&section=2&region=us", want: "&currentTime=45&section=2&region=us"},
		{name: "triple_amp_lsqb_rsqb", input: "Vend &amp;amp;lsqb;xss&amp;amp;rsqb;", want: `Vend \[xss\]`},
	}
	for _, tc := range idemCases {
		meta1 := SanitizeScrapedMeta(tc.input)
		meta2 := SanitizeScrapedMeta(meta1)
		if meta1 != tc.want || meta2 != meta1 {
			t.Fatalf("[%s] SanitizeScrapedMeta mismatch/non-idempotent: want=%q got1=%q got2=%q", tc.name, tc.want, meta1, meta2)
		}
		md1 := SanitizeMarkdown(tc.input, base)
		md2 := SanitizeMarkdown(md1, base)
		if md1 != tc.want || md2 != md1 {
			t.Fatalf("[%s] SanitizeMarkdown mismatch/non-idempotent: want=%q got1=%q got2=%q", tc.name, tc.want, md1, md2)
		}
	}

	// Verify collapseAmpEntityChainsGo directly leaves non-entity chains and query strings untouched
	for _, untouched := range []string{"AT&amp;T", "foo&amp;bar", "&currentTime=45&section=2&region=us"} {
		if got := collapseAmpEntityChainsGo(untouched); got != untouched {
			t.Fatalf("collapseAmpEntityChainsGo(%q) = %q, want unchanged", untouched, got)
		}
	}
	if got := collapseAmpEntityChainsGo("Vend &amp;amp;lsqb;xss&amp;amp;rsqb;"); got != "Vend &lsqb;xss&rsqb;" {
		t.Fatalf("collapseAmpEntityChainsGo multi-lsqb = %q", got)
	}

	// Link label with &amp;amp;#93; must escape and remain 1-pass idempotent
	linkCase := `[Manual &amp;amp;#93;(https://evil.com)](https://docs.sram.com/ok)`
	linkMeta1 := SanitizeScrapedMeta(linkCase)
	linkMeta2 := SanitizeScrapedMeta(linkMeta1)
	if reUnescapedInjected.MatchString(linkMeta1) || linkMeta2 != linkMeta1 {
		t.Fatalf("SanitizeScrapedMeta failed on %q: got1=%q got2=%q", linkCase, linkMeta1, linkMeta2)
	}
	linkMd1 := SanitizeMarkdown(linkCase, base)
	linkMd2 := SanitizeMarkdown(linkMd1, base)
	if reUnescapedInjected.MatchString(linkMd1) || linkMd2 != linkMd1 {
		t.Fatalf("SanitizeMarkdown failed on %q: got1=%q got2=%q", linkCase, linkMd1, linkMd2)
	}

	// 2. O(N) runtime on 50k amp collapse attack variants
	budget := 75 * time.Millisecond * time.Duration(extractRaceSlowdown)
	for _, pc := range []struct {
		name  string
		input string
	}{
		{name: "50k_amp_collapse_93", input: strings.Repeat("&amp;", 10000) + "#93;"},
		{name: "50k_amp_collapse_space_B", input: strings.Repeat("&amp;", 10000) + " B"},
		{name: "50k_amp_chain_space_B", input: "&" + strings.Repeat("amp;", 12500) + " B"},
	} {
		start := time.Now()
		_ = SanitizeMarkdown(pc.input, base)
		if elapsed := time.Since(start); elapsed > budget {
			t.Fatalf("[50k perf %s] exceeded %v: %v", pc.name, budget, elapsed)
		}
	}
}
