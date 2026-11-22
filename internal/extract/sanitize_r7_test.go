package extract

import (
	"bufio"
	"encoding/json"
	"html"
	"os"
	"regexp"
	"strings"
	"testing"
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

	// Ensure legitimate code generics and fenced code blocks remain intact!
	if got := SanitizeScrapedMarkdown("Returns `Promise<void>` over HTTP/2."); !strings.Contains(got, "`Promise<void>`") {
		t.Fatalf("expected `Promise<void>` preserved in inline code span, got %q", got)
	}
	if got := SanitizeScrapedMarkdown("```html\n<script>const ok = true;</script>\n```"); !strings.Contains(got, "<script>const ok = true;</script>") {
		t.Fatalf("expected fenced code block contents preserved verbatim, got %q", got)
	}
	if got := SanitizeScrapedMarkdown("| Col | Type |\n|---|---|\n| ret | `Promise<void>` |"); !strings.Contains(got, "`Promise<void>`") {
		t.Fatalf("expected single-cell table code span `Promise<void>` preserved, got %q", got)
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
