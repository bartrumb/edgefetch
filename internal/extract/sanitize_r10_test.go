package extract

import (
	"regexp"
	"strings"
	"testing"
)

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
