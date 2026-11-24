package extract

import (
	"strings"
	"testing"
	"unicode/utf8"
)

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
