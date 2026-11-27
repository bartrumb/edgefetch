package extract

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

const maxMarkdownCSVRowsFmtGo = 1000

// FormattedPayloadDoc holds the formatted Markdown, extracted title/description metadata,
// and optional parsed structured representation of a non-HTML payload (JSON, OpenAPI, Jupyter, vCard, iCalendar, Feed, CSV, Patch, Source).
type FormattedPayloadDoc struct {
	Title       string `json:"title,omitempty"`
	Description string `json:"description,omitempty"`
	Markdown    string `json:"markdown"`
	Structured  any    `json:"structured,omitempty"`
}

// YouTubeWatchMeta holds structured video metadata and synthesized Markdown extracted from a YouTube watch page's `ytInitialPlayerResponse`.
type YouTubeWatchMeta struct {
	VideoID       string `json:"videoId,omitempty"`
	Title         string `json:"title"`
	Author        string `json:"author,omitempty"`
	Description   string `json:"description,omitempty"`
	Duration      string `json:"duration,omitempty"`
	LengthSeconds int    `json:"lengthSeconds,omitempty"`
	ViewCount     int64  `json:"viewCount,omitempty"`
	URL           string `json:"url,omitempty"`
	Markdown      string `json:"markdown"`
}

var (
	inertiaSkipPropKeysFmtGo = map[string]bool{
		"errors":       true,
		"flash":        true,
		"ziggy":        true,
		"csrf_token":   true,
		"_token":       true,
		"jetstream":    true,
		"locale":       true,
		"locales":      true,
		"translations": true,
		"__inertia":    true,
	}

	rawSourceExtLangMapFmtGo = map[string]string{
		"toml":    "toml",
		"yaml":    "yaml",
		"yml":     "yaml",
		"rs":      "rust",
		"go":      "go",
		"py":      "python",
		"ts":      "ts",
		"tsx":     "tsx",
		"js":      "js",
		"jsx":     "jsx",
		"mjs":     "js",
		"cjs":     "js",
		"rb":      "ruby",
		"java":    "java",
		"kt":      "kotlin",
		"swift":   "swift",
		"c":       "c",
		"h":       "c",
		"cpp":     "cpp",
		"hpp":     "cpp",
		"cs":      "csharp",
		"php":     "php",
		"sh":      "bash",
		"bash":    "bash",
		"zsh":     "zsh",
		"ps1":     "powershell",
		"sql":     "sql",
		"proto":   "protobuf",
		"graphql": "graphql",
		"gql":     "graphql",
		"lua":     "lua",
		"zig":     "zig",
		"tf":      "hcl",
		"hcl":     "hcl",
		"nix":     "nix",
		"prisma":  "prisma",
		"css":     "css",
		"scss":    "scss",
	}

	reRichHTMLTagFmtGo           = newLazyRegexp(`(?i)<(?:p|div|ul|ol|li|h[1-6]|section|article|br|strong|em|a|table|blockquote)\b`)
	reHTMLDocPrefixFmtGo         = newLazyRegexp(`(?i)^\s*<!doctype\s+html|^\s*<html`)
	reQuickHTMLDetectFmtGo       = newLazyRegexp(`(?i)^\s*<!doctype\s+html|^\s*<html|<(?:head|body|main|article)\b`)
	reBeginVCardFmtGo            = newLazyRegexp(`(?im)^BEGIN:VCARD\b`)
	reBeginVCalendarFmtGo        = newLazyRegexp(`(?im)^BEGIN:VCALENDAR\b`)
	reIcsDateFmtGo               = newLazyRegexp(`^(\d{4})(\d{2})(\d{2})(?:T(\d{2})(\d{2})(\d{2})(Z)?)?$`)
	reIcsEscapeFmtGo             = newLazyRegexp(`\\([,;\\])`)
	reIcsNewlineFmtGo            = newLazyRegexp(`(?i)\\n`)
	reUnfoldLinesFmtGo           = newLazyRegexp(`\r?\n[ \t]`)
	rePatchURLFmtGo              = newLazyRegexp(`(?i)\.(?:patch|diff)(?:$|[?#])`)
	reFormatPatchFromFmtGo       = newLazyRegexp(`(?m)^From ([0-9a-f]{40})\b`)
	reFormatPatchSubjFmtGo       = newLazyRegexp(`(?m)^Subject:`)
	reDiffGitLineFmtGo           = newLazyRegexp(`(?m)^diff --git `)
	reDiffGitAPrefixFmtGo        = newLazyRegexp(`(?m)^diff --git a/`)
	reUnifiedMinusFmtGo          = newLazyRegexp(`(?m)^---\s+\S+`)
	reUnifiedPlusFmtGo           = newLazyRegexp(`(?m)^\+\+\+\s+\S+`)
	reUnifiedHunkFmtGo           = newLazyRegexp(`(?m)^@@\s+-`)
	rePatchPrefixBracketFmtGo    = newLazyRegexp(`(?i)^(?:\[PATCH[^\]]*\]\s*)+`)
	rePatchStatSeparatorFmtGo    = newLazyRegexp(`(?s)(?:^|\n)---\n.*$`)
	reHexShaFmtGo                = newLazyRegexp(`(?i)^[0-9a-f]{7,40}$`)
	reTomlNameFmtGo              = newLazyRegexp(`(?m)^\s*name\s*=\s*["']([^"'\r\n]+)["']`)
	reTomlVersionFmtGo           = newLazyRegexp(`(?m)^\s*version\s*=\s*["']([^"'\r\n]+)["']`)
	reTomlDescFmtGo              = newLazyRegexp(`(?ms)^\s*description\s*=\s*(?:"""(.*?)"""|'''(.*?)'''|["']([^"'\r\n]+)["'])`)
	reFeedHTMLBlockFmtGo         = newLazyRegexp(`(?i)<(?:p|div|h[1-6]|ul|ol|li|a|pre|blockquote|br|table)\b`)
	reBinaryAppMimeFmtGo         = newLazyRegexp(`(?i)^application/(?:x-)?(?:gzip|tar|gtar|zip|bzip2|xz|zstd|7z-compressed|rar|rar-compressed|octet-stream|wasm|java-archive|x-msdownload|x-executable|x-apple-diskimage|msword|vnd\.ms-|vnd\.openxmlformats)`)
	reBinaryURLExtFmtGo          = newLazyRegexp(`(?i)\.(?:tar\.gz|tgz|gz|zip|7z|rar|bz2|xz|zst|wasm|exe|dll|dmg|iso|bin|whl|jar|png|jpe?g|gif|webp|avif|mp3|mp4|wav|ogg|webm|mov|woff2?|ttf|otf)$`)
	reFigureSizePlainFmtGo       = newLazyRegexp(`^<Figure size .*>$`)
	reTranscriptCuesFmtGo        = newLazyRegexp(`(?i)\[(?:music|applause|laughter)\]`)
	reBoilerplateSchemaItemFmtGo = newLazyRegexp(`(?i)^(?:see full compatibility|learn more|specifications?|browser compatibility|see also|help improve mdn|report a problem(?: with this content)?|view on github|edit this page|skip to (?:main content|search|select language)|table of contents|in this article|on this page|back to top|read more|cookie preferences|privacy policy|terms of (?:use|service))$`)
	reEntityPropNameFmtGo        = newLazyRegexp(`(?i)^(?:headername|directivename|packagename|modulename|libraryname|apiname|methodname|functionname|classname|interfacename|elementname|tagname|propertyname|attributename|eventname|commandname|toolname|productname|topic|subject)$`)
	reHeaderTokenFmtGo           = newLazyRegexp(`^([A-Za-z][A-Za-z0-9-]+)(?:\b|\s|$)`)
	reTitleSplitSepFmtGo         = newLazyRegexp(`\s+(?:[-–—|:]|·)\s+`)
	reProseBlockSkipFmtGo        = newLazyRegexp(`^(?:#{1,6}\s|>|\||[-*]\s|\d+\.\s|!\[)`)
	reMdH2H3FmtGo                = newLazyRegexp(`(?m)^#{2,3}[ \t]+(.+)$`)
	reCamelSplitFmtGo            = newLazyRegexp(`([a-z0-9])([A-Z])`)
	reSubHeading34FmtGo          = newLazyRegexp(`^#{3,4}[ \t]+(.+)$`)
	reSkipSubHeadingFmtGo        = newLazyRegexp(`(?i)\b(?:directives?|examples?|syntax|specifications?|compatibility)\b`)
	reDtBoldLineFmtGo            = newLazyRegexp("^\\*\\*(?:`([^`\\n]+)`|([^*:\\n]{2,80}))\\*\\*$")
	reBulletOrNumLineFmtGo       = newLazyRegexp(`^(?:[-*]|\d+\.)[ \t]+(.+)$`)
	reHeading14LineFmtGo         = newLazyRegexp(`^(#{1,4})[ \t]+(.+)$`)
	reHTMLHeading14FmtGo         = newLazyRegexp(`(?is)<h([1-4])\b[^>]*>([\s\S]{0,400}?)</h[1-4]>`)
	reVersionPropFmtGo           = newLazyRegexp(`(?i)^(?:version|latestversion|currentversion|release)$`)
	reSemverHeadingFmtGo         = newLazyRegexp(`(?m)^#{1,2}[ \t]+[^\r\n#]{0,120}?\bv?(\d+\.\d+(?:\.\d+)?(?:-[0-9A-Za-z.-]+)?)\b`)
	reSemverAnyFmtGo             = newLazyRegexp(`\bv?(\d+\.\d+(?:\.\d+)?(?:-[0-9A-Za-z.-]+)?)\b`)
	reInstallPropFmtGo           = newLazyRegexp(`(?i)^(?:installcommand|install|installation)$`)
	reInstallCmdFmtGo            = newLazyRegexp(`(?i)\b((?:pip3?|uv[ \t]+(?:pip[ \t]+install|add)|poetry[ \t]+add|conda[ \t]+install|npm[ \t]+(?:install|i|add|create)|pnpm[ \t]+(?:add|install|i|create)|yarn[ \t]+(?:add|create)|bun[ \t]+(?:add|install|i|create)|cargo[ \t]+(?:add|install)|go[ \t]+(?:get|install)|brew[ \t]+install|gem[ \t]+install|composer[ \t]+require|dotnet[ \t]+add[ \t]+package)[ \t]+[^\r\n` + "`" + `"'|;]{1,120})`)
	reLicensePropFmtGo           = newLazyRegexp(`(?i)^(?:license|spdxlicense)$`)
	reLicenseHeadingFmtGo        = newLazyRegexp(`(?i)(?:^|\n)(?:#{1,4}[ \t]*License|\*\*License\*\*|License[ \t]*:)[ \t]*\r?\n+([^\r\n#|]{2,120})`)
	reLicenseSpdxFmtGo           = newLazyRegexp(`(?i)\b((?:MIT|Apache-2\.0|Apache[ \t]+Software[ \t]+License|BSD-[23]-Clause|BSD[ \t]+License|GPL-[23]\.0(?:-only|-or-later)?|LGPL-[23]\.[01]|MPL-2\.0|ISC|Unlicense)(?:[ \t]*\([^)\r\n]{1,40}\))?)\b`)
	reFuzzySepRunsFmtGo          = newLazyRegexp(`(?:\\_|\\-)+|[_\s-]+`)
)

// DecodeHTMLEntities decodes decimal (`&#123;`), hexadecimal (`&#x1f600;`), and named (`&amp;`, `&lt;`, `&mdash;`, etc.)
// HTML entities in linear O(N) time.
func DecodeHTMLEntities(input string) string {
	if input == "" || strings.IndexByte(input, '&') < 0 {
		return input
	}
	var sb strings.Builder
	sb.Grow(len(input))
	i := 0
	n := len(input)
	for i < n {
		if input[i] != '&' || i+2 >= n {
			sb.WriteByte(input[i])
			i++
			continue
		}
		if input[i+1] == '#' {
			p := i + 2
			isHex := false
			if p < n && (input[p] == 'x' || input[p] == 'X') {
				isHex = true
				p++
			}
			dStart := p
			for p < n && p-dStart < 10 {
				c := input[p]
				if isHex {
					if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
						break
					}
				} else if c < '0' || c > '9' {
					break
				}
				p++
			}
			if p > dStart && p < n && input[p] == ';' {
				base := 10
				if isHex {
					base = 16
				}
				if cp, err := strconv.ParseUint(input[dStart:p], base, 32); err == nil {
					if cp > 0 && cp <= 0x10FFFF {
						r := rune(cp)
						if utf8.ValidRune(r) {
							sb.WriteRune(r)
						} else {
							sb.WriteRune('\uFFFD')
						}
					}
					i = p + 1
					continue
				}
			}
		} else if isASCIIAlphaExtract(input[i+1]) {
			p := i + 2
			for p < n && p-(i+1) <= 16 && isASCIIAlnumExtract(input[p]) {
				p++
			}
			if p < n && input[p] == ';' {
				rawName := input[i+1 : p]
				if mapped, ok := markdownNamedEntities[rawName]; ok {
					sb.WriteString(mapped)
					i = p + 1
					continue
				}
				if mapped, ok := markdownNamedEntities[asciiLowerExtractString(rawName)]; ok {
					sb.WriteString(mapped)
					i = p + 1
					continue
				}
			}
		}
		sb.WriteByte(input[i])
		i++
	}
	return sb.String()
}

// DecodeMarkdownEntities decodes HTML entities in Markdown prose segments while leaving fenced code blocks untouched.
func DecodeMarkdownEntities(md string) string {
	if md == "" || strings.IndexByte(md, '&') < 0 {
		return md
	}
	parts := SplitMarkdownByCodeFences(md)
	for idx, part := range parts {
		if idx%2 == 0 {
			parts[idx] = stripInvisibleSmugglingCharsGo(DecodeHTMLEntities(part))
		}
	}
	return strings.Join(parts, "")
}

// MakeSafeCodeFence wraps `code` in a CommonMark backtick (or tilde when `preferTilde` is true) code fence
// guaranteed to exceed any interior run of fence characters.
func MakeSafeCodeFence(code, lang string, preferTilde bool) string {
	cleanCode := strings.ReplaceAll(code, "\r\n", "\n")
	cleanCode = strings.TrimRightFunc(cleanCode, unicode.IsSpace)
	safeLang := strings.TrimSpace(lang)
	safeLang = strings.NewReplacer("\r", "", "\n", "", "`", "").Replace(safeLang)

	if preferTilde {
		maxTildes := 3
		cur := 0
		for i := 0; i < len(cleanCode); i++ {
			if cleanCode[i] == '~' {
				cur++
				if cur >= 3 && cur >= maxTildes {
					maxTildes = cur + 1
				}
			} else {
				cur = 0
			}
		}
		if maxTildes < 4 {
			maxTildes = 4
		}
		fence := strings.Repeat("~", maxTildes)
		return fence + safeLang + "\n" + cleanCode + "\n" + fence
	}

	maxTicks := 2
	cur := 0
	for i := 0; i < len(cleanCode); i++ {
		if cleanCode[i] == '`' {
			cur++
			if cur >= 3 && cur > maxTicks {
				maxTicks = cur
			}
		} else {
			cur = 0
		}
	}
	fence := strings.Repeat("`", maxTicks+1)
	return fence + safeLang + "\n" + cleanCode + "\n" + fence
}

// SplitMarkdownByCodeFences splits Markdown into alternating `[prose, codeFence, prose, codeFence, ...]` segments
// (`idx % 2 == 1` is always a recognized top-level CommonMark fenced code block).
func SplitMarkdownByCodeFences(rawMD string) []string {
	return splitMarkdownByCodeFencesGo(rawMD)
}

func safeDecodeURIComponentFmtGo(raw string) string {
	if dec, err := url.PathUnescape(raw); err == nil {
		return dec
	}
	return raw
}

func stripMarkdownLinksToLabelsLinearFmtGo(text string) string {
	if text == "" || (!strings.Contains(text, "](") && strings.IndexByte(text, '<') < 0) {
		return text
	}
	bounded := truncateUTF8SafeFullDocGo(text, maxHTMLScanCharsFullDocGo)
	lines := strings.Split(bounded, "\n")
	for li, line := range lines {
		if !strings.Contains(line, "](") {
			continue
		}
		cursors := newMdLineCursorsGo()
		var out strings.Builder
		lastIdx := 0
		i := 0
		for i < len(line) {
			ch := line[i]
			if ch == '`' {
				if isBackslashEscapedAt(line, i) {
					i++
					continue
				}
				tEnd, sEnd := scanCodeSpanEndLinearGo(line, i, cursors)
				if sEnd > 0 {
					i = sEnd
				} else {
					i = tEnd
				}
				continue
			}
			if (ch == '!' || ch == '[') && !isBackslashEscapedAt(line, i) {
				if tok := tryParseMarkdownLinkOrImageAtGo(line, i, cursors, true); tok != nil {
					out.WriteString(line[lastIdx:i])
					cleanLabel := tok.rawLabel
					if strings.Contains(cleanLabel, "](") {
						cleanLabel = stripMarkdownLinksToLabelsLinearFmtGo(cleanLabel)
					}
					out.WriteString(cleanLabel)
					i = tok.end
					lastIdx = i
					continue
				}
			}
			i++
		}
		if lastIdx > 0 {
			out.WriteString(line[lastIdx:])
			lines[li] = out.String()
		}
	}
	return strings.Join(lines, "\n")
}

func jsonScalarToStringFmtGo(val any) string {
	switch v := val.(type) {
	case nil:
		return ""
	case string:
		return v
	case json.Number:
		return v.String()
	case bool:
		if v {
			return "true"
		}
		return "false"
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	case int:
		return strconv.Itoa(v)
	case int64:
		return strconv.FormatInt(v, 10)
	default:
		return fmt.Sprint(v)
	}
}

func isScalarJSONValueFmtGo(val any) bool {
	switch val.(type) {
	case string, json.Number, bool, float64, float32, int, int64, int32, uint, uint64:
		return true
	default:
		return false
	}
}

// FormatInertiaPagePropsToMarkdown renders an Inertia.js `data-page` payload (`{ component, props, url, version }`)
// into a clean GFM summary of the component and its non-boilerplate props.
func FormatInertiaPagePropsToMarkdown(props map[string]any, pageURL string) *FormattedPayloadDoc {
	if len(props) == 0 {
		return nil
	}
	rawComp, _ := props["component"].(string)
	decodedComp := stripInvisibleSmugglingCharsGo(decodeMarkdownEntitiesEscapingLinkBracketsPreservingLtGo(stripInvisibleSmugglingCharsGo(rawComp)))
	compClean := neutralizeAllUnsafeMarkdownLinksLinearGo(decodedComp)
	compClean = strings.NewReplacer("\r", " ", "\n", " ", "`", " ", "<", "&lt;").Replace(compClean)
	component := strings.Join(strings.Fields(compClean), " ")
	if component == "" {
		return nil
	}

	rawProps, ok := props["props"].(map[string]any)
	if !ok {
		rawProps = make(map[string]any)
	}

	bestTitle := ""
	bestDescription := ""
	visited := 0

	preEscapeInline := func(val any, maxLen int) string {
		rawStr := stripInvisibleSmugglingCharsGo(jsonScalarToStringFmtGo(val))
		if strings.TrimSpace(rawStr) == "" {
			return ""
		}
		decoded := stripInvisibleSmugglingCharsGo(decodeMarkdownEntitiesEscapingLinkBracketsPreservingLtGo(rawStr))
		safe := escapeUnescapedMarkdownBracketsGo(decoded)
		safe = strings.NewReplacer("\r\n", " ", "\n", " ", "\r", " ", "<", "&lt;").Replace(safe)
		safe = strings.TrimSpace(safe)
		if len(safe) > maxLen {
			safe = truncateUTF8SafeFullDocGo(safe, maxLen)
		}
		return safe
	}

	escapeKeyHeading := func(val string) string {
		s := preEscapeInline(val, 120)
		s = strings.TrimLeft(s, "# \t")
		return strings.NewReplacer("*", "", "_", "", "`", "", "[", "", "]", "", "|", "").Replace(s)
	}

	escapeCell := func(val any) string {
		return strings.ReplaceAll(preEscapeInline(val, 160), "|", `\|`)
	}

	convertRichString := func(raw string) string {
		cleaned := strings.TrimSpace(stripInvisibleSmugglingCharsGo(raw))
		if cleaned == "" {
			return ""
		}
		if reRichHTMLTagFmtGo.MatchString(cleaned) {
			sub := ExtractHTMLDocumentFull(cleaned, FullExtractOptions{
				BaseURL:         pageURL,
				OnlyMainContent: false,
				IncludeImages:   false,
			})
			conv := strings.TrimSpace(stripInvisibleSmugglingCharsGo(sub.Markdown))
			return strings.ReplaceAll(neutralizeAllUnsafeMarkdownLinksLinearGo(conv), "<", "&lt;")
		}
		decoded := stripInvisibleSmugglingCharsGo(decodeMarkdownProseEntitiesPreservingLinksAndLtGo(cleaned))
		return strings.ReplaceAll(neutralizeAllUnsafeMarkdownLinksLinearGo(decoded), "<", "&lt;")
	}

	var renderObjectFields func(obj map[string]any, depth int) []string
	renderObjectFields = func(obj map[string]any, depth int) []string {
		if depth > 3 || visited > 400 {
			return nil
		}
		var bullets []string
		var subBlocks []string
		keys := sortedMapKeys(obj)
		for _, k := range keys {
			visited++
			if visited > 400 {
				break
			}
			v := obj[k]
			lower := strings.ToLower(k)
			if inertiaSkipPropKeysFmtGo[lower] || v == nil || v == "" {
				continue
			}
			if lower == "auth" {
				if authMap, isMap := v.(map[string]any); isMap && authMap["user"] == nil {
					continue
				}
			}
			safeKey := escapeKeyHeading(k)
			if safeKey == "" {
				safeKey = "field"
			}
			switch vt := v.(type) {
			case string:
				clean := strings.TrimSpace(stripInvisibleSmugglingCharsGo(vt))
				if clean == "" {
					continue
				}
				safeScalar := preEscapeInline(clean, 300)
				if bestTitle == "" && (lower == "title" || lower == "pagetitle" || lower == "headline" || lower == "name") && len(clean) <= 180 {
					bestTitle = SanitizeScrapedMetadataField(clean, 180)
				}
				if bestDescription == "" && (lower == "description" || lower == "summary" || lower == "excerpt") &&
					len(clean) >= 20 && len(clean) <= 400 && !strings.Contains(clean, "<") {
					bestDescription = SanitizeScrapedMetadataField(clean, 400)
				}
				isProse := len(clean) >= 80 || lower == "body" || lower == "content" || lower == "markdown" || lower == "html" || lower == "descriptionhtml"
				if isProse && strings.ContainsAny(clean, " \t\r\n") {
					if rich := convertRichString(clean); rich != "" {
						subBlocks = append(subBlocks, rich)
					}
				} else if safeScalar != "" {
					bullets = append(bullets, "- **"+safeKey+"**: "+safeScalar)
				}
			case bool, float64, float32, int, int64, json.Number:
				bullets = append(bullets, "- **"+safeKey+"**: "+jsonScalarToStringFmtGo(vt))
			case []any:
				if len(vt) == 0 {
					continue
				}
				slice := vt
				if len(slice) > 40 {
					slice = slice[:40]
				}
				allScalars := true
				allObjects := true
				for _, it := range slice {
					if !isScalarJSONValueFmtGo(it) {
						allScalars = false
					}
					if _, isObj := it.(map[string]any); !isObj {
						allObjects = false
					}
				}
				if allScalars {
					var rendered []string
					for _, it := range slice {
						if s := preEscapeInline(it, 160); s != "" {
							rendered = append(rendered, s)
						}
					}
					if len(rendered) > 0 {
						bullets = append(bullets, "- **"+safeKey+"**: "+strings.Join(rendered, ", "))
					}
				} else if allObjects {
					firstRow := slice[0].(map[string]any)
					var cols []string
					for _, ck := range sortedMapKeys(firstRow) {
						if isScalarJSONValueFmtGo(firstRow[ck]) {
							cols = append(cols, ck)
							if len(cols) >= 6 {
								break
							}
						}
					}
					if len(cols) >= 2 {
						escapedHeaders := make([]string, len(cols))
						seps := make([]string, len(cols))
						for i, c := range cols {
							escapedHeaders[i] = escapeCell(c)
							seps[i] = "---"
						}
						tblLines := []string{
							"| " + strings.Join(escapedHeaders, " | ") + " |",
							"| " + strings.Join(seps, " | ") + " |",
						}
						for _, it := range slice {
							r := it.(map[string]any)
							cells := make([]string, len(cols))
							for i, c := range cols {
								cells[i] = escapeCell(r[c])
							}
							tblLines = append(tblLines, "| "+strings.Join(cells, " | ")+" |")
						}
						subBlocks = append(subBlocks, "### "+safeKey+"\n\n"+strings.Join(tblLines, "\n"))
					} else {
						var itemLines []string
						for _, it := range slice {
							r := it.(map[string]any)
							lblRaw := r["title"]
							if lblRaw == nil {
								lblRaw = r["name"]
							}
							if lblRaw == nil {
								lblRaw = r["label"]
							}
							if lblRaw == nil {
								lblRaw = r["id"]
							}
							lbl := preEscapeInline(lblRaw, 160)
							rawDesc := ""
							if bStr, ok := r["body"].(string); ok {
								rawDesc = convertRichString(bStr)
							} else if dStr, ok := r["description"].(string); ok {
								rawDesc = convertRichString(dStr)
							}
							desc := strings.Join(strings.Fields(rawDesc), " ")
							if lbl != "" && desc != "" {
								itemLines = append(itemLines, "- **"+lbl+"**: "+truncateUTF8SafeFullDocGo(desc, 400))
							} else if lbl != "" {
								itemLines = append(itemLines, "- "+lbl)
							}
						}
						if len(itemLines) > 0 {
							subBlocks = append(subBlocks, "### "+safeKey+"\n\n"+strings.Join(itemLines, "\n"))
						}
					}
				}
			case map[string]any:
				if depth < 2 {
					nested := renderObjectFields(vt, depth+1)
					if len(nested) > 0 {
						hPrefix := "##"
						if depth > 0 {
							hPrefix = "###"
						}
						subBlocks = append(subBlocks, hPrefix+" "+safeKey+"\n\n"+strings.Join(nested, "\n\n"))
					}
				}
			}
		}
		var out []string
		if len(bullets) > 0 {
			out = append(out, strings.Join(bullets, "\n"))
		}
		out = append(out, subBlocks...)
		return out
	}

	propSections := renderObjectFields(rawProps, 0)
	if len(propSections) == 0 {
		return nil
	}
	headingTitle := preEscapeInline(bestTitle, 180)
	if headingTitle == "" {
		headingTitle = preEscapeInline(strings.ReplaceAll(component, "/", " — "), 180)
	}
	headingTitle = strings.Join(strings.Fields(headingTitle), " ")
	sections := append([]string{"# " + headingTitle, "- **Inertia Component**: `" + component + "`"}, propSections...)
	return &FormattedPayloadDoc{
		Title:       bestTitle,
		Description: bestDescription,
		Markdown:    strings.TrimSpace(strings.Join(sections, "\n\n")),
		Structured:  props,
	}
}

func extractPrimaryEntityNameForSchemaFmtGo(rawHTML string, doc ExtractedDocumentFull, propNameLower string) string {
	candidate := ""
	if doc.Markdown != "" {
		for _, ln := range strings.Split(doc.Markdown, "\n") {
			trimmed := strings.TrimSpace(ln)
			if strings.HasPrefix(trimmed, "# ") {
				h1 := strings.TrimSpace(trimmed[2:])
				candidate = cleanHeadingPermalinksFullDocGo(strings.TrimSpace(strings.ReplaceAll(stripMarkdownLinksToLabelsLinearFmtGo(h1), "`", "")))
				break
			}
		}
	}
	if candidate == "" && rawHTML != "" && strings.Contains(asciiLowerExtractString(rawHTML), "<h1") {
		replacePairedHTMLElementsLinearFullDocGo(rawHTML, []string{"h1"}, func(_, _, _, inner string) string {
			if candidate == "" {
				candidate = cleanHeadingPermalinksFullDocGo(strings.TrimSpace(strings.ReplaceAll(cleanInlineHTMLFullDocGo(inner), "`", "")))
			}
			return ""
		}, 65536, 1024)
	}
	if candidate == "" && doc.Title != "" {
		parts := reTitleSplitSepFmtGo.Split(doc.Title, 2)
		if len(parts) > 0 {
			candidate = strings.TrimSpace(parts[0])
		}
	}
	if candidate == "" {
		return ""
	}
	if propNameLower == "headername" {
		if m := reHeaderTokenFmtGo.FindStringSubmatch(candidate); len(m) >= 2 {
			return m[1]
		}
	}
	return candidate
}

func singularizeSchemaStemFmtGo(word string) string {
	if strings.HasSuffix(word, "ies") && len(word) > 4 {
		return word[:len(word)-3] + "y"
	}
	if strings.HasSuffix(word, "ses") && len(word) > 4 {
		return word[:len(word)-2]
	}
	if strings.HasSuffix(word, "s") && !strings.HasSuffix(word, "ss") && len(word) > 3 {
		return word[:len(word)-1]
	}
	return word
}

func schemaPropPrimaryTypeFmtGo(propSpec any) string {
	m, ok := propSpec.(map[string]any)
	if !ok {
		return ""
	}
	switch t := m["type"].(type) {
	case string:
		return strings.ToLower(strings.TrimSpace(t))
	case []any:
		for _, elem := range t {
			if s, ok := elem.(string); ok && !strings.EqualFold(s, "null") {
				return strings.ToLower(strings.TrimSpace(s))
			}
		}
	}
	return ""
}

// ExtractStructuredJSONFromPageWithDiagnostics performs deterministic, keyless schema-guided structured extraction
// over JSON-LD (`application/ld+json`), document metadata, and GFM Markdown structure, returning the extracted map
// alongside matched and unfilled schema property names.
func ExtractStructuredJSONFromPageWithDiagnostics(
	rawHTML string,
	doc ExtractedDocumentFull,
	schema map[string]any,
	prompt string,
) (result map[string]any, matchedFields []string, unfilledFields []string) {
	_ = prompt
	var jsonLdObjects []map[string]any
	if rawHTML != "" {
		jsonLdObjects = flattenJsonLdEntitiesFullDocGo(rawHTML)
	}
	if len(jsonLdObjects) == 0 && len(doc.StructuredData) > 0 {
		jsonLdObjects = doc.StructuredData
	}

	result = make(map[string]any)
	matchedFields = make([]string, 0)
	unfilledFields = make([]string, 0)

	var props map[string]any
	if schema != nil {
		props, _ = schema["properties"].(map[string]any)
	}
	if len(props) == 0 {
		if doc.Title != "" {
			result["title"] = doc.Title
			matchedFields = append(matchedFields, "title")
		}
		if doc.Description != "" {
			result["description"] = doc.Description
			matchedFields = append(matchedFields, "description")
		}
		if len(jsonLdObjects) > 0 {
			result["jsonLd"] = jsonLdObjects
			matchedFields = append(matchedFields, "jsonLd")
		}
		return result, matchedFields, unfilledFields
	}

	mdWithoutFences := ""
	if doc.Markdown != "" {
		parts := SplitMarkdownByCodeFences(doc.Markdown)
		var prose []string
		for idx, p := range parts {
			if idx%2 == 0 {
				prose = append(prose, p)
			}
		}
		mdWithoutFences = strings.Join(prose, "")
	}
	mdScanSlice := truncateUTF8SafeFullDocGo(doc.Markdown, 65536)

	var lazyProduct map[string]any
	lazyProductComputed := false
	getProductData := func() map[string]any {
		if !lazyProductComputed {
			lazyProductComputed = true
			if rawHTML != "" {
				lazyProduct = ExtractStructuredProduct(rawHTML, doc.CanonicalURL, doc.Title, doc.Description)
			}
			if len(doc.Records) > 0 && doc.Records[0] != nil {
				rec := doc.Records[0]
				if lazyProduct == nil {
					lazyProduct = make(map[string]any)
				}
				for _, pair := range [][2]string{
					{"title", "title"},
					{"brand", "vendor"},
					{"brand", "brand"},
					{"currency", "currency"},
					{"sku", "sku"},
					{"mpn", "mpn"},
					{"gtin", "gtin"},
					{"gtin", "gtin13"},
				} {
					if lazyProduct[pair[0]] == nil {
						if s, ok := rec[pair[1]].(string); ok && strings.TrimSpace(s) != "" {
							lazyProduct[pair[0]] = strings.TrimSpace(s)
						}
					}
				}
				if lazyProduct["price"] == nil && rec["price"] != nil {
					lazyProduct["price"] = rec["price"]
				}
				if variants, ok := rec["variants"].([]any); ok && len(variants) > 0 {
					if v0, okV := variants[0].(map[string]any); okV && v0 != nil {
						if lazyProduct["price"] == nil && v0["price"] != nil {
							lazyProduct["price"] = v0["price"]
						}
						if lazyProduct["currency"] == nil {
							if c, okC := v0["currency"].(string); okC && strings.TrimSpace(c) != "" {
								lazyProduct["currency"] = strings.TrimSpace(c)
							}
						}
						if lazyProduct["sku"] == nil {
							if s, okS := v0["sku"].(string); okS && strings.TrimSpace(s) != "" {
								lazyProduct["sku"] = strings.TrimSpace(s)
							}
						}
						if lazyProduct["gtin"] == nil {
							if b, okB := v0["barcode"].(string); okB && strings.TrimSpace(b) != "" {
								lazyProduct["gtin"] = strings.TrimSpace(b)
							}
						}
					}
				}
				recordAvail := normalizeRecordAvailabilityFmtGo(rec["availability"])
				if recordAvail == "" {
					recordAvail = normalizeRecordAvailabilityFmtGo(rec["available"])
				}
				if recordAvail == "" {
					if variants, ok := rec["variants"].([]any); ok && len(variants) > 0 {
						var normAvails []string
						for _, vrAny := range variants {
							vr, okV := vrAny.(map[string]any)
							if !okV || vr == nil {
								continue
							}
							va := normalizeRecordAvailabilityFmtGo(vr["availability"])
							if va == "" {
								va = normalizeRecordAvailabilityFmtGo(vr["available"])
							}
							if va != "" {
								normAvails = append(normAvails, va)
							}
						}
						if len(normAvails) == 1 {
							recordAvail = normAvails[0]
						} else if len(normAvails) > 1 {
							picked := normAvails[0]
							for _, pref := range []string{"InStock", "PreOrder", "BackOrder"} {
								foundPref := false
								for _, na := range normAvails {
									if na == pref {
										picked = pref
										foundPref = true
										break
									}
								}
								if foundPref {
									break
								}
							}
							recordAvail = picked
						}
					}
				}
				if recordAvail != "" && (doc.PreferRecordAvailability || lazyProduct["availability"] == nil) {
					lazyProduct["availability"] = recordAvail
				}
			}
		}
		return lazyProduct
	}

	propNames := sortedMapKeys(props)
	for _, propName := range propNames {
		propSpec := props[propName]
		propType := schemaPropPrimaryTypeFmtGo(propSpec)
		lowerProp := strings.ToLower(propName)
		var val any
		found := false

		skipTopLevelLDForLiveAvail := doc.PreferRecordAvailability &&
			(lowerProp == "availability" || lowerProp == "stockstatus" ||
				lowerProp == "instock" || lowerProp == "available" || lowerProp == "in_stock")

		// 1. JSON-LD exact key match (case-insensitive)
		if !skipTopLevelLDForLiveAvail {
			for _, ld := range jsonLdObjects {
				for _, k := range sortedMapKeys(ld) {
					if strings.EqualFold(k, propName) && ld[k] != nil {
						cand := ld[k]
						if propType == "string" {
							if cm, isMap := cand.(map[string]any); isMap {
								if nm, ok := cm["name"].(string); ok && strings.TrimSpace(nm) != "" {
									cand = strings.TrimSpace(nm)
								} else if u, ok := cm["url"].(string); ok && strings.TrimSpace(u) != "" {
									cand = strings.TrimSpace(u)
								} else if id, ok := cm["@id"].(string); ok && strings.TrimSpace(id) != "" {
									cand = strings.TrimSpace(id)
								} else {
									continue
								}
							}
						}
						val = cand
						found = true
						break
					}
				}
				if found {
					break
				}
			}
		}

		// 1b. Commerce / Schema.org Product `offers` + OpenGraph product meta + twin records fallback
		if !found {
			if prodVal, prodOk := lookupSchemaProductFieldFmtGo(lowerProp, getProductData); prodOk {
				val = prodVal
				found = true
			}
		}

		// 2. Document metadata & Markdown structure heuristics
		if !found {
			switch {
			case lowerProp == "title" || lowerProp == "name" || lowerProp == "headline":
				cand := doc.Title
				if cand == "" {
					cand = extractPrimaryEntityNameForSchemaFmtGo(rawHTML, doc, lowerProp)
				}
				if cand != "" {
					val = cand
					found = true
				}
			case reEntityPropNameFmtGo.MatchString(lowerProp):
				if cand := extractPrimaryEntityNameForSchemaFmtGo(rawHTML, doc, lowerProp); cand != "" {
					val = cand
					found = true
				}
			case lowerProp == "description" || lowerProp == "summary" || lowerProp == "overview":
				cand := doc.Description
				if cand == "" && mdWithoutFences != "" {
					for _, rawB := range strings.Split(mdWithoutFences, "\n\n") {
						b := strings.TrimSpace(rawB)
						if len(b) >= 30 && !reProseBlockSkipFmtGo.MatchString(b) {
							cand = truncateUTF8SafeFullDocGo(strings.Join(strings.Fields(stripMarkdownLinksToLabelsLinearFmtGo(b)), " "), 500)
							break
						}
					}
				}
				if cand != "" {
					val = cand
					found = true
				}
			case lowerProp == "url" || lowerProp == "canonicalurl":
				if doc.CanonicalURL != "" {
					val = doc.CanonicalURL
					found = true
				}
			case lowerProp == "author":
				if doc.Author != "" {
					val = doc.Author
					found = true
				}
			case lowerProp == "publishedtime" || lowerProp == "datepublished":
				if doc.PublishedTime != "" {
					val = doc.PublishedTime
					found = true
				}
			case lowerProp == "modifiedtime" || lowerProp == "datemodified":
				if doc.ModifiedTime != "" {
					val = doc.ModifiedTime
					found = true
				}
			case lowerProp == "sitename":
				if doc.SiteName != "" {
					val = doc.SiteName
					found = true
				}
			case lowerProp == "language":
				if doc.Language != "" {
					val = doc.Language
					found = true
				}
			case lowerProp == "links":
				if len(doc.Links) > 0 {
					val = doc.Links
					found = true
				}
			case lowerProp == "images":
				if len(doc.Images) > 0 {
					urls := make([]string, len(doc.Images))
					for i, img := range doc.Images {
						urls[i] = img.URL
					}
					val = urls
					found = true
				}
			case propType == "array" && (mdWithoutFences != "" || rawHTML != ""):
				if arr := extractSchemaArrayFieldFmtGo(propName, mdWithoutFences, rawHTML); len(arr) > 0 {
					val = arr
					found = true
				}
			default:
				if cand, ok := extractSchemaScalarHeuristicFmtGo(propName, lowerProp, propType, mdScanSlice, doc.Title); ok {
					val = cand
					found = true
				}
			}
		}

		if found && val != nil {
			if (propType == "number" || propType == "integer") && !isNumericTypeFmtGo(val) {
				if s, ok := val.(string); ok {
					var cleanNum strings.Builder
					for i := 0; i < len(s); i++ {
						c := s[i]
						if (c >= '0' && c <= '9') || c == '.' || c == '-' {
							cleanNum.WriteByte(c)
						}
					}
					if f, err := strconv.ParseFloat(cleanNum.String(), 64); err == nil {
						if propType == "integer" {
							val = int64(f)
						} else {
							val = f
						}
					}
				}
			} else if propType == "boolean" {
				if s, ok := val.(string); ok {
					ls := strings.ToLower(strings.TrimSpace(s))
					val = ls == "true" || ls == "yes" || ls == "1"
				}
			}
			result[propName] = val
			matchedFields = append(matchedFields, propName)
		} else if propType == "array" {
			result[propName] = []any{}
			unfilledFields = append(unfilledFields, propName)
		} else {
			result[propName] = nil
			unfilledFields = append(unfilledFields, propName)
		}
	}

	return result, matchedFields, unfilledFields
}

func normalizeRecordAvailabilityFmtGo(v any) string {
	switch val := v.(type) {
	case bool:
		if val {
			return "InStock"
		}
		return "OutOfStock"
	case string:
		s := strings.ToLower(strings.Join(strings.Fields(val), " "))
		if s == "" {
			return ""
		}
		if strings.Contains(s, "out of stock") || strings.Contains(s, "outofstock") ||
			strings.Contains(s, "not in stock") || strings.Contains(s, "not-in-stock") ||
			strings.Contains(s, "not instock") || strings.Contains(s, "not available") ||
			strings.Contains(s, "no longer available") || strings.Contains(s, "sold out") ||
			strings.Contains(s, "soldout") || strings.Contains(s, "unavailable") ||
			strings.Contains(s, "discontinued") || s == "false" || s == "0" {
			return "OutOfStock"
		}
		if strings.Contains(s, "preorder") || strings.Contains(s, "pre-order") || strings.Contains(s, "pre_order") {
			return "PreOrder"
		}
		if strings.Contains(s, "backorder") || strings.Contains(s, "back-order") || strings.Contains(s, "back_order") {
			return "BackOrder"
		}
		if strings.Contains(s, "instock") || strings.Contains(s, "in stock") ||
			strings.Contains(s, "in_stock") || s == "available" || s == "true" || s == "1" {
			return "InStock"
		}
	}
	return ""
}

func isNumericTypeFmtGo(v any) bool {
	switch v.(type) {
	case int, int64, float64, float32, json.Number:
		return true
	}
	return false
}

func normalizeAlphaNumLowerFmtGo(s string) string {
	var sb strings.Builder
	sb.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			sb.WriteByte(c + ('a' - 'A'))
		} else if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') {
			sb.WriteByte(c)
		}
	}
	return sb.String()
}

func lookupSchemaProductFieldFmtGo(lowerProp string, getProduct func() map[string]any) (any, bool) {
	var prodKey string
	isInStockBool := false
	switch lowerProp {
	case "price", "lowprice", "highprice", "saleprice", "currentprice", "amount":
		prodKey = "price"
	case "currency", "pricecurrency":
		prodKey = "currency"
	case "availability", "stockstatus":
		prodKey = "availability"
	case "instock", "available", "in_stock":
		prodKey = "availability"
		isInStockBool = true
	case "brand", "vendor", "manufacturer":
		prodKey = "brand"
	case "sku", "productid":
		prodKey = "sku"
	case "mpn", "partnumber", "part_number", "model":
		prodKey = "mpn"
	case "gtin", "gtin13", "ean", "upc":
		prodKey = "gtin"
	case "url":
		prodKey = "url"
	case "rating", "ratingvalue", "averagerating":
		prodKey = "rating"
	case "reviewcount", "reviews_count", "ratingcount":
		prodKey = "reviewCount"
	}
	prod := getProduct()
	if len(prod) == 0 {
		return nil, false
	}
	if prodKey != "" {
		v, exists := prod[prodKey]
		if (!exists || v == nil) && prodKey == "mpn" {
			v, exists = prod["sku"]
		}
		if exists && v != nil {
			if isInStockBool {
				s := strings.ToLower(strings.TrimSpace(jsonScalarToString(v)))
				if s == "" {
					return nil, false
				}
				return strings.Contains(s, "instock") || s == "true" || s == "available", true
			}
			return v, true
		}
	}
	normProp := normalizeAlphaNumLowerFmtGo(lowerProp)
	if normProp == "category" {
		if cv, ok := prod["category"]; ok && cv != nil {
			return cv, true
		}
		normProp = "producttype"
	}
	if specsStr, ok := prod["specs"].(map[string]string); ok {
		for sk, sv := range specsStr {
			if normalizeAlphaNumLowerFmtGo(sk) == normProp && sv != "" {
				return sv, true
			}
		}
	} else if specsAny, ok := prod["specs"].(map[string]any); ok {
		for sk, sv := range specsAny {
			if normalizeAlphaNumLowerFmtGo(sk) == normProp && sv != nil {
				return sv, true
			}
		}
	}
	return nil, false
}

func extractSchemaArrayFieldFmtGo(propName, cleanMD, rawHTML string) []string {
	lowName := strings.ToLower(propName)
	if strings.Contains(lowName, "headings") || strings.Contains(lowName, "sections") || strings.Contains(lowName, "topics") {
		var headings []string
		for _, m := range reMdH2H3FmtGo.FindAllStringSubmatch(cleanMD, 40) {
			if len(m) >= 2 {
				s := strings.TrimSpace(stripMarkdownLinksToLabelsLinearFmtGo(m[1]))
				if s != "" && !reBoilerplateSchemaItemFmtGo.MatchString(s) {
					headings = append(headings, s)
					if len(headings) >= 20 {
						break
					}
				}
			}
		}
		return headings
	}

	spaced := strings.ToLower(reCamelSplitFmtGo.ReplaceAllString(propName, "$1 $2"))
	var propStems []string
	seenStem := make(map[string]bool)
	for _, w := range strings.FieldsFunc(spaced, func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsDigit(r) }) {
		if len(w) < 3 || w == "key" || w == "main" || w == "all" || w == "list" || w == "items" {
			continue
		}
		for _, st := range []string{w, singularizeSchemaStemFmtGo(w)} {
			if !seenStem[st] {
				seenStem[st] = true
				propStems = append(propStems, st)
			}
		}
	}

	cleanCandidateItem := func(rawItem string) string {
		s := stripMarkdownLinksToLabelsLinearFmtGo(rawItem)
		s = strings.TrimSpace(s)
		s = strings.TrimPrefix(strings.TrimSuffix(s, "**"), "**")
		s = strings.TrimPrefix(strings.TrimSuffix(s, "*"), "*")
		s = strings.TrimPrefix(strings.TrimSuffix(s, "`"), "`")
		return strings.TrimSpace(s)
	}
	isAcceptable := func(s string) bool {
		return len(s) >= 2 && len(s) <= 240 && !reBoilerplateSchemaItemFmtGo.MatchString(s)
	}
	lines := strings.Split(strings.ReplaceAll(cleanMD, "\r\n", "\n"), "\n")

	collectSectionItems := func(subset []string) []string {
		var dtOrSub []string
		seen := make(map[string]bool)
		for _, rawLine := range subset {
			t := strings.TrimSpace(rawLine)
			if sm := reSubHeading34FmtGo.FindStringSubmatch(t); len(sm) >= 2 {
				c := cleanCandidateItem(sm[1])
				if isAcceptable(c) && !reSkipSubHeadingFmtGo.MatchString(c) && !seen[c] {
					seen[c] = true
					dtOrSub = append(dtOrSub, c)
				}
				continue
			}
			if dm := reDtBoldLineFmtGo.FindStringSubmatch(t); len(dm) >= 3 {
				rawDt := dm[1]
				if rawDt == "" {
					rawDt = dm[2]
				}
				c := cleanCandidateItem(rawDt)
				if isAcceptable(c) && !seen[c] {
					seen[c] = true
					dtOrSub = append(dtOrSub, c)
				}
			}
		}
		if len(dtOrSub) >= 2 {
			if len(dtOrSub) > 30 {
				return dtOrSub[:30]
			}
			return dtOrSub
		}
		out := append([]string(nil), dtOrSub...)
		for _, rawLine := range subset {
			if bm := reBulletOrNumLineFmtGo.FindStringSubmatch(strings.TrimSpace(rawLine)); len(bm) >= 2 {
				c := cleanCandidateItem(bm[1])
				if len(c) >= 3 && isAcceptable(c) && !seen[c] {
					seen[c] = true
					out = append(out, c)
					if len(out) >= 25 {
						break
					}
				}
			}
		}
		return out
	}

	if len(propStems) > 0 {
		var collected []string
		seen := make(map[string]bool)
		for i := 0; i < len(lines); i++ {
			hm := reHeading14LineFmtGo.FindStringSubmatch(strings.TrimSpace(lines[i]))
			if len(hm) < 3 {
				continue
			}
			matchedRank := len(hm[1])
			headingLower := strings.ToLower(stripMarkdownLinksToLabelsLinearFmtGo(hm[2]))
			if reBoilerplateSchemaItemFmtGo.MatchString(headingLower) {
				continue
			}
			stemHit := false
			for _, st := range propStems {
				if strings.Contains(headingLower, st) {
					stemHit = true
					break
				}
			}
			if !stemHit {
				continue
			}
			var secLines []string
			for j := i + 1; j < len(lines); j++ {
				if nextHm := reHeading14LineFmtGo.FindStringSubmatch(strings.TrimSpace(lines[j])); len(nextHm) >= 3 && len(nextHm[1]) <= matchedRank {
					break
				}
				secLines = append(secLines, lines[j])
			}
			for _, it := range collectSectionItems(secLines) {
				if !seen[it] {
					seen[it] = true
					collected = append(collected, it)
					if len(collected) >= 30 {
						return collected
					}
				}
			}
		}
		if len(collected) > 0 {
			return collected
		}
		lowRaw := asciiLowerExtractString(rawHTML)
		if rawHTML != "" && strings.Contains(lowRaw, "<dl") && (strings.Contains(lowRaw, "<dt") || strings.Contains(lowRaw, "<code")) {
			var htmlTerms []string
			for _, loc := range reHTMLHeading14FmtGo.FindAllStringSubmatchIndex(rawHTML, 40) {
				hRank := int(rawHTML[loc[2]] - '0')
				hText := strings.ToLower(cleanInlineHTMLFullDocGo(rawHTML[loc[4]:loc[5]]))
				stemHit := false
				for _, st := range propStems {
					if strings.Contains(hText, st) {
						stemHit = true
						break
					}
				}
				if !stemHit {
					continue
				}
				afterIdx := loc[1]
				endSec := afterIdx + 65536
				if endSec > len(rawHTML) {
					endSec = len(rawHTML)
				}
				scanHTMLTagsLinearFullDocGo(rawHTML[afterIdx:endSec], func(t scannedTagFullDocGo) bool {
					if !t.isClosing && len(t.tagNameLower) == 2 && t.tagNameLower[0] == 'h' && int(t.tagNameLower[1]-'0') <= hRank {
						endSec = afterIdx + t.index
						return false
					}
					return true
				}, endSec-afterIdx, false)
				secHTML := rawHTML[afterIdx:endSec]
				replacePairedHTMLElementsLinearFullDocGo(secHTML, []string{"dt"}, func(_, _, _, dInner string) string {
					codeTxt := ""
					replacePairedHTMLElementsLinearFullDocGo(dInner, []string{"code"}, func(_, _, _, cInner string) string {
						if codeTxt == "" {
							codeTxt = cleanInlineHTMLFullDocGo(cInner)
						}
						return ""
					}, 2048, 512)
					term := strings.TrimSpace(codeTxt)
					if term == "" {
						term = strings.TrimSpace(cleanHeadingPermalinksFullDocGo(cleanInlineHTMLFullDocGo(dInner)))
					}
					if isAcceptable(term) && !seen[term] {
						seen[term] = true
						htmlTerms = append(htmlTerms, term)
					}
					return ""
				}, 65536, 2048)
			}
			if len(htmlTerms) > 30 {
				return htmlTerms[:30]
			}
			return htmlTerms
		}
		return nil
	}

	var bullets []string
	for _, rawLine := range lines {
		if bm := reBulletOrNumLineFmtGo.FindStringSubmatch(strings.TrimSpace(rawLine)); len(bm) >= 2 {
			c := cleanCandidateItem(bm[1])
			if len(c) >= 4 && isAcceptable(c) {
				bullets = append(bullets, c)
				if len(bullets) >= 15 {
					break
				}
			}
		}
	}
	return bullets
}

func extractSchemaScalarHeuristicFmtGo(propName, lowerProp, propType, mdScanSlice, docTitle string) (string, bool) {
	if len(propName) > 80 {
		return "", false
	}
	trimmedKey := strings.Trim(propName, " \t_-")
	if trimmedKey != "" && mdScanSlice != "" {
		escaped := regexp.QuoteMeta(trimmedKey)
		fuzzy := reFuzzySepRunsFmtGo.ReplaceAllString(escaped, `[ \t_-]{0,8}`)
		fuzzy = reCamelSplitFmtGo.ReplaceAllString(fuzzy, `$1[ \t_-]{0,8}$2`)
		pat := `(?im)(?:^|\n)[ \t]{0,32}(?:[-*][ \t]{0,16})?\*{0,2}` + fuzzy + `\*{0,2}[ \t]{0,16}:[ \t]{0,16}([^\r\n]{1,500})`
		if kvRe, err := regexp.Compile(pat); err == nil {
			if m := kvRe.FindStringSubmatch(mdScanSlice); len(m) >= 2 {
				v := strings.TrimSpace(m[1])
				if len(v) >= 2 && v[0] == '`' && v[len(v)-1] == '`' && !strings.Contains(v[1:len(v)-1], "`") {
					v = v[1 : len(v)-1]
				}
				if v != "" {
					return strings.TrimSpace(v), true
				}
			}
		}
		if strings.Contains(mdScanSlice, `"`+trimmedKey) || strings.Contains(strings.ToLower(mdScanSlice), `"`+strings.ToLower(trimmedKey)) {
			jsonPat := `(?i)"` + escaped + `"[ \t]*:[ \t]*(?:"([^"\\\r\n]{1,300})"|(-?\d+(?:\.\d+)?|true|false))\b`
			if jsonKvRe, err := regexp.Compile(jsonPat); err == nil {
				if jm := jsonKvRe.FindStringSubmatch(mdScanSlice); len(jm) >= 3 {
					cand := strings.TrimSpace(jm[1])
					if cand == "" {
						cand = strings.TrimSpace(jm[2])
					}
					if cand != "" {
						return cand, true
					}
				}
			}
		}
		if strings.Contains(mdScanSlice, "|") {
			gfmPat := `(?im)^[ \t]*\|[ \t]*\*{0,2}` + fuzzy + `(?:\s*\([^|\r\n]{1,40}\))?\*{0,2}[ \t]*\|[ \t]*([^|\r\n]{1,500})\|`
			if gfmRe, err := regexp.Compile(gfmPat); err == nil {
				for _, gm := range gfmRe.FindAllStringSubmatch(mdScanSlice, 8) {
					if len(gm) >= 2 {
						cand := strings.TrimSpace(gm[1])
						if len(cand) >= 2 && cand[0] == '`' && cand[len(cand)-1] == '`' && !strings.Contains(cand[1:len(cand)-1], "`") {
							cand = cand[1 : len(cand)-1]
						}
						if cand != "" && strings.Trim(cand, "-: \t") != "" {
							return strings.TrimSpace(cand), true
						}
					}
				}
			}
		}
	}
	if reVersionPropFmtGo.MatchString(lowerProp) {
		if m := reSemverHeadingFmtGo.FindStringSubmatch(mdScanSlice); len(m) >= 2 {
			return m[1], true
		}
		if m := reSemverAnyFmtGo.FindStringSubmatch(docTitle); len(m) >= 2 {
			return m[1], true
		}
	}
	if reInstallPropFmtGo.MatchString(lowerProp) && propType != "array" {
		if m := reInstallCmdFmtGo.FindStringSubmatch(mdScanSlice); len(m) >= 2 {
			cmd := m[1]
			if hashIdx := strings.Index(cmd, " #"); hashIdx >= 0 {
				cmd = cmd[:hashIdx]
			}
			return strings.TrimSpace(cmd), true
		}
	}
	if reLicensePropFmtGo.MatchString(lowerProp) {
		if m := reLicenseHeadingFmtGo.FindStringSubmatch(mdScanSlice); len(m) >= 2 {
			lic := strings.TrimLeft(strings.TrimSpace(m[1]), "-* \t")
			return strings.TrimSpace(stripMarkdownLinksToLabelsLinearFmtGo(lic)), true
		}
		if m := reLicenseSpdxFmtGo.FindStringSubmatch(mdScanSlice); len(m) >= 2 {
			return strings.TrimSpace(m[1]), true
		}
	}
	return "", false
}

// FormatVCardToMarkdown formats RFC 6350 vCard (`BEGIN:VCARD`) contact payloads into clean Markdown.
func FormatVCardToMarkdown(raw string) *FormattedPayloadDoc {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	hasBegin := reBeginVCardFmtGo.MatchString(raw)
	unfolded := reUnfoldLinesFmtGo.ReplaceAllString(raw, "")
	fullName := ""
	var bullets []string
	vcardData := make(map[string]any)

	for _, rawLine := range strings.Split(strings.ReplaceAll(unfolded, "\r\n", "\n"), "\n") {
		colon := strings.IndexByte(rawLine, ':')
		if colon <= 0 {
			continue
		}
		keyPart := strings.ToUpper(strings.TrimSpace(strings.Split(rawLine[:colon], ";")[0]))
		val := reIcsNewlineFmtGo.ReplaceAllString(rawLine[colon+1:], ", ")
		val = reIcsEscapeFmtGo.ReplaceAllString(val, "$1")
		val = strings.TrimSpace(val)
		if val == "" || keyPart == "BEGIN" || keyPart == "END" || keyPart == "VERSION" || keyPart == "PRODID" {
			continue
		}
		switch keyPart {
		case "FN":
			if fullName == "" {
				fullName = val
				vcardData["fullName"] = val
			}
		case "TITLE":
			bullets = append(bullets, "- **Title**: "+escapeDeclMarkdownBrackets(val))
			vcardData["title"] = val
		case "ORG":
			org := strings.ReplaceAll(val, ";", " · ")
			bullets = append(bullets, "- **Organization**: "+escapeDeclMarkdownBrackets(org))
			vcardData["organization"] = org
		case "EMAIL":
			bullets = append(bullets, "- **Email**: "+escapeDeclMarkdownBrackets(val))
			vcardData["email"] = val
		case "TEL":
			bullets = append(bullets, "- **Phone**: "+escapeDeclMarkdownBrackets(val))
			vcardData["phone"] = val
		case "URL":
			bullets = append(bullets, "- **URL**: "+escapeDeclMarkdownBrackets(val))
			vcardData["url"] = val
		case "ADR":
			var parts []string
			for _, seg := range strings.Split(val, ";") {
				if s := strings.TrimSpace(seg); s != "" {
					parts = append(parts, s)
				}
			}
			if len(parts) > 0 {
				cleanAdr := strings.Join(parts, ", ")
				bullets = append(bullets, "- **Location**: "+escapeDeclMarkdownBrackets(cleanAdr))
				vcardData["location"] = cleanAdr
			}
		case "NOTE":
			bullets = append(bullets, "- **Note**: "+escapeDeclMarkdownBrackets(val))
			vcardData["note"] = val
		}
	}

	if !hasBegin && fullName == "" && len(bullets) == 0 {
		return nil
	}
	heading := "# Contact Card (vCard)"
	if fullName != "" {
		heading = "# " + escapeDeclMarkdownBrackets(fullName)
	}
	lines := append([]string{heading, ""}, bullets...)
	return &FormattedPayloadDoc{
		Title:      SanitizeScrapedMetadataField(fullName, 512),
		Markdown:   SanitizeScrapedMarkdown(strings.TrimSpace(strings.Join(lines, "\n"))),
		Structured: vcardData,
	}
}

// FormatICalendarToMarkdown formats RFC 5545 iCalendar (`BEGIN:VCALENDAR`) feeds into structured Markdown event summaries.
func FormatICalendarToMarkdown(raw string) *FormattedPayloadDoc {
	headCheck := truncateUTF8SafeFullDocGo(raw, 512)
	if !reBeginVCalendarFmtGo.MatchString(headCheck) {
		return nil
	}
	bounded := truncateUTF8SafeFullDocGo(raw, maxHTMLScanCharsFullDocGo)
	unfolded := reUnfoldLinesFmtGo.ReplaceAllString(bounded, "")
	upperUnfolded := strings.ToUpper(unfolded)

	formatIcsDate := func(v string) string {
		clean := strings.TrimSpace(v)
		m := reIcsDateFmtGo.FindStringSubmatch(clean)
		if len(m) < 4 {
			return clean
		}
		datePart := m[1] + "-" + m[2] + "-" + m[3]
		if m[4] == "" {
			return datePart
		}
		utc := ""
		if m[7] != "" {
			utc = " UTC"
		}
		return datePart + " " + m[4] + ":" + m[5] + utc
	}
	unescapeIcsVal := func(v string) string {
		s := reIcsNewlineFmtGo.ReplaceAllString(v, " ")
		s = reIcsEscapeFmtGo.ReplaceAllString(s, "$1")
		return strings.Join(strings.Fields(s), " ")
	}

	calName := ""
	calDesc := ""
	firstVeventIdx := strings.Index(upperUnfolded, "BEGIN:VEVENT")
	headerEnd := len(unfolded)
	if firstVeventIdx >= 0 {
		headerEnd = firstVeventIdx
	} else if headerEnd > 8192 {
		headerEnd = 8192
	}
	for _, line := range strings.Split(strings.ReplaceAll(unfolded[:headerEnd], "\r\n", "\n"), "\n") {
		colon := strings.IndexByte(line, ':')
		if colon <= 0 {
			continue
		}
		k := strings.ToUpper(strings.TrimSpace(strings.Split(line[:colon], ";")[0]))
		v := unescapeIcsVal(line[colon+1:])
		if (k == "X-WR-CALNAME" || k == "NAME") && v != "" && calName == "" {
			calName = v
		}
		if (k == "X-WR-CALDESC" || k == "DESCRIPTION") && v != "" && calDesc == "" {
			calDesc = v
		}
	}

	var eventSections []string
	var structuredEvents []map[string]any
	const beginMarker = "BEGIN:VEVENT"
	const endMarker = "END:VEVENT"
	scanPos := len(unfolded)
	if firstVeventIdx >= 0 {
		scanPos = firstVeventIdx
	}
	for scanPos < len(upperUnfolded) && len(eventSections) < 50 {
		relB := strings.Index(upperUnfolded[scanPos:], beginMarker)
		if relB < 0 {
			break
		}
		bIdx := scanPos + relB
		afterBegin := bIdx + len(beginMarker)
		if afterBegin < len(upperUnfolded) {
			nc := upperUnfolded[afterBegin]
			if nc != '\n' && nc != '\r' && nc != ' ' && nc != '\t' {
				scanPos = afterBegin
				continue
			}
		}
		relE := strings.Index(upperUnfolded[afterBegin:], endMarker)
		if relE < 0 {
			break
		}
		eIdx := afterBegin + relE
		if eIdx > len(unfolded) {
			break
		}
		eventBody := unfolded[afterBegin:eIdx]
		scanPos = eIdx + len(endMarker)

		var summary, dtStart, dtEnd, location, evURL, desc string
		for _, line := range strings.Split(strings.ReplaceAll(eventBody, "\r\n", "\n"), "\n") {
			colon := strings.IndexByte(line, ':')
			if colon <= 0 {
				continue
			}
			k := strings.ToUpper(strings.TrimSpace(strings.Split(line[:colon], ";")[0]))
			rawVal := strings.TrimSpace(line[colon+1:])
			if rawVal == "" {
				continue
			}
			switch k {
			case "SUMMARY":
				summary = unescapeIcsVal(rawVal)
			case "DTSTART":
				dtStart = formatIcsDate(rawVal)
			case "DTEND":
				dtEnd = formatIcsDate(rawVal)
			case "LOCATION":
				location = unescapeIcsVal(rawVal)
			case "URL":
				evURL = rawVal
			case "DESCRIPTION":
				desc = unescapeIcsVal(rawVal)
			}
		}
		evTitle := summary
		if evTitle == "" {
			evTitle = "Event " + strconv.Itoa(len(eventSections)+1)
		}
		var bullets []string
		if dtStart != "" {
			when := dtStart
			if dtEnd != "" && dtEnd != dtStart {
				when = dtStart + " → " + dtEnd
			}
			bullets = append(bullets, "- **When**: "+escapeDeclMarkdownBrackets(when))
		}
		if location != "" {
			bullets = append(bullets, "- **Location**: "+escapeDeclMarkdownBrackets(location))
		}
		lowURL := asciiLowerExtractString(evURL[:minInt(len(evURL), 8)])
		if strings.HasPrefix(lowURL, "https://") || strings.HasPrefix(lowURL, "http://") {
			bullets = append(bullets, "- **URL**: "+escapeDeclMarkdownBrackets(evURL))
		}
		if desc != "" {
			bullets = append(bullets, "- **Details**: "+escapeDeclMarkdownBrackets(truncateUTF8SafeFullDocGo(desc, 600)))
		}
		evLines := append([]string{"## " + escapeDeclMarkdownBrackets(evTitle)}, bullets...)
		eventSections = append(eventSections, strings.Join(evLines, "\n"))
		structuredEvents = append(structuredEvents, map[string]any{
			"summary":  evTitle,
			"dtStart":  dtStart,
			"dtEnd":    dtEnd,
			"location": location,
			"url":      evURL,
		})
	}

	if calName == "" && len(eventSections) == 0 {
		return nil
	}
	title := calName
	if title == "" {
		title = "Calendar Events"
	}
	blocks := []string{"# " + escapeDeclMarkdownBrackets(title)}
	if calDesc != "" && calDesc != title {
		blocks = append(blocks, escapeDeclMarkdownBlock(calDesc))
	}
	if len(eventSections) > 0 {
		blocks = append(blocks, strings.Join(eventSections, "\n\n"))
	}
	return &FormattedPayloadDoc{
		Title:       SanitizeScrapedMetadataField(title, 512),
		Description: SanitizeScrapedMetadataField(calDesc, 2000),
		Markdown:    SanitizeScrapedMarkdown(strings.Join(blocks, "\n\n")),
		Structured:  structuredEvents,
	}
}

// FormatGitPatchToMarkdown formats `git format-patch` and unified `.patch`/`.diff` payloads into clean Markdown
// with commit metadata bullets and a 4-tilde `diff` code fence.
func FormatGitPatchToMarkdown(raw, urlStr string) *FormattedPayloadDoc {
	isPatchURL := urlStr != "" && rePatchURLFmtGo.MatchString(urlStr)
	normalized := strings.ReplaceAll(raw, "\r\n", "\n")
	head := truncateUTF8SafeFullDocGo(normalized, 2048)
	isFormatPatch := reFormatPatchFromFmtGo.MatchString(head) && reFormatPatchSubjFmtGo.MatchString(head) && reDiffGitLineFmtGo.MatchString(normalized)
	isUnifiedDiff := reDiffGitAPrefixFmtGo.MatchString(head) ||
		(reUnifiedMinusFmtGo.MatchString(head) && reUnifiedPlusFmtGo.MatchString(head) && reUnifiedHunkFmtGo.MatchString(head))
	if !isPatchURL && !isFormatPatch && !isUnifiedDiff {
		return nil
	}
	trimmed := strings.TrimSpace(normalized)
	if trimmed == "" || reHTMLDocPrefixFmtGo.MatchString(trimmed) {
		return nil
	}

	commitSha := ""
	if m := reFormatPatchFromFmtGo.FindStringSubmatch(head); len(m) >= 2 {
		commitSha = m[1]
	}
	var author, date, subject, commitBody string
	diffBody := trimmed

	if isFormatPatch {
		if loc := reDiffGitLineFmtGo.FindStringIndex(normalized); len(loc) == 2 && loc[0] > 0 {
			diffIdx := loc[0]
			preamble := normalized[:diffIdx]
			blankIdx := strings.Index(preamble, "\n\n")
			rawHeaders := preamble
			if blankIdx > 0 {
				rawHeaders = preamble[:blankIdx]
			}
			rawHeaders = reUnfoldLinesFmtGo.ReplaceAllString(rawHeaders, " ")
			for _, hLine := range strings.Split(rawHeaders, "\n") {
				lowH := asciiLowerExtractString(hLine[:minInt(len(hLine), 9)])
				if strings.HasPrefix(lowH, "from:") {
					author = strings.TrimSpace(hLine[5:])
				} else if strings.HasPrefix(lowH, "date:") {
					date = strings.TrimSpace(hLine[5:])
				} else if strings.HasPrefix(lowH, "subject:") {
					subjRaw := strings.TrimSpace(hLine[8:])
					subject = strings.TrimSpace(rePatchPrefixBracketFmtGo.ReplaceAllString(subjRaw, ""))
				}
			}
			if blankIdx > 0 {
				commitBody = strings.TrimSpace(rePatchStatSeparatorFmtGo.ReplaceAllString(preamble[blankIdx+2:], ""))
			}
			diffBody = strings.TrimRight(normalized[diffIdx:], " \t\r\n")
		}
	}

	fallbackTitle := "Git Patch"
	if urlStr != "" {
		if u, err := url.Parse(urlStr); err == nil && (u.Scheme == "https" || u.Scheme == "http") && u.Host != "" {
			var parts []string
			for _, p := range strings.Split(u.Path, "/") {
				if p != "" {
					parts = append(parts, p)
				}
			}
			if strings.EqualFold(u.Hostname(), "github.com") && len(parts) >= 4 && parts[2] == "commit" {
				cleanSha := strings.TrimSuffix(strings.TrimSuffix(parts[3], ".patch"), ".diff")
				if commitSha == "" && reHexShaFmtGo.MatchString(cleanSha) {
					commitSha = cleanSha
				}
				shortSha := cleanSha
				if len(shortSha) > 10 {
					shortSha = shortSha[:10]
				}
				fallbackTitle = parts[0] + "/" + parts[1] + "@" + shortSha
			} else if len(parts) > 0 {
				fallbackTitle = safeDecodeURIComponentFmtGo(parts[len(parts)-1])
			}
		} else if lowU := strings.ToLower(urlStr); strings.HasPrefix(lowU, "https://") || strings.HasPrefix(lowU, "http://") {
			rest := urlStr[strings.Index(urlStr, "://")+3:]
			if qIdx := strings.IndexAny(rest, "?#"); qIdx >= 0 {
				rest = rest[:qIdx]
			}
			if slashIdx := strings.IndexByte(rest, '/'); slashIdx >= 0 {
				pathPart := strings.Trim(rest[slashIdx+1:], "/")
				if pathPart != "" {
					segs := strings.Split(pathPart, "/")
					fallbackTitle = safeDecodeURIComponentFmtGo(segs[len(segs)-1])
				}
			}
		}
	}

	title := subject
	if title == "" {
		title = fallbackTitle
	}
	safeTitle := SanitizeScrapedMetadataField(title, 512)
	if safeTitle == "" {
		safeTitle = "Git Patch"
	}
	safeAuthor := SanitizeScrapedMeta(author)
	safeDate := SanitizeScrapedMeta(date)
	var metaBullets []string
	if commitSha != "" {
		shortCommit := commitSha
		if len(shortCommit) > 12 {
			shortCommit = shortCommit[:12]
		}
		safeCommit := sanitizeDeclInlineCodeVal(SanitizeScrapedMeta(shortCommit))
		metaBullets = append(metaBullets, "- **Commit**: `"+safeCommit+"`")
	}
	if safeAuthor != "" {
		metaBullets = append(metaBullets, "- **Author**: "+escapeDeclMarkdownBrackets(safeAuthor))
	}
	if safeDate != "" {
		metaBullets = append(metaBullets, "- **Date**: "+escapeDeclMarkdownBrackets(safeDate))
	}

	sections := []string{"# " + escapeDeclMarkdownBrackets(safeTitle)}
	if len(metaBullets) > 0 {
		sections = append(sections, strings.Join(metaBullets, "\n"))
	}
	if commitBody != "" {
		if safeCommitBody := SanitizeMarkdownWithOptions(commitBody, "", false); safeCommitBody != "" {
			sections = append(sections, safeCommitBody)
		}
	}
	sections = append(sections, MakeSafeCodeFence(diffBody, "diff", true))

	desc := ""
	if commitBody != "" {
		firstLine := strings.TrimSpace(strings.Split(commitBody, "\n")[0])
		desc = SanitizeScrapedMetadataField(escapeDeclMarkdownBrackets(firstLine), 280)
	}
	return &FormattedPayloadDoc{
		Title:       safeTitle,
		Description: desc,
		Markdown:    strings.Join(sections, "\n\n"),
	}
}

// FormatSourceCodeURLToMarkdown wraps raw source-code and configuration files (`Cargo.toml`, `.yaml`, `.rs`, `.go`, `.py`, `.ts`, `Dockerfile`, `Makefile`, etc.)
// served as plain text into fenced Markdown code blocks with accurate filename/package titles.
func FormatSourceCodeURLToMarkdown(raw, urlStr, contentType string) *FormattedPayloadDoc {
	if urlStr == "" {
		return nil
	}
	ctLower := strings.ToLower(contentType)
	if strings.Contains(ctLower, "html") || strings.Contains(ctLower, "markdown") ||
		strings.Contains(ctLower, "json") || strings.Contains(ctLower, "csv") {
		return nil
	}
	u, err := url.Parse(urlStr)
	if err != nil {
		return nil
	}
	var parts []string
	for _, p := range strings.Split(u.Path, "/") {
		if p != "" {
			parts = append(parts, p)
		}
	}
	if len(parts) == 0 {
		return nil
	}
	baseName := safeDecodeURIComponentFmtGo(parts[len(parts)-1])
	lowerBase := strings.ToLower(baseName)
	lang := ""
	switch {
	case lowerBase == "dockerfile" || strings.HasPrefix(lowerBase, "dockerfile."):
		lang = "dockerfile"
	case lowerBase == "makefile" || lowerBase == "gnumakefile":
		lang = "makefile"
	case lowerBase == "cmakelists.txt":
		lang = "cmake"
	case lowerBase == "go.mod" || lowerBase == "go.sum":
		lang = "go"
	default:
		if dot := strings.LastIndexByte(lowerBase, '.'); dot >= 0 && dot+1 < len(lowerBase) {
			lang = rawSourceExtLangMapFmtGo[lowerBase[dot+1:]]
		}
	}
	if lang == "" {
		return nil
	}

	trimmed := strings.TrimRight(strings.ReplaceAll(raw, "\r\n", "\n"), " \t\r\n")
	if strings.TrimSpace(trimmed) == "" || reHTMLDocPrefixFmtGo.MatchString(trimmed) {
		return nil
	}

	title := baseName
	if strings.EqualFold(u.Hostname(), "raw.githubusercontent.com") && len(parts) >= 4 {
		owner := parts[0]
		repo := parts[1]
		rest := parts[2:]
		var filePath string
		if len(rest) >= 4 && rest[0] == "refs" && (rest[1] == "heads" || rest[1] == "tags") {
			filePath = strings.Join(rest[3:], "/")
		} else {
			filePath = strings.Join(rest[1:], "/")
		}
		if filePath != "" {
			title = owner + "/" + repo + "/" + filePath
		}
	} else if len(parts) >= 2 {
		title = safeDecodeURIComponentFmtGo(parts[len(parts)-2]) + "/" + baseName
	}

	description := ""
	if lowerBase == "cargo.toml" || lowerBase == "pyproject.toml" {
		pkgName := ""
		if m := reTomlNameFmtGo.FindStringSubmatch(trimmed); len(m) >= 2 {
			pkgName = m[1]
		}
		pkgVer := ""
		if m := reTomlVersionFmtGo.FindStringSubmatch(trimmed); len(m) >= 2 {
			pkgVer = m[1]
		}
		pkgDesc := ""
		if m := reTomlDescFmtGo.FindStringSubmatch(trimmed); len(m) >= 4 {
			rawPkgDesc := firstNonEmptyFullDocGo(m[1], m[2], m[3])
			rawPkgDesc = strings.Join(strings.Fields(rawPkgDesc), " ")
			pkgDesc = truncateUTF8SafeFullDocGo(rawPkgDesc, 220)
		}
		var summaryParts []string
		if pkgName != "" && pkgVer != "" {
			summaryParts = append(summaryParts, pkgName+"@"+pkgVer)
		} else if pkgName != "" {
			summaryParts = append(summaryParts, pkgName)
		}
		if pkgDesc != "" {
			summaryParts = append(summaryParts, pkgDesc)
		}
		if len(summaryParts) > 0 {
			description = strings.Join(summaryParts, " — ")
		}
	}

	safeTitle := SanitizeScrapedMetadataField(title, 512)
	if safeTitle == "" {
		safeTitle = SanitizeScrapedMetadataField(baseName, 512)
	}
	safeDesc := SanitizeScrapedMetadataField(escapeDeclMarkdownBrackets(description), 512)
	return &FormattedPayloadDoc{
		Title:       safeTitle,
		Description: safeDesc,
		Markdown:    "# " + escapeDeclMarkdownBrackets(safeTitle) + "\n\n" + MakeSafeCodeFence(trimmed, lang, false),
	}
}

func unwrapXMLTextFmtGo(raw string) string {
	if raw == "" {
		return ""
	}
	if !strings.Contains(raw, "<![CDATA[") {
		return strings.TrimSpace(DecodeHTMLEntities(raw))
	}
	var out strings.Builder
	pos := 0
	for pos < len(raw) {
		relStart := strings.Index(raw[pos:], "<![CDATA[")
		if relStart < 0 {
			out.WriteString(DecodeHTMLEntities(raw[pos:]))
			break
		}
		start := pos + relStart
		if start > pos {
			out.WriteString(DecodeHTMLEntities(raw[pos:start]))
		}
		relEnd := strings.Index(raw[start+9:], "]]>")
		if relEnd < 0 {
			out.WriteString(raw[start+9:])
			break
		}
		end := start + 9 + relEnd
		out.WriteString(raw[start+9 : end])
		pos = end + 3
	}
	return strings.TrimSpace(out.String())
}

func matchFirstXMLTagFmtGo(block string, tagNames []string) string {
	lowerBlock := asciiLowerExtractString(block)
	for _, tag := range tagNames {
		tagLower := strings.ToLower(tag)
		openNeedle := "<" + tagLower
		closeNeedle := "</" + tagLower
		pos := 0
		for pos < len(lowerBlock) {
			relOpen := strings.Index(lowerBlock[pos:], openNeedle)
			if relOpen < 0 {
				break
			}
			openIdx := pos + relOpen
			afterName := openIdx + len(openNeedle)
			if afterName < len(lowerBlock) && !isTagNameBoundaryByteFullDocGo(lowerBlock[afterName]) {
				pos = afterName
				continue
			}
			relGt := strings.IndexByte(lowerBlock[afterName:], '>')
			if relGt < 0 {
				break
			}
			openGt := afterName + relGt
			if openGt > 0 && lowerBlock[openGt-1] == '/' {
				pos = openGt + 1
				continue
			}
			relClose := strings.Index(lowerBlock[openGt+1:], closeNeedle)
			if relClose < 0 {
				break
			}
			closeIdx := openGt + 1 + relClose
			afterClose := closeIdx + len(closeNeedle)
			if afterClose < len(lowerBlock) && !isTagNameBoundaryByteFullDocGo(lowerBlock[afterClose]) {
				pos = afterClose
				continue
			}
			inner := block[openGt+1 : closeIdx]
			if strings.TrimSpace(inner) != "" {
				return unwrapXMLTextFmtGo(inner)
			}
			pos = afterClose
		}
	}
	return ""
}

// FormatFeedXMLToMarkdown formats RSS 2.0, RDF, and Atom XML feeds into structured Markdown with per-item headings,
// public HTTPS links, publication dates, and summaries.
func FormatFeedXMLToMarkdown(raw, baseURL string) (doc *FormattedPayloadDoc, links []string) {
	if raw == "" {
		return nil, nil
	}
	boundedXML := truncateUTF8SafeFullDocGo(raw, 4*1024*1024)
	headLower := asciiLowerExtractString(boundedXML[:minInt(len(boundedXML), 1200)])
	hasRssRoot := strings.Contains(headLower, "<rss") || strings.Contains(headLower, "<rdf:rdf")
	hasAtomRoot := strings.Contains(headLower, "<feed")
	if !hasRssRoot && !hasAtomRoot {
		return nil, nil
	}

	lowerXML := asciiLowerExtractString(boundedXML)
	isRss := hasRssRoot && strings.Contains(lowerXML, "<item")
	isAtom := !isRss && hasAtomRoot && strings.Contains(lowerXML, "<entry")
	if !isRss && !isAtom {
		return nil, nil
	}

	openNeedle := "<item"
	closeNeedle := "</item>"
	if isAtom {
		openNeedle = "<entry"
		closeNeedle = "</entry>"
	}
	firstItemIdx := strings.Index(lowerXML, openNeedle)
	headerLim := 1200
	if firstItemIdx > 0 {
		headerLim = minInt(firstItemIdx, 32768)
	}
	if headerLim > len(boundedXML) {
		headerLim = len(boundedXML)
	}
	channelHeader := boundedXML[:headerLim]
	feedTitle := cleanInlineHTMLFullDocGo(matchFirstXMLTagFmtGo(channelHeader, []string{"title"}))
	feedDesc := cleanInlineHTMLFullDocGo(matchFirstXMLTagFmtGo(channelHeader, []string{"description", "subtitle"}))

	var lines []string
	if feedTitle != "" {
		lines = append(lines, "# "+escapeDeclMarkdownBrackets(feedTitle))
	}
	if feedDesc != "" && feedDesc != feedTitle {
		lines = append(lines, escapeDeclMarkdownBlock(feedDesc))
	}

	links = make([]string, 0)
	seenLinks := make(map[string]bool)
	count := 0
	searchPos := len(boundedXML)
	if firstItemIdx >= 0 {
		searchPos = firstItemIdx
	}

	for searchPos < len(lowerXML) && count < 40 {
		relOpen := strings.Index(lowerXML[searchPos:], openNeedle)
		if relOpen < 0 {
			break
		}
		openIdx := searchPos + relOpen
		afterName := openIdx + len(openNeedle)
		if afterName < len(lowerXML) && !isTagNameBoundaryByteFullDocGo(lowerXML[afterName]) {
			searchPos = afterName
			continue
		}
		relGt := strings.IndexByte(lowerXML[afterName:], '>')
		if relGt < 0 {
			break
		}
		openGt := afterName + relGt
		if openGt > 0 && lowerXML[openGt-1] == '/' {
			searchPos = openGt + 1
			continue
		}
		relClose := strings.Index(lowerXML[openGt+1:], closeNeedle)
		if relClose < 0 {
			break
		}
		closeIdx := openGt + 1 + relClose
		block := boundedXML[openGt+1 : closeIdx]
		searchPos = closeIdx + len(closeNeedle)

		itemTitle := cleanInlineHTMLFullDocGo(matchFirstXMLTagFmtGo(block, []string{"title"}))
		if itemTitle == "" {
			itemTitle = "Entry " + strconv.Itoa(count+1)
		}
		rawLink := ""
		if isAtom {
			altHref := ""
			anyHref := ""
			scanHTMLTagsLinearFullDocGo(block, func(tag scannedTagFullDocGo) bool {
				if tag.isClosing || tag.tagNameLower != "link" {
					return true
				}
				attrs := parseTagAttrsFullDocGo(tag.attrs)
				hrefVal := strings.TrimSpace(attrs["href"])
				if hrefVal == "" {
					return true
				}
				if anyHref == "" {
					anyHref = hrefVal
				}
				relVal := strings.ToLower(strings.TrimSpace(attrs["rel"]))
				if relVal == "" || relVal == "alternate" {
					altHref = hrefVal
					return false
				}
				return true
			}, minInt(len(block), 65536), false)
			if altHref != "" {
				rawLink = strings.TrimSpace(DecodeHTMLEntities(altHref))
			} else {
				rawLink = strings.TrimSpace(DecodeHTMLEntities(anyHref))
			}
		} else {
			rawLink = matchFirstXMLTagFmtGo(block, []string{"link"})
			if rawLink == "" {
				guid := matchFirstXMLTagFmtGo(block, []string{"guid"})
				lowG := asciiLowerExtractString(guid[:minInt(len(guid), 8)])
				if strings.HasPrefix(lowG, "https://") || strings.HasPrefix(lowG, "http://") {
					rawLink = guid
				}
			}
		}
		resolvedLink := resolveHTTPSHrefFullDocGo(rawLink, baseURL, false)
		if resolvedLink != "" && (!isSafePublicHTTPSFeedURL(resolvedLink) || strings.ContainsAny(resolvedLink, " \t\r\n<>()")) {
			resolvedLink = ""
		}
		if resolvedLink != "" && !seenLinks[resolvedLink] {
			seenLinks[resolvedLink] = true
			links = append(links, resolvedLink)
		}

		pubDate := cleanInlineHTMLFullDocGo(matchFirstXMLTagFmtGo(block, []string{"pubDate", "published", "updated", "dc:date"}))
		rawContent := matchFirstXMLTagFmtGo(block, []string{"content:encoded", "content", "description", "summary"})
		bodyMD := ""
		if rawContent != "" {
			if reFeedHTMLBlockFmtGo.MatchString(rawContent) {
				itemBase := resolvedLink
				if itemBase == "" {
					itemBase = baseURL
				}
				bodyMD = ExtractHTMLDocumentFull(rawContent, FullExtractOptions{
					BaseURL:         itemBase,
					OnlyMainContent: false,
					IncludeImages:   false,
				}).Markdown
			} else {
				bodyMD = escapeDeclMarkdownBlock(cleanInlineHTMLFullDocGo(rawContent))
			}
			if len(bodyMD) > 1800 {
				cut := strings.LastIndexByte(bodyMD[:1800], ' ')
				if cut <= 900 {
					cut = 1800
				}
				bodyMD = strings.TrimRightFunc(truncateUTF8SafeFullDocGo(bodyMD, cut), unicode.IsSpace) + "..."
			}
		}

		safeItemTitle := escapeDeclMarkdownBrackets(itemTitle)
		heading := "## " + safeItemTitle
		if resolvedLink != "" {
			heading = "## [" + safeItemTitle + "](" + resolvedLink + ")"
		}
		parts := []string{heading}
		if pubDate != "" {
			safePubDate := strings.ReplaceAll(escapeDeclMarkdownBrackets(pubDate), "*", `\*`)
			parts = append(parts, "*"+safePubDate+"*")
		}
		if bodyMD != "" {
			parts = append(parts, bodyMD)
		}
		lines = append(lines, strings.Join(parts, "\n\n"))
		count++
	}

	if count == 0 {
		return nil, nil
	}
	return &FormattedPayloadDoc{
		Title:       feedTitle,
		Description: feedDesc,
		Markdown:    strings.Join(lines, "\n\n"),
	}, links
}

// FormatDelimitedTableToMarkdown formats RFC 4180 CSV and TSV payloads into a clean GFM Markdown table
// with column preview and row count summary.
func FormatDelimitedTableToMarkdown(raw, sep, titleHint string) *FormattedPayloadDoc {
	trimmed := strings.TrimSpace(strings.TrimPrefix(raw, "\ufeff"))
	if trimmed == "" || trimmed[0] == '<' || trimmed[0] == '{' || trimmed[0] == '[' {
		return nil
	}

	var delimiter byte
	lowSep := strings.ToLower(strings.TrimSpace(sep))
	lowHint := strings.ToLower(strings.TrimSpace(titleHint))
	switch {
	case sep == "\t" || lowSep == "tsv" || strings.Contains(lowSep, "tab-separated") || strings.Contains(lowSep, "text/tsv"):
		delimiter = '\t'
	case len(sep) == 1 && (sep[0] == ',' || sep[0] == ';' || sep[0] == '|'):
		delimiter = sep[0]
	case strings.Contains(lowSep, "csv"):
		delimiter = ','
	case strings.HasSuffix(strings.Split(lowHint, "?")[0], ".tsv"):
		delimiter = '\t'
	case strings.HasSuffix(strings.Split(lowHint, "?")[0], ".csv"):
		delimiter = ','
	case sep == "":
		firstNL := strings.IndexByte(trimmed, '\n')
		firstLine := trimmed
		if firstNL >= 0 {
			firstLine = trimmed[:firstNL]
		}
		if strings.IndexByte(firstLine, '\t') >= 0 {
			delimiter = '\t'
		} else {
			delimiter = ','
		}
	default:
		return nil
	}

	var rows [][]string
	totalNonEmptyRows := 0
	var curRow []string
	var curField strings.Builder
	inQuotes := false
	n := len(trimmed)

	commitRow := func() {
		curRow = append(curRow, curField.String())
		curField.Reset()
		hasContent := false
		for _, cell := range curRow {
			if strings.TrimSpace(cell) != "" {
				hasContent = true
				break
			}
		}
		if hasContent {
			totalNonEmptyRows++
			if len(rows) <= maxMarkdownCSVRowsFmtGo {
				rows = append(rows, curRow)
			}
		}
		curRow = nil
	}

	for i := 0; i < n; i++ {
		ch := trimmed[i]
		if inQuotes {
			if ch == '"' {
				if i+1 < n && trimmed[i+1] == '"' {
					curField.WriteByte('"')
					i++
				} else {
					inQuotes = false
				}
			} else {
				curField.WriteByte(ch)
			}
		} else if ch == '"' && curField.Len() == 0 {
			inQuotes = true
		} else if ch == delimiter {
			if len(rows) <= maxMarkdownCSVRowsFmtGo {
				curRow = append(curRow, curField.String())
			}
			curField.Reset()
		} else if ch == '\r' {
			if i+1 < n && trimmed[i+1] == '\n' {
				i++
			}
			commitRow()
		} else if ch == '\n' {
			commitRow()
		} else if len(rows) <= maxMarkdownCSVRowsFmtGo || curField.Len() == 0 {
			curField.WriteByte(ch)
		}
	}
	if curField.Len() > 0 || len(curRow) > 0 {
		commitRow()
	}

	if len(rows) < 2 {
		return nil
	}
	colCount := 0
	for _, r := range rows {
		if len(r) > colCount {
			colCount = len(r)
		}
	}
	if colCount > 64 {
		colCount = 64
	}
	if colCount < 2 {
		return nil
	}

	dataRowCount := totalNonEmptyRows - 1
	if dataRowCount < 0 {
		dataRowCount = 0
	}

	title := ""
	trimmedHint := strings.TrimSpace(titleHint)
	if strings.HasPrefix(lowHint, "https://") || strings.HasPrefix(lowHint, "http://") {
		if u, err := url.Parse(trimmedHint); err == nil {
			segs := strings.Split(strings.Trim(u.Path, "/"), "/")
			if len(segs) > 0 && segs[len(segs)-1] != "" {
				title = safeDecodeURIComponentFmtGo(segs[len(segs)-1])
			}
		}
	} else if trimmedHint != "" {
		title = trimmedHint
	}
	if title == "" {
		if delimiter == '\t' {
			title = "Tabular Dataset (TSV)"
		} else {
			title = "Tabular Dataset (CSV)"
		}
	}

	safeTitle := SanitizeScrapedMetadataField(title, 512)
	if safeTitle == "" {
		if delimiter == '\t' {
			safeTitle = "Tabular Dataset (TSV)"
		} else {
			safeTitle = "Tabular Dataset (CSV)"
		}
	}

	formatRawCell := func(rawCell string) string {
		return SanitizeScrapedMeta(rawCell)
	}
	formatCell := func(rawCell string) string {
		s := escapeDeclMarkdownBrackets(formatRawCell(rawCell))
		return strings.ReplaceAll(s, "|", `\|`)
	}
	padRow := func(r []string) []string {
		out := make([]string, colCount)
		for i := 0; i < colCount; i++ {
			if i < len(r) {
				out[i] = formatCell(r[i])
			}
		}
		return out
	}

	headerCells := padRow(rows[0])
	rawHeaderCells := make([]string, colCount)
	for i := range headerCells {
		if i < len(rows[0]) {
			rawHeaderCells[i] = formatRawCell(rows[0][i])
		}
		if headerCells[i] == "" {
			headerCells[i] = "col_" + strconv.Itoa(i+1)
			rawHeaderCells[i] = headerCells[i]
		}
	}
	previewLim := colCount
	if previewLim > 8 {
		previewLim = 8
	}
	previewCols := make([]string, previewLim)
	for i := 0; i < previewLim; i++ {
		previewCols[i] = "`" + sanitizeDeclInlineCodeVal(escapeDeclMarkdownBrackets(rawHeaderCells[i])) + "`"
	}
	ellipsis := ""
	if colCount > 8 {
		ellipsis = ", …"
	}
	summaryLine := formatIntComma(int64(dataRowCount)) + " rows × " + strconv.Itoa(colCount) + " columns (" + strings.Join(previewCols, ", ") + ellipsis + ")"

	sepCells := make([]string, colCount)
	for i := range sepCells {
		sepCells[i] = "---"
	}
	renderedDataRows := rows[1:]
	if len(renderedDataRows) > maxMarkdownCSVRowsFmtGo {
		renderedDataRows = renderedDataRows[:maxMarkdownCSVRowsFmtGo]
	}
	tableLines := make([]string, 0, len(renderedDataRows)+2)
	tableLines = append(tableLines, "| "+strings.Join(headerCells, " | ")+" |")
	tableLines = append(tableLines, "| "+strings.Join(sepCells, " | ")+" |")
	for _, r := range renderedDataRows {
		tableLines = append(tableLines, "| "+strings.Join(padRow(r), " | ")+" |")
	}

	blocks := []string{"# " + escapeDeclMarkdownBrackets(safeTitle), summaryLine, strings.Join(tableLines, "\n")}
	if dataRowCount > len(renderedDataRows) {
		fmtKind := "CSV"
		if delimiter == '\t' {
			fmtKind = "TSV"
		}
		blocks = append(blocks, "_Showing first "+formatIntComma(int64(len(renderedDataRows)))+" of "+formatIntComma(int64(dataRowCount))+" rows (full raw "+fmtKind+" available via `artifactId`)._")
	}

	return &FormattedPayloadDoc{
		Title:       safeTitle,
		Description: SanitizeScrapedMetadataField(summaryLine, 512),
		Markdown:    strings.Join(blocks, "\n\n"),
		Structured: map[string]any{
			"rowCount":    dataRowCount,
			"columnCount": colCount,
			"columns":     headerCells,
		},
	}
}

func hasPDFMagicHeaderFmtGo(data []byte) bool {
	return IsPDFBytes(data)
}

// DetectUnsupportedBinaryPayload inspects `contentType`, magic headers, UTF-8/control-byte ratios, and URL extensions
// to reject binary archives, images, audio/video, fonts, and executables from Markdown text extraction.
func DetectUnsupportedBinaryPayload(data []byte, contentType, urlStr string) (unsupported bool, mimeLabel, reason string) {
	ct := strings.ToLower(strings.TrimSpace(strings.Split(contentType, ";")[0]))
	if ct == "application/pdf" || hasPDFMagicHeaderFmtGo(data) {
		return false, "", ""
	}
	if ct != "" {
		isMedia := (strings.HasPrefix(ct, "image/") && ct != "image/svg+xml") ||
			strings.HasPrefix(ct, "audio/") ||
			strings.HasPrefix(ct, "video/") ||
			strings.HasPrefix(ct, "font/")
		if isMedia || reBinaryAppMimeFmtGo.MatchString(ct) {
			return true, ct, fmt.Sprintf("Unsupported binary content-type %q for Markdown extraction", ct)
		}
	}

	sample := data
	if len(sample) > 2048 {
		sample = sample[:2048]
	}
	if len(sample) > 0 {
		detectedMime := ""
		switch {
		case len(sample) >= 2 && sample[0] == 0x1F && sample[1] == 0x8B:
			detectedMime = "application/gzip"
		case len(sample) >= 4 && bytes.HasPrefix(sample, []byte("PK\x03\x04")):
			detectedMime = "application/zip"
		case len(sample) >= 4 && bytes.HasPrefix(sample, []byte("\x89PNG")):
			detectedMime = "image/png"
		case len(sample) >= 3 && sample[0] == 0xFF && sample[1] == 0xD8 && sample[2] == 0xFF:
			detectedMime = "image/jpeg"
		case len(sample) >= 6 && (bytes.HasPrefix(sample, []byte("GIF87a")) || bytes.HasPrefix(sample, []byte("GIF89a"))):
			detectedMime = "image/gif"
		case len(sample) >= 12 && bytes.HasPrefix(sample, []byte("RIFF")) && bytes.Equal(sample[8:12], []byte("WEBP")):
			detectedMime = "image/webp"
		case len(sample) >= 4 && bytes.HasPrefix(sample, []byte("\x00asm")):
			detectedMime = "application/wasm"
		case len(sample) >= 4 && bytes.HasPrefix(sample, []byte("\x7fELF")):
			detectedMime = "application/x-executable"
		}
		if detectedMime != "" {
			label := ct
			if label == "" {
				label = detectedMime
			}
			ctSuffix := ""
			if ct != "" {
				ctSuffix = " (" + ct + ")"
			}
			return true, label, "Unsupported binary archive or media payload" + ctSuffix
		}

		nulCount := 0
		badCtrlCount := 0
		i := 0
		for i < len(sample) {
			b := sample[i]
			if b == 0 {
				nulCount++
				badCtrlCount++
				i++
				continue
			}
			if (b > 0 && b < 9) || (b > 13 && b < 32 && b != 27) {
				badCtrlCount++
				i++
				continue
			}
			if b >= 0x80 {
				r, w := utf8.DecodeRune(sample[i:])
				if r == utf8.RuneError && w == 1 {
					// Ignore trailing incomplete multi-byte UTF-8 sequence right at the 2048-byte boundary.
					if i+4 <= len(sample) || len(data) <= 2048 {
						badCtrlCount++
					}
				}
				i += w
				continue
			}
			i++
		}
		if nulCount >= 2 || (len(sample) >= 16 && float64(badCtrlCount)/float64(len(sample)) > 0.1) {
			label := ct
			if label == "" {
				label = "application/octet-stream"
			}
			ctSuffix := ""
			if ct != "" {
				ctSuffix = " (" + ct + ")"
			}
			return true, label, "Unsupported binary payload" + ctSuffix + " for Markdown extraction"
		}
	}

	if urlStr != "" && len(bytes.TrimSpace(sample)) == 0 {
		if u, err := url.Parse(urlStr); err == nil {
			p := strings.ToLower(u.Path)
			if !strings.HasSuffix(p, ".xml.gz") && reBinaryURLExtFmtGo.MatchString(p) {
				label := ct
				if label == "" {
					label = "application/octet-stream"
				}
				return true, label, "Unsupported binary URL extension for Markdown extraction"
			}
		}
	}

	return false, "", ""
}

// DeriveQuickMarkdownFromRawBytes synchronously derives clean Markdown from raw UTF-8 payload bytes
// (HTML, vCard, iCalendar, RSS/Atom XML, JSON/Jupyter/OpenAPI, CSV/TSV, Git patch, raw source code, or Markdown).
func DeriveQuickMarkdownFromRawBytes(data []byte, baseURL string) string {
	if len(data) == 0 || hasPDFMagicHeaderFmtGo(data) || !utf8.Valid(data) {
		return ""
	}
	if unsup, _, _ := DetectUnsupportedBinaryPayload(data, "", baseURL); unsup {
		return ""
	}
	rawText := string(data)
	if reQuickHTMLDetectFmtGo.MatchString(rawText) {
		return ExtractHTMLDocumentFull(rawText, FullExtractOptions{
			BaseURL:         baseURL,
			OnlyMainContent: true,
			IncludeImages:   true,
		}).Markdown
	}
	trimmed := strings.TrimSpace(rawText)
	if reBeginVCardFmtGo.MatchString(trimmed) {
		if vc := FormatVCardToMarkdown(rawText); vc != nil {
			return vc.Markdown
		}
	}
	if ics := FormatICalendarToMarkdown(rawText); ics != nil {
		return ics.Markdown
	}
	if feedDoc, _ := FormatFeedXMLToMarkdown(rawText, baseURL); feedDoc != nil {
		return feedDoc.Markdown
	}
	if strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[") {
		if jsonDoc := TryParseJSONPayloadForScrape(rawText, baseURL); jsonDoc != nil {
			return jsonDoc.Markdown
		}
	}
	lowURL := strings.ToLower(strings.Split(baseURL, "?")[0])
	if strings.HasSuffix(lowURL, ".csv") || strings.HasSuffix(lowURL, ".tsv") {
		if csvDoc := FormatDelimitedTableToMarkdown(rawText, "", baseURL); csvDoc != nil {
			return csvDoc.Markdown
		}
	}
	if patchDoc := FormatGitPatchToMarkdown(rawText, baseURL); patchDoc != nil {
		return patchDoc.Markdown
	}
	if strings.Contains(trimmed, "openapi:") || strings.Contains(trimmed, "swagger:") {
		if oaDoc := FormatOpenAPISpecToMarkdown(rawText, baseURL); oaDoc != nil {
			return oaDoc.Markdown
		}
	}
	if srcDoc := FormatSourceCodeURLToMarkdown(rawText, baseURL, ""); srcDoc != nil {
		return srcDoc.Markdown
	}
	_, _, fmBody := ParseMarkdownFrontmatter(truncateUTF8SafeFullDocGo(trimmed, maxHTMLScanCharsFullDocGo))
	return strings.TrimSpace(SanitizeMarkdownWithOptions(fmBody, baseURL, false))
}

func joinIpynbLinesFmtGo(val any) string {
	switch v := val.(type) {
	case string:
		return v
	case []any:
		var sb strings.Builder
		for _, item := range v {
			if s, ok := item.(string); ok {
				sb.WriteString(s)
			}
		}
		return sb.String()
	default:
		return ""
	}
}

func deriveFallbackTitleFromURLFmtGo(urlStr string) string {
	s := strings.TrimSpace(urlStr)
	if s == "" {
		return ""
	}
	if strings.HasPrefix(strings.ToLower(s), "https://") || strings.HasPrefix(strings.ToLower(s), "http://") {
		if u, err := url.Parse(s); err == nil {
			segs := strings.Split(strings.Trim(u.Path, "/"), "/")
			if len(segs) > 0 && segs[len(segs)-1] != "" {
				return safeDecodeURIComponentFmtGo(segs[len(segs)-1])
			}
		}
		return ""
	}
	return s
}

func formatParsedJupyterNotebookFmtGo(parsed any, fallbackTitle string) *FormattedPayloadDoc {
	nb, ok := parsed.(map[string]any)
	if !ok {
		return nil
	}
	var cellsRaw []any
	hasDirectCells := false
	if c, isArr := nb["cells"].([]any); isArr {
		cellsRaw = c
		hasDirectCells = true
	} else if ws, isArr := nb["worksheets"].([]any); isArr && len(ws) > 0 {
		if ws0, isMap := ws[0].(map[string]any); isMap {
			cellsRaw, _ = ws0["cells"].([]any)
		}
	}
	if cellsRaw == nil || (!isNumericTypeFmtGo(nb["nbformat"]) && !hasDirectCells) {
		return nil
	}

	meta, _ := nb["metadata"].(map[string]any)
	kernelspec, _ := meta["kernelspec"].(map[string]any)
	langInfo, _ := meta["language_info"].(map[string]any)
	rawLang, _ := kernelspec["language"].(string)
	if rawLang == "" {
		rawLang, _ = langInfo["name"].(string)
	}
	if rawLang == "" {
		rawLang = "python"
	}
	fenceLang := normalizeFenceLangFullDocGo(rawLang)
	if fenceLang == "" {
		fenceLang = "python"
	}

	title := ""
	if mt, ok := meta["title"].(string); ok && strings.TrimSpace(mt) != "" {
		title = SanitizeScrapedMetadataField(mt, 512)
	}
	description := ""
	var blocks []string

	for _, rawCell := range cellsRaw {
		cell, isMap := rawCell.(map[string]any)
		if !isMap {
			continue
		}
		cellType, _ := cell["cell_type"].(string)
		src := strings.TrimRight(strings.ReplaceAll(joinIpynbLinesFmtGo(cell["source"]), "\r\n", "\n"), " \t\r\n")
		if strings.TrimSpace(src) == "" {
			continue
		}

		switch cellType {
		case "markdown":
			trimmedMD := SanitizeMarkdownWithOptions(strings.TrimSpace(src), "", false)
			if trimmedMD == "" {
				continue
			}
			blocks = append(blocks, trimmedMD)
			for _, line := range strings.Split(trimmedMD, "\n") {
				tl := strings.TrimSpace(line)
				if tl == "" {
					continue
				}
				if title == "" && strings.HasPrefix(tl, "# ") {
					title = SanitizeScrapedMetadataField(tl[2:], 512)
				} else if description == "" && !strings.HasPrefix(tl, "#") && !strings.HasPrefix(tl, "```") && len(tl) >= 20 {
					description = SanitizeScrapedMetadataField(stripMarkdownLinksToLabelsLinearFmtGo(tl), 280)
				}
			}
		case "code":
			blocks = append(blocks, MakeSafeCodeFence(src, fenceLang, false))
			outputs, _ := cell["outputs"].([]any)
			if len(outputs) > 6 {
				outputs = outputs[:6]
			}
			var outSnippets []string
			for _, rawOut := range outputs {
				outMap, isOutMap := rawOut.(map[string]any)
				if !isOutMap {
					continue
				}
				outType, _ := outMap["output_type"].(string)
				switch outType {
				case "stream":
					if txt := strings.TrimSpace(joinIpynbLinesFmtGo(outMap["text"])); txt != "" {
						outSnippets = append(outSnippets, MakeSafeCodeFence(truncateUTF8SafeFullDocGo(txt, 1600), "text", false))
					}
				case "execute_result", "display_data":
					dataMap, _ := outMap["data"].(map[string]any)
					mdOut := strings.TrimSpace(joinIpynbLinesFmtGo(dataMap["text/markdown"]))
					plainOut := strings.TrimSpace(joinIpynbLinesFmtGo(dataMap["text/plain"]))
					if mdOut != "" {
						if cleanMdOut := SanitizeMarkdownWithOptions(truncateUTF8SafeFullDocGo(mdOut, 1600), "", false); cleanMdOut != "" {
							outSnippets = append(outSnippets, cleanMdOut)
						}
					} else if plainOut != "" && !reFigureSizePlainFmtGo.MatchString(plainOut) {
						outSnippets = append(outSnippets, MakeSafeCodeFence(truncateUTF8SafeFullDocGo(plainOut, 1600), "text", false))
					}
				case "error":
					ename, _ := outMap["ename"].(string)
					if ename == "" {
						ename = "Error"
					}
					evalue, _ := outMap["evalue"].(string)
					errMsg := ename
					if evalue != "" {
						errMsg += ": " + evalue
					}
					outSnippets = append(outSnippets, MakeSafeCodeFence(errMsg, "text", false))
				}
			}
			if len(outSnippets) > 0 {
				blocks = append(blocks, strings.Join(outSnippets, "\n\n"))
			}
		case "raw":
			blocks = append(blocks, MakeSafeCodeFence(src, "", false))
		}
	}

	if len(blocks) == 0 {
		return nil
	}
	finalTitle := title
	if finalTitle == "" {
		finalTitle = SanitizeScrapedMetadataField(fallbackTitle, 512)
	}
	fullMD := strings.Join(blocks, "\n\n")
	if finalTitle != "" && !strings.HasPrefix(blocks[0], "# ") {
		fullMD = "# " + escapeDeclMarkdownBrackets(finalTitle) + "\n\n" + fullMD
	}
	return &FormattedPayloadDoc{
		Title:       finalTitle,
		Description: SanitizeScrapedMetadataField(description, 280),
		Markdown:    fullMD,
		Structured:  parsed,
	}
}

// FormatJupyterNotebookToMarkdown converts a Jupyter Notebook (`.ipynb`) JSON string into clean Markdown,
// rendering Markdown cells natively, wrapping code cells in kernel-language fences, and keeping concise text/error outputs.
func FormatJupyterNotebookToMarkdown(raw, urlStr string) *FormattedPayloadDoc {
	trimmed := strings.TrimSpace(strings.TrimPrefix(raw, "\ufeff"))
	if !strings.HasPrefix(trimmed, "{") {
		return nil
	}
	parsed, ok := decodeJSONWithNumbers([]byte(trimmed))
	if !ok {
		return nil
	}
	return formatParsedJupyterNotebookFmtGo(parsed, deriveFallbackTitleFromURLFmtGo(urlStr))
}

func orderedKeysWithFallbackFmtGo(jsonBytes []byte, pathSegs []string, m map[string]any) []string {
	if len(jsonBytes) > 0 {
		if ordered := extractOrderedObjectKeys(jsonBytes, pathSegs); len(ordered) == len(m) {
			return ordered
		}
	}
	return sortedMapKeys(m)
}

func formatParsedOpenAPISpecFmtGo(parsed any, jsonBytes []byte) *FormattedPayloadDoc {
	spec, ok := parsed.(map[string]any)
	if !ok {
		return nil
	}
	oaVer := strings.TrimSpace(jsonScalarToStringFmtGo(spec["openapi"]))
	swVer := strings.TrimSpace(jsonScalarToStringFmtGo(spec["swagger"]))
	if swVer == "2" {
		swVer = "2.0"
	}
	if !strings.HasPrefix(oaVer, "3.") && !strings.HasPrefix(swVer, "2.") {
		return nil
	}
	pathsObj, ok := spec["paths"].(map[string]any)
	if !ok {
		return nil
	}

	info, _ := spec["info"].(map[string]any)
	rawTitle := strings.TrimSpace(jsonScalarToStringFmtGo(info["title"]))
	if rawTitle == "" {
		rawTitle = "API Specification"
	}
	apiVer := strings.TrimSpace(jsonScalarToStringFmtGo(info["version"]))
	specBadge := "Swagger " + swVer
	if oaVer != "" {
		specBadge = "OpenAPI " + oaVer
	}
	rawDesc, _ := info["description"].(string)
	rawDesc = strings.TrimSpace(rawDesc)
	cleanSummaryDesc := truncateUTF8SafeFullDocGo(strings.Join(strings.Fields(stripMarkdownLinksToLabelsLinearFmtGo(rawDesc)), " "), 300)

	safeTitle := escapeDeclMarkdownBrackets(SanitizeScrapedMeta(rawTitle))
	safeApiVer := escapeDeclMarkdownBrackets(SanitizeScrapedMeta(apiVer))
	safeSpecBadge := escapeDeclMarkdownBrackets(SanitizeScrapedMeta(specBadge))
	h1 := "# " + safeTitle + " (" + safeSpecBadge + ")"
	if safeApiVer != "" {
		h1 = "# " + safeTitle + " (v" + safeApiVer + " — " + safeSpecBadge + ")"
	}
	sections := []string{h1}
	if rawDesc != "" {
		sections = append(sections, escapeDeclMarkdownBlock(rawDesc))
	}

	// Servers (`OpenAPI 3.x` `servers[]` or `Swagger 2.0` `host` + `basePath`)
	if servers, isArr := spec["servers"].([]any); isArr && len(servers) > 0 {
		var srvLines []string
		for _, sRaw := range servers {
			sMap, isMap := sRaw.(map[string]any)
			if !isMap {
				continue
			}
			u, _ := sMap["url"].(string)
			u = strings.TrimSpace(u)
			d, _ := sMap["description"].(string)
			d = strings.TrimSpace(d)
			if u != "" {
				line := "- `" + sanitizeDeclInlineCodeVal(u) + "`"
				if d != "" {
					line += " — " + escapeDeclMarkdownBrackets(d)
				}
				srvLines = append(srvLines, line)
			}
		}
		if len(srvLines) > 0 {
			sections = append(sections, "## Servers\n\n"+strings.Join(srvLines, "\n"))
		}
	} else if hostStr, ok := spec["host"].(string); ok && strings.TrimSpace(hostStr) != "" {
		scheme := "https"
		if schemes, isArr := spec["schemes"].([]any); isArr && len(schemes) > 0 {
			if s0, ok := schemes[0].(string); ok && s0 != "" {
				scheme = s0
			}
		}
		bp, _ := spec["basePath"].(string)
		sections = append(sections, "## Servers\n\n- `"+sanitizeDeclInlineCodeVal(scheme+"://"+strings.TrimSpace(hostStr)+bp)+"`")
	}

	// Security Schemes
	components, _ := spec["components"].(map[string]any)
	var secDefs map[string]any
	secPath := []string{"components", "securitySchemes"}
	if sd, ok := components["securitySchemes"].(map[string]any); ok {
		secDefs = sd
	} else if sd, ok := spec["securityDefinitions"].(map[string]any); ok {
		secDefs = sd
		secPath = []string{"securityDefinitions"}
	}
	if len(secDefs) > 0 {
		var secLines []string
		secKeys := orderedKeysWithFallbackFmtGo(jsonBytes, secPath, secDefs)
		if len(secKeys) > 12 {
			secKeys = secKeys[:12]
		}
		for _, secName := range secKeys {
			sv, isMap := secDefs[secName].(map[string]any)
			if !isMap {
				continue
			}
			t, _ := sv["type"].(string)
			sch := ""
			if schemeVal, ok := sv["scheme"].(string); ok && schemeVal != "" {
				sch = " (" + escapeDeclMarkdownBrackets(schemeVal) + ")"
			} else if inVal, ok := sv["in"].(string); ok && inVal != "" {
				nmVal, _ := sv["name"].(string)
				sch = " (in " + escapeDeclMarkdownBrackets(inVal) + ": " + escapeDeclMarkdownBrackets(nmVal) + ")"
			}
			secLines = append(secLines, "- **"+escapeDeclMarkdownBrackets(secName)+"**: `"+sanitizeDeclInlineCodeVal(t)+"`"+sch)
		}
		if len(secLines) > 0 {
			sections = append(sections, "## Authentication\n\n"+strings.Join(secLines, "\n"))
		}
	}

	var formatSchemaRef func(sObj any) string
	formatSchemaRef = func(sObj any) string {
		so, isMap := sObj.(map[string]any)
		if !isMap {
			return ""
		}
		if ref, ok := so["$ref"].(string); ok && ref != "" {
			parts := strings.Split(ref, "/")
			return parts[len(parts)-1]
		}
		if so["type"] == "array" && so["items"] != nil {
			inner := formatSchemaRef(so["items"])
			if inner == "" {
				inner = "any"
			}
			return inner + "[]"
		}
		if tStr, ok := so["type"].(string); ok && tStr != "" {
			if fStr, ok := so["format"].(string); ok && fStr != "" {
				return tStr + "(" + fStr + ")"
			}
			return tStr
		}
		return ""
	}

	httpMethods := []string{"get", "post", "put", "patch", "delete", "options", "head"}
	tableRows := []string{
		"| Method | Path | Summary | Operation ID |",
		"| --- | --- | --- | --- |",
	}
	var opDetails []string
	opCount := 0

	routeKeys := orderedKeysWithFallbackFmtGo(jsonBytes, []string{"paths"}, pathsObj)
	for _, routePath := range routeKeys {
		pi, isMap := pathsObj[routePath].(map[string]any)
		if !isMap {
			continue
		}
		sharedParams, _ := pi["parameters"].([]any)
		for _, m := range httpMethods {
			opRec, isOpMap := pi[m].(map[string]any)
			if !isOpMap {
				continue
			}
			opCount++
			upperM := strings.ToUpper(m)
			rawSummary, _ := opRec["summary"].(string)
			if rawSummary == "" {
				if dStr, ok := opRec["description"].(string); ok {
					rawSummary = strings.Split(dStr, "\n")[0]
				}
			}
			summary := strings.ReplaceAll(strings.Join(strings.Fields(rawSummary), " "), "|", `\|`)
			summary = escapeDeclMarkdownBrackets(truncateUTF8SafeFullDocGo(summary, 120))
			opID, _ := opRec["operationId"].(string)
			opID = strings.TrimSpace(opID)

			if opCount <= 150 {
				opIDCell := ""
				if opID != "" {
					opIDCell = "`" + sanitizeDeclInlineCodeVal(opID) + "`"
				}
				tableRows = append(tableRows, "| `"+upperM+"` | `"+sanitizeDeclInlineCodeVal(routePath)+"` | "+summary+" | "+opIDCell+" |")
			}
			if opCount <= 60 {
				hLine := "### `" + upperM + " " + sanitizeDeclInlineCodeVal(routePath) + "`"
				if summary != "" {
					hLine += " — " + summary
				}
				lines := []string{hLine}
				opParams, _ := opRec["parameters"].([]any)
				allParams := append(append([]any(nil), sharedParams...), opParams...)
				if len(allParams) > 12 {
					allParams = allParams[:12]
				}
				var paramBits []string
				for _, pRaw := range allParams {
					pMap, isPMap := pRaw.(map[string]any)
					if !isPMap {
						continue
					}
					pName, ok := pMap["name"].(string)
					if !ok || pName == "" {
						continue
					}
					loc, _ := pMap["in"].(string)
					if loc == "" {
						loc = "query"
					}
					req := ""
					if reqBool, _ := pMap["required"].(bool); reqBool {
						req = ", required"
					}
					pType := formatSchemaRef(pMap["schema"])
					if pType == "" {
						pType, _ = pMap["type"].(string)
					}
					typeLabel := ""
					if pType != "" {
						typeLabel = ": " + escapeDeclMarkdownBrackets(pType)
					}
					paramBits = append(paramBits, "`"+sanitizeDeclInlineCodeVal(pName)+"` ("+escapeDeclMarkdownBrackets(loc)+typeLabel+req+")")
				}
				if len(paramBits) > 0 {
					lines = append(lines, "- **Parameters**: "+strings.Join(paramBits, ", "))
				}

				if rb, isRbMap := opRec["requestBody"].(map[string]any); isRbMap {
					rbContent, _ := rb["content"].(map[string]any)
					var mediaMap map[string]any
					if jm, ok := rbContent["application/json"].(map[string]any); ok {
						mediaMap = jm
					} else {
						for _, mk := range sortedMapKeys(rbContent) {
							if mm, ok := rbContent[mk].(map[string]any); ok {
								mediaMap = mm
								break
							}
						}
					}
					rbSchema := ""
					if mediaMap != nil {
						rbSchema = formatSchemaRef(mediaMap["schema"])
					}
					reqTag := ""
					if rbReq, _ := rb["required"].(bool); rbReq {
						reqTag = " *(required)*"
					}
					schemaLabel := "JSON"
					if rbSchema != "" {
						schemaLabel = "`" + sanitizeDeclInlineCodeVal(rbSchema) + "`"
					}
					lines = append(lines, "- **Request Body**"+reqTag+": "+schemaLabel)
				}

				if respMap, isRespMap := opRec["responses"].(map[string]any); isRespMap {
					respKeys := orderedKeysWithFallbackFmtGo(jsonBytes, []string{"paths", routePath, m, "responses"}, respMap)
					if len(respKeys) > 6 {
						respKeys = respKeys[:6]
					}
					var respBits []string
					for _, code := range respKeys {
						rRec, isRMap := respMap[code].(map[string]any)
						if !isRMap {
							continue
						}
						rDescStr, _ := rRec["description"].(string)
						rDesc := truncateUTF8SafeFullDocGo(strings.Join(strings.Fields(rDescStr), " "), 80)
						rContent, _ := rRec["content"].(map[string]any)
						rJSON, _ := rContent["application/json"].(map[string]any)
						var schemaTarget any
						if rJSON != nil && rJSON["schema"] != nil {
							schemaTarget = rJSON["schema"]
						} else {
							schemaTarget = rRec["schema"]
						}
						rSchema := formatSchemaRef(schemaTarget)
						bit := "`" + sanitizeDeclInlineCodeVal(code) + "`"
						if rSchema != "" {
							bit += " → `" + sanitizeDeclInlineCodeVal(rSchema) + "`"
						}
						if rDesc != "" {
							bit += " (" + escapeDeclMarkdownBrackets(rDesc) + ")"
						}
						respBits = append(respBits, bit)
					}
					if len(respBits) > 0 {
						lines = append(lines, "- **Responses**: "+strings.Join(respBits, "; "))
					}
				}
				opDetails = append(opDetails, strings.Join(lines, "\n"))
			}
		}
	}

	if len(tableRows) > 2 {
		sections = append(sections, "## Endpoints ("+strconv.Itoa(opCount)+")\n\n"+strings.Join(tableRows, "\n"))
	}
	if len(opDetails) > 0 {
		sections = append(sections, "## Operations\n\n"+strings.Join(opDetails, "\n\n"))
	}

	var schemasObj map[string]any
	schemaPath := []string{"components", "schemas"}
	if sc, ok := components["schemas"].(map[string]any); ok {
		schemasObj = sc
	} else if sc, ok := spec["definitions"].(map[string]any); ok {
		schemasObj = sc
		schemaPath = []string{"definitions"}
	}
	if len(schemasObj) > 0 {
		sKeys := orderedKeysWithFallbackFmtGo(jsonBytes, schemaPath, schemasObj)
		if len(sKeys) > 30 {
			sKeys = sKeys[:30]
		}
		var schemaLines []string
		for _, sName := range sKeys {
			sv, isMap := schemasObj[sName].(map[string]any)
			if !isMap {
				continue
			}
			var propNames []string
			if pMap, isPMap := sv["properties"].(map[string]any); isPMap {
				propNames = orderedKeysWithFallbackFmtGo(jsonBytes, append(append([]string(nil), schemaPath...), sName, "properties"), pMap)
			}
			line := "- **`" + sanitizeDeclInlineCodeVal(sName) + "`**"
			if len(propNames) > 0 {
				shown := propNames
				ellipsis := ""
				if len(shown) > 10 {
					shown = shown[:10]
					ellipsis = ", …"
				}
				safeProps := make([]string, len(shown))
				for idx, pn := range shown {
					safeProps[idx] = sanitizeDeclInlineCodeVal(pn)
				}
				line += ": `" + strings.Join(safeProps, "`, `") + "`" + ellipsis
			}
			schemaLines = append(schemaLines, line)
		}
		if len(schemaLines) > 0 {
			sections = append(sections, "## Schemas\n\n"+strings.Join(schemaLines, "\n"))
		}
	}

	return &FormattedPayloadDoc{
		Title:       SanitizeScrapedMetadataField(rawTitle, 512),
		Description: SanitizeScrapedMetadataField(cleanSummaryDesc, 300),
		Markdown:    SanitizeScrapedMarkdown(strings.Join(sections, "\n\n")),
		Structured:  parsed,
	}
}

// FormatOpenAPISpecToMarkdown formats OpenAPI 3.x and Swagger 2.0 specifications (in either JSON or YAML format via `YAMLToJSON`)
// into a compact, navigable GFM Markdown API reference.
func FormatOpenAPISpecToMarkdown(raw, urlStr string) *FormattedPayloadDoc {
	_ = urlStr
	trimmed := strings.TrimSpace(strings.TrimPrefix(raw, "\ufeff"))
	if trimmed == "" {
		return nil
	}
	var jsonBytes []byte
	if strings.HasPrefix(trimmed, "{") {
		jsonBytes = []byte(trimmed)
	} else {
		lowHead := asciiLowerExtractString(trimmed[:minInt(len(trimmed), 4096)])
		if !strings.Contains(lowHead, "openapi") && !strings.Contains(lowHead, "swagger") {
			return nil
		}
		converted, err := YAMLToJSON([]byte(trimmed))
		if err != nil {
			return nil
		}
		jsonBytes = converted
	}
	parsed, ok := decodeJSONWithNumbers(jsonBytes)
	if !ok {
		return nil
	}
	return formatParsedOpenAPISpecFmtGo(parsed, jsonBytes)
}

func marshalPrettyJSONNoEscapeFmtGo(val any) string {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(val); err != nil {
		b, _ := json.MarshalIndent(val, "", "  ")
		return string(b)
	}
	return strings.TrimRight(buf.String(), "\r\n")
}

const (
	maxJSONScrapeFullDecodeBytes = 2 << 20    // 2 MiB ceiling for full `map[string]any` DOM materialization
	maxJSONScrapeFenceBytes      = 512 * 1024 // 512 KiB preview cap for oversized multi-MiB JSON artifacts
)

// TryParseJSONPayloadForScrape parses JSON scrape payloads, upgrading Jupyter `.ipynb` notebooks and OpenAPI/Swagger specs
// to native GFM Markdown and formatting generic JSON objects/arrays in pretty-printed `json` fences with sanitized metadata.
func TryParseJSONPayloadForScrape(raw, urlStr string) *FormattedPayloadDoc {
	trimmed := strings.TrimSpace(strings.TrimPrefix(raw, "\ufeff"))
	if !strings.HasPrefix(trimmed, "{") && !strings.HasPrefix(trimmed, "[") {
		return nil
	}
	jsonBytes := []byte(trimmed)
	if len(jsonBytes) > maxJSONScrapeFullDecodeBytes {
		if !json.Valid(jsonBytes) {
			return nil
		}
		head := truncateUTF8SafeFullDocGo(trimmed, 8192)
		var title, description string
		if strings.HasPrefix(trimmed, "{") {
			nameStr := matchJSONStringFieldInSliceFmtGo(head, "name")
			verStr := matchJSONStringFieldInSliceFmtGo(head, "version")
			titleStr := matchJSONStringFieldInSliceFmtGo(head, "title")
			switch {
			case nameStr != "" && verStr != "":
				title = nameStr + "@" + verStr
			case titleStr != "":
				title = titleStr
			case nameStr != "":
				title = nameStr
			}
			descCand := firstNonEmptyFullDocGo(
				matchJSONStringFieldInSliceFmtGo(head, "description"),
				matchJSONStringFieldInSliceFmtGo(head, "summary"),
			)
			if descCand != "" {
				description = truncateUTF8SafeFullDocGo(descCand, 500)
			}
		}
		cleanTitle := SanitizeScrapedMetadataField(title, 512)
		cleanDesc := SanitizeScrapedMetadataField(description, 2000)
		preview := strings.TrimRight(truncateUTF8SafeFullDocGo(trimmed, maxJSONScrapeFenceBytes), " \t\r\n") +
			"\n// ... [JSON payload truncated at 512 KiB]"
		fence := MakeSafeCodeFence(preview, "json", false)
		md := fence
		if cleanTitle != "" {
			md = "# " + escapeDeclMarkdownBrackets(cleanTitle) + "\n\n" + fence
		}
		return &FormattedPayloadDoc{
			Title:       cleanTitle,
			Description: cleanDesc,
			Markdown:    md,
		}
	}
	parsed, ok := decodeJSONWithNumbers(jsonBytes)
	if !ok {
		return nil
	}
	if ipynbDoc := formatParsedJupyterNotebookFmtGo(parsed, deriveFallbackTitleFromURLFmtGo(urlStr)); ipynbDoc != nil {
		return ipynbDoc
	}
	if openAPIDoc := formatParsedOpenAPISpecFmtGo(parsed, jsonBytes); openAPIDoc != nil {
		return openAPIDoc
	}

	pretty := marshalPrettyJSONNoEscapeFmtGo(parsed)
	var title, description string
	if obj, isMap := parsed.(map[string]any); isMap {
		var nested map[string]any
		if infoMap, ok := obj["info"].(map[string]any); ok {
			nested = infoMap
		} else if dataMap, ok := obj["data"].(map[string]any); ok {
			nested = dataMap
		}
		strField := func(m map[string]any, key string) string {
			if m == nil {
				return ""
			}
			if s, ok := m[key].(string); ok {
				return strings.TrimSpace(s)
			}
			return ""
		}
		nameStr := firstNonEmptyFullDocGo(strField(obj, "name"), strField(nested, "name"))
		verStr := firstNonEmptyFullDocGo(strField(obj, "version"), strField(nested, "version"))
		titleStr := firstNonEmptyFullDocGo(strField(obj, "title"), strField(nested, "title"))
		switch {
		case nameStr != "" && verStr != "":
			title = nameStr + "@" + verStr
		case titleStr != "":
			title = titleStr
		case nameStr != "":
			title = nameStr
		}
		descCand := firstNonEmptyFullDocGo(strField(obj, "description"), strField(nested, "summary"), strField(nested, "description"))
		if descCand != "" {
			description = truncateUTF8SafeFullDocGo(descCand, 500)
		}
	}

	cleanTitle := SanitizeScrapedMetadataField(title, 512)
	cleanDesc := SanitizeScrapedMetadataField(description, 2000)
	fence := MakeSafeCodeFence(pretty, "json", false)
	md := fence
	if cleanTitle != "" {
		md = "# " + escapeDeclMarkdownBrackets(cleanTitle) + "\n\n" + fence
	}
	return &FormattedPayloadDoc{
		Title:       cleanTitle,
		Description: cleanDesc,
		Markdown:    md,
		Structured:  parsed,
	}
}

func matchJSONStringFieldInSliceFmtGo(slice, key string) string {
	needle := `"` + key + `":"`
	idx := strings.Index(slice, needle)
	if idx < 0 {
		return ""
	}
	start := idx + len(needle)
	i := start
	for i < len(slice) {
		if slice[i] == '\\' {
			i += 2
		} else if slice[i] == '"' {
			break
		} else {
			i++
		}
	}
	if i >= len(slice) {
		return ""
	}
	rawEsc := slice[start:i]
	var decoded string
	if err := json.Unmarshal([]byte(`"`+rawEsc+`"`), &decoded); err == nil {
		return strings.TrimSpace(decoded)
	}
	r := strings.NewReplacer(`\n`, "\n", `\"`, `"`, `\u0026`, "&")
	return strings.TrimSpace(r.Replace(rawEsc))
}

func formatDurationSecondsFmtGo(totalSec int) string {
	if totalSec <= 0 {
		return ""
	}
	h := totalSec / 3600
	m := (totalSec % 3600) / 60
	s := totalSec % 60
	if h > 0 {
		return fmt.Sprintf("%dh %dm %ds", h, m, s)
	}
	if m > 0 {
		return fmt.Sprintf("%dm %ds", m, s)
	}
	return fmt.Sprintf("%ds", s)
}

// sanitizeYouTubeWatchUntrustedFieldGo strips HTML comments/tags (including split/nested tags),
// pre-escapes any residual `<` (e.g., unclosed tags), and escapes line-leading code fences so
// untrusted YouTube videoDetails scalars cannot form raw-HTML fenced code blocks while preserving `\n`.
func sanitizeYouTubeWatchUntrustedFieldGo(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return ""
	}
	s := normalizeMarkdownLineEndings(stripInvisibleSmugglingCharsGo(trimmed))
	if strings.Contains(s, "<!--") {
		s = stripHtmlCommentsLinearGo(s, false)
	}
	if strings.IndexByte(s, '<') >= 0 && strings.IndexByte(s, '>') >= 0 {
		s = stripDangerousHTMLSubtreesGo(s)
		for pass := 0; pass < 4 && strings.IndexByte(s, '<') >= 0 && strings.IndexByte(s, '>') >= 0; pass++ {
			next := stripHTMLTagsQuoteAwareSchemaGo(s, " ", maxSanitizeMarkdownScanBytes)
			if next == s {
				break
			}
			s = next
		}
	}
	if strings.IndexByte(s, '<') >= 0 {
		s = strings.ReplaceAll(s, "<", "&lt;")
	}
	s = escapePostStripProseFencesGo(s)
	return SanitizeScrapedMarkdown(s)
}

func isValidYouTubeVideoIDFmtGo(id string) bool {
	if len(id) == 0 || len(id) > 32 {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

// ExtractYouTubeWatchMetadataFromHTML extracts `ytInitialPlayerResponse.videoDetails` metadata and clean Markdown
// from a YouTube watch page HTML document without launching a browser.
func ExtractYouTubeWatchMetadataFromHTML(rawHTML, urlStr string) *YouTubeWatchMeta {
	vdObjStart := -1
	searchFrom := 0
	for searchFrom < len(rawHTML) {
		rel := strings.Index(rawHTML[searchFrom:], `"videoDetails"`)
		if rel < 0 {
			break
		}
		k := searchFrom + rel + len(`"videoDetails"`)
		for k < len(rawHTML) && (rawHTML[k] == ' ' || rawHTML[k] == '\t' || rawHTML[k] == '\n' || rawHTML[k] == '\r') {
			k++
		}
		if k < len(rawHTML) && rawHTML[k] == ':' {
			k++
			for k < len(rawHTML) && (rawHTML[k] == ' ' || rawHTML[k] == '\t' || rawHTML[k] == '\n' || rawHTML[k] == '\r') {
				k++
			}
			if k < len(rawHTML) && rawHTML[k] == '{' {
				vdObjStart = k
				break
			}
		}
		searchFrom = searchFrom + rel + len(`"videoDetails"`)
	}
	if vdObjStart < 0 {
		return nil
	}
	balanced, _, okBalanced := ExtractBalancedJSONAt(rawHTML, vdObjStart, 256_000)
	if !okBalanced {
		return nil
	}
	var vdMap map[string]any
	if err := json.Unmarshal([]byte(balanced), &vdMap); err != nil || vdMap == nil {
		return nil
	}
	strField := func(k string) string {
		if v, ok := vdMap[k].(string); ok {
			return strings.TrimSpace(v)
		}
		return ""
	}
	rawTitle := strField("title")
	if rawTitle == "" {
		return nil
	}
	title := escapeMarkdownBracketsOnlyGo(sanitizeYouTubeWatchUntrustedFieldGo(rawTitle))
	if title == "" {
		return nil
	}
	videoID := strField("videoId")
	if !isValidYouTubeVideoIDFmtGo(videoID) {
		videoID = ""
	}
	author := escapeMarkdownBracketsOnlyGo(sanitizeYouTubeWatchUntrustedFieldGo(strField("author")))
	lengthSeconds := 0
	if lsStr := strField("lengthSeconds"); lsStr != "" {
		lengthSeconds, _ = strconv.Atoi(lsStr)
	} else if lsFloat, okF := vdMap["lengthSeconds"].(float64); okF && lsFloat >= 0 {
		lengthSeconds = int(lsFloat)
	}
	viewCountRaw := strField("viewCount")
	if viewCountRaw == "" {
		if vcFloat, okVC := vdMap["viewCount"].(float64); okVC && vcFloat >= 0 {
			viewCountRaw = strconv.FormatInt(int64(vcFloat), 10)
		}
	}
	shortDesc := sanitizeYouTubeWatchUntrustedFieldGo(strField("shortDescription"))

	collapseRenderedSingleLine := func(s string) string {
		if s == "" {
			return ""
		}
		collapsed := strings.NewReplacer("\r", " ", "\n", " ").Replace(s)
		collapsed = strings.Join(strings.Fields(collapsed), " ")
		bs := 0
		for i := len(collapsed) - 1; i >= 0 && collapsed[i] == '\\'; i-- {
			bs++
		}
		if bs%2 == 1 {
			collapsed += `\`
		}
		return collapsed
	}

	var metaBullets []string
	if author != "" {
		metaBullets = append(metaBullets, "- **Channel**: "+collapseRenderedSingleLine(author))
	}
	dur := formatDurationSecondsFmtGo(lengthSeconds)
	if dur != "" {
		metaBullets = append(metaBullets, "- **Duration**: "+dur)
	}
	var viewCount int64
	if viewCountRaw != "" {
		if vc, err := strconv.ParseInt(viewCountRaw, 10, 64); err == nil && vc >= 0 {
			viewCount = vc
			metaBullets = append(metaBullets, "- **Views**: "+formatIntComma(vc))
		}
	}

	parts := []string{"# " + collapseRenderedSingleLine(title)}
	if len(metaBullets) > 0 {
		parts = append(parts, strings.Join(metaBullets, "\n"))
	}
	if shortDesc != "" {
		parts = append(parts, "## Description\n\n"+shortDesc)
	}

	canonical := strings.TrimSpace(urlStr)
	if canonical == "" && videoID != "" {
		canonical = "https://www.youtube.com/watch?v=" + videoID
	}
	cleanMarkdown := SanitizeMarkdownWithOptions(strings.Join(parts, "\n\n"), canonical, false)
	return &YouTubeWatchMeta{
		VideoID:       videoID,
		Title:         title,
		Author:        author,
		Description:   shortDesc,
		Duration:      dur,
		LengthSeconds: lengthSeconds,
		ViewCount:     viewCount,
		URL:           canonical,
		Markdown:      cleanMarkdown,
	}
}

// ExtractYouTubeTranscriptFromHTML extracts timed caption/transcript segments from rendered YouTube transcript DOM elements.
func ExtractYouTubeTranscriptFromHTML(rawHTML string) string {
	if rawHTML == "" {
		return ""
	}
	bounded := truncateUTF8SafeFullDocGo(rawHTML, maxHTMLScanCharsFullDocGo)
	lower := asciiLowerExtractString(bounded)
	var segments []string

	if strings.Contains(lower, "transcript-segment-view-model") {
		replacePairedHTMLElementsLinearFullDocGo(bounded, []string{"transcript-segment-view-model"}, func(_, _, _, segInner string) string {
			roleText := ""
			replacePairedHTMLElementsLinearFullDocGo(segInner, []string{"span"}, func(_, _, sAttrs, sInner string) string {
				if roleText == "" && strings.EqualFold(strings.TrimSpace(parseTagAttrsFullDocGo(sAttrs)["role"]), "text") {
					roleText = sInner
				}
				return ""
			}, 4096, 2048)
			target := roleText
			if target == "" {
				target = segInner
			}
			if cleaned := cleanInlineHTMLFullDocGo(target); cleaned != "" {
				segments = append(segments, cleaned)
			}
			return ""
		}, maxHTMLScanCharsFullDocGo, 4096)
	}

	if len(segments) == 0 && strings.Contains(lower, "segment-text") {
		replacePairedHTMLElementsLinearFullDocGo(bounded, []string{"yt-formatted-string"}, func(_, _, attrStr, segInner string) string {
			if hasClassTokenFullDocGo(attrStr, "segment-text") {
				if cleaned := cleanInlineHTMLFullDocGo(segInner); cleaned != "" {
					segments = append(segments, cleaned)
				}
			}
			return ""
		}, maxHTMLScanCharsFullDocGo, 4096)
	}

	if len(segments) == 0 {
		return ""
	}
	joined := reTranscriptCuesFmtGo.ReplaceAllString(strings.Join(segments, " "), " ")
	return strings.Join(strings.Fields(joined), " ")
}
